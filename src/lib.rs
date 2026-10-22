// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

//! FFI layer of Qualia2FA: exposes `qualia2fa-core` as UniFFI bindings.
//!
//! # Responsibility of this crate
//!
//! This crate **only moves data**: it converts the primitive types passed in from
//! Kotlin/Swift into core types, calls the core, and converts the results back.
//! **Any cryptography, parsing or validation logic in this file is a design
//! regression** — such logic must stay inside `qualia2fa-core`, the only layer
//! that is free of unsafe code and can be audited on its own.
//!
//! A review of this crate has a single checklist item: **has any core logic been
//! moved in here?**
//!
//! `uniffi::setup_scaffolding!()` expands the unsafe code the FFI boundary needs
//! inside this crate (raw pointer dereferences, `catch_unwind`, transfer of string
//! ownership), so this crate is not `forbid(unsafe_code)`. The safety boundary runs
//! **between crates**: the core is `forbid(unsafe_code)`, and this crate is the
//! only place allowed to contain unsafe code, which must stay thin. `Cargo.toml`
//! sets `unsafe_code` to `warn` rather than `allow`, so new unsafe code is reported
//! at build time.
//!
//! # Handling of secret material
//!
//! The core's [`OtpSecret`] **deliberately implements neither `Clone` nor a raw
//! byte accessor**, and its `Debug` does not even print the length. Across the FFI
//! boundary a seed is always represented as a **Base32 string**:
//!
//! - inbound: `&str` -> [`OtpSecret::from_base32`]
//! - outbound: [`OtpSecret::to_base32`]
//!
//! Seed bytes therefore never cross the FFI boundary as a `Vec<u8>`, which would
//! leave one copy on each side outside the control of any erasure. Base32 is the
//! single narrow exit already chosen by the core, and this layer reuses it.
//!
//! **Known residual risk**: on the Kotlin/Swift side a Base32 string is an
//! ordinary `String`, not protected by `secrecy`'s erasure, and it may be copied
//! by the garbage collector or stored in a string pool. That is an inherent
//! limitation of managed languages, so **the client side must adopt its own
//! discipline**: a seed's Base32 exists only in the scope that needs it, is
//! dropped immediately afterwards, and is never logged or persisted.

uniffi::setup_scaffolding!();

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use qualia_bioauth as bioauth;
use qualia_bioauth::Backend;
use qualia_dik::keystore::PlatformKeyStore;
use qualia_dik::keystore::platform::{PlatformDirectMasterKeyStore, PlatformWrappedMasterKeyStore};
use qualia_dik::{
    DEVICE_ID_LEN, DeviceId, DeviceKeyStore, DevicePublicKey, DeviceSignature, DeviceSigner,
    DirectMasterKeyStore, MASTER_KEY_LEN, MasterKey as DikMasterKey, WrappedMasterKey,
    WrappedMasterKeyStore,
};
use qualia_transport::lan::transport::Recipient as LanRecipient;
use qualia_transport::lan::transport::{IrohLan, MAX_MESSAGE_LEN, PeerAddress};
use qualia_transport::lan::wire::{ENDPOINT_KEY_LEN, EndpointKey, Peer, PeerStatus};
use qualia_transport::lan::{LanAddress, lobby::Lobby};
use qualia2fa_core::auth;
use qualia2fa_core::flow::{self, DeviceKeys as _, Joiner, Login, SecureStore as _};
use qualia2fa_core::import::apply::{Choice as ImportChoice, Difference as ImportDifference};
use qualia2fa_core::motp::{self, MotpPin};
use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};
use qualia2fa_core::recovery::KdfParams;
use qualia2fa_core::sync::{
    Conflict, ConflictKind, Decision, PayloadKind, SeenSyncIds, adjudicate,
};
use qualia2fa_core::transport::{
    Recipient, Roster, SharePlan, SyncSession, Transport, TransportCapabilities,
};
use qualia2fa_core::uri;
use qualia2fa_core::vault::{Entry, EntryKind, Group, GroupChild, MasterKey, Vault, VaultFile};
use qualia2fa_core::yaotp::{self, YandexPin};
use qualia2fa_core::{Error, ExposeSecret as _, SecretString};

/// Length of a challenge-response session identifier.
///
/// The core's `auth::SESSION_ID_LEN` is a **private** constant (it belongs to the
/// protocol internals and is not meant to be depended on from above), so the
/// value is written out here. It is not arbitrary: the core's
/// `pairing::SESSION_ID_LEN` is 32 as well, and the two are equal on purpose —
/// session identifiers on one channel must have the same length, otherwise a
/// length comparison would report a difference where there is none.
const AUTH_SESSION_ID_LEN: usize = 32;

/// Length of a challenge-response confirmation tag (core `auth::CONFIRM_LEN`, also private).
const AUTH_CONFIRM_LEN: usize = 32;

/// Maximum length in characters of a seed string crossing the FFI boundary.
///
/// Real seeds are 16-64 bytes (about 26-104 Base32 characters). The limit is 2048,
/// which leaves room for non-standard cases while rejecting meaningless input such
/// as a huge string a client was tricked into passing in.
///
/// **This is a defensive limit, not a specification requirement**: the core
/// deliberately sets no lower bound on seed length (short seeds exist in the
/// wild), and judging whether a length is adequate is a UI-layer warning, see
/// [`is_secret_shorter_than_recommended`].
const MAX_SECRET_CHARS: usize = 2048;

/// Maximum length in characters of an `otpauth://` URI crossing the FFI boundary.
///
/// Real URIs are usually shorter than 200 characters. A QR code holds at most
/// about 2953 bytes, so 4096 covers any URI that can arrive from a QR code while
/// rejecting oversized input.
const MAX_URI_CHARS: usize = 4096;

/// Maximum length in characters of a vault field crossing the FFI boundary.
///
/// The core enforces its own limit on decrypted fields (`Entry::MAX_FIELD_LEN`,
/// 64 KiB bytes), but that is the **post-decryption** defence. This constant
/// guards the side coming in from the client: a UI text box has no reason to hold
/// more than this, and rejecting at the boundary is cheaper than running a whole
/// encryption pass only to fail inside the core.
///
/// The limit counts characters (8 Ki characters) rather than the core's 64 KiB
/// bytes because what the client sends is a string; counting bytes would make a
/// note containing non-ASCII text hit the limit much earlier. 8 Ki characters is
/// far beyond any real service name, account name or note.
const MAX_VAULT_FIELD_CHARS: usize = 8 * 1024;

/// Maximum length in characters of a device label crossing the FFI boundary.
///
/// The label ends up in the platform key store, and platforms differ in how long a
/// key name may be (Windows CNG, Android Keystore and the iOS keychain all impose
/// limits, and not all of them are documented). Real labels are short strings such
/// as `qualia2fa-device`, so 256 characters is ample while still rejecting an
/// oversized label passed in by a client.
const MAX_LABEL_CHARS: usize = 256;

/// Maximum length in characters of a passphrase crossing the FFI boundary.
///
/// The passphrase is fed to Argon2, whose running time grows linearly with the
/// input length. Without a limit, a multi-megabyte "passphrase" could occupy the
/// thread for a long time during export or import. **The limit is not a security
/// measure** (passphrase strength comes from entropy, not length); it only
/// rejects meaningless input.
const MAX_PASSPHRASE_CHARS: usize = 1024;

/// Maximum length in characters of QR code text crossing the FFI boundary.
///
/// The QR payload is 99 bytes, 159 characters in Base32. The limit is 512, which
/// leaves room for text the client may carry around the payload (for example a
/// user copying the code together with quotes from a chat log) while rejecting
/// oversized input.
const MAX_QR_TEXT_CHARS: usize = 512;

/// Summary of a core error, carried across the FFI boundary.
///
/// The core's [`Error`] is a `#[non_exhaustive]` rich error enum (carrying
/// `String`, `usize` and other payloads) and is not a UniFFI type: UniFFI requires
/// every field of an error enum to implement `Lift`/`Lower`/`TypeId`, and with
/// `#[uniffi(flat_error)]` the variants would cross the boundary as `Display` text
/// only, leaving the client one opaque string and **no way to dispatch the UI by
/// failure reason**. This type carries two fields:
///
/// - `kind`: a stable machine-readable identifier the client branches on
/// - `message`: user-facing text, for display and logs only
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCoreError {
    /// Stable error identifier; see the contract in [`core_error_kind`].
    pub kind: String,
    /// Human-readable error text (identical to the core's `Display`).
    pub message: String,
}

/// Maps a core error to a **stable** machine-readable identifier.
///
/// # Stability contract
///
/// These strings are what the client `switch`es on, so they are **part of the
/// public interface**: new values may be added, but existing values must not be
/// renamed or change meaning (a rename breaks client behaviour).
///
/// The client must have a fallback branch for unknown `kind` values: the core is
/// `#[non_exhaustive]`, so variants will be added and older clients will meet
/// values they have never seen.
///
/// `format!("{source:?}")` and automatic derivation from the variant name are
/// deliberately not used: `Debug` output is an implementation detail, renaming a
/// variant would silently change client behaviour, and it may contain payload
/// contents. Every string is written out in an explicit `match` arm so that a
/// rename is visible during review.
///
/// # Notes on individual kinds
///
/// - `vault_entry_not_found` is distinct from an empty vault: the entry the caller
///   is acting on no longer exists.
/// - `vault_bad_key_check` reports a structural problem (the key check value has
///   the wrong length, or the file is truncated or malformed), whereas
///   `vault_decryption_failed` reports a wrong key or a file that was modified.
/// - `device_not_registered` means this device has never been registered;
///   `vault_decryption_failed` means it was registered but the data cannot be
///   decrypted.
/// - `pairing_authentication_failed` deliberately does not distinguish a modified
///   ciphertext, a wrong session and a wrong joiner public key, so that an attacker
///   gets no oracle for "almost succeeded".
/// - Failures reported by the device identity library are split into
///   `device_public_key_invalid`, `device_signature_invalid` and `device_error`
///   rather than one generic kind. The master key storage failures carry kinds of
///   their own — `invalid_wrapped_key`, `invalid_master_key`, `key_not_exportable`,
///   `hardware_unavailable`, `unsupported_platform` — because each one sends the
///   host side down a different path.
/// - The final `_ => "unknown"` arm is **required**: the core's `Error` is
///   `#[non_exhaustive]`, so a wildcard arm is mandatory outside its own crate
///   (removing it is `E0004`). The price is that the compiler does not flag a newly
///   added core variant — `"unknown"` silently absorbs it and the client receives a
///   kind it cannot dispatch. The `every_mapped_error_kind_is_distinct_and_known`
///   test guards against that instead of the compiler: add one mapping arm per new
///   variant and add the value to that test's list.
#[must_use]
pub fn core_error_kind(source: &Error) -> &'static str {
    match source {
        Error::Base32InvalidCharacter { .. } => "base32_invalid_character",
        Error::Base32InvalidLength { .. } => "base32_invalid_length",
        Error::Base32InvalidPadding => "base32_invalid_padding",
        Error::SecretEmpty => "secret_empty",
        Error::SecretTooShort { .. } => "secret_too_short",
        Error::UnsupportedAlgorithm { .. } => "unsupported_algorithm",
        Error::UnsupportedDigits { .. } => "unsupported_digits",
        Error::InvalidPeriod => "invalid_period",
        Error::RandomnessUnavailable => "randomness_unavailable",
        Error::UriUnsupportedScheme => "uri_unsupported_scheme",
        Error::UriMissingType => "uri_missing_type",
        Error::UriUnsupportedType { .. } => "uri_unsupported_type",
        Error::UriMissingSecret => "uri_missing_secret",
        Error::UriMissingCounter => "uri_missing_counter",
        Error::UriUnexpectedCounter => "uri_unexpected_counter",
        Error::UriDuplicateParameter { .. } => "uri_duplicate_parameter",
        Error::UriInvalidParameter { .. } => "uri_invalid_parameter",
        Error::UriInvalidPercentEncoding => "uri_invalid_percent_encoding",
        Error::UriIssuerMismatch { .. } => "uri_issuer_mismatch",
        Error::UriAccountContainsColon { .. } => "uri_account_contains_colon",
        // ── Vault ──────────────────────────────────────────────────────────
        Error::VaultTruncated => "vault_truncated",
        Error::VaultBadMagic => "vault_bad_magic",
        Error::VaultUnsupportedVersion { .. } => "vault_unsupported_version",
        Error::VaultReservedByteNotZero { .. } => "vault_reserved_byte_not_zero",
        Error::VaultUnknownRecordKind { .. } => "vault_unknown_record_kind",
        Error::VaultRecordTooLong { .. } => "vault_record_too_long",
        Error::VaultTooManyRecords => "vault_too_many_records",
        Error::VaultTrailingBytes { .. } => "vault_trailing_bytes",
        Error::VaultDuplicateEntryId => "vault_duplicate_entry_id",
        Error::VaultEntryNotFound => "vault_entry_not_found",
        Error::VaultDuplicateField { .. } => "vault_duplicate_field",
        Error::VaultCorrupt => "vault_corrupt",
        Error::VaultBadKeyCheck => "vault_bad_key_check",
        Error::VaultInvalidUtf8 => "vault_invalid_utf8",
        Error::VaultDecryptionFailed => "vault_decryption_failed",
        // ── The group tree ─────────────────────────────────────────────────
        //
        // Each of these is a different answer for the interface: an unknown group or entry
        // means the view is stale and has to be refreshed, an immutable top group means the
        // action does not exist there, and a cycle or a depth refusal means the move the user
        // asked for cannot be drawn at all.
        Error::VaultDuplicateGroupId => "vault_duplicate_group_id",
        Error::VaultGroupNotFound => "vault_group_not_found",
        Error::VaultGroupUnknownEntry => "vault_group_unknown_entry",
        Error::VaultTopGroupImmutable => "vault_top_group_immutable",
        Error::VaultGroupTooManyChildren { .. } => "vault_group_too_many_children",
        Error::VaultGroupDuplicateChild => "vault_group_duplicate_child",
        Error::VaultGroupCycle => "vault_group_cycle",
        Error::VaultGroupDepthExceeded { .. } => "vault_group_depth_exceeded",
        Error::MasterKeyWrongLength { .. } => "master_key_wrong_length",
        Error::FieldTooLong { .. } => "field_too_long",
        Error::VaultIo { .. } => "vault_io",
        // ── Device identity, pairing, recovery, challenge-response ─────────
        Error::DevicePublicKeyInvalid { .. } => "device_public_key_invalid",
        Error::DeviceSignatureInvalid { .. } => "device_signature_invalid",
        Error::Device(qualia_dik::Error::DevicePublicKeyInvalid { .. }) => {
            "device_public_key_invalid"
        }
        Error::Device(qualia_dik::Error::DeviceSignatureInvalid { .. }) => {
            "device_signature_invalid"
        }
        // ── Master key storage ─────────────────────────────────────────────
        //
        // The four ways holding the master key can fail are told apart because the
        // host side does something different about each of them: a blob that will not
        // unwrap needs a recovery path, a platform with no backend needs the other
        // form (or another device), a store that will not hand the material back needs
        // the wrapped form, and a machine with no usable provider needs the user told.
        // A fifth kind, `device_error`, still covers every other key store failure.
        Error::Device(qualia_dik::Error::InvalidWrappedKey { .. }) => "invalid_wrapped_key",
        Error::Device(qualia_dik::Error::InvalidMasterKey { .. }) => "invalid_master_key",
        Error::Device(qualia_dik::Error::KeyNotExportable { .. }) => "key_not_exportable",
        Error::Device(qualia_dik::Error::HardwareUnavailable { .. }) => "hardware_unavailable",
        Error::Device(qualia_dik::Error::UnsupportedPlatform { .. }) => "unsupported_platform",
        Error::Device(_) => "device_error",
        Error::PairingPayloadMalformed { .. } => "pairing_payload_malformed",
        Error::PairingUnsupportedVersion { .. } => "pairing_unsupported_version",
        Error::PairingAuthenticationFailed => "pairing_authentication_failed",
        Error::RecoveryFileMalformed { .. } => "recovery_file_malformed",
        Error::RecoveryParametersInvalid { .. } => "recovery_parameters_invalid",
        Error::RecoveryPassphraseEmpty => "recovery_passphrase_empty",
        Error::RecoveryAuthenticationFailed => "recovery_authentication_failed",
        Error::RecoveryEncryptionFailed => "recovery_encryption_failed",
        Error::RecoveryKdfFailed => "recovery_kdf_failed",
        // ── The application lock's password wrap ────────────────────────────
        //
        // Each failure sends the unlock screen somewhere different: a file that is not a
        // lock wrap is a state to report (restore or reset), a password that does not open
        // it is a retry, and a damaged cost field is neither. They must not collapse into
        // `"unknown"`.
        Error::LockFileMalformed { .. } => "lock_file_malformed",
        Error::LockParametersInvalid { .. } => "lock_parameters_invalid",
        Error::LockPassphraseEmpty => "lock_passphrase_empty",
        Error::LockPasswordRejected => "lock_password_rejected",
        Error::LockEncryptionFailed => "lock_encryption_failed",
        Error::LockKdfFailed => "lock_kdf_failed",
        Error::UnsupportedFormatVersion { .. } => "unsupported_format_version",
        Error::AuthMessageMalformed { .. } => "auth_message_malformed",
        Error::AuthProofFailed => "auth_proof_failed",
        Error::DeviceKeyMissing => "device_key_missing",
        Error::DeviceNotRegistered => "device_not_registered",
        Error::DeviceIdentityMismatch => "device_identity_mismatch",
        Error::SecureStoreWriteFailed { .. } => "secure_store_write_failed",
        Error::TimestampZero => "timestamp_zero",
        // ── Another authenticator's files ──────────────────────────────────
        //
        // Both directions, because each one sends the user somewhere different: a file that is
        // too large, one that nests too deeply, a password that is wrong rather than missing, an
        // export that needs a password at all. A file-level failure is what the interface
        // reports instead of a preview, so collapsing them into one kind would leave it unable
        // to say which.
        Error::ImportFileTooLarge { .. } => "import_file_too_large",
        Error::ImportTooManyEntries { .. } => "import_too_many_entries",
        Error::ImportTooDeeplyNested { .. } => "import_too_deeply_nested",
        Error::ImportMalformed { .. } => "import_malformed",
        Error::ImportUnsupportedVersion { .. } => "import_unsupported_version",
        Error::ImportPasswordRequired => "import_password_required",
        Error::ImportEncryptionUnsupported { .. } => "import_encryption_unsupported",
        Error::ImportWrongPassword => "import_wrong_password",
        Error::ImportCorrupted => "import_corrupted",
        Error::ImportInvalidKdfParameters { .. } => "import_invalid_kdf_parameters",
        Error::ExportPasswordRequired => "export_password_required",
        Error::ExportPasswordEmpty => "export_password_empty",
        Error::ExportQrTooLong { .. } => "export_qr_too_long",
        Error::ExportTooLarge => "export_too_large",
        Error::ExportParameterRefused { .. } => "export_parameter_refused",
        // ── Portable vault containers ──────────────────────────────────────
        //
        // A `.q2fa` file that will not open sends the user somewhere different depending on
        // why: the wrong kind of file, a version this build does not read, a damaged length, a
        // bare vault file that carries no key, or a passphrase that is missing or wrong.
        Error::PortableBadMagic => "portable_bad_magic",
        Error::PortableUnsupportedVersion { .. } => "portable_unsupported_version",
        Error::PortableTruncated => "portable_truncated",
        Error::PortableLengthMismatch => "portable_length_mismatch",
        Error::PortableTooLarge { .. } => "portable_too_large",
        Error::PortableVaultFileWithoutKey => "portable_vault_file_without_key",
        Error::PortablePasswordRequired => "portable_password_required",
        // ── Synchronization and the channel ────────────────────────────────
        //
        // The sync family is mapped as a whole rather than only the variants the current
        // screen branches on: a payload that fails to open, a log that is full and a
        // channel that was used twice all mean different things to the user, and letting
        // them collapse into `"unknown"` would leave the host side unable to tell them
        // apart once it wants to.
        Error::SyncBadMagic => "sync_bad_magic",
        Error::SyncUnsupportedVersion { .. } => "sync_unsupported_version",
        Error::SyncEmptyPayload => "sync_empty_payload",
        Error::SyncTruncated => "sync_truncated",
        Error::SyncRecordCountMismatch { .. } => "sync_record_count_mismatch",
        Error::SyncTooManyRecords { .. } => "sync_too_many_records",
        Error::SyncCompressionFailed => "sync_compression_failed",
        Error::SyncDecompressionFailed => "sync_decompression_failed",
        Error::SyncPayloadTooLarge { .. } => "sync_payload_too_large",
        Error::SyncUnknownRecordKind { .. } => "sync_unknown_record_kind",
        Error::SyncMalformed { .. } => "sync_malformed",
        Error::SyncAuthenticationFailed => "sync_authentication_failed",
        Error::SyncIconRequiresByteTransport => "sync_icon_requires_byte_transport",
        Error::SyncAlreadyApplied => "sync_already_applied",
        Error::SyncIdLogFull { .. } => "sync_id_log_full",
        Error::SyncSenderMismatch => "sync_sender_mismatch",
        Error::SyncUnknownPayloadKind { .. } => "sync_unknown_payload_kind",
        Error::SyncNoSessionFound => "sync_no_session_found",
        Error::TransportFailed { .. } => "transport_failed",
        Error::TransportUnsupported { .. } => "transport_unsupported",
        Error::TransportAlreadyUsed => "transport_already_used",
        Error::TransportMessageTooLarge { .. } => "transport_message_too_large",
        _ => "unknown",
    }
}

impl FfiError {
    /// Stable error identifier, for the client to dispatch UI text on.
    ///
    /// The client could read `FfiError.Core.detail.kind` directly, but that would
    /// require every call site to match on the variant first. This method folds the
    /// boundary's own errors into the same set of identifiers (`input_too_long`),
    /// so the client needs a single `when`.
    #[must_use]
    pub fn kind(&self) -> &str {
        match self {
            FfiError::InputTooLong { .. } => "input_too_long",
            FfiError::InputEmpty { .. } => "input_empty",
            FfiError::WrongCodeKind { .. } => "wrong_code_kind",
            FfiError::Core { detail } => &detail.kind,
            FfiError::Qr { kind, .. } => kind,
            FfiError::Lan { kind, .. } => kind,
            FfiError::AuthBound { kind, .. } => kind,
            FfiError::InvalidDeviceId { .. } => "invalid_device_id",
            FfiError::UnknownConflict { .. } => "unknown_conflict",
        }
    }
}

impl From<Error> for FfiCoreError {
    fn from(source: Error) -> Self {
        FfiCoreError {
            kind: core_error_kind(&source).to_owned(),
            message: source.to_string(),
        }
    }
}

/// Lets [`FfiCoreError`] take part in an outer error's text through `Display`.
///
/// Written by hand rather than derived: `Display` outputs `message` and does not
/// repeat `kind` — `kind` is meant for programs, and putting it into user-facing
/// text only adds noise.
///
/// It is needed because `#[error("{source}")]` requires `source` to implement
/// `Display`; otherwise thiserror treats it as `Error::source()` instead and
/// reports an unsatisfied `as_dyn_error` trait bound.
impl core::fmt::Display for FfiCoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Errors originating in the FFI boundary itself.
///
/// Kept separate from the core's [`Error`] because "input too long" is a
/// **boundary** concern, not a core semantic. Core errors are passed through in
/// structured form as [`FfiCoreError`], which is not the same as discarding their
/// classification.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// The input exceeds the limit set by this layer.
    #[error("input too long: {kind} limit is {limit} characters, got {actual} characters")]
    InputTooLong {
        /// The restricted input category (`secret` / `uri`).
        kind: String,
        /// Maximum number of characters allowed.
        limit: u64,
        /// Actual number of characters.
        actual: u64,
    },

    /// The host asked for a code the entry's kind cannot produce.
    ///
    /// A time-based entry has no counter to advance and an HOTP entry has no clock to read, so
    /// calling the other function is a mistake in the host, not a fault in the vault. Named
    /// rather than silently computing something: a code from the wrong scheme never matches, and
    /// the user would see "the code is wrong" instead of "the wrong call was made".
    #[error("this entry computes its code with {wanted}, not as {kind}")]
    WrongCodeKind {
        /// What the host asked for.
        kind: String,
        /// What the entry actually needs.
        wanted: String,
    },

    /// A field the host side must fill in was empty.
    ///
    /// The one field this applies to is the PIN of an mOTP or Yandex entry: an empty text field
    /// means the user cleared it, and storing an empty PIN would produce codes that never match
    /// while looking like a working entry.
    #[error("input is empty: {kind}")]
    InputEmpty {
        /// The field that was empty.
        kind: String,
    },

    /// An error returned by the core.
    ///
    /// **No `#[from]`**: `#[from]` would make thiserror generate
    /// `impl From<Error> for FfiError`, but UniFFI requires every field to be a
    /// type that can cross the boundary, and the core `Error` is not. The
    /// conversion is a hand-written `From` that first reduces the error to the
    /// plain data of [`FfiCoreError`].
    ///
    /// The field is named `detail` rather than `source` on purpose: thiserror
    /// always treats a field named `source` as `Error::source()` (requiring
    /// `std::error::Error`), even when the text only writes `{source}`, and then
    /// reports an unsatisfied `as_dyn_error` bound.
    #[error("{detail}")]
    Core {
        /// Structured summary of the core error.
        detail: FfiCoreError,
    },

    /// An error from the transport layer behind the code channel.
    ///
    /// Kept separate from [`FfiError::Core`] because it is a different layer with a
    /// different set of failure modes: a payload that will not fit, an image with no code
    /// in it, an image whose buffer does not match its dimensions. The message never
    /// carries a payload.
    #[error("{detail}")]
    Qr {
        /// Stable kind for the host to branch on, in `snake_case`.
        kind: String,
        /// Human-readable detail. Never contains a payload or a secret.
        detail: String,
    },

    /// An error from the LAN channel.
    ///
    /// Separate from [`FfiError::Qr`] for the same reason that one is separate from
    /// [`FfiError::Core`]: it is a different layer with a different set of failure modes — a
    /// socket that cannot be opened, a connection to a peer that was never registered, a
    /// multicast group that cannot be joined. The message never carries a payload.
    #[error("{detail}")]
    Lan {
        /// Stable kind for the host to branch on, in `snake_case`.
        kind: String,
        /// Human-readable detail. Never contains a payload or a secret.
        detail: String,
    },

    /// An error from the platform auth-bound key store behind `master.key.bio`.
    ///
    /// Separate from [`FfiError::Core`] because the platform authentication path has its
    /// own failure modes (a cancelled gesture, an unavailable authenticator, a blob written
    /// by another backend), and the host has to tell them apart from vault errors.
    #[error("{detail}")]
    AuthBound {
        /// Stable kind for the host to branch on, in `snake_case`.
        kind: String,
        /// Human-readable detail. Never contains a key or a blob.
        detail: String,
    },

    /// An identifier handed across the boundary is not in the form this layer documents.
    ///
    /// Device identifiers cross as 64 hexadecimal characters (see [`FfiTransport`]). A
    /// value of another shape is a **host-side** mistake — a truncated copy, or a
    /// fingerprint formatted with separators — and reading it as some other device would
    /// attribute a payload to the wrong sender, which is what the sender check exists to
    /// prevent.
    #[error("{kind} is not 64 hexadecimal characters")]
    InvalidDeviceId {
        /// Which identifier was wrong (`device_id`), so the host side can point at it.
        kind: String,
    },

    /// A decision was handed over for a conflict that is not waiting.
    ///
    /// The conflicts of a receive replace the ones before them, so a decision kept from an
    /// older merge names nothing. Refusing it is deliberate: applying a decision to
    /// whatever now sits under that identifier is how a user ends up with content they
    /// never chose.
    #[error("no conflict is waiting for entry {entry_id}")]
    UnknownConflict {
        /// The entry identifier the decision named, as it was passed in.
        entry_id: String,
    },
}

/// Conversion from a core error to an FFI error.
///
/// Hand-written rather than `#[from]`; see [`FfiError::Core`].
impl From<Error> for FfiError {
    fn from(source: Error) -> Self {
        FfiError::Core {
            detail: source.into(),
        }
    }
}

/// Hash algorithm selection passed in over FFI.
///
/// The core's [`Algorithm`] is not exposed directly, for two reasons:
///
/// 1. The extra layer keeps the Rust API unaffected by renames of the client-side enum.
/// 2. If the core ever turns it into an enum carrying data, the FFI contract stays unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiAlgorithm {
    /// HMAC-SHA-1 (the RFC 6238 default; almost every real server supports only this).
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl From<FfiAlgorithm> for Algorithm {
    fn from(value: FfiAlgorithm) -> Self {
        match value {
            FfiAlgorithm::Sha1 => Algorithm::Sha1,
            FfiAlgorithm::Sha256 => Algorithm::Sha256,
            FfiAlgorithm::Sha512 => Algorithm::Sha512,
        }
    }
}

/// Number of digits in a generated code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDigits {
    /// 5 digits (Steam Guard).
    Five,
    /// 6 digits (the default).
    Six,
    /// 7 digits (used by some banks).
    Seven,
    /// 8 digits.
    Eight,
    /// 9 digits.
    Nine,
    /// A count a form does not offer. Only another application's export or a crafted file
    /// produces one, and it is carried through rather than rounded: rounding would silently
    /// change what the entry computes.
    Other {
        /// The count, between 1 and 9.
        digits: u8,
    },
}

impl FfiDigits {
    /// The digit count as the core models it.
    ///
    /// **Fallible on purpose.** A count outside 1..=9 is refused here rather than rounded to a
    /// count the core accepts: an entry silently saved with six digits when the caller asked for
    /// zero or ten produces codes that never match, and nothing on screen would say why. The
    /// fallback this replaced did exactly that.
    ///
    /// # Errors
    ///
    /// The core's own [`Error::DigitsZero`] or [`Error::DigitsTooMany`], which say which count
    /// was refused and why ten cannot be produced at all.
    fn to_core(self) -> Result<Digits, FfiError> {
        match self {
            FfiDigits::Five => Ok(Digits::FIVE),
            FfiDigits::Six => Ok(Digits::SIX),
            FfiDigits::Seven => Ok(Digits::SEVEN),
            FfiDigits::Eight => Ok(Digits::EIGHT),
            FfiDigits::Nine => Ok(Digits::new(9).expect("nine is a digit count the core accepts")),
            FfiDigits::Other { digits } => Ok(Digits::new(digits)?),
        }
    }
}

impl From<Digits> for FfiDigits {
    fn from(value: Digits) -> Self {
        match value.as_byte() {
            5 => FfiDigits::Five,
            6 => FfiDigits::Six,
            7 => FfiDigits::Seven,
            8 => FfiDigits::Eight,
            9 => FfiDigits::Nine,
            digits => FfiDigits::Other { digits },
        }
    }
}

/// The kind of an entry, with the parameters that belong to it.
///
/// The kind decides how a code is computed: a time step, a counter, and for two of them a PIN.
/// The former flat `period` / `counter` pair could not express an mOTP entry, a Yandex OTP entry
/// or a Steam Guard entry, so those arrived as ordinary TOTP entries and produced wrong codes.
///
/// # The PIN is an input, never an output
///
/// `pin` is written by the host when it creates or changes an entry, and the core never hands one
/// back: a PIN is key material with no display purpose, and the one place that needs to read it is
/// the code computation, which happens inside the core. [`FfiVaultEntry::pin_set`] says whether
/// one is stored, so a form can show that a PIN exists without being able to read it.
///
/// On **update**, `pin: None` means "keep the stored PIN": a host that edits a note must not have
/// to ask the user for a PIN it was never shown, and must not silently drop it either.
#[derive(Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiEntryKind {
    /// Time-based (RFC 6238).
    Totp {
        /// Time step in seconds.
        period: u64,
    },
    /// Counter-based (RFC 4226).
    Hotp {
        /// The counter.
        counter: u64,
    },
    /// mOTP: MD5, a ten-second step, six hexadecimal characters, and a PIN.
    Motp {
        /// Time step in seconds, ten by definition.
        period: u64,
        /// The PIN to store. See the type documentation.
        pin: Option<String>,
    },
    /// Yandex OTP: SHA-256, eight lower-case letters, and a PIN.
    Yandex {
        /// Time step in seconds, thirty by definition.
        period: u64,
        /// The PIN to store. See the type documentation.
        pin: Option<String>,
    },
    /// Steam Guard: SHA-1, five characters, a thirty-second step.
    Steam,
}

impl core::fmt::Debug for FfiEntryKind {
    /// Prints the shape only: the PIN of an mOTP or Yandex entry is key material and must not
    /// reach a log, a panic message or a crash dump.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (name, period) = match self {
            Self::Totp { period } => ("Totp", Some(*period)),
            Self::Motp { period, .. } => ("Motp", Some(*period)),
            Self::Yandex { period, .. } => ("Yandex", Some(*period)),
            Self::Hotp { .. } => ("Hotp", None),
            Self::Steam => ("Steam", None),
        };
        let mut debug = formatter.debug_struct(name);
        if let Some(period) = period {
            debug.field("period", &period);
        }
        if let Self::Hotp { counter } = self {
            debug.field("counter", counter);
        }
        if matches!(
            self,
            Self::Motp { pin: Some(_), .. } | Self::Yandex { pin: Some(_), .. }
        ) {
            debug.field("pin", &"<set>");
        }
        debug.finish_non_exhaustive()
    }
}

/// A parsed `otpauth://` entry.
///
/// The fields correspond one-to-one to the core [`uri::OtpAuth`]; the only differences are that
/// `secret` appears as a Base32 string rather than as an `OtpSecret`, and that the kind carries
/// the PIN as an input rather than as a readable value (see [`FfiEntryKind`]).
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiOtpAuth {
    /// The kind, with its period, counter and PIN.
    pub kind: FfiEntryKind,
    /// The secret, Base32 encoded (upper case).
    pub secret_base32: String,
    /// Issuer (service name), such as `GitHub`.
    pub issuer: Option<String>,
    /// Account name, such as `alice@example.com`.
    pub account: String,
    /// Hash algorithm in use.
    pub algorithm: FfiAlgorithm,
    /// Number of digits in a code.
    pub digits: FfiDigits,
}

impl FfiEntryKind {
    /// The kind as the host sees it.
    ///
    /// A stored PIN is reported as [`FfiVaultEntry::pin_set`] rather than as a value: the core
    /// never hands one out, because the only thing that needs to read it is the code computation,
    /// which happens there.
    fn from_core(kind: &EntryKind) -> Self {
        match kind {
            EntryKind::Totp { period } => Self::Totp { period: *period },
            EntryKind::Hotp { counter } => Self::Hotp { counter: *counter },
            EntryKind::Motp { period, .. } => Self::Motp {
                period: *period,
                pin: None,
            },
            EntryKind::Yandex { period, .. } => Self::Yandex {
                period: *period,
                pin: None,
            },
            EntryKind::Steam => Self::Steam,
        }
    }

    /// The kind as the core sees it.
    ///
    /// `existing` is the kind the entry has now, when there is one. Its PIN is **moved** into the
    /// result when the host supplied none, so that editing a note neither drops the PIN silently
    /// nor forces the user to retype a value the host was never shown.
    fn into_core(self, existing: Option<EntryKind>) -> Result<EntryKind, FfiError> {
        Ok(match self {
            Self::Totp { period } => EntryKind::Totp { period },
            Self::Hotp { counter } => EntryKind::Hotp { counter },
            Self::Steam => EntryKind::Steam,
            Self::Motp { period, pin } => EntryKind::Motp {
                period,
                pin: motp_pin(pin, existing)?,
            },
            Self::Yandex { period, pin } => EntryKind::Yandex {
                period,
                pin: yandex_pin(pin, existing)?,
            },
        })
    }
}

/// The mOTP PIN to store: what the host supplied, or the one the entry already has.
fn motp_pin(
    supplied: Option<String>,
    existing: Option<EntryKind>,
) -> Result<Option<MotpPin>, FfiError> {
    match supplied {
        Some(pin) => {
            check_len("pin", &pin, MAX_VAULT_FIELD_CHARS)?;
            if pin.is_empty() {
                return Err(FfiError::InputEmpty {
                    kind: "pin".to_owned(),
                });
            }
            Ok(Some(MotpPin::new(pin)))
        }
        None => Ok(match existing {
            Some(EntryKind::Motp { pin, .. }) => pin,
            _ => None,
        }),
    }
}

/// The Yandex PIN to store: what the host supplied, or the one the entry already has.
fn yandex_pin(
    supplied: Option<String>,
    existing: Option<EntryKind>,
) -> Result<Option<YandexPin>, FfiError> {
    match supplied {
        Some(pin) => {
            check_len("pin", &pin, MAX_VAULT_FIELD_CHARS)?;
            if pin.is_empty() {
                return Err(FfiError::InputEmpty {
                    kind: "pin".to_owned(),
                });
            }
            Ok(Some(YandexPin::new(pin)))
        }
        None => Ok(match existing {
            Some(EntryKind::Yandex { pin, .. }) => pin,
            _ => None,
        }),
    }
}

impl core::fmt::Debug for FfiOtpAuth {
    /// Prints everything except the secret: it is the one field that must not reach a log, a
    /// panic message or a crash dump, and the import preview makes this type travel through
    /// diagnostics for the first time.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FfiOtpAuth")
            .field("kind", &self.kind)
            .field("secret_base32", &"<redacted>")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .finish_non_exhaustive()
    }
}

/// Checks a string length limit and returns [`FfiError::InputTooLong`] when it is
/// exceeded.
///
/// The limit counts **characters**, not bytes: strings arriving from the host
/// side may contain multi-byte characters, and counting bytes would make such
/// input hit the limit sooner than the reported character count suggests.
fn check_len(kind: &str, value: &str, limit: usize) -> Result<(), FfiError> {
    let actual = value.chars().count();
    if actual > limit {
        return Err(FfiError::InputTooLong {
            kind: kind.to_owned(),
            limit: limit as u64,
            actual: actual as u64,
        });
    }
    Ok(())
}

/// Parses an `otpauth://` URI.
///
/// Parses and validates the Google Authenticator Key URI Format, including the
/// issuer/account prefix consistency check, rejection of repeated parameters and
/// percent decoding.
///
/// # Errors
///
/// Returns [`FfiError::InputTooLong`] when the input is too long; otherwise
/// returns a core error ([`FfiError::Core`]) whose meaning is documented on the
/// core `Error`.
#[uniffi::export]
pub fn parse_otpauth_uri(uri: String) -> Result<FfiOtpAuth, FfiError> {
    check_len("uri", &uri, MAX_URI_CHARS)?;
    let parsed = uri::parse(&uri)?;
    Ok(FfiOtpAuth {
        kind: FfiEntryKind::from_core(&parsed.kind),
        secret_base32: parsed.secret.to_base32(),
        issuer: parsed.issuer,
        account: parsed.account,
        algorithm: match parsed.algorithm {
            Algorithm::Sha1 => FfiAlgorithm::Sha1,
            Algorithm::Sha256 => FfiAlgorithm::Sha256,
            Algorithm::Sha512 => FfiAlgorithm::Sha512,
        },
        digits: parsed.digits.into(),
    })
}

/// Serializes an [`FfiOtpAuth`] back into an `otpauth://` URI.
///
/// # Errors
///
/// The core rejects an account name containing `:` — that character is
/// indistinguishable from the `issuer:account` separator, so encoding it would
/// change which part of a round-tripped URI belongs to the issuer and which to
/// the account. The rejection is intentional.
#[uniffi::export]
pub fn serialize_otpauth_uri(auth: FfiOtpAuth) -> Result<String, FfiError> {
    check_len("secret", &auth.secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&auth.secret_base32)?;
    let core_auth = uri::OtpAuth {
        kind: auth.kind.into_core(None)?,
        secret,
        issuer: auth.issuer,
        account: auth.account,
        algorithm: auth.algorithm.into(),
        digits: auth.digits.to_core()?,
    };
    Ok(uri::serialize(&core_auth)?)
}

/// Computes a TOTP code.
///
/// `unix_time` is Unix seconds and is **supplied by the host side**: the core
/// does not read a clock, so time always enters as a parameter, which is what
/// makes the RFC 6238 test vectors verifiable. The host side should pass the
/// system clock in seconds.
///
/// The return value is a fixed-width decimal string (leading zeros included)
/// whose length is given by `digits`.
#[uniffi::export]
pub fn totp_code(
    secret_base32: String,
    unix_time: u64,
    period: u64,
    algorithm: FfiAlgorithm,
    digits: FfiDigits,
) -> Result<String, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(otp::totp_code(
        &secret,
        unix_time,
        period,
        algorithm.into(),
        digits.to_core()?,
    )?)
}

/// Computes an HOTP code.
#[uniffi::export]
pub fn hotp_code(
    secret_base32: String,
    counter: u64,
    algorithm: FfiAlgorithm,
    digits: FfiDigits,
) -> Result<String, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(otp::hotp_code(
        &secret,
        counter,
        algorithm.into(),
        digits.to_core()?,
    ))
}

/// Computes a Steam Guard code (5 characters, custom alphabet).
///
/// `period` is normally 30, the time step Steam uses.
#[uniffi::export]
pub fn steam_guard_code(
    secret_base32: String,
    unix_time: u64,
    period: u64,
    algorithm: FfiAlgorithm,
) -> Result<String, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(otp::steam_guard_code(
        &secret,
        unix_time,
        period,
        algorithm.into(),
    )?)
}

/// Verifies a user-supplied code, allowing for clock drift.
///
/// `expected_counter` is the counter for the current time (`unix_time / period`).
/// `window` is the number of steps of drift allowed (RFC 6238 suggests 1, that
/// is ±1 step).
///
/// The return value is the offset that matched: `0` for the current step, `-1`
/// for one step behind, `1` for one step ahead, and so on. The offset is
/// **returned instead of a boolean** so that the host side can calibrate that
/// entry's clock deviation rather than only learn right or wrong.
///
/// The comparison is constant time and does not return early on a matching
/// prefix. `None` means verification failed, including a malformed input code.
#[uniffi::export]
pub fn verify_code_with_drift(
    secret_base32: String,
    expected_counter: u64,
    window: u64,
    algorithm: FfiAlgorithm,
    digits: FfiDigits,
    provided_code: String,
) -> Result<Option<i64>, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(otp::verify_with_drift(
        &secret,
        expected_counter,
        window,
        algorithm.into(),
        digits.to_core()?,
        &provided_code,
    ))
}

/// Compares two code strings for equality in constant time.
///
/// For host-side code that has already computed the expected code itself. Use
/// [`verify_code_with_drift`] when clock drift must be tolerated.
#[uniffi::export]
#[must_use]
pub fn codes_match(expected: String, provided: String) -> bool {
    otp::verify_code(&expected, &provided)
}

/// Recommended minimum secret length in bytes for the given algorithm.
///
/// Intended for a **warning** on import rather than a rejection: the core does
/// not enforce a minimum length, since short secrets exist in practice.
#[uniffi::export]
#[must_use]
pub fn recommended_min_secret_len(algorithm: FfiAlgorithm) -> u64 {
    otp::recommended_min_secret_len(algorithm.into()) as u64
}

/// Reports whether the secret is shorter than the recommended length.
///
/// The host side cannot compare lengths itself: it only has the Base32 string,
/// and the Base32 length is not linearly related to the byte length (5 bits per
/// character versus 8 bits per byte).
#[uniffi::export]
pub fn is_secret_shorter_than_recommended(
    secret_base32: String,
    algorithm: FfiAlgorithm,
) -> Result<bool, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(secret.is_shorter_than_recommended(algorithm.into()))
}

/// The **byte** length of the secret (not the Base32 string length).
///
/// Intended for host-side messages such as "20 bytes / 20 recommended".
#[uniffi::export]
pub fn secret_byte_len(secret_base32: String) -> Result<u64, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(secret.len() as u64)
}

/// Generates a random 256-bit secret and returns its Base32 representation.
///
/// Intended for generating a secret when a new entry is created. Randomness
/// comes from the OS CSPRNG (`getrandom`), not from a user-space PRNG.
///
/// 256 bits is the output length of SHA-256 and is above the recommended
/// minimum of every supported algorithm: the largest of the recommended minima
/// is 64 bytes (512 bits), so 32 bytes is equal in length to SHA-256's output,
/// shorter than SHA-512's block but still above its recommended minimum.
#[uniffi::export]
pub fn generate_secret_base32() -> Result<String, FfiError> {
    let mut bytes = [0_u8; 32];
    qualia2fa_core::getrandom::fill(&mut bytes).map_err(|_| FfiError::Core {
        detail: Error::RandomnessUnavailable.into(),
    })?;
    let secret = OtpSecret::from_bytes(bytes.to_vec())?;
    Ok(secret.to_base32())
}

/// The core library version, for compatibility checks and diagnostics.
///
/// This is the version of `qualia2fa-core`, not of this FFI crate: the semantic
/// version the host side needs to align with is the core's.
#[uniffi::export]
#[must_use]
pub fn core_version() -> String {
    qualia2fa_core::VERSION.to_owned()
}

// ═══════════════════════════════════════════════════════════════════════════
// The code channel: turning text into a QR code and back
// ═══════════════════════════════════════════════════════════════════════════

/// A rendered QR code, as pixels the host can draw.
///
/// The pixels are **grayscale**, one byte per pixel, `0` for black and `255` for white.
#[derive(Clone, uniffi::Record)]
pub struct FfiQrImage {
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// Grayscale pixels, row major, `width * height` bytes.
    pub pixels: Vec<u8>,
}

impl core::fmt::Debug for FfiQrImage {
    /// Prints the dimensions only: the pixels are the code, and during pairing the code
    /// carries session material that must not reach a log or a panic message.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FfiQrImage")
            .field("width", &self.width)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

/// The error correction level of a code, named by what it survives.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FfiEcLevel {
    /// About 7% of the code may be damaged.
    Low,
    /// About 15%.
    Medium,
    /// About 25%.
    Quartile,
    /// About 30%.
    High,
}

impl From<FfiEcLevel> for qualia_transport::qr::EcLevel {
    fn from(value: FfiEcLevel) -> Self {
        match value {
            FfiEcLevel::Low => Self::Low,
            FfiEcLevel::Medium => Self::Medium,
            FfiEcLevel::Quartile => Self::Quartile,
            FfiEcLevel::High => Self::High,
        }
    }
}

/// Encodes `text` into a single QR code and renders it as grayscale pixels.
///
/// `scale` is how many pixels one module becomes, `quiet_zone` how many modules of
/// margin surround the code. Text that does not fit in `max_version` is an error: the
/// code is never truncated, and the error correction level is not silently lowered.
///
/// # Errors
///
/// Returns [`FfiError::Qr`] with kind `payload_too_large` when the text does not fit, and
/// `bad_render_geometry` when `scale` or `quiet_zone` is zero.
#[uniffi::export]
pub fn qr_encode(
    text: String,
    ec_level: FfiEcLevel,
    max_version: u8,
    scale: u16,
    quiet_zone: u16,
) -> Result<FfiQrImage, FfiError> {
    let profile =
        qualia_transport::qr::QrProfile::new(ec_level.into(), max_version).map_err(qr_error)?;
    let symbol = profile.encode_payload(text.as_bytes()).map_err(qr_error)?;
    let image = symbol.render(scale, quiet_zone).map_err(qr_error)?;
    Ok(FfiQrImage {
        width: image.width(),
        height: image.height(),
        pixels: image.pixels().to_vec(),
    })
}

/// Reads the text back out of a grayscale image.
///
/// The text is carried inside the transport's own envelope (`Q2FA1:<index>/<count>:<BASE32>`),
/// which is what a code drawn by [`qr_encode`] contains and what any scanner sees; this
/// function unwraps it so the caller gets back the text it encoded.
///
/// The input is **pixels, not an image file**: decoding the file format belongs to the
/// platform (`ImageIO` on the JVM, `BitmapFactory` on Android, `UIImage` on iOS), because
/// format decoders are where the historical vulnerabilities live. The host converts an
/// imported image to grayscale and hands the result here.
///
/// # Errors
///
/// Returns [`FfiError::Qr`] with kind `bad_image_geometry` when the buffer does not match
/// the dimensions, `not_our_qr_text` when the code is not this application's, `no_qr_found`
/// when there is no code in the image, and `qr_decoder_panicked` when the decoder hit the
/// assertion that degenerate images trigger. That last one is contained rather than fixed:
/// the panic is caught here, and the fix belongs upstream.
#[uniffi::export]
pub fn qr_decode(pixels: Vec<u8>, width: u32, height: u32) -> Result<String, FfiError> {
    let image =
        qualia_transport::image::GrayImage::from_luma8(width, height, pixels).map_err(qr_error)?;
    let payload = qualia_transport::qr::scan::decode_payload(&image).map_err(qr_error)?;
    String::from_utf8(payload).map_err(|_| FfiError::Qr {
        kind: "payload_not_utf8".to_owned(),
        detail: "the code carried bytes that are not UTF-8 text".to_owned(),
    })
}

/// Reads **any** text out of a grayscale image, whichever application drew the code.
///
/// This is the entry point for a screen that receives text and decides what it means for
/// itself: an `otpauth://` link to import, a code handed over by someone else's server. Use
/// [`qr_decode`] instead when the caller wants *this* application's payload, because that one
/// skips foreign codes rather than handing back the first one it finds.
///
/// The input is pixels, not an image file, for the reason given on [`qr_decode`].
///
/// # Errors
///
/// The same kinds as [`qr_decode`] except `not_our_qr_text`, which this entry point cannot
/// report: a code of another application is exactly what it is here to read.
#[uniffi::export]
pub fn qr_decode_text(pixels: Vec<u8>, width: u32, height: u32) -> Result<String, FfiError> {
    let image =
        qualia_transport::image::GrayImage::from_luma8(width, height, pixels).map_err(qr_error)?;
    qualia_transport::qr::scan::decode_text(&image).map_err(qr_error)
}

/// Takes the envelope off a single-frame code, answering with what was put in.
///
/// The counterpart of [`qr_encode`]: a screen that reads a code gets the envelope, which says
/// how many codes the payload was split into, and a screen that shows one code at a time wants
/// back the text it drew. A code of a set (`2/5`) is not this function's business and is
/// reported as incomplete rather than unwrapped.
///
/// # Errors
///
/// Returns [`FfiError::Qr`] with kind `not_our_qr_text` for a text that is not this
/// application's envelope, `incomplete_frames` for one that is part of a set, and
/// `payload_not_utf8` for one whose contents are not text.
#[uniffi::export]
pub fn qr_unwrap_text(text: String) -> Result<String, FfiError> {
    let mut reassembler = qualia_transport::frame::Reassembler::from_first_frame();
    let payload = reassembler
        .push(text.trim())
        .map_err(qr_error)?
        .ok_or_else(|| FfiError::Qr {
            kind: "incomplete_frames".to_owned(),
            detail: "the code is one of several, so it carries only part of the payload".to_owned(),
        })?;
    String::from_utf8(payload).map_err(|_| FfiError::Qr {
        kind: "payload_not_utf8".to_owned(),
        detail: "the code carried bytes that are not UTF-8 text".to_owned(),
    })
}
/// What one code of a multi-frame payload holds, in bytes.
///
/// A payload larger than this has to be split, and this is the number to give
/// [`FfiFrameCollector::new`]: both sides have to agree on it, and it depends only on the
/// profile the codes are drawn with.
#[uniffi::export]
pub fn qr_frame_capacity(ec_level: FfiEcLevel, max_version: u8) -> Result<u32, FfiError> {
    let profile =
        qualia_transport::qr::QrProfile::new(ec_level.into(), max_version).map_err(qr_error)?;
    Ok(profile.frame_payload_capacity() as u32)
}

/// One image of a payload that needs more than one code.
#[derive(uniffi::Record)]
pub struct FfiQrFrame {
    /// The code's number in the sequence, counting from one.
    pub index: u32,
    /// How many codes the payload was split into.
    pub count: u32,
    /// The image to draw for this code.
    pub image: FfiQrImage,
}

/// Draws a payload as a sequence of codes, for payloads that one code cannot carry.
///
/// A payload that fits in a single code comes back as one frame, so the caller does not have to
/// decide which way to draw it: `count` says what the sequence is, and a sequence of one is the
/// same code [`qr_encode`] would draw.
///
/// # Errors
///
/// Returns [`FfiError::Qr`] with kind `payload_too_large` when the payload does not fit in
/// `max_frames` codes, and `bad_render_geometry` when `scale` or `quiet_zone` is zero.
#[uniffi::export]
pub fn qr_encode_frames(
    text: String,
    ec_level: FfiEcLevel,
    max_version: u8,
    max_frames: u32,
    scale: u16,
    quiet_zone: u16,
) -> Result<Vec<FfiQrFrame>, FfiError> {
    let profile =
        qualia_transport::qr::QrProfile::new(ec_level.into(), max_version).map_err(qr_error)?;
    let symbols = profile
        .encode_payload_frames(text.as_bytes(), max_frames)
        .map_err(qr_error)?;
    let count = symbols.len() as u32;
    symbols
        .into_iter()
        .enumerate()
        .map(|(position, symbol)| {
            let image = symbol.render(scale, quiet_zone).map_err(qr_error)?;
            Ok(FfiQrFrame {
                index: position as u32 + 1,
                count,
                image: FfiQrImage {
                    width: image.width(),
                    height: image.height(),
                    pixels: image.pixels().to_vec(),
                },
            })
        })
        .collect()
}

/// What one read code was, and what it did to the set it belongs to.
#[derive(uniffi::Record)]
pub struct FfiFrameStep {
    /// The code's number in the sequence, counting from one.
    pub index: u32,
    /// How many codes the sequence has.
    pub count: u32,
    /// The payload, present only in the call that completes the set.
    pub payload: Option<Vec<u8>>,
}
/// Collects the codes of a multi-frame payload, in any order and with repeats.
///
/// The caller reads one code at a time and hands each text to [`FfiFrameCollector::push`]; the
/// call that completes the set answers with the payload. Codes may arrive twice, out of order,
/// or both, which is what collecting them by camera looks like: the collector keeps what it has
/// and reports what is missing, so a screen can show the user how far along it is.
#[derive(uniffi::Object)]
pub struct FfiFrameCollector {
    inner: Mutex<qualia_transport::frame::Reassembler>,
}

#[uniffi::export]
impl FfiFrameCollector {
    /// A collector for codes drawn with a frame capacity of `capacity` bytes, which
    /// [`qr_frame_capacity`] reports for the profile they were drawn with.
    #[uniffi::constructor]
    pub fn new(capacity: u32) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(qualia_transport::frame::Reassembler::new(capacity as usize)),
        })
    }

    /// Takes one read code, answering with what it was and whether it completed the set.
    ///
    /// # Errors
    ///
    /// Returns [`FfiError::Qr`] with kind `not_our_qr_text` for a code of another application,
    /// and `malformed_frame_header` for one of this application's that is not a frame.
    pub fn push(&self, text: String) -> Result<FfiFrameStep, FfiError> {
        let frame = qualia_transport::frame::decode_frame(text.trim()).map_err(qr_error)?;
        let mut inner = self.lock();
        let payload = inner.push(text.trim()).map_err(qr_error)?;
        Ok(FfiFrameStep {
            index: frame.index,
            count: frame.total,
            payload,
        })
    }

    /// How many codes have been accepted so far.
    pub fn received(&self) -> u32 {
        self.lock().received() as u32
    }

    /// How many codes the set has, once one of them has said so.
    pub fn expected(&self) -> Option<u32> {
        self.lock().expected_frames()
    }

    /// The numbers of the codes still missing, once the count is known.
    pub fn missing(&self) -> Vec<u32> {
        self.lock().missing()
    }
}

impl FfiFrameCollector {
    /// Takes the lock, ignoring poisoning (see [`FfiVault::lock`]).
    fn lock(&self) -> std::sync::MutexGuard<'_, qualia_transport::frame::Reassembler> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Reduces a transport error to a kind and a message, without the payload.
///
/// The transport error is `#[non_exhaustive]`, so the wildcard arm is required by the
/// compiler rather than optional; a new variant therefore lands in `qr_error` until it is
/// mapped, which is what the host sees as an unnamed failure. Its own test pins the kinds
/// that matter.
fn qr_error(source: qualia_transport::Error) -> FfiError {
    use qualia_transport::Error as QrError;

    let kind = match &source {
        QrError::PayloadTooLarge { .. } => "payload_too_large",
        QrError::TooManyFrames { .. } => "too_many_frames",
        QrError::NotOurQrText => "not_our_qr_text",
        QrError::MalformedFrameHeader => "malformed_frame_header",
        QrError::MultiFrameUnsupported { .. } => "multi_frame_unsupported",
        QrError::UnknownEcLevel { .. } => "unknown_ec_level",
        QrError::VersionOutOfRange { .. } => "version_out_of_range",
        QrError::BadRenderGeometry { .. } => "bad_render_geometry",
        QrError::BadImageGeometry { .. } => "bad_image_geometry",
        QrError::NoQrFound => "no_qr_found",
        QrError::QrDecoderPanicked => "qr_decoder_panicked",
        QrError::QrNotText => "qr_not_text",
        _ => "qr_error",
    };

    FfiError::Qr {
        kind: kind.to_owned(),
        detail: source.to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Device identity, registration and login
// ═══════════════════════════════════════════════════════════════════════════
//
// The master key stays inside Rust wherever possible. The core `flow` module
// takes its platform dependencies as two trait parameters, so orchestration
// completes without the master key leaving Rust. This section has the same
// shape:
//
// - [`FfiVault`] **holds** the master key on the Rust side, and both entry
//   operations and serialization happen inside Rust. The host side only
//   receives vault file bytes and entry fields, never the master key: on the
//   open / add entry / serialize path the master key does not cross the
//   boundary at all.
// - The master key crosses the boundary in exactly two places, both
//   unavoidable: registration hands it to the platform key store
//   ([`FfiSecureStore`]), and login reads it back out of the platform key
//   store. Its permanent home is the host side's hardware key store, which only
//   the host side can reach.
// - [`FfiSecureStore`] therefore exchanges **bytes** rather than some key
//   handle: the master key arrives and leaves the host side as a 32-byte array.
//
// The minimal host-side implementation is to forward these two traits straight
// to the platform key store API, **with no decisions of its own**: any decision
// belongs in the core layer.

/// Source of the device identity key pair: forwarded by the host side to the
/// platform hardware key store.
///
/// Corresponds to the core [`qualia2fa_core::flow::DeviceKeys`]. An
/// implementation should forward directly to the platform layer, **with no
/// decisions of its own**.
///
/// # Contract the implementation must satisfy
///
/// - **`get_or_create` must be idempotent for the same `label`.** A label names
///   one key pair for the lifetime of the device.
/// - **A key must be persisted immediately**, not buffered until the end of a
///   session: a signing call may arrive in a later process start.
/// - **`sign` receives the raw message, not a digest.** The host side must not
///   hash it first: the core verifies with the standard ECDSA hash mode, so
///   hashing twice makes verification report `DeviceSignatureInvalid` while the
///   key and the message are both correct.
#[uniffi::export(with_foreign)]
pub trait FfiDeviceKeys: Send + Sync {
    /// Returns the public key for `label`, creating it when it does not exist.
    /// SEC1 uncompressed encoding, 65 bytes.
    fn get_or_create(&self, label: String) -> Result<Vec<u8>, FfiError>;

    /// Signs the **raw message** with the private key for `label`. Returns the
    /// 64-byte raw `r‖s`, not DER.
    fn sign(&self, label: String, message: Vec<u8>) -> Result<Vec<u8>, FfiError>;
}

/// Where the master key is persisted: forwarded by the host side to the
/// platform hardware key store.
///
/// Corresponds to the core [`qualia2fa_core::flow::SecureStore`].
///
/// # `load` returning `None` and returning `Err` are two different things
///
/// - `Ok(None)`: this device was **never registered**. The user interface
///   should guide the user to register or log in.
/// - `Err(..)`: the device was registered, but the key cannot be read now
///   (hardware reset, key deleted, different user account). The user interface
///   must **warn that data may be lost** and must never guide the user to
///   register again, since that would overwrite the old data with a new master
///   key and make the existing entries permanently unrecoverable.
///
/// Collapsing these two cases into one `None` is the easiest mistake at this
/// interface, and the user interface above cannot tell them apart.
#[uniffi::export(with_foreign)]
pub trait FfiSecureStore: Send + Sync {
    /// Reads the master key, 32 bytes. Returns `None` when the device was never
    /// registered.
    fn load_master_key(&self) -> Result<Option<Vec<u8>>, FfiError>;

    /// Writes the master key (32 bytes), overwriting any existing value.
    fn store_master_key(&self, key: Vec<u8>) -> Result<(), FfiError>;

    /// Deletes the master key. Calling it on a device that was never registered
    /// must not report an error.
    fn delete_master_key(&self) -> Result<(), FfiError>;

    /// Whether this store is hardware backed (TPM / Secure Enclave / Android
    /// Keystore).
    ///
    /// **Must be reported truthfully.** With no hardware available it returns
    /// `false` and the user interface asks for consent before continuing;
    /// claiming otherwise would tell the user that a software file is hardware
    /// protected.
    fn is_hardware_backed(&self) -> bool;
}

/// Forwarding implementation of the core `DeviceKeys`: bridges trait calls to
/// host-side callbacks.
struct ForeignDeviceKeys(Arc<dyn FfiDeviceKeys>);

impl qualia2fa_core::flow::DeviceKeys for ForeignDeviceKeys {
    fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey, Error> {
        let bytes = self
            .0
            .get_or_create(label.to_owned())
            .map_err(ffi_to_core_error)?;
        Ok(DevicePublicKey::from_sec1_bytes(&bytes)?)
    }

    fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature, Error> {
        let bytes = self
            .0
            .sign(label.to_owned(), message.to_vec())
            .map_err(ffi_to_core_error)?;
        Ok(DeviceSignature::from_bytes(&bytes)?)
    }
}

/// Forwarding implementation of the core `SecureStore`: bridges trait calls to
/// host-side callbacks.
struct ForeignSecureStore(Arc<dyn FfiSecureStore>);

impl qualia2fa_core::flow::SecureStore for ForeignSecureStore {
    fn load_master_key(&self) -> Result<Option<MasterKey>, Error> {
        let bytes = self.0.load_master_key().map_err(ffi_to_core_error)?;
        bytes
            .map(|bytes| flow::master_key_from_bytes(bytes.into()))
            .transpose()
    }

    fn store_master_key(&mut self, key: &MasterKey) -> Result<(), Error> {
        self.0
            .store_master_key(flow::master_key_to_bytes(key).expose_secret().to_vec())
            .map_err(ffi_to_core_error)
    }

    fn delete_master_key(&mut self) -> Result<(), Error> {
        self.0.delete_master_key().map_err(ffi_to_core_error)
    }

    fn is_hardware_backed(&self) -> bool {
        self.0.is_hardware_backed()
    }
}

/// Converts an [`FfiError`] returned by a host-side callback back into a core
/// error.
///
/// The errors appearing in these callbacks **are core errors already**: the host
/// side passes them back (for example, a platform key store reporting unavailable
/// hardware, which corresponds to the core [`Error::DeviceKeyMissing`]), and the
/// error handling in `flow` branches on that reason. [`FfiError::Core`] is mapped
/// back to a core variant through `kind`; what cannot be mapped back — the
/// boundary's own [`FfiError::InputTooLong`] and any kind added later — degrades to
/// [`Error::DeviceKeyMissing`].
fn ffi_to_core_error(source: FfiError) -> Error {
    match source {
        FfiError::Core { detail } => kind_to_core_error(&detail.kind),
        // None of the boundary's own errors can arrive from a host callback: the code
        // channel is called from the host, not into it, and an identifier or a conflict
        // named by the host is checked where it is used. They degrade the same way as any
        // other error that has no core equivalent.
        FfiError::InputTooLong { .. }
        | FfiError::InputEmpty { .. }
        | FfiError::WrongCodeKind { .. }
        | FfiError::Qr { .. }
        | FfiError::Lan { .. }
        | FfiError::InvalidDeviceId { .. }
        | FfiError::AuthBound { .. }
        | FfiError::UnknownConflict { .. } => Error::DeviceKeyMissing,
    }
}

/// Maps a stable error kind back to a core error variant.
///
/// **Only the device-identity-related ones**: this function is used on the
/// callback-crossing paths, where the set of possible core errors is limited
/// (missing key, mismatched identity, failed store write). Everything else
/// degrades to [`Error::DeviceKeyMissing`] rather than being forced into a
/// variant whose meaning does not fit: a wrong classification is worse than a
/// coarse one.
fn kind_to_core_error(kind: &str) -> Error {
    match kind {
        "device_key_missing" => Error::DeviceKeyMissing,
        "device_signature_invalid" => Error::Device(qualia_dik::Error::DeviceSignatureInvalid {
            reason: "signing failed on the client side",
        }),
        "secure_store_write_failed" => Error::SecureStoreWriteFailed {
            reason: "the client key store refused the write",
        },
        _ => Error::DeviceKeyMissing,
    }
}

/// The device identity key store of the current platform, exported to the host
/// side.
///
/// # What this object is for
///
/// [`FfiDeviceKeys`] is a **foreign** trait: the host side implements it. The
/// implementation that really exists — create a P-256 key inside the platform
/// key store, read its public key, sign with it — lives in `qualia-dik`, so a
/// host-side implementation of that trait would only forward. This object is
/// that forwarding, written once in Rust: the host side calls the methods below
/// and writes no key-store code of its own.
///
/// # Contract: the byte formats of [`FfiDeviceKeys`]
///
/// - [`FfiPlatformKeys::device_public_key`] returns the 65-byte SEC1
///   uncompressed point `0x04 || X(32) || Y(32)`, the encoding
///   [`FfiDeviceKeys::get_or_create`] has to return.
/// - [`FfiPlatformKeys::sign`] takes the **raw message** and returns the 64-byte
///   raw `r‖s`, the convention [`FfiDeviceKeys::sign`] has to follow.
///
/// # The backend is reported as it is
///
/// [`FfiPlatformKeys::backend`] and [`FfiPlatformKeys::is_hardware_backed`]
/// report the backend **actually in use**. Opening prefers the TPM and falls back
/// to the operating system software key store only when there is no TPM, and the
/// fallback stays visible: such a machine reports `"software"` and `false`.
/// Reporting a software key as hardware-protected would tell the user that a
/// private key which can be copied off the disk is held by hardware.
///
/// # No signer is kept between calls
///
/// `qualia-dik` hands out a signer as `Box<dyn DeviceSigner>`, and that trait is
/// neither `Send` nor `Sync`: a platform key handle is not thread safe, and the
/// library's Windows backend documents the intended pattern as one handle per
/// thread rather than one handle shared between threads. A UniFFI object must be
/// `Send + Sync`, so no handle is stored here. Every method opens the identity
/// under this object's label again, which is the pattern the platform backend
/// asks for; the label itself is created once, by [`FfiPlatformKeys::open`].
///
/// # This type does not implement `Debug`
///
/// Deriving it would delegate to the key store's own `Debug`, whose output is an
/// implementation detail rather than part of this interface, and the object sits
/// next to platform key material. Nothing in this crate needs it.
///
/// # Current state
///
/// Windows is the only platform with a backend implementation. On every other
/// platform [`FfiPlatformKeys::open`] fails with an error naming that platform;
/// there is **no** fallback to a software key.
#[derive(uniffi::Object)]
pub struct FfiPlatformKeys {
    /// Key store of the current platform, opened on the best available backend.
    store: PlatformKeyStore,
    /// Label of the device identity this object manages.
    label: String,
}

#[uniffi::export]
impl FfiPlatformKeys {
    /// Opens the best available platform backend and the identity stored under
    /// `label`, creating that identity when it does not exist yet.
    ///
    /// "Best available" is the platform's choice, not this layer's: on Windows
    /// the TPM 2.0 provider is preferred and the software key store is used only
    /// when no TPM is available. Which one was chosen is reported by
    /// [`FfiPlatformKeys::backend`], so the host side can tell the user before
    /// relying on the identity.
    ///
    /// # One label is one identity for the lifetime of the device
    ///
    /// The label is the only handle the platform key store has, so opening the
    /// same label again returns the same identity and never creates a second key.
    ///
    /// # The signer handle returned by the key store is dropped
    ///
    /// Creating the identity is what this call is for; see [`FfiPlatformKeys`]
    /// for why the platform handle is not kept between calls.
    ///
    /// # Errors
    ///
    /// [`FfiError::InputTooLong`] when the label is longer than the boundary
    /// limit; otherwise a [`FfiError::Core`] error: this machine has no usable
    /// platform key store, this platform has no backend yet, the platform rejects
    /// the label, or the platform refuses the operation. The key store failures
    /// carry the kind `device_error`.
    #[uniffi::constructor]
    pub fn open(label: String) -> Result<Arc<Self>, FfiError> {
        check_len("label", &label, MAX_LABEL_CHARS)?;
        let store = open_platform_key_store()?;
        store.open_or_create(&label).map_err(platform_error)?;
        Ok(Arc::new(Self { store, label }))
    }

    /// The SEC1 uncompressed public key of the identity under this object's
    /// label: 65 bytes, `0x04 || X(32) || Y(32)`.
    ///
    /// The same key [`FfiDeviceKeys::get_or_create`] has to return for that
    /// label, because both name one platform identity. A public key is not a
    /// secret: it is propagated to peer devices and shown in QR codes.
    ///
    /// # Errors
    ///
    /// A [`FfiError::Core`] error when the identity cannot be opened: it was
    /// deleted, this is a different user account, or no key store is available.
    pub fn device_public_key(&self) -> Result<Vec<u8>, FfiError> {
        let signer = self.signer()?;
        Ok(signer.public_key().as_sec1_bytes().to_vec())
    }

    /// The fingerprint of this device's identity: 64 hexadecimal characters.
    ///
    /// It is the identifier a sync payload carries as its sender, the value the channel
    /// reports for this device (see [`FfiTransport::local_device`]), and the string a
    /// pairing screen shows next to a requester. All three are the **same value by
    /// construction**: the fingerprint is derived from the public key, so two devices that
    /// show the same string really do hold the same identity, with no registry to keep in
    /// step and nothing to forge.
    ///
    /// # Errors
    ///
    /// A [`FfiError::Core`] error when the identity cannot be opened: it was deleted, this
    /// is a different user account, or no key store is available.
    pub fn device_id(&self) -> Result<String, FfiError> {
        Ok(self.signer()?.public_key().device_id().to_hex())
    }

    /// Signs the **raw message** with the identity under this object's label and
    /// returns the 64-byte raw `r‖s`.
    ///
    /// # Do not hash the message first
    ///
    /// The platform hashes with SHA-256 internally and the core verifies with the
    /// standard ECDSA hash mode, so a digest passed in here would be hashed a
    /// second time and every verification would report `device_signature_invalid`
    /// while both the key and the message are correct.
    ///
    /// # The return value is not DER
    ///
    /// It is the fixed 64-byte `r‖s` layout the protocol uses. DER is variable
    /// length (68 to 72 bytes, depending on leading zero padding), which would
    /// reveal the high bytes of `r` and `s` and give one mathematical signature
    /// several valid encodings.
    ///
    /// # Errors
    ///
    /// A [`FfiError::Core`] error (`device_error`) when the platform refuses to
    /// sign — a cancelled authentication prompt, for example — or the identity
    /// cannot be opened.
    pub fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let signer = self.signer()?;
        let signature = signer.sign(&message).map_err(platform_error)?;
        Ok(signature.as_bytes().to_vec())
    }

    /// The backend that holds this identity, as a stable short name: `"tpm"`,
    /// `"secure-enclave"`, `"android-keystore"`, `"software"` or
    /// `"unavailable"`.
    ///
    /// The value comes from the key store rather than from a signer, so asking
    /// for it opens no key handle. It is reported **truthfully** and may be
    /// weaker than what the platform could provide: a Windows machine without a
    /// TPM reports `"software"`, which means the private key is an ordinary
    /// operating system key store entry. An identity that opened successfully
    /// reports `"tpm"` or `"software"` today, since Windows is the only platform
    /// with a backend.
    #[must_use]
    pub fn backend(&self) -> String {
        self.store.backend().as_str().to_owned()
    }

    /// Whether the private key of this identity cannot leave hardware.
    ///
    /// Consistent with [`FfiPlatformKeys::backend`] by construction: `true`
    /// exactly when that backend is a hardware one. With `"software"` the key can
    /// be taken by an attacker who has administrator rights or disk access, so
    /// the host side has to tell the user before a critical operation.
    #[must_use]
    pub fn is_hardware_backed(&self) -> bool {
        self.store.backend().is_hardware_backed()
    }
}

/// Helpers of [`FfiPlatformKeys`] that are **not** exported.
///
/// A separate `impl` block on purpose: `#[uniffi::export]` processes every method
/// of the block it is attached to, including private ones, and it cannot generate
/// cross-boundary code for a Rust-only type such as `Box<dyn DeviceSigner>`.
impl FfiPlatformKeys {
    /// Opens the identity stored under this object's label.
    ///
    /// Written in fully qualified form rather than as a method call: the Windows
    /// backend has an **inherent** `open(preferred: WindowsProvider)`
    /// constructor, and an inherent method of that name wins method resolution
    /// and then fails on the argument type. Fully qualified syntax names the
    /// trait method on every platform.
    fn signer(&self) -> Result<Box<dyn DeviceSigner>, FfiError> {
        DeviceKeyStore::open(&self.store, &self.label).map_err(platform_error)
    }
}

/// Opens the platform key store on the best backend this machine has.
///
/// # Why one `cfg` appears here
///
/// The constructors differ **on purpose**: opening a key store can fail where there is one
/// to open — Windows may have no TPM, a key store held by another process or a policy that
/// forbids it, and Android may be reached without the Java VM this library needs — and those
/// return a `Result`. The placeholder compiled on the remaining platforms cannot fail and
/// returns the value directly. `qualia-dik` documents that callers write the call once per
/// platform instead of hiding the difference, so this function is the only place in this
/// crate where a platform `cfg` appears; no method carries one.
///
/// On a platform whose backend is not implemented, the store returned here fails
/// every operation with an error naming that platform, and **nothing falls back
/// to a software key**.
fn open_platform_key_store() -> Result<PlatformKeyStore, FfiError> {
    #[cfg(any(target_os = "windows", target_os = "android"))]
    {
        PlatformKeyStore::open_best_available().map_err(platform_error)
    }
    #[cfg(not(any(target_os = "windows", target_os = "android")))]
    {
        Ok(PlatformKeyStore::open_best_available())
    }
}

/// Converts an error of the device identity library into an [`FfiError`].
///
/// The core wraps that error in its own `Error::Device` variant (`#[from]`), so
/// it reaches the host side with the stable `kind` that [`core_error_kind`]
/// already assigns to it: `device_public_key_invalid`, `device_signature_invalid`
/// and the master key storage failures keep the specific kinds that function
/// lists, and every other key store failure is `device_error`. The library's
/// messages are safe to pass on: each `reason` field is a fixed `&'static str`
/// supplied by the library, never key material.
fn platform_error(source: qualia_dik::Error) -> FfiError {
    Error::from(source).into()
}

// ── The master key: the two forms the platform key store offers ──────────
//
// The application's master key has two storage forms, and `qualia-dik` models them as two
// interfaces reached through two constructors. This section mirrors that shape across the
// boundary instead of inventing a mode argument: the host side chooses a form by opening one
// object or the other. A review of this section asks the same question the platform key
// store section asks: **has any judgement been copied in from the library?**

/// The application's master key held **directly** by the platform key store.
///
/// The store keeps the material itself (a CNG key on Windows, a Keystore entry on Android)
/// and the host side persists nothing of its own for it. Reading it back returns the same
/// 32 bytes.
///
/// # The two forms, and how the host side picks one
///
/// [`FfiWrappedMasterKeyStore`] is the other form. There is no flag and no mode argument
/// anywhere in this section: a caller that wants the wrapped form reaches for the other
/// object, so a platform that implements only one form cannot silently answer for both.
/// [`FfiDirectMasterKeyStore::backend`] reports what actually answered.
///
/// # The master key crosses this boundary as bytes, and as nothing else
///
/// [`FfiDirectMasterKeyStore::store`] takes 32 bytes, [`FfiDirectMasterKeyStore::load`]
/// returns 32 bytes. The material is never formatted, never logged and never part of an
/// error message; the host side should drop its copy as soon as it has handed the bytes over
/// or built an [`FfiVault`] from them.
///
/// # Current state
///
/// Windows and Android have a backend. On every other platform
/// [`FfiDirectMasterKeyStore::open`] still succeeds — the object is usable and reports
/// `"unavailable"` — and every operation fails with the kind `unsupported_platform`. Nothing
/// falls back to an in-process map.
#[derive(uniffi::Object)]
pub struct FfiDirectMasterKeyStore {
    /// The store of this form, held as the interface rather than as the platform's concrete
    /// type: UniFFI objects cannot be generic, and the tests drive a software backend
    /// through exactly the methods production calls.
    store: Box<dyn DirectMasterKeyStore + Send + Sync>,
}

#[uniffi::export]
impl FfiDirectMasterKeyStore {
    /// Opens the direct master key store of the current platform.
    ///
    /// # Errors
    ///
    /// A [`FfiError::Core`] error with the kind `hardware_unavailable` when no provider on
    /// this machine can hold master key material. A platform whose backend is not
    /// implemented yet still opens: the failures arrive from the operations below, with the
    /// kind `unsupported_platform`, so the host side can name the platform instead of
    /// reporting a machine that is out of order.
    #[uniffi::constructor]
    pub fn open() -> Result<Arc<Self>, FfiError> {
        let store = open_platform_direct_master_key_store()?;
        Ok(Self::with_store(Box::new(store)))
    }

    /// The platform key store that holds the material, as a stable short name: `"tpm"`,
    /// `"android-keystore"`, `"software"`, `"secure-enclave"` or `"unavailable"`.
    ///
    /// Reported **truthfully**, exactly as [`FfiPlatformKeys::backend`] does: asking for it
    /// opens no key handle, and a machine without a TPM says `"software"` rather than
    /// pretending. The host side can use it to tell the user before relying on the store.
    #[must_use]
    pub fn backend(&self) -> String {
        self.store.backend().as_str().to_owned()
    }

    /// Whether the material cannot leave hardware.
    ///
    /// Consistent with [`FfiDirectMasterKeyStore::backend`] by construction: `true` exactly
    /// when that backend is a hardware one.
    #[must_use]
    pub fn is_hardware_backed(&self) -> bool {
        self.store.backend().is_hardware_backed()
    }

    /// Stores the 32-byte `key` under `label`, replacing what was stored there.
    ///
    /// Replacing is deliberate: a recovery or a re-pairing legitimately replaces the master
    /// key, and refusing would leave the host side unable to follow its own vault files.
    ///
    /// # Errors
    ///
    /// [`FfiError::InputTooLong`] for a label over the boundary limit; the core's
    /// `master_key_wrong_length` when `key` is not 32 bytes; `key_not_exportable` when the
    /// platform takes the material but will not hand it back, which is the case that wants
    /// [`FfiWrappedMasterKeyStore`]; otherwise a key store failure, reported as
    /// `hardware_unavailable`, `unsupported_platform` or `device_error`.
    pub fn store(&self, label: String, key: Vec<u8>) -> Result<(), FfiError> {
        check_len("label", &label, MAX_LABEL_CHARS)?;
        let key = dik_master_key(key)?;
        DirectMasterKeyStore::store(self.store.as_ref(), &label, &key).map_err(platform_error)
    }

    /// Reads back the master key stored under `label`: the 32 bytes
    /// [`FfiDirectMasterKeyStore::store`] was given.
    ///
    /// **Never creates or replaces anything**: a label that holds nothing fails instead.
    ///
    /// # Errors
    ///
    /// [`FfiError::InputTooLong`] for an oversized label, and otherwise a key store failure:
    /// a label that holds nothing is `device_error` today, an unusable platform is
    /// `unsupported_platform`, and `invalid_master_key` reports a store that returned
    /// something which is not master key material.
    pub fn load(&self, label: String) -> Result<Vec<u8>, FfiError> {
        check_len("label", &label, MAX_LABEL_CHARS)?;
        let key =
            DirectMasterKeyStore::load(self.store.as_ref(), &label).map_err(platform_error)?;
        Ok(key.as_bytes().to_vec())
    }

    /// Deletes the master key stored under `label`.
    ///
    /// # Warning
    ///
    /// Every vault of that account becomes unreadable on this device unless the key exists
    /// elsewhere — a recovery key, another device. **The host side has to ask the user
    /// first.**
    ///
    /// # Errors
    ///
    /// [`FfiError::InputTooLong`] for an oversized label, and otherwise the same key store
    /// failures as [`FfiDirectMasterKeyStore::load`].
    pub fn delete(&self, label: String) -> Result<(), FfiError> {
        check_len("label", &label, MAX_LABEL_CHARS)?;
        DirectMasterKeyStore::delete(self.store.as_ref(), &label).map_err(platform_error)
    }
}

/// The application's master key held **wrapped** by a key-encryption key inside the platform
/// key store.
///
/// The store generates the key-encryption key (a non-exportable CNG key on Windows, an
/// Android Keystore key on Android), keeps it where nothing can read it out, and wraps the
/// master key with it. [`FfiWrappedMasterKeyStore::store`] hands back the **wrapped bytes**
/// for the host side to persist, and [`FfiWrappedMasterKeyStore::load`] takes them back and
/// returns the master key.
///
/// # Nothing here wraps, unwraps or hands out a key-encryption key
///
/// Wrapping is the internal design of this form, and the library keeps it that way: no
/// operation of this object encrypts, decrypts or returns the key-encryption key, and none
/// is added here. The host side stores a master key and receives bytes to keep; what those
/// bytes mean is the platform's business.
///
/// # The bytes belong to one store entry
///
/// Bytes produced by another store entry, or damaged in storage, **fail** rather than unwrap
/// into a key that merely differs. That is what makes them safe to persist next to the vault
/// file they belong to. The wrapped form is not secret the way the master key is: whoever
/// copies the bytes still needs the platform key, which is not in them.
///
/// # Current state
///
/// Same as [`FfiDirectMasterKeyStore`]: Windows and Android have a backend, and every other
/// platform reports `unsupported_platform` from every operation.
#[derive(uniffi::Object)]
pub struct FfiWrappedMasterKeyStore {
    /// The store of this form, held as the interface for the reason given on
    /// [`FfiDirectMasterKeyStore`].
    store: Box<dyn WrappedMasterKeyStore + Send + Sync>,
}

#[uniffi::export]
impl FfiWrappedMasterKeyStore {
    /// Opens the wrapped master key store of the current platform.
    ///
    /// # Errors
    ///
    /// A [`FfiError::Core`] error with the kind `hardware_unavailable` when this machine has
    /// no provider that can create a key-encryption key; see
    /// [`FfiDirectMasterKeyStore::open`] for why an unimplemented platform opens anyway.
    #[uniffi::constructor]
    pub fn open() -> Result<Arc<Self>, FfiError> {
        let store = open_platform_wrapped_master_key_store()?;
        Ok(Self::with_store(Box::new(store)))
    }

    /// The platform key store that holds the key-encryption key, as a stable short name:
    /// `"tpm"`, `"android-keystore"`, `"software"`, `"secure-enclave"` or `"unavailable"`.
    ///
    /// Reported truthfully, like [`FfiDirectMasterKeyStore::backend`]; this is the value the
    /// host side tells the user about before it relies on the wrapped form.
    #[must_use]
    pub fn backend(&self) -> String {
        self.store.backend().as_str().to_owned()
    }

    /// Whether the key-encryption key cannot leave hardware.
    ///
    /// Consistent with [`FfiWrappedMasterKeyStore::backend`] by construction: `true` exactly
    /// when that backend is a hardware one.
    #[must_use]
    pub fn is_hardware_backed(&self) -> bool {
        self.store.backend().is_hardware_backed()
    }

    /// Wraps the 32-byte `key` under `label` and returns the **bytes the host side has to
    /// persist**.
    ///
    /// The bytes are opaque: their length and contents belong to the platform, and only the
    /// same store entry can turn them back into the master key. Persist them next to the
    /// vault file they belong to; losing them means the master key has to be recovered
    /// another way, and deleting the label's entry makes them permanently unusable.
    ///
    /// Wrapping under a label that already exists reuses the key-encryption key that is
    /// already there, so bytes persisted earlier keep unwrapping.
    ///
    /// # Errors
    ///
    /// [`FfiError::InputTooLong`] for an oversized label; the core's
    /// `master_key_wrong_length` when `key` is not 32 bytes; otherwise a key store failure,
    /// reported as `unsupported_platform` or `device_error` — a platform that cannot create
    /// a key-encryption key included.
    pub fn store(&self, label: String, key: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        check_len("label", &label, MAX_LABEL_CHARS)?;
        let key = dik_master_key(key)?;
        let wrapped = WrappedMasterKeyStore::store(self.store.as_ref(), &label, &key)
            .map_err(platform_error)?;
        Ok(wrapped.into_bytes())
    }

    /// Unwraps `wrapped` — the bytes [`FfiWrappedMasterKeyStore::store`] handed back for
    /// `label` — and returns the master key.
    ///
    /// # Errors
    ///
    /// `invalid_wrapped_key` when the bytes do not unwrap: a damaged blob, or one produced
    /// by another store entry or another device. **The method never returns bytes it could
    /// not authenticate**, so a failure here means "these bytes are unusable", not "here is
    /// a different key". A label that holds no key-encryption key at all is `device_error`
    /// today.
    pub fn load(&self, label: String, wrapped: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        check_len("label", &label, MAX_LABEL_CHARS)?;
        let wrapped = WrappedMasterKey::from_bytes(wrapped);
        let key = WrappedMasterKeyStore::load(self.store.as_ref(), &label, &wrapped)
            .map_err(platform_error)?;
        Ok(key.as_bytes().to_vec())
    }

    /// Deletes the key-encryption key stored under `label`.
    ///
    /// # Warning
    ///
    /// Every blob wrapped with that key becomes permanently unusable, which is how a device
    /// forgets a master key. **The host side has to ask the user first**, and it has to be
    /// prepared for the persisted bytes to be worthless afterwards.
    ///
    /// # Errors
    ///
    /// [`FfiError::InputTooLong`] for an oversized label, and otherwise the same key store
    /// failures as [`FfiWrappedMasterKeyStore::load`].
    pub fn delete(&self, label: String) -> Result<(), FfiError> {
        check_len("label", &label, MAX_LABEL_CHARS)?;
        WrappedMasterKeyStore::delete(self.store.as_ref(), &label).map_err(platform_error)
    }
}

/// Helpers of the master key store objects that are **not** exported.
///
/// Separate `impl` blocks on purpose: `#[uniffi::export]` lowers every method of the block
/// it is attached to, and it cannot generate cross-boundary code for a
/// `Box<dyn DirectMasterKeyStore>` or a `Box<dyn WrappedMasterKeyStore>`.
impl FfiDirectMasterKeyStore {
    /// Wraps a store in the exported object.
    fn with_store(store: Box<dyn DirectMasterKeyStore + Send + Sync>) -> Arc<Self> {
        Arc::new(Self { store })
    }
}

impl FfiWrappedMasterKeyStore {
    /// Wraps a store in the exported object.
    fn with_store(store: Box<dyn WrappedMasterKeyStore + Send + Sync>) -> Arc<Self> {
        Arc::new(Self { store })
    }
}

/// What the platform's auth-bound key store can do, asked before offering the path.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiAuthAvailability {
    /// The platform can create and use an authentication-bound key.
    Available {
        /// Stable backend name (`windows-webauthn`, `android-keystore`, ...).
        backend: String,
        /// Whether the platform reported hardware protection. Never guessed.
        hardware_backed: bool,
    },
    /// The mechanism exists, but this machine or user cannot use it right now.
    Unavailable {
        /// Why the platform refused; fixed text from the backend.
        reason: String,
    },
    /// This build has no backend for the platform.
    Unsupported {
        /// Why no backend exists; fixed text from the fallback.
        reason: String,
    },
}

/// The platform auth-bound key store used by `master.key.bio`.
///
/// The master key crosses this boundary as a `Vec<u8>` only where the host has no other
/// option: [`FfiVault::wrap_master_for_auth_bound`] keeps the key inside the vault, and the
/// login path needs the unwrapped key to open the vault at all. The bytes are erased on the
/// Rust side after use; the host-side copy is the caller's responsibility.
#[derive(uniffi::Object)]
pub struct FfiAuthBoundKeyStore {
    /// The platform store, held as the interface so the host sees one object on every
    /// platform, including the unsupported fallback.
    store: Box<dyn bioauth::AuthBoundKeyStore>,
}

#[uniffi::export]
impl FfiAuthBoundKeyStore {
    /// Builds a store over a host-supplied platform sealer.
    ///
    /// `backend` names the mechanism the host uses: `android-keystore` or
    /// `apple-secure-enclave`. It is written into every blob, so it must describe what the
    /// host actually did; a blob records it and a mismatch is refused on the way in.
    ///
    /// # Errors
    ///
    /// `bioauth_unknown_backend` when the name is not one this build knows.
    #[uniffi::constructor]
    pub fn with_host(
        sealer: Arc<dyn FfiPlatformSealer>,
        backend: String,
    ) -> Result<Arc<Self>, FfiError> {
        let backend = backend_from_name(&backend)?;
        Ok(Arc::new(Self {
            store: Box::new(bioauth::DelegatingKeyStore::new(Arc::new(HostSealer {
                host: sealer,
                backend,
            }))),
        }))
    }

    /// Opens the auth-bound key store of the current platform.
    ///
    /// Opening never fails: a platform without a backend returns an object whose
    /// [`FfiAuthBoundKeyStore::availability`] is `unsupported`, which lets the host show
    /// the truth instead of a "could not open" error.
    #[uniffi::constructor]
    pub fn open() -> Arc<Self> {
        Arc::new(Self {
            store: bioauth::platform::open_best_available(),
        })
    }

    /// Reports what this store can do, without prompting.
    #[must_use]
    pub fn availability(&self) -> FfiAuthAvailability {
        match self.store.availability() {
            bioauth::Availability::Available {
                backend,
                hardware_backed,
            } => FfiAuthAvailability::Available {
                backend: backend.name().to_owned(),
                hardware_backed,
            },
            bioauth::Availability::Unavailable { reason } => FfiAuthAvailability::Unavailable {
                reason: reason.to_owned(),
            },
            bioauth::Availability::Unsupported { reason } => FfiAuthAvailability::Unsupported {
                reason: reason.to_owned(),
            },
        }
    }

    /// Creates the platform credential or key, prompting if the platform requires it.
    ///
    /// # Errors
    ///
    /// [`FfiError::AuthBound`] with the backend's kind; `bioauth_authentication_failed`
    /// when the user cancelled, `bioauth_unavailable` when the platform is not usable.
    pub fn create(&self) -> Result<(), FfiError> {
        self.store.create().map_err(auth_bound_error)
    }

    /// Wraps `master_key` and returns the complete blob for `master.key.bio`.
    ///
    /// # Errors
    ///
    /// [`FfiError::AuthBound`] for a cancelled gesture or an unavailable platform;
    /// `bioauth_master_key_wrong_length` when the key is not 32 bytes.
    pub fn wrap(&self, master_key: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let master = bioauth::MasterKey::from_bytes(&master_key).map_err(auth_bound_error)?;
        self.store.wrap(&master).map_err(auth_bound_error)
    }

    /// Authenticates the user and returns the master key from `blob`.
    ///
    /// # Errors
    ///
    /// [`FfiError::AuthBound`] with `bioauth_authentication_failed` for a cancelled
    /// gesture, `bioauth_wrong_backend` for a blob written by another backend, and
    /// `bioauth_wrapped_payload_invalid` for a damaged blob.
    pub fn unwrap(&self, blob: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let master = self.store.unwrap(&blob).map_err(auth_bound_error)?;
        Ok(master.expose_secret().to_vec())
    }

    /// Deletes the platform key or credential this store remembers.
    pub fn delete(&self) -> Result<(), FfiError> {
        self.store.delete().map_err(auth_bound_error)
    }

    /// Deletes the platform credential named by `blob`.
    ///
    /// Used when the host turns the second path off after a restart and no longer has the
    /// credential id in memory. The blob is checked against this backend before anything is
    /// deleted, so a copied Windows blob does not delete an unrelated Android key.
    pub fn delete_blob(&self, blob: Vec<u8>) -> Result<(), FfiError> {
        self.store.delete_blob(&blob).map_err(auth_bound_error)
    }
}

impl FfiAuthBoundKeyStore {
    /// Wraps a store for tests, which need a backend whose answers are fixed.
    #[cfg(test)]
    fn with_store(store: Box<dyn bioauth::AuthBoundKeyStore>) -> Arc<Self> {
        Arc::new(Self { store })
    }
}

/// The platform half of `master.key.bio`, implemented by the host application.
///
/// Android cannot be served from Rust: an auth-bound key lives in the Android Keystore and
/// using it needs a `BiometricPrompt` attached to an Activity's UI thread, which a library
/// cannot host. The host therefore supplies the sealing calls, and this crate keeps the
/// envelope, the backend identifier and the length checks.
///
/// Implementations may prompt and may block until the user has authenticated.
#[uniffi::export(with_foreign)]
pub trait FfiPlatformSealer: Send + Sync {
    /// The backend these bytes belong to: `android-keystore` or `apple-secure-enclave`.
    fn backend(&self) -> String;

    /// Reports whether sealing is possible right now, without prompting.
    fn availability(&self) -> FfiAuthAvailability;

    /// Seals 32 bytes of key material, prompting if the platform requires it.
    fn seal(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, FfiError>;

    /// Authenticates the user and returns the plaintext.
    ///
    /// A cancelled gesture is an error, never a buffer of zeros.
    fn unseal(&self, envelope: Vec<u8>) -> Result<Vec<u8>, FfiError>;

    /// Deletes the platform key. Idempotent.
    fn delete(&self) -> Result<(), FfiError>;
}

/// Adapts a host [`FfiPlatformSealer`] to the crate's own seam.
///
/// The adapter is where the two error vocabularies meet: a cancelled gesture has to stay
/// `AuthenticationFailed` across the boundary, because the caller shows a different message
/// for "the user pressed cancel" than for "the platform is broken".
impl core::fmt::Debug for HostSealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HostSealer")
    }
}

struct HostSealer {
    /// The host's implementation.
    host: Arc<dyn FfiPlatformSealer>,
    /// The backend the host declared, checked once when the store is built.
    backend: Backend,
}

/// Maps the boundary error back into the crate's vocabulary.
fn host_error(error: FfiError) -> bioauth::Error {
    match error.kind() {
        "bioauth_authentication_failed" => bioauth::Error::AuthenticationFailed,
        "bioauth_wrapped_payload_invalid" => bioauth::Error::WrappedPayloadInvalid {
            reason: "the host could not authenticate the envelope",
        },
        "bioauth_unavailable" => bioauth::Error::Unavailable {
            reason: "the platform cannot authenticate right now",
        },
        _ => bioauth::Error::Platform {
            operation: "host platform sealer",
            code: 0,
        },
    }
}

impl bioauth::PlatformSealer for HostSealer {
    fn backend(&self) -> Backend {
        self.backend
    }

    fn availability(&self) -> bioauth::Availability {
        match self.host.availability() {
            FfiAuthAvailability::Available {
                backend: _,
                hardware_backed,
            } => bioauth::Availability::Available {
                backend: self.backend,
                hardware_backed,
            },
            FfiAuthAvailability::Unavailable { reason } => bioauth::Availability::Unavailable {
                reason: leak_reason(&reason),
            },
            FfiAuthAvailability::Unsupported { reason } => bioauth::Availability::Unsupported {
                reason: leak_reason(&reason),
            },
        }
    }

    fn seal(&self, plaintext: &[u8]) -> bioauth::Result<Vec<u8>> {
        self.host
            .seal(plaintext.to_vec())
            .map_err(host_error)
            .and_then(|sealed| {
                if sealed.is_empty() {
                    Err(bioauth::Error::PayloadEmpty)
                } else {
                    Ok(sealed)
                }
            })
    }

    fn unseal(&self, envelope: &[u8]) -> bioauth::Result<Vec<u8>> {
        self.host.unseal(envelope.to_vec()).map_err(host_error)
    }

    fn delete(&self) -> bioauth::Result<()> {
        self.host.delete().map_err(host_error)
    }
}

/// Interns a host-supplied reason so the crate's `&'static str` reasons can carry it.
///
/// The crate's reasons are static strings because they are fixed messages; a host reason
/// comes from the platform. Leaking is bounded by the number of distinct platform answers,
/// which is a handful per process, and the alternative would be to drop the platform's own
/// words from the report.
fn leak_reason(reason: &str) -> &'static str {
    if reason.is_empty() {
        return "the platform reported no reason";
    }
    Box::leak(reason.to_owned().into_boxed_str())
}

/// Reads the backend a host declares, rejecting a name this build does not know.
fn backend_from_name(name: &str) -> Result<Backend, FfiError> {
    match name {
        "android-keystore" => Ok(Backend::AndroidKeystore),
        "apple-secure-enclave" => Ok(Backend::AppleSecureEnclave),
        other => Err(FfiError::AuthBound {
            kind: "bioauth_unknown_backend".to_owned(),
            detail: format!("{other} is not a backend a host may supply"),
        }),
    }
}

/// Maps a `qualia_bioauth` error to the FFI error.
fn auth_bound_error(error: bioauth::Error) -> FfiError {
    use bioauth::Error as E;
    let kind = match &error {
        E::Malformed { .. } => "bioauth_malformed",
        E::UnsupportedVersion { .. } => "bioauth_unsupported_version",
        E::UnknownBackend { .. } => "bioauth_unknown_backend",
        E::WrongBackend { .. } => "bioauth_wrong_backend",
        E::PayloadTooLong { .. } => "bioauth_payload_too_long",
        E::PayloadEmpty => "bioauth_payload_empty",
        E::MasterKeyWrongLength { .. } => "bioauth_master_key_wrong_length",
        E::Unavailable { .. } => "bioauth_unavailable",
        E::AuthenticationFailed => "bioauth_authentication_failed",
        E::WrappedPayloadInvalid { .. } => "bioauth_wrapped_payload_invalid",
        E::Platform { .. } => "bioauth_platform",
        E::RandomnessUnavailable => "bioauth_randomness_unavailable",
        E::MockAuthenticationFailed => "bioauth_mock_authentication_failed",
        _ => "bioauth_unknown",
    };
    FfiError::AuthBound {
        kind: kind.to_owned(),
        detail: error.to_string(),
    }
}

/// Length of a password-wrapped master key (`master.key.pw`).
///
/// The host side writes the file the wrap returns; the length is exposed so that a
/// reader can reject a wrong-sized file before calling the unwrap function, which has to
/// run Argon2id.
#[uniffi::export]
#[must_use]
pub fn lock_wrap_len() -> u64 {
    qualia2fa_core::LOCK_WRAP_LEN as u64
}

/// Wraps a 32-byte master key with the unlock password.
///
/// The returned bytes are `master.key.pw`: the complete file, magic and all. The host
/// side writes them next to the vault. The master key must be 32 bytes, the same
/// boundary [`FfiVault::from_master_key`] uses.
///
/// # Errors
///
/// - a master key of the wrong length: `master_key_wrong_length`
/// - an empty password: `lock_passphrase_empty`
/// - an oversized password: [`FfiError::InputTooLong`]
/// - a derivation failure: `lock_kdf_failed`
/// - an encryption failure: `lock_encryption_failed`
#[uniffi::export]
pub fn wrap_master_key_with_password(
    master_key: Vec<u8>,
    password: String,
) -> Result<Vec<u8>, FfiError> {
    check_len("password", &password, MAX_PASSPHRASE_CHARS)?;
    let master = flow::master_key_from_bytes(master_key.into())?;
    let passphrase = SecretString::from(password);
    qualia2fa_core::lock::wrap(&master, &passphrase, &KdfParams::recommended()).map_err(Into::into)
}

/// Opens a password-wrapped master key and returns the 32-byte key.
///
/// The caller hands the returned bytes to an in-memory [`FfiSecureStore`] and then calls
/// [`FfiVault::open`]. The bytes are the master key itself, so the host side must wipe
/// its copy as soon as the vault object exists.
///
/// # Errors
///
/// - a malformed file: `lock_file_malformed`
/// - an unsupported version or algorithm: `unsupported_format_version`
/// - parameters out of range: `lock_parameters_invalid`
/// - an empty password: `lock_passphrase_empty`
/// - a wrong password or tampered file: `lock_password_rejected`
/// - a derivation failure: `lock_kdf_failed`
///
/// `lock_password_rejected` merges "wrong password" and "file modified" on purpose; the
/// unlock screen shows the same message for both.
#[uniffi::export]
pub fn unwrap_master_key_with_password(
    wrapped: Vec<u8>,
    password: String,
) -> Result<Vec<u8>, FfiError> {
    check_len("password", &password, MAX_PASSPHRASE_CHARS)?;
    let passphrase = SecretString::from(password);
    let master = qualia2fa_core::lock::unwrap(&wrapped, &passphrase)?;
    Ok(flow::master_key_to_bytes(&master).expose_secret().to_vec())
}

/// Builds the `lock.marker` contents.
///
/// The marker records that the lock is enabled, which wraps existed when it was written and
/// when the migration finished. It contains no secret; its flags are advisory and the
/// application must still look at the actual wrap files.
///
/// # Errors
///
/// - neither wrap present: `lock_file_malformed`
/// - `migrated_at` of zero: `timestamp_zero`
#[uniffi::export]
pub fn lock_marker(password: bool, biometric: bool, migrated_at: u64) -> Result<Vec<u8>, FfiError> {
    Ok(qualia2fa_core::LockMarker::new(password, biometric, migrated_at)?.encode())
}

/// Builds the `lock.pending` contents.
///
/// Its presence means a creation, migration or recovery is in progress and the next start
/// must finish or roll back. It contains no secret.
///
/// # Errors
///
/// A zero `started_at`: `timestamp_zero`.
#[uniffi::export]
pub fn lock_pending(started_at: u64) -> Result<Vec<u8>, FfiError> {
    Ok(qualia2fa_core::LockPending::new(started_at)?.encode())
}

/// Whether `bytes` are a valid `lock.marker`.
///
/// A marker that cannot be read is **not** a legacy installation: the caller must fail
/// closed instead of opening the vault without a password.
#[uniffi::export]
#[must_use]
pub fn is_lock_marker(bytes: Vec<u8>) -> bool {
    qualia2fa_core::LockMarker::parse(&bytes).is_ok()
}

/// Whether `bytes` are a valid `lock.pending`.
#[uniffi::export]
#[must_use]
pub fn is_lock_pending(bytes: Vec<u8>) -> bool {
    qualia2fa_core::LockPending::parse(&bytes).is_ok()
}

/// Whether `bytes` are a structurally valid password wrap, without running Argon2id.
///
/// This is the cheap "is there a usable password path on this device" question. It does not
/// prove the password is known; only [`unwrap_master_key_with_password`] does.
#[uniffi::export]
#[must_use]
pub fn is_lock_password_wrap(bytes: Vec<u8>) -> bool {
    qualia2fa_core::lock::WrapHeader::parse(&bytes).is_ok()
}

/// Opens the direct master key store of the current platform.
///
/// The `cfg` split is the one [`open_platform_key_store`] documents: opening a platform
/// store is fallible where the platform has one, and the placeholder compiled on the
/// remaining platforms cannot fail.
fn open_platform_direct_master_key_store() -> Result<PlatformDirectMasterKeyStore, FfiError> {
    #[cfg(any(target_os = "windows", target_os = "android"))]
    {
        PlatformDirectMasterKeyStore::open_best_available().map_err(platform_error)
    }
    #[cfg(not(any(target_os = "windows", target_os = "android")))]
    {
        Ok(PlatformDirectMasterKeyStore::open_best_available())
    }
}

/// Opens the wrapped master key store of the current platform; see
/// [`open_platform_direct_master_key_store`] for the `cfg` split.
fn open_platform_wrapped_master_key_store() -> Result<PlatformWrappedMasterKeyStore, FfiError> {
    #[cfg(any(target_os = "windows", target_os = "android"))]
    {
        PlatformWrappedMasterKeyStore::open_best_available().map_err(platform_error)
    }
    #[cfg(not(any(target_os = "windows", target_os = "android")))]
    {
        Ok(PlatformWrappedMasterKeyStore::open_best_available())
    }
}

/// Converts the bytes of a master key handed across the boundary into the library's type.
///
/// The library takes the material as a fixed-size array, so its length is checked by the
/// conversion itself. A wrong length is reported as the core's `master_key_wrong_length` —
/// the kind the host side already dispatches on for [`FfiVault::from_master_key`] — rather
/// than as a kind of its own. Both sides agree on the length by construction: the constant
/// used here is the library's, and it is the same 32 bytes the core's vault layer uses.
fn dik_master_key(bytes: Vec<u8>) -> Result<DikMasterKey, FfiError> {
    <[u8; MASTER_KEY_LEN]>::try_from(bytes)
        .map(DikMasterKey::from_bytes)
        .map_err(|bytes: Vec<u8>| {
            Error::MasterKeyWrongLength {
                expected: MASTER_KEY_LEN,
                actual: bytes.len(),
            }
            .into()
        })
}

/// The image format of an [`FfiEntryIcon`].
///
/// The three are the formats the vault stores. The host side decodes the bytes itself, because
/// image decoding is a platform API (`BitmapFactory` on one platform, `ImageIO` on another) and
/// this crate does no decoding of its own. SVG is stored and exported but this version has no
/// renderer for it: a host that cannot draw one falls back to the letter badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiIconMime {
    /// `image/png`.
    Png,
    /// `image/jpeg`.
    Jpeg,
    /// `image/svg+xml`.
    Svg,
}

impl From<FfiIconMime> for qualia2fa_core::vault::IconMime {
    fn from(value: FfiIconMime) -> Self {
        match value {
            FfiIconMime::Png => Self::Png,
            FfiIconMime::Jpeg => Self::Jpeg,
            FfiIconMime::Svg => Self::Svg,
        }
    }
}

impl From<qualia2fa_core::vault::IconMime> for FfiIconMime {
    fn from(value: qualia2fa_core::vault::IconMime) -> Self {
        match value {
            qualia2fa_core::vault::IconMime::Png => Self::Png,
            qualia2fa_core::vault::IconMime::Jpeg => Self::Jpeg,
            qualia2fa_core::vault::IconMime::Svg => Self::Svg,
        }
    }
}

/// The picture an entry shows beside its name.
///
/// The bytes are the original file, not decoded pixels: the platform decodes them when the card
/// is drawn, and this crate only moves them. The type is **not** a secret, but its bytes are
/// never printed: `Debug` reports the format and the length.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiEntryIcon {
    /// The format the bytes are in.
    pub mime: FfiIconMime,
    /// The original image file bytes.
    pub bytes: Vec<u8>,
}

impl core::fmt::Debug for FfiEntryIcon {
    /// Prints the format and the length, never the picture.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FfiEntryIcon")
            .field("mime", &self.mime)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

impl FfiEntryIcon {
    /// Reads an icon as the host side sees it.
    fn from_core(icon: &qualia2fa_core::vault::EntryIcon) -> Self {
        Self {
            mime: icon.mime.into(),
            bytes: icon.bytes.clone(),
        }
    }

    /// Builds a core icon, checking the node limit.
    fn to_core(&self) -> Result<qualia2fa_core::vault::EntryIcon, FfiError> {
        Ok(qualia2fa_core::vault::EntryIcon::new(
            self.mime.into(),
            self.bytes.clone(),
        )?)
    }
}

/// A 2FA entry, as represented across the FFI boundary.
///
/// Relation to [`uri::OtpAuth`]: that type is the parse result of an `otpauth://`
/// URI, while this one is what a vault stores. The fields are similar but **not
/// equivalent** — a vault entry adds a display name, a note and timestamps, and
/// has no "URI type" field (HOTP is expressed by `counter` being `None`).
///
/// The core's [`EntryId`](qualia2fa_core::vault::EntryId) is 16 bytes; it crosses
/// the boundary as a 32-character lower-case hexadecimal string, the form the host
/// side uses as an opaque identifier (list item key, naming an entry to delete).
/// Strings have value semantics, whereas byte-array equality and hashing in
/// managed languages are often by reference.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiVaultEntry {
    /// Entry identifier, a 32-character lower-case hexadecimal string.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Issuer (service name).
    pub issuer: Option<String>,
    /// Account name.
    pub account: String,
    /// The secret, Base32 encoded (upper case). See the module documentation for
    /// the secret representation.
    pub secret_base32: String,
    /// Hash algorithm in use.
    pub algorithm: FfiAlgorithm,
    /// Number of digits in a code.
    pub digits: FfiDigits,
    /// The kind: what decides how a code is computed, and which parameters it uses.
    pub kind: FfiEntryKind,
    /// Whether a PIN is stored for this entry.
    ///
    /// Read-only: the core never hands a PIN back, because the only thing that needs to read one
    /// is the code computation, which happens there. A form can use this to show that a PIN
    /// exists, and passes the new value through [`FfiEntryKind`] when the user changes it.
    pub pin_set: bool,
    /// User note.
    pub note: String,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// Last modification time in Unix seconds.
    pub updated_at: u64,
    /// The icon shown beside the name, when the entry has one.
    ///
    /// Read and written literally: an update that passes `None` **removes** the icon. The host
    /// side gets the value back from [`FfiVault::entry`] and hands the same value in when it edits
    /// other fields, which is what keeps an imported picture alive through an edit.
    pub icon: Option<FfiEntryIcon>,
}

/// One child of a group: an entry or another group.
///
/// The two live in one type because the child list **is** the display order: an entry and a
/// child group have to be told apart to be drawn, and the order between them is what the user
/// arranged. The identifiers are the same 32-character hexadecimal strings the rest of the
/// surface uses.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiGroupChild {
    /// An entry that belongs to this group.
    Entry {
        /// Entry identifier, 32 hexadecimal characters.
        id: String,
    },
    /// A named group whose children hang from this one.
    Group {
        /// Group identifier, 32 hexadecimal characters.
        id: String,
    },
}

impl FfiGroupChild {
    /// Reads one child as the host side sees it.
    fn from_core(child: &GroupChild) -> Self {
        match child {
            GroupChild::Entry(id) => Self::Entry { id: id.to_string() },
            GroupChild::Group(id) => Self::Group {
                id: hex_id(id.as_bytes()),
            },
        }
    }

    /// Turns one child back into the core's type.
    fn to_core(&self) -> Result<GroupChild, FfiError> {
        Ok(match self {
            Self::Entry { id } => GroupChild::Entry(parse_entry_id(id)?),
            Self::Group { id } => GroupChild::Group(parse_group_id(id)?),
        })
    }
}

/// A group: its name and the ordered list of its children.
///
/// A group is a **sequence**, not a set: the child list is what the user arranged, and it is
/// synchronized between devices (see [`FfiConflict`] for what happens when two devices arrange
/// the same group differently).
///
/// The **top group** is the root of the tree: entries that belong to no named group live there,
/// it is always first in pre-order, it has no name, and its identifier is all zeroes;
/// [`FfiGroup::top`] says so rather than leaving the host to recognize that identifier.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiGroup {
    /// The group's identifier, 32 hexadecimal characters.
    pub id: String,
    /// The name, empty for the top group.
    pub name: String,
    /// Whether this is the top group.
    pub top: bool,
    /// The children in display order: entries and child groups mixed.
    ///
    /// This is the truth. It is written whole by [`FfiVault::set_children`], the way the vault
    /// stores it, so a move is one call and has no intermediate state.
    pub children: Vec<FfiGroupChild>,
    /// The entries of this group, **derived** from `children`, in the same order.
    ///
    /// A view, not a second source of truth: it exists so that a caller that only arranges
    /// entries does not have to filter `children` itself. Writing the arrangement goes through
    /// [`FfiVault::set_children`] (whole list) or [`FfiVault::set_ordering`] (entries only).
    pub entry_ids: Vec<String>,
}

impl FfiGroup {
    /// Reads one group as the host side sees it.
    fn from_core(id: &qualia2fa_core::vault::GroupId, group: &Group) -> Self {
        Self {
            id: hex_id(id.as_bytes()),
            name: group.name.clone(),
            top: id.is_top(),
            children: group
                .children
                .iter()
                .map(FfiGroupChild::from_core)
                .collect(),
            entry_ids: group.entry_ids().iter().map(ToString::to_string).collect(),
        }
    }
}

impl core::fmt::Debug for FfiVaultEntry {
    /// Prints everything except the secret: it is the one field that must not reach a log, a
    /// panic message or a crash dump, and the import preview makes this type travel through
    /// diagnostics for the first time.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FfiVaultEntry")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret_base32", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("kind", &self.kind)
            .field("pin_set", &self.pin_set)
            .field("note", &self.note)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("icon", &self.icon)
            .finish_non_exhaustive()
    }
}

impl FfiVaultEntry {
    /// Converts a core entry into its cross-boundary representation.
    fn from_core(id: &qualia2fa_core::vault::EntryId, entry: &Entry) -> Self {
        Self {
            id: id.to_string(),
            name: entry.name.clone(),
            issuer: entry.issuer.clone(),
            account: entry.account.clone(),
            secret_base32: entry.secret.to_base32(),
            algorithm: match entry.algorithm {
                Algorithm::Sha1 => FfiAlgorithm::Sha1,
                Algorithm::Sha256 => FfiAlgorithm::Sha256,
                Algorithm::Sha512 => FfiAlgorithm::Sha512,
            },
            digits: entry.digits.into(),
            kind: FfiEntryKind::from_core(&entry.kind),
            pin_set: entry.kind.motp_pin().is_some() || entry.kind.yandex_pin().is_some(),
            note: entry.note.clone(),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
            icon: entry.icon.as_ref().map(FfiEntryIcon::from_core),
        }
    }

    /// Builds a core entry. `now` fills in the creation and modification times.
    ///
    /// `existing` is the kind the stored entry has, when this is an update: a PIN the host did not
    /// supply is carried over from it (see [`FfiEntryKind`]).
    fn to_core(&self, now: u64, existing: Option<EntryKind>) -> Result<Entry, FfiError> {
        check_len("secret", &self.secret_base32, MAX_SECRET_CHARS)?;
        check_len("name", &self.name, MAX_VAULT_FIELD_CHARS)?;
        check_len("account", &self.account, MAX_VAULT_FIELD_CHARS)?;
        check_len("note", &self.note, MAX_VAULT_FIELD_CHARS)?;
        if let Some(issuer) = &self.issuer {
            check_len("issuer", issuer, MAX_VAULT_FIELD_CHARS)?;
        }
        let secret = OtpSecret::from_base32(&self.secret_base32)?;
        let icon = match &self.icon {
            Some(icon) => Some(icon.to_core()?),
            None => None,
        };
        Ok(Entry::new(
            self.name.clone(),
            self.issuer.clone(),
            self.account.clone(),
            secret,
            self.algorithm.into(),
            self.digits.to_core()?,
            self.kind.clone().into_core(existing)?,
            self.note.clone(),
            now,
            now,
        )?
        .with_icon(icon))
    }

    /// Parses the 16-byte hexadecimal identifier.
    fn parse_id(&self) -> Result<qualia2fa_core::vault::EntryId, FfiError> {
        parse_entry_id(&self.id)
    }
}

/// Parses the hexadecimal representation of an `EntryId` (32 lower-case
/// hexadecimal characters).
fn parse_entry_id(text: &str) -> Result<qualia2fa_core::vault::EntryId, FfiError> {
    check_len("entry_id", text, 32)?;
    let bytes = text.as_bytes();
    if bytes.len() != 32 {
        return Err(FfiError::Core {
            detail: Error::UriInvalidParameter {
                name: "entry_id".to_owned(),
                reason: "must be 32 hexadecimal characters".to_owned(),
            }
            .into(),
        });
    }
    let mut id = [0_u8; 16];
    for (index, slot) in id.iter_mut().enumerate() {
        let hi = hex_digit(bytes[index * 2])?;
        let lo = hex_digit(bytes[index * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(qualia2fa_core::vault::EntryId::from_bytes(id))
}

/// Parses the hexadecimal representation of a `GroupId` (32 lower-case hexadecimal characters).
///
/// The same shape as an entry identifier, and parsed the same way: a group identifier is opaque to
/// the host side, which only ever passes back what this layer gave it.
fn parse_group_id(text: &str) -> Result<qualia2fa_core::vault::GroupId, FfiError> {
    check_len("group_id", text, 32)?;
    let bytes = text.as_bytes();
    if bytes.len() != 32 {
        return Err(FfiError::Core {
            detail: Error::UriInvalidParameter {
                name: "group_id".to_owned(),
                reason: "must be 32 hexadecimal characters".to_owned(),
            }
            .into(),
        });
    }
    let mut id = [0_u8; 16];
    for (index, slot) in id.iter_mut().enumerate() {
        let hi = hex_digit(bytes[index * 2])?;
        let lo = hex_digit(bytes[index * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(qualia2fa_core::vault::GroupId::from_bytes(id))
}

/// One hexadecimal character → its value.
fn hex_digit(byte: u8) -> Result<u8, FfiError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(FfiError::Core {
            detail: Error::UriInvalidParameter {
                name: "entry_id".to_owned(),
                reason: "contains a non-hexadecimal character".to_owned(),
            }
            .into(),
        }),
    }
}

/// An unlocked vault.
///
/// # The master key does not cross the boundary
///
/// This object **holds** the master key on the Rust side, and entry operations
/// and serialization happen inside Rust. On the open vault → read entries →
/// write entries → serialize path, the master key never appears as bytes in
/// Kotlin or Swift.
///
/// # Host-side lifetime
///
/// The host side constructs this object when the user unlocks the application
/// and **discards** it (drops the reference) when the application goes to the
/// background or the user locks it. The Rust-side `Drop` wipes the master key
/// when the object is collected, but that depends on collection timing, so
/// locking **must not** rely on the collector: locking means actually dropping
/// the reference and letting the user interface ask for an unlock again.
#[derive(uniffi::Object)]
pub struct FfiVault {
    /// The core vault state, including the master key.
    ///
    /// UniFFI shares exported objects as `Arc<Self>`, and `Arc` grants no mutable
    /// borrow, so the state sits behind a container with interior mutability.
    /// `Mutex` and not `RefCell`: UniFFI's `#[Object]` requires `Send + Sync`, which
    /// `RefCell` does not provide.
    ///
    /// **The lock granularity is one method call**, and only in-memory work
    /// happens under the lock (hash-table insert and remove, copying entry
    /// fields). Encryption and Argon2 run outside the lock: one export
    /// derivation takes hundreds of milliseconds, and holding the lock across it
    /// would stall concurrent user-interface refreshes.
    ///
    /// Poisoning is absorbed with `unwrap_or_else`: this lock guards a data
    /// structure, and the methods inside it contain no panicking code. Should a
    /// panic happen anyway, recovering the data is preferable to failing every
    /// later call, which would leave the user unable to read or write entries.
    inner: std::sync::Mutex<VaultFile>,
}

impl FfiVault {
    /// Builds from a core vault.
    fn wrap(inner: VaultFile) -> Arc<Self> {
        Arc::new(Self {
            inner: std::sync::Mutex::new(inner),
        })
    }
}

#[uniffi::export]
impl FfiVault {
    /// Creates an empty vault from an existing master key.
    ///
    /// Used by two paths:
    ///
    /// - after [`FfiJoiner::complete`]: the master key has been obtained and
    ///   written to the platform store, and a vault object to operate on is now
    ///   needed;
    /// - after [`import_recovery_key`]: the same.
    ///
    /// # An empty vault is expected
    ///
    /// The master key and the entries are **transferred separately**: logging in
    /// brings the key, not the content. The first vault the host side obtains is
    /// necessarily empty, and the entries come back through sync or from a local
    /// file.
    ///
    /// # The master key crosses the boundary here, and only here
    ///
    /// The parameter is a 32-byte plaintext key — the case where the host side
    /// already holds the master key, which cannot be avoided. After this call
    /// the host side can drop those 32 bytes; everything later goes through this
    /// object.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MasterKeyWrongLength`] when the length is not 32 bytes.
    #[uniffi::constructor]
    pub fn from_master_key(master_key: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        let master = flow::master_key_from_bytes(master_key.into())?;
        Ok(Self::wrap(flow::empty_vault(master)))
    }

    /// Re-wraps this vault's master key with a new unlock password.
    ///
    /// The old password is checked against `old_wrap` **and** against this vault's master key
    /// before a new wrap is produced. The caller writes the returned bytes atomically over
    /// `master.key.pw`; if the write fails, the old wrap is still there.
    ///
    /// The master key bytes are copied under the vault lock, and Argon2id runs after the lock
    /// is released, so a concurrent screen refresh is not held up by the derivation.
    ///
    /// # Errors
    ///
    /// - a malformed `old_wrap`: `lock_file_malformed` / `unsupported_format_version` /
    ///   `lock_parameters_invalid`
    /// - a wrong old password, or one for another account: `lock_password_rejected`
    /// - an empty password: `lock_passphrase_empty`
    /// - an oversized password: [`FfiError::InputTooLong`]
    /// - a derivation or encryption failure: `lock_kdf_failed` / `lock_encryption_failed`
    pub fn rewrap_lock_password(
        &self,
        old_wrap: Vec<u8>,
        old_password: String,
        new_password: String,
    ) -> Result<Vec<u8>, FfiError> {
        check_len("old_password", &old_password, MAX_PASSPHRASE_CHARS)?;
        check_len("new_password", &new_password, MAX_PASSPHRASE_CHARS)?;
        let old = SecretString::from(old_password);
        let new = SecretString::from(new_password);

        let master = {
            let file = self.lock();
            MasterKey::from_bytes(flow::master_key_to_bytes(file.master_key()))?
        };
        let opened = qualia2fa_core::lock::unwrap(&old_wrap, &old)?;
        if !opened.matches(&master) {
            return Err(Error::LockPasswordRejected.into());
        }
        qualia2fa_core::lock::wrap(&master, &new, &KdfParams::recommended()).map_err(Into::into)
    }

    /// Wraps this vault's master key with the platform auth-bound store.
    ///
    /// The key bytes are copied under the vault lock and the platform prompt runs after the
    /// lock is released, so a Hello or biometric prompt does not freeze other vault calls.
    /// The returned bytes are the complete `master.key.bio` blob.
    ///
    /// # Errors
    ///
    /// [`FfiError::AuthBound`] for a cancelled gesture, an unavailable platform, or a
    /// platform failure. The master key is never returned to the host by this method.
    pub fn wrap_master_for_auth_bound(
        &self,
        store: Arc<FfiAuthBoundKeyStore>,
    ) -> Result<Vec<u8>, FfiError> {
        let master = {
            let file = self.lock();
            bioauth::MasterKey::from_bytes(file.master_key().expose()).map_err(auth_bound_error)?
        };
        store.store.wrap(&master).map_err(auth_bound_error)
    }

    /// Registers a new device: generates a master key, obtains a device
    /// identity, and hands the master key to the platform key store.
    ///
    /// # What this step does and does not do
    ///
    /// **Does**: generate the master key → obtain the device identity → write
    /// the master key into [`FfiSecureStore`].
    /// **Does not** create a vault file or write to disk. It returns an empty
    /// [`FfiVault`]; the host side adds the first entries and then calls
    /// [`FfiVault::serialize`] to persist them.
    ///
    /// # Errors
    ///
    /// Returns the corresponding error when creating the device identity or
    /// writing the master key fails, and in that case **leaves nothing on disk**
    /// (this function writes no file). The platform key store may be
    /// unavailable; the host side should treat that as a state to report to the
    /// user rather than retry.
    #[uniffi::constructor]
    pub fn register(
        keys: Arc<dyn FfiDeviceKeys>,
        store: Arc<dyn FfiSecureStore>,
        label: String,
    ) -> Result<Arc<Self>, FfiError> {
        check_len("label", &label, MAX_LABEL_CHARS)?;
        let mut keys = ForeignDeviceKeys(keys);
        let mut store = ForeignSecureStore(store);
        let registered = flow::registration(&mut keys, &mut store, &label)?;
        Ok(Self::wrap(registered.into_vault()))
    }

    /// Opens a vault file with the master key from the platform key store.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DeviceNotRegistered`] (`kind` is
    /// `device_not_registered`) when the device was never registered, and
    /// [`Error::VaultDecryptionFailed`] (`kind` is `vault_decryption_failed`)
    /// when a master key exists but the file cannot be opened. The host side
    /// must distinguish the two: the first guides the user to register or log
    /// in, the second warns that the data may be damaged or that the master key
    /// was replaced.
    ///
    /// # An empty vault also tells whether the master key is right
    ///
    /// Format version 2 places a master key check value at the end of the file,
    /// so **a file with no entries is judged as well**: a wrong master key
    /// returns [`Error::VaultDecryptionFailed`] immediately instead of only
    /// after the user adds a first entry. The host side may therefore present
    /// "unlocked" as soon as the open succeeds.
    ///
    /// **Old version 1 files still cannot be judged** — such a file carries no
    /// information to judge with. Use the challenge-response of [`FfiVerifier`]
    /// for authoritative confirmation, since it does not depend on file
    /// content.
    #[uniffi::constructor]
    pub fn open(store: Arc<dyn FfiSecureStore>, data: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        let store = ForeignSecureStore(store);
        let file = flow::open_vault(&store, &data)?;
        Ok(Self::wrap(file))
    }

    /// Number of entries.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.lock().vault().len() as u64
    }

    /// Whether there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().vault().is_empty()
    }

    /// Number of tombstones.
    ///
    /// A tombstone is the record that an entry was deleted, which lets the
    /// deletion propagate between devices. User interfaces normally need not
    /// show it, but it is useful when diagnosing.
    #[must_use]
    pub fn tombstone_count(&self) -> u64 {
        self.lock().vault().tombstone_count() as u64
    }

    /// All current entries.
    ///
    /// # Order
    ///
    /// The order is **not guaranteed**, because the core indexes entries with a
    /// hash table. The host side must sort the list itself (by name, by creation
    /// time, and so on) and must not rely on this order being stable.
    #[must_use]
    pub fn entries(&self) -> Vec<FfiVaultEntry> {
        self.lock()
            .vault()
            .iter()
            .map(|(id, entry)| FfiVaultEntry::from_core(id, entry))
            .collect()
    }

    /// Returns one entry by identifier. `None` when it does not exist.
    #[must_use]
    pub fn entry(&self, id: String) -> Option<FfiVaultEntry> {
        let id = parse_entry_id(&id).ok()?;
        self.lock()
            .vault()
            .get(&id)
            .map(|entry| FfiVaultEntry::from_core(&id, entry))
    }

    /// Adds an entry and returns its identifier.
    ///
    /// `now` is Unix seconds, **supplied by the host side** — the core does not
    /// read a clock.
    pub fn add_entry(&self, entry: FfiVaultEntry, now: u64) -> Result<String, FfiError> {
        flow::check_now(now)?;
        let core = entry.to_core(now, None)?;
        let id = self.lock().vault_mut().insert(core)?;
        Ok(id.to_string())
    }

    /// Modifies an existing entry.
    ///
    /// Returns [`Error::VaultEntryNotFound`] (`kind` is `vault_entry_not_found`)
    /// when the identifier is not found.
    ///
    /// # The identifier is preserved
    ///
    /// The identifier is the only thing by which devices refer to "the same
    /// entry": changing it reads as one deletion plus one insertion during sync,
    /// which misplaces that entry's history and tombstone on other devices.
    /// Modification must therefore **keep the identifier**.
    ///
    /// So this takes out the old entry, replaces its content and puts it back
    /// under the **same** identifier. The creation time is preserved as well: it
    /// records when the user added the entry, and letting it change would make
    /// the user interface reorder rows.
    pub fn update_entry(&self, entry: FfiVaultEntry, now: u64) -> Result<(), FfiError> {
        flow::check_now(now)?;
        let id = entry.parse_id()?;
        let mut vault = self.lock();
        // The stored kind is handed over so a PIN the host did not supply is carried across
        // instead of being dropped: the host was never shown it, and losing it would produce an
        // entry that silently stops matching.
        let existing = vault
            .vault()
            .get(&id)
            .ok_or(Error::VaultEntryNotFound)?
            .duplicate()?
            .kind;
        let mut core = entry.to_core(now, Some(existing))?;
        let created_at = vault
            .vault()
            .get(&id)
            .ok_or(Error::VaultEntryNotFound)?
            .created_at;
        core.created_at = created_at;
        vault.vault_mut().replace(id, core)?;
        Ok(())
    }

    /// Deletes an entry, leaving a tombstone.
    ///
    /// Returns whether an entry was deleted (`false` means the identifier did
    /// not exist).
    ///
    /// # A tombstone is how deletion is recorded
    ///
    /// Erasing the record outright would make another device bring the entry
    /// **back** at the next sync, since it does not know about the deletion
    /// here. The tombstone is the fact "this entry was deleted" and travels with
    /// the entries.
    pub fn remove_entry(&self, id: String, now: u64) -> Result<bool, FfiError> {
        flow::check_now(now)?;
        let id = parse_entry_id(&id)?;
        Ok(self.lock().vault_mut().remove(&id, now).is_some())
    }

    /// The groups in **pre-order**: the top group first, then each group's children depth-first.
    ///
    /// That is the tree the core stores and the order the interface draws; the host does not
    /// sort, because a sort would be a second opinion about the arrangement. `children` is the
    /// truth (entries and child groups mixed), and `entry_ids` is the derived view of its entry
    /// children.
    #[must_use]
    pub fn groups(&self) -> Vec<FfiGroup> {
        let vault = self.lock();
        vault
            .vault()
            .groups()
            .map(|(id, group)| FfiGroup::from_core(id, group))
            .collect()
    }

    /// The ordered children of one group, or `None` when there is no such group.
    #[must_use]
    pub fn children_of(&self, group_id: String) -> Option<Vec<FfiGroupChild>> {
        let id = parse_group_id(&group_id).ok()?;
        let vault = self.lock();
        vault
            .vault()
            .children_of(&id)
            .map(|children| children.iter().map(FfiGroupChild::from_core).collect())
    }

    /// The parent of a named group, or `None` for the top group and an unknown identifier.
    ///
    /// Worked out from the child lists, which is where the parent relationship lives; there is no
    /// parent field to read.
    #[must_use]
    pub fn parent_of(&self, group_id: String) -> Option<String> {
        let id = parse_group_id(&group_id).ok()?;
        let vault = self.lock();
        vault
            .vault()
            .parent_of(&id)
            .map(|parent| hex_id(parent.as_bytes()))
    }

    /// The depth of a group: the top group is 0, its named children 1, and so on.
    #[must_use]
    pub fn depth_of(&self, group_id: String) -> Option<u64> {
        let id = parse_group_id(&group_id).ok()?;
        let vault = self.lock();
        vault
            .vault()
            .depth_of(&id)
            .map(|depth| u64::try_from(depth).unwrap_or(u64::MAX))
    }

    /// The group an entry belongs to, as 32 hexadecimal characters.
    ///
    /// Always `Some` for an entry the vault holds: an entry that belongs to no named group belongs
    /// to the top group, which is a group like any other here.
    #[must_use]
    pub fn group_of(&self, entry_id: String) -> Option<String> {
        let id = parse_entry_id(&entry_id).ok()?;
        let vault = self.lock();
        vault
            .vault()
            .group_of(&id)
            .map(|group| hex_id(group.as_bytes()))
    }

    /// Creates a named group under the **top group** and returns its identifier.
    ///
    /// # Errors
    ///
    /// The core's error for a name longer than a vault field allows (`field_too_long`).
    pub fn create_group(&self, name: String) -> Result<String, FfiError> {
        check_len("group_name", &name, MAX_VAULT_FIELD_CHARS)?;
        if name.is_empty() {
            return Err(FfiError::InputEmpty {
                kind: "group_name".to_owned(),
            });
        }
        let id = self.lock().vault_mut().create_group(name)?;
        Ok(hex_id(id.as_bytes()))
    }

    /// Creates a named group as the **last child** of `parent_id` and returns its identifier.
    ///
    /// # Errors
    ///
    /// [`Error::VaultGroupNotFound`] (`kind` is `vault_group_not_found`) for an unknown parent,
    /// [`Error::VaultGroupDepthExceeded`] (`vault_group_depth_exceeded`) when the new group would
    /// be nested deeper than the interface can draw, and `field_too_long` for an over-long name.
    pub fn create_group_in(&self, parent_id: String, name: String) -> Result<String, FfiError> {
        check_len("group_name", &name, MAX_VAULT_FIELD_CHARS)?;
        if name.is_empty() {
            return Err(FfiError::InputEmpty {
                kind: "group_name".to_owned(),
            });
        }
        let parent = parse_group_id(&parent_id)?;
        let id = self.lock().vault_mut().create_group_in(&parent, name)?;
        Ok(hex_id(id.as_bytes()))
    }

    /// Renames a group.
    ///
    /// # Errors
    ///
    /// [`Error::VaultTopGroupImmutable`] (`kind` is `vault_top_group_immutable`) for the top group,
    /// which has no name to edit, and [`Error::VaultGroupNotFound`] for an unknown identifier.
    pub fn rename_group(&self, group_id: String, name: String) -> Result<(), FfiError> {
        check_len("group_name", &name, MAX_VAULT_FIELD_CHARS)?;
        let id = parse_group_id(&group_id)?;
        self.lock().vault_mut().rename_group(&id, name)?;
        Ok(())
    }

    /// Replaces the whole child list of a group: the one write behind every move.
    ///
    /// A list is a sequence, and this is how the vault stores one, so a move, an insertion or a
    /// deletion is a single call with no intermediate state. A child the new list drops is not
    /// deleted: an entry returns to the top group and a child group moves to this group's parent.
    ///
    /// # Errors
    ///
    /// - `vault_group_not_found`: the group or a child group does not exist.
    /// - `vault_group_unknown_entry`: a child names an entry the vault does not hold.
    /// - `vault_group_duplicate_child`: the list names one child twice.
    /// - `vault_group_cycle`: the list would put a group inside itself.
    /// - `vault_group_depth_exceeded`: the moved subtree would be nested too deeply.
    pub fn set_children(
        &self,
        group_id: String,
        children: Vec<FfiGroupChild>,
    ) -> Result<(), FfiError> {
        let id = parse_group_id(&group_id)?;
        let mut parsed = Vec::with_capacity(children.len());
        for child in &children {
            parsed.push(child.to_core()?);
        }
        self.lock().vault_mut().set_children(&id, parsed)?;
        Ok(())
    }

    /// Removes a group.
    ///
    /// Nothing is deleted: the group's children move to its parent, keeping their relative order
    /// and their place in that parent's list.
    ///
    /// # Errors
    ///
    /// [`Error::VaultTopGroupImmutable`] for the top group, and [`Error::VaultGroupNotFound`] for
    /// an unknown identifier.
    pub fn remove_group(&self, group_id: String) -> Result<(), FfiError> {
        let id = parse_group_id(&group_id)?;
        self.lock().vault_mut().remove_group(&id)?;
        Ok(())
    }

    /// Replaces the **entry** children of a group, keeping the positions of its child groups.
    ///
    /// The list is the whole entry sequence, not a change to it: a host that reorders one row
    /// sends the result, which is both simpler and safer than describing a move. Entries the new
    /// list drops return to the top group unless another group claims them.
    ///
    /// # Errors
    ///
    /// [`Error::VaultGroupNotFound`] for an unknown group,
    /// [`Error::VaultGroupUnknownEntry`] for an identifier the vault does not hold, and
    /// [`Error::VaultGroupDuplicateChild`] when the list names one entry twice.
    pub fn set_ordering(&self, group_id: String, entry_ids: Vec<String>) -> Result<(), FfiError> {
        let id = parse_group_id(&group_id)?;
        let mut parsed = Vec::with_capacity(entry_ids.len());
        for entry_id in &entry_ids {
            parsed.push(parse_entry_id(entry_id)?);
        }
        self.lock().vault_mut().set_ordering(&id, parsed)?;
        Ok(())
    }

    /// Moves an entry into a group, appending it to that group's ordering.
    ///
    /// This is the "move to group" operation: the entry leaves wherever it was, so the host does
    /// not have to know where it came from.
    ///
    /// # Errors
    ///
    /// [`Error::VaultEntryNotFound`] for an unknown entry and [`Error::VaultGroupNotFound`] for an
    /// unknown group.
    pub fn assign_to_group(&self, entry_id: String, group_id: String) -> Result<(), FfiError> {
        let entry = parse_entry_id(&entry_id)?;
        let group = parse_group_id(&group_id)?;
        self.lock().vault_mut().assign_to_group(&entry, &group)?;
        Ok(())
    }

    /// Serializes into vault file bytes for the host side to persist.
    ///
    /// The host side should write the file **atomically** (write a temporary
    /// file, then rename) rather than overwrite in place: losing power halfway
    /// leaves a file that cannot be opened, and the user's only copy of the data
    /// is inside it. The core provides `vault::write_file_atomically`, but it
    /// performs I/O and is not part of this library's exported surface.
    pub fn serialize(&self) -> Result<Vec<u8>, FfiError> {
        Ok(self.lock().serialize()?)
    }

    /// Computes the current code for one entry.
    ///
    /// `unix_time` is supplied by the host side (the core does not read a clock). The **kind of
    /// the entry** decides how the code is computed: a Steam Guard entry produces five
    /// characters, an mOTP entry six hexadecimal ones, a Yandex entry eight lower-case letters.
    /// The host does not have to know which function to call, which is what used to make those
    /// three arrive as ordinary TOTP entries and produce codes that never matched.
    ///
    /// # Errors
    ///
    /// [`Error::PinRequired`] (`kind` is `pin_required`) when the entry computes with a PIN and
    /// has none, and [`Error::VaultEntryNotFound`] when the identifier is unknown. An HOTP entry
    /// has no time-based code: use [`FfiVault::hotp_for`] with the counter the user is on.
    pub fn code_for(&self, id: String, unix_time: u64) -> Result<String, FfiError> {
        self.with_entry(&id, |entry| match entry.kind {
            EntryKind::Totp { period } => Ok(otp::totp_code(
                &entry.secret,
                unix_time,
                period,
                entry.algorithm,
                entry.digits,
            )?),
            EntryKind::Motp { period, ref pin } => Ok(motp::motp_code(
                &entry.secret,
                pin.as_ref(),
                period,
                unix_time,
            )?),
            EntryKind::Yandex { period, ref pin } => Ok(yaotp::yaotp_code(
                &entry.secret,
                pin.as_ref(),
                period,
                unix_time,
            )?),
            EntryKind::Steam => Ok(otp::steam_guard_code(
                &entry.secret,
                unix_time,
                otp::STEAM_PERIOD,
                entry.algorithm,
            )?),
            EntryKind::Hotp { .. } => Err(FfiError::WrongCodeKind {
                kind: "hotp".to_owned(),
                wanted: "time".to_owned(),
            }),
        })
    }

    /// Computes the code for one HOTP entry at the given counter.
    ///
    /// The counter comes from the host side: advancing it is the user's decision (the interface
    /// shows the next code and only then moves on), and this layer does not store a counter it
    /// was not asked to store. Use [`FfiVault::code_for`] for every other kind.
    pub fn hotp_for(&self, id: String, counter: u64) -> Result<String, FfiError> {
        self.with_entry(&id, |entry| match entry.kind {
            EntryKind::Hotp { .. } => Ok(otp::hotp_code(
                &entry.secret,
                counter,
                entry.algorithm,
                entry.digits,
            )),
            _ => Err(FfiError::WrongCodeKind {
                kind: "not_hotp".to_owned(),
                wanted: "counter".to_owned(),
            }),
        })
    }
    /// Exports a recovery key file protected by a passphrase.
    ///
    /// # KDF parameters
    ///
    /// Passing `None` for `memory_kib` / `iterations` / `parallelism` uses the
    /// core defaults (64 MiB / 3 iterations / 1 lane). The host side **must
    /// not** lower them for speed: the export cost is paid once, whereas an
    /// attacker who obtains the file attacks it offline, so lower parameters
    /// weaken the last line of defence directly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RecoveryParametersInvalid`] (`kind` is
    /// `recovery_parameters_invalid`) when the parameters fall outside the range
    /// the core allows (memory at most 1 GiB, at most 1000 iterations). **Both
    /// bounds are checked**, because the parameters can come from the host
    /// side's sliders and from **someone else's** file.
    ///
    /// # Handling the return value
    ///
    /// The caller receives **encrypted** file bytes, not the master key. The
    /// host side should only write them to a location the user chose or show
    /// them as a QR code for the user to copy down, and should keep them out of
    /// the clipboard history. The passphrase itself is not part of the return
    /// value and must not be persisted by the host side.
    pub fn export_recovery_key(
        &self,
        passphrase: String,
        memory_kib: Option<u64>,
        iterations: Option<u64>,
        parallelism: Option<u64>,
    ) -> Result<Vec<u8>, FfiError> {
        check_len("passphrase", &passphrase, MAX_PASSPHRASE_CHARS)?;
        let params = kdf_params(memory_kib, iterations, parallelism)?;
        let vault = self.lock();
        Ok(flow::export_recovery_key(
            vault.master_key(),
            &SecretString::from(passphrase),
            Some(params),
        )?)
    }
}

impl FfiVault {
    /// Takes the lock, ignoring poisoning.
    ///
    /// Poisoning means a thread panicked while holding the lock. The data
    /// structure's **invariants** still hold at that point (this lock guards
    /// hash-table insert and remove, which have no half-modified intermediate
    /// state), so recovering is preferable to failing every later call, which
    /// would leave the user unable to read or write entries at all.
    fn lock(&self) -> std::sync::MutexGuard<'_, VaultFile> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Computes the three derived fields of an entry.
    ///
    /// It does not return `&Entry`: entries live behind the `MutexGuard`, which
    /// is released when the function returns, so a borrow cannot escape. The
    /// core's `OtpSecret` deliberately does not implement `Clone`, so this
    /// **computes the code and returns the string** rather than copying the
    /// entry or the secret out.
    fn with_entry(
        &self,
        id: &str,
        compute: impl FnOnce(&Entry) -> Result<String, FfiError>,
    ) -> Result<String, FfiError> {
        let id = parse_entry_id(id)?;
        let vault = self.lock();
        let entry = vault.vault().get(&id).ok_or(Error::VaultEntryNotFound)?;
        compute(entry)
    }
}

/// Opens a vault with the master key held by an [`FfiVault`].
///
/// # The return value is a byte string, not a printable short code
///
/// The recovery key file is designed so that a user can copy it onto paper or
/// into a QR code. It is **not** the master key: the master key inside it is
/// encrypted under a key derived from the user passphrase with Argon2id (see the
/// core `recovery` module). Returning `Vec<u8>` is therefore safe, but the host
/// side should still keep it out of logs and the clipboard history.
///
/// # Relation to [`FfiVault::export_recovery_key`]
///
/// Both do the same thing; only the source of the master key differs:
///
/// - [`FfiVault::export_recovery_key`]: the device is **already unlocked** and the
///   master key is on the Rust side. Prefer that path — the master key does not
///   cross the boundary at all.
/// - this function: the caller only holds master key bytes (for example just
///   obtained from [`FfiJoiner::complete`], before a vault exists). The master
///   key crosses the boundary once here.
#[uniffi::export]
pub fn export_recovery_key_from_master(
    master_key: Vec<u8>,
    passphrase: String,
    memory_kib: Option<u64>,
    iterations: Option<u64>,
    parallelism: Option<u64>,
) -> Result<Vec<u8>, FfiError> {
    check_len("passphrase", &passphrase, MAX_PASSPHRASE_CHARS)?;
    let params = kdf_params(memory_kib, iterations, parallelism)?;
    let master = flow::master_key_from_bytes(master_key.into())?;
    Ok(flow::export_recovery_key(
        &master,
        &SecretString::from(passphrase),
        Some(params),
    )?)
}

/// Recovers the master key from a recovery key file with a passphrase and
/// **writes it into the platform key store**.
///
/// The write goes through the core `SecureStore` abstraction, so this path and
/// login share the same ordering guarantees at the storage step.
///
/// Returns the 32 bytes of the master key. The host side either passes them to
/// [`FfiSecureStore::store_master_key`] or drops them, since this function has
/// already written the store once; building an [`FfiVault`] from the returned bytes
/// avoids a second key-store read, which is a hardware access that prompts for
/// biometrics on some platforms.
///
/// # Errors
///
/// A wrong passphrase returns [`Error::RecoveryAuthenticationFailed`] (`kind` is
/// `recovery_authentication_failed`); a malformed file returns
/// [`Error::RecoveryFileMalformed`]; out-of-range parameters return
/// [`Error::RecoveryParametersInvalid`].
///
/// **A wrong passphrase and a damaged file must be distinguished**: the first
/// asks the user to type it again, the second reports that the file is unusable.
#[uniffi::export]
pub fn import_recovery_key(
    file: Vec<u8>,
    passphrase: String,
    store: Arc<dyn FfiSecureStore>,
) -> Result<Vec<u8>, FfiError> {
    check_len("passphrase", &passphrase, MAX_PASSPHRASE_CHARS)?;
    let mut store = ForeignSecureStore(store);
    let master = flow::import_recovery_key(&file, &SecretString::from(passphrase), &mut store)?;
    Ok(flow::master_key_to_bytes(&master).expose_secret().to_vec())
}

/// Writes a master key into the platform key store.
///
/// For use by the host side after [`FfiJoiner::complete`], which returns master
/// key bytes and leaves the timing of the store write to the host side. This is
/// a separate step rather than something `complete` does itself, because
/// "login finished" and "key saved" are two actions in a user interface.
///
/// # Errors
///
/// Returns [`Error::MasterKeyWrongLength`] when the key length is not 32 bytes.
#[uniffi::export]
pub fn store_master_key(
    master_key: Vec<u8>,
    store: Arc<dyn FfiSecureStore>,
) -> Result<(), FfiError> {
    let master = flow::master_key_from_bytes(master_key.into())?;
    let mut store = ForeignSecureStore(store);
    store.store_master_key(&master)?;
    Ok(())
}

// ── Login: initiator and joiner ──────────────────────────────────────────

/// The initiator of a login: a device that is **already logged in** and holds
/// the master key.
///
/// It displays the QR code, receives the request and hands the master key to the
/// other device in encrypted form.
///
/// # One login serves exactly one request
///
/// The core enforces this with the **type system** (`authorize` consumes the
/// pending session), so a second call necessarily fails and the host side needs
/// no flag of its own. All the host side does is keep one QR code per
/// [`FfiLogin`] instance and drop it after a successful authorization.
///
/// # Replay protection across restarts
///
/// The core's `Login` guarantees single use within one process. Keeping replay
/// protection across application restarts would require persisting used session
/// identifiers and restoring them at the next login. **This layer does not expose
/// that path**: the core's `NonceLog` has no serialization entry point, so
/// cross-restart protection is presently unreachable.
///
/// That is not a gap for the current protocol: a pending session itself does not
/// survive a restart (it contains an ephemeral private key that the host side
/// cannot write to disk), so there is nothing to replay.
#[derive(uniffi::Object)]
pub struct FfiLogin {
    /// The core initiator state.
    inner: std::sync::Mutex<Login>,
}

#[uniffi::export]
impl FfiLogin {
    /// Starts a login and returns the text to display as a QR code.
    #[uniffi::constructor]
    pub fn begin() -> Result<Arc<Self>, FfiError> {
        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(Login::new()?),
        }))
    }

    /// The text to display as a QR code.
    ///
    /// This is the **only** channel that has to be shown to the other device. It
    /// contains no master key (see the module documentation of the core
    /// `pairing`), but it is the credential for this session, so it must not be
    /// sent to a chat log or shared as a screenshot.
    pub fn payload(&self) -> String {
        self.lock().payload().to_base32()
    }

    /// Accepts the request the other device sends after scanning the QR code and
    /// returns the reply bytes to send back.
    ///
    /// # Authorization is user confirmation
    ///
    /// The moment this function is called, the master key is encrypted and handed
    /// to the other device. The host side **must** therefore obtain user
    /// confirmation before calling it (for example by asking whether the user
    /// really started a login on a new device). The core cannot make that
    /// decision for the host side, and should not.
    ///
    /// # Errors
    ///
    /// A request that did not come from this session, tampered ciphertext, and a
    /// login that has already been authorized all return
    /// [`Error::PairingAuthenticationFailed`]. **The reason is deliberately not
    /// split further**, so that an attacker gains no oracle distinguishing "almost
    /// succeeded"; host-side text should stay generic as well.
    pub fn authorize(&self, vault: Arc<FfiVault>, msg1: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let vault = vault.lock();
        let mut login = self.lock();
        Ok(login.authorize(&msg1, vault.master_key())?)
    }

    /// The device identifier declared by the requester (a value exists only after
    /// a successful authorization).
    pub fn joiner_device_id(&self) -> Option<String> {
        self.lock().joiner_device().map(|id| id.to_hex())
    }
}

impl FfiLogin {
    /// Takes the lock, ignoring poisoning (see [`FfiVault::lock`]).
    fn lock(&self) -> std::sync::MutexGuard<'_, Login> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The joiner of a login: a new device that does not have the master key yet.
///
/// # The lifecycle is scan → request → reply → complete
///
/// The request must be issued and completed by the **same** object: the session
/// identifier is determined by this session's ephemeral key, so a different
/// object means a different session and the reply cannot be opened. The core
/// expresses this in the type system (`request` borrows `&self` instead of
/// consuming it, and only `complete` consumes), so as long as the host side does
/// not rebuild the object the behavior is right.
#[derive(uniffi::Object)]
pub struct FfiJoiner {
    /// The core joiner state.
    inner: std::sync::Mutex<Joiner>,
}

#[uniffi::export]
impl FfiJoiner {
    /// Establishes a session from the scanned QR code text. `label` is the label
    /// of this device's identity in the platform key store.
    ///
    /// This step does not send the request; the core keeps `new` and `request` as
    /// two steps and this layer keeps the same granularity. Sending the request
    /// needs the device identity, and obtaining it prompts for biometrics on some
    /// platforms, so the host side can tell the user that a local key is about to
    /// be created first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PairingPayloadMalformed`] when the text is not a valid QR
    /// payload. Note that "not a valid payload" and "valid payload but a
    /// mismatched session" are two different things; the latter only surfaces at
    /// [`FfiJoiner::complete`].
    #[uniffi::constructor]
    pub fn from_qr(text: String, label: String) -> Result<Arc<Self>, FfiError> {
        check_len("qr", &text, MAX_QR_TEXT_CHARS)?;
        check_len("label", &label, MAX_LABEL_CHARS)?;
        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(Joiner::from_base32(&text, &label)?),
        }))
    }

    /// The request bytes to send to the initiator. **Idempotent**: repeated calls
    /// return the same message and do not sign again.
    ///
    /// Signing again would produce a new session identifier and the initiator
    /// would no longer recognize it as the same login, so idempotence is a
    /// correctness requirement rather than an optimization.
    pub fn request(&self, keys: Arc<dyn FfiDeviceKeys>) -> Result<Vec<u8>, FfiError> {
        let mut keys = ForeignDeviceKeys(keys);
        let mut joiner = self.lock();
        Ok(joiner.request(&mut keys)?)
    }

    /// The device identity this device declares in this session (SEC1
    /// uncompressed encoding, 65 bytes).
    ///
    /// The initiator should display it together with
    /// [`FfiLogin::joiner_device_id`] for the user to confirm, so that the user
    /// can tell whether the requesting device is the expected one. Returns `None`
    /// after completion.
    #[must_use]
    pub fn identity(&self) -> Option<Vec<u8>> {
        self.lock().identity().map(|bytes| bytes.to_vec())
    }

    /// Completes the login with the initiator's reply: verifies the reply, takes
    /// out the master key and **writes it into the platform key store**.
    ///
    /// Returns the 32 bytes of the master key so that the host side can build an
    /// [`FfiVault`] right away with [`FfiVault::from_master_key`] instead of
    /// reading the key store again; every read is another hardware access that
    /// prompts for biometrics on some platforms.
    ///
    /// # This is where the reply is actually verified
    ///
    /// Decryption and authentication of the reply happen here, not in
    /// [`FfiJoiner::from_qr`]. A login failure is therefore only trustworthy from
    /// this function.
    ///
    /// # Single use
    ///
    /// The core's session is single use (`complete` takes it internally), so a
    /// second call returns [`Error::PairingAuthenticationFailed`] and **not** a
    /// different error from a forged reply. Reporting "already used" separately
    /// would tell an attacker that the replay was detected.
    ///
    /// # Errors
    ///
    /// A reply from another session, tampered ciphertext, an initiator using a
    /// different master key, and a completed login all return
    /// [`Error::PairingAuthenticationFailed`]. A failure to write the master key
    /// into the platform store returns [`Error::SecureStoreWriteFailed`]; in that
    /// case **the master key is left nowhere** and the host side should have the
    /// user log in again.
    pub fn complete(
        &self,
        msg2: Vec<u8>,
        keys: Arc<dyn FfiDeviceKeys>,
        store: Arc<dyn FfiSecureStore>,
    ) -> Result<Vec<u8>, FfiError> {
        let mut keys = ForeignDeviceKeys(keys);
        let mut store = ForeignSecureStore(store);
        let master = self.lock().complete(&msg2, &mut keys, &mut store)?;
        Ok(flow::master_key_to_bytes(&master).expose_secret().to_vec())
    }
}

impl FfiJoiner {
    /// Takes the lock, ignoring poisoning (see [`FfiVault::lock`]).
    fn lock(&self) -> std::sync::MutexGuard<'_, Joiner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

// ── Challenge-response: proving possession of the master key ─────────────
//
// This section has **three messages**, and their direction is the opposite of
// the usual "request/response":
//
// 1. verifier → responder: the challenge (`FfiVerifier::challenge` →
//    `FfiResponder::accept`)
// 2. responder → verifier: the response (`FfiResponder::respond` →
//    `FfiVerifier::verify`)
// 3. verifier → responder: the confirmation tag (`FfiVerifier::session_id` and
//    `FfiVerifier::confirmation` → `FfiResponder::confirm`)
//
// The third step is easy to omit, and it is the proof in the **opposite**
// direction: the responder uses it to confirm that the party answering really
// is the verifier that sent the challenge. With only the first two steps,
// anyone can send a challenge and then pretend to have verified it.

/// The verifier: confirms that the other side actually holds the master key.
///
/// # Where it is used
///
/// 1. **Confirming a successful unlock.** A version 2 vault file already tells
///    whether the master key is right (see [`FfiVault::open`]), so this path
///    mainly serves **old version 1 files** and the case of having only a master
///    key and no file yet.
/// 2. **Cross-device identity confirmation.** It does not depend on file
///    content, so it is the only proof available when the file is missing or
///    damaged.
///
/// # Difference from pairing
///
/// Pairing hands the master key to the other side; challenge-response proves
/// possession of the master key without handing it over. The former happens once
/// at login, the latter at any time. **Challenge-response is not login**: it
/// transfers no key.
#[derive(uniffi::Object)]
pub struct FfiVerifier {
    /// The core verifier state. `verify` consumes it, hence the `Option`.
    inner: std::sync::Mutex<Option<auth::Verifier>>,
    /// The challenge bytes to send in the first step.
    challenge: Vec<u8>,
    /// The session identifier computed after the second step, sent back to the
    /// other side in the third step.
    session_id: std::sync::Mutex<Option<[u8; AUTH_SESSION_ID_LEN]>>,
    /// The confirmation tag computed after the second step, sent back to the
    /// other side in the third step.
    confirmation: std::sync::Mutex<Option<[u8; AUTH_CONFIRM_LEN]>>,
}

#[uniffi::export]
impl FfiVerifier {
    /// Starts a challenge.
    #[uniffi::constructor]
    pub fn begin() -> Result<Arc<Self>, FfiError> {
        let (challenge, verifier) = auth::begin()?;
        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(Some(verifier)),
            challenge,
            session_id: std::sync::Mutex::new(None),
            confirmation: std::sync::Mutex::new(None),
        }))
    }

    /// The challenge bytes to send to the other side.
    #[must_use]
    pub fn challenge(&self) -> Vec<u8> {
        self.challenge.clone()
    }

    /// Verifies the other side's response and returns `true` on success.
    ///
    /// Failure returns [`Error::AuthProofFailed`] (`kind` is `auth_proof_failed`);
    /// **do not** read anything else into it: this error is produced only when a
    /// tag does not match.
    ///
    /// # Single use
    ///
    /// The challenge is single use (the core's `verify` consumes `self`). A
    /// repeated verification returns [`Error::AuthProofFailed`] — the same error
    /// as a forged response, for the reason given at [`FfiJoiner::complete`]: no
    /// distinguishing signal for a replayer.
    ///
    /// # The third step follows a success
    ///
    /// After receiving `true`, the host side must send
    /// [`FfiVerifier::session_id`] and [`FfiVerifier::confirmation`] back to the
    /// other side, which verifies them with [`FfiResponder::confirm`]. **Omitting
    /// the third step leaves the authentication half done**: the responder has no
    /// way to confirm that the party answering really is the verifier.
    pub fn verify(&self, response: Vec<u8>, vault: Arc<FfiVault>) -> Result<bool, FfiError> {
        let verifier = {
            let mut guard = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.take().ok_or(Error::AuthProofFailed)?
        };
        let vault = vault.lock();
        let verified = verifier.verify(&response, vault.master_key())?;
        *self
            .session_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(*verified.session_id());
        *self
            .confirmation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(verified.confirmation());
        Ok(true)
    }

    /// The session identifier to send back in the third step. `None` before a
    /// successful verification.
    #[must_use]
    pub fn session_id(&self) -> Option<Vec<u8>> {
        self.session_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map(|id| id.to_vec())
    }

    /// The confirmation tag to send back in the third step. `None` before a
    /// successful verification.
    #[must_use]
    pub fn confirmation(&self) -> Option<Vec<u8>> {
        self.confirmation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map(|tag| tag.to_vec())
    }
}

/// The responder: holds the master key and proves it to the verifier.
#[derive(uniffi::Object)]
pub struct FfiResponder {
    /// The core responder state.
    inner: std::sync::Mutex<auth::Responder>,
}

#[uniffi::export]
impl FfiResponder {
    /// Accepts a challenge sent by the other side.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthMessageMalformed`] when the challenge is malformed
    /// (length, version, or an ephemeral public key that is not on the curve).
    #[uniffi::constructor]
    pub fn accept(challenge: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(auth::accept(&challenge)?),
        }))
    }

    /// The device identity this device uses in this session (SEC1 uncompressed
    /// encoding, 65 bytes).
    #[must_use]
    pub fn identity(&self) -> Vec<u8> {
        self.lock().public_key().to_vec()
    }

    /// Produces the response to hand to the verifier.
    ///
    /// Signing goes through [`FfiDeviceKeys::sign`] and **receives the raw
    /// message**; the host-side implementation must not hash it first, since the
    /// core verifies with the standard ECDSA hash mode and hashing twice makes
    /// every verification fail.
    pub fn respond(
        &self,
        vault: Arc<FfiVault>,
        label: String,
        keys: Arc<dyn FfiDeviceKeys>,
    ) -> Result<Vec<u8>, FfiError> {
        check_len("label", &label, MAX_LABEL_CHARS)?;
        let vault = vault.lock();
        let responder = self.lock();
        let mut keys = ForeignDeviceKeys(keys);
        let device = keys.get_or_create(&label)?;
        let response =
            responder.respond(vault.master_key(), device.as_sec1_bytes(), |message| {
                keys.sign(&label, message)
            })?;
        Ok(response)
    }

    /// Verifies the confirmation tag sent back by the verifier (the third step).
    ///
    /// Returns `true` on success. **This step must not be skipped**: it proves
    /// that the other side can actually compute the session key rather than only
    /// forwarding a challenge.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthProofFailed`] when the tag does not match or the
    /// session identifier does not match, and [`Error::AuthMessageMalformed`]
    /// when the tag length is wrong.
    pub fn confirm(
        &self,
        vault: Arc<FfiVault>,
        session_id: Vec<u8>,
        confirmation: Vec<u8>,
    ) -> Result<bool, FfiError> {
        let session_id: [u8; AUTH_SESSION_ID_LEN] =
            session_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::AuthMessageMalformed {
                    reason: "wrong session identifier length",
                })?;
        let vault = vault.lock();
        let responder = self.lock();
        auth::confirm(vault.master_key(), &responder, &session_id, &confirmation)?;
        Ok(true)
    }
}

impl FfiResponder {
    /// Takes the lock, ignoring poisoning.
    fn lock(&self) -> std::sync::MutexGuard<'_, auth::Responder> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Builds [`KdfParams`] from the optional host-side values.
///
/// The values come from the host side (the user can adjust them in the user
/// interface) and, on import, from a file that is attacker controlled. The range
/// check lives in the core's `KdfParams::new`, which bounds both ends; this
/// function passes its error through rather than judging on its own, so there is a
/// single implementation of the check.
///
/// The host side passes `u64` rather than the core's `u32`: UniFFI maps `u32` to
/// an unsigned type on the Kotlin side, which Kotlin does not have natively. A
/// value above `u32` is rejected by the core's range check and is never silently
/// truncated.
fn kdf_params(
    memory_kib: Option<u64>,
    iterations: Option<u64>,
    parallelism: Option<u64>,
) -> Result<KdfParams, FfiError> {
    if memory_kib.is_none() && iterations.is_none() && parallelism.is_none() {
        return Ok(KdfParams::recommended());
    }
    let recommended = KdfParams::recommended();
    let narrow = |value: u64, what: &'static str| -> Result<u32, FfiError> {
        u32::try_from(value).map_err(|_| Error::RecoveryParametersInvalid { reason: what }.into())
    };
    Ok(KdfParams::new(
        narrow(
            memory_kib.unwrap_or(u64::from(recommended.memory_kib())),
            "memory limit is outside the representable range",
        )?,
        narrow(
            iterations.unwrap_or(u64::from(recommended.iterations())),
            "iteration count is outside the representable range",
        )?,
        narrow(
            parallelism.unwrap_or(u64::from(recommended.parallelism())),
            "parallelism is outside the representable range",
        )?,
    )?)
}

// ── Synchronization: the channel contract and one session ────────────────
//
// The core owns the protocol: which payload goes first, what a merge does, what a conflict
// means. This half only moves data across the boundary:
//
//   - the host side implements a channel (`FfiTransport`), which is where a real
//     transport lives (today the text/QR code channel, later a LAN one);
//   - `FfiSyncSession` drives one exchange against such a channel.
//
// Nothing here decides anything. A review of this section has one question: **has any
// protocol rule been copied in from the core?**

/// How many parties take part in one sync.
///
/// Mirrors [`qualia2fa_core::transport::Roster`]. The distinction has to be declared by
/// the channel rather than guessed by the caller: the same code is two-party over QR codes
/// and may be multi-party for the same use over a LAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiRoster {
    /// Exactly two parties. Transfer starts as soon as they connect.
    TwoParty,
    /// Three or more parties. The initiator decides when to start.
    MultiParty,
}

impl From<FfiRoster> for Roster {
    fn from(value: FfiRoster) -> Self {
        match value {
            FfiRoster::TwoParty => Self::TwoParty,
            FfiRoster::MultiParty => Self::MultiParty,
        }
    }
}

/// What a channel can do.
///
/// Mirrors [`qualia2fa_core::transport::TransportCapabilities`]; see it for the meaning of
/// each field. Two points matter at this boundary:
///
/// - **The values are a declaration, not a probe.** They must be available before the
///   exchange starts, so the caller can pick a mode before anything is displayed.
/// - **`max_message_len` is one message**, not one physical artifact: a channel that shows
///   several codes in sequence declares the sum over all of them, and how the bytes are cut
///   into frames is the channel's business.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiTransportCapabilities {
    /// Roster of this channel.
    pub roster: FfiRoster,
    /// Per-message byte limit; `None` means a byte stream with no limit.
    pub max_message_len: Option<u64>,
    /// Largest QR version this channel may display, if it displays codes.
    pub max_qr_version: Option<u8>,
    /// Whether this channel may be used only once (QR codes are).
    pub single_use: bool,
    /// Whether this channel can carry a whole payload, or only link establishment.
    pub can_carry_payload: bool,
}

impl From<FfiTransportCapabilities> for TransportCapabilities {
    fn from(value: FfiTransportCapabilities) -> Self {
        Self {
            roster: value.roster.into(),
            // A limit wider than this platform can address is treated as the largest one
            // it can: the direction is safe (a channel never gets a limit larger than it
            // declared) and the value is far beyond any real message.
            max_message_len: value
                .max_message_len
                .map(|len| usize::try_from(len).unwrap_or(usize::MAX)),
            max_qr_version: value.max_qr_version,
            single_use: value.single_use,
            can_carry_payload: value.can_carry_payload,
        }
    }
}

/// The recipient of one message.
///
/// Mirrors [`qualia2fa_core::transport::Recipient`]. The recipient is an explicit parameter
/// rather than left implicit: on a channel with several peers, "forward this to one peer"
/// and "broadcast" are two different actions.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiRecipient {
    /// Send to this peer only: a 64-character hexadecimal device identifier.
    One {
        /// Device identifier, hexadecimal.
        device_id: String,
    },
    /// Send to every peer of the current session.
    All,
}

impl TryFrom<FfiRecipient> for Recipient {
    type Error = FfiError;

    fn try_from(value: FfiRecipient) -> Result<Self, FfiError> {
        Ok(match value {
            FfiRecipient::One { device_id } => Self::One(parse_device_id(&device_id)?),
            FfiRecipient::All => Self::All,
        })
    }
}

/// One message taken off a channel, together with the sender the channel claims.
///
/// Mirrors the return value of [`qualia2fa_core::transport::Transport::receive`]. The
/// `sender` is the **channel's claim**, and the core compares it with the sender inside the
/// payload: the payload's own field proves only that nobody changed it, while "who actually
/// handed this over" is something only the channel knows.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiReceivedMessage {
    /// The sending device as the channel reports it, hexadecimal.
    pub sender: String,
    /// The message bytes.
    pub message: Vec<u8>,
}

/// A channel that can move sync payloads.
///
/// **Implemented by the host side**, and by this layer's own [`FfiLanChannel`]: a session
/// takes either and cannot tell them apart.
///
/// Corresponds to [`qualia2fa_core::transport::Transport`]. An implementation forwards to a
/// real transport, **with no decisions of its own**: every protocol rule (what the bytes
/// mean, whether a payload was already applied, whether a sender is acceptable) lives in the
/// core.
///
/// # Contract the implementation must satisfy
///
/// 1. **`receive` must report the sender truthfully**, not just hand back bytes. On a
///    broadcast channel any device can replay a payload someone else sent, so "the payload
///    says it is from B" and "C actually sent it" can hold at the same time. The core turns
///    the comparison into a hard check, so misreporting the sender only makes the sync fail.
/// 2. **`send` must respect [`FfiRecipient`]**; `One` must not degrade into a broadcast.
/// 3. **`receive` must not block indefinitely.** With no message available it returns
///    `Ok(None)`, which the core reports as "no session found"; how long to wait is the
///    host side's decision, because the core has no clock.
/// 4. **A `single_use` channel must fail its second use** with
///    [`FfiError::Qr`]`{ kind: "transport_already_used" }`.
/// 5. **Device identifiers are 64 hexadecimal characters**: the 32-byte device fingerprint
///    (`qualia_dik::DeviceId`), the same value the pairing flow shows as a device identity.
#[uniffi::export(with_foreign)]
pub trait FfiTransport: Send + Sync {
    /// What this channel can do.
    fn capabilities(&self) -> FfiTransportCapabilities;

    /// This device's identifier, hexadecimal.
    ///
    /// It fills in the `sender` of outgoing payloads, so both sides of an exchange agree on
    /// who sent what.
    fn local_device(&self) -> String;

    /// Sends one message.
    fn send(&self, to: FfiRecipient, message: Vec<u8>) -> Result<(), FfiError>;

    /// Takes one message off the channel.
    ///
    /// `Ok(None)` means "nothing available right now", which is a normal state and not an
    /// error; `Err` means the channel itself failed.
    fn receive(&self) -> Result<Option<FfiReceivedMessage>, FfiError>;

    /// Every peer in the current session.
    ///
    /// Zero or one element on a two-party channel. This defines what `All` means.
    fn peers(&self) -> Result<Vec<String>, FfiError>;
}

/// Forwarding implementation of the core `Transport`: bridges trait calls to the host-side
/// channel, after parsing this device's identifier **once** when the adapter is built.
///
/// Parsing up front is what makes it possible to satisfy the core trait at all: the core
/// asks for `local_device()` as a value that cannot fail, so an identifier that cannot be
/// parsed has to be reported before the session starts rather than in the middle of it.
struct ForeignTransport {
    /// The host-side channel.
    channel: Arc<dyn FfiTransport>,
    /// This device's identifier, parsed once.
    me: DeviceId,
}

impl ForeignTransport {
    /// Builds the adapter, rejecting an unparsable local device identifier.
    fn new(channel: Arc<dyn FfiTransport>) -> Result<Self, FfiError> {
        let me = parse_device_id(&channel.local_device())?;
        Ok(Self { channel, me })
    }
}

impl Transport for ForeignTransport {
    fn capabilities(&self) -> TransportCapabilities {
        self.channel.capabilities().into()
    }

    fn local_device(&self) -> DeviceId {
        self.me
    }

    fn send(&self, to: Recipient, message: &[u8]) -> Result<(), Error> {
        let to = match to {
            Recipient::One(id) => FfiRecipient::One {
                device_id: id.to_hex(),
            },
            Recipient::All => FfiRecipient::All,
        };
        self.channel
            .send(to, message.to_vec())
            .map_err(transport_error_to_core_error)
    }

    fn receive(&self) -> Result<(DeviceId, Vec<u8>), Error> {
        match self
            .channel
            .receive()
            .map_err(transport_error_to_core_error)?
        {
            Some(received) => {
                let sender =
                    parse_device_id(&received.sender).map_err(|_| Error::TransportFailed {
                        reason: "the channel reported a device identifier that is not hexadecimal",
                    })?;
                Ok((sender, received.message))
            }
            None => Err(Error::SyncNoSessionFound),
        }
    }

    fn peers(&self) -> Result<Vec<DeviceId>, Error> {
        self.channel
            .peers()
            .map_err(transport_error_to_core_error)?
            .iter()
            .map(|id| {
                parse_device_id(id).map_err(|_| Error::TransportFailed {
                    reason: "the channel reported a device identifier that is not hexadecimal",
                })
            })
            .collect()
    }
}

/// Parses a device identifier: exactly 64 hexadecimal characters.
///
/// The form is the one every other device identifier at this boundary uses (see
/// [`FfiTransport`] point 5), so a value taken from a pairing screen can be compared with
/// one from a sync payload without conversion.
fn parse_device_id(text: &str) -> Result<DeviceId, FfiError> {
    let invalid = || FfiError::InvalidDeviceId {
        kind: "device_id".to_owned(),
    };
    let bytes = text.as_bytes();
    if bytes.len() != DEVICE_ID_LEN * 2 {
        return Err(invalid());
    }

    let mut id = [0_u8; DEVICE_ID_LEN];
    for (index, slot) in id.iter_mut().enumerate() {
        let high = hex_digit(bytes[index * 2]).map_err(|_| invalid())?;
        let low = hex_digit(bytes[index * 2 + 1]).map_err(|_| invalid())?;
        *slot = (high << 4) | low;
    }
    Ok(DeviceId::from_bytes(id))
}

/// Converts a failure reported by a channel back into a core error.
///
/// A channel reports failures as [`FfiError::Qr`] (the host side's own) or [`FfiError::Lan`]
/// (this layer's), and both carry a stable `kind` (see [`FfiError::kind`]). Two of them have a
/// core equivalent the protocol reacts to, and they are the two where the reaction differs:
///
/// - `transport_already_used`: a one-shot channel was used twice.
/// - `sync_no_session_found`: nothing to receive. A channel that prefers `Ok(None)` for
///   that state never produces it, but one that carries the core's wording does.
///
/// Everything else becomes [`Error::TransportFailed`] with an opaque reason: the channel's
/// own message belongs to the channel and is not part of the protocol layer.
fn transport_error_to_core_error(source: FfiError) -> Error {
    match &source {
        FfiError::Qr { kind, .. } | FfiError::Lan { kind, .. }
            if kind == "transport_already_used" =>
        {
            Error::TransportAlreadyUsed
        }
        FfiError::Qr { kind, .. } | FfiError::Lan { kind, .. }
            if kind == "sync_no_session_found" =>
        {
            Error::SyncNoSessionFound
        }
        _ => Error::TransportFailed {
            reason: "the channel reported a failure",
        },
    }
}

/// What a payload asks the peer to do.
///
/// Mirrors [`qualia2fa_core::sync::PayloadKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiPayloadKind {
    /// The sender's full state: accept it and merge.
    Vault,
    /// A request: send me your full state.
    Request,
}

impl From<FfiPayloadKind> for PayloadKind {
    fn from(value: FfiPayloadKind) -> Self {
        match value {
            FfiPayloadKind::Vault => Self::Vault,
            FfiPayloadKind::Request => Self::Request,
        }
    }
}

/// Which route one share takes.
///
/// Mirrors [`qualia2fa_core::transport::SharePlan`]. "Does not fit" is a route, not a
/// failure: a request (which carries no records) goes out first and the payload is left to a
/// channel that can carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSharePlan {
    /// The whole payload fits this channel.
    FullPayload {
        /// Size in bytes after sealing.
        len: u64,
    },
    /// It does not fit: a link on another channel is needed first.
    LinkEstablishment {
        /// Number of bytes the payload needs.
        needed: u64,
        /// Largest number of bytes this channel can carry.
        limit: u64,
    },
}

impl From<SharePlan> for FfiSharePlan {
    fn from(value: SharePlan) -> Self {
        match value {
            SharePlan::FullPayload { len } => Self::FullPayload { len: len as u64 },
            SharePlan::LinkEstablishment { needed, limit } => Self::LinkEstablishment {
                needed: needed as u64,
                limit: limit as u64,
            },
        }
    }
}

// ── Importing another authenticator's export ─────────────────────────

/// An export format the host side can name.
///
/// [`detect_import_format`] answers the same question from the content, which is what a file
/// the user picked needs: the extension is a hint, not evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiImportFormat {
    /// The JSON export, plaintext or encrypted.
    Json,
    /// The HTML export: one table row per entry.
    Html,
    /// The text export: one URI per line.
    Text,
}

impl From<FfiImportFormat> for qualia2fa_core::import::ImportFormat {
    fn from(value: FfiImportFormat) -> Self {
        match value {
            FfiImportFormat::Json => Self::Json,
            FfiImportFormat::Html => Self::Html,
            FfiImportFormat::Text => Self::Text,
        }
    }
}

/// Names one field in which an imported entry differs from the one the vault holds.
///
/// # Stability contract
///
/// New values may be added; an existing one must not be renamed or change meaning, and a client
/// needs a fallback branch. Values: `name`, `issuer`, `account`, `note`, `algorithm`, `digits`,
/// `kind` (the kind carries the step, the counter and any PIN).
#[must_use]
fn import_difference_name(difference: ImportDifference) -> &'static str {
    match difference {
        ImportDifference::Name => "name",
        ImportDifference::Issuer => "issuer",
        ImportDifference::Account => "account",
        ImportDifference::Note => "note",
        ImportDifference::Algorithm => "algorithm",
        ImportDifference::Digits => "digits",
        ImportDifference::Kind => "kind",
    }
}

/// Formats a sixteen-byte identifier the way the host side names entries and groups.
#[must_use]
fn hex_id(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// One entry an export holds, as the preview shows it.
///
/// **No secret and no PIN cross here.** The preview answers "what is in this file?", and a name, a
/// service, an account and the shape of the code answer it; the key material stays in Rust, where
/// applying the import reads it again.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiImportedEntry {
    /// Where the entry was in the export, counting from 1.
    ///
    /// This is the handle a decision names: positions are unique within one export, and the entry
    /// has no identifier yet.
    pub position: u64,
    /// Display name.
    pub name: String,
    /// Issuer (service name), if any.
    pub issuer: Option<String>,
    /// Account name.
    pub account: String,
    /// Hash algorithm the code uses.
    pub algorithm: FfiAlgorithm,
    /// Number of digits in the code.
    pub digits: FfiDigits,
    /// The kind, without the PIN (see [`FfiEntryKind`]).
    pub kind: FfiEntryKind,
    /// Whether the export marked it a favourite.
    ///
    /// Not a field of the entry: an import turns it into **order**, placing favourites before the
    /// rest within their group.
    pub favorite: bool,
    /// Whether the export carried an icon, which this version drops.
    pub icon_dropped: bool,
    /// Whether the time step had to be assumed, because the format does not carry one.
    pub period_assumed: bool,
}

/// One entry of an export that could not be read.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiImportProblem {
    /// Where in the export it was, counting from 1.
    pub position: u64,
    /// Why it was skipped, in a phrase meant for the user.
    ///
    /// Never carries a value from the file: a problem list ends up in logs and screenshots.
    pub reason: String,
}

/// A group the export defined.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiImportedGroup {
    /// The group's identifier, 32 hexadecimal characters, the same on every device that imports
    /// this file.
    pub id: String,
    /// The name the export gave it.
    pub name: String,
}

/// What was dropped or assumed across a whole export.
///
/// Counts rather than a list: the interface says this once, in one sentence, instead of
/// interrupting per entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiDroppedSummary {
    /// Entries whose icon was dropped.
    pub icons: u64,
    /// Entries whose time step was assumed.
    pub periods_assumed: u64,
    /// Entries skipped because the same export listed them twice.
    pub duplicates: u64,
}

/// What the vault already holds that relates to one imported entry.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiImportMatch {
    /// Where the entry was in the export, counting from 1.
    pub position: u64,
    /// Whether the vault already holds this entry, in every field the user can see.
    pub identical: bool,
    /// Entries in the vault that use the same secret, as 32 hexadecimal characters each.
    pub existing: Vec<String>,
    /// The fields that differ from the closest match, as stable names.
    ///
    /// # Stability contract
    ///
    /// New values may be added; an existing one must not be renamed or change meaning, and a
    /// client needs a fallback branch. Values: `name`, `issuer`, `account`, `note`, `algorithm`,
    /// `digits`, `kind` (the kind carries the step, the counter and any PIN).
    pub differences: Vec<String>,
}

/// What to do with one imported entry.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiImportDecision {
    /// Add it, leaving whatever the vault holds alone.
    Add,
    /// Change nothing: the vault already holds it.
    Skip,
    /// Put the imported version in place of the entry with this identifier.
    ///
    /// The identifier stays, so the entry keeps its group and its place in the ordering.
    Replace {
        /// The entry to replace, as 32 hexadecimal characters.
        entry_id: String,
    },
    /// Add it and keep the existing entry as well.
    KeepBoth,
}

/// One answer, keyed by the position the entry had in the export.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiImportChoice {
    /// The position of the entry this answer is about.
    pub position: u64,
    /// What to do with it.
    pub decision: FfiImportDecision,
}

/// What an applied import did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiImportApplied {
    /// Entries added.
    pub added: u64,
    /// Entries whose content was replaced.
    pub replaced: u64,
    /// Entries left alone because the vault already held them.
    pub skipped: u64,
    /// Groups created from the export, as 32 hexadecimal characters each.
    pub groups_created: Vec<String>,
    /// Groups the export named that the vault already had.
    pub groups_existing: Vec<String>,
}

/// One export, read and waiting for a decision.
///
/// The parsed export lives here, in Rust, **with its secrets**: the preview the host side sees
/// holds none of them, and applying the import reads them from this object rather than from a
/// second copy the host would have to keep.
#[derive(uniffi::Object)]
pub struct FfiImport {
    /// The parsed export.
    report: qualia2fa_core::import::ImportReport,
}

#[uniffi::export]
impl FfiImport {
    /// Reads an export without touching a vault.
    ///
    /// `password` is only looked at when the export is encrypted; `now` is the current Unix second
    /// supplied by the host side (this library reads no clock) and becomes the creation and
    /// modification time of every imported entry.
    ///
    /// # Errors
    ///
    /// A file-level failure: not the format it claims to be, larger than this layer reads, a
    /// version it does not read, or a password it needs or does not accept. An entry that cannot
    /// be read is **not** such a failure: it appears in [`FfiImport::problems`] and the rest of
    /// the file is imported.
    #[uniffi::constructor]
    pub fn preview(
        bytes: Vec<u8>,
        format: FfiImportFormat,
        password: Option<String>,
        now: u64,
    ) -> Result<Arc<Self>, FfiError> {
        flow::check_now(now)?;
        let report = qualia2fa_core::import::import(
            &bytes,
            format.into(),
            now,
            password.as_ref().map(String::as_bytes),
        )?;
        Ok(Arc::new(Self { report }))
    }

    /// The entries that could be read, in the order the export listed them.
    #[must_use]
    pub fn entries(&self) -> Vec<FfiImportedEntry> {
        self.report
            .entries
            .iter()
            .map(|imported| FfiImportedEntry {
                position: imported.position as u64,
                name: imported.entry.name.clone(),
                issuer: imported.entry.issuer.clone(),
                account: imported.entry.account.clone(),
                algorithm: match imported.entry.algorithm {
                    Algorithm::Sha1 => FfiAlgorithm::Sha1,
                    Algorithm::Sha256 => FfiAlgorithm::Sha256,
                    Algorithm::Sha512 => FfiAlgorithm::Sha512,
                },
                digits: imported.entry.digits.into(),
                kind: FfiEntryKind::from_core(&imported.entry.kind),
                favorite: imported.favorite,
                icon_dropped: imported
                    .notes
                    .contains(&qualia2fa_core::import::ImportNote::IconDropped),
                period_assumed: imported.notes.iter().any(|note| {
                    matches!(
                        note,
                        qualia2fa_core::import::ImportNote::PeriodAssumed { .. }
                    )
                }),
            })
            .collect()
    }

    /// The entries that could not be read, each with its position and a reason.
    #[must_use]
    pub fn problems(&self) -> Vec<FfiImportProblem> {
        self.report
            .problems
            .iter()
            .map(|problem| FfiImportProblem {
                position: problem.position as u64,
                reason: problem.reason.clone(),
            })
            .collect()
    }

    /// The groups the export defined.
    #[must_use]
    pub fn groups(&self) -> Vec<FfiImportedGroup> {
        self.report
            .groups
            .iter()
            .map(|group| FfiImportedGroup {
                id: hex_id(group.id.as_bytes()),
                name: group.name.clone(),
            })
            .collect()
    }

    /// What was dropped or assumed across the whole export.
    #[must_use]
    pub fn dropped(&self) -> FfiDroppedSummary {
        FfiDroppedSummary {
            icons: self.report.dropped.icons as u64,
            periods_assumed: self.report.dropped.periods_assumed as u64,
            duplicates: self.report.dropped.duplicates as u64,
        }
    }

    /// Compares every entry against a vault.
    ///
    /// The result is in the order of [`FfiImport::entries`]. An entry that is `identical` should
    /// be skipped without asking; one that is not, but has entries in `existing`, is the question
    /// the user answers with [`FfiImportChoice`].
    #[must_use]
    pub fn compare(&self, vault: Arc<FfiVault>) -> Vec<FfiImportMatch> {
        let vault = vault.lock();
        qualia2fa_core::import::apply::compare(&self.report, vault.vault())
            .into_iter()
            .map(|found| FfiImportMatch {
                position: found.position as u64,
                identical: found.identical,
                existing: found.existing.iter().map(ToString::to_string).collect(),
                differences: found
                    .differences
                    .into_iter()
                    .map(|difference| import_difference_name(difference).to_owned())
                    .collect(),
            })
            .collect()
    }

    /// Applies the import to a vault.
    ///
    /// `choices` holds the answers for the entries the user was asked about; an entry with no
    /// answer is added, unless the vault already holds it exactly, in which case it is skipped.
    /// **Nothing is ever overwritten without an answer.**
    ///
    /// # Errors
    ///
    /// The core's error when an answer names an entry the vault no longer holds
    /// (`vault_entry_not_found`), and its errors for a name that is too long or an identifier that
    /// is taken.
    pub fn apply(
        &self,
        vault: Arc<FfiVault>,
        choices: Vec<FfiImportChoice>,
    ) -> Result<FfiImportApplied, FfiError> {
        let mut answers: HashMap<usize, ImportChoice> = HashMap::new();
        for choice in choices {
            let decision = match choice.decision {
                FfiImportDecision::Add => ImportChoice::Add,
                FfiImportDecision::Skip => ImportChoice::Skip,
                FfiImportDecision::KeepBoth => ImportChoice::KeepBoth,
                FfiImportDecision::Replace { entry_id } => {
                    ImportChoice::Replace(parse_entry_id(&entry_id)?)
                }
            };
            answers.insert(choice.position as usize, decision);
        }

        let mut vault = vault.lock();
        let applied =
            qualia2fa_core::import::apply::apply(vault.vault_mut(), &self.report, &answers)?;
        Ok(FfiImportApplied {
            added: applied.added.len() as u64,
            replaced: applied.replaced.len() as u64,
            skipped: applied.skipped as u64,
            groups_created: applied
                .groups_created
                .iter()
                .map(|id| hex_id(id.as_bytes()))
                .collect(),
            groups_existing: applied
                .groups_existing
                .iter()
                .map(|id| hex_id(id.as_bytes()))
                .collect(),
        })
    }
}

/// Guesses the format of an export from its content.
///
/// Returns `None` when it is not recognisable; the host side should then ask the user, which costs
/// one question and avoids reading a file as the wrong format.
///
/// A **free function** rather than a method on [`FfiImport`]: it answers a question about some
/// bytes rather than building the object, and UniFFI 0.29 exports neither an associated function
/// nor a constructor that returns something other than `Self`.
#[uniffi::export]
#[must_use]
pub fn detect_import_format(bytes: Vec<u8>) -> Option<FfiImportFormat> {
    match qualia2fa_core::import::ImportFormat::detect(&bytes)? {
        qualia2fa_core::import::ImportFormat::Json => Some(FfiImportFormat::Json),
        qualia2fa_core::import::ImportFormat::Html => Some(FfiImportFormat::Html),
        qualia2fa_core::import::ImportFormat::Text => Some(FfiImportFormat::Text),
    }
}
// ── Writing an export ────────────────────────────────────────────────

/// An export format the host side can choose.
///
/// The six are the interface's numbered choices, in the order the interface offers them: the two
/// `.q2fa` containers first, then the four shapes another authenticator reads.
///
/// # They are not equally safe, and not equally complete
///
/// Only the two encrypted forms protect anything. The plain vault container is the format that
/// restores an account on a clean device, and it does so because the **master key is inside it in
/// clear** - the interface has to say that more strongly than it says anything about the other
/// files. [`FfiExportFormat::EncryptedVault`] and [`FfiExportFormat::EncryptedJson`] ask for a
/// password; the other four hold every secret as it stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiExportFormat {
    /// A plain `.q2fa`: the master key in clear plus the whole vault ciphertext.
    Vault,
    /// A passphrase-protected `.q2fa`: the master key wrapped by the core recovery format.
    EncryptedVault,
    /// One `otpauth://` URI per line. Carries no name, no note and no group.
    Text,
    /// The JSON export: every field, the flat groups and the icons included.
    Json,
    /// The JSON export, locked with a password.
    EncryptedJson,
    /// The HTML export: a table with a QR code drawn for every entry.
    ///
    /// The code is what makes this format usable one account at a time, and it is also why the
    /// file is as sensitive as the vault: each code holds an entry's URI with its secret.
    Html,
}

impl From<FfiExportFormat> for qualia2fa_core::export::ExportFormat {
    fn from(value: FfiExportFormat) -> Self {
        match value {
            FfiExportFormat::Vault => Self::Vault,
            FfiExportFormat::EncryptedVault => Self::EncryptedVault,
            FfiExportFormat::Text => Self::Text,
            FfiExportFormat::Json => Self::Json,
            FfiExportFormat::EncryptedJson => Self::EncryptedJson,
            FfiExportFormat::Html => Self::Html,
        }
    }
}

/// How much of the group tree an export format carries.
///
/// A boolean would be a lie for the JSON forms: they keep the group **names and memberships** and
/// lose the nesting, and the interface must be able to say which it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiGroupCarrying {
    /// The format has nowhere to put a group.
    None,
    /// The format keeps the named groups as one flat level, without the nesting.
    FlatGroups,
    /// The format keeps the whole tree: parents, nesting and the mixed order.
    FullTree,
}

impl From<qualia2fa_core::export::GroupCarrying> for FfiGroupCarrying {
    fn from(value: qualia2fa_core::export::GroupCarrying) -> Self {
        match value {
            qualia2fa_core::export::GroupCarrying::None => Self::None,
            qualia2fa_core::export::GroupCarrying::FlatGroups => Self::FlatGroups,
            qualia2fa_core::export::GroupCarrying::FullTree => Self::FullTree,
        }
    }
}

/// Whether this format is written with a password.
///
/// Asked **before** the file is named, so that the password question appears where it belongs
/// instead of being discovered from an error after the user has chosen a location.
#[uniffi::export]
#[must_use]
pub fn export_format_needs_password(format: FfiExportFormat) -> bool {
    qualia2fa_core::export::ExportFormat::from(format).needs_password()
}

/// The file name extension for this format, without the dot.
///
/// Both JSON forms share one, and so do both `.q2fa` forms: they are the same file with and
/// without a password, and a reader tells them apart by the magic or by the `db` field.
#[uniffi::export]
#[must_use]
pub fn export_format_extension(format: FfiExportFormat) -> String {
    qualia2fa_core::export::ExportFormat::from(format)
        .extension()
        .to_owned()
}

/// Whether this format carries the groups **at all**.
///
/// Kept for callers that only need "does it keep my groups"; the interface should prefer
/// [`export_format_group_carrying`], which tells the flat JSON forms apart from the two `.q2fa`
/// containers.
#[uniffi::export]
#[must_use]
pub fn export_format_carries_groups(format: FfiExportFormat) -> bool {
    qualia2fa_core::export::ExportFormat::from(format).carries_groups()
}

/// How much of the group tree this format carries.
#[uniffi::export]
#[must_use]
pub fn export_format_group_carrying(format: FfiExportFormat) -> FfiGroupCarrying {
    qualia2fa_core::export::ExportFormat::from(format)
        .group_carrying()
        .into()
}

/// The deepest a named group may be nested; the top group is depth zero.
///
/// The interface uses it to refuse a drop it cannot draw, and the vault enforces the same value.
#[uniffi::export]
#[must_use]
pub fn max_group_depth() -> u64 {
    u64::try_from(qualia2fa_core::vault::Vault::MAX_GROUP_DEPTH).unwrap_or(u64::MAX)
}

// ── Portable vault files ─────────────────────────────────────────────

/// What a `.q2fa` file turned out to be, judged by its magic.
///
/// # It says nothing about the contents
///
/// A file can carry the right magic and still be damaged, and the encrypted form still needs its
/// passphrase. What this answers is what the **interface** needs before it asks anything: whether
/// to show a password field, whether the file is a full backup, or whether it is the old key-only
/// shape that can only reopen a vault this device already has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiPortableKind {
    /// The master key in clear plus the vault ciphertext.
    PlainVault,
    /// The passphrase-wrapped master key plus the vault ciphertext.
    EncryptedVault,
    /// The old key-only recovery file: no entries of its own.
    KeyOnly,
}

impl From<qualia2fa_core::portable::PortableKind> for FfiPortableKind {
    fn from(value: qualia2fa_core::portable::PortableKind) -> Self {
        match value {
            qualia2fa_core::portable::PortableKind::PlainVault => Self::PlainVault,
            qualia2fa_core::portable::PortableKind::EncryptedVault => Self::EncryptedVault,
            qualia2fa_core::portable::PortableKind::KeyOnly => Self::KeyOnly,
        }
    }
}

/// Recognizes a portable vault file without opening it.
///
/// `None` means the file is not one of the three portable shapes. In particular a **bare vault
/// file** (`Q2FAVLT\0`) answers `None`: it holds ciphertext but no master key, and the interface
/// should tell the user to export a vault backup instead of trying to import it.
#[uniffi::export]
#[must_use]
pub fn detect_portable_file(file: Vec<u8>) -> Option<FfiPortableKind> {
    qualia2fa_core::portable::detect(&file).map(FfiPortableKind::from)
}

/// What opening a portable vault file produced.
///
/// The two cases are kept apart rather than folded into "a vault or an error": an old key-only
/// file is a legitimate file, and the reason it cannot restore an account on its own is a
/// property of the file, not a failure.
#[derive(uniffi::Record)]
pub struct FfiPortableRestore {
    /// The restored vault, when the file carried one. Its master key is already stored.
    pub vault: Option<Arc<FfiVault>>,
    /// Whether the file was an old key-only recovery file.
    ///
    /// Nothing was written in that case. A caller that has a local vault may retry with
    /// [`import_recovery_key`] and open that vault with the restored key.
    pub key_only: bool,
}

/// Restores an account from a portable `.q2fa` file.
///
/// # What it does
///
/// Splits the container, recovers the master key (from the file itself for the plain form, from
/// the passphrase for the encrypted one), **writes the key into the platform store**, and opens
/// the vault the container carries. If the vault does not open, the previous key is put back
/// before the error is returned: a damaged or mismatched file must not leave the device on a key
/// that opens nothing.
///
/// # Errors
///
/// - `portable_vault_file_without_key`: the file is a bare vault file.
/// - `portable_password_required`: the encrypted form was opened with no password.
/// - `portable_bad_magic`, `portable_unsupported_version`, `portable_truncated`,
///   `portable_length_mismatch`, `portable_too_large`: the container is malformed.
/// - `recovery_authentication_failed`: the passphrase is wrong, or the wrapped part was modified.
/// - `vault_decryption_failed`: the key does not open the vault the file carries; the previous
///   key has been put back.
#[uniffi::export]
pub fn open_portable_file(
    file: Vec<u8>,
    password: Option<String>,
    store: Arc<dyn FfiSecureStore>,
) -> Result<FfiPortableRestore, FfiError> {
    if let Some(password) = &password {
        check_len("passphrase", password, MAX_PASSPHRASE_CHARS)?;
    }
    let passphrase = SecretString::from(password.unwrap_or_default());
    let mut store = ForeignSecureStore(store);
    match flow::open_portable(&file, &passphrase, &mut store)? {
        flow::PortableRestore::Vault(vault_file) => Ok(FfiPortableRestore {
            vault: Some(FfiVault::wrap(vault_file)),
            key_only: false,
        }),
        flow::PortableRestore::KeyOnly => Ok(FfiPortableRestore {
            vault: None,
            key_only: true,
        }),
    }
}

#[uniffi::export]
impl FfiVault {
    /// Writes the whole vault out in one of the export formats.
    ///
    /// The bytes are returned rather than written anywhere: this library does no I/O, so where
    /// the file goes is the host side's decision (the platform's own save dialog).
    ///
    /// # What crosses the boundary
    ///
    /// For [`FfiExportFormat::Vault`], **the master key in clear** beside the vault ciphertext:
    /// that is what lets the file restore an account on a clean device, and it is why the
    /// interface must warn more strongly about it than about the four formats another
    /// authenticator reads. [`FfiExportFormat::EncryptedVault`] is the same pair with the master
    /// key wrapped by a passphrase. The three plaintext external formats hold every secret in
    /// the vault as it stands; only the two encrypted forms protect anything, and an empty
    /// password is refused rather than accepted.
    ///
    /// # The lock is held for the whole call
    ///
    /// Deliberately, and unlike the entry methods: an export reads the entire vault, so it needs
    /// one consistent view of it, and releasing the lock would mean copying the vault first -
    /// a second copy of every secret in memory for as long as that copy lives. The cost is that
    /// a concurrent refresh waits, and a user who has just asked for an export is not editing
    /// entries at that moment.
    ///
    /// # Errors
    ///
    /// The core's kind reaches the host side: `export_password_required` when either encrypted
    /// form was chosen with no password, `export_password_empty`, `uri_account_contains_colon`
    /// when an entry's account cannot be written into a URI, `export_qr_too_long` when one
    /// entry's URI does not fit the QR code of the HTML export, `export_too_large` when the
    /// vault does not fit a `.q2fa` container, and `randomness_unavailable` when the OS random
    /// source is unavailable (the salt, the nonces and the master key come from it).
    pub fn export(
        &self,
        format: FfiExportFormat,
        password: Option<String>,
    ) -> Result<Vec<u8>, FfiError> {
        let password = password.map(String::into_bytes);
        let vault = self.lock();
        let bytes = qualia2fa_core::export::export(&vault, format.into(), password.as_deref())?;
        Ok(bytes)
    }
}

/// What the user decided about one conflict.
///
/// Mirrors [`qualia2fa_core::sync::Decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDecision {
    /// Keep the state of this device; the peer's version is discarded.
    KeepLocal,
    /// Take the peer's version, discarding the state of this device.
    TakeIncoming,
}

impl From<FfiDecision> for Decision {
    fn from(value: FfiDecision) -> Self {
        match value {
            FfiDecision::KeepLocal => Self::KeepLocal,
            FfiDecision::TakeIncoming => Self::TakeIncoming,
        }
    }
}

/// One side of a conflict, as far as it can be shown.
///
/// **No secret crosses here.** A conflict is displayed so the user can tell two versions
/// apart, and a name, a service, an account and a note are what that needs; the seed would
/// only add a second copy of key material in the host process, where it cannot be erased.
/// The decision itself is applied inside Rust, from the copy the conflict already holds.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiConflictSide {
    /// Display name.
    pub name: String,
    /// Issuer (service name), if any.
    pub issuer: Option<String>,
    /// Account name.
    pub account: String,
    /// Note.
    pub note: String,
    /// Last modification time of this version (Unix seconds, from the device that wrote it).
    pub updated_at: u64,
}

impl FfiConflictSide {
    /// Reads the displayable fields of one entry.
    fn from_entry(entry: &Entry) -> Self {
        Self {
            name: entry.name.clone(),
            issuer: entry.issuer.clone(),
            account: entry.account.clone(),
            note: entry.note.clone(),
            updated_at: entry.updated_at,
        }
    }
}

/// Two arrangements of the same group, for the user to choose between.
///
/// A group is a **sequence**, so two devices can disagree about it without disagreeing about a
/// single entry: each added its own children, or one reordered what both have. Neither side is
/// wrong, which is why this is the user's choice and not a merge rule.
///
/// The two lists hold the whole child arrangement - entries and child groups mixed - in display
/// order. A reference the vault does not hold is one the peer knows and this device does not; the
/// host side can look up the names of the rest in its own group list. The identifiers are the
/// same on both sides for every child both devices hold, so what is being chosen is an
/// **arrangement**, not a set.
///
/// # Moving a group can produce two of these
///
/// Moving a group between parents rewrites the old parent's list and the new parent's list, and
/// each is a separate record, so each can be reported. They are independent conflicts about two
/// different groups; applying either answer keeps the tree valid, because a child has only one
/// parent.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiOrderingConflict {
    /// The group's name on this device.
    pub local_name: String,
    /// The group's name on the peer, which differs when the disagreement is a rename.
    pub incoming_name: String,
    /// Whether this is the top group, which entries belong to when they belong to no named one.
    ///
    /// Such a group has no name, and the two name fields are empty.
    pub top: bool,
    /// This device's arrangement, in order.
    pub local: Vec<FfiGroupChild>,
    /// The peer's arrangement, in order.
    pub incoming: Vec<FfiGroupChild>,
}

/// One disagreement a human has to settle.
///
/// The fields are **normalized**, which is not how the core stores them: there,
/// `DeletionConflict` keeps the peer's record in one field and the local tombstone in
/// another, because that is what has to be written back. Here:
///
/// - `local` is the live entry **this device** holds, if it holds one;
/// - `incoming` is the live entry the **peer** sent, if it sent one.
///
/// A tombstone has nothing to display, so the side that deleted is `None`. Which side
/// deleted is what `kind` says.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiConflict {
    /// The entry in disagreement, as 32 hexadecimal characters.
    pub entry_id: String,
    /// Stable identifier of the shape; see [`conflict_kind`].
    pub kind: String,
    /// The local version, when this device holds a live entry.
    pub local: Option<FfiConflictSide>,
    /// The peer's version, when the peer sent a live entry.
    pub incoming: Option<FfiConflictSide>,
    /// Whether the local version is the later one.
    ///
    /// A **hint for the user interface**, not a basis for a decision: the peer fills in its
    /// own timestamps. The core never picks a side from it, and neither does the host side.
    pub local_is_newer: bool,
    /// The two arrangements in disagreement, when the conflict is about one.
    ///
    /// When this is `Some`, the two sides above are `None` and `entry_id` is a **group**
    /// identifier rather than an entry one: that is the identifier the decision names. The core
    /// reuses one field for both because a decision about an ordering is a decision about a
    /// whole group, and the conflict carries whichever identifier the decision needs.
    pub ordering: Option<FfiOrderingConflict>,
}

impl FfiConflict {
    /// Converts one conflict for display, normalizing the two sides.
    ///
    /// The local side of `peer_deleted` is **read from the vault** rather than taken from
    /// the conflict: the core leaves it out on purpose (it is already stored, and copying
    /// it would duplicate key material for a screen that only shows names), so the vault is
    /// where that version lives.
    fn from_core(conflict: &Conflict, vault: &Vault) -> Self {
        let mut ordering = None;
        let (local, incoming, local_is_newer) = match &conflict.kind {
            ConflictKind::OrderingMismatch { local, incoming } => {
                ordering = Some(FfiOrderingConflict {
                    local_name: local.name.clone(),
                    incoming_name: incoming.name.clone(),
                    top: conflict.group_id().is_some_and(|id| id.is_top()),
                    local: local
                        .children
                        .iter()
                        .map(FfiGroupChild::from_core)
                        .collect(),
                    incoming: incoming
                        .children
                        .iter()
                        .map(FfiGroupChild::from_core)
                        .collect(),
                });
                (None, None, false)
            }
            ConflictKind::EntryMismatch { local, incoming } => (
                Some(FfiConflictSide::from_entry(local)),
                Some(FfiConflictSide::from_entry(incoming)),
                false,
            ),
            ConflictKind::DeletionConflict {
                local,
                local_is_newer,
                ..
            } => (
                vault
                    .get(&conflict.entry_id)
                    .map(FfiConflictSide::from_entry),
                local
                    .as_ref()
                    .map(|entry| FfiConflictSide::from_entry(entry)),
                *local_is_newer,
            ),
        };
        Self {
            entry_id: conflict.entry_id.to_string(),
            kind: conflict_kind(conflict).to_owned(),
            local,
            incoming,
            local_is_newer,
            ordering,
        }
    }
}

/// Names the shape of a conflict, in the form the host side branches on.
///
/// # Stability contract
///
/// These strings are part of the public interface: new values may be added, but an existing
/// one must not be renamed or change meaning. A client must have a fallback branch for
/// values it does not know, because a newer library may report a shape it has never seen.
///
/// | value | meaning | deciding |
/// |---|---|---|
/// | `entry_mismatch` | both sides hold a live entry with different content | either version |
/// | `peer_deleted` | the peer reports a deletion; this device holds a newer entry | keep the entry, or accept the deletion |
/// | `local_deleted` | this device reports a deletion; the peer still holds an entry | keep it deleted, or restore the peer's entry |
/// | `ordering_mismatch` | both devices arranged a group, differently | this device's arrangement, or the peer's |
#[must_use]
pub fn conflict_kind(conflict: &Conflict) -> &'static str {
    match &conflict.kind {
        ConflictKind::EntryMismatch { .. } => "entry_mismatch",
        ConflictKind::DeletionConflict { local: None, .. } => "peer_deleted",
        ConflictKind::DeletionConflict { local: Some(_), .. } => "local_deleted",
        ConflictKind::OrderingMismatch { .. } => "ordering_mismatch",
    }
}

/// The result of one receive.
///
/// Mirrors [`qualia2fa_core::transport::SyncOutcome`], with the counters as plain numbers so
/// the host side can summarize a sync without looking at the conflicts.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSyncOutcome {
    /// Identifier of the payload just processed, hexadecimal.
    pub sync_id: String,
    /// Number of entries added.
    pub added: u64,
    /// Number of tombstones added.
    pub tombstones_added: u64,
    /// Number of deletions applied.
    pub deletions_applied: u64,
    /// Number of records whose content was already identical.
    pub unchanged: u64,
    /// Whether this sync changed nothing at all.
    ///
    /// Reported by the core rather than computed here: "nothing changed" and "everything
    /// was already there" are one condition, and assembling it at a second place is how the
    /// two stop agreeing.
    pub made_no_change: bool,
    /// Whether conflicts are waiting for a decision.
    pub needs_adjudication: bool,
    /// The conflicts themselves, to show the user.
    pub conflicts: Vec<FfiConflict>,
}

/// One synchronization session against one channel.
///
/// # It borrows the vault, so the vault must not be reassigned while it is used
///
/// The session works on the [`FfiVault`] object it was opened with. The host side keeps that
/// object alive; the merge writes into it, and the host side **must persist it afterwards**
/// ([`FfiVault::serialize`]) or the merged records are lost when the process ends.
///
/// # The replay log lives in this object
///
/// The core keeps a log of processed payload identifiers so that the same payload is not
/// decrypted and merged again. It is not persisted, for the same reason the pairing session
/// is not: a log written to disk is another store to keep in step with the vault, and the
/// code channel is out-of-band and one-shot, so the practical exposure is a user who
/// re-applies a code they already applied — which merges to the same content. A long-lived
/// broadcast channel (a LAN) will need the log to survive a restart, and that is the point
/// at which it becomes worth persisting.
///
/// # Only one exchange at a time
///
/// A session accepts payloads from **any** peer: the channel it is used with has confirmed
/// the peer out of band (the user carried the code). A channel that carries several peers
/// has to restrict them instead, and that entry point is not exposed yet, because no such
/// channel exists.
#[derive(uniffi::Object)]
pub struct FfiSyncSession {
    /// The vault being synchronized: master key and records both stay on this side.
    vault: Arc<FfiVault>,
    /// Identifiers of the payloads already processed.
    seen: std::sync::Mutex<SeenSyncIds>,
    /// Conflicts of the last receive that are waiting for a decision.
    pending: std::sync::Mutex<Vec<Conflict>>,
}

#[uniffi::export]
impl FfiSyncSession {
    /// Opens a session on an unlocked vault.
    #[uniffi::constructor]
    pub fn open(vault: Arc<FfiVault>) -> Arc<Self> {
        Arc::new(Self {
            vault,
            seen: std::sync::Mutex::new(SeenSyncIds::new()),
            pending: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Asks which route sharing this vault's state takes on `transport`.
    ///
    /// Sends nothing and displays nothing: the answer is needed **before** a code is shown,
    /// and [`FfiSyncSession::send`] seals and sends in one step, leaving no chance to look
    /// at the size first.
    pub fn plan_share(&self, transport: Arc<dyn FfiTransport>) -> Result<FfiSharePlan, FfiError> {
        let transport = ForeignTransport::new(transport)?;
        let mut vault = self.vault.lock();
        let mut seen = self.lock_seen();
        let (master, contents) = vault.split_mut();
        let session = SyncSession::open(master, contents, &mut seen);
        Ok(session.plan_share(&transport)?.into())
    }

    /// Seals this vault's state (or a request for the peer's) and sends it.
    ///
    /// Returns the payload identifier, hexadecimal. The payload is **not** recorded in the
    /// replay log: that log holds what this device received, and recording an outgoing
    /// payload would make this device reject its own payload when a peer sends it back.
    pub fn send(
        &self,
        transport: Arc<dyn FfiTransport>,
        to: FfiRecipient,
        kind: FfiPayloadKind,
    ) -> Result<String, FfiError> {
        let transport = ForeignTransport::new(transport)?;
        let to = Recipient::try_from(to)?;
        let mut vault = self.vault.lock();
        let mut seen = self.lock_seen();
        let (master, contents) = vault.split_mut();
        let session = SyncSession::open(master, contents, &mut seen);
        Ok(to_hex(&session.send(&transport, to, kind.into())?))
    }

    /// Receives one message and merges its records into the vault.
    ///
    /// The conflicts of this receive **replace** the ones still waiting from the previous
    /// one: a decision belongs to the merge that reported it, and carrying a conflict
    /// forward from an older merge would apply a decision to content the user is no longer
    /// looking at. The host side must decide before receiving again, or accept that those
    /// conflicts are dropped.
    ///
    /// # Errors
    ///
    /// Every rejected payload keeps its own error: `sync_no_session_found` when the channel
    /// had nothing, `sync_already_applied` for a payload that was already processed,
    /// `sync_sender_mismatch` when the envelope's sender and the payload's disagree, and the
    /// authentication failures of the payload itself. **Both the vault and the replay log are
    /// left unchanged** when it fails.
    pub fn receive(&self, transport: Arc<dyn FfiTransport>) -> Result<FfiSyncOutcome, FfiError> {
        let transport = ForeignTransport::new(transport)?;

        let (record, conflicts) = {
            let mut vault = self.vault.lock();
            let mut seen = self.lock_seen();
            let (master, contents) = vault.split_mut();
            let mut session = SyncSession::open(master, contents, &mut seen);
            let outcome = session.receive(&transport)?;

            let made_no_change = outcome.made_no_change();
            let needs_adjudication = outcome.needs_adjudication();
            let merge = outcome.merge;
            let record = FfiSyncOutcome {
                sync_id: to_hex(&outcome.sync_id),
                added: merge.added as u64,
                tombstones_added: merge.tombstones_added as u64,
                deletions_applied: merge.deletions_applied as u64,
                unchanged: merge.unchanged as u64,
                made_no_change,
                needs_adjudication,
                conflicts: merge
                    .conflicts
                    .iter()
                    .map(|conflict| FfiConflict::from_core(conflict, vault.vault()))
                    .collect(),
            };
            (record, merge.conflicts)
        };

        *self.lock_pending() = conflicts;
        Ok(record)
    }

    /// The conflicts waiting for a decision, in the order the merge reported them.
    #[must_use]
    pub fn pending_conflicts(&self) -> Vec<FfiConflict> {
        let vault = self.vault.lock();
        self.lock_pending()
            .iter()
            .map(|conflict| FfiConflict::from_core(conflict, vault.vault()))
            .collect()
    }

    /// Applies one decision to the vault.
    ///
    /// `entry_id` names the conflict, which is the identifier the conflict record carries.
    /// An identifier rather than a position on purpose: a position shifts as soon as one
    /// conflict is decided, and a caller that kept the list it displayed would then decide
    /// the wrong entry.
    ///
    /// What each decision means for each shape is documented on
    /// [`qualia2fa_core::sync::Decision`]; the rules stay in the core.
    ///
    /// # Errors
    ///
    /// [`FfiError::UnknownConflict`] when nothing is waiting for that identifier, and the
    /// core's error when the conflict no longer describes the vault (the entry was deleted
    /// or re-created in the meantime). Nothing is written when the call fails, and the
    /// conflict stays pending.
    pub fn adjudicate(&self, entry_id: String, decision: FfiDecision) -> Result<(), FfiError> {
        let conflict = {
            let mut pending = self.lock_pending();
            let index = pending
                .iter()
                .position(|conflict| conflict.entry_id.to_string() == entry_id)
                .ok_or_else(|| FfiError::UnknownConflict {
                    entry_id: entry_id.clone(),
                })?;
            pending.remove(index)
        };

        let outcome = {
            let mut vault = self.vault.lock();
            adjudicate(vault.vault_mut(), &conflict, decision.into())
        };
        match outcome {
            Ok(_) => Ok(()),
            Err(error) => {
                // The decision did not apply, so the conflict is still open and has to stay
                // where the caller can see it.
                self.lock_pending().push(conflict);
                Err(error.into())
            }
        }
    }
}

impl FfiSyncSession {
    /// Takes the replay-log lock, ignoring poisoning (see [`FfiVault::lock`]).
    fn lock_seen(&self) -> std::sync::MutexGuard<'_, SeenSyncIds> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Takes the pending-conflict lock, ignoring poisoning.
    ///
    /// **Lock order**: this lock is taken while the vault lock is held in
    /// [`FfiSyncSession::pending_conflicts`], so the vault always comes first.
    /// [`FfiSyncSession::adjudicate`] takes a conflict **out** of the list and releases this
    /// lock before it reaches for the vault, so the two orders never nest into a cycle.
    fn lock_pending(&self) -> std::sync::MutexGuard<'_, Vec<Conflict>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Lower-case hexadecimal form of a byte string.
///
/// Same form as every other identifier at this boundary; the core's own `Display` is used
/// where the type has one (`EntryId`), and this covers the raw byte strings that do not.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0F), 16).unwrap_or('0'));
    }
    out
}

// ── The LAN channel: discovery, and an FfiTransport this layer owns ──────
//
// The code channel above is the host side's: the application implements [`FfiTransport`] over
// text the user carries from one device to the other. This half runs the other way — the
// channel is built here, out of `qualia-transport`'s iroh endpoint, and handed to the host
// side as an object it forwards to. A review of this section asks the same question the sync
// section asks: **has any protocol rule been copied in from the core?**

/// One device the lobby has heard announcing itself on this network segment.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiLanPeer {
    /// Device identifier, hexadecimal, the form every identifier uses at this boundary.
    pub device_id: String,
    /// The peer's connection record, as [`FfiLanChannel::remember_peer`] takes it.
    ///
    /// Carried as the transport's own bytes rather than as a string invented here: the record
    /// is versioned and checksummed there, and its fields are the endpoint public key and the
    /// port.
    pub record: Vec<u8>,
    /// The peer's address, as `ip:port`, or `None` when there was no source for it.
    ///
    /// **This is the only address a peer can be dialed at.** An announcement carries no address
    /// of its own, and an endpoint reports its own sockets as the wildcard address, so neither
    /// the peer nor this device can name one: whoever received the datagram is the only party
    /// that knows where it came from. The IP is that sender's; the port is the one the peer
    /// announced, because the datagram itself left the lobby's socket.
    pub socket: Option<String>,
    /// Whether the peer is still announcing itself (`false` after a `Bye`).
    pub here: bool,
}

/// The LAN channel: one endpoint on this network segment, and the peers it sends to.
///
/// # It satisfies the same contract as a host-side channel
///
/// The five points in [`FfiTransport`]'s documentation hold here unchanged: `receive` reports
/// the sender truthfully, `send` respects the recipient, `receive` never blocks, the channel
/// is not single-use, and device identifiers are 64 hexadecimal characters. The difference is
/// **who owns it**: this object, rather than the application.
///
/// # What it declares
///
/// One message may be up to the transport's own cap, the channel may be reused, and it can
/// carry a whole payload. The roster is declared multi-party because the endpoint accepts a
/// connection from any device on the segment, even though one exchange involves two of them:
/// the declaration describes the channel, not the session.
///
/// # The peer table is kept here as well
///
/// [`FfiTransport::peers`] has to answer what `All` means, and the transport's own accessor
/// reports *connected* peers while `All` goes to *registered* ones. This layer therefore
/// mirrors the table it writes, through [`FfiLanChannel::remember_peer`] and
/// [`FfiLanChannel::forget_peer`] alone.
///
/// # Current state
///
/// The endpoint is bound to a system-chosen port and its key is generated per process; neither
/// is persisted. A peer that remembered an earlier address has to be told the current one,
/// which is what a lobby announcement or a code the user carries is for.
#[derive(uniffi::Object)]
pub struct FfiLanChannel {
    /// The endpoint and its own peer table.
    inner: IrohLan,
    /// This device's identifier, parsed once: the core asks for it as a value that cannot fail.
    me: DeviceId,
    /// The peers this channel sends to, in the order they were registered.
    peers: Mutex<Vec<DeviceId>>,
}

#[uniffi::export]
impl FfiLanChannel {
    /// Opens an endpoint for this device, bound to a system-chosen port.
    ///
    /// The endpoint key is generated here and is **not** the device identity from the platform
    /// key store: it is the transport's own identity, proved by the QUIC handshake.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidDeviceId`] when the identifier is not 64 hexadecimal characters;
    /// [`FfiError::Core`]`{ kind: "randomness_unavailable" }` when the endpoint key cannot be
    /// generated; [`FfiError::Lan`] when the endpoint cannot be built, which in practice means
    /// no free port or system policy blocking UDP.
    #[uniffi::constructor]
    pub fn open(device_id: String) -> Result<Arc<Self>, FfiError> {
        let me = parse_device_id(&device_id)?;
        let mut secret = [0_u8; ENDPOINT_KEY_LEN];
        qualia2fa_core::getrandom::fill(&mut secret).map_err(|_| FfiError::Core {
            detail: Error::RandomnessUnavailable.into(),
        })?;

        Ok(Arc::new(Self {
            inner: IrohLan::open(me, EndpointKey::from_bytes(secret)).map_err(lan_error)?,
            me,
            peers: Mutex::new(Vec::new()),
        }))
    }

    /// This endpoint's connection record: what a peer needs in order to dial it.
    ///
    /// # Errors
    ///
    /// [`FfiError::Lan`]`{ kind: "lan_socket" }` when the endpoint has no bound socket, which
    /// cannot happen while it is open.
    pub fn record(&self) -> Result<Vec<u8>, FfiError> {
        let port = self.port()?;
        Ok(LanAddress::new(self.inner.endpoint_key(), port)
            .encode()
            .to_vec())
    }

    /// Registers a peer this channel may send to.
    ///
    /// `socket` is `ip:port`, taken from a lobby announcement: see [`FfiLanPeer::socket`] for
    /// why nothing else can supply it. **Its port is not used**: the record carries the port the
    /// endpoint listens on, while the address a datagram arrives from carries the lobby's, so
    /// only its IP is kept.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidDeviceId`] for a malformed identifier,
    /// [`FfiError::Lan`]`{ kind: "bad_socket" }` for an address that is not `ip:port`, and the
    /// transport's own kinds for a record it cannot parse.
    pub fn remember_peer(
        &self,
        device_id: String,
        record: Vec<u8>,
        socket: String,
    ) -> Result<(), FfiError> {
        let device = parse_device_id(&device_id)?;
        let address = LanAddress::decode(&record).map_err(lan_error)?;
        let socket = parse_socket(&socket)?;
        self.inner.remember_peer(PeerAddress::new(
            device,
            address.endpoint_key,
            Some(SocketAddr::new(socket.ip(), address.port)),
        ));

        let mut peers = self.lock_peers();
        if !peers.contains(&device) {
            peers.push(device);
        }
        Ok(())
    }

    /// Forgets a peer, and closes the connection to it.
    ///
    /// # Errors
    ///
    /// [`FfiError::InvalidDeviceId`] when the identifier is malformed.
    pub fn forget_peer(&self, device_id: String) -> Result<(), FfiError> {
        let device = parse_device_id(&device_id)?;
        self.inner.forget_peer(&device);
        self.lock_peers().retain(|known| *known != device);
        Ok(())
    }

    /// This channel as the transport trait the sessions take.
    ///
    /// The host side passes the result wherever it passes its own channel: one exchange over
    /// two kinds of carrier, with no branch in the session and nothing copied. UniFFI hands
    /// this object across as an [`FfiTransport`] implementation.
    #[must_use]
    pub fn transport(self: &Arc<Self>) -> Arc<dyn FfiTransport> {
        Arc::clone(self) as Arc<dyn FfiTransport>
    }

    /// Starts announcing this endpoint on the local network, and collecting announcements.
    ///
    /// # Errors
    ///
    /// [`FfiError::Lan`]: `lan_socket` when the endpoint has no bound socket, and the
    /// transport's socket kinds when the multicast group cannot be joined — no network, or
    /// network policy blocking multicast.
    pub fn open_lobby(&self) -> Result<Arc<FfiLanLobby>, FfiError> {
        let port = self.port()?;
        let lobby = Lobby::open(self.me, self.inner.endpoint_key(), port).map_err(lan_error)?;
        Ok(Arc::new(FfiLanLobby {
            inner: Mutex::new(lobby),
        }))
    }

    /// Closes the endpoint: every connection is closed and its runtime stops.
    ///
    /// Calling it more than once is safe.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

/// The five methods a session calls, with this channel behind them.
///
/// A plain Rust implementation of the trait the host side implements for itself, so the
/// session takes a `dyn FfiTransport` and cannot tell which of the two it was handed.
impl FfiTransport for FfiLanChannel {
    /// One message may be up to the transport's own cap, the channel may be reused, and it
    /// carries a whole payload.
    fn capabilities(&self) -> FfiTransportCapabilities {
        FfiTransportCapabilities {
            roster: FfiRoster::MultiParty,
            max_message_len: Some(MAX_MESSAGE_LEN as u64),
            max_qr_version: None,
            single_use: false,
            can_carry_payload: true,
        }
    }

    fn local_device(&self) -> String {
        self.me.to_hex()
    }

    /// Returns once the send is **accepted**: the write happens on the transport's own thread
    /// and cannot report back through this call. What is knowable now — a recipient that was
    /// never registered, or a message past the declared cap — is reported here.
    fn send(&self, to: FfiRecipient, message: Vec<u8>) -> Result<(), FfiError> {
        let to = match to {
            FfiRecipient::One { device_id } => LanRecipient::One(parse_device_id(&device_id)?),
            FfiRecipient::All => LanRecipient::All,
        };
        self.inner.send(to, &message).map_err(lan_error)
    }

    /// `Ok(None)` is "nothing available", not a failure; the caller waits or does something
    /// else. The sender is the device the message claims, which the core compares with the
    /// sender inside the payload.
    fn receive(&self) -> Result<Option<FfiReceivedMessage>, FfiError> {
        match self.inner.try_receive() {
            Ok((sender, message)) => Ok(Some(FfiReceivedMessage {
                sender: sender.to_hex(),
                message,
            })),
            Err(qualia_transport::Error::TransportEmpty) => Ok(None),
            Err(other) => Err(lan_error(other)),
        }
    }

    /// The peers this channel will send to, which is what `All` means.
    fn peers(&self) -> Result<Vec<String>, FfiError> {
        Ok(self.lock_peers().iter().map(|id| id.to_hex()).collect())
    }
}

impl FfiLanChannel {
    /// This endpoint's port, or the socket kind when it has none.
    fn port(&self) -> Result<u16, FfiError> {
        self.inner.port().ok_or_else(|| {
            lan_error(qualia_transport::Error::LanSocket {
                operation: "endpoint_port",
            })
        })
    }

    /// Takes the peer-table lock, ignoring poisoning (see [`FfiVault::lock`]).
    fn lock_peers(&self) -> std::sync::MutexGuard<'_, Vec<DeviceId>> {
        self.peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The lobby: which devices are announcing themselves on this network segment.
///
/// # What it does
///
/// One UDP socket in the multicast group and one background thread that announces this
/// endpoint every thirty seconds and collects what the others announce, keeping a view of the
/// peers that have not gone stale after three minutes.
///
/// # It discovers, it does not connect
///
/// No payload travels through the lobby. Its answer is "who is probably here, and where to
/// reach them", which is a **hint**: an announcement is unauthenticated, so a peer in this
/// list may be a device claiming an identity it does not hold. What a connection proves is the
/// endpoint key, and what a payload proves is the master key.
///
/// # It is only useful on one segment
///
/// Multicast reaches one broadcast domain. Where it does not, a peer has to be handed an
/// address out of band instead, and the only party that can supply a dialable one is a
/// receiver — see [`FfiLanPeer::socket`].
#[derive(uniffi::Object)]
pub struct FfiLanLobby {
    /// The lobby, including its worker thread and its own view.
    inner: Mutex<Lobby>,
}

#[uniffi::export]
impl FfiLanLobby {
    /// Every peer the lobby knows, whether or not it is still here.
    ///
    /// A peer that said goodbye or went stale is reported too, with `here` false: "switched
    /// off" and "lost the network" look different to a user, and dropping the entry would lose
    /// that difference.
    ///
    /// **The pending events are drained first.** The view this reads is the caller's copy, and
    /// the lobby advances it as events are taken off its queue: reading the view without taking
    /// them reports an empty list however many devices are announcing themselves. Draining is
    /// what the transport's own documentation asks of a caller, and it makes a second call
    /// report what the first one did.
    #[must_use]
    pub fn peers(&self) -> Vec<FfiLanPeer> {
        let mut lobby = self.lock();
        while lobby.try_poll().is_some() {}
        lobby.view().all().into_iter().map(lan_peer_of).collect()
    }

    /// Announces this endpoint now instead of waiting for the interval.
    ///
    /// # Errors
    ///
    /// [`FfiError::Lan`] with the transport's socket kinds when the datagram cannot be sent.
    pub fn announce_now(&self) -> Result<(), FfiError> {
        self.lock().announce_now().map_err(lan_error)
    }

    /// Closes the lobby: one `Bye`, then the worker thread and the socket.
    ///
    /// Calling it more than once is safe.
    pub fn shutdown(&self) {
        self.lock().shutdown();
    }
}

impl FfiLanLobby {
    /// Takes the lobby lock, ignoring poisoning (see [`FfiVault::lock`]).
    fn lock(&self) -> std::sync::MutexGuard<'_, Lobby> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Reduces one peer of the lobby's view to what the host side is handed.
fn lan_peer_of(peer: Peer) -> FfiLanPeer {
    FfiLanPeer {
        device_id: peer.device.to_hex(),
        record: LanAddress::new(peer.endpoint_key, peer.port)
            .encode()
            .to_vec(),
        socket: peer.socket().map(|socket| socket.to_string()),
        here: peer.status == PeerStatus::Here,
    }
}

/// Parses `ip:port`, the form a socket address crosses this boundary in.
///
/// That form is the one `std::net::SocketAddr` prints, so an address taken from a lobby
/// announcement round-trips through it unchanged.
fn parse_socket(text: &str) -> Result<SocketAddr, FfiError> {
    text.parse::<SocketAddr>().map_err(|_| FfiError::Lan {
        kind: "bad_socket".to_owned(),
        detail: "the address is not `ip:port`".to_owned(),
    })
}

/// Reduces a LAN failure to a kind and a message, without any payload.
///
/// Separate from [`qr_error`] because the two halves of `qualia-transport` fail differently:
/// the code channel fails on text and on capacity, this one on sockets, connections and the
/// transport's own limits. The wildcard arm is required by the transport's `#[non_exhaustive]`
/// error enum, so an unmapped variant reaches the host as `lan_error`; its own test pins the
/// kinds that matter.
fn lan_error(source: qualia_transport::Error) -> FfiError {
    use qualia_transport::Error as LanError;

    let kind = match &source {
        LanError::NoConnectionToPeer => "no_connection_to_peer",
        LanError::TransportEmpty => "transport_empty",
        LanError::PayloadTooLarge { .. } => "payload_too_large",
        LanError::NoLanPeersFound => "no_lan_peers_found",
        LanError::LanSocket { .. } => "lan_socket",
        LanError::LanTransport { .. } => "lan_transport",
        LanError::NotOurLanAddress => "not_our_lan_address",
        LanError::BadLanAddressLength { .. } => "bad_lan_address_length",
        LanError::ZeroPort => "zero_port",
        _ => "lan_error",
    };

    FfiError::Lan {
        kind: kind.to_owned(),
        detail: source.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qualia_dik::{MockDirectMasterKeyStore, MockWrappedMasterKeyStore};

    #[test]
    fn a_qr_code_survives_encoding_and_decoding() {
        for text in [
            "hello",
            "otpauth://totp/Example:alice?secret=MZXW6YTBOI",
            "中文内容，含标点。",
        ] {
            let image = qr_encode(text.to_owned(), FfiEcLevel::Medium, 20, 4, 4)
                .expect("the text must fit in a version 20 code");
            assert_eq!(image.pixels.len(), (image.width * image.height) as usize);
            assert!(image.pixels.contains(&0), "the code must have dark modules");
            assert!(
                image.pixels.contains(&255),
                "the code must have light modules"
            );

            let decoded =
                qr_decode(image.pixels, image.width, image.height).expect("the code must decode");
            assert_eq!(decoded, text, "the text must come back unchanged");
        }
    }

    #[test]
    fn a_buffer_that_does_not_match_the_dimensions_is_an_error() {
        let error = qr_decode(vec![0; 10], 100, 100).expect_err("a short buffer must be rejected");
        assert_eq!(error.kind(), "bad_image_geometry");
    }

    #[test]
    fn an_image_without_a_code_reports_that_rather_than_panicking() {
        let error = qr_decode(vec![255; 64 * 64], 64, 64).expect_err("a blank image has no code");
        assert_eq!(error.kind(), "no_qr_found");
    }

    #[test]
    fn text_that_does_not_fit_is_rejected_rather_than_truncated() {
        let error = qr_encode("a".repeat(8_000), FfiEcLevel::Medium, 20, 4, 4)
            .expect_err("the text must not fit");
        assert_eq!(error.kind(), "payload_too_large");
    }

    #[test]
    fn zero_scale_is_rejected() {
        let error = qr_encode("x".to_owned(), FfiEcLevel::Medium, 20, 0, 4)
            .expect_err("zero scale cannot render");
        assert_eq!(error.kind(), "bad_render_geometry");
    }

    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vector_survives_the_ffi_boundary() {
        let code = totp_code(
            RFC_SECRET.to_owned(),
            59,
            30,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
        )
        .expect("should compute");
        assert_eq!(code, "94287082");
    }

    #[test]
    fn uri_roundtrips_through_ffi_types() {
        let original = "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA256&digits=7&period=45";
        let parsed = parse_otpauth_uri(original.to_owned()).expect("should parse");
        assert_eq!(parsed.account, "alice");
        assert_eq!(parsed.issuer.as_deref(), Some("ACME"));
        assert_eq!(parsed.algorithm, FfiAlgorithm::Sha256);
        assert_eq!(parsed.digits, FfiDigits::Seven);
        assert_eq!(parsed.kind, FfiEntryKind::Totp { period: 45 });

        let back = serialize_otpauth_uri(parsed.clone()).expect("should serialize");
        let reparsed = parse_otpauth_uri(back).expect("should parse again");
        assert_eq!(
            reparsed, parsed,
            "the entry should be equivalent after an FFI round trip"
        );
    }

    #[test]
    fn oversized_input_is_rejected_at_the_boundary() {
        let huge = "A".repeat(MAX_SECRET_CHARS + 1);
        match secret_byte_len(huge) {
            Err(FfiError::InputTooLong {
                kind,
                limit,
                actual,
            }) => {
                assert_eq!(kind, "secret");
                assert_eq!(limit, MAX_SECRET_CHARS as u64);
                assert_eq!(actual, (MAX_SECRET_CHARS + 1) as u64);
            }
            other => panic!("expected InputTooLong, got {other:?}"),
        }
    }

    #[test]
    fn length_limit_counts_characters_not_bytes() {
        let chinese = "中".repeat(MAX_SECRET_CHARS);
        match secret_byte_len(chinese) {
            Err(FfiError::InputTooLong { .. }) => {
                panic!("counting characters must not hit the limit")
            }
            Err(FfiError::Core { .. }) => {}
            Err(FfiError::Qr { .. }) => {
                panic!("the code channel is not involved in a length check")
            }
            Err(other) => panic!("unexpected error kind {}", other.kind()),
            Ok(_) => panic!("non-Base32 input must not parse"),
        }
    }

    #[test]
    fn hotp_matches_rfc4226_through_ffi() {
        let expected = ["755224", "287082", "359152", "969429"];
        for (counter, want) in expected.iter().enumerate() {
            let got = hotp_code(
                RFC_SECRET.to_owned(),
                counter as u64,
                FfiAlgorithm::Sha1,
                FfiDigits::Six,
            )
            .expect("should compute");
            assert_eq!(&got, want, "counter={counter}");
        }
    }

    #[test]
    fn drift_verification_returns_the_offset() {
        let code = totp_code(
            RFC_SECRET.to_owned(),
            59,
            30,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
        )
        .expect("should compute");
        let hit = verify_code_with_drift(
            RFC_SECRET.to_owned(),
            1,
            1,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
            code.clone(),
        )
        .expect("should verify");
        assert_eq!(hit, Some(0));

        let next = totp_code(
            RFC_SECRET.to_owned(),
            89,
            30,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
        )
        .expect("should compute");
        let offset = verify_code_with_drift(
            RFC_SECRET.to_owned(),
            1,
            1,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
            next,
        )
        .expect("should verify");
        assert_eq!(offset, Some(1));
    }

    #[test]
    fn generated_secrets_are_32_bytes_and_unique() {
        let a = generate_secret_base32().expect("should generate");
        let b = generate_secret_base32().expect("should generate");
        assert_ne!(a, b, "two generated secrets must differ");
        assert_eq!(secret_byte_len(a).expect("should parse"), 32);
    }

    #[test]
    fn colon_in_account_is_rejected_at_serialize() {
        let auth = FfiOtpAuth {
            kind: FfiEntryKind::Totp { period: 30 },
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            issuer: None,
            account: "a:b".to_owned(),
            algorithm: FfiAlgorithm::Sha1,
            digits: FfiDigits::Six,
        };
        assert!(
            serialize_otpauth_uri(auth).is_err(),
            "an account name containing a colon must be rejected"
        );
    }

    // ── Registration, login, recovery, challenge-response ────────────

    /// A device identity for tests: keys are derived deterministically from the
    /// label.
    ///
    /// Determinism keeps "the same device" consistent between calls, as a real
    /// platform key store does (the same label returns the same key). With true
    /// randomness, the property "getting the same label again returns the same
    /// key" could not be verified.
    #[derive(Default)]
    struct TestKeys {
        keys: std::sync::Mutex<std::collections::HashMap<String, p256::ecdsa::SigningKey>>,
    }

    impl TestKeys {
        /// Returns or creates the signing key for a label.
        fn key_for(&self, label: &str) -> p256::ecdsa::SigningKey {
            let mut keys = self.keys.lock().expect("no lock poisoning in tests");
            keys.entry(label.to_owned())
                .or_insert_with(|| {
                    let scalar = sha2::Digest::finalize({
                        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
                        sha2::Digest::update(&mut hasher, label.as_bytes());
                        hasher
                    });
                    p256::ecdsa::SigningKey::from_slice(&scalar).expect("the scalar must be valid")
                })
                .clone()
        }
    }

    impl FfiDeviceKeys for TestKeys {
        fn get_or_create(&self, label: String) -> Result<Vec<u8>, FfiError> {
            let key = self.key_for(&label);
            Ok(key.verifying_key().to_sec1_point(false).as_bytes().to_vec())
        }

        fn sign(&self, label: String, message: Vec<u8>) -> Result<Vec<u8>, FfiError> {
            use p256::ecdsa::signature::Signer as _;
            let key = self.key_for(&label);
            let signature: p256::ecdsa::Signature = key.sign(&message);
            Ok(signature.to_bytes().to_vec())
        }
    }

    /// A platform key store for tests: keeps the master key in memory.
    #[derive(Default)]
    struct TestStore {
        master: std::sync::Mutex<Option<Vec<u8>>>,
    }

    impl FfiSecureStore for TestStore {
        fn load_master_key(&self) -> Result<Option<Vec<u8>>, FfiError> {
            Ok(self
                .master
                .lock()
                .expect("no lock poisoning in tests")
                .clone())
        }

        fn store_master_key(&self, key: Vec<u8>) -> Result<(), FfiError> {
            *self.master.lock().expect("no lock poisoning in tests") = Some(key);
            Ok(())
        }

        fn delete_master_key(&self) -> Result<(), FfiError> {
            *self.master.lock().expect("no lock poisoning in tests") = None;
            Ok(())
        }

        fn is_hardware_backed(&self) -> bool {
            false
        }
    }

    /// A minimal usable entry.
    fn sample_entry(name: &str) -> FfiVaultEntry {
        FfiVaultEntry {
            id: String::new(),
            name: name.to_owned(),
            issuer: Some("ACME".to_owned()),
            account: "alice".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: FfiAlgorithm::Sha1,
            digits: FfiDigits::Six,
            kind: FfiEntryKind::Totp { period: 30 },
            pin_set: false,
            note: String::new(),
            created_at: 0,
            updated_at: 0,
            icon: None,
        }
    }

    const NOW: u64 = 1_700_000_000;

    /// An **empty** vault must also tell whether the master key is right.
    ///
    /// This covers the gap that format version 2 closes: in version 1 the master
    /// key only took part in the AEAD of each record, and an empty file has no
    /// records, so any 32-byte key opened it and the user interface showed
    /// "unlocked" for a wrong key.
    ///
    /// The observable behavior for the host side is that `FfiVault.open` rejects a
    /// wrong master key even for a file with **no entries at all**, so "the open
    /// succeeded" can be taken as "unlocked" directly.
    #[test]
    fn an_empty_vault_rejects_a_wrong_master_key() {
        let store_a = Arc::new(TestStore::default());
        let vault_a = FfiVault::register(
            Arc::new(TestKeys::default()),
            store_a,
            "device-a".to_owned(),
        )
        .expect("registration should succeed");
        assert!(
            vault_a.is_empty(),
            "precondition: this vault really is empty"
        );
        let data = vault_a.serialize().expect("should serialize");

        let store_b = Arc::new(TestStore::default());
        FfiVault::register(
            Arc::new(TestKeys::default()),
            store_b.clone(),
            "device-b".to_owned(),
        )
        .expect("registration should succeed");

        let error = FfiVault::open(store_b, data)
            .err()
            .expect("an empty vault must be rejected with a wrong key");
        assert_eq!(
            error.kind(),
            "vault_decryption_failed",
            "it must be \"cannot decrypt\", not \"not registered\": the two lead to completely different user interface actions"
        );
    }

    /// A registered vault accepts entries, computes codes, and can be serialized
    /// and opened again.
    ///
    /// This follows the most common host-side path: register → add entry →
    /// persist → reopen → read a code.
    #[test]
    fn a_registered_vault_roundtrips_through_the_boundary() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys.clone(), store.clone(), "device-a".to_owned())
            .expect("registration should succeed");
        assert!(vault.is_empty(), "registration adds no entries");

        let id = vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("should add the entry");
        assert_eq!(vault.entry_count(), 1);

        let code = vault
            .code_for(id.clone(), NOW)
            .expect("should compute the code");
        assert_eq!(code.len(), 6, "six-digit code");

        let data = vault.serialize().expect("should serialize");
        let reopened =
            FfiVault::open(store, data).expect("should open with the master key from the store");
        assert_eq!(reopened.entry_count(), 1);
        assert_eq!(
            reopened.code_for(id, NOW).expect("should compute the code"),
            code,
            "the same entry must produce the same code after reopening"
        );
    }

    /// Updating an entry must not change its identifier and must not leave a
    /// tombstone.
    ///
    /// A changed identifier reads as one deletion plus one insertion during sync,
    /// and a tombstone reads as "this entry was deleted"; both cause a visible
    /// error on another device.
    #[test]
    fn updating_an_entry_keeps_its_id_and_leaves_no_tombstone() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys, store, "device-a".to_owned())
            .expect("registration should succeed");
        let id = vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("should add the entry");

        let mut edited = sample_entry("GitHub (work)");
        edited.id = id.clone();
        vault
            .update_entry(edited, NOW + 60)
            .expect("should update the entry");

        assert_eq!(vault.entry_count(), 1, "an update must not add an entry");
        assert_eq!(vault.tombstone_count(), 0, "an update is not a deletion");
        let entry = vault
            .entry(id)
            .expect("the identifier must still point at the entry");
        assert_eq!(entry.name, "GitHub (work)");
        assert_eq!(
            entry.created_at, NOW,
            "the creation time should be preserved"
        );
    }

    /// A **nonexistent** identifier must be reported separately by update and by
    /// removal.
    ///
    /// Collapsing the two would show an empty list where the user was just
    /// looking at an entry.
    #[test]
    fn a_missing_entry_id_is_reported_as_not_found() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys, store, "device-a".to_owned())
            .expect("registration should succeed");

        let mut ghost = sample_entry("ghost");
        ghost.id = "0".repeat(32);
        let error = vault
            .update_entry(ghost, NOW)
            .expect_err("a nonexistent identifier should be reported");
        assert_eq!(error.kind(), "vault_entry_not_found");

        assert!(
            !vault
                .remove_entry("0".repeat(32), NOW)
                .expect("should be callable"),
            "removing a nonexistent entry should return false"
        );
        assert_eq!(vault.entry_count(), 0);
    }

    /// Logging in hands the master key to the new device unchanged, so the new
    /// device can open the old device's vault.
    ///
    /// Asserting only "no error" is not enough: an implementation that replaced
    /// the master key with a fresh random value reports no error either.
    #[test]
    fn login_transfers_the_master_key_across_the_boundary() {
        let old_keys = Arc::new(TestKeys::default());
        let old_store = Arc::new(TestStore::default());
        let old_vault =
            FfiVault::register(old_keys.clone(), old_store.clone(), "device-a".to_owned())
                .expect("registration should succeed");
        old_vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("should add the entry");
        let data = old_vault.serialize().expect("should serialize");

        let login = FfiLogin::begin().expect("should start the login");
        let joiner_keys = Arc::new(TestKeys::default());
        let joiner = FfiJoiner::from_qr(login.payload(), "device-b".to_owned())
            .expect("should establish the session");
        let request = joiner
            .request(joiner_keys.clone())
            .expect("should send the request");
        let reply = login
            .authorize(old_vault.clone(), request)
            .expect("should authorize");
        let joiner_store = Arc::new(TestStore::default());
        let master = joiner
            .complete(reply, joiner_keys, joiner_store.clone())
            .expect("should complete the login");

        assert_eq!(master.len(), 32, "the master key is 32 bytes");
        assert!(
            joiner_store.master.lock().expect("not poisoned").is_some(),
            "the master key must already be in the new device's platform store"
        );

        let new_vault = FfiVault::open(joiner_store, data)
            .expect("the new device should open the old device's vault");
        assert_eq!(
            new_vault.entry_count(),
            1,
            "the old device's entry should be visible"
        );
    }

    /// A login can be completed only once, and the second attempt reports the
    /// same error as a forged reply.
    #[test]
    fn a_login_cannot_be_completed_twice_across_the_boundary() {
        let old_keys = Arc::new(TestKeys::default());
        let old_store = Arc::new(TestStore::default());
        let old_vault = FfiVault::register(old_keys, old_store, "device-a".to_owned())
            .expect("registration should succeed");
        let login = FfiLogin::begin().expect("should start the login");
        let joiner_keys = Arc::new(TestKeys::default());
        let joiner = FfiJoiner::from_qr(login.payload(), "device-b".to_owned())
            .expect("should establish the session");
        let request = joiner
            .request(joiner_keys.clone())
            .expect("should send the request");
        let reply = login
            .authorize(old_vault, request)
            .expect("should authorize");
        let joiner_store = Arc::new(TestStore::default());

        joiner
            .complete(reply.clone(), joiner_keys.clone(), joiner_store.clone())
            .expect("the first attempt should succeed");
        let error = joiner
            .complete(reply, joiner_keys, joiner_store)
            .expect_err("the second attempt must fail");
        assert_eq!(
            error.kind(),
            "pairing_authentication_failed",
            "it must be the same error as a forged reply, so a replayer gets no distinguishing signal"
        );
    }

    /// A recovery key file restores the same master key.
    #[test]
    fn a_recovery_file_restores_the_same_master_key() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys, store, "device-a".to_owned())
            .expect("registration should succeed");
        vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("should add the entry");
        let data = vault.serialize().expect("should serialize");

        let file = vault
            .export_recovery_key("correct horse".to_owned(), Some(8), Some(1), Some(1))
            .expect("should export");

        let new_store = Arc::new(TestStore::default());
        let restored =
            import_recovery_key(file.clone(), "correct horse".to_owned(), new_store.clone())
                .expect("should import");
        assert_eq!(restored.len(), 32);

        let reopened = FfiVault::open(new_store, data).expect("should open");
        assert_eq!(reopened.entry_count(), 1);

        let wrong = import_recovery_key(
            file,
            "wrong passphrase".to_owned(),
            Arc::new(TestStore::default()),
        )
        .expect_err("a wrong passphrase should fail");
        assert_eq!(wrong.kind(), "recovery_authentication_failed");
    }

    /// All three steps of the challenge-response must work, with the master key
    /// staying inside the boundary.
    #[test]
    fn challenge_response_confirms_both_sides_across_the_boundary() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys.clone(), store, "device-a".to_owned())
            .expect("registration should succeed");

        let verifier = FfiVerifier::begin().expect("should start the challenge");
        let responder =
            FfiResponder::accept(verifier.challenge()).expect("should accept the challenge");
        let response = responder
            .respond(vault.clone(), "device-a".to_owned(), keys)
            .expect("should produce the response");

        assert!(
            verifier
                .verify(response, vault.clone())
                .expect("should verify the response"),
            "the second step should pass"
        );

        let session_id = verifier
            .session_id()
            .expect("a session identifier should exist after verification");
        let confirmation = verifier
            .confirmation()
            .expect("a confirmation tag should exist after verification");
        assert!(
            responder
                .confirm(vault, session_id, confirmation)
                .expect("should confirm"),
            "the third step should pass"
        );
    }

    /// Challenge-response is single use, like pairing.
    #[test]
    fn a_challenge_cannot_be_verified_twice() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys.clone(), store, "device-a".to_owned())
            .expect("registration should succeed");
        let verifier = FfiVerifier::begin().expect("should start the challenge");
        let responder =
            FfiResponder::accept(verifier.challenge()).expect("should accept the challenge");
        let response = responder
            .respond(vault.clone(), "device-a".to_owned(), keys)
            .expect("should produce the response");

        verifier
            .verify(response.clone(), vault.clone())
            .expect("the first attempt should pass");
        let error = verifier
            .verify(response, vault)
            .expect_err("the second attempt must fail");
        assert_eq!(error.kind(), "auth_proof_failed");
    }

    /// Every kind is unique, and none of them falls into `"unknown"`.
    ///
    /// `core_error_kind` ends with a `_ => "unknown"` fallback (the core `Error` is
    /// marked `non_exhaustive`, so that arm is required). The compiler therefore
    /// **does not warn about a newly added core variant**; this test is the
    /// reminder: a variant missing from the mapping shows up here as `"unknown"`.
    #[test]
    fn every_mapped_error_kind_is_distinct_and_known() {
        let kinds = [
            core_error_kind(&Error::SecretEmpty),
            core_error_kind(&Error::VaultTruncated),
            core_error_kind(&Error::VaultCorrupt),
            core_error_kind(&Error::VaultDecryptionFailed),
            core_error_kind(&Error::VaultEntryNotFound),
            core_error_kind(&Error::VaultBadKeyCheck),
            core_error_kind(&Error::VaultDuplicateGroupId),
            core_error_kind(&Error::VaultGroupNotFound),
            core_error_kind(&Error::VaultGroupUnknownEntry),
            core_error_kind(&Error::VaultTopGroupImmutable),
            core_error_kind(&Error::VaultGroupTooManyChildren {
                limit: 1,
                actual: 2,
            }),
            core_error_kind(&Error::VaultGroupDuplicateChild),
            core_error_kind(&Error::VaultGroupCycle),
            core_error_kind(&Error::VaultGroupDepthExceeded {
                limit: 3,
                actual: 4,
            }),
            core_error_kind(&Error::MasterKeyWrongLength {
                expected: 32,
                actual: 1,
            }),
            core_error_kind(&Error::DeviceKeyMissing),
            core_error_kind(&Error::DeviceNotRegistered),
            core_error_kind(&Error::DeviceIdentityMismatch),
            core_error_kind(&Error::PairingAuthenticationFailed),
            core_error_kind(&Error::RecoveryAuthenticationFailed),
            // The unlock password wrap. A malformed file, a rejected password, an empty
            // password and a damaged cost field are four different answers for the unlock
            // screen, so each needs its own kind.
            core_error_kind(&Error::LockFileMalformed { reason: "test" }),
            core_error_kind(&Error::LockParametersInvalid { reason: "test" }),
            core_error_kind(&Error::LockPassphraseEmpty),
            core_error_kind(&Error::LockPasswordRejected),
            core_error_kind(&Error::LockEncryptionFailed),
            core_error_kind(&Error::LockKdfFailed),
            core_error_kind(&Error::AuthProofFailed),
            core_error_kind(&Error::TimestampZero),
            core_error_kind(&Error::SyncAlreadyApplied),
            core_error_kind(&Error::SyncNoSessionFound),
            core_error_kind(&Error::SyncSenderMismatch),
            core_error_kind(&Error::SyncAuthenticationFailed),
            core_error_kind(&Error::SyncIconRequiresByteTransport),
            core_error_kind(&Error::SyncIdLogFull { limit: 4096 }),
            core_error_kind(&Error::TransportFailed { reason: "test" }),
            core_error_kind(&Error::TransportAlreadyUsed),
            core_error_kind(&Error::TransportMessageTooLarge {
                needed: 100,
                limit: 10,
            }),
            core_error_kind(&Error::TransportUnsupported { operation: "test" }),
            // Another authenticator's files, in both directions. A file-level failure is what the
            // interface shows instead of a preview, and the ways it can fail are the user's
            // answers: choose the file again, choose another file, supply the password, correct
            // the password, or re-export it from the other application.
            core_error_kind(&Error::ImportFileTooLarge {
                limit: 1,
                actual: 2,
            }),
            core_error_kind(&Error::ImportTooManyEntries {
                limit: 1,
                actual: 2,
            }),
            core_error_kind(&Error::ImportTooDeeplyNested { limit: 1 }),
            core_error_kind(&Error::ImportMalformed { reason: "test" }),
            core_error_kind(&Error::ImportUnsupportedVersion {
                version: 2,
                supported: 1,
            }),
            core_error_kind(&Error::ImportPasswordRequired),
            core_error_kind(&Error::ImportEncryptionUnsupported { reason: "test" }),
            core_error_kind(&Error::ImportWrongPassword),
            core_error_kind(&Error::ImportCorrupted),
            core_error_kind(&Error::ImportInvalidKdfParameters { reason: "test" }),
            core_error_kind(&Error::ExportPasswordRequired),
            core_error_kind(&Error::ExportPasswordEmpty),
            core_error_kind(&Error::ExportQrTooLong { position: 1 }),
            core_error_kind(&Error::ExportTooLarge),
            core_error_kind(&Error::ExportParameterRefused { parameter: "test" }),
            // Portable vault containers. Each way one can fail sends the host side somewhere
            // different: choose another file, update the application, re-export, or supply the
            // passphrase.
            core_error_kind(&Error::PortableBadMagic),
            core_error_kind(&Error::PortableUnsupportedVersion { version: 2 }),
            core_error_kind(&Error::PortableTruncated),
            core_error_kind(&Error::PortableLengthMismatch),
            core_error_kind(&Error::PortableTooLarge {
                limit: 1,
                actual: 2,
            }),
            core_error_kind(&Error::PortableVaultFileWithoutKey),
            core_error_kind(&Error::PortablePasswordRequired),
            // The master key storage failures of the device identity library. Each one sends
            // the host side somewhere different, so each one needs a kind of its own: a blob
            // that will not unwrap wants a recovery path, a platform with no backend wants
            // the other form, a store that will not hand the material back wants the wrapped
            // form, and a machine with no usable provider has to be told to the user.
            core_error_kind(&Error::Device(qualia_dik::Error::InvalidWrappedKey {
                reason: "test",
                code: 0,
            })),
            core_error_kind(&Error::Device(qualia_dik::Error::InvalidMasterKey {
                reason: "test",
            })),
            core_error_kind(&Error::Device(qualia_dik::Error::KeyNotExportable {
                reason: "test",
            })),
            core_error_kind(&Error::Device(qualia_dik::Error::HardwareUnavailable {
                reason: String::from("test"),
            })),
            core_error_kind(&Error::Device(qualia_dik::Error::UnsupportedPlatform {
                platform: "test",
            })),
        ];
        for kind in kinds {
            assert_ne!(kind, "unknown", "a variant is not mapped to a stable kind");
        }
        let unique: std::collections::HashSet<_> = kinds.iter().collect();
        assert_eq!(
            unique.len(),
            kinds.len(),
            "two variants map to the same kind, so the client side cannot tell them apart"
        );
    }

    /// The boundary's own errors are branched on by the host side too, so each needs a kind of
    /// its own and none may degrade to `unknown`.
    #[test]
    fn every_boundary_error_kind_is_distinct_and_known() {
        let kinds: Vec<String> = vec![
            FfiError::InputTooLong {
                kind: "secret".to_owned(),
                limit: 1,
                actual: 2,
            }
            .kind()
            .to_owned(),
            FfiError::InputEmpty {
                kind: "pin".to_owned(),
            }
            .kind()
            .to_owned(),
            FfiError::WrongCodeKind {
                kind: "hotp".to_owned(),
                wanted: "time".to_owned(),
            }
            .kind()
            .to_owned(),
            FfiError::InvalidDeviceId {
                kind: "device_id".to_owned(),
            }
            .kind()
            .to_owned(),
            FfiError::UnknownConflict {
                entry_id: "0".repeat(32),
            }
            .kind()
            .to_owned(),
        ];

        for kind in &kinds {
            assert_ne!(kind, "unknown", "a variant is not mapped to a stable kind");
        }
        let unique: std::collections::HashSet<_> = kinds.iter().collect();
        assert_eq!(
            unique.len(),
            kinds.len(),
            "two variants map to the same kind, so the client side cannot tell them apart"
        );
    }

    /// The kind decides how a code is produced; the host does not choose the function.
    #[test]
    fn each_kind_produces_its_own_shape_of_code() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys, store, "device-a".to_owned())
            .expect("registration should succeed");

        let motp = FfiVaultEntry {
            kind: FfiEntryKind::Motp {
                period: 10,
                pin: Some("1234".to_owned()),
            },
            ..sample_entry("mOTP")
        };
        let motp_id = vault.add_entry(motp, NOW).expect("should add the entry");
        let code = vault
            .code_for(motp_id.clone(), NOW)
            .expect("should compute the mOTP code");
        assert_eq!(code.len(), 6, "mOTP codes are six characters");
        assert!(
            code.chars().all(|character| character.is_ascii_hexdigit()),
            "mOTP codes are hexadecimal, actual {code}"
        );

        let steam = FfiVaultEntry {
            kind: FfiEntryKind::Steam,
            digits: FfiDigits::Five,
            ..sample_entry("Steam")
        };
        let steam_id = vault.add_entry(steam, NOW).expect("should add the entry");
        let code = vault
            .code_for(steam_id, NOW)
            .expect("should compute the Steam code");
        assert_eq!(code.len(), 5, "Steam Guard codes are five characters");

        // Yandex OTP verifies its secret length, so this one needs a sixteen-byte secret.
        let yandex = FfiVaultEntry {
            kind: FfiEntryKind::Yandex {
                period: 30,
                pin: Some("1234".to_owned()),
            },
            digits: FfiDigits::Eight,
            secret_base32: "LA2V6KMCGYMWWVEW64RNP3JA3I".to_owned(),
            ..sample_entry("Yandex")
        };
        let yandex_id = vault.add_entry(yandex, NOW).expect("should add the entry");
        let code = vault
            .code_for(yandex_id, NOW)
            .expect("should compute the Yandex code");
        assert_eq!(code.len(), 8, "Yandex OTP codes are eight letters");
        assert!(
            code.chars().all(|character| character.is_ascii_lowercase()),
            "Yandex OTP codes are lower-case letters, actual {code}"
        );

        // The PIN is stored but never handed back.
        let stored = vault.entry(motp_id).expect("the entry exists");
        assert!(stored.pin_set, "the PIN is reported as set");
        assert_eq!(
            stored.kind,
            FfiEntryKind::Motp {
                period: 10,
                pin: None
            },
            "and its value does not cross the boundary"
        );
    }

    /// Calling the wrong function for an entry's kind is an error, not a wrong code.
    #[test]
    fn a_code_the_kind_cannot_produce_is_refused() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys, store, "device-a".to_owned())
            .expect("registration should succeed");

        let totp_id = vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("should add the entry");
        let error = vault
            .hotp_for(totp_id, 1)
            .expect_err("a time-based entry has no counter to advance");
        assert_eq!(error.kind(), "wrong_code_kind");

        let hotp = FfiVaultEntry {
            kind: FfiEntryKind::Hotp { counter: 0 },
            ..sample_entry("Bank")
        };
        let hotp_id = vault.add_entry(hotp, NOW).expect("should add the entry");
        let error = vault
            .code_for(hotp_id, NOW)
            .expect_err("an event-based entry has no clock to read");
        assert_eq!(error.kind(), "wrong_code_kind");
    }

    /// An export is previewed, compared and applied; no secret crosses the boundary while it is.
    #[test]
    fn an_export_previews_compares_and_applies() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys, store, "device-a".to_owned())
            .expect("registration should succeed");

        // The vault already holds "GitHub" with this secret; the export spells the same account
        // differently and adds one the vault does not have.
        let existing_id = vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("should add the entry");
        let export = "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME\n\
                      otpauth://totp/Bank:bob?secret=KRSXG5CTMVRXEZLU&issuer=Bank\n";

        assert_eq!(
            detect_import_format(export.as_bytes().to_vec()),
            Some(FfiImportFormat::Text)
        );
        let import =
            FfiImport::preview(export.as_bytes().to_vec(), FfiImportFormat::Text, None, NOW)
                .expect("the export should be read");

        let entries = import.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].position, 1);
        assert_eq!(entries[0].account, "alice");
        assert!(import.problems().is_empty());

        let matches = import.compare(vault.clone());
        assert_eq!(matches.len(), 2);
        assert_eq!(
            matches[0].existing,
            vec![existing_id.clone()],
            "the same secret identifies the account"
        );
        assert!(!matches[0].identical, "the name differs");
        assert!(matches[0].differences.contains(&"name".to_owned()));
        assert!(matches[1].existing.is_empty(), "the second entry is new");

        // The user keeps what the vault holds and adds only the second entry.
        let applied = import
            .apply(
                vault.clone(),
                vec![FfiImportChoice {
                    position: 1,
                    decision: FfiImportDecision::Skip,
                }],
            )
            .expect("the import should apply");
        assert_eq!(applied.added, 1);
        assert_eq!(applied.skipped, 1);
        assert_eq!(vault.entry_count(), 2);
        assert_eq!(
            vault.entry(existing_id).map(|entry| entry.name),
            Some("GitHub".to_owned()),
            "a skipped entry keeps what the vault held"
        );

        // Applying the same import again: the entry that was added the first time is skipped as
        // an exact duplicate, while the one the user declined comes back as a question. That is
        // the deliberate rule - a differing entry is never resolved automatically, because only
        // a human can say whether "ACME:alice" and "GitHub" are the same account.
        let again = import
            .apply(vault.clone(), Vec::new())
            .expect("applies again");
        assert_eq!(again.added, 1);
        assert_eq!(again.skipped, 1);
        assert_eq!(vault.entry_count(), 3);

        // Answered with Skip, it leaves the vault alone.
        let settled = import
            .apply(
                vault.clone(),
                vec![FfiImportChoice {
                    position: 1,
                    decision: FfiImportDecision::Skip,
                }],
            )
            .expect("applies once more");
        assert_eq!(settled.added, 0);
        assert_eq!(settled.skipped, 2);
        assert_eq!(vault.entry_count(), 3);

        // An encrypted export without a password is refused rather than read as empty.
        let encrypted = br#"{"version":1,"header":{"slots":[],"params":{}},"db":"AAAA"}"#;
        assert!(
            FfiImport::preview(encrypted.to_vec(), FfiImportFormat::Json, None, NOW).is_err(),
            "an encrypted export needs a password"
        );
    }

    /// The kind of an entry without its PIN, which is what a read-back can be compared on.
    ///
    /// A URI carries a PIN and a JSON entry carries one, so an import that went through those
    /// would disagree with the preview, which never hands a PIN back (see [`FfiEntryKind`]).
    fn kind_shape(kind: &FfiEntryKind) -> FfiEntryKind {
        match kind {
            FfiEntryKind::Motp { period, .. } => FfiEntryKind::Motp {
                period: *period,
                pin: None,
            },
            FfiEntryKind::Yandex { period, .. } => FfiEntryKind::Yandex {
                period: *period,
                pin: None,
            },
            other => other.clone(),
        }
    }

    /// The interface's questions about a format, answered without naming a file.
    #[test]
    fn the_export_formats_describe_themselves() {
        for format in [
            FfiExportFormat::Vault,
            FfiExportFormat::Text,
            FfiExportFormat::Json,
            FfiExportFormat::Html,
        ] {
            assert!(
                !export_format_needs_password(format),
                "{format:?} is written as it stands"
            );
        }
        for format in [
            FfiExportFormat::EncryptedVault,
            FfiExportFormat::EncryptedJson,
        ] {
            assert!(
                export_format_needs_password(format),
                "{format:?} asks for a password"
            );
        }

        assert_eq!(export_format_extension(FfiExportFormat::Vault), "q2fa");
        assert_eq!(
            export_format_extension(FfiExportFormat::EncryptedVault),
            "q2fa",
            "both vault containers are one file with and without a password"
        );
        assert_eq!(export_format_extension(FfiExportFormat::Text), "txt");
        assert_eq!(export_format_extension(FfiExportFormat::Json), "json");
        assert_eq!(
            export_format_extension(FfiExportFormat::EncryptedJson),
            "json",
            "both JSON forms are one file with and without a password"
        );
        assert_eq!(export_format_extension(FfiExportFormat::Html), "html");

        assert_eq!(
            export_format_group_carrying(FfiExportFormat::Vault),
            FfiGroupCarrying::FullTree
        );
        assert_eq!(
            export_format_group_carrying(FfiExportFormat::EncryptedVault),
            FfiGroupCarrying::FullTree
        );
        assert_eq!(
            export_format_group_carrying(FfiExportFormat::Json),
            FfiGroupCarrying::FlatGroups,
            "the JSON forms keep the group names and memberships, not the nesting"
        );
        assert_eq!(
            export_format_group_carrying(FfiExportFormat::EncryptedJson),
            FfiGroupCarrying::FlatGroups
        );
        assert_eq!(
            export_format_group_carrying(FfiExportFormat::Text),
            FfiGroupCarrying::None,
            "a list of URIs has nowhere to put a group"
        );
        assert_eq!(
            export_format_group_carrying(FfiExportFormat::Html),
            FfiGroupCarrying::None
        );
        assert!(!export_format_carries_groups(FfiExportFormat::Text));
        assert!(export_format_carries_groups(FfiExportFormat::Json));
        assert!(export_format_carries_groups(FfiExportFormat::Vault));
        assert_eq!(max_group_depth(), 3);
    }

    /// A plain `.q2fa` restores on a clean device, and the key is written to its store.
    #[test]
    fn a_plain_portable_vault_restores_through_the_boundary() {
        let (vault, _) = registered_vault("device-a");
        vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("the entry should be added");
        let bytes = vault
            .export(FfiExportFormat::Vault, None)
            .expect("the plain container is written");
        assert_eq!(
            detect_portable_file(bytes.clone()),
            Some(FfiPortableKind::PlainVault)
        );

        let store = Arc::new(TestStore::default());
        let restored = open_portable_file(bytes, None, store.clone()).expect("it opens");
        assert!(!restored.key_only);
        let restored = restored.vault.expect("the file carried a vault");
        assert_eq!(restored.entry_count(), 1, "the entry came along");
        assert!(
            store
                .master
                .lock()
                .expect("no lock poisoning in tests")
                .is_some(),
            "the restored key must be in the platform store"
        );
    }

    /// The encrypted container needs its passphrase, and a wrong one changes nothing.
    #[test]
    fn an_encrypted_portable_vault_needs_its_passphrase() {
        let (vault, _) = registered_vault("device-a");
        vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("the entry should be added");
        let bytes = vault
            .export(
                FfiExportFormat::EncryptedVault,
                Some("correct horse".to_owned()),
            )
            .expect("the encrypted container is written");
        assert_eq!(
            detect_portable_file(bytes.clone()),
            Some(FfiPortableKind::EncryptedVault)
        );

        let store = Arc::new(TestStore::default());
        let missing = open_portable_file(bytes.clone(), None, store.clone());
        assert!(
            missing.is_err(),
            "a passphrase-protected file must not open without one"
        );
        assert!(
            store
                .master
                .lock()
                .expect("no lock poisoning in tests")
                .is_none(),
            "a failed open must not write a key"
        );

        let wrong = open_portable_file(bytes.clone(), Some("wrong".to_owned()), store.clone());
        assert!(wrong.is_err());

        let opened = open_portable_file(bytes, Some("correct horse".to_owned()), store)
            .expect("the right passphrase opens it");
        assert_eq!(
            opened
                .vault
                .expect("the file carried a vault")
                .entry_count(),
            1
        );
    }

    /// The two shapes that are not a full backup are recognized and answered.
    #[test]
    fn a_bare_vault_file_and_a_key_only_file_are_told_apart() {
        let (vault, _) = registered_vault("device-a");
        let bare = vault.serialize().expect("should serialize");
        assert_eq!(
            detect_portable_file(bare.clone()),
            None,
            "a bare vault file is not a portable container"
        );
        let refused = match open_portable_file(bare, None, Arc::new(TestStore::default())) {
            Ok(_) => panic!("a bare vault file carries no key"),
            Err(error) => error,
        };
        assert_eq!(refused.kind(), "portable_vault_file_without_key");

        let key_only = vault
            .export_recovery_key("passphrase".to_owned(), None, None, None)
            .expect("the old key-only file is written");
        assert_eq!(
            detect_portable_file(key_only.clone()),
            Some(FfiPortableKind::KeyOnly)
        );
        let store = Arc::new(TestStore::default());
        let outcome = open_portable_file(key_only, Some("passphrase".to_owned()), store.clone())
            .expect("the file is valid");
        assert!(outcome.key_only, "the old shape carries no entries");
        assert!(outcome.vault.is_none());
        assert!(
            store
                .master
                .lock()
                .expect("no lock poisoning in tests")
                .is_none(),
            "nothing was written, so a local vault cannot be left on a new key"
        );
    }

    /// Every kind the vault holds comes back out of every format, across the boundary.
    ///
    /// The export is the object the host side holds and the bytes are what it would write to a
    /// file; the import is what it would do with that file. Both halves are exercised here, in
    /// all four formats, because each one carries the fields differently - a URI has no name, a
    /// table writes the mOTP secret in hexadecimal, and the encrypted form is a different shape
    /// altogether.
    #[test]
    fn an_export_round_trips_across_the_boundary() {
        let (vault, _) = registered_vault("device-a");
        let written = [
            sample_entry("GitHub"),
            FfiVaultEntry {
                kind: FfiEntryKind::Hotp { counter: 7 },
                ..sample_entry("Bank")
            },
            FfiVaultEntry {
                kind: FfiEntryKind::Steam,
                digits: FfiDigits::Five,
                ..sample_entry("Steam")
            },
            FfiVaultEntry {
                kind: FfiEntryKind::Motp {
                    period: 10,
                    pin: Some("1234".to_owned()),
                },
                ..sample_entry("mOTP")
            },
            FfiVaultEntry {
                kind: FfiEntryKind::Yandex {
                    period: 30,
                    pin: Some("1234".to_owned()),
                },
                secret_base32: "LA2V6KMCGYMWWVEW64RNP3JA3I".to_owned(),
                ..sample_entry("Yandex")
            },
        ];
        for entry in &written {
            vault
                .add_entry(entry.clone(), NOW)
                .expect("the entry should be added");
        }

        for (format, import_format) in [
            (FfiExportFormat::Text, FfiImportFormat::Text),
            (FfiExportFormat::Json, FfiImportFormat::Json),
            (FfiExportFormat::Html, FfiImportFormat::Html),
            (FfiExportFormat::EncryptedJson, FfiImportFormat::Json),
        ] {
            let password = export_format_needs_password(format).then(|| "correct horse".to_owned());
            let bytes = vault
                .export(format, password.clone())
                .unwrap_or_else(|error| panic!("{format:?} should be written: {error}"));
            let import = FfiImport::preview(bytes, import_format, password, NOW)
                .unwrap_or_else(|error| panic!("{format:?} should read back: {error}"));

            assert!(
                import.problems().is_empty(),
                "{format:?} produced problems: {:?}",
                import.problems()
            );
            let read = import.entries();
            assert_eq!(read.len(), written.len(), "{format:?}");
            for entry in &written {
                let expected = kind_shape(&entry.kind);
                assert!(
                    read.iter().any(|one| kind_shape(&one.kind) == expected),
                    "{format:?} came back without {expected:?}: {:?}",
                    read.iter().map(|one| &one.kind).collect::<Vec<_>>()
                );
            }
        }
    }

    /// The encrypted form is the only one that hides anything, and it insists on a password.
    #[test]
    fn an_encrypted_export_needs_a_real_password() {
        let (vault, _) = registered_vault("device-a");
        vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("the entry should be added");

        let missing = vault
            .export(FfiExportFormat::EncryptedJson, None)
            .expect_err("an encrypted export needs a password");
        assert_eq!(missing.kind(), "export_password_required");

        let empty = vault
            .export(FfiExportFormat::EncryptedJson, Some(String::new()))
            .expect_err("an empty password protects nothing");
        assert_eq!(empty.kind(), "export_password_empty");

        let bytes = vault
            .export(
                FfiExportFormat::EncryptedJson,
                Some("correct horse".to_owned()),
            )
            .expect("the export should be written");
        assert!(
            !String::from_utf8_lossy(&bytes).contains("JBSWY3DPEHPK3PXP"),
            "the secret must not survive in the file as it stands"
        );

        let without = match FfiImport::preview(bytes.clone(), FfiImportFormat::Json, None, NOW) {
            Err(error) => error,
            Ok(_) => panic!("an encrypted export must not open without a password"),
        };
        assert_eq!(without.kind(), "import_password_required");

        let wrong = match FfiImport::preview(
            bytes.clone(),
            FfiImportFormat::Json,
            Some("correct horsf".to_owned()),
            NOW,
        ) {
            Err(error) => error,
            Ok(_) => panic!("a wrong password must not open the file"),
        };
        assert_eq!(wrong.kind(), "import_wrong_password");

        let opened = FfiImport::preview(
            bytes,
            FfiImportFormat::Json,
            Some("correct horse".to_owned()),
            NOW,
        )
        .expect("the password opens it");
        assert_eq!(opened.entries().len(), 1);
    }

    /// A step that is not the default survives an HTML export and import.
    ///
    /// This is the pair of changes that only works together: the writer draws the step into the
    /// QR code, and the reader takes it back out. A default step would come back as 30 and the
    /// codes the user sees would never match the ones the other application shows.
    #[test]
    fn an_exported_html_file_keeps_a_step_that_is_not_the_default() {
        let (vault, _) = registered_vault("device-a");
        vault
            .add_entry(
                FfiVaultEntry {
                    kind: FfiEntryKind::Totp { period: 90 },
                    ..sample_entry("GitHub")
                },
                NOW,
            )
            .expect("the entry should be added");

        let bytes = vault
            .export(FfiExportFormat::Html, None)
            .expect("the export should be written");
        let import = FfiImport::preview(bytes, FfiImportFormat::Html, None, NOW)
            .expect("the export should read back");
        let read = import.entries();

        assert_eq!(read.len(), 1);
        assert_eq!(read[0].kind, FfiEntryKind::Totp { period: 90 });
        assert!(
            !read[0].period_assumed,
            "the step was in the code, so nothing was assumed"
        );
    }

    /// Groups and their child lists cross the boundary, and the tree is what the host reads.
    #[test]
    fn groups_and_orderings_cross_the_boundary() {
        let (vault, _) = registered_vault("device-a");
        let top = "0".repeat(32);

        let first = vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("should add the entry");
        let second = vault
            .add_entry(sample_entry("Bank"), NOW)
            .expect("should add the entry");

        // Everything starts in the top group, in the order it was added.
        let groups = vault.groups();
        assert_eq!(groups.len(), 1);
        assert!(groups[0].top);
        assert_eq!(groups[0].id, top);
        assert!(groups[0].name.is_empty());
        assert_eq!(
            groups[0].children,
            vec![
                FfiGroupChild::Entry { id: first.clone() },
                FfiGroupChild::Entry { id: second.clone() }
            ]
        );
        assert_eq!(groups[0].entry_ids, vec![first.clone(), second.clone()]);
        assert_eq!(vault.group_of(first.clone()), Some(top.clone()));

        // A new group is appended to the top group's children and receives an entry.
        let work = vault
            .create_group("Work".to_owned())
            .expect("creates the group");
        vault
            .assign_to_group(first.clone(), work.clone())
            .expect("moves the entry");
        let groups = vault.groups();
        assert_eq!(groups.len(), 2);
        assert!(groups[0].top, "the top group stays first");
        assert_eq!(groups[1].name, "Work");
        assert_eq!(groups[1].entry_ids, vec![first.clone()]);
        assert_eq!(
            groups[0].entry_ids,
            vec![second.clone()],
            "the entry left the top group"
        );
        assert_eq!(vault.group_of(first.clone()), Some(work.clone()));

        // A child group lives inside its parent, and the pre-order walk shows it there.
        let sub = vault
            .create_group_in(work.clone(), "Sub".to_owned())
            .expect("creates the child group");
        assert_eq!(vault.parent_of(sub.clone()), Some(work.clone()));
        assert_eq!(vault.depth_of(sub.clone()), Some(2));
        assert_eq!(vault.parent_of(work.clone()), Some(top.clone()));
        assert_eq!(
            vault.children_of(work.clone()),
            Some(vec![
                FfiGroupChild::Entry { id: first.clone() },
                FfiGroupChild::Group { id: sub.clone() }
            ])
        );
        let names: Vec<String> = vault.groups().into_iter().map(|group| group.name).collect();
        assert_eq!(
            names,
            vec![String::new(), "Work".to_owned(), "Sub".to_owned()]
        );

        // A whole list is one write: the entries move to the top group, and the child group
        // stays where it was.
        vault
            .set_children(
                top.clone(),
                vec![
                    FfiGroupChild::Entry { id: second.clone() },
                    FfiGroupChild::Group { id: work.clone() },
                ],
            )
            .expect("the list is valid");
        assert_eq!(vault.parent_of(sub.clone()), Some(work.clone()));

        // Renaming is visible in the next read; the top group has no name to change.
        vault
            .rename_group(work.clone(), "Work stuff".to_owned())
            .expect("renames");
        assert_eq!(vault.groups()[1].name, "Work stuff");
        assert!(
            vault.rename_group(top.clone(), "Nope".to_owned()).is_err(),
            "the top group has no name"
        );

        // A group cannot be put inside its own subtree.
        let cycle =
            vault.set_children(sub.clone(), vec![FfiGroupChild::Group { id: work.clone() }]);
        assert!(
            cycle.is_err(),
            "a group inside its own ancestor must be refused"
        );

        // Setting an ordering moves the entries it names and leaves the child groups' places.
        vault
            .set_ordering(work.clone(), vec![first.clone(), second.clone()])
            .expect("sets the ordering");
        assert_eq!(
            vault.groups()[1].entry_ids,
            vec![first.clone(), second.clone()],
            "the entries are where the ordering put them"
        );

        // Removing a group moves its children to its parent; no entry is deleted with it.
        vault.remove_group(work.clone()).expect("removes the group");
        let groups = vault.groups();
        assert_eq!(groups.len(), 2, "the top group and Sub");
        assert_eq!(vault.entry_count(), 2);
        assert_eq!(
            groups[0].entry_ids,
            vec![first.clone(), second.clone()],
            "both entries are back in the top group"
        );
        assert_eq!(
            vault.parent_of(sub),
            Some(top),
            "the child group took its parent's place"
        );
        assert!(vault.remove_group("0".repeat(32)).is_err(), "the top group");
    }

    /// An icon crosses the boundary with the entry and survives a round trip through the file.
    #[test]
    fn an_icon_crosses_the_boundary() {
        let (vault, _) = registered_vault("device-a");
        let icon = FfiEntryIcon {
            mime: FfiIconMime::Png,
            bytes: vec![0x89, b'P', b'N', b'G'],
        };
        let id = vault
            .add_entry(
                FfiVaultEntry {
                    icon: Some(icon.clone()),
                    ..sample_entry("with icon")
                },
                NOW,
            )
            .expect("the entry should be added");

        let read = vault.entry(id.clone()).expect("the entry is there");
        assert_eq!(read.icon, Some(icon.clone()));
        let debug = format!("{read:?}");
        assert!(
            !debug.contains("137, 80, 78, 71"),
            "the icon bytes must not reach a log: {debug}"
        );

        // The icon travels through the file and comes back unchanged.
        let bytes = vault.serialize().expect("should serialize");
        let store = Arc::new(TestStore::default());
        store
            .store_master_key(vault.lock().master_key().expose().to_vec())
            .expect("the key is stored");
        let reopened = FfiVault::open(store, bytes).expect("the file opens");
        assert_eq!(
            reopened.entry(id).expect("the entry is there").icon,
            Some(icon),
            "the picture survives the file"
        );
    }

    /// Key material does not reach a `Debug` printout, which is where a panic message, a log
    /// line and a crash dump all come from.
    #[test]
    fn key_material_never_reaches_a_debug_printout() {
        let entry = sample_entry("GitHub");
        let printed = format!("{entry:?}");
        assert!(
            !printed.contains("JBSWY3DPEHPK3PXP"),
            "the secret must not appear: {printed}"
        );
        assert!(printed.contains("<redacted>"), "actual {printed}");

        let auth = FfiOtpAuth {
            kind: FfiEntryKind::Motp {
                period: 10,
                pin: Some("5210481216086702".to_owned()),
            },
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            issuer: None,
            account: "alice".to_owned(),
            algorithm: FfiAlgorithm::Sha1,
            digits: FfiDigits::Six,
        };
        let printed = format!("{auth:?}");
        assert!(
            !printed.contains("JBSWY3DPEHPK3PXP"),
            "the secret must not appear: {printed}"
        );
        assert!(
            !printed.contains("5210481216086702"),
            "the PIN must not appear: {printed}"
        );
        assert!(
            format!("{:?}", auth.kind).contains("<set>"),
            "the fact that a PIN is set is what an operator needs"
        );
    }

    // ── Platform key store forwarding ────────────────────────────────

    /// Sequence that keeps the labels of one process distinct.
    ///
    /// `cargo test` runs tests in parallel and the platform key store is global
    /// shared state: two tests that use one label would delete each other's keys.
    static PLATFORM_LABEL_SEQUENCE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    /// A device label for tests, unique across the machine.
    ///
    /// The label becomes an entry in the **system-wide** key namespace, so it
    /// carries the `Q2faTest-` prefix the device identity kit's own integration
    /// tests use. A label without that prefix could name a real user identity,
    /// and deleting one costs that user the device identity permanently.
    fn test_label(name: &str) -> String {
        let sequence = PLATFORM_LABEL_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        format!("Q2faTest-{name}-{pid}-{sequence}")
    }

    /// The label limit is enforced before the platform is touched.
    ///
    /// This holds on every machine, with or without a key store: an oversized
    /// label has to be rejected at the boundary and never reach the platform.
    #[test]
    fn an_oversized_label_is_rejected_before_the_platform_is_touched() {
        match FfiPlatformKeys::open("a".repeat(MAX_LABEL_CHARS + 1)) {
            Err(FfiError::InputTooLong { kind, limit, .. }) => {
                assert_eq!(kind, "label");
                assert_eq!(limit, MAX_LABEL_CHARS as u64);
            }
            Err(_) => panic!("expected an InputTooLong error, got another error kind"),
            Ok(_) => panic!("an oversized label must not reach the platform key store"),
        }
    }

    /// The exported key store forwards to the platform's own key store.
    ///
    /// Requires a usable platform key store: the TPM or the software KSP on
    /// Windows. Where there is none — a platform whose backend is not implemented
    /// yet, or a machine whose key store cannot be opened — the test **skips with
    /// a printed reason** instead of failing, because what it checks (forwarding)
    /// cannot be observed without a key store. Printing the reason keeps a skip
    /// distinguishable from a pass in the test output.
    #[test]
    fn platform_keys_forward_to_the_platform_key_store() {
        let label = test_label("platform-keys");
        let keys = match FfiPlatformKeys::open(label.clone()) {
            Ok(keys) => keys,
            Err(error) => {
                println!("skipping: no usable platform key store on this machine ({error})");
                return;
            }
        };

        let public_key = keys
            .device_public_key()
            .expect("the public key of the opened identity should be readable");
        assert_eq!(
            public_key.len(),
            65,
            "the public key must be a 65-byte SEC1 uncompressed point"
        );
        let public_key = qualia_dik::DevicePublicKey::from_sec1_bytes(&public_key)
            .expect("the platform must return a point on P-256");

        let message = b"\x01Qualia2FA platform keys";
        let signature = keys.sign(message.to_vec()).expect("signing should succeed");
        assert_eq!(
            signature.len(),
            64,
            "the signature must be the 64-byte raw r||s, not DER"
        );
        let signature = qualia_dik::DeviceSignature::from_bytes(&signature)
            .expect("a 64-byte raw signature should parse");

        qualia_dik::device::verify(&public_key, message, &signature)
            .expect("the signature must verify over the raw message, not over a digest");

        let backend = keys.backend();
        assert!(
            backend == "tpm" || backend == "software",
            "an identity that opened must report a real backend, got {backend}"
        );
        assert_eq!(
            keys.is_hardware_backed(),
            backend == "tpm",
            "is_hardware_backed must agree with the backend that is reported"
        );

        let reopened = FfiPlatformKeys::open(label.clone()).expect("reopening should succeed");
        assert_eq!(
            reopened
                .device_public_key()
                .expect("the public key should be readable again"),
            public_key.as_sec1_bytes().to_vec(),
            "the identity under one label changed: the key was not persisted"
        );

        DeviceKeyStore::delete(&keys.store, label.as_str())
            .expect("the test identity should be removable");
    }

    // ── Master key storage, both forms ───────────────────────────────

    /// The material the master key tests store and expect back.
    ///
    /// A fixed pattern rather than random bytes: every test here compares what came back with
    /// what went in, and a value that changed per run would hide a wrong-bytes result behind
    /// a comparison that never had a chance to fail.
    const TEST_MASTER_KEY: [u8; MASTER_KEY_LEN] = [0x5A; MASTER_KEY_LEN];

    /// A direct store over the software backend.
    ///
    /// The platform stores of both forms exist on Windows and Android only, so a test driving
    /// a real one would **skip on every other platform, CI included**, and pin nothing about
    /// the marshalling. The software backend is reached through exactly the methods
    /// production calls, and it reports `"software"` honestly.
    fn direct_store() -> Arc<FfiDirectMasterKeyStore> {
        FfiDirectMasterKeyStore::with_store(Box::new(MockDirectMasterKeyStore::new()))
    }

    /// A wrapped store over the software backend.
    fn wrapped_store() -> Arc<FfiWrappedMasterKeyStore> {
        FfiWrappedMasterKeyStore::with_store(Box::new(MockWrappedMasterKeyStore::new()))
    }

    /// The direct form round-trips, and deleting the key ends it.
    #[test]
    fn the_direct_master_key_round_trips_across_the_boundary() {
        let store = direct_store();
        let label = String::from("direct-master-key");

        assert_eq!(
            store.backend(),
            "software",
            "the store must report the backend that answered"
        );
        assert!(
            !store.is_hardware_backed(),
            "a software backend must not be reported as hardware backed"
        );

        store
            .store(label.clone(), TEST_MASTER_KEY.to_vec())
            .expect("storing the material should succeed");
        assert_eq!(
            store
                .load(label.clone())
                .expect("the material should be readable"),
            TEST_MASTER_KEY.to_vec(),
            "the direct form returned material other than what was stored"
        );

        store
            .delete(label.clone())
            .expect("deleting the key should succeed");
        assert!(
            store.load(label.clone()).is_err(),
            "the key is still readable after it was deleted"
        );
    }

    /// The wrapped form hands back the bytes to persist, and takes them back.
    #[test]
    fn the_wrapped_master_key_round_trips_across_the_boundary() {
        let store = wrapped_store();
        let label = String::from("wrapped-master-key");

        assert_eq!(
            store.backend(),
            "software",
            "the store must report the backend that answered"
        );
        assert!(
            !store.is_hardware_backed(),
            "a software backend must not be reported as hardware backed"
        );

        let wrapped = store
            .store(label.clone(), TEST_MASTER_KEY.to_vec())
            .expect("wrapping the material should succeed");
        assert!(
            !wrapped.is_empty() && wrapped != TEST_MASTER_KEY.to_vec(),
            "the wrapped form has to be bytes of its own, not the material"
        );

        assert_eq!(
            store
                .load(label.clone(), wrapped.clone())
                .expect("the wrapped bytes should unwrap"),
            TEST_MASTER_KEY.to_vec(),
            "the wrapped form returned material other than what was stored"
        );
        // These bytes are what the host persists, so they have to keep working.
        assert_eq!(
            store
                .load(label.clone(), wrapped.clone())
                .expect("the wrapped bytes should unwrap again"),
            TEST_MASTER_KEY.to_vec(),
            "the wrapped bytes stopped unwrapping after a first use"
        );

        store
            .delete(label.clone())
            .expect("deleting the key-encryption key should succeed");
        assert!(
            store.load(label.clone(), wrapped).is_err(),
            "the wrapped bytes still unwrap after the key-encryption key was deleted"
        );
    }

    /// A damaged or foreign blob is refused, never turned into some other key.
    #[test]
    fn a_wrapped_blob_that_does_not_unwrap_is_refused() {
        let store = wrapped_store();
        let label = String::from("damaged-wrapped-key");
        let mut wrapped = store
            .store(label.clone(), TEST_MASTER_KEY.to_vec())
            .expect("wrapping the material should succeed");

        // The last byte belongs to the authentication tag: changing it leaves the length and
        // every other byte in place, which is the shape of a blob damaged in storage.
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        let error = store
            .load(label.clone(), wrapped)
            .expect_err("a damaged blob must not unwrap");
        assert_eq!(
            error.kind(),
            "invalid_wrapped_key",
            "a damaged blob has to be reported as such rather than as a store failure"
        );

        // A truncated blob is refused as well rather than padded into 32 bytes.
        let error = store
            .load(label.clone(), vec![0_u8; 8])
            .expect_err("a truncated blob must not unwrap");
        assert_eq!(
            error.kind(),
            "invalid_wrapped_key",
            "a truncated blob has to be reported as such"
        );

        // Bytes from another store entry do not unwrap either: the key-encryption key
        // differs, so accepting them would hand back a key that merely looks valid.
        let other = String::from("another-wrapped-key");
        store
            .store(other.clone(), [0x11_u8; MASTER_KEY_LEN].to_vec())
            .expect("the second entry should wrap");
        let foreign = store
            .store(other, TEST_MASTER_KEY.to_vec())
            .expect("the second entry should wrap again");
        let error = store
            .load(label, foreign)
            .expect_err("bytes of another store entry must not unwrap");
        assert_eq!(
            error.kind(),
            "invalid_wrapped_key",
            "bytes of another store entry have to be refused"
        );
    }

    /// Neither the material nor the blob it was wrapped into reaches an error message.
    #[test]
    fn master_key_material_never_reaches_an_error_message() {
        let store = wrapped_store();
        let label = String::from("material-in-messages");
        let material = [0xA5_u8; MASTER_KEY_LEN];
        let wrapped = store
            .store(label.clone(), material.to_vec())
            .expect("wrapping the material should succeed");

        let mut damaged = wrapped.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 0x01;
        let error = store
            .load(label, damaged)
            .expect_err("a damaged blob must not unwrap");

        let rendered = format!("{error} | {error:?}");
        for leak in [
            to_hex(&material),
            format!("{material:?}"),
            to_hex(&wrapped),
            format!("{wrapped:?}"),
        ] {
            assert!(
                !rendered.contains(&leak),
                "an error message carries master key material or the blob wrapping it: {rendered}"
            );
        }
    }

    /// The boundary's own limits are enforced before anything else is done with the input.
    #[test]
    fn an_oversized_label_is_rejected_before_the_master_key_store_is_reached() {
        let store = direct_store();
        // Both inputs are wrong. If the label limit did not come first, the report would be
        // about the key length instead, and a label the store forbids would have been passed
        // on to be judged there.
        let error = store
            .store("a".repeat(MAX_LABEL_CHARS + 1), vec![0_u8; 1])
            .expect_err("an oversized label must be rejected");
        assert_eq!(error.kind(), "input_too_long");
    }

    /// A master key of the wrong length is refused with the core's own kind.
    #[test]
    fn a_master_key_of_the_wrong_length_is_refused() {
        let store = direct_store();
        let error = store
            .store(
                String::from("short-master-key"),
                vec![0_u8; MASTER_KEY_LEN - 1],
            )
            .expect_err("a short master key must be refused");
        assert_eq!(
            error.kind(),
            "master_key_wrong_length",
            "a wrong length has to be reported with the kind the vault paths already use"
        );
    }

    // ── Synchronization across the boundary ──────────────────────────

    /// A channel for tests: two queues and no protocol of its own.
    ///
    /// It makes no decisions on purpose. A channel that de-duplicated, reordered or
    /// retried would hide exactly the defects these tests are looking for, because every
    /// protocol rule is supposed to live in the core.
    struct MemoryChannel {
        /// This device's identifier, hexadecimal.
        me: String,
        /// The capabilities this channel declares.
        caps: FfiTransportCapabilities,
        /// Outbound queue: `(recipient, bytes)`.
        outbox: std::sync::Mutex<Vec<(FfiRecipient, Vec<u8>)>>,
        /// Inbound queue, with the sender the channel claims for each message.
        inbox: std::sync::Mutex<Vec<FfiReceivedMessage>>,
        /// Peers this channel claims.
        peers: Vec<String>,
    }

    impl MemoryChannel {
        /// An empty two-party channel for the device with this identifier.
        fn new(me: String) -> Self {
            Self {
                me,
                caps: FfiTransportCapabilities {
                    roster: FfiRoster::TwoParty,
                    // The code channel of the application is text: the user carries the
                    // payload by hand, so it has no per-message limit.
                    max_message_len: None,
                    max_qr_version: None,
                    single_use: false,
                    can_carry_payload: true,
                },
                outbox: std::sync::Mutex::new(Vec::new()),
                inbox: std::sync::Mutex::new(Vec::new()),
                peers: Vec::new(),
            }
        }

        /// Moves this channel's outbound queue into another channel's inbound queue.
        ///
        /// The outbound queue is **not** cleared, so one payload can be delivered again —
        /// which is how the replay cases are exercised.
        ///
        /// With `honest` set to `false` the claimed sender is replaced by this channel's
        /// own identifier, which models a third party handing over somebody else's payload.
        fn deliver_to(&self, target: &Self, honest: bool) {
            let outbox = self.outbox.lock().expect("no lock poisoning in tests");
            let mut inbox = target.inbox.lock().expect("no lock poisoning in tests");
            for (recipient, bytes) in outbox.iter() {
                let addressed = match recipient {
                    FfiRecipient::All => true,
                    FfiRecipient::One { device_id } => *device_id == target.me,
                };
                if !addressed {
                    continue;
                }
                inbox.push(FfiReceivedMessage {
                    sender: if honest {
                        self.me.clone()
                    } else {
                        target.me.clone()
                    },
                    message: bytes.clone(),
                });
            }
        }

        /// Discards every message in the outbound queue.
        fn clear_outbox(&self) {
            self.outbox
                .lock()
                .expect("no lock poisoning in tests")
                .clear();
        }

        /// Pushes a message straight into the inbound queue, as an attacker would.
        fn inject(&self, claimed_sender: String, message: Vec<u8>) {
            self.inbox
                .lock()
                .expect("no lock poisoning in tests")
                .push(FfiReceivedMessage {
                    sender: claimed_sender,
                    message,
                });
        }
    }

    impl FfiTransport for MemoryChannel {
        fn capabilities(&self) -> FfiTransportCapabilities {
            self.caps
        }

        fn local_device(&self) -> String {
            self.me.clone()
        }

        fn send(&self, to: FfiRecipient, message: Vec<u8>) -> Result<(), FfiError> {
            self.outbox
                .lock()
                .expect("no lock poisoning in tests")
                .push((to, message));
            Ok(())
        }

        fn receive(&self) -> Result<Option<FfiReceivedMessage>, FfiError> {
            let mut inbox = self.inbox.lock().expect("no lock poisoning in tests");
            if inbox.is_empty() {
                // "Nothing available" is a state, not a failure.
                return Ok(None);
            }
            Ok(Some(inbox.remove(0)))
        }

        fn peers(&self) -> Result<Vec<String>, FfiError> {
            Ok(self.peers.clone())
        }
    }

    /// A device identifier for tests: one hexadecimal digit repeated to 64 characters.
    fn test_device_id(digit: char) -> String {
        std::iter::repeat_n(digit, 64).collect()
    }

    /// Registers a vault and hands back the store holding its master key.
    fn registered_vault(label: &str) -> (Arc<FfiVault>, Arc<TestStore>) {
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(
            Arc::new(TestKeys::default()),
            store.clone(),
            label.to_owned(),
        )
        .expect("registration should succeed");
        (vault, store)
    }

    /// The second device of the same account: the same master key, its own empty vault.
    fn vault_of_the_same_account(store: &TestStore) -> Arc<FfiVault> {
        let master = store
            .master
            .lock()
            .expect("no lock poisoning in tests")
            .clone()
            .expect("the account is registered, so a master key exists");
        FfiVault::from_master_key(master).expect("32 bytes are a master key")
    }

    /// Two devices of one account, both holding the same entry.
    struct TwoDevices {
        /// The first device's vault.
        vault_a: Arc<FfiVault>,
        /// The second device's vault.
        vault_b: Arc<FfiVault>,
        /// The first device's session.
        session_a: Arc<FfiSyncSession>,
        /// The second device's session.
        session_b: Arc<FfiSyncSession>,
        /// The first device's channel.
        channel_a: Arc<MemoryChannel>,
        /// The second device's channel.
        channel_b: Arc<MemoryChannel>,
        /// The identifier the two devices share.
        entry_id: String,
    }

    impl TwoDevices {
        /// Registers A, gives B the same master key, and syncs one entry from A to B.
        fn with_one_shared_entry() -> Self {
            let (vault_a, store_a) = registered_vault("device-a");
            let vault_b = vault_of_the_same_account(&store_a);
            let entry_id = vault_a
                .add_entry(sample_entry("GitHub"), NOW)
                .expect("the entry should be added");

            let devices = Self {
                session_a: FfiSyncSession::open(vault_a.clone()),
                session_b: FfiSyncSession::open(vault_b.clone()),
                channel_a: Arc::new(MemoryChannel::new(test_device_id('a'))),
                channel_b: Arc::new(MemoryChannel::new(test_device_id('b'))),
                vault_a,
                vault_b,
                entry_id,
            };

            let outcome = devices.sync_a_to_b();
            assert_eq!(outcome.added, 1, "precondition: B receives the entry");
            devices.channel_a.clear_outbox();
            devices
        }

        /// Sends A's state to B's channel and merges it there.
        fn sync_a_to_b(&self) -> FfiSyncOutcome {
            self.session_a
                .send(
                    self.channel_a.clone(),
                    FfiRecipient::All,
                    FfiPayloadKind::Vault,
                )
                .expect("sending should succeed");
            self.channel_a.deliver_to(&self.channel_b, true);
            self.session_b
                .receive(self.channel_b.clone())
                .expect("receiving should succeed")
        }
    }

    /// **The criterion for the whole feature**: two vaults exchange their entries through a
    /// channel, in one process.
    ///
    /// Asserting "no error" would not be enough: a session that sends an empty payload and
    /// merges nothing reports no error either. What is asserted is that the entry really
    /// arrives and keeps its identifier, that the way back changes nothing, and that a
    /// re-delivered payload is refused.
    #[test]
    fn two_vaults_complete_a_sync_across_the_boundary() {
        let (vault_a, store_a) = registered_vault("device-a");
        let vault_b = vault_of_the_same_account(&store_a);
        let entry_id = vault_a
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("the entry should be added");
        assert_eq!(vault_b.entry_count(), 0, "precondition: B starts empty");

        let session_a = FfiSyncSession::open(vault_a.clone());
        let session_b = FfiSyncSession::open(vault_b.clone());
        let channel_a = Arc::new(MemoryChannel::new(test_device_id('a')));
        let channel_b = Arc::new(MemoryChannel::new(test_device_id('b')));

        let plan = session_a
            .plan_share(channel_a.clone())
            .expect("planning should succeed");
        assert!(
            matches!(plan, FfiSharePlan::FullPayload { len } if len > 0),
            "a vault with one entry plans as a full payload: {plan:?}"
        );

        let sync_id = session_a
            .send(channel_a.clone(), FfiRecipient::All, FfiPayloadKind::Vault)
            .expect("sending should succeed");
        assert_eq!(sync_id.len(), 64, "a payload identifier is 32 bytes in hex");

        channel_a.deliver_to(&channel_b, true);
        let outcome = session_b
            .receive(channel_b.clone())
            .expect("receiving should succeed");
        assert_eq!(outcome.added, 1, "the entry must arrive: {outcome:?}");
        assert!(
            !outcome.needs_adjudication,
            "an ordinary sync asks the user nothing: {outcome:?}"
        );
        assert!(!outcome.made_no_change, "something did change: {outcome:?}");
        assert_eq!(vault_b.entry_count(), 1);
        let arrived = vault_b.entries();
        assert_eq!(arrived[0].name, "GitHub");
        assert_eq!(
            arrived[0].id, entry_id,
            "the entry keeps its identifier, which is the only thing the two devices agree on"
        );

        let replay = session_b
            .receive(channel_b.clone())
            .expect_err("nothing is queued any more, so the channel reports no session");
        assert_eq!(replay.kind(), "sync_no_session_found");

        // Delivering the very same bytes again is a replay, and is refused.
        channel_a.deliver_to(&channel_b, true);
        let replay = session_b
            .receive(channel_b.clone())
            .expect_err("the same payload must not be applied twice");
        assert_eq!(replay.kind(), "sync_already_applied");

        session_b
            .send(channel_b.clone(), FfiRecipient::All, FfiPayloadKind::Vault)
            .expect("sending back should succeed");
        channel_b.deliver_to(&channel_a, true);
        let back = session_a
            .receive(channel_a.clone())
            .expect("receiving should succeed");
        assert!(
            back.made_no_change,
            "A already holds everything B has: {back:?}"
        );
        assert!(!back.needs_adjudication);
    }

    /// A payload that claims a different sender than the channel reports is refused.
    ///
    /// This is the third-party case: the payload is cryptographically valid, so only the
    /// channel's own report can tell that somebody else handed it over.
    #[test]
    fn a_payload_whose_sender_disagrees_with_the_channel_is_refused() {
        let devices = TwoDevices::with_one_shared_entry();
        let mut second_entry = sample_entry("GitLab");
        second_entry.name = "GitLab".to_owned();
        devices
            .vault_a
            .add_entry(second_entry, NOW + 10)
            .expect("the entry should be added");

        devices
            .session_a
            .send(
                devices.channel_a.clone(),
                FfiRecipient::All,
                FfiPayloadKind::Vault,
            )
            .expect("sending should succeed");
        devices.channel_a.deliver_to(&devices.channel_b, false);

        let error = devices
            .session_b
            .receive(devices.channel_b.clone())
            .expect_err("a misreported sender must be refused");
        assert_eq!(error.kind(), "sync_sender_mismatch");
        assert_eq!(
            devices.vault_b.entry_count(),
            1,
            "a refused payload must not modify the vault"
        );
    }

    /// A device identifier that is not hexadecimal is refused before anything is sent.
    #[test]
    fn an_identifier_that_is_not_hexadecimal_is_refused() {
        let (vault, _) = registered_vault("device-a");
        let session = FfiSyncSession::open(vault);
        let channel = Arc::new(MemoryChannel::new("not a device identifier".to_owned()));

        let error = session
            .send(channel, FfiRecipient::All, FfiPayloadKind::Vault)
            .expect_err("the identifier must be rejected");
        assert_eq!(error.kind(), "invalid_device_id");
    }

    /// A decision for a conflict that is not waiting is refused rather than applied to
    /// whatever now sits under that identifier.
    #[test]
    fn a_decision_for_a_conflict_that_is_not_waiting_is_refused() {
        let (vault, _) = registered_vault("device-a");
        let session = FfiSyncSession::open(vault);

        let error = session
            .adjudicate("0".repeat(32), FfiDecision::KeepLocal)
            .expect_err("nothing is waiting for this identifier");
        assert_eq!(error.kind(), "unknown_conflict");
    }

    /// A deletion the peer reports about an entry **edited here** is a decision for a human.
    ///
    /// The two directions of "one side deleted it" are pinned separately: here the peer
    /// deleted and this device edited afterwards; the nested test covers the other one.
    #[test]
    fn a_peer_deletion_of_an_edited_entry_is_reported_and_closed_by_the_decision() {
        let devices = TwoDevices::with_one_shared_entry();

        let mut edited = sample_entry("GitHub (work)");
        edited.id = devices.entry_id.clone();
        devices
            .vault_b
            .update_entry(edited, NOW + 120)
            .expect("the edit should be accepted");
        devices
            .vault_a
            .remove_entry(devices.entry_id.clone(), NOW + 60)
            .expect("the deletion should be accepted");

        let outcome = devices.sync_a_to_b();
        assert!(
            outcome.needs_adjudication,
            "a deletion against an edited entry must be reported: {outcome:?}"
        );
        assert_eq!(
            outcome.deletions_applied, 0,
            "nothing may be deleted before the user decides"
        );
        assert_eq!(
            devices.vault_b.entry_count(),
            1,
            "the entry is still there until the decision"
        );
        assert_eq!(outcome.conflicts.len(), 1);
        let conflict = &outcome.conflicts[0];
        assert_eq!(conflict.kind, "peer_deleted");
        assert_eq!(conflict.entry_id, devices.entry_id);
        assert_eq!(
            conflict
                .local
                .as_ref()
                .expect("the local version is shown")
                .name,
            "GitHub (work)"
        );
        assert!(
            conflict.incoming.is_none(),
            "the peer sent a tombstone, which has nothing to show"
        );
        assert!(
            devices.session_b.pending_conflicts().len() == 1,
            "the conflict stays available until it is decided"
        );

        devices
            .session_b
            .adjudicate(devices.entry_id.clone(), FfiDecision::TakeIncoming)
            .expect("the decision should apply");
        assert_eq!(devices.vault_b.entry_count(), 0, "the deletion is applied");
        assert_eq!(devices.vault_b.tombstone_count(), 1);
        assert!(
            devices.session_b.pending_conflicts().is_empty(),
            "a decided conflict stops being pending"
        );

        devices.channel_a.clear_outbox();
        let settled = devices.sync_a_to_b();
        assert!(
            !settled.needs_adjudication,
            "the decision must close the conflict: {settled:?}"
        );
    }

    /// An entry deleted **here** that the peer still holds can be kept deleted.
    #[test]
    fn a_local_deletion_can_be_confirmed_against_a_peer_that_still_has_the_entry() {
        let devices = TwoDevices::with_one_shared_entry();
        devices
            .vault_b
            .remove_entry(devices.entry_id.clone(), NOW + 60)
            .expect("the deletion should be accepted");

        let outcome = devices.sync_a_to_b();
        assert!(outcome.needs_adjudication, "{outcome:?}");
        let conflict = &outcome.conflicts[0];
        assert_eq!(conflict.kind, "local_deleted");
        assert!(
            conflict.local.is_none(),
            "this device holds only a tombstone, so there is no local version to show"
        );
        assert_eq!(
            conflict
                .incoming
                .as_ref()
                .expect("the peer's version is shown")
                .name,
            "GitHub"
        );

        devices
            .session_b
            .adjudicate(devices.entry_id.clone(), FfiDecision::KeepLocal)
            .expect("the decision should apply");
        assert_eq!(devices.vault_b.entry_count(), 0, "the entry stays deleted");
        assert!(
            devices.vault_b.tombstone_count() == 1,
            "the deletion is still recorded, so it keeps travelling"
        );
    }

    /// The same conflict, decided the other way: the entry comes back.
    ///
    /// This is the case that needs the tombstone to be dropped: keeping it next to a live
    /// entry would let the payload builder send the tombstone on its own, and the peer would
    /// delete the entry again.
    #[test]
    fn an_entry_deleted_here_can_be_restored_from_the_peer() {
        let devices = TwoDevices::with_one_shared_entry();
        devices
            .vault_b
            .remove_entry(devices.entry_id.clone(), NOW + 60)
            .expect("the deletion should be accepted");

        let outcome = devices.sync_a_to_b();
        assert_eq!(outcome.conflicts[0].kind, "local_deleted");
        devices
            .session_b
            .adjudicate(devices.entry_id.clone(), FfiDecision::TakeIncoming)
            .expect("the decision should apply");

        assert_eq!(devices.vault_b.entry_count(), 1, "the entry is back");
        assert_eq!(
            devices.vault_b.tombstone_count(),
            0,
            "the tombstone must be gone, or the peer would delete the entry again"
        );
        assert_eq!(
            devices
                .vault_b
                .entry(devices.entry_id.clone())
                .expect("the entry is readable")
                .name,
            "GitHub"
        );

        devices.channel_a.clear_outbox();
        let settled = devices.sync_a_to_b();
        assert!(
            !settled.needs_adjudication,
            "the decision must close the conflict: {settled:?}"
        );
        assert!(settled.made_no_change, "both sides now hold the same entry");
    }

    /// A payload that authenticates but is not a payload at all is refused without touching
    /// the vault, and the error says which layer rejected it.
    #[test]
    fn a_garbage_payload_is_refused_across_the_boundary() {
        let devices = TwoDevices::with_one_shared_entry();
        devices
            .channel_b
            .inject(test_device_id('a'), vec![0_u8; 200]);

        let error = devices
            .session_b
            .receive(devices.channel_b.clone())
            .expect_err("random bytes are not a payload");
        assert_eq!(
            error.kind(),
            "sync_bad_magic",
            "the header is checked before anything is decrypted"
        );
        assert_eq!(devices.vault_b.entry_count(), 1, "the vault is untouched");
    }

    /// A payload too large for one code travels as several, collected across the boundary.
    ///
    /// The frame images are read back through the same entry point a camera's picture goes
    /// through, so what is asserted is the whole path: draw the frames, take their text out of
    /// the pixels, hand them over in the wrong order and with a repeat, and get back the
    /// payload that went in.
    #[test]
    fn a_payload_too_large_for_one_code_travels_as_several() {
        let payload = format!("otpauth://totp/example?secret={}", "A".repeat(3000));
        let frames = qr_encode_frames(payload.clone(), FfiEcLevel::Medium, 20, 32, 4, 4)
            .expect("the frames should be drawn");
        assert!(
            frames.len() > 1,
            "3000 bytes must need more than one code, not {}",
            frames.len()
        );

        let capacity = qr_frame_capacity(FfiEcLevel::Medium, 20).expect("a capacity");
        let collector = FfiFrameCollector::new(capacity);
        let mut order: Vec<&FfiQrFrame> = frames.iter().rev().collect();
        order.push(frames.first().expect("at least one frame"));

        let mut completed: Option<Vec<u8>> = None;
        for frame in order {
            let text = qr_decode_text(
                frame.image.pixels.clone(),
                frame.image.width,
                frame.image.height,
            )
            .expect("a frame's own image must be readable");
            let step = collector.push(text).expect("a frame of this application");
            assert!(step.index >= 1 && step.index <= step.count);
            if let Some(bytes) = step.payload {
                completed = Some(bytes);
            }
        }

        assert_eq!(
            String::from_utf8(completed.expect("the set completes")).expect("UTF-8 text"),
            payload
        );
        assert!(collector.missing().is_empty(), "nothing is left missing");
    }

    // ── The LAN channel ──────────────────────────────────────────────────

    /// A device identifier in the form this boundary uses, derived from a seed.
    fn lan_device(seed: u8) -> String {
        DeviceId::from_bytes([seed; 32]).to_hex()
    }

    #[test]
    fn a_socket_address_round_trips_and_a_wrong_one_is_rejected() {
        let socket = parse_socket("192.168.1.5:41234").expect("a printed address must parse");
        assert_eq!(socket.to_string(), "192.168.1.5:41234");
        assert_eq!(
            parse_socket("192.168.1.5")
                .expect_err("a missing port is not an address")
                .kind(),
            "bad_socket"
        );
        assert_eq!(
            parse_socket("not an address")
                .expect_err("text is not an address")
                .kind(),
            "bad_socket"
        );
    }

    /// The LAN kinds are distinct and are the ones the host side branches on.
    ///
    /// The transport's error enum is `#[non_exhaustive]`, so an unmapped variant lands in
    /// `lan_error` without the compiler saying anything. This list is what says it.
    #[test]
    fn every_lan_error_kind_is_distinct_and_known() {
        use qualia_transport::Error as LanError;

        let cases = [
            (LanError::NoConnectionToPeer, "no_connection_to_peer"),
            (LanError::TransportEmpty, "transport_empty"),
            (
                LanError::PayloadTooLarge {
                    needed: 10,
                    limit: 1,
                },
                "payload_too_large",
            ),
            (LanError::NoLanPeersFound, "no_lan_peers_found"),
            (LanError::LanSocket { operation: "bind" }, "lan_socket"),
            (
                LanError::LanTransport {
                    operation: "connect",
                },
                "lan_transport",
            ),
            (LanError::NotOurLanAddress, "not_our_lan_address"),
            (
                LanError::BadLanAddressLength {
                    expected: 42,
                    actual: 4,
                },
                "bad_lan_address_length",
            ),
            (LanError::ZeroPort, "zero_port"),
        ];

        let mut seen = std::collections::HashSet::new();
        for (source, expected) in cases {
            assert_eq!(lan_error(source).kind(), expected);
            assert!(seen.insert(expected), "{expected} is mapped twice");
        }
    }

    /// The channel answers the trait's questions, and answers them the same way through the
    /// trait object a session is handed.
    #[test]
    fn the_lan_capabilities_describe_a_reusable_stream() {
        let Ok(channel) = FfiLanChannel::open(lan_device(1)) else {
            return;
        };

        let caps = channel.capabilities();
        assert_eq!(caps.roster, FfiRoster::MultiParty);
        assert_eq!(caps.max_message_len, Some(MAX_MESSAGE_LEN as u64));
        assert_eq!(caps.max_qr_version, None, "this channel displays no code");
        assert!(!caps.single_use, "a connection is not a one-shot artifact");
        assert!(caps.can_carry_payload);

        assert_eq!(channel.local_device(), lan_device(1));
        assert!(
            channel
                .peers()
                .expect("the peer table is readable")
                .is_empty(),
            "a fresh channel has no peers"
        );
        assert!(
            channel
                .receive()
                .expect("an empty inbox is not a failure")
                .is_none(),
            "nothing has been sent to this channel"
        );

        let transport = channel.transport();
        assert_eq!(transport.local_device(), lan_device(1));
        assert_eq!(transport.capabilities().roster, FfiRoster::MultiParty);
        assert_eq!(
            transport.capabilities().max_message_len,
            Some(MAX_MESSAGE_LEN as u64)
        );
        assert!(
            transport
                .peers()
                .expect("the peer table is readable")
                .is_empty()
        );

        channel.shutdown();
    }

    #[test]
    fn the_record_is_the_transports_own_connection_record() {
        let Ok(channel) = FfiLanChannel::open(lan_device(2)) else {
            return;
        };

        let record = channel.record().expect("an open endpoint has a record");
        let address = LanAddress::decode(&record).expect("a record this layer built must decode");
        assert_eq!(address.port, channel.inner.port().expect("a bound port"));
        assert_eq!(address.endpoint_key, channel.inner.endpoint_key());

        channel.shutdown();
    }

    #[test]
    fn a_peer_must_be_registered_before_it_can_be_sent_to() {
        let Ok(channel) = FfiLanChannel::open(lan_device(3)) else {
            return;
        };

        let error = channel
            .send(
                FfiRecipient::One {
                    device_id: lan_device(4),
                },
                b"hello".to_vec(),
            )
            .expect_err("a peer that was never registered has no connection");
        assert_eq!(error.kind(), "no_connection_to_peer");

        assert!(
            channel.send(FfiRecipient::All, b"hello".to_vec()).is_ok(),
            "a broadcast with nobody registered is accepted and reaches nobody"
        );

        channel.shutdown();
    }

    #[test]
    fn registering_a_peer_takes_a_record_and_an_address() {
        let Ok(channel) = FfiLanChannel::open(lan_device(5)) else {
            return;
        };
        let Ok(other) = FfiLanChannel::open(lan_device(6)) else {
            return;
        };

        let record = other.record().expect("a record");
        let socket = format!("127.0.0.1:{}", other.inner.port().expect("a port"));
        channel
            .remember_peer(lan_device(6), record.clone(), socket.clone())
            .expect("registering a peer with a real record must work");
        assert_eq!(
            channel.peers().expect("the peer table is readable"),
            vec![lan_device(6)]
        );

        assert_eq!(
            channel
                .remember_peer(lan_device(6), vec![0; 4], socket.clone())
                .expect_err("four bytes are not a connection record")
                .kind(),
            "not_our_lan_address"
        );
        assert_eq!(
            channel
                .remember_peer(lan_device(6), record.clone(), "not an address".to_owned())
                .expect_err("a socket address is `ip:port`")
                .kind(),
            "bad_socket"
        );
        assert_eq!(
            channel
                .remember_peer("nope".to_owned(), record.clone(), socket)
                .expect_err("an identifier is 64 hexadecimal characters")
                .kind(),
            "invalid_device_id"
        );
        assert_eq!(
            channel.peers().expect("the peer table is readable"),
            vec![lan_device(6)],
            "a rejected registration must not change the peer table"
        );

        channel
            .forget_peer(lan_device(6))
            .expect("forgetting works");
        assert!(
            channel
                .peers()
                .expect("the peer table is readable")
                .is_empty()
        );
        assert_eq!(
            channel
                .forget_peer("nope".to_owned())
                .expect_err("a malformed identifier is refused")
                .kind(),
            "invalid_device_id"
        );

        other.shutdown();
        channel.shutdown();
    }

    /// Two channels on this machine exchange one message, sender included.
    ///
    /// Loopback is the only requirement: the addresses come from the endpoints themselves, so
    /// nothing here needs a real network segment. This is also what pins the sender claim — the
    /// field the core compares with the sender inside a payload.
    #[test]
    fn two_channels_exchange_a_message_over_loopback() {
        let Ok(a) = FfiLanChannel::open(lan_device(7)) else {
            return;
        };
        let Ok(b) = FfiLanChannel::open(lan_device(8)) else {
            return;
        };

        let record = b.record().expect("a record");
        // The port in this address is deliberately wrong, and only its IP is meant to matter:
        // the record carries the port the endpoint listens on, while the address a datagram
        // arrives from carries the lobby's. A caller that hands over what it saw must still
        // end up dialing the endpoint.
        a.remember_peer(lan_device(8), record, "127.0.0.1:1".to_owned())
            .expect("registering a peer must work");

        a.send(
            FfiRecipient::One {
                device_id: lan_device(8),
            },
            b"the payload".to_vec(),
        )
        .expect("the send must be accepted");

        let received = (0..200)
            .find_map(|_| {
                std::thread::sleep(std::time::Duration::from_millis(25));
                b.receive().expect("receiving must not fail")
            })
            .expect("the message must arrive within five seconds");
        assert_eq!(received.sender, lan_device(7), "the sender is the claim");
        assert_eq!(received.message, b"the payload");

        a.shutdown();
        b.shutdown();
    }

    /// A discovered peer is offered at the endpoint's own port, not at the port its
    /// announcement was sent from.
    ///
    /// The two differ whenever the lobby is in use — announcements leave the lobby's socket,
    /// which is bound to the multicast port — and dialing the sender's port reaches a socket
    /// that speaks the announcement format and never answers a connection.
    #[test]
    fn a_discovered_peer_is_offered_at_the_endpoints_own_port() {
        let device = DeviceId::from_bytes([7; 32]);
        let peer = Peer {
            device,
            endpoint_key: EndpointKey::from_bytes([8; 32]),
            port: 41_007,
            source: Some(SocketAddr::from(([192, 168, 1, 7], 21_377))),
            status: PeerStatus::Here,
            last_seen_ms: 0,
            sequence: 0,
        };

        let offered = lan_peer_of(peer);
        assert_eq!(offered.device_id, device.to_hex());
        assert_eq!(
            offered.socket.as_deref(),
            Some("192.168.1.7:41007"),
            "the IP comes from the datagram and the port from the announcement"
        );
        assert_eq!(
            LanAddress::decode(&offered.record)
                .expect("a record this layer built must decode")
                .port,
            41_007
        );
        assert!(offered.here);

        let source_unknown = lan_peer_of(Peer {
            source: None,
            ..peer
        });
        assert_eq!(
            source_unknown.socket, None,
            "a peer whose announcement had no source can be shown but not dialed"
        );
    }

    #[test]
    fn a_lobby_reports_its_view_and_stops_cleanly() {
        let Ok(channel) = FfiLanChannel::open(lan_device(9)) else {
            return;
        };
        let Ok(lobby) = channel.open_lobby() else {
            return;
        };

        assert!(
            lobby.peers().is_empty(),
            "a lobby that just opened has heard nobody"
        );
        lobby
            .announce_now()
            .expect("announcing must reach the socket");
        lobby.shutdown();
        lobby.shutdown();

        channel.shutdown();
    }

    /// The password wrap round trips across the boundary and reports a wrong password.
    #[test]
    fn lock_password_wrap_roundtrips() {
        let master = MasterKey::generate().expect("randomness should be available");
        let master_bytes = flow::master_key_to_bytes(&master).expose_secret().to_vec();

        let file = wrap_master_key_with_password(master_bytes.clone(), "correct horse".to_owned())
            .expect("wrapping should succeed");
        assert_eq!(
            file.len() as u64,
            lock_wrap_len(),
            "the exposed length must match what the wrap returns"
        );

        let restored = unwrap_master_key_with_password(file.clone(), "correct horse".to_owned())
            .expect("the right password must open it");
        assert_eq!(restored, master_bytes);

        let error = unwrap_master_key_with_password(file, "wrong password".to_owned())
            .expect_err("a wrong password must be rejected");
        assert_eq!(error.kind(), "lock_password_rejected");
    }

    /// Empty and oversized passwords are rejected at the boundary.
    #[test]
    fn lock_password_limits_are_enforced() {
        let master = MasterKey::generate().expect("randomness should be available");
        let master_bytes = flow::master_key_to_bytes(&master).expose_secret().to_vec();

        let error = wrap_master_key_with_password(master_bytes.clone(), String::new())
            .expect_err("an empty password must be rejected");
        assert_eq!(error.kind(), "lock_passphrase_empty");

        let oversized = "x".repeat(MAX_PASSPHRASE_CHARS + 1);
        let error = wrap_master_key_with_password(master_bytes, oversized)
            .expect_err("an oversized password must be rejected");
        assert_eq!(error.kind(), "input_too_long");
    }

    /// The state helpers build and recognize the two marker files.
    #[test]
    fn lock_state_files_roundtrip() {
        let marker = lock_marker(true, false, 1_700_000_000).expect("marker");
        assert!(is_lock_marker(marker.clone()));
        assert!(!is_lock_marker(vec![0_u8; 19]));

        let pending = lock_pending(1_700_000_000).expect("pending");
        assert!(is_lock_pending(pending.clone()));
        assert!(!is_lock_pending(vec![0_u8; 18]));

        assert!(
            lock_marker(false, false, 1).is_err(),
            "a marker that names no wrap must be rejected"
        );
        assert!(lock_pending(0).is_err(), "a zero time must be rejected");
    }

    /// A password wrap is recognizable without running Argon2id.
    #[test]
    fn lock_password_wrap_is_recognized_without_the_kdf() {
        let master = MasterKey::generate().expect("randomness should be available");
        let master_bytes = flow::master_key_to_bytes(&master).expose_secret().to_vec();
        let file = wrap_master_key_with_password(master_bytes, "correct horse".to_owned())
            .expect("wrapping should succeed");

        assert!(is_lock_password_wrap(file.clone()));
        assert!(!is_lock_password_wrap(file[..file.len() - 1].to_vec()));
        assert!(!is_lock_password_wrap(vec![0_u8; 110]));
    }

    /// Changing the password checks the old one against the open vault's master key.
    #[test]
    fn rewrap_lock_password_checks_the_old_password() {
        let master = MasterKey::generate().expect("randomness should be available");
        let master_bytes = flow::master_key_to_bytes(&master).expose_secret().to_vec();
        let vault = FfiVault::from_master_key(master_bytes.clone()).expect("the vault should open");
        let old_wrap =
            wrap_master_key_with_password(master_bytes.clone(), "old password".to_owned())
                .expect("the old wrap should be written");

        let new_wrap = vault
            .rewrap_lock_password(
                old_wrap.clone(),
                "old password".to_owned(),
                "new password".to_owned(),
            )
            .expect("the new wrap should be written");
        assert_eq!(
            unwrap_master_key_with_password(new_wrap, "new password".to_owned())
                .expect("the new wrap should open"),
            master_bytes
        );

        let error = vault
            .rewrap_lock_password(
                old_wrap.clone(),
                "not the old password".to_owned(),
                "new password".to_owned(),
            )
            .expect_err("a wrong old password must be rejected");
        assert_eq!(error.kind(), "lock_password_rejected");

        let other_master = MasterKey::generate().expect("randomness should be available");
        let other_vault = FfiVault::from_master_key(
            flow::master_key_to_bytes(&other_master)
                .expose_secret()
                .to_vec(),
        )
        .expect("the other vault should open");
        let error = other_vault
            .rewrap_lock_password(
                old_wrap.clone(),
                "old password".to_owned(),
                "new password".to_owned(),
            )
            .expect_err("a wrap from another account must be rejected");
        assert_eq!(error.kind(), "lock_password_rejected");

        let error = vault
            .rewrap_lock_password(old_wrap, "old password".to_owned(), String::new())
            .expect_err("an empty new password must be rejected");
        assert_eq!(error.kind(), "lock_passphrase_empty");
    }

    /// A backend with fixed answers, so the wrapper's mapping can be tested without a prompt.
    #[derive(Debug)]
    struct UnsupportedAuthStore;

    impl bioauth::AuthBoundKeyStore for UnsupportedAuthStore {
        fn availability(&self) -> bioauth::Availability {
            bioauth::Availability::Unsupported {
                reason: "test backend",
            }
        }

        fn create(&self) -> bioauth::Result<()> {
            Err(bioauth::Error::Unavailable {
                reason: "test backend",
            })
        }

        fn wrap(&self, _master: &bioauth::MasterKey) -> bioauth::Result<Vec<u8>> {
            Err(bioauth::Error::Unavailable {
                reason: "test backend",
            })
        }

        fn unwrap(&self, _blob: &[u8]) -> bioauth::Result<bioauth::MasterKey> {
            Err(bioauth::Error::Unavailable {
                reason: "test backend",
            })
        }

        fn delete_blob(&self, _blob: &[u8]) -> bioauth::Result<()> {
            Ok(())
        }

        fn delete(&self) -> bioauth::Result<()> {
            Ok(())
        }
    }

    /// A host sealer whose answers are fixed, so the boundary can be exercised here.
    #[derive(Debug)]
    struct FakeHostSealer {
        cancelled: std::sync::atomic::AtomicBool,
    }

    impl FfiPlatformSealer for FakeHostSealer {
        fn backend(&self) -> String {
            "android-keystore".to_owned()
        }

        fn availability(&self) -> FfiAuthAvailability {
            FfiAuthAvailability::Available {
                backend: "android-keystore".to_owned(),
                hardware_backed: true,
            }
        }

        fn seal(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, FfiError> {
            if self.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(FfiError::AuthBound {
                    kind: "bioauth_authentication_failed".to_owned(),
                    detail: "the prompt was dismissed".to_owned(),
                });
            }
            Ok(plaintext.iter().map(|byte| byte ^ 0x5A).collect())
        }

        fn unseal(&self, envelope: Vec<u8>) -> Result<Vec<u8>, FfiError> {
            if self.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(FfiError::AuthBound {
                    kind: "bioauth_authentication_failed".to_owned(),
                    detail: "the prompt was dismissed".to_owned(),
                });
            }
            Ok(envelope.iter().map(|byte| byte ^ 0x5A).collect())
        }

        fn delete(&self) -> Result<(), FfiError> {
            Ok(())
        }
    }

    /// A host-supplied sealer seals and unseals through the same envelope.
    #[test]
    fn a_host_sealer_roundtrips() {
        let host = Arc::new(FakeHostSealer {
            cancelled: std::sync::atomic::AtomicBool::new(false),
        });
        let store = FfiAuthBoundKeyStore::with_host(host.clone(), "android-keystore".to_owned())
            .expect("the backend name is known");
        assert!(matches!(
            store.availability(),
            FfiAuthAvailability::Available { .. }
        ));

        let master = vec![5_u8; 32];
        let blob = store.wrap(master.clone()).expect("seal");
        assert_ne!(&blob[blob.len() - 32..], master.as_slice());
        assert_eq!(store.unwrap(blob).expect("unseal"), master);

        host.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let error = match store.wrap(master.clone()) {
            Ok(_) => panic!("a cancelled gesture must fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), "bioauth_authentication_failed");
    }

    /// A backend name this build does not know is rejected at construction.
    #[test]
    fn an_unknown_host_backend_is_rejected() {
        let host = Arc::new(FakeHostSealer {
            cancelled: std::sync::atomic::AtomicBool::new(false),
        });
        let built = FfiAuthBoundKeyStore::with_host(host, "not-a-backend".to_owned());
        let error = match built {
            Ok(_) => panic!("an unknown backend must be refused"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), "bioauth_unknown_backend");
    }

    /// The auth-bound wrapper keeps the library's error kinds and never falls back.
    #[test]
    fn auth_bound_errors_keep_their_kind() {
        let store = FfiAuthBoundKeyStore::with_store(Box::new(UnsupportedAuthStore));
        assert!(matches!(
            store.availability(),
            FfiAuthAvailability::Unsupported { .. }
        ));

        let error = store
            .wrap(vec![0_u8; 31])
            .expect_err("a 31-byte key must be rejected");
        assert_eq!(error.kind(), "bioauth_master_key_wrong_length");

        let error = store.create().expect_err("the test backend is unavailable");
        assert_eq!(error.kind(), "bioauth_unavailable");

        let vault = FfiVault::from_master_key(vec![9_u8; 32]).expect("the vault should open");
        let error = vault
            .wrap_master_for_auth_bound(store)
            .expect_err("the test backend must not wrap");
        assert_eq!(error.kind(), "bioauth_unavailable");
    }
}
