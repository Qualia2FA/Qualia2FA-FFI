<div align="center" style="align-items: center">

# Qualia2FA-FFI

简体中文 | [English](README.en.md)

把 [`qualia2fa-core`](https://github.com/Qualia2FA/Qualia2FA-Core) 暴露为 [UniFFI](https://mozilla.github.io/uniffi-rs/) 绑定，供 Kotlin、Swift 等托管语言调用。

[![License](https://img.shields.io/github/license/Qualia2FA/Qualia2FA-FFI?label=License)][License]
[![Releases](https://img.shields.io/github/downloads/Qualia2FA/Qualia2FA-FFI/total?logo=github&label=Downloads)][Releases]
[![crates.io](https://img.shields.io/crates/d/qualia2fa-ffi?logo=crates.io&label=crates.io+Downloads)][crates.io]

[License]: LICENSE

[Releases]: https://github.com/Qualia2FA/Qualia2FA-FFI/releases

[crates.io]: https://crates.io/crates/qualia2fa-ffi

</div>

---

| 项       | 值                                                     |
|----------|--------------------------------------------------------|
| Crate 名 | `qualia2fa-ffi`                                        |
| 类型     | `cdylib` + `staticlib`（另有 `uniffi-bindgen` 二进制） |
| Edition  | 2024                                                   |
| 许可证   | `LGPL-3.0-or-later`                                    |
| UniFFI   | **`0.29`**                                             |

已导出如下功能：
- OTP（TOTP / HOTP / mOTP / Yandex OTP / Steam Guard）
- 保险库
- 树状分组（父子关系、条目与子分组的混合顺序）
- 导入与导出（六种格式，含两个 `.q2fa` 容器）
- 图标（随条目过边界，字节原样）
- 恢复密钥
- 注册/登录
- 挑战-应答与同步

除此之外，本层还**自己实现**了局域网通道（组播发现 + 端点数据面）——那一半只在 Rust 侧可用，端侧实现不了。

## 用法

### 1. 构建动态库

```bash
cargo build --release
```

产物为 `target/release/qualia2fa_ffi.dll`（Windows）、`.so`（Linux/Android）、
`.dylib`（macOS/iOS）。要静态库则取同目录下的 `.lib`/`.a`。

### 2. 生成端侧绑定

绑定生成器是本仓库自己的二进制，这样**生成绑定所用的 UniFFI 版本与库编译时
所用的完全一致**。改用全局安装的 `uniffi-bindgen` 会让两边版本漂移，产出
「能编译但运行时不匹配」的绑定。

```bash
cd FFI    # 必须在仓库根执行：uniffi-bindgen 内部会调用 cargo metadata

# Kotlin（JVM 桌面端与 Android 共用同一份绑定）
cargo run --bin uniffi-bindgen -- generate \
    --library target/debug/qualia2fa_ffi.dll \
    --language kotlin --out-dir ./bindings

# Swift（iOS）
cargo run --bin uniffi-bindgen -- generate \
    --library target/debug/qualia2fa_ffi.dll \
    --language swift --out-dir ./bindings-swift
```

生成的绑定落在 `bindings/`、`bindings-swift/`，**不入库**——它们是派生物，应由
端侧构建流程在编译前生成。入库会立刻产生「绑定与接口定义不同步」的问题：改了
Rust 签名却忘了重新生成，编译期不报错、运行期才崩。

> 提示若出现 `Unable to auto-format ... using ktlint: program not found`，只是缺少
> 可选的 `ktlint`，产物依然正确可用。

### 3. 在 Kotlin 中调用

生成的绑定位于 `uniffi.qualia2fa_ffi` 包下，函数为顶层函数：

```kotlin
import uniffi.qualia2fa_ffi.*

val entry = parseOtpauthUri("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP")
val code = totpCode(entry.secretBase32, System.currentTimeMillis() / 1000, entry.period, entry.algorithm, entry.digits)
```

### 4. 分发动态库

绑定通过 JNA（JVM）或系统动态加载器（Swift）按**名字**查找动态库，因此
`qualia2fa_ffi.dll` / `libqualia2fa_ffi.so` / `libqualia2fa_ffi.dylib` 必须与
应用一起分发，并落在加载器能找到的位置。各平台的放置方式由端侧构建决定。

## 接口

### 验证码

| 函数                                                                                    | 说明                                   |
|-----------------------------------------------------------------------------------------|----------------------------------------|
| `parse_otpauth_uri`                                                                     | 解析 `otpauth://` URI                  |
| `serialize_otpauth_uri`                                                                 | 序列化回 URI（账号名含 `:` 会被拒绝）  |
| `totp_code` / `hotp_code`                                                               | 计算验证码                             |
| `steam_guard_code`                                                                      | Steam Guard 5 位字母表                 |
| `verify_code_with_drift`                                                                | 容错校验，返回命中的偏移量便于时钟校准 |
| `codes_match`                                                                           | 常量时间比较                           |
| `generate_secret_base32`                                                                | 生成 256 位随机种子（OS CSPRNG）       |
| `recommended_min_secret_len` / `is_secret_shorter_than_recommended` / `secret_byte_len` | 种子强度提示                           |
| `core_version`                                                                          | 核心版本，供兼容性检查                 |

**时间一律由调用方传入。** 核心不读时钟，只有时间作为参数传入，RFC 6238 的
测试向量才能被确定性地验证。端侧应传系统时钟的 Unix 秒数。

### 保险库（`FfiVault`）

条目本身由 `FfiVault` 持有，**主密钥留在 Rust 侧**。「打开 → 列条目 → 改条目 →
存回文件」这条最常见的路径上，主密钥一次都不会以字节形式出现在 Kotlin/Swift 里。

| 方法                                                        | 说明                                        |
|-------------------------------------------------------------|---------------------------------------------|
| `FfiVault.register(keys, store, label)`                     | 生成主密钥、取得设备身份、写入平台密钥库    |
| `FfiVault.open(store, data)`                                | 用密钥库里的主密钥打开保险库文件            |
| `FfiVault.fromMasterKey(bytes)`                             | 用已有主密钥建立空保险库（登录/恢复之后用） |
| `entryCount` / `isEmpty` / `tombstoneCount`                 | 计数                                        |
| `entries` / `entry(id)`                                     | 读取条目（**顺序不保证**，列表请自行排序）  |
| `addEntry(entry, now)` → `id`                               | 新增                                        |
| `updateEntry(entry, now)`                                   | 修改（**标识不变、不留墓碑**）              |
| `removeEntry(id, now)` → `Bool`                             | 删除（留墓碑）                              |
| `serialize`                                                 | 序列化，供端侧**原子地**落盘                |
| `codeFor(id, now)` / `hotpFor(id, counter)`                 | 按**条目的种类**算验证码                    |
| `groups` / `childrenOf(id)` / `parentOf(id)` / `depthOf(id)` | 树本身：前序的组列表、某组的子节点、父与深度（顶分组永远是第一个） |
| `createGroupIn` / `renameGroup` / `setChildren` / `removeGroup` | 新建到指定父、改名、写一整条子节点列表、删除（子节点移到父分组） |
| `setOrdering` / `assignToGroup`                             | 只重排某组里的条目，以及把条目移进某个分组（`setChildren` 的子集用法） |
| `export(format, password)`                                  | 导出六种格式之一（两个 `.q2fa` 容器 + 四种外部格式） |
| `detectPortableFile` / `openPortableFile` / `FfiPortableRestore` | 识别并恢复 `.q2fa`（含旧 key-only 文件），失败时回滚主密钥 |
| `exportRecoveryKey(passphrase, …)`                          | 导出恢复密钥文件                            |

`updateEntry` 与 `removeEntry` 的区别不只是语义：修改保留条目标识，删除留下墓碑。
两者在另一台设备上被读成完全不同的操作，因此**不要**用「删除 + 新增」实现修改。

### 导入（`FfiImport`）

导入一份来自 Qualia2FA / Aegis 的导出：`FfiImport.preview(bytes, format, password, now)` 读它（JSON、HTML，
或每行一个 URI；加密的 JSON 需要口令），`detectFormat(bytes)` 也可以先从内容猜格式。返回的对象上，
`entries` / `problems` / `groups` / `dropped` 是预览要显示的东西，`compare(vault)` 说出「哪些已经有
了、哪些共享同一把密钥但字段不同（要人来定）」，`apply(vault, choices)` 落实答案。

**密钥与 PIN 都不跨界**：`FfiImportedEntry` 只有名字、服务、账号、算法、位数与种类，而种类里的 PIN
是空的；解析后的导出留在 Rust 侧，应用时由它自己读回来。**没给答案的条目一律是「加入」**，绝不覆盖
——丢掉用户写过的备注，比留下一条他能删掉的重复更糟。

### 导出（`FfiVault.export`）

`vault.export(format, password)` 写出整份保险库并返回文件字节：**本层不做 I/O**，写到哪里由端侧
的保存对话框决定。六种格式分两类：两个 `.q2fa` 容器（`Vault` 主密钥明文、`EncryptedVault`
口令包裹）能完整恢复账号（条目、分组树、图标）；`Text`（每行一个 URI）、`Json`、
`EncryptedJson`、`Html`（每个条目画一张二维码）是别的认证器读的，只有 JSON 带得走图标与
扁平的组名。界面在选格式时要问的四件事各有一个函数：`exportFormatNeedsPassword`、
`exportFormatExtension`、`exportFormatCarriesGroups` 与 `exportFormatGroupCarrying`
（`None` / `FlatGroups` / `FullTree`）。

**只有 `EncryptedJson` 与 `EncryptedVault` 保护任何东西。** `Vault` 把主密钥明文放在文件里；
其余明文格式与保险库本身一样敏感：明文种子就在里面，`Html` 每张二维码里就是那条目的
`otpauth://` URI（含密钥）。写文件之前界面必须把这件事说清楚。

**空口令会被拒绝**（`export_password_empty`），它等于谁都能打开。加密走格式自己的两段式：
scrypt 导出槽密钥、槽里放随机主密钥、主密钥用 AES-256-GCM 加密数据库，所有随机值都来自 OS CSPRNG。
导出期间 Rust 侧持有保险库的锁（整份保险库要读一遍，取快照等于在内存里多一份全部密钥的副本）。

### 注册与登录

```kotlin
// 新设备注册
val vault = FfiVault.register(deviceKeys, secureStore, "qualia2fa-device")

// 老设备（已登录）：出示二维码
val login = FfiLogin.begin()
showQrCode(login.payload())

// 新设备：扫码、发请求、拿回应答后完成
val joiner = FfiJoiner.fromQr(scannedText, "qualia2fa-device")
val request = joiner.request(deviceKeys)
// …把 request 交给老设备…
val reply = login.authorize(oldVault, request)   // 界面在这里必须先让用户确认
val masterKey = joiner.complete(reply, deviceKeys, secureStore)
```

| 方法                                    | 说明                                                                                                                                                                                                              |
|-----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `FfiLogin.begin()` / `payload()`        | 发起登录，取得二维码文本                                                                                                                                                                                          |
| `FfiLogin.authorize(vault, msg1)`       | 授权（**调用即交出主密钥**，界面须先确认）                                                                                                                                                                        |
| `FfiLogin.joinerDeviceId()`             | 请求方的设备标识，显示给用户核对                                                                                                                                                                                  |
| `FfiJoiner.fromQr(text, label)`         | 扫码建立会话                                                                                                                                                                                                      |
| `FfiJoiner.request(keys)`               | 发出请求（幂等）                                                                                                                                                                                                  |
| `FfiJoiner.identity()`                  | 本机身份，完成之前才有值                                                                                                                                                                                          |
| `FfiJoiner.complete(msg2, keys, store)` | 验证应答、取回主密钥、写入密钥库                                                                                                                                                                                  |
| `FfiPlatformKeys.open(label)`           | 打开平台密钥库里的设备身份（Windows 上是 CNG/TPM，没有 TPM 时是 CNG 软件库）。它把 `qualia-dik` 的实现搬到边界这一侧，host 只需写一层不含判断的转发去实现 `FfiDeviceKeys`；`backend()` 如实报告实际拿到的是哪一种 |

一次登录只能完成一次。第二次调用报的是**与「应答是伪造的」相同的错误**，这是故意
的——单独报「已经用过了」等于告诉重放者他被认出来了。端侧文案也应保持笼统。

### 主密钥的两种存法（`FfiDirectMasterKeyStore` / `FfiWrappedMasterKeyStore`）

主密钥在平台上只有两种存法，**用哪个对象去问就是选择，没有模式参数**：

| 方法                               | 说明                                                                                                                                                                                          |
|------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `FfiDirectMasterKeyStore.open()`   | 打开「平台库直接持有材料」的那一种（Windows 上是 CNG，Android 上是 Keystore）：`store(label, key)` / `load(label)` / `delete(label)`，端侧不为它持久化任何东西                                |
| `FfiWrappedMasterKeyStore.open()`  | 打开「平台库持有一把不可导出的 KEK」的那一种：`store(label, key)` **返回要由端侧持久化的包裹字节**，`load(label, wrapped)` 把它们收回来，`delete(label)` 删掉 KEK（先前那些字节随之永久作废） |
| `backend()` / `isHardwareBacked()` | 如实报告实际答话的后端（`"tpm"` / `"android-keystore"` / `"software"` / `"secure-enclave"` / `"unavailable"`），端侧应在依赖它之前把这一点告诉用户                                            |

主密钥**只以字节过边界**（32 字节进、32 字节出），既不进日志也不进错误消息；拿到之后
端侧应立刻丢弃，或直接用 `FfiVault.fromMasterKey` 建保险库。包裹形式交出的字节是不透明
的：端侧只负责把它们与对应的保险库文件一起持久化，**任何包裹/解包、加解密或取得 KEK
的操作都不在这层接口里**——那是平台库内部的事。没有可用提供者时报
`hardware_unavailable`，平台还没有后端时报 `unsupported_platform`，**不会**退化成内存里
的软件实现。

### 恢复密钥

| 函数                                         | 说明                               |
|----------------------------------------------|------------------------------------|
| `FfiVault.exportRecoveryKey`                 | 设备已解锁时导出（主密钥不过边界） |
| `exportRecoveryKeyFromMaster`                | 只有主密钥字节时导出               |
| `importRecoveryKey(file, passphrase, store)` | 导入并写入密钥库，返回主密钥       |
| `storeMasterKey(bytes, store)`               | 单独保存主密钥                     |

KDF 参数（`memory_kib` / `iterations` / `parallelism`）传 `null` 用推荐值
（64 MiB / 3 次 / 1 路）。**不要为了「快」调低**：导出是一次性开销，而拿到文件的
攻击者是离线暴力破解，参数调低直接削弱用户最后一道防线。

### 挑战-应答

用来证明「对方持有主密钥」而不把主密钥交出去。它与登录不同：登录传输密钥，它只做
证明。**三步都要走完**，漏掉第三步等于只做了一半认证。

```kotlin
val verifier = FfiVerifier.begin()
val responder = FfiResponder.accept(verifier.challenge())
val response = responder.respond(vault, label, deviceKeys)
verifier.verify(response, vault)                  // 第二步：主密钥确实对得上
responder.confirm(vault, verifier.sessionId()!!, verifier.confirmation()!!)  // 第三步
```

> **空保险库也能判定主密钥对错。** 文件格式版本 2 在末尾放了一个主密钥检查值，
> 因此 `FfiVault.open` 在**一个条目都没有**的文件上也会拒绝错误的主密钥。端侧可以
> 把「打开成功」直接当成「已解锁」。
>
> 例外是**版本 1 的旧文件**：那份文件里确实没有可判定的信息，需要权威确认时用
> 挑战-应答。

### 同步（`FfiSyncSession`）

同步是**两台设备各出一个码、一次一个方向**：一方出示自己的状态，另一方读入并合并，
然后反过来。载荷由核心加密并认证，通道只负责搬字节。

**通道有两条，接口只有一个**（`FfiTransport`）：一条由端侧实现，把载荷变成用户搬运的
文本/二维码；另一条由本层实现，走局域网（见下）。两者满足同一套契约，所以会话代码对
两种载体没有分支。

```kotlin
// 通道：一个出站队列 + 一个入站队列，不含任何判断
class CodeChannel(private val me: String) : FfiTransport { /* … */ }

val session = FfiSyncSession.open(vault)

// 出示自己的状态
session.send(channel, FfiRecipient.All, FfiPayloadKind.Vault)
showQrCode(channel.takeOutgoing())

// 读入对方的码并合并
channel.accept(senderId, payloadBytes)
val outcome = session.receive(channel)
if (outcome.needsAdjudication) {
    for (conflict in session.pendingConflicts()) {
        showConflict(conflict)
    }
    session.adjudicate(conflict.entryId, FfiDecision.TakeIncoming)
}
vault.serialize()?.let(::saveVault)     // 合并写进了保险库，必须落盘
```

| 成员                                    | 说明                                                                 |
|-----------------------------------------|----------------------------------------------------------------------|
| `FfiSyncSession.open(vault)`            | 在一个已解锁的保险库上开会话                                         |
| `send(transport, to, kind)` → `syncId`  | 封装并发出（`Vault` = 自己的全部状态，`Request` = 「把你的发给我」） |
| `receive(transport)` → `FfiSyncOutcome` | 读入一条消息并合并；失败时保险库与重放日志都不变                     |
| `pendingConflicts()`                    | 还没裁决的冲突，按合并报告的先后排列                                 |
| `adjudicate(entryId, decision)`         | 裁决一条，**按标识而不是下标**（下标会在裁决后移位）                 |
| `planShare(transport)`                  | 只回答装不装得下，不发送也不显示                                     |
| `FfiPlatformKeys.deviceId()`            | 本机设备标识，通道要如实报告它                                       |

`FfiTransport` 的实现要求与核心 `Transport` 一致：**如实报告发送方**（核心会拿它和
载荷里那个认证过的字段对账）、尊重 `FfiRecipient.One`、没有消息时返回 `null` 而不是
阻塞、一次性通道第二次使用要报 `transport_already_used`。设备标识一律是 **64 位
十六进制**。

冲突的 `kind` 是稳定字符串，端侧对未知值要有兜底分支：

| kind             | 含义                           | 两个选择                    |
|------------------|--------------------------------|-----------------------------|
| `entry_mismatch` | 两边都有这条条目，内容不同     | 保留本机版本 / 采用对方版本 |
| `peer_deleted`   | 对方删除了它，本机改过它并留着 | 保留条目 / 接受删除         |
| `local_deleted`  | 本机删除了它，对方还留着       | 保持删除 / 恢复条目         |

> **裁决只作用于本机。** 「采用对方版本」会真正写进保险库，所以**必须落盘**；
> 「保留本机版本」不会让分歧消失——对方仍持有另一版，轮到它同步时它会问它的用户。
> 两边都选择之后才会收敛。

> **重放日志不落盘。** 同一次运行里同一个载荷不会被应用两次；重启之后日志是空的，
> 同一个载荷可以再被合并一次——合并是幂等的，结果不变。二维码通道是带外、一次性的，
> 这个边界因此可以接受；局域网通道用的是同一个会话，所以它的重放日志同样只存在于
> 本次运行里。将来需要它跨重启时再暴露出来。

### 局域网通道（`FfiLanChannel` / `FfiLanLobby`）

除了二维码那一半，本层还**自己实现**了局域网通道：`FfiLanChannel` 是一个可以拨号的
端点，`FfiLanLobby` 是同一网段上的发现。它与端侧自己实现的 `FfiTransport` **满足同一套
契约**（`send` / `receive` / `peers` / `capabilities`），因此会话代码对两种载体没有
分支：`FfiSyncSession` 收的是 `Arc<dyn FfiTransport>`，看不出拿到的是哪一个。

```kotlin
// 发起方：打开端点与大厅，把 record() 交给自己的配对码
val channel = FfiLanChannel.open(deviceId)      // 显式打开：占一个 UDP 端口与一套运行时
val lobby = channel.openLobby()                 // 显式开始公告；不调用就不公告
showCode(withRecord(host.payload(), channel.record()))

// 加入方：扫到码之后在大厅里按记录找到那台设备，记下它可拨的地址
val record = recordOf(scannedText)              // 端侧自己那层配对码里带的记录
val peer = lobby.peers().firstOrNull { it.record.contentEquals(record) }
if (peer?.socket != null) channel.rememberPeer(peer.deviceId, peer.record, peer.socket!!)

// 之后就是同一套同步会话：载体换了，协议与裁决一个字都没变
val session = FfiSyncSession.open(vault)
session.send(channel.transport(), FfiRecipient.One(peer.deviceId), FfiPayloadKind.Vault)
```

`withRecord` / `recordOf` 代表端侧自己那层配对码：**本层不定义配对码的文本格式**，它只
提供 `record()`（交出去）与 `FfiLanPeer.record`（拿来比对）。没有大厅可用时（不在同一
网段、或组播被禁），记录仍然说得清**要找谁**，但说不出**去哪里找**：`rememberPeer` 还需
一个可拨的地址，而那个地址只有收到过对方报文的一方才有。

| 成员                                     | 说明                                                                                                                         |
|------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| `FfiLanChannel.open(deviceId)`           | 打开端点，端口由系统选；**端点密钥每次运行重新生成、不落盘**                                                                 |
| `record()`                               | 本端点的连接记录（端点公钥 + 端口，42 字节定长），交给配对码或别的带外通道                                                   |
| `rememberPeer(deviceId, record, socket)` | 登记一个可拨的对端；`socket` 只有 **IP** 有用，**端口以记录为准**                                                            |
| `forgetPeer(deviceId)`                   | 忘记该对端并关闭到它的连接                                                                                                   |
| `transport()`                            | 把本对象作为 `FfiTransport` 交给会话                                                                                         |
| `openLobby()`                            | 开始公告与收听，返回 `FfiLanLobby`                                                                                           |
| `shutdown()`                             | 关闭端点：连接全关、运行时停止；重复调用安全                                                                                 |
| `FfiLanLobby.peers()`                    | 已知的对端，**含已经离开的**（`here` 为 false）                                                                              |
| `FfiLanLobby.announceNow()`              | 立刻公告一次，不等下一个周期                                                                                                 |
| `FfiLanLobby.shutdown()`                 | 一次告别，然后停掉线程与 socket；重复调用安全                                                                                |
| `FfiLanPeer`                             | `deviceId` / `record` / `socket`（可拨地址 `ip:port`：IP 来自收到报文的那一方、端口是端点公告的那个；可能为 `null`）/ `here` |

三件使用者必须知道的事：

1. **显式打开、显式关闭，不做后台同步。** 打开一个通道就占一个 UDP 端口与一套 tokio
   运行时（2 个工作线程），打开大厅之后还会按 30 秒的周期往网段里公告自己、并收听
   别人的公告。两者都不会自动回收：让界面在需要它们的屏幕出现时打开，离开时
   `shutdown()`。
2. **连接记录里没有 IP。** `record()` 只有端点公钥与端口，IP 来自**收到组播报文的那
   一方**——端点自己报出来的 socket 是通配地址（`0.0.0.0`），照它拨号拨不通。因此跨过
   带外那一步的方式正是「码里带记录，对方在大厅里按记录找到你」，而
   `FfiLanPeer.socket` 是唯一可拨的地址；没有它的对端只能显示、不能连接。
3. **依赖 `qualia-transport 0.1.3` 并打开 feature `iroh-lan`，本 crate 无条件打开它。**
   iroh、tokio 及其依赖树会进入每一次构建（Android 那份也一样），构建时间与产物体积
   都明显增加。组播发现与二维码并不需要这个 feature，需要它的是这里的数据面。

> `transport().peers()` 报告的是**登记过**的对端，`FfiRecipient.All` 发的就是这些；大厅
> 报告的是**听到的**对端。两者不是同一个集合：要让一台设备能收到消息，先把它从大厅
> 登记进来。公告本身**不认证**——它只回答「这个网段上大概有谁、去哪里找他」，真的身份
> 由连接握手证明，载荷该不该收由核心按设备标识判断。

### 0.3.0 的破坏性变更

- **依赖 `qualia2fa-core 0.3.0`**：保险库格式 **4**、同步载荷 **4**，与 0.2.x **无法同步**；
  旧保险库照旧能读，旧端的版本错误是明确的。
- **分组变成树**：`FfiGroup` 不再有 `order`，多出 `children`（`FfiGroupChild`：条目 / 分组）；
  `moveGroup` 被 `setChildren` / `createGroupIn` 取代。冲突里的 `local` / `incoming` 也换成子节点列表。
- **条目多出 `icon`**（`FfiEntryIcon`：格式 + 原始字节），导出入口多出两个 `.q2fa` 格式与
  `FfiGroupCarrying`。

### 0.2.0 的破坏性变更

- **条目形状**：`FfiVaultEntry` / `FfiOtpAuth` 不再有 `period` / `counter` / `uri_type`，改为
  `kind`（`FfiEntryKind`：TOTP / HOTP / mOTP / Yandex OTP / Steam）。`FfiDigits` 补上 `Five` /
  `Nine` 与 `OtherDigits`（表单不提供的档位照实带过）。
- **算码入口**：`totpFor` / `steamGuardFor` 合并成 `codeFor`（由条目自己的种类决定算法），
  `hotpFor` 保留。对条目调错函数会得到 `wrong_code_kind`，而不是一个永远对不上的码。
- **PIN 只进不出**：写入时经 `FfiEntryKind` 的 `pin` 传入，读取时只报 `pinSet`。更新时
  `pin: None` 表示**保留原有 PIN**，所以编辑备注不需要用户重输。
- **依赖 `qualia2fa-core 0.2.0`**：保险库格式 **3**、同步载荷 **3**，与 0.1.x **无法同步**，
  两端必须一起升级。
- **依赖 `qualia2fa-core 0.2.1`**（自 0.2.3 起）：`export` 与它的三个格式函数是这一版新增的；
  0.2.1 也是 HTML 读取端能从二维码里取出步长的那一版，两者配套。
- **依赖 `qualia2fa-core 0.2.2`**（自 0.2.4 起）：HTML 导出的三个单元格改成 Aegis 实际写的
  那样——类型写成大写、收藏栏写 `false`、没人填的字段留**空单元格**（只有对这条条目不适用
  的字段才写 `-`）。读取端一直两种都认，改动只影响写出去的文件长什么样。

FFI 错误跨到 Kotlin 后是 `sealed class FfiException`：

| 变体              | 含义                                                                              |
|-------------------|-----------------------------------------------------------------------------------|
| `InputTooLong`    | 输入超过边界上限                                                                  |
| `Core`            | 核心返回的错误，结构化为 `FfiCoreError { kind, message }`                         |
| `Qr`              | 二维码那一半的通道自身报出的失败（`kind` + `detail`），例如图片里读不出码         |
| `Lan`             | 局域网通道自身报出的失败（`kind` + `detail`），例如加入不了组播组、对端没有登记过 |
| `InvalidDeviceId` | 传进来的设备标识不是 64 位十六进制                                                |
| `UnknownConflict` | 为一条不在等待裁决的冲突做了裁决：裁决只属于产生它的那次合并                      |

`Lan` 的 `kind` 与 `Qr` 一样是稳定标识，常见的几个：`lan_socket`（端点没有绑定的 socket）、
`lan_transport`（运行时或绑定失败）、`no_connection_to_peer`（对端没登记过或连不上）、
`payload_too_large`、`no_lan_peers_found`、`bad_socket`（传进来的地址不是 `ip:port`），
以及连接记录的 `not_our_lan_address` / `bad_lan_address_length` / `zero_port`。枚举是
`#[non_exhaustive]` 的，未映射的变体一律落到 `lan_error`，因此**兜底分支必须有**。

主密钥两种存法的失败同样各有其 kind：`invalid_wrapped_key`（包裹字节解不开——被损坏，
或来自另一个库条目、另一台设备；**不会**退回成另一把看起来有效的密钥）、
`invalid_master_key`、`key_not_exportable`（平台库收下了材料却不肯交出来，这种平台该用
包裹形式）、`hardware_unavailable`、`unsupported_platform`。

`kind` 是**稳定的机器可读标识**（如 `secret_empty`、`vault_entry_not_found`），
端侧据此分流 UI；`message` 仅供展示与日志。这些字符串属于公开接口：**可以新增，
但既有值不得改名**。

有几组 `kind` 是刻意分开的，合并它们会造成用户可见的错误：

| kind                             | 不要与它合并                 | 合并的后果                                                               |
|----------------------------------|------------------------------|--------------------------------------------------------------------------|
| `device_not_registered`          | `vault_decryption_failed`    | 用户被引导重新注册，原有条目永久丢失                                     |
| `vault_entry_not_found`          | 「保险库为空」               | 显示空列表，而用户刚才还在看条目                                         |
| `recovery_authentication_failed` | `recovery_file_malformed`    | 用户反复试口令，而问题不在口令                                           |
| `pairing_authentication_failed`  | 任何更具体的错误             | 给攻击者一个「差一点就成功」的预言机                                     |
| `sync_already_applied`           | `sync_authentication_failed` | 把「已经合并过」报成「这个码是假的」，用户会去重新生成一个本来没问题的码 |
| `sync_sender_mismatch`           | `sync_authentication_failed` | 把「来源对不上」报成「密钥不对」，排查方向完全错                         |

`pairing_authentication_failed` 覆盖密文被改、会话对不上、应答来自另一次登录等
多种成因，**这是刻意的**。端侧文案应当保持笼统（「配对失败，请重新扫码」），不要
试图从它推断更具体的原因。

核心是 `#[non_exhaustive]` 的，未来会新增错误变体，因此端侧**必须对未知
`kind` 有兜底分支**：

```kotlin
try {
    parseOtpauthUri(input)
} catch (e: FfiException.Core) {
    when (e.detail.kind) {
        "uri_missing_secret" -> showReenterHint()
        "randomness_unavailable" -> showRetryHint()
        else -> showGenericError(e.detail.message)   // 必须保留兜底分支
    }
}
```

## 秘密材料

跨 FFI 边界时，OTP 种子统一以 **Base32 字符串**表示（传入走 `from_base32`，
传出走 `to_base32`）。种子的字节**永远不会**以 `Vec<u8>` 形式经过 FFI——那会在
两侧各留一份不受擦除控制的拷贝。

> ⚠️ **端侧必须知晓的残留风险**：Base32 字符串在 Kotlin/Swift 侧是普通 `String`，
> 不受核心 `secrecy` 的擦除保护，且可能被 GC 复制、进字符串常量池。这是托管语言
> 的固有限制。端侧应约定：种子的 Base32 只在必要作用域内存在，用完立即丢弃，
> **绝不写入日志或持久化**。

**主密钥**同理但更进一步：它正常路径下**根本不过边界**。`FfiVault` 在 Rust 侧持有
它，读条目、改条目、算验证码、序列化都在 Rust 内完成。只有下面这几个入口需要端侧交出
或接收它：

- `FfiVault.fromMasterKey(bytes)` / `storeMasterKey(bytes, store)`：登录或恢复之后，
  端侧手里已经有主密钥字节。
- `FfiJoiner.complete(...)` / `importRecoveryKey(...)`：返回主密钥字节，供端侧立刻
  建一个 `FfiVault` 或交给密钥库。
- `FfiDirectMasterKeyStore.store/load` 与 `FfiWrappedMasterKeyStore.store/load`：两种
  存法，材料以 32 字节进出，包裹形式进出的则是它自己那串不透明字节。

拿到之后端侧应当**立刻丢掉**那些字节。`FfiDeviceKeys` / `FfiSecureStore` 两个回调
之所以用字节而不是结构体，正是因为主密钥的永久归宿是平台密钥库，而只有端侧能访问
它——把整个密钥库抽象搬进 Rust 会让每个平台的 `unsafe` 跟着进来。

## 参与贡献

### 最重要的约定：这里只做搬运

本 crate 的职责是：把端侧传来的原始类型转成核心类型、调用核心、把结果转回去。

**任何加密、解析、校验逻辑出现在这里都是设计倒退。** 那些必须留在
`qualia2fa-core` 内，因为只有核心是无 `unsafe`、可独立审计的。代码审查时的
检查项就一条：**有没有把核心的逻辑搬到这里来**。

### 为什么这里不能 `#![forbid(unsafe_code)]`

`uniffi::setup_scaffolding!()` 在本 crate 内展开 FFI 边界所需的 unsafe 代码
（裸指针解引用、`catch_unwind`、字符串所有权转移）。**FFI 边界本身就是 unsafe
的**，这是不可协商的。安全边界因此划在 **crate 之间**：

| crate            | 约束                                      |
|------------------|-------------------------------------------|
| `qualia2fa-core` | `#![forbid(unsafe_code)]`，无 I/O，无时钟 |
| `qualia2fa-ffi`  | 唯一允许 `unsafe` 的地方，且必须是薄的    |

`Cargo.toml` 里把 `unsafe_code` 设为 `warn` 而非 `allow`，是为了让任何**新增**的
`unsafe` 在构建时发出声音；CI 用 `-D warnings` 把它上升为硬错误。

### UniFFI 版本为何停在 `0.29`

上游最新是 `0.32.2`，但端的绑定生成器 **Gobley 强制 `uniffi = "0.29.4"`**，Rust
侧与 Kotlin 侧的脚手架**必须同版本**，否则生成的序列化格式不匹配。

取 `0.29`（等价 `^0.29`）而非写死 `=0.29.4`：`0.29.5` 已发布且同 minor 内 semver
兼容，既能吃到补丁又不会跨到 `0.30`。

这也是 **`uniffi` 不进 `qualia2fa-core`** 的原因：绑定生成器的版本锁定不该牵连
核心。核心保持与任何绑定工具无关。

### 提交前

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

本仓库按版本号依赖 `qualia2fa-core` 与 `qualia-dik`，两者都发布在 crates.io 上，
因此不检出任何上游目录，也没有 submodule。

## 许可证

LGPL-3.0-or-later，见 [`LICENSE`](LICENSE) 与 [`COPYING.LESSER`](COPYING.LESSER)。
