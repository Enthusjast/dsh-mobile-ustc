# Android APK 更新：API 与签名信任依据

研究日期：2026-10-26。范围：本仓 `minSdk 26`、`targetSdk/compileSdk 36` 的单 APK 自更新；依据官方 API 文档与固定版本 AOSP 源码。本次仅进行文档 / 源码研究，未运行构建、设备测试或生产签名验证。

## 实施建议

首版使用**已安装应用的当前签名证书作为信任锚，只接受同一当前签名身份**。从 Android 查询本应用已安装签名，不从下载元数据建立新信任；元数据里的证书 SHA-256 必须同时匹配该锚和通过验签的候选 APK。Android 的更新身份以签名证书为基础；应用安装时已经由平台校验。[应用签名说明][signing] [平台更新身份检查][update-check]

建议按下面的顺序实现。这是本仓策略建议，不是 Android 自带的完整更新协议：

1. 从现有明确部署的 HTTPS 服务取得有界、严格解析的发行元数据，要求 `version_code`、APK 整体 `sha256`、`package_name`、签名证书 SHA-256、HTTPS 下载地址、最低协议版本、灰度与说明。元数据不能替换本机签名锚。协议字段的含义和支持窗口需要契约明确；先检查当前协议是否满足要求，不满足就拒绝本次更新并给出原因，不能绕过兼容策略。
2. 下载到应用私有目录下的临时文件，限制长度、超时、重定向与来源；关闭写流后对**实际完整文件**计算 SHA-256。固定候选文件与元数据快照，避免并发下载 / 恢复覆盖已验证文件。校验失败删除临时文件。私有存储的访问边界见[Android 存储说明][storage]；摘要、文件不可变和并发约束是本仓的实现要求。
3. 使用下文的带签名标志 `getPackageArchiveInfo` 路径，完成签名内容校验并取得候选包身份；拒绝 `null`、空签名、缺失 `signingInfo`、解析 / 验证异常。API 28+ 不能因 `signingInfo == null` 而退回仅提取证书或仅解析 Manifest 的路径。API 36 可额外调用 `getVerifiedSigningInfo(path, SigningInfo.VERSION_SIGNING_BLOCK_V2)`；它是 API 36 才增加的公开验签 API。[PackageManager][pm]
4. 候选包名必须同时等于本机 `packageName` 和元数据包名；候选真实 version code 必须等于元数据且大于已安装版本，拒绝相同版本和降级。API 28+ 用 `longVersionCode`，26–27 用非负 `versionCode.toLong()`。API 版本差异见[PackageInfo][package-info]。最低 Android SDK / 单 APK 完整性也要检查；最终兼容性仍由安装器判断。
5. 对通过验签的证书编码计算 SHA-256，与已安装**当前**签名身份及元数据精确比较。单签名时 API 28+ 的 `signingCertificateHistory.last()` 是当前签名；API 26–27 取 `signatures`。多签名身份是全部签名的集合，不能“任一匹配”；首版可明确拒绝多签名，或实现完整集合精确相等。[SigningInfo][signing-info]
6. 所有检查通过后才提供安装操作。安装前重新确认当前已安装版本 / 签名与候选仍一致，并对同一私有文件再次校验摘要；之后由系统安装器独立作最后验证。升级成功只能在查询到已安装版本 / 签名匹配后确认。失败、取消或结果不明应保留原应用可用，并允许重新下载 / 重试；不得靠先卸载来解决签名冲突。平台最终仍检查更新签名及版本。[平台检查][update-check]

元数据 SHA-256 用于固定所有下载字节；它不能独立证明发布者身份。候选 APK 的有效签名和本机签名锚负责限制发布者。已有部署的服务身份和学校认证方式继续适用，此处不新增凭据或信任根服务。发行说明、灰度和最低协议属于服务元数据，APK 签名不自动认证这些外部字段；生产发布前仍需验证其来源与服务契约。

## `getPackageArchiveInfo` 是否真的验签

**带正确标志时，已审读的 AOSP 实现会校验 APK 内容签名。无标志的包信息解析不能证明签名有效。** 公开 API 文档主要承诺返回包信息，下面的内容验证结论来自固定版本的实现依据，不能替代目标设备测试。[PackageManager][pm]

| 平台 / 固定源码 | 已确认行为 | 本仓使用方式 |
| --- | --- | --- |
| API 26，`android-8.0.0_r1` | `GET_SIGNATURES` 触发 `collectCertificates(pkg, 0)`；收集过程尝试 v2 全量验证，否则验证 v1；源码明确其同时断言内容签名正确且一致。[入口][archive26] [验证][parser26] | 使用 `GET_SIGNATURES`；任何缺失签名 / 异常均拒绝。 |
| API 28 / 29，`android-9.0.0_r61` / `android-10.0.0_r47` | archive 入口**仅检查 `GET_SIGNATURES`** 才调用 `collectCertificates(..., false /* skipVerify */)`。仅用 `GET_SIGNING_CERTIFICATES` 可使 `signingInfo` 为空；生成代码要求实际已有 signing details。[28 入口][archive28] [29 入口][archive29] [生成与验证][parser28] | API 28+ 合并 `GET_SIGNATURES or GET_SIGNING_CERTIFICATES`，以 `signingInfo` 读取当前签名。保留 deprecated 标志是针对这些实际实现的兼容措施。 |
| API 31，`android-12.0.0_r1` | `ApplicationPackageManager` 对两种标志任一启用收集，`ParsingPackageUtils` 使用 `skipVerify=false`，最终进入 `ApkSignatureVerifier.verify`。[入口][archive31] [验证][parser31] | 同上，并严格检查返回结果。 |
| API 36，`android-16.0.0_r1` | 任一签名标志设置 `PARSE_COLLECT_CERTIFICATES`；解析路径调用 `getSigningDetails(..., false)`，最终进入完整 `ApkSignatureVerifier.verify`。[入口][archive36] [验证][parser36] | API 33+ 可用 `PackageInfoFlags.of(flags.toLong())` 重载。API 36 的公开独立验签 API 可作为额外明确验证入口。 |

这里审读的是上述平台快照，不声称逐个审计过 26–36 的每个维护版本或 OEM 分支。实现应隔离平台适配层，并在最低、28/29、当前目标平台上加入真实篡改 APK 设备测试。不要把名称包含 `unsafeGetCertsWithoutVerification` 的隐藏 API 当成验签接口，也不要反射使用平台内部类。固定 API 36 源码明确区分完整 `verify` 与仅收集证书的危险路径。[ApkSignatureVerifier][platform-verifier]

## apksig / ApkVerifier 的适用位置

`ApkVerifier.verify()` 的成功条件是 `Result.isVerified()`，仅返回证书或没有抛异常不代表成功。Builder 可显式设置 `setMinCheckedPlatformVersion(26)` / `setMaxCheckedPlatformVersion(36)`；它检查给定范围内**该工具已知**的平台签名行为，不等于真实系统安装 / 运行成功。签名证书只能在验证成功后使用。[固定 API 36 ApkVerifier 源码][apk-verifier]

官方 apksig README 明确写明它面向 Android 设备之外的运行环境；AOSP 构建目标是 `java_library_host`，Java 1.8。纯 Java 不等于官方支持 Android 运行时。**首版不为设备内验签引入 `com.android.tools.build:apksig` 依赖**；使用上述平台验证路径，将 apksigner / ApkVerifier 放在主机构建和夹具生成、发行检查中。若以后需要嵌入，必须固定精确 Maven 版本、检查该产物 / 传递依赖、D8/R8、密码算法和 API 26/目标平台运行结果，再评审维护责任；本次没有证明任何 Maven 版本的设备内兼容性。[README][apksig-readme] [构建目标][apksig-build]

主机验收可用锁定 SDK Build Tools 的 `apksigner verify --verbose --print-certs --min-sdk-version 26 --max-sdk-version 36 <apk>`，记录实际工具版本、退出码与证书摘要。不能仅因设置了数值 36，就声称旧工具拥有全部 API 36 行为知识。[apksigner 命令文档][apksigner] 本仓当前显式 Build Tools 35.0.0；是否足以承担最终 API 36 发行验收尚未在本次研究中验证。

## 签名方案与轮换边界

| 系统范围 | 签名能力与发布约束 |
| --- | --- |
| API 26–27 | 已支持 v2（自 API 24）；不理解 v3 轮换。必须提供这些系统能验证的签名，保留旧设备所需的原签名身份。[v2][v2] [v3][v3] |
| API 28–32 | 支持 v3 的 proof-of-rotation。v3 仅支持单签名者；轮换通过旧 / 新密钥间的签名链证明，不能靠两个证书摘要出现在元数据里代替。[v3][v3] |
| API 33–36 | API 33 引入 v3.1，可按 SDK 定向轮换；标准工具默认将轮换定向到 API 33+，较早系统沿用原身份。指定 API 28 起轮换需显式 `--rotation-min-sdk-version 28`，并保留对更早设备的签名方案与密钥。[v3.1][v31] [apksigner][apksigner] |

现代 Android 对 targetSdk >= 30 的应用要求至少 v2；`targetSdk 36` 发行不能仅使用 v1。API 26 的历史系统并不知道后来的 target 规则，因此不能单靠在旧设备上安装成功来证明当前发布签名符合要求。[平台最低方案检查][platform-verifier] v2 / v3 内容保护不覆盖整个 APK Signing Block；整体下载 SHA-256 仍有独立价值。[v2][v2]

**首版遇到当前签名变化一律拒绝，即使候选历史中含有旧证书。** 放开轮换需要独立确认原 / 新发布密钥的真实控制、工具与 SDK 定向、验证过的 lineage、相应 capability 和单向升级 / 回退政策，再执行跨 API 26、28、32、33、36 的设备矩阵。平台更新身份判断涉及 `INSTALLED_DATA` / `ROLLBACK` capability；“两个历史集合存在交集”不足以复刻该规则。[平台更新身份检查][update-check] `hasSigningCertificate` 用于已安装包的身份查询，不能替代下载 APK 的内容验签。[PackageManager][pm]

## 系统安装与恢复

应用应声明 `REQUEST_INSTALL_PACKAGES`，并在 API 26+ 查询 `canRequestPackageInstalls()`。用户按来源授权；未授权时可引导 `Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES`（本应用 `package:` URI），回到前台后重新查询。它不是普通运行时权限弹窗。[PackageManager][pm] [Settings][settings]

建议使用 `PackageInstaller.Session`：写入已验证 APK，关闭全部流再 `commit()`，处理 `STATUS_PENDING_USER_ACTION` 提供的系统 Intent，以及最终成功 / 失败。API 31+ 显式 `USER_ACTION_REQUIRED`。targetSdk 36 的 commit 回调 `PendingIntent` 必须是可变的：target >=35 使用 immutable 回调会抛异常；将其限定到本应用显式 receiver，绑定本次 session，不接受任意外部广播改变安装状态。来源与 session 之外，再通过已安装包查询确认最终结果。[Session][install-session] [SessionParams][install-params] [状态码][installer]

如果选择 URI 安装流程，`ACTION_INSTALL_PACKAGE` 自 API 29 弃用，官方建议改用 PackageInstaller。旧流程要求 `content:` URI；使用只暴露 APK 专用子目录的非导出 FileProvider，`grantUriPermissions=true`，临时只读授权，不能暴露私有根目录或授予写权限。FileProvider 只是文件访问代理，不验证 APK。Session 写入流程不需要 FileProvider。[Intent][intent] [FileProvider][file-provider]

建议持久保存发行身份、候选摘要和 installer session id 等有界状态。进程重建 / 返回安装器后，先查询已安装包和已有 session；结果不明显示待核对，不能把“已打开安装器”标成完成。中断、空间不足、权限撤销、用户取消、验证失败均可重试；清理放弃的 session 和无效临时文件。已提交 session 会封存，不能继续修改；重启后仍未最终完成时存在再次 commit 的恢复能力。[Session][install-session] 所谓回滚先指失败后旧版本继续工作；不承诺普通应用能自动降级已成功安装的版本，也不把卸载重装当成无损回退。

## 无生产签名密钥时的本地验证

可以使用隔离测试密钥签署同包名不同版本的夹具，不需要生产密钥：一个与当前测试安装同签名的有效升级、不同签名的有效 APK、错误包名、重复 / 较低版本、截断 APK，以及修改已签名内容后重新计算元数据 SHA-256 的 APK。后者确保真正测试签名内容校验，不仅是摘要不匹配。另测不支持协议、rollout 未命中、网络中断 / 重定向、空间不足、取消、权限设置往返、进程重建和文件被替换。预安装检查失败时应断言根本没有提交 installer session / 发起安装 Intent；系统安装器自身的拒绝不能代替这个断言。

设备测试需分清“只验证候选”与“真正升级自己”：自更新会替换运行中的 APK，夹具应在任务专用测试设备和可恢复安装中运行。SDK / Gradle 的 debug 证书可支持开发测试，但不能作为生产可信发行身份；发布更新必须持有原发行签名私钥或经过验证的轮换关系。[应用签名说明][signing]

待落实事项：生产 release signer 与保管 / 轮换政策、真实部署的更新端点与 HTTPS 下载来源、协议窗口语义、灰度分配、目标 OEM 安装行为，以及各目标平台的真实预安装验签 / 安装恢复证据。当前可完成同签名测试闭环；不能据此声称生产学校分发或生产签名已经验收。

[pm]: https://developer.android.com/reference/android/content/pm/PackageManager
[package-info]: https://developer.android.com/reference/android/content/pm/PackageInfo
[signing-info]: https://developer.android.com/reference/android/content/pm/SigningInfo
[signing]: https://developer.android.com/studio/publish/app-signing
[storage]: https://developer.android.com/training/data-storage/app-specific
[archive26]: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/core/java/android/content/pm/PackageManager.java#4588
[parser26]: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/core/java/android/content/pm/PackageParser.java#1443
[archive28]: https://android.googlesource.com/platform/frameworks/base/+/android-9.0.0_r61/core/java/android/content/pm/PackageManager.java#4797
[archive29]: https://android.googlesource.com/platform/frameworks/base/+/android-10.0.0_r47/core/java/android/content/pm/PackageManager.java#5572
[parser28]: https://android.googlesource.com/platform/frameworks/base/+/android-9.0.0_r1/core/java/android/content/pm/PackageParser.java#811
[archive31]: https://android.googlesource.com/platform/frameworks/base/+/android-12.0.0_r1/core/java/android/app/ApplicationPackageManager.java#2101
[parser31]: https://android.googlesource.com/platform/frameworks/base/+/android-12.0.0_r1/core/java/android/content/pm/parsing/ParsingPackageUtils.java#286
[archive36]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/android/content/pm/PackageManager.java#9006
[parser36]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/com/android/internal/pm/pkg/parsing/ParsingPackageUtils.java#645
[platform-verifier]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/android/util/apk/ApkSignatureVerifier.java#574
[update-check]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageManagerServiceUtils.java#537
[apksig-readme]: https://android.googlesource.com/platform/tools/apksig/+/android-16.0.0_r1/README.md
[apksig-build]: https://android.googlesource.com/platform/tools/apksig/+/184702d9d18877edf9e5296c4e191cf0aa2b5fbb/Android.bp#36
[apk-verifier]: https://android.googlesource.com/platform/tools/apksig/+/android-16.0.0_r1/src/main/java/com/android/apksig/ApkVerifier.java#131
[apksigner]: https://developer.android.com/tools/apksigner
[v2]: https://source.android.com/docs/security/features/apksigning/v2
[v3]: https://source.android.com/docs/security/features/apksigning/v3
[v31]: https://source.android.com/docs/security/features/apksigning/v3-1
[settings]: https://developer.android.com/reference/android/provider/Settings#ACTION_MANAGE_UNKNOWN_APP_SOURCES
[install-session]: https://developer.android.com/reference/android/content/pm/PackageInstaller.Session
[install-params]: https://developer.android.com/reference/android/content/pm/PackageInstaller.SessionParams#setRequireUserAction(int)
[installer]: https://developer.android.com/reference/android/content/pm/PackageInstaller
[intent]: https://developer.android.com/reference/android/content/Intent#ACTION_INSTALL_PACKAGE
[file-provider]: https://developer.android.com/reference/androidx/core/content/FileProvider

## 2026-10-27：Session 封存、读取与进程重建恢复

本节只讨论本应用拥有的普通、非 staged、非 DataLoader、未转移所有权的单 APK session。**跨 API 26–36 的内容读取 / 摘要核对应在首次 `commit()` 前完成；已收到 `STATUS_PENDING_USER_ACTION` 的恢复分支不能再依赖 `getNames()/openRead()`。** 再次 `commit()` 是恢复安装流程的动作，不是只读状态查询，也不保证一定返回确认 Intent。以下是固定源码核对结果，尚未进行设备验证。

### 内容读取的前置条件

正常调用者须拥有 session；`openSession(id)` 会检查访问权并准备 session。`openRead(name)` 的名称须对应先前写入的文件；准备好并不代表文件存在、已写完或字节正确。应用仍应关闭写流、检查精确文件集合并读取实际 session 字节计算摘要，再首次提交。[公开 Session / openSession 文档][install-session] [PackageInstaller 文档][installer]

| 固定平台源码 | `getNames()` | `openRead(name)` | 提交后等待用户确认时 |
| --- | --- | --- | --- |
| API 26，`android-8.0.0_r1` | 调用 `assertPreparedAndNotSealed`：要求 `mPrepared && !mSealed`；未准备抛 `IllegalStateException`，已封存抛 `SecurityException`。[断言与列举][session26-read] | 同一断言；名称还须是有效文件名，打开文件可能产生 I/O 错误。[读取][session26-open-read] | 首次 commit 已设置 `mSealed=true`；两个方法均不可调用，即使安装尚未完成。[提交][session26-commit] |
| API 28，`android-9.0.0_r1` | 要求 owner / root、`mPrepared && !mCommitted && !mDestroyed`。[列举][session28-read] | 相同状态与身份要求。[读取][session28-open-read] | commit 在发送处理消息前设置 `mCommitted=true`；两个方法均不可调用。单独 sealed 且尚未 committed 的状态与此不同，不能混为一谈。[断言][session28-assert] [提交][session28-commit] |
| API 36，`android-16.0.0_r1` | 放宽到 owner / root 或合格系统 verifier，且 `mPrepared && !mDestroyed`；committed 时从 stageDir 列举。可能为空，不能据此证明已安装。[列举][session36-read] | 仍要求 owner / root、非 DataLoader，以及 `mPrepared && !mCommitted && !mDestroyed`；committed 时抛 `SecurityException`。[读取][session36-open-read] [断言][session36-assert] | 正常提交路径在发送确认 Intent 前已 committed；`getNames()` 可能可用，`openRead()` 不可用。因此不能利用列举成功来认定 session 可重新读取校验。[提交处理][session36-stream] [等待确认][session36-pending] |

当前公开文档也有方法间差异：`getNames()` 只列 abandoned 的 `SecurityException`，`openRead()` 仍明确列 committed 或 abandoned。[Session 文档][install-session] API 26 / 28 的固定实现比当前 `getNames()` 文档限制更严；不要把最新文档的读取能力倒推到旧系统。session 状态检查与下一次 Binder 调用之间也可变化，读取失败应作为当前操作失败 / 待核对处理，不能改用未验证的外部文件来冒充已经核对过的 session。

### `isSealed` / `isCommitted` 的恢复含义

`SessionInfo.isSealed()` 自 API 26 公开，描述 session 已封存、不能再修改；`isCommitted()` 自 API 29 公开，描述曾调用 commit，API 26 / 28 不能调用它。[SessionInfo 文档][session-info] 两者都不表示用户已经同意、仍在等待确认或安装已经成功。固定源码还表明：

- API 26 的销毁路径也将 `mSealed=true`；所以 sealed 本身不是一个可继续操作的存活证明。[销毁][session26-destroy]
- API 36 首先封存，随后异步 `streamValidateAndCommit()` 才设置内部 `mCommitted`，`SessionInfo` 直接导出这两个状态。因此 `sealed=true && committed=false` 可能是提交处理中的快照；不能因为 `!isCommitted` 就回到可写的 PREPARED 分支。[状态导出][session36-info] [封存][session36-seal] [异步提交][session36-stream]
- `isSealed=false` 只排除当时已封存；仍须实际打开、核对文件集合及内容，不能由此单独恢复“已验证 PREPARED”。`isActive()` 也不是安装结果：仅持有打开的 Session 即可被视为 active。[SessionInfo 文档][session-info]

### 再次 commit 能否重新取得确认 Intent

公开 `commit()` 文档从 API 26 就明确允许“设备重启且 session 尚未 finalized”后再次提交；`close()` 文档允许重新打开未结束的 session。文档没有逐字承诺“应用进程重建后一定重新发确认 Intent”。但以下三版服务端实现均支持**同一安装 UID 重新打开仍存在、未销毁、仍需用户确认的原 session，替换回调并再次驱动确认流程**，这是源码核对结论。[API 26 公开契约][session26-public-commit] [当前公开契约][install-session]

| 平台 | 再次 commit 的已确认路径与限制 |
| --- | --- |
| API 26 | `commit(statusReceiver)` 要求非空回调；第一次检查写流并封存，再次提交不会因已封存而拒绝。它创建新 observer，Handler 将其替换为 `mRemoteObserver`；`commitLocked()` 要求未销毁且已封存，若 `!mPermissionsAccepted` 再次调用 `onUserActionRequired`。应用应通过 owner 检查的 `openSession()` 重开；不是任意 session id 均可恢复。[commit / observer][session26-commit] [确认分支][session26-pending] [访问控制][session26-service] |
| API 28 | 要求 owner / root、prepared、未销毁、普通 commit 的安装 UID 未发生 transfer。先替换 observer；已经 sealed 就跳过重新封存，并**不因 `mCommitted=true` 拒绝再次提交**。Handler 再检查 `needToAskForPermissionsLocked()`，仍需要时再发确认 Intent。第一次封存前必须关闭写流。[commit][session28-commit] [确认分支][session28-pending] |
| API 36 | `markAsSealed()` 注释及代码明确支持多次调用来更新回调：要求 owner / root、prepared、未销毁、无未关闭写传输，并检查 transfer / FRP 等限制；更新回调后，已 sealed 直接返回成功。后续 `streamValidateAndCommit()` 遇已 committed 直接返回 true，再进入 `handleInstall()` 的用户确认判断。target >=35 的回调 PendingIntent 必须可变。[封存 / 回调][session36-seal] [再次驱动][session36-stream] [确认分支][session36-pending] [公开 commit 文档][install-session] |

这里的“重新取得”是通过新绑定回调异步接收 `STATUS_PENDING_USER_ACTION` 与 `Intent.EXTRA_INTENT`；不是 `commit()` 的返回值。API 26 / 28 adapter 和 API 36 发送方法都会捕获 IntentSender 发送失败，因此提交调用返回也不能证明回调已送达。[API 26 adapter][session26-adapter] [API 28 adapter][session28-adapter] [API 36 发送][session36-send] 仅在用户主动恢复且仍需确认时展示返回的系统 Intent；后台只保存待处理状态。[状态码文档][installer]

**实施建议：**恢复先查询实际已安装包，再查询原 session。只有未封存的原 session 才进入 `getNames/openRead` 校验；已封存的恢复沿用首次提交前持久保存的 session id、候选发行身份、session 字节摘要与验证记录，不能因旧系统拒绝读取就误判“APK 篡改”。在确认仍为本次待确认流程、用户主动继续时，可重新绑定限定到本应用且绑定该 session 的回调并再次 commit。缺少可靠关联记录时保持未知，不能把其他 session 或新下载文件的摘要移植过来。不要在轮询、每次页面恢复或所有 sealed 状态上自动反复 commit：用户可能已确认、安装正在进行，API 26 的旧路径也没有把重复提交定义成无副作用查询。[API 26 提交后执行路径][session26-pending] [API 36 安装处理][session36-pending]

### 成功、失败与未知

- **成功：**本仓仅在重新查询到目标包的真实已安装 version code 和当前签名符合本次候选时确认。受绑定回调的 `STATUS_SUCCESS` 作为触发核对的事件，不能单独作为安装证明；sealed、committed、active、确认页已打开也都不是证明。公开状态只说相应操作成功；staged / preapproval 还有不同的成功含义，本节实现不启用这些模式。[状态文档][installer] [Session 文档][install-session]
- **失败：**与本次 session 可靠关联的最终失败 / 用户拒绝应记录失败，并重新查询安装事实；`SecurityException`、`IOException` 或 `IllegalStateException` 表示该方法当次不能完成，单次异常不能证明候选内容被篡改，也不能证明其他安装操作未成功。[读取 / commit 文档][install-session]
- **未知：**丢失回调、缺少确认 Intent、session 不存在、归属不符、已封存但无法核对关联、状态检查期间竞态，均先保留待核对状态。普通 session 成功和失败后都可能被移出活动表，因此 `getSessionInfo(id)==null` 不区分成功与失败；有 session 也不保证下一次调用仍有效。应再次核对安装包后再决定是否允许新的尝试。[API 文档][installer] [API 26 清理][session26-finish] [API 28 清理][session28-finish] [API 36 清理][session36-finish]

本节没有验证 OEM 分支和运行时回调送达情况，也不把 AOSP 的可重提交流程扩展为恰好一次安装、确认 Intent 必然送达、或者所有 sealed session 都可恢复的保证。

### 同日设备补充：未封存 `openRead` 的 SELinux 限制

随后在本仓任务专用 AOSP API 26 x86_64 模拟器、普通应用 UID、SELinux Enforcing 下执行时，未封存 `openRead("base.apk")` 仍失败。内核 / logcat 明确拒绝向 `untrusted_app` 交付 `apk_tmp_file` 的 read FD；客户端表现为 `RuntimeException(DeadSystemException)`，而同一个 system_server PID 持续存活。失败证据为 `.local/app-install-api26-diagnostic-device.log` 和 `.local/app-install-api26-diagnostic-logcat.txt`。因此上述 Java 状态前置条件是必要条件，不能据其声称普通应用在该镜像上必能读回。没有修改 SELinux 策略或获取特权安装权限。

本仓后端据此采用已验证私有候选的完整写流摘要、fsync 和本应用独占写入约束，保留进程内的原候选关联；未提交 session 丢失该关联就退役重做准备。持久的封存前摘要证明实际输出过哪些字节，不独立证明系统暂存盘读回；平台最终验签与安装后 base APK 全量摘要分别负责后续校验。已封存、确曾等待确认的原 session 恢复条件不变。具体实现边界和设备验证见[安装会话记录](android-apk-installation.md)。

[session-info]: https://developer.android.com/reference/android/content/pm/PackageInstaller.SessionInfo
[session26-read]: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#323
[session26-open-read]: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#496
[session26-commit]: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#522
[session26-pending]: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#564
[session26-destroy]: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#1182
[session26-service]: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerService.java#788
[session26-adapter]: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerService.java#1051
[session26-finish]: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerService.java#1275
[session26-public-commit]: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/core/java/android/content/pm/PackageInstaller.java#870
[session28-read]: https://android.googlesource.com/platform/frameworks/base/+/android-9.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#554
[session28-open-read]: https://android.googlesource.com/platform/frameworks/base/+/android-9.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#725
[session28-assert]: https://android.googlesource.com/platform/frameworks/base/+/android-9.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#478
[session28-commit]: https://android.googlesource.com/platform/frameworks/base/+/android-9.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#781
[session28-pending]: https://android.googlesource.com/platform/frameworks/base/+/android-9.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#930
[session28-adapter]: https://android.googlesource.com/platform/frameworks/base/+/android-9.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerService.java#881
[session28-finish]: https://android.googlesource.com/platform/frameworks/base/+/android-9.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerService.java#1105
[session36-read]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#1564
[session36-open-read]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#2100
[session36-assert]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#1498
[session36-info]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#1375
[session36-seal]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#2433
[session36-stream]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#2296
[session36-pending]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#2838
[session36-send]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java#5582
[session36-finish]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerService.java#2300
