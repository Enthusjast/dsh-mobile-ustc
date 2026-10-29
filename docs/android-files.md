# Android 文件协议、传输与附件命令

Android 已提供系统文件选择、前台上传、受保护文件 API、匿名流式 PUT、加密上传意图和文件 ID 命令。实际 Kotlin 客户端已通过 TLS Go / PostgreSQL、S3 SDK 协议对端、扫描协议对端和真实 npm DSH 的联合测试。会话历史已显示受限附件摘要；[导出的 Host 来源层](file-export-sources.md)、[服务端鉴权下载](file-export-service.md) 和 [Relay 协调](file-export-relay.md) 已实现，Android 已接入来源浏览、原请求恢复和系统文档保存；API 26 APK 已通过真实 Go / DSH 的受控文件组合，生产基础设施与目标真机验收仍待完成。

## 系统选择器与恢复

会话附件面板仅在当前用户具有上传权限时出现。选中的 `content://` 由 ContentResolver 分两次流式读取，先计算长度和 SHA-256，再在匿名 PUT 中核对原字节。不会申请整个存储空间权限，也不持久化 URI 或获取永久读取授权。离开前台、退出账号或切换页面会取消传输并关闭输入源。

每次系统选择都有独立 UUID、Activity Result 注册键、账号代次和明确 runtime/session。过时结果不能被重新标记为新账号的选择。选择器导致应用进入后台时，只在内存保留原会话的草稿；返回原会话后恢复，离开该会话或退出账号立即清除，不写入 saved state。

Room v5 在已有 SQLCipher/WAL 中新增 `file_uploads`。它只保存原 request ID、目标、名称、长度、摘要、已登记文件 ID 和原消息关联。登记前保存原意图，匿名 PUT 前保存文件 ID；不保存文件字节、URI、签名 URL、header 或原生 receipt。每个设备账号最多 64 条上传记录；撤权和账号退出按现有数据生命周期清理。

重新进入会话后只查询已知 ID。中断的上传需要明确核对或重新选择原文件，按原名称、大小和摘要验证后继续同一登记。不会凭空生成新的上传 ID。扫描通过与电脑暂存分别展示；只有当前仍可发送的未绑定附件可勾选，最多 15 个，可单独发送或与文本组合。

保存文件消息时，上传关联与原命令在同一数据库事务内提交。任一文件不存在、目标不符或已属于其他消息，整批回滚，避免部分关联。上传完成、绑定原请求和 Agent 入队使用不同文案；面板不会把这些状态当成任务完成。

## 元数据与传输

`FileManifest` 限制文件为 200,000,000 字节以内，文件名最多 512 个 UTF-8 字节，拒绝路径分隔符、控制字符、非标量 Unicode、空白名和点目录名。Kotlin 解析同一组 `contracts/files/v1/golden/` 样例，上传元数据只有名称、准确大小和 SHA-256。

`RemoteApi.registerFile` 使用调用者保存的原 request ID，经现有 JWT / DPoP 通道登记上传。`fileUploadURL`、`commitFile` 和 `fileStatus` 分别刷新原上传地址、提交扫描和查询持久状态。注册响应必须与指定 runtime、session 和完整 manifest 一致，后续响应还须保持原文件 ID。

`PreparedFileUpload` 与创建它的 RemoteApi 实例绑定。地址和签名 header 只存在于内存，不能放进 UI 状态、日志、命令、saved state 或本地数据库。刷新身份后须从新 API 实例取得该原文件的新 capability，不能把旧句柄挪到另一个账号 / 部署 / 客户端。

`uploadFile` 采用同一受控 TLS 策略，发送独立匿名 PUT；没有学校 Authorization、DPoP 或 Cookie。地址只接受 HTTPS，拒绝 userinfo、fragment、未知 / 重复签名 header、错误长度 / checksum / 类型和超长寿命。仅允许明确的 S3 内容 / checksum / SSE-KMS 签名字段，不跟随重定向，也不自动重放一次性 body。

body 每次从调用者提供的 InputStream 工厂重新打开，以 64 KiB 缓冲流式读取，核对准确长度并重新计算 SHA-256。变更的文件、短流、超长流、源读取失败或期限失效都会中止，不自动 commit。取消同时取消 HTTP 并关闭已经打开的源；提供者读取阻塞时，独立协程期限也会退出等待并尝试关闭源，不仅依赖 socket 超时。进度只是已写字节数，上传完成和扫描 / 原生准入分别确认。

## 区分扫描、暂存与消费

公共 `FileStatus.state` 继续表示 uploading / scanning / clean / rejected / expired。新增可选 `delivery` 提示用于客户端展示：

| delivery | 含义 |
| --- | --- |
| waiting | 对象已 clean，当前 Host 尚未确认可以接收附件消息。 |
| ready + expires_at | 当前连接已发送暂存确认，且短租约仍有效；只是展示提示。 |
| bound + request_id / command_state | 已归属原命令，不能作为另一个新命令的附件。 |

提示只在原文件设备授权通过后返回，不暴露原生 receipt、对象 key、下载 ticket 或连接标识。Host 断线、替换或租约失效会使未绑定文件回到 waiting；只支持暂存但不支持文件消息的旧 Host 也不会显示 ready。实际发送仍重新执行 [服务端原子准入](file-message-relay.md)，不能把 ready 当成凭据。

Kotlin `readyForMessage` 还限制提示的本地有效期最多五秒。没有 delivery 的旧响应可以展示上传 / 扫描状态，但不能据此宣称附件已经可以发送。一个上传意图只归属一个原消息；发送 / 扫描失败不生成新消息 ID 去猜测重试。

本次消息的选择是内存内的展示状态：用户可以随时移出已选项，即使五秒暂存提示刚刚失效或连接已断开；移出不会删除上传记录。重新加入仍必须满足当前 `readyForMessage`，发送协调器继续重新核验能力与暂存，不因取消选择而改变原请求或文件记录。

## 命令与能力

`CommandIntent.message` 可组合文本和文件 ID，也支持只有附件的消息。所有 content 合计最多 16 项，文件项只能是 type=file / file_id=UUID；重复文件 ID、原生 receipt 和路径均被拒绝。摘要与 Go / Node 共享样例完全相同，原意图可继续由现有加密命令日志保存。

手机在有 message.submit 范围时提供 `message.files.v1`，实际协商成功后 `SessionCommands.state.canAttachFiles` 才为真。发送前再次检查能力；旧服务 / Host 下会保留原草稿并返回 file.unsupported，不写入不支持的文件帧。断线清除当前能力，不自动发送旧连接队列。已尝试命令继续先通过原有 REST 状态对账，再决定是否能以原 ID 重发。

投递未确认且原命令没有任何远端保存证据时，用户可明确重试原文件消息。状态接口失败本身不证明命令不存在（服务端可能用 access.denied 隐藏差别）；客户端还必须逐一取得当前授权下、目标相同、未绑定且暂存仍有效的文件状态，才允许短时间内以原 ID / 摘要继续。不会伪造 received，也不会在重连时自动重发。原命令已有保存 / 入队证据、文件已绑定或无法核对时，继续保持结果待确认。

## 导出浏览、下载与文档保存

Android 的 `file.export.v1` 使用现有会话接收器，不另开竞争读取者。当前 ticket 明确含 `session.read` / `file.download` 且双方协商该能力时，才允许浏览和准备来源；归档会话与 viewer 可以在其明确授权下导出。工作区目录只保留原 grant 明确授予的 workspace UUID，会话授权不会推导出工作区授权。

来源和游标只存在于当前连接内存，重连即清除。每页至多十六项，包括可继续翻页的空页；超出 2,000,000,000 字节的来源不能选择。准备导出前，Room v6 在原 SQLCipher / WAL 中新增 `file_exports` 保存原 request ID、来源 UUID、epoch、目标、来源类型和显示元数据；获知文件后再固定 file_id、准确长度和 SHA-256。以后改变文件或摘要均冲突。已有命令和上传记录通过 v5→v6 迁移保留；每个账号设备最多六十四条导出记录。

重新打开只查询原 `/v1/file-exports/{request_id}` 或已知 file_id，不重新发送导出请求，不使用旧来源句柄。已经准备、扫描通过和文档已保存分别展示。移除本机记录不是云端删除，停止原作业也不承诺收回已经签发的短期 PUT 地址。

保存选择使用独立 UUID 和 Activity Result 注册键，绑定原账号代次、runtime、session、request 和不可变文件摘要。系统选择器返回前只保留内存意图；返回原会话并重新打开加密数据库后，才核对原文件并开始下载。不保存 URI、永久文档授权、正文或网络凭据。迟到的已取消选择只清理其新建空文档，不能转给新账号；重复的已消费回调不会删除已保存文档。

`RemoteApi.downloadExport` 先重新读取受权元数据，再经 JWT / DPoP 请求二进制 content。只对明确 nonce 挑战重试 GET；不重定向、不请求 Range，不把文件 body 交给 JSON 缓冲器。它检查准确的 Content-Length、二进制类型、identity 编码和服务端摘要 header，并逐块独立计算 SHA-256。下载期间普通 REST 请求仍能进行。前台任务取消会取消 HTTP 并关闭输入 / 输出；网络单次读取和整个传输均有期限。

下载先进入应用私有缓存中的分块 AES-GCM 暂存文件，每块最多 64 KiB，绑定 manifest、块位置和长度。随机密钥和 nonce 前缀只存在内存；不产生明文磁盘副本。篡改、交换、截断或追加记录都不能通过发布校验。正常退出删除暂存，进程重开清理失去密钥的残留密文。

系统文档位置须支持写入、删除和重命名，并能回读。开始写入前将目标标成 `DSH-incomplete-<UUID>.dsh-partial`；下载校验后才解密复制，再从文档提供者回读核对长度和 SHA-256。成功后改成最终名称并显示“已保存”。失败或取消优先删除、退而清空目标；两者均失败会明确提示用户删除不完整文档。进程在复制期间退出时，提供者内可能留下带未完成标记的文档，用户需自行清理；没有持久化 URI，不能承诺进程重启后自动删除它。

此设计保持字节缓冲有界，但尚未完成 2 GB 实际传输、所有云文档提供者或厂商系统的验收。内容校验成功证明本次回读结果，不证明提供者未来持久性或独立云端备份。

## 历史中的附件

Host 将原生 file 块转换为现有 text 显示块，例如 `[附件：资料.txt（12 字节）]`。仅有文件的消息因而也能显示在快照、实时历史和既有加密缓存中，旧版读取方继续使用同一文本格式。它使用 DSH 准入后的显示名，不把手机原文件名当成实际存储名。

只有合法的叶文件名和非负安全整数大小可以进入摘要；无效元数据显示“请在电脑端查看”。原生 attachmentId、receipt、路径、URL、额外字段和文件字节均被丢弃。摘要只用于阅读，下载仍需独立的受限导出授权。原生注入的模型上下文继续仅推进 cursor，不因其中包含文件而成为用户消息。

## 本地证据

- Kotlin 模型测试使用同一 Go / Node 上传样例和文件消息摘要，覆盖字段白名单、路径 / receipt 混入、大小 / Unicode、重复引用和存储格式恢复。
- 实际 HTTPS 对端验证注册 nonce、匿名 PUT 的准确字节与 header、服务 / 对象 nonce 隔离、重定向拒绝、TLS 身份错误、跨 API 句柄、空文件、到期与取消关闭输入源。
- Kotlin 会话客户端测试确认文件命令先保存后发送，旧 peer 不接收文件帧；既有聊天、问题、审批和归档同时回归。
- `npm run test:remote-kotlin` 增加实际文件组合：Kotlin 登记两次仍为同一文件、匿名直传、Go worker 扫描、轮询 ready、现有命令组件发送、DSH 实际附件入队。最终只有一个文件归属、一条原生用户消息和一次 prompt 调用。该 JVM 组合使用内存命令日志测试适配器，文件消息的实际 SQLCipher / WAL 生命周期另由下述 APK 组合验证。

上述协议基线记录为 `.local/android-files-network-first.log`、`.local/android-files-expiry-test.log`、`.local/android-files-full-check-second.log`、`.local/android-files-kotlin-chain-final.log`、`.local/android-files-host-contract-final.log`。

2026-10-26 的上传界面与恢复改动已通过完整 Android check、Lint、debug APK / test APK 构建，以及 138 项协议 / 命令 / 网络测试。API 26 安全模拟器的原有选择器 / 聊天 / 命令回归共 20 项通过；加密上传测试进一步覆盖 WAL / 重开、v4→v5 迁移、批量回滚、范围清理和不虚构回执的原 ID 重试。记录为 `.local/android-upload-ui-full-check-second.log`、`.local/android-upload-ui-device-second.log`。

新增设备组合从选择器结果处理入口注入受控 content URI，经独立进程的真实 Binder ContentProvider、生产 DocumentFileSource / SessionUploads、TLS REST 与匿名 PUT 夹具、SQLCipher 和 Relay 命令组件完成文件单独发送。测试分别等待 scanning、clean/waiting、ready 和原命令 agent_queued，确认重进页面仍只关联原上传 / 原消息，没有再次 PUT 或提交新命令。最新选择器、上传持久性、附件面板和输入框共 13 项设备测试通过，记录为 `.local/android-upload-provider-device-second.log`。系统 DocumentsUI 的人工点选和真实对象服务仍属于后续验收范围。

安全历史摘要已通过 `npm run verify` 的 214 项 Host 测试。随后 `npm run test:remote-kotlin` 再次通过隔离 PostgreSQL 的完整 Go race 套件和实际 npm DSH 0.2.1-rc.2 联合测试：Kotlin 发送只有附件的消息，等待其原生历史中的准确显示名 / 大小摘要，核对绑定并重试原请求，最终仍只有一次原生 prompt 和一条文件归属。记录为 `.local/android-upload-host-summary-verify.log`、`.local/android-file-summary-kotlin-chain.log`。

Android 导出接入又通过 150 项协议 / 命令 / 网络 JVM 测试、完整 Android check、Lint 与开发 APK / test APK 构建。API 26 安全模拟器进一步通过 27 项相关设备回归，其中新增十项覆盖导出加密记录、v5→v6 迁移、稳定 / 变化 URI 的文档提供者、回读损坏、清理失败、账号退出和前后台切换；原上传、选择器、聊天与输入框一并回归。记录为 `.local/android-exports-core-tests.log`、`.local/android-export-lint-final.log`、`.local/android-export-final-check.log`、`.local/android-export-save-final-build.log` 和 `.local/android-export-save-device-final.log`。

新增 APK 组合从创建文档的结果处理入口注入单次 URI 授权，经过生产 SessionExports / RemoteApi、JWT / DPoP / TLS 协议夹具、真实 SQLCipher / WAL 与独立进程 Binder DocumentsProvider 完成保存。用例确认登记前已有原记录，系统选择器导致的前台重开不重新准入，重复 Activity Result 不删除已保存文件，迟到账号结果不下载，后台取消清理目标。提供者由测试 APK 的 MANAGE_DOCUMENTS 权限保护，只给目标应用具体文档的读取 / 写入授权；生产 APK 没有增加文档管理权限。这组提供者用例没有人工操作 DocumentsUI，与下述真实 Go / DSH 组合分开记录。

随后 `npm run test:remote-kotlin` 再次通过完整隔离 PostgreSQL / Go race / Kotlin / 真实 npm DSH 0.2.1-rc.2 联合回归，记录为 `.local/android-export-save-kotlin-chain.log`。该回归覆盖已有真实服务和原生运行时组合；新增 APK 文件路径另由下述显式设备组合验证。

2026-10-26 的 `npm run test:remote-android -- emulator-5594` 扩展组合已通过：同一个真实 npm DSH CLI / 正常插件会话先执行两次签名审批，再接收 APK 的扫描后文件消息；随后 APK 浏览并导出普通工作区二进制、空文件和该持久附件，经真实 Go 文件服务 / Relay、S3 SDK 协议对端、扫描 worker 和带单 URI 授权的 Binder DocumentsProvider 完成保存与回读校验。提供者重命名会改变 URI。控制器重开还原同一上传 / 消息关联和三个导出原请求，并查询真实 REST 原请求接口。

原生侧独立核对一次附件准入、三个 prompt 调用和三条原生用户消息，导出没有额外发起 prompt。PostgreSQL 核对一个上传 / 消息归属、三个带 origin / workspace 的已上传导出、四个 clean 扫描 attempt、三个 served 下载审计，以及四次成功匿名 PUT；重开没有增加对象。完整审批 / 归档 / 文件组合耗时约 199 秒，记录为 `.local/android-real-files-catalog-fixed.log`，运行方式见 [APK 组合说明](android-device-composition.md)。这仍是小文件、本地协议夹具和安全模拟器的证据，不覆盖真实学校、对象服务、病毒引擎或物理手机。

扩展设备组合完成后，隔离 PostgreSQL 的全部 Go race / Kotlin / 真实 DSH 回归再次通过，记录为 `.local/android-real-files-full-regression.log`。

对象 / scanner / 身份 / 模型仍是夹具；没有使用 TokenWorks，也没有声称完成实际学校、KMS、病毒签名引擎或文件全链路实机验收。
