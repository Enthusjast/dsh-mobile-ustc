# Android 文件协议、传输与附件命令

Android 已提供系统文件选择、前台上传、受保护文件 API、匿名流式 PUT、加密上传意图和文件 ID 命令。实际 Kotlin 客户端已通过 TLS Go / PostgreSQL、S3 SDK 协议对端、扫描协议对端和真实 npm DSH 的联合测试。会话历史已显示受限附件摘要；受限导出和 APK 到真实后端的文件联合验收仍待完成。

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

## 命令与能力

`CommandIntent.message` 可组合文本和文件 ID，也支持只有附件的消息。所有 content 合计最多 16 项，文件项只能是 type=file / file_id=UUID；重复文件 ID、原生 receipt 和路径均被拒绝。摘要与 Go / Node 共享样例完全相同，原意图可继续由现有加密命令日志保存。

手机在有 message.submit 范围时提供 `message.files.v1`，实际协商成功后 `SessionCommands.state.canAttachFiles` 才为真。发送前再次检查能力；旧服务 / Host 下会保留原草稿并返回 file.unsupported，不写入不支持的文件帧。断线清除当前能力，不自动发送旧连接队列。已尝试命令继续先通过原有 REST 状态对账，再决定是否能以原 ID 重发。

投递未确认且原命令没有任何远端保存证据时，用户可明确重试原文件消息。状态接口失败本身不证明命令不存在（服务端可能用 access.denied 隐藏差别）；客户端还必须逐一取得当前授权下、目标相同、未绑定且暂存仍有效的文件状态，才允许短时间内以原 ID / 摘要继续。不会伪造 received，也不会在重连时自动重发。原命令已有保存 / 入队证据、文件已绑定或无法核对时，继续保持结果待确认。

## 历史中的附件

Host 将原生 file 块转换为现有 text 显示块，例如 `[附件：资料.txt（12 字节）]`。仅有文件的消息因而也能显示在快照、实时历史和既有加密缓存中，旧版读取方继续使用同一文本格式。它使用 DSH 准入后的显示名，不把手机原文件名当成实际存储名。

只有合法的叶文件名和非负安全整数大小可以进入摘要；无效元数据显示“请在电脑端查看”。原生 attachmentId、receipt、路径、URL、额外字段和文件字节均被丢弃。摘要只用于阅读，下载仍需独立的受限导出授权。原生注入的模型上下文继续仅推进 cursor，不因其中包含文件而成为用户消息。

## 本地证据

- Kotlin 模型测试使用同一 Go / Node 上传样例和文件消息摘要，覆盖字段白名单、路径 / receipt 混入、大小 / Unicode、重复引用和存储格式恢复。
- 实际 HTTPS 对端验证注册 nonce、匿名 PUT 的准确字节与 header、服务 / 对象 nonce 隔离、重定向拒绝、TLS 身份错误、跨 API 句柄、空文件、到期与取消关闭输入源。
- Kotlin 会话客户端测试确认文件命令先保存后发送，旧 peer 不接收文件帧；既有聊天、问题、审批和归档同时回归。
- `npm run test:remote-kotlin` 增加实际文件组合：Kotlin 登记两次仍为同一文件、匿名直传、Go worker 扫描、轮询 ready、现有命令组件发送、DSH 实际附件入队。最终只有一个文件归属、一条原生用户消息和一次 prompt 调用。该 JVM 组合使用内存命令日志测试适配器，文件消息的实际 SQLCipher / WAL 生命周期仍需 APK 场景验证。

上述协议基线记录为 `.local/android-files-network-first.log`、`.local/android-files-expiry-test.log`、`.local/android-files-full-check-second.log`、`.local/android-files-kotlin-chain-final.log`、`.local/android-files-host-contract-final.log`。

2026-10-26 的上传界面与恢复改动已通过完整 Android check、Lint、debug APK / test APK 构建，以及 138 项协议 / 命令 / 网络测试。API 26 安全模拟器的原有选择器 / 聊天 / 命令回归共 20 项通过；加密上传测试进一步覆盖 WAL / 重开、v4→v5 迁移、批量回滚、范围清理和不虚构回执的原 ID 重试。记录为 `.local/android-upload-ui-full-check-second.log`、`.local/android-upload-ui-device-second.log`。

新增设备组合从选择器结果处理入口注入受控 content URI，经独立进程的真实 Binder ContentProvider、生产 DocumentFileSource / SessionUploads、TLS REST 与匿名 PUT 夹具、SQLCipher 和 Relay 命令组件完成文件单独发送。测试分别等待 scanning、clean/waiting、ready 和原命令 agent_queued，确认重进页面仍只关联原上传 / 原消息，没有再次 PUT 或提交新命令。最新选择器、上传持久性、附件面板和输入框共 13 项设备测试通过，记录为 `.local/android-upload-provider-device-second.log`。系统 DocumentsUI 的人工点选和真实对象服务仍属于后续验收范围。

安全历史摘要已通过 `npm run verify` 的 214 项 Host 测试。随后 `npm run test:remote-kotlin` 再次通过隔离 PostgreSQL 的完整 Go race 套件和实际 npm DSH 0.2.1-rc.2 联合测试：Kotlin 发送只有附件的消息，等待其原生历史中的准确显示名 / 大小摘要，核对绑定并重试原请求，最终仍只有一次原生 prompt 和一条文件归属。记录为 `.local/android-upload-host-summary-verify.log`、`.local/android-file-summary-kotlin-chain.log`。

对象 / scanner / 身份 / 模型仍是夹具；没有使用 TokenWorks，也没有声称完成实际学校、KMS、病毒签名引擎或文件全链路实机验收。
