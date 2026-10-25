# Android 文件协议、传输与附件命令

Android 共享模块已提供受保护文件 API、匿名流式 PUT、严格元数据解析和文件 ID 命令。实际 Kotlin 客户端已通过 TLS Go / PostgreSQL、S3 SDK 协议对端、扫描协议对端和真实 npm DSH 的联合测试。文件选择 / 上传界面、上传意图的进程恢复、会话附件显示和受限导出尚待接入；本节不表示 APK 文件验收已经完成。

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

UI 接入还须处理投递未确认且服务端尚无命令记录的状态，结合文件是否仍未绑定来决定显式恢复，不能伪造 received 或盲目重发。文件字节与 URL 不属于消息正文，文件选择 / 本地输入源恢复需要独立、按账号隔离的保存策略。

## 本地证据

- Kotlin 模型测试使用同一 Go / Node 上传样例和文件消息摘要，覆盖字段白名单、路径 / receipt 混入、大小 / Unicode、重复引用和存储格式恢复。
- 实际 HTTPS 对端验证注册 nonce、匿名 PUT 的准确字节与 header、服务 / 对象 nonce 隔离、重定向拒绝、TLS 身份错误、跨 API 句柄、空文件、到期与取消关闭输入源。
- Kotlin 会话客户端测试确认文件命令先保存后发送，旧 peer 不接收文件帧；既有聊天、问题、审批和归档同时回归。
- `npm run test:remote-kotlin` 增加实际文件组合：Kotlin 登记两次仍为同一文件、匿名直传、Go worker 扫描、轮询 ready、现有命令组件发送、DSH 实际附件入队。最终只有一个文件归属、一条原生用户消息和一次 prompt 调用。该 JVM 组合使用内存命令日志测试适配器，文件消息的实际 SQLCipher / WAL 生命周期仍需 APK 场景验证。

本机记录为 `.local/android-files-network-first.log`、`.local/android-files-expiry-test.log`、`.local/android-files-full-check-second.log`、`.local/android-files-kotlin-chain-final.log`、`.local/android-files-host-contract-final.log`。完整 Android check、debug APK 构建和 135 项协议 / 命令 / 网络测试通过。对象 / scanner / 身份 / 模型仍是夹具；没有使用 TokenWorks，也没有声称完成实际学校、KMS、病毒签名引擎或 APK 文件实机验收。
