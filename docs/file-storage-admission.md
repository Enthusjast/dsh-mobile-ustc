# 文件隔离存储与扫描准入

此阶段实现 Go 内部文件组件，尚未注册文件 REST 路由、扫描后台作业、元数据 / 配额事务、Relay offer 或 Android 文件入口。原生 DSH 文件准入见 [native-file-admission.md](native-file-admission.md)。

## 完整字节验证

`VerifiedReader` 要求声明大小和小写 SHA-256，逐块计算真实摘要并流式送入独立扫描实例。最大输入 200,000,000 字节，内部单次读取不超过 65,536 字节。

最终数据块在真实 EOF、完整字节数、摘要和扫描结果均通过后才返回。这样对象存储客户端即使只消费声明的 Content-Length、不再读取 EOF，也无法完成未经验证的请求体。空文件在返回 reader 之前完成 EOF、空摘要和扫描检查，避免零长度 HTTP body 完全不触发 Read。

短流、多余字节、错误摘要、异常 / 不前进的 reader、扫描写入失败或不可用结果均不产生 verified 状态。部分流可能已进入私有候选写入；只有组件返回成功和随后持久元数据转换，才可能成为可交接文件。

## clamd 传输

`ClamAV` 使用独立的 `zINSTREAM` 连接和大端长度帧。只接受一个完整、NUL 结尾的 `stream: OK` 记录及连接关闭；FOUND 拒绝，限额错误、未知 / 额外 / 超长 / 未结束回复和守护进程不可用均拒绝准入。调用超时或取消会关闭连接并中断等待。

可配置本机绝对 Unix socket，或验证服务端身份的 TLS/TCP；没有未验证 TCP 或默认 clean 实现。TCP 要求明确 ServerName，TLS 最低版本为 1.2。

生产部署仍需配置并验证实际 clamd、签名库更新和与 200 MB 上传上限相符的 StreamMaxLength、MaxFileSize、MaxScanSize、归档展开限制及超限告警策略。协议收到 OK 不能证明这些配置或实际病毒检测已经验收。本阶段的扫描对端是协议夹具，没有声称运行真实病毒引擎。

## S3 对象边界

锁定 AWS SDK for Go v2 S3 `v1.114.1`、核心 `v1.47.1` 和 Smithy `v1.28.1`。构造时要求 HTTPS 端点、region、bucket、显式 KMS key ID 及外部提供的凭据；不自动读取用户默认 AWS profile。HTTP 不跟随重定向，不自动解压文件内容。

对象键仅由服务器拥有的组织、会话、文件和 attempt UUID 构造：`remote-files/v1/<kind>/<org>/<session>/<file>/<attempt>`。文件名和客户端路径不参与存储键。上传 capability 只能指向 quarantine，最长 15 分钟，绑定实际大小、SHA-256、内容类型和 SSE-KMS；格式化对象时隐藏签名 URL，URL 只用于显式响应，不用于审计或持久化。

已验证对象使用不同的 `objects` 键，通过 `If-None-Match: *` 写入已打开且通过扫描的实际流。不会在扫描完成后再从可能已被重写的 quarantine 键执行 CopyObject。签名使用 TLS 下的 unsigned streaming payload，加上显式 SHA-256 checksum，避免要求 rewind 来源；禁用自动请求重试。

成功写入必须同时满足 reader 的 verified 状态、PUT 的 SHA-256 及 SSE-KMS 响应，再核对 HEAD 的实际大小、checksum、算法和 key ID。HEAD 没有替代内容校验或扫描。GET 同样核对实际长度及明确的 SSE-KMS/key ID，调用方继续校验完整内容。

KMS key ID 应使用对象服务实际返回的标识；缺少或不同的加密证据会拒绝。SSE-KMS 请求及响应校验不是实际 KMS 部署验收。本阶段的 TLS S3 对端验证真实 SigV4 签名，并在夹具内部用 AES-GCM 保存候选字节；没有把该夹具当成生产 KMS 或对象服务。

写入响应丢失仍返回 unavailable，不能据此标记 clean；相同候选键冲突返回 conflict。未引用候选对象与过期 quarantine 需要后续持久清理作业，本组件不承诺在失败后立即删除。

## 验证记录

`go test -race -count=1 -v ./internal/files` 及 `go vet ./internal/files` 通过。34 项结果（含子用例）覆盖：

- 已声明长度的消费者不读取 EOF、最后一块等待扫描、空文件、短 / 长流、异常 reader、摘要与源错误。
- INSTREAM 字节和帧边界、FOUND / 限额 / 畸形回复、取消、Unix socket、TLS 身份校验与错误证书名称拒绝。
- 真实 SDK 的签名 PUT / GET / HEAD / DELETE；隔离能力的摘要和路径绑定、不可覆盖候选对象、显式 KMS 证据及错误响应。
- 流式发送已开始后才结束扫描；隔离对象在打开 GET 后变化，最终写入仍是已扫描的同一流。
- 响应丢失不自动重试，不将权限头随重定向转发给另一个 TLS 对端。

完整 `npm run test:remote-kotlin` 通过现有 Go race、隔离 PostgreSQL、Kotlin TLS 客户端和 npm DSH 回归。该组合目前验证既有聊天 / 归档 / 审批链路，不是文件端到端验收。本机证据为 `.local/files-s3-final.log`、`.local/files-s3-results.jsonl`、`.local/files-backend-regression.log`。

接口依据：[ClamAV 命令协议](https://docs.clamav.net/manual/Usage/Scanning.html)、[AWS SDK 流式来源](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/sdk-utilities-s3.html)、[SSE-KMS](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)。具体实现同时以锁定模块源码和实际协议测试为准。
