# 文件 REST 与后台服务

文件登记、隔离上传、扫描、候选写入、状态确认及后台清理现已接入正常 Go 服务入口。启用文件服务后，扫描通过的对象可通过 [Host 交接](file-host-handoffs.md) 暂存到真实 DSH 会话，再经 [消息附件授权](file-message-relay.md) 引用文件 ID。[Android 文件入口和显示](android-files.md) 已接入。`clean` 不表示 Host 收到文件、生成 receipt 或消息入队。

to_host 公共状态另提供可选 delivery 提示，区分 clean 后的 waiting、当前短租约下的 ready，以及已归属原命令的 bound。该提示不授予任何新权限；发送时仍执行完整事务检查。[Android 共享客户端](android-files.md) 已解析该状态，并接入匿名 PUT、选择器和加密恢复 UI。

新增 [Host 导出账本与手机鉴权下载](file-export-service.md) 使用 from_host 方向，没有 message delivery 提示。下载需单独开启 exports.enabled，并验证扫描配置覆盖导出上限。Host 导出 Relay 协调和手机保存入口尚待接入。

## 启用与配置

设置 `REMOTE_FILES_CONFIG_FILE` 指向受保护 JSON 文件；未设置时不创建文件服务、不启动文件 worker，也不注册文件路由。样例位于 `deploy/files/`：

- `files.json.example`：对象端点、region、bucket、准确的 SSE-KMS key ID、凭据 / CA、scanner 与配额。
- `s3-credentials.json.example`：独立对象服务账号；不是手机或桌面模型凭据。
- `clamd.conf.example`：上传上限、归档扫描及超限拒绝所需的明确设置。

复制成实际配置后，主配置、凭据和 scanner policy 文件须为当前服务可读的私有普通文件（0600 或更严格），不接受最终路径符号链接。相对文件路径基于主配置目录解析。CA 文件有大小 / 普通文件限制，省略时使用系统信任根。配置错误返回固定错误，不输出配置内容或秘密。

S3 只接受明确 HTTPS 端点、region、bucket、KMS key ID 和外部凭据，不读取用户默认 AWS profile。Unix scanner 要求绝对 socket 路径；远端 TCP scanner 要求验证服务端身份的 TLS 和 ServerName。对象 bucket 仍须由运维配置为私有，限制账号权限，并验证实际 KMS、上传时限和对象生命周期。

scanner policy 读取实际部署的 clamd 配置（或内容一致的受保护副本）并计算 SHA-256。解析要求明确、足够的 StreamMaxLength / MaxFileSize / MaxScanSize、启用 ScanArchive / AlertExceedsMax、有限的 MaxRecursion / MaxFiles / MaxScanTime；不接受 Include、关键项重复或无限阈值。该检查不能证明 socket 对端确实使用同一配置，部署必须核对。

## 扫描自检和健康

文件服务启动后先通过 scanner 扫描一个干净样本，再要求标准无害 EICAR 测试样本返回拒绝。样本只在内存中构造和发送给 scanner，不创建工作区文件或对象存储对象。没有 always-clean 生产后备实现。

自检每分钟更新，超过两分钟或时钟向后变化使结果失效。尚未通过或失败时不登记新上传、不刷新 capability、不提交新扫描；既有状态仍可在当前授权下查询。启用文件功能时 `/readyz` 也检查该状态；它不声称已经测试真实对象服务 KMS 或全部病毒检测能力。

## 当前 REST

下表的手机入口通过原有学校身份 / DPoP 中间件、手机客户端限制及活动设备检查。短操作的数据库 / 签名上下文最多三秒，且不超过已验证 token 的实际到期时间。没有客户端提供的 uploader、device、object key、lease 或本地路径选择器。Host 使用单独的 [安装密钥绑定读取入口](file-host-handoffs.md)。

| 入口 | 行为 |
| --- | --- |
| `POST /v1/runtimes/{id}/sessions/{session_id}/files` | 登记 `request_id/name/size_bytes/sha256`，原子预留配额；返回原文件和仍可用的隔离 PUT capability。 |
| `GET /v1/files/{id}` | 对账原设备的持久元数据；不返回签名地址、对象键、原生 receipt 或内部租约。 |
| `POST /v1/files/{id}/upload-url` | 空 JSON body；当前仍满足原始授权且 uploading 时，在原始期限内刷新隔离 PUT。 |
| `POST /v1/files/{id}/commit` | 空 JSON body；把上传转换为 scanning，返回 202；重复终态返回 200，不复制原命令。 |

上传 body 直接 PUT 到对象服务，按返回的已签名 header 和已声明长度发送；不要附带学校 OAuth / DPoP 凭据。capability 是短期秘密，不能放入 URL 日志、审计或持久手机记录。签名地址不能承诺立即撤销。

协议和共享样例见 `contracts/openapi/remote.yaml`、`contracts/files/v1/golden/`。原始登记 ID 跨网络重试保持不变；URL 失败或丢失回执可重新对账 / 获取同一文件的 capability，不新建一个上传意图。

## worker 生命周期

正常服务入口启动 1 至 8 个受限扫描 worker、scanner 自检和过期 / 删除 worker，与 HTTP / Relay 使用同一退出上下文。扫描领取、续期、完成均由 [事务账本](file-transfer-ledger.md) 重新检查当前授权。

每个作业有整体超时和按实际租约到期触发的取消计时器；每五秒尝试续期，数据库续期操作有独立短超时。撤权、失去租约或关闭进程会取消源对象读取、clamd 和 S3 请求。完成仍须通过数据库的最终租约 / 授权检查，不依据对象存在推断成功。

同一取消上下文连接对象 GET、[字节 / 扫描准入](file-storage-admission.md)、不可覆盖候选 PUT、KMS / checksum 响应核对与原子 clean 确认。失联 / 关闭的 attempt 保留已登记候选键，后续由新租约接管；不重放旧 reader。失败只写固定错误码，不把远端错误、文件名或签名 URL 作为日志。

清理 worker先使过期文件失效，按删除租约调用实际对象服务，然后提交删除确认。最后一个追踪对象删除后才释放一次配额；当前 clean 对象受保护。元数据过期 / 删除对账不等于测量物理 bucket 容量，也不删除 DSH 自己的持久附件。

## 验证

已通过：

- `npm run verify`：194 项 Host / 契约测试，含 OpenAPI 公共样例、路径和权限选择器拒绝；Go 同时解析同一共享样例。
- `go vet` 和 race 用例：scanner always-clean 拒绝、自检失效、完整 S3 流、恶意内容、续租撤权、租约到期和退出取消；受保护配置、符号链接、TLS / KMS / 配额 / scanner 限制校验。
- 真实 PostgreSQL + 正常认证 / DPoP REST + 实际 AWS S3 SDK + TLS 对象协议对端 + Unix clamd 协议对端：登记 / 幂等 / 上传 / commit / 扫描 / 候选 / clean / outbox 串联，恶意内容和传输中撤权拒绝，另一个设备和 Host OAuth 客户端拒绝。
- 配置后启动实际编译的 `cmd/remote` 子进程，自动 worker完成扫描，SIGTERM 正常退出，日志无文件名 / capability / 私钥内容。
- 后台 GC 实际删除源 / 候选对象后才释放 PostgreSQL 配额；完整 Go race、Kotlin TLS 和 npm DSH 回归保持通过。

本节原始记录：`.local/files-api-host-final.log`、`.local/files-api-unit-final.log`、`.local/files-api-backend-final.log`。随后完成的 Host offer、当前 epoch / connection 的交接授权与真实 DSH receipt 暂存见 [交接记录](file-host-handoffs.md)，消息引用和消费见 [Relay 文件消息](file-message-relay.md)。对象协议夹具在内存中用 AES-GCM 保存字节；clamd 对端是协议夹具。没有声称运行真实 KMS、实际病毒签名引擎或完成文件 APK 到 DSH 验收。受限导出和手机 UI 仍需继续实现。
