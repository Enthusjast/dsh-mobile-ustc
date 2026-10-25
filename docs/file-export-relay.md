# 受限来源经 Relay 导出

正常插件已将 [Host 来源层](file-export-sources.md) 与 [Go 导出 / 扫描 / 下载](file-export-service.md) 接入 `file.export.v1`。开启后端 exports.enabled 且双方实际协商该能力时，手机可按会话浏览来源、选择文件并启动导出。Android 的类型适配、浏览 / 保存 / 恢复界面仍需接入。

当前 Host 来源适配要求 Linux procfs；不支持的平台不宣告能力。旧服务不接受该扩展时，插件继续提供已协商的聊天 / 审批等能力，不把新文件请求变成普通消息或本机路径读取。真实 DSH CLI 的握手回归同时验证新能力摘要和旧服务未接受该能力的组合。

## 手机选择与 Host 读取

初次 `file.exports.list` 返回“会话附件”目录，以及明确允许的工作区 exportRoots。手机后续只提交 directory_id、cursor 或 source_id 这类随机 UUID；不会提供路径、原生存储 ID、receipt、user/device 身份或权限标记。

目录及游标保存在当前 Host 连接的私有目录中。工作区目录按内核 fd 相对读取，不跟随根、父级或最终组件的符号链接，跳过特殊类型和多硬链接文件。每页最多十六项，单页最多检查二百五十六个目录项；空页仍可携带继续游标。名称只含当前层叶名，不发送主机绝对路径。超出 2 GB 上限的文件显示不可导出标记。

会话附件来自固定持久切点的原生日志分页，继续排除模型注入的 user-role 上下文。元数据只提取合法显示名、长度和内部选择位置；原生 ref 和日志正文不会进入来源回复。图片选择对应原生已保存的归一化对象。

列表不预先哈希整个目录。文件选择时，Host 重新解析当前会话和目录策略，以列表记录的 inode / 版本指纹检查工作区文件，再固定描述符、计算摘要。列表后改写、替换或失去策略的来源会拒绝。准备与上传期间继续检查短租约，并使用 [来源读取层](file-export-sources.md) 的长度 / SHA-256 与尾块规则。

当前目录缓存最多 1024 个条目、八个分页游标，最长五分钟；已准备文件沿用三十二个句柄 / 两个摘要作业的预算。分页游标不可同时推进、跨目录、跨会话或换用户 / 设备 / key / grant generation 使用。连接结束会关闭目录、游标和该连接持有的作业。

## 字面 scope 与持久来源类型

会话级与工作区级权限分开计算。只有 ticket 和当前 grant 都明确包含目标 workspace UUID 时，Go 才发出 allow_workspace；不会把 session grant 或 session.read 自动升级为共享工作区浏览权。

Host 根据该标记过滤根目录，并在准备时检查所选来源；Go 还检查 Host 回复的 origin，不能借一个不透明 ID 绕过 scope。设备相同、grant version 相同但 ticket 更窄时，同样不能使用较宽连接得到的工作区 ID。

迁移 `013_export_scope` 持久记录 session_attachment / workspace_artifact 以及工作区来源的原 workspace UUID。工作区导出在登记、上传确认、扫描和下载的每一步，都需要当前字面 workspace grant；只保留原 session grant 不够。旧版未区分来源的行被标为失效，不能在升级后推定具有更宽权限。回滚仍保留对象和配额清理依据。

## 生命周期与回执

| 帧 | 方向与意义 |
| --- | --- |
| `file.exports.list` / `file.exports.result` | 手机请求受权元数据；Go 给 Host 转发独立操作 ID，结果只回原 socket。 |
| `file.export.request` | 手机用原 request ID 选择一个 source_id。 |
| `file.export.manifest` | Host 返回已准备来源的名称、长度、摘要、origin 和期限。 |
| `file.export.upload` | Go 给原 Host 返回已登记文件和隔离 PUT capability；不回手机。 |
| `file.export.uploaded` / `file.export.committed` | Host 完成匿名 PUT 后确认；Go 持久消费原来源上传证明，允许后台扫描。 |
| `file.export.accepted` | 手机取得原文件的 uploading / scanning / 后续对账状态；不表示文档已保存。 |
| `file.export.renew` / `file.export.renewed` | Host 批量续原操作的短租约，不改变 owner、key、grant 或最晚期限。 |
| `file.export.cancel` / `file.export.abort` / `file.export.error` | 手机取消、服务端终止或固定错误；不包含路径 / URL / 正文。 |

Go 给每次 Host 操作生成新的 request ID，并保存原手机 request ID、确切 socket、目标、用户 / 设备及安装 / epoch / connection 对应关系。来源权限从数据库解析，Host 回复不能选择请求者或自行决定 scope。每个作业最长五分钟且不超过连接 / 凭据期限，权限租约最长五秒；过期回复不能恢复旧作业。

当前每 Host 最多八个作业、每手机 socket 四个、每 Relay 进程二百五十六个，Host 队列也有上限。手机文件请求共用既有操作速率预算；续租、撤权、断线或取消与哈希 / 对象 I/O 分开处理，慢文件不能阻止租约消息被读取。

工作区文件内容只经匿名 HTTPS PUT 进入隔离对象。发送方限制 URL / header、寿命、长度和摘要，不附带学校 Authorization、DPoP 或 Cookie，不跟随重定向，也不自动重放一次性输入流。S3 SDK 会为已知空 PUT 省略 Content-Type 签名，服务端仍明确返回固定的二进制传输 header；真实空文件链路已有回归。

服务端先原子登记配额、文件与来源，再发上传能力。元数据暂时不可用或 scanner 自检未就绪时，可在原操作期限内对同一登记 / 确认重试，不重新读取来源生成一条新用户意图。已登记的原请求在重试时先查持久记录，保留原 file_id；更换 source_id、目标或 epoch 会冲突。原 socket / Host 已结束时，使用已有 request ID 的 REST 对账，不把新连接接到旧一次性输入流上。

取消只停止当前作业和读取；已经签发的 PUT capability 仍遵守原短期到期语义。未完成文件由既有过期 / GC 处理；取消不声称已经抹除对象。扫描和鉴权下载仍采用 [后端策略](file-export-service.md)，手机最终还要校验保存结果。

## 本地证据与剩余边界

共享扩展 Schema 与样例位于 `contracts/ws/v1/file-export.schema.json`、`contracts/ws/v1/golden/file.export.*` / `file.exports.*`，由 `npm run contracts` 生成。Go 和 Node 分别检查手机 / Host 消息形状，运行时另检查角色、路由、期限和当前 scope。

真实 npm DSH 0.2.1-rc.2 的正常插件已通过 TLS Go / PostgreSQL / S3 SDK 协议对端 / scanner 协议对端联合用例：工作区普通文件、空文件和原生日志附件经浏览、准备、匿名 PUT、扫描与鉴权下载；原 request ID 重试仍是同一文件，跨设备 ID 被拒绝，窄 session ticket 只能枚举 / 准备会话附件，导出没有增加 prompt 或原生用户消息。另有错误形状、越权元数据、grant generation 续租失败、上传确认越序与目录版本变化测试。

原生组合的记录为 `.local/export-relay-native-empty-fixed.log`；前置来源、传输和权限用例见 `.local/export-catalog-tests-first.log`、`.local/export-transport-tests-first.log`、`.local/export-scope-postgres-first.log`。完整 `npm run verify` 的契约 / 类型 / 构建与 236 项 Host 测试通过，记录为 `.local/export-relay-host-verify-second.log`；Go vet 与全部隔离 PostgreSQL / Go race / Kotlin / 真实 DSH 联合回归通过，记录为 `.local/export-relay-go-vet.log`、`.local/export-relay-full-kotlin-chain.log`。

这仍是本地夹具组合。Android 保存入口与 APK 导出组合、大尺寸实际扫描 / 传输、macOS / Windows 来源适配和生产基础设施验收尚未完成；没有使用 TokenWorks 或真实学校配置。
