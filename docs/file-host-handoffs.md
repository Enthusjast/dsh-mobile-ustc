# 扫描对象到 Host 会话的交接

正常 Go 服务和 Host 插件现已接通扫描对象到 DSH 0.2.1-rc.2 会话的流式暂存。交接使用已登记安装密钥、当前 WSS 连接与运行代次；原生 receipt 只在 Host 内存中保存。手机消息的附件 ID 授权 / 转换、Android 文件 UI 和受限导出尚待实现，当前手机 `message.submit` 仍只接受文本。

## 配置与迁移

按顺序应用 `deploy/sql/010_file_handoffs.up.sql`，然后更新 Go 服务和 Host 插件。使用已有 `REMOTE_FILES_CONFIG_FILE` 的同一对象服务、scanner policy 与事务账本；未配置时服务端不注册 Host 文件路由，也不协商该能力。没有新增身份服务或通用对象下载入口。

Host 启用远控 Relay 后提供 `file.handoff.v1`，只有服务端也提供该能力时才构造文件 peer。该扩展依赖 `session.catalog.v1`。不支持文件的旧服务仍可连接，手机不能使用 Host 文件帧取得读取权限。Schema 和样例位于 `contracts/ws/v1/file-handoff.schema.json` 与 `contracts/ws/v1/golden/file.*.json`。

回滚时先停用文件交接，再执行 `010_file_handoffs.down.sql`。该操作丢弃临时交接元数据；已经生成的 DSH 持久附件由 DSH 管理。再次启用只从仍有效的 clean 元数据建立新交接，不恢复旧 ticket 或 receipt。

## offer、读取与暂存

1. Go 每秒为当前 Host 查找至多两个待交接文件，仅选当前 scanner policy 下 clean、会话可写、原始上传设备 / key / grant 仍有效的对象。每连接至多追踪 32 个交接；Host 至多并行下载两个文件。
2. `file.offer` 包含不可变名称 / 大小 / SHA-256、原始上传用户和设备、授权版本、交接 UUID、一次性读取 ticket 及期限。每文件只允许一个活动交接，最多每分钟十次重建。达到限制的文件不阻塞其他待交接文件。
3. Host 从已经认证的 Relay origin 构造 `GET /v1/host-files/{handoff_id}/content`。它使用 `Authorization: DSH-File <ticket>` 和 `X-DSH-File-Proof`，拒绝重定向、内容压缩和不匹配的响应长度 / 类型。不会向对象服务传递安装凭据或学校 token。
4. Go 事务校验已登记安装公钥、原始上传者和当前资源授权，再原子消费 ticket。无效证明不消费 ticket，并发有效请求只有一个成功。ticket 仅保存 SHA-256。消费后的网络失败需要重新 offer，不能重放旧 GET。
5. Go 通过私有 S3 SDK 代理读取已提交对象。Host 将流拆成不超过 64 KiB 的块，由原生准入层核对准确大小和 SHA-256，随后保留目标会话的临时 receipt。上传不会写入或覆盖工作区路径。
6. Host 只发送 `file.staged` 的文件 ID、交接 ID 和准入后的名称 / 大小 / 摘要。服务端持久确认后回 `file.staged.ack`，Host 才开放该临时映射。确认会标记相应 `file.clean` outbox 事件已处理，但不代表任何消息已进入 Agent 队列。

读取证明的头必须严格为 `typ=dsh-file-read-proof+jwt, alg=ES256`。payload 只包含 `iss/aud/htm/htu/runtime_id/runtime_epoch/connection_id/handoff_id/file_id/ath/iat/jti`，audience 固定为 `urn:dsh-mobile-ustc:file-read`，`ath` 为 ticket 字符串的 base64url SHA-256。GET 路径和公开 origin 必须准确匹配，`iat` 最大偏差 30 秒。不能用证明内嵌公钥替代已登记密钥。Node / Go 共用 `contracts/security/file-read-proof.json`，其中所有密钥均为公开测试夹具。

成功读取和暂存分别产生 `file.host_read`、`file.host_staged` 安装主体审计；读取审计与 ticket 消费同事务，暂存重试只记一次。审计仅记录资源 ID、连接 / 代次、密钥版本、大小和摘要，不记录 ticket、文件名、路径、receipt 或内容。

## 续租与失效

交接租约最长五秒，Host 每秒批量发送 `file.renew`；硬到期最长五分钟，并进一步受 Host 凭据、原始 grant 和对象期限约束。续租不能恢复已过期交接，也不能延长硬到期。Host 校验应答 request ID、资源路由和租约集合；缺项、错误或应答丢失会撤销对应暂存并取消读取。

Go 在对象请求开始前启动权限监控，因此等待响应头和读取 body 均可取消。监控每 500 毫秒检查数据库与当前 Host 连接，单次数据库检查最多一秒；同时使用租约计时器、硬到期和连接生命周期。撤权、scanner policy 变化、归档、断线、密钥 / runtime epoch / connection 变化均使旧交接失效。

Host 映射还绑定原始上传用户、设备、目标会话和实际原生 receipt。错误用户 / 设备 / 会话不能解析 receipt；会话释放、连接关闭或租约失效会退休 receipt。重连从有效 clean 元数据重新下载并生成新 receipt，持久附件字节不等于 receipt 仍有权限。

当前尚无“文件已用于某条消息”的消费账本。未过期的 clean 文件在重连或交接硬到期后仍可能重新暂存；后续消息附件工作必须补齐消费及对账，不能将当前 staged 作为消息成功状态。手机公共状态目前仍只报告上传 / 扫描状态。

## 本地验证

- `npm run verify`：201 项 Host / 契约测试通过，包含实际 npm DSH Loader 的内容校验、设备 / 会话隔离、确认关联、重定向、丢失续租、断线清理、原生会话释放后重新暂存，以及共享 Schema / 签名夹具。
- `npm run test:remote-dsh`：完整 Go race、真实 PostgreSQL、TLS HTTP / WSS 与正常 npm DSH CLI 回归通过。新增文件联调使用真实 DSH Loader 组件及正常远控插件，验证 clean → offer → 安装签名读取 → 原生 receipt → staged ack → grant 撤销后 receipt 回收。
- `npm run test:remote-kotlin`：完整 Go / PostgreSQL / DSH 回归与实际 Kotlin TLS Relay 客户端组合通过，手机既有能力保持兼容。
- Go 覆盖一次性 ticket 的并发竞争、无效证明不消费、Host / epoch / 连接隔离、归档 / scanner policy / 上传授权变化，以及响应头和 body 阻塞时的撤权取消。

本机记录：`.local/files-handoff-verify-final.log`、`.local/files-handoff-native-final.log`、`.local/files-handoff-backend-final.log`。身份、模型、S3 协议对端与 clamd 对端仍是本地夹具；没有执行 TokenWorks、学校真实身份、真实 KMS / 病毒签名引擎、文件 APK 或生产部署验收。
