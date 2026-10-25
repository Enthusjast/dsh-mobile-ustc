# Relay 消息附件授权与消费

公网 v1 Relay 现在支持经双方协商的文件 ID 消息。实际本地组合已走通受保护上传 / 扫描、Host 暂存、文件引用、原生 DSH 入队与重复提交。Android 文件 API、选择 / 上传界面、文件消息显示和受限导出尚待实现；学校身份、对象服务和扫描引擎仍使用夹具。

## 协商与消息结构

手机和 Host 必须同时协商 `message.files.v1`；Host 还需 `command.relay.v1`、`file.handoff.v1` 和 `session.catalog.v1`。服务端仅在配置了文件服务和事务附件账本时提供文件消息能力。旧客户端继续使用文本消息，未协商的源端或目标 Host 会得到 `protocol.unsupported`。

消息仍为 `message.submit`，文件 content 项严格为 `{"type":"file","file_id":"<UUID>"}`，允许与文本混合，合计最多 16 项，不允许重复文件 ID。文件项不能带 text、receipt、路径、名称、对象 key 或租约。`queue` / `steer` 和命令 request ID 的语义不变。摘要覆盖有序的原始 content，文件项的 JCS 字段顺序为 file_id / type。

共享协议见 `contracts/ws/v1/relay.schema.json` 和 `contracts/ws/v1/golden/message-file-submit*.json`。Node 和 Go 校验同一摘要。JSON Schema 描述字段结构，当前能力、文件 ID 唯一性和资源授权由运行时额外检查。

## 原子准入

`RecordRealtimeFileCommand` 在原有命令事务中完成所有检查和引用预留，随后才允许 Relay 转发。它先核对手机当前用户、设备密钥、grant、message.submit 和会话范围，再将每个文件与原始上传用户 / 设备 / key / grant 版本、目标 runtime / session、clean 状态、当前 scanner policy、对象期限和当前 Host 的 staged 交接逐项绑定。

数据库 staged 事务可能比 Host 暂存确认帧更早可见。Relay 因此还要求确认帧已进入当前 Host 的发送队列，并在事务结束前再次核对该连接的暂存记录和期限。确认帧必定先于文件消息进入同一个发送队列。失去就绪状态、断线或任一附件失败，命令、整批引用和相应成功审计一起回滚，不出现部分附件入队。

迁移 `011_file_message_refs.up.sql` 保存每个上传意图所属的 device / request 与本次交接 ID，外键指向既有命令和文件账本。命令摘要绑定附件顺序和消息内容，服务端不新增正文或原生 receipt 存储。`file.message_bound` 审计只包含文件、交接、请求 ID 和摘要。文件行按固定顺序加锁，两个并发命令争用一个文件时只有一个能成功；其他事务不会保留一个空命令。

一个上传意图只能用于一个消息意图。重试保留原 request ID 和相同内容，可以重新使用原归属；另一个 request ID 必须新建上传意图。多附件必须全部可用。`file.already_bound` 表示已有其他命令占用，`file.staging_required` 表示当前暂存或确认不可用，`access.denied` 表示当前资源或原始上传授权不匹配。

## 消费与恢复

`received` 状态的原命令仍可在对象和授权有效时重新暂存，并把引用更新到当前连接的新交接。`host_accepted` / `dispatching` 的既有交接可以续租，供当前 Host 完成原生提交；完成或不确定的命令不能取得新交接。候选查询也排除已经离开 received 状态的消息文件，避免已消费文件在重连后反复下载。

服务端已经保存 `agent_queued` 等后续状态的原命令重试只返回持久回执，不要求仍有 clean 对象、活跃交接或原生 receipt，也不再次转发。Host 的 [本地日志和原生恢复](file-message-native.md) 继续处理已接收请求的幂等性。

服务端仍为 received、但原始文件归属已经提交时，如果暂存、对象期限或原始上传授权不再允许新准入，服务端可选择只读对账。它仍须核对当前手机用户 / 设备 / grant、message.submit 与会话范围、原始命令摘要、完整文件 ID 集合和当前 Host 连接。已归档会话只允许核对已有意图，不能新建附件消息。数据库故障不会转换成对账许可；尝试重新暂存过程中失效时，先回滚该次附件更新，再返回只读模式。

该路径另需 Host 协商 `message.files.reconcile.v1`。服务端发送 Host 专用的 `message.files.reconcile` 帧，携带原请求、当前 epoch 和原始 `message.submit` 摘要。该帧只能调用 Runtime 的对账入口，不能调用普通 dispatch 或 prompt。手机不能发送该类型；旧 Host 不具备对账能力时得到 `file.staging_required`，不会降级为新的消息准入。该模式只存在于当前转发尝试中，不写入公共命令状态或授予新的下载 / receipt 权限。

Host 对账先验证本地原命令 owner 和摘要，再读取原生队列 / 会话记录及持久化检查点。原生消息存在时可恢复 `agent_queued`；本地命令不存在或没有原生证据时保留 `outcome_unknown`，不创建新意图、不新增消息。缺少确认不能成为创建新 request ID 自动重放的依据。

先应用 010，再应用 011，然后更新服务端和插件。回滚 011 时先停用文件消息；down 迁移将所有已绑定文件标为 expired，并废止相应交接，然后删除归属表。再次 up 不会使旧上传重新可用。回滚整个文件模块还须按 011 → 010 → 009 顺序执行；已有 DSH 持久附件独立保留。

## 验证范围

- Host / 契约回归共 213 项通过，包含 file ID 形状、路径 / receipt 混入拒绝、只读对账路由和跨语言摘要样例。对账帧的摘要始终对应原始 message.submit。
- 真实 PostgreSQL / Go race 覆盖原子命令与附件预留、整批回滚、同文件多命令竞争、原请求幂等、消费后不再 offer、终态重试、失去连接就绪、授权 / policy / epoch / 到期变化，以及迁移回滚不恢复旧文件。
- TLS HTTP / WSS 验证未暂存、另一手机设备、未协商手机、旧 Host 和确认顺序竞争均被拒绝，失败不留下命令；已授权消息与终态回执可正确路由。
- 正常 Host 插件和真实 npm DSH 0.2.1-rc.2 Loader 收到经 Go 上传 / 扫描 / 交接的字节，实际文件出现在原生用户消息中；重复提交只有一条用户消息，并有一个持久文件归属记录。另一个场景继续验证 grant 撤销后的 receipt 回收。
- 在同一真实 TLS / PostgreSQL / DSH 组合中，故障注入恢复 Host 准入前保存的加密 dispatching 记录、模拟 Relay 回执全部丢失，并使文件到期、移除所有源对象。重试仍从原生证据恢复 agent_queued，prompt 调用总数保持 1；删除本地命令证据时返回 outcome_unknown，用户消息和 prompt 调用数均不增加。
- PostgreSQL 用例验证未绑定意图不能请求对账、清单 / 摘要不可更改、当前连接 / grant 仍需有效，以及多附件回退不保留部分 handoff 更新。WSS 用例验证手机发送 Host 专用帧会被拒绝，旧 Host 不会收到新的准入请求。
- 既有 Kotlin TLS Relay 客户端与正常 npm DSH CLI 组合执行回归。Kotlin 客户端本轮仍只发送文本，没有声称完成 Android 文件链路。

原始文件消息记录为 `.local/file-message-relay-verify-final.log` 和 `.local/file-message-relay-backend-final.log`；新增对账记录为 `.local/file-reconcile-relay-verify-final.log`、`.local/file-reconcile-chain-second.log` 和 `.local/file-reconcile-relay-backend-final.log`。S3 / clamd 协议对端、身份和模型均是本地夹具，未执行 TokenWorks、真实 KMS / 病毒签名库或文件 APK 实机验收。
