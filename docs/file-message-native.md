# Host 消息附件转换与恢复

Host Runtime 现在可以将已确认交接的文件 ID 转为同一原生会话的临时 receipt，并随 `queue` / `steer` prompt 提交。服务端已接入 [附件授权 / 消费账本与 v1 Relay](file-message-relay.md)，双方协商 `message.files.v1` 后可使用。[Android 文件上传和消息界面](android-files.md) 已接入。

## ID 与原生准入

消息 content 中的文件项严格为 `{"type":"file","file_id":"<UUID>"}`，最多与文本合计 16 项，同一消息不允许重复文件 ID。原生 receipt、对象 key、工作区路径和客户端提供的文件信息均不能混入命令。本地结构见 `contracts/m0/command.schema.json`，公共 v1 结构及协商规则见 [Relay 文件消息](file-message-relay.md)。

Runtime 在实际 dispatch 时根据当前上传者 user / device、目标会话、连接租约、暂存确认和原生 receipt 状态解析全部文件项。任何一项不可用时整条消息在调用原生 prompt 前被拒绝；没有部分文件入队。失败记为确定的 `file.staging_required`，重试同一命令返回同一结果。确认尚未到达、连接失效或会话释放后都不能绕过检查。

提交给 DSH 的请求 ID 继续按设备分区，命令摘要覆盖原始文件 ID 内容。原生 prompt 尝试结束后退休对应 receipt；文件字节由原生附件存储保留。Relay 文件 peer 检测到 receipt 被消费后释放交接，不继续为已消费映射续租。命令日志的附件项仅接收文件 ID，临时 receipt 不写入 SQLite 或对外结果。

## 崩溃与幂等恢复

本地日志已经 `agent_queued` 的重试直接返回保存结果，不重新解析已经退休的 receipt。同一个 request ID 改为另一个文件 ID 会因摘要冲突而拒绝。

处于 `dispatching` 的消息在崩溃后可能已经进入原生持久日志，也可能尚未入队。恢复缺少 receipt 时，Runtime 直接核对 DSH 0.2.1-rc.2 原生 inbox 与会话事件中的设备分区 request ID，并等待已有状态的持久化检查点，不调用 prompt，也不提交占位 receipt。没有原生记录时，命令保留 `outcome_unknown`，不能据此自动重放。

Host 另提供 `reconcileFileMessage`：它先只读查询原命令日志并验证 owner 和完整摘要，未知命令不会新增日志；即使当前仍有有效 receipt，对账也不能把一个尚未入队的意图变成新消息。同一请求仍在执行入队时，对账等待该次操作并重报其结果。该方法已接入 [Host 专用 Relay 对账帧](file-message-relay.md)，可以处理原生已入队但中转对象到期、回执丢失的情况。

实际 npm DSH Loader 和重新打开的加密 SQLite 日志已验证这些行为：全新 DSH 上下文可恢复原持久消息；仍在原生 inbox 中的请求可以确认已有准入，队列长度不增加；缺少原生证据的恢复不会产生用户消息。恢复普通原生会话仍使用 Session Controller 的既有生命周期。升级 DSH 时必须重新验证原生 request source、队列和持久化契约。

## 验证与下一步

`host/remote-control/tests/file-messages.test.ts` 覆盖设备 / 用户 / 会话隔离、未确认与取消映射、多个附件中的缺项、receipt 退休、已确认重试、内容冲突、有 / 无原生证据的持久恢复、未知意图、有效 receipt 下禁止新准入、并发对账、原生队列和重新加载 DSH。接入 Relay 对账后，`npm run verify` 的 213 项测试全部通过，包含现有 Host 文件交接、DSH CLI、协议和审批回归；本机记录为 `.local/file-reconcile-relay-verify-final.log`。

服务端归属绑定、逐文件授权、能力协商和对象到期后的只读结果恢复已接入，验证记录见 [Relay 文件消息](file-message-relay.md)。文件历史现以合法显示名和字节数生成受限文字摘要；仅有附件的消息也可阅读。下一步继续受限导出和 APK 文件后端联合验收。
