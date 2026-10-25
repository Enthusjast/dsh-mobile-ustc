# Host 消息附件转换与恢复

Host Runtime 现在可以将已确认交接的文件 ID 转为同一原生会话的临时 receipt，并随 `queue` / `steer` prompt 提交。当前只完成 Host 内部转换与本地 v0 命令结构；公网 v1 Relay 仍拒绝文件消息。服务端附件授权 / 消费账本和 Android 文件消息尚待实现，插件没有提前提供 `message.files.v1` 能力。

## ID 与原生准入

消息 content 中的文件项严格为 `{"type":"file","file_id":"<UUID>"}`，最多与文本合计 16 项，同一消息不允许重复文件 ID。原生 receipt、对象 key、工作区路径和客户端提供的文件信息均不能混入命令。结构见 `contracts/m0/command.schema.json`；公网 text-only v1 契约保持原有边界。

Runtime 在实际 dispatch 时根据当前上传者 user / device、目标会话、连接租约、暂存确认和原生 receipt 状态解析全部文件项。任何一项不可用时整条消息在调用原生 prompt 前被拒绝；没有部分文件入队。失败记为确定的 `file.staging_required`，重试同一命令返回同一结果。确认尚未到达、连接失效或会话释放后都不能绕过检查。

提交给 DSH 的请求 ID 继续按设备分区，命令摘要覆盖原始文件 ID 内容。原生 prompt 尝试结束后退休对应 receipt；文件字节由原生附件存储保留。Relay 文件 peer 检测到 receipt 被消费后释放交接，不继续为已消费映射续租。命令日志的附件项仅接收文件 ID，临时 receipt 不写入 SQLite 或对外结果。

## 崩溃与幂等恢复

本地日志已经 `agent_queued` 的重试直接返回保存结果，不重新解析已经退休的 receipt。同一个 request ID 改为另一个文件 ID 会因摘要冲突而拒绝。

处于 `dispatching` 的消息在崩溃后可能已经进入原生持久日志，也可能尚未入队。原生 DSH 0.2.1-rc.2 在解析附件 receipt 前检查已知 request ID。恢复缺少 receipt 时，Runtime 提交一个没有对应授权记录的占位 receipt：原生系统只能凭原请求的已有记录返回幂等结果；没有原生记录时，附件准入拒绝占位值，命令保留 `outcome_unknown`，不能据此自动重放。

该行为已经用实际 npm DSH Loader 和重新打开的加密 SQLite 日志验证：原生已持久接收的文件消息恢复后仍只有一条用户消息；缺少原生证据的恢复不会产生用户消息。原生接口若变更去重顺序，必须重新验证这一行为后升级。

## 验证与下一步

`host/remote-control/tests/file-messages.test.ts` 覆盖设备 / 用户 / 会话隔离、未确认与取消映射、多个附件中的缺项、receipt 退休、已确认重试、内容冲突，以及有 / 无原生证据的持久恢复。`npm run verify` 的 206 项测试全部通过，包含现有 Host 文件交接、DSH CLI、协议和审批回归；本机记录为 `.local/file-message-native-verify-final.log`。

下一步需要在服务端将文件与原始命令绑定，校验 clean 状态、扫描策略、当前设备与授权版本、会话、当前 Host staged 交接及消费归属，并在公共协议中协商能力。完成后才能开放手机文件项和 Android 上传 / 发送界面。
