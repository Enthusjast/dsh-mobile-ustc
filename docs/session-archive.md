# 会话归档

基线：npm DSH `0.2.1-rc.2`，使用当前进程的 Workspace Registry。未使用 TokenWorks。归档保留原生会话日志和工作区中的位置，移除置顶；恢复使用同一原生会话 ID。

## 命令与状态

Host 本地协议接受 `session.archive`，payload 必须包含 `archived` 和 `stop_activity` 两个布尔值。归档时默认选择 `stop_activity: false`：原生活动提供者报告任意活动，则拒绝为 `session.active`，不改变归档状态。恢复必须为 `{ archived: false, stop_activity: false }`。

明确选择 `stop_activity: true` 时，DSH 先持久归档，再通知原生活动所有者停止。调用不等待执行结束；停止提供者的失败不会撤销归档。已归档会话的重复原生归档是空操作，不会再次请求停止。

`settled` 仅表示此次归档或恢复已越过 Workspace Domain 的持久化屏障，不表示任务已停止、工具已结束、Agent 已释放或订阅已取消。Session 日志的 `flush` 与此屏障分别处理。

命令摘要绑定原始 runtime epoch、session、完整 payload。所有归档、恢复和其他命令共用持久 request ID 命名空间。已持久完成的重试返回原始结果；若此前已进入 dispatching 而结果未保存，重试保持 `outcome_unknown`，不重放、不依据当前归档状态推断原命令成功。桌面可能在其后执行相反操作。

## 目录、读写和执行

Host 目录将原生归档集合投影为 `archived`；监听 Workspace Domain 的持久变化，桌面归档或恢复也会发布目录增量。会话仍能解析以读取历史或恢复。远程消息和模型选择拒绝归档目标。

Session Controller 安装的原生 `ArchivedSessionGate` 还会拒绝归档会话及其 subagent 后代的下一次模型步骤；fork 的执行不受父会话归档影响。该门控不终止已经执行的外部副作用。

## 验证记录

`npm run verify` 通过契约生成检查、TypeScript 检查、插件构建及 179 项 Host 测试。其中 `host/remote-control/tests/archive.test.ts` 使用真实 Cordis Loader、JSONL 会话存储、JSON Domain、Workspace Registry、Agent Loop 和 Session Controller，覆盖：

- 归档移除置顶、保留工作区位置和完整日志；重建 Loader 后恢复并继续同一会话。
- 活动 turn 的普通归档拒绝且无写入；显式归档并停止在 durable archive 之后通知，丢弃原生排队消息并正常结束 turn。
- 归档后的迟到消息不产生模型回复；恢复后能继续。
- subagent 后代门控和独立 fork；此夹具未装配完整 subagent、schedule、job 所有者。
- 桌面归档 / 恢复目录通知、归档历史读取和写入拒绝。
- 持久命令阶段、活动拒绝、已完成重试、epoch 冲突及 dispatching 后未知结果。

模型使用确定性本地夹具。此阶段尚未接入移动中继命令和 Android UI；未验证真实学校身份、完整发行组合、物理设备、进程强杀或断电。
