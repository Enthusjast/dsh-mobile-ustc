# Host 本地日志事务观测

启用私有指标的 Relay 与 Host 同时协商 `host.observations.v1` 和
`host.journal.observations.v1` 后，现有 `host.observations` 累计窗口增加两个固定 operation：

| operation | 范围 | result |
| --- | --- | --- |
| journal_command | 持久命令日志实际进入的 SQLite 事务 | persisted / failed |
| journal_approval | 同库审批日志实际进入的 SQLite 事务 | persisted / failed |

从尝试 `BEGIN IMMEDIATE` 前计时，成功样本在 `COMMIT` 返回后结束；失败样本在原有回滚尝试后结束。
因此包含锁等待、事务内校验／加解密／SQL 和提交同步的时间，但不是单独的 fsync 延迟。
事务外的摘要、校验、加密、原生执行、网络授权等待不在这个计时范围内。

`persisted` 表示这次事务提交成功，其中也可能只有读取或幂等查重；不能把次数当作命令数、
写入行数或审批批准数。`failed` 包含 BEGIN、事务体、COMMIT 的失败，也包含内容冲突、
审批过期等业务拒绝；不能单凭它认定磁盘损坏。审批日志的关闭／中毒预检查、
命令状态转换的事务外预检查及提前返回，不生成事务样本。

启动建库、迁移、密钥获取／校验和关闭时的 `wal_checkpoint(TRUNCATE)` 没有这个计时。
命令重启恢复与审批 boot 初始化复用事务封装，但正常插件在握手前执行，不缓存离线样本。
原生 `sessions.flush` 的 checkpoint 仍是[原生操作观测](host-native-observations.md)中的独立样本。

## 兼容、隐私和发送边界

旧 Relay 只接受 `host.observations.v1` 时，Host 保留原有原生操作观测，日志操作不会读取计时时钟或
积累样本；未协商基础能力时完全不发送观察帧。新 Relay 接受旧 Host。手机无法协商任一 Host 观测能力；
缺少日志扩展能力的 Host 发送日志 cell 时整份报告被忽略，普通连接仍可继续。

两个日志 operation 只允许 `persisted` / `failed`，所有窗口最多 19 个固定 operation/result 组合。
原有 5 秒累计发送、16 KiB 编码上限、背压跳过、单调差值、连接代次校验和丢弃边界继续适用。
没有增加逐次事件、重发队列或数据库存储。连接结束时尚未发送的样本可以丢失，
跨越连接替换完成的 span 不会计入新连接。观察器异常不会改变事务返回值或原有错误处理。

样本只含 operation/result、计数、整数微秒和直方图桶，不传递命令、路径、用户、审批 ID、
正文、SQL 或错误文本。指标仍使用现有固定前缀，不新增动态标签：

```promql
sum by (operation, result) (rate(dsh_remote_host_native_operations_total{operation=~"journal_command|journal_approval"}[5m]))
histogram_quantile(0.95, sum by (le, operation, result) (rate(dsh_remote_host_native_operation_duration_seconds_bucket{operation=~"journal_command|journal_approval"}[5m])))
```

这些是当前已认证 Host 的自报运行观察，不能授权调用或替代 journal、审批证明及服务端账本。
命令回执仍由原有持久化路径决定，指标未发出也不触发重放。

## 本地验证

- TypeScript 用真实 SQLite 检查提交、内容冲突回滚、另一连接的写锁导致 BEGIN 失败、
  幂等提前返回及观察器抛错；确定性时钟核对微秒和每个事务只结束一次。
- 现有私有子进程 WAL ENOSPC / sync EIO 夹具核对命令和审批事务失败均被记录，
  持久回执、恢复去重及单次审批消费仍符合原有语义。直接 WAL checkpoint 失败不误记为事务失败。
- TypeScript / JSON Schema / Go 共用 `host-observations-journal` golden，核对新组合、
  累计差值、重复报告及秒单位直方图。实际 WSS 检查单独协商、旧 Host 的新 cell 拒绝和手机伪造。
- 本机 npm dsh 0.2.1-rc.2 与双节点 Go／私有 PostgreSQL 组合核对真实命令和审批日志的成功样本
  到达 owner 私有指标。身份和模型继续使用本地夹具。

验证日志：`.local/journal-observations-host-verify.log`、`.local/journal-observations-go-focused.log`、
`.local/journal-observations-native.log`。不包含大负载、物理手机、厂商推送或生产磁盘验收。
