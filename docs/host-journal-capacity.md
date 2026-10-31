# Host 日志主库容量与 SQLite FULL

Host 命令日志和审批日志共享同一条已验证密钥的 SQLite WAL/FULL 连接。插件设置
`commandJournalMaxBytes` 为该连接的主数据库增加页数预算，默认 1 GiB；允许 1 MiB–8 GiB，
必须为整 MiB。直接使用 `PersistentCommandJournal.open` 时，对应参数为
`{ maxDatabaseBytes: ... }`。非法数值在创建目录、密钥或数据库之前拒绝。

```yaml
commandJournalMaxBytes: 1073741824
```

每次打开和重开都根据数据库实际 page_size 设置并回读 `PRAGMA max_page_count`。命令与
审批共用页预算，原有十万条命令/审批、4096 条待处理命令、64 项活跃审批及单条编码限制
继续独立执行。已有页数大于新预算时拒绝打开，不缩小、覆盖或重建数据库，不淘汰未知结果、
签名证据、nonce/execution tombstone 或原 request ID 的去重记录。需要增加容量时由
运维明确调整配置并重开，保留原数据库及密钥。

该配置限制 SQLite 逻辑主库页数；WAL、SHM、密钥封装文件、文件系统元数据和 DSH 原生日志
有各自的生命周期。长事务/外部 reader 可延迟 WAL checkpoint，因此不能把此数值解释为
目录或整块磁盘的硬配额。生产仍须单独配置磁盘空间、权限、保留/归档与监控。

## 容量故障语义

接收命令必须先提交 host_accepted，进入原生操作前必须先提交 dispatching。对应写入失败
时不执行原生操作，也不发送尚未持久的阶段回执。原生消息已经入队/flush，但本地结果
写入失败时，不发送 agent_queued 成功回执；尽可能保存 outcome_unknown。若连未知标记
也写不下，原 dispatching 记录保留，不能把存储错误显示成已确认未执行。

恢复空间后，明确的未知结果仍待对账，不自动重放。仍为 dispatching 的消息通过原 device/
request ID 进入既有 DSH 去重恢复；重开与显式重试不产生第二条用户消息。其他不具备原生
去重证明的模糊变更继续按原规则拒绝重放。

审批存储失败会毒化当前审批 owner 并取消在途操作。pending、approved 和 consumed 的
事务失败均不返回新的 guard 许可；已消费执行的 settled 写入失败不能改称未执行。重开
使用新 boot，原未消费请求进入 invalidated，已消费但未持久终结的请求进入 outcome_unknown，
不恢复旧执行回调、旧 nonce 或许可。

## 验证

小型真实 SQLite 测试将主库限制到 1 MiB，写入有限加密记录直到 pager 返回原生错误码
13（SQLITE_FULL），验证失败命令没有落库、原记录仍可解密、重开重复应用预算、增容可恢复，
缩容失败不修改旧文件。命令和审批 handle 指向同一连接和预算。

故障夹具只在自有测试数据库建立临时触发器，要求写入超过预算的 zeroblob，触发真实
SQLite 分配失败/自动回滚；不是 monkeypatch journal 方法或伪造抛错。实际 DSH Loader
组合覆盖接收、dispatching、结果和未知标记写入失败，核对阶段回执、原生日志及重开后的
同 ID 去重。审批另覆盖 register、decision、consume、settle 四个故障点，无效许可不执行，
已消费的执行不重放。

插件配置组合还通过本机 IPC 验证：1 MiB 限额拒绝一次日志接收时不会创建原生会话，恢复
写入后原 request ID 可完成创建，重复请求返回同一结果，不再创建第二个会话。

完整 Host/契约/类型/构建检查及本机 npm DSH `0.2.1-rc.2` 双节点正常链路分别回归。

独立的 [WAL/VFS 错误夹具](host-journal-io-faults.md)另验证自有 Linux 子进程中的 ENOSPC
与同步 EIO，以及失败回执、guard 和原 ID 恢复边界。

这些是主库容量耗尽证据，不替代操作系统 ENOSPC、WAL/fsync/EIO、断电或目标平台文件系统
验收。本轮不修改 Android APP，不尝试其他运行时，不执行大负载、真机或厂商推送配置。
