# 命令状态与存储指标

生产入口启用既有私有指标监听器时，也会在 PostgreSQL 命令仓库登记观察器。
所有标签使用固定动作、状态、来源或结果词表；不保存 request ID 去重缓存，
不暴露用户、设备、runtime、会话、正文、digest、文件路径或证明。
公开协议及持久命令状态机不变。

## 指标口径

下表省略共同前缀 `dsh_remote_`。

| 指标 | 含义 |
| --- | --- |
| `command_transitions_total{action,from,to,origin}` | 本进程确认提交的新命令或状态转换次数；新登记为 `none → received` |
| `command_state_entry_age_seconds{action,state}` | 每次已提交状态转换的 `updated_at - created_at`；初始 `received` 不产生年龄样本 |
| `command_state_dwell_seconds{action,from,to}` | 每次转换的当前 `updated_at - 上一状态 updated_at` |
| `command_store_duration_seconds{operation,result}` | 单次仓库调用的单调时钟耗时，包含校验、授权、数据库锁等待、事务提交和观察调用；包括重试及未改变状态的成功调用 |
| `command_timestamp_anomalies_total{interval}` | 缺失或倒退的数据库时间戳，按 age / dwell 计数；异常区间不进入时延分布 |

`action` 对应数据库动作：`message.submit`、`session.create`、`session.cancel`、
`session.archive`、`question.answer`。普通与 timed question 的持久动作都归为
`question.answer`。旧记录的空动作和未知值归为 `other`。

`origin` 为 `device`（首次登记）、`host`（Host 回执）、`relay`（转发写出结果不确定）。
`operation` 为 admit / create / file_admit / receipt / unknown。
结果为 ok / denied / conflict / invalid / not_ready / limited / cancelled / error；
`not_ready` 表示文件尚未具备准入条件，不作为数据库故障。所有未知值统一归为 `other`。

## 转换计数与回执边界

只有数据库提交确认成功后才记录转换。相同 request ID 的重复提交、相同状态的重复回执、
多手机回执扇出和状态查询都不产生新的转换。并发调用由原命令行锁和唯一约束确定唯一写入者，
观察器只统计真正插入或改变状态的那个事务。文件引用准入失败、审计失败和延迟到 commit
才触发的失败都不会产生转换计数；仓库尝试耗时仍会记录失败结果。

Host 未上报的阶段不会被指标补齐。`received` 仍只表示服务端登记；
`host_accepted` 和 `agent_queued` 的原有持久语义由 Host 负责。指标既不授予权限，
也不把网络写出成功解释成原生入队或执行完成。

未知结果出现次数可以从 `to="outcome_unknown"` 的转换获取。它是进入未知状态的次数，
不是唯一命令数，也不是数据库当前未知积压。一条命令经过有效对账离开未知状态后，
再次出现未知结果会产生新的转换。维护 CLI 的恢复批量隔离不走网络命令仓库观察路径，
其未知命令数量在[恢复记录](database-recovery.md)中，不能用这里的 counter 代替。

```promql
sum by (action, from, to) (rate(dsh_remote_command_transitions_total[5m]))
sum by (origin) (increase(dsh_remote_command_transitions_total{to="outcome_unknown"}[1h]))
histogram_quantile(0.95, sum by (le, action, state) (rate(dsh_remote_command_state_entry_age_seconds_bucket[5m])))
histogram_quantile(0.95, sum by (le, operation, result) (rate(dsh_remote_command_store_duration_seconds_bucket[5m])))
```

## 时间与多节点边界

年龄与停留时间都使用同一数据库保存的时间戳相减，不使用客户端上报时间，也不把服务进程
墙钟与数据库墙钟相减。`created_at` 以及初始 `updated_at` 沿用现有登记事务的 `now()`；
后续状态更新使用 `clock_timestamp()`。因此年龄起点是数据库命令创建时间，不是手机点击
时间、Host 本地 journal flush 时间或事务 commit 确认时刻。

这些区间可能包含主机、网络、原生入队、模型或人工等待；不能用它们替代路由 SLO。
它们也不是“第一次进入某状态”的唯一样本：合法地离开未知结果再进入一个阶段时，会再次采样。
没有经过的状态不会产生时延值。倒退时间计入异常 counter，而不会被截成零延迟。

跨节点路径只在执行命令数据库事务的 owner 节点记录转换。入口隧道不重复统计。
每个 registry 的 counter 随进程重启清零，Prometheus 应按实例采集后使用 rate/increase。
数据库 commit 已发生但确认丢失、进程在提交和采样间退出或未启用指标时可能漏掉样本；
观察结果不具备持久、恰好一次交付保证。持久状态及 audit 才是命令对账依据。
采集器仍只读取本地指标，不在 scrape 时查询数据库。

## 本地验证

2026-10-27 的小型私有 PostgreSQL/race 测试验证：

- 8 次并发提交只登记一个创建转换，4 次并发相同回执只登记一个状态转换；状态查询不增计数。
- 在 commit 时故意触发延迟审计失败，状态回滚且没有成功转换；失败尝试保留耗时。
- 五类动作的未知结果及后续 Host 对账保持真实转换边，不虚构缺失阶段。
- 文件未就绪时整个准入回滚；准备完成后的显式重试只计一次，旧空动作归为 other。
- 数据库时间倒退不会生成虚假的低时延；未知输入不能生成动态标签或进入指标正文。

真实 npm DSH 双节点组合还将各动作创建计数与 PostgreSQL 命令行数核对，将 Host 转换总数与
持久 receipt 审计数核对，并检查正常 `host_accepted → dispatching → agent_queued` 的停留样本。
身份和模型是本地夹具。当前没有进行容量、真机或厂商通道测试；原生 checkpoint 失败、
完整原生阶段分解及数据库未知积压等剩余指标仍需继续开发。

记录为 `.local/command-metrics-store-first.log`（真实 PostgreSQL 竞态、回滚、未知结果和文件用例）、
`.local/command-metrics-component.log`（组件 race）和 `.local/command-metrics-full-second.log`
（完整 Go race/私有 PostgreSQL 与实际 npm DSH 0.2.1-rc.2 组合，原生部分约 11.823 秒）。
首次完整运行的 Go 回归通过，但原生断言错误地期待跳过 dispatching；修正断言后完整组合通过，
失败记录仍保留在 `.local/command-metrics-full-first.log`。TypeScript check 与 `go vet ./...` 均通过。

后续[Host 原生观测](host-native-observations.md)另有实际方法和 checkpoint 失败的可选自报链路。
不要从命令缺失某阶段推断原生失败，也不要将 Host 自报转换为已提交命令计数或新的持久确认。

后续[当前数据库未知积压](unknown-results-metrics.md)通过有期限后台快照提供可下降的数量，
包含保留的历史/恢复未知行。失败保留旧值并报告新鲜度；它不从转换计数相减，不代替逐项对账。

`session.model.select` 是[模型选择命令](session-model-selection.md)的固定动作标签。
其 `settled` 在原生会话检查点完成后产生；provider、model 和 reasoning 标识不进入指标标签。

共享[命令准入预算](shared-command-limits.md)耗尽时，command store 尝试结果为固定 `limited`。
它包含共享配额检查的耗时，不产生 command 状态转换；主体 UUID 和策略摘要不作为指标标签。
