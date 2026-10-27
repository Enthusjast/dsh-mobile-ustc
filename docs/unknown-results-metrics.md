# 当前未知结果积压快照

`dsh_remote_unknown_results{kind="command|approval"}` 记录数据库最近一次成功快照中，
commands / approvals 的当前 state 为 outcome_unknown 的行数。它来自单条只读 SQL 的共同
MVCC 快照，不从进程内状态转换计数相减。合法历史结果使状态离开 unknown 后，下次成功
快照会减少；同一行反复重传不会增加积压。

统计包含数据库仍保留的历史、旧 epoch、恢复隔离以及旧审批 metadata_version=0 的未知行，
即使没有当前在线 Host 或有效手机 grant。它不是“当前可以重新执行”的集合，采样不创建权限、
不恢复回调、不发送命令，也不代替逐项对账。历史保留/删除策略会影响这个行数。
这是全库快照；不按组织、用户、设备或资源拆分，不输出任何 ID、digest、正文、凭据或错误文本。

## 可用性与新鲜度

| 指标 | 含义 |
| --- | --- |
| `unknown_results{kind}` | 上一次成功快照的数量；首次成功前缺席，不伪造零值 |
| `unknown_snapshot_available` | 最近一次完成的采样是否成功；启动/失败为 0，成功为 1 |
| `unknown_snapshot_last_success_timestamp_seconds` | 成功采样完成时的服务进程墙钟；首次成功前为 0 |
| `unknown_snapshot_age_seconds` | 缓存快照的单调时钟年龄；首次成功前缺席 |
| `unknown_snapshot_duration_seconds{result}` | 每次后台采样的单调耗时；result 为 ok / error / timeout / cancelled / invalid |

共同前缀为 `dsh_remote_`。查询失败、超时或返回无效负计数时，保留上次成功的数量与时间，
available 变为 0；不能把失败显示成“积压已清零”。成功读取空库会发布真实零值并恢复 available。
两类计数、可用性和时间从同一份本地快照采集，不在一次 scrape 中混用两轮数据。

available 只说明最近一次完成的尝试，不能独立证明数据仍然新鲜；采样阻塞、worker 停止或
服务卡顿时应结合 age。last_success 受服务墙钟调整影响；本地 age 用单调时钟计算。

## 运行边界

只有启用既有私有指标时，生产入口才进行后台采样。每轮查询期限为一秒，完成后等待十秒再
尝试，每进程最多一个进行中的读取；SIGTERM/控制任务取消会取消它并等待结束。
HTTP scrape 只读取本地缓存，不访问数据库；指标关闭时不查询。
采样不可用不改变业务 readiness、授权或命令状态，也不打印数据库错误原文。

计数查询仍需要数据库工作量，与业务连接共享既有连接池；一秒期限限制等待和查询时间，
不证明大表/高峰成本已经验收。目标负载、查询计划、保留规模与集群采样预算仍需另行测量。
Prometheus 数值为浮点计数，不能作为持久精确账本。

同一数据库的多个 Relay 会分别发布同一全库数量。**不能相加不同节点的该 gauge**，
应按部署/数据库作用域选择新鲜且 available 的实例后取 max 或选择一个采样来源。
部署/数据库作用域由采集系统的外部标签区分；应用不把数据库地址/名称写入指标。

例如，以下查询先筛选最近成功且年龄小于 30 秒的实例，再按 Prometheus 配置的 cluster 标签
聚合；30 秒仅为示例新鲜度窗口，不是生产告警承诺。不可用/过旧时应保留“无可靠数据”状态。

```promql
max by (cluster, kind) (
  dsh_remote_unknown_results
  and on (cluster, job, instance) (dsh_remote_unknown_snapshot_available == 1)
  and on (cluster, job, instance) (dsh_remote_unknown_snapshot_age_seconds < 30)
)
```

这与[命令状态进入次数](command-observability.md)、[审批状态转换](approval-observability.md)
互补。前者会因进程重启丢失且只会增加；当前数据库快照能下降，但有采样延迟和保留策略边界。

## 本地验证

私有 PostgreSQL/race 用例建立两个未知命令、一个真实已消费后未知的审批，以及一个保留的旧版
未知审批，验证回滚不改变计数，真实 Host settled 和命令终态使积压下降，旧版行删除后归零。
持有表锁阻塞查询时，50 ms 调用方期限能取消读取并返回不可用；不把该故障当作空库。
组件用例验证首次无数据、失败/负值保留旧快照、成功零值恢复、关闭指标无查询、scrape 无源 I/O
以及退出取消在途查询。独立生产服务从私有端点读取到成功快照，SIGTERM 后 worker/listener 结束。

全部使用小型本地夹具，没有运行大负载、真机或厂商推送配置测试；没有引入数据库迁移或公共接口。
