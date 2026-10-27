# 文件扫描与交接指标

生产入口启用 `REMOTE_METRICS_LISTEN_ADDR` 时，文件 worker 和仓库绑定同一私有 registry。
停用指标时业务行为保持一致；采集器不查询数据库、不拉取对象或访问 Host。
共同前缀为 `dsh_remote_`，标签仅使用固定词表，不含用户、设备、runtime、session、
file、handoff、attempt ID，文件名、大小、摘要、正文、对象 key、扫描策略摘要或下载凭据。

## 扫描尝试

`file_scan_attempt_duration_seconds{direction,result}` 从 worker 成功领取 claim 之后开始，
用进程单调时钟计量对象读取、长度/摘要校验、扫描、候选对象写入及完成/失败记录处理。
不包含上传、等待领取、重试退避或其他任务的排队时间。没有 claim、scanner readiness 拒绝
以及定期健康探测都不增加扫描样本；探测用 EICAR 不会被误计为用户文件拒绝。

`direction` 为 to_host / from_host / other；`result` 为 clean、access_denied、stale、
rejected、integrity、scanner_unavailable、invalid、cancelled、timeout、unavailable 或 other。
clean 只有在验证/扫描/对象写入和 `CompleteScan` 返回成功后产生，单纯 scanner 返回干净
不会计为 clean。失败时优先保留扫描上下文的撤权、租约到期或超时原因，否则使用返回错误的
固定分类；不解析扫描器、数据库和对象存储的异常文本。

这是领取后的尝试分布。失败类别不证明对应 `FailScan` 已提交，断电前尚未返回的尝试也可能缺失；
不能把样本直接当作持久文件终态数。成功 copy 后数据库提交失败仍记为 unavailable，
并继续沿既有失败记录/清理路径处理，不会凭指标把候选对象发布为 clean。

## 交接里程碑与耗时

| 指标 | 含义 |
| --- | --- |
| `file_handoff_events_total{stage}` | 已确认 commit 的 offered、read_started、staged 次数 |
| `file_handoff_age_seconds{stage}` | 从该 handoff 的数据库 created_at 到首次 read_started 或 staged 更新的数据库时间差 |
| `file_handoff_read_to_stage_seconds` | 从该 handoff 的 read_started_at 到首次 staged 更新的数据库时间差 |
| `file_handoff_operation_duration_seconds{operation,result}` | offer / read / stage / renew / end 仓库尝试的单调耗时，包括验证、锁、审计和 commit |
| `file_clock_anomalies_total{stage}` | 因数据库时间差为负而丢弃的区间数；同一次 staged 可以有两个异常区间 |

offered 表示新建交接及其单次读取凭据已提交，不保证 offer 已发到 Host。
read_started 表示当前 Host 证明校验通过、单次 ticket 已消费且读取审计提交，不保证对象已经打开
或完整字节已送达。staged 表示服务端确认提交了当前 Host 对精确文件大小/摘要的暂存回报；
不是独立观察到 Host 磁盘，也不是 DSH 会话 receipt、Agent 入队或执行完成。
原生文件引用的准入和消费仍见[文件消息协议](file-message-relay.md)。

有效 offer 已存在时的成功空返回、重复 staged 回报和续期只增加操作耗时样本，不重复计里程碑。
ticket 并发竞争只有已提交的胜者增加 read_started。审计、outbox 或延迟 commit 失败不产生
里程碑/成功区间。过期后新建 handoff 使用新身份，属于新一次交接；这些不是唯一文件数。
end、过期清理、恢复隔离等失效路径未纳入里程碑，不能由三个计数推导当前活跃积压。

operation 的 result 为 ok、access_denied、stale、conflict、quota、invalid、cancelled、timeout、
unavailable 或 other。ok 包括成功空返回与相同结果重试，不能替代里程碑计数。
调用方上下文取消/到期的失败优先记为 cancelled/timeout；内部数据库准入错误也可能是 unavailable。

交接区间两端均使用数据库时钟，避免把服务节点时钟差混入时延；它们截止于状态更新，
在整个外层事务确认 commit 后才观察，因此不包含该更新之后的审计与 commit 等待。
负区间保留已提交的事件计数、跳过相应 histogram 并增加 clock_anomalies；
有效的其他区间仍可采样。仓库尝试耗时使用独立的进程单调时钟，不能与两个 percentile 相加。

```promql
sum by (direction, result) (rate(dsh_remote_file_scan_attempt_duration_seconds_count[5m]))
histogram_quantile(0.95, sum by (le, direction) (rate(dsh_remote_file_scan_attempt_duration_seconds_bucket{result="clean"}[5m])))
histogram_quantile(0.95, sum by (le) (rate(dsh_remote_file_handoff_read_to_stage_seconds_bucket[5m])))
sum by (operation, result) (rate(dsh_remote_file_handoff_operation_duration_seconds_count[5m]))
```

这些观察不属于路由 SLO，包含扫描/存储或 Host 下载与暂存等待。指标是进程本地尽力采样，
关闭采集、重启、commit 确认丢失或提交后崩溃可能导致缺失，不能代替 audit 和元数据对账。

## 本地证据与边界

组件 race 测试覆盖实际 TLS S3 字节流的 clean/from_host、拒绝、摘要错误、撤权、租约到期、
扫描超时、退出取消及完成记录失败；空轮询和探测不产生任务样本。
私有 PostgreSQL 用例覆盖并发 offer/read/stage、相同结果重试、offer/read/stage 的延迟 commit
失败回滚，以及数据库负时间差。成功里程碑与持久 read/staged 审计一致。

独立生产文件服务进程启动两个 worker，实际处理一个 clean 和一个 rejected 文件，
从私有 HTTP 指标端点核对各一个样本并检查元数据/正文/凭据未泄露；SIGTERM 后 listener 关闭。
普通 npm DSH 0.2.1-rc.2 的五种文件交接场景（撤权、消息、两种历史对账、跨节点消息）
继续校验实际上传、暂存、消息引用消费和幂等重试，并将里程碑与数据库行及审计核对。

对象存储、scanner、身份及模型均为本地协议夹具。没有运行大负载、真机或厂商推送配置测试；
没有新增数据库迁移、公共协议或 Android 行为。上传耗时、手机最终保存、导出下载全程和
完整文件生命周期的终态/积压监控仍需独立补齐。
