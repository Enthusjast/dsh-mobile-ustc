# Go 服务运行指标

服务使用独立的 Prometheus registry，按[命名与标签约定](https://prometheus.io/docs/practices/naming/)输出 `dsh_remote_` 指标。实现锁定 `client_golang v1.25.0`；没有使用全局默认 registry。指标包含运行统计，不包含用户、组织、设备、主机、runtime、会话、request ID、正文、路径、凭据或签名证明。

## 开启与生命周期

默认不创建指标监听器。按服务 README 配好既有身份、数据库等环境后，在 `services/remote` 中显式设置：

```sh
REMOTE_METRICS_LISTEN_ADDR=127.0.0.1:9090 go run ./cmd/remote
```

通过同机 `GET /metrics` 采集。地址必须是回环 IP 字面量和有效端口；拒绝 wildcard、公网地址、hostname、URL 与缺少端口的输入。测试可以使用端口 0，实际部署选择固定端口。业务监听器上 `/metrics` 仍为 404，指标监听器不提供业务、健康检查或调试路由。响应为 `no-store`，最多并发两条采集请求，处理超时两秒；单独限制请求头、读写和空闲时间。并发请求共享同一次采集，避免超时后重复堆积底层 gather；使用锁定库版本的 CoalesceGather 选项，并有阻塞 collector 的实际并发 HTTP 测试。

配置了指标但无法绑定时，服务启动失败。运行期间指标监听器意外退出，会停止业务接入并清理升级后的 WSS 连接；正常 SIGTERM 同时关闭业务、控制 worker 和指标监听器。HTTP scrape 只读取本地计数和快照，不查询数据库或身份服务；当前未知积压由单独的有期限后台查询更新。

## 已有指标及精确含义

下表省略共同前缀 `dsh_remote_`。

| 指标 | 含义 |
| --- | --- |
| `relay_connections{role,phase}` | 当前已升级 socket 数；phase 为 handshaking / active / closing，尚未完成密钥证明的 socket 不算 active |
| `relay_queued_messages{role}` / `relay_queued_bytes{role}` | 当前等待 writer 的消息数及其序列化 UTF-8 payload 字节 |
| `relay_inflight_bytes{role}` | writer 当前持有的 payload 字节，独立于等待队列 |
| `relay_max_connection_queued_bytes{role}` | 当前单条连接的最大等待字节，非历史峰值 |
| `relay_queued_connections{role,bytes_le}` | 当前队列字节不超过各固定边界的连接数；是累计边界 gauge，连接关闭后会减少，不能对它使用 counter 的 rate |
| `relay_subscriptions` / `relay_catalog_assembly_bytes` / `relay_creation_options_bytes` | 当前读取订阅、目录分片缓冲及创建选项缓冲 |
| `relay_draining` | 进入 drain 后为 1 |
| `relay_received_frames_total{role}` / `relay_received_bytes_total{role}` | 成功读取的完整 WebSocket data message 数与 payload 字节，包括随后被拒绝的消息 |
| `relay_written_frames_total{role}` / `relay_written_bytes_total{role}` | 实际成功完成写入的 data message 数与 payload 字节 |
| `relay_queue_duration_seconds{role}` | 入队尝试至 writer 取出消息，包含短时 admission 锁等待，不含 socket I/O |
| `relay_session_route_duration_seconds` | 成功的 session 数据帧从 Go 入口完整读取后，到目标连接写出完成；包含解码、当前数据库授权、排队及写入，不含前置 TLS 入口与原生执行 |
| `relay_send_duration_seconds{role,result}` | 入队尝试至 writer 完成，包含队列、提交前检查和目标网络写入；result 为 written / error |
| `relay_rejected_sends_total{role,reason}` | 入队前因序列化、大小、关闭、取消或队列满而拒绝 |
| `relay_protocol_errors_total{class}` / `relay_resyncs_total` | 固定类别的协议错误尝试，以及要求重同步的错误 / 订阅失效次数 |
| `command_transitions_total{action,from,to,origin}` | 当前进程确认提交的命令创建/状态转换；未改变状态的重试不重复计数 |
| `command_state_entry_age_seconds{action,state}` / `command_state_dwell_seconds{action,from,to}` | 数据库创建至状态进入的年龄，以及前一状态停留时间；可能含模型/人工等待 |
| `command_store_duration_seconds{operation,result}` | 每次仓库调用的单调耗时，含重复调用和失败尝试 |
| `command_timestamp_anomalies_total{interval}` | 缺失/倒退的数据库时间；不产生虚假的零延迟样本 |
| `command_forward_duration_seconds{result}` | 已登记命令的当前租约复查、转发和回执处理；区分 forwarded / duplicate / denied / queue_full / unknown / reconcile_unavailable |
| `relay_revoked_connections_total{role,reason}` | 选中进行授权失效处理的连接，每个连接最多累计一次；区分 access_revoked / authority_unavailable |
| `control_run_duration_seconds{worker,result}` | outbox / leases / consumer 所有权 / consumer_cleanup / approval_expiry 的独立尝试耗时，区分 ok / error / cancelled |
| `control_available{worker}` | 最近一次尝试成功为 1，失败或首次成功前为 0；停止时取消不更新可用性 |
| `control_last_success_timestamp_seconds{worker}` | 最近成功的 Unix 时间，尚未成功为 0 |
| `control_events_total{topic,result}` | 本进程 apply_error / ack_error / published 尝试数；重试不等同新的业务事件 |
| `control_event_age_seconds{topic}` | 数据库 created_at 至本进程处理并确认 published 完成的年龄，仅在成功确认后观察 |
| `control_event_future_timestamps_total` | 数据库创建时间位于服务未来的已确认事件；这些样本不进入年龄分布 |

角色只取 installation / device / other；结果、错误分类、worker 和 topic 均映射到固定词表。未知字符串归为 other，不创建动态标签。另有官方 Go runtime / process collector 的资源指标；没有导出环境变量或启动参数。

普通等待队列保留 16 条 × 64 KiB 的限制；[控制通知优先队列](relay-control-priority.md)另有
8 帧、合计 128 KiB 预算。现有排队消息数和字节合计两条队列，writer 另持有最多一条。
队列统计不包含 TLS / TCP 缓冲或对端积压。取消一次已经入队的等待，不会移除帧或证明未发送；
字节保持到实际 writer 取出，或连接停止时释放两条等待队列。inflight 仍等待当前写入结束后
归零。这与原命令未知结果的处理一致。

frame 指项目协议的完整 WebSocket message，不是底层线缆分片；包含握手、心跳与控制消息。installation 入站与 device 出站可分别观察主机输出和手机扇出，但不能推算 DSH 合并前的原始事件数或纯正文速率。`command_forward_duration_seconds` 不含命令最初的持久登记，也不含原生入队 / 执行或模型 / 人工等待；不把它写成完整命令耗时。

session 路由时间由服务内部单调时钟记录，入口时间不接受远端字段且不写入协议。只观察成功写出的帧，失败 / 重同步需结合其他指标及负载的完整投递检查。300 ms 桶用于指定负载预算；详细条件和真实 TLS 客户端计时见[认证容量样本](authenticated-capacity.md)。

控制事件年龄包含轮询积压、处理、通知 / 连接关闭及数据库确认。它只证明当前单进程处理窗口，不能代替手机实际收到通知、原生副作用停止或多节点传播的测量。未来时间单独计数；不把时钟偏差截成零延迟。控制 worker 与授权失败关闭行为保持独立，指标不延长任何租约。

采用[逐节点确认](control-fanout.md)后，各进程独立记录该窗口；实例之间需在采集端区分，不能把首个实例的成功当作全节点完成。节点失去 consumer 所有权时停止服务，`consumer_cleanup` 失败单独报告。

## 采集示例

```promql
sum by (role, phase) (dsh_remote_relay_connections)
sum by (role) (rate(dsh_remote_relay_written_bytes_total[5m]))
histogram_quantile(0.95, sum by (le, role) (rate(dsh_remote_relay_queue_duration_seconds_bucket[5m])))
histogram_quantile(0.95, sum by (le, topic) (rate(dsh_remote_control_event_age_seconds_bucket[5m])))
dsh_remote_control_available
```

`relay_queued_*` 与 `relay_inflight_bytes` 查看当前资源，累计 counter / duration histogram 才用于 rate 或增量。阈值需要试点与负载基线，当前不预设已满足 SLO 的告警数值。

## 2026-10-27 验证与边界

Go 1.26.10 的组件 race 回归通过，记录 `.local/observability-component-tests.log`。实际 WSS 测试阻塞一个 writer、填满 16 条等待队列，取消已经入队的调用后验证字节仍被统计；额外发送被拒绝，随后真正发送全部消息并归零。重复控制事件只累计实际选中的两个连接；失败的 apply / ack 不进入已完成年龄。未知角色 / topic / 正文样例不能生成动态标签，未来时间单独计数，监听器限制及端口清理通过。

`python3 tools/integration/run_remote_dsh.py` 的 Go race suite 与隔离 PostgreSQL 集成通过，本轮未启用专用 Android / Kotlin 开关。随后生产 Go 入口、npm DSH 0.2.1-rc.2、本地签名身份与模型夹具组合通过，记录 `.local/observability-full-chain.log`。原生组合耗时 12.190 秒，校验实际 Host / 手机 active 连接、完整流量、命令转发 / 重试、设备与 grant 撤权指标；返回文本不含本轮 ID、正文、工具参数或审批证明。独立文件服务子进程也校验配置的指标、两个真实控制 worker 的成功状态，以及 SIGTERM 后端口释放。TypeScript check 通过，记录 `.local/observability-ts-integration-check.log`。

加入单次 gather 合并与并发上限回归后，同一完整入口再次通过，最终日志为 `.local/observability-full-final.log`，原生组合耗时 11.447 秒。阻塞 collector 的实际并发 HTTP 用例另以 race 模式重复 10 次通过，记录 `.local/observability-concurrent-scrapes-repeat.log`；只要求重叠采集保持单次执行，允许前一轮结束后开始新的顺序采集。`go vet ./...` 通过，记录 `.local/observability-go-vet.log`。

Linux amd64、Go 1.26.10、Intel Core Ultra 5 338H、`-cpu=2`、每个 benchmark 一秒的微基准记录为 `.local/observability-benchmarks.log`：每组 Received / Dequeued / Written 观察调用约 263.3 ns，零分配；仅对 12000 个合成 socket 元数据采集约 1.50 ms、64257 B / 738 次分配。后者未建立真实连接、认证或排队正文，只测 collector 成本。

```sh
go test -run '^$' -bench 'Benchmark(FrameMetrics|RelayMetrics)' \
  -benchtime=1s -count=1 -cpu=2 ./internal/observability ./internal/relay
```

这些是本地组件及真实 DSH 组合证据。学校生产、物理手机、目标负载与故障 SLO 未在本轮验收；后续还需覆盖 Host 原始 / 合并事件、命令原生阶段与 checkpoint 失败、审批终态、文件扫描 / 交接与推送结果，并完成认证负载、备份恢复和多节点共享 replay / 路由 / fanout。

## 跨节点补充

[节点路由](relay-routing.md)新增 `dsh_remote_relay_proxy_tunnels`、按固定方向统计的
`dsh_remote_relay_proxy_inflight_bytes`、`dsh_remote_relay_tunnel_transit_duration_seconds`
和 `dsh_remote_relay_owner_http_forwards`。入口隧道与 owner 业务连接分别计数；前者包括尚在准入的隧道。
HTTP 转发上限为 128。隧道时延只覆盖一个入口转发方向，已有 session route 只覆盖 owner
处理路径；不能相加两个 p95 来宣称完整跨节点 SLO，需认证客户端端到端负载另测。
共享 DPoP、控制逐节点分发和双节点业务链路已有分阶段证据，目标集群容量、备份恢复和更广故障窗口仍待验收。

## 命令状态补充

[命令指标口径](command-observability.md)详细说明提交后计数、重试/扇出去重、未知结果进入次数、
状态年龄与停留时间、数据库时钟异常以及进程重启/提交确认丢失的边界。指标不替代持久对账，
不是当前未知积压数量，也不把原生/人工等待混入路由 SLO。正常 dsh 链路的 dispatching 阶段保留。

## Host 原生观测补充

[可选 Host 观测扩展](host-native-observations.md)记录真实 native prompt/create/reconcile、
checkpoint/cold checkpoint 的固定结果及耗时。只有启用私有指标时才协商，按连接累计求增量，
不保存操作正文或资源标签。`host_native_operations_total` 与 `host_native_operation_duration_seconds`
是 Host 自报，不能替代 command ledger 或路由 SLO；`host_observation_reports_total` 和
`host_native_dropped_samples_total` 显示验证/限速及部分 source 丢弃。当前有实际 CLI flush 故障夹具，
不代表生产磁盘与完整原生阶段验收。

## 审批与租约补充

[审批指标](approval-observability.md)把控制状态和 Host journal 事实分别计数，
`approval_state_transitions_total` 的 allowed 不表示执行完成；执行结果使用
`approval_host_transitions_total{to="settled"}` 的 outcome。
租约的 `approval_lease_preparations_total`、lifetime、availability_checks 和 remaining
分别描述提交后的准备、裁剪期限及检查点，不能解释成已投递或已消费。
所有转换在整个事务确认 commit 后采样，失败/相同结果重试不增加转换次数。

## 文件扫描与交接补充

[文件指标口径](file-observability.md)将领取后的扫描尝试与提交后的交接里程碑分开。
`file_scan_attempt_duration_seconds` 包括校验、扫描、对象写入及仓库完成/失败处理；
`file_handoff_age_seconds` 和 `file_handoff_read_to_stage_seconds` 使用数据库区间，
只有新里程碑的整个 commit 得到确认后才采样。staged 仍是 Host 暂存回报，不等于原生准入。
固定标签的仓库尝试耗时保留失败与重试，负时间差单独计数；这些指标不是当前积压或路由 SLO。

## 推送结果补充

[推送指标口径](push-observability.md)将 sender 返回、完成事务 commit 和客户端
posted/opened/blocked 去重回执分开。`push_delivery_results_total` 使用实际提交后的结果，
包括失效 endpoint 与重试期限裁剪；`push_client_receipts_total` 不表示人已经看见。
两个数据库年龄指标分别截止于完成更新/回执插入，单独报告负时间差；不能用接受数减去回执数
宣称未展示率。未配置推送时不建立通道或访问 provider。

## 当前未知积压补充

[数据库未知结果快照](unknown-results-metrics.md)提供 `unknown_results{kind="command|approval"}`，
与只增的状态进入次数分开。后台每轮有一秒期限、完成后间隔十秒，scrape 读取本地快照。
首次成功前不输出假零值；失败保留旧数量并报告不可用及年龄。它包含仍保留的旧代/恢复未知行，
不授予重试权限。同库多节点不能把该 gauge 相加，应按外部部署作用域选择新鲜可用来源。
