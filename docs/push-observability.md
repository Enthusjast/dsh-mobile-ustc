# 推送发送结果与客户端展示回执

启用私有 `REMOTE_METRICS_LISTEN_ADDR` 后，生产入口把 FCM sender 和推送仓库绑定到同一
registry。没有推送配置时不会新建通道或联系 provider。采集器不访问数据库/Google/手机；
标签不含用户、设备、binding、notification、source、lease ID、组织、project/package、
FID、地址摘要、provider message ID、challenge、撤销凭据、token、原始响应或异常文本。

## 三种事实

共同前缀为 `dsh_remote_`。

| 指标 | 记录点 |
| --- | --- |
| `push_provider_send_duration_seconds{kind,result}` | 每次 FCM `Send` 返回；包括本地验证、OAuth、发送前权限重查及响应处理 |
| `push_delivery_results_total{kind,state,code}` | 当前 lease 的完成事务及审计得到 commit 确认后 |
| `push_client_receipts_total{kind,state}` | 当前已认证设备上报 posted / opened / blocked，去重插入和审计得到 commit 确认后 |
| `push_operation_duration_seconds{operation,result}` | complete / receipt 的仓库尝试单调耗时，包括失败、相同结果重试和锁/commit 等待 |

kind 为 challenge / approval / question / timed_question / other。
sender result 为 provider_accepted / retry / invalid_endpoint / failed / expired / other。
Send 尝试可能在本地验证或权限重查阶段结束，不能把它的样本数当作实际 provider HTTP 次数。
发送返回 provider_accepted 仅表示接口返回了可接受的成功响应；随后数据库提交仍可能失败。
异常传输返回 retry/provider_result_unknown，不据此推断 provider 未接收。

仓库 state 使用**实际持久写入的结果**：provider_accepted / retry / failed / expired / other。
invalid_endpoint 会先禁用 binding，再以 failed 提交；重试时限/预算不足会改写为 expired。
这些变化只有整个事务 commit 后才计数。旧 lease 和重复 Complete 不新增结果；
同一 notification 通过新 lease 重试并提交，属于新的尝试，可以产生多个结果。
planner 的批量过期、预算清理和 channel confirmed 等变化未纳入该计数，它不是完整状态转换表。

code 为固定本地分类：none、authority_changed、metadata_unavailable、invalid_envelope、expired、
provider_auth_unavailable、provider_result_unknown、provider_redirect、provider_unregistered、
provider_throttled、provider_unavailable、provider_rejected 或 other。
未知分类统一归 other，不把数据库/网络响应文本用作标签。

客户端 state 的 posted 表示 App 报告已尝试向 OS 发布通知，opened 表示报告发生打开流程，
blocked 表示报告展示受阻。它们均是客户端遥测，不证明人已经看见，也不改变审批/问题状态。
一个 notification 可以分别有三类回执，每种只计首次已提交插入；相同回执重传或多条 HTTP
竞争不重复计数。它们不是互斥终态，也不能相加当成独立用户数。

operation result 为 ok / access_denied / expired / lease / conflict / invalid / cancelled / timeout /
unavailable / other。ok 包括相同回执成功去重；它不等于新增客户端事实。

## 时间口径与缺失

`push_delivery_age_seconds{kind,state}` 使用 delivery 的数据库 created_at 到完成更新的 updated_at；
包括排队、退避、OAuth、当前尝试以及前次尝试的累计等待。一次重试完成可增加一次年龄样本，
不是纯 provider 网络时延。`push_client_receipt_age_seconds{kind,state}` 从同一 created_at
到回执 received_at，是数据库收到回执的时间，不是手机 OS 的展示时间。

两个区间都在 commit 得到确认后采样，但截止于更新/插入，不包括之后的审计及 commit 等待。
负时间差保留事实计数，丢弃相应区间，并增加 `push_clock_anomalies_total{source="delivery|receipt"}`。
单调时钟的 sender/operation 耗时与数据库年龄独立；不能相加 percentile 推导端到端延迟。

没有客户端回执可能来自离线、进程限制、通知权限、未启用通道、回执丢失或源权限已结束，
不能仅由差值归因为“推送未展示”。各计数还受指标停用、进程重启、commit 确认丢失、
提交后崩溃和多节点采样影响；不能替代持久审计、队列表和客户端对账。
没有为每个 notification 建立指标标签或缓存，不能从这些计数计算精确当前积压/送达率。

```promql
sum by (kind, result) (rate(dsh_remote_push_provider_send_duration_seconds_count[5m]))
sum by (kind, state, code) (rate(dsh_remote_push_delivery_results_total[5m]))
sum by (kind, state) (increase(dsh_remote_push_client_receipts_total[1h]))
histogram_quantile(0.95, sum by (le, kind, state) (rate(dsh_remote_push_client_receipt_age_seconds_bucket[5m])))
```

## 本地验证范围

race/私有 PostgreSQL 用例覆盖同一通知的重试、新 lease、并发 Complete、并发/重复 posted、
opened/blocked 独立回执，完成与回执审计在延迟 commit 时失败的回滚，最终结果改写、未知 code
固定归类及负数据库时间差。计数与持久审计核对，回执不改变 pending 审批，外设备不能写回执。

FCM 组件使用隔离 TLS 对端验证成功、拒绝、重试、失效地址、重定向和撤权，并采集 sender
结果；发送本身不能生成数据库或客户端计数。既有 HTTPS/JWT/DPoP 组合还经过队列 worker、
真实 RSA OAuth assertion 和正常 FCM sender，检查 challenge 的 sender 接受与提交结果各一次，
没有虚构客户端回执，指标不含凭据、端点或 challenge。

这里的 Google 域名由测试 transport 改接到本地 TLS 对端，未联系真实 Google 服务；
客户端回执为经过正式仓库鉴权的夹具上报，不代表真机通知展示验收。本轮未配置厂商推送、
未运行大负载或真机测试，也未改变 Android 通知行为。
