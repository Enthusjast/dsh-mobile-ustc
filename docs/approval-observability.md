# 审批状态、执行结果与租约指标

生产入口启用既有私有指标时，审批仓库和授权租约 provider 也绑定同一 registry。
观察只发生在事务确认提交后，不改变审批决定、签名校验、Host 最终 guard 或三秒租约上限。
所有标签使用固定词表，不包含用户、设备、runtime、approval、execution、lease ID、digest、
authority key ID、参数、正文或签名证明。采集器不访问数据库。

## 状态与执行事实分开

共同前缀为 `dsh_remote_`。

| 指标 | 含义 |
| --- | --- |
| `approval_state_transitions_total{from,to,cause}` | 已确认提交的控制面状态转换；新登记为 none → pending |
| `approval_host_transitions_total{from,to,outcome}` | 已提交的 Host journal 事实转换；outcome 为 none / succeeded / failed / cancelled |
| `approval_operation_duration_seconds{operation,result}` | 单次 register / decide / host_result / lease 尝试的单调耗时，包括验证、授权、锁等待、签名和 commit |

`cause` 为 registration / decision / host_result / expiry / connection；它表示写入路径，
不是从异常文本推断的根因。空状态归为 none，未知值归为 other。
操作结果为 ok / denied / expired / conflict / invalid / cancelled / error；cancelled 表示调用方
上下文已取消的失败，内部准入/数据库超时也可能归入 error，不以这些类别替代具体故障诊断。

控制面 `decision_received` 只表示已接受 allow 决定；`allowed` 可以在 Host 报告 consumed 时出现，
**不表示执行已完成**。Host 的 approved、consumed、settled 分别是 journal 中不同事实。
执行结果分布应观察 `approval_host_transitions_total{to="settled"}` 的 outcome。
这些仍是经过身份和精确上下文检查后记录的 Host 事实，并非服务端独立观察到了外部副作用。

一个 denied 决定和后续 Host denied 回报分别属于两套计数，不能相加当作两个审批。
重复登记、重复签名决定、同一 Host 结果和旧消息重传不会重复计转换；只读状态/详情及多手机引用
扇出不增加它们。相应成功仓库尝试仍记录耗时。

## 失效、重连及失败提交

登记请求可能清理同 runtime 的过期审批。即使该登记本身是重复请求，只要事务确认提交了其他审批
的过期变化，expiry 转换也会计入。过期指标来自实际写入，并非到达 deadline 的瞬间自动加一。
Host 自己报告 expired 则归入 host_result 路径。

runtime 重新接入/断开引起的 invalidated 或 outcome_unknown，只有整个连接事务提交后才采样。
失败的审计、CAS 或延迟到 commit 才失败的事务不产生成功转换；完整事务的可确认重试不会重复计数。
旧连接关闭没有匹配当前连接时，也不会新建失效转换。

可能已经执行的决定在断连后保留未知结果。后续合法历史 settled 回报可以记录修正，
但修正本身不能取得新的执行租约。outcome_unknown 可以被后续事实澄清，因此计数是状态进入次数，
不是当前未知积压或唯一审批终态集合。恢复 CLI 的批量隔离另见[恢复记录](database-recovery.md)，
不经普通网络仓库计数路径。

## 租约准备与可用性

| 指标 | 含义 |
| --- | --- |
| `approval_lease_preparations_total{decision}` | 已签名且 audit/outbox 的 commit 得到确认的准备次数 |
| `approval_lease_lifetime_seconds{decision}` | 声明的 expires_at − issued_at，按各原始权限期限裁剪，正值且最多三秒 |
| `approval_lease_availability_checks_total{decision,result}` | commit 后检查时的 available / expired；不是投递回执 |
| `approval_lease_remaining_seconds{decision}` | 可用性检查时的正剩余量；数据库 expiry 与服务进程墙钟相减，受两者时钟差影响 |

`decision` 为 allow_once / reject / other。reject 的权限证明只用于传递已记录的否定决定，
不授予工具执行许可。相同原始决定的两次成功 Issue 会生成不同 lease UUID，应计两次准备；
这不是重复决定，也不会刷新原认证、grant 或签名决定的有效期。

准备成功不等于 proof 已返回、已写出、已验证或已执行。锁、审计和签名成功后，lease 仍可能在
commit 中或网络投递前过期。commit 已确认但检查时已过期，准备计数保留，expired 检查计数增加，
调用返回错误和空 proof。签名或 commit 失败不会产生成功准备。

最终返回前及 Host 接收/消费时的既有独立期限检查保持不变。availability 指标只记录那个检查点，
不能保证调用者实际收到时仍未过期。没有按 lease UUID 建立消费缓存，也没有假设一个审批的
consumed 回报恰好对应某个 renewal；不要据此计算精确活跃租约数量或每条 lease 的消费率。

```promql
sum by (to, cause) (rate(dsh_remote_approval_state_transitions_total[5m]))
sum by (outcome) (increase(dsh_remote_approval_host_transitions_total{to="settled"}[1h]))
sum by (decision, result) (rate(dsh_remote_approval_lease_availability_checks_total[5m]))
histogram_quantile(0.95, sum by (le, decision) (rate(dsh_remote_approval_lease_remaining_seconds_bucket[5m])))
```

这些是进程本地、尽力采样的计数。关闭指标、进程重启、commit 确认丢失或提交后立刻崩溃可能造成
缺失，不能代替持久 audit、审批表和 Host journal 对账。状态次数不相当于唯一用户/工具次数。

## 本地验证

私有 PostgreSQL/race 用例覆盖并发登记/决定、重复 Host 结果、准备续期、拒绝决定，以及决定、
执行结果和 lease 在 commit 时失败的回滚。额外延迟 commit 使短期 grant 的 lease 准备后过期，
验证它被计为已准备但不返回 proof。过期清理在重复登记时提交、在失败登记时回滚，
断开/替换及历史 settled 修正均按实际写入计数。指标文本不含资源、参数、JWS 或 authority ID。

正常 npm DSH 0.2.1-rc.2 双节点组合还将登记/决定及 Host 事实计数分别与持久审计核对，
将 lease 准备次数与 authorization.prepare 审计核对，并继续验证真实 Bash 的 allow/reject/cancel/revoke。
身份与模型为本地夹具。没有运行大负载、真机或厂商推送配置测试，生产稳定性和完整可观测性仍未验收。
