# Host 原生操作与 checkpoint 观测

可选能力 `host.observations.v1` 将当前 Host 的有限原生操作统计发送给其 owner Relay。
只有配置私有指标的服务才协商该能力；手机端不能取得或发送该能力。旧 Host 不需要升级才能连接，
新 Host 遇到不支持扩展的旧 Relay 时继续原有业务，不发送观测帧。

这与[已提交命令指标](command-observability.md)是不同来源：这里是已登记 Host 的自报数据，
不能证明命令已保存、原生入队、审批有效或工具执行完成，也不能作为授权及路由决策依据。

## 记录位置与含义

只在真实调用返回或抛出时采样，不根据缺失的 command.receipt 推断失败。
原生错误对象、用户正文、文件路径、模型信息和资源 ID 不进入观察器。

| operation | 记录范围 | result |
| --- | --- | --- |
| checkpoint | 当前 Session 查找及 `sessions.flush` | persisted：flush 确认；unavailable：Session 未挂载或 flush 返回 false；failed：检查/flush 抛出异常 |
| cold_checkpoint | 未挂载会话的持久游标读取和必要的 live cut 复查 | persisted / failed；协议也预留 unavailable |
| prompt | `sessionController.prompt` 调用，不含随后单独的 checkpoint | ok / error / cancelled |
| create | `sessionController.create` 调用，不含随后 checkpoint / catalog | ok / error / cancelled |
| prompt_reconcile | 现有请求证据检查、必要的 checkpoint 和 Agent 身份复查，绝不新建 prompt | ok / error / cancelled |

`ok` 仅表示对应原生方法返回。checkpoint 失败后，现有 journal 和命令状态仍按原规则进入未知结果，
不会因为观测成功发送而升级为 agent_queued。正常重试读取 journal，不能为补指标再次入队。

这些操作并非互斥阶段：cold checkpoint 的 live fallback、prompt_reconcile 内部可能调用 checkpoint。
不要将全部操作次数相加当作唯一命令数，也不要将这些耗时相加当作总执行时间。
`cold_checkpoint.failed` 可能是读取、取消或会话切换检查失败，不直接等同于磁盘 I/O 错误。

## 有界发送与连接生命周期

每个 DshClient 只绑定当前连接的观察器；未协商能力时不计时、不缓存离线样本。
观察器异常不会改变原生返回值或异常。连接替换时丢弃旧窗口，跨越连接替换完成的旧 span
不会归到新连接。窗口不保留每次调用的记录或 request ID。

连接内按 operation/result 固定组合累计 count、整数微秒 sum 和 12 个累计直方图桶。
最多 15 个组合，每五秒最多尝试发送一个有变化的窗口，编码上限 16 KiB。
桶边界为 1、5、10、50、100、300、500、1000、5000、10000、30000、60000 ms，
大于最后边界的样本进入隐含的 +Inf 桶。source duration 使用进程单调时钟，时间戳不会跨机器相减。

当 WebSocket 已关闭或已有超过 128 KiB 待发送数据时跳过观测发送，保留累计值等待后续窗口。
观测发送不等待回调、不添加独立重发队列、不因自己的超时终止业务连接。
调用结果也不等待观测。观察器只接受安全整数和固定词表；不合法或窗口计数饱和的样本计入 dropped。
dropped 不包含未绑定、连接结束或网络中丢失的所有观察，不能当作完整丢失率。

## 接收规则

`host.observations` 是安装实例专用帧。通用 Relay schema、TypeScript/Zod 和 Go 有同源 golden，
由 `tools/generate-native-observation-contract.ts` 维护。帧携带 runtime_id、runtime_epoch
和 connection_id 来校验当前连接，这些字段不作为指标标签，也不写入数据库。

服务端对已协商 Host 的观测尝试最多每秒处理一次。它检查协商能力、角色、当前 runtime/epoch/connection、
字段白名单、组合去重、数值边界、直方图与 sum 的一致性，并重新验证当前 Host 数据库连接。
重复序号只有在报告完全相同时才可幂等忽略；旧序号、计数回退、缺失旧组合、非法增量均被拒绝。
合法新序号按上次窗口求差，不能把每次完整累计数重复相加。

非法 Host 观测只计固定类别结果并忽略，普通业务仍可继续；无法解码的通用协议帧仍执行原有关闭策略。
手机伪造返回 access.denied。指标关闭或能力未协商时，服务不接受该扩展。

## 私有指标

共同前缀为 `dsh_remote_`；operation/result 为上述固定词表，没有动态标签。

| 指标 | 含义 |
| --- | --- |
| host_native_operations_total{operation,result} | 当前 Relay 已接收的原生操作增量累计 |
| host_native_operation_duration_seconds{operation,result} | 同一增量的标准 Prometheus 直方图；source 微秒转换为秒 |
| host_native_dropped_samples_total | Host 窗口报告的 dropped 增量 |
| host_observation_reports_total{result} | accepted / duplicate / rejected / throttled / denied 次数 |

```promql
sum by (result) (rate(dsh_remote_host_native_operations_total{operation="checkpoint"}[5m]))
histogram_quantile(0.95, sum by (le, operation, result) (rate(dsh_remote_host_native_operation_duration_seconds_bucket[5m])))
increase(dsh_remote_host_native_dropped_samples_total[1h])
```

这些是可丢失的运行观察，不持久化、不提供恰好一次交付。节点重启会清零，连接末尾未上报的样本可能丢失。
未收到报告不等于操作失败；Host 也可能自报不实数据。command ledger、原生 journal 和审批证明保持原有权威边界。
采集器只复制本地有限计数，不查询数据库或 Host。

## 本地验证与边界

小型测试覆盖窗口聚合、快照不变性、连接重绑、发送异常、背压及 span 不重计数。
真实 DSH Session 上注入 flush false / 异常，区分 unavailable 与 failed，验证未知命令重试不再次 prompt。
Go/race 测试核对 TypeScript goldens、累计差值、重复/回退、桶和微秒单位，以及真实 WSS 上的手机伪造、
限速、当前连接失效和指标隐私。

实际 npm DSH 0.2.1-rc.2 CLI、两个生产 Go 进程与私有 PostgreSQL 的组合验证了正常 prompt/checkpoint
报告；临时 profile 的 flush 注入异常后，手机收到 failed checkpoint，owner 私有指标出现相应失败计数。
移除故障后继续历史、聊天、审批和撤权。异常文本和本地路径未出现在指标中。
身份与模型均为本地夹具；没有运行容量、物理手机或厂商推送配置测试。

本阶段不覆盖 journal 自身持久写入耗时、所有原生操作的阶段分解或生产磁盘故障演练。

2026-10-27 的本地记录：

- `.local/native-observations-go-final.log`：Go/race 的差值、真实 WSS、直方图单位与权限测试通过。
- `.local/native-observations-npm-verify-final.log`：245 个主机侧用例全部通过，含实际 npm DSH CLI 以及旧 Relay 不协商新能力的组合。
- `.local/native-observations-full-fault.log`：完整 Go race/私有 PostgreSQL 与双节点生产入口通过，真实 CLI 原生部分约 15.578 秒，包含临时 flush 故障到失败指标的链路。
- `.local/native-observations-source-final2.log`：最后的 Source 发送重入/背压回归通过；发送过程中完成的样本仍留给下次累计报告。

TypeScript check、contract check、构建和 `go vet ./...` 通过。早期测试的未初始化零值轮询及旧能力列表断言失败日志仍保留；相应断言和零值初始化已修正。
