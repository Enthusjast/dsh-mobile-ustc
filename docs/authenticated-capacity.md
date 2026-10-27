# 认证 TLS / WSS 容量夹具

`run_remote_dsh.py --relay-load` 在全新、仅 Unix socket 的私有 PostgreSQL 集群中运行生产 Go 服务二进制。测试进程提供 TLS 1.3 入口、签名 issuer / JWKS 与 Host / 手机协议 peer；服务仍使用正式 JWT、DPoP、主机 challenge / credential、ticket 和注册密钥握手，并发配置不能关闭认证或授权。

目录先预置独立的用户、设备、主机密钥、runtime、workspace、session 和精确 grant，再从真正的 HTTPS API 取得凭据。每个 Host / 手机对拥有不同用户与三把不同密钥，保持一主机一手机的连接分布。目录 / 登记已预置，学校登录、浏览器、Android Keystore、注册 UI、真实 DSH 模型执行和多节点不在本夹具的测量范围。普通 `test:remote-dsh` 另行验证真实 npm DSH 0.2.1-rc.2。

## 执行与固定边界

```sh
python3 tools/integration/run_remote_dsh.py \
  --relay-load 100 --load-workers 16 --load-hold-seconds 30 \
  --load-active-pairs 20 --load-events-per-second 20 --load-payload-bytes 512 \
  --load-output .local/relay-capacity/example-100
```

连接数是 Host + 手机之和，必须为 4–12000 的偶数；worker 为 1–64，稳态窗口 5–90 秒，活跃对最多 2000 且不超过已配置对数，源速率每对 1–20 帧每秒，正文为 128–16384 字节。未选 active pair 的连接仍通过每 15 秒的协议心跳保持与数据库检查；早期连接在其余准入期间也持续维护。

有状态 protocol smoke 可以加 `--load-race`，它同时启用服务与测试进程的 race instrumentation，二进制 build info 会核对实际模式。容量数据使用普通二进制；本工具拒绝在普通容量模式下继承 `GOFLAGS=-race`。模式互斥，专用开关不从以前的环境继承。默认测试不会偷偷开始容量场景；即使 Go 错误 skip，外层也要求匹配本次完整配置的 passed 收据。

输出必须是仓库 `.local` 内尚不存在的目录，既有批次不能覆盖。每个目录为 0700，报告、服务日志、证书及 Prometheus 快照为 0600。保存配置、Go / 二进制 race 模式、源码提交和脏文件、实际服务 SHA、阶段、HTTP 状态 / 耗时、连接资源与失败信息；不保存 raw token、私钥或流内容。私有集群退出前只提取 SQLSTATE 计数，不复制 SQL、参数与数据库转储。

## 每次运行验证

先以一个真实 peer 对验证篡改 JWT、错误 DPoP 密钥、跨 runtime 请求和错误 WSS 证明都被拒绝；错误 WSS 证明后原 ticket 仍能完成正确握手。随后并发建立剩余连接，必须由生产指标报告准确 active 数量。

活跃 pair 经过真实目录发布、订阅、快照与 attempt start。每条投影流按 pair 分散起始相位、固定间隔发送，不进行合并，扇出固定为 1。接收端检查 runtime / epoch / session / subscription / sync / attempt、完整正文、连续 index 和实际发送时间；要求计划帧全部送达。发送端最大节奏落后预算为 250 ms，尾部投递等待最多 5 秒，客户端精确 p95 必须小于 500 ms。Go 完整入口读取至目标写出的直方图另要求至少 95% 落在 300 ms 桶内；桶判断不冒充精确 p95。

结束前实际撤销一个设备，要求有序通知并在 5 秒内关闭，其他连接及心跳继续可用。显式关闭后，生产连接 / 订阅指标及数据库 runtime connection 必须归零，服务 SIGTERM 必须完成。失败不会改成成功，也不会减小原请求的负载自动重跑。

Go 服务的 CPU、RSS、fd、goroutine、heap 与队列单独采集；驱动进程的统计包含 TLS 入口、issuer 与所有负载 peer，不能归算为服务本身。Go route 指标不含 TLS 入口、模型或人工等待；客户端单调时钟耗时包含整个 fixture 投递。512 字节指流文本，JSON / TLS / TCP 开销另计。PostgreSQL CPU、跨机器网络与长期稳定性需要后续测量。

## 当前证据

初步 race smoke 已在四条真实连接、两条 20 Hz 会话、五秒窗口下通过 200 帧的完整投递与负面检查，记录 `.local/capacity-race-smoke-first.log`。扩大并发后发现的真实事务冲突及修复证据见[并发准入](serializable-admission.md)。100 连接的修复批次通过，后续规模结果按独立批次记录。

这些协议 Host 是负载 peer，未创建同等数量的 DSH / 模型进程。单节点基准、模拟器结果或合成元数据采集都不能证明集群 12000 连接、2000 活跃会话 × 20 Hz、慢消费者、节点故障、重连 / 续期风暴、文件混合负载或正式试点的全部出口。

## 已完成的分级样本

Linux amd64、Go 1.26.10、16 GiB 宿主，保留可见 API 36 preview，关闭已完成验收的专用测试 VM；驱动 / TLS 入口 / PostgreSQL 与服务共享该宿主。服务连接池 30，SERIALIZABLE 准入默认 4；合并窗口 0，单订阅扇出 1，文本 512 字节。下面均为独立批次，普通服务与驱动二进制，未启用 race。

| 连接 | 活跃会话 × Hz | 窗口 | 完整交付 | 准入 | 客户端 p95 / p99 | 撤权样本 |
| --- | --- | --- | --- | --- | --- | --- |
| 1000 | 100 × 20 | 30 s | 60000 / 60000 | 3.628 s | 30.227 / 88.057 ms | 86.18 ms |
| 3000 | 200 × 20 | 30 s | 120000 / 120000 | 6.923 s | 66.408 / 177.009 ms | 76.40 ms |

对应目录 `.local/relay-capacity/baseline-1000-gated/` 与 `.local/relay-capacity/baseline-3000-lease-joins/`。后者 loaded 时服务 RSS 276774912 B、heap 88325232 B、6050 goroutine、3052 fd；这些是采样点，非历史峰值，也不包含驱动、TLS 入口和 PostgreSQL 的占用。所有已配置连接在窗口后保持，当前排队字节为零；完整角色快照和驱动资源在各自报告中。

早期 1000 / 3000 的失败分别定位到[准入冲突](serializable-admission.md)和[批量租约](lease-validation-capacity.md)，原目录 / 日志保留。新批次成功没有改写旧批次。3000 是计划中的单节点测量点；集群 12000 与 2000 活跃会话 × 20 Hz 仍待实现和测量。

## 当前提交的独立复核

提交 `848aec8bae575863b2614f813c62270e05b80319` 再次运行相同的 3000 / 200 × 20 Hz / 30 s 配置，日志 `.local/capacity-848aec8-3000.log`，证据 `.local/relay-capacity/848aec8-3000/`。源码脏文件列表为空（按约定排除未跟踪的 PLAN.md），实际服务 SHA-256 为 `c0a9154787a8de9580f82f2be45e3c66b0b3c5e7a556b42a09704896270c2592`。

本轮准入 5.508 秒，120000 帧和 124178000 字节 JSON 协议内容全部交付，客户端 p95 33.326 ms / p99 97.249 ms / max 327.595 ms，Go route 的 300 ms 桶比例为 1，撤权样本 230.36 ms。每个 peer 至少三次心跳；唯一 challenge / 凭据、各准入 audit、关闭后的连接 / 订阅 / runtime connection 归零和正常退出均由该批次严格断言。787 个 `40001` 在服务内部处理。

这些是独立重复样本，时间差异保留而不取最好值。最终 race smoke 记录为 `.local/capacity-race-smoke-final.log`；完整 PostgreSQL race suite 与真实 npm DSH 0.2.1-rc.2 组合记录为 `.local/capacity-full-regression.log`。TypeScript check、Go vet、CLI 互斥 / 边界 / 不覆盖证据及小样本 nearest-rank 分位回归均通过。指标和报告的字节数不包含 TLS / TCP 包头与 framing。
