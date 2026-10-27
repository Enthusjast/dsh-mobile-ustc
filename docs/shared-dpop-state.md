# 跨进程 DPoP nonce 与 replay 状态

生产 Go 入口现在使用迁移 018 的 PostgreSQL proof repository。内存实现保留给显式构造的库 / 单元夹具；生产入口不提供存储故障时的内存回退。原来的公开 JWT / DPoP / 设备 / grant 检查继续执行。

依据 [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) 的证明绑定与重放要求，签名、算法、注册密钥绑定、htm / htu / ath / iat 校验先于存储。验证后的每次 gate 在一次事务内决定原 nonce 与 jti 是否可用，登记成功消费并生成下一 nonce。未认证、篡改或错误请求用途不会到达共享状态。

## 事务与命名空间

资源域由可信 issuer、audience 和 public origin 的长度前缀 SHA-256 定义；仓库与 Authenticator 的资源域必须一致。节点不能用自身 ID 划分状态，HTTP 请求也不能选择域。issuer / audience 使用配置的精确身份值；origin 的 scheme / host 按现有 URI 比较规则统一大小写。

每个资源固定 256 个 bucket，按证明密钥 thumbprint 的哈希分桶。Nonce 与 jti 分别使用带用途和长度前缀的 SHA-256 标识；数据库不保存 raw nonce、jti、token、JWK thumbprint 或用户 ID。

READ COMMITTED 事务先取得一个 bucket 的行锁，再读取数据库时钟。所有节点按相同顺序更新该 bucket 的条目和精确计数，无跨 bucket 写入。有效 nonce 的删除、jti tombstone、下一 nonce 和计数一起提交；只有成功提交后，中间件才进入受保护接口。相同证明竞争时最多一次成功，重放会得到新 challenge，但不会消耗另一个尚可用的 nonce。

下一 nonce 写入、quota 或提交失败时整笔操作回滚；没有接受结果或新 nonce 返回，HTTP 为 503。未知提交结果不自动重试资源动作。丢失 gate 结果最多留下不可见的 proof 元数据，不表示业务动作已执行。

## 容量、期限与故障

`REMOTE_DPOP_ENTRIES_PER_BUCKET` 在启动时校验 64–65536，默认 8192，即每资源最多 2097152 个 nonce / jti 条目。已有资源的持久设置必须与每个节点一致，否则启动失败；不能通过改本机设置偷偷扩容或建立第二套 replay 域。调整需要协调所有节点及数据库设置，保留尚有效的条目。

Nonce 与成功消费的 replay tombstone 采用数据库时钟的五分钟期限。Gate 的数据库操作最长两秒，初始化最长三秒。每次操作只回收本 bucket 最多 512 个过期条目；独立 worker 每秒处理最多 16 个有过期数据的 bucket，不扫描或删除所有活跃条目。过期首先在授权判断中生效，物理清理可以稍后完成，条目总量仍有硬上限。

数据库不可达、锁等待超时、配置不一致或容量不足都会失败关闭；不会变成一次新的可接受授权。清理 worker 只记录可用性变化，不记录资源域、密钥、nonce、jti、SQL 或参数。未改动 WSS ticket 的独立一次性证明、注册设备 / 安装密钥、现有租约或撤权期限。

先应用 018，再运行新版服务；旧版内存节点不能被计为已经具备跨节点 replay 保证。恢复旧数据库可能回退消费事实，安全备份恢复和外部撤销 / 代次同步仍需独立演练，不能直接清空 proof 表作为上线恢复路径。

## 2026-10-27 验证

`.local/shared-proof-security-final.log` 的私有 PostgreSQL / race 用例覆盖：

- 两个独立连接池竞争同一证明，仅一次成功；重建 repository 后仍拒绝原证明；相同 jti 不能借另一个 nonce 重用，拒绝后该 nonce 可用于新 jti。
- 两个资源域不能互用 nonce。冲突配置被拒绝。写入下一 nonce 的真实数据库 trigger 故障会回滚原 nonce 删除与 jti 登记，恢复后原证明可用。
- 容量耗尽不部分消费，过期回收后可继续；512 条清理边界和未过期 tombstone 保留；取消不修改状态，只有摘要入库。
- 一个连接池默认 SERIALIZABLE 时，repository 明确的行锁事务仍使用指定隔离语义，保持跨池单次消费。

两个真实生产服务进程经同一校验证书的 TLS 1.3 入口，验证 A 的 challenge 可在 B 消费、并发竞争只进入一次接口、进程重启保留状态。阻塞数据库 bucket 造成有界 503，释放后相同证明仍可成功。记录 `.local/shared-proof-two-process-first.log` 和最终安全回归。完整回归曾出现夹具停机失败（`.local/shared-proof-full-first.log`），该批次保持失败；夹具在停止进程前退役其拥有的 idle / speculative backend 连接后，完整 PostgreSQL race suite 与实际 npm DSH 组合通过（`.local/shared-proof-full-second.log`）。

生产入口使用 PostgreSQL 后，同一单节点 3000 连接、200 活跃会话 × 20 Hz、30 秒窗口通过，120000 帧全部送达，准入 6.572 秒，端到端 p95 30.343 ms / p99 64.814 ms，Go route 的 300 ms 桶比例为 1。记录 `.local/shared-proof-3000.log` 与 `.local/relay-capacity/shared-proof-3000/`。这些是该夹具的独立条件，不把前后不同运行的延迟差异归因于单项优化。

本阶段只完成共享认证状态。跨节点连接路由、持久控制事件逐节点分发、12000 集群 / 目标 40000 源帧每秒、生产身份与物理设备仍未完成。
