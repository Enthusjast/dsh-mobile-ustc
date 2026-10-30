# 并发准入的完整事务重试

真实 TLS 负载夹具在 100 条连接 / 16 个并发准入 worker 时，首先于 host challenge 接口得到 503。私有 PostgreSQL 的脱敏诊断记录了 SQLSTATE `40001`；仅修复 challenge / credential 后，随后 WSS 准入也暴露同类问题。原失败保留在 `.local/capacity-baseline-100-diagnostic.log`、`.local/capacity-baseline-100-retry-v1.log` 和各自的证据目录，没有改记为通过。

服务保持 SERIALIZABLE 隔离、原权限与限额，在数据库层为以下完整元数据事务增加有界重试：主机 challenge、凭据交换、runtime attach、session catalog、手机 ticket 签发 / 准备 / 消费。每次尝试重新创建事务，失败事务的 rollback 在回调返回前完成，重新检查身份、安装 / 设备密钥、当前授权、挑战期限与消耗状态。

[Runtime 授权 PUT / DELETE](runtime-grant-writes.md) 也使用同一确认中止重试规则；它们在事务内
锁定当前手机及 DPoP 指纹，并与并发设备撤销协调。普通错误和结果不明的提交不重放。

按照 [PostgreSQL 18 的事务重试规则](https://www.postgresql.org/docs/18/mvcc-serialization-failure-handling.html)，只对数据库明确中止的 `40001`、`40P01` 重试整段逻辑。最多十六次尝试，退避从 5 ms 增长并在 80 ms 封顶，加同范围随机抖动；等待受原请求 context 约束。业务拒绝、额度、唯一性冲突、连接错误与不确定的提交结果不自动重试。对外仍使用原结构化错误，不输出驱动 SQL / 参数。

放大至 1000 连接 / 32 个 worker 后，单靠增加重试次数仍会耗尽预算。服务现在将同时运行的这七类 SERIALIZABLE 事务限制为默认 4 个，与既有 30 个数据库连接分开管理；其他已连接流量与控制检查不占此 gate。`REMOTE_SERIALIZABLE_ADMISSIONS` 只在启动时接受 1–30，开始使用后不能改动。等待发生在创建事务快照之前，取消不会开始新事务，回滚与 panic 都释放槽位，退避期间让出槽位。外部负载仍保持相同连接数和 worker 数。

迁移 017 增加凭据的完整 installation_id 索引。同步清理包含已撤销及过期凭据，原来仅覆盖 active 行的部分索引不能完整支持该条件。没有修改旧迁移或降低隔离级别。

这里的回调仅包含数据库和本地密码学处理。失败尝试的新 nonce / 凭据不会返回，audit / outbox 也随事务回滚；签名检查和随机值在新尝试中重新执行。HTTP 请求与 DPoP proof 没有重发，高风险工具执行、文件外部副作用或未知结果命令没有接入此循环。

2026-10-27 验证记录 `.local/serializable-postgres-first.log`：

- 私有数据库 trigger 连续两次抛出 `40001`，第三次只产生一条 challenge 与一条成功 audit，返回摘要对应已提交值。
- 在凭据写入处连续中止两次，challenge 最终只消费一次、只保留一条有效凭据和一条成功 audit；原 proof 的之后重放仍被拒绝。
- 首次尝试中止后暂停账号，下一次尝试重新查询身份并拒绝，没有遗留 challenge。
- 单元分类覆盖两个可重试 SQLSTATE、`23505`、连接错误、业务拒绝、未知提交结果、有界上限和取消。

补充回归 `.local/admission-lease-security-final.log` 在 runtime attach、catalog、ticket 签发 / 消费的最后 audit 插入处连续两次中止：此前的数据修改必须整体回滚，最终仍只有一次 audit，消耗后的 ticket 不能重用。准入 gate 的取消、panic 释放、配置范围和启动后不可调整也通过。

新一轮 100 连接 / 20 个活跃会话 / 每会话 20 帧每秒 / 30 秒通过，12000 帧全部按序送达，客户端端到端 p95 为 1.413 ms，单个撤权样本为 88.66 ms。数据库仍记录了 166 次 `40001`，说明冲突在真实隔离规则下发生并由服务内部处理；这不说明数据库没有争用。记录为 `.local/capacity-baseline-100-retry-v2.log` 与 `.local/relay-capacity/baseline-100-retry-v2/`。

使用 gate 4 / 重试上限 16 / 迁移 017 的 1000 连接场景随后通过：100 个活跃会话、20 Hz、30 秒共 60000 帧，准入 3.628 秒、端到端 p95 30.227 ms，536 个 `40001` 在内部处理。记录 `.local/capacity-baseline-1000-gated.log`。更大场景同时暴露并修复了[批量租约查询瓶颈](lease-validation-capacity.md)，完整结果见[认证容量夹具](authenticated-capacity.md)。

这是本地连接与元数据准入验证。后续扩容仍需测量冲突率、尾延迟、查询计划与连接池压力；未知 COMMIT、节点故障、备份恢复、生产身份与目标规模仍需独立验收。
