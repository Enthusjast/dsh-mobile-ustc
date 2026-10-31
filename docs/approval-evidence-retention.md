# 审批证据材料的保留延期

迁移 `045_approval_evidence_retention` 增加离线管理命令和追加式延期记录。默认保留规则仍是
决定时间起至少一个 UTC 日历年；组织需要更长保留时，可以把已有证据材料的总期限延至
原始决定时间起 2–10 个 UTC 日历年。新期限必须晚于当前有效期限，并且在操作时尚未到期。

这只延长数据库内独立证据材料快照的保留，不修改决定 JWS、公钥、摘要、原始证据身份或
最初的 `retain_until`。有效期限为原始期限与全部延期记录中的最大值。它不改变审批状态，
不恢复旧授权、回调或执行能力；也不把已经删除的材料从别处重建回来。

## 离线命令与结果对账

先按顺序应用迁移至 045，使用独立受控数据库角色，并从数据库备份之外取得当前部署代次。
二进制构建和恢复前提见[数据库恢复](database-recovery.md)。在仓库根目录运行：

```sh
export REMOTE_DATABASE_EPOCH='<当前外部部署代次 UUID>'
.local/remote archive retain-approval \
  --operation-id '<本次延期的稳定 UUID>' \
  --approval-id '<已有审批证据 UUID>' \
  --expected-epoch "$REMOTE_DATABASE_EPOCH" \
  --retention-years 3
```

`3` 表示从原始决定日起总共三年，不是从操作当天再加三年。日期采用 UTC 日历计算，
例如 2024-02-29 的三年期限是 2027-02-28，四年期限是 2028-02-29，时分秒不因会话时区变化。
期限、来源代次和记录时间由数据库计算，调用方不能伪造。

延期记录与 `approval.evidence.retention.extend` 审计同事务提交。审计抛错、忽略插入、
记录写入失败或提交失败均不返回成功。输出只有操作／审批 ID、来源／当前代次、总年数、
原有效期限、新期限及记录时间，不包含用户、设备、公钥、JWS、工具参数或数据库连接。

输出丢失或结果未知时，用相同操作 UUID、审批 ID、总年数和代次重试，取得原操作结果；
不会重复追加或重复审计。相同操作 UUID 改参数会冲突。进一步延期须使用新操作 UUID 和
更长的总年数。旧操作重试仍返回当时的历史结果，不代表后来追加的当前最大期限，也不会
缩短后来已生效的延期。每条证据最多九个递增年数选择，延期记录永久保留供对账。

## 权限、并发与恢复

迁移不会创建角色或给 PUBLIC 授权。管理角色至少需要：

- SELECT `approval_decision_evidence`、`approval_evidence_retention_extensions`、恢复状态和恢复谱系。
- INSERT 新表的 `id, approval_id, operation_epoch, retention_years` 列。
- SELECT / UPDATE 材料表的 `approval_id` 列用于行锁；不需要 SELECT JWS 或公钥。
- 恢复状态表 `slot` 列的 UPDATE 行锁权限；不需要修改代次。
- INSERT 审计的 `actor_type, actor_id, action, result, metadata` 列、SELECT 返回的 `id` 列和审计序列 USAGE。

数据库触发器仍拒绝修改／删除／TRUNCATE 延期记录；材料表的 UPDATE 权限只用于锁定，
不能绕过原有不可变保护。到期删除角色另需 SELECT 延期记录，以检查有效期限；没有读取权限
时删除失败关闭。直接 SQL 和离线文件访问仍需部署方的数据库／系统审计。

延期、证据到期删除在同一材料行上串行。延期先提交时，等待中的删除在新快照中看到延期并
拒绝删除；删除先提交时，延期报告材料不可用，不保存虚假的延期记录。为避免旧事务快照
漏读等待期间提交的延期，材料删除和延期插入只接受 READ COMMITTED。命令显式使用该隔离
级别；直接管理 SQL 也必须遵循。原有[未完成导出](approval-evidence-export.md)仍独立阻止删除。

数据库恢复包含延期和审计。隔离或外部代次不匹配时拒绝新操作；释放后的后继代次必须具有
到来源代次的可信恢复谱系，使用新操作 UUID 才能继续延期。旧代操作不能在新代重放。
延期从不重建 runtime grants 或恢复设备凭据。存在延期记录时 045 的 down 迁移拒绝执行，
需要修改时使用经审阅的前向迁移。

## 边界与本地验证

这里不提供无限期法律保全、缩短期限或自动删除。延期到期后仍需有权限的管理员按原规则
显式删除材料，删除审计与删除同事务提交，证据身份、签名指纹和延期历史保留。

本命令也不管理导出文件、外部副本、数据库备份或密钥的生命周期。已导出的证据文件保留
当时的原始证据字段，不会因后来的数据库延期自动改写；组织需要同时调整独立副本的保留。
不能把数据库内延期当作完整冷归档、法务保全或生产备份验收。

真实隔离 PostgreSQL / race 用例覆盖原证据字节不变、递增和幂等、四个并发重试、
延期／删除两种先后顺序、陈旧快照拒绝、审计错误／忽略及记录忽略回滚、最小权限、
UTC 闰年、到期删除和不可变／down 保护。实际 `pg_dump` / `pg_restore` 验证延期保留及恢复代次；
生产二进制验证结果丢失后的同 UUID 对账和输出隐私。本机 npm dsh 0.2.1-rc.2 的正常双节点
链路另行回归。身份与模型仍使用本地夹具，不涉及 Android 修改、大负载、真机或厂商配置。

本机记录：`.local/evidence-retention-focused-final.log`、`.local/evidence-retention-go-final.log`、
`.local/evidence-retention-go-vet.log`、`.local/evidence-retention-native.log`。
