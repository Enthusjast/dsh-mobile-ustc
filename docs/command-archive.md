# 命令元数据保留与归档

迁移 `046_command_archive` 增加有界的离线归档命令。默认把创建时间和最后状态更新时间均已超过
30 × 24 小时的 `settled` / `rejected` 命令移出热表。`received`、`host_accepted`、`dispatching`、
`agent_queued`、`observed` 和 `outcome_unknown` 不进入归档；原生入队不等于执行完成，不能
为了清理空间把这些状态改成 settled。

历史表保留原始元数据、摘要和终态，包括创建后的 session UUID、fork 来源、已知 child 和独立
副作用结果。服务端仍不保存聊天正文、原生 receipt、工具参数或问题正文。新历史表与原表在
同一个 PostgreSQL 内，不是独立冷备份。

## 管理命令与保留配置

在应用迁移、更新全部服务节点和数据库权限后，使用当前外部部署代次执行。二进制构建方法见
[数据库恢复](database-recovery.md)。以下命令在仓库根目录运行，连接从受控环境注入：

```sh
export REMOTE_DATABASE_EPOCH='<当前外部部署代次 UUID>'
.local/remote archive commands \
  --batch-id '<本批唯一 UUID>' \
  --expected-epoch "$REMOTE_DATABASE_EPOCH" \
  --hot-days 30 --cold-days 0 --limit 64
```

`hot-days` 为 1–3650，默认 30；`cold-days` 为移入历史后额外的最短保留天数，允许 0–3650，
默认 0。一天始终按 24 小时计算，不受会话时区或夏令时影响。默认没有另加一年的历史保留。
`0` 表示历史元数据提交后即可由具备删除权限的管理员清理，不表示归档命令自动删除历史。
选择更长的附加期限后不能修改已提交批次来缩短它。

每批默认 64、最多 128 条，按更新时间和完整主键选择并跳过已锁定行；单行 JSON 上限 64 KiB。
时间和主键只用于选择，不是完整性水位，之前锁定或晚提交的旧记录可进入后续批次。
批次、原行精确复制、热行删除和 `command.archive.batch` 审计在同一事务提交。
复制、删除、审计、计数核对或提交失败均整体回滚。数据库还在提交时检查完整数量、热行已移除
及同事务审计，不能通过忽略写入得到部分成功。

输出只有批次 ID、操作代次、配置、数量和时间，不输出原命令、设备、用户或摘要。
输出丢失时用同一批次 UUID、代次和参数重试，返回原结果，不再次移动数据或增加审计。
旧结果是当时的归档结果，不证明后来仍存在全部历史材料；空批次也需要新的 UUID 才会处理新候选。

## 状态、去重与文件引用

`commands` 是可更新的热表，`command_archive` 保存不可修改的终态；`command_records` 是仅供
读取的联合视图。原有状态端点、当前 socket 的回执授权、提问答案对账和文件 delivery 都读取
两处记录。读取仍执行当前用户、设备、组织、runtime、session/workspace 和 grant 检查，归档
不会提供历史权限。重复准入返回同一终态，改变摘要或目标仍冲突。迟到的相同 Host 回执可以
幂等核对，不同状态或改变 fork 证据的回执不能改写归档记录。

`command_keys` 从迁移时的活跃记录建立，此后与每次新准入一起提交，永久保留
`device_id + request_id` 两个 UUID。它不含用户、摘要、状态或结果。热行和历史行删除都不会
释放这个身份；历史材料清理后原 ID 的新准入返回现有 `command.request_conflict`，不会再次
转发。原状态查询在没有材料时返回原有 not-found，不伪造“未执行”。Host 的本地原 ID 去重
继续独立执行，客户端不能通过自动换 ID 掩盖不确定结果。

文件消息引用改为引用永久身份，归档不会拆散文件与原命令的关系。已有引用会阻止历史元数据
到期删除，直到引用按自身生命周期处理；不能让“缺少 command join”变成新的下载或 receipt
授权。归档后的文件重试只核对原绑定，不取得新 handoff。仅到期、无文件引用的历史行可以
显式删除，每条删除与 `command.archive.delete` 审计一起提交，审计忽略／失败均阻止删除。
历史删除使用 READ COMMITTED，以免锁等待后的旧快照漏读引用。批次和永久身份不可删除或 TRUNCATE。

## 权限、升级与恢复

迁移不创建角色，不向 PUBLIC 授权，联合视图使用 `security_invoker`，不会借视图所有者绕过
底表权限。普通服务新增需要读取 `command_records`、`command_archive`、`command_keys`，
以及向 `command_keys(device_id,request_id)` INSERT 和读取 RETURNING 的权限；新请求还需
原有热表权限。不能把永久身份表的 DELETE/UPDATE 授给服务。

归档管理角色需读取／插入历史和批次、读取并锁定／删除热行、读取恢复状态并锁定 `slot`、
写审计并使用审计序列。行锁的 UPDATE 权限可限于热表 `request_id` 列，触发器仍禁止改变身份。
热行删除及批次完整性检查还需读取审计的 action、actor_type、database_epoch、producer_xid、metadata。
历史删除角色另需 DELETE 历史、SELECT 批次／文件引用和写删除审计、读取返回的 audit `id`。
数据库直接读取与操作审计仍由部署方配置。

迁移需要锁定命令和文件引用表并建立身份索引，部署时须评估窗口。首次归档前停止旧版本
读写节点、按顺序应用迁移、补齐 ACL，并让所有读者使用新版本；不能让不理解历史表的旧节点
与已开始归档的新节点混用。旧节点可能漏读文件引用对应的历史状态，不能将其视为兼容滚动升级。
本功能没有对生产环境执行迁移或清理。

恢复会保留历史、批次和永久身份；隔离或外部代次不匹配时归档失败，释放后使用新批次和新代次。
已有终态不随恢复改为未知，其他未完成命令仍按恢复规则处理。批次代次只表示归档发生在哪个
数据库历史中，不能用它推断旧命令最初写入的来源代次。存在归档使用记录或已退役身份时，
046 的 down 拒绝破坏性回退。需要更改时使用经审阅的前向迁移。

## 验证与边界

隔离 PostgreSQL / race 验证状态筛选、原行精确复制、当前权限、文件绑定、fork 结果、提问
对账、并发幂等／锁定行、写入忽略与审计故障回滚、到期清理后 ID 不复用、视图 ACL 和历史
迁移顺序。真实 `pg_dump` / `pg_restore` 保留终态和身份且不恢复 grants；实际生产二进制
核对输出丢失后的同 UUID 重试。

本机 npm dsh 0.2.1-rc.2 与双节点生产入口另验证已完成创建／取消的元数据归档、手机原 ID
重试、相同原生会话及后续聊天、审批和撤权。身份与模型为本地夹具。没有运行 Android、
大负载、真机、厂商通道或生产保留任务；永久身份、审计和外部备份仍按各自边界保留，不宣称完整擦除。

本机记录：`.local/command-archive-focused-final.log`、`.local/command-archive-go-final.log`、
`.local/command-archive-go-vet.log`、`.local/command-archive-native.log`。
