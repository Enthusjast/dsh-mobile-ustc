# 连接配额策略的离线变更

`remote connection-limits describe` 继续只描述本机配置。迁移
`043_connection_policy_changes` 增加管理员使用的 `status` 和 `replace`，没有公开 HTTP 路由。
数据库地址通过受控 `REMOTE_DATABASE_URL` 提供；两项数据库命令还要求显式设置当前
`REMOTE_DATABASE_EPOCH`，且数据库已解除恢复隔离。它们不代替管理员、配置来源和变更流程核验。

```sh
.local/remote connection-limits status
.local/remote connection-limits describe --policy-file /受控目录/new-connection-limits.json
```

`status` 返回数据库代次、当前策略/摘要、有效 consumer 租约数量和 `occupancy_retained`。
保留标志包含手机占用行及 Host 路由元数据，可能存在已失效但尚未清理的记录；它不等于
当前有效 socket 数，也不返回用户或设备列表。尚未初始化时策略/摘要为 null，查询不创建策略。

先按[共享连接配额](shared-connection-limits.md)格式保存受保护的新文件，核对新值、规范化
SHA-256 与当前旧摘要。停止并排空全部 Relay、控制 worker 及其他维护 consumer，然后执行：

```sh
.local/remote connection-limits replace \
  --operation-id '<本次全新操作 UUID>' \
  --expected-sha256 '<status 返回的旧策略 SHA-256>' \
  --policy-file /受控目录/new-connection-limits.json
```

事务锁定当前恢复代次、consumer 登记/续租和连接策略，重新比较旧摘要并确认没有有效
consumer 租约。旧摘要、同策略空替换、恢复隔离、错误代次、尚有有效租约或锁超时都会拒绝。
不会自动停服务、缩短租约或删占用记录。租约数量为零不是所有物理进程已经停止的证明，
管理员仍须核对暂停/断网或尚未登记的旧程序；旧版本节点也必须排空。

成功时原子更新连接策略，并保存不可变回执及 `connection_policy.replace` 系统审计。
手机占用行、Host 路由、consumer、命令、授权和执行事实均保持原样，不通过清空状态腾名额。
新 consumer generation 和原有过期机制继续排除失效占用；后续有界清理仍按原规则执行。
SQL 没有实际更新成期望策略、回执或审计写入失败时整体回滚。

随后让所有节点使用同一新文件再启动。正式入口登记 consumer 后核对当前连接策略；
旧配置启动失败时释放该登记并在监听前退出。运行中的准入仍核对内容和摘要，旧缓存不构成
继续使用旧限制的许可。没有热重载或自动调参接口，`command-limits` 与连接配额相互独立。

输出丢失或提交结果不明确时，用原操作 UUID、原旧摘要及相同文件内容重试。已提交操作只
返回原回执，即使节点已重新上线或后来换过其他策略，也不回退当前值、不再写审计。
复用操作 ID 携带其他参数会拒绝；两个竞争同一旧摘要的新操作最多成功一个。
恢复旧数据库后仍须先执行恢复隔离/身份重建，使用新的外部代次和新的操作 UUID，不能用
配置回执恢复旧连接或跳过当前权限。

回执只包含操作/数据库代次 UUID、前后摘要、公开预算和数据库时间，不声称识别操作者的
学校身份。变更历史用于去重和追溯，不能更新或删除；迁移 043 的 down 遇到历史记录时拒绝。
普通审计仍走原保留/归档机制。共享 consumer 门禁也用于命令策略，避免两种流程使用不同
登记/续租锁定规则。

本地 PostgreSQL 测试覆盖占用保留、有效租约拒绝、比较替换、原 ID/历史对账、并发竞争、
恢复代次、审计/实际更新失败回滚、记录不可变及空迁移往返。正式二进制和双进程 TLS 夹具
另验证排空、输出丢失重试、旧配置启动清理和新配置可用；本机 npm DSH `0.2.1-rc.2`
链路单独回归。身份和模型为夹具，没有学校生产变更、Android APP、真机、大负载或厂商配置。
