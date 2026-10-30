# 安装下的 profile 管理

安装所有者或当前组织管理员可以查看一套安装保存的 runtime UUID，并永久撤销其中一个
profile。它复用[安装管理](installation-management.md)的权限边界，适用于停用旧 profile，
同时保留该 OS 用户安装下的其他 profile。整套密钥遗失仍应撤销整个 installation。

```http
GET /v1/installations/<installation UUID>/runtimes?limit=50
Authorization: DPoP <resource-access-token>
DPoP: <fresh-proof>
```

响应 `data` 包含 `installation_id`、`items` 和 `next_cursor`。每条记录只有 `runtime_id`、
`state`、`last_seen_at`、`revoked_at`；不返回本机 profile reference、工作区路径、原生会话 ID、
模型设置、连接 ID、公私钥或凭据。管理元数据不授予会话内容访问权。

状态为 `pending`、`active` 或 `revoked`。active 表示登记和绑定条件成立，不代表在线；最后
活动时间也不能证明当前连接仍有效。目录保留已撤销记录，方便核对响应丢失后的状态。安装或
Host 被撤销时，所属记录显示 revoked；安装管理者仍须满足当前账号、设备及组织成员条件。

默认每页 50 条、最多 100 条，按 runtime UUID 升序，使用已有 `(installation_id,id)` 索引。
游标绑定账号、DPoP 密钥、安装及目录用途，每页重新检查当前管理权限。它不是权限凭据或
历史快照；管理员降级、退出组织、账号/手机停用后不能凭旧游标继续查看。只接受 `limit` 和
`cursor`，拒绝未知/重复/空参数、非规范数值和 GET 正文。

## 单独撤销

```http
DELETE /v1/installations/<installation UUID>/runtimes/<runtime UUID>
Authorization: DPoP <resource-access-token>
DPoP: <fresh-proof>
```

两条路由都要求活跃账号、当前登记且未撤销的手机 DPoP 密钥、当前组织成员关系，以及安装
所有权或当前组织 admin 角色。普通 runtime owner grant 不会赋予安装生命周期管理权。
Host OAuth 客户端不能调用这些手机接口。不接受 DELETE 正文或查询选择器；不存在、归属
不匹配或无权管理的 UUID 均统一拒绝，不披露其他安装的存在。

成功返回 `{ "ok": true, "data": { "revoked": true } }`。事务内核对当前手机证明及管理者，
锁定目标 runtime 与安装/Host 和当前成员关系，并执行：

- 永久撤销目标 runtime，取消其未完成绑定申请，消费未使用的手机 ticket。
- 撤销该 runtime 的全部 grants 并增加版本，令活动会话目录和文件交接失效。
- 保存 grant 资源审计、一个 `runtime.revoke` 管理审计及持久 `runtime.revoked` 事件；事件
  关闭目标 runtime 的 Host 和手机连接，继续使用既有逐节点确认和历史归档机制。

安装和 Host 对象、安装密钥、共享短期凭据/challenge、兄弟 profile 及设备不被此操作撤销。
共享凭据在接入和业务操作时仍检查具体 runtime，所以不能用它重连已撤销的 profile。
如果整套安装已经没有符合接入条件的 profile，既有凭据查询也会按当前资格拒绝。

安装锁与授权/登记路径协调；锁等待期间提交的新 grants 会纳入本次撤销。审计或事件写入
失败会整体回滚。再次 DELETE 同一目标仍须重新鉴权，成功重试不重复增加版本、审计或事件。
随后撤销整套安装仍会停用剩余 profile。命令、审批、归档历史和本机日志不会被该接口删除，
也不宣称终止已经开始的本机外部副作用。

runtime UUID 和同一安装内的原 profile reference 不复用。重新接入需要按登记流程使用新的 profile
reference 或新安装身份，不会自动承接旧 grants；删除本机绑定文件或复制旧凭据不能恢复。
该接口复用现有数据库结构和迁移 034 的事件索引，无新增迁移或 Android APP 改动。

## 本地验证

隔离 PostgreSQL 测试覆盖目录/游标、所有者和管理员、runtime owner 无权替代安装所有者、
当前成员和密钥、归属不匹配、待绑定 profile、并发幂等、审计失败回滚、锁等待期间新增授权，
以及 ticket 和已暂存文件交接失效。既有 Relay 测试验证目标 Host/多部手机断开、兄弟 profile
连接可继续心跳；整套安装撤销的原有测试也继续运行。

双节点 Go/PostgreSQL/本机 npm DSH 0.2.1-rc.2 组合通过正常双端绑定增加一个 fixture profile，
分页查看并撤销它，检查各节点确认后，由 owner 手机在同一个真实 DSH 主机连接上获取新的
原生会话快照。被撤销的附加 profile 是元数据夹具；保留的主 profile 运行真实 DSH。身份和
模型仍是本地夹具，未进行学校配置、Android、真机、大负载或厂商推送验收。
