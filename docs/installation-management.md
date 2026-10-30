# 主机安装发现与撤销

手机可通过 `GET /v1/installations` 发现可管理的主机安装，再显式调用
`DELETE /v1/installations/{id}` 处理主机遗失、重装或安装密钥丢失。它管理的是某 OS 用户下的
一次安装身份，撤销会覆盖该安装的全部 profile；同一物理主机的其他安装保持原状态。
如只停用一个 profile，可使用[安装下的 runtime 目录及单项撤销](installation-profile-management.md)，
保留安装密钥及其余 profile；两者使用相同的安装管理权限边界。

两条路由都要求当前活跃账号、已登记且未撤销的手机 DPoP 密钥，以及目标组织的当前成员关系。
目标必须由当前账号拥有，或当前成员关系的角色为 `admin`。普通 runtime owner grant 不会
自动取得整套安装的管理权。Host OAuth 客户端不能调用这些手机路由。

## 发现

```http
GET /v1/installations?limit=50
Authorization: DPoP <resource-access-token>
DPoP: <fresh-proof>
```

默认每页 50 条，最多 100 条，按创建时间及 UUID 倒序。响应 `data.items` 包含安装、主机和
组织 UUID、主机别名、所有者内部 UUID、`is_owner`、`key_version`、`runtime_count`、状态及
创建/撤销时间。`runtime_count` 是该安装保存的 profile 总数，不是在线数量；用于判断整套
撤销的范围。状态为 `pending`、`active` 或 `revoked`，其中 active 只描述登记状态，不是当前
连接授权。响应不包含安装公钥、私钥、连接凭据、用户 subject、路径或模型配置。

继续分页时使用 `next_cursor`；没有后续页时它为 `null`。游标绑定当前服务用户和 DPoP 密钥，
并带安装目录用途。它只是元数据定位器，不是权限凭据，也不是历史快照。每页重新校验账号、
手机密钥、当前成员关系及管理角色；组织管理员降级或用户退出组织后，旧游标不能保留原权限。
不同目录的游标不能互换。只支持 `limit` 和 `cursor`，重复、未知或无效查询以及 GET 正文被拒绝。

## 显式撤销

```http
DELETE /v1/installations/<installation UUID>
Authorization: DPoP <resource-access-token>
DPoP: <fresh-proof>
```

不接受正文或查询选择器。成功返回 `{ "ok": true, "data": { "revoked": true } }`。不存在或
无权管理的 UUID 统一拒绝，不披露它属于谁。服务端在同一事务内完成：

- 永久撤销安装和其全部 runtime；撤销全部 Host 短期凭据，消费未使用 challenge 和 ticket。
- 撤销该安装下所有用户的 runtime grants 并提高版本；取消待绑定申请，令活动会话元数据和
  文件交接失效。保留已归档会话状态、命令、审批、历史及设备登记，不删除本机密钥或日志。
- 保存安装与 grant 的资源审计，写入已有 grant 撤销事件以及逐 runtime 的 `runtime.revoked`
  控制事件。事件关闭该 runtime 的 Host 和手机连接，不影响其他安装的 runtime 连接。

安装行锁与现有登记、授权和取证路径协调。撤销使用后续的新语句快照，把锁等待期间已经提交
的凭据或 grants 纳入本次撤销。审计或 outbox 失败会整体回滚。响应丢失时可用同一安装 UUID
再次 DELETE；已撤销安装仍需重新验证调用者权限，但不会重复修改版本或新增成功审计。

撤销不是终止任意已开始的本机外部副作用，也不能回收对象服务已经签发的短期能力。已有的
同步授权检查、三秒审批许可、文件租约和断连清理继续适用。账号仍可保持活跃，手机设备也不会
被此操作撤销。安装 ID 不复用；重新接入须按组织流程使用新安装身份重新登记和双端绑定。
不能仅删除本机绑定文件、清空 revoked 标记或复制旧凭据来恢复权限。

## 分发、归档与部署

迁移 `034_installation_management` 增加安装目录索引，并扩展控制事件保留索引。
`runtime.revoked` 沿用按节点持久确认、恢复代次和历史归档/加密导出机制；读取历史不会重放
事件或恢复权限。私有指标使用固定 topic 标签。身份清单同步退休安装时也发布同一 runtime
事件，周期授权检查仍是独立的失败关闭路径。

启用新管理入口前更新所有 Relay 及归档/验证工具。旧版本不认识新事件主题，不能将其跳过或
把旧工具验收当作新主题已被处理；任何回滚仍须核对代码、协议和历史兼容性。down 迁移只恢复
索引，不会撤销已经提交的安装撤销，也不会删除保留的事件。

## 本地验证

真实隔离 PostgreSQL 测试覆盖所有者/管理员和跨组织边界、runtime owner 无权替代安装所有者、
失去成员关系、分页角色变化、全部 profile/凭据撤销、同主机其他安装保留、幂等并发请求、审计/
事件失败回滚和锁等待期间新增 grant。新控制事件的连接隔离、持久确认、归档与不恢复权限的历史导出也
有独立测试。

默认 Go/PostgreSQL/本机 npm DSH 组合继续测试身份清单停用路径。专用安装 API 组合为：

```sh
REMOTE_TEST_DSH_BIN=/本机安装路径/dsh \
  python3 tools/integration/run_host_enrollment_terminal.py --installation-revoke \
  --output .local/installation-revoke-new-run.log
```

它让安装所有者的已登记手机发现并撤销正常 DSH 插件，检查每个 Relay 节点的确认、Host 断开、
新取证和仍未过期的缓存秘密被拒绝。身份、模型和密钥库仍是本地夹具；本轮未修改 Android APP。
