# 主机与 runtime 分页目录

已登记手机可使用 `GET /v1/host-directory` 和 `GET /v1/runtime-directory` 分批发现当前有权
枚举的主机和 profile。两条路由默认每页 50 条，最多 100 条，只接受 `limit` 和 `cursor`。

```http
GET /v1/runtime-directory?limit=50
Authorization: DPoP <resource-access-token>
DPoP: <fresh-proof>
```

响应 `data` 包含 `items` 和 `next_cursor`；游标为 null 时结束。主机条目沿用公开 Host
元数据：UUID、别名和登记状态。同一主机有多个可见 profile 时只出现一次。runtime 条目
沿用公开 Runtime 元数据：UUID、主机/组织 UUID、版本、最后活动时间及调用者自己的当前
grant 角色、范围、版本和期限。不返回其他用户的 grants、profile reference、本机路径、
连接 ID、公私钥、凭据或会话正文。

## 可见性和当前证明

每页在同一个数据库语句快照中核对活跃账号、当前登记且未撤销的手机及 DPoP 公钥指纹，
再按组织成员关系、主机/安装/runtime 状态、绑定批准情况和当前有效 grant 过滤。枚举条件
与既有完整列表共用同一规则：明确的 `host.list`，或 `session.list` 且至少有一个会话被
grant 的 sessions/workspaces 范围覆盖。单独的 `session.read` 不授予目录枚举。

组织管理员或安装所有者没有 runtime grant 时，也不会自动获得该内容目录。安装生命周期
管理仍使用[安装目录及 profile 管理](installation-profile-management.md)。已登记且活跃的
账号没有可见资源时返回空页；账号、设备或证明失效则拒绝请求。失去成员关系或撤销 grant
后，相应资源会从后续页消失。数据库错误返回 503，不伪造成空目录。

runtime 的 access 是调用者当前 grant 的元数据快照，不是 ticket、执行许可或授权缓存。
正文、消息、审批和文件操作仍要核对各自当前权限。Host 的 active 描述登记状态，最后
活动时间也不能证明当前在线；目录读取不启动原生 Agent。

## 稳定分页

主机和 runtime 分别按自身 UUID 升序。别名、在线活动或展示排序变化不会把记录移动到游标
另一侧；客户端可在取得所需条目后自行按展示规则排序。游标绑定目录用途、用户 UUID 和
DPoP 密钥，只定位记录，不授予权限，也不冻结历史快照。两种目录游标不可交换，跨账号或
换钥不能继续使用原游标。新增到已读位置以前的资源，需要刷新后才能重新遍历。

请求拒绝未知、重复或空参数、非规范数值、超长/不规范游标、重复 JSON 字段及 GET 正文。
身份和范围不能通过 query/body 选择。Host OAuth 客户端不能调用这些手机路由。响应使用
`no-store`。

查询使用 limit+1 判断后续页，不使用 OFFSET，也不先把完整列表加载到 Go 内存。复用已有
`runtime_grants_user_active(user_id,runtime_id)` 索引，无需新增迁移。按范围过滤和主机去重
可能需要扫描更多候选行；每次查询有两秒期限，本轮没有测量大目录或目标规模性能。

旧 `GET /v1/hosts`、`GET /v1/runtimes` 保留完整列表格式；新分页通过独立路径接入，不截断
旧客户端结果。Android APP 本轮未修改，其分页接入需要后续单独完成。

## 本地验证

隔离 PostgreSQL 测试覆盖多主机/profile 分页、同主机去重、别名变化、与完整列表可见集合
一致、自己的 grant 快照、跨组织隔离、缩权及账号/设备/成员/授权/资源失效。游标用途、
用户和证明绑定、严格 JSON、目录动作和空账号边界另有测试。HTTP 用例检查实际 actor/page
参数传入仓库、默认页长、正文及选择器拒绝、Host 客户端边界和错误响应。

实际本机 npm DSH 0.2.1-rc.2 双节点组合分页读取两个已绑定 profile，核对与完整目录一致、
主机只出现一次、当前 owner grant 快照及已撤销用户的空目录。身份、模型和手机协议对端
仍为本地夹具；学校身份、Android、真机、大负载及厂商推送未作为本轮验收。
