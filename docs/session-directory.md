# 有界会话目录

`GET /v1/runtimes/{id}/session-directory` 分页返回指定 runtime 中当前可枚举的会话元数据。
它供会话较多时逐页发现资源，不读取正文或原生日志，也不签发连接凭据。

```http
GET /v1/runtimes/<runtime UUID>/session-directory?limit=50
Authorization: DPoP <resource-access-token>
DPoP: <fresh-proof>
```

每页在同一个数据库语句快照中检查活跃账号、当前登记且未撤销的手机 DPoP 密钥、组织成员
关系、未撤销安装和已批准 runtime，以及未到期/撤销的当前 grant。actions 必须包含
`session.list`。`host.list`、`session.read`、组织 admin 或安装所有权本身均不补授会话枚举。
Host OAuth 客户端不能调用此手机接口。

结果只包含当前 grant 的 sessions UUID 或 workspaces UUID 覆盖的会话。空资源数组不授予
访问；没有 workspace 归属的会话只能由明确的 session UUID 范围覆盖。授权变化或工作区
映射变化后，后续页按当前范围过滤，旧游标不能保留先前权限。

响应 `data` 包含 `runtime_id`、`items`、`next_cursor`。每条记录沿用公开 Session 元数据：
会话 UUID、workspace UUID/null、状态、`last_persisted_seq` 和 `updated_at`。不包含原生 ID、
标题、路径、模型设置、聊天正文、设备公私钥或 token。目录可包含真实的 archived/unavailable
元数据，不能把主机离线或无授权当作没有历史；新鲜状态仍依赖 Host 目录同步，正文读取仍需
主机在线及当前 `session.read` 权限。

## 分页规则

默认每页 50 条，最多 100 条，按会话 UUID 升序。UUID 排序不受活动时间更新影响；如果按
可变的 `updated_at` 跨页排序，活跃会话可能在读取期间跨过游标而重复或漏项。调用方可在
获取完整目录后按活动时间展示。

`next_cursor` 为 null 时结束。否则将其作为下一次请求的 `cursor`，每次使用新的 DPoP
proof。游标绑定目录用途、用户 UUID、DPoP 密钥及 runtime UUID，只提供位置，不是权限凭据
或历史快照。成员关系、设备、账号或 runtime 失效后，原游标会被拒绝；普通缩权则按新范围
筛选。同一分页期间新增到已读位置以前的会话或新获授权资源，需要刷新才能重新遍历。

只接受 `limit` 和 `cursor`；重复/未知/空参数、非规范数值、超长游标及 GET 正文返回 400。
缺失资源、当前授权或有效设备统一拒绝，数据库故障返回 503，不伪造空页。已有 session.list
但资源数组为空的有效授权返回空 items。响应沿用 `no-store`。

迁移 `035_session_directory` 为 `(runtime_id,id)` 增加目录索引；回退仅删除该索引，不改变
会话、授权、历史或客户端游标数据。查询用 limit+1 判断后续页，不使用 OFFSET，也不先将
完整会话列表加载到 Go 内存。稀疏范围可能需要扫描更多候选行，查询有两秒期限；这不等于
已经验证大目录或目标规模下的时延。

## 客户端与验证边界

原 `GET /v1/runtimes/{id}/sessions` 继续提供既有完整列表格式，没有静默截断或新增必需字段。
新分页能力通过独立目录路径接入；调用方必须实现游标遍历，不能把第一页误作完整列表。
本轮不修改 Android APP；其当前目录调用仍使用旧接口，分页 UI/客户端接入需后续独立完成。

隔离 PostgreSQL 测试覆盖 workspace/明确 session 范围、隐藏及兄弟 runtime、空范围、归档和
离线状态、活动时间变化不影响 UUID 分页、跨页缩权、账号/设备/成员/授权/runtimes 失效，
以及游标的用途/账号/密钥/runtime 绑定和严格 JSON 解析。HTTP 测试检查当前 phone proof
传入仓库、默认/最大页长、参数及正文拒绝、Host 客户端边界和错误处理。

实际本机 npm DSH 0.2.1-rc.2 双节点组合从 Host 发布的会话目录逐页获取元数据，以契约校验
每页，确认无重复 UUID且完整可见集合与已有目录相同；被撤销者不能继续读取。身份和模型为
本地夹具，学校身份、Android、真机、大负载及厂商推送均不作为本轮验收。
