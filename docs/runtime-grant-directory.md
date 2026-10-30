# Runtime 授权目录

`GET /v1/runtimes/{id}/grants` 供当前管理者核对一个 profile 的既有授权，并使用已有的
PUT / DELETE 授权接口修改或撤销相应用户的权限。该接口只读，不创建账号、授权或审计事件。

```http
GET /v1/runtimes/<runtime UUID>/grants?limit=50
Authorization: DPoP <resource-access-token>
DPoP: <fresh-proof>
```

调用者必须是活跃账号，持有已登记且未撤销的手机 DPoP 密钥，并且仍是目标组织成员。
目标 Host 必须为 active，安装及 runtime 未被撤销，且 profile 绑定已经批准。管理权限与
现有授权修改接口一致：当前组织管理员，或持有该 runtime 未过期、未撤销的 owner grant，
且其 actions 包含 `grant.manage`。仅有安装所有权、普通 operator/viewer grant 或
`session.read` 权限均不足以读取其他用户的授权。Host OAuth 客户端不能调用此手机接口。

响应 `data` 包含 `runtime_id`、`items` 和 `next_cursor`。每条授权仅返回用户内部 UUID、
角色、actions/workspace/session UUID 范围、`grant_version`、授予者内部 UUID、到期/撤销时间
及当前状态。不返回学校 subject、个人资料、设备列表、公私钥、凭据、本机路径或聊天正文。
目录包含该 runtime 保存的全部授权记录；管理者可核对已失效的旧授权，而不会因此恢复权限。

状态按以下顺序确定：

1. `revoked`：授权已被显式撤销。
2. `expired`：未撤销，但已到期。
3. `inactive`：未撤销且未到期，但接收者账号不活跃或已失去组织成员关系。
4. `active`：以上条件均未发生。

`active` 描述授权记录当前资格，不表示在线、具有任意资源权限或已获某次工具执行批准。
每个具体操作仍检查当前账号、设备、资源范围、版本、runtime 代次和必要的单次签名。

分页默认 50 条，最大 100 条，按用户 UUID 升序，使用已有 `(runtime_id,user_id)` 主键索引，
不需要新增数据库迁移。游标绑定目录用途、当前账号、DPoP 密钥及 runtime；它仅提供位置，
不冻结历史，也不授予权限。每一页在同一个数据库语句快照中检查管理权并读取结果。管理者的
grant 过期/撤销、角色降级、账号停用、退出组织或 profile 撤销后，原游标也会被拒绝。
并发新增到游标以前的用户不会自动补入后续页；需要刷新目录才能重新遍历。

请求只接受 `limit` 和 `cursor`。未知、重复、非规范数值或空参数、GET 正文及非法 runtime
UUID 返回 400。不存在或无权管理的 runtime 统一返回 403；数据库故障返回 503，不把故障
伪装成空目录。成功和错误响应都使用已有 `no-store` 策略。

查看授权不会扩大可授予范围。非管理员 owner 仍只能委托自身范围内的权限，不能新授予 owner；
最后一个有效 owner 的撤销规则继续由现有写接口执行。目录中的 `grant_version` 也不会把
现有 PUT / DELETE 变为比较并交换操作；执行前应刷新，成功后重新读取当前记录。

隔离 PostgreSQL 测试覆盖分页、过期/撤销/接收者停用、当前管理权限、成员关系、设备证明、
跨组织及未批准 profile。HTTP 测试覆盖手机/Host 客户端边界、参数和错误处理。实际本机
npm DSH 0.2.1-rc.2 组合验证 owner 手机分页读取、完整 owner actions 的契约校验、撤销后
由另一 owner 查看旧记录，以及被撤销管理者无法再次读取。身份与模型仍使用本地夹具；未
修改 Android APP，也未进行真机、大负载或厂商推送配置验收。
