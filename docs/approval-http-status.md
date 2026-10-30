# HTTP 审批状态核对

`GET /v1/approvals/{id}` 返回一个已知审批的控制面状态。手机无需先建立 WSS 或取得 ticket，
Host 离线时也能核对已记录的结果。接口只读，不恢复回调、修改状态或签发执行许可。

```http
GET /v1/approvals/<approval UUID>
Authorization: DPoP <resource-access-token>
DPoP: <fresh-proof>
```

调用者必须是活跃账号，使用当前登记且未撤销的手机 DPoP 密钥，仍属于目标组织，并拥有
该 runtime 当前未过期/撤销的 owner grant。actions 必须同时包含 `approval.decide` 和
`session.read`，且 sessions 或 workspaces 范围覆盖原审批会话/工作区。operator、仅有
读取或批准动作、组织 admin 或安装所有权本身均不足以访问。Host OAuth 客户端不能调用
此手机路由。审批 UUID 仅用于定位，不能当作权限凭据。

服务端在同一事务中解析已验证的 issuer/subject、设备和公钥指纹，再进入与 WSS
`approval.status.get` 相同的当前 owner 读取策略。事务核对设备/授权版本和完整资源归属链，
持锁直到提交，并在等待审批行锁后按数据库当前时间复核 grant 到期。每个 HTTP 请求使用
当前 grant，之前的读取、旧 ticket 或旧连接不会保留已经失去的权限；读取也不会扩大旧
WSS 连接的范围或延长其寿命。

响应 `data` 沿用 `ApprovalStatus`，只有审批/runtime/epoch/session/execution UUID、binding
摘要、控制状态、原截止时间及已记录的决定/决定摘要、Host 状态和最终 outcome。没有完整
参数、原生会话/call ID、nonce、原始 JWS、审批详情、公私钥或模型凭据。

`allowed` 或 Host `consumed` 表示许可已经消费，不能显示为工具执行成功；只有 Host
`settled` 携带 `succeeded`、`failed` 或 `cancelled` 执行结果。`outcome_unknown` 表示尚无
足够持久事实，不能当作未执行后自动重做。读取保留真实记录，不把过期 pending 或未知结果
伪造成已完成。任何后续决定都须重新核对当前交互、期限、签名和执行许可。

状态元数据不要求 Host 的原连接仍在线；Host、安装、runtime 和调用者的正常授权资格仍需
有效。资源被撤销后拒绝访问，服务端保留的审计历史按独立管理流程处理。完整审批详情仍需
原在线连接及明确的 WSS 请求；状态查询不会代理详情或令历史审批再次执行。

该 GET 路由可独立于可选签名配置读取已存在的绑定元数据。POST 决定和执行许可继续受
签名配置及既有在线授权流程约束。旧的未绑定 metadata_version=0 行不会因此取得可读资格。
不接受正文或 query 选择器；非法格式返回 400，不存在或无权访问统一返回 403，数据库故障
返回 503。响应使用 `no-store`。接口不产生新 ticket、审计或 outbox，也没有新增数据库迁移。

## 本地验证

隔离 PostgreSQL 测试覆盖无 ticket/离线状态、HTTP 与 WSS 结果一致、成功结果保留、当前
session/workspace 范围、旧 ticket 不继承新版本、错误用户/密钥/设备、owner/动作要求、
组织和资源撤销，以及等待锁期间到期。HTTP 测试核对 JWT/DPoP 身份与当前设备传入仓库、
Host 客户端拒绝、正文/选择器拒绝及无结果泄露的错误响应。

本机 npm DSH 0.2.1-rc.2 联合夹具在 owner 手机尚无 WSS 时读取真实待审批和最终结果；
账号取消场景在 Host 断开且手机 socket 关闭后继续通过 HTTP 核对最终状态。数据库故障
恢复场景先以 HTTP 读取补报结果，再建立新 WSS，要求两种状态完全一致。身份、模型和
手机对端均为本地夹具；学校身份、Android APP、真机、大负载和厂商推送未作为本轮验收。
