# 远程会话模型选择

Host 和手机同时协商 `command.relay.v1`、`session.model.select.v1` 后，可以提交：

```json
{
  "v": 1,
  "type": "session.model.select",
  "request_id": "66666666-6666-4666-8666-666666666666",
  "runtime_id": "33333333-3333-4333-8333-333333333333",
  "runtime_epoch": "44444444-4444-4444-8444-444444444444",
  "session_id": "55555555-5555-4555-8555-555555555555",
  "payload": { "provider": "fixture", "model": "offline" }
}
```

`reasoning_effort` 可选，存在时必须是非空字符串。provider / model 最长 128 个 UTF-16
代码单元，effort 最长 64 个；这些值是原生目录标识，payload 不提供 URL、API key 或其他配置字段。
实际可用性由 Host 当前的 `modelCatalog` 核对，不能通过调用者提供新的 provider 或模型配置。
手机协议客户端可先读取[会话授权下的分页模型目录](session-model-catalog.md)，再提交选择。
本机 `model.catalog` 调试接口仍可使用；Android 界面接入为单独工作。

## 授权与去重

ticket 和当前 grant 都必须显式包含 `session.model.select`，目标会话或其工作区必须在范围内。
共同[命令准入期限检查](command-admission-expiry.md)在资源锁等待后与提交前重新核对 grant
到期时间，模型选择不能凭等待前仍有效的授权继续准入。
owner / operator 可以被授予该动作，viewer 不允许；普通读、聊天、中断和管理权限均不隐含它。
迁移不会扩大现有 grant 或 ticket。新绑定产生的 owner grant 包含新动作；已有安装须由合格
管理者显式调整授权，再取得新 ticket。每次提交，包括相同请求重试，都重新核对当前账号、
设备密钥版本、成员关系、安装、runtime、grant 版本/期限、范围和会话状态。

Relay 使用当前 Host 连接验证 runtime epoch。JCS 摘要覆盖类型、原 epoch、会话 UUID 和
完整 payload；服务端补充真实用户、设备和摘要后转发。它与其他命令共用设备内 request ID
命名空间，改变 payload、动作、目标或 epoch 不能重用原请求。参数只在转发期间使用，
控制面保存动作、摘要、ID 和状态，不保存模型选择正文、设置或凭据。

## 原生执行与持久性

Host 先在受保护命令日志记录 `host_accepted`，按会话串行执行。DSH 适配器重新核对当前
原生模型目录及 reasoning effort，使用当前进程的 `sessionController.selectModel`，随后
等待该会话的持久化检查点，最后记录和返回 `settled`。本地检查点不可用或失败时保留
`outcome_unknown`。无效目录项确定拒绝，不关闭其他订阅。

原生 DSH 将选择写入会话 `model/selection` 日志，并异步保存 profile 默认模型。这里的
`settled` 证明会话检查点完成，不证明那个独立的默认设置后台写入已完成，也不承诺撤销已开始
使用原模型的调用。它遵循 DSH 自身的下一步选择规则，不取消 Agent 或重新启动 SDK 进程。
会话内容投影继续把模型配置事件转成 cursor，不因本功能导出完整原生事件。

相同已完成请求从 Host 日志重建回执，不再调用原生接口。中途崩溃的 dispatching 选择可能已
写入原生日志，保留未知结果而不自动重选。操作受 epoch 约束；恢复旧请求时不能改成新 epoch
强行重放。旧版本机模型选择日志没有该 epoch 摘要，升级后冲突需保留并人工对账，不自动改写。

## 部署与验证

先应用迁移 `037_model_selection`，再部署理解新动作的服务和 Host。迁移扩展命令动作约束，
不修改旧命令、授权或正文。down 在存在新动作证据时拒绝并回滚，不能删除或重分类命令来回退。
旧 peers 未协商该 capability 时拒绝新操作，其余已协商操作继续按原协议运行。

Go 测试覆盖双端 capability、显式动作与资源、旧 epoch、错误参数、已完成重试不转发、
当前授权变化、动作/摘要冲突、viewer 隔离和迁移保护。Unicode / 转义 golden 同时校验 Go、
TypeScript 摘要及 JSON Schema。Host 原生 Loader 测试验证选择事件的 checkpoint、日志重开
后重建回执、无效模型/effort 拒绝、失败检查点保持未知和取消后不进入原生选择。

双节点 Go / 隔离 PostgreSQL / 本机 npm DSH `0.2.1-rc.2` 组合选择已登记的离线模型，核对
成功状态、原请求重试、内容冲突、缺失模型拒绝以及真实 controller 只被调用一次。身份和模型
使用本地夹具；本次没有 Android APP、真机、大负载或厂商推送配置改动。
