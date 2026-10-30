# 会话授权下的模型目录

双方协商 `session.read.v1` 和 `session.models.v1` 后，手机在已取得快照的会话订阅上查询：

```json
{
  "v": 1,
  "type": "session.models.get",
  "request_id": "66666666-6666-4666-8666-666666666666",
  "runtime_id": "33333333-3333-4333-8333-333333333333",
  "runtime_epoch": "44444444-4444-4444-8444-444444444444",
  "session_id": "55555555-5555-4555-8555-555555555555",
  "subscription_id": "99999999-9999-4999-8999-999999999999",
  "payload": { "sync_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "limit": 25 }
}
```

`limit` 必填，范围 1–50。后续页带上原样返回的 `cursor`；不接受空值、null 或其他选择器。
响应 `session.models.result` 保留原请求、订阅、会话、epoch 和 `sync_id`，payload 包含
`items`、`next_cursor` 和 `unavailable_provider_count`。每项只有 provider / model 的
`{id,label}` 及 `reasoning_efforts: [{id,label}]`。部分原生 provider 查询失败时，计数明确表示
目录不完整，但不输出 provider 错误正文、配置、URL、Key、全局默认选择、描述或其他扩展字段。
标识和标签属于不可信展示数据；客户端必须按普通文本渲染。

查询要求 ticket 和当前 grant 同时具备 `session.read`、`session.model.select` 及该会话/工作区
范围。目录、聊天或 grant 管理权限本身不补授这两个动作。每次请求和响应都重新验证当前账号、
手机密钥、成员关系、grant 版本/期限、资源归属及当前 Host 连接。订阅必须已完成快照且 sync
一致；另一 socket、旧 epoch、旧订阅或已撤销权限不能借原查询读取模型信息。

## 分页和资源边界

Host 按 provider ID、model ID 的 UTF-16 顺序排列当前可用目录。游标绑定 runtime、epoch、
会话、sync、目录摘要和位置，不是授权凭据。每页重新取得原生目录；目录展示字段或可用数量
变化时返回 `protocol.resync_required`，客户端应从第一页重新获取。它不是持久历史快照，
也不承诺列出的模型在稍后仍可用；选择命令仍重新检查原生目录。

每页最多 50 项和 32 KiB，包括 Relay 的 JSON 转义成本；空间不足时减少本页项目数并返回
后续游标，不静默丢弃后续项。每项最多 32 个 reasoning effort。ID 长度沿用模型选择限制，
展示标签最多 256 个 UTF-16 代码单元且不含 ASCII 控制符。投影后的完整目录上限为 128 个
可用 provider、8192 个模型、4 MiB；失败 provider 数量另限制为最多 128。
重复 ID、无效元数据或单项超限失败，不返回伪造的完整目录。

每个订阅最多两条在途模型查询，复用已有读取速率与发送队列限制。Relay 为每次转发生成独立
关联 ID，响应时还原手机原 ID；五秒超时释放路由，迟到响应被丢弃，不会匹配后来复用的请求。
取消订阅、断连或 Host 替换也清理路由与定时器。

Host 查询有三秒等待期限，并随订阅取消。针对同一个原生 controller，正在进行的目录读取由
调用者共享，直至原生调用实际结束。provider 忽略取消时仍只占用这一条读取，重试和 Relay
重连不会再启动同 controller 的重复读取；取消只结束调用方等待，不能宣称强制终止 provider。
没有磁盘或控制面目录缓存。模型目录查询不创建命令记录或触发 Agent / 模型选择。

错误使用 `session.models.error` 和固定 code，并保留查询的 sync；被拒绝的外层请求仍使用
既有 `error`。目录变化、离线、大小限制和权限失败应显示对应状态，不能当作成功的空目录。

## 接入与证据

本功能无新增数据库迁移；[选择命令](session-model-selection.md)仍要求既有迁移 037。
普通 Host 自动提供新 capability，旧 peers 不协商它时继续使用原协议。Android 消费和界面
接入保留为单独工作；本轮未修改或测试 Android APP。

小型测试覆盖完整分页、Unicode/转义字节预算、跨资源游标、目录变化、配置/默认值/错误脱敏、
并发共享、忽略取消的 provider、订阅取消与迟到结果。Go socket 测试覆盖双端 capability、
显式授权、同步身份、响应前撤权、在途预算、真实五秒超时与旧响应不能认领新路由；PostgreSQL
用例验证移除选择动作后原 ticket 的读取也被拒绝。

实际 npm DSH `0.2.1-rc.2`、双节点 Go 和隔离 PostgreSQL 组合以每页一项读取两个原生模型，
核对无重复、当前 sync 和不可用数量，再执行原生模型选择；数据库 dump 不含仅在目录中出现的
备用模型标识。身份和模型仍为本地夹具，未进行学校真实配置、真机、大负载或厂商通道验收。
