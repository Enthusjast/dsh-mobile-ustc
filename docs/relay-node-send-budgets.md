# Relay 节点发送字节预算

Relay 在原有单连接 FIFO 和控制优先队列之外，为整个节点的待发送 payload 增加共享字节
预算。所有已升级连接共用预算，包含握手、Host 和手机连接；消息先按现有固定白名单归类，
普通内容和控制通知分别申请额度。普通内容耗尽时，控制通知仍可使用自己的保留额度。

默认普通额度 256 MiB、控制额度 16 MiB。每条连接仍最多等待 16 条普通帧、8 条控制帧，
控制等待字节仍不超过 128 KiB，单帧仍为 64 KiB。writer 延续四条控制帧后让普通帧取得
进展的规则。任一连接或节点额度不足时沿用 queue-full，由原调用者执行重同步、关闭或
命令未知结果对账，不静默丢帧，也不根据取消等待自动重放正文。

## 配置

按 [`deploy/relay-queue-limits.example.json`](../deploy/relay-queue-limits.example.json)
保存当前用户拥有、仅所有者可读写的普通文件，例如 `0600`。使用启动配置：

```sh
export REMOTE_RELAY_QUEUE_LIMITS_FILE=/受控目录/node-queues.json
.local/remote queue-limits describe
.local/remote queue-limits describe --limits-file /受控目录/node-queues.json
```

省略文件仍启用默认预算。JSON 必须包含 `v`、`ordinary_bytes` 和 `control_bytes` 三个整数，
版本固定为 1；拒绝遗漏、null、重复字段、大小写别名、额外字段或超过 4 KiB 的文件。
普通额度范围为 64 KiB–8 GiB；控制额度为 64 KiB–256 MiB，且不超过普通额度。
无效配置在业务监听前失败关闭，不把配置内容、路径或凭据写入固定错误消息。

`describe` 只显示配置，不连接数据库、不启动服务，也不报告虚构的运行中占用。预算只在
启动时配置一次，接入过连接后即使已经全部断开也不能重置；旧 writer 可能仍持有数据。
调整需排空并重启相应节点，各节点可以按自身内存使用不同设置。本机字节预算与现有
PostgreSQL 共享连接配额、命令速率预算分别执行，无需新协议能力或数据库迁移。

## 占用与释放

序列化后的完整信封在入队时原子申请字节，连接队列满时撤销本次申请。额度一直保留到
真正写入成功或失败；writer 从队列取走帧不会提前归还额度。取消调用者的等待也不删除
已经入队的帧，不能据此断言对端未收到或未执行。

停止连接会释放仍在两条等待队列中的帧，writer 当前持有的帧继续计入占用，直到该次写入
结束。即使连接已从活动路由移除，节点仍计入这个正在退出的 writer，避免关闭或重连抢先
复用同一批内存额度。握手的路由仍只在 `hello.ok` 获得 writer 槽位后发布。

字节预算度量应用保留的已编码 payload；Go 对象、序列化临时分配、GC、TLS/TCP、代理
tunnel 和对端缓冲各有自己的生命周期，不把本指标解释为进程 RSS 或完整内存上限。

## 指标与验证

私有指标新增 `relay_send_reserved_bytes{lane}` 和 `relay_send_limit_bytes{lane}`，共同
前缀仍为 `dsh_remote_`，lane 只取 ordinary/control。前者合计等待和正在写入的 payload，
后者为本节点配置；均不使用用户、资源、帧类型或正文标签。原来的角色队列与 inflight
指标继续区分两阶段，`relay_rejected_sends_total{reason="full"}` 同时覆盖连接和节点不足。

真实 WebSocket 小型测试覆盖另一连接不能越过节点额度、writer 与正在退出的连接继续
占用、控制保留、入队后取消、双队列清理、写入失败后的容量重用，以及并发申请不超支。
配置测试覆盖严格字段、私有文件、离线命令和启动后不能重置。双生产进程 TLS/PostgreSQL
夹具验证一节点自定义预算、另一节点保留默认值，正常密钥证明/目录通信可用，无效文件在
接入前被拒绝。完整 Go race 与本机 npm DSH `0.2.1-rc.2` 双节点终端链路另行回归。

身份和模型为本地夹具。本轮不修改 Android APP，不运行大负载、真机或厂商推送配置测试；
默认数值是资源保护设置，尚未作为生产负载或 SLO 的验收结论。
