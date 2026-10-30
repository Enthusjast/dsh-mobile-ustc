# Relay 控制通知优先队列

Relay 每条连接仍只有一个 WebSocket writer。它从两条有界 FIFO 中取帧：普通内容队列保留
16 帧、每帧最多 64 KiB；控制队列有独立的 8 帧、合计 128 KiB 预算。普通队列满时，
当前审批和撤权通知仍能申请控制预算；控制队列满时也不会占用普通内容的槽位。

控制类型使用固定白名单：`access.revoked`、`runtime.changed`、`server.draining`，以及
`approval.invalidate`、`approval.decision`、`approval.reference`、`approval.snapshot`、
`approval.registered`、`approval.result.ack`、`approval.details.get`、`approval.unsubscribed`。
完整审批上下文及其 fragment、会话快照/增量、正文命令和命令回执走普通队列。
类型归类发生在内部消息已序列化之后；协议角色、scope、当前权限、签名和绑定检查继续由
原业务处理器执行，队列优先级本身不产生授权。

存在普通积压时，writer 最多连续取四条控制帧，再取一条普通帧，然后继续优先检查控制队列。
两条队列各自保持先入先出；它们之间按该规则调度。选择下一帧与入队计数共用一个短锁，
锁不覆盖 socket I/O、数据库查询或握手的 `beforeWrite`。writer 等待有限的唤醒信号，
不会轮询空队列。已取出的帧仍由该 writer 完成，优先级不能抢占正在进行的网络写入。

原始单帧限制、五秒网络写入期限及慢消费者失败路径继续适用。达到任一队列预算时返回原有
queue-full 错误，由调用者执行对应关闭、重同步或失败处理。撤权和 Host 审批失效通知仍受
原来的短通知期限约束；无法投递时关闭连接，执行许可仍按原有租约到期，不能因为已经进入
控制队列就宣称 Host 已消费撤权或停止了已开始的外部副作用。

## 取消、关闭与指标

入队前已经取消的调用被拒绝。调用在入队后取消等待时，帧仍可能已经发送或随后发送，
其字节继续计入队列直到实际 dequeue。调用方不能据此断言命令未执行或自动重放。
连接停止时，先阻止新入队，再释放两条队列的帧及统计；等待者收到连接结束。
当前 writer 持有的帧独立计入 inflight，直到实际完成或失败，不混入被释放的等待预算。
`hello.ok` 的路由发布仍在其已取得 writer 槽位后执行，后续帧不能抢在它之前使用该路由。

现有 `relay_queued_messages`、`relay_queued_bytes`、最大排队字节和队列分布 gauge 合计两条
等待队列，`relay_inflight_bytes` 独立统计当前帧。`relay_rejected_sends_total{reason="full"}`
覆盖帧数或字节预算耗尽；它不包含正文、帧类型或资源 ID 标签。容量上限描述应用 payload
缓冲，不包括 TLS/TCP、代理 tunnel 的在途字节或对端缓冲。

## 验证

修复前，真实 WebSocket 回归在普通队列填满后稳定拒绝 `approval.invalidate`。修复后该通知
在当前写入完成后先于普通积压投递。其他小型用例覆盖控制 FIFO、四比一发送公平性、普通
溢出、控制帧数和字节上限、双队列关闭释放及类型白名单。既有队列计数、握手路由就绪、
慢关闭连接隔离、审批和撤权回归继续验证。

完整 Go race/隔离 PostgreSQL、本机 npm DSH `0.2.1-rc.2` 双节点正常链路及单独的数据库
失联恢复夹具分别验证消息、审批、挂起批准失效和持久结果对账。身份和模型使用本地夹具。
这些是功能与失败边界证据；没有进行大负载、目标延迟 SLO、Android APP、真机或厂商通道验收。
本次不需要协议或数据库迁移。
