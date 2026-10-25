# Relay 关闭连接与回执隔离

2026-10-26 的文件回归复现了一项已有问题：同一设备的第二条连接发送不支持的帧，收到错误后停止读取。该连接还在关闭握手中，却继续出现在回执接收列表。Host 广播回执先选中它时，另一条健康连接也会等待，导致到期附件对账测试超时。

锁定的 WebSocket 库在一次 Close 已经开始时，会让并发 CloseNow 等待现有关闭流程。因此原来的 250 ms 定时 CloseNow 不能保证打断一个没有应答的握手；只增加测试等待时间会保留这项投递问题。

Relay 现在通过统一的策略关闭入口先标记连接 closing，并停止其发送队列，立即阻止新路由和广播选择。握手仍发送原有关闭状态；超过短暂等待窗口时，关闭升级时捕获的底层 TCP 连接。TLS 连接在强制关闭时也直接终止底层传输，不额外等待 TLS 关闭通知。捕获句柄只保留 transport，不保留 HTTP ResponseWriter 或原始凭据请求。

回执发送遇到已结束的接收方时也会立即移除其路由资格并终止传输，避免再次等待正在进行的 WebSocket Close。命令持久状态、设备 / scope 授权与原请求身份不变；客户端仍可通过原状态接口对账。

`closing_test.go` 用真实 WebSocket 和同一设备的两条连接验证：违规方不再读取关闭帧时，健康方仍收到准确的原命令回执；违规连接在短暂等待后从活动连接中释放。该回归在修复前稳定失败。实际 TLS / PostgreSQL 的到期文件对账在修复前多次失败，修复后连续十五轮（含支持 / 不支持 Host 对账能力的两种场景）全部通过。

本机记录为 `.local/relay-close-before-fix.log`、`.local/relay-close-after-fix.log`、`.local/file-export-reconcile-repeat.log` 和 `.local/file-export-reconcile-repeat-after.log`。这些是关闭和回执隔离证据，不是目标负载下的延迟或容量验收。

随后 `npm run test:remote-kotlin` 的完整隔离 PostgreSQL / Go race / Kotlin / 真实 npm DSH 回归也已通过，含原有文件准入、对象到期对账、审批、提问、归档、持久状态与撤权。记录为 `.local/file-export-runtime-kotlin-chain-final.log`。
