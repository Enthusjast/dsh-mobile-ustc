# Host 连接队列、断线与原命令对账

Host 接收队列同时限制为最多 32 个待处理帧、512 KiB 原始编码字节，单帧仍最多 64 KiB。
限制在入队之前检查，出队时释放字节预算。这个预算只覆盖 Host 入站待处理帧，不代表
WebSocket 实现缓冲、原生会话、文件、订阅队列或进程总内存已经完成容量验收。

读取队列的终止条件包括 transport close/error、binary/超长帧、队列预算超限、读取超时和
连接取消。终止立即清空待处理帧，拒绝当前/后续读取，取消该连接的 signal 并终止 socket；
后续 message 事件不能重新向已结束队列追加。已解析但尚未处理的帧也要再次检查生命周期。
server.draining 一经处理立即退役该连接，不再接受其后排队的命令。

旧实现只保存队列错误，`next()` 却先出队再检查错误；message listener 在队列结束后仍追加，
在途 dispatch 还不会因 socket close 收到取消。慢处理可能让队列继续增长，并把旧帧送到原生
运行时。现在终止路径优先于缓存帧，断线/预算超限不会等待慢 dispatch 后才通知取消。

接收循环同时将当前 handler 的等待绑定到连接 signal。原生或外部实现即使暂不响应取消，
也不能阻塞连接退役与重新握手。握手 signer 的等待同样受连接取消约束；晚到的签名或命令
回执仍只属于旧 socket，不会转投新连接。这里中断的是网络 owner 的等待；**不承诺终止
不配合的原生调用、撤销已发生的外部副作用或恢复未提交日志**。

重新接入仍经过退避、`HostCredentialProvider.acquire(signal)` 和当前安装密钥的全新 challenge
证明，重新发布 catalog。旧入站队列和旧订阅不会迁移，手机需要新的 subscription/sync。
纯连接重建不改变仍在运行的 DSH runtime epoch，也不创建新 Agent 或自动重发命令。

连接丢失可能发生在本地 journal 提交、原生准入或回执之间。已有本地记录和副作用不能被
“连接取消”当成未执行。原 request_id 的显式重试继续沿既有 journal 去重/原生对账规则：
已入队的原消息恢复 agent_queued，不再调用 prompt；不明确的结果保留 unknown。
新连接收到晚回执也不能据此让旧调用重新取得执行授权。

## 小型夹具证据

三个真实 WebSocket 回归在修复前失败：第一条 dispatch 等待时，主动关闭 transport、
发送 34 个小帧，或发送 10 个约 60 KiB 帧，均未及时取消原连接。修复后它们验证在途
signal 取消、缓存命令丢弃、第二次获取凭据、新 connection/challenge 以及只接收显式新操作。
这些是队列边界用例，不是大负载或重连风暴测试。

额外用例覆盖 signer 不返回时关闭、dispatch 忽略取消时仍可重连、晚签名/回执不能跨 socket，
以及 draining 后的尾随命令丢弃。实际 npm DSH 0.2.1-rc.2 Loader 组合主动断开已入队命令的
Host transport，检查新的证明/catalog、相同运行代次、没有自动重发，随后显式重试原 ID：
回执恢复 agent_queued，新 sync 的原生日志仍只有一条对应 user/message。

身份、模型和 Relay peer 是本地夹具。普通生产 Go/PostgreSQL 双节点 DSH 链路另外验证兼容性。
没有使用 TokenWorks，没有进行大负载、真机或厂商推送配置；所有旧未知结果仍需持久事实对账。
