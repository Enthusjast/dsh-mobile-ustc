# 原生 DSH 的 Relay 崩溃与恢复演练

该模式使用本机 npm DSH `0.2.1-rc.2`、两个实际 Go Relay 子进程和一个隔离 PostgreSQL。
Host 连到 A，手机经 B 的私有 mTLS 路由接入 A。演练只对本次创建的 A 子进程句柄发送
SIGKILL，保留数据库、B、原生 DSH 和本机 IPC；不接受外部 PID、不修改系统数据库或进程。

```sh
REMOTE_TEST_DSH_BIN=/本机安装路径/dsh \
  python3 tools/integration/run_host_enrollment_terminal.py --relay-crash \
  --output .local/native-relay-crash-new-run.log
```

输出必须是仓库 `.local` 下尚不存在的文件。底层 runner 的对应参数是
`--cross-node --dsh-only --relay-crash`，与数据库中断、自然换证、安装撤销及账号退休分别
运行。参数校验在打开日志、终端或数据库前拒绝组合；每次调用显式激活模式，继承的
`REMOTE_TEST_RELAY_CRASH` 会先被清除，普通运行不注入故障。

## 故障与检查

组合先完成正常的登记、密钥证明、聊天、读取、提问、签名审批及撤权链路。随后仍有权限的
owner 手机发送一条新原生消息，等待 `agent_queued` 和独立 HTTP 对账，预先签发一份尚未
使用的手机 ticket，并记录原生会话、Host 连接、节点 generation 与路由。

强制终止 A 后，旧手机连接必须在五秒内关闭。测试确认旧 runtime/route 数据仍在，不能用
优雅退出、删除路由、清空 consumer 或伪造租约到期来通过。经 B 连接这个尚未恢复的 owner
必须返回 503，不能制造本地业务连接；失败的私有传输不消费手机 ticket。B 的 HTTP 命令
对账仍返回原 `agent_queued` 事实。

等待 A 的真实十秒 consumer 租约自然到期，然后用相同节点 ID、证书和配置显式重启 A。
等待期间持续检查 B 子进程、数据库就绪及其原 generation/有效租约；DSH 进程保持存活。
新 A 必须取得新 generation，正常 Host 插件沿原退避流程重新完成密钥证明，取得新的连接
ID，同时保留原 DSH runtime epoch、原生会话映射和持久命令事实。

手机使用新的 ticket 和连接重新接入。旧 subscription/sync 的历史页请求被拒绝，新的
快照必须使用新的 subscription/sync，并只包含一条原消息。再用原 request ID 和相同正文
显式重试，仍返回原 `agent_queued`；随后新 request ID 的消息也应正常进入真实 DSH。
替换快照中的原消息和新消息各只有一条，服务端原请求只有一行元数据。新数据库 dump
继续排除这两条正文及未消费 ticket 的原始秘密；此前已撤销的用户仍不能取得 ticket。

## 证据与边界

2026-10-31 的本机样本中，旧手机在 30 ms 内关闭；包含自然租约等待、显式重启、Host
重连、手机换快照和原请求对账的全过程约 18.8 秒。整组实际组合约 41.6 秒。记录保存在
`.local/native-relay-crash-reviewed-first.log`，没有提交私有日志。

TypeScript 检查、contract check、Host 测试及 Go/PostgreSQL 路由 race 回归分别验证；普通
双节点 dsh 组合还以继承故障环境变量的方式运行，确认只有显式参数才能触发新模式。

本演练恢复的是同一个节点身份下的新进程，原 Host 仍连接其原入口。它与
[协议夹具的 owner 迁移/接管](relay-routing.md)及[原生数据库失联恢复](database-outage-drill.md)
共同补充不同故障证据，不证明生产 supervisor、入口负载均衡或跨节点自动迁移已配置。
收到明确原生回执后的重试结果也不代表任意外部副作用的恰好一次执行。

身份和模型为本地夹具；本轮不修改 Android APP，不涉及学校生产、真机、大负载或厂商
推送配置，也不以单个样本声明生产 SLO、RPO/RTO 或重连风暴能力。
