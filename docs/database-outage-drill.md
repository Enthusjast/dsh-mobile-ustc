# 小型数据库中断与恢复演练

该演练使用一个本机 npm DSH 0.2.1-rc.2 Host、两台实际 Go Relay 子进程及隔离 PostgreSQL。
身份、模型、手机协议对端和密钥配置为本地夹具。它验证短时数据库连接不可用时的失败关闭、
进程退出、显式重启与原命令对账；没有产生目标规模的负载。

```sh
REMOTE_TEST_DSH_BIN=/本机安装路径/dsh \
  python3 tools/integration/run_host_enrollment_terminal.py --database-outage \
  --output .local/database-outage-new-run.log
```

输出路径必须是仓库 `.local` 下的新文件。该模式选择独立的双节点 DSH 组合，与五分钟续期、
安装撤销、账号取消和其他组合分别运行。Go 业务和数据库不在此模式中修改 schema 或权限策略。

## 注入的故障

组合先完成实际登记、绑定、会话、审批、提问和撤权链路。之后由仍有权的 owner 手机在当前
原生会话发送一条消息，等待 `agent_queued` 和 REST 对账确认，并提前取得当前 DPoP nonce。

测试助手只接受 runner 创建的精确 Unix-socket DSN、`dsh_e2e` 用户、`postgres` 数据库及
`dsh-go-e2e-*` 目录。注入前校验目录真实路径与服务器报告的 `data_directory`；不接受通用
数据库 URL、其他数据库、带附加凭据的 DSN 或非绝对工具路径。拒绝边界有独立单元测试。

助手通过同一隔离集群的 `template1` 维护连接关闭目标数据库的新连接，并终止其现有 client
backends。它在 finally 中重新启用连接，即使中途验证失败也会尝试恢复；最外层 runner 继续
拥有整个临时集群的退出和删除。测试不会停止系统数据库集群，也不依赖修改服务端时钟。

故障期间发送带有效资源 token、当前 proof key 和提前取得 nonce 的 ticket 请求，必须返回
503 或因服务停止而无法连接。原手机连接须在五秒内关闭，两台 Go 子进程均须自行以退出码 1
结束，不能靠测试发送 kill 来完成。DSH 进程及本机 IPC 保持可用，原 runtime epoch 保留。

## 恢复与对账

重新启用数据库连接后，演练检查没有新增 ticket、原命令仍为 `agent_queued`，且原 Host
所有权记录仍在。它等待两台旧 consumer 的实际十秒租约自然到期，不删除路由、不清理
consumer，也不伪造过期时间。随后使用原 node ID、证书和配置显式重启 Relay，取得新 generation。

正常 Host 插件沿自身退避逻辑重新握手。演练要求新的连接 ID、相同 DSH epoch 和相同原生
会话映射。owner 手机取得新的 ticket/连接和 subscription/sync；原先已撤销的用户仍不能
取得 ticket。新快照里对应用户消息必须只有一条。再显式使用原 request ID 和原内容重试，
仍返回已有 `agent_queued` 事实，替换快照不能出现第二条消息。数据库 dump 同时排除测试正文。

该流程把数据库连接恢复、服务进程重启、Host 重连和手机重新同步分别验证。DSH 进程持续
运行，原生会话映射保持，服务端没有正文队列可供自动重放。命令已提交前的故障、未知结果及其他状态仍按
各自的命令日志和恢复规则处理，不能从本用例推断任意副作用的恰好一次执行。

## 证据范围

本地记录包含实际旧手机关闭耗时、数据库重新启用连接耗时，以及新握手/原请求对账完成耗时。
2026-10-30 的 `.local/database-outage-dsh-final.log` 记录：旧手机关闭 233 ms，数据库重新启用
连接 242 ms，包含自然租约等待、Relay 重启、Host/手机重连及原请求对账的全过程为 18550 ms。
整组测试通过，恢复后的已撤销 grant 仍拒绝 ticket，数据库 dump 不包含本次测试正文。
这些是单个隔离样本，不能证明生产 SLO、持续数据库不可用、磁盘损坏、主备切换、目标连接数
或重连风暴下的行为。学校身份、Android APP、真机和厂商推送均未参与本轮。

本演练保持原数据库内容和 deployment epoch；从备份恢复旧数据则必须执行
[数据库恢复隔离与新代次流程](database-recovery.md)。生产进程重启与数据库高可用仍由部署
运维负责，不能用本地夹具的显式重启当作生产 supervisor 已经配置或通过验收。
