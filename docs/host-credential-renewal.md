# 主机凭据自然到期与重连测试

可显式运行 `--host-renewal`，用真实 Go 服务、隔离 PostgreSQL 和本机 npm DSH
`0.2.1-rc.2` 等待一轮正常五分钟主机凭据自然到期。测试不缩短服务端期限，不推进进程时钟，
也不通过改数据库到期字段或主动断开连接来触发换证。默认联合测试不等待这五分钟。

```sh
REMOTE_TEST_DSH_BIN=/本机安装路径/dsh \
  python3 tools/integration/run_remote_dsh.py --dsh-only --cross-node --host-renewal
```

需要同时验证终端配对时，使用临时 PTY 包装器；输出路径必须是仓库 `.local` 下尚不存在的文件：

```sh
REMOTE_TEST_DSH_BIN=/本机安装路径/dsh \
  python3 tools/integration/run_host_enrollment_terminal.py --renewal \
  --output .local/host-renewal-new-run.log
```

依赖和隔离规则见[Go/DSH 联合测试说明](go-dsh-integration.md)。该模式只选择原生 DSH 组合，
不启动 Android、Kotlin 或容量测试；每次运行都显式启用，不从继承的环境变量自动激活。

测试先创建一条原生会话并持久提交带固定 request ID 的消息，然后保持原 Host 连接。到期前，
本地 issuer 夹具向同一账号/安装密钥提供新的资源 JWT，原 Host 租约仍须保持有效。旧五分钟
期限结束后，普通插件应重新读取资源来源、校验 JWT、完成新的安装 challenge、获取主机凭据，
再通过新连接握手接入。

检查包括：只出现一次预期的插件换证；旧凭据 getter 拒绝过期访问；原生 runtime epoch 和会话
映射保持不变；原消息 ID 重试返回持久结果；随后手机协议夹具重新读取快照，只出现一条对应
用户消息。测试继续运行通常的聊天、审批和撤权链路，并确认一份仍未到期的缓存连接秘密在
所有者被暂停后也被服务端拒绝。所有测试资源 token、连接秘密和消息标记都纳入数据库与指标
的排除检查。

这里的资源来源更新由本地 issuer 和原子替换的私有夹具文件完成，不代表学校 token endpoint
刷新或生产登录适配器已验收。一轮自然换证也不能替代长时间连续运行、手机续期、目标负载、
生产网络与密钥库验收。

2026-10-30 的本机运行使用安装的 DSH CLI `0.2.1-rc.2`、双节点生产 Go 入口及隔离 PostgreSQL，
在 300968 ms 的观察后完成一轮自然换证，整段组合约 324.6 秒。普通联合回归、类型检查和
Python 编译检查也通过。本机证据为 `.local/host-natural-renewal-final.log`；日志未纳入提交。
