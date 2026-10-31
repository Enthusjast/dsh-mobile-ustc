# Host journal 的 WAL 写入与同步故障

本地 Linux 测试在独立 Node 子进程中加载一个测试专用 I/O interposer，向实际 SQLite VFS
返回 WAL 写入 `ENOSPC`、WAL 同步 `EIO` 或 checkpoint 主库同步 `EIO`。它补充
[主库容量 SQLITE_FULL](host-journal-capacity.md)；不修改生产 journal 方法，也不把物理
磁盘填满，不向已有进程注入代码。

## 注入范围

父测试只创建、编译和启动本次拥有的临时库及子进程。库没有生产配置入口。只有 canonical
路径、当前用户拥有、0700 的 `dsh-journal-io-*` 根目录才启用；目标固定为其
`state/commands.sqlite` 或 `state/commands.sqlite-wal`，不接受任意目标文件名。

库通过 `/proc/self/fd` 核对真实打开的对象，要求普通文件、当前用户、单硬链接及私有权限。
控制文件也必须为私有普通文件，不跟随符号链接。错误只在显式控制文件存在且操作/目标
精确匹配时返回；同进程其他文件和原生 DSH 日志正常读写。证据文件只追加 w/s/m 字节，
不包含路径、正文、nonce、token 或密钥。父测试结束后移除全部临时文件。

错误前缀、非私有目录和符号链接根目录的负面测试确认注入保持停用；正常用例在激活期间
同时写入一个非目标文件，确认没有影响它。非 Linux 或缺少 C 编译器时该专用测试明确
skip，不声称对应平台已验收。

## 故障点与结果

| 故障点 | 本地样本结果 |
| --- | --- |
| 接收命令的 WAL 写入 ENOSPC | 没有 host_accepted 回执，没有原生入队；恢复后原 ID 可执行一次 |
| dispatching 的 WAL 同步 EIO | 只有已提交 host_accepted，没有进入原生操作 |
| 原生已入队后的结果 WAL 写入 ENOSPC | 未发 agent_queued，原生消息已存在；重开后保留 dispatching 并按原 ID 去重 |
| 原生已入队后的结果 WAL 同步 EIO | 未发持久成功回执，恢复/重试没有产生第二条原生消息 |
| checkpoint 主库同步 EIO | 先前已提交 agent_queued 记录仍能解密、通过 integrity_check 并对账 |
| 审批决定 WAL 写入 ENOSPC | 当前 owner 进入存储失败状态，没有可用许可 |
| guard 消费 WAL 同步 EIO | guard 不返回，执行次数为零，重开不恢复旧执行许可 |

每个样本要求发生真实的定向 syscall 故障，保留错误计数，检查阶段回执、原生事件、重开
后的 SQLite 完整性及原 device/request ID 去重。样本观察到 SQLITE_FULL 基码 13 和
SQLITE_IOERR_FSYNC 扩展码 1034；诊断只记录这些固定元数据及状态。

同步失败不等价于“事务一定没有提交”，也不等价于“原生操作没有发生”。测试允许恢复
时看到合法的已提交/未知事实，要求失败时不发布未经确认的持久回执；明确 unknown 不
自动重放，其余消息恢复沿既有原生去重规则。审批失败会关闭本 owner 的授权，旧 boot
的请求重开后只能失效或保持 unknown，不能从一次 I/O 错误推断工具未执行。

## 验证命令与边界

```sh
node_modules/.bin/tsx --test host/remote-control/tests/journal-io-fault.test.ts
```

完整 `npm run verify` 及本机 npm DSH `0.2.1-rc.2` 的正常双节点终端组合分别回归。
这些是定向 VFS/syscall 错误传播证据，不是物理磁盘耗尽、介质损坏、掉电、真实 fsync
持久性或 Windows/macOS 文件系统验收。它们也不覆盖全部可能的部分写入和存储重排序。
本轮不修改 Android APP，不尝试其他运行时，不执行大负载、真机或厂商推送配置。
