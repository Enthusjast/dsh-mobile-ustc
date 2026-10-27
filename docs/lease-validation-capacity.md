# 批量租约的精确连接查询

原实现对每个 lease 执行相关的授权子查询，从用户 / 组织关联到主机集合。在同一组织 1500 个独立 runtime 的真实 TLS 负载中，3000 条连接已全部完成准入，但批量检查耗尽了原两秒期限。控制 worker 按既有规则关闭全部采样连接，订阅准备失败。失败记录为 `.local/capacity-baseline-3000.log` 与该批次的 `service.log`；其中 leases unavailable=true 和两个 PostgreSQL `57014` 保持为实际失败证据。

现在一次 materialized 输入解析后，从 lease 的精确 runtime UUID 开始集合连接，设备与安装实例分支分别检查后合并。仍每批最多 128，仍每秒运行独立检查，仍使用整个 worker 的两秒期限；任何权威检查失败仍关闭本次采样连接。

| 分支 | 保留的检查 |
| --- | --- |
| 手机 | 活跃用户、设备 / 密钥版本 / thumbprint、组织成员、活跃 host / installation / runtime、登记批准、精确 grant 版本 / 撤销 / 期限 / scope，以及每个 workspace / session 的 runtime 所属 |
| 主机 | 活跃 host / installation / runtime、登记批准、installation ID / key version、runtime epoch / connection ID / connection key version |

没有新增授权缓存。前台命令、回执和每个内容帧继续执行各自的数据库授权。Scope 数组形状错误会判为该连接无效；不会被转换为通配权限。缺失资源和无关 lease 不会污染同批有效结果。

2026-10-27 的 18 组 PostgreSQL 状态变更回归通过，包括有效样例、暂停用户、设备撤销 / 轮换、成员移除、grant 版本 / 撤销 / 期限 / scope、host / installation / runtime 状态、安装密钥轮换、epoch / connection key 变化、workspace / session 缺失和异常 scope。每组同时带一个独立无效输入并核对结果隔离；见 `.local/admission-lease-security-final.log`。既有批准 / 撤权 / 连接 / 资源检查也在私有集群中回归。

同一 3000 连接、32 个准入 worker、200 个活跃会话 × 20 Hz、30 秒窗口重新通过，120000 帧按序交付。准入 6.923 秒，客户端投递 p95 66.408 ms / p99 177.009 ms，Go 入口路由样本全部位于 300 ms 桶内，撤权样本 76.40 ms；控制期限保持两秒。记录 `.local/capacity-baseline-3000-lease-joins.log`。这一结果覆盖该单节点 fixture 条件，不能替代多节点、目标 40000 源帧每秒或长期试点。
