# 文件登记、扫描租约与清理账本

迁移 `009_file_transfers` 和 `store.FileStore` 为手机到主机的文件链路保存元数据、配额预留、扫描候选和删除证据。文件正文仍只进入对象存储 / 原生附件存储；不写入 PostgreSQL，也不把签名 URL、原生 receipt 或主机路径当成文件身份。

## 登记和当前授权

登记绑定设备 request ID、runtime / session、纯显示文件名、声明大小和 SHA-256。服务端按 JCS 计算请求摘要，生成文件及隔离 attempt UUID。同一设备同一 ID 的相同请求返回原文件；更换内容、名称或目标发生冲突。

每次通过当前 issuer / subject、token 绑定的设备 proof key、未撤销设备、组织成员关系、主机、安装、runtime、获批准登记、grant、角色及会话 / 工作区范围解析授权。上传要求 operator / owner 和明确 `file.upload`；归档会话不接受新登记或提交。主机暂时不可用时可以准备隔离文件，后续实际交接仍需当前主机和原生会话确认。

上传能力和首次 commit 还绑定登记时的设备 key version、proof key 和 grant version，不能把旧 intent 静默升级到变更后的权限。当前仍有权限的原设备可以读取自己的原始状态作对账；另一个设备不能仅凭文件 ID 读取其私有登记记录。

所有锁等待后使用数据库 `clock_timestamp()` 再检查授权 / 租约到期，不把事务开始时间当作当前时间。

## 配额和状态

组织、用户、会话同时预留字节和文件数量，配置必须明确给出并通过层级与时限校验。配额行按 organization / session / user 固定顺序锁定；幂等重试在预留前重读原记录。空文件仍消费文件数量配额。

预留、文件、设备绑定、隔离对象键和审计一起提交；审计失败全部回滚。登记状态为 uploading；commit 只把原文件转换为 scanning，重复 commit 返回当前状态，不重复启动作业。上传 URL 最长 15 分钟、未提交上传最长 48 小时、对象保留最长 90 天。

配额是服务端逻辑预留，不是对象服务实测磁盘占用。拒绝 / 过期不会立即释放预留，只有全部追踪对象完成删除确认后才释放一次。对象服务仍须配置独立的物理容量、上传时限及生命周期规则。

## 扫描与发布

worker 通过 SKIP LOCKED 竞争文件，每个文件只有一个 active attempt。30 秒租约可续期，绑定 attempt UUID、随机 lease UUID、scanner policy SHA-256 和登记授权。候选对象键在网络写入前持久保存；失联 / 崩溃后的接管创建新键并保留旧键供清理。

领取、续期、完成均重新验证设备、grant 和会话。过期租约不能复活，旧 worker 不能覆盖接管结果。暂时性扫描 / 存储错误有退避和三次上限；恶意内容、摘要错误或撤权不能成为 clean。

完成操作要求可信 worker 已经通过 [存储与扫描准入](file-storage-admission.md)。数据库事务原子写入 clean、候选指针、策略摘要、保留期、审计和 `file.clean` outbox 引用。重复确认原完成事实不重复审计或发布。仓库方法本身不读取正文；仓库测试提供的是可信 worker 的完成事实，不替代真实 I/O 验证。

`file.clean` 事件目前保留为 pending；已有控制 worker 只选择自己的 topic，不能提前消费或丢弃它。后续文件 Relay 必须重查当前状态 / 授权后才发 offer。后台扫描 / 清理和受保护 REST 现已由 [文件服务](file-rest-service.md) 接入正常 Go 入口。

## 过期与删除证据

过期任务使文件失去交接资格，并使旧扫描 attempt 作废。对象删除使用独立租约，键必须能从服务器资源 UUID 重新构造且与账本一致。当前 clean 的候选对象受保护；原始隔离对象和失败候选可按清理计划删除。

删除失败不释放配额；删除证据与最后一次配额扣减在同一事务提交。重复或旧 lease 不会重复扣减。已经删除的键继续每日对账，以覆盖短期 PUT 能力或延迟写入晚于早前删除的情况。该对账不等同于即时撤销签名地址，也不能替代对象服务生命周期配置。

迁移把没有设备绑定 / 扫描证明的旧行标为 expired；查询还要求新的 transfer 账本存在。down 迁移先使本阶段行失效，再删除账本；重新 up 不会把遗留 clean 标志当成当前授权。回滚不删除对象服务中的实际字节，操作前需保留对象追踪元数据及相应恢复 / 清理安排。

## 验证与边界

真实隔离 PostgreSQL 和完整 Go race 回归覆盖并发登记 / 配额、同 ID 重试、空文件数量、审计回滚、资源 / 设备 / grant / 归档拒绝、锁等待到期、扫描竞争 / 接管 / 重试、撤权、原子 clean 与 outbox、GC 证据 / 配额、迁移 down / up 失效语义。公共 JSON 和格式化输出不包含内部 lease、object key 或签名能力。

`npm run test:remote-kotlin` 还通过原有 Kotlin TLS、普通 npm DSH `0.2.1-rc.2`、聊天 / 归档 / 问题 / 审批回归。本机记录：`.local/files-ledger-final.log`；早期登记、扫描、清理分阶段记录为 `.local/files-ledger-first.log`、`.local/files-scans-first.log`、`.local/files-cleanup-first.log`。

文件后台 worker、S3 / clamd 传输和受保护 REST 现已接通。下一步接当前 runtime 的流式交接、手机文件入口与 APK 组合。真实对象服务 KMS、实际病毒引擎与其限制 / 签名库仍需独立验收。
