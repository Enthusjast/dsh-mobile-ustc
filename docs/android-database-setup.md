# 加密数据库首次打开的并发约束

真实 APK 自升级验收暴露了本地数据库问题：进程替换后账号、设备 ID、证明 / 审批密钥指纹均一致，但 SQLCipher 打开命令库报页 HMAC 校验失败。普通独立数据库的关闭重开通过；随后在原 versionCode 2 上，以同一新 owner 并发执行四次首次打开，稳定复现 `data.unavailable`，包含 DatabaseKeyVault 的并发失败。

此前各 `SqlCommandJournal` 实例独立创建包装密钥文件和首次 SQLite 数据库，没有跨实例的建立锁。并发调用可能在另一个调用者创建数据库时发布不同的密钥信封。因此把包装密钥建立、首次数据库打开与身份行初始化放入进程级 setup 锁，并让账号擦除使用同一锁。数据库后续事务继续使用原有锁与 SQLite/WAL 机制。应用组件使用同一进程；本次未扩展为多进程数据库协议。

原损坏记录保持失败关闭，不重新生成密钥、不删除数据库或退回明文。底层异常 cause 保留用于诊断；正常业务仍使用结构化错误码。

2026-10-27 验证：

- 原 v2 的并发首次打开失败，记录 `.local/app-self-upgrade-v2-concurrent-open.log`；普通重开对照通过，记录 `.local/app-self-upgrade-v2-room-reopen.log`。
- 修复版本在保留数据的同版本调试替换后，并发首次打开通过，记录 `.local/app-data-concurrent-open-fixed-api36.log`。
- API 36 的全部 10 项 CommandPersistenceTest 通过，记录 `.local/app-data-persistence-fixed-api36.log`，覆盖加密重开、并发请求、隔离、丢失密钥、撤权 / 清理和原始命令恢复。
- 完整 Gradle check 和 app/test 构建通过，记录 `.local/app-data-concurrent-setup-fix-build.log`。

这些结果证明并发建立回归已修复；原首次自升级的 Room 失败不能改记为通过。需要用修复后的基线与 v2 重新完成真实安装和数据恢复验收。
