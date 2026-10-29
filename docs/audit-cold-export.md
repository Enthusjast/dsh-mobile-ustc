# 审计历史的加密文件导出

迁移 `029_audit_cold_exports` 可将一个完整的[数据库审计归档批次](audit-archive.md)写成认证
加密文件。文件保存批次元数据、每条原始审计记录及所需恢复谱系；迁移前无法确认的来源代次
保持未知，不会被标成当前代次。文件不包含审批签名材料；审批证明使用[独立导出](approval-evidence-export.md)。

单批最多 128 条，每条源记录最多 256 KiB，文件明文最多 64 MiB，恢复记录最多 256 条。
原始审计 JSON 以字节形式保留，不用事务 ID 判断跨集群顺序。文件可能包含用户、设备或资源
元数据，必须由组织的密钥和访问策略保护。批次不完整、源结构无效、恢复谱系无法证明或超过
上限时操作失败，不会把部分文件标为成功。

这不是已部署的异地备份或自动保留设施。生产仍需配置密钥托管、独立副本、访问审计、法律
保全、调度和恢复演练。持有对称密钥的人也能生成有效文件；同一数据库及其超级用户可以同时
改变来源和摘要，因此加密校验不能代替独立来源见证或证明生产 RPO/RTO。

## 前提与权限

先按顺序应用迁移至 029，完成节点升级并通过 `archive audit` 建立数据库历史批次。数据库连接
从 `REMOTE_DATABASE_URL` 的受控环境注入；数据库代次、稳定归档域及唯一导出 UUID 保存在
备份之外。不同归档类型应使用不同导出 UUID。密钥为独立托管的原始 32 字节随机文件，目标
目录必须预先存在；文件和目录的所有权、权限、绝对路径、符号链接、密钥标识与文件系统同步
要求与[控制事件导出](control-cold-export.md)相同。

导出角色需要 SELECT 数据库历史批次和源记录、SELECT/INSERT `audit_cold_exports` 及其状态
更新权限、读取恢复状态和谱系，以及写入 `audit_log` 和使用序列。源记录行锁的 UPDATE 可限于
`source_id`，恢复状态行锁的 UPDATE 可限于受约束的 `slot`；触发器仍拒绝修改历史内容，角色
不需要修改恢复代次。删除到期历史的角色还需读取 `audit_cold_exports` 以检查未完成操作。
迁移不创建角色或向 PUBLIC 授权；直接数据库读取、离线文件读取和被数据库拒绝的访问需要
部署方提供独立审计。

## 导出与验证

以下命令在仓库根目录执行，二进制构建方式见[数据库恢复](database-recovery.md)：

```sh
export REMOTE_ARCHIVE_DOMAIN_ID='<外部保存的归档域 UUID>'
export REMOTE_DATABASE_EPOCH='<外部保存的当前数据库代次 UUID>'
.local/remote archive export-audit \
  --export-id '<本次导出 UUID>' --batch-id '<数据库审计批次 UUID>' \
  --expected-epoch "$REMOTE_DATABASE_EPOCH" --domain-id "$REMOTE_ARCHIVE_DOMAIN_ID" \
  --key-id '<密钥标识>' --key-file /受控目录/archive.key \
  --directory /受控目录/audit-archives
```

准备事务锁定并核对整批源记录、数量和恢复路径，固定域、代次、密钥与目录身份，并写
`audit.cold.export.prepared` 审计。无效或不完整来源、未释放谱系以及源变化均失败并记录相应
审计。文件使用 AES-256-GCM、随机 salt 和 nonce；先写仅所有者可访问的临时文件，同步并回读
校验后以不可覆盖方式发布，再将数据库状态与 `published` 审计一起提交。

输出丢失时使用相同 UUID、批次、域、密钥、代次及原目录重试。仅当源明文与已固定摘要完全
一致时才可重建相同密文；已有损坏或不同文件不会被覆盖。已发布文件缺失且源历史仍完整时，
重试可修复文件：先记录 `repair_started`，完成后记录 `repaired`。若完成审计失败或进程中断，
重试会核对已有文件并记录 `verified`；运维应结合这些记录对账。源历史到期删除后不能从该
数据库重建文件，必须保留并验证独立副本。

在线验证可读取另一个受保护的副本目录，并核对数据库记录与当前恢复谱系：

```sh
.local/remote archive verify-audit-export \
  --export-id '<本次导出 UUID>' --batch-id '<数据库审计批次 UUID>' \
  --expected-epoch "$REMOTE_DATABASE_EPOCH" --domain-id "$REMOTE_ARCHIVE_DOMAIN_ID" \
  --key-id '<密钥标识>' --key-file /受控目录/archive.key \
  --directory /受控目录/audit-archives
```

恢复后的已释放后继代次可以在线验证旧文件，不能将旧导出 UUID 重绑定到新代次；源批次仍
完整时可用新 UUID 在新代次生成含恢复谱系的文件。数据库不可用时可离线核对文件认证、源行
结构和文件内谱系；它不查询数据库、不写数据库审计，结果标为 `offline`：

```sh
.local/remote archive verify-audit-offline \
  --export-id '<本次导出 UUID>' --domain-id "$REMOTE_ARCHIVE_DOMAIN_ID" \
  --key-id '<密钥标识>' --key-file /受控目录/archive.key \
  --directory /受控目录/audit-archives
```

正常输出只有操作/批次/代次标识、数量、状态、文件摘要、大小和时间；不输出审计正文、主体、
路径、密钥或数据库连接。源行读取和离线读取的完整访问审计仍由部署方负责。

## 中止、到期与限制

未完成导出会固定整个源批次，即使保留期已经到期也不会自动释放。确认无法继续时，用相同域、
密钥和当前代次显式中止；不需要原目录，且不会删除可能已经写出的文件：

```sh
.local/remote archive abort-audit-export \
  --export-id '<本次导出 UUID>' --batch-id '<数据库审计批次 UUID>' \
  --expected-epoch "$REMOTE_DATABASE_EPOCH" --domain-id "$REMOTE_ARCHIVE_DOMAIN_ID" \
  --key-id '<密钥标识>' --key-file /受控目录/archive.key
```

已释放的后继代次可中止祖先代次的未完成导出，已发布操作不能中止。文件的保留、复制和删除
由组织设施管理；存在任何导出记录时迁移 029 拒绝 down。现无文件导入功能，不能用本工具把
历史写回活跃审计表。源 JSON 嵌套或大小超过校验边界时需通过受控备份流程处理，不能静默
略过。处理较大批次会占用数倍于文件大小的内存和 CPU；目前没有最大尺寸或目标负载证据，
应从小批次开始。

## 本地验证

小型隔离 PostgreSQL/race 夹具覆盖来源完整性、未知旧代次、加密篡改、错误密钥、并发准备和
到期删除、审计失败、中止以及真实 `pg_dump` / `pg_restore` 后的谱系。实际服务二进制验证
输出丢失对账、离线验证、受保护副本、修复中断和损坏文件不覆盖。没有运行最大文件、大负载、
生产归档或真机测试。
