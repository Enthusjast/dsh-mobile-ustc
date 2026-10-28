# 控制事件历史的加密导出

迁移 `023_control_cold_exports` 和 `remote archive` 的管理命令可以将一个已归档的控制事件
批次写成受认证的加密文件。它只包含该批次的原始事件、归档时仍存在的节点确认和验证所需的
已释放恢复谱系；源数据可能包含资源标识和元数据。文件不是活跃控制事件的重放格式，当前
也没有历史导入功能。审批证明和完整审计日志不在此导出范围内。

操作由受控的本地管理角色显式发起，不提供公网 API，也不会自动部署、定时导出或清理文件。
部署方仍需提供加密备份、异地副本、密钥托管和轮换、法律保全、审计日志/审批证明归档、
文件访问审计及恢复演练。单次成功导出不代表这些设施已经配置，也不证明生产 RPO/RTO。

## 前提与权限

先按顺序应用迁移至 023，升级所有 Relay 节点，并按[控制事件归档](control-archive.md)
建立批次。正常 Relay 不需要读取导出表或文件。导出角色需要读取批次、历史事件、确认和
恢复记录，读写 `control_archive_exports` 并写入 `audit_log`；所需数据库 ACL 及访问审计
由部署方配置，不应向 PUBLIC 授权。迁移还禁止向已提交的历史批次追加事件或确认。

在数据库备份之外保存稳定的 `REMOTE_ARCHIVE_DOMAIN_ID` 和当前 `REMOTE_DATABASE_EPOCH`，
每次调用都须显式给出匹配的值。批次 UUID 来自 `archive control`，导出 UUID 由操作方生成并
保存；新批次或新加密操作使用新 UUID。文件名固定为 `<导出 UUID>.dshca`。

密钥是独立托管的 **32 字节原始随机密钥**，不是口令、hex 或 base64 文本；标识使用 1–32
个字母、数字、下划线或连字符。密钥文件必须为当前用户所有、普通文件、权限不宽于 `0600`，
目标目录必须预先存在、为当前用户所有且权限不宽于 `0700`。路径必须是绝对路径且不含符号链接。
应保护所有上级目录、运行账号和密钥交付过程；文件权限不能防止同一用户或特权管理员访问。
生产文件系统还须支持硬链接、文件与目录同步。不要把密钥内容、数据库密码放进参数或日志。

## 导出、对账与验证

以下命令由操作人员在仓库根目录执行。服务二进制的构建方式见[数据库恢复](database-recovery.md)。
所有占位项均需替换，`REMOTE_DATABASE_URL` 通过受控环境注入：

```sh
export REMOTE_ARCHIVE_DOMAIN_ID='<外部保存的归档域 UUID>'
export REMOTE_DATABASE_EPOCH='<外部保存的当前数据库代次 UUID>'
.local/remote archive export \
  --export-id '<本次导出 UUID>' \
  --batch-id '<已归档批次 UUID>' \
  --expected-epoch "$REMOTE_DATABASE_EPOCH" \
  --domain-id "$REMOTE_ARCHIVE_DOMAIN_ID" \
  --key-id '<密钥标识>' \
  --key-file /受控目录/archive.key \
  --directory /受控目录/control-archives
```

准备事务固定批次、代次、域、密钥及目录身份，并记录 `prepared` 审计。文件先写入仅所有者
可读写的临时文件，完成同步和回读验证后，以不可覆盖方式发布并同步目录；随后数据库状态
与 `published` 审计一起提交。正常输出仅含操作标识、代次、数量、加密文件摘要、大小及时间，
不含源 payload、密钥、路径或数据库连接信息。

若命令中断或输出丢失，保留原 UUID、密钥、参数和原目录重试；同一操作不会重新选择源批次。
只有源内容与已记录的摘要完全一致时才可重建同一密文，已有不同或损坏的文件不会被覆盖。
已发布文件丢失时，同一代次、原目录且源历史仍完整的情况下可重试重建。文件写入之前会记录
`repair_started`，成功后记录 `repaired`；若后者写入失败或进程中断，重试会验证已有文件并
记录 `verified`。应结合这些记录和文件状态对账，不能把未完成的意图当作成功。源历史删除后
无法依赖此功能重建文件，必须保留并验证独立副本。

在线验证使用相同的域、密钥、批次和当前代次；目录可以是受保护的副本位置：

```sh
.local/remote archive verify \
  --export-id '<本次导出 UUID>' --batch-id '<已归档批次 UUID>' \
  --expected-epoch "$REMOTE_DATABASE_EPOCH" --domain-id "$REMOTE_ARCHIVE_DOMAIN_ID" \
  --key-id '<密钥标识>' --key-file /受控目录/archive.key \
  --directory /受控目录/control-archives
```

在线验证检查密文、内容结构和数据库中的原始摘要，并写入 `verified` 审计；成功输出标记为
`database_audited`。恢复到新数据库代次后，只有经过已释放的恢复谱系才能在线验证旧导出，
旧导出操作不能在新代次重新发布；可用新导出 UUID 在新代次导出仍完整的旧批次。

数据库不可用时可使用离线校验；它认证文件及其域、导出 UUID 和密钥，但不检查数据库记录，
也不会写数据库审计，输出明确标记 `offline`。实际文件读取需要部署方的独立访问审计：

```sh
.local/remote archive verify-offline \
  --export-id '<本次导出 UUID>' --domain-id "$REMOTE_ARCHIVE_DOMAIN_ID" \
  --key-id '<密钥标识>' --key-file /受控目录/archive.key \
  --directory /受控目录/control-archives
```

## 取消与保留

尚未完成的导出会阻止其源历史到期删除，不会因等待超时自动释放。无法继续时，在核对后用
同一域、密钥、批次和当前代次显式中止；恢复后的新代次只能中止其已释放来源代次的未完成
操作。中止和审计在同一事务中提交，不删除可能已写出的文件：

```sh
.local/remote archive abort-export \
  --export-id '<本次导出 UUID>' --batch-id '<已归档批次 UUID>' \
  --expected-epoch "$REMOTE_DATABASE_EPOCH" --domain-id "$REMOTE_ARCHIVE_DOMAIN_ID" \
  --key-id '<密钥标识>' --key-file /受控目录/archive.key
```

已发布或已中止操作保留身份用于对账；已发布操作不能中止。文件与源历史各自遵守组织的
保留、保全、删除及密钥生命周期规定。现有批次、导出或恢复记录存在时迁移 023 的 down
拒绝执行，需要修正时使用经审阅的前向迁移。

文件使用 AES-256-GCM，每次导出从密钥及随机 salt 派生独立子密钥，头部和密文均受认证。
单批最多 128 个事件、8192 条确认、256 条恢复记录，明文最多 8 MiB；超过上限或源历史不
完整时失败，不产生成功导出。历史对象和导出记录受数据库 ACL 保护，数据库超级用户仍能
绕过普通访问控制；密钥丢失则无法解密副本。

## 本地验证边界

隔离 PostgreSQL 和 race 用例覆盖幂等重试、损坏与错误密钥、源内容变化、并发准备和到期删除、
中止、审计失败对账，以及真实 `pg_dump` / `pg_restore` 后的代次隔离、复制文件验证和谱系。
实际服务二进制在本地夹具中执行了导出和离线验证。没有运行生产归档、容量或真机测试；
学校身份配置与厂商推送通道尚未就绪。
