# 审批证据的加密文件导出

迁移 `028_approval_evidence_exports` 增加受控的离线管理命令，可以把一条已经捕获、具有原始
JWS 摘要的审批证据写成认证加密文件。文件包含签名、验签公钥、必要的历史绑定及已释放的恢复
谱系；其中有用户和设备标识，但不包含工具参数正文或完整审批上下文。它只供历史核查，不会
授予执行权限。没有已捕获材料或可信摘要的旧记录不能导出。

该功能不自动配置备份设施、法律保全、密钥托管、文件访问审计或生产恢复目标，也不包含完整
审计日志；审计批次使用[独立加密导出](audit-cold-export.md)。文件可[导入独立历史表](cold-history-import.md)；
数据库恢复仍按[恢复流程](database-recovery.md)隔离和重建授权。验签及认证加密不能代替对来源机构、密钥持有人、当时身份和策略的独立核对。
持有归档对称密钥的人也能生成有效文件；摘要与源证据若由同一数据库超级用户同时修改，本工具
不能作为独立防篡改见证。

## 前提与权限

先按顺序应用迁移至 028，核对数据库备份、时间、节点版本及[证据保留](approval-evidence.md)。
在数据库备份之外保存稳定的 `REMOTE_ARCHIVE_DOMAIN_ID`、当前 `REMOTE_DATABASE_EPOCH`
和每次操作的唯一导出 UUID；应跨不同归档类型避免复用导出 UUID。密钥须由组织独立管理，
使用仅所有者可访问的**原始 32 字节随机密钥文件**和仅所有者可访问的已有目录。路径、所有权、
非符号链接、文件系统同步及密钥标识要求与[控制事件导出](control-cold-export.md)相同。

导出角色需要受控读取证据、材料、签名摘要和恢复谱系，读取/插入 `approval_evidence_exports`
并更新其状态；材料行锁的 UPDATE 可限于 `approval_id` 列，恢复状态表行锁的 UPDATE 可限于
`slot` 列。还需要向 `audit_log` 写审计及使用序列。只验证已发布文件的角色可只读导出记录、
恢复状态和谱系并写审计，不需要读取数据库中的证明材料。迁移不创建角色或向 PUBLIC 授权；
直接数据库读取及离线文件读取仍需部署方独立审计。

## 导出和验证

以下命令在仓库根目录执行，`.local/remote` 的构建方法见[数据库恢复](database-recovery.md)。
数据库连接从受控环境注入，所有占位值均需替换：

```sh
export REMOTE_ARCHIVE_DOMAIN_ID='<外部保存的归档域 UUID>'
export REMOTE_DATABASE_EPOCH='<外部保存的当前数据库代次 UUID>'
.local/remote archive export-approval \
  --export-id '<本次导出 UUID>' --approval-id '<审批 UUID>' \
  --expected-epoch "$REMOTE_DATABASE_EPOCH" --domain-id "$REMOTE_ARCHIVE_DOMAIN_ID" \
  --key-id '<密钥标识>' --key-file /受控目录/archive.key \
  --directory /受控目录/approval-archives
```

准备事务先核对原始签名字节摘要、公钥和签名以及来源谱系，固定域、代次、密钥和目录身份，
并写 `approval.evidence.export.prepared` 审计。无效或缺失材料及不相关来源的准备失败也记录
审计。明文最多 8 MiB、恢复记录最多 256 条；超出上限时失败，不输出部分成功。文件使用
AES-256-GCM、随机 salt 和 nonce，先写仅所有者可访问的临时文件，同步并回读验证后以不可覆盖
方式发布，最后在数据库中提交 `published` 和审计。

输出丢失或结果不确定时使用相同 UUID、域、密钥、审批、代次和原目录重试；只有源明文与固定
摘要完全一致时才允许重建相同密文。已发布文件缺失且源材料仍完整时可重建，先记录
`repair_started`，完成后记录 `repaired`。若完成审计失败或进程中断，重试会验证已有文件并
记录 `verified`；应结合意图、结果和文件状态对账。现有损坏或不同的文件不会被覆盖。源材料
到期删除后不能靠数据库重建文件，必须维护并验证独立副本。

在线验证可使用另一个受保护的副本目录；它核对数据库导出记录并写入验证审计：

```sh
.local/remote archive verify-approval-export \
  --export-id '<本次导出 UUID>' --approval-id '<审批 UUID>' \
  --expected-epoch "$REMOTE_DATABASE_EPOCH" --domain-id "$REMOTE_ARCHIVE_DOMAIN_ID" \
  --key-id '<密钥标识>' --key-file /受控目录/archive.key \
  --directory /受控目录/approval-archives
```

恢复后的新代次只能在线验证来自已释放来源谱系的旧导出，不能用旧操作重新发布。若历史材料
仍完整，可用新导出 UUID 在新代次生成包含恢复谱系的新文件。数据库不可用时可离线验证文件
认证、签名、记录及文件内谱系；该模式不查询数据库、不写数据库审计，输出标为 `offline`：

```sh
.local/remote archive verify-approval-offline \
  --export-id '<本次导出 UUID>' --domain-id "$REMOTE_ARCHIVE_DOMAIN_ID" \
  --key-id '<密钥标识>' --key-file /受控目录/archive.key \
  --directory /受控目录/approval-archives
```

各命令的正常输出只有操作、审批和代次标识、状态、文件摘要、大小、时间及摘要来源，不输出
JWS、公钥、用户/设备 ID、路径或数据库连接。失败输出也不包含这些内容。

## 中止与到期

未完成导出会阻止源证据材料到期删除，直到发布或显式审计中止；不会超时自动释放。目录丢失
时可以不提供目录，用同一归档域和密钥中止：

```sh
.local/remote archive abort-approval-export \
  --export-id '<本次导出 UUID>' --approval-id '<审批 UUID>' \
  --expected-epoch "$REMOTE_DATABASE_EPOCH" --domain-id "$REMOTE_ARCHIVE_DOMAIN_ID" \
  --key-id '<密钥标识>' --key-file /受控目录/archive.key
```

恢复后的已释放后继代次可以中止来源代次的未完成操作。中止不删除可能已写出的文件；已发布
操作不能中止。材料到期删除角色必须能读取导出状态，以检查未完成操作，并遵守原有的审计和
保留约束，以及[后来追加的保留延期](approval-evidence-retention.md)。文件本身的保留、复制、
删除和密钥生命周期仍由组织设施管理。导出身份永久保留，
存在任何导出记录时迁移 028 拒绝 down。

## 本地验证

隔离 PostgreSQL/race 用例覆盖加密/签名/域校验、并发幂等、源变化拒绝、到期删除竞争、审计
失败与中止，以及真实 `pg_dump` / `pg_restore` 后的代次和谱系。实际服务二进制验证准备后
重试、输出丢失、受保护副本、离线校验、修复审计中断和损坏文件不覆盖。模型和身份使用本地
夹具；未运行生产归档、大负载或真机测试。
