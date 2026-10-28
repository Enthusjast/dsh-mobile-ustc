# 数据库恢复后的隔离与授权重建

迁移 `021_recovery_epochs` 增加恢复状态、恢复记录、旧组织关系归档和控制事件的数据库代次。
生产入口在监听前检查 `REMOTE_DATABASE_EPOCH`、数据库代次和 `ready` 状态；每次 HTTP
准入再次查询，独立后台检查负责终止已有连接和 worker。检查失败不使用内存结果继续服务。

这套工具防止按规定流程恢复时复用旧授权。它无法凭数据库自身判断“这是旧备份”：
部署代次必须保存在数据库备份之外，并在恢复时生成全新的 UUID。不能同时从备份恢复旧配置、
旧代次并直接开放服务。首次部署兼容代次为 `00000000-0000-4000-8000-000000000000`；
省略环境变量只允许这个初始代次。恢复后必须显式配置新值。

## 操作边界

以下是离线管理员流程，不是公网 API，也不会自动操作生产环境。恢复前关闭公网入口，
停止所有旧 Relay、控制面写入和身份同步任务，确认 Host 断连并等待已有短期执行授权到期。
检查备份来源、完整性、加密和 PostgreSQL 兼容性。使用组织已有的加密备份、WAL 和密钥设施；
本工具不替代这些设施，也未证明生产 RPO 5 分钟 / RTO 30 分钟。

将新部署代次写入外部配置后再连接恢复库。所有节点必须使用同一个新值。只从受控配置注入
`REMOTE_DATABASE_URL`，不要把数据库口令写入命令行、日志或工单。

```sh
# 在仓库的 services/remote 目录构建；工具与服务使用同一个二进制。
go build -o ../../.local/remote ./cmd/remote

# 以下命令在仓库根目录运行。新代次及操作 UUID 需在备份之外保存。
export REMOTE_DATABASE_EPOCH='<全新的部署代次 UUID>'
.local/remote recovery status
.local/remote recovery quarantine \
  --expected-epoch '<status 返回的备份代次>' \
  --epoch "$REMOTE_DATABASE_EPOCH" \
  --recovery-id '<本次恢复的操作 UUID>'
```

`quarantine` 在单个事务中完成这些操作：

- 吊销所有旧设备、安装、runtime grants、Host 短期凭据及未使用的 ticket/challenge，
  取消待绑定申请，暂停旧账号，将组织关系保存到恢复归档后移除。
- 清除 runtime 在线连接，令运行会话不可用；已归档会话保持归档。未完成命令转为
  `outcome_unknown`，已完成或已拒绝的命令保留终态；挂起审批失效，可能已执行的审批保留未知结果。
- 使文件交接失效，停用旧推送绑定和待投递任务；更换所有 consumer 的连接代次并结束租约。
- 保存恢复记录和元数据审计。保留原 proof、outbox、ack、命令和审批记录；不会通过清表重建通过条件。

数据库代次和隔离状态随事务一起提交。锁等待或其他失败会整体回滚。输出丢失或提交结果不确定时，
用原操作 UUID 和原参数重试、核对状态；不要新建操作掩盖未知结果。已释放操作的同参数重试只返回原结果，
不会再次吊销后来建立的授权。新的恢复必须使用新的操作 UUID 和新的部署代次。

## 当前身份清单与释放

隔离后，从当前可信身份与组织管理来源取得完整清单。清单必须在本次隔离之后采集，
有效期不超过 15 分钟，且在释放时仍有效。记录使用已验证的 `issuer + subject`，不按邮箱关联。
未列出的旧账号继续停用；组织 UUID 必须已经存在，未知组织使整个导入失败。

清单是离线管理员提供的可信输入。工具检查结构、issuer、完整声明、时效、重复项及角色，
**不能证明导出来源真实或已经包含学校最新状态**。管理员必须通过可信渠道核对来源和完整性，
不能把备份内的用户表重新导出后当作当前清单。真实学校接入尚未配置，本仓只有本地身份夹具证据。

文件格式如下；这些是占位数据，需替换 UUID、issuer、subject、时间和全部身份关系。
`complete: false` 故意不能释放，完成核对后才能声明完整：

```json
{
  "v": 1,
  "complete": false,
  "recovery_id": "aaaaaaaa-1111-4111-8111-111111111111",
  "database_epoch": "bbbbbbbb-1111-4111-8111-111111111111",
  "issuer": "https://identity.example.edu",
  "captured_at": "2026-10-27T09:00:00Z",
  "expires_at": "2026-10-27T09:10:00Z",
  "users": [
    {
      "subject": "example-subject",
      "status": "active",
      "memberships": [
        {"organization_id": "cccccccc-1111-4111-8111-111111111111", "role": "member"}
      ]
    }
  ]
}
```

状态允许 `active`、`suspended`、`deleted`；角色允许 `member`、`admin`。停用账号的
`memberships` 必须为空。最多 20000 个账号，每账号最多 256 个组织关系，文件上限 8 MiB。
配置文件必须是仅所有者可读写的普通文件（例如权限 `0600`）。文件不要入库；恢复审计仅保存解析后固定结构编码的 SHA-256 和数量。

```sh
chmod 600 /受控目录/current-authority.json
export REMOTE_ISSUER='<与服务配置完全一致的可信 issuer>'
.local/remote recovery release \
  --recovery-id '<同一操作 UUID>' \
  --authority-file /受控目录/current-authority.json
.local/remote recovery status
```

释放只重建当前账号和组织关系，**不会恢复旧设备、安装或 runtime grants**。身份表写入与
释放状态在同一个事务提交，外键或其他错误不会留下部分开放状态。相同清单可以对账重试；
已释放后换一份清单不能借此更改结果。

释放设置新的 access-token `iat` 下界，校验不使用时钟宽限放宽这个下界。客户端需要刷新身份、
轮换已撤销的设备/安装密钥并重新登记、绑定和授权。学校 token 撤销、时钟同步以及发行端的
重新登记操作仍需在实际身份系统验证，不能据此宣称任意旧 token 已在 IdP 全局撤销。

确认 `ready`、外部代次一致和重新登记路径后，再逐步启动新节点、核对授权并恢复入口。
尚未取得当前可信身份清单时保持隔离。已直接发出的对象存储能力不受数据库事务控制：
恢复前按存储设施的能力 TTL、凭据轮换或访问策略撤销旧能力，并核对对象版本、摘要和扫描状态；
本地数据库恢复验证不能替代这个步骤。

## 控制事件、证明与回滚

旧事务快照属于来源数据库历史。旧 outbox 记录保留原数据库代次；新 consumer 只读取当前代次，
恢复后的稳定节点重新建立当前历史的覆盖快照。旧 ack 保留，不会用旧快照确认新事件。
新事件强制写入当前代次，不能通过调用方字段伪造或修改历史身份。

DPoP 资源状态按数据库代次重新绑定，旧 nonce/jti 记录保留并与新状态分离。旧凭据不能因为
备份回退而重新可用。当前代次的正常到期清理和 consumer 退役继续适用。
[控制事件归档](control-archive.md)在 release 后可将超过保留期的旧代事件及仍存在的 ack
原样移动到数据库历史表；短暂 consumer 不会先级联删除旧 ack。受控的
[加密文件导出](control-cold-export.md)可以保存和验证控制事件历史，但尚不能导入历史，
也不包含 proof 或完整审计日志。旧代 proof 的自动归档清理和外部备份设施仍未实现；不要手工清表绕过恢复。

发生恢复后，`021` 的 down 迁移拒绝执行。不能回滚到不理解恢复代次的旧程序或清除恢复记录；
需要修正时使用经过验证的前向迁移。

## 本地证据与未完成项

`TestRecoveryAcrossActualClusterRestoreFencesAuthorityAndPreservesHistory` 使用真实 `pg_dump`
和 `pg_restore`，恢复到另一个 system identifier 的临时 PostgreSQL 集群，覆盖旧授权回退、
隔离、旧 ticket/Host 凭据拒绝、proof/outbox/ack 保留、当前身份替换、旧证明拒绝、consumer 重建、
幂等对账和失败事务回滚。

`TestProductionRecoveryCLIRequiresFreshEpochAndAuthorityBeforeServing` 使用实际生产二进制，
验证部署代次不匹配或未释放时拒绝启动、受保护文件要求、释放后的新身份认证与旧设备拒绝，
以及运行中的节点和已升级连接被恢复隔离终止。普通跨节点 npm DSH 功能回归继续使用本地身份与模型。

这不是学校生产恢复验收。加密备份/WAL 设施、对象存储恢复、学校身份清单来源和 IdP 撤销、
真实发行端重新登记以及生产恢复目标仍需独立证据。按当前开发要求不运行大负载、真机测试或厂商通道配置。

2026-10-27 本地记录：`.local/recovery-full-final.log` 通过完整 Go race/隔离 PostgreSQL
和实际 npm DSH 0.2.1-rc.2 双节点组合，原生组合约 12.058 秒；加入迁移事务后，
`.local/recovery-atomic-migration-final.log` 再次通过恢复相关用例（含真实跨集群恢复）。
`go vet ./...` 通过，记录 `.local/recovery-go-vet-final.log`。这些是功能夹具证据；
新加入的 HTTP 准入数据库检查尚未做容量测量。持续可用性、端侧重登记及未完成命令的恢复对账仍需推进。
