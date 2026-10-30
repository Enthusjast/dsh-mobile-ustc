# 学校身份与组织映射同步

`remote identities` 是离线管理员命令，用当前可信目录的完整清单建立和更新远控服务的用户及
组织映射。它使用 `issuer + subject` 保持用户 UUID，不按邮箱匹配，也不创建密码或新的 SSO。
迁移 `032_identity_sync` 增加按数据库代次、issuer 保存的同步版本和操作回执。

**清单覆盖配置 issuer 下的全部用户。未列出的已有用户会暂停，其成员关系会移除。**
仅可从组织认可的当前身份目录导出完整清单，核对后再声明 `complete: true`。文件权限和结构
校验不能证明目录来源真实、完整或及时；学校连接器仍需接入实际身份系统。本仓使用本地夹具。

## 操作

先应用迁移 001–032，再构建服务二进制。数据库地址、可信 issuer 和当前数据库代次从受控环境
配置提供，不把数据库口令写入命令行：

```sh
# 在 services/remote 目录构建；以下运行命令以仓库根目录为例。
go build -o ../../.local/remote ./cmd/remote

export REMOTE_ISSUER='<与服务一致的可信 issuer>'
export REMOTE_DATABASE_EPOCH='<当前部署代次 UUID>'
.local/remote identities status
.local/remote identities apply --authority-file /受控目录/current-identities.json
```

`status` 返回当前同步版本；没有同步过时为 0。新清单的 `expected_revision` 必须等于该值，
`revision` 必须加一，采集时间不能早于上次成功清单。它必须在过去十五分钟内采集、尚未到期，
有效期不超过十五分钟。每次新的同步使用新 operation UUID；输出丢失或结果不明确时，保留并
重试**原操作 UUID 与原清单**。相同清单的数组重排不改变指纹。

已提交操作即使清单后来过期也可返回原回执，不重复修改状态；已执行更新版本后核对旧操作也
不会回退当前映射。相同操作 ID 携带不同内容、旧版本竞争、数据库代次变化或未解除恢复隔离
均被拒绝。不同 issuer 的用户和成员关系不会被本次清单替换。

清单示例故意使用 `complete: false`，不能直接导入；需替换占位值、完整采集并完成核对。

```json
{
  "v": 1,
  "complete": false,
  "operation_id": "aaaaaaaa-1111-4111-8111-111111111111",
  "database_epoch": "00000000-0000-4000-8000-000000000000",
  "issuer": "https://identity.example.edu",
  "expected_revision": 0,
  "revision": 1,
  "captured_at": "2026-10-30T02:00:00Z",
  "expires_at": "2026-10-30T02:10:00Z",
  "organizations": [
    {"organization_id": "bbbbbbbb-1111-4111-8111-111111111111", "slug": "example", "name": "示例组织"}
  ],
  "users": [
    {"subject": "example-subject", "status": "active", "memberships": [
      {"organization_id": "bbbbbbbb-1111-4111-8111-111111111111", "role": "member"}
    ]}
  ]
}
```

文件必须是仅当前所有者可读写的普通文件（例如 `0600`），最多 8 MiB、20000 个用户、256 个
组织，每个用户最多 256 个成员关系。状态为 `active`、`suspended` 或 `deleted`，暂停或删除的
用户成员关系必须为空；`deleted` 不能再激活。角色为 `member` 或 `admin`，每条成员关系必须
引用清单声明的组织。缺失数组、重复用户/组织/成员关系、未知字段和重复 JSON 字段被拒绝。

组织以显式 UUID 和 slug 登记；冲突的 UUID/slug 不能相互接管。清单可创建组织并更新匹配组织
的公开名称，但不删除组织对象。名称属于共享组织元数据，管理员须核对其全局影响。

## 权限变化

- 暂停、删除或遗漏用户会永久撤销其现有设备、安装及 runtime grants；该安装上其他用户的
  grants 也会撤销。重新激活用户只恢复目录身份和所声明的成员关系，不复活这些凭据或 grants。
- 活跃用户失去某组织成员关系时，撤销其在该组织的 grants 和自己拥有的安装；设备仍可服务
  其他组织。管理员降为普通成员时撤销其该组织 grants，仍有效的成员关系和安装保持原状态。
- 新用户、成员关系或管理员角色本身不创建 runtime grants。需要通过正常主机绑定和授权流程
  获得访问权限；恢复成员关系也不会恢复先前 grants。
- 相关未使用 ticket/challenge 和 Host 凭据会失效，失去参与资格的待绑定申请会取消。
  设备/授权撤销事件与状态修改在同一事务写入既有 outbox。Host 继续受周期授权检查约束，
  已签发的短期执行许可仍受既有撤销通知和期限约束。

同步、版本、操作回执及审计在一个事务提交。来源版本行和目标 issuer 的用户行保持排他锁，
与现有登记路径的共享用户锁协调；READ COMMITTED 的后续语句会看到锁等待期间已提交的登记，
将其纳入撤权。审计或 outbox 失败整体回滚；仅对
PostgreSQL 明确中止的事务做有限重试，不把未知提交结果当作失败重新执行。回执和审计只保存
指纹、版本、时间、数量，以及变更资源的内部 UUID、状态和角色，不保存输入清单或 token。
逐资源审计以 operation UUID 关联本次同步，不包含 subject。正常身份表仍按系统职责保存当前 subject 和
成员关系。命令不直接操作 IdP 会话或对象存储已经签发的能力。

数据库恢复后使用新的外部代次，本代次的同步版本从 0 开始；旧回执保留为历史，不能替代
[恢复隔离与当前身份释放流程](database-recovery.md)。已经同步过的数据库不能执行迁移 032
的 down；更正通过下一份当前可信清单或前向修复进行。

## 本地证据

真实隔离 PostgreSQL 测试覆盖首次创建、稳定 UUID、完整清单遗漏、组织隔离、成员关系与角色
变化、账号再启用不复活权限、版本竞争、过期/历史操作重试、审计和 outbox 失败回滚及禁止破坏性
回滚。生产 CLI 另验证输出丢失后核对同一操作。Go/PostgreSQL/本机 npm DSH `0.2.1-rc.2`
联合夹具使用该命令首次建立组织和用户映射、完成主机绑定，再暂停主机所有者，并检查真实 Host
断开、重新取凭据及旧连接秘密被拒绝。
这些证据使用本地身份与密钥夹具；学校目录来源、生产更新频率和目标规模仍需独立验收。
