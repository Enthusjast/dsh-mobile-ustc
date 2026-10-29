# 主机绑定定位信息持久化

`HostEnrollmentBindingStore` 在发送主机确认前保存从已验证登记回执得到的绑定定位信息。它与
[待处理恢复存储](host-enrollment-recovery.md)使用不同文件：前者保留 host、installation、runtime、
profile 和工作区映射，后者保留短期配对码。绑定文件不包含配对码、access token、私钥或手机用户
的 issuer / subject，也不会自行创建或恢复授权。
主机别名和软件版本属于可变展示 / 运行信息，不写入永久身份绑定；主机改名或升级后仍按稳定 ID、
profile 和安装公钥重新核对。首次本机确认前的显示信息仍会按[登记流程](host-enrollment-client.md)
验证。

调用 `binding.confirm(recovery, attempt, receipt, approve, signal)` 时，客户端先持久保存绑定定位信息，
再确保待处理尝试已保存，并在本机核对后发送确认。即使进程在确认成功后、调用方收到结果前退出，
重启后也能用绑定文件向服务端查询历史状态，不依赖十分钟后失效的本机配对码。若确认或确认后的
查询结果不明确，记录保留，调用方应使用 `binding.open(signal)` 对账，不自动重发确认。

`open` 每次使用当前资源账号和安装密钥访问 host-review，核对原 request / enrollment、组织、
主机、安装、runtime、profile、工作区及公钥指纹；只有服务端报告已批准才返回不可变的绑定元数据。
待确认、拒绝或无法核对时不会返回可用绑定。**历史批准不是当前连接授权**：启动 Relay 时仍须通过
`HostRestCredentialProvider` 获取当前短期凭据，服务端继续检查安装、runtime、grant 和撤销状态。
不能把恢复的 ID、历史批准或旧备份当作绕过在线授权的凭据。
工作区记录只包含不透明 reference 和 UUID，不包含本机路径；发行端必须将 reference 映射到
可信的本地工作区配置，不能从服务端数据派生或接受任意 cwd。

## 接入

```ts
import {
  HostEnrollmentBindingStore, HostEnrollmentClient, HostEnrollmentRecoveryStore,
  type HostEnrollmentApprovalReview, type HostEnrollmentIntent, type HostEnrollmentOptions, type HostEnrollmentReceipt, type JournalKeyProtector,
} from '@ustc/dsh-remote-control'

declare const options: HostEnrollmentOptions
declare const protector: JournalKeyProtector
declare const pendingPath: string
declare const bindingPath: string // 与 pendingPath 不同
declare const signal: AbortSignal
declare const approveLocally: (review: HostEnrollmentApprovalReview, signal: AbortSignal) => Promise<boolean>
const client = new HostEnrollmentClient(options)
const recovery = new HostEnrollmentRecoveryStore({ path: pendingPath, client, protector })
const binding = new HostEnrollmentBindingStore({ path: bindingPath, client, protector })

// 已有绑定可用 binding.open(signal) 重新向服务端核对。
// 新登记的 attempt 必须先由 recovery.create(attempt, signal) 获得 receipt；
// 手机确认后，以下回调必须由受信任的本机界面取得明确同意。
declare const attempt: HostEnrollmentIntent
declare const receipt: HostEnrollmentReceipt
const bound = await binding.confirm(recovery, attempt, receipt, approveLocally, signal)
// 保存成功后才清理短期配对码；bound.installationId / runtimeId 用于后续配置。
await recovery.remove(attempt, signal); attempt.destroy()
// 不再使用时：binding.close(); recovery.close(); client.close()。
```

实际恢复时，`open` 返回 `undefined` 只表示本机没有绑定文件，不证明服务端没有旧登记；不要据此
自动生成新的安装身份或 request ID。若文件存在但登记尚未批准，`open` 返回
`host.enrollment.review_required`；应恢复原待处理尝试并重新取得明确同意。若短期配对码已过期，
应按服务端状态和组织策略处理旧申请，不能伪造成功或重复使用旧决定。若服务不可用、账号变化、
文件损坏或身份不匹配，读取失败且保留原文件。
若重启时待处理尝试已超过本机恢复期限，但 `binding.open` 已重新确认服务端历史状态为批准，
调用方可显式使用 `recovery.discard(signal)` 清理仍能认证的过期待处理文件。查询失败或状态未知时
不要丢弃它。

绑定文件采用随机数据密钥、AES-256-GCM 和受信任平台封装器，认证绑定路径、账号 / 资源 / scopes、
安装公钥和封装器标识。它遵循与待处理恢复文件相同的 Linux 私有目录、不可覆盖发布、同步、链接和
取消规则。相同定位信息可幂等保存，不同绑定返回冲突，不能覆盖旧身份。`discard` 是显式本机删除，
不会撤销服务端安装或 grant；轮换 / 重绑前必须先按组织流程撤销旧授权。

同一 JavaScript 运行域内同一路径的操作互斥；跨进程删除仍需要发行端保证唯一宿主所有者。丢失
封装密钥、文件或备份不能通过自动创建新绑定掩盖。系统密钥库、断电持久性和恢复仍需在目标发行版
验收；具体限制见[恢复存储说明](host-enrollment-recovery.md)。

## 本地验证

小型测试覆盖确认前持久化、相同回执幂等、伪造 / 冲突 / 篡改 / 错误账号拒绝、确认响应丢失、
确认后查询失败、账号取消和并发删除。测试将本机时间推进超过配对码恢复期限，再以当前资源身份
重新读取已批准绑定。Go / PostgreSQL / 本机 DSH 双节点夹具另验证重启后使用持久的 installation、
runtime 和工作区映射完成 Host 连接；学校身份、本机确认界面和生产密钥库仍未验收。
