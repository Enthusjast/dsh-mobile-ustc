# 主机绑定客户端

`HostEnrollmentClient` 使用现有的已验证资源登录适配器和安装密钥签名器，向远控服务发起
短期登记申请、读取主机专用的用户核对信息，并在调用方明确确认后提交主机决定。它不包含
学校登录、安装密钥生成、桌面确认界面或自动恢复存储；这些能力必须由发行端提供。

## 接入顺序

```ts
import {
  HostEnrollmentClient,
  type HostEnrollmentOptions, type HostEnrollmentApprovalReview,
} from '@ustc/dsh-remote-control'

// account 必须验证资源 access token、签名、issuer、audience、scope 和 DPoP 绑定，
// 并在登出、账号切换或安装密钥变更时取消其 signal。
declare const options: HostEnrollmentOptions
declare const signal: AbortSignal
declare const organizationIdFromTrustedConfiguration: string
declare const protectedPendingStore: { save(value: Uint8Array): Promise<void> }
declare const trustedLocalConfirmation: (review: HostEnrollmentApprovalReview, signal: AbortSignal) => Promise<boolean>
const client = new HostEnrollmentClient(options)
const attempt = client.prepare({
  organizationId: organizationIdFromTrustedConfiguration,
  alias: '办公室电脑',
  profileRef: 'default',
  dshVersion: '0.2.1-rc.2',
  applicationVersion: 'example',
  pluginVersion: '0.0.1',
  protocolVersion: 1,
  workspaceRefs: ['project'],
})

// 在首次请求前，将恢复数据写入调用方的认证加密存储，并清除临时缓冲区。
const recovery = attempt.exportRecovery()
try { await protectedPendingStore.save(recovery) } finally { recovery.fill(0) }
const receipt = await client.create(attempt, signal)
// 仅在本机受信任界面展示 receipt.details.enrollment_id 和 attempt.code，供手机绑定。

// 手机完成确认后，调用方在受信任本机界面显示用户和主机信息并取得明确选择。
const approved = await client.confirm(attempt, receipt, async (review, consentSignal) => {
  return await trustedLocalConfirmation(review, consentSignal) // 只有明确同意才返回 true
}, signal)
// 完成或放弃后，删除受保护恢复数据并销毁 attempt；不再使用时调用 client.close()。
```

示例中的组织 ID、受保护存储和确认界面由发行端提供，不能从手机请求或不受信任文本直接
推导权限。`review.confirmed_user` 提供 UUID、issuer、subject 和当前 eligibility；issuer / subject
应作为身份键，并通过可信组织目录展示可辨认名称。界面必须安全显示不受信任字符串，不把
普通点击、默认值或后台恢复当作本机同意。客户端在同意前后各读取一次当前 review，检查
安装公钥指纹、组织、主机、profile、工作区和确认用户；用户或组织名称变化、设备失效、
授权过期或账号取消时不发送确认。服务端仍在最终事务内重新检查设备、授权和撤销状态。

## 恢复与未知结果

`prepare` 为一次尝试生成独立 request ID 和 256 位配对码。`exportRecovery()` 返回的字节包含
该配对码和登记元数据，但不包含 access token 或安装私钥；必须使用带完整性保护的用户私有
存储，不能写日志、普通配置或共享目录。`restore(bytes)` 将恢复数据绑定到相同的资源 origin、
账号、客户端、scopes 和安装公钥。调用方应清除读写缓冲区并在完成后删除恢复记录；Node、
网络库和 JavaScript 字符串中的所有副本无法保证擦除。尝试最多在本机保留十分钟，服务端
登记仍按其五分钟期限生效。`destroy()` 取消该尝试的在途操作并禁止再次读取配对码；账号
signal 取消或客户端关闭后也不能继续使用该尝试。

只有严格匹配的 DPoP nonce 挑战会在服务端业务处理前自动重试一次。发送创建或确认请求后，
断线、取消、超时、服务端故障或不可信响应可能返回 `host.enrollment.outcome_unknown`，不能
当作未执行。创建可由调用方显式使用**同一**恢复尝试重试；服务端按原 request ID、配对码和
完整请求去重。确认结果不自动重发：先用 `review(attempt, receipt, signal)` 对账；若仍需确认，
再次取得明确的本机同意。不能为未知结果自动生成新的 request ID 或配对码。

每个请求独立取得并验证资源会话，以新的 DPoP proof 向固定 origin 和三个登记路径发送；它不
接受任意 RPC 路径或跟随重定向。并发操作使用各自的 nonce，最多八个在途请求；每个操作有
十五秒期限，同一进程内的同一尝试只允许一个本机确认流程，确认界面最多等待两分钟并受登记期限约束；
多个宿主进程共享恢复记录时，发行端还需协调所有权。响应必须是有界、无重复字段、
`no-store` 的 JSON，签名器的每个 ES256 输出都会用已登记公钥验证。

## 本地证据与边界

本地 HTTP 夹具覆盖恢复、身份和公钥绑定、明确同意、用户变化、撤权、取消、响应丢失、
重定向以及并发 nonce。双节点 Go / PostgreSQL / 本机安装的 DSH `0.2.1-rc.2` 组合使用本地
issuer、模型和手机协议夹具，通过实际主机客户端完成创建、手机确认、主机核对及确认，再
接入正常 Host Relay。没有使用 TokenWorks、学校身份、生产密钥库或 Android APP。

目标发行版仍需提供受信任的本机确认界面、认证加密恢复存储、安装密钥生成与登记生命周期，
并与学校资源登录适配器和实际身份目录联调。不能把当前回调或本地夹具当作这些验收已完成。
