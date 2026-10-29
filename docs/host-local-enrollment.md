# Linux 终端主机绑定确认

主机程序可使用 `runHostEnrollmentOnTerminal` 在 Linux 控制终端完成登记：先保护待处理尝试，
只向 `/dev/tty` 展示短期配对码和主机信息，等待手机确认，再显示服务端返回的用户、组织、
主机、工作区和安装公钥指纹。操作者须核对用户后输入界面随机生成的六位挑战，例如
`APPROVE 123456`；其他输入均拒绝。未确认、取消、超时或本机终端不可用时不会自动批准。

不受信任的显示字段以可打印 ASCII 表示，控制符、换行和非 ASCII 字符均被转义，避免这些字段
改变终端输出。发行端仍须通过可信组织目录核对显示的用户 UUID、issuer 和 subject；转义后的
名称不能替代身份核验。

**控制终端不能证明物理在场。** `/dev/tty` 可能来自 SSH、终端复用器，或由同一用户的其他
进程控制。终端录制、滚屏及其备份可能保留配对码和身份信息。只有当操作者信任该终端及其
访问者、并接受这些保留风险时才使用此入口；不要把配对码复制到日志或共享渠道。

## 接入

调用前需先配置已验证的学校资源账号、安装密钥和独立的受保护存储路径。以下示例只展示流程，
具体配置与恢复规则见[登记客户端](host-enrollment-client.md)、[恢复存储](host-enrollment-recovery.md)
和[绑定定位存储](host-enrollment-binding.md)。

```ts
import {
  HostEnrollmentBindingStore, HostEnrollmentClient, HostEnrollmentRecoveryStore,
  runHostEnrollmentOnTerminal,
  type HostEnrollmentOptions, type JournalKeyProtector,
} from '@ustc/dsh-remote-control'

declare const options: HostEnrollmentOptions
declare const protector: JournalKeyProtector
declare const pendingPath: string // 用户私有目录内的绝对路径
declare const bindingPath: string // 与 pendingPath 不同
declare const organizationId: string // 来自可信配置
declare const signal: AbortSignal

const client = new HostEnrollmentClient(options)
const recovery = new HostEnrollmentRecoveryStore({ path: pendingPath, client, protector })
const binding = new HostEnrollmentBindingStore({ path: bindingPath, client, protector })
const existing = await binding.open(signal)
if (!existing) {
  let attempt = await recovery.load(signal)
  if (!attempt) {
    // 仅在确认不存在未对账的旧申请后创建；本机文件缺失本身不构成证明。
    attempt = client.prepare({ organizationId, alias: '办公室电脑', profileRef: 'default',
      protocolVersion: 1, workspaceRefs: ['project'] })
  }
  const receipt = await recovery.create(attempt, signal) // 创建前先持久化，重试沿用同一尝试
  const enrolled = await runHostEnrollmentOnTerminal({ client, recovery, binding, attempt, receipt, signal })
  // 已重新核对批准状态且绑定定位信息持久化后，再删除短期配对码。
  await recovery.remove(attempt, signal)
  attempt.destroy()
  // 使用 enrolled.installationId、enrolled.runtimeId 和 enrolled.workspaces 配置运行实例。
}
// 不再使用时调用 binding.close(); recovery.close(); client.close()。
```

即使调用方之前直接使用 `client.create`，此入口也会在展示配对码之前保存并校验恢复记录；
但创建请求本身可能已经产生未知结果，因此新代码仍应使用 `recovery.create` 先保存再创建。
确认前还会保存绑定定位信息。确认响应丢失或结果未知时保留两份记录，使用相同尝试和
`binding.open` 对账，不自动重发确认。若创建回执或轮询结果已经批准，入口只接受经在线复核、
且 request ID、enrollment ID 和其他身份字段均匹配的绑定；缺失或不匹配时返回
`host.local_enrollment.recovery_required`。

入口约每五秒轮询一次，整个等待受登记期限、最多五分钟和调用方取消信号约束。相同 JavaScript
运行域内的终端展示或确认互斥；跨进程的终端及恢复文件所有权需由发行端协调。
`presentHostEnrollmentOnTerminal` 和 `approveHostEnrollmentOnTerminal` 也可分别使用，但它们
只负责展示或取得选择，不负责保存恢复记录、发送批准或校验完整绑定流程；调用方必须自行
遵守上述顺序和身份验证要求。

## 验证范围

自动测试使用隔离 PTY 检查准确挑战、拒绝、预先输入、长度限制、取消、无控制终端、并发和
终端控制字符。另有 Go / PostgreSQL / 本机 npm DSH `0.2.1-rc.2` 双节点夹具，使用临时控制
终端、模拟手机及本地身份、模型和密钥服务完成绑定与连接。真实桌面确认界面、学校身份目录、
生产密钥库和目标发行环境仍需验收。
