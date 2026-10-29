# Linux 终端主机绑定确认

主机程序可使用 `runHostEnrollmentOnTerminal` 在 Linux 控制终端完成登记：先保护待处理尝试，
只向 `/dev/tty` 展示短期配对码和主机信息，等待手机确认，再显示服务端返回的用户、组织、
主机、工作区和安装公钥指纹。操作者须核对用户后输入界面随机生成的六位挑战，例如
`APPROVE 123456`；其他输入均拒绝。未确认、取消、超时或本机终端不可用时不会自动批准。
`HostTerminalEnrollmentWorkflow` 将这一入口与已有绑定和受保护恢复记录组合，供发行端显式
恢复旧申请或开始新申请。

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
  HostTerminalEnrollmentWorkflow,
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
const workflow = new HostTerminalEnrollmentWorkflow({ client, recovery, binding })
let enrolled = await workflow.resume(signal)
if (!enrolled) {
  // 仅在独立确认不存在未对账的旧申请后创建；本机文件缺失本身不构成证明。
  enrolled = await workflow.start({ organizationId, alias: '办公室电脑', profileRef: 'default',
    protocolVersion: 1, workspaceRefs: ['project'] }, signal)
}
// 使用 enrolled.installationId、enrolled.runtimeId 和 enrolled.workspaces 配置运行实例。
// 按需显式调用 workflow.cleanup(signal)，仅在在线批准与待处理记录匹配时清理。
// 不再使用时调用 workflow.close(); binding.close(); recovery.close(); client.close()。
```

`resume` 先在线复核已有绑定；若已有定位文件仍待确认，则加载受保护尝试并以原 request ID 和
配对码显式重试创建，再进行终端确认。已有待确认定位文件但恢复记录缺失时返回
`host.terminal_enrollment.recovery_required`；无本机记录时返回 `undefined`，不会自动创建。
`start` 在已有绑定、待确认定位文件或可恢复尝试时返回 `host.terminal_enrollment.existing`。
只有调用方确认没有未对账的远端申请时才能显式调用 `start`。

创建前先保存待处理记录；创建成功后先保存并核对绑定定位信息，再展示配对码。冲突在展示前
失败，已有文件不会被覆盖。确认响应丢失或结果未知时保留两份记录，重新调用 `resume` 对账，
不自动重发确认。若创建回执或轮询结果已经批准，入口只接受经在线复核、且 request ID、
enrollment ID 和其他身份字段均匹配的绑定；缺失或不匹配时返回
`host.local_enrollment.recovery_required`。

协调入口不会自动删除待处理记录。已有批准绑定优先返回，不能据此认为其他恢复记录已对账。
显式调用 `workflow.cleanup(signal)` 会重新在线验证已批准绑定，并对认证解密后的恢复记录核对
完整恢复内容摘要、账号、安装密钥、request ID、组织、profile、可选原 host 和工作区引用；
一致时才删除，记录已超过十分钟恢复期限也可匹配，但不会重新启用配对码。版本 1 定位文件没有
摘要，不能通过该方法清理。没有恢复文件时返回 `false`；绑定缺失、仍待批准、记录不匹配、
文件损坏或在线核对失败时保留文件并返回错误。取消和文件错误发生在
删除过程时，调用方应再次核对文件，不能推断是否已删除。对于其他申请或无法验证的记录，应先
核对服务端状态并按组织流程处理，不能自动丢弃或覆盖。
即使调用方之前直接使用 `client.create`，较低层 `runHostEnrollmentOnTerminal` 也会在展示
配对码前保存恢复记录，但创建请求本身可能已产生未知结果；新代码应使用协调入口。

入口约每五秒轮询一次，整个等待受登记期限、最多五分钟和调用方取消信号约束。相同 JavaScript
运行域内的终端展示或确认互斥；同一个协调对象只允许一个流程在途。不同协调对象、跨进程的
终端及恢复文件所有权需由发行端协调。关闭协调对象只取消它的在途操作，不关闭调用方提供的
客户端和存储。
`presentHostEnrollmentOnTerminal` 和 `approveHostEnrollmentOnTerminal` 也可分别使用，但它们
只负责展示或取得选择，不负责保存恢复记录、发送批准或校验完整绑定流程；调用方必须自行
遵守上述顺序和身份验证要求。

## 验证范围

自动测试使用隔离 PTY 检查准确挑战、拒绝、预先输入、长度限制、取消、无控制终端、并发和
终端控制字符；新建、未知结果恢复、缺失记录、冲突和已有绑定另有小型测试。清理测试还模拟
超过十分钟的过期、版本 1 兼容、错误身份、内容不匹配、损坏及取消。Go / PostgreSQL /
本机 npm DSH `0.2.1-rc.2` 双节点夹具使用临时控制终端，恢复已保存的待确认定位文件和原申请，
以模拟手机及本地身份、模型和密钥服务完成绑定与连接。真实桌面确认界面、学校身份目录、
生产密钥库和目标发行环境仍需验收。
