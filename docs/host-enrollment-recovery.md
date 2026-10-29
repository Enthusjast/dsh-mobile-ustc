# Linux 主机登记恢复存储

`HostEnrollmentRecoveryStore` 为一条待处理的主机登记尝试保存认证加密的恢复记录。它与
[`HostEnrollmentClient`](host-enrollment-client.md) 配合：调用方先保存尝试，再发送创建请求；
进程重启后加载同一 request ID 和配对码，并显式对账。它不保存 access token、安装私钥、手机
审批密钥或聊天正文，也不会自行连接服务或自动提交登记。

## 保护与使用

存储只支持 Linux，路径必须是绝对路径；父目录必须由当前用户拥有且为 `0700`，文件为
当前用户拥有的 `0600` 普通文件。路径不能经过符号链接；祖先目录必须由 root 或当前用户拥有，
组或其他用户可写的祖先目录必须带 sticky 位。实现使用 `/proc/self/fd` 固定已检查的父目录；
系统不提供这些能力时失败关闭。应为一个安装身份 / profile 使用专门的私有目录和文件。

调用方必须提供受信任的 `JournalKeyProtector`；没有文件明文密钥回退。每条记录使用随机
32 字节数据密钥和 AES-256-GCM，将数据密钥通过封装器保护。文件的完整性认证绑定恢复路径、
封装器标识和由资源 origin、账号、客户端、scopes、安装公钥派生的客户端绑定值。错误账号、
安装密钥、路径、封装器、损坏文件或不可用密钥库都会失败，不会创建替代记录。Linux 可使用
[Secret Service 封装器](linux-secret-service-journal-key.md)，但其实际部署、解锁、备份和恢复
策略仍由发行端负责。

```ts
import {
  HostEnrollmentClient, HostEnrollmentRecoveryStore,
  type HostEnrollmentOptions, type JournalKeyProtector,
} from '@ustc/dsh-remote-control'

declare const options: HostEnrollmentOptions
declare const protector: JournalKeyProtector
declare const privateRecoveryPath: string
declare const trustedOrganizationId: string
declare const signal: AbortSignal
const client = new HostEnrollmentClient(options)
const store = new HostEnrollmentRecoveryStore({ path: privateRecoveryPath, client, protector })

let attempt = await store.load(signal)
if (!attempt) {
  // 仅在调用方已确认没有未对账的旧请求时创建新尝试。
  attempt = client.prepare({ organizationId: trustedOrganizationId, alias: '办公室电脑',
    profileRef: 'default', protocolVersion: 1, workspaceRefs: ['project'] })
}
const receipt = await store.create(attempt, signal) // 先持久保存，再发起创建请求
// 手机确认后，使用 HostEnrollmentBindingStore.confirm 保留绑定 ID 并取得本机明确同意。
// 已确认完成且服务端绑定 ID 已可靠保存后：await store.remove(attempt, signal); attempt.destroy();
// 不再使用时：store.close(); client.close();
```

`store.create` 和 `store.confirm` 先调用 `save`，只有保存成功才显式调用客户端的对应操作；
如果网络结果未知，受保护记录保留供对账。`save` 不覆盖已有文件：相同恢复内容可幂等保存，
不同尝试返回 `conflict`；应先加载并处理
原记录。创建使用仅含密文和封装密钥的私有临时文件，完成文件同步后以不可覆盖的硬链接发布、
同步目录，再读回并认证。若进程在发布后退出，加载时只清理指向同一 inode 的本存储临时链接；
其他硬链接被拒绝。发布之前遗留的临时文件也不含明文，但不会自动删除，需在停止所有相关
进程后按本机保留策略清理。

`remove(attempt, signal)` 只删除解密后与指定尝试完全一致的记录；`discard(signal)` 是显式丢弃
操作，可用于已过期但仍能认证的记录。不要在创建或确认结果未知时自动丢弃：丢失恢复记录会
失去按原 request ID 和配对码安全重试的能力。文件不存在只能说明本机没有记录，不能证明服务端
从未处理旧请求。取消或 I/O 错误发生在发布后时，文件可能已经存在；应先加载或用同一尝试
重试保存，不应直接开始新的登记。

同一 JavaScript 运行域内（包括重复加载的包）同一路径只允许一个存储操作；`store.create` 和
`store.confirm` 在对应操作结束前保持该限制，避免同一运行域提前删除恢复记录。不可覆盖发布也能避免两个进程
相互覆盖。删除操作的
文件身份检查不是跨进程原子锁，发行端必须保证同一恢复路径同时只有一个宿主所有者，不能让
一个进程删除另一个进程的新记录。账号取消或 `close()` 后存储拒绝读取；若此时需要清理，应在
相同身份恢复后显式处理。删除不保证擦除备份、底层介质或 JavaScript / 系统库内存副本。平台
封装调用有期限和取消信号，文件系统本身不提供硬实时保证。

## 本地证据与边界

小型测试覆盖重开、幂等保存、冲突、错误身份/密钥/路径、篡改、权限和链接、过期丢弃、取消、
迟到的封装结果、两个进程竞争保存，以及创建或确认响应丢失后的恢复。隔离 D-Bus / 临时 GNOME Keyring 通过 libsecret 测试命令保存并
恢复真实加密记录；Go / PostgreSQL / 本机 DSH 双节点夹具使用独立测试命令对端。没有访问
用户现有密钥库。目标发行版的 `secret-tool`、生产会话解锁、备份和本机确认界面仍需验收。
