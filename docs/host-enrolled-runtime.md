# 已登记主机的插件启动

Linux 发行集成可使用 `createEnrolledRemoteControlPlugin` 启动正常 Relay 插件。它在打开命令
日志、调试 socket 或 Relay 之前重新读取受保护绑定并向服务端核对批准状态，再检查配置的运行
实例、profile、安装身份及工作区映射。绑定缺失、待确认、被撤销、无法复核或配置不一致时，
插件启动失败，不会自动重新登记。

## 接入

先通过[主机登记流程](host-local-enrollment.md)获得批准并持久化绑定，再由发行端提供相同
资源账号、安装签名器、受保护日志密钥封装器和审批策略：

```ts
import {
  createEnrolledRemoteControlPlugin, HostEnrollmentBindingStore, HostEnrollmentClient,
  HostRestCredentialProvider,
  type HostEnrollmentOptions, type HostRestCredentialOptions, type JournalKeyProtector,
  type SignedApprovalOptions,
} from '@ustc/dsh-remote-control'

// 值来自可信发行配置、当前已验证账号和受保护安装密钥。
declare const enrollmentOptions: HostEnrollmentOptions
declare const credentialOptions: HostRestCredentialOptions
declare const bindingPath: string
declare const bindingProtector: JournalKeyProtector
declare const journalProtector: JournalKeyProtector
declare const signedApprovals: SignedApprovalOptions
declare const profileRef: string

const client = new HostEnrollmentClient(enrollmentOptions)
const binding = new HostEnrollmentBindingStore({ path: bindingPath, client, protector: bindingProtector })
const credentials = new HostRestCredentialProvider(credentialOptions)
const plugin = createEnrolledRemoteControlPlugin({ client, binding, credentials, profileRef }, signedApprovals, journalProtector)
export const { name, inject, apply } = plugin
// 发行端退出或切换账号时，取消账号 signal 并关闭上述对象。
```

插件配置必须设置 `relayUrl`、`applicationVersion`、已登记的 `runtimeId` 和
`requireProtectedJournalKey: true`。每个 `workspaces[].id` 必须等于登记时的 workspace reference，
`remoteId` 必须等于该 reference 对应的登记 UUID；可以只启用已登记工作区的子集，但不能重复
引用、UUID 或规范化后的本地路径。`signedApprovals` 中的 host / installation ID 必须与绑定一致。
绑定客户端与凭据 provider 使用的 origin、issuer、subject、audience、client ID、安装公钥及
scope 列表必须一致，scope 顺序也必须相同。

## 所有权与边界

已批准绑定仍只是定位信息，不是当前连接权限。每次插件加载都在线复核；后续凭据签发、握手、
授权租约和撤权仍由服务端检查。账号、绑定存储或凭据 provider 的 signal 结束时，Relay 会停止；
加载器卸载时会取消尚未完成的在线核对。调用方仍负责关闭自己创建的客户端、存储、签名器和
provider。可选的本机调试 socket 具有独立的本地访问边界，不应当作生产远程入口。

`profileRef` 和 reference 到本机 `cwd` 的映射必须由可信发行配置提供。校验只比较声明值及路径
的词法规范化结果，不能证明进程实际属于某个桌面 profile，也不证明不同符号链接或挂载不会
指向同一目录；发行端必须维护这层所有权关系。封装器接口的存在也不能证明第三方密钥库已达到
生产保护要求。学校登录、真实身份目录、生产密钥库和目标发行生命周期仍需独立验收。

`apply` 和 `createRemoteControlPlugin` 仍保留供 M0 调试或其他显式集成使用；它们没有上述
绑定到配置的检查。不要把未使用该检查的入口当作已完成的发行集成。

## 本地验证

小型测试覆盖缺失或待确认绑定、错误账号 / origin / scope / 安装密钥、错误 host / runtime /
profile / 工作区、重复映射和加载过程中取消；错误映射在日志和 socket 创建前被拒绝。
Go / 隔离 PostgreSQL / 本机 npm DSH `0.2.1-rc.2` 双节点夹具让正常插件重新打开已批准绑定，
验证声明后完成签名连接、会话和审批链路。测试使用本地 issuer、模型与密钥服务，不代表学校
身份或生产发行验收。
