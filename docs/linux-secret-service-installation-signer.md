# Linux Secret Service 安装密钥签名器

`LinuxSecretServiceInstallationSigner` 为现有
[`HostRestCredentialProvider`](host-credential-provider.md) 提供安装密钥签名。它从当前用户的
Secret Service 读取**预先配置**的安装私钥，用于资源请求、一次性凭据交换和 Relay 握手；
不创建或替换密钥、不发起安装登记，也不自行取得学校资源登录态。Linux 首次安装可使用
[安装密钥生成与重开](linux-installation-key.md)，其生命周期和生产验收边界单独说明。

部署方通过可信流程配置唯一条目。值须为 P-256 私钥的 PKCS#8 DER 编码，再按 RFC 4648
标准 base64 编码；此格式应与 Node 的 PKCS#8 导出一致。查找属性 `service` 和 `account`
必须稳定、非秘密，不能放入密钥、密码或 token。每次签名均重新读取条目，并对照调用方提供的
已登记公钥，拒绝私钥替换、错误曲线、非规范编码或不一致的公钥。签名为 ES256 使用的
64 字节 IEEE-P1363 格式。

适配器不会检查同属性条目的唯一性；部署流程必须保证唯一性和可信的公钥登记。保护密钥不能
作为日志密钥复用；安装重新登记、旧安装撤销、备份及轮换仍需独立流程，不能通过覆盖条目
使新密钥自动继承旧授权。

## 接入

`secret-tool` 必须满足[日志密钥适配器](linux-secret-service-journal-key.md)相同的程序路径、
目录权限和用户会话条件。下面的公钥、学校资源配置、登录适配器和 installation ID 必须来自
实际已验证的登记和身份流程；代码不实现这些流程。

```ts
import {
  HostRestCredentialProvider, LinuxSecretServiceInstallationSigner,
  type HostResourceAccessProvider, type HostResourceIdentity,
} from '@ustc/dsh-remote-control'

declare const account: HostResourceAccessProvider
declare const identity: HostResourceIdentity
declare const installationId: string
declare const publicJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string }
declare const remoteOrigin: string
const signer = new LinuxSecretServiceInstallationSigner({
  executable: '/usr/bin/secret-tool',
  service: 'ustc-dsh-installation',
  account: 'stable-installation-reference',
  publicJwk,
  ownerSignal: account.signal,
})
const credentials = new HostRestCredentialProvider({
  origin: remoteOrigin, installationId, identity, publicJwk, signer, account,
  requiredScopes: ['remote.access'],
})
// 账号登出或安装密钥切换时 account.signal 必须取消。
// 不再使用时：credentials.close(); signer.close()。
```

每次查找最多等待五秒，最多同时进行八次；达到上限、条目不可用、所有者取消或关闭时均
失败关闭。取消会终止仍在运行的查找子进程；晚到结果不能恢复签名能力。签名器不缓存私钥，
不把私钥放入命令行、错误消息或对象的普通日志表示。与日志适配器一样，它不保证擦除
JavaScript、OpenSSL 或内核中的所有副本，也不提供硬件隔离；已解锁会话中的同用户进程仍可能
访问密钥库。发行端负责退出和重新绑定时结束整个插件的凭据生命周期。

## 本地验证与限制

小型测试覆盖公钥绑定、私钥替换、曲线和编码错误、签名输入副本、并发上限、取消和子进程
清理。隔离 D-Bus / 临时 GNOME Keyring 使用 libsecret 测试命令读取临时安装私钥并验证签名；
Go / PostgreSQL / npm DSH 双节点夹具使用独立测试命令对端。没有访问用户现有密钥库。

本机没有 `secret-tool`，因此这些证据不代表已验证目标发行版的该二进制、生产会话解锁策略、
学校资源登录、安装登记或恢复流程；生产部署前仍需分别验收。
