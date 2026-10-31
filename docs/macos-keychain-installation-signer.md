# macOS Keychain 安装密钥签名适配

`MacOSKeychainInstallationSigner` 是可选的只读安装签名器。它从指定的当前用户 Keychain
读取预先配置的安装私钥，每次签名前核对已登记公钥，返回 ES256 使用的 64 字节
IEEE-P1363 签名。它不生成、登记、替换、持久化或返回安装私钥，不缓存私钥。

当前只有接口源码核查与 Linux 上的 Darwin 协议夹具。没有在真实 macOS 调用 Keychain，
不能据此宣称完成 macOS 平台、系统提示、沙箱、条目／扩展 ACL 或锁定／解锁验收。
它也不是 Secure Enclave／硬件签名接口：私钥会被当前 Host 进程和 Node/OpenSSL 短暂使用。

## 配置与接入

由可信发行流程配置唯一的安装私钥条目。值须为 P-256 的规范 PKCS#8 DER，再编码成单行
标准 Base64 可打印文本；与 Node 的 PKCS#8 导出保持一致。不要存成原始二进制或 PEM，
也不要把口令、模型凭据或[日志主密钥](macos-keychain-journal-key.md)作为安装签名密钥。

`publicJwk` 来自已经验证的安装登记；不能把条目中新出现的私钥自行解释成同一已登记身份。
同属性条目的唯一性、条目预置、公钥登记、备份和轮换由可信发行流程负责。适配器不创建
Keychain，也不会修改其搜索列表、条目、访问控制或文件权限。

```ts
import {
  MacOSKeychainInstallationSigner, HostRestCredentialProvider,
  type HostResourceAccessProvider, type HostResourceIdentity,
} from '@ustc/dsh-remote-control'

declare const account: HostResourceAccessProvider
declare const identity: HostResourceIdentity
declare const installationId: string
declare const publicJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string }
declare const remoteOrigin: string
const signer = new MacOSKeychainInstallationSigner({
  executable: '/usr/bin/security',
  keychainPath: '/Users/<current-user>/Library/Keychains/login.keychain-db',
  service: 'cn.edu.ustc.dsh.installation',
  account: 'preprovisioned-installation-reference',
  publicJwk,
  ownerSignal: account.signal,
})
const credentials = new HostRestCredentialProvider({
  origin: remoteOrigin, identity, installationId, publicJwk, signer, account,
  requiredScopes: ['remote.access'],
})
// 账号结束／安装更换时须取消 account.signal。
// 不再使用时关闭 credentials 和 signer。
```

此例只连接已登记安装的签名接口，不提供 macOS 安装密钥生成器、首次登记 UI 或学校登录
适配器。完整 macOS 发行装配仍未通过；默认插件没有自动启用这一后端。

## 读取、签名与所有权

与日志适配器共用只读 Keychain 引用验证：仅 Darwin、受信任的绝对 security 程序路径、
明确的当前用户 0600 单链接 Keychain 文件、规范路径及受保护父目录链。service/account
为有界的非秘密属性。实际命令仍是 `find-generic-password -s ... -a ... -w <keychain>`，
不使用 shell，参数不含私钥、主密钥、口令或 token，不回退到其他 Keychain／默认搜索列表。
[Apple 接口依据和系统 UI 边界](macos-keychain-journal-key.md#命令行为与边界)继续适用。
尤其不能将 `-w` 当作无系统提示保证，也不应自动响应系统授权对话框。

每次 sign 重新读取值，stdout 上限 2048 字节、DER 上限 1024 字节。接着检查规范 Base64、
可解析的 PKCS#8、P-256 曲线及规范 DER 重导出字节相等，再从私钥推导公钥，与构造时冻结
的已登记 JWK 逐字段核对。错误曲线、尾随字节、替换私钥或身份不匹配均失败关闭，不会通过
更新内存公钥让新条目继承旧权限。Linux 签名器共用这些检查，保留原有格式和错误口径。

签名输入在第一次异步读取前复制，范围 1–16384 字节；每实例最多八个在途签名，单次查找
有五秒取消期限。ownerSignal、close 或超时会结束在途调用；晚到条目不能恢复签名能力。
关闭后再次 sign 同样拒绝，close 可重复调用。只终止自己拥有的查找子进程，系统 UI 清理
和内核硬实时退出仍不能由 Linux 夹具证明。

输入、编码数据、DER 和重导出副本在结束时清除；JavaScript、Node/OpenSSL 和系统 CLI 的
全部内存副本擦除不在可保证范围内。普通 string/inspect/JSON 不返回私钥或原始查找引用。
数据签名也不替代服务端当前安装状态、密钥版本、挑战用途、连接证明和用户／资源授权检查。

## 本地验证与待验项目

独立 Node 子进程只在夹具自身模拟 Darwin，使用测试程序和占位 Keychain 文件；不调用
系统 security、不访问用户 Keychain。用例覆盖：

- 签名格式、已登记公钥验证、异步输入副本和调用方配置变化。
- 私钥替换、错误曲线、非规范 DER／Base64、错误用途字节、超长输出、非零退出与权限变化。
- 所有者结束、close、八个并发操作上限、无协作 helper 清理和关闭后的拒绝。
- 参数、普通对象表示不含私钥；占位 Keychain 内容不变，不产生持久私钥副本。

Linux 原有安装签名、日志封装和隔离 Secret Service 回归通过；完整 Host 验证为 493 项，
本机 npm dsh 0.2.1-rc.2、两个生产 Go 进程与私有 PostgreSQL 的正常 Linux 链路另行回归。
实际 macOS 的预置／读取、权限、UI、锁定、账号切换、私钥恢复和签名进程身份仍须独立验收。

记录：`.local/macos-signer-focused.log`、`.local/macos-signer-host-verify.log`、
`.local/macos-signer-linux-dsh.log`。身份、模型、证书和密钥服务为本地夹具；没有修改 Android
APP、提交 PLAN.md、尝试 TokenWorks，未运行大负载、真机或厂商推送配置。
