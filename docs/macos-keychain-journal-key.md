# macOS Keychain 日志密钥命令适配

`MacOSKeychainJournalProtector` 是可选的只读适配器：通过受信任的 `security` 可执行文件，
在明确指定的当前用户 Keychain 文件中查找已预置的 32 字节主密钥，再封装日志数据密钥。
默认插件不自动选择它，不创建／修改 Keychain，不生成或替换主密钥，不回退到 `.key` 文件。

**当前证据是 Apple 接口源码核查、Linux 上的 Darwin 命令协议夹具，以及 Linux 原有链路回归。**
尚未在真实 macOS 执行。此实现不能作为完整 macOS 发行、Keychain 权限、锁定／解锁、系统提示、
扩展 ACL、沙箱或 APFS 持久性的验收通过；Windows DPAPI 仍是独立工作；另有[可选安装签名器](macos-keychain-installation-signer.md)，
同样只有命令协议夹具，未完成真实 macOS 验收。

## 调用与绑定

由发行端预置一个可打印的、规范 Base64 文本，解码后恰为 32 个随机字节，并通过可信配置
提供精确 service/account 和 Keychain 文件。不能把原始二进制、口令或已有模型凭据当作主密钥。
不要通过命令行参数、普通配置、日志或远程协议传递该值。

```ts
import { MacOSKeychainJournalProtector, createRemoteControlPlugin } from '@ustc/dsh-remote-control'
import type { HostCredentialProvider, SignedApprovalOptions } from '@ustc/dsh-remote-control'

declare const credentials: HostCredentialProvider
declare const signedApprovals: SignedApprovalOptions
const protector = new MacOSKeychainJournalProtector({
  executable: '/usr/bin/security',
  keychainPath: '/Users/<current-user>/Library/Keychains/login.keychain-db',
  service: 'cn.edu.ustc.dsh.journal',
  account: 'preprovisioned-runtime-master',
})
const plugin = createRemoteControlPlugin(credentials, signedApprovals, protector)
// 还需显式配置 requireProtectedJournalKey: true。
```

这只连接日志封装接口，不提供 macOS 学校账号适配、安装密钥登记或完整已登记运行时的发行装配。
这些依赖仍须由经过审阅的发行集成提供。构造器仅允许 Darwin；其他平台在启动 helper 前拒绝，
没有用于生产的模拟平台／降级开关。

实际命令的参数固定为：

```text
security find-generic-password -s <service> -a <account> -w <absolute-keychain-path>
```

service/account 仅允许有界的字母、数字、点、下划线和连字符，且不以短横线开头。
命令不使用 shell，stdin 关闭；参数中只有非秘密引用，没有数据密钥或主密钥。
必须指定 Keychain 文件，不回退到用户的默认搜索列表、其他文件或系统 Keychain。

可执行文件须为规范化绝对路径、root／当前用户所有的可执行普通文件，不允许符号链接、
setuid/setgid 或其他用户可写路径。Keychain 路径须为规范化绝对路径、当前用户所有的 0600
普通文件，且只有一个硬链接；父目录链执行相同的所有权和不可替换检查。库只检查，不修改
Keychain 文件权限。Unix mode 检查不证明 macOS 扩展 ACL 或条目访问控制符合发行策略。

## 命令行为与边界

Apple 官方 SecurityTool 的[手册](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/security.1)
和[查找实现](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/keychain_find.c)
说明 `-a` / `-s` 匹配属性，`-w` 只把密码写到 stdout，余下参数构成指定 Keychain 数组。
`do_password_item_printing` 对不可打印字节可能输出十六进制，因此预置值必须是可打印的 Base64
文本；本适配器不猜测其他编码。

2026-10-31 读取的 `keychain_find.c` 内容 SHA-256 为
`d2c7f006e9bba0585de241e579441662488d4397bafd9587b22df7e0c90216e9`。
这是命令接口核查记录，不是目标机器上 `/usr/bin/security` 的版本证明。

该命令调用 Keychain 内容读取，可能遇到系统授权／解锁提示。当前适配器**不承诺无 UI**，
不自动响应或批准提示。若发行策略要求完全非交互，应保持该适配器未启用，并选择经过目标
系统验证的原生集成。停止一个 CLI 子进程不等于已经验证 SecurityAgent 界面的清理行为。
Keychain 的系统授权与手机对工具调用的签名审批是两个独立边界。

每次操作重新读取主密钥，stdout 上限 128 字节，stderr 丢弃；缺失、锁定、权限拒绝、非零退出、
无效编码、超长输出和取消都报告固定不可用错误，不复制原始输出或异常。已有日志的正常打开
流程给封装调用五秒期限并联动账号／插件取消；直接调用 wrap/unwrap 时，调用方也应提供有期限
的 AbortSignal。只有当前进程拥有的 helper 会被终止，取消后不发布迟到密钥结果。

公共命令读取器每实例最多八项未结束的文件系统检查和八个尚未 close 的 helper；取消不会
提前释放仍存活 helper 的名额。SIGTERM 后有 250 ms 的 SIGKILL 升级，失败路径关闭 stdout
并清除已接收片段。环境中的 LD_/DYLD_、NODE_OPTIONS、PYTHONPATH/PYTHONHOME 不传给 helper。
这些是用户态边界，不是系统调用或内核进程退出的硬实时保证。

Keychain 引用的路径、service、account 进入稳定 provider ID 的摘要；包／日志中的 ID 不含
这些原始值。新封装使用独立的 `DSHKCK01` 与 HMAC 派生域，包含随机 salt、nonce 和 AES-256-GCM，
认证上下文与现有日志层的 runtime／路径／provider 绑定共同检查。现有 Linux `DSHSSK01`、
provider ID、派生域和 100 字节格式保持不变，不会把两个后端的密文混用。

主密钥丢失、变更或引用错误时，已有密文不被覆盖；恢复应按已批准流程保全原文件和密钥。
打开后的数据密钥仍位于 Host 进程内，锁定 Keychain 不会自动撤回它。账号结束和当前权限
检查继续独立生效；JavaScript／原生加密库及外部 CLI 的全部内存擦除不在可保证范围内。

## 本地验证

- 五类独立子进程夹具覆盖往返／认证失败、持久日志重开与错误主密钥、参数及错误输出、
  文件／符号链接／硬链接／可写目录拒绝、取消与八个 helper 上限及退出后恢复。
- 夹具先加载代码，再仅在自身 Node 进程模拟 `process.platform=darwin`；它使用测试程序和
  无 Keychain 格式的占位文件，不调用系统 security、不读取用户 Keychain。这些结果只能
  证明命令和调用方边界，不能证明真实 macOS 行为。
- 构造器在实际非 Darwin 平台拒绝。公共字符串／inspect／JSON 不包含主密钥和原始引用；
  参数中没有密钥；取消的无协作 helper 被终止，占位 Keychain 文件内容保持不变。
- Linux 已有封装格式的独立 HMAC/解密检查、隔离 Secret Service、安装签名器、日志和登记
  恢复继续通过；完整 Host 验证 488 项，无跳过。本机 npm dsh 0.2.1-rc.2、两个生产 Go 进程
  和私有 PostgreSQL 的原有 Linux 正常链路另行回归。

记录：`.local/macos-keychain-focused-final.log`、`.local/macos-keychain-host-verify-final.log`、
`.local/macos-keychain-linux-dsh.log`。身份、模型和密钥服务为本地夹具；没有修改 Android APP、
提交 PLAN.md、尝试 TokenWorks，也没有运行大负载、真机或厂商推送配置。
