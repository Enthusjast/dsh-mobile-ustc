# Linux Secret Service 日志密钥封装器

`LinuxSecretServiceJournalProtector` 是[主机日志密钥封装接口](host-journal-key-protection.md)的
Linux 实现。它调用受信任的 `secret-tool lookup`，从当前用户的 Secret Service 读取预先配置的
保护密钥，再用随机 salt 派生子密钥，以 AES-256-GCM 封装日志的数据密钥。runtime、日志绝对
路径和封装器标识被绑定到认证数据；封装文件损坏或绑定不同时不能解封。

适配器只读取现有条目，不创建、更新或替换 Secret Service 数据。部署方必须通过受控流程事先
配置**唯一**条目：值为 32 字节随机密钥的规范 RFC 4648 base64 文本，`service` 与 `account`
是稳定、非秘密的查找属性。不要把密码、token 或密钥本身放进属性；命令行只携带这些属性，
密钥通过子进程输出读取，不出现在参数或应用日志。适配器不会检查多个同属性条目的唯一性，
必须由部署流程保证；错误或不稳定的条目会使解封失败，不会生成替代密钥。

## 接入

`secret-tool` 的路径必须是绝对路径，指向非符号链接的普通可执行文件；文件和其父目录必须
由 root 或当前用户拥有，且不能被组或其他用户写入。其所有祖先目录也必须由 root 或当前用户
拥有；组或其他用户可写的祖先目录必须设置 sticky 位，以防其他用户替换可信用户拥有的路径。
部署方应提供可信系统程序路径，当前会话
必须能够访问正确的 D-Bus 和已解锁 Secret Service；可执行文件不能带 setuid/setgid 等特殊权限。
适配器剔除动态链接器注入变量，不输出
子进程的 stderr，也不跟随 shell 命令字符串。

```ts
import {
  LinuxSecretServiceJournalProtector, createRemoteControlPlugin,
  type HostCredentialProvider, type SignedApprovalOptions,
} from '@ustc/dsh-remote-control'

declare const hostCredentials: HostCredentialProvider
declare const signedApprovalOptions: SignedApprovalOptions
const protector = new LinuxSecretServiceJournalProtector({
  executable: '/usr/bin/secret-tool',
  service: 'ustc-dsh-journal',
  account: 'stable-installation-reference',
})
const plugin = createRemoteControlPlugin(hostCredentials, signedApprovalOptions, protector)
// 插件配置同时设置 requireProtectedJournalKey: true。
```

以上路径和属性是示例，需在目标机器核对。配置项和属性不是密钥备份方案。条目丢失、被替换、
锁定或服务不可用时日志启动失败，不回退到同目录明文密钥。封装器标识由查找属性派生；属性
改变或保护密钥被覆盖都会使旧封装文件不可用。当前没有自动轮换或跨主机迁移，应先制定经
验证的恢复和重新封装流程，不能覆盖已有条目后再尝试恢复旧日志。
日志打开流程会为封装调用设置五秒期限；若直接调用适配器，应自行提供有限期限的取消信号。

## 安全边界

进程会在内存中短暂持有保护密钥和数据密钥，并在可控缓冲区中清除它们；不能承诺清除所有
JavaScript、系统库或内核副本。当前用户会话已解锁时，同用户恶意进程可能使用同一 Secret
Service；本适配器不提供硬件隔离，也不证明后台密钥库的加密、解锁策略或发行版配置。旧
`.key` 的迁移和历史备份限制见[日志密钥说明](host-journal-key-protection.md)。
日志打开后数据密钥保留在当前进程，Secret Service 后续锁定不会自动撤回它；发行端仍需在
账号退出或密钥所有权变化时取消凭据生命周期并卸载插件。

## 本地验证与限制

小型测试覆盖严格 base64 解码、密钥上下文绑定、密文篡改、不可用/错误响应、可执行文件和
祖先目录权限、取消与子进程退出，以及调用参数和日志脱敏。另有隔离的 D-Bus 会话和临时 GNOME
Keyring：通过 libsecret 的测试命令适配层存取临时保护密钥，实际创建并重开受保护日志；没有
访问用户现有密钥库。本机未安装 `secret-tool`，因此尚未直接验证目标发行版的该二进制或生产
会话解锁策略。npm DSH 组合使用测试命令对端；真实学校身份、生产密钥库、Windows/macOS、
Android、真机和大负载不在本次证据内。
