# Linux 安装密钥生成与重开

`LinuxInstallationKeyStore` 在当前用户的 Secret Service 中创建一把 P-256 安装密钥，并保存
不含私钥的本机引用。它只在调用 `create` 时生成密钥；`open` 只读取已有身份，不会因为文件或
密钥库缺失而创建新密钥。返回的公钥和签名器可用于[主机登记客户端](host-enrollment-client.md)
和[连接凭据 provider](host-credential-provider.md)。

```ts
import { LinuxInstallationKeyStore } from '@ustc/dsh-remote-control'

declare const ownerSignal: AbortSignal // 安装所有者退出或身份切换时取消
declare const operationSignal: AbortSignal
const keys = new LinuxInstallationKeyStore({
  path: '/home/example/.local/share/dsh-remote/installation/reference.json',
  executable: '/usr/bin/secret-tool',
  service: 'ustc-dsh-installation',
  ownerSignal,
})
let installation = await keys.open(operationSignal)
// 只有已确认这是首次安装时才显式调用 keys.create(operationSignal)。
// 已有安装的文件丢失时应先恢复或撤销旧安装，不能自动创建替代身份。
if (!installation) throw new Error('installation identity requires setup or recovery')
// 将 installation.publicJwk 和 installation.signer 交给主机登记 / 凭据接口。
// 不再使用时调用 installation.close(); keys.close()。
```

路径、Secret Service 命名空间和可执行文件必须来自可信本机配置。路径所在目录与
[登记恢复存储](host-enrollment-recovery.md)一样要求当前用户 `0700`、无符号链接及可信祖先；
引用文件为 `0600`。`secret-tool` 使用与[现有签名器](linux-secret-service-installation-signer.md)
相同的程序和目录校验。它必须能访问该用户的 D-Bus 和已解锁 Secret Service；新条目使用随机
引用，避免选择固定属性并覆盖已有条目。

## 原子性与恢复

创建时生成新的 P-256 私钥和 192 位随机非秘密条目引用，通过 stdin 将规范 base64 PKCS#8
写入 Secret Service，随后重新读取并验证私钥、公钥和签名。私钥不会出现在命令行参数或本机
引用文件中。引用文件包含路径绑定、公钥、非秘密条目属性和由该私钥生成的完整性签名；文件
经同步和不可覆盖发布后再读回验证。复制引用到其他路径会被拒绝。这个自签名用于检测引用
不一致，不能防御已经控制当前用户及其已解锁密钥库的进程，也不提供硬件隔离。`secret-tool`
会更新属性完全相同的条目，因此唯一性依赖随机引用和受信任的当前用户会话。

已有引用、损坏引用、错误密钥、不可用或锁定的密钥库均不会被覆盖或替换。`create` 遇到已有
文件返回 `host.installation_key.exists`；应使用 `open` 核对原身份。同一 JavaScript 运行域内
同一路径只允许一个操作，独立进程通过不可覆盖发布竞争，失败者不能覆盖成功者。

Secret Service 写入、文件发布或取消可能发生在调用方收到结果之前。`host.installation_key.outcome_unknown`
表示需要先调用 `open` 对账；若引用已经存在且能验证，继续使用该身份。若引用不存在但操作曾
进入密钥库，可能留下未被引用的密钥库条目；此时本 API 尚未返回身份，也没有发起服务端登记。
只有确认确属首次安装且没有旧身份需要恢复时，调用方才可显式重试。竞争失败和崩溃也可能留下
孤立条目；代码不会自动执行可能误删其他条目的 `secret-tool clear`。应在停止相关进程后，由
操作人员按密钥库策略核对和清理。

当前实现不负责密钥轮换、旧安装撤销、跨路径迁移或备份；这些操作必须保持服务端授权边界。
服务端旧安装可通过[安装发现与撤销入口](installation-management.md)显式退役；该操作不会删除
此处的本机密钥或引用，也不会生成替代身份。
恢复应使用经过验证的密钥库备份及原引用路径，丢失密钥后需撤销旧安装并重新绑定。关闭 store
或取消所有者 signal 会使其返回的签名器失效。Secret Service 后端自身的断电持久性需在目标
发行版验证；写入成功和重新读取不构成断电验收。该引用不保存服务端分配的 installation / runtime
ID；可通过[绑定定位存储](host-enrollment-binding.md)在清理待处理记录前可靠保存。可控缓冲区在使用后清除，但不能保证 JavaScript、
OpenSSL、密钥库或内核中的所有副本被擦除。

## 本地验证与限制

小型测试覆盖生成、重开、公钥证明、损坏或替换、路径权限、取消、密钥库错误和跨进程竞争。
本机未安装 `secret-tool`；验证时从 Ubuntu `libsecret-tools` 0.21.7-2build1 包提取实际程序到
临时私有目录，在隔离 D-Bus / 临时 GNOME Keyring 中创建并重开密钥，没有修改系统安装或访问
现有用户密钥库。该次提取的程序 SHA-256 为
`949b1223e548aa2a2b33e63493b2ee174ff3da986cc38c2d8ac4328d578e99c3`。
Go / PostgreSQL / 本机 DSH 双节点组合使用测试命令对端，验证生成身份、登记、
Host 凭据和 Relay。学校 SSO、生产密钥库、发行版解锁策略及桌面确认界面仍需独立验收。
