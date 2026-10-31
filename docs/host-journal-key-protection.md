# 主机日志密钥的可插拔封装

主机命令日志和审批日志共用一个 32 字节数据密钥。调用方现在可以为插件显式提供
`JournalKeyProtector`，由受信任的平台适配层封装该密钥；SQLite 同目录只保留受保护的
`.wrapped-key` 文件，命令和审批内容仍由现有 AES-256-GCM 日志加密。

仓库提供[Linux Secret Service 适配器](linux-secret-service-journal-key.md)，其目标发行版和
生产会话仍需验收。另有可选的[macOS Keychain 命令适配](macos-keychain-journal-key.md)，
目前只有接口核查与 Linux 上的 Darwin 协议夹具，尚无 macOS 平台验收；DPAPI 和硬件密钥
适配尚未实现。默认的本地
文件模式仍会使用 `.key`；它适用于明确接受该边界的开发环境，不能当作平台保护。生产集成
必须自行提供经过审阅的平台封装器并配置 `requireProtectedJournalKey: true`，封装器缺失、
不可用、损坏或身份不匹配时启动失败，不回退到文件模式。

## 接口和所有权

`JournalKeyProtector` 的 `id` 是稳定的非秘密标识，只允许小写字母、数字、点、下划线和连字符，
长度不超过 64。`wrap` / `unwrap` 接收密钥材料、绑定上下文和取消信号，返回的字节数组所有权
交给调用方，调用方会复制并清除返回数组。封装器必须使用经过验证的机密性和完整性保护，将
提供的上下文纳入认证，并保持相同 `id` 对应同一可恢复的保护密钥；接口本身无法证明第三方
实现安全，也不会替代其访问控制和密钥轮换方案。

```ts
import { createRemoteControlPlugin, type HostCredentialProvider, type JournalKeyProtector, type SignedApprovalOptions } from '@ustc/dsh-remote-control'

// platformProtector 由发行端受信任的平台密钥设施提供，不是可直接运行的示例实现。
declare const platformProtector: JournalKeyProtector
declare const hostCredentials: HostCredentialProvider
declare const signedApprovalOptions: SignedApprovalOptions
const plugin = createRemoteControlPlugin(hostCredentials, signedApprovalOptions, platformProtector)
// 插件配置同时设置 requireProtectedJournalKey: true。
```

绑定上下文包含 runtime UUID、规范化的绝对日志路径和封装器标识。复制数据库及封装文件到
另一条路径不会自动解封；恢复到原路径，或通过另行设计的受控迁移重新封装。封装器更换、
平台密钥丢失或路径变化不会自动生成替代密钥，也不会恢复旧授权。

封装调用有五秒上限并传入取消信号；插件卸载或凭据所有者取消时会中止正在等待的调用。
不遵守取消的适配器不能继续发布结果，但仍可能保留其自身复制的内存，不能承诺 JavaScript
或外部平台进程的安全擦除。SQLite 同步 I/O 与操作系统调用也不构成硬实时保证。

## 首次创建、旧日志迁移和故障

新日志先生成随机数据密钥，通过封装器往返校验后写入仅所有者可访问的临时文件；文件同步、
不可覆盖发布和目录同步完成后再创建或打开数据库。并发创建采用已发布的同一份封装密钥；
已有损坏或不同内容不会被覆盖。封装文件与数据库均使用 0600，目录要求为当前用户拥有的
0700，路径不得经过符号链接。当前封装文件实现只在 POSIX 平台启用；Windows 适配和目标系统
的文件权限/持久性需另行实现和验证。

已有 `.key` 的日志先用原密钥验证数据库和日志完整性，再封装、回读校验并持久发布，最后
确认旧密钥文件仍为同一安全普通文件后删除并同步目录。旧密钥存在额外硬链接、权限异常、
内容变化或与已存在的封装文件不一致时失败并保留原文件。进程在发布后、删除旧密钥前退出时，
下次使用相同封装器核对两者并继续；默认文件模式看到封装文件时拒绝降级。
如果文件模式与封装模式在同一空路径同时首次启动，可能留下不匹配的两份密钥文件并拒绝启动；
原数据库不会被覆盖，需由操作人员根据可信备份和完整性检查进行对账。部署时应先停止旧实例，
再切换密钥模式。

旧备份或曾经复制过的明文 `.key` 不会被此迁移自动找到或擦除，应按组织的备份、密钥轮换和
保留流程处理；删除文件也不保证底层介质被安全擦除。只有本地数据库存在、两种密钥文件均缺失时，程序拒绝重新生成密钥。密钥丢失
意味着旧日志无法解密，应按已批准的备份/重登记流程恢复，不能用新密钥掩盖旧状态。

## 本地验证边界

临时目录测试覆盖新建、旧日志迁移、错误密钥、封装器失败、取消、路径/身份绑定、损坏文件、
硬链接和符号链接拒绝、并发创建及插件卸载。Go/PostgreSQL/npm DSH 双节点夹具使用测试密钥
服务对端验证正常插件链路；隔离的 D-Bus/GNOME Keyring 另行验证 Secret Service 存取。
未使用 TokenWorks、真实学校身份、生产系统密钥库、Android、真机、大负载或厂商推送配置。
