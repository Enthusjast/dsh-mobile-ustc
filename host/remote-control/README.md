# Remote Control 进程内原型

本包是默认关闭的 Cordis 函数插件，导出 `name / inject / Config / apply`，使用当前进程的服务，不启动 SDK 子进程。运行 `npm run build` 后装配 `lib/index.js`。

M0 支持工作区白名单内根会话的列表、创建、文本 queue / steer、中断、可用模型列表和选择、快照、固定切点历史分页和 assistant 流，以及本地单次工具审批、普通提问和计划确认。模型选项从当前桌面目录校验；不接受手机指定桌面未注册的 provider、model 或 reasoning effort。DSH 原生会话 ID 保留在映射层，对外用按 profile 隔离的稳定 UUID。

本机 IPC 是显式选择的调试入口；仅使用 Relay 时可省略 `socketPath`。启用 IPC 时：Linux / macOS 使用权限 0700 父目录内的 Unix socket，Windows 使用按 runtime 隔离、`readableAll` 与 `writableAll` 均关闭的命名管道。修改示例配置为实际 profile 的稳定 UUID、绝对路径和已存在 preset：

```yaml
- id: ustc-remote-control
  name: /absolute/path/to/dsh-mobile-ustc/host/remote-control/lib/index.js
  config:
    enabled: true
    runtimeId: 44444444-4444-4444-8444-444444444444
    socketPath: /tmp/dsh-remote-private/probe.sock
    workspaces:
      - id: project
        remoteId: 66666666-6666-4666-8666-666666666666 # workspace UUID returned by host enrollment
        label: 项目名称 # 明确允许展示给手机的名称；不从 cwd 或本地 id 推导
        cwd: /absolute/path/to/workspace
    presets: [your-existing-preset]
    highRiskTools: [bash, pwsh, run_code]
```

M1 可选配置 `relayUrl` 和真实 `applicationVersion`。启用 Relay 时，插件还需要由发行 / 主机集成提供的 `HostCredentialProvider`；不要把安装私钥写进 DSH YAML。通过 `createRemoteControlPlugin(provider)` 构造 Loader 插件入口，provider 在每次连接前取得短期主机 credential，并用 OS 安全存储中的安装密钥对握手输入签名：

```js
import { createRemoteControlPlugin } from '/absolute/path/to/dsh-mobile-ustc/host/remote-control/lib/index.js'
import { hostCredentials } from './os-key-store.js'

export const { name, inject, apply } = createRemoteControlPlugin(hostCredentials)
```

主插件配置中的 `relayUrl` 可用 HTTPS/WSS 地址；仅回环地址允许明文 HTTP/WS。Relay 连接和本机调试入口共用同一个 `ProbeRuntime`、命令日志与 DSH Agent。安装 credential 获取、OIDC/DPoP 调用及 OS 密钥库适配由宿主集成提供，尚未接入 TokenWorks 发行包。

Windows 的 `socketPath` 形如 `\\.\pipe\dsh-mobile-ustc-<runtimeId>`。Node IPC server 将 `readableAll` 和 `writableAll` 都设为 false。当前 Linux DSH CLI 集成测试覆盖 Unix socket；命名管道访问 ACL 还需在 Windows 的 DSH CLI 测试中验收。

socket 父目录必须归当前用户所有、权限 0700 且不经过符号链接；插件将 socket 权限设为 0600，不覆盖已有监听。`runtimeId` 按安装用户 / profile 单独配置，重启保持不变，每次加载生成新 `runtime_epoch`。关闭或卸载插件会关闭连接、订阅和挂起交互。

读取当前代次：

```sh
curl --unix-socket /tmp/dsh-remote-private/probe.sock http://localhost/m0/probe
```

操作通过 `POST /m0/command` 提交严格 JSON 信封，响应为 NDJSON：

```json
{
  "v": 0,
  "type": "session.list",
  "request_id": "66666666-6666-4666-8666-666666666666",
  "runtime_epoch": "替换为 probe 返回的 UUID",
  "payload": {}
}
```

协议定义见 `src/protocol.ts`。它是 M0 本机协议 v0，不能作为生产移动协议 v1 使用。长快照以 base64 字节分片，客户端收全后再解析和替换；断线后重新订阅取得新 `sync_id`。分页必须引用仍然打开的订阅及其固定 cursor。未知日志类型只导出位置，不导出配置或内部正文；模型 replay 元数据不会转发。

受保护工具在原生审批服务中等待本地应答，并通过最终 guard 检查当前执行 token。前置 listener 跳过等待或桌面入口直接返回允许时，guard 仍拒绝执行。这只验证了已声明工具经 DSH ToolRuntime 的路径；底层 capability、真实微信 / 桌面共存及完整企业策略需另行组合验收。

普通提问与工具批准分开处理。主机已接入 timed question 的原生前台 claim、超时 continued 投影与迟到消息路径，已用本机 npm DSH 服务及真实工具循环验证；Relay 已通过独立 `question.timed.v1` 接入，支持按订阅领取 / 释放等待和持久迟到消息；本机 Go/PostgreSQL/DSH 联合测试已通过，Android UI 仍待实现。生命周期、重载与验收范围见 [timed question 适配记录](../../docs/timed-question-adapter.md)。文件、归档、子 Agent 接管、完整复合执行适配、学校身份和账号切换仍待交付或验收。Windows 命名管道代码已实现，仍需发行包及 Windows 实机验收。

Relay 双方协商 `question.blocking.v1` 后，普通阻塞式问题和计划确认随会话订阅发送待答快照。回答须绑定会话与 epoch、具备 `question.answer` 权限，并经加密命令日志记录；多设备只能完成一次，重试返回持久结果。问题回答不能应答工具审批。协议与阻塞式问题限制见 [问题应答说明](../../docs/question-protocol.md)。

正式插件现在支持显式提供的签名审批集成：`createRemoteControlPlugin(hostCredentials, signedOptions)`。`signedOptions` 提供已登记的 host/installation 身份、匹配控制面的 policyVersion/requiredAssurance、独立安装的 authority 公钥锚，以及可选的可信 capability 分类和资源版本读取器。默认保护全部受管理调用，不把原型的 `highRiskTools` 名单当作完整企业风险分类。工作区必须带唯一 `remoteId`；实际执行目录由原生 WorkingDirectory 服务读取，并再次核对物理根目录与实时资源。示例与限制见 [原生签名审批接入](../../docs/approval-native.md)。

签名模式使用真实原生审批服务并保留其拒绝策略，手机决定与原生允许必须同时成立。本机未签名 `interaction.answer` 无法批准该模式。最终 guard 校验后，公开工具定义的本体适配器在异步包装器之后提交一次性消费；signal 约束再次检查租约、目录和工具替换，阻止过期调度及重试复用。签名主机还要求协商 `approval.invalidation.v1`：撤销设备或提高用户授权版本会按当前连接使受影响的未消费许可失效，异步验签不能恢复旧权限。运行时 / 网络断开使未消费请求失效，不恢复旧 Promise；已开始的工具保留实际结果。SQLite schema 3 记录待确认结果，直到匹配指纹的服务端确认；重连补报事实，不重放工具。真实 Go / PostgreSQL / npm DSH CLI 已走通 Bash 允许一次、篡改签名不消费、拒绝、取消、guard 后撤权阻止本体执行与持久结果对账，学校 IdP、Android、生产密钥供给及其它 capability / 平台路径仍有验收缺口。

每个 runtime 使用独立 SQLite WAL 命令日志。修改命令在调用 DSH 前先提交 `host_accepted`；`session.create` 在创建结果 flush 成功后才返回确定结果，`message.submit` 在 DSH 接受且 `sessions.flush()` 持久检查点成功后记录 `agent_queued`，其它已完成操作记为 `settled`。日志以 request_id 和规范化操作摘要去重；同 ID 不同内容返回冲突。消息重试复用 DSH 原生 requestId，可在插件重启后再次提交并避免重复插入；其它处于 dispatching 的操作标为 `outcome_unknown`，不会自动重放。数据库保存 AES-256-GCM 加密的命令 / 结果正文，收到持久确认后清除命令正文；请求摘要和状态保留。最多保留 100,000 条幂等记录及 4,096 条未完成正文，达到上限后拒绝新修改，不淘汰旧 request_id。

默认数据库路径是 Linux 的 `$XDG_STATE_HOME`（否则 `~/.local/state`）、macOS 的 `~/Library/Application Support` 或 Windows 的 `%LOCALAPPDATA%` 下按 runtimeId 隔离的目录；可用 `commandJournalPath` 指定绝对路径。POSIX 目录必须是当前用户拥有的 0700 目录，数据库和 `.key` 文件为 0600。Windows 路径限制在当前用户的 `%LOCALAPPDATA%`，依赖该目录继承的用户 ACL，仍需 Windows 实机检查。AES 密钥与数据库位于同一受保护目录，因此复制整个目录仍包含解密密钥；M1 还需把密钥包装进平台安全存储。当前本机调试协议使用 `local` 用户 / 设备标识；Relay 接入后必须由已验证的 user_id/device_id 作为日志分区键。

SQLite 使用 Node.js v24 的 `node:sqlite` 同步 API；该 Node 版本将模块标记为 Release Candidate，且同步数据库操作会短暂占用事件循环。单条正文和事务均有界；构建及 DSH CLI 集成验证以仓库锁定的 Node 24 runtime 为准。[Node.js v24 SQLite 文档](https://nodejs.org/download/release/latest-v24.x/docs/api/sqlite.html)。主机 Relay 接受经签名握手后的文本 queue / steer 帧，校验服务端提供的规范化摘要，以验证后的 user_id/device_id 分区写入命令日志，并发送 host_accepted、dispatching、agent_queued 等回执。agent_queued 仍等待 DSH 会话持久化检查点。主机同时通过 `session.catalog.v1` 发布会话目录元数据；目录包含确定性 session UUID、原生 DSH ID、可选控制面 workspace UUID、状态和持久化位置，不包含正文、标题或本机路径。插件在连接建立及会话增删时发布完整快照，运行状态和消息活动变化使用增量更新；离开允许工作区的会话会被标记为不可用并清除 workspace 映射。

若授权按 workspace 限定，workspace 配置必须带 `remoteId`，其值为主机登记返回的 workspace UUID；缺少映射时该会话不会匹配 workspace grant。session grant 可按 session UUID 单独限定。

DSH CLI 0.2.1-rc.2 集成测试使用临时 P-256 密钥和本机回环 WSS 协议对端，证明签名握手、命令入队和回执、WSS 快照、固定切点分页、assistant 增量与替换同步代次均使用同一个 DSH Agent；内容帧按共享 JSON Schema 校验。它没有启动 Go Relay、PostgreSQL、学校身份服务或生产密钥库；这些组合仍需单独验收。

Relay 双方协商 `session.read.v1` 后，可打开按连接隔离的会话订阅。主机发送带 `subscription_id` / `sync_id` 的快照、原生事件、持久化检查点和 assistant 流，分页引用仍打开的固定快照。取消订阅只释放 follower，不中断 Agent；断线后重新订阅。正文投影最大 2 MiB，超过 64 KiB 信封时按字节分片。每订阅 / 整个主机连接的待发队列分别限制为 3 MiB / 12 MiB，超限后中止 follower 并要求重同步。读取仍依赖 Relay 每帧核对 `session.read` 及当前授权范围。协议、限制和待完成项见 [会话读取说明](../../docs/session-read-protocol.md)。

双方协商 `session.create.v1` 后，手机可在获授权的 workspace UUID 下用已配置 preset 创建会话。创建命令先保存工作区目标，完成后返回持久会话 UUID；重试共用命令去重，不会重复创建。协议与验收范围见 [会话创建说明](../../docs/session-create-protocol.md)。

双方协商 `session.cancel.v1` 后，手机可用独立的 `session.cancel` 权限中断当前会话；请求须绑定当前 `runtime_epoch`。已完成的请求重试只返回持久回执，不能再次中断后续任务。`settled` 表示原生 cancel 已应答，任务停止应以随后的 `turn/end` 为准。详见 [远程中断协议](../../docs/session-cancel-protocol.md)。

双方协商 `session.archive.v1` 后，可用 `session.archive` 权限归档或恢复同一会话。命令绑定原始 epoch 和显式的 `archived` / `stop_activity` 选项，调用当前进程的原生 Workspace Registry；`settled` 表示归档状态持久保存。归档保留历史；活动会话默认拒绝归档，明确选择停止也不等待执行结束。详见 [会话归档](../../docs/session-archive.md)。

另运行 `npm run test:remote-dsh` 可启动真实 Go 服务、隔离 PostgreSQL 和同一本机 npm DSH，验证完整的登记、双端绑定、密钥证明、目录、聊天读取与撤权链路。该测试已通过；身份、模型和密钥 provider 使用本地夹具，学校 IdP、Android 和生产密钥库仍待验收。运行条件及数据边界见 [联合测试记录](../../docs/go-dsh-integration.md)。

手机创建选项通过 `session.create_options.v1` 发布到当前主机连接，包含已登记工作区 UUID、公开 label 和允许的 preset token。每个快照最多 128 个工作区和 128 个 preset，label 最多 32 个 Unicode 字符／128 字节。未配置 label 时只使用工作区 UUID 的短标识；不导出本地工作区引用、路径、preset 定义或模型凭据。详情见 [创建协议](../../docs/session-create-protocol.md) 和 [Android 创建流程](../../docs/android-session-creation.md)。

双方协商 `file.handoff.v1` 后，插件通过当前安装密钥和连接绑定的一次性读取证明下载 clean 对象，校验内容后暂存原生会话 receipt。receipt 由五秒续租、当前连接和原始上传设备约束，断线 / 撤权 / 会话释放后失效。进一步协商 `message.files.v1` 后，可引用服务端已原子授权的文件 ID 入队；[Android 上传与附件界面](../../docs/android-files.md) 已接入。详见 [Host 文件交接](../../docs/file-host-handoffs.md) 和 [消息附件](../../docs/file-message-relay.md)。

Host 另协商 `message.files.reconcile.v1`，使已登记原命令在对象到期或暂存失效后仍可核对已有结果。服务端专用对账帧只查询原生请求记录和持久化检查点，不走普通消息提交；缺少本地证据时保留未知结果。该能力不提供新的下载、receipt 或消息准入权限。

受限导出的 [Host 来源层](../../docs/file-export-sources.md) 已提供会话持久附件 / 图片、显式 exportRoots 下的工作区交付物、不透明来源 ID 和运行时清理，并通过 [file.export.v1](../../docs/file-export-relay.md) 接入服务端登记、扫描与鉴权下载。Linux 读取固定文件描述符并核对版本 / 摘要；未知执行世界和缺少安全文件适配的平台拒绝读取。工作区目录还要求 ticket 与当前 grant 的字面 workspace 范围，不能仅靠会话权限进入。Android 保存链路仍需接入。

The optional [native observations extension](../../docs/host-native-observations.md)
is negotiated only when the Relay exposes private operational metrics. Native
prompt/create/reconciliation and checkpoint outcomes use bounded aggregate
windows, without command IDs, paths, bodies or exception text. Observation
failure/backpressure never changes command results or replays work; old peers
can omit the capability. These are self-reported runtime statistics, not execution
permission or durable receipts.

[Host connection retirement](../../docs/host-relay-lifecycle.md) bounds incoming
frames by count and bytes. Transport loss, queue overflow and draining discard
the old queue and cancel its owner immediately. Pending signatures and native
handler waits cannot block a fresh handshake; late results stay on the retired
socket. Original-ID retries still reconcile the durable journal and never infer
that disconnection undid an external effect.

The Host independently expires its negotiated connection using bounded server
time and a monotonic lifetime. Pongs cannot extend the original credential;
expiry triggers a new provider acquisition and proof. Stable authenticated
transports reset accumulated failure backoff, while short flaps keep exponential
delay. The same lifecycle record documents timing/skew limits and fixture scope.
