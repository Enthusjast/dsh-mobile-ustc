# Remote Control 进程内原型

本包是默认关闭的 Cordis 函数插件，导出 `name / inject / Config / apply`，使用当前进程的服务，不启动 SDK 子进程。运行 `npm run build` 后装配 `lib/index.js`。

M0 支持工作区白名单内根会话的列表、创建、文本 queue / steer、中断、可用模型列表和选择、快照、固定切点历史分页和 assistant 流，以及本地单次工具审批、普通提问和计划确认。模型选项从当前桌面目录校验；不接受手机指定桌面未注册的 provider、model 或 reasoning effort。DSH 原生会话 ID 保留在映射层，对外用按 profile 隔离的稳定 UUID。

插件仅在本机 IPC 上监听：Linux / macOS 使用权限 0700 父目录内的 Unix socket，Windows 使用按 runtime 隔离、`readableAll` 与 `writableAll` 均关闭的命名管道。修改示例配置为实际 profile 的稳定 UUID、绝对路径和已存在 preset：

```yaml
- id: ustc-remote-control
  name: /absolute/path/to/dsh-mobile-ustc/host/remote-control/lib/index.js
  config:
    enabled: true
    runtimeId: 44444444-4444-4444-8444-444444444444
    socketPath: /tmp/dsh-remote-private/probe.sock
    workspaces:
      - id: project
        cwd: /absolute/path/to/workspace
    presets: [your-existing-preset]
    highRiskTools: [bash, pwsh, run_code]
```

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

普通提问与工具批准分开处理。timed question 的原生前台 claim 和迟到回答适配尚未完成，当前明确拒绝该类型。文件、归档、子 Agent 接管、签名审批、学校身份、可靠命令日志和账号切换均尚未交付。Windows 命名管道代码已实现，仍需发行包及 Windows 实机验收。

同代次的修改命令按 request_id 去重、冲突检查并串行准入，最多保留 2048 个请求，满后拒绝新修改。状态仅在内存中保存；重启后不能依赖它自动重试。`native_accepted` 只表示原生准入；`checkpoint` 单独报告真实 flush 结果。本包不发出 `host_accepted / agent_queued` 等 M1 持久回执。
