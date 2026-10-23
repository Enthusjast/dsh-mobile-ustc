# M0 兼容与验证记录

记录日期：2026-10-23。此记录区分源码与 npm Loader 验证，以及尚未完成的真实桌面验收。

## 锁定基线

| 组件 | 基线 | 证据 |
| --- | --- | --- |
| DSH | `0.2.1-rc.2`；源码 `687f282e8625c6b8d11ff58211a90524be2e4317` | `npm ls @deepseek-ai/dsh @deepseek-ai/dsh-api-session-controller`；本仓 `package-lock.json` |
| EduWork 本校核心 | `0.4.7`；`eb2d6433e2e9afac407d6d82030753889207c068` | 锁定核心的发行回执及 `core.lock.json` |
| TokenWorks | `0.2.103`；本地发行源 `3b6f9d32f89132950218ae67db9994747c79daa5` | TokenWorks `VERSION`、`core.lock.json`、`edition/distribution.json` |
| 本开发环境 | Node `v24.20.0`，Linux x64 | `node --version`、`process.platform / process.arch` |

EduWork 核心源码已按 `core.lock.json` 检出。发行审计命令 `node .local/eduwork/scripts/audit-eduwork-distribution.mjs --root .local/eduwork --verify-receipt` 报告 2114 个文件、无跳过、错误或警告。该结果证明锁定源码回执符合审计器，不证明插件已在桌面发行版中运行。尚未取得或运行锁定基线的 TokenWorks 桌面 dev 包；npm DSH 包和本地模拟宿主不能代替该发行组合。

## 已验证

`npm ci --ignore-scripts && npm run verify` 通过干净安装、契约生成检查、TypeScript 严格检查、插件构建及 24 项测试。本机 `dsh --version` 确认为 `0.2.1-rc.2`。CLI 集成测试用独立临时 `DSH_HOME` 启动真实 `dsh` Web profile，加载构建后的插件和一个确定性本地模型插件，完成会话创建、列表、发送、实时 assistant 输出、取消、快照、历史分页、普通问题应答及一次 Bash 审批拒绝；拒绝后检查哨兵文件未产生。子进程不继承模型 Key 或用户登录状态，模型响应完全来自本地 fixture。进程收到 SIGINT 后退出码为 130，IPC socket 已清理。

其余 Loader 测试用真实 Cordis Loader 与 DSH 0.2.1-rc.2 的 Session、Agent、Session Controller、JSON 存储、Workspace 注册、附件、审批、问题和 Tool Runtime 服务。没有连接真实模型、学校身份或桌面发行包。CLI profile 中会话是在临时 DSH 主机内新建的；它不证明已安装桌面 profile 中的既有会话可见，也不代替 TokenWorks 发行组合验收。

Loader 与 DSH CLI 测试共同覆盖工作区及 preset 白名单、opaque 原生 ID 到 profile UUID 的映射、同一 Agent 继续会话、queue、steer、cancel、checkpoint、实时订阅、历史分页、session cursor、实时改名事件、桌面模型目录校验、审批允许 / 拒绝 / 取消 / 超时、普通结构化提问和计划选择、提前返回允许的 listener 无法绕过最终 guard，以及卸载后 socket 和挂起交互清理。M0 协议 v0 的生成式 JSON Schema 与 TS 解析器共享两份 golden 请求和一份拒绝样例。允许一次的工具执行与前置 listener 绕过用真实 DSH Tool Runtime Loader 测试；当前 CLI profile 的端到端 Bash 场景验证拒绝与不执行，尚未验证真实 UI 的 allow_once 路径。

锁定 DSH 的 `follow` 能提供开场快照、固定历史 cursor、durable event 和可选 process-local assistant stream；`page` 接收 DSH 读取地址与 cursor，不接受移动端的 session UUID 直接作为原生 ID。`flush` 的返回值指出持久化 listener 是否参与，因此本原型只报告实际得到的 checkpoint，不伪造持久回执。

## 与发行版组合相关的发现

- `SessionController` 公开 list、create、prompt、cancel、selectModel、page、follow 和 flush。当前没有通用 archive API；M0 不暴露归档。
- `fileUploads.uploadStream` 和 prompt receipt 是可用的 DSH 接口；本原型未提供文件传输命令，也没有验证 receipt 的消费、重启或回收行为。
- 子 Agent 有原生父子身份。M0 列表隐藏子 Agent；远端不能用根会话接口接管子 Agent。
- `approval/request` 提供一次决策，但没有完整工具参数。原型将真实 Tool Runtime 执行上下文与 call ID 绑定，并在最终 guard 消费当前执行 token；没有在真实 TokenWorks / 微信组合里验证 listener 顺序或绕过路径。
- 普通问题与工具批准走各自的 DSH 服务。Timed question 需要前台 claim 及迟到答案路径；本原型拒绝 timed question，不把它降级成普通问题。
- M0 在 Unix 平台使用当前用户私有 socket，在 Windows 使用关闭全用户读写的命名管道。Linux Unix socket 已在真实 DSH CLI profile 中验证；Windows 命名管道和 ACL 尚未在 Windows 实机运行。测试覆盖临时 DSH profile，不读取已安装用户 profile，也未连接 oidc-proxy；账号切换撤权和已安装桌面 profile 共存仍未验证。

## M0 尚未验收的出口

目前没有证据证明 TokenWorks 发行版里既有桌面会话可经此插件继续，也没有在真实发行组合里跑过真实工具审批、普通提问、账号切换、窗口关闭、插件重载或企业核心兼容检查。需取得锁定核心配套的 TokenWorks dev 包和可用的非生产 profile / 工作区，再按 [PLAN.md](../PLAN.md) 的 M0 清单运行发行组合验收。未验收项保持待办，不能用离线 Loader 测试代替。
