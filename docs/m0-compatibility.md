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

`npm run verify` 通过 TypeScript 严格检查、插件构建及 20 项离线测试。Loader 测试用真实 Cordis Loader 与 DSH 0.2.1-rc.2 的 Session、Agent、Session Controller、JSON 存储、Workspace 注册、附件、审批、问题和 Tool Runtime 服务；唯一替代项是确定性离线模型，没有连接模型服务、学校身份或真实桌面发行版。

验证覆盖工作区及 preset 白名单、opaque 原生 ID 到 profile UUID 的映射、同一 Agent 继续会话、queue、checkpoint、实时订阅、历史分页、session cursor、实时改名事件、桌面模型目录校验、审批允许 / 拒绝 / 取消 / 超时、普通结构化提问和计划选择、提前返回允许的 listener 无法绕过最终 guard，以及卸载后 socket 和挂起交互清理。M0 协议 v0 的生成式 JSON Schema 与 TS 解析器共享两份 golden 请求和一份拒绝样例。

锁定 DSH 的 `follow` 能提供开场快照、固定历史 cursor、durable event 和可选 process-local assistant stream；`page` 接收 DSH 读取地址与 cursor，不接受移动端的 session UUID 直接作为原生 ID。`flush` 的返回值指出持久化 listener 是否参与，因此本原型只报告实际得到的 checkpoint，不伪造持久回执。

## 与发行版组合相关的发现

- `SessionController` 公开 list、create、prompt、cancel、selectModel、page、follow 和 flush。当前没有通用 archive API；M0 不暴露归档。
- `fileUploads.uploadStream` 和 prompt receipt 是可用的 DSH 接口；本原型未提供文件传输命令，也没有验证 receipt 的消费、重启或回收行为。
- 子 Agent 有原生父子身份。M0 列表隐藏子 Agent；远端不能用根会话接口接管子 Agent。
- `approval/request` 提供一次决策，但没有完整工具参数。原型将真实 Tool Runtime 执行上下文与 call ID 绑定，并在最终 guard 消费当前执行 token；没有在真实 TokenWorks / 微信组合里验证 listener 顺序或绕过路径。
- 普通问题与工具批准走各自的 DSH 服务。Timed question 需要前台 claim 及迟到答案路径；本原型拒绝 timed question，不把它降级成普通问题。
- M0 使用运行于同一用户下的 Unix socket，未连接 oidc-proxy。账号切换撤权、发行版关闭窗口和桌面服务共存仍需在真实 dev 包中验证。

## M0 尚未验收的出口

目前没有证据证明 TokenWorks 发行版里既有桌面会话可经此插件继续，也没有在真实发行组合里跑过真实工具审批、普通提问、账号切换、窗口关闭、插件重载或企业核心兼容检查。需取得锁定核心配套的 TokenWorks dev 包和可用的非生产 profile / 工作区，再按 [PLAN.md](../PLAN.md) 的 M0 清单运行发行组合验收。未验收项保持待办，不能用离线 Loader 测试代替。
