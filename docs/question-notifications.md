# 普通与定时提问的后台引用

Host 现在独立发布当前运行时的普通 / 定时提问引用，Go 根据这些引用和当前设备、组织、授权与源状态规划提醒。手机离开前台、取消会话订阅时，不再因此失去问题来源。该来源与 signed approval 元数据分别授权；不是第二份问题正文库，也不提供答题或执行许可。

## Host 发布

升级前应用迁移 `015_question_references`。支持该仓库方法的 Relay 才宣告 `question.references.v1`；正常 DSH 插件协商成功后启动发布器。旧 Host / Relay 没有这个能力时，不会伪造提问通知，原有前台问题接口继续使用。

一个 `question.references` 帧携带当前 runtime / epoch、请求 UUID、递增 sequence 和最多 128 个引用。每个引用严格只有 question UUID、会话 UUID、kind、state 和可空的原生 expires_at。原生 call ID、问题 / 选项 / 答案、工具参数、文件、路径和签名均不进入此消息。原生 session ID 只在 Host 内用于目录屏障，不进入问题引用消息。

普通问题发布 `pending` 和原生截止时间。定时问题区分 `pending`、`continued` 和 `reply_queued`；未取得原生前台倒计时的 pending 明确使用 null，continued / reply_queued 也使用 null。读取引用不会调用 attachWait、占用手机的前台 claim 或延长原生等待。无可靠结束原因的缺项只记为 `ended`，不把它推断成“已经回答”。

来源严格匹配当前远控会话目录：精确存活、受管、可独立控制且没有父会话元数据的根 Agent。DSH 0.2.1-rc.2 在事件分发前拒绝受其他 Agent 拥有的子 Agent 人工提问，错误为 `DELEGATED_CALLER`，要求根 Agent 汇总未解决的问题；本插件保留这一原生限制。带父会话历史、尚不在远控目录内的独立 fork 也保留在原生应答链，不抢占回调或发布无法登记的引用。这防止一个不可路由的问题拖断整个 Host 连接，并不把父子历史当成新的访问授权。

每条连接先确认相关会话目录，再发送完整问题快照，一次只保留一个待确认快照。后续变化合并发布；新写入至少相隔 250 毫秒，未变化时每 15 秒发送快照续租。目录确认只保留当前活动引用涉及的会话，续租不反复触发原生会话持久化。确认检查请求、runtime / epoch、sequence 和数量；拒绝或十秒确认超时会关闭该连接，从新连接重建完整快照。

共享 schema / goldens 位于 `contracts/push/v1`，通用 Relay schema 中的两个定义由同一 Zod 来源生成。`npm run contracts` 同步生成，`contracts:check` 检查漂移。

## 持久状态与边界

PostgreSQL 只保存五字段引用、原 Host 连接、顺序摘要、租约和时间。快照事务锁定当前安装密钥 / runtime 连接与 feed；相同 sequence 只接受同一内容，不能跳序。同 epoch 重新连接可从 sequence 1 重述仍在等待的原 ID；旧连接不能续租，新 epoch / 另一会话或 kind 不能接管这个 ID。

源租约为 45 秒。只有当前目录里的有效会话能登记，缺项原子结束。每运行时最多 128 个活动输入，每小时最多新增 2048 个引用，连接替换不重置预算。正文 / 未知字段、缺失期限字段、重复 ID、错误状态组合和超限快照均拒绝。内容不变的租约更新不重复写内容审计。已结束的元数据按七天期限分批清理；新 epoch 会结束旧活动元数据，旧提醒仍可辨认为 stale_epoch。

## 提醒与状态查询

只有当前 owner / operator 且具备 `session.read` 和 `question.answer`、当前会话 / 工作区范围、有效设备 / proof key / 组织的用户才能收到或核对提问提醒。发送前和 Google OAuth 取 token 后分别重查源、租约和当前权限。`reply_queued` 不再规划新的待回答提醒。每绑定 / 源问题保留独立的稳定 notification UUID，同会话多个问题不合并成一个源记录。

普通问题的 transport 有效期不超过其原生期限或十分钟。定时问题使用最多十分钟的 transport 提醒窗口；这个窗口不改变原生等待，也不把已经 continued 的问题重新变成前台调用。provider 包仍只有 binding / notification / expiry 等最小值；它不包含源正文和任何答案。

REST 重新取得的是当前状态。主机断线返回 `host_offline`，运行代次变化返回 `stale_epoch`。主机在线而 feed 过期或新连接尚未核对来源时，返回 `state_unavailable`，不能冒充在线可答。只有在线且当前源租约有效时，查询结果的 expires_at 才反映这次短期状态核对的有效期限；它与已发送 transport 包的 TTL 是两件事。已有普通 / 定时问题仍须由原生会话重新提供完整表单和答案校验。

离线的最小引用查询独立核对当前身份、密钥、授权版本、角色和会话范围；它不放宽原有正文读取规则。已撤权、跨组织、旧 proof key 或失去回答权限的请求被拒绝。后台 worker、REST 回执与提问答案互不替代。

## 本地验证

2026-10-26，242 项 Host 检查 / 构建 / 测试通过，记录为 `.local/question-native-scope-final.log`。覆盖无前台 watcher 的普通问题创建 / 结束、原生定时问题的无 claim 继续、完整快照顺序 / 合并 / 续租、错误确认和确认超时、拒绝正文混入，以及保留原生子 Agent 拒绝和目录外 fork 的原生应答器；真实 npm DSH CLI 的普通问题通过已关闭会话订阅的 WSS 连接发布了引用。

定向 Go race / PostgreSQL / HTTPS 用例通过，记录为 `.local/question-references-go-fourth.log`。覆盖严格 Host 方向、协商能力、共享字段、旧连接 / 跳序 / 改内容重放、目录归属、跨 epoch ID、重连后的新增预算、独立同会话提醒、租约过期、断线、设备 key / 回答权限撤销，并核对最小离线引用没有放宽正文读取。

完整隔离 PostgreSQL / Go race / Kotlin / 真实 npm DSH 0.2.1-rc.2 回归通过，最终记录为 `.local/question-notifications-full-final.log`。正常插件在没有该定时会话手机订阅时发布 continued 元数据，重新订阅后取到同一个原生问题并只提交一次后续消息。完整数据库 dump 排除了该问题 / 答案、原生正文、路径、签名与原始凭据标记。学校与模型为本地夹具，没有尝试 TokenWorks。

[Android 点击流程](android-notifications.md) 另行通过 209 项 JVM 测试和 133 项 API 26 应用回归。普通表单和 continued 后续答复均需要新鲜原生句柄与明确操作；通知不会 claim、回答或审批。原生只读状态、结束 / 错配 ID 和重复卡片有对应设备测试。APK 的 provider 由本地夹具替代，不能把这些分层证据当成真实云端到达率。

真实 FCM project/app、目标机型、Doze / 进程回收、厂商通道、通知延迟和生产规模仍待验收。这些组件测试不等于完整 APK → Go → DSH → 真实云推送的端到端交付。
