# 已知会话与最小答复授权

通知已携带经过服务端重新授权的 runtime / session 引用，手机无需先枚举目录。`GET /v1/runtimes/{id}/sessions/{session_id}` 解析这一个已知资源，验证当前学校身份、登记设备及 proof key、组织、安装、runtime、当前 `session.read` 和会话 / 工作区归属，返回真实会话元数据与调用者自己的当前权限快照。它不会补授 `host.list` 或 `session.list`；原目录接口继续按各自权限过滤。

响应只有 runtime 与 session。runtime 不含主机别名、设置或凭据；会话不含原生 ID、路径或正文。权限快照描述的是调用者现有授权，供后续窄化 ticket 使用，不是新的凭据。离线会话仍可返回真实元数据，后续正文与缓存读取继续各自核对权限。错误资源、错误 key、已失效身份 / 授权或仅有目录权限的请求被拒绝。接口拒绝所有 query 参数，身份和设备不能由调用者选择。

Android 将它保存为当前已知会话的临时上下文，不把结果混进可枚举的运行时目录。通知入口、前后台恢复及凭据刷新重新查询精确资源；退出、返回和导航变化隔离迟到响应。新订阅仍需重新申请 ticket、核对 native epoch / sync 和完整当前问题。返回入口回到提醒，不能借这一条资源获得其他会话列表。

## 本设备答复状态

已获 `session.read` 与 `question.answer` 的 owner / operator 可以提交和核对自己的提问答复，无需同时取得通用 `command.status`。客户端仍不把缺少设备来源字段的 WSS 提示当成持久接收证明，而是查询：

```text
GET /v1/runtimes/{id}/sessions/{session_id}/question-answers/{request_id}
```

该接口只返回当前身份 / proof 设备、精确 runtime / session 下原来已分类为 `question.answer` 的请求状态，且每次重新检查当前读取、回答、资源和组织权限。普通答复与 timed 后续答复使用同一业务动作；后者的 `agent_queued` 仍需原生持久化检查点。它不能查询其他设备、聊天、中断、归档、创建或未知用途的记录，也不放宽原通用状态接口。

迁移 `016_command_actions` 为新命令保存用途元数据。用途与原 user / device / runtime / session / digest 一起不可变，冲突重试拒绝。旧行保留 null；不能从 digest 或调用者自报类型推断历史用途，原 ID 重试也不会把旧行改分类。旧行需要原有 `command.status` 才能使用通用接口对账。升级需先应用 016；回滚后丢失的用途不能被当成窄查询授权。

没有通用状态权限时，Android 只为已知提问原请求使用窄查询；其他命令维持原来的权限要求。写入原请求在本机加密持久化，未知结果不自动重答；失败、迟到结果与重连不创建第二条答案。

## 验证范围

数据库用例验证无目录权限时的精确读取与原目录空结果、离线元数据、错误资源 / key / 截止时间、list-only 拒绝、自己的分类答复可查、其他用途 / 旧行不可查、用途不能更改、撤销回答权限后拒绝，以及通用状态权限没有被补授。迁移回退再升级需保留原命令事实；用途丢失后，原请求重试也不能重新分类。

HTTP 用例使用 JWT / DPoP 核对当前 actor、设备、资源、token 截止时间、phone / host 客户端分离与 query 选择器拒绝。Kotlin HTTPS 用例验证精确 URL / proof、回应身份和窄状态路径，目录 scope 用例验证只读 / 回答权限不隐含枚举或通用状态权限。

2026-10-26 的 212 项共享 JVM 用例通过，没有失败或跳过；Android `check :app:assembleDebug :app:assembleDebugAndroidTest` 包含 lint，通过最终构建，记录为 `.local/known-session-reviewed-build.log`。专用 API 26 AVD 的完整 135 项应用回归通过，用时 831 秒，记录为 `.local/known-session-device-all.log`。复查发现目录刷新期间返回提醒可能重新写入旧上下文，补上导航代次检查后，最终 APK 又通过 17 项通知 / 账号会话 / Hilt 启动用例，用时 203 秒，记录为 `.local/known-session-reviewed-device.log`。

这些设备夹具验证不出现在目录中的已知提问、最小权限明确答复及窄对账、前后台恢复、注销隔离和页面切换后丢弃迟到结果；真实学校、物理设备与云推送验收仍分别进行。

最终代码通过 `npm run test:remote-kotlin` 的完整隔离 PostgreSQL / Go `-race -count=1 ./...`、生产 Kotlin 客户端及真实 npm DSH 0.2.1-rc.2 组合，记录为 `.local/known-session-full-final.log`。原生双设备提问竞争的获胜设备通过窄 REST 状态查询核对原请求与摘要，精确会话接口返回同一个真实会话且不含原生 ID；迁移回退 / 再升级和用途冲突用例亦在该次完整数据库测试中通过。Host 的 242 项既有用例通过，记录为 `.local/known-session-host-verify.log`。这些组合使用本地身份 / 模型夹具，没有尝试 TokenWorks。
