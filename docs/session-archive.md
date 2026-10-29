# 会话归档

基线：npm DSH `0.2.1-rc.2`，使用当前进程的 Workspace Registry。未使用 TokenWorks。归档保留原生会话日志和工作区中的位置，移除置顶；恢复使用同一原生会话 ID。

## 命令与状态

Host 本地协议和移动协议接受 `session.archive`，payload 必须包含 `archived` 和 `stop_activity` 两个布尔值。移动端、Relay 和 Host 需协商 `session.archive.v1`；每次命令检查当前设备、grant 和 `session.archive` 的会话 / 工作区范围。归档时默认选择 `stop_activity: false`：原生活动提供者报告任意活动，则拒绝为 `session.active`，不改变归档状态。恢复必须为 `{ archived: false, stop_activity: false }`。

为兼容主机和插件分别加载 DSH 包的情况，Host 在普通归档前先查询原生活动；若已有活动，
尚未调用归档操作便明确拒绝。DSH 在真正归档时仍会再次检查。若活动在两次检查之间出现，
而原生错误来自另一份 DSH 包，Host 不按错误名称推断是否写入，会保守记录 `outcome_unknown`。
已归档的幂等操作及显式归档并停止不受这次预检查影响。

明确选择 `stop_activity: true` 时，DSH 先持久归档，再通知原生活动所有者停止。调用不等待执行结束；停止提供者的失败不会撤销归档。已归档会话的重复原生归档是空操作，不会再次请求停止。

`settled` 仅表示此次归档或恢复已越过 Workspace Domain 的持久化屏障，不表示任务已停止、工具已结束、Agent 已释放或订阅已取消。Session 日志的 `flush` 与此屏障分别处理。

命令摘要绑定原始 runtime epoch、session、完整 payload。所有归档、恢复和其他命令共用持久 request ID 命名空间。已持久完成的重试返回原始结果；若此前已进入 dispatching 而结果未保存，重试保持 `outcome_unknown`，不重放、不依据当前归档状态推断原命令成功。桌面可能在其后执行相反操作。

## 目录、读写和执行

Host 目录将原生归档集合投影为 `archived`；监听 Workspace Domain 的持久变化，桌面归档或恢复也会发布目录增量。会话仍能解析以读取历史或恢复。远程消息和模型选择拒绝归档目标。

Go 允许获授权的 `archived` 目标执行归档 / 恢复，读取历史和查询原命令状态；拒绝对其提交消息、中断、答复及前台问题 claim。不可用目标拒绝归档 / 恢复。服务端仅存命令元数据和摘要，归档状态通过原生目录同步更新，不由收到的归档命令乐观修改。创建结果捕获时已归档的会话仍可确认创建；创建回执不会覆盖其后目录中的状态。

Session Controller 安装的原生 `ArchivedSessionGate` 还会拒绝归档会话及其 subagent 后代的下一次模型步骤；fork 的执行不受父会话归档影响。该门控不终止已经执行的外部副作用。

## Android

会话阅读页提供归档 / 恢复确认，归档默认不请求停止。停止选项必须显式勾选，未提交选择不进入 SavedInstanceState；页面重建或切换会话、epoch 时不恢复选择，连接或权限不可用时关闭确认。归档回执显示“归档操作已确认”，不宣称任务已结束。

发送前将 epoch、两个布尔选项、request ID 和摘要保存到现有 SQLCipher 命令日志；同一 ID 不能变成相反操作。连接恢复或控制器重建只查询原状态，不自动重发。只含 `session.read`、`command.status` 和 `session.archive` 的连接可恢复归档会话；新连接逐命令检查所需能力。

归档页保留历史和本机发送记录，隐藏消息输入和执行交互。确认后重新读取主机目录并重建相应范围的连接，恢复后才能继续发送。历史回执不会乐观覆盖目录中的当前状态。目录变化传播期间重读有次数上限；刷新失败时保留原命令供对账。

## 验证记录

`npm run verify` 通过契约生成检查、TypeScript 检查、插件构建及 179 项 Host 测试。其中 `host/remote-control/tests/archive.test.ts` 使用真实 Cordis Loader、JSONL 会话存储、JSON Domain、Workspace Registry、Agent Loop 和 Session Controller，覆盖：

- 归档移除置顶、保留工作区位置和完整日志；重建 Loader 后恢复并继续同一会话。
- 活动 turn 的普通归档拒绝且无写入；显式归档并停止在 durable archive 之后通知，丢弃原生排队消息并正常结束 turn。
- 归档后的迟到消息不产生模型回复；恢复后能继续。
- subagent 后代门控和独立 fork；此夹具未装配完整 subagent、schedule、job 所有者。
- 桌面归档 / 恢复目录通知、归档历史读取和写入拒绝。
- 持久命令阶段、活动拒绝、已完成重试、epoch 冲突及 dispatching 后未知结果。

`REMOTE_TEST_GO=/opt/go1.26.10/bin/go REMOTE_TEST_PG_BIN=/usr/lib/postgresql/18/bin npm run test:remote-dsh` 通过完整 Go race / PostgreSQL 回归及真实 npm DSH CLI 组合。移动 WSS 命令完成闲置归档、归档历史读取、消息拒绝、恢复、活动拒绝、显式归档并请求停止；原生 turn 正常记录 aborted，恢复后继续问题和审批。历史归档请求的 settled 重试未覆盖其后的桌面恢复。TS / Go 使用三组共享 golden 验证闲置归档、归档并停止、恢复的 epoch-bound 摘要和严格 payload。

2026-10-29 使用显式选择的本机 npm 安装 `dsh 0.2.1-rc.2` 和双节点夹具复测通过。主机插件和
全局 DSH 分别加载 Workspace 包时，正在运行的会话依然在归档调用前被明确拒绝；活动在预检查后
变化或其他无法识别的错误仍按未知结果处理。夹具身份和模型均为本地数据。

回归同时修复握手路由发布时序：`hello.ok` 进入有序 writer 后、写出前才发布路由，保证对端收到成功时可立即使用，并使并发业务帧排在 hello 之后。重复连接测试检查 Host 和手机两种路由及能力已可用。

Android 完整 check / lint、应用和测试 APK 构建通过；174 项共享 JVM 测试通过，零失败 / 跳过。共享 Kotlin 客户端经真实 TLS Go / PostgreSQL / npm DSH 完成归档与恢复。新增 golden、状态演进、归档专用 scope、拒绝未知能力、发送前持久化失败和重建后不重发均有测试。

专用 API 26 AVD 的 14 项定向应用用例覆盖归档确认与停止选择、界面重建 / epoch 变化、历史页禁用输入、SQLCipher 原命令恢复，以及既有聊天、创建和断线恢复。归档控制器 2 项等待新连接就绪后复测通过；其余 12 项沿用同轮通过结果。完整应用回归的前次 96 项记录另见应用验收文档。

`npm run test:remote-android -- emulator-5580` 的完整 APK → TLS Go → PostgreSQL → 正常 npm DSH 组合在 2026-10-25 通过，Go 包含 race 检测，耗时约 131 秒。应用完成原生归档、原生恢复，并在控制器重建后恢复两个独立原请求、摘要、settled 状态和单次发送次数。Go 检查两个当前设备的持久回执；Host 独立检查原生集合已经恢复，允许的 Bash 文件只写入一次且拒绝文件未产生。设备登记和两次工具审批仍使用三次真实平台生物识别签名。学校身份及模型使用本地夹具，归档权限在夹具中显式授予。

本次本机证据：`.local/archive-final-host.log`、`.local/archive-go-dsh-kotlin-final.log`、`.local/archive-android-build.log`、`.local/archive-android-final-check.log`、`.local/android-sources/archive-native-first.log`、`.local/android-sources/archive-native-retest.log`、`.local/android-sources/archive-device-composition-final.log`。

未验证真实学校身份、完整发行组合、物理设备、进程强杀或断电。
