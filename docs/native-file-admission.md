# 原生文件准入

基线为本仓锁定 npm DSH `0.2.1-rc.2`。本阶段使用当前进程的 `fileUploads` 和 `sessionController`，身份和模型仍为本地夹具。

## 字节和 receipt 的边界

`fileUploads.uploadStream` 先调用原生附件存储保存完整文件，再为接收 Agent 的精确 Session 分配 receipt。文件引用含 `attachmentId: sha256:<摘要>`、规范化显示名和字节数，不是工作区路径。文件存入原生附件存储，不覆盖工作区同名文件。

receipt 保存在原生 Session 的 WeakMap 中。已进入原生队列的文件是持久附件引用；receipt 随对应用户消息记录而退休，也可通过原生 binding / retirePrompt 公共入口明确回收。回收 receipt 不删除已准入的排队文件或其对象。更换会话不能使用该 receipt；Loader 重建后，未使用的旧 receipt 也不可用。

原生 prompt 先按 request ID 查找已排队或已记录的用户输入，再解析文件 receipt。因此原请求的 receipt 已退休甚至运行时重建后，同一已记录 request ID 仍可返回接收结果；新请求必须重新交接。不同内容共用 request ID 的冲突检查继续由插件命令日志负责，不能只依靠原生去重。

## Host 适配

`DshClient.uploadFile` 每次通过工作区、根会话和 runtime 映射解析移动会话 UUID；归档会话不准入文件。`file-admission.ts` 验证纯显示文件名、声明大小和小写 SHA-256。单文件最多 200,000,000 字节；来源必须按 1 至 65,536 字节的 chunk 供给，空文件不产生 chunk。

适配逐块复制、计数和计算摘要，保留原生背压；不收集完整文件。超出声明长度时在转交多余字节前拒绝，EOF 时校验完整长度与实际内容摘要。原生返回的字节数和内容地址再次核对。取消、流错误、摘要错误或归档竞争不能发布 receipt；存储结束后才发生的取消 / 归档也会回收未发布的原生 receipt。

原生存储没有文件大小准入限额，因此远控不能省略自己的校验。显示名仍由 DSH 规范化，例如 `资料?.bin` 变成 `资料_.bin`。适配拒绝路径分隔符、控制字符、非标量 Unicode 和过长名字。

此内部适配现已接入 [Host 文件交接](file-host-handoffs.md)、[文件消息](file-message-native.md) 和 [Android 上传界面](android-files.md)。手机命令只能提供授权文件 ID，继续拒绝裸 receipt 和任意路径。原生工作目录上下文只推进手机 cursor，不出现在移动正文。

历史投影将原生文件块转换为兼容既有读取方的文字摘要，只含合法显示名和字节数。没有文字的文件消息也能展示；无效元数据使用固定占位文案。不会导出 attachmentId、receipt、路径、URL 或其他原生字段，也不会将该摘要当成下载权限。

## 验证

初次原生准入验证时，`npm run verify` 通过严格类型检查、构建、契约检查和 193 项 Host 测试。其中 `files.test.ts` 的 14 项真实 Loader 用例覆盖二进制逐字节保存 / 读取、文件名规范化、跨会话和 profile 拒绝、空文件、大小及 chunk 限额、源错误、摘要 / 长度错误、取消、流中及存储后归档竞争、队列 receipt 回收、重复请求和 Loader 重建后的重新交接。检查原生运行上下文路径与 receipt 不进入移动投影。增加安全历史摘要后，完整 Host 套件为 214 项，继续验证实际原生显示名 / 大小可见而 attachmentId 和 receipt 不可见；当前联合证据见 [Android 文件](android-files.md)。

本机记录：`.local/files-native-final.log` 和 `.local/files-host-verify.log`。本阶段验证 graceful Loader 重建，不替代进程强杀 / 断电；回收 receipt 也不承诺删除原生附件对象。

隔离对象存储、扫描、元数据 / 配额事务、当前授权的 offer 与下载，以及手机上传 / 文件 ID 消息已逐步接入，组合证据见上述文档。受限导出及 APK 对真实文件后端的组合仍待完成。未扫描的对象不能进入本适配；下载来源与原生 receipt 都不能由未授权手机指定。
