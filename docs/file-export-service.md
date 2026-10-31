# 导出登记、扫描与手机鉴权下载

Go 服务已实现 `from_host` 导出账本、Host 上传能力、共享扫描 / 对象清理和手机 JWT/DPoP 下载。Host 的 [受限来源层](file-export-sources.md) 已经通过 [file.export.v1 Relay 协调](file-export-relay.md) 接通，Android 保存文档入口仍待完成。当前没有向手机开放任意路径或自行提交 Host manifest 的创建接口。

## 开关和大小

`REMOTE_FILES_CONFIG_FILE` 的 `exports.enabled` 默认 false。显式开启后才注册以下下载 / 对账路由；启用还要求受保护 clamd policy 中的 StreamMaxLength、MaxFileSize 和 MaxScanSize 都覆盖 2,000,000,000 字节。

```json
{ "exports": { "enabled": true } }
```

该字段属于现有完整文件配置，不是独立配置文件。现有 `deploy/files/clamd.conf.example` 保持手机上传的 200 MB 基线；要开启导出，须为实际扫描进程部署对应的上限，并给远控服务提供内容相同的受保护配置副本。配置检查和 EICAR 自检不能替代实际部署、引擎限制、签名库及大文件验收。

手机 `to_host` 上传继续最多 200,000,000 字节、PUT 最长十五分钟。Host 导出来源与签名 PUT 最多 2,000,000,000 字节、最长五分钟，并同时受组织、用户和会话配额约束。导出没有扩大普通手机上传签名器的权限。

## 原子登记和来源证明

迁移 `012_file_exports` 在既有 files / file_transfers 账本旁记录来源 UUID、安装身份 / key version、runtime epoch、connection、原凭据期限、来源期限和已上传事实。表里不保存原生 attachmentId、receipt、主机路径、URL 或正文。初始 DDL 的 uploader 字段在导出方向表示请求并接收该导出的用户 / 设备。

内部 `RegisterExport` 由可信协调层在验证手机请求和 Host 回复后调用。登记要求当前 operator / owner、明确 session.read + file.download、目标范围、有效设备 proof key、组织成员关系和同一 runtime 的当前安装 / 连接证明。Host 身份或源 UUID不能替代手机权限。

原 request ID、来源 UUID / epoch、目标和完整 manifest 参与请求摘要。同设备同 ID 返回原记录；更换来源、名称、长度、摘要或目标会冲突。配额、文件、来源证明、隔离对象键和审计一起提交，审计失败全部回滚。上传和导出共用配额行，不能通过切换方向绕过总额。

新导出的上传窗口取来源、主机凭据、当前 grant 与五分钟上限中的最早期限。等待权限 / 配额锁后使用数据库当前时间检查，不延长已经到期的来源。Host PUT capability 只存在于内存，不进入数据库或一般日志；它在短期到期前可能仍可使用，不能声称即时撤回已签发的对象地址。

普通手机 upload-url / commit 入口拒绝 from_host 文件。导出同样不能被用作手机到主机的交接、原生 receipt 或消息附件。

## 扫描、离线与清理

当前原 Host 连接在来源期限内确认上传后，事务记录 uploaded_at 并把原文件转为 scanning；重复确认不启动第二个作业。只有对象存在或一个 scanning 标志都不能替代这项来源事实。

之后由已有扫描 worker 领取，逐字节校验长度 / SHA-256、扫描并向不可覆盖候选写入同一条流。导出 worker 还检查原设备 key / grant generation 和当前 read / download 范围。上传证明已经持久消费后，扫描和已 clean 对象的读取可在 Host 离线时继续；设备、成员、安装 / runtime 或权限被撤销时仍拒绝。

clean、候选指针、保留期、审计和 `file.export.clean` 元数据事件原子发布。新的方向筛选使这些对象不会进入 file.offer 队列。对象跟踪、过期、删除租约及配额释放沿用原有路径；没有实际删除确认就不释放配额。

down 迁移只使导出失效、终止扫描并保留对象与配额追踪，不能遗失 GC 依据。重新 up 不恢复旧来源证明或下载权限。迁移应按依赖逆序回滚。

## 手机 API 与流的生命周期

[上传/导出准入期限](file-rest-admission-expiry.md)进一步核对来源确认、opened 审计和
预签名等待后的有效性；结束后的结果回执继续只记录历史，不恢复下载或来源权限。

| 入口 | 含义 |
| --- | --- |
| `GET /v1/file-exports/{request_id}` | 用原登记 request ID 找回原文件，不重新准备来源；未知 / 无权限均失败关闭。 |
| `GET /v1/files/{file_id}` | 当前原设备的元数据；direction 区分上传和导出，导出没有原生 message delivery 提示。 |
| `GET /v1/files/{file_id}/content` | 当前原设备的 clean 导出字节；不返回公共对象地址。 |

正文入口经过正常手机客户端限制、JWT / DPoP、活动设备和实时权限解析。另一个设备及 Host OAuth 客户端都不能仅凭文件 UUID 下载原设备的私有导出。下载要求正确的已提交对象键、已上传证明、当前 scanner policy 和未过期文件；当前设备 key 不得把旧 key 的私有导出直接升级为新权限。

响应使用 application/octet-stream、attachment 文件名、准确 Content-Length / X-DSH-Content-SHA256、nosniff 与 no-store/no-transform。拒绝 Range 和 query/object-key 选择器。服务端重新校验实际字节，并在完成长度与摘要验证前保留最后一块；对象服务提供的新 checksum 不能覆盖原 manifest。

每次流最多五分钟且不超过 token / 文件到期。授权使用五秒短租约、每半秒复核；独立取消计时器确保阻塞中的数据库续期不会延长旧租约。即使新 grant 仍允许相同操作，generation 变化也终止已经打开的旧流，新请求须重新授权。撤权、token / 租约到期、进程关闭和客户端取消都会关闭对象读取，慢写也有独立期限。

当前每设备最多两个、每进程最多六十四个下载，缓冲最多 64 KiB 一块。它们是本阶段的资源预算，不是目标容量测试结果。

审计只记录下载 ID、文件 ID、摘要、长度和 opened / served / cancelled / failed，不含名称、URL 或正文。served 只表示服务端完成了校验和响应写出；Android 仍须独立验证所保存字节，不能把它当作系统文档已经安全发布的证明。

## 证据与剩余范围

2026-10-26 的本地测试已覆盖：

- 隔离 PostgreSQL：登记幂等 / 冲突、来源 / 设备 / epoch / 范围拒绝、并发共享配额、等待锁后到期、审计整批回滚、当前 Host 上传证明、离线扫描、私有对账、方向隔离与迁移失效。
- 实际 JWT/DPoP TLS API、AWS S3 SDK、加密对象协议对端和 Unix scanner 协议对端：上传、扫描、完整下载、恶意内容拒绝、请求 ID 恢复、其他设备 / Host OAuth 拒绝、进行中授权变更、阻塞 headers 取消和对象篡改拒绝。
- 服务测试：摘要尾块、served / failed / cancelled 区分、续期阻塞不延长租约、关闭和并发预算；无扫描 reader 不能通过候选发布入口。
- OpenAPI / Go 共享 export-clean 样例与 Node 严格解析，上传 200 MB 和导出 2 GB 分别约束；完整 Host 套件 231 项通过。

本机记录为 `.local/file-export-postgres-http-second.log`、`.local/file-export-reader-unit-final.log`、`.local/file-export-backend-host-verify.log`、`.local/file-export-backend-vet.log`。完整 `npm run test:remote-kotlin` 的 Go race、现有 Kotlin 文件 / 聊天 / 审批 / 提问 / 归档和真实 npm DSH 回归也已通过，记录为 `.local/file-export-backend-full-chain.log`。

后续 [Relay 组合](file-export-relay.md) 已验证来源到后端的实际导出；Android 导出 / 保存 / 恢复、APK 文件联合链路及跨平台来源适配仍需继续实现。2 GB 目前有边界与签名检查，尚未做该尺寸的真实扫描 / 下载性能验收。对象、scanner、身份与模型仍为本地夹具；这些结果不证明真实 KMS、病毒签名引擎、学校 IdP 或公开网络验收。
