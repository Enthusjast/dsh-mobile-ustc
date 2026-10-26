# 通知登记与 FCM 后端

可选 Go 通知服务提供设备 / 组织绑定的地址登记、推送归属挑战、加密地址与挑战队列、当前权限过滤、持久发送租约、FCM HTTP 发送和客户端回执 API。[Android 接收、设置与点击流程](android-notifications.md) 已加入，当前自动来源是已经由真实 Host 登记的 signed approval 元数据。普通 / timed question 的后台元数据发布和厂商通道仍待接入；真实 Google 送达与目标手机验收尚未完成。

没有设置 `REMOTE_PUSH_CONFIG_FILE` 时不注册通知路由、不启动发送 worker，也不请求 Google 凭据。显式配置 `{"enabled":false}` 同样停用。源码只接受 FCM FID 地址，能力接口明确返回 `address_kind: fid` 和实际支持的 source 列表，不把旧 token 占位列或未接入的厂商通道当成可用能力。

## 登记与退出

1. 客户端先保护性保存自己生成的 binding UUID 和 32 字节随机注销 secret；请求只携带该 secret 的 SHA-256。组织、当前设备和 proof key 的归属由 JWT / DPoP 与数据库核对，客户端不能自报 user/device/key version。
2. `POST /v1/push-bindings` 原子保存原请求摘要、加密 FID 和加密的随机挑战。HTTP 响应只有 pending 元数据，没有地址和挑战。
3. worker 使用 NORMAL 优先级、data-only 消息把短期挑战发到那个 FID。知道地址本身不能证明拥有它，也不能替换已登记设备。
4. 收到挑战的客户端仅在对应的原登记意图仍有效时，用原设备 JWT / DPoP 确认。挑战三分钟到期；错误 nonce、别的设备 / key / 组织均不能确认。有效通道为七天租约，可以用当前设备 proof 续期。
5. 活跃地址在同一 provider/project 内唯一。另一个已验证登记也不能静默挤掉原通道；原持有者需先明确停用。新的 pending 挑战不抢占活跃地址。
6. 退出账号时，客户端先清除本地接收绑定、取消该账号通知和挂起入口，再用删除专用 secret 请求停用。这个 capability 只能删除原绑定，不能读元数据、换接收者或执行交互，因此可在旧 OAuth 会话已经失效后完成清理。错误 / 未知 secret 返回相同空响应。Android 的离线退出围栏与延迟删除已通过本地设备夹具，物理手机与真实 Google 通道仍需验收。

原 ID 的同样登记返回原状态；更换地址、组织、key 或注销摘要会冲突。过期 / 已撤销通道不会因重试恢复。每设备每小时最多十个、每用户最多二十个新意图，事务级用户预算锁阻止靠增加设备绕过；同 ID 查询和重试不占新的登记记录。

## 地址、队列与当前权限

迁移 `014_push_delivery` 新建 bindings、deliveries、receipts 和 lookup-key 元数据。旧 `devices.push_*` 只是从未接入的占位数据，迁移会清空，不能安全升级成新授权。

地址和挑战分别以 AES-256-GCM 加密，AAD 绑定原设备、用户、组织、key version、proof thumbprint、provider/project、原请求及具体交付。日志表示和通用 JSON 序列化不会输出地址 / nonce / Google token。地址唯一索引用独立密钥的 HMAC；lookup key 的指纹在数据库中固定，不能通过静默换钥绕开地址唯一性。加密 key ID 可以轮换，但必须保留活跃通道需要的旧 key。启动时核对已有活跃密文，缺 key 或错误 key 会拒绝该显式配置。

worker 从审批元数据和当前 owner grant 生成每绑定 / 每审批独立的稳定 notification UUID；不会按 session collapse 两个请求。内容只含协议版本、当前绑定、notification UUID 和有效期，不含 host alias、工具参数、问题正文、JWS、文件内容或原生 ID。Android 把这些值当成不可信路由提示，不能据此批准任何操作。

队列用 PostgreSQL `FOR UPDATE SKIP LOCKED` 与二十秒 lease 协调。每次发出前检查活跃设备 / 组织、原 key、租约、当前 grant、session、Host epoch / connection 和 pending 审批；获取 Google token 后紧邻 HTTP 请求还会重查。控制面不可用时延后发送，撤权 / 代次变化失败关闭。相关 grant 更新后可以保留同一 notification UUID 重新规划尚未成功的原提醒，不能重放审批或创建新工具调用。

FCM 结果丢失只能按原 UUID 至少一次重试，不能承诺外部 exactly-once。接收侧必须去重。最多八次尝试，遵守有界 `Retry-After`、有效期和退避；UNREGISTERED 停用失效地址。transport 引用默认保留七天，再按源审批 / 审计各自的生命周期处理。planner 分批处理，inbox 是已物化引用的分页视图，不是第二份问题 / 审批正文库；完整原生交互入口和更多来源仍需后续 Android / Host 集成。

## 状态与点击

`queued/retry/leased`、`provider_accepted` 和客户端报告的 `posted/opened/blocked` 分开保存。FCM 接受、OS posting 尝试和人实际看见不是同一个事实；客户端回执不改变任何审批状态。

`GET /v1/notifications/{id}` 和分页 inbox 重新核对当前设备 / key / 组织与源权限，只返回 runtime / epoch / session / source UUID、状态和 availability。主机离线、代次变化和源结束分别有状态；没有完整工具参数或执行许可。点击提醒后的手机流程必须重新取原生详情、核对当前 epoch 和期限，并沿原有人工核对 / 生物识别 / 签名接口行动。此处没有“通知中直接允许”的 API。

HTTP 路由和错误形状见 `contracts/openapi/remote.yaml`；共享严格 schema 与样例位于 `contracts/push/v1`。`npm run contracts` 生成，`contracts:check` 检查。FCM data 全部是字符串，registration challenge 与 interaction 两个用途不互换。

## 受保护配置

先应用 014，再配置私有文件。示例只说明结构，所有 key 必须由部署方独立随机生成，不能使用示例文本：

```json
{
  "enabled": true,
  "workers": 2,
  "encryption": {
    "active_key_id": "2026-10",
    "keys": {"2026-10": "<32 random bytes in standard base64>"},
    "lookup_key": "<another stable 32 random bytes in standard base64>"
  },
  "fcm": {
    "project_id": "your-firebase-project",
    "package_name": "cn.edu.ustc.dsh.mobile",
    "service_account_file": "google-service-account.json"
  }
}
```

配置及 service-account JSON 必须是普通文件、owner-only 权限，不接受最后组件的符号链接或超限文件。凭据路径相对配置文件解析。服务账号 RSA key 至少 2048 位，只向固定 Google OAuth token 端点签署 firebase.messaging 用途的短期 JWT assertion；缓存短期 Bearer token，不把学校 token 转给 Google。发送端固定 HTTPS FCM endpoint，不跟随重定向、不带 cookie、不输出原始错误响应或服务账号内容。成功 provider message name 只保留摘要。

静态文件权限不是生产 KMS / workload identity 的验收。生产账号权限、私钥保管与轮换、实际 FCM project/app 登记、真实设备到达率和设备锁屏 / Doze / 通知权限行为仍需部署与实机验证。Android 已锁定 Firebase Messaging 26.0.1；默认 APK 没有推送配置，不初始化 Firebase、不自动登记。显式配置且用户启用后才登记；SDK 自动展示路径在非导出接收服务中被拒绝，展示由本地账号围栏控制。

官方接口依据：[FCM HTTP Message/FID](https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages)、[服务端认证](https://firebase.google.com/docs/cloud-messaging/auth-server)、[Android 接收与后台行为](https://firebase.google.com/docs/cloud-messaging/android/receive)、[优先级与可见通知要求](https://firebase.google.com/docs/cloud-messaging/android/message-priority)、[错误与重试](https://firebase.google.com/docs/cloud-messaging/error-codes)。此处使用普通 data-only HTTP 消息，不采用可能由服务端补发自动展示的 EAP remote notification。

## 本地验证边界

Go 单元测试核对跨 key/owner 密文、轮换、日志脱敏、服务账号 JWT 用途 / 签名与 token 缓存、data-only FID 包、两种优先级、发送前重查、重定向拒绝和错误分类。PostgreSQL 用例覆盖原请求恢复、归属挑战、错误 nonce / 设备、地址冲突、注销、独立同会话提醒、客户端回执去重、Host 离线和撤权；租约过期可重取，旧 lease 不能覆盖结果。

HTTPS 组合使用真实 JWT / DPoP、PostgreSQL、队列 worker、RSA OAuth assertion 和 FCM sender。测试 transport 仅把两个固定 Google 域名改接到隔离 TLS 对端；不会联络实际 Google endpoint。原设备需接收并确认对端收到的挑战，另一设备失败。它证明本地协议 / 生命周期路径，不证明 Google 接受或真实手机已显示通知。

目标用例可用 `python3 tools/integration/run_remote_dsh.py --go-run '^TestPush|TestFCM|TestOAuth|TestCipher'` 在隔离 PostgreSQL 中运行；不设置这个选项时仍运行完整 Go race 与真实 npm DSH 组合。没有使用 TokenWorks、真实学校账号、真实 Google 私钥或真实推送接收者。

2026-10-26 的十三项定向 Go race / PostgreSQL / HTTPS / 密码学用例通过，记录为 `.local/push-backend-final-checks.log`；新增字段和共享样例检查通过，`npm run verify` 的 236 项 Host 测试通过，记录为 `.local/push-backend-host-verify.log`。完整隔离 PostgreSQL / Go race / Kotlin / 真实 npm DSH 0.2.1-rc.2 回归通过，记录为 `.local/push-backend-full-chain-final.log`。增加登记并发预算后再次通过全部通知定向用例。
