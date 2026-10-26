# APK 发行元数据与灰度选择

当前交付范围是可选的 Go 发行目录、已认证查询端点、严格的 Kotlin 读取与共享样例。默认不启用发行端点。Android 应用界面尚未接入更新检查；下载、私有文件保存、安装前内容 / 签名验证及系统安装恢复仍需实现。[平台签名与安装研究](android-updates-research.md)记录下一阶段的依据，不能把本阶段元数据测试写成 APK 安装验收。

## 配置与访问

服务启动时可通过 `REMOTE_APP_RELEASES_FILE` 指定一个受保护的 JSON 文件。它使用现有本机配置文件读取规则：普通文件、无 symlink、禁止组 / 其他用户权限、内容上限 128 KiB。错误配置导致启动失败，错误信息不包含路径、下载地址或原内容。文件不含签名私钥；证书 SHA-256 是公开身份元数据。

[配置模板](../deploy/android/releases.example.json)中的包名、版本、哈希、组织、地址和说明均为示例，没有对应的可安装发行物。生产发布前必须用实际 APK 和验证过的发行签名 / 兼容政策生成这些字段。配置是进程启动快照，变更或撤回需要重新验证配置并重启；当前没有发布管理 API、在线热更新或跨节点配置同步。

启用后的接口是：

```text
GET /v1/app/releases/latest?organization_id=<uuid>&version_code=<integer>&protocol_version=1&android_api=<integer>
```

接口沿用学校 JWT / DPoP，并只允许已登记、当前有效的手机 proof key。数据库在同一个读取快照中重新核对 active 学校用户、原 issuer / subject、当前设备与 proof、所选组织成员关系和 token 截止时间。请求只能选择自己当前所属的组织，不能指定用户、设备、下载地址或 signing identity；不要求主机枚举、会话读取或其他 runtime 授权。Host OAuth 客户端不能使用此手机接口。接口拒绝未知 / 重复字段、损坏的 query 编码及非规范数字值；响应禁用缓存。未配置时路由不存在，返回 404。

`version_code` 与 `android_api` 是调用者声明的选择条件，不构成授权。最终手机接入须从本机 PackageManager / 系统读取真实安装信息，并在安装前重新核对。当前 Kotlin SDK 会验证响应中的请求版本、预期包名、协议、版本窗口和独立提供的下载来源集合；尚未把这个集合的应用打包配置接入产品页面。

## 发行与兼容政策

配置声明唯一包名、1–8 个 HTTPS 下载来源、明确的 `supported_client_versions` 包含上下限，以及最多 64 项 publication。每项 publication 指定目标组织，公开响应只包含选中的发行元数据，不包含其他组织列表。

每个发行包含：

| 字段 | 含义 |
| --- | --- |
| `release_id` | 灰度分配所用的稳定发行 UUID |
| `version_code` / `version_name` | 候选安装版本与展示名称 |
| `package_name` | 必须与目录包名和客户端预期相同 |
| `sha256` / `size_bytes` | 固定完整下载字节，大小限制为 1–512 MiB |
| `signing_cert_sha256` | 候选签名证书摘要；不能替换本机已安装签名信任锚 |
| `download_url` | 预配置来源内的规范 HTTPS 文件地址 |
| `minimum_protocol_version` / `maximum_protocol_version` | 候选支持的协议范围，含上下限 |
| `minimum_android_api` | 候选最低 Android API |
| `rollout_basis_points` | 百分之一百分点；100 = 1%，10000 = 100% |
| `release_notes` | 有界纯文本说明；允许换行 / tab，拒绝其他控制字符 |

文件地址拒绝 userinfo、query、fragment、编码路径、相对路径片段和反斜线。服务目录和客户端独立提供的来源集合都必须接受该来源；未来下载器仍需独立拒绝重定向并隔离学校凭据。当前没有实现下载器，也不支持带 query 的预签名 APK 地址。

选择结果包含当前请求版本、协议 1、明确的客户端版本窗口、与窗口一致的 `current_supported`，以及一个更高的适用版本或 `release: null`。候选必须位于服务公布的客户端版本窗口、覆盖当前协议、满足 Android API、组织和灰度条件。输入顺序不影响最高适用版本选择；新发行暂不适用时仍可选择较早的适用升级。已安装相同或更高版本时不推荐降级。

这个窗口当前是发行元数据，尚未按自报 version code 强制阻断其他业务 API，也不触发强制安装。撤回 publication 可阻止之后的新选择，但不能撤销已经安装的 APK。配置发布纪律必须保持发行 UUID / version code 对应的字节和签名不变；当前启动快照只检查本份目录内部的 ID / 版本唯一性，没有跨重启的持久发行登记。真正的回退、旧版本继续工作、成功升级后的恢复及目标机型验收仍待后续验证。

## 稳定灰度

灰度分桶使用下面串的 SHA-256，取前 8 字节的大端无符号数，对 10000 取模：

```text
dsh-mobile-update-rollout-v1<NUL>organization_id<NUL>user_id<NUL>device_id<NUL>release_id
```

桶值小于该发行的 basis points 时命中。身份和设备 UUID 来自本次数据库核对，不接受 caller selector。零比例不会产生候选；相同组织 / 用户 / 登记设备 / 发行的选择稳定，提高比例不会移除原来已命中的设备。重新登记产生新设备 ID 后可以获得不同桶位。灰度是分发政策，不是访问控制或执行授权。

## 验证记录

2026-10-26 的 219 项共享 JVM 测试通过，没有失败或跳过，记录为 `.local/app-releases-jvm-first.log`。Go 与 Kotlin 共同读取 [golden 选择响应](../contracts/golden/app-release-selection.json)，OpenAPI schema 亦验证该样例。覆盖不一致的请求上下文 / 支持窗口、旧版本、错误包名、协议和 Android API 不适用、零比例、非法哈希 / 大小 / 文本、来源漂移及歧义 JSON。HTTPS SDK 用例还核对当前配置组织、DPoP nonce 重试与独立 jti，并验证退役检查不能发送请求。

最终 `check :app:assembleDebug :app:assembleDebugAndroidTest` 包含 lint，通过构建，记录为 `.local/app-releases-android-build.log`。本阶段没有新增或调用应用侧安装 / 页面流程，因此没有把前一阶段的 API 26 应用回归当作新增更新流程的设备验收。

Go vet 与定向 race 测试通过，完整 `npm run test:remote-kotlin` 的隔离 PostgreSQL / Go race / Kotlin / 真实 npm DSH 0.2.1-rc.2 组合通过，记录为 `.local/app-releases-go-vet.log`、`.local/app-releases-go-first.log` 和 `.local/app-releases-full-first.log`。生产入口加载 0600 目录，并在未登记任何 Host / runtime grant 时返回当前手机适用的示例元数据；同版本 / 更高版本不收到降级候选，跨组织、失去成员关系、未登记设备、Host 客户端与设备选择器被拒绝。数据库用例独立检查错误账号、设备 / key、组织、过期凭据、暂停用户与撤销。灰度用例验证稳定、扩大比例的单调性、最高适用发行及撤回行为。

以上没有下载 APK、验证 APK 内容签名、发起系统安装或连接真实学校 / 云分发服务。生产签名密钥、真实发行地址、手机侧下载与安装实现、OEM 行为、版本迁移与失败恢复仍是后续工作；本阶段没有尝试 TokenWorks。
