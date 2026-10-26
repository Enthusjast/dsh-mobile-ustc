# Android 通知与当前状态核对

Android 开发 APK 现在提供可选 FCM 通道登记、后台最小引用接收、系统通知、提醒列表和点击后的在线核对。当前自动来源是 signed approval；普通问题、timed question 和厂商通道仍待后续接入。用户尚未申请厂商推送通道，也未提供学校 / Firebase 生产配置，开发继续使用隔离夹具。

## 配置与启用

Firebase Messaging 精确锁定为 26.0.1，依赖锁和 SHA-256 校验文件一起提交。此版本使用 `register()` 和 Firebase Installations FID；客户端与服务端声明 `address_kind: fid`，不把旧 registration token 当成这个协议的地址。

默认构建没有 `push-deployment.json`。Manifest 移除 `FirebaseInitProvider` 和库的通用 messaging service，关闭自动登记、analytics、默认数据采集及通知代理。没有有效公开配置时不初始化 Firebase；配置存在且设备支持 Google Play Services 时，仍需用户在已登录账号的“通知与待核对提醒”中主动启用。未配置或 GMS 不可用会显示能力状态。

公开配置只包含部署摘要、包名和 Firebase Android application options。不得放入 service-account JSON、私钥、学校 token 或 client secret。配置使用严格字段白名单，并绑定同一安装包的登录部署：

```json
{
  "v": 1,
  "deployment_sha256": "<canonical deployment.json SHA-256>",
  "package_name": "cn.edu.ustc.dsh.mobile",
  "fcm": {
    "project_id": "your-firebase-project",
    "application_id": "1:123456789:android:0123456789abcdef",
    "sender_id": "123456789",
    "api_key": "<public Firebase Android API key>"
  }
}
```

先验证学校的公开部署文件，再对生成的规范化文件计算摘要：

```sh
cd android
./gradlew :core:auth:validateDeployment -PdeploymentConfig=/absolute/path/public-deployment.json
sha256sum core/auth/build/generated/validatedDeployment/deployment.json
./gradlew :app:assembleDebug \
  -PdeploymentConfig=/absolute/path/public-deployment.json \
  -PpushConfig=/absolute/path/public-push.json
```

`pushConfig` 必须与 `deploymentConfig` 同时提供。构建先执行共享 Kotlin 配置校验，再复制公开 assets；下一次无配置构建删除先前生成的登录与推送配置。默认 APK 不能用于真实学校登录或云端推送验收。

## 账号围栏与接收

登记先在 AndroidKeyStore AES-GCM 保护的独立 routing vault 中持久保存 binding UUID、FID 和删除专用 capability，再向 Go 发起登记。原账号 / 设备通过 FCM 收到三分钟挑战后，只有仍在前台的原登记流程可以用当前 JWT / DPoP 确认。服务返回 pending 元数据不等于完成归属验证；后台退出会取消待确认登记。活跃通道使用七天租约，可在设置中续期。

routing vault 位于 `noBackupFilesDir`，不与账号凭据库混用。它只保存账号摘要、公开部署 / 通道元数据、FID、删除 capability、有界提醒引用与回执。其密钥允许首次解锁后在锁屏期间使用，不保存学校凭据、proof / approval 私钥、工具参数、问题正文、答案或签名。账号 vault 和审批生物识别限制保持原规则。

接收服务非导出、非 direct-boot-aware；在 Firebase superclass 自动展示路径前拒绝 `gcm.n.*` / `gcm.notification.*` 数据。data-only 交互包必须是严格五个字符串字段，并匹配部署、配置、sender、binding、期限和本地时钟围栏。SDK 地址变化会停用旧路由。重启应用时先核对公开部署是否仍一致，不恢复 OAuth 或后台 WSS。

独立提醒 UUID 去重，最多保存最近 64 个本地引用。多个请求合并为一个通用账号 inbox 通知，服务端分页 inbox 保留各个引用；本地窗口上限不用于删除服务端请求。系统通知与其锁屏 public version 都隐藏正文、参数和主机别名。系统允许通知时尝试 posting，并延后在前台上传 `posted/opened/blocked`；这不是人实际看见的证明。没有通知权限不会声称通道可显示提醒。

本地退出先同步清除接收绑定和挂起导航、取消系统通知，再清理 OAuth / 账号密钥。仍在途中的旧包只能被丢弃。原删除 capability 保存在加密清理队列，由有界 HTTPS 请求和受系统约束的 JobScheduler 重试；请求只有原绑定的注销 capability，无学校 JWT、DPoP 或 cookie。旧通道清理失败时阻止新的登记。路由密文损坏 / 密钥丢失时失败关闭，无法恢复的 capability 也可能丢失；原服务端通道需等待租约到期或由管理员撤销，不能承诺无损自助恢复。

## 点击与人工审批

系统入口是显式、不可变 PendingIntent，只包含 binding 和通知 UUID / inbox 路径，不接受动作、决定或签名字段。点击后先检查当前账号，再通过已认证 REST 重新取引用，然后重新取得 runtime / session / epoch、订阅和完整审批详情。主机离线、epoch 变化、权限丢失或源请求已结束时给出状态，不构造执行许可。

新鲜引用只能打开原有审批核对页。用户仍需核对完整参数，明确选择，再完成原有单次生物识别签名；通知本身不会签名或发送决定。前后台变化、账号切换、返回设置和切换会话都会隔离未完成的提醒导航。多个提醒查询互相替换，迟到响应不能覆盖用户的新导航。

## 验证与边界

共享 JVM 测试覆盖严格最小包、跨用途 / 错误身份拒绝、公开配置与部署绑定、REST 返回引用身份、注销不附带学校凭据及重定向拒绝。设备夹具使用真实 AndroidKeyStore、实际 NotificationManager 和账号控制器；Google transport 由显式测试 provider 替代，REST 身份端点是隔离 HTTPS 对端。

2026-10-26 的 208 项共享 JVM 测试通过，无失败或跳过；`check :app:assembleDebug :app:assembleDebugAndroidTest` 包括 lint，通过最终构建。专用 API 26 AVD 的 128 项应用回归通过，用时 783 秒，包含八项通知用例，以及原有账号、会话、审批、问题、文件、归档、创建和加密缓存用例。设备登记与工具审批使用实际平台生物识别操作；模拟指纹样本只发给本次显式夹具报告的对应提示。记录为 `.local/android-push-device-regression.log` 和 `.local/android-push-review-final-build.log`。

页面隔离改动后，另行通过 20 项账号绑定 / 会话 / 通知 / 实际 Hilt 启动定向回归，用时 177 秒，记录为 `.local/android-push-lifecycle-fixed.log`。其中启动用例确认默认安装包不初始化 Firebase。首次定向运行的启动用例在退出时失败：新增的 `onNewIntent.setIntent()` 替换了 ActivityScenario 用于匹配生命周期的原始启动 Intent。移除这次不必要的替换，保持按传入的新 Intent 处理通知后，完整 20 项重跑通过；没有跳过该启动用例。

最后一版 debug APK / 测试 APK 与 lint 通过，记录为 `.local/android-push-release-check.log`。在该 APK 上把专用 AVD 锁屏，确认前后 `deviceLocked=1`，四项本地接收 / 去重 / 加密路由用例再次通过，用时七秒，记录为 `.local/android-push-locked-routing.log`；随后恢复原测试 PIN 解锁。这验证首次解锁后的 routing key 使用和本地通知围栏，不证明真实云推送在锁屏或 Doze 下送达。

构建配置检查验证匹配的公开 assets、拒绝额外私钥字段、拒绝单独提供 pushConfig，以及无配置构建删除先前的两份 assets；记录为 `.local/android-push-assets-check.log`。合并 Manifest 确认没有自动 Firebase initializer 或通用自动展示 service，只有非导出的接收服务和受 BIND_JOB_SERVICE 保护的清理服务。默认 APK 内无登录 / 推送 assets。

八项通知用例单独运行方式如下。使用本任务专用、已设置安全锁且解锁、已登记强生物识别的测试设备，先安装默认 debug APK 和对应测试 APK：

```sh
adb -s <owned-test-serial> shell am instrument -w \
  -e accountFixture true -e networkFixture true \
  -e class cn.edu.ustc.dsh.mobile.NotificationCenterTest,cn.edu.ustc.dsh.mobile.NotificationFlowTest \
  cn.edu.ustc.dsh.mobile.test/androidx.test.runner.AndroidJUnitRunner
```

本轮 Go 修复也通过通知定向 PostgreSQL / HTTPS 回归和完整隔离 Go race / Kotlin / 真实 npm DSH 0.2.1-rc.2 组合，记录为 `.local/push-api-regression.log` 和 `.local/android-push-full-chain.log`；没有尝试 TokenWorks。

这些证据分别验证 Android 生命周期、Go 后端和真实 npm DSH 的既有链路。尚未证明 Google 接受当前 project/app、真实推送接收、Doze / 进程回收 / OEM 后台行为、清理 Job 的真实系统调度、现代系统通知权限、通知延迟目标或物理设备稳定性。完整 Android → Go → DSH 通知组合、普通 / timed question 来源、厂商配置及目标机型验收仍是后续工作。
