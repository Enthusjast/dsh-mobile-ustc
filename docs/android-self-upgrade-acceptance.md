# 真实自升级的两阶段验收

入口为 `run_remote_dsh.py --android-upgrade SERIAL --android-avd AVD --upgrade-receipt FILE`。它建立专用 PostgreSQL 数据库、宿主 TLS/OIDC 夹具和真实 Go API，随后启动 Android 安装前 / 安装后方法。身份服务保持在宿主进程，手机进程被 APK 替换终止后仍可验证同一账号。

只接受 `dsh-remote-api26/36` 专用 AVD 和完整可执行同签名 v2 收据，排除物理设备及可见 preview。驱动再次验证 Manifest、DEX、签名和完整文件摘要；不接受微型无代码预安装候选。设备必须处于 debug 基线 v1，驱动不会静默降级或重置 userdata。

安装前执行真实 PKCE / DPoP 登录与生物识别设备登记，写入加密待核对命令；从更新页打开系统来源设置，验证系统包和本应用标签，操作实际可勾选节点并返回。没有自动开始下载。之后通过生产更新协调器匿名下载完整 APK、平台验签和准备原 session，复查发行后打开固定系统组件的安装确认，匹配本应用和明确的 Update / Install 按钮。

安装前 evidence 和确认关联保留在应用 noBackup 私有目录。确认安装导致 instrumentation 进程结束，只能在 PackageManager 报告目标版本、实际安装 base APK 摘要匹配，并且独立安装后方法通过时认定成功。安装后需重新通过仍存活的身份服务验证原账号，比较账号 / 设备 / 两个密钥指纹，重开 SQLCipher 命令库并核对原请求摘要、尝试次数及 RECONCILE 状态，再要求生产更新页证明实际安装包完整内容匹配。结果不包含 raw token 或手机私钥。

## 2026-10-27 实际运行状态

- 首轮发现常规 Gradle 切换会删除临时 fixture build 输出，已改为保留 `artifacts/app-full-v2.apk`；后续常规构建后副本仍存在且摘要一致。
- 后续修正了夹具角色与权限不匹配：测试需 operator 读写权限，不应声明缺少 grant.manage 的 owner。
- Android 16 设置使用可勾选通用 View，原 Switch 选择器不适用；Compose 文本查询返回空时改为遍历实际可访问节点，并继续校验系统组件与应用标签。
- 第六轮确实完成系统来源权限往返、下载 / 校验、系统用户确认，以及完整 APK v1→v2 替换。驱动证明安装的 base APK 是目标 `639794d7dc99d679d4cf82812bf681ec4b9956dce63f5c18822b7df36db20e85`。
- 安装后原账号、设备与两把密钥指纹比较通过，但 SQLCipher 数据库页 HMAC 校验失败，因此整体验收失败，日志 `.local/app-self-upgrade-api36-sixth.log` 和 `.local/app-self-upgrade-post-first-logcat.txt`。
- 独立并发首次打开复现出存储建立竞态，已另行修复和回归，见[数据库建立约束](android-database-setup.md)。需重新使用修复后的基线和 v2 完成整条链路，不能把原失败批次改记为通过。

当前验收框架已编译且完成上述实际阶段，完整成功仍待重跑。系统 UI 在软件模拟下的冷启动 ANR、来源权限恢复、宿主时间长间隔及正常 / 失败退出的日志均需保留；这些夹具不代表学校生产、目标 OEM 或冷启动性能验收。
