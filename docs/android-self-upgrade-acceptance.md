# 真实自升级的两阶段验收

入口为 `run_remote_dsh.py --android-upgrade SERIAL --android-avd AVD --upgrade-receipt FILE`。它建立专用 PostgreSQL 数据库、宿主 TLS/OIDC 夹具和真实 Go API，随后启动 Android 安装前 / 安装后方法。身份服务保持在宿主进程，手机进程被 APK 替换终止后仍可验证同一账号。

只接受 `dsh-remote-api26/36` 专用 AVD 和完整可执行同签名 v2 收据，排除物理设备及可见 preview。驱动再次验证 Manifest、DEX、签名和完整文件摘要；不接受微型无代码预安装候选。设备必须处于 debug 基线 v1，驱动不会静默降级或重置 userdata。

原生驱动将两阶段日志、公开结果与摘要证明保存在 `.local/app-self-upgrade/<run_id>/`，即使宿主临时集群清理或来源权限恢复失败也保留。目录为 0700、文件为 0600；只复制指定诊断文件，不复制 OIDC 输入、token、私钥或数据库。摘要中的 `native_passed` 只说明手机两阶段通过，最终成功仍需外层 Go 用例验证相同设备的数据库记录、下载次数及发行复查次数。

安装前执行真实 PKCE / DPoP 登录与生物识别设备登记，写入加密待核对命令；从更新页打开系统来源设置，验证系统包和本应用标签，操作实际可勾选节点并返回。没有自动开始下载。之后通过生产更新协调器匿名下载完整 APK、平台验签和准备原 session，复查发行后打开固定系统组件的安装确认，匹配本应用和明确的 Update / Install 按钮。

安装前 evidence 和确认关联保留在应用 noBackup 私有目录。确认安装导致 instrumentation 进程结束，只能在 PackageManager 报告目标版本、实际安装 base APK 摘要匹配，并且独立安装后方法通过时认定成功。安装后需重新通过仍存活的身份服务验证原账号，比较账号 / 设备 / 两个密钥指纹，重开 SQLCipher 命令库并核对原请求摘要、尝试次数及 RECONCILE 状态，再要求生产更新页证明实际安装包完整内容匹配。结果不包含 raw token 或手机私钥。

## 2026-10-27 实际运行状态

- 首轮发现常规 Gradle 切换会删除临时 fixture build 输出，已改为保留 `artifacts/app-full-v2.apk`；后续常规构建后副本仍存在且摘要一致。
- 后续修正了夹具角色与权限不匹配：测试需 operator 读写权限，不应声明缺少 grant.manage 的 owner。
- Android 16 设置使用可勾选通用 View，原 Switch 选择器不适用；Compose 文本查询返回空时改为遍历实际可访问节点，并继续校验系统组件与应用标签。
- 第六轮确实完成系统来源权限往返、下载 / 校验、系统用户确认，以及完整 APK v1→v2 替换。驱动证明安装的 base APK 是目标 `639794d7dc99d679d4cf82812bf681ec4b9956dce63f5c18822b7df36db20e85`。
- 安装后原账号、设备与两把密钥指纹比较通过，但 SQLCipher 数据库页 HMAC 校验失败，因此整体验收失败，日志 `.local/app-self-upgrade-api36-sixth.log` 和 `.local/app-self-upgrade-post-first-logcat.txt`。
- 独立并发首次打开复现出存储建立竞态，已另行修复和回归，见[数据库建立约束](android-database-setup.md)。需重新使用修复后的基线和 v2 完成整条链路，不能把原失败批次改记为通过。

原第六轮的失败结论保持不变。系统 UI 在软件模拟下的冷启动 ANR、来源权限恢复、宿主时间长间隔及正常 / 失败退出的日志均需保留；这些夹具不代表学校生产、目标 OEM 或冷启动性能验收。

## 2026-10-27 修复后 API 36 完整通过

专用 `dsh-remote-api36` / `emulator-5596` 使用保留 userdata 的调试基线准备后，完成一次新的系统 v1→v2 自升级。准备操作仅针对已核对 AVD、DEBUGGABLE、已安装完整摘要及同一签名的测试包；显式 `adb install -r -d` 恢复 v1 前后，68 个持久私有文件的路径 / 内容组合摘要相同，原失败批次的数据没有删除。这不是产品降级能力，也不是本轮升级成功的依据。准备记录为 `.local/app-self-upgrade-fixed-baseline-restoration.json`。

本轮使用 `.local/apk-upgrade/pinned-baseline-fixed-v2/fixture.json` 的两份固定完整 APK：

| 工件 | versionCode | 完整 SHA-256 |
| --- | --- | --- |
| 修复后基线 | 1 | `01cde7360665592066938364abce815651323a4c83939fdf52157462808ed773` |
| 修复后候选及实际安装包 | 2 | `b86f2310c82b75e971dbb3aaa97e5024ce4827a26a75407d614599b92a9939b2` |

证书摘要仍为 `e2a2a295e9b3365ecc68befd446aa7a4dd7edd19e2bb37f67d2a9061db7049d5`。候选生产代码包含并发建立修复；夹具收据准确保留构建时的 Git 提交和未提交测试工具变更。两份保留工件在后续正常 Gradle 构建后重新验签 / 核对仍一致。

执行命令：

```sh
python3 tools/integration/run_remote_dsh.py \
  --android-upgrade emulator-5596 --android-avd dsh-remote-api36 \
  --upgrade-receipt .local/apk-upgrade/pinned-baseline-fixed-v2/fixture.json
```

外层 Go/PostgreSQL 用例 `TestAndroidAppSelfUpgradePreservesIdentityAndData` 在 229.18 秒内通过，日志 `.local/app-self-upgrade-fixed-api36-second.log`。原生两阶段证据为 `.local/app-self-upgrade/299c43fa-0ace-46cd-96b3-6554e5638c6a/`，安装后独立方法通过，耗时 48.919 秒。它证明系统来源设置往返、用户确认完整 APK 替换、旧进程实际死亡、精确安装字节、原账号 / 用户 / 设备 / 两把密钥指纹、SQLCipher 原请求 / 摘要 / 尝试次数 1 / RECONCILE 状态，以及生产更新页的 INSTALLED 核对全部成立。外层随后验证同一活跃设备数据库记录、恰好一次匿名下载和至少三次发行复查。

来源 app-op 恢复为原 `default`，本轮 adb reverse 已移除；可见 preview 与其 watcher 持续运行。软件模拟设备使用已准备的系统 / 应用缓存，测试前实际出现过 System UI ANR 并选择正常 Wait，因此本记录不证明冷启动性能。API 26 的独立记录见下节；物理设备 / OEM、公网与生产签名发行仍需分别验证。

## 2026-10-27 API 26 完整通过

专用 `dsh-remote-api26` / `emulator-5594` 保留原 FDE userdata，用既有测试 PIN 启动并解锁，原包仍为 versionCode 1。本轮由驱动以普通同版本替换装入上述固定基线，没有降级、卸载或清空数据。

首轮停在来源设置，尚未下载或安装目标：该平台的 `android.widget.Switch` 是 enabled / checkable，但不可点击；实际 ACTION_CLICK 属于带「Allow from this source」文字的外层设置行。日志为 `.local/app-self-upgrade-fixed-api26-first.log`，失败证据为 `.local/app-self-upgrade/2357b53b-bb74-4d13-8828-29a96386c79b/`。测试选择器现在读取 Switch 状态，并在限定祖先层级内匹配该系统设置行；仍要求系统包和本应用标签。API 36 的直接 Compose toggle 点击路径保留，没有增加 shell 授权或坐标批准。

第二轮命令仅将上例参数改为 `--android-upgrade emulator-5594 --android-avd dsh-remote-api26`，继续使用同一固定收据及完全相同的 v1 / v2 字节。外层 Go/PostgreSQL 用例在 249.96 秒内通过，日志 `.local/app-self-upgrade-fixed-api26-second.log`；独立安装后方法在 18.541 秒内通过。完整证据为 `.local/app-self-upgrade/7fb384a3-0521-40be-b432-94c56fdfd0ae/`，测试 APK / 测试源码摘要另记于 `.local/app-self-upgrade-fixed-api26-harness.json`，应用 APK 未因选择器修正而改变。

本轮同样通过来源设置往返、系统明确确认、原进程死亡、目标 base APK 完整摘要、同一账号 / 用户 / 设备 / 两把密钥指纹、SQLCipher 原请求及摘要、尝试次数 1 / RECONCILE、生产更新页 INSTALLED、服务设备记录及下载 / 发行复查次数。结束后来源 app-op 恢复为原默认状态（API 26 查询显示 No operations），adb reverse 为空。两端保存的证据均复核为目录 0700、四个指定文件各 0600，结果与独立安装摘要一致。

两端使用同一数据库 schema 的调试夹具。它们证明当前代码在真实包替换和进程死亡后的保留 / 恢复，不证明未来 schema 迁移、旧版回滚、生产身份、OEM 安装策略、物理密钥硬件或冷启动性能，也不代表 M3 / M4 完整出口通过。
