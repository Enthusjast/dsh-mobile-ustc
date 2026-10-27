# 完整应用升级夹具构建

预安装检查使用的十个微型候选没有执行代码，不能批准安装来证明真实自升级。`build_app_upgrade_fixture.py` 另行构建包含实际 DSH 移动应用代码的 versionCode 2 APK；它只构建、核对和输出记录，不部署或批准安装。

```sh
python3 tools/integration/build_app_upgrade_fixture.py \
  --output .local/apk-upgrade/example-v2
```

运行前需从当前源码完成正常的 versionCode 1 / `0.1.0-dev` debug APK 构建。输出目录必须尚不存在，防止覆盖先前批次的证据。构建使用独立 Gradle init script，把所有项目 build 目录移到指定 `.local` 子目录，并在 Android DSL 最终确认阶段设置测试版本 `2` / `0.2.0-upgrade-fixture`。脚本只允许 `:app:assembleDebug`；拒绝其他任务、部署配置、IDE testOnly 参数以及仓库 `.local` 之外的输出。

完成后输出 `fixture.json`，包含实际构建的包名、版本、大小、完整 SHA-256、经宿主工具验证的单一证书摘要、基线和候选路径，以及 Git 提交与未提交文件列表。主 APK 不包含学校 / 推送 / 更新部署资产或微型候选。检查实际 Manifest 和 DEX，要求 `MainActivity`、`DshApplication`、`LoginController`、`AppInstallations` 代码存在，不接受无代码或 testOnly 包。基线与 v2 必须使用同一 debug signer。

验证后的 v1 和 v2 分别复制到输出目录的 `artifacts/app-full-v1.apk` 和 `artifacts/app-full-v2.apk`，收据指向这两份保留副本。Gradle 在同一项目切回正常 build 目录时可能清理旧任务输出，也可能重新生成正常 v1；收据不能引用任何可变的 Gradle 输出。后续正常构建不会改变本批次准备安装的基线或候选，设备驱动继续逐项检查实际字节。

构建前后核对常规 app/test APK 摘要，保证可见预览继续使用原来的正常输出。临时 APK 和生成记录均保留在 `.local`，不进入 Git；没有使用生产签名材料。

## 2026-10-27 构建证据

隔离任务图验证通过：`.local/app-upgrade-isolation-dry-run.log`。实际完整构建通过：`.local/apk-upgrade/d5d71dd-v2/build.log`，记录为该目录的 `fixture.json`。

本次基线 versionCode 1 的 SHA-256 为 `5b45c5572bc8852cc2d9c9aa4cd639dac2a58dd03a6c878d6dbb804dc9deec25`；候选 versionCode 2 为 `639794d7dc99d679d4cf82812bf681ec4b9956dce63f5c18822b7df36db20e85`，包含完整的 15 个 DEX 分片。两者证书 SHA-256 均为 `e2a2a295e9b3365ecc68befd446aa7a4dd7edd19e2bb37f67d2a9061db7049d5`。实际使用 SDK Build Tools 35.0.0 的 aapt2 / apksigner，并显式检查 26–36 范围；这不替代目标设备上的平台验签与运行证明。

构建时包含尚未提交的诊断改动，已在 `source_dirty_files` 明确记录，不能仅凭 `source_revision` 把该二进制归因于一个干净提交。宿主工具、完整 DEX、同签名和构建成功只证明它可作为后续真实升级候选；系统来源设置往返、用户确认安装、重开 v2、凭据 / 密钥 / Room 数据保留，以及外部身份服务在进程替换后的重新验证仍需独立验收。
