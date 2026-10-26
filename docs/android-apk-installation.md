# APK 安装会话与持久记录

本阶段在[私有下载 / 平台验签](android-apk-preflight.md)之后增加独立公共更新配置、加密安装记录和本应用的 PackageInstaller 后端。产品更新页面、账号 / 页面 / 前后台协调器、发行复查及真实完整应用升级验收仍待接入。后端要求调用者在每次提交前提供新的授权检查；仅保存 APK 或取得旧的验签结果不能代替当前发行和账号权限。

## 独立公共配置

构建时可提供 `-PappUpdateConfig=/absolute/path/app-update-deployment.json`，同时必须有 `-PdeploymentConfig=...`。模板位于 `deploy/android/app-update-deployment.example.json`。字段严格限定为版本、当前登录部署的规范 JSON SHA-256、应用包名和 1–8 个 HTTPS 下载 origin；每个 origin 不得含路径、查询、片段或凭据，集合不得重复。更改学校配置后须重新计算绑定摘要。配置不包含生产密钥、签名信任根或可替换的元数据服务地址；元数据仍来自当前已登录的远控 API。

`:core:auth:validateAppUpdateDeployment` 先验证学校配置，再验证并输出规范化的更新配置；主 APK 仅复制经过验证的资产。默认未配置构建会删除上一次生成的更新资产，不会继续携带旧部署。配置只限制下载来源；APK 的当前已安装签名仍是发布者信任锚。

## 安装记录

`AppInstallationRecord` 绑定原账号 / 组织 / 部署 / 用户 / 设备、独立更新配置摘要、原已安装版本和签名、完整候选发行、系统 session id、32 字节随机 nonce 与时间。完整校验过的写流复制并同步成功后才持久记录 `PREPARED` 与对应 `prepared_sha256`；该摘要表示本次实际输出的候选字节，不冒充对系统暂存盘的独立读回。后续状态变化不能修改该次尝试身份。

`AppInstallationStorage` 按 slot 保存于 `noBackupFilesDir/app-installations`，使用独立 AndroidKeyStore AES-256-GCM 密钥，slot / 包名 / revision 作为认证上下文。载荷有界，AtomicFile 写入、文件和目录同步后必须读回复核；旧 revision 或活动尝试的身份替换均失败。缺失 / 损坏密钥不会自动生成一份替代历史。普通删除只允许终态；显式恢复先清理本应用安装会话，再重置不可读记录。它不保存 OAuth、设备证明或审批凭据，也不要求在结果广播中取得生物识别授权。

## 提交、确认与结果

`AppInstallations.prepare` 重新平台验签，将候选复制到唯一的 `base.apk`，对完整写流核对长度 / SHA-256、同步并关闭输出，再记录 PREPARED。它在当前进程保留原尝试与私有候选的关联。未提交的准备失败会放弃该 session。已有未结束记录或本应用尚存的安装 session 会阻止隐式创建第二次尝试。

`commit` 对未封存 session 要求本进程仍持有上述关联，重新平台验签原私有候选并核对会话文件集合，然后调用挂起的 `authorize(record)`，复核调用者仍然有效，持久写入 COMMITTING，最后才跨 Binder 提交。所有会话写入均局限在本应用后端，没有外部写入入口或共享 UID；准备后不会再打开写流。API 31+ 显式要求用户操作；API 33+ 声明下载文件来源。应用声明 `REQUEST_INSTALL_PACKAGES`，后端每次重新查询当前来源权限。来源设置的明确引导由后续产品协调器处理。

API 26 实测在 SELinux Enforcing 下，即便 session 尚未封存，普通应用也无法通过 Binder 接收 `apk_tmp_file` 的读取描述符，表现为 `DeadSystemException`，系统服务本身仍然存活。因此业务流程不依赖 `openRead()`；不会关闭 SELinux 或授予特权来绕过限制。代价是 API 26 没有独立的系统暂存文件读回证据；依赖校验过的写流、fsync、独占的本应用会话写入，以及系统安装器的最终验签。安装后的完整 APK 摘要还会独立核对。更高平台的设备测试可以额外读取未封存内容，但不将这种可选能力作为最低平台的前提。

结果 PendingIntent 限定到非导出的本应用 receiver，并固定本次 slot / session / nonce；API 31+ 使用可变回调。receiver 校验原始关联后只保存提示。等待用户操作的 Intent 必须解析到系统应用，并固定为解析出的系统组件；仅保存在内存，后端不会启动 Activity。后续界面需在用户主动继续时取得和启动它。

回调成功仅进入 RESULT_REPORTED。`confirmInstalled` 必须重新查询实际包名、version code、当前签名，并核对已安装 base APK 的精确长度和 SHA-256 后才能保存 INSTALLED。session 消失、确认页打开、sealed、提交返回或 SUCCESS 广播均不能独立证明更新成功。终态不能被迟到广播回退；失败后仍可通过独立的安装事实核对确认目标已存在。

## 恢复与取消边界

未提交会话在进程重建后丢失私有候选关联，必须退役并重新准备；磁盘上的 PREPARED 不能单独恢复提交权限。封存 session 在支持平台上禁止 `openRead`。只有原先持久收到过 WAITING_USER、具备封存前写流摘要、原 session 仍属于本应用且原已安装基线未变时，用户明确继续才可再次提交同一 session，并重新执行当前账号和发行检查。只有 COMMITTING、缺少等待确认回执的封存状态保持未知，不能盲目再次 commit。具体 API 依据见[研究记录](android-updates-research.md)。

提交前失败可退役和清理；已提交尝试的继续失败会保留原关联供核对。提交调用已尝试后抛异常视为不确定，不能因此重建 session。显式取消放弃原会话并记录 RETIRED；已进入安装执行的系统流程仍可能完成，应依实际已安装事实显示当前版本，不承诺撤回已生效的更新。没有卸载重装、自动降级、静默安装或后台自动重放。

## 本地验证入口

`AppInstallationStorageTest` 在真实 AndroidKeyStore 上验证加密、重开、revision 冲突、AAD / 密文篡改和丢失密钥。`AppInstallationsTest` 使用生成的无执行代码候选，仅准备 / 提交到系统要求用户确认的位置；不会启动、批准或实际安装候选。测试结束核对原应用和原 session 集合，并清理本次会话。

```sh
python3 tools/integration/run_apk_update_preflight.py \
  --serial emulator-5594 --avd dsh-remote-api26 --installer-fixture
python3 tools/integration/run_apk_update_preflight.py \
  --serial emulator-5596 --avd dsh-remote-api36 --installer-fixture --prepare-dex
```

runner 只接受明确拥有的测试 AVD，安装普通 app/test APK，临时打开此应用的未知来源 app-op 并在 finally 中恢复原值；不授予特权安装权限，不操作 preview 或物理设备。以上是验证入口，实际运行结论应以记录中的平台、最终构建和通过数为准。完整应用的真实自更新、升级后数据保存、进程死亡、来源权限设置往返和 OEM 安装行为仍需后续独立验收。

## 2026-10-27 验证记录

`check :app:assembleDebug :app:assembleDebugAndroidTest` 通过，记录为 `.local/app-install-backend-write-binding-build.log`。共享 JVM 236 项，加上应用状态机在 debug / release 各 3 项，共 242 次测试结果无失败或跳过。lint 无错误，保留现有和 API 辅助类的建议性警告。新增公共配置实际经过 `:app:prepareDeployment` 复制，核对其登录部署绑定；随后默认配置任务清空全部生成资产，记录分别为 `.local/app-install-config-assets.log` 和 `.local/app-install-config-assets-cleared.log`。

默认主 APK SHA-256 为 `967208167ffcc66c28f4567da4ba45bb1d22e34739fb6e3cd963a3b9f7eb7533`。该 APK 在 AOSP API 26 x86_64 revision 1、SELinux Enforcing 上通过 28 项设备用例（13 项签名 / 下载、1 项真实启动、4 项加密记录、10 项安装后端），耗时 77.4 秒，记录为 `.local/app-install-api26-write-binding-device.log`。包括首次提交获得系统确认、丢弃内存 Intent 后在同一 sealed session 上显式重新提交并再次获得确认，以及未知结果 / 退役记录不能自动重放。候选始终未被批准或安装，原应用版本与签名、测试前后的 own session 集合保持一致。

同一 APK 在 AOSP API 36 x86_64 revision 2 上也通过全部 28 项，耗时 362.9 秒，记录为 `.local/app-install-api36-warmed-device.log` 和 `.local/app-install-api36-warmed-runner.log`。在此平台另行读回未封存 session 的字节，核对完整长度和 SHA-256；封存后仍断言读取被拒绝。来源 app-op 的原值成功恢复。测试使用 2 GiB 软件模拟、关闭测试机虚拟 Wi-Fi / 蓝牙，并显式 `--prepare-dex`；HTTPS 夹具只使用 localhost 环回，未弱化 TLS、SELinux 或系统验签。

API 36 首轮在第一个签名用例后因系统 `WifiHandlerThread` 的 `DeadSystemException` 导致 system_server 重启、instrumentation 中止；该轮没有执行安装后端。失败日志为 `.local/app-install-api36-device.log` 与 `.local/app-install-api36-system-crash.txt`。崩溃时 finally 的 app-op 恢复也因系统服务不可用而失败；服务恢复后明确还原为 default，再启动上述成功复测。runner 已改为同时保留测试失败与清理失败信息，避免后者掩盖前者。上述通过结果证明预编译、系统恢复后的本地功能，不代表冷启动稳定性、公网下载或真实升级验收。

早期两轮各有 9 项准备失败，分别保存在 `.local/app-install-api26-device.log` 和 `.local/app-install-api26-diagnostic-device.log`；底层原因是前述 SELinux 的未封存 read FD 限制，并非候选签名失败。这些失败没有被当作通过证据。最终流程改用完整校验过的写入 / fsync 关联，未弱化设备策略。此次只用新后端对象模拟进程重建后的内存丢失；真实 kill / 重启和完成整包自更新仍属于后续验收。
