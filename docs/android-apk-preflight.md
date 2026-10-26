# APK 私有下载与安装前校验

本阶段实现[发行元数据](app-release-metadata.md)之后的匿名 HTTPS 下载、私有候选文件与平台 APK 校验。应用页面、独立打包的下载来源配置、当前发行复查、系统安装及安装恢复尚未接入。验证结果不代表已安装，也不构成可持久复用的安装授权。

## 下载与候选文件

`LoginHttp.downloadAppRelease` 只接受严格解析的 `AppRelease`、调用者独立提供的 HTTPS 来源集合与应用私有目录。它自行构造匿名 GET；调用者不能提供 Authorization、DPoP、cookie、任意 header 或范围请求。下载使用独立的 HTTP 连接池，清除资源客户端的应用 / 网络拦截器、认证器、cookie 与缓存，保留原 TLS 信任与网络代理配置。默认 TLS 仍使用系统信任；测试专用信任只存在于夹具。元数据查询与下载响应的 nonce 状态分离。

只接受 200、APK / octet-stream 类型和 identity 编码；已提供的 Content-Length 必须唯一且精确。允许合法 chunked / 无长度响应，始终按发行元数据限制实际写入并核对最终摘要；拒绝 Transfer-Encoding / Content-Length 冲突、重复长度、重定向、部分内容及压缩。单次调用有界，不自动重试或续传。64 KiB 缓冲写入，文件长度始终不能超过声明值，大小上限沿用 512 MiB。取消或当前所有者回调退役会关闭请求和文件，移除部分内容；失败后的新尝试重新下载。

`PrivateApkCandidate` 创建唯一临时文件，写入时仅 owner 可读写，流关闭并同步后重新读取实际文件核对长度与 SHA-256，成功后去除写权限。未完成的 writer 不能被当作候选；候选不能重新打开 writer。文件只位于调用者提供的应用私有目录，没有公开 URI、FileProvider 或外部存储路径。

`inspectVerified` **只验证字节绑定，不验证 APK 签名**。它在同一锁内检查普通文件、NOFOLLOW、长度、摘要和文件身份，在平台回调前后重新核对。关闭操作先原子作废并移除路径，不等待检查锁；未完成的 writer 在 IO 线程清理，迟到的检查结果不能返回。`copyVerifiedTo` 也核对实际复制的字节；未来安装器调用者必须先取得新的平台校验结果，并在复制失败时放弃系统 session，不能提交部分文件。旧的内存校验结果不能绕过下一次文件检查。

应用启动清理 `cacheDir/apk-updates` 的弃用暂存文件；进程退出不会留下可信标记，下一次需重新取得当前元数据和候选。当前 SDK 的调用者负责按账号 / 页面代次提供回调、取消任务，并在下载完成后的离开 / 账号切换时关闭保留的候选。产品控制器尚未接线，不能据此宣称已有完整的后台或安装恢复行为。

## 平台签名与身份

`AndroidApkVerifier` 从 PackageManager 查询本机已安装应用，取得当前 package / version code / 当前签名证书 SHA-256。它不会从下载元数据、历史证书交集或候选本身创建新信任锚。当前策略只支持单个当前签名身份；多 signer / split 安装与共享 UID 发行失败关闭，当前签名变化需要后续独立轮换方案。

候选同时满足以下条件才返回本次结果：

1. 当前已安装包仍与原快照相同；元数据包名 / 签名匹配本机，候选 version code 更高。
2. 元数据覆盖当前协议 / Android API，且不属于零比例 publication。
3. 文件必须位于本应用 `cacheDir/apk-updates` 内；对完整、匹配元数据摘要的私有文件调用带验签标志的 archive 查询，任何空结果、异常或缺失签名都拒绝。
4. 实际 APK 的包名、version code、version name、最低 SDK 及验证过的当前证书与元数据 / 本机逐一匹配。
5. 平台检查前后文件字节仍匹配，已安装包仍是同一快照。

API 26/27 使用 `GET_SIGNATURES`。28+ 同时请求 `GET_SIGNATURES | GET_SIGNING_CERTIFICATES`，并强制使用 `signingInfo`；保留旧标志是为已核对的 28/29 archive 行为，不因缺失 signingInfo 回退。单 signer 的 history 最后一个证书才是当前身份。API 33+ 使用 flags 类型重载；API 36 另行调用公开 `PackageManager.getVerifiedSigningInfo(..., VERSION_SIGNING_BLOCK_V2)`。依据与范围见[平台研究](android-updates-research.md)。没有反射隐藏平台 API，也没有把 host-only apksig 嵌入 Android。

当前平台检查证明目标设备上的内容签名有效，不代表一台旧系统已经证明全部较新系统的签名方案 / 安装行为。尤其 API 26 不理解后来的 v3 轮换或新版 targetSdk 的最低签名规则。发行流水线和每个目标平台仍须独立验证，不把旧设备成功当作跨版本发行验收。

## 可复现的本地夹具

构建测试 APK 时，`prepareApkUpdateFixtures` 用 SDK Build Tools 35.0.0 和 Gradle 的普通 debug 证书生成十个微型 APK：同签名升级、同版本、降级、错误包名、错误 signer、较高 SDK、带签名轮换历史、多 signer、篡改与截断。候选不含执行代码，供预安装检查；没有用它们替换运行中的应用。测试 APK 包含候选与公开摘要；主 APK 不含这些夹具，也不包含生成用私钥。生产签名密钥没有被使用或申请。

篡改夹具修改已签名 APK 的未压缩 asset，重算 ZIP CRC 并保持 manifest-only 解析成功，然后重算元数据的完整 SHA-256。宿主 apksigner 拒绝它，而下载 / SHA 检查允许它进入平台签名关卡，用于证明没有把摘要或证书提取冒充内容验签。SDK 工具实际报告 apksigner 0.9；该工具的 host 验证不替代设备证据。

轮换夹具在 26/27 保留原当前 signer，28+ 改用新当前 signer，且包含原证书历史。旧系统仍可核对其本身看到的原身份；了解轮换的平台必须拒绝以历史旧证书匹配新当前 signer。多 signer 夹具包含两个有效签名，不能因其中一个匹配而通过。

先完成正常构建，再在已启动、已解锁的任务专用 AVD 上运行：

```sh
cd android
./gradlew check :app:assembleDebug :app:assembleDebugAndroidTest
cd ..
python3 tools/integration/run_apk_update_preflight.py --serial emulator-5594 --avd dsh-remote-api26
python3 tools/integration/run_apk_update_preflight.py --serial emulator-5596 --avd dsh-remote-api36 --prepare-dex
```

runner 要求显式的测试 emulator serial 与匹配的 `dsh-remote-api...` 名称，排除可见 preview 与物理设备。它验证默认主 APK 没有学校 / push / 测试资产，检查测试 APK 完整，然后只安装普通 app/test APK。候选 APK 仅被下载和校验；测试逐项确认原安装快照及本应用 installer session ID 集合未变化。没有卸载、重置 userdata、触碰其他 AVD 或自动确认安装。

## 验证记录

2026-10-26，最终 `check :app:assembleDebug :app:assembleDebugAndroidTest` 包含 lint，通过构建；233 项共享 JVM 用例无失败或跳过，记录为 `.local/apk-preflight-final-check.log`。下载专项包含合法 HTTP/1.1 分块、实际协商的 HTTP/2 无长度响应、错误长度 / 摘要、TE / CL 冲突、重定向、取消、所有者退役、拦截器凭据隔离、符号链接 / 文件替换与进行检查时的非阻塞作废。已认证元数据与匿名文件下载也验证 nonce / cookie 不串用。

同一最终默认 APK（SHA-256 `4b1741406e308e996f483af1cbaf9f49144ad84d3b4689304402485d000b1336`）通过 API 26 与 API 36 各 14 项实际平台 / Hilt 启动用例，用时分别 12.2 秒和 36.8 秒，记录为 `.local/apk-preflight-api26-final-device.log` 与 `.local/apk-preflight-api36-final-device.log`。这些用例调用真实平台验签，包含保持 ZIP 有效且重算元数据摘要的篡改反例，以及匿名 HTTPS 分块下载后进入同一签名关卡。每个用例之后原应用版本 / 证书和本应用 installer session 集合保持不变。

API 36 使用独立 AOSP Android 16 x86_64 revision 2 AVD、软件模拟和最终 2 GiB 内存配置。首次冷启动存在系统级 ANR / system_server 重启，第一次 instrumentation 进程在进入应用代码前停在 ART Dex 类加载，零项用例执行；失败记录为 `.local/apk-preflight-api36-device.log` 与 `.local/apk-preflight-api36-startup-anr.txt`。保留原 AVD 数据、关闭测试实例的蓝牙 / 动画，并在安装 app/test APK 后使用显式 `--prepare-dex` 生成代码缓存；没有修改系统超时或跳过断言。后续完整用例通过，包括最终 APK；相应命令 / 输出见 `.local/apk-preflight-api36-final-runner.log`。这证明准备后的功能行为，不证明首次冷启动延迟 / 稳定性验收。

构建初期修正了生成夹具与 AndroidTest lint 之间的显式任务依赖；分块测试也修正了把 HTTP/1.1 chunk framing 放进 HTTP/2 DATA 的不合法夹具，改为分别验证真实 HTTP/1.1 与 HTTP/2 响应。对应失败没有被当成通过证据。

这些证据不代替真实学校来源、生产 release signer、目标 OEM、28/29 的独立设备验证、系统安装确认 / 取消、进程死亡后的 session 对账、升级后的数据库兼容及失败恢复验收。真正自更新需使用保留完整应用组件的更高版本 APK，并验证升级后重开；该工作仍待完成。
