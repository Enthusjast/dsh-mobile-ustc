# dsh-mobile-ustc

TokenWorks / DSH 移动远程控制平台。主机插件与 Go 中继已通过本机 DSH CLI、隔离 PostgreSQL 的联合测试；身份与可靠传输仍在开发。

主机插件位于 [host/remote-control](host/remote-control/README.md)，Go 服务位于 [services/remote](services/remote/README.md)。当前可验证登记与绑定、授权、会话创建、目录与读取、消息与中断、普通问题应答、签名审批及结果对账、主动撤权。[Android 工程](android/README.md) 已实现共享审批协议、签名和 Keystore 适配，并通过 API 26 模拟器的指纹签名测试；尚未完成生产身份接入、部署或完整手机客户端。本机 IPC 调试入口默认关闭。

需要 Node.js 24（至少 24.15.0）：

```sh
npm ci --ignore-scripts
npm run verify
```

验证使用精确锁定的 DSH 0.2.1-rc.2 npm 包，启动临时 DSH Web profile 并加载插件与本地确定性模型。它不表示学校 SSO、真实模型或手机实机验收通过。

Android 工程使用 JDK 17 或 21。`npm run test:android` 运行 Kotlin 测试和 Android lint，平台模块需要 SDK 36 / Build Tools 35.0.0；`npm run test:android:core` 只验证共享协议和签名模块，无需 Android SDK。首次执行需要下载 Gradle 和锁定的 Maven 依赖。
