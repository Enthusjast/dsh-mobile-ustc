# dsh-mobile-ustc

TokenWorks / DSH 移动远程控制平台。主机插件与 Go 中继已通过本机 DSH CLI、隔离 PostgreSQL 的联合测试；身份与可靠传输仍在开发。

主机插件位于 [host/remote-control](host/remote-control/README.md)，Go 服务位于 [services/remote](services/remote/README.md)。当前可验证登记与绑定、授权、会话创建、目录与读取、消息与中断、普通问题应答、主动撤权。尚未完成生产身份接入、部署或 Android 客户端。本机 IPC 调试入口默认关闭。

需要 Node.js 24（至少 24.15.0）：

```sh
npm ci --ignore-scripts
npm run verify
```

验证使用精确锁定的 DSH 0.2.1-rc.2 npm 包，启动临时 DSH Web profile 并加载插件与本地确定性模型。它不表示学校 SSO、真实模型或手机实机验收通过。
