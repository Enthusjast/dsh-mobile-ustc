# dsh-mobile-ustc

TokenWorks / DSH 移动远程控制平台。M0 进程内原型已完成本机 DSH CLI 验证；M1 的资源身份与 DPoP 验证基础正在实现。

主机端原型位于 [host/remote-control](host/remote-control/README.md)，Go 资源身份基础位于 [services/remote](services/remote/README.md)。主机原型通过本机 IPC 提供调试入口，默认关闭；尚无生产中继或 Android 客户端。

需要 Node.js 24（至少 24.15.0）：

```sh
npm ci --ignore-scripts
npm run verify
```

验证使用精确锁定的 DSH 0.2.1-rc.2 npm 包，启动临时 DSH Web profile 并加载插件与本地确定性模型。它不表示学校 SSO、真实模型或手机实机验收通过。
