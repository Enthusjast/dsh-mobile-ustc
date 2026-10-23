# dsh-mobile-ustc

TokenWorks / DSH 移动远程控制平台。当前开发处于 M0：在现有运行进程中接入会话、流式历史和人工交互。

已实现的原型位于 [host/remote-control](host/remote-control/README.md)。它通过当前用户私有的 Unix socket 提供本地调试入口，默认关闭；尚无公网服务或 Android 客户端。

需要 Node.js 24（至少 24.15.0）：

```sh
npm ci --ignore-scripts
npm run verify
```

验证使用精确锁定的 DSH 0.2.1-rc.2 npm 包、真实 Cordis Loader、Agent、Session Controller、JSONL 持久化和一个确定性的测试模型。测试成功不表示真实 TokenWorks 桌面、学校 SSO、模型服务或手机实机验收通过。
