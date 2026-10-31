# Windows 当前用户 DPAPI 原生协议基础

`tools/native/windows/dpapi-helper.c` 实现一个专用于 32 字节日志数据密钥的原生保护／解封
协议。它不接受文件路径，不创建日志或安装密钥，不提供任意数据加密或命令执行接口。
当前只有 MinGW x64 严格编译及 Wine 10 的 Windows API 模拟结果。

**这不是 Windows 受保护日志已交付。** 现有 `loadProtectedKey` 的 Win32 拒绝仍保持不变；
未增加默认 DPAPI provider，也未放宽 Windows 的文件检查。Windows 私有目录／ACL、辅助
程序来源验证、发布与迁移持久性、真实用户上下文及目标系统故障验收仍须接入和验证。

## 原生边界

helper 只接受两个操作名：`journal-protect-v1`、`journal-unprotect-v1`。密钥、上下文和
密文只通过二进制 stdin/stdout 传递，参数没有这些值，不使用 shell。每次调用完成后退出。

每次操作先查询当前进程的 TokenUser，拒绝无效 SID、SYSTEM、LocalService 和 NetworkService。
程序不接受 caller 提供的 SID，也不更换或模拟登录身份。保护时仅设置
`CRYPTPROTECT_UI_FORBIDDEN`，从不设置 `CRYPTPROTECT_LOCAL_MACHINE`，无 UI 提示参数或
其他范围的重试。生产程序没有测试身份／范围覆盖开关。

Microsoft 的[CryptProtectData 文档](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
说明 LOCAL_MACHINE 会改为同机用户可解密的机器范围，UI_FORBIDDEN 要求不展示 UI。
[CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
要求相同 additional entropy，并通常依赖相同登录凭据和机器；文档所述域恢复、漫游与管理
边界仍适用。没有把 Wine 当前用户往返解释成真实 Windows 跨用户隔离证明。

unprotect 也使用 UI_FORBIDDEN。它不提供一种可靠识别外部 DPAPI blob 原始保护范围的机制；
不能单凭解封成功就信任任意来历的 blob。后续接入仍须校验 provider／runtime／路径上下文、
辅助程序与文件来源、私有 ACL 和原日志的密钥检查，不能用此程序替代这些边界。

## 协议 v1

每次请求必须读取到 EOF，不能附加第二个请求或尾随字节：

| 字段 | 编码 |
| --- | --- |
| magic | 8 字节 ASCII `DSHDPQ01` |
| context_length | 4 字节 unsigned little-endian |
| data_length | 4 字节 unsigned little-endian |
| context | 1–16384 个任意字节 |
| data | protect 恰为 32 字节；unprotect 为 1–16384 字节 blob |

固定请求缓冲上限为 32784 字节，额外一字节只用于识别超限；不会按声明长度分配内存。
additional entropy 为固定域 `dsh-mobile-ustc/journal-dpapi/v1`、一个 NUL、再加原 context。
两个方向使用完全相同的组合。context 可以含 NUL 和二进制内容，不按 C 字符串截断。

成功响应为 ASCII `DSHDPR01`、4 字节 unsigned little-endian 输出长度及输出字节。
保护 blob 限于 48–16384 字节；解封结果必须恰为 32 字节。只有 API 成功且长度合规才开始
响应；写入中断仍返回失败，调用方必须同时核对退出码与完整响应，丢弃不完整结果。

所有失败退出码非零，stderr 只有固定不可用消息，不回显输入、操作系统原始异常或密钥。
helper 在结束前清除请求、entropy、输出和临时头，关闭 Token 句柄，释放 DPAPI 分配。
这不保证 Windows／Wine、内核、调用方或传输缓冲中的全部副本已安全擦除。

## 本地编译与 Wine 探针

独立策略测试 `dpapi-policy-test.c` 引用实际生产源码并重命名其入口，在自己的测试入口中
检查三个服务 SID 被拒绝、普通样例 SID 被允许，以及保护标志没有机器范围并启用 UI 禁止。
这些测试分支没有编译进生产 helper 的操作接口。

本机使用 Ubuntu 提供的 MinGW-w64 GCC 13.2.0，依赖只下载并解压到 `.local/windows-dpapi-sdk`，
没有系统安装。下载包 SHA-256 和版本记录位于该目录的 `packages.json`。编译开启 C11、
O2、Wall/Wextra/Wpedantic/Werror，链接 crypt32/advapi32；PE 时间戳关闭，未签名或发布。
MSVC、真实 Windows SDK／运行环境和可信安装流程尚未验收。

探针必须显式给出工具位置和仓库 `.local` 内的新输出目录，例如：

```sh
python3 tools/integration/run_windows_dpapi.py \
  --compiler /绝对路径/MinGW/usr/bin/x86_64-w64-mingw32-gcc-posix \
  --sdk-root /绝对路径/MinGW \
  --wine /usr/bin/wine \
  --wineserver /usr/lib/x86_64-linux-gnu/wine/wineserver \
  --output .local/dpapi-protocol-new
```

该源码探针目前面向 Linux 的已解压 Ubuntu MinGW 目录布局，不自动下载或安装依赖。
编译及源文件／二进制摘要记录在输出 summary；没有声称这是完整工具链来源证明或签名回执。

runner 只创建自己的新 Wine 前缀，不接受外部前缀。先清除继承的 WINE_*／LD_*／DYLD_ 及
语言注入配置，再设置私有 WINEPREFIX 和明确的 WINESERVER，禁用 Mono／Gecko／菜单集成与
显示。它不使用用户现有 Wine profile，不运行 DSH Windows 包，不触碰已安装桌面 profile。
只向该前缀的 Wine server 请求结束，并用等待确认服务已经退出；`-k` 返回未发现服务时不
单凭退出码判断结果。私有前缀和 summary 保留为证据，不提交到 Git。

## 验证记录与接入出口

`.local/windows-dpapi-protocol-reviewed.log` 及私有输出 summary 记录 17 项通过：当前模拟用户
往返、随机化保护、错误上下文、密文损坏、16 KiB 二进制上下文、错误／短 magic、空／超限
上下文、错误密钥长度、尾随数据、伪造长度、请求超限、空密文、未知操作，以及负面检查后原
blob 仍能解封。策略二进制另检查 SID 与 flags。测试没有把明文数据密钥写入输出文件。

`.local/windows-dpapi-host-verify.log` 记录 495 项 Host 验证全部通过，无跳过，包含实际本机
npm dsh 0.2.1-rc.2 的原有 CLI 回归和探针参数／环境隔离检查。没有修改 Host 生产 TS 代码、
Android APP 或 PLAN.md，没有尝试 TokenWorks，也未执行大负载、真实设备或厂商推送配置。

下一步 Windows 接入必须先提供可信辅助程序启动与当前用户私有文件 ACL，再连接已有日志
封装／发布流程；不能删除当前 Win32 拒绝或绕开文件权限来把协议基础当作生产后端。
真实 Windows 的 SID／域策略、DPAPI 备份恢复、UI、文件替换、NTFS 持久性、升级和回滚仍需
各自证据。Wine 验证既不是这些出口的替代，也不改变真实 Windows acceptance 为 false 的记录。

后续[helper 安装文件自检](windows-helper-file-guard.md)增加 owner／DACL、重解析点、
链接及共享句柄门禁；仍不是完整的启动端可信验证，也不启用 Windows 日志。
