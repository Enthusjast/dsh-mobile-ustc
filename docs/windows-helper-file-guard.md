# Windows DPAPI helper 安装文件自检

DPAPI 原生程序现在在读取任何请求之前，检查自己的映像文件和父目录链，并持有只读共享
句柄直到操作结束。这个原生边界补充[DPAPI 协议基础](windows-dpapi-primitive.md)，不启用
Windows 受保护日志，也不提供已经完成的 Node 启动验证或 Windows 数据目录实现。

## 检查与锁定

当前 TokenUser 必须通过原有非 SYSTEM／服务账号检查。程序从 GetModuleFileNameW 取得
实际模块路径，不接受调用者另给安装路径；只接受有界的本地 drive-letter 路径，最多 128 个
组成部分。当前版本不接受 UNC／扩展命名空间形式，其他部署路径仍需独立设计和验收。

每个组成部分使用 CreateFileW 打开：

- GENERIC_READ、READ_CONTROL、FILE_READ_ATTRIBUTES；目录同时使用 BACKUP_SEMANTICS。
- OPEN_REPARSE_POINT，随后检查句柄属性，拒绝重解析点、错误文件类型和映像的额外硬链接。
- 只设置 FILE_SHARE_READ，不允许共享写入或删除；句柄保留到 DPAPI 完成或失败退出。

必须请求真实读取权限，单纯元数据权限的句柄不构成所需的写／删除共享限制。实际文件对象
测试验证持有检查句柄时，新的写／删除打开收到共享冲突；关闭检查句柄后可重新打开。

通过 GetSecurityInfo 读取同一句柄的 owner／DACL。owner 只接受当前用户、SYSTEM 或内置
Administrators；DACL 必须存在、非 NULL 且有效。普通读取／执行权限可以授给其他主体，但
其他主体的写数据、追加、写 EA／属性、删除子项、DELETE、WRITE_DAC 或 WRITE_OWNER 均拒绝。
泛型权限先按文件映射展开；不依赖 Deny ACE 去抵消不安全 Allow，未知 object／callback ACE
保守拒绝。ACE 中的 SID 长度也必须落在该 ACE 边界内。

该白名单不自动信任任意服务 SID 或不同 owner；例如 TrustedInstaller owner 的部署路径
尚未加入支持，不能用“都是本机用户”放宽规则。检查过程中部分打开的句柄、描述符和 Token
均在失败时释放。错误保持固定不可用消息，不输出 SID、安全描述符、路径或请求内容。

[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
要求读取 owner／DACL 的句柄具备 READ_CONTROL。
[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
说明 FILE_SHARE_DELETE 与后续删除／重命名访问的关系，以及 OPEN_REPARSE_POINT 的含义。
这些接口依据不替代目标 Windows 的真实文件对象、共享规则和安装验收。

## 不能由自检建立的信任

helper 自检不是可执行程序身份认证：不可信程序可以不执行自己的检查，依赖 DLL 也可能在
程序入口之前加载。不能先把明文密钥交给未知程序，再相信它声称通过 ACL 检查。
后续启动端仍须在传递秘密前验证签名配置中的辅助程序摘要／可信安装来源、路径和权限，
并解决检查与启动的绑定。这一前置条件目前未接入，未导出可用的 Windows journal provider。

这些是安装程序文件的可替换性检查，不是 SQLite／wrapped-key／临时文件的私有 ACL，
更不是 NTFS 发布、目录同步、掉电恢复或回滚证明。`loadProtectedKey` 的 Win32 拒绝保留；
没有删除拒绝条件、绕开权限，或启用当前 Windows 开发文件模式作为生产替代。

## 本地验证

严格 MinGW x64 构建包含：

- 原 helper：当前用户 DPAPI／禁止 UI 及新安装文件门禁。
- 策略 fixture：引用生产源码，检查 owner、正常 RX、不可信写／改 ACL／删子项、NULL DACL、
  不安全 Allow 即使有 Deny 也拒绝，以及文件类型、重解析点和链接数。
- 文件对象 fixture：对私有测试 helper 实际设置 DACL，验证写入权限拒绝、读取／执行允许、
  额外硬链接拒绝，以及共享锁在持有／关闭期间的行为；它恢复原始 DACL 的保护标志。

Wine 的 Z: 映射把本机 Unix 根呈现为 Anonymous owner，新门禁拒绝该路径。探针改为在自己
私有 Wine C: 根下安装相同二进制，不放宽 owner 判断。三个真实拒绝用例保持 stdin 未发送、
未关闭，验证不安全映像、硬链接映像和可写父目录在读取请求之前就退出。

另一个限制是 Wine 在文件对象上丢弃单独给 Builtin Users 的 WRITE_DAC ACE。回读已确认该
ACE 缺失；程序没有把这种结果当作 Windows 权限正确。合成描述符仍检查 WRITE_DAC 拒绝，
真实对象粒度被记录为 `wine-file-object-write-dac-ace-readback` 未验证项；Windows acceptance
仍为 false。真实 Windows 的 ACE、SID、共享与重解析点行为需要单独验收。

`.local/windows-helper-acl-final.log` 记录 23 个已验证检查组／协议场景通过，并单列上述一个
未验证项；包含原 DPAPI 的 17 个场景。summary 保留 header/C 源文件及二进制摘要，探针只
管理自己的 Wine 前缀，最终等待确认其 server 结束。不复制 Wine drive 映射或用户 profile。

`.local/windows-helper-acl-host-verify.log` 记录原有 Host 495 项验证全部通过，含本机 npm dsh
0.2.1-rc.2 CLI；本批未更改 Host 生产 TS 或 Go 代码。没有修改 Android APP、提交 PLAN.md、
尝试 TokenWorks，也没有执行大负载、真机或厂商推送配置。
