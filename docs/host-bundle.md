# Host npm 包、输入清单与离线校验

`tools/release/host_bundle.py` 为本仓的进程内 Host 插件生成本地 npm 包和校验清单。
它不签名、不上传、不发布，不生成 TokenWorks 发行配置，也不读取用户已安装的 profile、
模型凭据或学校账号。包仍是 `private: true`、当前版本 `0.0.1`，不能据此认定已通过发行验收。

## 构建与复现

在仓库根目录完成依赖安装和正常验证，再明确指定本机 npm 安装的 dsh：

```sh
npm ci --offline --ignore-scripts
npm run verify
export REMOTE_TEST_DSH_BIN=/本机/npm/安装的/dsh
python3 tools/release/host_bundle.py build \
  --output "$PWD/.local/host-bundle-a" --dsh-bin "$REMOTE_TEST_DSH_BIN"
```

输出目录必须是仓库 `.local` 的直接子目录，且尚不存在。目录为 0700；包、清单和构建日志为
0600。当前私有文件检查使用 POSIX 所有权／权限，在 Linux 上验证；Windows ACL、签名和目标
平台打包不在这份证据内。失败时没有 verified 成功输出；已有失败目录不会被自动覆盖，应保存
证据并用新目录重试。

工具要求 Node 24.15+ 且低于 25，以及真实 `dsh --version` 为 `0.2.1-rc.2`。
它检查正常发行输入的 Git 状态，包括根 package/lock/tsconfig、Host package/build 配置、README、
全部 Host src 和 contracts；这些输入有修改、删除、未跟踪文件（包括被 gitignore 隐藏的文件）或符号链接时拒绝构建。
无关工作区改动不被当作 Host 输入，PLAN.md 和 Android 代码不会进入包或输入清单。
当前工作区若有未提交的 Host README 改动，也会被正确拒绝，不能偷偷使用旧副本替代。

编译发生在新的私有暂存目录，不修改工作区 `host/remote-control/lib`，不复用其中的陈旧文件。
source map 使用固定的相对 sourceRoot。AST 检查覆盖运行时／类型 import、export、静态
require 与相对模块边界，直接模块必须在 dependencies 或 peerDependencies 中显式声明；
不会把注释／普通字符串误当作导入，也不允许通过计算式动态导入绕过该检查。npm pack 禁用脚本并开启 offline；产物只能包含
`package.json`、README 和 lib 下的 JS、声明及 source map。实际 tar 文件必须与暂存目录逐字节
一致。安装／准备／打包 hook、额外本地文件、测试、PLAN、配置和运行状态均不允许混入。

成功目录包含：

- `ustc-dsh-remote-control-0.0.1.tgz`：仅插件运行文件和元数据，不含 node_modules；peer 仍需由宿主提供。
- `manifest.json`：源码 commit 与逐文件输入摘要、builder 摘要、Node/npm/TypeScript、构建平台、
  dsh CLI 版本和入口文件摘要、实际解析的直接／peer 版本，以及包大小、哈希、逐文件清单和模式。
- `build.log`：本地编译／npm 输出，保留作构建诊断，不在 npm 包内。

工具核对已解析依赖版本与声明的精确版本，并记录锁文件摘要；这不等于独立验证了全部
node_modules 文件、依赖供应链或编译器可信性，也不替代来源审计。源码 commit 指发行运行
输入的 Git 基线；开发中的工具／测试改动由 builder 文件摘要单独记录。正式交付前应在最终
批准的 commit 和受控环境重新构建并保存验证记录。

相同运行输入、builder 和工具链可在另一个新目录重建：

```sh
python3 tools/release/host_bundle.py build \
  --output "$PWD/.local/host-bundle-b" --dsh-bin "$REMOTE_TEST_DSH_BIN"
```

本机两次独立构建的包和清单摘要均相同。清单不包含构建绝对路径或易变的生成时间；它记录的
平台／工具链仍需与重现环境对应，不能将单机重现推广为所有平台重现。

## 离线校验与加载

校验不需要 Git、npm、Node、DSH 或网络，只用 Python 标准库和当前可信的 verifier。
必须从受控构建结果或独立可信渠道取得清单 SHA-256，再验证受保护的目录：

```sh
BUNDLE_MANIFEST_SHA256='<独立保存的 64 位小写清单摘要>'
python3 tools/release/host_bundle.py verify \
  --directory "$PWD/.local/host-bundle-a" \
  --expected-manifest-sha256 "$BUNDLE_MANIFEST_SHA256"
```

这不是签名或发布者身份认证。如果攻击者能同时改写包、清单和调用方信任的摘要，校验不能
证明来源。不能只读取同目录清单的自报摘要就把外来包当作可信程序。

清单在取出包文件名之前先核对独立摘要；随后核对整个压缩包、文件清单、模块入口和精确
依赖声明。压缩输入上限 16 MiB，单文件 8 MiB、文件数据合计 32 MiB、最多 512 个文件；
解压总字节另有包含 tar 头／填充的固定上限。拒绝路径穿越、绝对路径、反斜杠／控制字符、
链接、特殊文件、重复条目、稀疏／扩展头和末尾隐藏的额外归档成员。

只有全部检查完成后才可选择 `--unpack <新目录>`。其父目录必须为当前用户拥有的规范化
0700 目录，目标不能已存在。解包逐个创建普通文件，不使用 extractall；文件为 0600。
工具不安装依赖、不执行包代码；I/O 失败留下的部分目录不能作为成功产物使用。

已安装 dsh 的现有 CLI 测试可以加载经校验的新解包，失败时不会回退到工作区 lib：

```sh
REMOTE_TEST_HOST_BUNDLE_DIRECTORY="$PWD/.local/host-bundle-a" \
REMOTE_TEST_HOST_BUNDLE_MANIFEST_SHA256="$BUNDLE_MANIFEST_SHA256" \
REMOTE_TEST_DSH_BIN="$REMOTE_TEST_DSH_BIN" \
  npx tsx --test host/remote-control/tests/dsh-cli.integration.test.ts
```

正常 Go 双节点／已安装 dsh 组合使用显式参数：

```sh
python3 tools/integration/run_host_enrollment_terminal.py \
  --host-bundle-directory "$PWD/.local/host-bundle-a" \
  --host-bundle-manifest-sha256 "$BUNDLE_MANIFEST_SHA256" \
  --output .local/host-bundle-go-dsh.log
```

底层 runner 同样支持这两个参数，并要求 `--dsh-only`，可配合 `--cross-node`。
缺失配对、错误摘要或离线校验失败在启动组合资源前拒绝；未显式选择包时，底层 runner 会
清除继承的 bundle 环境变量，保持正常工作区入口。Node 测试在加载程序前再次验证并提取到
独立私有目录；登记客户端和 DSH 插件使用相同的包入口。此处依赖由锁定的测试宿主提供，
没有声称执行了生产安装或真实企业发行装配。

## 本地证据

- `.local/host-bundle-approved-a.json`、`host-bundle-approved-b.json`：两次独立构建，包与清单一致，221 个文件。
- `.local/host-bundle-peer-verify-final.log`：481 个 Host 测试、契约、类型和构建通过，无跳过。
  包括七组 Python 校验测试，以及 bundle 参数／错误摘要在组合资源创建前拒绝。
- `.local/host-bundle-approved-cli.log`：实际 npm dsh 读取已验证包，完成会话、聊天、重连去重、审批拒绝和普通提问。
- `.local/host-bundle-approved-go.log`：两个生产 Go 进程／私有 PostgreSQL／实际 npm dsh 使用包入口，
  完成登记、受保护密钥、聊天、审批、提问、归档对账、文件状态和撤权链路。

测试包基于干净的运行输入 `8d7770c`；身份、模型和密钥服务均为本地夹具。
没有签名或发布，没有修改 Android APP、提交 PLAN.md、尝试 TokenWorks，也没有执行大负载、
真机或厂商推送配置。学校身份、三平台发行和试点／生产验收仍保持独立出口条件。
