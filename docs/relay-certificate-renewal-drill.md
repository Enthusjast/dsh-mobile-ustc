# 节点间 mTLS 叶证书和私钥续期演练

计划要求证书与密钥轮换有演练记录。这个独立开关用两个实际生产 Go 子进程、私有 PostgreSQL
和本机 npm dsh 0.2.1-rc.2，验证**同一 CA 下更换节点叶证书及私钥并逐个重启**后的恢复。
身份、模型和证书均为本地夹具，不接入学校、生产 CA、已有桌面 profile 或生产密钥库。

## 运行范围

在仓库根目录运行，输出必须是仓库 `.local` 内尚不存在的新文件：

```sh
REMOTE_TEST_DSH_BIN=/本机/npm/安装的/dsh \
  python3 tools/integration/run_host_enrollment_terminal.py \
  --relay-certificate-renewal --output .local/relay-leaf-renewal.log
```

无须终端确认夹具时可用底层入口：

```sh
python3 tools/integration/run_remote_dsh.py \
  --cross-node --dsh-only --relay-certificate-renewal
```

必须独立运行；不能同时选 Host 凭据续期、安装撤销、账号退出、数据库故障、Relay 崩溃、
Go suite、Kotlin／Android 或容量模式。runner 会先清除继承的演练环境变量，再按本次参数开启，
不会因为上一轮 shell 的状态自动更新凭据或重启节点。常规运行保持原来的正常链路。

仅通过本次 `startProcess` 返回的两个子进程 handle 发送 SIGTERM；不接受外部 PID，不终止
DSH 或 PostgreSQL。凭据位于本次私有测试根下，目录必须归当前用户所有、权限 0700、无符号
链接别名；节点只接受已登记的 fixture UUID 和 loopback 地址，最多两个。更换入口只接受
闭包中的节点索引，不接受替代 CA、证书路径、URI 或任意网络地址。

## 观察内容

先在真实 DSH 会话发送一个原 ID 命令，等待原生持久 `agent_queued`，再依次更新手机入口 B、
Host owner A。每个步骤都执行：

1. 记录当前 TLS peer 指纹、节点 generation、Host connection 和未更新节点的租约。
2. 正常停止选中的节点，确认旧手机连接关闭；其余节点、数据库和 DSH 保持运行。
3. 在私有临时目录生成新 EC 私钥和叶证书。保留 CA、节点 UUID、SAN、client/server EKU、
   端口与配置路径；检查新公钥确实不同且匹配证书，并完成两种用途的 CA 验证。
4. 在节点已停止时替换该节点的 key/cert 文件，再显式启动同一生产入口。新的 TLS 1.3 连接
   核对服务实际呈现的指纹等于新证书。入口更新时 owner 的 Host connection 不变；owner
   更新时等待同一正常插件以新 connection 重连。未更新节点的 generation 和租约保持有效。
5. 手机重新申请 ticket 并完成设备证明、取得新快照。旧订阅／sync 必须拒绝；原 ID 显式对账
   仍只有一条原生用户消息，每一轮的新命令也只出现一次。最终 DSH epoch、原生 session ID
   与最初相同，数据库 dump 中没有这些命令正文。

两个方向都通过实际路由业务：B 更新后用新 client 证书连旧 A；随后 A 更新，新 B 连接新 A。
独立 TLS probe 核对服务证书，业务握手继续验证节点 URI、数据库 generation、当前 route 和
设备证明；probe 不能替代这些业务授权。

## 对部署流程的含义

生产入口在启动时读取节点证书、私钥和 CA；当前没有热重载。替换磁盘文件不会更换现有
进程的 TLS 配置。这份夹具采用“停止单节点、更换匹配文件、重启并验证”的顺序，**两文件
替换不是在线原子更新或断电恢复承诺**。生产实施仍需已有证书发行流程、备份和回退、剩余
有效期与容量余量，以及当前版本全部节点的配置／信任核对；不能把本地命令用于生产文件。

本演练没有更换 CA 或证明旧叶证书已撤销。在相同 CA 信任下，尚未过期的旧叶证书可能继续
被接受，这与单纯续期不同。CA 信任切换、紧急泄露处置、CRL/OCSP、自动证书管理、公开入口
TLS、生产私钥托管、SLO 和无人值守滚动升级不在这份证据范围内。DSH 继续使用自身原生日志，
演练不自动重发命令或重新执行副作用。

## 本地记录

- `.local/relay-cert-renewal-host-verify.log`：479 项 Host 测试全部通过，无跳过；契约、类型和构建通过。
- `.local/relay-cert-renewal-go-tls.log`：生产入口 mTLS 配置与身份匹配的 Go race 回归通过。
- `.local/relay-cert-renewal-native.log`：实际两节点／已安装 dsh 组合通过；入口轮约 524 ms，owner 轮约 1691 ms。
  这是本机单次恢复观察，不是性能或可用性目标。
- `.local/relay-cert-renewal-normal.log`：父环境设置同名演练变量，但未传开关的普通完整链路仍不执行续期。

新增测试还覆盖新 key/cert 与 CA／身份不变、配置不变、0600、无效索引、caller 输入变化、
危险目录／别名／外部地址拒绝，以及模式互斥在创建输出或进程前生效。没有修改 Android APP，
没有运行大负载、真机或厂商推送配置，也未尝试 TokenWorks。
