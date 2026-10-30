# Host 资源身份到连接凭据的 REST provider

Host 包导出 `HostRestCredentialProvider`，实现既有 `HostCredentialProvider` 接口。
它使用已登记安装密钥、当前资源登录态和正式 Go REST 接口取得连接凭据，随后交给普通 Host
握手。不生成安装密钥、不登记/重新绑定 installation、不读取学校/模型配置、不实现 OAuth
登录或 refresh token 流程，也不把短期连接秘密写到磁盘。

Linux 可选择[Secret Service 安装密钥签名器](linux-secret-service-installation-signer.md)读取
预配置私钥；它不代替安装登记、学校身份适配或目标系统验收。

## 接入条件与所有权

调用方提供这些固定输入：可信远控 origin、已确认的 installation UUID、P-256 公共 JWK、
返回 64 字节 IEEE-P1363 签名的安装 signer，以及预期 issuer / subject / resource audience /
host client ID / 必需 scopes。公共 JWK 拒绝私钥字段和非规范编码，签名在发送前用该公钥
独立验证；provider 不接收或导出私钥。

`HostResourceAccessProvider` 是**现有已验证登录态的适配接口**。它收到固定 origin、资源用途、
账号和安装 proof-key thumbprint，应通过发行端受支持的资源凭据能力返回已验证的远控 access
token、DPoP 类型、同一身份/用途/密钥、签名有效期与 scopes。Discovery、issuer/JWKS 签名、
nonce、token 用途与刷新校验由该登录适配器负责；这些描述字段自身不是已验证身份的证明。
Go 服务还会独立验证 JWT / DPoP、当前账号、安装归属、登记状态、密钥版本及撤销。

也可使用 [HostResourceJwtProvider](host-resource-jwt.md) 对既有登录来源返回的 DPoP JWT
进行本地签名和用途校验。它需要显式可信 issuer / JWKS 配置，登录和刷新仍由发行端提供。

`HostResourceAccess.expiresAt` 是经过验证的有效 access-token 到期时间，单位为 Unix 毫秒，
不能把 OAuth 的 expires_in 秒数或未经验证的 JWT payload 直接当作该值。

服务端当前要求 token 的 DPoP 密钥与已登记安装公钥一致。绑定其他密钥的现有桌面 token
不能直接使用，也不能改成 Bearer。发行端需通过受支持的身份接口取得该资源/密钥绑定；
学校配置不可用时，本仓使用明确的本地 issuer 夹具，不引入登录降级或模型 Key 作为替代。

适配器的 `signal` 必须在登出、账号/安装密钥切换时取消。provider 的 signal 同时受本地
`close()` 控制；取消会结束在途 REST、清除本地缓存，拒绝晚回调，并使普通 Host Relay 结束
已有 socket/订阅。预期身份和用途不匹配时，在任何 HTTP 写入之前拒绝。密钥丢失/重装仍需
重新登记，不能用这个 provider 恢复旧 grants 或把旧安装自动移交给其他账号。

```ts
import { HostRestCredentialProvider, createRemoteControlPlugin } from '@ustc/dsh-remote-control'

// 以下变量由已确认的安装身份和发行端登录/密钥适配层提供，不是学校 SDK 的示例 API。
const credentials = new HostRestCredentialProvider({
  origin: remoteOrigin,
  installationId: enrolledInstallationId,
  publicJwk: installationPublicJwk,
  signer: installationSigner,
  identity: { issuer, subject, audience: remoteAudience, clientId: hostClientId },
  requiredScopes: remoteScopes,
  account: existingVerifiedResourceAdapter,
})
const plugin = createRemoteControlPlugin(credentials, signedApprovalOptions)
// 账户所有者结束时取消 account.signal；不再使用该 provider 时调用 credentials.close()。
```

默认仅 HTTPS，使用 Node 的正常系统证书验证，没有跳过 TLS 的参数。仅显式设置
`allowLoopbackHttp: true` 时允许字面 loopback IP 的 HTTP，用于本地开发。
origin 不允许用户信息、路径、查询或 fragment。Host Relay 还检查自己的 WSS/WS origin
与 provider 的 origin 完全对应，不能把 A 的凭据发到 B。

## 请求、nonce 与未知结果

provider 只向固定 origin 发送两个 POST：`/v1/host-credentials/challenges` 和
`/v1/host-credentials`。每次 HTTP 使用新的 ES256 DPoP proof，绑定 POST、精确 htu、
access-token SHA-256、iat、随机 jti 及资源 nonce。安装 challenge 的 proof 使用独立用途
`dsh-host-credential-proof+jwt`，绑定 installation、固定 audience、challenge ID 和原 nonce。
它不把普通 DPoP 当作业务正文签名。

仅对严格匹配的 401 / `DPoP error="use_dpop_nonce"`、`auth.proof_invalid` 及规范新 nonce，
重试一次原 HTTP 请求，并重新签署 DPoP/jti。这条服务端 middleware 在业务操作之前返回；
交换的原 challenge proof 保持不变。其他 401/403、限流、网络丢失、超时、重定向或响应解析
失败均不自动重放 POST，不回退到旧的临近到期缓存。结果不明确时返回固定错误；下一次显式
获取从新 challenge 开始，不再次消费原 proof。未知的旧凭据/挑战按既有服务端期限与配额处理。

资源 nonce 只属于这个 origin/安装 key 的 provider，不与 issuer token endpoint nonce 混用。
请求没有 cookie、不会跟随重定向，不接受响应给出的其他 endpoint。响应要求 JSON、no-store、
identity 编码且最多 16 KiB；严格解析拒绝重复字段、错误 UTF-8、额外字段、非规范秘密和错误
installation / audience / key / 类型 / 期限。不会将原始错误响应或解析异常作为错误消息输出。

## 缓存、并发和期限

同一 provider 的并发获取共享一个在途 mint，避免突破 pending challenge/active credential
配额。一个等待者取消不取消其他等待者；最后一个等待者退出会取消操作，晚到结果不能重新
填充缓存。整个 mint 有 15 秒期限；资源 token 的到期也会取消后续操作。调用方仍应绑定自己的
取消 signal。忽略取消的外部登录/签名调用不会阻塞等待方，也不能在结束后发布结果。

连接凭据按已校验的 installation / key / owner 保存于内存，使用绝对到期和单调剩余量中较短
者，最多五分钟；临近 30 秒时重新取得当前资源登录态并换证。正常网络重连可复用仍有效的
短期凭据，但每次仍完成新的 socket challenge。缓存不是当前授权证明：Go 每次接入仍检查
最新撤销/版本，旧凭据不能恢复权限。原资源 JWT 到期不会自动延长派生凭据；后续 mint 需要
适配器给出有效资源身份。派生连接凭据采用 Go 服务既有的独立五分钟策略，缓存命中不会刷新
这个期限；原连接期限见[连接生命周期](host-relay-lifecycle.md)。

provider/返回凭据的普通字符串、JSON 和 Node inspect 均脱敏；凭据秘密不作为可枚举字段。
调用方显式读取 `.credential` 才取得用于 HTTP upgrade 的值。JavaScript 字符串不能承诺安全
擦除或抗进程内存读取，调用方仍不得把原值写入日志、配置或磁盘。关闭后的 getter/signer 拒绝使用。

## 本地证据及未完成项

真实小型 HTTP/WebSocket 夹具覆盖并发 mint/缓存/临近到期换证、两个签名用途、有限 nonce
重试、账号/用途/密钥/scopes 拒绝、独立等待者取消、晚资源回调、错误签名/输入突变、丢失交换
响应后新 challenge、重定向不跟随、JSON/大小/编码/保密边界，以及 account signal 终止实际 Host。

正常 npm DSH 0.2.1-rc.2 插件已改用导出的 REST provider，通过生产 Go / 私有 PostgreSQL
完成资源 JWT/DPoP、一次性安装 challenge、连接密钥证明与原生业务链路；测试不再把固定
连接秘密嵌入插件夹具。父进程独立获取也检查正常缓存。资源 token/私钥仍为本地 issuer 和
临时受保护夹具，不代表学校登录适配器或生产 OS key store 已经接入。

同一生产组合在末尾吊销测试 installation：正常 Host 被周期授权检查断开，新 provider 的
正式 REST 获取返回 denied，旧缓存秘密在 HTTP upgrade 被拒绝。客户端缓存没有恢复权限。
资源 token 和连接秘密也被加入数据库 dump 与私有指标的排除检查。

另有显式启用的[五分钟自然到期组合](host-credential-renewal.md)，检查普通插件在原期限结束后
重新取证、握手和恢复原生会话。它使用本地 issuer 更新资源来源，真实学校刷新及长时间连续
运行仍需独立验收。

没有改动 Android APP，也没有运行 Android 构建/设备测试、大负载或厂商推送配置。
真实学校资源配置、生产登录/密钥适配器、安装重登记、长时间换证和完整恢复验收仍需继续完成。
