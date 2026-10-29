# Host 资源 JWT 本地验证

`HostResourceJwtProvider` 将既有登录组件取得的 DPoP 资源 access token 适配为
`HostResourceAccessProvider`。它使用明确配置的可信 issuer、签名密钥地址和当前安装公钥，
在主机发送登记或连接凭据请求前验证 JWT。远控服务仍独立验证令牌、设备证明和当前授权。

这个组件不实现登录、OIDC Discovery、token exchange 或 refresh，也不读取桌面应用或模型配置。
发行端须用受支持的现有登录能力获取绑定当前安装密钥的资源 token，并在登出、账号切换或
安装密钥变更时取消 source 的 `signal`。不能从未经验证的 token 自行选定预期账号、issuer、
audience、client ID 或 JWKS 地址。学校配置尚未登记时只能使用隔离夹具，不能改用 Bearer 或
其他用途的令牌。

## 接入

```ts
import {
  HostEnrollmentClient, HostResourceJwtProvider, HostRestCredentialProvider,
  type HostResourceIdentity, type HostResourceTokenSource,
} from '@ustc/dsh-remote-control'

// 这些值由发行端的可信配置和当前登录账号提供。
declare const origin: string
declare const identity: HostResourceIdentity
declare const jwksUrl: string
declare const publicJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string }
declare const signer: { sign(input: Uint8Array): Uint8Array | Promise<Uint8Array> }
declare const installationId: string
declare const source: HostResourceTokenSource // 返回 { token, tokenType: 'DPoP' }

const requiredScopes = ['remote.access']
const account = new HostResourceJwtProvider({ origin, identity, jwksUrl, publicJwk, requiredScopes, source })
const enrollment = new HostEnrollmentClient({ origin, identity, publicJwk, requiredScopes, signer, account })
const credentials = new HostRestCredentialProvider({ origin, identity, installationId, publicJwk, requiredScopes, signer, account })
// 分别配合本机绑定确认及 Relay 使用；不再使用时关闭三个对象。
```

JWKS URL 是信任根的一部分：发行端必须确认它属于配置的 issuer。组件不从 JWT header、HTTP
重定向或 Discovery 动态选择地址；HTTPS 使用系统证书验证。仅显式设置 `allowLoopbackHttp`
时，才允许字面 loopback IP 上的 HTTP 夹具。来源只返回 token 和 DPoP 类型；用户标识、资源
用途及必要 scope 必须来自预先可信的配置。source 应遵守取消信号，不能在账号变化后继续
返回旧 token。

## 校验与限制

- 支持 `at+jwt` / `application/at+jwt` 的 ES256 P-256 或至少 2048 位 RS256 签名。
  拒绝重复 JSON 字段、非规范 base64url、未知算法、嵌入密钥和远程密钥 header。
- 校验 issuer、subject、audience、client ID、jti、iat、exp、可选 nbf、scope 和 `cnf.jkt`。
  令牌签发到过期不超过 15 分钟，剩余期限超过一秒且不超过 15 分钟；iat / nbf 允许最多
  30 秒时钟偏差。令牌必须与配置的安装公钥指纹一致。
- JWKS 响应最多 128 KiB、32 个键，拒绝私钥、重复 key ID、非签名用途、重定向和错误内容类型。
  缓存最多 60 秒并遵守 `no-cache` / `no-store`；未知 key ID 的刷新间隔至少五秒。同一 key ID
  换钥时，旧缓存失效前不会因签名错误而主动刷新，因此应使用新的 key ID 或等待缓存到期。
  没有可用缓存时若遇到未知 key ID，限流期间其他请求也会暂时失败关闭。
- 同一 provider 最多八个在途取令牌操作；共享 JWKS 请求最多等待五秒，单次取令牌最多等待
  15 秒。一个调用者取消不会取消其他调用者共享的签名密钥请求；账号取消会使所有调用失效。
- 返回对象的普通字符串、JSON、inspect 和对象展开不包含 token；显式读取 `.token` 才取得值。
  账号结束或令牌到期后 getter 拒绝访问。JavaScript 内存副本不能保证擦除，source 和调用方
  仍不得把 token 写入日志或普通配置。

本地 JWT 验证只能确认令牌及其绑定，不能证明服务端当前授权、撤权状态或学校 IdP 是否支持
所要求的资源配置。服务端继续执行独立校验；`HostRestCredentialProvider` 仍以短期连接凭据
和新握手访问 Relay。

## 本地验证与边界

小型测试覆盖 ES256 / RS256、身份和用途不匹配、过期、重复声明、错误签名、密钥轮换、禁用
缓存、未知 key ID 限流、无效 JWKS、并发与取消。Go / 隔离 PostgreSQL / 本机 npm DSH
`0.2.1-rc.2` 双节点夹具让登记客户端和正常插件分别从本地 issuer 的 JWKS 校验资源 JWT，再
完成主机绑定、连接及业务链路。测试身份、登录来源、模型和密钥库均为夹具；真实学校 IdP、
资源注册、登录刷新适配及生产密钥库尚未验收。
