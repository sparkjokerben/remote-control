# DSH Remote Control 跨模块契约

本文件是 `remote-control` 插件、主站 `apps/api`、主站 `apps/web`、中继 `apps/miniprogram-bff` 与小程序 `apps/miniprogram` 的**唯一对齐依据**。改动协议必须同步修改本文件与全部消费方。

## 1. 模块边界

| 模块 | 职责 |
| --- | --- |
| `packages/remote-control` | 开源 `dsh` 插件（MIT，零私有依赖）。`src/crypto/**` 为纯 TS E2EE，供插件与小程序共享；Host 端负责 OIDC、隧道、会话桥、WebUI 桥；`src/client/**` 仅注册两个加法型 list 插槽按钮 |
| `apps/api` | 订阅配额、OIDC 客户端种子、E2EE 公钥库、BFF 签名接口、插件目录 API |
| `apps/web` | `/plugins` 公开下载页、`/admin/plugin-catalog` 管理页、档位与运行时配置表单 |
| `apps/miniprogram-bff` | 单实例隧道中继、Session 密文盲转、WebUI 反向代理、微信订阅消息、`MP_verify_*.txt` |
| `apps/miniprogram` | `subpackages/remote` 三个页面：远控列表、E2EE 会话控制台、横竖屏 WebUI 容器 |

约束：插件必须可脱离本仓库独立开源发布——不导入任何 `@gooftoken/*` 包，依赖只用已发布的 npm 包，域名/中继地址全部来自插件配置。

## 2. E2EE 规格（`@gooftoken/remote-control/crypto`）

### 2.1 原语与编码

- Ed25519 签名、X25519 密钥交换、HKDF-SHA256、ChaCha20-Poly1305（`@noble/curves/ed25519.js`、`@noble/hashes/{hkdf,sha2}.js`、`@noble/ciphers/chacha.js`）。
- 全部二进制在 JSON 中用 **base64url（无 padding）**。
- `crypto` 子入口必须在小程序运行：禁止 `Buffer`、`atob`/`btoa`、`TextEncoder`/`TextDecoder`、`crypto`/`wx` 全局；UTF-8 与 base64url 自行实现。
- 随机源显式注入：`type Rng = (length: number) => Uint8Array`。导出 `systemRng`（`globalThis.crypto.getRandomValues`）与 `createSeededRng(seed: Uint8Array)`（ChaCha20 派生，供小程序用 `wx.getRandomValues` 取一次 32B 种子后使用）。

### 2.2 设备公钥包

```ts
interface DeviceKeyBundle {
  keyId: string      // base64url(SHA-256(ikSignPub))
  ikSignPub: string  // Ed25519 公钥 32B
  ikDhPub: string    // X25519 公钥 32B
  spkPub: string     // X25519 signed prekey 公钥 32B
  spkSig: string     // Ed25519(ikSign) over utf8("gt-remote-spk-v1|" + keyId + "|" + spkPub)
}
interface DevicePrivateKeys { ikSignPriv: string; ikDhPriv: string; spkPriv: string }
```

`bundleHash = base64url(SHA-256(JSON.stringify({keyId,ikSignPub,ikDhPub,spkPub,spkSig})))`（字段顺序固定）。

身份绑定：节点 `nodeId` 必须等于其 `bundle.keyId`。BFF 校验 `hello.publicKey` 自洽且 `keyId === nodeId`，小程序的 `beginHandshake`/`createHandshakeInit` 强制同一约束，TOFU pin 以 `{nodeId, bundleHash}` 记录两者；任一不匹配即阻断，不得换用新 nodeId 绕过 pin。

### 2.3 握手（X3DH，1-RTT）

客户端 = 小程序；节点 = `dsh`。双方各持长期身份密钥与 SPK。

```ts
interface HandshakeInit {
  t: 'handshake.init'; v: 1
  nodeId: string; sessionId: string; clientId: string
  clientKey: DeviceKeyBundle
  ephemeralPub: string
  signature: string   // Ed25519(client ikSign) over
                      // utf8("gt-remote-x3dh-init-v1|"+nodeId+"|"+sessionId+"|"+clientId+"|"+clientBundleHash+"|"+nodeBundleHash+"|"+ephemeralPub)
}
interface HandshakeAck {
  t: 'handshake.ack'; v: 1
  nodeId: string; sessionId: string; clientId: string
  nodeKey: DeviceKeyBundle
  ephemeralPub: string
  signature: string   // Ed25519(node ikSign) over
                      // utf8("gt-remote-x3dh-ack-v1|"+nodeId+"|"+sessionId+"|"+clientId+"|"+nodeBundleHash+"|"+clientBundleHash+"|"+nodeEphemeralPub+"|"+clientEphemeralPub)
  safetyNumber: string
}
interface HandshakeErr {
  t: 'handshake.err'; v: 1
  nodeId: string; sessionId: string
  code: 'IDENTITY_KEY_CHANGED' | 'INVALID_SIGNATURE' | 'UNSUPPORTED_VERSION'
  message?: string
  peerKey?: DeviceKeyBundle
}
```

DH 输入（客户端为发起方，`C` = 客户端，`N` = 节点）：

```
dh1 = X25519(C.ikDhPriv, N.spkPub)
dh2 = X25519(C.ephPriv,  N.ikDhPub)
dh3 = X25519(C.ephPriv,  N.spkPub)
dh4 = X25519(C.ephPriv,  N.ephPub)
ikm = dh1 | dh2 | dh3 | dh4
salt = SHA-256(sort([clientBundleHash, nodeBundleHash]).join('|'))
root = HKDF-SHA256(ikm, salt, "gt-remote-x3dh-v1|" + nodeId + "|" + sessionId, 32)
```

方向链：`ck_n2c = HKDF(root, "gt-remote-chain-v1|n2c", 32)`，`ck_c2n = HKDF(root, "gt-remote-chain-v1|c2n", 32)`。节点发送用 `ck_n2c`，小程序发送用 `ck_c2n`。

### 2.4 对称棘轮

每发一条消息：

```
okm  = HKDF-SHA256(ck, "gt-remote-ratchet-v1", 64)
ck'  = okm[0..32]; mk = okm[32..64]
nonce = HKDF-SHA256(ck, "gt-remote-nonce-v1", 12)
ct = ChaCha20-Poly1305(mk, nonce, plaintext, aad)
aad = utf8("gt-remote-aad-v1|" + nodeId + "|" + sessionId + "|" + senderId + "|" + seq)
```

帧格式：`{ v: 1, seq: number, nonce: string, ct: string }`，`senderId` 为 `clientId` 或 `nodeId`。

接收端维护 `recvSeq` 与最多 256 个跳过的消息密钥；`seq < recvSeq` 直接拒绝（重放）；`seq - recvSeq > 256` 拒绝（窗口越界）。所有失败抛 `RatchetError`（含 `code`）。

### 2.5 TOFU 与安全码

- 首次连接的客户端不自动 TOFU。节点先校验 `clientId` 与 `clientKey.keyId` 的确定性绑定（`mp-<keyId>` 或 `<keyId>`），把已验签的握手放入待批准队列（每会话与总计均有上限，5 分钟过期）；批准前不回 `handshake.ack`、不推送快照或消息，也不写入 pin。`clientId` 未绑定到设备密钥，或会话客户端/棘轮超出上限时直接返回 `handshake.err/INVALID_SIGNATURE`。
- 主机 `/remote status` 列出待批准安全码；用户与小程序对比安全码后运行 `/remote approve <安全码>`，节点才发送 ack、快照并写入 pin。安全码比较对空格不敏感。
- 双方本地持久化对端 `peerId -> bundleHash`；与已钉死值不一致时节点返回 `handshake.err/IDENTITY_KEY_CHANGED` 并阻断握手。小程序只展示告警，不自行改写信任：用户在主机核对后执行 `/remote reset <clientId>` 清理钉死，客户端重新握手并再次经 `/remote approve` 信任。
- `safetyNumber(nodeBundleHash, clientBundleHash)`：`SHA-256("gt-remote-safety-v1|" + sort([a,b]).join("|"))` 取前 12 字节转十进制，`BigInt` 对 `10^20` 取模，左侧补零到 20 位，输出 `"12345 67890 12345 67890"`。两端结果必须一致。

### 2.6 加密载荷消息

```ts
interface MessageView {
  id: string
  role: 'user' | 'assistant' | 'system' | 'tool'
  text: string
  ts: number
  toolName?: string
}
interface PendingInteraction {
  id: string
  kind: 'approval' | 'question'
  toolName?: string
  callId?: string
  reason?: string
  questions?: Array<{ id: string; header?: string; question: string; multiSelect: boolean; options: Array<{ id: string; label: string }> }>
}
type EncryptedClientMessage =
  | { t: 'snapshot.request' }
  | { t: 'prompt'; text: string; mode: 'followup' | 'steer' }
  | { t: 'cancel' }
  | { t: 'approval.resolve'; interactionId: string; outcome: 'allowed-once' | 'rejected' }
  | { t: 'question.answer'; interactionId: string; answers: Array<{ id: string; selected: string[]; custom?: string }> }
  | { t: 'model.set'; provider: string; model: string; reasoningEffort?: string }
  | { t: 'preset.set'; preset: 'workspace-write' | 'danger-full-access' }
  | { t: 'ping'; ts: number }
type EncryptedNodeMessage =
  | { t: 'snapshot'; sessionId: string; title: string; cwd: string; status: 'running' | 'idle'; model?: { provider: string; model: string }; preset?: string; seq: number; messages: MessageView[]; pending: PendingInteraction[] }
  | { t: 'delta'; seq: number; text: string }
  | { t: 'message'; message: MessageView }
  | { t: 'tool'; phase: 'call' | 'result'; callId: string; name: string; args?: string; result?: string; ok?: boolean }
  | { t: 'status'; status: 'running' | 'idle' }
  | { t: 'interaction.open'; interaction: PendingInteraction }
  | { t: 'interaction.settled'; interactionId: string }
  | { t: 'pong'; ts: number }
  | { t: 'error'; code: string; message: string }
```

## 3. 隧道协议（`dsh` ⇄ `miniprogram-bff`）

单条出站 WSS：`GET /dsh-tunnel/connect`，头 `Authorization: Bearer at_...`，子协议 `gt-remote-tunnel.v1`。

### 3.1 文本帧（JSON，`t` 为判别字段）

| `t` | 方向 | 字段 |
| --- | --- | --- |
| `hello` | 插件→BFF | `proto:1, nodeId, hostname, platform, dshVersion, pluginVersion, webUiEnabled, sessions:[{sessionId,title,cwd,status}], publicKey:DeviceKeyBundle` |
| `hello.ack` | BFF→插件 | `proto:1, nodeId, userId, tierCode, maxNodes` |
| `state.sync` | 插件→BFF | `webUiEnabled, sessions:[{sessionId,title,cwd,status}], publicKey` |
| `ping` / `pong` | 双向 | `ts:number` |
| `notify.trigger` | 插件→BFF | `eventId, sessionId?, kind:'approval'\|'question'\|'turn_end'\|'turn_error', title, summary, ts` |
| `notify.cancel` | 插件→BFF | `eventId` |
| `e2ee.msg` | 双向 | 插件→BFF：`nodeId, sessionId, msg:HandshakeInit\|HandshakeErr`；BFF→插件：`nodeId, sessionId, from:'mp', msg:HandshakeInit`；BFF→小程序：`nodeId, sessionId, from:'node', msg:HandshakeAck\|HandshakeErr` |
| `e2ee.env` | 双向 | `nodeId, sessionId, frame:EncryptedFrame` |
| `http.req` | BFF→插件 | `streamId, method, path, query, headers:Record<string,string[]>, hasBody:boolean` |
| `http.res` | 插件→BFF | `streamId, status, headers:Record<string,string[]>, hasBody:boolean` |
| `http.abort` | 双向 | `streamId` |
| `ws.open` | BFF→插件 | `streamId, path, query, headers:Record<string,string[]>` |
| `ws.ack` | 插件→BFF | `streamId, ok, protocol?, error?` |
| `ws.close` | 双向 | `streamId, code, reason` |

### 3.2 二进制帧（仅 WebUI 数据面）

6 字节头：`kind:u8 | flags:u8(0) | streamId:u32be`（`streamId` 必须非零），其后为原始负载，单帧 ≤ 64 KiB：

- `0x01` HTTP 请求/响应体分片；`0x02` HTTP 体结束；
- `0x11` WebSocket 文本帧；`0x12` WebSocket 二进制帧。

## 4. BFF HTTP 接口（`https://mp.<DOMAIN>`）

小程序侧（Bearer 小程序 JWT，除注明外）：

| 方法/路径 | 说明 |
| --- | --- |
| `GET /mp/dsh/overview` | 返回 `{enabled,tier_code,tier_name,tier_expires_at,max_nodes,remaining_quota,notify_template_id,oidc_issuer,client_id,install_command,nodes:[NodeSummary]}`；`NodeSummary = {nodeId,hostname,platform,webUiEnabled,publicKey,sessions}` |
| `POST /mp/dsh/e2ee-keys` | 上报本机 `{device_id,label,ik_sign_pub,ik_dh_pub,spk_pub,spk_sig}` |
| `POST /mp/dsh/subscribe-quota` | `{accepted:boolean}`，成功返回 `{remaining_quota}` |
| `POST /mp/dsh/ws-ticket` | 返回 `{ticket,expires_in:30}` |
| `GET /mp/dsh/ws?ticket=` | 升级 WSS；也接受 `Authorization: Bearer <jwt>` |
| `POST /mp/dsh/nodes/:nodeId/webui/launch` | 仅节点 `webUiEnabled` 时返回 `{url,expires_in}` |
| `GET /MP_verify_:rest` | 业务域名校验文本 |

小程序 WSS（`/mp/dsh/ws`）下行帧：`{t:'welcome', nodes}`、`{t:'targets.sync', nodes}`、`{t:'node.offline', nodeId}`、`{t:'e2ee.msg', nodeId, sessionId, from:'node', msg}`、`{t:'e2ee.env', nodeId, sessionId, frame}`；上行只允许 `e2ee.msg` 与 `e2ee.env`。

WebUI 反向代理：`GET /dsh/:nodeId` → `302 /dsh/:nodeId/`；`/dsh/:nodeId/?ticket=` 换 `goof_dsh_sess` Cookie（`Path=/dsh/<nodeId>/; HttpOnly; Secure; SameSite=Lax; Max-Age=7200`）后 302 去查询串；`/dsh/:nodeId/*` 与 `WSS /dsh/:nodeId/api/remote.mux` 经隧道转发。

## 5. 主站签名接口（`apps/api`，`mpsign` 保护）

| 方法/路径 | 说明 |
| --- | --- |
| `POST /api/v1/miniprogram/dsh/verify-tunnel` | 入参 `{access_token, device_key?}`；校验 OIDC `at_`（未吊销、未过期、client 为 `dsh-remote`、`user_token_version` 一致）；返回 `{user_id,email,tier_code,tier_name,tier_expires_at,dsh_remote_enabled,dsh_remote_max_nodes,wechat_openid,notify:{template_id,thing_key,phrase_key,time_key},issuer,client_id}` |
| `POST /api/v1/miniprogram/dsh/authorize-user` | Bearer 小程序 JWT；同上返回（`access_token` 换为 JWT 校验） |
| `GET/POST /api/v1/miniprogram/dsh/e2ee-keys` | Bearer JWT；按 `(user_id, peer_type, peer_id)` upsert/读取公钥包 |
| `GET /api/v1/miniprogram/webview-verify` | 返回 `{filename,content}` |

插件目录（公开 `:8080`）：

- `GET /api/v1/plugin-catalog`：`{code:0,data:[PluginItem]}`。
- `GET /api/v1/plugin-catalog/index.json`：裸 `dsh` Custom Plugin Index（`format:1,title,plugins:[{name,title,description,icon,author,homepage,repository,metadata,versions:[{version,publishTimestamp,source,engines}]}]`）。`publishTimestamp` 为 Unix 秒整数；`source` 必须是对象：npm 为 `{type:'npm',registry?}`，git 为 `{type:'git',url,commit,path?}`（`url` 必须 https，`commit` 为 40 位 SHA）。
- 管理 `:8081`：`GET/POST /api/v1/admin/plugin-catalog`、`PUT/DELETE /api/v1/admin/plugin-catalog/:id`（禁止使用 `retired_routes_test.go` 中断言 404 的 `/api/v1/admin/plugins`）。

## 6. 插件行为

命令（`ctx.commands.register`）：

- `/remote` 或 `/remote session [off|stop]`：开启/关闭当前会话 E2EE 远控。
- `/remote webui [off|stop]`：开启/关闭整机 WebUI 远控。
- `/remote stop`：关闭全部远控并断开隧道。
- `/remote status`：登录态、隧道状态、配额、共享会话数、E2EE 安全码、待批准客户端。
- `/remote approve <安全码>`：批准首次连接的客户端；节点随后发送 ack 与会话快照。
- `/remote reset <clientId|安全码>`：清理待批准握手或已钉死的客户端密钥，用于小程序重装后重新配对。
- `/remote login [callback-url]`：OIDC 登录或无头粘贴回调。
- `/remote logout`：吊销令牌并清理凭据。

规则：任一远控开启时若无凭据则自动发起 OIDC 登录，成功后接续开启；`webUiEnabled` 或共享会话为空的节点不维持隧道；会话未显式 `session` 开启时不得出现在 `state.sync`。

OIDC 种子客户端 `dsh-remote`（迁移 384）已注册 `http://127.0.0.1/callback` 与 `http://localhost/callback`：插件固定监听 `127.0.0.1:<随机端口>/callback`，native 客户端按 loopback 路径匹配并忽略端口；运维不得清空该列表，否则 authorize 直接 400。

WebUI 视口垫片（仅隧道返回的 `text/html`）：

- 将现有 `<meta name="viewport">` 替换为 `width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover`；
- 注入 `:where(html,body,#root){height:100dvh;min-height:100%;-webkit-text-size-adjust:100%;box-sizing:border-box}`、安全区 `env(safe-area-inset-*)` 内边距（竖屏上下、横屏左右，`@media (orientation:landscape) and (max-height:520px)`）、以及 `visualViewport` 同步 `--gt-vvh` 的脚本；
- 不改动任何 `dsh` 内部类名、主题变量或插槽。
- WebUI 始终以 `/dsh/<nodeId>/` 前缀提供服务（HTML 内 `<base href="./">`）；第三方插件必须使用文档相对路径（`plugins/...`、`api/...`），根绝对路径（`/api/...`）会落到中继根路径而非该节点。

## 6.1 插件内部模块接口（Host 核心 / 桥接并行实现）

```ts
export type Logger = Pick<Console, 'debug' | 'info' | 'warn' | 'error'>

// config.ts
export interface Config {
  enabled: boolean
  domain: string
  issuerUrl?: string
  relayUrl?: string
  clientId: string
  nodeName?: string
  notifyOnTurnEnd: boolean
  notifyOnApproval: boolean
}
export interface ResolvedConfig {
  issuerUrl: string
  relayUrl: string
  clientId: string
  nodeName: string
  notifyOnTurnEnd: boolean
  notifyOnApproval: boolean
}
export function resolveConfig(config: Config, fallbacks?: { domain?: string; nodeName?: string }): ResolvedConfig

// credentials.ts
export interface Grant { issuer: string; relay: string; clientId: string; nodeId: string; accessToken: string; refreshToken: string; expiresAt: number; domain: string }
export interface DeviceIdentity { bundle: DeviceKeyBundle; privateKeys: DevicePrivateKeys }
export interface PersistedState { grant?: Grant; identity?: DeviceIdentity; pins: Record<string, string> }
export interface CredentialStore {
  load(): Promise<PersistedState>
  saveGrant(grant: Grant): Promise<void>
  saveIdentity(identity: DeviceIdentity): Promise<void>
  setPin(peerId: string, hash: string): Promise<void>
  clear(): Promise<void>
}
export function createCredentialStore(ctx: Context, log: Logger): CredentialStore

// tunnel.ts
export type TunnelFrame = { t: string; [key: string]: unknown }
export interface Tunnel {
  connect(): Promise<void>
  disconnect(): void
  readonly status: 'offline' | 'connecting' | 'online' | 'error'
  sendText(frame: TunnelFrame): void
  sendBinary(kind: number, streamId: number, payload: Uint8Array): void
  onText(handler: (frame: TunnelFrame) => void): () => void
  onBinary(handler: (kind: number, streamId: number, payload: Uint8Array) => void): () => void
  onStatus(handler: (status: TunnelStatus) => void): () => void
  dispose(): void
}
export function createTunnel(deps: {
  config: ResolvedConfig
  store: CredentialStore
  refreshToken(): Promise<Grant | null>
  log: Logger
}): Tunnel

// session-bridge.ts
export interface PendingApproval {
  sessionId: string
  clientId: string
  safetyNumber: string
  receivedAt: number
}
export interface SessionBridge {
  readonly shared: string[]
  status(sessionId?: string): { shared: boolean; safetyNumber?: string }
  pendingApprovals(): PendingApproval[]
  approve(safetyNumber: string): Promise<{ ok: boolean; approved: number; error?: string }>
  clients(): Array<{ sessionId: string; clientId: string; safetyNumber: string; pending: boolean }>
  reset(raw: string): Promise<{ ok: boolean; reset: number; error?: string }>
  toggle(sessionId: string, enabled: boolean): Promise<{ ok: boolean; error?: string }>
  stopAll(): Promise<void>
  handleText(frame: TunnelFrame): void
  dispose(): void
}
export function createSessionBridge(ctx: Context, deps: BridgeDeps): SessionBridge

// webui-bridge.ts
export interface WebUiBridge {
  status(): { available: boolean; active: boolean }
  toggle(enabled: boolean): Promise<{ ok: boolean; error?: string }>
  handleText(frame: TunnelFrame): void
  handleBinary(kind: number, streamId: number, payload: Uint8Array): void
  stopAll(): void
}
export function createWebUiBridge(ctx: Context, deps: BridgeDeps): WebUiBridge

export interface BridgeDeps {
  config: ResolvedConfig
  store: CredentialStore
  tunnel: Tunnel
  rng: Rng
  log: Logger
  onStateChanged(): void
  onNotify(event: { kind: 'approval' | 'question' | 'turn_end' | 'turn_error'; sessionId?: string; title: string; summary: string }): string | void
  onNotifyCancel(eventId: string): void
}

// control-route.ts
export function registerControlRoute(ctx: Context, deps: {
  runtime: { session: SessionBridge; webui: WebUiBridge }
  log: Logger
}): () => void

// index.ts（Host 核心负责组装）
export const name = 'remote-control'
export const inject = ['agents', 'sessions', 'credentials', 'commands']
export const Config: Schema<Config>
export function apply(ctx: Context, config: Config): void
```

Client 端注意：仓库未依赖 `@deepseek-ai/dsh-client-ui-layout`，`SlotMap` 中没有插槽声明，注册时对插槽名与 props 做最小类型断言，禁止导入 UI 布局包内部模块。

## 7. 小程序行为

- 远控列表仅展示节点自报的 `webUiEnabled` 与共享会话，不提供模式切换开关。
- 顶部胶囊 `提醒 N 次 [+1]`：点击显式请求一次订阅消息并上报；`N === 0` 时随页面首次点击手势自动请求一次（每次进入仅一次）。
- Session 页面：握手前展示加载态；首次连接保持 pending，需主机 `/remote approve <安全码>` 后才会收到 ack 与消息；`IDENTITY_KEY_CHANGED` 全屏阻断并要求确认；安全码弹窗展示 20 位分组数字。
- WebUI 页面：`index.config.ts` 设置 `pageOrientation: 'auto'`。

## 8. 验证要求

```sh
pnpm -r run typecheck
pnpm --filter @gooftoken/remote-control run test:run
pnpm --filter './packages/*' run test:run
# 发布门禁：构建双产物、真实加载 client 入口，并生成 tgz。
pnpm --filter @gooftoken/remote-control run build
pnpm --filter @gooftoken/remote-control run test:dist
pnpm --filter @gooftoken/remote-control run pack:release
# CI 随后解包 release/remote-control.tgz，断言 lib/index.js、lib/client.*、src/crypto、
# LICENSE、assets/icon-180.png 均存在，并从解包目录做一次 require/import 冒烟。
go build ./... && go test -tags=unit ./apps/api/... ./apps/miniprogram-bff/...
make errors && make openapi            # 生成物需提交，CI 校验无漂移
pnpm --filter @gooftoken/web run build
pnpm --filter @gooftoken/miniprogram run test:run
TARO_APP_DOMAIN=example.com pnpm --filter @gooftoken/miniprogram run build:weapp
sh deploy/tests/miniprogram-bff-deploy-test.sh
```

## 9. 公开仓库与自动同步

- 公开仓库 `sparkjokerben/remote-control` 只包含 `packages/remote-control` 的内容、`tools/public-remote-control` 脚手架与本契约文档，不含 monorepo 其它文件。
- 私有主仓 `.github/workflows/publish-remote-control.yml` 在 `main` 的相关路径变更时单向同步（`rsync --delete`），公开仓的直接修改会被覆盖；鉴权使用仓库级 Deploy Key（secret `PUBLIC_REPO_DEPLOY_KEY`，仅该公开仓写权限）。
- 公开仓 `.github/workflows/release.yml` 在 `package.json` 版本变化时自动创建 `v<version>` tag 与 GitHub Release，资产固定为 `remote-control.tgz`；`.github/workflows/ci.yml` 对每次同步执行 typecheck、单测、构建与客户端入口冒烟。
