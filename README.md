# @gooftoken/remote-control

DeepSeek Harness (`dsh`) 远程控制插件：把本机 `dsh` 与微信小程序配对，支持两种由宿主按需开启的形态。

- **Session 远控**：仅暴露显式开启的会话；X3DH 自动协商 + 对称棘轮，全程端到端加密（E2EE），中继服务器只转发密文。
- **WebUI 远控**：把完整 `dsh` WebUI 经反向隧道映射到小程序 `<WebView>`；除视口/安全区垫片外零 UI 侵入，兼容第三方 UI 美化插件。

## 安装

```sh
dsh plugin --profile web add @gooftoken/remote-control
dsh plugin --profile web add ./remote-control.tgz   # 离线包
```

## 使用

在 `dsh` 内：

```
/remote session      # 开启当前会话的加密远控（未登录会自动拉起 OIDC 登录）
/remote webui        # 开启整机 WebUI 远控
/remote status       # 连接状态、配额、20 位安全码与待批准客户端
/remote approve <安全码>  # 批准首次连接的客户端
/remote reset <clientId|安全码>  # 小程序重装后清理密钥记录并重新配对
/remote stop         # 关闭全部远控
/remote login        # 手动登录（无头 SSH 可粘贴回调 URL）
/remote logout
```

会话头部与侧栏提供同功能的加法按钮。

## 配置

插件通过 Schemastery 配置（`dsh` 设置面板或 `cordis.patch.yml`）：

| 键 | 说明 |
| --- | --- |
| `enabled` | 插件总开关 |
| `domain` | GoofToken 部署域名（派生 `https://www.<domain>` 与 `wss://mp.<domain>`） |
| `issuerUrl` / `relayUrl` | 本地开发时显式覆盖 OIDC 与中继地址 |
| `clientId` | OIDC 原生客户端 ID，默认 `dsh-remote` |
| `nodeName` | 设备显示名，默认主机名 |
| `notifyOnTurnEnd` / `notifyOnApproval` | 是否触发小程序订阅消息 |

凭据、E2EE 私钥与 TOFU 公钥钉死均存于 `$DSH_HOME/.credentials.yaml`，不使用 `.env`。

## 安全模型

- 长期身份密钥（Ed25519 + X25519）、签名预共享密钥与会话临时密钥全部在本地生成，私钥不出设备。
- 每次会话连接执行一次 4-DH X3DH 协商，之后每条消息推进对称 HKDF 棘轮；ChaCha20-Poly1305 的 AAD 绑定 `nodeId|sessionId|senderId|seq`，拒绝重放与乱序越界。
- 首次连接不做自动 TOFU：未登记客户端先进入待批准队列，主机核对 20 位安全码并运行 `/remote approve <安全码>` 后才发送 ack 与会话内容；批准后钉死对端身份公钥，公钥变更时立即阻断握手并告警。
- 双方可核对 20 位安全码（4×5 位数字）。
- 订阅消息只发送脱敏事件类型，不包含代码、路径或对话正文。

## 开发

```sh
pnpm install
pnpm --filter @gooftoken/remote-control run typecheck
pnpm --filter @gooftoken/remote-control run test:run
pnpm --filter @gooftoken/remote-control run build
pnpm --filter @gooftoken/remote-control run test:dist
pnpm --filter @gooftoken/remote-control run pack:release
```

协议细节见仓库 `docs/DSH-REMOTE-CONTROL.md`。

## 开源发布

本包不依赖任何私有 workspace 包，可整体复制到独立公开仓库发布：

1. 公开仓库根目录放置本包内容（或 `packages/remote-control` 子目录），添加 GitHub topic `dsh-plugin`，仓库需满 1 天。
2. `pnpm install && pnpm run build && pnpm run pack:release`，把 `release/remote-control.tgz` 上传到 GitHub Release（资产名不带版本号）。
3. 截图放在 `package.json` 同级并在 `screenshots.json` 声明；图标使用 `assets/icon-180.png`。
4. 参考 `scripts/awesome-entry.yml` 向 `awesome-dsh-plugin` 提交 `data/plugins/<owner>__<repo>.yml`（每 PR 最多 3 条，先改 YAML 不手改 README）。

## License

MIT
