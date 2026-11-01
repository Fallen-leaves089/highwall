# HighWall Native Core

Rust 原生数据面，采用 B+D-4 架构：在同一个模块化网关内完成 L5 TLS/QUIC 终止与 L7 H1/H2/H3、WebSocket、gRPC 检查。`subprojects/l5wall` 仍是独立子项目，用于 L5 单独部署和演进；两者共享策略目标，但不是相互替代关系。

当前版本为开发中的 `0.1.0-dev.0`。本地完整链路回归和 release 构建已完成；DSH 首轮独立验收为 0 Critical、0 High、3 Medium、8 Low、3 信息项。r5 定向复测为 0 Critical、0 High：8 个指定项中 7 项定向关闭（HWA-01/02/03/07/08/09/10）；HWA-11 随后在 r6 窄范围独立复测中关闭（400 + 270、失败回退、上游零命中、审计不泄漏）。HWA-04/05/06 未在 r5/r6 复测。完整残余风险和生产准入边界见 [`docs/DSH-R6-RESULTS-20261101.md`](../../docs/DSH-R6-RESULTS-20261101.md)、[`docs/DSH-R5-RESULTS-20261101.md`](../../docs/DSH-R5-RESULTS-20261101.md) 与 [`docs/DSH-REMEDIATION-20261101.md`](../../docs/DSH-REMEDIATION-20261101.md)。在完整验收和人工审批前，不应把它标记为生产已完成。

## 安全默认值

- 默认只监听回环地址；开启非回环监听必须显式设置 `listen.allow_non_loopback=true`。`quic.host` 可单独指定 QUIC 绑定地址，省略时继承 `listen.host`，非回环地址同样需要该显式开关。
- TLS 最低版本默认 TLS 1.3；QUIC 只允许 TLS 1.3，0-RTT 和连接迁移默认关闭。
- 可选设置 `quic.allowed_client_networks`，在 Retry 和握手前按真实 UDP 来源拒绝未授权客户端；为空表示不限制来源。
- ALPN 使用显式白名单；未知 ALPN 拒绝，不回落。
- H2/H3 的流、请求、头部、帧、重置、空闲连接和握手资源都有上限。
- 请求和响应正文的 WAF/DLP 检查覆盖 H1/H2/H3、压缩正文、请求 trailers 和响应 trailers；gRPC 消息有独立预算。
- H1 只接受单个合法 `Transfer-Encoding: chunked`，解块后重新生成长度 framing；重复或组合 TE、TE+CL 和请求 trailers 会被拒绝。单个 chunked 不会被伪装成“全部拒绝”。
- Agent 检测状态按来源和全局上限约束，不会因随机来源或 UA 轮换无限增长。
- 审计启用时默认失败关闭；启动检查会初始化审计写入路径。
- 自动封禁默认只作用于精确 IP，并带 TTL 和容量上限。

## 构建与验证

```powershell
Set-Location '<HighWall checkout>\subprojects\native-core'
$env:CARGO_HTTP_PROXY=''
$env:HTTP_PROXY=''
$env:HTTPS_PROXY=''
$env:ALL_PROXY=''
$env:GIT_CONFIG_GLOBAL='NUL'
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
```

当前 `cargo test --all-targets --locked` 为 143 项通过。

## 配置与启动

```powershell
Copy-Item -LiteralPath .\config.example.json -Destination .\highwall-native.json
.\target\release\highwall-native-core.exe --config .\highwall-native.json --check
.\target\release\highwall-native-core.exe --config .\highwall-native.json
```

示例配置默认不启用 TLS/QUIC，仅用于本地 H1 验证。生产入口应至少启用 TLS，并按需启用 QUIC。启用 gRPC 路由时必须设置 `routes[].grpc=true`；启用 WebSocket 时必须设置 `routes[].websocket=true` 并配置明确的 Origin 与子协议。

## L4Wall 与 PROXY v2

L4Wall 的 listener 设置 `send_proxy_v2=true` 后，会在每条上游连接前写入标准 PROXY v2 TCP header。原生核心应把 `listen.proxy_protocol.mode` 设为 `required`，并只把 `trusted_proxy_networks` 指向确切的 L4Wall 来源：

```json
{
  "listen": {
    "proxy_protocol": {
      "mode": "required",
      "trusted_proxy_networks": ["127.0.0.1/32"],
      "header_timeout_ms": 2000
    }
  }
}
```

不要把 `trusted_proxy_networks` 放宽到 `0.0.0.0/0`；未受信 peer、缺失头、非法版本和超时都会拒绝，且不会把上游连接建立到错误来源。Python HighWall 不解析 PROXY v2，因此只应在原生核心或其他明确兼容的上游前启用。

## mTLS 强制要求

mTLS 不是“只配 CA 就算完成”。当 `tls.mtls` 为 `optional` 或 `required` 时，必须同时配置：

- `tls.client_ca_file`：客户端证书链验证 CA。
- `tls.client_crl_file`：客户端证书吊销列表。

缺少任一项都会拒绝启动。CRL 必须由同一 CA 签发、未过期且签名有效；吊销证书会在握手阶段被拒绝。示例：

```json
{
  "tls": {
    "cert_file": "certs/server.pem",
    "key_file": "certs/server-key.pem",
    "crl_file": null,
    "require_private_key_permissions": true,
    "min_version": "tls13",
    "validate_certificate": true,
    "allowed_sni": ["gateway.example.internal"],
    "allow_missing_sni": false,
    "mtls": "required",
    "client_ca_file": "certs/client-ca.pem",
    "client_crl_file": "certs/client-ca.crl.pem",
    "alpn": ["h2", "http/1.1"],
    "require_sni_host_match": true
  }
}
```

## Windows 私钥 ACL

`require_private_key_permissions=true` 时，Windows 启动检查会读取 DACL，并拒绝继承权限、过宽权限、未知 ACE 类型以及非当前运行账户/SYSTEM/Administrators 的授权主体。开发目录默认继承权限通常不合格，必须收紧到运行账户：

```powershell
$key = (Resolve-Path -LiteralPath '.\certs\server-key.pem').Path
$sid = (whoami /user /fo csv /nh).Split(',')[-1].Trim().Trim('"')
icacls $key /inheritance:r /grant:r "*${sid}:(R)"
icacls $key /remove:g '*S-1-1-0' '*S-1-5-32-545'
```

若服务以专用账户运行，应把 `$sid` 换成该服务账户的 SID，而不是只按当前登录用户授权。不要通过关闭 `require_private_key_permissions` 绕过错误；`--check` 的输出应清楚指出被拒绝的主体或 ACE。

## 独立镜像

原生的独立镜像定义在仓库根目录 `Dockerfile.native`，使用多阶段 Rust 1.97.1 构建（MSRV 1.88），以 UID `10001` 非 root 运行。Python 的 `Dockerfile` 保持 Python-only，不包含原生核心或 vendored `h3`：

```bash
docker build --file Dockerfile.native --tag highwall-native-core:dev .
docker run --rm highwall-native-core:dev --version
```

当前环境没有运行 Docker daemon，镜像未本地构建验证。部署时只读挂载配置、证书和私钥，并把审计路径放在独立持久卷；私钥 UID 和权限必须满足 `require_private_key_permissions`。

## Windows 防火墙与二进制路径

Windows 自动生成的防火墙 Allow/Block 规则可能绑定二进制的绝对路径。本轮复验中，已验证的新二进制从 `target/release-verify/release` 启动时，UDP/QUIC 被一条自动 Block 规则丢弃，而规范化路径 `target/release` 只收到 TCP。部署时必须显式创建并验证 TCP 和 UDP 入站规则，不能因为同一份代码在另一个路径可运行就假设 QUIC 可达；发布替换二进制后也要重新验证 UDP。

## 当前限制

- 真实 TCP/UDP listener 已覆盖 TLS/QUIC、H1/H2/H3、PROXY v2、Retry、未知 ALPN、0-RTT、连接迁移、来源 ACL 和 QUIC 绑定地址；仍需补 QPACK 阻塞、长时间放大/流控饱和、慢速流量组合和更多浏览器/客户端互操作。
- 当前 H1/H2/H3 只声明 C3。真实 WebSocket 端到端、标准 JA3/JA4、流式背压饱和和部分 slow-flow 攻击仍未达到 C4 门槛。
- H3/UDP 直达原生 listener，不经过 L4Wall。HWA-08 的封禁可观测性已定向关闭，但被封禁来源仍可完成 TLS/QUIC 握手后才收到 HTTP 403，需由前置网络/L4 拒绝降低握手资源成本；H2/H3 仍未达到 C4。
- 发布前必须完成其余 DSH 残余项复核；HWA-11 的 r6 窄范围关闭不能替代完整生产准入，DSH 对生产发布仍建议 no push。公开源码与脱敏测试记录的推送已获单独授权。
