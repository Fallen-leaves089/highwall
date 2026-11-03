# L5Wall

L5Wall 是 HighWall 仓库中的独立 TLS 会话层子项目，用 Python 3.10+ 标准库实现。它负责 TLS 终止、会话策略和 B+D-1 过渡期的有界 HTTP/1.1 桥接，不负责 HTTP 路由、WAF、DLP 或 H2/H3 解析。

当前版本：`0.2.1`（2026-11-03 发布）。覆盖等级：`C1`，**不完整**。它已经能终止 TLS、执行 SNI/ALPN 白名单、TLS 最低版本、mTLS 模式、SNI/Host 一致性校验和有界转发，并在连接抖动时重试瞬时监听错误、在停机时排空在途连接；但没有标准 JA3/JA4、0-RTT 策略、QUIC、H2/H3 检查或握手前 TCP 预算。不要把它写成完整 L5/L7 防护。

## 独立发布与部署

L5Wall 使用自己的版本号和发布流，不跟随 HighWall 的 `v*` 标签：

- 发布标签：`l5wall-v0.2.1`
- Python 包：`l5wall-0.2.1-py3-none-any.whl`、`l5wall-0.2.1.tar.gz` 和 `SHA256SUMS`
- 容器镜像：`ghcr.io/fallen-leaves089/l5wall:0.2.1`（`linux/amd64`、`linux/arm64`）
- 发布工作流：仅 `l5wall-v*` 标签或手动指定已有标签触发

镜像带 cosign keyless 签名、GitHub provenance 和 SBOM attestation。`0.2.1` 是 Alpha、C1、非生产就绪版本，完整边界见 [docs/RELEASE-NOTES.md](docs/RELEASE-NOTES.md)。

主机安装、systemd、容器和 Kubernetes 约束见 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)。特别注意：`serve` 只监听回环，容器不能直接用 bridge 网络加 `-p 18443:18443` 暴露；必须使用 host network 或共享网络命名空间。

## 边界

```text
客户端
  |  TLS / SNI / ALPN / 可选客户端证书
  v
L5Wall (TLS 握手守卫)
  |  已认证的 ssl.SSLSocket + L5 元数据
  |  HTTP/1.1 首头预检 + SNI/Host 一致性
  v
HighWall L7 数据面（回环或同主机私有链路）
```

- L5Wall 必须先声明“谁终止 TLS”。如果 HAProxy/Envoy 在前面终止 TLS，L5Wall 拿不到真实客户端的握手信息，不能把后面的流量当作 L5 覆盖。
- `serve` 只允许回环监听和回环上游；当前不监听公网，也没有管理面。
- 它不会被 HighWall 0.12.0 自动加载；`serve` 是 B+D-1 的独立进程过渡入口，B+D-4 集成仍是后续阶段。
- `serve` 只接受 `http/1.1` ALPN；H2/H3 不会被降级伪装成已检查。
- `serve` 当前不转发原始客户端 IP；HighWall 看到的来源是回环地址。**不要在这个桥接后面启用按 IP 封禁、来源 ACL 或依赖真实来源的限速**，否则会把所有客户端当成同一来源。真实客户端归属需要外层可信代理写 XFF/PROXY，或等待后续原生核心接入。
- 测试证书只用于回环集成测试，不能用于生产。

## 快速检查

```powershell
cd subprojects/l5wall
python test_certificates.py
python -m unittest discover -s tests -v
python -m l5wall check --config config.example.json
python -m l5wall inspect --config config.example.json
python -m l5wall serve --config config.example.json
```

## 配置

完整示例见 [config.example.json](config.example.json)。配置是严格 JSON：未知字段、重复键、缺失证书、非法 SNI/ALPN 或非法的 mTLS 组合都会拒绝启动检查。

| 字段 | 作用 | 默认/建议 |
|---|---|---|
| `cert_file` / `key_file` | 服务端证书链和私钥 | 必须存在且不能是符号链接；生产使用独立权限保护 |
| `min_version` | 最低 TLS 版本 | `TLSv1_2`；高安全场景可设 `TLSv1_3` |
| `allowed_alpn` | 允许的 ALPN 协议 | 默认只允许 `http/1.1`；未知 ALPN 拒绝，不回落 |
| `allowed_sni` | SNI 白名单 | 默认 `localhost`；支持 `*.example.test` 形式的单层或多层后缀匹配 |
| `allow_missing_sni` | 是否允许无 SNI | 默认 `false`；只有明确接受无 SNI 客户端时才开启 |
| `mtls_mode` | `off` / `optional` / `required` | 默认 `off`；开启时必须提供 `client_ca_file` |
| `handshake_timeout` | 单次握手超时 | 默认 5 秒；按网络条件调整，不能无限等待 |
| `listen_host` / `listen_port` | 本地 TLS 入口 | 默认 `127.0.0.1:18443`；预览版只允许回环 |
| `upstream_host` / `upstream_port` | 本地 HighWall H1 入口 | 默认 `127.0.0.1:18080`；预览版只允许回环 |
| `max_connections` | 同时处理的桥接连接数 | 默认 128；满额时拒绝新连接 |
| `connect_timeout` / `idle_timeout` | 上游连接和空闲超时 | 默认 5 秒 / 30 秒；不能无限等待 |
| `shutdown_timeout` | `SIGTERM`/`SIGINT` 后等待在途连接完成的时限 | 默认 8 秒；必须小于服务管理器的停止宽限，超时后强制关闭剩余连接 |
| `max_bytes_per_direction` | 单方向转发字节上限 | 默认 64 MiB；超限关闭连接 |
| `max_request_head_bytes` | 首个 H1 请求头上限 | 默认 32 KiB；超限在到达上游前拒绝 |
| `require_sni_host_match` | 是否要求 SNI 与 Host 一致 | 默认 `true`；关闭会降低 L5/L7 关联保证 |

客户端证书只输出 SHA-256 指纹，不保存证书原文、私钥或 Cookie/Authorization。

## 失败关闭

- 配置或证书不可读、格式非法、私钥不匹配：`check` 失败，不启动监听。
- TLS 握手失败、客户端不发送数据或超过握手超时：关闭连接并抛出 `L5HandshakeError`。
- ALPN 不在白名单、SNI 不在白名单、缺少必需 SNI、TLS 版本低于下限：关闭连接并抛出 `L5Denied`。
- mTLS `required` 但没有客户端证书：握手阶段拒绝。
- 未知 ALPN 不会回落到 HTTP/1.1。
- `serve` 模式下，缺少 Host、重复 Host、Host 与 SNI 不一致、裸 CR/LF、TE/CL 混用、Upgrade 和 H2 preface 会在上游连接前拒绝。
- 请求头、连接数、单方向字节或空闲时间超过配置上限：关闭连接，不继续转发。
- 监听器遇到 `EINTR`、连接中止、Windows socket reset 或文件描述符/缓冲区耗尽等瞬时错误时，记录告警并指数退避重试（50 ms 起，封顶 1 s），不会静默退出。
- 监听器遇到真正的不可恢复错误时显式失败，由进程管理器决定是否重启；不会把“监听器已失效但进程仍存活”当成正常状态。
- 收到 `SIGTERM` 后停止接受新连接，并在 `shutdown_timeout` 内等待在途连接完成；超过时限才强制关闭。

## 当前未覆盖

- JA3/JA4、H2/QUIC 指纹、TLS 扩展级异常检测；
- 0-RTT 重放、会话票据轮换、连接迁移和 QUIC；
- 握手前的 TCP 并发、字节和内存预算；
- H2/H3/WebSocket/gRPC 语义检查。
- serve 当前只用于同主机回环过渡，不解决多层代理的真实客户端 IP 传递；这是按 IP 策略和低误伤验收的硬前置条件。

这些问题不能通过“能建立 TLS 连接”推断为已解决。目标架构和后续阶段见 [`../../docs/GUARDRAIL-ARCHITECTURE.md`](../../docs/GUARDRAIL-ARCHITECTURE.md)。

## 测试

当前 42 项测试覆盖配置拒绝、SNI/ALPN/TLS 版本策略、mTLS 缺证书、通配符边界、真实回环 TLS 握手、正常 H1 转发、SNI/Host 不一致、缺少/重复 Host、非法 Host、TE/CL 混用、超大请求头、未知 ALPN、H2 preface、控制字符、转发字节上限、瞬时/致命 accept 错误分类、故障注入后的继续监听、快速连接风暴后的正常请求、优雅排空与排空超时、私钥不进入 inspect 输出，以及包版本/许可证与仓库根的一致性。测试证书由 `test_certificates.py` 在 `tests/fixtures/` 运行时生成，目录已被 Git 忽略；这些材料只允许回环测试使用，不能进入生产或发布包。测试生成器需要开发依赖 `cryptography`，L5Wall 运行时本身仍为零第三方依赖。发布前用 `scripts/check_dist.py` 检查 wheel/sdist 不含测试目录、证书或私钥。

安全边界见 [SECURITY.md](SECURITY.md) 和 [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)。
