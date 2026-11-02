# HighWall 0.12.0 Alpha 预发布

[English](RELEASE-v0.12.0.en.md) | 简体中文

状态：GitHub pre-release（Alpha）。这是可供评审和验证的预发布，不是生产发布，不附带生产支持承诺。最新稳定版仍是 `0.11.0`，本次发布不会移动 `latest`。

## 本版本包含

- 精确客户端 IP + 请求形状的执法键；`/24`、`/64` 只用于关联，不自动扩大封禁。
- `highwall ops preview` 只读 Safe Ops 预演；R2/R3 默认拒绝，没有执行入口。
- `highwall capabilities --json` 描述 Python H1 基线的 C0-C4 等级；原生核心能力单独按 H1/H2/H3 声明。
- 独立 `subprojects/l5wall` 0.2.0：TLS 终止、SNI/ALPN/mTLS 策略、握手超时、回环 H1 桥接、SNI/Host 一致性、请求头/连接/字节上限。L5Wall 继续作为独立服务发布，不并入 Python wheel。
- 阶段 1 的 `l5wall serve` 只允许回环监听和回环上游，只接受 `http/1.1` ALPN；H2/H3 不会被伪装成已检查。
- 回环桥接不传递原始客户端 IP；不能在其后启用按 IP 封禁、来源 ACL 或依赖真实来源的限速。
- L4Wall 可选 `send_proxy_v2`，支持向上游发送标准 PROXY v2 TCP header；原生核心可要求 PROXY v2，并只信任显式配置的代理网段。
- Rust 原生 B+D-4 核心：TLS/QUIC、H1/H2/H3 严格解析、H1 WebSocket、H2/H3 gRPC、压缩/trailers、有界正文 WAF/DLP、精确 IP 封禁、mTLS/CRL、QUIC Retry、默认禁 0-RTT/迁移和 QUIC 客户端网络 ACL。
- TCP 和 UDP 是两条入口：H1/H2 可经 L4Wall 和 PROXY v2；H3 当前直达原生 QUIC listener，不经过 L4Wall。
- Python 镜像保持 Python-only；原生核心使用独立 `Dockerfile.native`，以非 root 运行，不把 Rust 依赖塞入 Python wheel 或镜像。

## 发布资产

GitHub Release 预期包含：

- `highwall-0.12.0-py3-none-any.whl` 与 `highwall-0.12.0.tar.gz`。
- Linux x86_64 原生二进制 `highwall-native-core-0.12.0-linux-x86_64`。
- Windows x86_64 原生二进制 `highwall-native-core-0.12.0-windows-x86_64.exe`。
- 原生核心示例配置 `highwall-native-config-0.12.0.example.json`。
- 覆盖上述资产的 `SHA256SUMS`。

发布工作流会为资产生成 GitHub build provenance attestation。容器工作流另外发布 Python-only 镜像 `ghcr.io/fallen-leaves089/highwall:0.12.0`（linux/amd64、linux/arm64），带 OCI provenance、SBOM 和 cosign 签名；它不是完整 B+D-4 镜像。`Dockerfile.native` 本轮未作为公开 GHCR 镜像发布，原生路径以 Release 中的独立二进制为准。

## 验证

- 根 Python：384 项测试通过；`coverage --branch` 总覆盖率 81%，高于项目 80% 门槛；原生真实串联默认跳过，显式开启后单独通过。
- L4Wall：71 项测试通过，包括 PROXY v2 编码和上游首包。
- L5Wall：36 项测试通过；含真实回环 TLS→HighWall 串联、未知 ALPN、SNI/Host 不一致、异常 framing、超大请求头、转发字节上限，以及跨平台许可证一致性检查。
- 原生核心：`cargo test --all-targets --locked` 144 项通过；`cargo fmt --all -- --check`、`cargo clippy --all-targets --locked -- -D warnings` 和锁定依赖的 release 构建通过。
- `ruff`、`mypy`（30 个根源文件）、`compileall`、解析器 fuzz（2000 轮、8000 次检查）、示例/严格配置检查和 `highwall diff` 通过。
- DSH 首轮独立验收：0 Critical、0 High、3 Medium、8 Low、3 信息项。r5 定向复测为 0 Critical、0 High：8 个指定项中 7 项定向关闭（HWA-01/02/03/07/08/09/10）；HWA-11 在 r6 窄范围独立复测中关闭。HWA-04/05/06 由维护者 r7 以仓库内可重复测试复核通过，见 [REGRESSION-R7-20261102.md](REGRESSION-R7-20261102.md)；r7 不是 DSH 独立验收，不能把这三个编号写成 DSH 已独立复测。
- 维护者 R7 定向结果：HWA-04 的三个重复伪头部拒绝均为 H3_MESSAGE_ERROR 270、上游零命中；HWA-05 的四个 HEAD 路由均为 200、正确 Content-Length、0 B 正文、每个上游命中 1；HWA-06 在 8192 B 为 200/上游命中 1，在 8193 B 为 413 `HW-NATIVE-PROTOCOL-001`/上游命中 0。
- 发布标签工作流会在 Python 3.10–3.14 上重复根测试，并在 Linux/Windows 原生 runner 上重复静态检查和测试。本地结果不能替代该远程结果；正式发布前以 Release/Container 工作流状态为准。

## 部署边界

- H1/H2/H3 仍只声明 C3，不声明 C4。C4 所需的完整流式背压饱和、QPACK 阻塞、真实 WebSocket 端到端和更完整的 slow-flow 覆盖仍未关闭。
- H3/UDP 绕过 L4Wall；应用层 QUIC ACL 不能替代主机防火墙或安全组。部署必须另设 UDP 来源限制、速率限制和入口 ACL。
- 被封禁来源仍可能先完成 TLS/QUIC 握手，再收到 HTTP 403。当前结论只证明应用层拒绝，不证明握手前零成本。
- 原生封禁是进程内状态，带 TTL 和容量上限；重启清空，单写者持久状态服务尚未接入。
- 运行中进程映像没有独立 attestation；DSH 的 `runtime_process_image_evidence=false` / `process_image_independent_attestation=false` 仍然成立。Release 资产 attestation 只证明构建产物来源，不证明某个运行进程就是该产物。
- Docker/HAProxy 真实边缘、`standard` 容器拓扑、原生镜像公开分发、真实多节点状态服务和审计写失败拓扑未在本轮验收。Docker 是可选打包/部署层，不阻塞原生可执行文件路径。
- 本轮未修改主机防火墙规则；Windows 自动规则可能绑定二进制绝对路径，部署必须显式创建并复验 TCP/UDP Allow 规则。
- 本项目尚未完成独立第三方安全审计；DSH 结果是本轮安全验证输入，不等于外部审计证书或生产准入。

## 发布门槛与回滚

不得把本版本标记为生产发布，也不得把 C3 写成 C4 或完整防护。DSH 对生产发布的 no-push 建议保持不变；本次只发布 Alpha 预发布和脱敏、可复现的验证记录。

回滚策略：生产环境继续使用并固定 `0.11.0` 及对应摘要；不要依赖 `latest`。若需要评估 0.12.0，使用 Release 中的固定版本资产并先核对 `SHA256SUMS` 与 build provenance，再在隔离环境完成入口、真实来源、H3/UDP 网络层封堵和回滚演练。
