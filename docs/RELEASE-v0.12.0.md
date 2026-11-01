# HighWall 0.12.0.dev0 开发快照（未发布）

[English](RELEASE-v0.12.0.en.md) | 简体中文

状态：未发布开发快照，不是生产发布，不附带生产支持承诺。

## 本快照包含

- 精确客户端 IP + 请求形状的执法键；`/24`、`/64` 只用于关联，不自动扩大封禁。
- `highwall ops preview` 只读 Safe Ops 预演；R2/R3 默认拒绝，没有执行入口。
- `highwall capabilities --json` 描述 Python H1 基线的 C0-C4 等级；原生核心能力单独按 H1/H2/H3 声明。
- 独立 `subprojects/l5wall` 0.2.0：TLS 终止、SNI/ALPN/mTLS 策略、握手超时、回环 H1 桥接、SNI/Host 一致性、请求头/连接/字节上限。
- 阶段 1 的 `l5wall serve` 只允许回环监听和回环上游，只接受 `http/1.1` ALPN；H2/H3 不会被伪装成已检查。
- 回环桥接不传递原始客户端 IP；不能在其后启用按 IP 封禁、来源 ACL 或依赖真实来源的限速。
- L4Wall 可选 `send_proxy_v2`，支持向上游发送标准 PROXY v2 TCP header；原生核心可要求 PROXY v2，并只信任显式配置的代理网段。
- Rust 原生 B+D-4 核心：TLS/QUIC、H1/H2/H3 严格解析、H1 WebSocket、H2/H3 gRPC、压缩/trailers、有界正文 WAF/DLP、精确 IP 封禁、mTLS/CRL、QUIC Retry、默认禁 0-RTT/迁移和 QUIC 客户端网络 ACL。
- TCP 和 UDP 是两条入口：H1/H2 可经 L4Wall 和 PROXY v2；H3 当前直达原生 QUIC listener，不经过 L4Wall。
- Python 镜像保持 Python-only；原生核心使用独立 `Dockerfile.native`，以非 root 运行，不把 Rust 依赖塞入 Python wheel 或镜像。

## 验证

- 根 Python 测试：全量回归通过；原生真实串联默认跳过，显式开启后单独通过；分支覆盖率 81%。
- L4Wall：71 项测试通过，包括 PROXY v2 编码和上游首包。
- L5Wall：34 项测试通过；含真实回环 TLS→HighWall 串联、未知 ALPN、SNI/Host 不一致、异常 framing、超大请求头和转发字节上限。
- 原生核心：`cargo test --all-targets --locked` 143 项通过；`cargo fmt`、`cargo clippy --locked -D warnings` 和锁定依赖的 release 构建通过。
- DSH 首轮独立验收：0 Critical、0 High、3 Medium、8 Low、3 信息项。r5 定向复测为 0 Critical、0 High：8 个指定项中 7 项定向关闭（HWA-01/02/03/07/08/09/10）；HWA-11 由 r6 窄范围复测关闭，HWA-04/05/06 未在 r5/r6 复测。r5/r6 报告见 [DSH-R5-RESULTS-20261101.md](DSH-R5-RESULTS-20261101.md) 与 [DSH-R6-RESULTS-20261101.md](DSH-R6-RESULTS-20261101.md)。
- 显式开启的真实 L4Wall→原生核心串联：1 项通过，验证 PROXY v2 恢复真实来源并到达上游。
- `ruff`、`mypy`、`compileall`、解析器 fuzz、示例配置检查、严格配置检查和 `highwall diff` 通过。
- CI 增加锁定依赖的 `native-core` job 和 `Dockerfile.native` 镜像构建检查；本地已通过配置校验，远程执行结果以发布 PR 的 CI 状态为准。

## 仍未覆盖

- r5/r6 的定向关闭不等于完整验收：HWA-11 只关闭窄范围；H3/UDP 绕过 L4Wall；被封禁来源仍能完成 TLS/QUIC 握手后才收到 HTTP 403；H1/H2/H3 仍只有 C3；没有完整的 WebSocket/gRPC、QPACK/流控饱和、管理面/Safe Ops/审计写失败和真实容器拓扑证据。不能把定向结果当作生产准入。
- 原生 H1/H2/H3 只声明 C3，不声明 C4；标准 JA3/JA4、真实 WebSocket 端到端、QPACK 阻塞、流式背压饱和和部分 slow-flow 攻击仍未完整覆盖。
- 原生封禁当前是进程内状态，带 TTL 和容量上限；重启清空，单写者持久状态服务尚未接入。
- H3 不经过 L4Wall；应用层 QUIC ACL 不能替代主机防火墙或安全组，部署必须补齐网络层来源限制。
- Docker/HAProxy 真实边缘、`standard` 容器拓扑、原生镜像构建和真实多节点状态服务未验收；Docker 是可选打包/部署层，当前 Docker daemon 不可用，但不阻塞原生可执行文件路径。
- 本轮未修改防火墙规则；验证表明 Windows 自动规则可能绑定二进制绝对路径，部署必须显式创建并复验 TCP/UDP Allow。

## 发布门槛

不得把本快照标记为 `v0.12.0` 生产发布，也不得把 C3 写成 C4 或完整防护。r5 可以支持人工发布评审，HWA-11 已在 r6 窄范围定向关闭；进入正式生产发布评审前仍需完成其余残余项范围确认、构建/进程来源绑定、真实容器拓扑和部署网络层封锁验证。DSH 对生产发布明确建议 no push；公开源码与脱敏测试记录已获单独授权。
