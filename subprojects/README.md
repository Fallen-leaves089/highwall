# HighWall 子项目

本目录存放与 HighWall 同仓库、但可以独立安装和测试的子系统。当前包含 L4Wall `0.1.0`、L5Wall `0.2.0` 和原生核心 `0.1.0-dev.0`。

## L4Wall

`l4wall/` 是失败关闭的 TCP L4 防护网关，负责连接级准入、限速、超时、行为评分、封禁和审计。它不替代 HighWall 的 L7 WAF/DLP，也不替代主机防火墙、云清洗或应用自身的认证授权。

### 两种运行形态

- `lite`：L4Wall 直接串联在客户端和 HighWall 之间，适合单机、小规模和 Windows。当前 Python 实现就是这一形态。
- `standard`：HAProxy/Envoy 承担数据面，L4Wall 作为控制面，负责评分、封禁和审计。标准部署骨架见 `../deploy/standard/`，控制面进程仍在后续里程碑中。

可选共享封禁读取端已经可用：从私网 Redis 增量导入版本化 JSON，本地封禁优先，超时/坏数据/容量不足都不会清空本地封禁或拖垮数据面。自动发布端和 Controller 尚未实现。

### 独立验证

```powershell
cd subprojects/l4wall
python -m unittest discover -s tests -q
python scripts/demo.py
python -m l4wall check --config config.example.json
```

### 边界

- 只处理显式配置的 TCP listener。
- 不抗 SYN flood、带宽型 DDoS，也不处理 UDP/QUIC；H3 必须由原生核心或独立 QUIC 网关承接。
- 不做 TLS 终止、SNI、JA3/JA4。
- 详细边界见 `../docs/STACK.md` 和 `l4wall/docs/THREAT_MODEL.md`。

## Native Core

`native-core/` 是 Rust 实现的 B+D-4 原生数据面，在同一模块化网关内完成 TLS/QUIC 终止和 H1/H2/H3 严格解析，并包含 H1 WebSocket、H2/H3 gRPC、有界正文 WAF/DLP、精确 IP 封禁、mTLS/CRL、QUIC Retry 和客户端网络 ACL。TCP 可由 L4Wall 发送 PROXY v2 后接入；UDP/H3 当前直达原生 QUIC listener，不经过 L4Wall。

当前 H1/H2/H3 按 C3 声明，C4 未声明。本地 Rust 测试、release 构建和 L4Wall→原生串联已通过；DSH 首轮验收发现 3 Medium、8 Low，r5 定向复测为 0 Critical、0 High、8 项中 7 项关闭，HWA-11 随后在 r6 窄范围关闭，HWA-04/05/06 未在 r5/r6 复测。完整残余风险仍未关闭，不能把定向复测当作生产准入，DSH 对生产发布仍建议 no push；公开源码与脱敏记录已获单独授权。详见 [`native-core/README.md`](native-core/README.md)、[`../docs/DSH-R6-RESULTS-20261101.md`](../docs/DSH-R6-RESULTS-20261101.md)、[`../docs/DSH-R5-RESULTS-20261101.md`](../docs/DSH-R5-RESULTS-20261101.md) 和 [`../docs/DSH-REMEDIATION-20261101.md`](../docs/DSH-REMEDIATION-20261101.md)。

## L5Wall

`l5wall/` 是独立的 TLS 会话层子项目，维护自己的版本、测试、威胁模型和检查工具。当前 `0.2.0` 覆盖等级为 `C1`：实现 TLS 1.2/1.3 终止、最低版本、SNI/ALPN 白名单、mTLS 模式、握手超时、最小化 L5 元数据和回环 H1 桥接；不负责 HTTP 路由、WAF 或 DLP。

它尚未被 Python HighWall 0.12.0 自动加载，也没有完整 JA3/JA4、0-RTT、QUIC、H2/H3 或握手前 TCP 预算，不能按完整 L5 防护宣传。部署上可用于 B+D-1 独立串联；B+D-4 原生核心内另有一套共享策略目标的 L5/L7 实现，并不声称直接链接或复用 l5wall 代码。两者继续独立演进，源码和接口边界保持分离。详见 [`l5wall/README.md`](l5wall/README.md) 和 [`../docs/GUARDRAIL-ARCHITECTURE.md`](../docs/GUARDRAIL-ARCHITECTURE.md)。
