# DSH r5 独立定向复测结果（2026-11-01）

- 状态：r5 定向复测历史记录；可以进入人工发布评审，但不是发布许可；记录生成时未推送，脱敏后随公开仓库发布
- 被测对象：HighWall `0.12.0.dev0` 工作树、L4Wall、Rust 原生 B+D-4 数据面
- 基线提交：`114e8f11af508c550f8a64f4ec85ed826fd964bb`（`main`，工作树包含未提交修改）
- 独立测试方：DSH（DeepSeek Harness）AI Agent
- 独立报告：`dsh-evidence/highwall-remediation-r5-20261101/report-r5.md`
- 机器汇总：`dsh-evidence/highwall-remediation-r5-20261101/summary-r5.json`
- 证据目录：`dsh-evidence/highwall-remediation-r5-20261101/evidence-r5/`

> 本文是授权隔离靶场中的定向复测摘要，不是第三方审计、安全认证或完整生产准入。r5 只复测 8 个指定测试项，`HWA-04`、`HWA-05`、`HWA-06` 本轮未复测。旧 r3 报告和证据保持原样，不被本轮覆盖。

> 公开脱敏说明：实验室私网地址已替换为 RFC 5737 文档地址；本机绝对路径、进程号、一次性浏览器配置和未被 Git 跟踪的原始证据已移除或改为逻辑路径。原始证据不随仓库发布。

## 1. 结论

- 严重级别：**0 Critical、0 High**；本轮没有发现可直接绕过核心策略、访问管理面或导致失败开放的新问题。
- 8 个指定测试项中：**7 项定向关闭**，`HWA-11` 仍为 **open（低危候选残余风险）**，0 项 partial。
- 定向关闭：`HWA-01`、`HWA-02`、`HWA-03`、`HWA-07`、`HWA-08`、`HWA-09`、`HWA-10`。
- 范围外未复测：`HWA-04`、`HWA-05`、`HWA-06`；沿用 r2/r3 的历史定向结论，不能据此主张全量复验。
- DSH 判定：`production_ready=false`、`manual_release_review_input=true`、`push_recommendation=no push`。

> **后续状态（2026-11-01，DSH r6）**：HWA-11 已完成独立窄范围复测，状态为 **closed (narrow HWA-11 retest only)**；线路 400 + 270、失败回退、上游零命中和审计不泄漏均通过。运行进程映像仍无独立取证，完整生产准入未完成，DSH 对生产发布仍建议 no push。用户已另行授权公开源码与脱敏测试记录；该授权不改变生产发布门禁。本文件正文保留 r5 当时“无 HTTP 4xx”的原始结论，不能被改写成 r5 已关闭；后续结果见 [DSH-R6-RESULTS-20261101.md](DSH-R6-RESULTS-20261101.md)。
- 结论：**足以支持进入人工发布评审，但不足以作为生产准入依据。** 公开源码推送授权不构成生产发布许可。

## 2. 范围与证据

- 唯一目标：`192.0.2.10:18443` 的 TCP 和 UDP；SNI/Host 为 `gateway.test`；来源为 `198.51.100.132`（公开版使用 RFC 5737 文档地址）。
- TCP：`DSH -> L4Wall -> PROXY v2 -> 原生 TLS/H1/H2 -> upstream`。
- UDP：`DSH -> 原生 QUIC/H3 -> upstream`，不经过 L4Wall。
- 源码快照：332/332 个文件哈希校验通过；快照清单 SHA256 为 `3A365A247810B53A3EF7C7F38EE72D5BD874E25C2809BD86BD938DC84806DB5D`。
- 运行配置：native `108CEDBB77F239F12A8799A233F86BBB0296DA4762BA75CB64B77434BB71950F`；L4Wall `2F4F8B571D89DBBE601159EC23A170FEF2536CDD56EC66FDD8196AB6FE8808DB`。
- 二进制产物：7,806,464 B，SHA256 `85779353214CCF3C6E5DBF8837F9A22E699BB00779BE04A8B17E539375254A29`；DSH 用 `sha256sum` 和 Python hashlib 两次只读重算，均与 manifest 匹配。
- 证据规模：83 条请求记录、166 个原始请求/响应/帧文件、15 个 Python 复现脚本；另有 `entropy-r5.json`、预检记录和阶段日志。
- 运行配置边界：`agent.mode=suspect`、`max_user_agent_changes=12`、`bans.violation_threshold=5/60s`、`bans.response_violation_threshold=10/300s`、`detect_high_entropy=true`；路由的 `websocket` 和 `grpc` 均关闭。
- DSH 网络模式为 `internet`，只在任务和应用层限制唯一目标；公网出口未被网络层完全封锁，这是本轮残余风险。收尾后应恢复 `locked`。

## 3. 逐项结果

| ID | 原级别 | r5 状态 | 关键证据 | 残余 |
|---|---|---|---|---|
| HWA-01 WAF 规避 | Medium | **closed（定向）** | 12 个跨 H1/H2/H3 变体全部 403：`WAF-002/003/007`；含 70 KiB、multipart、gzip、四层 Base64；未到 upstream | 编码矩阵非穷举；无运行审计副本 |
| HWA-02 Agent 阈值/误伤 | Medium | **closed（定向）** | 12 个不同 UA 均 200；第 13 个 429 `AGENT-001`，带 `Retry-After: 60` 和 `highwall-automation-budget`；61.1 s 后恢复 200，未累计封禁 | 结论绑定本轮 `suspect/12` 配置，不能外推 |
| HWA-03 DLP 覆盖 | Medium | **closed（定向，含熵口径复核）** | H1/H2/H3 高熵均 451 `DLP-004`；JWT/Google/GitHub → `DLP-003`，AWS → `DLP-001`，PEM → `DLP-002`；评审反馈后的双口径 ≥5.0 随机串三协议全部命中 | 非上下文熵阈值为 5.0；阈值边界附近可能放行；未知格式未覆盖 |
| HWA-07 H1 framing | Low | **closed（定向）** | 合法单 chunked 200、正文回显并重框定为 `Content-Length`；重复 TE、TE+CL、trailer、非法 chunk size、`gzip,chunked` 均 400；未到 upstream | 其他 framing 组合和 H2/H3 framing 未覆盖 |
| HWA-08 封禁不可观测 | Low | **closed（定向）** | 5 次 `WAF-006` 触发封禁；新建 H1/H2/H3 均在 TLS/QUIC 握手后收到 403 `BAN-001` + `Retry-After: 299` + `X-RateLimit-Policy: highwall-source-ban`；304.7 s 后恢复 200 | 被封禁来源仍可完成握手；无管理面查询/撤销 |
| HWA-09 响应 DLP 不计违规 | Low | **closed（定向）** | 10 次 `/secret` 451 `DLP-002`；#1–#9 无封禁头，#10 带封禁头；随后新连接 403 `BAN-001`；恢复 200；请求方向预算未受影响 | 300 s 内仍允许最多 9 次响应探测；产品风险决策 |
| HWA-10 H2 非法 SETTINGS | Low | **closed（定向）** | `INITIAL_WINDOW_SIZE=0x80000000` → GOAWAY `error_code=3`（`FLOW_CONTROL_ERROR`），连接关闭，无 HTTP 请求到 upstream | 其他 SETTINGS 值未逐项覆盖 |
| HWA-11 H3 authority/Host | Low | **open（候选残余风险）** | 缺失 `:authority` 和 Host 不一致均只得到 `StreamReset 270` + `StopSending 270`，没有 HTTP 4xx；未到 upstream，未观察到绕过 | H3 客户端难以区分协议拒绝与网络故障 |

## 4. 关键证据说明

### 4.1 HWA-08/HWA-09 封禁路径

- HWA-08：5 次 `GET /.git/HEAD` 均为 403 `WAF-006`；第 5 次达到 `5/60s` 阈值。随后 H1/H2/H3 新连接都能建立 TLS/QUIC，但请求返回 403 `BAN-001`，带 `Retry-After: 299` 和封禁策略头。r3 的“TLS 前 EOF、与网络故障不可区分”没有复现。
- HWA-09：响应方向违规使用独立的 `10/300s` 预算。第 10 次 451 带封禁头，新连接请求 `/ok` 得到 403 `BAN-001`；第 6–9 次仍为 451，证明没有共用请求方向的 `5/60s` 阈值。两次封禁均按 `Retry-After` 等待后恢复 200。
- 封禁总数严格为 2 次（HWA-08、HWA-09 各一次）；没有换 IP、改 gid 或绕过封禁。

### 4.2 HWA-03 熵口径

DSH 复核确认源码 `high_entropy_token()` 使用的是**区分大小写的原始字节 Shannon 熵**。旧 phase3 的 H2 载荷熵为 4.9841，低于 5.0，所以返回 200 是阈值边界，不是绕过；同批 H1/H3 分别为 5.0466/5.0096，命中 451 与源码一致。

评审反馈后的复测载荷经过脚本内验证：原始字节 Shannon 5.9375、case-folded Shannon 5.1014、min-entropy 5.0000、`log2(distinct)` 5.9542。H1/H2/H3 各一次均返回 451 `DLP-004`，前后基线 `/ok` 均 200，3 次拒绝未达到封禁阈值。

### 4.3 HWA-10/HWA-11

- HWA-10 的 GOAWAY 错误码来自 vendored `h2 0.4.20` 的设置校验和错误映射，不是 HighWall 自行伪造；线路级原始帧已保存。
- HWA-11 仍然 fail-closed，但没有 HTTP 4xx 或统一错误码；DSH 没有观察到上游到达或策略绕过。该问题为低危客户端可观测性/互通性残余，不应写成已关闭。

### 4.4 二进制与进程边界

DSH 只独立确认“交付产物副本 == manifest 声明的二进制”。报告中的 `runtime_process_image_evidence=false` 表示 DSH 没有取得宿主 PID、运行中映像哈希或服务定义，因此不能据此证明被测进程就是该副本，也没有证明可复现构建或源码到产物的完整绑定。

维护者另在宿主机只读核对了运行中的 native 进程映像，文件哈希同样为 `85779353214CCF3C6E5DBF8837F9A22E699BB00779BE04A8B17E539375254A29`；四个独立 release 产物的哈希也一致。该补充属于**维护者证据**，不能替代独立进程取证；正式发布仍应补齐签名的构建证明、SBOM、进程/服务绑定和远程 runner 验证。

## 5. 残余风险与未验证项

- **HWA-11（低危 open）**：H3 缺失 authority/Host 不一致只返回 reset 270，没有 HTTP 4xx。
- **H3/UDP 绕过 L4Wall**：H3 直达原生 QUIC listener；必须在主机防火墙或安全组单独限制 UDP 来源。
- **封禁后的握手成本**：HWA-08 的可观测性已定向关闭，但被封禁来源仍能完成 TLS/QUIC 握手后才收到 HTTP 403；需要前置网络/L4 拒绝来降低握手资源成本。
- **覆盖等级**：H1/H2/H3 仍只声明 C3；标准 JA3/JA4、QPACK/HPACK 阻塞、流控和背压饱和、0-RTT、连接迁移、真实 WebSocket/gRPC 端到端未达到 C4。
- **审计与证据**：没有 native/upstream/L4Wall 运行审计副本，拒绝请求的“未到上游”是客户端可观测证据加源码路径，不是逐条审计对账。
- **未覆盖面**：管理面/Safe Ops/审计写失败、流控与资源饱和、慢速耗尽、容器/HAProxy 编排和真实多节点状态均未验收。
- **构建链**：DSH 未独立证明运行进程和可复现构建；CI 的 native job 和镜像构建仍取决于远程 runner 与可选 Docker 交付路径。

## 6. 发布与推送建议

本轮可以进入人工发布评审，评审输入必须同时包含：HWA-11 的书面风险接受、C3-only 声明、H3/UDP 网络层限制、封禁握手成本、未覆盖项和构建/进程绑定计划。

**不建议直接进行生产发布。** DSH 对生产发布保持 `no push`；在人工评审完成、残余风险书面接受、发布物和构建来源绑定、完整验收范围确认前，不应把 r5 定向结果当作生产发布依据。用户已授权公开源码和脱敏测试记录，这两件事必须分开处理。

## 7. 证据冻结

- r5 报告 SHA256：`8A0B61574006D5D3D61679F20A94E00DEEA1B125FA8E8F15AE87EE0F5F0DDE45`
- r5 汇总 SHA256：`9806A7B05411DEBBAF281916EA3AA876081DA14329B6426EC6B06D1EF04387CB`
- r3 报告仍保留在 `dsh-evidence/highwall-remediation-20261101/report-r3.md`，未被本轮覆盖。
