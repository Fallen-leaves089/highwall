# DSH AI Agent 安全验收计划

- 状态：首轮独立验收及 r2/r3/r5/r6 定向复测已完成；完整残余项、人工复核和发布审批尚未完成
- 执行者：DSH（DeepSeek Harness）独立 AI Agent
- 被测对象：HighWall、L4Wall、L5Wall 和目标 B+D-4 原生核心
- 性质：隔离靶场中的授权对抗测试，不是第三方审计或安全认证
- 关联设计：[GUARDRAIL-ARCHITECTURE.md](GUARDRAIL-ARCHITECTURE.md)；r6 结果：[DSH-R6-RESULTS-20261101.md](DSH-R6-RESULTS-20261101.md)

> 公开脱敏说明：实验室私网地址已替换为 RFC 5737 文档地址；本机绝对路径、进程号、一次性浏览器配置和未被 Git 跟踪的原始证据已移除或改为逻辑路径。原始证据不随仓库发布。

## 1. 目标

在目标版本完成后，由 DSH 作为独立测试方验证：

- 已知入口是否默认拒绝、失败关闭、资源有界。
- L4/L5/L7 分层是否能阻止直连、协议绕过和策略降级。
- H1/H2/H3/WebSocket/gRPC 的实际覆盖等级是否与声明一致。
- AI Agent 风险评分是否既能发现自动化滥用，又不扩大误伤。
- DLP、WAF、限速、慢速通道、封禁和审计是否能协同工作。
- Safe Ops 是否拒绝破坏性、不可逆和被提示注入污染的操作。

DSH 只负责测试和报告，不直接修改代码、配置、状态或生产数据。发现问题后由维护者做最小复现、根因修复和回归测试。

## 2. 授权与隔离

允许：

- 只访问 `$DSH_ROOT/etc/drill-target` 中唯一允许的 `IPv4:port`。
- 使用 DSH Kali WSL2 沙箱、临时目录、一次性测试证书和模拟上游。
- 对被测实例发起有限、可回滚、可复现的协议和负载测试。
- 读取为验收准备的源码快照、配置快照、构建哈希和审计证据。

禁止：

- 扫描公网、局域网、WSL 网关其他端口或任何未列入 drill-target 的目标。
- 连接真实业务、数据库、生产证书、真实密钥或生产审计目录。
- 修改宿主机防火墙、路由、DNS、服务、用户或 WSL 网络配置。
- 对真实数据执行删除、格式化、覆盖、清空备份或不可逆操作。
- 通过改 gid、挂载或其他方式绕过 DSH 自身网络隔离。
- 把 Cookie、Authorization、私钥、API Key 或完整请求体写入报告。

测试完成后切回 DSH `locked` 模式。需要公网时只允许测试依赖下载，不把公网作为被测入口。

## 3. 靶场拓扑

```text
DSH Kali 沙箱
    | TCP/UDP 只允许 192.0.2.10:18443（文档地址）
    v
TCP: L4Wall -> PROXY v2 -> 原生 TLS/H1/H2 -> 一次性上游
UDP: 原生 QUIC/H3 -> 一次性上游

一次性模拟上游（记录请求次数和到达内容）
```

- 测试入口只暴露一个地址和端口；HighWall、上游和管理面不映射到公网。
- 管理面保持回环或专用管理网，不能被 DSH 从数据面访问。
- 每次测试前重建 `offenders.json`、审计文件和临时上游，避免旧封禁污染结果。
- TCP 测试经过 L4Wall，真实来源由 PROXY v2 传给原生核心；UDP/H3 直达原生 QUIC listener，不经过 L4Wall。
- 原生 QUIC ACL 和 L4Wall 来源 ACL 都只放行本轮 Kali 地址的 `/32`，不得扩成网段。
- 证据同时来自客户端响应、原生审计、L4Wall 审计、上游到达计数和进程指标。

## 4. 测试阶段

### 4.1 预检

- 记录源码提交、构建产物哈希、配置哈希和测试时间。
- 执行 `highwall check`、`highwall diff`、启动前 ACL 和监听地址检查。
- 确认目标只有一个入口，管理面、上游和宿主机端口不可达。
- 清空旧审计、旧封禁和旧指标；确认测试证书和密钥是一次性的。
- 记录 DSH 当前网络模式、drill-target 和停止开关。

### 4.2 黑盒基线

- 正常浏览器、curl、Go、Node、Python 客户端通过。
- 错误 Host、未知 ALPN、SNI/Host 不一致、缺失 SNI、非法方法、绝对 URI。
- 重复 `Content-Length`、TE/CL、重复/组合 TE、Trailer、Expect、Upgrade、h2c；单个合法 `chunked` 在原生 H1 路径应被接受并按显式长度重框定。
- 路径穿越、编码分隔符、Unicode 归一化、NUL、超长请求行、超大 Header/body。
- WAF、DLP、Origin/CSRF、限速、蜜罐、慢速通道、熔断和审计关联。

### 4.3 L5 与协议

- TLS 1.0/1.1 拒绝、TLS 1.2/1.3 配置边界、证书过期、SAN 不匹配、链不完整。
- mTLS off/optional/required、EKU、吊销失败和客户端证书身份映射。
- 0-RTT 默认拒绝或严格限制；会话票据轮换和重放。
- ClientHello 大小、分片、重复 extension、握手并发和超时。
- JA3/JA4、H2 SETTINGS、QUIC 传输参数只作为信号，验证不能单独触发大范围封禁。

### 4.4 H2/H3/WebSocket/gRPC

- H2 Rapid Reset、CONTINUATION flood、HPACK bomb、流控、GOAWAY、非法 SETTINGS。
- H3 Initial 放大、Retry、0-RTT、连接迁移、QPACK 阻塞、控制流和未知帧。
- WebSocket 显式路由、Origin、子协议、帧大小、空闲超时和消息检查边界。
- gRPC trailers、压缩、deadline、状态码和二进制正文是否绕过 DLP/WAF。
- 如果当前版本只达到 C1/C2，必须如实记录，不能按 C3/C4 判通过。

### 4.5 AI Agent 与低误伤

- 浏览器形状、Agent 形状、UA 伪装、Header 顺序、TLS 指纹轮换。
- 规律节奏、突发、路径枚举、ID 枚举、404/403 比例和查询变体。
- 低频慢速、多 IP、共享 NAT、企业出口、搜索引擎和监控流量。
- 自动封禁是否只作用于精确 IP；`/24`、`/64`、ASN 是否只用于分析。
- 达到阈值后的 observe、throttle、suspect、confirmed、campaign 处置是否可解释、可撤销。
- Agent 流量是否被误判为正常，正常流量是否被误伤；两者都必须记录。

### 4.6 DLP/WAF 回归

上一轮 DSH 已发现以下问题，必须在新版本复测：

- DLP 对空格变形、Base64、编码、高熵串和未知格式的漏报。
- 响应被 DLP 拦截时使用 502，和真实上游故障难以区分。
- `agent_mode=block` 在低强度只读流量下没有观察到独立拦截。
- 限速和自动封禁未做充分加压验证。
- 旧版本只覆盖 H1，H2/H3/TLS 未验证。

新增回归应覆盖 H2/H3 的响应头、trailers、压缩和流式正文，不得只测 H1。

### 4.7 Safe Ops

在一次性目录和假资产上验证：

- 删除、格式化、覆盖、改防火墙、删证书、删备份、改 ACL、清日志。
- 路径穿越、符号链接、Windows junction/reparse point、UNC、通配符和变量注入。
- 伪造批准、重放 nonce、过期批准、Agent 自批准、提示注入和跨环境复用。
- 备份不可读、回滚失败、审计中断、审批服务不可用。
- R3 操作必须默认拒绝；break-glass 必须离线、短时、双人、可审计。

### 4.8 故障与降级

- 审计不可写、策略服务不可用、风险状态服务不可用、Redis 不可用。
- 证书即将过期、轮换失败、上游持续 5xx、限速槽位耗尽。
- 关闭评分、关闭 WAF、放宽 ALPN、扩大来源范围等配置变更是否被安全降级检查拦截。
- 任何故障都不能变成“全部放行”或“清空封禁”。

## 5. 证据与报告

DSH 报告至少包含：

- 被测版本、构建/配置/源码哈希、时间窗口和授权范围。
- 每条请求的方法、目标、状态、规则 ID、关键响应头和时间；敏感值脱敏。
- 上游是否收到请求、HighWall 审计是否记录、封禁范围是否正确。
- 可复现的最小脚本或原始字节；不能只给结论。
- 严重级别、影响、前置条件、复现步骤、证据路径和建议修复。
- 未覆盖项、环境限制和可能的误报。

严重级别：

- Critical：可直接绕过全部入口、访问上游/管理面或造成不可接受的持久影响。
- High：可绕过核心策略、扩大封禁范围、导致失败开放或泄露敏感数据。
- Medium：特定配置或特定协议下可绕过、误伤明显或证据不足但风险真实。
- Low：信息性、加固建议、文档不一致或低影响绕过。

## 6. 发布门禁

- 未授权请求不能到达上游或管理面。
- 未知 ALPN 不回落；SNI/Host 不一致拒绝；0-RTT 默认拒绝。
- H2/H3 攻击流量不能耗尽流、内存、槽位或审计队列。
- 自动封禁不扩大到未配置的前缀或 ASN。
- 审计中没有 Cookie、Authorization、原始查询串、请求体原文或密钥。
- 策略、审计、审批不可用时失败关闭。
- Safe Ops 的 R3 操作默认拒绝，break-glass 不可被普通 Agent 自助使用。
- Critical/High 问题全部关闭或有明确人工接受记录；Medium 必须修复或记录残余风险。
- DSH 的关键发现必须由维护者独立复现；不能只凭 AI 报告改代码。

## 7. DSH 任务提示模板

完成后将以下模板交给 DSH，填入本轮实际值：

```text
你是独立安全测试 Agent。本轮只测试授权靶场：
目标：<drill-target IPv4:port>
版本/提交：<commit>
配置哈希：<sha256>
授权时间窗：<start> 至 <end>
禁止：公网/局域网其他地址、生产系统、真实数据、宿主机修改、DoS、持久化、密钥读取。
只使用 drill-target；每次请求记录方法、路径、状态、规则 ID、请求 ID 和时间。
先做黑盒基线和低误伤观察，再做协议、L5、Agent、DLP/WAF、Safe Ops 和故障测试。
遇到 429/封禁先等待并记录，不通过换 IP 或改 gid 绕过。
发现 Critical/High 立即停止该测试面，保留最小证据并报告。
输出到报告目录，包含可复现脚本、证据、未覆盖项和严重级别；不要修改被测代码或配置。
```

## 8. 当前状态

- DSH 安装在隔离目录 `$DSH_ROOT`，使用 Kali WSL2 独立用户和命名空间。
- 历史轮次（r3 及以前）曾启动 supervisor、proxy 和 web；网络模式为 `internet`，仅在应用层额外放行固定目标，随后停止服务并切回 `locked`。该模式的公网出口未被网络层完全封锁，属于历史残余风险。
- r5 期间 DSH 同样使用 `internet` 模式，仅在任务层和应用层限制唯一目标 `192.0.2.10:18443` 的 TCP+UDP；这不是网络层完全封锁，报告已记录为残余风险。目标事实以 r5 报告和 manifest 为准。
- r5 drill-target 为 `192.0.2.10:18443`；Kali 来源为 `198.51.100.132/32`，L4Wall 和原生 QUIC ACL 都只精确放行该地址。TCP 链路为 `DSH -> L4Wall -> PROXY v2 -> 原生 TLS/H1/H2 -> upstream`；UDP 链路为 `DSH -> 原生 QUIC/H3 -> upstream`。H3 不经过 L4Wall 是已知的非对称风险。公开版地址为 RFC 5737 文档地址。
- r3 历史靶场使用 `agent.mode=confirmed`、`max_user_agent_changes=4` 等更激进的参数，不能外推到 r5 或默认配置。r5 使用 `agent.mode=suspect`、`max_user_agent_changes=12`、请求方向 `5/60s`、响应方向 `10/300s` 阈值，并开启高熵 DLP；结论必须绑定该配置解释。
- 首轮源码快照、二进制、配置和证书公钥哈希记录在 `dsh-evidence/highwall-acceptance-20261101/manifest.json`；源码清单 191 个文件校验通过。该快照的 `binaries_reverified=false`，不能把首轮二进制哈希当成最终发布物证明。
- 首轮独立验收已完成，报告为 `dsh-evidence/highwall-acceptance-20261101/report.md`，结论为 0 Critical、0 High、3 Medium、8 Low、3 信息项。该文件保留第一轮失败记录，不能被第二轮的修复结论覆盖。维护者已逐项修复或记录残余风险。
- 修复后的第二轮定向严格复测为 23/23 通过，证据位于 `dsh-evidence/highwall-remediation-20261101/evidence/remediation-r2/`；逐项说明见 [DSH-REMEDIATION-20261101.md](DSH-REMEDIATION-20261101.md)。
- 第二轮独立复核报告为 `dsh-evidence/highwall-remediation-20261101/report-r2.md`，确认 23/23 是脚本口径、完整验收仍不通过，并明确“不推送”。
- r5 独立定向复测为 0 Critical、0 High；报告和汇总位于 `dsh-evidence/highwall-remediation-r5-20261101/report-r5.md`、`summary-r5.json`，逐项摘要见 [DSH-R5-RESULTS-20261101.md](DSH-R5-RESULTS-20261101.md)。8 个指定项中 7 项定向关闭，HWA-11 为低危 open；HWA-04/05/06 未复测。二进制副本哈希经 DSH 两次只读重算匹配，但 `runtime_process_image_evidence=false`。
- r5 定向复测只覆盖指定断言，不是完整复验；在该轮 HWA-11 仍为低危 open。H3/UDP 绕过 L4Wall、封禁后握手成本、H2/H3 C3、完整 WebSocket/gRPC、QPACK/流控饱和、管理面/Safe Ops/审计故障和真实容器拓扑仍未关闭或未验收。
- r6 仅复测 HWA-11：报告和汇总位于 `dsh-evidence/highwall-remediation-r6-20261101/report-r6.md`、`summary-r6.json`，SHA256 分别为 `7D69900B1B02FB13F56C70FB4E5450D20881C68264B7CCC37439811625E2B102`、`8272FA65146DD7D27F611EE5E337F0B80CE9B003A4A52E0CBA5D82F033159517`。A–E 全部通过：400 + 270、失败回退、上游零命中、审计规则正确且原始主机值泄漏 0；状态为 **closed (narrow HWA-11 retest only)**。`process_image_independent_attestation=false`，不能据此证明运行进程映像或完成生产准入。
- 发布评审前仍必须由维护者阅读原始证据、抽查复现，并对 AI 结论做人工复核；不能只凭 23/23、r5 的 7/8 或 r6 的 HWA-11 `closed` 进入生产发布。DSH 对生产发布的 no push 建议保持不变；本次仅获得公开源码和脱敏测试记录的推送授权。
- r5/r6 收尾已停止一次性上游、原生核心、L4Wall、DSH supervisor/web 和专用 headless 浏览器，DSH 切回 `locked`；18443/18444/18445 TCP、18443 UDP、3080 和 9333 均已复核为无监听。原始运行目录、构建缓存、测试证书/私钥和一次性浏览器配置未纳入公开仓库，也没有上传或压缩；具体清理记录保留在未发布的维护者快照中。

## 9. 非目标

- 不替代第三方安全审计、渗透测试合同或合规认证。
- 不做带宽型 DDoS、运营商链路攻击、主机提权或物理攻击。
- 不验证上游业务认证、授权、数据库约束和业务逻辑漏洞。
- 不把 AI Agent 的通过当作绝对安全证明。
