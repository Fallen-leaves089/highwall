# DSH 独立验收修复记录（2026-11-01）

- 状态：首轮、r2、r3、r5 和 r6 定向复核完成；完整安全验收未完成；记录生成时未推送，脱敏后随公开仓库发布
- 被测对象：HighWall `0.12.0.dev0` 开发快照、L4Wall、L5Wall 与原生 B+D-4 数据面
- 基线提交：`114e8f11af508c550f8a64f4ec85ed826fd964bb`（`main`，工作树包含本轮未提交修改）
- 独立测试方：DSH（DeepSeek Harness）AI Agent
- 关联材料：[DSH 安全验收计划](DSH-SECURITY-ACCEPTANCE.md)、[r6 定向复测结果](DSH-R6-RESULTS-20261101.md)、[r5 定向复测结果](DSH-R5-RESULTS-20261101.md)、[r3 定向复核结果](DSH-R3-RESULTS-20261101.md)、[护栏架构](GUARDRAIL-ARCHITECTURE.md)、[威胁模型](THREAT_MODEL.md)

> 本文记录的是授权隔离靶场中的内部验收与修复，不是第三方审计、安全认证或生产准入证明。`23/23` 仅指第二轮定向脚本检查，r5 的 `7/8` 也仅指定向关闭数量，r6 的 `closed` 仅限 HWA-11 线路/审计窄范围复测，均不能替代完整验收。第三轮 r3 的历史结果见 [DSH-R3-RESULTS-20261101.md](DSH-R3-RESULTS-20261101.md)，r5 历史结果见 [DSH-R5-RESULTS-20261101.md](DSH-R5-RESULTS-20261101.md)，最新 r6 结果见 [DSH-R6-RESULTS-20261101.md](DSH-R6-RESULTS-20261101.md)。

> 公开脱敏说明：实验室私网地址已替换为 RFC 5737 文档地址；本机绝对路径、进程号、一次性浏览器配置和未被 Git 跟踪的原始证据已移除或改为逻辑路径。原始证据不随仓库发布。

## 1. 结论摘要

- 首轮 DSH 独立验收：**0 Critical、0 High、3 Medium、8 Low、3 信息项**。
- 修复后第二轮定向严格复测：`passed=23`、`failed=0`、`total=23`；对应 34 个实际网络请求，`agent-429-backpressure` 是包含 12 个请求的聚合项。
- 第二轮 r2 定向关闭：HWA-04、HWA-06；r2 部分关闭：HWA-01、HWA-02、HWA-03、HWA-05、HWA-07；r2 仍未关闭：HWA-08、HWA-09；r2 未验证：HWA-10、HWA-11。
- 第三轮 r3 定向结果：2 项定向关闭、4 项部分关闭、4 项仍开放、1 项未验证。
- r3 定向关闭：HWA-05、HWA-06；部分关闭：HWA-01、HWA-02、HWA-03、HWA-07；仍开放：HWA-08、HWA-09、HWA-10、HWA-11；HWA-04 本轮未复测。
- r3 已补充运行审计对账：被 WAF、协议、429 和封禁拒绝的请求未到达 upstream；HWA-11 的客户端 reset 在服务端审计中对应内部 400，且未到达 upstream。
- r5 独立定向结果：**0 Critical、0 High**；8 个指定项中 7 项定向关闭（HWA-01、HWA-02、HWA-03、HWA-07、HWA-08、HWA-09、HWA-10），HWA-11 仍为低危 open 候选残余；HWA-04、HWA-05、HWA-06 本轮未复测。
- r6 独立窄范围结果：HWA-11 **closed（narrow HWA-11 retest only）**；A–E 全部通过，8 个 HTTP 请求加 1 个无 HTTP 的 TCP 连通探针，新增 Critical/High/Medium/Low 均为 0，畸形请求上游命中 0、原始主机值泄漏 0。
- r5 已确认封禁可观测性和响应 DLP 独立预算：H1/H2/H3 封禁后均返回 403 `HW-NATIVE-BAN-001` 和 `Retry-After`，响应 DLP 使用独立 `10/300s` 预算；详见 [DSH-R5-RESULTS-20261101.md](DSH-R5-RESULTS-20261101.md)。
- 结论：**r5/r6 可以支持人工发布评审，但不足以作为完整生产准入；DSH 对生产发布建议 no push。** 公开源码与脱敏测试记录已获单独授权，不等于生产发布、标签、镜像或二进制 release 许可。

严重级别严格沿用首轮 `findings.json`，不在本文重新定级。

## 2. 证据来源与口径

### 2.1 首轮验收

- 报告：`dsh-evidence/highwall-acceptance-20261101/report.md`
- 机器可读发现：`dsh-evidence/highwall-acceptance-20261101/findings.json`
- 首轮源码、二进制和配置清单：`dsh-evidence/highwall-acceptance-20261101/manifest.json`
- 首轮 `manifest.json` 记录 `binaries_reverified=false`，不能把首轮二进制哈希当成最终发布物证明。

### 2.2 第二轮定向复测

- DSH 最终复核报告：`dsh-evidence/highwall-remediation-20261101/report-r2.md`
- 汇总：`dsh-evidence/highwall-remediation-20261101/evidence/remediation-r2/retest-r2-summary.json`
- 请求记录：`dsh-evidence/highwall-remediation-20261101/evidence/remediation-r2/retest-r2.jsonl`
- 原始请求/响应：`dsh-evidence/highwall-remediation-20261101/evidence/remediation-r2/raw/`
- 运行审计副本：`dsh-evidence/highwall-remediation-20261101/evidence/runtime-20261101-r3/`
- 只读源码证据：`dsh-evidence/highwall-remediation-20261101/evidence/current-source-20261101/`

原始首轮 `report.md` 仍保留失败记录，不能覆盖或改写成修复后报告。第二轮以 `report-r2.md`、`retest-r2-summary.json`、JSONL、`raw/` 和运行审计副本为准。

### 2.3 复测限制

- `23/23` 是脚本判定口径，不是 23 个独立请求；实际网络请求为 34 个。
- 客户端响应与运行审计副本相互对账，但不是独立抓包；审计副本由被测方提供。
- H3 Google key、H2 Google key、H1 单字段 `chunked, chunked` 和事后 `/ok` 是补充探针，只有客户端证据，不在运行审计快照内。
- 没有连接生产系统、真实业务、真实证书或真实密钥；未读取凭据。

### 2.4 r5 定向复测

- 独立报告：`dsh-evidence/highwall-remediation-r5-20261101/report-r5.md`，SHA256 `8A0B61574006D5D3D61679F20A94E00DEEA1B125FA8E8F15AE87EE0F5F0DDE45`。
- 机器汇总：`dsh-evidence/highwall-remediation-r5-20261101/summary-r5.json`，SHA256 `9806A7B05411DEBBAF281916EA3AA876081DA14329B6426EC6B06D1EF04387CB`。
- 请求与原始证据：`evidence-r5/`，83 条请求记录、166 个原始请求/响应/帧文件、15 个 Python 复现脚本；`entropy-r5.json` 保存 HWA-03 熵口径底稿。
- 源码快照：332/332 个文件校验通过，清单哈希 `3A365A247810B53A3EF7C7F38EE72D5BD874E25C2809BD86BD938DC84806DB5D`；native/L4Wall 配置哈希分别为 `108CEDBB77F239F12A8799A233F86BBB0296DA4762BA75CB64B77434BB71950F` 和 `2F4F8B571D89DBBE601159EC23A170FEF2536CDD56EC66FDD8196AB6FE8808DB`。
- 二进制副本：7,806,464 B，SHA256 `85779353214CCF3C6E5DBF8837F9A22E699BB00779BE04A8B17E539375254A29`；DSH 两次只读重算匹配 manifest。DSH 的 `runtime_process_image_evidence=false`，因此该结论只证明产物副本匹配，不独立证明运行进程映像或构建来源。
- 维护者补充证据：运行中的 native 进程映像哈希与上述产物一致；四个独立 release 产物哈希也一致。这是维护者证据，不是独立取证。
- r3 报告、r3 证据和 r2 结果均保留，没有被 r5 覆盖。

### 2.5 r6 定向复测

- 独立报告：`dsh-evidence/highwall-remediation-r6-20261101/report-r6.md`，SHA256 `7D69900B1B02FB13F56C70FB4E5450D20881C68264B7CCC37439811625E2B102`。
- 机器汇总：`dsh-evidence/highwall-remediation-r6-20261101/summary-r6.json`，SHA256 `8272FA65146DD7D27F611EE5E337F0B80CE9B003A4A52E0CBA5D82F033159517`。
- 证据目录：`evidence-r6/`，38 个文件、433,281 B；包含预检、A–E 用例、原始 H1/H2/H3 轨迹、审计/上游对账、时间线和可复现脚本。
- 二进制副本：7,814,656 B，SHA256 `07E213C92D395616FBF9F8DB190EA2938670E0AC9C74D6EEA088AAD98D776A89`；DSH 用三种方法独立重算并匹配 manifest。
- 配置和源码：native 配置 `5DC379871C407E50211927191268D9C1E0DA029DDB8A91F428CE1F6D489C0A24`，L4Wall 配置 `6605329586BCB1B190EDA7E713B4B1C8289B0C3193C80009107AB4B1BAEC6BF4`；`source-clean/` 87/87 个文件校验通过，清单哈希 `AFA177F2C3C8BAE4FB8E1CBADB1F649E3C288BB21C4D7FD04D87C8636A9D692D`。
- DSH 无法从 Kali 查询 Windows PID 或哈希运行进程映像；`process_image_independent_attestation=false`。线路/审计通过不能替代进程映像、可复现构建和发布物绑定证明。
- r2/r3/r5 报告、证据和历史结论均保留，没有被 r6 覆盖。

## 3. HWA-01 至 HWA-11 逐项状态

下表保留第二轮 r2 的历史状态，不再作为当前结论。r3 的历史定向状态和运行审计对账见 [DSH-R3-RESULTS-20261101.md](DSH-R3-RESULTS-20261101.md)；r5 状态见下文 3.1 和 [DSH-R5-RESULTS-20261101.md](DSH-R5-RESULTS-20261101.md)，最新 r6 窄范围结果见 3.2 和 [DSH-R6-RESULTS-20261101.md](DSH-R6-RESULTS-20261101.md)。

| ID | 原级别 | 状态 | 已确认的修复或证据 | 仍未完成的部分 |
|---|---|---|---|---|
| HWA-01 WAF 四类载荷规避 | Medium | **部分关闭** | H1 上 query 百分号编码 XSS、70 KiB 正文、二进制正文、双层 Base64 四类原变体均被 403；四层 Base64 进入 `HW-NATIVE-WAF-007` fail-closed。被拒请求未到达上游。 | 只复测 H1；压缩、multipart、header-borne、其他编码及 H2/H3 变体未完整覆盖。 |
| HWA-02 Agent 阈值与封禁误伤 | Medium | **部分关闭** | 429 返回 `Retry-After: 60` 与 `X-RateLimit-Policy: highwall-automation-budget`；429-only burst 不累计封禁证据；最后 429 后 61.424 秒恢复 200，未触发封禁。 | 定向运行仍使用 `agent.max_user_agent_changes=4`，5 个不同 UA 仍可触发 429；误伤根因未消除。示例配置的 `observe`/较宽阈值未做等价低误伤验收。 |
| HWA-03 DLP 覆盖缺口 | Medium | **部分关闭** | JWT 在 H1/H2/H3 均返回 451 `HW-NATIVE-DLP-003`；Google 风格 key 在 H1 及补充 H2/H3 探针均返回 451 `HW-NATIVE-DLP-003`；请求方向拒绝未到达上游。 | `policy.dlp.detect_high_entropy=false` 仍保持，高熵检测未启用、未测试；未知格式和其他云厂商密钥未覆盖。 |
| HWA-04 H3 重复伪头 | Low | **已关闭（定向）** | H3 重复 `:path` 客户端无 HTTP 响应，收到 `StreamReset`，错误码 270（`0x10E`，`H3_MESSAGE_ERROR`）；native 审计为 `HW-NATIVE-H3-001` 且 `bytes_out=0`；上游无该请求。vendored h3 对重复伪头显式拒绝。 | 只黑盒复测重复 `:path`；`:method`、`:authority` 等其他重复伪头未逐项黑盒复测，QPACK/流控边界未验收。 |
| HWA-05 HEAD 到有正文路由返回 502 | Low | **部分关闭** | `HEAD /large` 返回 200、`Content-Length: 2097152`、0 B 正文；不再读取并丢弃上游正文。 | 原 finding 中的 `HEAD /ok`、`HEAD /status/200` 未逐条复测；其他路由和上游异常场景未覆盖。 |
| HWA-06 单行头上限未生效 | Low | **已关闭（定向）** | 单行 `X-Large` 10 KiB 返回 413 `HW-NATIVE-PROTOCOL-001`；源码使用 `max_header_line_bytes` 作为行读取上限。 | 8192/8193 精确边界未逐字节测试；H2/H3 header-list 上限语义不在本项结论内。 |
| HWA-07 H1 chunked/trailer/组合 TE | Low | **部分关闭** | 两个 `Transfer-Encoding` 头返回 400 `HW-NATIVE-PROTOCOL-001`；带 trailer 的 chunked 返回 400 `HW-NATIVE-PROTOCOL-002`；补充单字段 `chunked, chunked` 返回 400 `PROTOCOL-001`。 | 合法单 chunked 的接受与重框定未复测；README/SECURITY 文档一致性未完成全量核对；其他 framing 组合未覆盖。 |
| HWA-08 封禁不可观测 | Low | **仍未关闭** | 本轮没有触发封禁；429 可观测性不等于封禁路径可观测。源码仍在 TLS 前检查并直接丢弃被封禁连接。 | 无 TLS 后 429/403/Retry-After、TLS alert、管理面查询/撤销或统一封禁原因码的黑盒证据；封禁与网络故障仍不可区分。 |
| HWA-09 响应 DLP 不计违规 | Low | **仍未关闭** | 行为被再次确认：4 次请求方向拒绝加 1 次响应 DLP 451 后，0.426 秒后的普通请求仍为 200；响应方向不调用请求路径的违规计数。 | 这是设计保留/待风险接受状态，不是已修复。是否计入软计数、速率限制或审计指标尚无产品决策。 |
| HWA-10 H2 非法 SETTINGS 错误码 | Low | **未验证** | 本轮只有 H2 普通请求，没有 SETTINGS/帧级用例。 | 需补 SETTINGS `INITIAL_WINDOW_SIZE` 非法值等黑盒复测；不能从 23/23 推断已修复或仍存在。 |
| HWA-11 H3 缺失 authority/Host 不一致 | Low | **closed（r6 窄范围）** | DSH r6 在运行服务上复测：A 缺失 authority/Host、B/C authority 与 Host 不一致均返回 HTTP 400 空正文和 `STOP_SENDING` 270，失败发送回退为 `RESET_STREAM` 270；畸形请求上游命中 0，审计 `HW-NATIVE-H3-AUTHORITY-001/002` 正确，原始主机值泄漏 0。 | 只覆盖 HWA-11 线路/审计窄范围；运行进程映像无独立取证，管理面、跨版本客户端兼容性和其他 H3 错误路径仍未验收。 |

### 3.1 r5 定向状态（保留历史，附 r6 后续）

| ID | r5 状态 | 结论摘要 |
|---|---|---|
| HWA-01 WAF 规避 | **closed（定向）** | H1/H2/H3 共 12 个跨协议变体全部拦截；不含上游到达。 |
| HWA-02 Agent 阈值/误伤 | **closed（定向）** | 12 UA 均 200，第 13 UA 为 429 + 预算头，61.1 秒后恢复，未封禁。 |
| HWA-03 DLP 覆盖 | **closed（定向，含熵口径复核）** | 高熵、JWT、AWS、Google、GitHub、PEM 均按规则拦截；补充双口径 ≥5.0 载荷在 H1/H2/H3 全部命中。 |
| HWA-07 H1 framing | **closed（定向）** | 合法 chunked 接受并重框定；重复 TE、TE+CL、trailer、非法 chunk size 和 `gzip,chunked` 均拒绝。 |
| HWA-08 封禁不可观测 | **closed（定向）** | 封禁后 H1/H2/H3 均返回 403 `BAN-001` + `Retry-After` + 策略头，TTL 后恢复。 |
| HWA-09 响应 DLP 不计违规 | **closed（定向）** | 第 10 次响应 DLP 451 触发独立 `10/300s` 预算，随后 403 `BAN-001`，恢复验证通过。 |
| HWA-10 H2 非法 SETTINGS | **closed（定向）** | GOAWAY `FLOW_CONTROL_ERROR=3`，连接关闭，无 HTTP 请求。 |
| HWA-11 H3 authority/Host | **open（r5）→ closed（r6 窄范围）** | r5 时仅得到 reset/stop sending 270，没有 HTTP 4xx；r6 在运行服务上确认 400 + 270、失败回退、上游零命中和审计不泄漏。 |

`HWA-04`、`HWA-05`、`HWA-06` 不在 r5 任务书范围内，本轮未复测；沿用历史定向状态，但不能据此主张全量复验。r5 统计为 **0 Critical、0 High、7/8 定向关闭、1 项低危 open**。

### 3.2 HWA-11 修复与 r6 独立复测

- vendored `h3 0.0.8` 仅在 `MissingAuthority` 和 `ContradictedAuthority` 两类错误上发送空正文 `400 Bad Request`，发送和 finish 受 1 秒上限约束；成功后发送 stop sending 270，失败则回退 reset 270 + stop sending 270。
- native-core 使用结构化原因前缀分类，不从 `Display` 文本做子串匹配，避免恶意头值伪造规则或重置预算。审计规则为 `HW-NATIVE-H3-AUTHORITY-001`（缺失）和 `HW-NATIVE-H3-AUTHORITY-002`（不一致），detail 只记录 `response_result=sent|failed`、`protocol_error=H3_MESSAGE_ERROR(0x10E)`、`upstream_reached=false`，不记录原始 Host/authority。
- 原始 QUIC/H3 回归覆盖：线路级 400、stop sending 270、上游零命中、发送失败回退、审计 JSONL 与原始主机值不泄漏。
- 本地验证：native-core 75 单元 + 1 配置 + 15 实时监听 + 34 协议 + 18 安全回归全部通过；vendored `h3` 在启用其第三方后端测试特性后 229 项通过；native-core `clippy -D warnings` 通过。
- DSH r6 独立复测：A 缺失 `:authority`/Host、B/C 不一致均得到 HTTP 400 空正文、`STOP_SENDING` 270、无响应侧 `RESET_STREAM`、上游零命中；D 正常 H3 基线为 200 `ok` 且上游 +1；E 强制发送失败只观察到 `STOP_SENDING` + `RESET_STREAM` 270、无 HTTP 响应，审计 `response_result=failed`。
- 审计规则计数为 `AUTHORITY-001` ×2、`AUTHORITY-002` ×2；畸形请求上游命中总数 0，原始主机值泄漏 0；没有出现 `403 BAN-001` 或 `429`。结论为 **closed，仅限 HWA-11 窄范围**，不是生产准入。
- 该状态只代表本地实现与本地验证完成；仍需 DSH r6 独立复测运行中的构建产物、线路级响应和审计副本后，才能讨论关闭。

## 4. 关键证据说明

### 4.1 H3 重复 `:path`（HWA-04）

- 请求包含两个 `:path`：`/ok` 与 `/status/500`。
- 客户端 `connected=true`、`send_error=null`，但没有 `HeadersReceived`，响应为空，`StreamReset` 的错误码为 270（`0x10E`）。
- native 审计记录 `HW-NATIVE-H3-001`、`bytes_out=0`，detail 明确 `duplicate pseudo-header: :path`。
- `upstream.jsonl` 请求 ID 集合不包含该请求；前后相邻 H3 请求均存在，排除单条日志丢失。

### 4.2 H1 严格性（HWA-05、HWA-06、HWA-07）

- `HEAD /large`：200、`Content-Length: 2097152`、0 B 正文、耗时 6 ms。
- 单行 10 KiB 请求头：413 `HW-NATIVE-PROTOCOL-001`。
- 重复 `Transfer-Encoding` 头：400 `HW-NATIVE-PROTOCOL-001`。
- chunked trailer：400 `HW-NATIVE-PROTOCOL-002`。
- 补充单字段 `chunked, chunked`：400 `HW-NATIVE-PROTOCOL-001`。

这些证据来自 H1 路径，不能自动外推到 H2/H3 的全部 framing 行为。

### 4.3 WAF、DLP 与 429

- H1 WAF 四类原变体分别命中 `HW-NATIVE-WAF-003`、`HW-NATIVE-WAF-002`、`HW-NATIVE-WAF-002`、`HW-NATIVE-WAF-002`；四层 Base64 命中 `HW-NATIVE-WAF-007`。
- WAF-007 是解码深度/预算耗尽的 fail-closed 规则，不是 SQLi 明文规则匹配。
- JWT 在 H1/H2/H3 均命中 DLP-003；Google 风格 key 在 H1 和补充 H2/H3 探针中命中 DLP-003。
- 429 聚合项前五次状态为 `[200,200,200,200,429]`；bucket 6/6 为 429；7 个 429 均带精确 `Retry-After: 60` 与策略头；61.424 秒后恢复 200。
- H3 `/secret` 的响应方向 DLP 451 按设计拦截响应，但该 451 不进入请求方向违规计数，见 HWA-09。

### 4.4 审计对账

- `retest-r2.jsonl` 共 37 行：1 条 start、34 个请求、1 条聚合项、1 条 end。
- `raw/` 共 68 个文件，即 34 对请求/响应。
- native 审计 35 个 request_id：1 个为本轮开始前的 H3 `/ok`，其余 34 个对应当轮请求。
- upstream 在本轮窗口内 14 条，全部为允许请求；被 WAF/DLP/协议/429 拒绝的请求未出现在 upstream。
- L4Wall 审计为本轮 TCP 连接的 29 对 allowed/closed 事件；UDP/H3 不经过 L4Wall。

## 5. 残余风险与未验证项

以下内容不能因 r5 的 `7/8` 定向关闭而自动关闭：

- **H3/UDP 绕过 L4Wall**：TCP 的 H1/H2 经 L4Wall，UDP 的 QUIC/H3 直达原生 listener。L4Wall 的 ACL、并发上限、威胁评分和封禁不覆盖 UDP。网络层必须单独限制 UDP 来源；应用层 QUIC ACL 不能替代主机防火墙或安全组。
- **H2/H3 仍只声明 C3**：标准 JA3/JA4、QPACK 动态表/阻塞、完整流控与背压饱和、0-RTT 重放、连接迁移、TLS 握手速率边界等未达到 C4 门槛。
- **封禁后的握手成本**：HWA-08 的可观测性已定向关闭，但被封禁来源仍能完成 TLS/QUIC 握手后才收到 HTTP 403；需要前置网络/L4 拒绝降低握手资源成本。
- **响应 DLP 探测窗口**：HWA-09 的独立预算已定向关闭，但 300 秒内仍允许最多 9 次响应方向探测尝试；是否进一步收紧是产品风险决策。
- **高熵 DLP 的阈值边界**：`detect_high_entropy=true` 已生效，且补充载荷在 H1/H2/H3 全部命中；但非上下文熵阈值恰为 5.0，低于阈值的随机串按设计放行，未知格式仍未覆盖。
- **WebSocket/gRPC 端到端未验收**：运行配置的路由为 `websocket:false`、`grpc:false`；原验收只覆盖了拒绝路径。
- **管理面、Safe Ops、审计故障未验收**：R2/R3 默认拒绝、break-glass、审批/nonce/回滚、审计写失败和队列满均没有完整黑盒证据。
- **流控/资源饱和未验收**：slow loris、窗口耗尽、慢读、HPACK/QPACK bomb、H2/H3 并发饱和和长时间放大未完整测试。
- **容器拓扑未验收**：没有真实 Docker/HAProxy 编排验证。
- **构建/进程来源仍未完成独立证明**：r5 release 产物 SHA256 为 `85779353214CCF3C6E5DBF8837F9A22E699BB00779BE04A8B17E539375254A29`，四次独立构建产物一致，维护者核对运行进程路径也匹配；但 DSH 的 `runtime_process_image_evidence=false`，因此仍缺签名的构建证明、SBOM、进程/服务绑定和远程 runner 证据。
- **HWA-11 窄范围关闭不等于全量关闭**：r6 只覆盖缺失/矛盾 authority 的线路与审计断言；运行进程映像仍无独立取证，管理面查询、跨版本客户端兼容性和其他 H3 错误路径未验收。HWA-10 已在 r5 定向关闭。

## 6. 本轮本地验证

维护者本地验证记录：

- 根 Python：全量回归通过；原生真实串联默认跳过，显式开启后单独通过；分支覆盖率 81%。
- L4Wall：71 项通过；Ruff、mypy、`l4wall check` 通过。
- L5Wall：34 项通过；Ruff、mypy、`l5wall check` 通过。
- 原生核心：`cargo fmt --all -- --check`、`cargo clippy --all-targets --locked -- -D warnings`、`cargo test --all-targets --locked` 全部通过，测试 143 项；release 构建到独立目录成功。
- 可复现性：四个独立 release 产物均为 7,806,464 B，SHA256 均为 `85779353214CCF3C6E5DBF8837F9A22E699BB00779BE04A8B17E539375254A29`；运行中 native 进程映像文件哈希也一致。该证据由维护者采集，不等同于独立进程取证或签名构建证明。
- HWA-11 后续 release：`subprojects/native-core/target/release/highwall-native-core.exe`，7,814,656 B，SHA256 `07E213C92D395616FBF9F8DB190EA2938670E0AC9C74D6EEA088AAD98D776A89`；DSH r6 已独立重算交付副本哈希并验证运行线路/审计，但运行进程映像仍无独立取证。
- r5 独立复测：0 Critical、0 High；83 条请求、166 个原始文件；HWA-08/HWA-09 各触发一次封禁并恢复；HWA-03 补充熵口径复测在 H1/H2/H3 全部命中；HWA-11 当时仍为低危 open。
- HWA-11 r6 独立窄范围复测：原始 QUIC/H3 测试确认 400 + 270、失败回退、上游零命中和审计不泄漏原始主机值；DSH 判定 `closed`，但 `production_ready=false`、`no push`。
- 真实 L4Wall→原生串联：显式开启后 1 项通过。
- 解析器 fuzz、示例/严格配置校验和 `highwall diff`：通过。
- 原生测试计数通过 `cargo test --all-targets --locked -- --list` 复核为 143；CI 工作流 YAML 可解析，job 为 `test`、`native-core`、`native-image`。
- `Dockerfile.native` 的静态检查通过：构建输入存在、使用 `rust:1.97.1-bookworm`、`--locked` release 构建、UID `10001` 非 root、暴露 18443 TCP/UDP；但本机 Docker daemon 不可用，镜像未在本机构建验证，CI 的 `native-image` job 也尚未在远程 runner 实际执行。Docker 是可选打包层，不阻塞原生路径。

测试通过只证明已执行路径，不证明未执行路径安全。

## 7. 工具链与部署边界

- 原生核心 `rust-version=1.88`（MSRV）；本地工具链和构建镜像固定 `rust:1.97.1-bookworm`，不代表所有 Rust 版本组合都受支持。
- Python `Dockerfile` 仍是 Python-only，不包含原生核心或 vendored `h3`，不能称为完整 B+D-4 镜像。
- `Dockerfile.native` 是独立原生镜像定义，使用多阶段构建并以 UID `10001` 非 root 运行；它不会自动启动 L4Wall。`EXPOSE 18443/tcp 18443/udp` 只是镜像元数据，实际监听端口以挂载的 `native.json` 为准。
- `Dockerfile.native` 不内置配置文件、证书或私钥，部署必须只读挂载；私钥 UID 和权限必须满足 `tls.require_private_key_permissions`。
- Windows 自动防火墙规则可能绑定二进制绝对路径。部署必须显式创建并复验 TCP 和 UDP 入站 Allow 规则；同一份代码换到另一路径运行不能假设 QUIC 可达。
- H3/UDP 必须由主机防火墙、安全组或等价网络控制单独限制授权来源。

## 8. 回滚与保留

修复前快照：

- `rollback-snapshots/pre-remediation-20261101-035947/workspace.tar.gz`
- `rollback-snapshots/pre-remediation-20261101-035947/workspace/`
- `rollback-snapshots/pre-remediation-20261101-035947/tracked-worktree.patch`
- `rollback-snapshots/pre-remediation-20261101-035947/files.sha256`
- `rollback-snapshots/pre-remediation-20261101-035947/artifacts.sha256`
- `rollback-snapshots/pre-remediation-20261101-035947/git-head.txt`
- `rollback-snapshots/pre-remediation-20261101-035947/git-status.txt`
- `rollback-snapshots/binaries/highwall-native-core.release-pre-20261101.exe`

r5 后快照：`rollback-snapshots/post-remediation-r5-20261101-164500/`。包含最终源码/文档工作树、`tracked-worktree.patch`、`git-head.txt`、`git-status.txt`、`files.sha256`、构建/测试日志副本、DSH r5 报告/汇总/证据副本、运行进程绑定记录和 `ROLLBACK.md`。快照排除 `.git`、`target*`、`.runtime-*`、缓存、构建产物、私钥和证书；被排除的敏感测试文件路径在 `ROLLBACK.md` 中单独列明。该目录是维护者本地回滚点，不随公开仓库发布。

## 9. 发布门禁

在生产发布、打标签或发布镜像前：

- 不建发布标签、不发布镜像；公开源码和脱敏测试记录的推送已获单独授权，但不能视为生产发布。
- 不把 `23/23`、r5 的 `7/8` 或 r6 的 HWA-11 `closed` 写成完整验收或生产准入。
- 不把 H1/H2/H3 的 C3 写成 C4。
- 不把 H3/UDP 的 L4Wall 绕过写成已解决。
- 不把 HWA-08、HWA-09、HWA-10 的定向关闭扩展为其他配置、完整生产或 C4 结论。
- 不把 HWA-11 的 r6 窄范围 `closed` 扩展为完整 H3 验收或生产准入；运行进程映像仍无独立取证。
- 不把 HWA-04/05/06 的历史定向结论写成 r5 已复测；本轮未覆盖。

进入正式生产发布评审至少需要：对残留 Medium 形成书面风险接受；完成运行进程/构建来源绑定、SBOM 和可复现构建证明；确认 H3/UDP 网络层限制和封禁后握手成本；完成管理面/Safe Ops/审计故障/流控饱和/真实容器拓扑的范围确认；由人工审批人复核 r5/r6 证据。HWA-11 的 r6 窄范围关闭不能替代上述完整准入条件。DSH 对生产发布的 **no push** 建议保持不变。
