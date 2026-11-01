# HighWall r3 定向复核结果（2026-11-01）

- 状态：r3 定向复核历史记录；完整安全验收未完成；记录生成时未推送，脱敏后随公开仓库发布
- 被测对象：HighWall `0.12.0.dev0` 本地工作树、L4Wall、原生 B+D-4 数据面
- 基线提交：`114e8f11af508c550f8a64f4ec85ed826fd964bb`（`main`，工作树未提交）
- 测试方：DSH（DeepSeek Harness）AI Agent
- 测试目标：`192.0.2.10:18443` 的 TCP H1/H2 与 UDP H3（公开版使用 RFC 5737 文档地址替换实验室地址）
- 测试窗口：`2026-11-01T05:50:23Z` 至 `2026-11-01T06:00:32Z`

> 本文是隔离靶场中的定向复核记录，不是全量渗透测试、第三方审计或生产准入证明。本轮 10 个定向项加 HWA-04 历史项共 11 项，其中 2 项定向关闭、4 项部分关闭、4 项仍开放、1 项本轮未验证。

> 公开脱敏说明：实验室私网地址已替换为 RFC 5737 文档地址；本机绝对路径、进程号、一次性浏览器配置和未被 Git 跟踪的原始证据已移除或改为逻辑路径。原始证据不随仓库发布。

## 1. 结论摘要

- 定向关闭：HWA-05、HWA-06。
- 部分关闭：HWA-01、HWA-02、HWA-03、HWA-07。
- 仍开放：HWA-08、HWA-09、HWA-10、HWA-11。
- 本轮未验证：HWA-04；仅保留第二轮 r2 的定向证据。
- HWA-08 的单次封禁和 305 秒恢复均可复现，但封禁期间客户端仍然只能看到 TLS 前 EOF，不能区分策略封禁与网络故障。
- 运行审计已补充对账：被 WAF、协议、429 和封禁拒绝的请求均未到达 upstream；HWA-11 的客户端 reset 在服务端审计中对应内部 400，且未到达 upstream。
- **不足以作为完整生产准入。** 公开源码和脱敏测试记录已获单独授权；生产发布、标签、镜像和二进制 release 仍需完整门禁。

## 2. 证据

### 2.1 DSH 客户端证据

- 报告：`dsh-evidence/highwall-remediation-r3-20261101/report-r3.md`
- 汇总：`dsh-evidence/highwall-remediation-r3-20261101/summary-r3.json`
- 请求记录：`dsh-evidence/highwall-remediation-r3-20261101/evidence-r3/requests.jsonl`
- 原始字节：`dsh-evidence/highwall-remediation-r3-20261101/evidence-r3/raw/`
- 测试脚本：`dsh-evidence/highwall-remediation-r3-20261101/evidence-r3/scripts/`

`requests.jsonl` 共 38 条记录：H1 27、H2 6、H3 4、TLS 探针 1；`raw/` 共 76 个文件。H2/H3 原始材料主要是库层帧和头/正文 trace，不是 TLS/QUIC 密文或 pcap。

### 2.2 运行审计

- 运行配置与审计副本：`dsh-evidence/highwall-remediation-r3-20261101/runtime-r4/`
- native 审计：68 条事件；upstream：20 条允许请求；L4Wall：75 条连接事件。
- 审计副本在停止靶场前复制，包含 `native-audit.jsonl`、`l4wall-audit.jsonl`、`upstream.jsonl` 和三份运行配置/启动材料。
- 审计副本不包含证书私钥、凭据、Cookie、Authorization 或测试令牌。

## 3. 逐项结果

| ID | 状态 | 客户端事实 | 运行审计对账 | 残余问题 |
|---|---|---|---|---|
| HWA-01 WAF 载荷规避 | **部分关闭** | H2 query 百分号 XSS 为 403 `WAF-003`；H2 71,680 字节正文 SQLi、H3 二进制 SQLi、H3 双层 Base64 SQLi 均为 403 `WAF-002`。 | 四个被拒请求均未到达 upstream；仅允许的 H1/H3 基线请求到达。 | 只覆盖 4 个定向变体；压缩、multipart、header-borne 和完整 H1/H2/H3 矩阵未验证。 |
| HWA-02 Agent 阈值误伤 | **部分关闭** | 5 个不同 UA 约 1 秒间隔得到 `[200,200,200,200,429]`；429 带 `Retry-After: 60` 和 `X-RateLimit-Policy: highwall-automation-budget`；65 秒后 `/ok` 为 200。 | 两个 429 请求均未到达 upstream；被允许的 UA 请求到达。 | 运行配置为 `agent.mode=confirmed`、`max_user_agent_changes=4`，低 UA 阈值误伤根因仍在；5 次 429 累计路径未验证。 |
| HWA-03 DLP 覆盖缺口 | **部分关闭** | 64 字符高熵 POST 正文返回 200 并回显；运行配置 `detect_high_entropy=false`。 | 该 64 字节正文到达 upstream。 | 高熵检测仍关闭；JWT/Google 风格 key 只有 r2 结果，本轮未重测。 |
| HWA-04 H3 重复伪头 | **本轮未验证** | 本轮没有重复伪头用例。 | 未做 r3 对账。 | 只有 r2 的重复 `:path` 定向证据；不能把 r2 结论扩展为 r3 或全 H3。 |
| HWA-05 HEAD 正文路由 | **定向关闭** | `HEAD /ok`、`/status/200`、`/large`、`/echo` 均为 200，正文 0 字节；`/large` 带 `Content-Length: 2097152`，没有 502。 | 四个 HEAD 请求均到达 upstream。 | 仅 H1；其他路由和上游异常场景未覆盖。 |
| HWA-06 单行头上限 | **定向关闭** | 单行内容不含 CRLF 时，8192 字节为 200，8193 字节为 413 `PROTOCOL-001`；含 CRLF 时为 8194/8195。 | 413 请求未到达 upstream。 | 仅 H1 单行边界；总头大小和 H2/H3 header-list 上限未覆盖。 |
| HWA-07 H1 chunked/trailer | **部分关闭** | 单个合法 `Transfer-Encoding: chunked` POST 返回 200，正文 `test` 被重框定为 `Content-Length: 4`；`chunked, chunked` 为 400 `PROTOCOL-001`；带 trailer 为 400 `PROTOCOL-002`。 | 合法单 chunked 到达 upstream，正文 4 字节；两个非法请求未到达。 | 文档曾声称拒绝所有 TE，现已按实测修正；尚未由独立测试方复测修正后的文档和更多 framing 组合。 |
| HWA-08 封禁不可观测 | **仍开放** | 5 次 `GET /.git/HEAD` 在 1.70 秒内均为 403 `WAF-006`；新 TCP 连接可建立，但 TLS 握手得到 `SSLEOFError`，0 字节服务端响应，无 ServerHello、TLS alert 或 HTTP 429/403；305.0 秒后 `/ok` 为 200。 | 第 5 次拒绝后 native 记录 `HW-NATIVE-BAN-001`；L4Wall 对被封禁连接记录 `upstream_error`/`io_error`；被拒请求均未到达 upstream。 | 客户端仍无法区分封禁与 TLS 层网络故障；没有 Retry-After、TLS alert、管理面查询/撤销或统一原因码。TTL 恢复有效不等于可观测性关闭。 |
| HWA-09 响应 DLP 不计违规 | **仍开放** | 3 次 `/secret` 均为 451 `DLP-002`，随后 `/ok` 在 1.03 秒后为 200；之后仍需 5 次请求方向 WAF 拒绝才触发封禁。 | 3 次 `/secret` 均到达 upstream，响应被 native DLP 拦截；后续 5 次 WAF 请求未到达 upstream。 | 响应方向 DLP 不计入请求方向封禁预算；需要产品决策或书面风险接受。 |
| HWA-10 H2 非法 SETTINGS | **仍开放** | `SETTINGS INITIAL_WINDOW_SIZE=0x80000000` 后服务端发 SETTINGS，再发 GOAWAY `error_code=1`（`PROTOCOL_ERROR`）并 EOF；没有 HTTP 请求。 | 未进入 HTTP 请求路径；没有 upstream 请求。 | RFC 9113 期望 `FLOW_CONTROL_ERROR=3`；fail-closed 成立，但协议一致性/互通问题仍在，不是绕过成功。 |
| HWA-11 H3 authority/Host | **仍开放** | 缺失 `:authority` 和 Host/`:authority` 不一致都只产生 `StreamReset`/`StopSending` 错误码 270（`0x10E`），客户端没有收到 HTTP 4xx。 | native 审计记录内部 400 `HW-NATIVE-H3-001`，两个请求均未到达 upstream。 | 客户端仍没有可解析的 HTTP 4xx/错误体；服务端内部 400 与客户端 reset 的可观测性不一致。 |

## 4. 审计对账说明

- native 审计中的 `accepted` 只表示请求进入原生处理路径，真正到达 upstream 的请求必须同时出现在 `upstream.jsonl`。
- HWA-01/02/07/08/09 的拒绝请求均未出现在 upstream；HWA-03 的高熵请求按运行配置允许并到达 upstream；HWA-10 未进入 HTTP 请求路径；HWA-11 的内部 400 未到达 upstream。HWA-09 的 `/secret` 请求到达 upstream，但其敏感响应被 DLP 在 native 内拦截。
- HWA-05 的四条 HEAD 和 HWA-07 的合法单 chunked 均在 upstream 可见，说明定向关闭不是仅凭客户端状态码推断。
- L4Wall 审计只覆盖 TCP 连接；H3/UDP 直接进入原生 QUIC listener，因此不能用 L4Wall 事件证明 H3 的来源限制或封禁效果。
- 审计副本由被测方运行环境生成，不是独立抓包；不能替代外部 pcap、构建来源绑定或第三方测试。

## 5. 收尾状态

- r4 的一次性 upstream、native、L4Wall 已停止；18443/18444/18445 TCP 和 18443 UDP 已释放。
- DSH 服务已停止，`$DSH_ROOT/etc/network-mode` 已恢复为 `locked`。
- 一次性运行目录清理已按绝对路径核验后尝试，但被当前执行策略硬性拦截，未删除任何文件。保留目录：
- 一次性运行目录和测试证书/私钥未纳入公开仓库，也没有上传或压缩；具体清理记录保留在未发布的维护者快照中。

## 6. 审批边界

- r3 生成时未 commit、未 push、未建发布标签、未发布镜像；后续公开发布由新一轮人工审批覆盖。
- 不把本记录写成完整验收、生产准入或 C4 证明。
- HWA-08/HWA-09 需要产品决策或书面风险接受；HWA-10/HWA-11 仍可复现；HWA-01/02/03/07 仍需扩展矩阵或独立复测。
- 发布前至少需要重新构建并绑定源码/二进制哈希，补做完整协议矩阵、管理面/Safe Ops、审计故障、流控饱和、真实容器拓扑和 H3/UDP 网络边界测试。
