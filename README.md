# HighWall

[English](README.en.md) | 简体中文

[![CI](https://github.com/Fallen-leaves089/highwall/actions/workflows/ci.yml/badge.svg)](https://github.com/Fallen-leaves089/highwall/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) [![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

HighWall 是一个**失败关闭（fail-closed）的 HTTP/1.1 应用层反向代理与防护网关**。它只使用 Python 标准库，目标是把应用入口处最容易出现分歧的解析、策略、资源限制和审计做成可审计的小内核。

当前源码与最新发布版本：`0.11.0`。v0.3 把防护目标从“防响应泄漏”扩展为同时覆盖**机密性、完整性和可用性**；v0.4 增加可配置的精确路径蜜罐、首击封禁和有界拖延；v0.5 增加内置蜜罐模板与预设组；v0.6 增加配置生成、实际生效值检查和本地快速部署；v0.7 收紧路径规范化、请求 body 编码、响应 DLP 与审计脱敏，并加入路由级限速和 TLS HSTS；v0.8 增加多信号攻击者指纹、持久标记、两阶段遏制、L7 DDoS 告警和异步 Webhook；v0.9 增加原子配置热加载、TLS 证书热轮换、优雅排空停机和重载代次指标；v0.10 增加配置变更预演 `highwall diff`、CI 静态检查/类型检查/覆盖率门槛、CodeQL、Dependabot 和发布镜像签名/证明；v0.11 增加独立的 L4Wall 连接级防护子项目、标准复合部署骨架和可复现实机攻防靶场，并补齐 503 在途审计与发布脱敏检查。它仍不是已经完成第三方审计的生产级产品。

> **v0.11 重点**：L4Wall 负责连接级准入、限速、字节上限和封禁，HighWall 继续负责 HTTP/1.1 的 WAF/DLP；两者可通过 `lite` 串联或 `standard` 骨架部署。上线前先用 [docs/STACK.md](docs/STACK.md) 核对入口、直连封堵和真实客户端 IP。

## 目录

- [30 秒看懂](#30-秒看懂)
- [30 秒演示](#30-秒演示)
- [它解决什么](#它解决什么)
- [攻击者指纹、标记与拖延](#攻击者指纹标记与拖延)
- [L7 DDoS 告警与 5 分钟响应窗口](#l7-ddos-告警与-5-分钟响应窗口)
- [威胁防护快速启用](#威胁防护快速启用)
- [L4Wall 子项目与复合部署](#l4wall-子项目与复合部署)
- [快速开始](#快速开始)
- [配置要点](#配置要点)
- [配置变更检查](#配置变更检查)
- [常见问题与排查](#常见问题与排查)
- [部署原则](#部署原则)
- [测试与冒烟](#测试与冒烟)

## 30 秒看懂

HighWall 把入口处最容易出错的解析、默认拒绝、资源上限、审计和响应检查放进一个只依赖 Python 标准库的小进程，适合放在应用前面做一层可审计的 L7 防护。

- **fail-closed**：解析歧义、配置错误或上游失败时返回错误，不静默放行。
- **零第三方运行时依赖**：核心代理只使用 Python 标准库，便于审计和小规模部署。
- **可验证**：自带测试、`highwall check` / `inspect` / `diff`、本地 quickstart 和 JSONL 审计。

- 适合：给内部服务、静态站、管理面或小型 API 增加一层入口防护。
- 不适合：抗大流量 DDoS、代理 WebSocket/HTTP/2，或替代应用自身的认证授权。
- 复合部署：仓库包含独立的 L4 子项目 [L4Wall](subprojects/l4wall/README.md)；标准形态、旁路规则和验收方法见 [docs/STACK.md](docs/STACK.md)。

> HighWall 仍是 `0.11.0`，尚未经过独立第三方安全审计。生产使用前请先读 [它不解决什么](#它不解决什么) 和 [部署原则](#部署原则)。

> **防护边界**：WAF、DLP、行为评分和蜜罐都是降低暴露面的启发式，不是认证或安全边界；同主机、同命名空间或已失陷客户端无法靠它们区分，DLP 也不能承诺“防泄漏”。

## 30 秒演示

Windows 单机演示（无需第二台电脑、无需管理员权限）：

```powershell
git clone https://github.com/Fallen-leaves089/highwall.git
cd highwall
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\demo.ps1
```

脚本会在回环地址上启动一个临时上游和 HighWall，发送正常请求、错误 Host、SQL 注入、路径穿越、蜜罐和非法方法，打印审计事件，然后自动停止并清理。输出类似：

```text
HighWall single-machine demo
  listen:   127.0.0.1:<port>
  upstream: 127.0.0.1:<port>

[PASS] normal       status=200 expected=200
[PASS] bad host     status=403 expected=403
[PASS] sqli         status=403 expected=403
[PASS] traversal    status=400 expected=400
[PASS] honeypot     status=200 expected=200
[PASS] trace        status=405 expected=405

[audit] request_blocked status=403 rule=HW-HOST-1003
[audit] honeypot_hit    status=200 rule=HW-HONEY-env_probe
```

任何断言失败时脚本返回非零退出码。需要保留临时运行目录时加 `-KeepRuntime`。

持久运行仍然使用 quickstart（会启动一个演示上游）：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 -WithDemoUpstream
```

也可以只生成配置并检查：

```bash
python -m highwall init --upstream http://127.0.0.1:8080 --allowed-host app.internal --output config.json
python -m highwall check -c config.json
python -m highwall serve -c config.json
```

更多参数见 [快速开始](#快速开始)。

## 它解决什么

- 严格解析 HTTP/1.x：只接受 origin-form、显式 `Content-Length`，拒绝 `Transfer-Encoding`、`TE`、折叠头、重复敏感头、协议升级和编码请求体，直接消除常见的 CL.TE / TE.CL 请求走私面。
- Host、方法、路径前缀三层默认拒绝；Host 必须精确匹配配置中的 authority。
- 路径解码后做点段、编码分隔符、反斜杠、控制字符和 NFKC 归一化检查；默认拒绝路径参数、尾随点和尾随空格，路由 ACL/方法/只读判断统一按大小写不敏感的规范化路径执行。
- 保守的应用层签名（SQL 注入、XSS、路径穿越、命令注入、JNDI、SSRF 启发式），支持 `detect` 与 `block` 模式。
- 每个请求有绝对头/体期限；上游连接、读取和整个上游响应都有独立上限。
- 并发连接、请求行、头数量/大小、请求体、响应体和内存预算均有硬上限。
- 可按客户端 CIDR 做应用层允许/拒绝；拒绝列表优先，未配置时保持兼容。
- 可选的 Origin 白名单：配置后，写方法缺少或伪造 Origin 会被拒绝，`Sec-Fetch-Site: cross-site` 的写请求也会被拒绝。
- 可按客户端限制并发连接数，并在短时间内反复触发协议/策略错误时临时封禁该客户端。
- 可对 HTTP/TLS 形状和来源前缀做多信号指纹关联；疑似阶段先限速，确认后写入有界持久标记，并对慢速通道施加 5 分钟疑似窗口或 15 分钟确认窗口。
- 可聚合 L7 请求速率、拒绝比例、连接饱和度、TLS 失败和上游错误，触发 DDoS 告警并异步推送 Webhook；支持恢复事件和 5 分钟响应窗口。
- 可按最长路径前缀配置路由策略：方法子集、只读、路由级来源 CIDR、请求体上限、独立并发槽位和每客户端令牌桶限速。
- 可配置精确路径蜜罐：内置常见扫描路径模板，返回本地静态诱饵，绝不访问上游；命中后记录独立审计事件，并可立即封禁来源或施加有上限的短延迟。
- 支持全局或路由级 `read_only`：写方法在到达上游前被拒绝，适合静态站、备份浏览和管理读写分离。
- 可对精确 `GET` 路径做响应完整性钉扎：校验状态码和响应体 SHA-256；`detect` 记录，`block` 返回 502 且不转发被替换的内容。
- 可启用上游熔断：连续连接失败、超时或 5xx 后短暂拒绝请求，冷却后用有界半开探针验证恢复，避免故障放大。
- 可设置全局在途请求上限，防止已建立连接同时占满处理线程；路由级并发槽位可保护昂贵接口。
- 响应侧 DLP：扫描有界响应体前缀和响应头，识别私钥、常见云/代码托管/支付/AI token、JWT、数据库 URI 凭证和常见调试栈泄漏；支持 UTF-8、Latin-1 和 UTF-16，`Set-Cookie` 默认排除以避免登录会话误报。
- 对上游强制 `Accept-Encoding: identity`，拒绝压缩或编码歧义的响应，避免 DLP 被压缩层绕过。
- 上游响应重新分帧：拒绝重复/非法 `Content-Length`、`Content-Length` 与 `Transfer-Encoding` 冲突、非 `chunked` 的上游 `Transfer-Encoding`，并重新生成 `Content-Length`。
- 客户端的 `X-Forwarded-*`、`Forwarded`、`X-Original-URL`、`X-HTTP-Method-Override` 等绕过头不会原样到达上游。
- 审计 JSONL 固定字段，不记录查询串、Cookie、Authorization 或请求体；敏感路径段和路径参数默认脱敏，也可选择哈希或显式精确记录；审计文件限制大小并轮转。
- 启用 TLS 时若未显式配置 HSTS，自动添加 `Strict-Transport-Security: max-age=31536000`。
- 管理面只允许回环地址，使用环境变量提供的 Bearer token，只读暴露健康、指标和审计尾部。
- 附带只读 Windows 宿主审计脚本，检查防火墙默认策略、RPC/SMB/RDP 监听、端口转发、Defender/ASR、备份可见性和 HighWall 文件 ACL；脚本不修改任何系统状态。
- 附带 `highwall init`、`highwall inspect` 和 Windows `scripts/quickstart.ps1`：一条命令生成配置、启动、验收并记录状态；不会静默覆盖已有配置。

## CIA 覆盖边界

| 目标 | HighWall 可做的 L7 控制 | 仍需其他层完成 |
|---|---|---|
| 机密性 | Host/路径/来源约束、WAF、响应 DLP、安全头、回环管理面 | 用户认证、密钥管理、磁盘/内存/回环保护、最小出网 |
| 完整性 | 路由方法白名单、只读模式、请求体限制、响应 SHA-256 钉扎、受控响应头 | 上游业务授权、数据库约束、文件完整性、EDR、不可变备份 |
| 可用性 | 连接/在途/路由并发上限、速率限制、临时封禁、攻击者标记、慢速槽位、L7 DDoS 告警、上游熔断、超时 | 带宽清洗、SYN flood 防护、主机容量、上游高可用与灾备 |

## 攻击者指纹、标记与拖延

HighWall 0.8 的指纹是**多信号关联**，不是身份认证，也不承诺“全球最精确”：

- HTTP header 名称、顺序和稳定字段（User-Agent、Accept、Sec-Fetch-* 等）；
- HighWall 终止 TLS 时的 ClientHello：版本、cipher、extension、group、signature algorithm、ALPN 和 SNI 是否存在；
- 来源 `/24`（IPv4）或 `/64`（IPv6）前缀。

Cookie、Authorization、Proxy-Authorization、Set-Cookie、API Key 等敏感头只以 `<redacted>` 参与形状哈希。原始路径、查询串、请求体、Cookie 值和 token 不进入指纹、持久标记或告警载荷。TLS 指纹只在 HighWall 自己终止 TLS 时可用；如果 TLS 在前面终止，则只能使用 HTTP 形状和来源前缀。

判定分两阶段：

1. `suspected`：请求速率、路径广度和策略违规分数达到阈值后，在 `throttle` / `tarpit` 模式下先延迟；默认遏制窗口 `containment_seconds=300`（5 分钟）。
2. `confirmed`：达到 `confirm_score`、命中已有确认标记，或持续疑似 `confirm_after_seconds=300` 后确认；写入 `offenders.json`，默认持续慢速 `confirmed_containment_seconds=900`（15 分钟），标记 TTL `mark_ttl_seconds=86400`。

`mode` 可选 `monitor`（只告警、不启用慢速，但达到 `confirmed` 仍会写标记）、`throttle`（延迟）、`tarpit`（慢速响应）和 `block`（429）。`tarpit` 只在已确认攻击者上启用慢速通道；每个攻击者和全局槽位都有上限，槽位满时返回 429，不会继续占用线程。建议先 `monitor` 观察误报，再切换到 `tarpit`。

慢速通道的容量估算为 `T ≈ ceil(N / S) × H`：默认 `S=4` 个单攻击者槽位、`H=15` 秒时，约 80 个请求可形成 5 分钟窗口，约 240 个请求可形成 15 分钟窗口。`H` 来自 `tarpit_hold_seconds`，并受 `max_tarpit_hold_seconds` 上限约束；HighWall 从响应头发送完成到最后一个响应体分块完成，按 `H` 秒调度。若单请求保持时间调为 10 秒，则 5 分钟约需 120 个请求。它是容量估算，不是 SLA：攻击者轮换 `/24`、TLS/Header 指纹、使用僵尸网络或在槽位满后重试，都会改变实际效果。共享 NAT 也可能造成连带慢速。

标记文件只包含派生指纹、分数、信号和可选客户端 IP（默认不记录），不包含请求内容；应放在受 ACL 保护的数据目录。管理面开启后，可用 Bearer token 查看：

```powershell
curl.exe -H "Authorization: Bearer $env:HIGHWALL_ADMIN_TOKEN" http://127.0.0.1:18091/offenders
```

## L7 DDoS 告警与 5 分钟响应窗口

HighWall 聚合 5 类 L7 信号：请求速率、拒绝比例、连接饱和度、TLS 握手失败数和上游错误比例。默认至少 2 类信号同时成立才发出 `ddos_suspected`；持续 300 秒后升级为 `ddos_escalated`，无信号 30 秒后发出 `ddos_recovered`。告警载荷中的 `containment_window_seconds=300` 是建议的 5 分钟响应窗口，不是自动清洗承诺。

Webhook 通过有界异步队列发送，失败重试一次，队列满时丢弃并计数，不阻塞请求线程。默认只允许 HTTPS，禁止重定向和 URL 内嵌凭证：

```powershell
$env:HIGHWALL_ALERT_WEBHOOK = "https://alerts.example.com/highwall"
$env:HIGHWALL_ALERT_TOKEN = "<16+ random characters>"
```

DDoS 告警应接入 NOC/值班系统，并在 5 分钟窗口内完成：确认 CDN/清洗中心状态、检查上游容量和错误、保留审计证据、按预案启用边缘限流。**带宽型 L3/L4 DDoS 必须在运营商/清洗中心处理**；HighWall 可能先于告警失去可达性，因此必须配置独立于本机的外部心跳监控。不要为了看告警把管理面暴露到公网。

### 告警事件与第一动作

| 事件 | 含义 | 值班第一动作 |
|---|---|---|
| `threat_suspected` | 单个攻击者指纹达到疑似阈值 | 核对来源前缀、共享 NAT、正常自动化与审计事件，观察是否继续升级 |
| `threat_confirmed` | 达到确认阈值或命中已有持久标记 | 保留证据，确认慢速槽位没有拖垮正常连接，再决定是否人工封禁 |
| `ddos_suspected` | 至少 2 类 L7 信号同时异常 | 立即通知值班，开始 5 分钟响应窗口，不等待 HighWall 自动清洗 |
| `ddos_escalated` | 异常持续 300 秒仍未恢复 | 升级 NOC、网络或清洗团队，检查 CDN、上游容量和边缘限流 |
| `ddos_recovered` | L7 信号已恢复 | 先观察并保留证据，不要立即撤销所有人工处置 |

### 5 分钟响应清单

- **0–1 分钟**：确认告警时间、受影响域名和告警来源；先不要重启 HighWall，避免丢失现场和慢速槽位状态。
- **1–3 分钟**：检查 CDN/清洗中心状态、上游 5xx/超时、连接饱和度、TLS 握手失败和审计事件。
- **3–5 分钟**：按预案启用边缘限流或清洗，保留审计和指标，通知业务负责人。
- **5 分钟后仍为 `ddos_escalated`**：升级网络、运营商或清洗团队；HighWall 不能替代带宽清洗和上游扩容。

### Webhook 载荷示例

以下只是字段示例，不是固定值。默认不包含客户端 IP、原始路径、Cookie、Authorization 或请求体：

```json
{
  "schema": "highwall.alert.v1",
  "event": "ddos_escalated",
  "severity": "critical",
  "layer": "L7",
  "signals": {
    "request_rate": 812.4,
    "connection_saturation": 0.93
  },
  "action": "escalate_to_noc_and_check_edge_scrubbing",
  "containment_window_seconds": 300,
  "recommended_actions": [
    "notify_noc",
    "check_edge_scrubbing",
    "verify_upstream_capacity",
    "preserve_audit_logs"
  ]
}
```

## 威胁防护快速启用

`highwall init` 和 `scripts/quickstart.ps1` 生成的配置默认关闭 `threat_detection`、`ddos_detection` 和 `alerting`，避免在未确认业务流量前自动限速或发告警。`config.example.json` 为了展示字段，把威胁检测和 DDoS 检测设为 `true`，但仍将 `alerting.enabled` 设为 `false`；不能直接把它当成生产配置。

建议按以下顺序启用：

1. 先使用 `mode=monitor` 观察 `threat_suspected` / `threat_confirmed`，确认共享 NAT、监控探针和正常自动化没有被误判。
2. 确认 `per_actor_tarpit_slots`、`global_tarpit_slots` 和 `tarpit_hold_seconds` 不超过连接/线程预算，再切换为 `mode=tarpit`。
3. 把 `offender_path` 放在服务账户可写、其他账户不可读写的目录；Windows 可使用 `C:/ProgramData/HighWall/data/offenders.json`，不要放在公开静态目录或审计日志目录。
4. 设置 Webhook 并在同一服务环境中打开 `alerting.enabled=true`，然后观察 `alert_sent_total`、`alert_failed_total` 和 `alert_dropped_total`。

`monitor` 不会慢速或阻断请求，但达到 `confirmed` 后仍会写入 `offenders.json`，以便重启后继续关联风险；若当前阶段完全不想产生持久标记，请先不要启用 `threat_detection`，或把 `offender_path` 指向单独的临时目录。

`threat_detection.agent_mode` 默认 `score`：请求呈现明显的脚本/Agent 特征（自动化 UA、缺少浏览器头、无 Cookie、节奏规律、单路径聚焦或同路径参数扫描）时只加分。企业需要直接处置时，只改这一行：`block` 按来源 IP 封禁，`throttle` 按当前指纹/请求形状限流；该开关不依赖 `rate_limit.auto_ban_threshold`。`throttle` 不是 IP 级封禁，轮换 UA 或请求形状可能重新获得干净配额；需要强处置明显 Agent 时选 `block`。`agent_min_signals` 默认 3，`agent_score` 默认 30。

把以下关键字段合并到现有配置中（片段不能单独作为完整配置）：

```json
{
  "threat_detection": {
    "enabled": true,
    "mode": "monitor",
    "confirm_after_seconds": 300,
    "containment_seconds": 300,
    "confirmed_containment_seconds": 900,
    "tarpit_hold_seconds": 15,
    "per_actor_tarpit_slots": 4,
    "global_tarpit_slots": 16,
    "offender_path": "/var/lib/highwall/offenders.json"
  },
  "ddos_detection": {
    "enabled": true,
    "escalation_seconds": 300
  },
  "alerting": {
    "enabled": true
  }
}
```

```powershell
$env:HIGHWALL_ALERT_WEBHOOK = "https://alerts.example.com/highwall"
$env:HIGHWALL_ALERT_TOKEN = "<16+ random characters>"
```

`HIGHWALL_ALERT_TOKEN` 是可选 Bearer token，但生产环境建议使用；不要把 token 写进配置文件、README、命令行参数或审计日志。Webhook 默认只允许 HTTPS，并禁止重定向和 URL 内嵌凭证。

## 自定义蜜罐

蜜罐是显式配置的**精确路径诱饵**。请求只有在通过来源 ACL 和 Host 白名单后，才会按规范化路径匹配；命中后由 HighWall 直接返回静态内容，不连接上游。为避免扫描器因普通 WAF/方法规则提前收到 403，蜜罐路径不套用普通 `allowed_methods`、Content-Type、Origin、只读和 WAF 约束。

```json
{
  "enabled": true,
  "ban_seconds": 0,
  "presets": ["common"]
}
```

安全约束：

- 只按规范化后的完整路径精确匹配，不做前缀或通配符匹配；查询串不参与匹配。
- `presets` 可直接启用内置组：`common`、`secrets`、`wordpress`、`spring`、`admin`、`devops`、`cloud`，也可列出单个模板名；显式 `routes` 会按路径覆盖预设。
- 响应体必须写在配置内且不超过 64 KiB；只允许安全自定义响应头，限制 `Content-Type`、`Content-Length`、`Set-Cookie`、`Server` 等托管头。
- 不反射 URL、Header 或请求体，不记录请求体、Header、Cookie、Authorization 或查询串；审计只记录方法、路径、来源、状态和规则 ID。
- `ban_seconds` 大于 0 时，第一次命中即封禁该来源；封禁状态只保存在内存中。共享 NAT 出口可能被连带封禁，可通过设为 `0` 关闭。
- `delay_ms` 最大 5000，用于低成本拖延，不是抗 DDoS 队列；它仍占用全局在途槽位。
- 禁止把蜜罐路径设置为真实业务端点，也不要放入任何真实凭证、私钥或可用于横向移动的信息。

详细说明见 [`docs/HONEYPOT.md`](docs/HONEYPOT.md)，模板清单与参考来源见 [`docs/HONEYPOT-TEMPLATES.md`](docs/HONEYPOT-TEMPLATES.md)。命中在审计中表现为 `honeypot_hit`，并产生 `honeypot_hits_total`、`honeypot_bans_total`、`honeypot_ban_rejections_total` 和 `honeypot_ban_entries` 指标。

## 它不解决什么

HighWall 是 L7 网关，不是“绝对高防”：

- **不做**流量清洗或抗大流量 DDoS；带宽、连接数和上游容量仍需网络层防护。
- **指纹不是身份**：HTTP/TLS 形状可被伪造或轮换；`/24` 或 `/64` 关联可能把共享出口的正常用户一起限速。标记只用于风险关联，不能作为认证、归因或司法证据。
- **DDoS 告警不是清洗**：`ddos_suspected` / `ddos_escalated` 只说明 L7 信号异常，不保证识别流量来源；链路或主机饱和时 HighWall 本身可能不可达。
- **不能修复**上游应用自身的认证、授权、IDOR、默认口令、密钥泄漏或未修补漏洞。
- **不能保护**已经拿到同主机 root / 同名字空间 / 读进程内存 / 嗅探环回流量的攻击者。它必须和独立用户、命名空间、文件 ACL、网络隔离一起使用。
- **不能防勒索软件或擦除型攻击**。L7 网关无法阻止拥有主机写权限的进程删除文件；必须依赖低权限账户、受控文件夹、EDR、离线/不可变备份和恢复演练。
- **不能替代主机防火墙或网络分段**：客户端 CIDR ACL 只处理已经到达 HighWall 的 HTTP 请求，不处理 DNS 隧道、RPC、原始套接字或其他非 HTTP 流量。
- `read_only` 只按 HTTP 方法阻断 `POST`/`PUT`/`PATCH`/`DELETE`，无法识别通过 `GET` 触发副作用的错误业务设计。
- 完整性钉扎只覆盖配置中精确匹配的静态 `GET` 路径和状态码；查询串不参与匹配，也不会因为加了 query 就绕过校验。它不覆盖 HEAD、动态页面、响应头、WebSocket 或流式响应。
- 蜜罐只覆盖显式配置的精确路径，不能发现所有扫描；它可能被指纹识别，误触封禁会影响共享 NAT 来源，也不提供高交互 shell、文件落盘或反制能力。
- 熔断器会在上游连续故障时主动返回 503；它是故障隔离，不是 DDoS 清洗或容量保证。
- 持久标记可能因共享 NAT、代理池或刻意模仿正常浏览器而产生误报；默认先 `monitor`，并保护 `offenders.json` 不被未授权修改或删除。
- **不代理** WebSocket、HTTP/2、双向流式响应；检测到 Upgrade 会拒绝。响应会缓冲到 `max_response_bytes`。
- WAF 签名是启发式，不保证覆盖所有变体，可能误报；未知业务建议先 `detect` 观察再 `block`。
- 响应 DLP 也是启发式：只扫描 `response_scan_max_bytes` 限定的响应体前缀和响应头，媒体类型不构成免扫条件，会启发式尝试 UTF-8/Latin-1/UTF-16；`Set-Cookie` 被有意排除以避免登录 JWT 误报。未知编码、分片、二进制和业务自定义格式仍可能漏报。未知业务应先设 `response_scan_mode=detect`。
- 不给上游添加登录、MFA 或授权能力。上游自己的会话安全仍然重要。
- 不自动管理证书；TLS 证书和私钥需要由部署者提供并保护。

## L4Wall 子项目与复合部署

HighWall 仓库包含独立的 L4 子项目 [L4Wall](subprojects/l4wall/README.md)。它负责连接级准入、限速、超时、行为评分、封禁和审计；HighWall 继续负责 HTTP/1.1 的 WAF、DLP 和 L7 策略。两者不合并进程，也不互相替代。

支持两种形态：

- `lite`：`客户端 -> L4Wall -> HighWall -> 上游`，适合单机、小规模和 Windows。
- `standard`：`客户端 -> HAProxy/Envoy -> HighWall -> 上游`，HAProxy 负责 TLS、HTTP/2、WebSocket 和真实 IP 清洗；L4Wall 作为连接级控制面。部署骨架见 [`deploy/standard/`](deploy/standard/README.md)。

上线前必须读 [docs/STACK.md](docs/STACK.md)，重点确认：HighWall 和上游没有公网端口、L4Wall 管理面只回环、客户端转发头会被边缘删除并重写、直连 HighWall/上游在攻击者视角下不可达。L4Wall 已实现可选的 Redis 共享封禁读取端；自动发布端、Controller 和多节点 HA 仍在后续里程碑，不能把标准骨架当成完整控制面。

## 架构

```text
client / browser
      |
      | HTTP/1.1 (可选 TLS)
      v
+---------------------- HighWall process ----------------------+
| strict parser -> connection/rate/ban + in-flight limits        |
| -> fingerprint -> threat score -> throttle/tarpit/mark         |
| -> client ACL -> Host/path -> honeypot OR route/read-only -> WAF/body |
| -> bounded upstream client <-> circuit breaker                 |
| -> response framing/sanitizer -> integrity pins -> DLP         |
| -> L7 DDoS signals -> async webhook alerts                     |
| -> audit + metrics                                             |
+---------------------------------------------------------------+
      |
      | HTTP/HTTPS, connection: close
      v
upstream application (ideally loopback or private network)
```

管理面是独立的回环 HTTP listener，不能从外部网络访问。

## 快速开始

要求 Windows PowerShell 5.1 或更新版本、Python 3.10 或更新版本，不安装第三方依赖。

不想使用源码检出时，可从 [v0.11.0 Release](https://github.com/Fallen-leaves089/highwall/releases/tag/v0.11.0) 下载 wheel/sdist 和 `SHA256SUMS`，校验后安装：

```bash
python -m pip install highwall-0.11.0-py3-none-any.whl
```

```powershell
Set-Location <HighWall checkout>
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 `
  -UpstreamUrl http://127.0.0.1:8080 `
  -AllowedHost app.internal `
  -WithDemoUpstream
```

脚本会自动：

- 在 `.runtime\config.json` 生成回环监听、管理面关闭、WAF/DLP 阻断、在途背压、上游熔断和 `common` 蜜罐预设的配置；
- 校验配置并启动 HighWall；
- `-WithDemoUpstream` 时同时启动本地演示上游，并验证 Host 拒绝、正常转发、蜜罐命中与审计落盘；
- 写入 PID、日志、配置 SHA-256 和审计文件；重复执行不会重复启动。配置在启动后被改动时 `-Status` 返回异常并提示重启；这是实验脚本的保守行为，生产实例可用本文的 `/reload`。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 -Status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 -Stop
```

对真实上游部署时去掉 `-WithDemoUpstream`。已有配置会直接复用；如果命令行参数与配置不一致，脚本返回错误，不会假装修改成功。要修改已有配置，先停止实例并显式使用 `-Reconfigure`：脚本只合并命令行显式传入的参数，未指定的路由、TLS、限流、扫描模式等字段保持原值，旧配置会备份为 `config.json.bak.<时间戳>`。

也可以直接生成配置并核对实际生效值：

```powershell
python -m highwall init --upstream http://127.0.0.1:8080 --allowed-host app.internal --output config.json
python -m highwall check -c config.json
python -m highwall inspect -c config.json
```

`init` 默认拒绝覆盖已有文件；需要局部修改时可使用 `init --base config.json --output config.json --force --listen-port 18091`，未显式给出的字段会保留。`inspect` 会展开蜜罐预设，并输出生效后的监听、TLS、超时、上游熔断、ACL、WAF、响应扫描、安全头、限流、审计和管理面参数。

`config.example.json` 仍可作为完整字段参考。快速部署脚本只面向本地实验/验收，不创建 Windows 服务、计划任务或 ACL；生产托管按部署基线执行。

如果要启用管理面，修改配置中的：

```json
{
  "admin": { "enabled": true }
}
```

然后生成 token 并注入环境变量：

```powershell
$env:HIGHWALL_ADMIN_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
python -m highwall serve -c .runtime\config.json
```

访问：

```powershell
curl.exe http://127.0.0.1:18091/healthz
curl.exe -H "Authorization: Bearer $env:HIGHWALL_ADMIN_TOKEN" http://127.0.0.1:18091/metrics
curl.exe -H "Authorization: Bearer $env:HIGHWALL_ADMIN_TOKEN" http://127.0.0.1:18091/offenders
curl.exe -H "Authorization: Bearer $env:HIGHWALL_ADMIN_TOKEN" "http://127.0.0.1:18091/audit/tail?lines=50"
```

管理 token 只在环境变量中读取；不要写进 `config.json`、命令行或审计日志。token 长度必须是 32–512 个可见非空格 ASCII 字符。

## 容器镜像

版本标签会构建多架构镜像并发布到 GitHub Container Registry（GHCR）。镜像页见 [HighWall GHCR package](https://github.com/Fallen-leaves089/highwall/pkgs/container/highwall)，版本说明见 [v0.11.0 Release](https://github.com/Fallen-leaves089/highwall/releases/tag/v0.11.0)。`0.11.0` 镜像随 tag 发布，并带有 cosign 签名和 GitHub provenance attestation；更早的 `0.9.0` 镜像没有这些证明，不能反向声称已签名。

```bash
docker pull ghcr.io/fallen-leaves089/highwall:0.11.0
```

镜像以 UID `10001` 非 root 运行，默认执行 `python -m highwall serve -c /etc/highwall/config.json`。镜像不内置配置，缺少配置时会直接拒绝启动，不会退化为放行。

先生成一个适合容器的配置。容器内必须监听 `0.0.0.0`，审计文件写到持久卷：

```bash
python -m highwall init \
  --upstream http://host.docker.internal:8080 \
  --listen-host 0.0.0.0 \
  --allowed-host app.internal \
  --audit-path /var/lib/highwall/audit.jsonl \
  --output config.json
```

`host.docker.internal` 适用于 Docker Desktop；Linux Docker 请改成容器可达的服务名或私网地址。

```bash
docker run --rm --name highwall \
  -p 18090:18090 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -v "${PWD}/config.json:/etc/highwall/config.json:ro" \
  -v highwall-data:/var/lib/highwall \
  ghcr.io/fallen-leaves089/highwall:0.11.0
```

- 生产环境启用 TLS 时，把证书和私钥只读挂载到容器内，并在配置中使用容器内路径。
- 不要暴露管理面端口；管理面默认关闭，开启后也应只在受控网络内访问。
- `latest` 跟随最近发布的版本标签；生产部署应固定版本号。
- `v0.10.0` 及之后发布的镜像可用以下命令验证构建来源和签名；验证时把版本号替换为实际部署的不可变 tag：

```bash
gh attestation verify oci://ghcr.io/fallen-leaves089/highwall:0.11.0 \
  --repo Fallen-leaves089/highwall

cosign verify ghcr.io/fallen-leaves089/highwall:0.11.0 \
  --certificate-identity-regexp '^https://github.com/Fallen-leaves089/highwall/.github/workflows/container.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## 配置要点

- `policy.allowed_hosts`：精确 authority 白名单。`example.com`、`example.com:443`、`www.example.com` 是三个不同的值；Host 大小写会归一化，末尾点会去掉。
- `policy.allowed_path_prefixes`：按完整路径段匹配；建议生产环境收窄到实际业务前缀，不要长期使用 `/`。
- `policy.deny_path_prefixes`：先做路径归一化，再按前缀拒绝。默认覆盖 `.git`、`.env`、`server-status`、部分 actuator 端点。
- `policy.allow_path_parameters` / `allow_trailing_dot_or_space`：默认均为 `false`。只有旧业务确实依赖 `;jsessionid` 或尾随点/空格时才显式打开；兼容模式仅影响路由判据，WAF 仍扫描完整路径。
- `policy.waf_mode`：`detect` 只记录命中，`block` 直接拒绝。第一次接入未知业务建议用 `detect`。
- `policy.trusted_proxies`：只有 HighWall 确实在可信反向代理后面时才填写；不要填写 `0.0.0.0/0`。
- `policy.allowed_client_networks` / `denied_client_networks`：可选的 CIDR ACL，拒绝优先；空列表表示不按来源网段过滤。它是 L7 判据，不替代主机防火墙。
- `policy.allowed_origins`：可选的规范 Origin 白名单，例如 `https://app.example.com`。配置后，`POST`/`PUT`/`PATCH`/`DELETE` 必须带允许的 Origin，跨站写请求会被拒绝；为空时保持原来的非浏览器兼容行为。浏览器跨域写请求会先发 `OPTIONS` 预检，启用该白名单时要把 `OPTIONS` 加入 `allowed_methods`，并确认上游能响应预检。
- `policy.read_only`：全局只读开关；`routes[].read_only` 只对命中的最长路径前缀生效。它不识别 GET 副作用。
- `policy.routes`：按最长路径前缀选择；可设置 `methods`、`read_only`、`max_body_bytes`、`max_concurrent`、`rate`、`rate_burst` 和 `allowed_client_networks`。路由方法必须是全局 `allowed_methods` 的子集，空路由来源列表会被拒绝而不是静默放行；`rate` 是每客户端每秒令牌数，`rate_burst` 省略时取速率向上取整。
- `policy.honeypot`：默认关闭；启用后按规范化后的精确路径拦截诱饵，支持内置 `presets` 或自定义 `routes`、静态状态码、Content-Type、Body、受限响应头、服务端标识、首击封禁和 0–5000 ms 拖延。命中不访问上游，并绕过普通方法/Content-Type/WAF/只读限制以保留诱捕效果；Host 和客户端 ACL 仍然优先。
- `policy.response_integrity_mode` / `integrity_pins`：对规范化后的 `GET` 路由路径（大小写不敏感）校验 `status` 和响应体 SHA-256；支持 `off`、`detect`、`block`。钉扎值必须随受控发布流程更新。
- `upstream.circuit_breaker`：`failure_threshold`、`window`、`open_seconds` 和 `half_open_max_requests` 控制上游故障隔离；只把超时、连接/协议失败和 5xx 计为失败，4xx 视为上游可达。
- `server.max_inflight_requests`：全局在途请求上限，`0` 表示关闭；应小于 `max_connections` 才能形成独立背压。
- `server.shutdown_timeout`：收到 `SIGINT`/`SIGTERM`/`SIGBREAK` 后等待在途请求完成的秒数，默认 30；`0` 表示不等待并立即关闭剩余连接。
- `policy.allowed_body_content_types`：没有 Content-Type 或媒体类型不在列表中的请求体一律拒绝。
- `policy.response_scan_mode` / `response_scan_max_bytes` / `response_scan_headers`：上游响应的秘密/调试信息扫描，分别支持 `off`、`detect`、`block`；只扫描有界前缀，默认 1 MiB。媒体类型不再作为免扫条件，并尝试 UTF-8/Latin-1/UTF-16 解码；响应头默认参与扫描，`Set-Cookie` 固定排除。
- `server.max_connections_per_ip`：单个来源 IP 的并发连接上限；`0` 关闭限制，可信代理来源不计入。它不能替代总连接上限。
- `policy.routes[].max_concurrent`：路由级在途请求上限，`0` 表示关闭，不能超过 `server.max_connections`；超限返回 503 和 `Retry-After`。
- `rate_limit.auto_ban_threshold` / `auto_ban_window` / `auto_ban_seconds`：在时间窗内累计协议或策略错误后临时拒绝该来源；`threshold=0` 关闭这条“错误累计”自动封禁路径，但不关闭 `threat_detection.agent_mode=block` 的定向封禁。封禁状态只在内存中，重启即清空。
- `threat_detection`：多信号攻击者指纹、两阶段确认、慢速槽位和持久标记。`enabled` 默认关闭；建议先 `mode=monitor`，再切 `tarpit`。`agent_mode` 默认 `score`（只加分），可改为 `block` 或 `throttle` 来直接处置明显自动化：`block` 封来源 IP，`throttle` 只限制当前指纹，换请求形状可能绕过限速。`containment_seconds=300` 是疑似窗口，`confirmed_containment_seconds=900` 是确认后的持续慢速窗口；`offender_path` 必须是受保护的可写路径。
- `ddos_detection`：L7 请求速率、拒绝比例、连接饱和度、TLS 失败和上游错误的多信号聚合；`escalation_seconds=300` 表示持续 5 分钟才升级告警，`recovery_seconds` 控制恢复事件。它不会自动清洗带宽型 DDoS。
- `alerting`：异步 Webhook 告警。`enabled=true` 时 `HIGHWALL_ALERT_WEBHOOK` 必须存在且默认为 HTTPS；可选 `HIGHWALL_ALERT_TOKEN`。`include_client_ip` 默认 `false`，`allow_http` 默认 `false`。队列满会丢弃并增加 `alert_dropped_total`，不会阻塞请求。
- `upstream.total_timeout`：整个上游交换（连接、响应头、响应体）的绝对上限；`read_timeout` 是单次读取上限。
- `server.tls`：只做服务端 TLS，不替代上游 TLS 校验；证书和私钥路径按配置文件所在目录解析。握手在工作线程内执行并受 `handshake_timeout` 约束，慢握手不会阻塞新的 accept；TLS 启用且未配置 HSTS 时会自动添加一年期 HSTS。替换证书文件或路径后可通过 `POST /reload` 让新握手使用新证书。
- `audit.path`：相对路径按配置文件目录解析；日志目录必须由服务账户和运维账户保护。`audit.path_mode` 支持 `redact`（默认）、`hash` 和 `exact`；默认模式会清洗/解码路径并脱敏敏感键、后续值和明显高熵段。`audit.on_write_failure` 默认 `fail_closed`：运行期写失败后，从下一次请求起返回 503；设为 `continue` 则只计数并继续。启动时路径不可写会直接拒绝启动。
- `admin.enabled`：默认关闭；打开后强制回环监听和 token。管理面提供 `/healthz`、`/metrics`、`/offenders`、`/audit/tail` 和受保护的 `POST /reload`。

完整示例见 [`config.example.json`](config.example.json)。蜜罐配置见 [`docs/HONEYPOT.md`](docs/HONEYPOT.md)，威胁边界见 [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)，部署基线见 [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)，漏洞报告方式见 [`SECURITY.md`](SECURITY.md)。

## 配置变更检查

`highwall check --strict` 在普通校验之外检查高危配置开关：只有 `high` 级告警会让退出码变为 `4`，`medium` 级仍只打印 warning。建议在企业 CI 中启用，避免以下组合悄悄进入生产：`trusted_proxies` 非空、打开分号路径参数/尾随点空格、关闭编码分隔符或重复头拒绝、关闭 WAF、配置了完整性钉扎却关闭强制检查、审计写入失败改为 `continue`。

`highwall check` 只回答“候选配置能否启动”；`highwall diff` 比较两份配置解析、默认值展开和路径规范化后的**实际生效值**，并回答“切换后哪些字段会变、需要重启还是可热加载、是否削弱了现有安全控制”。比较不含管理 token、Webhook token 等秘密值，只保留环境变量名。

```powershell
python -m highwall diff -c config.json --candidate config.next.json
python -m highwall diff -c config.json --candidate config.next.json --json
```

候选配置会经过完整加载和 TLS/管理 token 检查；无效配置返回 `2`，不会进入比较。排序差异（例如 Host、方法、CIDR 白名单顺序）不会产生虚假变更。

| 退出码 | 含义 | 建议动作 |
|---|---|---|
| `0` | 没有生效值变化 | 可继续其他验收 |
| `1` | 只有可热加载变化，且未检测到安全降级 | 评审 `security_review` 后通过 `SIGHUP` 或 `POST /reload` 应用 |
| `2` | 配置无效或命令行错误 | 修复配置，不启动、不重载 |
| `3` | 存在必须重启的字段；未检测到阻断性安全降级 | 安排滚动重启并复核变更 |
| `4` | 检测到安全降级 | 默认阻止晋级；确认是受控变更后再调整策略 |

安全降级包括关闭 WAF/DLP/限流/只读、关闭 TLS 或降低最低 TLS 版本、扩大 Host/方法/路径/CIDR/Origin 白名单、移除安全头或完整性钉扎、弱化威胁遏制模式，以及放宽路由方法、来源、请求体、并发或限速限制。上游目标、管理面启用、TLS 证书/私钥路径和审计路径变化会进入非阻断的 `security_review`，仍需人工确认。`diff` 是变更审阅工具，不是“配置已无漏洞”的证明。

## 配置热加载与优雅停机

HighWall 支持原子配置重载和排空停机。重载会先完整加载、校验新配置，并构建新的运行时和 TLS 上下文；任一步失败都会保留旧配置和旧连接，进程继续服务。

上线前先运行 `highwall diff`：退出码 `4` 应先按安全降级处理；退出码 `3` 表示本次变更不能只靠热加载，需要滚动重启。

- POSIX 使用 `SIGHUP`；Windows 使用管理面 `POST /reload`（管理面需启用并携带 Bearer token）。
- 可热更新策略、路由、上游、限流、审计、告警、威胁/DDOS 检测、管理 token、TLS 证书内容和路径、超时等。
- 不能热改监听地址/端口、`max_connections`、`max_inflight_requests`、TLS 启用状态和管理面监听；这些变更返回 `rejected` 并提示重启。
- 未变化的限速桶、自动封禁、蜜罐封禁、攻击者标记、熔断器和指标会复用；配置变化的部分重建。旧运行时在在途请求结束后释放。
- `server.shutdown_timeout` 控制停机排空等待，默认 30 秒；超时会关闭剩余连接。排空期间新连接返回 503（TLS 连接直接关闭）。
- 证书轮换：替换证书/私钥文件或修改路径后触发重载，新握手使用新证书；已建立连接保持旧上下文直到结束。

```powershell
curl.exe -X POST -H "Authorization: Bearer $env:HIGHWALL_ADMIN_TOKEN" http://127.0.0.1:18091/reload
```

## 常见问题与排查

**没有收到 Webhook 告警。** 先确认配置文件里 `alerting.enabled=true`，并确认 `HIGHWALL_ALERT_WEBHOOK` 存在于启动 HighWall 的同一个进程环境中；只设置 shell 变量但配置关闭不会发送。再检查接收端是否返回 2xx，以及 `alert_failed_total` / `alert_dropped_total` 是否增长。管理面只用于查看状态，不要暴露到公网。

**没有生成攻击者标记。** 只有 `confirmed` 会写入 `offenders.json`；`suspected` 只做限速或告警。检查请求是否达到 `score_threshold`、`confirm_score` 或 `confirm_after_seconds`，并确认 `offender_path` 对服务账户可写。标记是风险关联，不是认证或永久封禁。

**正常用户被限速。** 指纹按来源 `/24` 或 `/64` 关联，共享 NAT、代理池、监控探针可能被连带影响。先在 `monitor` 模式观察，再调整阈值和槽位；必要时用路由 ACL 或来源例外把正常流量隔离出来。

**为什么 HighWall 不自动处理 DDoS。** 它只做 L7 信号检测和告警；带宽型 L3/L4 DDoS、SYN flood 和清洗必须在 CDN、运营商或清洗中心完成。主机或链路饱和时 HighWall 可能先失联，因此外部心跳监控是必需的。

## 部署原则

1. 先只绑定回环做验收，再绑定业务网卡；不要直接暴露到公网。
2. 使用专用低权限账户运行，配置、审计、证书目录与运行账户分离 ACL。
3. 不要从 WSL 可写目录、共享开发工作区或任何攻击机可写目录启动生产实例。
4. 上游放在回环或私有网段，并用主机防火墙限制“网关 -> 上游”和“运维 -> 管理面”。
5. 生产环境启用 TLS，私钥权限只给服务账户；不要使用自签名证书对外。
6. 保留现有网络隔离和用户/命名空间分离。HighWall 不能替代操作系统边界。
7. 先运行 `highwall check`、`highwall inspect`；配置晋级前再运行 `highwall diff`。配置错误时进程应拒绝启动，而不是降级放行。
8. 把审计日志持续外送或写入不可变存储；本机可写日志无法抵抗同权限攻击者。定期做离线恢复演练。
9. 对高风险写接口优先做路由级只读、方法子集和来源限制；不要让 `GET` 承担删除、转账或改配置等副作用。
10. 指纹/标记先以 `monitor` 观察，确认共享 NAT 和正常自动化流量没有误伤后再启用 `tarpit`；持久标记文件和审计文件使用同一级别的 ACL 保护。
11. DDoS 告警接入外部 NOC，并配置独立于 HighWall 主机的主动心跳；L3/L4 清洗、运营商联动和上游扩容属于本产品之外的能力。

## 测试与冒烟

```powershell
Set-Location <HighWall checkout>
python -m pip install -e ".[dev]"
python -m ruff check highwall scripts tests
python -m mypy
python -m coverage run --branch -m unittest discover -s tests -v
python -m coverage report
```

测试只使用临时目录和临时回环端口，不会修改防火墙、端口转发或外部服务。`coverage report` 从 `pyproject.toml` 读取 80% 的行/分支覆盖率门槛；低于门槛时返回非零。

只验证威胁检测、攻击者标记、慢速槽位、DDoS 状态机和 Webhook 队列：

```powershell
python -m unittest tests.test_threat -v
```

发布前建议再跑配置和语法检查：

```powershell
python -m compileall -q highwall scripts tests
python -m highwall check -c config.example.json
python -m highwall check -c config.example.json --strict
python -m highwall diff -c config.example.json --candidate config.example.json
```

解析器模糊测试使用确定性种子，只把 `HighWallError` 视为预期拒绝；其他异常、超时或崩溃会导致非零退出：

```powershell
python -m scripts.fuzz_parser --iterations 20000 --seed 20261028
```

fuzz 用于发现解析边界上的未处理异常和性能退化，不是形式化证明，也不替代代码审计。

本地性能基线使用临时回环上游和临时端口，不需要外部服务：

```powershell
python -m scripts.benchmark_proxy
python -m scripts.benchmark_proxy --json
```

脚本分别测量直连上游、经 HighWall 的允许请求和 WAF 拦截请求，输出 p50/p95/p99 与吞吐。数字会受当前机器负载、审计落盘、DLP/WAF 规则和 Python 版本影响，只能作为同机回归基线，不是容量 SLA 或采购承诺。

当前测试套件覆盖严格解析、路径参数/尾随点绕过、大小写路由绕过、请求编码、WAF 绕过矩阵、DLP（二进制/UTF-16/响应头/Set-Cookie 误报）、路由限速、HSTS、审计脱敏、路由策略、只读、响应钉扎、熔断状态机、在途/路由并发背压、自定义蜜罐、首击封禁、攻击者指纹/标记/慢速槽位、DDoS 状态机、告警去重与队列背压、管理面、配置生成/覆盖规则、配置 diff 的重启/安全降级分类与宿主审计脚本。Windows 集成测试会真实启动回环网关，验证 TLS 指纹关联、确认后慢速响应、上游零转发、审计落盘、漂移检测、重配备份和停止流程；不修改防火墙、端口转发或外部服务。

跨层回环攻防验收位于 `tests/test_attack_defense.py`：真实 TCP 串联 L4Wall、HighWall 和模拟上游，覆盖 L4 封禁/限速/超时、共享封禁故障隔离、L7 Host/走私/穿越/WAF/DLP/CSRF/XFF，以及直连 HighWall/上游的绕过边界。完整矩阵、实测结果和未验证项见 [docs/ATTACK_TESTING.md](docs/ATTACK_TESTING.md)。

GitHub Actions 在 Ubuntu/Windows 和 Python 3.10–3.12 上执行 Ruff、mypy、覆盖率与完整测试；CodeQL 每周和每次 PR 扫描；Dependabot 每周检查 Actions、Python 开发依赖和 Docker 基础镜像。所有第三方 Actions 固定到提交 SHA，发布镜像附带 SBOM、provenance、cosign 签名和 GitHub attestation。

## 开源许可

HighWall 以 [Apache License 2.0](LICENSE) 开源发布，版权与归属信息见 [NOTICE](NOTICE)。你可以在许可证允许的范围内使用、修改、分发和商业部署；许可证包含明确的专利授权与专利反制条款，软件按现状提供，不附带任何担保。

HighWall 不是“装上就安全”的魔法墙。它提供的是一组能被审计、能被测试、默认拒绝的 L7 不变量，真正的安全仍然来自纵深防御。
