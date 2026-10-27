# HighWall

[English](README.en.md) | 简体中文

[![CI](https://github.com/Fallen-leaves089/highwall/actions/workflows/ci.yml/badge.svg)](https://github.com/Fallen-leaves089/highwall/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) [![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

HighWall 是一个**失败关闭（fail-closed）的 HTTP/1.1 应用层反向代理与防护网关**。它只使用 Python 标准库，目标是把应用入口处最容易出现分歧的解析、策略、资源限制和审计做成可审计的小内核。

当前版本：`0.7.1`。v0.3 把防护目标从“防响应泄漏”扩展为同时覆盖**机密性、完整性和可用性**；v0.4 增加可配置的精确路径蜜罐、首击封禁和有界拖延；v0.5 增加内置蜜罐模板与预设组；v0.6 增加配置生成、实际生效值检查和本地快速部署；v0.7 收紧路径规范化、请求 body 编码、响应 DLP 与审计脱敏，并加入路由级限速和 TLS HSTS。它仍不是已经完成第三方审计的生产级产品。

## 30 秒看懂

HighWall 把入口处最容易出错的解析、默认拒绝、资源上限、审计和响应检查放进一个只依赖 Python 标准库的小进程，适合放在应用前面做一层可审计的 L7 防护。

- **fail-closed**：解析歧义、配置错误或上游失败时返回错误，不静默放行。
- **零第三方运行时依赖**：核心代理只使用 Python 标准库，便于审计和小规模部署。
- **可验证**：自带测试、`highwall check` / `inspect`、本地 quickstart 和 JSONL 审计。

- 适合：给内部服务、静态站、管理面或小型 API 增加一层入口防护。
- 不适合：抗大流量 DDoS、代理 WebSocket/HTTP/2，或替代应用自身的认证授权。

> HighWall 仍是 `0.7.1`，尚未经过独立第三方安全审计。生产使用前请先读 [它不解决什么](#它不解决什么) 和 [部署原则](#部署原则)。

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
| 可用性 | 连接/在途/路由并发上限、速率限制、临时封禁、上游熔断、超时 | 带宽清洗、SYN flood 防护、主机容量、上游高可用与灾备 |

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
- **不能修复**上游应用自身的认证、授权、IDOR、默认口令、密钥泄漏或未修补漏洞。
- **不能保护**已经拿到同主机 root / 同名字空间 / 读进程内存 / 嗅探环回流量的攻击者。它必须和独立用户、命名空间、文件 ACL、网络隔离一起使用。
- **不能防勒索软件或擦除型攻击**。L7 网关无法阻止拥有主机写权限的进程删除文件；必须依赖低权限账户、受控文件夹、EDR、离线/不可变备份和恢复演练。
- **不能替代主机防火墙或网络分段**：客户端 CIDR ACL 只处理已经到达 HighWall 的 HTTP 请求，不处理 DNS 隧道、RPC、原始套接字或其他非 HTTP 流量。
- `read_only` 只按 HTTP 方法阻断 `POST`/`PUT`/`PATCH`/`DELETE`，无法识别通过 `GET` 触发副作用的错误业务设计。
- 完整性钉扎只覆盖配置中精确匹配的静态 `GET` 路径和状态码，不覆盖查询串、动态页面、HEAD、WebSocket 或流式响应。
- 蜜罐只覆盖显式配置的精确路径，不能发现所有扫描；它可能被指纹识别，误触封禁会影响共享 NAT 来源，也不提供高交互 shell、文件落盘或反制能力。
- 熔断器会在上游连续故障时主动返回 503；它是故障隔离，不是 DDoS 清洗或容量保证。
- **不代理** WebSocket、HTTP/2、双向流式响应；检测到 Upgrade 会拒绝。响应会缓冲到 `max_response_bytes`。
- WAF 签名是启发式，不保证覆盖所有变体，可能误报；未知业务建议先 `detect` 观察再 `block`。
- 响应 DLP 也是启发式：只扫描 `response_scan_max_bytes` 限定的响应体前缀和响应头，媒体类型不构成免扫条件，会启发式尝试 UTF-8/Latin-1/UTF-16；`Set-Cookie` 被有意排除以避免登录 JWT 误报。未知编码、分片、二进制和业务自定义格式仍可能漏报。未知业务应先设 `response_scan_mode=detect`。
- 不给上游添加登录、MFA 或授权能力。上游自己的会话安全仍然重要。
- 不自动管理证书；TLS 证书和私钥需要由部署者提供并保护。

## 架构

```text
client / browser
      |
      | HTTP/1.1 (可选 TLS)
      v
+---------------------- HighWall process ----------------------+
| strict parser -> connection/rate/ban + in-flight limits        |
| -> client ACL -> Host/path -> honeypot OR route/read-only -> WAF/body |
| -> bounded upstream client <-> circuit breaker                 |
| -> response framing/sanitizer -> integrity pins -> DLP         |
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
- 写入 PID、日志、配置 SHA-256 和审计文件；重复执行不会重复启动，配置在启动后被改动时 `-Status` 返回异常并提示重启。

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
"admin": { "enabled": true }
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
curl.exe -H "Authorization: Bearer $env:HIGHWALL_ADMIN_TOKEN" "http://127.0.0.1:18091/audit/tail?lines=50"
```

管理 token 只在环境变量中读取；不要写进 `config.json`、命令行或审计日志。token 长度必须是 32–512 个可见非空格 ASCII 字符。

## 容器镜像

版本标签会构建多架构镜像并发布到 GitHub Container Registry（GHCR）。发布页见 [HighWall GHCR package](https://github.com/Fallen-leaves089/highwall/pkgs/container/highwall)，版本说明见 [v0.7.1 Release](https://github.com/Fallen-leaves089/highwall/releases/tag/v0.7.1)。

```bash
docker pull ghcr.io/fallen-leaves089/highwall:0.7.1
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
  ghcr.io/fallen-leaves089/highwall:0.7.1
```

- 生产环境启用 TLS 时，把证书和私钥只读挂载到容器内，并在配置中使用容器内路径。
- 不要暴露管理面端口；管理面默认关闭，开启后也应只在受控网络内访问。
- `latest` 跟随最近发布的版本标签；生产部署应固定版本号。

## 配置要点

- `policy.allowed_hosts`：精确 authority 白名单。`example.com`、`example.com:443`、`www.example.com` 是三个不同的值；Host 大小写会归一化，末尾点会去掉。
- `policy.allowed_path_prefixes`：按完整路径段匹配；建议生产环境收窄到实际业务前缀，不要长期使用 `/`。
- `policy.deny_path_prefixes`：先做路径归一化，再按前缀拒绝。默认覆盖 `.git`、`.env`、`server-status`、部分 actuator 端点。
- `policy.allow_path_parameters` / `allow_trailing_dot_or_space`：默认均为 `false`。只有旧业务确实依赖 `;jsessionid` 或尾随点/空格时才显式打开；兼容模式仅影响路由判据，WAF 仍扫描完整路径。
- `policy.waf_mode`：`detect` 只记录命中，`block` 直接拒绝。第一次接入未知业务建议用 `detect`。
- `policy.trusted_proxies`：只有 HighWall 确实在可信反向代理后面时才填写；不要填写 `0.0.0.0/0`。
- `policy.allowed_client_networks` / `denied_client_networks`：可选的 CIDR ACL，拒绝优先；空列表表示不按来源网段过滤。它是 L7 判据，不替代主机防火墙。
- `policy.allowed_origins`：可选的规范 Origin 白名单，例如 `https://app.example.com`。配置后，`POST`/`PUT`/`PATCH`/`DELETE` 必须带允许的 Origin，跨站写请求会被拒绝；为空时保持原来的非浏览器兼容行为。
- `policy.read_only`：全局只读开关；`routes[].read_only` 只对命中的最长路径前缀生效。它不识别 GET 副作用。
- `policy.routes`：按最长路径前缀选择；可设置 `methods`、`read_only`、`max_body_bytes`、`max_concurrent`、`rate`、`rate_burst` 和 `allowed_client_networks`。路由方法必须是全局 `allowed_methods` 的子集，空路由来源列表会被拒绝而不是静默放行；`rate` 是每客户端每秒令牌数，`rate_burst` 省略时取速率向上取整。
- `policy.honeypot`：默认关闭；启用后按规范化后的精确路径拦截诱饵，支持内置 `presets` 或自定义 `routes`、静态状态码、Content-Type、Body、受限响应头、服务端标识、首击封禁和 0–5000 ms 拖延。命中不访问上游，并绕过普通方法/Content-Type/WAF/只读限制以保留诱捕效果；Host 和客户端 ACL 仍然优先。
- `policy.response_integrity_mode` / `integrity_pins`：对规范化后的 `GET` 路由路径（大小写不敏感）校验 `status` 和响应体 SHA-256；支持 `off`、`detect`、`block`。钉扎值必须随受控发布流程更新。
- `upstream.circuit_breaker`：`failure_threshold`、`window`、`open_seconds` 和 `half_open_max_requests` 控制上游故障隔离；只把超时、连接/协议失败和 5xx 计为失败，4xx 视为上游可达。
- `server.max_inflight_requests`：全局在途请求上限，`0` 表示关闭；应小于 `max_connections` 才能形成独立背压。
- `policy.allowed_body_content_types`：没有 Content-Type 或媒体类型不在列表中的请求体一律拒绝。
- `policy.response_scan_mode` / `response_scan_max_bytes` / `response_scan_headers`：上游响应的秘密/调试信息扫描，分别支持 `off`、`detect`、`block`；只扫描有界前缀，默认 1 MiB。媒体类型不再作为免扫条件，并尝试 UTF-8/Latin-1/UTF-16 解码；响应头默认参与扫描，`Set-Cookie` 固定排除。
- `server.max_connections_per_ip`：单个来源 IP 的并发连接上限；`0` 关闭限制，可信代理来源不计入。它不能替代总连接上限。
- `policy.routes[].max_concurrent`：路由级在途请求上限，`0` 表示关闭，不能超过 `server.max_connections`；超限返回 503 和 `Retry-After`。
- `rate_limit.auto_ban_threshold` / `auto_ban_window` / `auto_ban_seconds`：在时间窗内累计协议或策略错误后临时拒绝该来源；`threshold=0` 关闭。封禁状态只在内存中，重启即清空。
- `upstream.total_timeout`：整个上游交换（连接、响应头、响应体）的绝对上限；`read_timeout` 是单次读取上限。
- `server.tls`：只做服务端 TLS，不替代上游 TLS 校验；证书和私钥路径按配置文件所在目录解析。握手在工作线程内执行并受 `handshake_timeout` 约束，慢握手不会阻塞新的 accept；TLS 启用且未配置 HSTS 时会自动添加一年期 HSTS。
- `audit.path`：相对路径按配置文件目录解析；日志目录必须由服务账户和运维账户保护。`audit.path_mode` 支持 `redact`（默认）、`hash` 和 `exact`；默认模式会清洗/解码路径并脱敏敏感键、后续值和明显高熵段。
- `admin.enabled`：默认关闭；打开后强制回环监听和 token。

完整示例见 [`config.example.json`](config.example.json)。蜜罐配置见 [`docs/HONEYPOT.md`](docs/HONEYPOT.md)，威胁边界见 [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)，部署基线见 [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)，漏洞报告方式见 [`SECURITY.md`](SECURITY.md)。

## 部署原则

1. 先只绑定回环做验收，再绑定业务网卡；不要直接暴露到公网。
2. 使用专用低权限账户运行，配置、审计、证书目录与运行账户分离 ACL。
3. 不要从 WSL 可写目录、Codex 工作区或任何攻击机可写目录启动生产实例。
4. 上游放在回环或私有网段，并用主机防火墙限制“网关 -> 上游”和“运维 -> 管理面”。
5. 生产环境启用 TLS，私钥权限只给服务账户；不要使用自签名证书对外。
6. 保留现有网络隔离和用户/命名空间分离。HighWall 不能替代操作系统边界。
7. 先运行 `highwall check` 和 `highwall inspect`，再启动服务；配置错误时进程应拒绝启动，而不是降级放行。
8. 把审计日志持续外送或写入不可变存储；本机可写日志无法抵抗同权限攻击者。定期做离线恢复演练。
9. 对高风险写接口优先做路由级只读、方法子集和来源限制；不要让 `GET` 承担删除、转账或改配置等副作用。

## 测试

```powershell
Set-Location <HighWall checkout>
python -m unittest discover -s tests -v
```

测试只使用临时目录和临时回环端口，不会修改防火墙、端口转发或外部服务。

当前测试套件覆盖严格解析、路径参数/尾随点绕过、大小写路由绕过、请求编码、WAF 绕过矩阵、DLP（二进制/UTF-16/响应头/Set-Cookie 误报）、路由限速、HSTS、审计脱敏、路由策略、只读、响应钉扎、熔断状态机、在途/路由并发背压、自定义蜜罐、首击封禁、管理面、配置生成/覆盖规则与宿主审计脚本。Windows 集成测试会真实启动回环网关，验证漂移检测、重配备份和停止流程；不修改防火墙、端口转发或外部服务。

## 开源许可

HighWall 以 [Apache License 2.0](LICENSE) 开源发布，版权与归属信息见 [NOTICE](NOTICE)。你可以在许可证允许的范围内使用、修改、分发和商业部署；许可证包含明确的专利授权与专利反制条款，软件按现状提供，不附带任何担保。

HighWall 不是“装上就安全”的魔法墙。它提供的是一组能被审计、能被测试、默认拒绝的 L7 不变量，真正的安全仍然来自纵深防御。
