# HighWall Deployment Baseline

本文给的是**受保护的 L7 网关**部署基线，不是“装到公网就安全”的一键方案。先按回环验收，再逐步开放。

需要 L4 连接级防护、HAProxy/Envoy 边缘和真实客户端 IP 清洗时，先读 [复合部署基线](STACK.md)；本文件只覆盖 HighWall 自身的 L7 部署。

## 0. 快速部署（实验/验收）

本地实验或回环验收可以使用一条命令完成配置、启动和实际行为验证：

```powershell
Set-Location <HighWall checkout>
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\quickstart.ps1 `
  -UpstreamUrl http://127.0.0.1:8080 `
  -AllowedHost app.internal `
  -WithDemoUpstream
```

`quickstart.ps1` 会：

- 在 `-RuntimeDir`（默认 `.runtime`）生成配置和审计文件；
- 使用 `highwall check` 校验，并用 `highwall inspect` 读取实际生效值；
- 启动回环网关；`-WithDemoUpstream` 时额外启动一次性演示上游；
- 验证非法 Host 返回 403、允许 Host 能到上游、蜜罐状态码符合配置、审计事件已落盘；
- 记录 PID、启动时间、配置 SHA-256 和日志；自动化调用不会等待后台子进程退出。

运行状态和停止：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 -Status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 -Stop
```

这套脚本只服务于实验/验收，不创建服务、计划任务或 ACL，也不修改防火墙。生产实例仍按后文使用专用账户、受保护目录和外部进程管理器。

### 覆盖与参数生效

- `highwall init` 默认拒绝覆盖已有配置；确需覆盖时必须显式使用 `--force`。
- `quickstart.ps1` 默认复用已有配置。命令行传入的上游、监听、Host、方法或蜜罐参数与配置不一致时直接报错，不会静默忽略。
- 要修改已有实例，先 `-Stop`，再显式使用 `-Reconfigure`；脚本只合并命令行显式传入的参数，未指定的路由、TLS、超时、限流、扫描模式和安全头保持原值，旧配置自动备份为 `config.json.bak.<时间戳>`。
- 手工局部修改使用 `python -m highwall init --base config.json --output config.json --force --listen-port 18091`；`--base` 模式只修改显式字段，并在写盘前验证合并结果。若配置包含相对审计或 TLS 路径，输出到另一个目录会被拒绝，避免相对路径悄悄指向新位置。
- `highwall inspect` 输出的是解析、默认值和蜜罐预设展开后的生效值，不是原始文件回显，包含 TLS、超时、路由、WAF、响应扫描、安全头、限流和管理面参数。用它核对“写了但没生效”的情况。
- 配置晋级前运行 `highwall diff -c config.json --candidate config.next.json`：`0` 表示无生效变化，`1` 表示只需热加载，`3` 表示必须重启，`4` 表示检测到安全降级。候选配置会先经过完整校验；`security_review` 中的上游、管理面或审计路径变化仍需人工确认。
- `--force` 是原子替换配置文件；Windows ACL 可能随新文件继承父目录权限。生产环境替换后应重新核对服务账户 ACL；可热改字段通过 `/reload` 生效，监听地址/端口、`max_connections`、`max_inflight_requests` 或 TLS 启用状态变更仍需重启。
- HighWall 支持原子配置重载：POSIX 发送 `SIGHUP`，或调用管理面 `POST /reload`。重载失败会保留旧配置；监听地址/端口、`max_connections`、`max_inflight_requests`、TLS 启用状态和管理面监听仍需重启。`quickstart.ps1 -Status` 仍会比较启动时记录的 SHA-256 与当前文件，并在发现变化时提示重启，这是实验脚本的保守行为，不代表进程不能热加载。

### 配置重载与证书轮换

```powershell
python -m highwall check -c C:\ProgramData\HighWall\config.json
python -m highwall diff -c C:\ProgramData\HighWall\config.json --candidate C:\ProgramData\HighWall\config.next.json
curl.exe -X POST -H "Authorization: Bearer $env:HIGHWALL_ADMIN_TOKEN" http://127.0.0.1:18091/reload
```

- 先在同一个服务环境里确认新配置能通过 `check`，并用 `diff` 确认没有必须重启或阻断晋级的安全降级，再调用 `/reload`；返回 `{"status":"reloaded","generation":N}` 表示已切换。
- 失败返回 `{"status":"rejected","error":"..."}`，旧配置继续服务；检查日志和 `config_reload_failures_total`。
- 证书轮换可替换文件内容或路径后重载；新握手使用新证书，旧连接保持旧上下文直到结束。轮换后用新连接验证证书链和主机名。
- 需要修改监听地址/端口、`max_connections`、`max_inflight_requests`、TLS 启用状态或管理面监听时，使用滚动重启。
- `server.shutdown_timeout` 控制 `SIGINT`/`SIGTERM`/`SIGBREAK` 后的排空等待；排空期间新连接返回 503（TLS 连接直接关闭），超时后剩余连接被关闭。

## 1. 目录与账户

建议把程序、配置、审计、证书分开：

```text
C:\Program Files\HighWall\             # 程序，只读
C:\ProgramData\HighWall\config.json    # 配置，服务账户只读
C:\ProgramData\HighWall\data\          # audit 和运行数据，服务账户可写
C:\ProgramData\HighWall\certs\         # 证书和私钥，仅服务账户可读
```

不要从以下位置启动生产实例：

- WSL 可写目录、映射盘或 9p 共享目录；
- 共享开发工作区或 IDE 可写目录；
- 攻击机可写目录；
- 临时目录或用户可写的“下载”目录。

Windows 可在**明确确认路径后**用 `icacls` 收紧 ACL。下面的命令只是示例，执行前先核对绝对路径和服务账户：

```powershell
# 示例，不要在未确认账户/路径时直接执行
$serviceAccount = 'HIGHWALL-SVC'
icacls 'C:\Program Files\HighWall' /inheritance:r /grant:r "$serviceAccount:(OI)(CI)RX"
icacls 'C:\ProgramData\HighWall\config.json' /inheritance:r /grant:r "$serviceAccount:R"
icacls 'C:\ProgramData\HighWall\data' /inheritance:r /grant:r "$serviceAccount:(OI)(CI)MODIFY"
icacls 'C:\ProgramData\HighWall\certs' /inheritance:r /grant:r "$serviceAccount:(OI)(CI)R"
```

服务账户不应是本地 Administrator，不应拥有 `SeDebugPrivilege`、备份/还原、驱动加载或容器管理权限。

## 2. 配置

推荐用 `init` 生成紧凑配置，再按真实业务收窄：

```powershell
python -m highwall init `
  --upstream http://127.0.0.1:8080 `
  --allowed-host app.internal `
  --listen-host 127.0.0.1 `
  --listen-port 18090 `
  --honeypot-preset common `
  --output 'C:\ProgramData\HighWall\config.json'
```

生成的配置默认包含回环监听、管理面关闭、WAF/DLP 阻断、32 个全局在途槽位、上游熔断和 `common` 蜜罐预设（`ban_seconds=0`）。仍至少核对并按业务修改：

- `upstream.host` / `upstream.port` 指向真实上游；
- `policy.allowed_hosts` 收窄到真实域名/authority；
- `policy.allowed_path_prefixes` 收窄到业务前缀；
- `policy.allowed_methods` 只保留需要的方法；
- `policy.allowed_body_content_types` 只保留业务需要的类型；
- `policy.allow_path_parameters` 和 `policy.allow_trailing_dot_or_space` 默认 `false`。只有上游确实依赖这类路径且已逐项验证路由、只读、完整性和 WAF 边界时才允许打开。
- `policy.allowed_client_networks` 按真实入口网段收窄；`denied_client_networks` 用于明确排除的网段，拒绝优先；不要配置 `0.0.0.0/0` 或 `::/0`；
- `policy.allowed_origins` 填浏览器实际使用的 scheme + authority；配置后写请求必须带匹配的 Origin，curl/API 客户端要么绕过该入口，要么显式提供来源；
- 浏览器跨域写请求会先发 `OPTIONS` 预检；默认 `allowed_methods` 不含 `OPTIONS`，启用 `allowed_origins` 时要显式加入 `OPTIONS`，并确认上游能正确响应预检，否则浏览器会拿到 405；
- `policy.read_only` 适合纯静态或只读窗口；对 `/admin`、`/backup`、删除/审批等前缀优先使用 `routes[].read_only`、方法子集和来源 CIDR，而不是全局关闭写能力；
- 路由必须是全局 `allowed_methods` 的子集；`routes[].allowed_client_networks` 为空是配置错误，不会被静默解释为“不限制”；`max_concurrent=0` 才是关闭路由槽位；`rate=0` 才是关闭路由限速，`rate_burst` 不能单独设置；
- `read_only` 只按方法阻断写请求，不会识别 GET 副作用；有破坏性的 GET 接口必须在上游修正或从入口移除；
- `policy.response_scan_mode` 建议先设 `detect` 观察误报，再切 `block`；`response_scan_max_bytes` 按业务响应大小和 CPU/内存预算调整；`response_scan_headers=true` 才会扫描响应头，`Set-Cookie` 固定不扫描；
- 响应 DLP 不按媒体类型跳过，会尝试 UTF-8、Latin-1 和 UTF-16；启用 `block` 前应验证二进制下载、UTF-16 页面和包含 JWT 的 `Set-Cookie` 登录流程；
- `policy.response_integrity_mode` 默认 `off`；只对计划内、精确路径的静态 GET 响应启用钉扎。先 `detect` 观察，再切 `block`；
- `policy.honeypot` 默认关闭；只使用真实不存在的精确路径。生产启用首击封禁前，先用 `ban_seconds=0` 观察命中与误触，再按 NAT/共享出口规模设置封禁时长；
- 蜜罐诱饵必须是静态假数据，不得包含真实 token、私钥、Cookie 或内部凭据；`delay_ms` 会占用全局在途槽位，不要当作 DDoS 队列；
- `upstream.max_response_bytes` 与 `server.max_connections` 按内存预算调整；
- `server.max_inflight_requests` 设置全局在途上限，建议小于 `max_connections`，否则不会形成额外背压；超限返回 503；
- `upstream.circuit_breaker` 的 `failure_threshold`、`window`、`open_seconds` 和 `half_open_max_requests` 按上游容量和恢复时间调整；熔断期间会主动返回 503；
- `server.max_connections_per_ip` 约束单来源并发；反向代理/LB 来源若在 `trusted_proxies` 中则不按 TCP 来源计数；
- `rate_limit.auto_ban_threshold` 设为 `0` 可关闭“错误累计”自动封禁；它不会关闭 `threat_detection.agent_mode=block` 的定向封禁。启用时按 NAT/共享出口规模调整阈值、窗口和封禁时长；
- `threat_detection` 默认关闭。先以 `mode=monitor` 观察 `threat_suspected` / `threat_confirmed`，再启用 `tarpit`；默认 `containment_seconds=300` 是疑似限速窗口，`confirmed_containment_seconds=900` 是确认后的慢速窗口。`per_actor_tarpit_slots` 和 `global_tarpit_slots` 要与线程、连接数和业务容量匹配；`agent_mode=block` 按来源 IP 封禁，`throttle` 只限制当前指纹/请求形状，轮换 UA 可能重新获得干净配额；
- `threat_detection.offender_path` 指向受 ACL 保护的可写数据目录，例如 `C:\ProgramData\HighWall\data\offenders.json`；不要放在只读程序目录、WSL 可写目录或与审计日志相同的公开目录。标记有 TTL 和容量上限，不是永久封禁源；
- `ddos_detection` 默认关闭。启用后聚合 L7 请求速率、拒绝比例、连接饱和度、TLS 失败和上游错误；默认需要至少 2 类信号，持续 300 秒升级告警，无信号 30 秒恢复。它不识别 L3/L4 来源，也不做带宽清洗；
- `alerting` 默认关闭。启用时必须通过 `HIGHWALL_ALERT_WEBHOOK` 提供 HTTPS URL，可选 `HIGHWALL_ALERT_TOKEN`；不要把 token 写进配置或命令行。`include_client_ip=false` 是推荐默认值，`allow_http=false` 不应在生产打开；
- `audit.path` 指向受保护的数据目录（例如相对配置目录的 `data\\audit.jsonl`），不要与只读 `config.json` 同级写入；
- `audit.path_mode` 默认 `redact`，会解码并脱敏敏感路径段和参数；`hash` 适合只做关联分析，`exact` 只应在明确接受路径进入审计日志后启用；
- `admin.enabled` 默认保持 `false`，需要时再打开。

先验证：

```powershell
cd 'C:\Program Files\HighWall'
python -m highwall check -c 'C:\ProgramData\HighWall\config.json'
python -m highwall check -c 'C:\ProgramData\HighWall\config.json' --strict
```

`check` 不应修改防火墙、创建监听器或启动上游。`--strict` 在存在 `high` 级高危告警时返回 `4`，适合接入企业 CI 或变更门禁；`medium` 级告警仍只提示，不阻断晋级。

高危告警包括：`policy.trusted_proxies` 非空、打开 `allow_path_parameters` 或 `allow_trailing_dot_or_space`、关闭 `reject_encoded_separators` 或 `reject_duplicate_headers`、关闭 `waf_enabled`、配置了 `integrity_pins` 但 `response_integrity_mode=off`、`audit.on_write_failure` 不是 `fail_closed`。`trusted_proxies`、`allowed_origins`、路由/全局来源 CIDR 和路径兼容开关都应按最小范围配置，并在变更后重新验证。

再核对展开后的实际生效值：

```powershell
python -m highwall inspect -c 'C:\ProgramData\HighWall\config.json'
```

重点确认 `server.listen_*`、`upstream.*`、`policy.allowed_*`、`policy.routes`、`policy.honeypot.routes`、`rate_limit`、`audit.path` 和 `admin` 与预期一致。`inspect` 不连接上游、不创建监听器，也不输出管理 token 或蜜罐响应体。

注意：这些是 **L7 判据**。客户端 ACL、Origin 校验和 DLP 都不能替代主机防火墙、DNS 策略、netns 或上游认证；DLP 只读取有界文本前缀，且不再接受压缩上游响应，以免扫描被绕过。

### 完整性钉扎生成

钉扎值是**响应体原始字节**的 SHA-256，不是页面标题、ETag 或文件元数据。先用受控客户端取回未经压缩的响应体，再计算哈希：

```powershell
curl.exe --silent --show-error --fail `
  -H 'Host: app.internal' `
  http://127.0.0.1:18090/assets/app.js `
  --output .\app.js.bin

$digest = (Get-FileHash .\app.js.bin -Algorithm SHA256).Hash.ToLowerInvariant()
$digest
Remove-Item -LiteralPath .\app.js.bin
```

把结果写入 `policy.integrity_pins`：

```json
{
  "path": "/assets/app.js",
  "status": 200,
  "sha256": "替换为 64 位小写十六进制摘要"
}
```

要求：

- 路径必须是精确的规范化 GET 路径；查询串不参与匹配；
- 上游响应不能压缩或动态改变，否则会按策略进入 detect/block；
- 发布流程必须同时更新内容和钉扎值，并保留审计记录；
- 钉扎基线自身也要受 ACL 和变更审查保护，否则攻击者可同时替换内容与基线。

### 自定义蜜罐

在 `policy.honeypot` 中可用 `presets` 一行启用内置模板，也可用 `routes` 覆盖或新增诱饵。命中后 HighWall 直接返回本地静态响应，不连接上游；Host 和客户端 CIDR ACL 仍然优先。

```json
{
  "enabled": true,
  "ban_seconds": 0,
  "presets": ["common"]
}
```

部署要求：

- 诱饵路径必须精确且真实不存在，不要覆盖正常路由；蜜罐优先于普通路径允许/拒绝、方法、Content-Type、Origin、只读和 WAF 判断。
- `common` 包含多个栈的扫描路径，启用前逐项核对真实业务路由；需要更窄范围时选择 `secrets`、`wordpress`、`spring`、`admin`、`devops` 或单个模板名。
- 先设 `ban_seconds=0` 上线观察 `honeypot_hits_total` 和审计事件，确认没有正常用户误触，再启用首击封禁。
- Body 最大 64 KiB；禁止设置网关托管的响应头；响应不反射输入，也不记录请求体、Header、Cookie、Authorization 或查询串。
- 蜜罐不是高交互沙箱、DDoS 防护或取证执行环境。详细边界见 [`HONEYPOT.md`](HONEYPOT.md)，模板清单和参考来源见 [`HONEYPOT-TEMPLATES.md`](HONEYPOT-TEMPLATES.md)。

## 3. 管理 token

管理面默认关闭。启用时，token 必须至少 32 个随机可见字符，通过环境变量注入：

```powershell
$env:HIGHWALL_ADMIN_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
```

生产环境不要把 token 放进：

- `config.json`；
- 命令行参数；
- PowerShell 历史记录；
- 审计日志；
- Git 仓库；
- 与配置相同的可读目录。

如果使用 Windows 服务或计划任务，令牌应由服务账户的环境/受 ACL 保护的启动包装器提供；具体方式取决于你的任务调度器，不要使用全机器可读的明文变量。

管理 listener 必须保持：

```json
"listen_host": "127.0.0.1"
```

不要用端口转发、反向代理或 `netsh interface portproxy` 暴露管理端口。

## 4. TLS

生产环境启用：

```json
"server": {
  "tls": {
    "enabled": true,
    "cert_file": "C:\\ProgramData\\HighWall\\certs\\fullchain.pem",
    "key_file": "C:\\ProgramData\\HighWall\\certs\\privkey.pem",
    "min_version": "TLSv1_2",
    "handshake_timeout": 5.0
  }
}
```

要求：

- 证书链完整，私钥只给服务账户读；
- 不使用生产私钥的自签名证书对接公网；
- 如果前置了 TLS 终止代理，明确设置 `trusted_proxies`，不要让任意客户端伪造 XFF；
- TLS 握手在工作线程内完成，受 `handshake_timeout` 约束；慢握手不会阻塞新的 accept，但仍占用一个连接槽。连接数或单 IP 上限满载时，TLS 监听直接关闭新连接，客户端会看到握手失败或连接重置；
- TLS 启用且没有显式配置 HSTS 时，HighWall 自动添加 `Strict-Transport-Security: max-age=31536000`；如通过 `security_headers` 显式覆盖，必须确认全站 HTTPS 和 `max-age` 策略。

HighWall 到上游的 HTTPS 使用 Python 默认证书校验；本地自签名上游需要另行设计受控 CA，而不是关闭校验。

## 5. Windows 启动方式

HighWall 是普通 Python 进程，不是 Windows SCM 服务。可用任务计划程序、服务包装器或现有进程管理器托管，但必须：

- 使用专用服务账户；
- 工作目录设到安装目录；
- 显式传入受保护的配置文件；
- 失败时停止/重启并记录事件；
- 不把 stdout/stderr 指到攻击者或 WSL 可写目录；
- 不把管理 token 打印到日志。

`scripts/quickstart.ps1` 仅用于本地验收，不是生产服务安装器；不要把 `.runtime` 目录直接当作受保护的生产安装目录。

示例（仅演示任务计划，不要直接复制执行）：

```powershell
$action = New-ScheduledTaskAction `
  -Execute 'C:\Program Files\HighWall\python.exe' `
  -Argument '-m highwall serve -c C:\ProgramData\HighWall\config.json' `
  -WorkingDirectory 'C:\Program Files\HighWall'
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask `
  -TaskName 'HighWall' `
  -Action $action `
  -Trigger $trigger `
  -User 'HIGHWALL-SVC' `
  -RunLevel Limited
```

创建任务、设置 ACL、开放端口都属于系统变更，应先确认路径、账户和回滚方式。

## 6. 网络放置

推荐：

```text
Internet / intranet
        |
   [host firewall / load balancer / DDoS protection]
        |
   HighWall :443 (TLS)
        |
   upstream 127.0.0.1:8080 或私网地址
```

要求：

- 上游只接受 HighWall 所在主机/网段的连接；
- 管理面只允许本机 loopback；
- 不把上游管理端口、数据库、RPC 或调试端口暴露给客户端；
- 保留现有主机防火墙和 WSL/容器隔离；
- 如果要限制出网，HighWall 只需要到上游和证书/时间源的连接。

HighWall 不替代防火墙、netns、用户隔离或上游认证。

## 7. 日志与监控

审计是 JSONL 固定字段，不包含查询串、Cookie、Authorization 或请求体。

- 审计目录使用独立 ACL；
- 设置磁盘容量告警；
- 通过管理面或本地日志采集读取；不要直接暴露日志文件；
- 监控启动失败、`audit_write_failures_total`、`upstream_errors_total`、`blocked_total` 和 `rate_limited_total`；
- 监控 `dlp_detected_total`、`dlp_blocked_total`、`ip_connection_rejections_total`、`auto_bans_total` 和 `auto_ban_rejections_total`；
- 监控 `integrity_detected_total`、`integrity_blocked_total`、`circuit_state`、`circuit_open_total`、`circuit_rejections_total`、`inflight_rejections_total`、`route_rate_limit_rejections_total`、`route_concurrency_rejections_total` 和 `tls_handshake_failures_total`；
- 监控 `threat_detected_total`、`threat_tarpitted_total`、`threat_tarpit_shed_total`、`tarpit_active`、`offender_marks`、`ddos_detected_total`、`ddos_escalated_total`、`ddos_recovered_total`、`alert_sent_total`、`alert_failed_total`、`alert_dropped_total` 和 `alert_queue_depth`；
- 把审计日志持续外送或写入不可变存储；本机可写日志不能抵抗同权限攻击者修改或删除；
- 自动封禁只存在内存中；重启会清空。需要长期封禁时，应使用主机防火墙或上游访问控制，而不是把应用内状态当持久策略；
- 管理 token 轮换：更新服务环境中的 token 后执行 `/reload`；新运行时切换后旧 token 对新请求失效，正在处理的单次管理请求可能完成。
- 监控 `config_reloads_total`、`config_reload_failures_total` 和 `config_generation`；失败重载不会改变生效配置。

### 外部告警 Webhook

建议把确认攻击者、DDoS 疑似的告警接入现有 NOC/值班系统，而不是只在本机看日志。示例（仅演示变量注入，不要把真实 token 写进脚本仓库）：

```powershell
$env:HIGHWALL_ALERT_WEBHOOK = 'https://alerts.example.com/highwall'
$env:HIGHWALL_ALERT_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
python -m highwall serve -c 'C:\ProgramData\HighWall\config.json'
```

接收端应校验 Bearer token、限制请求体大小、把告警写入独立审计，并按 `event` 分流：

- `threat_suspected` / `threat_confirmed`：检查指纹、分数、信号和标记，结合共享 NAT 与业务变更确认是否误报；
- `ddos_suspected`：立即通知值班，开始 5 分钟响应窗口；
- `ddos_escalated`：按 DDoS 预案升级到网络/清洗团队，检查 CDN、上游容量和边缘限流；
- `ddos_recovered`：记录恢复时间，但不要立即撤销所有人工处置，先确认攻击没有转为低频持续。

`containment_window_seconds=300` 是建议响应窗口，不是自动清洗承诺。带宽型 L3/L4 DDoS 必须在运营商或清洗中心处理；HighWall 主机可能先失去可达性，因此必须配置独立于本机的主动心跳和外部告警升级链路。Webhook 发送是尽力而为：队列满、接收端故障或网络中断会导致丢失，相关指标必须报警。

## 8. 宿主只读审计

`scripts/host-audit.ps1` 只读取 Windows 宿主状态，不修改防火墙、端口转发、服务、ACL 或 HighWall 配置。要求 Windows PowerShell 5.1 或更高版本：

```powershell
# 人类可读输出
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\host-audit.ps1 `
  -ConfigPath 'C:\ProgramData\HighWall\config.json' `
  -AuditPath 'C:\ProgramData\HighWall\data\audit.jsonl'

# 机器可读输出
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\host-audit.ps1 -Json
```

检查范围：

- Windows Firewall 三个 profile 是否启用、默认入站是否 `Block`；
- 135/RPC、139/445/SMB、3389/RDP、5985/5986/WinRM 是否监听在非 loopback 地址；
- v4tov4 portproxy 表、RDP/SMBv1/SMB signing/WinRM；
- Defender 实时保护、ASR、Controlled Folder Access 和备份可见性；
- HighWall 代码、配置、审计路径是否存在宽泛读/写 ACE；
- WSL 宿主地址和 netns 边界提示。

退出码：

- `0`：没有达到 `-FailOn` 严重度的 FAIL；
- `1`：存在达到阈值的 FAIL；
- WARN 不会导致非零退出，但必须人工复核，不能当作通过。

脚本无法检查 WSL 内部 loopback、DSH 凭证、进程内存或已植入的持久化；它也不是 EDR、攻击面扫描器或修复工具。

## 9. Linux systemd 示例

`deploy/highwall.service` 是参考单元，不是自动安装器。它假设：

- 程序在 `/opt/highwall`；
- 配置在 `/etc/highwall/config.json`；
- 数据/审计在 `/var/lib/highwall`；
- 运行账户为 `highwall`；
- 不使用 1024 以下特权端口。

根据实际情况修改路径和账户后再安装。

## 10. 验收清单

- [ ] `python -m highwall check` 通过。
- [ ] 企业 CI/变更门禁执行 `python -m highwall check --strict`，没有 `high` 级高危告警；`medium` 告警已逐项评估。
- [ ] 只绑定回环时，正常请求能到达上游。
- [ ] 非允许 Host、方法、路径、Content-Type 被拒绝。
- [ ] 分号路径参数、尾随点/空格和编码分隔符在默认配置下被拒绝；打开兼容开关后的行为已单独测试。
- [ ] 配置客户端 ACL 后，允许网段可访问、拒绝网段返回 403，且可信代理解析符合预期。
- [ ] 配置 Origin 后，写方法缺少/伪造 Origin 返回 403，合法 Origin 可到达上游。
- [ ] 全局只读阻止所有写方法；路由只读只影响命中前缀；路由方法子集和来源 CIDR 生效。
- [ ] 路由级请求体上限和并发槽位返回预期的 413/503，超限请求不增加上游计数。
- [ ] 精确 GET 路径的完整性钉扎在 `detect` 记录、在 `block` 返回 502 且不泄露被替换的响应体。
- [ ] 上游连续 5xx/超时后熔断打开并返回 503；恢复探针成功后状态回到 closed。
- [ ] `server.max_inflight_requests` 超限返回 503，而不是无限排队。
- [ ] `POST /reload` 在配置有语法错误或监听字段变化时返回 `rejected`，旧配置继续服务；成功时 `generation` 增加。
- [ ] 晋级前 `highwall diff` 的退出码符合预期：无变化为 `0`，仅热加载为 `1`，需重启为 `3`，安全降级为 `4`；`security_review` 项已人工确认。
- [ ] 证书轮换后新连接使用新证书，旧连接不被强制中断；排空期间新连接返回 503，在途请求在 `shutdown_timeout` 内完成。
- [ ] 上游返回私钥或调试栈时，DLP 的 `block` 模式返回 502 且不把原文转发给客户端；`detect` 模式只记录。
- [ ] UTF-16 BOM、NUL body 和非 UTF-8/ASCII 声明 charset 被拒绝；DLP 能覆盖响应头、二进制响应体和 UTF-16 响应，并正确跳过 `Set-Cookie`。
- [ ] 单 IP 超过并发上限时返回 503；累计违规达到阈值后临时返回 429，窗口/时长符合配置。
- [ ] 路由 `rate`/`rate_burst` 超限返回 429 和 `Retry-After`，且未命中路由的流量不受该路由桶影响。
- [ ] 一个客户端停在 TLS 握手阶段时，其他客户端仍能完成 TLS 请求；握手超时/失败后连接和 IP 槽位可复用，`tls_handshake_failures_total` 增加。
- [ ] `Transfer-Encoding`、重复 `Content-Length`、Upgrade 被拒绝。
- [ ] 慢头和慢上游能按期限超时。
- [ ] 管理面从非 loopback 不可达。
- [ ] 审计不包含 Cookie/Authorization/查询串/body；`redact` 能遮盖敏感路径，`exact` 仅在明确选择时使用。
- [ ] 证书、配置、审计目录 ACL 正确。
- [ ] TLS 响应带预期 HSTS；若显式覆盖安全头，已核对实际值。
- [ ] `scripts/host-audit.ps1 -Json` 已运行并人工复核；宽泛 ACL、wildcard portproxy 和敏感服务监听均有处置记录。
- [ ] EDR/Defender、受控文件夹或等价保护已启用，离线/不可变备份和恢复演练已验证。
- [ ] 上游只接受网关连接。
- [ ] 确认 DNS、RPC、数据库、原始套接字和其他非 HTTP 流量由主机防火墙或网络隔离单独处理。
- [ ] 现有网络隔离、端口转发和应用靶场未被误改。
- [ ] 威胁检测先以 `monitor` 运行，确认疑似/确认事件、共享 NAT 和正常自动化流量无异常后，再启用 `tarpit`；慢速窗口、槽位上限和 429 行为符合预期。
- [ ] 确认 `offenders.json` 位于受 ACL 保护的可写目录，TTL、最大条目数和备份/恢复流程已核对；标记文件不能被公网或低权限用户读取、替换或删除。
- [ ] Webhook 使用 HTTPS 和随机 Bearer token；接收端能验证 token、处理 `threat_*` 与 `ddos_*` 事件，并监控 `alert_sent_total` / `alert_failed_total` / `alert_dropped_total`。
- [ ] 已演练 5 分钟 DDoS 响应窗口：通知值班、检查 CDN/清洗中心、核对上游容量、保留审计证据、按预案启用边缘限流。
- [ ] 已配置独立于 HighWall 主机的主动心跳；确认 L3/L4 清洗、运营商联动和上游扩容由外部流程负责。

任何“把服务暴露到真实网卡/公网”的动作，都应在这些检查完成并得到明确确认后再执行。
