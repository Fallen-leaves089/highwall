# Security Policy

## Supported versions

HighWall 目前是 v0.9 系列（最新版本 `0.9.0`）。只有最新发布版本接收安全修复；旧版本不承诺回补。

## Reporting a vulnerability

请在托管仓库使用**私密安全公告（private security advisory）**联系维护者。仓库建立前，不要公开可直接利用的 PoC、token、证书私钥、完整攻击链或未修复的绕过细节。

报告中请尽量包含：

- 受影响版本、配置和部署拓扑；
- 触发条件、最小复现、预期行为与实际行为；
- 是否有认证/网络前置条件；
- 影响范围（可用性、机密性、完整性、是否可绕过 Host/路径/WAF）；
- 已尝试的缓解方式。

不要提交真实的生产 token、私钥、Cookie、用户数据或未脱敏的审计日志。

## Security properties

HighWall 尝试维持以下不变量：

- **默认拒绝**：未知配置键、无 Host、未允许的方法或路径、没有合法 Content-Type 的请求体都不会转发。
- **单一解析路径**：请求由自己的严格解析器读取，不把模糊的 framing 交给上游；不接受 Transfer-Encoding、Trailer、Expect、Upgrade、编码请求体。带 body 的请求只接受 UTF-8/ASCII charset，并拒绝 UTF-16 BOM、NUL 字节和其他歧义编码。
- **唯一 authority**：Host 先 canonicalize，再做精确 allowlist 匹配。
- **路径唯一解释**：路径经过严格解码、NFKC 和点段检查；默认拒绝分号路径参数、尾随点和尾随空格。Host/来源 ACL 先执行；路由、只读判断和完整性钉扎使用规范化路径，并以大小写不敏感方式比较；上游目标保留原始查询串语义。
- **有界资源**：连接数、头/行/体/响应体、上游总时限、配置大小与 JSON 嵌套深度、审计文件大小和客户端表都有上限。
- **来源约束**：可选的客户端 CIDR 允许/拒绝 ACL 在 Host/WAF 前执行，拒绝优先；该判断只能约束已到达 HighWall 的 HTTP 请求。
- **写入面收敛**：全局或路由级 `read_only` 在转发前拒绝写方法；路由可进一步限制方法子集、来源 CIDR、请求体上限和并发槽位。该判断只按 HTTP 方法工作，不能识别有副作用的 GET。
- **写请求来源校验**：配置 `allowed_origins` 后，写方法必须带规范 Origin；允许列表之外的 Origin 和跨站 Fetch Metadata 写请求会被拒绝。
- **响应不可分裂**：上游头值经过校验，逐跳头和 `Content-Length` 被重建，安全头由网关统一覆盖。
- **传输安全默认值**：TLS 开启且未显式配置 HSTS 时，自动添加一年期 `Strict-Transport-Security`；显式配置仍可覆盖。TLS 握手在工作线程内完成并受 `handshake_timeout` 约束，慢握手不会阻塞接受循环；连接槽位满载时 TLS 连接直接关闭，而不是发送明文 503。
- **静态响应完整性**：可为精确 `GET` 路径钉扎状态码和响应体 SHA-256；`block` 模式不会转发被替换的响应，`detect` 模式保留原响应并审计。
- **响应泄漏收敛**：对响应体的有界前缀和响应头做秘密/调试信息检测，响应体不按媒体类型跳过扫描，并尝试 UTF-8、Latin-1 和 UTF-16；`Set-Cookie` 固定排除以避免把会话 JWT 当泄漏。`block` 模式不转发命中内容，并拒绝压缩或编码歧义的上游响应以避免绕过扫描。
- **故障隔离**：上游连接失败、超时或 5xx 达到阈值后熔断，冷却期只允许有界半开探针；熔断期间明确返回 503 和 `Retry-After`，不把故障继续放大到上游。
- **在途背压**：全局在途请求和路由并发槽位均有硬上限，超限在读取请求体前拒绝，避免处理线程被无限占用；拒绝响应会在 Windows 上有界排空后优雅关闭。
- **滥用状态有界**：单 IP 并发连接、全局/路由令牌桶限速和短时间内累计违规都可限制；临时封禁表与客户端桶有容量上限，重启即清空，不写入持久状态。
- **诱捕隔离**：蜜罐按规范化后的精确路径匹配，Host/来源 ACL 仍优先；内置模板和自定义路由都只返回配置内静态内容，不访问上游、不反射输入、不记录 Header/body/Cookie，并可在首次命中后立即封禁来源。
- **攻击者关联与遏制有界**：指纹只使用 HTTP Header 形状、TLS ClientHello 和来源前缀；Cookie、Authorization、查询串、路径、请求体和 token 不进入指纹或标记。疑似先限速 5 分钟，确认后写入有 TTL 和容量上限的 `offenders.json`，再施加 15 分钟慢速窗口；慢速槽位按攻击者和全局双重限额，满槽返回 429。
- **告警可观测但不阻塞请求**：L7 DDoS 需要多类信号同时成立，告警包含 `ddos_suspected`、`ddos_escalated` 和 `ddos_recovered`，默认给出 300 秒响应窗口；Webhook 使用有界异步队列、HTTPS、禁止重定向和失败重试，队列满时丢弃并计数。
- **变更原子性**：重载先完整加载并校验新配置，再构建新运行时和 TLS 上下文；任一步失败都保留旧配置、旧运行时和旧连接。监听地址/端口、`max_connections`、`max_inflight_requests`、TLS 启用状态和管理面监听不能热改，必须重启。旧运行时在在途请求结束后释放，未变化的限速/封禁/标记/指标会复用。
- **秘密不落审计**：查询串、Cookie、Authorization、请求体和管理 token 不写入审计；路径默认按 `redact` 清洗/解码并脱敏敏感段和路径参数，也可显式选择 `hash` 或 `exact`；管理 token 不出现在 Runtime `repr`。
- **管理面本地化**：管理 listener 只允许 loopback，管理请求还校验 loopback peer 与 Host，使用常量时间摘要比较 Bearer token。
- **失败关闭**：配置文件必须是普通文件，不能被符号链接/重解析点替换；配置/审计路径不可用时启动失败。

## Deployment assumptions

这些属性只在正确部署下成立：

- 服务进程使用专用低权限账户，不拥有调试、备份、内核驱动或容器管理权限；
- 配置、审计、证书和私钥所在目录不被低权限用户或攻击机写入；
- 主机启用 EDR/Defender、受控文件夹或等价保护，并有经过恢复演练的离线/不可变备份；
- 上游服务不信任未经 HighWall 校验的旁路连接；
- 管理面不通过端口转发、反向代理或公网暴露；
- 如启用 `allowed_client_networks`，其 CIDR 与真实网络放置一致；如启用 `allowed_origins`，浏览器实际使用的 scheme/host/port 已纳入白名单；
- 操作系统、Python、上游应用和证书保持更新；
- 网络隔离、主机防火墙、用户/命名空间分离仍然存在。

## Non-goals and known limitations

- 不是抗 DDoS 设备；没有流量清洗、SYN flood 防护或带宽保证。
- 不修复上游认证、授权、业务逻辑、默认口令、密钥管理或内存安全漏洞。
- 不能阻止勒索软件、擦除程序或已取得主机写权限的进程删除/破坏文件；这不是 L7 代理能建立的边界。
- WAF 是启发式检测，不是完备证明；可能漏报和误报。
- 完整性钉扎只适用于配置中精确匹配的静态 GET 路径；动态页面、查询串、HEAD、编码内容或未配置路径不受保护。
- `read_only` 只阻断写方法和配置为不安全的方法，不能识别通过 GET 触发的业务副作用。
- 响应 DLP 不是数据分类系统：只检查有界响应体前缀和响应头，启发式尝试 UTF-8/Latin-1/UTF-16，不保证覆盖任意编码、压缩、分片、二进制或流式内容中的秘密；`Set-Cookie` 被有意排除，因此不会拦截其中的会话 token。
- 不代理 WebSocket、HTTP/2 或流式响应；响应会缓冲，受 `max_response_bytes` 限制。
- 熔断器会在故障时主动拒绝请求并返回 503；它不是 DDoS 清洗、带宽保证或上游高可用方案。
- 不能防御已获得运行主机 root、可读进程内存、可嗅探回环、可修改二进制或可替换配置的攻击者。
- 不能替代防火墙、netns、DNS 控制、RPC 端口隔离或主机出站策略；应用层 ACL 对 DNS 隧道和任意 TCP/UDP 流量无效。
- 路由限速和自动封禁只存在于进程内存，重启即清空；它们也不是带宽或连接表容量防御。
- 保留原始查询串是为了不改变上游业务语义；WAF 只保证扫描重复解码视图，不代表查询串被重写或语义规范化。
- HSTS 只在客户端遵守、TLS 配置正确且全站 HTTPS 时生效，不会修复证书错误或阻止首次明文访问；它也不能替代浏览器和上游的传输安全配置。
- 慢 TLS 握手仍会占用一个连接槽和线程，受 `max_connections`、`max_inflight_requests` 和 `handshake_timeout` 共同限制；这不是 SYN flood 或 DDoS 防御。
- 自动封禁可能被 NAT/代理后的共享来源放大影响；启用前应结合真实来源识别和业务流量评估阈值。
- 蜜罐只覆盖显式配置的精确路径，可能被指纹识别；首击封禁会连带影响共享 NAT 来源，`delay_ms` 也会占用在途槽位。它不是高交互沙箱、取证执行环境或 DDoS 防御。
- 指纹不是身份，也不保证唯一或不可伪造。攻击者可轮换 Header/TLS 形状、代理池或 `/24`、`/64` 来源；共享 NAT 或正常自动化也可能被关联和限速。标记只能用于风险关联，不能作为认证、归因或司法证据。
- 慢速通道只能拖慢读取完整响应的客户端，攻击者可以关闭连接、并发重试或轮换指纹；`tarpit` 槽位满时会返回 429。`containment_seconds=300`、`confirmed_containment_seconds=900` 是策略窗口，不是对攻击者的硬性时间保证。
- DDoS 告警只覆盖到达 HighWall 的 L7 信号，不识别真实攻击来源，也不清洗带宽、SYN flood 或运营商侧流量。链路/主机饱和时 HighWall 可能先失去可达性，必须配置独立于本机的外部心跳，并由 CDN、清洗中心或运营商处置 L3/L4。
- Webhook 是尽力而为的通知通道：队列有界、只重试一次，网络故障或接收端不可用时会丢失告警并增加 `alert_failed_total` / `alert_dropped_total`，不能替代外部心跳和值班升级流程。
- 不自动轮换上游密钥、管理 token 或证书；这些需要部署流程处理。
- 热加载只替换配置和证书，不修复已建立连接、上游进程或宿主问题；证书轮换只影响新握手，旧连接会继续使用旧上下文直到结束。审计路径热切换时，旧运行时的在途请求仍写入旧文件，可能短暂产生两份日志。
- 热加载不能改变监听地址/端口、`max_connections`、`max_inflight_requests`、TLS 启用状态或管理面监听；这些变更会返回 `rejected`，必须通过滚动重启完成。重载期间新连接可能短暂使用旧配置，直到原子切换完成。
- 内置蜜罐预设只提供常见路径外形，不能保证与真实业务路由不冲突；启用前必须逐项核对。它们不能替代独立诱捕网络或高交互沙箱。
- 当前没有第三方安全审计，不应把 `0.9.0` 当作生产级“绝对高防”承诺，也不应宣称“全球最精确指纹”。

## Hardening checklist

- [ ] 生产实例从受 ACL 保护的安装目录启动，不从 WSL 可写目录启动。
- [ ] 使用专用低权限账户，禁用不必要的特权。
- [ ] `admin.enabled` 仅在需要时打开，listener 保持 `127.0.0.1`。
- [ ] 管理 token 通过受保护的环境/服务配置注入，至少 32 个随机字符。
- [ ] 热加载前先运行 `highwall check`；通过 `POST /reload` 或 `SIGHUP` 后确认返回 `reloaded`，并观察 `config_reloads_total` / `config_reload_failures_total`。
- [ ] 监听地址/端口、`max_connections`、`max_inflight_requests`、TLS 启用状态或管理面监听变更使用滚动重启，不要依赖热加载。
- [ ] 证书轮换后用新连接验证证书链和主机名；不要假设已建立的 TLS 连接会立即切换到新证书。
- [ ] 用 `server.shutdown_timeout` 验证排空期间新连接返回 503、在途请求完成、超时后剩余连接被关闭。
- [ ] `policy.allowed_hosts`、`allowed_path_prefixes`、`allowed_methods` 收到业务实际需要的最小集合。
- [ ] 保持 `allow_path_parameters=false`、`allow_trailing_dot_or_space=false`；只有在逐项验证上游兼容性后才允许打开，并重新测试路由、只读和完整性边界。
- [ ] 对备份、管理、删除等高风险前缀配置路由级 `read_only`、方法子集和来源 CIDR；不要把 GET 当作安全方法。
- [ ] 为昂贵或高风险路由配置 `rate` / `rate_burst`，并用真实流量验证 429/`Retry-After` 不会误伤共享 NAT 来源。
- [ ] 先用 `waf_mode=detect` 观察，再切到 `block`。
- [ ] 为浏览器业务配置 `allowed_origins`；非浏览器 API 客户端使用独立入口或明确评估 Origin 策略。
- [ ] 按真实来源网段配置客户端 ACL；不要用应用层 ACL 代替主机防火墙。
- [ ] 先用 `response_scan_mode=detect` 检查误报，再切到 `block`；确认上游不依赖压缩响应，并验证响应头和 UTF-16/二进制响应不会被绕过。
- [ ] 对静态关键页面先计算并审核 SHA-256，再启用 `response_integrity_mode=block`；发布时同步更新钉扎值。
- [ ] 设置 `server.max_inflight_requests` 和路由 `max_concurrent`，为昂贵接口保留独立背压。
- [ ] 根据上游容量和恢复时间设置熔断阈值/冷却时间，并监控 503 与 `circuit_state`。
- [ ] 调整 `max_connections_per_ip` 和自动封禁阈值，避免 NAT/共享出口被误伤。
- [ ] 蜜罐只使用确认真实不存在的精确路径；先以 `ban_seconds=0` 观察审计和命中指标，再启用首击封禁。
- [ ] 蜜罐诱饵不得包含真实凭证、私钥、Cookie 或可横向移动的内部信息；延迟保持最小必要值。
- [ ] 威胁检测先以 `mode=monitor` 观察 `threat_suspected` / `threat_confirmed` 和共享 NAT 误报，再切换 `tarpit`；确认 `per_actor_tarpit_slots`、`global_tarpit_slots` 与线程/连接预算匹配。
- [ ] `offender_path` 放在受 ACL 保护的可写数据目录；标记 TTL、最大条目数和备份/恢复流程已确认，不能把标记文件当作认证或永久封禁源。
- [ ] 启用告警时使用 HTTPS Webhook 和随机 Bearer token，验证 5 分钟升级窗口、恢复事件和 `alert_sent_total` / `alert_failed_total` / `alert_dropped_total`；不要把管理面暴露到公网。
- [ ] 对 L7 DDoS 告警建立值班 runbook：5 分钟内确认 CDN/清洗中心、上游容量、审计证据和边缘限流；L3/L4 清洗与运营商联动由外部流程负责。
- [ ] 配置独立于 HighWall 主机的主动心跳；主机或链路饱和时仍能由外部系统触发告警和升级。
- [ ] 生产启用 TLS；证书私钥仅服务账户可读。
- [ ] 确认 TLS 响应的 HSTS 生效；如显式覆盖 `Strict-Transport-Security`，确认其 `max-age` 与全站 HTTPS 策略一致。
- [ ] 用一个不完成握手的连接占住槽位，确认其他客户端仍可建立 TLS 连接；握手失败或超时后连接、在途和 IP 槽位会释放，`tls_handshake_failures_total` 增加。
- [ ] 审计目录独立、受 ACL 保护、有容量和轮转策略。
- [ ] 保持 `audit.path_mode=redact` 或 `hash`；仅在接受敏感路径进入日志的风险后才使用 `exact`。
- [ ] 审计日志持续外送或写入不可变存储，并定期验证日志完整性和恢复流程。
- [ ] 启用 EDR/Defender、受控文件夹或等价保护；维护离线/不可变备份并做恢复演练。
- [ ] 运行 `scripts/host-audit.ps1 -Json`，人工复核端口转发、RPC/SMB/RDP 监听和宽泛 ACL。
- [ ] 上游只接受 HighWall 所在主机/网段的连接。
- [ ] 不对公网开放管理面；不使用端口转发绕过 loopback 限制。
- [ ] 监控 `highwall_upstream_errors_total`、`highwall_rate_limited_total`、`highwall_dlp_blocked_total`、`highwall_integrity_blocked_total`、`highwall_circuit_state`、`highwall_circuit_rejections_total`、`highwall_inflight_rejections_total`、`highwall_route_rate_limit_rejections_total`、`highwall_tls_handshake_failures_total`、`highwall_auto_bans_total`、`highwall_threat_detected_total`、`highwall_threat_tarpitted_total`、`highwall_threat_tarpit_shed_total`、`highwall_tarpit_active`、`highwall_offender_marks`、`highwall_ddos_detected_total`、`highwall_ddos_escalated_total`、`highwall_ddos_recovered_total`、`highwall_alert_sent_total`、`highwall_alert_failed_total`、`highwall_alert_dropped_total`、`highwall_config_reloads_total`、`highwall_config_reload_failures_total`、`highwall_config_generation`、`highwall_drain_rejections_total`、`highwall_audit_write_failures_total` 和磁盘余量。
