# L4Wall

L4Wall 是一个**失败关闭（fail-closed）的 TCP L4 防护网关**，用 Python 3.10+ 标准库实现，不依赖第三方运行时包。它放在应用或 HighWall 前面，只放行配置过的监听端口，并对连接行为做准入、限速、超时、封禁和审计。

当前版本：`0.1.0`。这是一个可运行的 MVP，不是经过独立审计的生产级产品。生产使用前请先读 [它不解决什么](#它不解决什么) 和 [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)。

## 为什么需要 L4Wall

HighWall 负责 HTTP/1.1 的 L7 语义：Host、方法、路径、WAF、DLP、响应完整性和 L7 DDoS 信号。它明确不处理 SYN flood、非 HTTP 协议、带宽型 DDoS 和 L3/L4 清洗。

L4Wall 补的是这一段：

- 只开放配置过的 TCP 监听端口，未配置的端口不经过它；
- 在连接建立后、业务协议解析前，先做来源、并发、速率、首字节和空闲超时检查；
- 对多端口扇出、短连接、零字节探测、拒绝风暴和固定节奏做行为评分；
- 把允许、拒绝、限速、封禁和关闭原因写进 JSONL 审计；
- 审计写入失败时默认拒绝新连接，而不是静默放行。

```text
攻击 Agent / 客户端
        |
        v
  L4Wall (TCP 连接准入)
        |
        v
  HighWall (HTTP L7 策略)
        |
        v
  上游应用
```

## 30 秒演示

Windows 单机回环演示，不需要管理员权限，不需要外网：

```powershell
cd subprojects/l4wall
python scripts/demo.py
```

脚本会启动一个临时 echo 上游和两个受保护监听端口，先发一个正常请求，再模拟 Agent 的多端口扇出、短连接和零字节探测，打印审计并验证封禁。任何断言失败都会返回非零退出码。

输出重点类似：

```text
[PASS] normal echo
[INFO] agent probes: 12 connections across web/api
[PASS] source banned: 127.0.0.1/32
[audit] connection_denied ... reason=connection_rate
[audit] connection_closed ... signals=["listener_fanout","zero_byte_probes"]
[audit] source_banned ... reason=agent_confirmed
```

## 快速开始

```powershell
cd subprojects/l4wall
python -m l4wall init --path config.json
python -m l4wall check --config config.json
python -m l4wall run --config config.json
```

`init` 不会覆盖已有配置。生成后至少修改每个 listener 的 `listen_port`、`upstream_host` 和 `upstream_port`。

也可以安装成命令：

```powershell
python -m pip install -e .
l4wall check --config config.json
l4wall run --config config.json
```

## 配置要点

完整示例见 [config.example.json](config.example.json)。

| 配置 | 作用 | 建议 |
|---|---|---|
| `server.listen_host` | 所有 listener 的绑定地址 | 单机先用 `127.0.0.1`；对外服务再显式改 |
| `server.max_connections` | 全局并发连接上限 | 按文件描述符和上游容量设置 |
| `server.max_connections_per_ip` | 单来源并发上限 | 防止单 IP 占满槽位 |
| `server.require_client_allowlist` | 强制每个 listener 配来源白名单 | 生产建议开启 |
| `listeners[].allowed_client_networks` | 来源 CIDR 白名单 | 空表示允许所有未被拒绝的来源 |
| `listeners[].denied_client_networks` | 来源 CIDR 黑名单 | 拒绝优先于允许 |
| `listeners[].first_byte_timeout` | 客户端首字节超时 | 降低慢连接占用 |
| `listeners[].idle_timeout` | 双向空闲超时 | 按业务长连接需求调整 |
| `listeners[].max_connection_seconds` | 单连接最长寿命 | 防止无限期占用 |
| `listeners[].max_bytes_per_direction` | 单向字节上限 | 只做资源上限，不做内容检查 |
| `listeners[].new_connections_per_second` | 单 listener 新建连接速率 | 按正常业务峰值设置 |
| `threat_detection.mode` | `score` / `throttle` / `block` | 先 `score` 观察，再 `block` |
| `threat_detection.agent_*` | Agent 行为评分参数 | 结合审计调阈值，不要照搬 |
| `threat_detection.ban_prefix_v4/v6` | 封禁聚合前缀 | 默认精确封禁；确认网段归属后再用 `/24`、`/64` |
| `threat_detection.shared_bans` | 可选 Redis 共享封禁读取 | 默认关闭；只连私网，本地封禁始终优先 |
| `audit.on_write_failure` | 审计失败策略 | 保持 `fail_closed` |
| `admin.enabled` | 回环管理面 | 只在需要时开启，token 从环境变量读取 |

配置是严格 JSON：未知字段、重复端口、非法 CIDR、非回环管理面都会直接报错，网关不会带着半套策略启动。

`audit.path` 和 `threat_detection.offender_path` 如果写相对路径，会相对 `--config` 所在目录解析，而不是相对启动时的当前目录。这样从快捷方式、计划任务或任意目录启动都能找到同一份审计和封禁文件。

### 共享封禁（可选）

`threat_detection.shared_bans` 让多个 L4Wall 读取同一份 Redis 封禁集合。它默认关闭；启用后仍以本地 `offenders.json` 和内存封禁为第一来源，Redis 只做增量补充。

```json
"shared_bans": {
  "enabled": true,
  "backend": "redis",
  "host": "127.0.0.1",
  "port": 6379,
  "db": 0,
  "key": "l4wall:bans:v1",
  "connect_timeout": 0.5,
  "read_timeout": 0.5,
  "sync_interval_seconds": 1.0,
  "password_env": "",
  "max_payload_bytes": 1048576,
  "max_ttl_seconds": 86400.0
}
```

Redis 值必须是版本化 JSON：

```json
{
  "version": 1,
  "updated": 2000000000.0,
  "entries": [
    {
      "network": "203.0.113.7/32",
      "reason": "agent_confirmed",
      "created": 2000000000.0,
      "expires": 2000000800.0
    }
  ]
}
```

故障隔离不变量：

- Redis 超时、拒绝连接、DNS 失败、空键、坏 JSON 或超大响应：本地封禁继续生效，不清空。
- Redis 返回空数组或同步没有变化：只更新健康指标，不删除本地封禁。
- 远端条目只能新增或延长，不能缩短、改名或删除本地封禁；同一网段取更晚的过期时间。
- 远端前缀不能比 `ban_prefix_v4/v6` 更宽；远端 TTL 会被 `max_ttl_seconds` 截断。
- 封禁表达到 `max_ban_entries` 时优先保留本地条目，远端条目不能挤掉本地封禁。
- 同步在独立后台任务运行；失败只写指标、审计和日志，不取消主服务，也不阻塞连接处理。
- 故障日志在状态切换时写一次，持续故障最多每 60 秒补一条，避免 Redis 故障淹没审计盘。
- 导入成功的远端封禁会原子写入 `offenders.json`，因此 Redis 短期不可用时重启仍保留最后已知封禁。

`password_env` 为空表示不发送 `AUTH`；设置后从环境变量读取密码，配置文件中不保存明文。本实现不提供 Redis TLS，`host` 只能是回环或私网地址，DNS 解析到公网地址会拒绝连接。Redis 必须放在专用管理网或容器内部网络，不能发布公网端口。

监控指标：`l4wall_shared_sync_total`、`l4wall_shared_sync_failures_total`、`l4wall_shared_entries_imported_total`、`l4wall_shared_rejected_entries_total`、`l4wall_shared_connected`、`l4wall_shared_last_success_timestamp`、`l4wall_shared_last_failure_timestamp`。审计事件：`shared_sync_ok`、`shared_sync_failed`、`shared_sync_rejected`、`shared_persist_failed`。

当前实现的是**共享封禁读取端**。把本地封禁自动发布到 Redis、跨节点冲突合并和 L4Wall Controller 仍未完成；不要把它当成已经完成的全自动共享控制面。

显式封禁（本地或共享）在 `threat_detection.enabled=false` 时仍然生效；该开关只关闭新的启发式评分和自动封禁。要解除封禁，删除 `offenders.json` 中对应条目或等待 TTL 到期。

## 能防什么

- **端口面收敛**：只有 `listeners` 里显式配置的端口会被代理，其他端口不会因为 L4Wall 而开放。
- **来源收敛**：CIDR 白名单/黑名单，拒绝规则优先；可选强制每个 listener 配白名单。
- **连接洪泛**：全局并发、单 IP 并发、单 listener 新建连接令牌桶。
- **慢连接占用**：首字节超时、空闲超时、单连接最长寿命。
- **连接型探测**：多 listener 扇出、短连接、零字节探测、拒绝风暴、固定间隔节奏。
- **自动化 Agent 行为**：达到阈值后按 `score` 只记录、`throttle` 延迟、`block` 拒绝并封禁。
- **封禁持久化**：`offenders.json` 原子写入，重启后仍生效；支持 IPv4 `/24`、IPv6 `/64` 聚合。
- **共享封禁读取**：可选从私网 Redis 增量导入，故障隔离、TTL 截断、容量保护和本地优先。
- **审计与排障**：JSONL 固定字段、轮转、敏感字段不落盘；审计失败默认拒绝新连接。
- **回环管理面**：`/healthz`、`/metrics`、`/audit/tail`，Bearer token 从环境变量读取。

## 它不解决什么

- **带宽型 DDoS / SYN flood**：L4Wall 只能看到已经完成 TCP 握手的连接；链路饱和、伪造源 IP 的 SYN flood 和运营商侧拥塞必须在 CDN、清洗中心或运营商处理。
- **全端口可见性**：它只保护配置过的 listener。要覆盖整机所有端口，仍需 Windows 防火墙、WFP、nftables 或云安全组。
- **已失陷主机**：如果攻击者已经能在同一主机上读写进程内存、配置或审计文件，L4Wall 不能建立可信边界。
- **内容与身份**：它不解析 HTTP、不读 payload、不做认证授权；L4 看不到 User-Agent、Cookie 或路径。
- **Agent 身份识别**：这里的 “Agent” 指自动化扫描/爆破/连接洪泛行为，不是对某个 AI 代理的身份认证。会模仿正常流量、使用住宅代理或低频慢速的 Agent 可以绕过启发式评分。
- **TLS 内容**：当前版本不做 TLS 终止、SNI 白名单或 JA3/JA4 指纹；这些属于后续 L5/L6 能力。

## 与 HighWall 的关系

- L4Wall 和 HighWall 是两个独立进程，L4Wall 不修改 HighWall 代码。
- `lite` 串联：`客户端 -> L4Wall -> HighWall -> 上游`，适合单机和小规模。
- `standard` 形态：`客户端 -> HAProxy/Envoy -> HighWall -> 上游`；HAProxy 负责 TLS、HTTP/2、WebSocket 和真实 IP 清洗，L4Wall 作为连接级控制面。完整基线见 [docs/STACK.md](../../docs/STACK.md)。
- L4Wall 是透明 TCP 转发，不会自动写 PROXY protocol 或 `X-Forwarded-For`。`lite` 下 HighWall 看到的来源是 L4Wall 地址，不能据此做真实客户端归属；需要按真实客户端做 L7 限速和封禁时，使用 `standard` 形态。
- `policy.allowed_client_networks` 检查的是 HighWall 解析后的客户端 IP，不是 L4Wall 的 peer 地址。不要把它误填成 L4Wall 的 `/32`；网络层仍必须保证只有 L4Wall 能访问 HighWall。
- 两层审计目前只能按时间戳、listener、来源 IP 近似关联；跨层精确关联 ID 仍是后续工作。

## 测试与验证

```powershell
python -m unittest discover -s tests -v
python scripts/demo.py
python -m l4wall check --config config.json
python -m l4wall inspect --config config.json
```

测试覆盖配置严格性、CIDR 策略、令牌桶、审计轮转、Agent 评分、封禁持久化、回环转发、来源拒绝、连接限速、首字节超时、字节上限、单 IP 并发上限、封禁检查独立于评分开关，以及共享封禁的超时、坏 JSON、超大响应、空键、过期/跨版本条目、TTL 截断和本地优先合并。跨层回环攻防验收见 [docs/ATTACK_TESTING.md](../../docs/ATTACK_TESTING.md)。

## 目录

```text
subprojects/l4wall/
  l4wall/          核心包：config、policy、ratelimit、tracker、shared_state、audit、gateway、admin、cli
  tests/           标准库 unittest
  scripts/demo.py  单机回环演示
  docs/            威胁模型与部署基线
  config.example.json
```

## 安全说明

这是一个 `0.1.0` MVP，尚未经过独立第三方审计。不要在未读威胁模型的情况下直接暴露到公网。安全问题请按 [SECURITY.md](SECURITY.md) 的方式报告。

