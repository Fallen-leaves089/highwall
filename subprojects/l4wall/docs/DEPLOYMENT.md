# L4Wall 部署基线

本文给的是单机/小规模部署基线，不是“装到公网就安全”的一键方案。先回环验收，再逐步开放。

## 拓扑

推荐把 L4Wall 放在 HighWall 前面：

```text
客户端
  |
  v
L4Wall:18080  --TCP-->  HighWall:18090  --HTTP-->  上游:8080
```

- 客户端只能访问 L4Wall 的监听端口；
- HighWall 只接受来自 L4Wall 的连接；
- 上游只接受来自 HighWall 的连接；
- 三层都不要直接绑定公网可直连地址，除非有主机防火墙或云安全组兜底。

## 前置条件

- Python 3.10+；
- 不需要第三方运行时包；
- 不需要管理员权限即可运行回环演示；
- 绑定低端口（<1024）或修改主机防火墙需要管理员/root。

## 配置步骤

1. 生成配置：

   ```powershell
   python -m l4wall init --path config.json
   ```

2. 设置 `server.listen_host`：

   - 单机验收：`127.0.0.1`；
   - WSL 内服务：WSL 虚拟网卡地址，或按现有 `hw-drill` 模式只暴露网关端口；
   - 对外服务：明确的私网/公网地址，并配合主机防火墙。

3. 为每个 listener 设置：

   - `name`：审计关联用的稳定名称；
   - `listen_port`：客户端实际访问的端口；
   - `upstream_host` / `upstream_port`：HighWall 或应用的地址；
   - `allowed_client_networks`：生产环境建议只列必要网段；
   - `first_byte_timeout`、`idle_timeout`、`max_connection_seconds`：按协议调整；
   - `max_bytes_per_direction`：按正常业务上限设置。

   相对路径的 `audit.path` 和 `threat_detection.offender_path` 会相对 `config.json` 所在目录解析，便于用计划任务或快捷方式从任意工作目录启动。

4. 先以 `threat_detection.mode=score` 运行，观察审计中的 `signals` 和 `score`，确认健康检查/监控不会误报。

5. 调整阈值后改为 `throttle`，最后再考虑 `block`。

6. 如需管理面：

   ```powershell
   $env:L4WALL_ADMIN_TOKEN = "<long-random-token>"
   ```

   并在配置中设置 `admin.enabled=true`。管理面只允许回环地址；不要把管理端口转发到局域网或公网。

7. 启动：

   ```powershell
   python -m l4wall run --config config.json
   ```

   或使用 `scripts/run.ps1 -Config .\config.json`。

## 共享封禁（可选）

共享封禁默认关闭。需要多节点使用同一份封禁集合时，部署一个只在内网可达的 Redis，并让各 L4Wall 读取同一个键。当前实现只负责**读取和合并**；自动发布本地封禁、L4Wall Controller 和跨节点冲突合并仍待实现。

Redis 部署要求：

- 只绑定回环、私网或容器内部网络，不发布宿主机公网端口；
- 不使用公网托管的 Redis；本实现不支持 Redis TLS；
- 启用持久化并给封禁键留出固定内存，示例：`appendonly yes`、`maxmemory 64mb`、`maxmemory-policy noeviction`；
- 如启用密码，用 `password_env` 指向环境变量，不把密码写进配置；
- Redis 账号只给 `SELECT`、`GET` 权限；当前读取端不需要写权限。

示例（仅说明网络形态，命令需按实际网络调整）：

```powershell
docker run -d --name l4wall-redis `
  --network l4wall-internal `
  --restart unless-stopped `
  -v l4wall-redis-data:/data `
  redis:7-alpine `
  redis-server --appendonly yes --maxmemory 64mb --maxmemory-policy noeviction
```

配置示例：

```json
"shared_bans": {
  "enabled": true,
  "backend": "redis",
  "host": "172.31.0.40",
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

Redis 值是版本化 JSON；完整字段和示例见 [README 的共享封禁章节](../README.md#共享封禁可选)。也可以用管理机写入测试条目：

```powershell
$json = '{"version":1,"updated":2000000000.0,"entries":[{"network":"203.0.113.7/32","reason":"agent_confirmed","created":2000000000.0,"expires":2000000800.0}]}'
redis-cli -h 172.31.0.40 SET l4wall:bans:v1 $json
```

故障与恢复顺序：

1. Redis 故障时不要清空 `offenders.json`，也不要把 `shared_bans.enabled` 改成绕过审计的临时规则；
2. 查看 `l4wall_shared_connected=0`、`l4wall_shared_sync_failures_total` 和 `shared_sync_failed`；
3. 本地封禁和最后已知远端封禁继续生效，数据面不应出现放行或主服务退出；
4. 恢复 Redis 后确认 `l4wall_shared_last_success_timestamp` 前进、`shared_sync_ok` 出现；
5. 复核 Redis 中的条目 TTL、前缀和原因，确认没有污染或过宽封禁。

共享层验证至少要做：

- 停止 Redis，确认新连接仍按本地封禁处理、网关进程不退出；
- 把 Redis 值改成坏 JSON，确认本地封禁不被清空且出现 `shared_sync_failed`；
- 写入空数组，确认本地封禁仍存在；
- 写入过期条目和跨版本文档，确认不会导入；
- 写入超过 `max_ttl_seconds` 的条目，确认过期时间被截断；
- 写入比 `ban_prefix_v4/v6` 更宽的前缀，确认条目被拒绝；
- 写入公网 Redis 地址或让私网域名解析到公网，确认连接被拒绝。

## 网络与防火墙

- 只开放 L4Wall 的 listener 端口；
- 阻断客户端直接访问 HighWall 和上游；
- 在 Windows 上用 Windows Defender Firewall 或 WFP 限制入站；
- 在 WSL 中确认上游绑定在不会转发到 Windows 的地址（例如 `127.0.0.2`），避免 Windows 侧 Agent 绕过网关直连；
- 如果使用云主机，安全组只放行 L4Wall 端口，管理面只允许堡垒机/回环。

## 容量与资源

- 单进程 asyncio，每连接两个 pump 协程；主要资源是文件描述符、内存缓冲和上游连接；
- `server.max_connections` 应小于操作系统文件描述符上限，并留出管理面和 HighWall 的余量；
- `max_connections_per_ip` 防止单来源占满槽位；
- `new_connections_per_second` 和 `new_connections_burst` 按正常峰值设置，不要用演示值；
- 审计文件按 `audit.max_bytes` 轮转，外部监控应同时采集磁盘和 `l4wall_audit_errors_total`。

## 与 HighWall 串联

- L4Wall 的 `upstream_host/upstream_port` 指向 HighWall；
- 网络层只允许 L4Wall 访问 HighWall；不要把 `policy.allowed_client_networks` 误填成 L4Wall 的 `/32`，它检查的是 HighWall 解析后的客户端 IP；
- L4Wall 是透明 TCP 转发，不会自动写 PROXY protocol 或 `X-Forwarded-For`；需要按真实客户端做 L7 策略时，使用 [复合部署基线](../../../docs/STACK.md) 的 `standard` 形态；
- HighWall 的 `allowed_hosts` 仍按业务域名配置；
- 两层审计目前按时间戳、listener 名和来源 IP 近似关联，尚无跨层精确关联 ID；
- L4Wall 不替代 HighWall 的 Host/WAF/DLP/响应完整性策略。

## 验收清单

- [ ] `python -m l4wall check --config config.json` 返回 0；
- [ ] 正常请求能通过 L4Wall 到达上游并返回；
- [ ] 不在白名单的来源被拒绝，审计有 `source_not_allowed`；
- [ ] 第二连接超过单 IP 并发时被拒绝，审计有 `ip_capacity`；
- [ ] 新建连接超过令牌桶时被拒绝，审计有 `connection_rate`；
- [ ] 连接后不发送数据会在 `first_byte_timeout` 后关闭；
- [ ] 超过 `max_bytes_per_direction` 的会话被关闭，审计有 `byte_limit`；
- [ ] 多端口短连接/零字节探测达到阈值后出现 `source_banned`；
- [ ] 重启后 `offenders.json` 中的封禁仍生效；
- [ ] 启用共享封禁后，Redis 停止时本地封禁仍生效，进程不退出；
- [ ] 坏 JSON、空键、超大响应、过期/跨版本/过宽前缀条目不会清空或扩大本地封禁；
- [ ] `shared_bans.host` 只解析到回环或私网地址，Redis 没有公网端口；
- [ ] `l4wall_shared_*` 指标和 `shared_sync_*` 审计已接入告警；
- [ ] 审计轮转后旧文件存在且新文件继续写入；
- [ ] 管理面无 token 返回 401，错误 token 返回 401；
- [ ] 关闭进程时监听端口释放，未完成会话在 `shutdown_timeout` 内被排空/取消。

## 运行手册

1. 每天检查 `connection_denied`、`connection_throttled`、`source_banned` 和 `upstream_error` 的比例；
2. 出现 `agent_suspected` 时先看 `signals`，不要只看分数；
3. 误报集中在健康检查/监控时，优先加来源白名单或调高 `short_connections`/`min_connections`；
4. 确认攻击网段归属后再使用 `/24`、`/64` 聚合封禁；
5. offender 文件损坏时不要删掉了事，先保留证据并检查磁盘/权限；
6. 配置变更前先跑 `check` 和 `inspect`，变更后先回环验收再放量。

## 明确不承诺

- 不承诺抗带宽型 DDoS 或 SYN flood；
- 不承诺识别所有 Agent；
- 不承诺防止已失陷主机上的绕过；
- 不承诺替代主机防火墙、上游认证或 HighWall 的 L7 策略。

