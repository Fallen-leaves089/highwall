# HighWall + L4Wall 复合部署基线

本文是 B 方案的实施基线：**HAProxy/Envoy 做数据面，L4Wall 做连接级策略控制面，HighWall 继续做 HTTP/1.1 L7 防护**。它描述信任边界、入口、真实客户端 IP、直连封堵、封禁同步、故障策略和验收方法。

这不是第三方审计报告，也不是“绝对无漏”的承诺。目标是让每个入口都有归属、有默认拒绝、有审计、有验证，避免“以为覆盖了、实际可绕过”的路径。

## 1. 结论

- 标准生产形态面向 Linux/容器；Windows 和小规模继续使用 L4Wall `lite`。
- HighWall 不重写。HTTP/2、TLS、WebSocket 由边缘代理处理；需要检查的 HTTP 流量归一化成 HTTP/1.1 后交给 HighWall。
- L4Wall 在标准形态中**不应有公网数据口**；它读连接日志和指标，做评分、封禁和审计，通过数据面接口下发策略。
- 所有真实客户端 IP 只能由可信边缘写入；客户端自带的转发头一律丢弃。
- 上游只允许 HighWall 访问，HighWall 只允许边缘代理访问。

入口：轻量形态见 [L4Wall README](../subprojects/l4wall/README.md)，标准部署骨架见 [deploy/standard/README.md](../deploy/standard/README.md)。

## 2. 适用目标

本基线针对约 80% 的自托管 Web/API 场景：

- HTTP/1.1、HTTP/2、TLS、WebSocket；
- IPv4 和 IPv6；
- 单机到小集群，约 1k–10k 并发；
- Linux/容器为主，Windows 可开发和小规模运行；
- 需要真实客户端 IP、连接级限速、共享封禁、基本可观测性和旁路验证。

## 3. 非目标

- 带宽型 DDoS、SYN flood、运营商侧拥塞；
- UDP、QUIC/HTTP3；
- 多租户全局调度、跨地域 Anycast；
- 全量 WebSocket 消息内容检查；
- 替代应用认证、授权、会话安全和主机 EDR；
- 已失陷主机上的可信边界。

## 4. 信任边界

```text
客户端
  |
  v
云清洗 / 主机防火墙 / 安全组
  |  只放行 80/443（示例为 8080/8443）
  v
HAProxy / Envoy
  TLS、HTTP/2、WebSocket、PROXY v2
  删除客户端转发头，写入可信 X-Forwarded-For
  |
  v
HighWall
  HTTP/1.1、WAF、DLP、L7 限速、蜜罐、审计
  |
  v
上游应用
  只允许 HighWall 访问

L4Wall Controller
  读取边缘连接日志/指标，做行为评分、两阶段封禁、审计
  通过数据面接口下发封禁

共享状态（standard）
  SQLite WAL（单机）或 Redis（多机）
```

信任规则：

- 边缘代理是唯一可信的客户端 IP 来源。
- HighWall 只信任边缘代理的转发头，不信任客户端直接提交的转发头。
- L4Wall 管理面只信任回环或专用管理网。
- 上游不信任公网，只信任 HighWall。

## 5. 部署形态

| 形态 | 数据面 | 控制面 | 适用 | 当前状态 |
|---|---|---|---|---|
| `lite` | Python L4Wall 直接转发 | L4Wall 自身 | 单机、小规模、Windows | 已实现并通过测试 |
| `standard` | HAProxy/Envoy | L4Wall Controller | Linux/容器、单机或小集群 | 部署骨架已提供，控制面待接入 |
| `scale` | Envoy/Kubernetes | L4Wall Controller + 共享状态 | 多节点、水平扩展 | 后续里程碑 |

`standard` 的第一阶段只保证：边缘入口、真实 IP、网络闭环、L7 防护和验收脚本。L4Wall 的 Redis 共享封禁**读取端**已经实现，但 Controller、自动发布和动态封禁下发仍属于下一阶段，不能把当前骨架当成完整控制面。

## 6. 端口与入口

### lite

| 入口 | 默认地址 | 说明 |
|---|---|---|
| L4Wall 数据面 | `127.0.0.1:18080` | 对外入口，按实际改成私网/公网地址 |
| HighWall | `127.0.0.1:18090` | 只允许 L4Wall 访问 |
| 上游 | `127.0.0.1:8080` | 只允许 HighWall 访问 |
| L4Wall 管理面 | `127.0.0.1:18091` | 回环、Bearer token，默认关闭 |

### standard

| 入口 | 默认地址 | 是否发布 | 说明 |
|---|---|---|---|
| 边缘 HTTP | `0.0.0.0:8080` | 是 | 示例入口，生产改为 80/443 |
| 边缘 HTTPS | `0.0.0.0:8443` | 可选 | 需要证书后启用 |
| HighWall | `172.30.0.20:18090` / `172.31.0.20` | 否 | 边缘网只允许 HAProxy，上游网只允许上游 |
| 上游 | `172.31.0.30:18080` | 否 | `internal` 网络，只允许 HighWall 访问 |
| HAProxy 管理 socket | `/var/run/haproxy/admin.sock` | 否 | 仅容器/本机管理 |

硬规则：

- 主机防火墙或云安全组只放行边缘端口。
- HighWall 和上游不映射到宿主机公网端口。
- 所有 listener 必须显式绑定地址；不要无意识地使用 `0.0.0.0`。
- IPv4 和 IPv6 使用同一套拒绝规则。

## 7. 真实客户端 IP

标准形态由 HAProxy 做三件事：

1. 删除客户端提交的 `X-Forwarded-For`、`Forwarded`、`X-Real-IP`；
2. 写入唯一的可信 `X-Forwarded-For: <客户端地址>`；
3. 写入 `X-Forwarded-Proto` 和 `X-Forwarded-Host`。

HighWall 侧：

- `policy.trusted_proxies` 只填 HAProxy 的固定地址或最小网段；
- `policy.max_xff_hops` 设为实际代理跳数，不要放宽到无界；
- `policy.allowed_client_networks` 检查的是**解析后的客户端 IP**，不是 HAProxy 的 peer 地址。不要把它填成 HAProxy 的 `/32`，否则所有真实客户端都会被拒绝。
- 客户端直连 HighWall 时，peer 不在 `trusted_proxies` 中，XFF 不会被采信；但网络层仍必须禁止直连。

注意：`highwall check --strict` 会把非空 `trusted_proxies` 判为高风险并返回 4。这是预期的强制复核，不是配置错误；只有确认 HighWall 只被该边缘地址访问后才允许晋级。

验收时必须发送伪造头：

```text
X-Forwarded-For: 203.0.113.9
```

预期：上游和审计看到的是真实连接来源，不是 `203.0.113.9`；伪造来源不能获得独立限速额度或绕过封禁。

## 8. 直连与旁路

### 直连 L4Wall 数据口

- `standard` 形态下 L4Wall 不应有公网数据口；如果能直连，按配置漏洞处理。
- `lite` 形态下 L4Wall 就是入口；必须绑定正确地址并配置来源白名单。
- 不要把 `lite` 和 `standard` 同时暴露成两条可绕过的路径。

### 直连 L4Wall 管理口

- 只绑定 `127.0.0.1` 或专用管理网；
- 必须使用 Bearer token；
- 远程管理走 VPN、跳板机或 mTLS；
- token 泄露时先轮换，再查审计；
- 管理面默认关闭，不用时不启动。

### 直连 HighWall 或上游

- 直连 HighWall 会绕过边缘的 TLS、HTTP/2、XFF 清洗和连接限速；
- 直连上游会绕过全部 L7 策略；
- 两者都必须在网络层拒绝，而不是只靠应用层提示。

推荐验证：

- 从非边缘主机连接 HighWall 端口，应超时或拒绝；
- 从非 HighWall 主机连接上游端口，应超时或拒绝；
- 从公网扫描宿主机，只看到边缘端口；
- 容器环境检查 `docker compose ps` 和端口映射，确认 HighWall/上游没有 `0.0.0.0` 发布。

## 9. 封禁与共享状态

当前状态：

- `lite`：L4Wall 本地 `offenders.json`，HighWall 本地 `offenders.json`，两份状态不自动同步。
- L4Wall 已提供可选的私网 Redis 共享封禁**读取端**：后台拉取版本化 JSON，只增量合并，故障不进入数据面。
- L4Wall 尚未提供本地封禁自动发布、冲突合并和 Controller；当前部署骨架仍不包含这些控制面组件。
- HighWall 的 L7 封禁仍独立保存，尚未与 L4Wall 共享集合自动合并。

已实现的读取端不变量：

- Redis 超时、拒绝连接、DNS 失败、空键、坏 JSON 或超大响应：保留本地和最后已知封禁，不清空。
- 本地封禁始终优先；远端只能新增或延长，不能缩短、改名或删除本地封禁，也不能挤掉本地容量。
- 远端前缀不能比 `ban_prefix_v4/v6` 更宽，TTL 受 `max_ttl_seconds` 截断，默认精确 IP。
- 同步在独立后台任务运行，失败只写指标、审计和节流日志，不取消主服务。
- 导入成功的远端封禁落入本地 `offenders.json`，Redis 短期不可用时重启仍保留最后已知封禁。

共享读取端指标：`l4wall_shared_sync_total`、`l4wall_shared_sync_failures_total`、`l4wall_shared_entries_imported_total`、`l4wall_shared_rejected_entries_total`、`l4wall_shared_connected`、`l4wall_shared_last_success_timestamp`、`l4wall_shared_last_failure_timestamp`。审计事件：`shared_sync_ok`、`shared_sync_failed`、`shared_sync_rejected`、`shared_persist_failed`。

配置和故障演练见 [L4Wall 部署基线](../subprojects/l4wall/docs/DEPLOYMENT.md#共享封禁可选)。

目标模型：

- 单机使用 SQLite WAL；多机使用 Redis；
- 记录 canonical IP/前缀、原因、阶段、分数、过期时间、来源节点；
- 默认精确 IP，不默认 `/24` 或 `/64` 聚合；
- 封禁 TTL 到期自动恢复；
- 共享状态不可用时，保留最后一次已知封禁，不清空；新策略暂停下发并告警。

### Controller 接口契约

| 项 | 约定 |
|---|---|
| 输入 | 边缘 JSON 日志或指标：时间、来源、frontend/backend、上下行字节、持续时间、状态、终止原因 |
| 输出 | deny map 条目：IP/前缀、TTL、原因、阶段、分数、来源节点 |
| 审计 | 每次封禁、延长、解除、下发失败都写 JSONL |
| 失败 | 保留最后已知封禁；停止新策略并告警，不清空数据面 |
| 安全 | 只接受边缘日志/管理网输入；不解析公网 HTTP 内容；管理接口只回环或 mTLS |

Controller 不应成为新的公网入口。它的输入是可信边缘产生的结构化事件，输出是受限的封禁策略；任何“让客户端直接提交评分事件”的设计都应拒绝。

## 10. 审计与关联

已有：

- HighWall 生成 `request_id`，写 JSONL 审计；
- L4Wall 写连接级 JSONL 审计，包含 listener、来源、决策、信号和原因。

尚未完成：

- 跨层统一的 `connection_id`；
- 边缘请求 ID 透传到 HighWall 审计；
- L4Wall Controller 与 HighWall 的封禁事件关联。

在完成前，跨层排障只能按时间、来源、listener、路径近似关联，不能声称已经做到精确追踪。

## 11. 故障与降级

| 故障 | 行为 | 必要动作 |
|---|---|---|
| 边缘代理不可用 | 入口不可达 | 告警、恢复、检查 VIP/健康检查 |
| HighWall 不可用 | 返回 503 或连接失败 | 告警，不要绕过 HighWall 直连上游 |
| L4Wall Controller 不可用 | 已有规则继续生效，新封禁停止 | 告警，保留最后已知策略 |
| 共享状态不可用 | 保留最后已知封禁，停止新策略 | 告警，不要清空封禁 |
| 审计盘满 | HighWall/L4Wall 失败关闭 | 扩容、轮转、恢复后验证 |
| 配置错误 | 拒绝启动或热加载拒绝 | 保留旧配置，回滚 |
| 证书过期 | TLS 握手失败 | 监控到期时间，提前轮换 |

失败关闭是安全默认值，但会放大可用性风险。生产必须同时有监控、容量和恢复流程。

## 12. 上线检查清单

- [ ] 所有 listener 有明确归属和允许来源。
- [ ] 主机防火墙/安全组默认拒绝，只放行边缘端口。
- [ ] HighWall 和上游没有公网端口映射。
- [ ] HAProxy 删除客户端转发头并写入可信 XFF。
- [ ] HighWall 的 `trusted_proxies` 只包含边缘地址。
- [ ] `allowed_client_networks` 没有被误填成边缘地址。
- [ ] L4Wall 管理面只回环/管理网，token 不在配置或命令历史里。
- [ ] 审计目录有配额、轮转和告警。
- [ ] 证书有效期和轮换流程已验证。
- [ ] 封禁默认精确 IP，聚合前缀有业务依据。
- [ ] 旁路、伪造 XFF、直连 HighWall/上游测试通过。
- [ ] 并发、PPS、p99 延迟基线已记录。

## 13. 攻击者视角验收

标准骨架：

```powershell
cd deploy/standard
docker compose up --build -d
python verify.py
```

重点确认：

- 正常请求经边缘到达上游；
- 伪造 `X-Forwarded-For` 不改变真实来源；
- 宿主机的 HighWall/上游端口不可达；
- 日志和审计能定位拒绝原因；
- 停止 HighWall 后入口失败关闭，而不是绕过；
- 停止边缘代理后入口不可达，而不是直连上游。

本地回环复合链路（无需 Docker）：

```powershell
cd <仓库根目录>
python -m unittest tests.test_attack_defense -v
```

覆盖 L4 来源/并发/速率/首字节/字节上限/零字节探测/扇出/持久化、共享封禁导入与故障隔离、L7 Host/走私/穿越/WAF/DLP/CSRF/XFF，以及直连 HighWall/上游的绕过边界。完整矩阵、实测结果和未验证项见 [ATTACK_TESTING.md](ATTACK_TESTING.md)。

`lite`：

```powershell
cd subprojects/l4wall
python -m unittest discover -s tests -q
python scripts/demo.py
python -m l4wall check --config config.example.json
```

## 14. 当前实现状态

| 能力 | 状态 | 说明 |
|---|---|---|
| L4Wall lite | 已实现 | 65 个测试、演示、配置校验通过 |
| L4+L7 回环攻防验收 | 已实现 | 26 项端到端测试；真实 TCP 串联 L4Wall/HighWall/模拟上游 |
| 标准拓扑攻防验收 | 未验证 | Docker daemon 不可用；未做容器、HAProxy、TLS、HTTP/2、WebSocket |
| L4Wall 子项目迁移 | 已完成 | `subprojects/l4wall` |
| 标准部署骨架 | 已提供 | Docker Compose/HAProxy/HighWall 示例；当前环境无 Docker daemon，未做容器级运行验证 |
| 真实 IP 清洗配置 | 已提供 | HAProxy 删除并重写 XFF |
| 旁路验收脚本 | 已提供 | `deploy/standard/verify.py` |
| L4Wall 共享封禁读取端 | 已实现 | 私网 Redis、严格解析、本地优先、故障隔离；测试覆盖超时/坏数据/容量 |
| L4Wall 共享封禁发布端 | 待实现 | 本地封禁自动发布、跨节点冲突合并 |
| L4Wall Controller | 待实现 | 评分、封禁下发、控制面 |
| 跨层关联 ID | 待实现 | 需要 HighWall 记录边缘请求 ID |
| HTTP/2/WebSocket 检查 | 部分 | 边缘可承接；HighWall 不检查 WebSocket 内容 |
| 多节点/HA | 待实现 | 需要共享状态和 VIP/编排 |

## 15. 演进路线

- P0：本文、子项目迁移、标准部署骨架、真实 IP、旁路验证、CI。
- P1：L4Wall 共享封禁发布端、L4Wall Controller、HAProxy 动态 deny map、跨层关联 ID。
- P2：多节点、Kubernetes/Envoy、OpenTelemetry、云清洗接入、故障演练。

任何阶段都不要把“尚未验证”写成“已覆盖”。如果某个入口没有网络层拒绝、没有审计、没有攻击者视角测试，就仍然按未覆盖处理。
