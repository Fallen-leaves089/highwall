# L4Wall + HighWall 回环攻防验收

版本：HighWall `0.10.0` / L4Wall 子项目当前版本  
日期：2026-10-30  
性质：维护者在隔离本机环境中执行的自动化授权攻防验收  
范围：`攻击客户端 -> L4Wall -> HighWall -> 模拟上游` 的本地回环链路

## 0. 结论先看

- 26 项端到端攻防与边界测试全部通过：`tests/test_attack_defense.py`。
- L4Wall 64 项、HighWall 354 项回归测试通过。
- 本轮发现并修复 1 个失败开放问题：关闭启发式评分时，已存在的本地/共享封禁会被跳过。现在封禁检查独立于评分开关。
- 同时修复共享同步超时后的孤儿任务和未取回异常，避免故障场景产生后台悬空任务。
- 已实际验证：L4 连接层拒绝不会到达 HighWall 或上游；L4 封禁重启后仍生效；Redis 不可达或返回坏 JSON 不会清空本地封禁；共享封禁可被导入并拦截流量。
- 实机链路（独立 WSL 实例内的攻击方代理）：28/28 通过；基线、L7 边界、响应 DLP、L4 并发上限四个阶段均未发现可确认的绕过。
- 本轮另修复 1 个审计缺口：全局在途请求超限时返回的 503 没有审计记录，现已补记并加回归测试。
- 未实际验证：Docker/HAProxy 真实边缘、TLS、HTTP/2、WebSocket、宿主机防火墙、真实 Redis、L4Wall Controller、共享封禁发布端、多节点 HA。
- 本文不声称“无漏”。本地回环链路通过，不等于标准容器拓扑或生产拓扑通过。

## 1. 环境与安全边界

- 所有测试只绑定 `127.0.0.1` 的临时端口，不扫描公网，不连接第三方目标。
- 上游是测试桩，不连接真实业务、数据库或生产系统。
- 不修改 Windows 防火墙、端口代理、路由、DNS、TLS 证书或系统服务。
- 假 Redis 只监听回环，仅用于验证 RESP 读取、版本化载荷解析和故障隔离。
- 封禁文件、审计文件和临时目录都位于 `TemporaryDirectory`，测试结束后删除。
- 实机测试中攻击方代理运行在独立 WSL 实例，出口策略只放行靶场边缘的单个地址与端口；主机侧不对其他端口放行。
- 实机审计目录只在本机留存，不随仓库发布；本文不记录具体地址、实例名和工具身份。

## 2. 拓扑

```text
攻击客户端
   |  raw TCP / HTTP
   v
L4Wall（web / api 两个 listener）
   |  透明 TCP 转发
   v
HighWall（Host、方法、路径、WAF、DLP、CSRF、响应扫描）
   |  HTTP
   v
模拟上游（记录到达请求 / 提供泄漏响应）
```

L4Wall 在自己的 asyncio 线程中运行，HighWall 在测试线程中运行；两者只通过真实 TCP 连接通信，没有 mock 掉数据面。L4Wall 的 `web` 和 `api` listener 分别绑定临时端口，便于验证多 listener 扇出。

实机变体把“攻击客户端”换成独立 WSL 实例，经主机虚拟网卡访问 L4Wall 边缘，其余链路不变。边缘只暴露一个端口，攻击方侧只放行该边缘地址与端口，其他目标保持阻断。

## 3. 自动化测试矩阵

> 说明：为了让测试在数秒内完成，L4 评分用例使用收紧后的阈值（例如 `min_zero_byte_connections=1`、`min_connections=2`），只验证判定链路和封禁效果；这不代表默认配置也会在同样次数内封禁。默认阈值见 `subprojects/l4wall/config.example.json`。

| 层 | 场景 | 预期与断言 | 测试 |
|---|---|---|---|
| 基线 | 正常 HTTP 请求穿过整条链路 | 200，且上游只收到 1 次请求 | `test_normal_request_passes_whole_chain` |
| L7 | 错误 Host | 403，上游 0 次请求 | `test_wrong_host_is_blocked_before_upstream` |
| L7 | 绝对 URI、重复 Host | 400 | `test_absolute_uri_and_duplicate_host_are_blocked` |
| L7 | 重复 Content-Length、TE/CL 混用、单独 TE | 400，未发生请求走私 | `test_request_smuggling_variants_are_blocked` |
| L7 | 路径穿越、编码分隔符、NUL、`/.git` | 400/403，上游 0 次请求 | `test_path_traversal_variants_are_blocked` |
| L7 | SQLi、命令注入、JNDI、XSS | 403，上游 0 次请求 | `test_waf_categories_are_blocked` |
| L7 | GET 携带 body、超大 body/路径/头部 | 400/413/414/431 | `test_oversized_and_get_body_requests_are_blocked` |
| L7 | 上游响应含私钥或调试栈 | 502，响应体不含私钥/堆栈 | `test_dlp_blocks_private_key_and_debug_trace` |
| L7 | CSRF：缺失或错误 Origin | 403；正确 Origin 通过 | `test_csrf_origin_is_required_for_unsafe_methods` |
| L7 | 客户端伪造 X-Forwarded-For | 不被信任，上游看到真实 peer `127.0.0.1` | `test_spoofed_xff_is_not_trusted` |
| L7 | 单 IP 限速 | 第一条 200，第二条 429，带 `Retry-After`，上游只收到 1 次 | `test_highwall_per_ip_rate_limit_returns_429` |
| L7 | 上游读超时 | 504 | `test_upstream_timeout_returns_504` |
| L7 | 慢 header | 408 | `test_slow_header_deadline_returns_408` |
| L4 | 来源白名单 | 连接直接关闭，未进入 HighWall/上游 | `test_l4_source_allowlist_blocks_before_highwall` |
| L4 | 单 IP 并发上限 | 第三条连接被 `ip_capacity` 拒绝 | `test_l4_per_ip_concurrency_limit` |
| L4 | 新建连接速率 | 超出 burst 的连接被 `connection_rate` 拒绝 | `test_l4_new_connection_rate_limit` |
| L4 | 首字节超时 | `first_byte_timeout`，连接关闭 | `test_l4_first_byte_timeout` |
| L4 | 单方向字节上限 | `byte_limit`，连接关闭 | `test_l4_byte_limit` |
| L4 | 零字节探测 | 触发 `source_banned`，后续请求被 `banned` 拒绝且不到上游 | `test_l4_zero_byte_probe_bans_source_and_stops_later_requests` |
| L4 | 多 listener 扇出 | 达到评分阈值后封禁，后续请求被拒绝 | `test_l4_listener_fanout_triggers_ban` |
| L4 | 封禁持久化 | 重启后仍从 `offenders.json` 恢复封禁 | `test_l4_ban_survives_restart` |
| 共享 | 从 Redis 导入 `127.0.0.1/32` | 导入成功并拦截流量；审计出现 `shared_sync_ok` | `test_shared_ban_is_imported_and_blocks_traffic` |
| 共享 | Redis 返回过宽前缀 `/8` | 条目被拒绝，不扩大封禁范围 | `test_shared_overwide_prefix_is_rejected` |
| 共享 | Redis 不可达 | 数据面继续工作；本地封禁继续生效；审计出现 `shared_sync_failed` | `test_shared_failure_does_not_break_local_ban` |
| 共享 | Redis 返回坏 JSON | 不清空已持久化的本地封禁 | `test_bad_shared_payload_does_not_clear_persisted_ban` |
| 边界 | 直连 HighWall / 上游 | 绕过 L4 ACL；用于证明网络隔离不可省略 | `test_direct_highwall_and_upstream_access_bypasses_l4_acl` |

## 4. 实测结果

执行环境：Windows，Python 3.10，全部使用回环临时端口。

```text
tests/test_attack_defense.py                 26 tests   OK
subprojects/l4wall/tests                     64 tests   OK
tests（HighWall 全量）                       354 tests  OK
ruff check（含 subprojects/l4wall）          通过
mypy（HighWall 28 个源文件）                 通过
mypy（L4Wall 13 个源文件）                   通过
compileall                                   通过
l4wall demo                                  PASS
l4wall check --config config.example.json    通过
deploy/standard/highwall 配置检查             通过（仅有预期的安全告警）
```

攻防子集耗时约 4 秒；它不替代长时间压测、容量测试或真实网络环境验收。

实机链路结果（独立 WSL 攻击方 → 边缘 → HighWall → 测试上游）：

```text
阶段 1 基线                     通过
阶段 2 L7 边界                  通过
阶段 3 响应 DLP                 通过
阶段 4 L4 单 IP 并发上限         通过
实机矩阵                        28/28 通过，0 失败
```

实机矩阵另报告 2 条已知边界风险：直连 HighWall、直连上游仍可访问，需靠网络层隔离，详见第 6 节。

修复验收（在途请求 503 审计）：40 并发下客户端收到 31 个 200、1 个 503、8 条无 HTTP 响应；审计侧为 31 条 `request_allowed` 加 1 条 `request_blocked`（`HW-SERVER-1001`），可追溯率由 31/32 提升到 32/32，客户端 `X-Request-ID` 与审计 `request_id` 一致。

## 5. 本轮发现与修复

### 5.1 关闭评分导致显式封禁失效

修复前的判定顺序是：

```python
if not self.config.enabled:
    return _allow()
if self.bans.check(address) is not None:
    return deny
```

影响：`threat_detection.enabled=false` 时，本地 `offenders.json` 或已导入的共享封禁仍然存在，但连接会被直接放行。这是一个失败开放行为，尤其会让“关闭启发式评分、保留中心封禁”的部署失效。

修复后，封禁检查先于评分开关：

```python
if self.bans.check(address) is not None:
    return deny
if not self.config.enabled:
    return allow
```

语义边界：

- `threat_detection.enabled=false` 只关闭新的启发式评分和自动封禁，不释放已有封禁。
- 要解除封禁，应删除 `offenders.json` 中对应条目，或等待 TTL 到期。
- 回归测试：`test_existing_ban_is_enforced_when_scoring_disabled` 和 `test_shared_ban_is_imported_and_blocks_traffic`。

### 5.2 共享同步超时后的孤儿任务

现象：坏载荷端到端测试偶发输出 `Task exception was never retrieved`。原因是 `SharedRedisSource.fetch()` 外层 `asyncio.wait_for()` 与内层 `_fetch()` 的完成竞争：外层判定超时/取消后，内层任务仍可能带着 `SharedStateError` 结束，异常没有被取回。

修复：

- 移除包住整段 `_fetch()` 的外层 `wait_for`；
- DNS、连接、每次 Redis 命令读取和 writer 关闭各自使用有界超时；
- `_close_writer()` 的 `wait_closed()` 增加 1 秒上限；
- 取消可以正常传播到 `_fetch()`，不会留下后台任务。

回归：`test_shared_state.test_read_timeout_is_bounded` 仍验证读取超时有界；坏 JSON 端到端测试连续重复运行不再出现未取回异常。

### 5.3 在途请求超限 503 未写审计

现象：实机并发探测时客户端收到 `503`（`Content-Length: 0`，无 Rule ID），但审计里没有对应记录。L4 审计显示 32 条连接被放行，HighWall 审计只有 31 条。

原因：`_reject_busy()` 在全局在途请求超过 `server.max_inflight_requests` 时直接回 503，只累加 `blocked_total` 和 `inflight_rejections_total` 指标，不写审计。

影响：该拒绝路径不可追溯，破坏了“每个被拒绝请求都有规则号”的审计一致性；行为本身仍是失败关闭。

修复：

- 先生成 24 位 `request_id`，再写审计、再回包；
- 503 响应增加 `X-Request-ID` 和 `Retry-After: 1`；
- 审计记录 `HW-SERVER-1001`、`status=503`、`outcome=blocked`、真实 `response_bytes` 与 `duration_ms`，`detail=inflight_limit`；
- 此时尚未解析请求，`method`/`path` 记为 `-` 和空串。

回归：`test_global_inflight_limit_returns_503` 断言审计恰好一条 503、规则号正确、`request_id` 与客户端响应头一致、`response_bytes` 大于 0。

### 5.4 L4 收包上限与 HighWall body 上限未对齐

现象：实机探测中，`Content-Length` 略小于 1 MiB 的请求被直接断连（无 HTTP 响应），而 `Content-Length` 超过 1 MiB 的请求反而能收到 413。

原因：L4Wall 的 `max_bytes_per_direction` 按方向累计，**请求头也计入**。当时靶场把该值设成 1 MiB，与 HighWall 的 `max_body_bytes`（同样 1 MiB）相同，于是“body + 请求头 > 1 MiB 但 body ≤ 1 MiB”这一窄区间会被 L4 中途切断；只有 HighWall 在读 body 前按 `Content-Length` 直接回 413 的请求才能拿到响应。

修复：靶场的 L4 收包上限提高到 2 MiB，仍作为兜底。复测：1048491 字节 body 由“断连”变为 200，1048577 字节 body 返回 413（`HW-PROTO-1106`）。

部署建议：L4Wall 的 `max_bytes_per_direction` 应大于 HighWall 的 `max_body_bytes + max_header_bytes`，并留出余量；两者相等会把 HighWall 的 413 挤成连接重置。

附带限制：HighWall 不接受 `Expect` 头，带 `Expect: 100-continue` 的请求直接返回 417（`HW-PROTO-1103`）。这是有意的严格策略，但标准客户端上传大于约 1 KB 的内容时会默认带该头，需要显式去掉。

## 6. 直连边界

自动化测试明确验证了两条绕过路径：

1. **直连 HighWall**：当 L4Wall 的来源白名单拒绝本机时，直接连接 HighWall 仍然返回 200。HighWall 仍会执行 L7 策略，但完全绕过 L4 的来源 ACL、连接限速、字节上限和封禁。
2. **直连上游**：直接向模拟上游发送带 SQLi 查询串的请求返回 200，说明上游自身不提供网关级保护。

因此生产部署必须满足：

- HighWall 和上游只监听回环或私网地址，不能有公网端口映射。
- 主机防火墙/安全组默认拒绝，只放行“边缘 -> L4Wall -> HighWall -> 上游”的必要路径。
- L4Wall listener 必须是入口或位于受控网络之后；L4Wall 不认证客户端，公开 listener 只能依赖来源白名单、限速和字节上限。
- HighWall 的 `policy.allowed_client_networks` 检查的是 L7 解析出的客户端 IP，不是 L4Wall 的 peer 地址，不能替代网络层 ACL。
- 同一主机失陷后无法维持这条边界；攻击者可以改配置、读封禁文件或直连上游。

## 7. 尚未验证

以下项目本轮没有运行，不能写成“已覆盖”：

- Docker daemon 不可用，未做容器级 `docker compose` 验收。
- 未运行真实 HAProxy 边缘，未验证 TLS 终止、HTTP/2、WebSocket、PROXY protocol 和真实 IP 清洗。
- 未连接真实 Redis；假 Redis 只验证 RESP 形状、版本化 JSON、TTL/前缀拒绝和故障隔离。
- 未测试 SYN flood、带宽型 DDoS、链路饱和；L4Wall 只能看到已完成 TCP 握手的连接。
- 未验证 Windows 防火墙、WFP、nftables、云安全组或宿主机网络隔离。
- 未实现或未验证：L4Wall Controller、共享封禁发布端、跨节点冲突合并、多节点 HA、跨层关联 ID。
- 未做 IPv6 端到端链路、NAT/代理池真实来源、长时间 soak、p99 容量基线。
- 未测试同主机提权、进程内存读取、配置篡改或审计文件篡改。

## 8. 复现命令

在仓库根目录执行：

```powershell
cd <仓库根目录>
python -m unittest tests.test_attack_defense -v
python -m unittest discover -s tests -q

cd subprojects\l4wall
python -m unittest discover -s tests -q
python scripts\demo.py
python -m l4wall check --config config.example.json

cd <仓库根目录>
python scripts\attack_range.py --wsl --wsl-distro Ubuntu
```

静态检查：

```powershell
cd <仓库根目录>
python -m pip install -e ".[dev]"
python -m ruff check highwall scripts tests deploy/standard subprojects/l4wall
python -m mypy
cd subprojects\l4wall
python -m mypy l4wall
```

测试文件会把 `subprojects/l4wall` 加入 `sys.path`，因此从 HighWall 根目录运行即可，不需要额外安装 L4Wall。

## 9. 判读原则

- “通过”只表示：在本文记录的配置、载荷和本机回环环境下，观察到了预期拒绝或隔离。
- 失败必须做最小根因修复并补回归测试；不能只改文档或放宽断言。
- 未运行的项目必须标为未验证，不能用“设计上应该可以”替代实测。
- WAF、DLP、CSRF、启发式评分和共享封禁都有漏报与误报；任何“绝对无漏”的表述都不成立。
