# HighWall v0.11.0 + L4Wall 0.1.0

[English](RELEASE-v0.11.0.en.md) | 简体中文

发布日期：2026-10-30

## 概览

`v0.11.0` 把仓库从单一 HTTP/1.1 防护网关扩展为可组合的两层防护基线：

- **L4Wall 0.1.0**：失败关闭的 TCP 连接级网关，负责准入、并发/速率限制、超时、字节上限、行为评分、封禁和审计。
- **HighWall 0.11.0**：继续负责 HTTP/1.1 的 Host/方法/路径策略、WAF、DLP、响应完整性、L7 限速和蜜罐。
- **复合部署**：提供 `lite` 串联形态和 `standard` 边缘代理骨架；两者都不把“部署了组件”等同于“已经覆盖所有入口”。

## 新增

### L4Wall 子项目

- 连接级来源白名单和默认拒绝。
- 单 IP 并发上限、新建连接速率和连接突发控制。
- 首字节、空闲、总连接时长和单方向字节上限。
- 多 listener 扇出、短连接、零字节探测、拒绝风暴和固定节奏等行为信号。
- 两阶段评分、限时遏制、确认封禁和 `offenders.json` 持久化。
- JSONL 审计、回环管理面、健康检查和 Prometheus 文本指标。
- 可选私网 Redis 共享封禁读取端：版本化 JSON、严格字段校验、容量限制、TTL 截断、本地优先和故障隔离。

### 复合部署与攻防验收

- `scripts/attack_range.py`：本机回环靶场，覆盖 L4Wall -> HighWall -> 模拟上游的 28 项矩阵；支持独立 WSL 攻击实例和常驻模式。
- `deploy/standard/`：HAProxy、Compose、TLS 变体、上游回声服务和旁路验收脚本。
- `docs/STACK.md`：信任边界、真实客户端 IP、直连封堵、封禁同步、故障策略和验收清单。
- `docs/ATTACK_TESTING.md`：自动化矩阵、实机结果、已修复问题和未验证项。

## 修复与加固

- 全局在途请求超限时，`503` 响应现在带 `Retry-After: 1` 和 `X-Request-ID`；审计同步记录 `request_id`、`HW-SERVER-1001`、`status=503`、`detail=inflight_limit` 和真实响应字节数。
- `l4wall inspect` 不再输出密码或管理令牌的环境变量名，并增加脱敏回归测试。
- 靶场把 L4 单方向字节上限调整到 2 MiB，使 HighWall 的 `413` 在临界区间可观测。
- 发布包补充 `subprojects/`，sdist 不会再漏掉 L4Wall 源码。

## 验证

- HighWall 全量：354 项测试通过。
- L4Wall：65 项测试通过。
- 跨层攻防：26 项端到端测试通过。
- `ruff`、`mypy`、`compileall`、配置检查和干净虚拟环境安装通过。
- PR CI：Ubuntu/Windows x Python 3.10/3.11/3.12、CodeQL、静态分析全部通过。
- 实机矩阵：28/28 通过，0 失败；2 项已知边界风险已记录，未计作通过项。
- 40 并发复测：31 个 `200`、1 个可追溯 `503`、8 个无 HTTP 响应；L4 侧 32 个允许、8 个 `ip_capacity` 拒绝。
- 审计对账：在途请求允许/拒绝记录的 `request_id` 与客户端 `X-Request-ID` 32/32 对齐。
- 字节边界：1,048,491 字节返回 `200`，1,048,577 字节返回 `413`（`HW-PROTO-1106`）。

## 下载

- `highwall-0.11.0-py3-none-any.whl`
- `highwall-0.11.0.tar.gz`
- `l4wall-0.1.0-py3-none-any.whl`
- `l4wall-0.1.0.tar.gz`
- `SHA256SUMS`

```bash
python -m pip install highwall-0.11.0-py3-none-any.whl
python -m pip install l4wall-0.1.0-py3-none-any.whl
```

下载后先用 `SHA256SUMS` 校验，再安装。

## 容器镜像

`v0.11.0` 标签会触发多架构镜像构建并发布到 GHCR：

```bash
docker pull ghcr.io/fallen-leaves089/highwall:0.11.0
```

镜像带 SBOM、GitHub provenance attestation 和 cosign 签名。生产环境应固定不可变版本，不要依赖 `latest`。

## 兼容性

- HighWall 的 HTTP/1.1 配置 schema 未破坏性变更；`v0.10.0` 配置可继续使用。
- L4Wall 是独立进程和独立 `0.1.0` 包，不要求 HighWall 进程内加载。
- `lite` 形态下 HighWall 看到的来源是 L4Wall 地址；需要真实客户端归属时使用 `standard` 骨架。

## 边界与未覆盖项

- HighWall 0.11.0 和 L4Wall 0.1.0 都是 alpha 阶段，未经过独立第三方安全审计。
- L4Wall 不处理带宽型 DDoS、SYN flood、UDP、QUIC/HTTP3，也不替代应用认证、授权或主机 EDR。
- `standard` 骨架当前只保证入口、真实 IP、网络闭环、L7 防护和验收；L4Wall Controller、动态封禁下发和多节点 HA 仍是后续里程碑。
- 共享封禁目前只有读取端，自动发布、冲突合并和 Controller 尚未实现。
- Docker/HAProxy 的完整容器拓扑仍需在目标环境执行联调；本地回环通过不等于生产拓扑通过。
- 直连 HighWall 或上游会绕过 L4 ACL；必须用网络 ACL 和监听地址保证攻击者不可达。
- 本版本不声称“绝对无漏”。未验证项和残余风险以 `docs/ATTACK_TESTING.md` 与 `docs/STACK.md` 为准。
