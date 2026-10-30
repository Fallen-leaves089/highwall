# 标准部署骨架

这是 B 方案的 `standard` 起点：HAProxy 做边缘数据面，HighWall 做 HTTP/1.1 L7 防护，上游不发布到宿主机。L4Wall Controller、动态封禁下发和共享状态仍在后续里程碑，当前目录不能当作完整控制面。

## 启动

```powershell
cd deploy/standard
Copy-Item .env.example .env
docker compose up --build -d
python verify.py
```

演示上游只用于验收。生产必须把 `highwall/config.json` 的 `upstream.host`/`port` 改成真实上游，并收窄 `allowed_hosts`、`allowed_client_networks`、方法和路径。

## 网络与端口

- 边缘：宿主 `8080`（HTTPS 配置为 `8443`）。
- HighWall：边缘网 `172.30.0.20:18090`，上游网 `172.31.0.20`；不发布到宿主机。
- 上游：`172.31.0.30:18080`，位于 `internal` 网络，不发布到宿主机，也不能主动访问外网。
- HAProxy 管理 socket：容器内 `/var/run/haproxy/admin.sock`。

不要给 HighWall 或上游增加 `ports` 映射。需要从宿主机排障时，用 `docker compose exec` 或临时 SSH 隧道，不要长期发布。

## 真实客户端 IP

`haproxy/haproxy.cfg` 会删除客户端提交的 `X-Forwarded-For`、`Forwarded`、`X-Real-IP`，再写入唯一的可信 XFF。HighWall 的 `trusted_proxies` 只允许 `172.30.0.10/32`。

`policy.allowed_client_networks` 检查的是解析后的客户端 IP，不是 HAProxy 地址。示例留空，依赖“HighWall 只被 HAProxy 访问”的网络闭环；生产应按真实客户端网段填写，不要填 `172.30.0.10/32`。

## TLS

默认使用 HTTP，便于本地验收。启用 TLS：

1. 准备 `certs/site.pem`（证书链 + 私钥）；
2. 在 `.env` 设置 `HAPROXY_CONFIG=./haproxy/haproxy-tls.cfg`；
3. 用 TLS 叠加文件启动：`docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d`；
4. 用 `https://127.0.0.1:8443` 验证证书链和 Host。

也可以让 HighWall 自己终止 TLS；两种方式不要同时启用，避免证书和 XFF 语义混乱。

## 验收

```powershell
python verify.py
```

脚本检查：

- 正常请求经边缘到达上游；
- 伪造 `X-Forwarded-For` 被替换；
- 宿主机上的 HighWall/上游端口不可达。

如果本机没有 Docker daemon，脚本会失败并提示先启动容器；不要用 `--skip-direct` 掩盖旁路问题。

## 故障排查

```powershell
docker compose ps
docker compose logs -f haproxy highwall upstream
docker compose exec highwall python -m highwall check -c /etc/highwall/config.json
```

HighWall 审计写入 `highwall-data` 卷的 `/var/lib/highwall/audit.jsonl`。生产要给它配额、轮转和独立备份，并监控磁盘。

配置校验：

```powershell
python -m highwall check -c deploy/standard/highwall/config.json
```

`check --strict` 会把 `trusted_proxies` 判为高风险并返回 4，这是预期行为：只有确认 HighWall 只被该边缘地址访问时才允许晋级。`allowed_client_networks` 为空也会产生 medium warning，生产应按真实客户端网段收窄。

## 当前不包含

- L4Wall Controller 进程；
- HAProxy 动态 deny map 下发；
- SQLite/Redis 共享封禁：L4Wall 读取端已实现，但本标准骨架还没有接入 Redis 和 L4Wall Controller；
- 多节点、VIP、自动故障转移；
- HTTP/2/WebSocket 内容检查。

这些缺口在 `docs/STACK.md` 中有明确状态，不要用“已有边缘代理”代替。
