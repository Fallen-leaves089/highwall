# L5Wall 独立部署

本文适用于 L5Wall `0.2.1`。它是 **Alpha、覆盖等级 C1、非生产就绪** 的 TLS 会话守卫，不是完整的 L5/L7 防护。

## 1. 部署拓扑

`0.2.1` 强制 `listen_host` 和 `upstream_host` 都是回环地址，因此推荐的单机拓扑是：

```text
客户端
  |  TCP（不终止 TLS）
  v
L4Wall / HAProxy TCP mode / 云负载均衡 TCP 监听
  |  127.0.0.1:18443
  v
L5Wall（终止 TLS、SNI/ALPN/mTLS 策略、H1 首头预检）
  |  127.0.0.1:18080
  v
HighWall H1 数据面或业务上游
```

必须遵守：

- **L5Wall 之前不能有终止 TLS 的代理。** HAProxy/Envoy/CDN 一旦终止 TLS，L5Wall 只能看到内层连接，不能再声称拥有真实客户端握手信息。
- **L5Wall 是 TLS 终止点。** 它和上游之间是明文 H1 回环链路，不能再跨不可信网络。
- **不要在这个桥接后面启用按 IP 封禁、来源 ACL 或按真实来源限速。** `0.2.1` 不转发原始客户端 IP，HighWall 看到的来源是 `127.0.0.1`。
- **只接受 `http/1.1` ALPN。** H2/H3 不会降级伪装成已检查；需要 H2/H3 时使用原生 B+D-4 数据面。

## 2. 前置条件

- Linux x86_64/arm64，或 Windows 主机直接安装；容器方式见第 4 节。
- Python 3.10+（仅使用标准库运行）。
- 服务端证书链和私钥；生产证书不要使用仓库里的测试证书。
- 上游 H1 服务已经监听回环地址，且不直接暴露公网。
- 一个能执行 `l5wall check` 的非特权账户。

## 3. 主机安装（wheel）

从 GitHub Release 下载 `l5wall-0.2.1-py3-none-any.whl` 和 `SHA256SUMS`，先校验：

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

创建运行账户和目录：

```bash
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin l5wall
sudo install -d -o root -g l5wall -m 0750 /opt/l5wall /etc/l5wall /etc/l5wall/tls
sudo python3 -m venv /opt/l5wall
sudo /opt/l5wall/bin/pip install --no-cache-dir ./l5wall-0.2.1-py3-none-any.whl
```

把证书放到 `/etc/l5wall/tls/`，私钥建议 `root:l5wall 0640`，证书 `0644`。配置文件示例见 [`../deploy/l5wall/config.example.json`](../deploy/l5wall/config.example.json)；把 SNI、证书路径和上游端口换成实际值。

先做静态检查，再启动：

```bash
sudo -u l5wall /opt/l5wall/bin/l5wall check -c /etc/l5wall/config.json
sudo -u l5wall /opt/l5wall/bin/l5wall inspect -c /etc/l5wall/config.json
```

`inspect` 只输出非敏感配置，不会输出私钥、Cookie 或 Authorization。

systemd 示例在 [`../deploy/systemd/l5wall.service`](../deploy/systemd/l5wall.service)。安装前先按目标路径检查：

```bash
sudo cp subprojects/l5wall/deploy/systemd/l5wall.service /etc/systemd/system/l5wall.service
sudo systemctl daemon-reload
sudo systemctl enable --now l5wall
sudo systemctl status l5wall
```

单元里的 `MemoryDenyWriteExecute`、`SystemCallFilter` 等 hardening 选项按目标发行版的 Python 行为验证；如果目标环境不兼容，先只移除冲突项并记录原因，不要整体关闭沙箱。

## 4. 容器

镜像：`ghcr.io/fallen-leaves089/l5wall:0.2.1`，支持 `linux/amd64` 和 `linux/arm64`，带 cosign 签名、GitHub provenance 和 SBOM attestation。

### 为什么不能直接用 `-p 18443:18443`

L5Wall 在容器内监听 `127.0.0.1:18443`。Docker 的端口发布转发到容器网卡地址，不会转发到容器回环地址，所以普通 bridge 网络加 `-p` 会连不上。这不是镜像坏了，而是回环安全约束的直接结果。

`0.2.1` 支持两种容器部署方式：

1. **Linux host network（推荐用于单机验证）**：容器直接使用宿主机回环，见 [`../deploy/docker-compose.host.yml`](../deploy/docker-compose.host.yml)。
2. **共享网络命名空间**：L5Wall、HighWall 和一个 TCP 入口容器加入同一个 netns；入口容器监听 `0.0.0.0` 并把 TCP 转发到 `127.0.0.1:18443`。不要把入口容器做成 TLS 终止代理。

host network 示例：

```bash
docker run --rm --network host \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --user 10001:10001 \
  -v /etc/l5wall/config.json:/etc/l5wall/config.json:ro \
  -v /etc/l5wall/tls:/etc/l5wall/tls:ro \
  --tmpfs /tmp:size=16m,mode=1777 \
  ghcr.io/fallen-leaves089/l5wall:0.2.1
```

镜像自带的 `HEALTHCHECK` 只验证配置和证书可用，不代表监听端口一定可服务；生产监控应另外做 TLS 握手探针。

### Kubernetes

`0.2.1` 不建议直接用普通 `Service` 暴露：Service 的目标是 Pod IP，而 L5Wall 只监听 Pod 回环。可行方式只有：

- `hostNetwork: true` + `hostPort`；或
- 在同一个 Pod 内增加一个只做 TCP 转发的 sidecar，由它监听 Pod IP 并转发到 `127.0.0.1:18443`。

这两种方式都需要额外的主机端口或转发组件。若目标是完整的 H2/H3 与真实来源，使用原生 B+D-4 数据面，不要用 L5Wall 拼凑。

## 5. 证书与权限

- 配置加载会拒绝符号链接证书和私钥；不要把证书目录做成指向可变路径的 symlink。
- 私钥只给运行用户读权限；容器内运行 UID/GID 是 `10001:10001`。
- 证书轮换需要替换文件后重启 L5Wall；`0.2.1` 不支持热加载证书。
- 测试证书只允许回环测试，不能进入生产镜像或发布包。

## 6. 上线检查

- `l5wall check` 返回 0。
- 监听地址只有回环；`ss -ltnp` 不应出现 `0.0.0.0:18443` 或 `[::]:18443`。
- 客户端 TLS 1.2/1.3 可握手；低于 `min_version` 的版本被拒绝。
- ALPN 只协商 `http/1.1`；H2 preface 被拒绝。
- SNI 不在白名单、缺少 SNI、SNI 与 Host 不一致时连接被关闭。
- 开启 mTLS 时，缺少客户端证书的握手被拒绝。
- 上游关闭时连接被关闭，不会挂起等待。
- 证书和私钥不出现在日志、`inspect` 输出或镜像层中。

## 7. 升级与回滚

- 固定镜像 digest，不要只用 `latest`。
- 升级前保留上一版 wheel/镜像和配置；先在新端口做 `check`，再切换入口。
- `0.2.1` 收到 `SIGTERM` 后停止接受新连接，并在 `shutdown_timeout`（默认 8 秒）内等待在途连接完成；超时才强制关闭剩余连接。服务管理器的停止宽限必须大于 `shutdown_timeout`，例如 systemd `TimeoutStopSec=12` 或 Compose `stop_grace_period: 12s`。
- 回滚时恢复上一版镜像/ wheel 和配置，重新执行 `check`，再恢复入口流量。

## 8. 故障排查

| 现象 | 优先检查 |
|---|---|
| `configuration error` | 配置字段、证书路径、私钥匹配、SNI/ALPN 合法性 |
| `listener error` | 18443 是否被占用、是否误配非回环地址 |
| 连接立即断开 | SNI/ALPN/mTLS 策略、TLS 版本、SNI 与 Host 是否一致 |
| 容器端口不通 | 是否误用 bridge + `-p`；改用 host network 或共享 netns |
| 上游收不到请求 | 上游是否监听回环、端口是否正确、请求头是否被预检拒绝 |

安全问题请按 [`../SECURITY.md`](../SECURITY.md) 报告。
