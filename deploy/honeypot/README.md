# 隔离式高交互蜜罐

本目录提供一个可直接启动的隔离式高交互诱饵环境，供 HighWall 与 L4Wall
接入。它刻意**不是**生产应用、身份系统、数据库或管理网的复制品。

网关只把流量转发给专用诱饵后端。真实 SSH 与 HTTP 服务运行在独立容器中，
根文件系统只读、能力被移除、宿主端口只绑定回环、没有公网出网能力。

## 拓扑

```text
互联网 / 靶场客户端
        |
        |  HighWall 或 L4Wall 在回环/私网地址上的诱饵端口
        v
  HighWall / L4Wall
        |
        |  只连该 listener 的专用后端；绝不回落到业务 upstream
        +--------------------------+
        |                          |
        v                          v
  highwall-honeypot-ssh    highwall-honeypot-web
  172.30.0.10:2222         172.31.0.20:8080
  真实 OpenSSH             有状态的登录/管理台诱饵
        |                          |
        `------ 两个独立 internal 网络 ------'
```

SSH 与 Web 容器分别位于两个独立的 Docker internal 网络，既不能访问公网，
也不能互相访问。宿主网关使用发布到 `127.0.0.1` 的端口；容器化网关必须显式
接入两个网络，并使用固定私网 IP，因为 `backend` 配置只接受 IP 字面量，
不接受 Docker 服务名。

## 前置条件

- Docker Engine 或 Docker Desktop，带 Compose v2。
- 对目标网络有明确授权。不要在你没有所有权或管理权的网络上部署。
- 默认容器合计约 1 vCPU、384 MiB 内存，不含 Docker 自身和网关开销。
- 不要放入真实凭据、客户数据、私钥、生产数据库快照或宿主目录挂载。
  这些诱饵应当随时可以丢弃和重建。

## 启动

在本目录执行：

```powershell
Copy-Item .env.example .env
docker compose up -d --build
python verify.py --docker require
```

默认宿主绑定：

| 服务 | 宿主绑定 | 容器端口 |
|---|---|---:|
| SSH 诱饵 | `127.0.0.1:12222` | `2222` |
| Web 诱饵 | `127.0.0.1:18080` | `8080` |

端口只发布到回环地址。不要在不可信网络上改成 `0.0.0.0`。如果网关位于另一台
主机，应让诱饵主机保持私网，在主机防火墙限制来源，并通过专用网络连接。

SSH 密码是可见的诱饵值 `highwall-decoy-only`，可以在构建前通过 `.env`
修改。它不是安全边界，绝不能复用真实账户密码或密钥。

## 宿主网关配置

### HighWall L7 listener

在 `policy.honeypot.listeners` 中增加独立端口。入站请求仍须通过 Host 白名单
和客户端 CIDR ACL；`host_header` 是发给诱饵后端的 Host，不是另一个面向客户端
的白名单。

```json
{
  "policy": {
    "allowed_hosts": ["admin.staging.invalid"],
    "honeypot": {
      "enabled": true,
      "ban_seconds": 0,
      "presets": ["common"],
      "listeners": [
        {
          "name": "live-admin",
          "listen_host": "127.0.0.1",
          "listen_port": 18092,
          "backend": {
            "scheme": "http",
            "host": "127.0.0.1",
            "port": 18080,
            "host_header": "admin.staging.invalid",
            "server_header": "nginx",
            "connect_timeout": 2,
            "read_timeout": 15,
            "total_timeout": 30,
            "max_response_bytes": 4194304
          }
        }
      ]
    }
  }
}
```

请求命中静态 `presets` 时仍由网关本地响应；其余路径只发往这个专用后端。
后端不可用时返回 `502` 或 `504`，不会回落到业务 `upstream`。

浏览器或测试客户端必须显式发送允许的 Host：

```powershell
curl.exe -i -H "Host: admin.staging.invalid" http://127.0.0.1:18092/login
```

登录页接受任意非空用户名并生成伪会话。它只是诱饵，不构成认证系统。

### L4Wall TCP listener

```json
{
  "honeypots": [
    {
      "name": "ssh-live",
      "listen_host": "127.0.0.1",
      "listen_port": 18094,
      "template": "custom",
      "backend_host": "127.0.0.1",
      "backend_port": 12222,
      "backend_connect_timeout": 2,
      "max_bytes_in": 4194304,
      "max_bytes_out": 4194304,
      "max_connection_seconds": 1800,
      "ban_seconds": 0
    }
  ]
}
```

L4Wall 默认每方向 64 KiB，比较保守；只有在隔离后端和网关容量允许时才提高。
调查期间保持 `ban_seconds=0`：正数会在诱饵会话结束后封禁来源，阻止继续交互。

通过网关端口验证真实 SSH：

```powershell
ssh -p 18094 root@127.0.0.1
```

SSH 容器是真实 OpenSSH，容器内 root 不是宿主 root。容器没有宿主挂载、
Docker socket、host 网络，根文件系统只读，能力被移除。但这只能降低风险，
不能保证抵御容器或内核逃逸；应持续修补 Docker 与宿主，并按“可被攻陷资产”
管理。

## 容器化网关

如果 HighWall 或 L4Wall 在容器中运行，把网关容器接入两个诱饵网络：

```powershell
docker network connect highwall-honeypot-web <gateway-container>
docker network connect highwall-honeypot-ssh <gateway-container>
```

随后在后端配置中使用固定地址：

| 后端 | 地址 |
|---|---|
| Web 诱饵 | `172.31.0.20:8080` |
| SSH 诱饵 | `172.30.0.10:2222` |

网关仍需保留原有的业务/上游网络，不要把正常业务网络替换掉。使用 Compose
管理网关时，应把这两个网络声明为 `external`，不要只依赖一次性的
`docker network connect`。

## 验收

`verify.py` 只使用 Python 标准库。它会检查 Web 登录与会话流、OpenSSH banner、
发布端口是否只绑定回环、容器是否无法访问公网，以及 SSH 与 Web 是否网络隔离。

```powershell
python verify.py --docker require
```

预期输出：

```text
[PASS] web/login: login page is present
[PASS] web/session: login redirect and session flow work
[PASS] ssh/banner: SSH-2.0-OpenSSH_...
[PASS] docker/services: containers are running
[PASS] docker/loopback: ssh-live=127.0.0.1:..., web-live=127.0.0.1:...
[PASS] docker/web-egress: web container has no public egress
[PASS] docker/cross-network: SSH and web containers are network-isolated
```

Docker 不可用时，`--docker auto` 会跳过 Docker 专属检查，只验证宿主端口。
用于交付门禁时应使用 `--docker require`。

## 运维

### 重置

当前没有持久化卷。重建容器会丢弃 shell 状态、伪会话、上传文件和运行时生成的
SSH 主机密钥：

```powershell
docker compose down --remove-orphans
docker compose up -d --build --force-recreate
```

如果长时间演练需要稳定的 SSH 主机密钥，应把预生成密钥以只读方式挂载，并同步
修改 `sshd_config` 的 `HostKey` 路径。不要把可写宿主目录挂进诱饵容器。

### 更新与回滚

```powershell
docker compose build --pull
docker compose up -d
```

正式演练应固定镜像 digest，并保留上一版 Compose 文件用于回滚。每次更新后重新
运行 `python verify.py --docker require`。

### 日志与证据

容器日志限制为 10 MiB × 3 个文件。HighWall/L4Wall 审计日志是独立通道，应发送
到受保护的外部收集器。不要把 Docker 本地 JSON 日志当作完整证据链。需要取证时，
事先记录时间源、收集器、保留期、访问路径和哈希校验方式，并从隔离主机导出，
不要在诱饵容器内执行取证工具。

### 常见问题

- HighWall 返回 `502`/`504`：Web 诱饵没启动、端口不对或超时。
- L4Wall 审计出现 `backend_unreachable`：检查 `127.0.0.1:12222` 和容器状态。
- 浏览器反复跳回登录页：确认客户端发送了允许的 Host，并保留伪 `session` Cookie。
- `verify.py` 报公网可达：立即停止部署，先修正 Docker 网络，不要继续收集交互。

## 安全、隐私与法务边界

- 只在你拥有或获得明确授权的网络上部署。
- 高交互诱饵是**可被攻陷资产**。必须假设攻击者能登录、上传文件、运行工具，
  并尝试容器或内核逃逸。
- 不要把 Docker socket、宿主根目录、云元数据代理、生产密钥或真实客户数据
  挂载进诱饵。
- 保持 Docker、内核和容器运行时为最新版本。容器内 root 不是宿主 root，
  但仍是实际攻击面。
- 诱饵日志可能包含来源 IP、攻击者输入的凭据和上传内容。部署前先确定收集目的、
  访问权限、保留期限、删除流程和事件升级路径，并遵守适用的隐私与网络安全法规。
- 不反制、不反向连接、不投放恶意代码、不收集授权范围外的数据。HighWall 和
  L4Wall 本身不执行不可信内容，也不提供反制功能。
- 不要把诱饵端口直接发布到公网。应放在网关之后，限制来源，并隔离管理面。

## “完整仿真”的代价

本目录是**隔离式高交互最小闭环**，不是完整业务环境复制。要逼近完整仿真，
至少需要：

- 精确的应用版本、依赖、Web 服务器、TLS 配置、数据库、缓存、消息队列、
  身份提供方和种子数据；
- 不暴露真实用户的生产级假账户、权限、业务流程、可观测副作用和已知漏洞；
- DNS、证书、代理、监控和网络拓扑足够接近目标，避免被指纹识别；
- 快照、自动重建、恶意样本隔离、流量/磁盘取证、日志外送和独立取证网络；
- 持续补丁、漂移控制、法务与隐私评估，以及长期值守人员。

粗略规划模型：

| 形态 | 基础设施 | 工程与运维 | 主要风险 |
|---|---|---|---|
| 静态模板 | 几乎可忽略 | 小时级 | 易被指纹识别，交互有限 |
| 本目录的隔离高交互闭环 | 约 1 vCPU / 384 MiB，另加网关 | 每个服务数天 | 诱饵被攻陷、容器逃逸 |
| 完整业务栈复制 | 4–16+ vCPU、8–32+ GiB 内存，另加数据库和存储 | 数周到数月，之后持续维护 | 成本高、数据泄漏、环境漂移、法务暴露 |

硬件通常不是最大成本。真正昂贵的是可信的假数据、隔离工程、取证准备、持续补丁，
以及安全运营人员。若目标只是发现扫描和获得低风险交互信号，默认静态模板更划算。

## 文件

- `docker-compose.yml`：隔离容器、回环端口、资源限制和独立网络。
- `web/decoy.py`：有状态伪登录和管理台。
- `ssh/Dockerfile`、`ssh/sshd_config`：受限容器中的真实 OpenSSH。
- `verify.py`：无第三方依赖的验收脚本。
- `.env.example`：回环端口和诱饵密码。
