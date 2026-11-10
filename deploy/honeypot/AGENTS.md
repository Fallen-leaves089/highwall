# 蜜罐目录约定

- 本目录的镜像仅用于隔离诱饵与回环转发，不是 HighWall/L4Wall 网关镜像，也不是生产应用。
- `highwall-honeypot-ssh-live`：真实 OpenSSH 诱饵；`highwall-honeypot-web-live`：HTTP 伪登录/管理台；`highwall-honeypot-relay`：两个转发服务共用的最小 TCP 转发器。
- 带 `:test` 或 `*-python315:test` 的本地标签仅用于兼容性验收，可以删除，不是部署依赖。
- 修改镜像、路由、资源限制或凭据前，先读 `README.md` 的“镜像用途与边界”和“安全、隐私与法务边界”。