# L5Wall 0.2.0

发布日期：2026-11-02

L5Wall 0.2.0 是 L5Wall 作为独立服务发布的第一个版本。它是 HighWall 仓库中的 TLS 会话层子项目，拥有独立版本号、测试矩阵、威胁模型、部署说明和发布产物。

## 状态

- 覆盖等级：**C1**，不完整。
- 成熟度：**Alpha**，未经独立第三方安全审计，非生产就绪。
- 运行时只依赖 Python 3.10+ 标准库。

它已经能终止 TLS、执行 SNI/ALPN 白名单、最低 TLS 版本、mTLS、SNI/Host 一致性和有界 H1 转发；没有标准 JA3/JA4、0-RTT 策略、QUIC、H2/H3 检查或握手前 TCP 预算。不要把它描述成完整 L5/L7 防护。

## 发布产物

- `l5wall-0.2.0-py3-none-any.whl`
- `l5wall-0.2.0.tar.gz`
- `SHA256SUMS`
- `ghcr.io/fallen-leaves089/l5wall:0.2.0`（`linux/amd64`、`linux/arm64`）

镜像带 cosign keyless 签名、GitHub provenance 和 SBOM attestation。安装前请校验 `SHA256SUMS`。

## 安装

```bash
python3 -m venv /opt/l5wall
/opt/l5wall/bin/pip install --no-cache-dir ./l5wall-0.2.0-py3-none-any.whl
/opt/l5wall/bin/l5wall --version
```

完整部署步骤见 [DEPLOYMENT.md](https://github.com/Fallen-leaves089/highwall/blob/main/subprojects/l5wall/docs/DEPLOYMENT.md)。

## 边界

- `serve` 只允许回环监听和回环上游；容器部署需要 host network 或共享网络命名空间。
- 不转发原始客户端 IP；不要在其后启用按 IP 封禁、来源 ACL 或依赖真实来源的限速。
- 只接受 `http/1.1` ALPN；H2/H3 不会被降级伪装成已检查。
- L5Wall 之前不能有终止 TLS 的代理，否则真实客户端握手信息已经丢失。

## 验证

- 36 项标准库 `unittest` 通过。
- `ruff`、`mypy`、`l5wall check` 通过。
- wheel/sdist 构建和安装自检通过；发布包不包含测试证书、私钥或测试目录。
- 证书、SPDX 许可证和 NOTICE 均随包分发。

## 许可

Apache-2.0。见 `LICENSE` 和 `NOTICE`。
