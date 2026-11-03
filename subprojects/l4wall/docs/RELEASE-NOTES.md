# L4Wall 0.1.0

发布日期：2026-11-03

L4Wall 是 HighWall 仓库中的独立 TCP L4 防护网关，负责连接级准入、并发与速率限制、超时、字节上限、行为评分、封禁和审计。`0.1.0` 现在以独立标签和独立 GitHub Release 发布，不再依附 HighWall 主版本包。

## 发布性质

- 本发布完整复用 `v0.11.0` 官方 Release 中的 L4Wall `0.1.0` wheel 和 sdist，没有重新构建，也没有修改包内容。
- 发布标签指向 `v0.11.0` 对应源码提交 `18e9f7e79870681b915fe85fb051a6a06b2378d2`；发布资产沿用该 Release 的官方 L4Wall 附件，不来自当前 `main`。
- `main` 上的后续 L4Wall 改动不属于本发布，包括之后加入的 PROXY v2 发送能力等。
- 历史 sdist 保留了当时打包的 `tests/` 和 `l4wall.egg-info`；本次为了保持字节一致而没有清理。新的 `l4wall-v*` 发布流会对未来构建执行测试、缓存、密钥和许可证检查。
- 历史资产没有 GitHub artifact attestation；本发布只声明其 SHA-256 与 `v0.11.0` 官方资产记录一致，不声称存在构建 provenance。

## 发布产物

- `l4wall-0.1.0-py3-none-any.whl`
- `l4wall-0.1.0.tar.gz`
- `SHA256SUMS`（只包含上面两个 L4Wall 文件）

SHA-256：

```text
7bbbb9ad244ea5df911c697545e35089a15d3aa470fd4a497709d5d8df9b98bc  l4wall-0.1.0-py3-none-any.whl
5c5759e2a1f694b5296128622bbc3d31551097988cb1d85adaa1d8af46698dcf  l4wall-0.1.0.tar.gz
```

独立发布的标准下载位置是本 Release 的 **Assets**；旧版 `v0.11.0` 页面仅保留原始 L4Wall 附件以兼容旧链接。L4Wall 不提供 GHCR 镜像、PyPI 包或其他额外下载渠道，也不把 HighWall、L5Wall 或原生核心二进制打进 L4Wall 包。

## 状态

- 版本：`0.1.0`
- 成熟度：**Alpha / MVP**
- 运行时：Python 3.10+，只依赖标准库
- 覆盖：TCP 连接级防护；没有 TLS/HTTP 内容检查
- 审计与生产准入：未经过独立第三方安全审计，不是生产就绪产品

`v0.11.0` 的历史验证记录为 65 项 L4Wall 测试通过。本次独立发布额外复核资产哈希、干净虚拟环境安装、CLI 版本和初始化配置检查。

## 安装

先下载本 Release 的三个附件并校验：

```bash
sha256sum -c SHA256SUMS
python3 -m venv /opt/l4wall
/opt/l4wall/bin/pip install --no-cache-dir ./l4wall-0.1.0-py3-none-any.whl
/opt/l4wall/bin/l4wall --version
/opt/l4wall/bin/l4wall init --path ./config.json
/opt/l4wall/bin/l4wall check --config ./config.json
```

生产前请阅读 [L4Wall README](https://github.com/Fallen-leaves089/highwall/blob/main/subprojects/l4wall/README.md)、[部署基线](https://github.com/Fallen-leaves089/highwall/blob/main/subprojects/l4wall/docs/DEPLOYMENT.md) 和 [威胁模型](https://github.com/Fallen-leaves089/highwall/blob/main/subprojects/l4wall/docs/THREAT_MODEL.md)。

## 边界

- 不处理带宽型 DDoS、SYN flood、UDP、QUIC/HTTP3 或运营商侧拥塞。
- 不解析 HTTP，不做认证、授权、WAF、DLP、TLS 终止或 JA3/JA4。
- 只保护显式配置的 listener；直连 HighWall 或上游仍会绕过 L4Wall，必须用监听地址和网络 ACL 收紧。
- 共享封禁在 `0.1.0` 中只有读取端；自动发布、Controller、多节点冲突合并和 HA 尚未实现。
- 不适用于已失陷主机；攻击者若能修改配置、审计或进程内存，L4 边界已经失效。

## 许可

Apache-2.0。许可证与 NOTICE 见仓库根目录；未来独立构建也会随 wheel/sdist 分发对应文件。
