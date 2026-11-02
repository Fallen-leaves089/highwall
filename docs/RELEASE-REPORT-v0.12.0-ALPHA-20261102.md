# HighWall v0.12.0 Alpha 发布报告

- 报告日期：2026-11-02（Asia/Shanghai）
- 发布结论：**允许作为 Alpha 预发布公开；不得作为生产版本发布。**
- 仓库：`Fallen-leaves089/highwall`
- 生产回滚基线：继续固定 `v0.11.0`，不要依赖 `latest`。

## 1. 发布结论

HighWall `v0.12.0` 已完成 GitHub pre-release 发布，状态为 `prerelease=true`、`draft=false`。Release、Container、CI、CodeQL 工作流均成功，发布资产、容器镜像、平台列表、GitHub 来源证明和独立 L5Wall 服务均已复核。

本次只满足 **Alpha 公开评审和隔离验证** 门槛，不满足生产准入。DSH 对生产发布的 `no-push` 建议保持不变；H1/H2/H3 仍只声明 C3，不能写成 C4 或完整防护。

## 2. 发布标识

| 项目 | 值 |
|---|---|
| PR | `#23`，已 squash 合并 |
| PR 地址 | https://github.com/Fallen-leaves089/highwall/pull/23 |
| PR 头提交 | `bb1a1d9b1484c13f9d88d1f1a27d8802620d3c02` |
| 合并提交/标签目标 | `821048de27efd94ee268660c45d444088e2a7630` |
| 标签 | `v0.12.0`，annotated tag |
| Release | https://github.com/Fallen-leaves089/highwall/releases/tag/v0.12.0 |
| Release 标题 | `HighWall 0.12.0 (Alpha)` |
| 仓库 Latest | 仍为 `v0.11.0`，未被本次预发布或 L5Wall 发布覆盖 |

PR 头提交的 16 项检查全部成功；合并提交上 GitHub 可见的 26 个 check-run 全部成功。`v0.12.0` 标签、合并提交和 Release 源提交一致。

## 3. Release 资产

资产校验：下载后先核对 `SHA256SUMS`，再用 `scripts/check_dist.py` 检查发行包内容。

| 资产 | 字节 | SHA-256 | GitHub 来源证明 |
|---|---:|---|---|
| `highwall-0.12.0-py3-none-any.whl` | 128,642 | `e0f9ced29894f7a84165bd25df0c0fc1bfaaf5386d604a22885731073909b05d` | 1 条 SLSA provenance v1 |
| `highwall-0.12.0.tar.gz` | 464,863 | `a2cec0976721f289d07ada04593aef3aa13f23b644127d485d522ee495ec4979` | 1 条 SLSA provenance v1 |
| `highwall-native-config-0.12.0.example.json` | 3,699 | `0c873ce8ae30f14905dde0629596f3cf3b62b4dd1c7ec0ccabd07585e09dc328` | 1 条 SLSA provenance v1 |
| `highwall-native-core-0.12.0-linux-x86_64` | 10,731,080 | `63bc9572f9bccba2f683c678b699b1b43454160c39afee5e944eab6a0cb24545` | 1 条 SLSA provenance v1 |
| `highwall-native-core-0.12.0-windows-x86_64.exe` | 7,821,312 | `64342fd4711db0fc3e5acb3dcc33e49b1d2c830d6df67b943b61fb7ee694c5b5` | 1 条 SLSA provenance v1 |
| `SHA256SUMS` | 517 | `174d458873f65d65900a50b0efe2052eba0fdd0f3293cde849260d6ebf11080b` | 1 条 SLSA provenance v1 |

维护者下载产物后重新计算的 SHA-256 与 `SHA256SUMS` 完全一致；GitHub Release API 返回的 asset digest 也与上述值一致。6 个资产均能通过 GitHub Attestations API 查询到 1 条 `https://slsa.dev/provenance/v1` 证明。

发布版 wheel 已在全新虚拟环境安装成功，`highwall --version` 输出 `0.12.0`。发布版 Windows 原生二进制输出版本 `0.12.0`，示例配置执行 `--check` 返回 `configuration ok`。`scripts/check_dist.py` 对最终发布包通过。

## 4. GHCR 镜像与供应链信息

镜像：`ghcr.io/fallen-leaves089/highwall`

主 digest：`sha256:d7c826352cf7cef04917a3f768769f456abe49d3ba45795d2f5537ccd4e4569f`

| 标签 | digest | 状态 |
|---|---|---|
| `0.12.0` | `sha256:d7c826352cf7cef04917a3f768769f456abe49d3ba45795d2f5537ccd4e4569f` | 指向本次预发布 |
| `0.12` | 同上 | 一致 |
| `sha-821048d` | 同上 | 一致 |
| `latest` | `sha256:efedb3b9cca32a65f086c1a2ba89ae3c268a45e7a94a4158acfa5e8cda6c2dfc` | 仍指向 `0.11.0` |
| `0.11.0` | 同上 | 与 `latest` 完全一致 |

OCI image index 内容已复核：

| 平台 | 平台 manifest digest |
|---|---|
| `linux/amd64` | `sha256:1e7f7191afc79189d705430ba0dd4c1afedd77e4caf9918bd4bf87dd916ab77e` |
| `linux/arm64` | `sha256:f33bc9430702a080af0e7d545a90b23fd76817ff159298a926919fae644a6559` |

索引中另有 2 个 `attestation-manifest`，分别对应 amd64 和 arm64；每个证明 manifest 同时包含 SPDX SBOM 和 SLSA provenance v1。GitHub Attestations API 对顶层 image digest 返回 1 条 SLSA provenance v1，subject 为 `ghcr.io/fallen-leaves089/highwall`，digest 与主镜像一致。

cosign keyless 签名 tag 存在：

- `sha256-d7c826352cf7cef04917a3f768769f456abe49d3ba45795d2f5537ccd4e4569f.sig`
- 该签名 manifest 的 registry digest：`sha256:505e8ca639a4653e0dd74e841c64bb66f1dbb9385e03996f17c41230be8977fb`

本轮完成的是签名 tag 和证明存在性核验，未独立重新执行 cosign 密码学验签。镜像为 **Python-only 镜像**，不是完整 B+D-4 数据面；`Dockerfile.native` 本轮没有作为公开 GHCR 镜像发布，原生路径以 Release 中的独立二进制为准。

## 5. 工作流结果

| 工作流 | 结果 | 地址 |
|---|---|---|
| CI | success | https://github.com/Fallen-leaves089/highwall/actions/runs/41373105083 |
| CodeQL | success | https://github.com/Fallen-leaves089/highwall/actions/runs/41373105080 |
| Container | success | https://github.com/Fallen-leaves089/highwall/actions/runs/41373125373 |
| Release | success | https://github.com/Fallen-leaves089/highwall/actions/runs/41373125382 |
| L5Wall Release | success | https://github.com/Fallen-leaves089/highwall/actions/runs/41366457334 |

CI 覆盖 Python 3.10–3.14、Linux/Windows 原生执行、L5Wall package、原生核心构建和 CodeQL；Release/Container 均在合并提交 `821048de27efd94ee268660c45d444088e2a7630` 上运行。

## 6. 维护者与远程验证

| 范围 | 结果 |
|---|---|
| 根 Python | 384 项通过，1 项原生串联默认跳过；分支覆盖率 81% |
| L4Wall | 71 项通过 |
| L5Wall | 36 项通过 |
| 原生核心 | 144 项通过 |
| L4Wall → native PROXY v2 真实串联 | 1 项通过 |
| 静态检查 | `ruff`、`mypy`（30 个根源文件）、`compileall` 通过 |
| 解析器 fuzz | 2,000 轮、8,000 次检查，0 unexpected |
| 配置检查 | 示例配置 `check`、`--strict`、`highwall diff` 通过 |
| Rust 质量门禁 | `cargo fmt --check`、`cargo clippy --all-targets --locked -- -D warnings`、锁定依赖 release build 通过 |
| 发布产物 | `check_dist.py` 通过；wheel 可安装；原生二进制可执行且配置检查通过 |

维护者 R7 定向回归结果：

- HWA-04：重复 `:path`、`:method`、`:authority` 均返回 H3 `H3_MESSAGE_ERROR` 270，上游命中 0；合法 raw QPACK 正对照通过。
- HWA-05：四个 HEAD 路由均为 200，保留正确 `Content-Length`，正文 0 B，每个上游命中 1。
- HWA-06：单行 8192 B 为 200/上游命中 1；8193 B 为 413 `HW-NATIVE-PROTOCOL-001`/上游命中 0。

R7 是维护者执行的仓库内定向回归，不是 DSH 独立复测，不能把 HWA-04/05/06 写成 DSH 已独立关闭。

## 7. 安全验收状态

- DSH 首轮独立验收：0 Critical、0 High、3 Medium、8 Low、3 信息项。
- r5 定向复测：0 Critical、0 High；8 个指定项中 7 项定向关闭。
- r6：HWA-11 在窄范围独立复测中关闭。
- HWA-04/05/06：由维护者 r7 以可重复仓库内测试复核通过，但未获 DSH 独立复测。
- 完整生产准入、人工复核、真实边缘拓扑验收和独立第三方安全审计仍未完成。

因此，本版本可发布为 Alpha 预发布和脱敏、可复现的验证记录，不能当作安全认证或生产可用证明。

## 8. 残余风险与明确边界

- H1/H2/H3 仍只声明 C3，不声明 C4；流式背压饱和、QPACK 阻塞、真实 WebSocket 端到端和完整 slow-flow 覆盖仍未关闭。
- H3/UDP 当前绕过 L4Wall；应用层 QUIC ACL 不能替代主机防火墙、安全组或网络层 UDP 来源限制。
- 被封禁来源仍可能先完成 TLS/QUIC 握手，再收到 HTTP 403；当前只证明应用层拒绝，不证明握手前零成本。
- 原生封禁是进程内状态，带 TTL 和容量上限；重启会清空，单写者持久状态服务尚未接入，多节点一致性未验收。
- 运行中进程映像没有独立 attestation；Release 资产和镜像 provenance 只证明构建产物来源，不证明某个运行进程就是该产物。
- 真实 Docker/HAProxy 拓扑、`standard` 容器拓扑、原生公开镜像、审计写失败拓扑和多节点状态未完成验收。
- 本轮镜像由 GitHub Actions 构建；未在仓库 CI 之外重复 Docker 拓扑验收。
- 尚未完成独立第三方安全审计；DSH 结果不等于外部审计证书。
- cosign 签名 tag 存在性已核验，但本轮未独立重新执行密码学验签。
- `SECURITY.md` 仍写着“当前源码与最新发布版本均为 0.11.0”，属于非阻断的文档陈旧项；建议下个文档 PR 改为“最新稳定版 0.11.0，0.12.0 为 Alpha 预发布源码”。该问题不影响本次 tag、资产或镜像。

## 9. L5Wall 独立服务发布

L5Wall 继续保持为独立子项目服务，不并入 HighWall Python wheel。

| 项目 | 值 |
|---|---|
| 标签 | `l5wall-v0.2.0` |
| 标签提交 | `8e44e4ee01039d0d8ae9921773987891fecfe7b8` |
| Release | https://github.com/Fallen-leaves089/highwall/releases/tag/l5wall-v0.2.0 |
| Release 状态 | 正式 Release，但 `latest=false`，未覆盖主项目 Latest |
| 镜像 | `ghcr.io/fallen-leaves089/l5wall:0.2.0` |
| 镜像 digest | `sha256:f87eb6704b368cf959d17c525070c4f94de4dcb5e8f1435214ed5ab7a81172bf` |
| 平台 | `linux/amd64`、`linux/arm64` |
| 签名 | keyless 签名 tag 存在 |
| 证明 | 两个平台各含 SPDX SBOM 与 SLSA provenance v1 |

L5Wall Python 资产：

| 资产 | SHA-256 |
|---|---|
| `l5wall-0.2.0-py3-none-any.whl` | `7d20ba5455af149781ab90db534ad6ab9ec51ad4446d1dc6592d02876b3e93e5` |
| `l5wall-0.2.0.tar.gz` | `4622b77c4fa537936077c9f5822ba44cd5c6b193d6201d988b2b6b3a22ddc842` |
| `SHA256SUMS` | `40251ac8f2d616f8552c0e2f72cf52ebbec13522f9926071007e85440cb04e8e` |

L5Wall `0.2.0` 的覆盖等级仍是 C1，只做 TLS 终止和有界 HTTP/1.1 回环桥接；只接受 `http/1.1` ALPN，不转发真实客户端 IP，不能替代 L4/L7/H2/H3 数据面。它是独立服务发布，不是生产就绪的完整 L5。

## 10. 回滚与使用建议

- 生产环境继续固定 `v0.11.0`；容器回滚固定 digest `sha256:efedb3b9cca32a65f086c1a2ba89ae3c268a45e7a94a4158acfa5e8cda6c2dfc`。
- 不要依赖 `latest`；本次发布没有移动 `latest`，它仍与 `0.11.0` 一致。
- 评估 0.12.0 时使用 Release 中的固定资产和固定镜像 digest，先核对 `SHA256SUMS`、GitHub provenance 和 OCI 证明，再在隔离环境完成入口、真实来源、H3/UDP 网络层封堵和回滚演练。
- L5Wall 只能作为独立 Alpha 服务验证，不应替代现有生产入口或按真实客户端 IP 做封禁的链路。
- 如果撤销预发布，只应撤销 GitHub pre-release 和标签引用，不应把 `latest` 或生产环境切换到 0.12.0。

## 11. 收尾核验

- 维护者工作树干净，HEAD 为 `821048de27efd94ee268660c45d444088e2a7630`。
- `v0.12.0` 是 annotated tag，指向同一合并提交。
- 6 个 Release 资产的大小和 SHA-256 全部与发布记录及 GitHub API 一致。
- GHCR `0.12.0`、`0.12`、`sha-821048d` 为同一 digest；`latest` 与 `0.11.0` 仍为同一旧 digest。
- L5Wall `l5wall-v0.2.0` 独立 Release 和镜像存在，未被标记为仓库 Latest。
- 未发现需要阻断本次 Alpha 预发布的资产、工作流或镜像一致性问题。

**最终决定：发布完成，可作为 Alpha 预发布公开评审；生产发布仍保持拒绝，继续固定 0.11.0。**
