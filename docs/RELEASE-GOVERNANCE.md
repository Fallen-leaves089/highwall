# 发布治理

本文件记录 HighWall 发布链路的仓库设置和人工门禁。它是操作约束，不是生产准入证明；`docs/DSH-SECURITY-ACCEPTANCE.md` 和版本发布说明中的未验证项仍然有效。

## 受保护的 tag

仓库规则集 `Release tags` 对以下 ref 启用 `deletion` 和 `update` 限制：

- `refs/tags/v*`
- `refs/tags/l4wall-v*`
- `refs/tags/l5wall-v*`

规则集没有 bypass actor。已发布 tag 不能被删除、移动或强制覆盖；需要撤销发布时，应发布新的修复版本，并把旧版本标记为受影响，而不是复用版本号。

## 发布审批

所有会写入 Release、GHCR 包或签名的工作 job 都引用 GitHub environment `release`。该环境至少要求一名维护者批准，使 tag 推送与最终发布之间保留一次显式人工确认。

当前仓库只有一个维护者，且环境允许自我批准和管理员绕过，因此该门禁主要用于防止误触发和误发布，不等同于双人复核。面向生产交付时，应增加第二名维护者，并改为禁止自我批准和管理员绕过。

发布前至少核对：

- 目标提交上的 CI、CodeQL 和所需回归全部通过；
- tag 格式与项目版本一致，且对应 release notes 已存在；
- `THIRD_PARTY_NOTICES.md` 与当前 `Cargo.lock` 一致，并由 GitHub 托管 CI 重新生成比对；
- `SHA256SUMS`、artifact attestation、镜像 provenance 和 cosign 签名可复验；
- 发布说明没有把 Alpha、C3 或未验收能力写成生产可用。

## 发布通道

Release 工作流只接受带数字序号的预发布 tag，避免 `alpha`、`beta`、`rc` 之间的语义混淆：

| Git tag | 通道 | Python 包版本 | GitHub Release |
| --- | --- | --- | --- |
| `v0.13.0-alpha.1` | Alpha | `0.13.0a1` | pre-release |
| `v0.13.0-beta.2` | Beta | `0.13.0b2` | pre-release |
| `v0.13.0-rc.1` | Release Candidate | `0.13.0rc1` | pre-release |
| `v0.13.0` | Stable | `0.13.0` | 正式版 |

L4Wall 和 L5Wall 使用相同规则，只把前缀分别换成 `l4wall-v` 和 `l5wall-v`。发布 job 从 tag 推导包版本，并在 runner 的工作副本中写入 Python PEP 440 版本和 Cargo 版本；不要求为每个预发布版本单独提交版本号修改。

预发布 Release 必须设置 `--prerelease`，标题带 `Alpha`、`Beta` 或 `Release Candidate`。L5Wall 的 `latest` 镜像 tag 只在 Stable 通道移动。

`workflow_dispatch` 只能重跑位于当前工作流提交上的既有 tag；脚本会检查 `HEAD` 与 `GITHUB_SHA` 一致，防止用旧 tag 生成指向新提交的 provenance。

## 供应链产物

HighWall 原生 Release 会执行两次干净构建并比较二进制，生成 `.buildproof.json`；还会为每个目标生成 CycloneDX JSON SBOM。SBOM、构建证明、原生二进制、Python 包和 `THIRD_PARTY_NOTICES.md` 一起进入 `SHA256SUMS` 和 build provenance attestation。

发布流程会在上传前执行 `gh attestation verify`。L5Wall 和 HighWall 镜像在签名后执行 `cosign verify`；`sign-image.yml` 在签名前验证镜像 provenance 来自本仓库的 `container.yml`。

## 工作流约束

- GitHub Actions 只使用 GitHub 托管 runner，不配置自托管 runner。
- 所有第三方 Action 固定到完整提交 SHA；仓库设置 `sha_pinning_required=true` 会拒绝未固定的引用。
- 仓库只允许 GitHub 官方 Action，以及 `docker/setup-buildx-action`、`docker/login-action`、`docker/metadata-action`、`docker/build-push-action`、`sigstore/cosign-installer`。
- `workflow_dispatch` 重跑只用于同一个既有 tag。发布 job 会更新已有 Release 资产，不应创建第二个同版本 Release。
- 发布 job 的写权限必须保持最小化；验证 job 继续使用 `contents: read`。
- 任何发布路径改动都应在临时公开仓库用真实 tag 验证，不直接拿正式 tag 试跑。
