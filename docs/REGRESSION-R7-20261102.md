# HighWall 0.12.0 R7 维护者定向回归（非独立验收）

- 日期：`2026-11-02`
- 被测对象：HighWall `0.12.0` Alpha 发布候选中的 Rust 原生数据面
- 基线：`d6f9512` 加 0.12.0 发布候选修改
- 范围：仅复核 HWA-04、HWA-05、HWA-06，并重跑原生核心全量测试
- 性质：**维护者执行的仓库内定向回归，不是 DSH 独立安全验收，也不能替代生产准入**

## 结论

HWA-04、HWA-05、HWA-06 在本轮可重复测试中通过，且拒绝路径均验证了上游零命中或准确的边界行为。维护者定向回归只能解除“缺少可重复测试证据”这一项疑问；DSH 对这些编号的独立状态仍是未在 r5/r6 复测。不得把本结果写成 DSH 已独立关闭，也不得据此改变 C3 声明、H3/UDP 边界或生产发布结论。

## 定向结果

| 编号 | 用例 | 请求数 | 观察结果 |
|---|---|---:|---|
| HWA-04 | `h3_raw_qpack_duplicate_pseudo_header_is_rejected_before_upstream` | 1 | 重复 `:path` 被重置为 H3 `H3_MESSAGE_ERROR` 270，上游命中 0 |
| HWA-04 | `h3_duplicate_method_is_reset_with_h3_message_error_before_upstream` | 1 | 重复 `:method` 被重置为 270，上游命中 0 |
| HWA-04 | `h3_duplicate_authority_is_reset_with_h3_message_error_before_upstream` | 1 | 重复 `:authority` 被重置为 270，上游命中 0 |
| HWA-04 正对照 | `h3_raw_qpack_valid_request_is_a_positive_control` | 1 | 合法 raw QPACK 请求到达上游，证明拒绝不是测试夹具整体失效 |
| HWA-05 | `h1_head_response_without_body_is_forwarded_as_success` | 4 | `/ok`、`/status/200`、`/large`、`/echo` 均为 200，保留正确 `Content-Length`（2048、6、2097152、0），正文 0 B，每个请求上游命中 1 |
| HWA-06 | `h1_header_line_limit_is_exact_at_the_configured_boundary` | 2 | 单行 8192 B 为 200、上游命中 1；8193 B 为 413 `HW-NATIVE-PROTOCOL-001`、上游命中 0 |

HWA-04 的 3 个拒绝请求、HWA-05 的 4 个 HEAD 请求和 HWA-06 的 2 个边界请求合计 9 个定向请求；另加 1 个 H3 正对照。测试代码位于 [`subprojects/native-core/tests/security_regressions.rs`](../subprojects/native-core/tests/security_regressions.rs) 与 [`subprojects/native-core/tests/protocols.rs`](../subprojects/native-core/tests/protocols.rs)。

## 复现命令

在 `subprojects/native-core` 中执行：

```powershell
cargo test --all-targets --locked h3_raw_qpack_duplicate_pseudo_header_is_rejected_before_upstream
cargo test --all-targets --locked h3_duplicate_method_is_reset_with_h3_message_error_before_upstream
cargo test --all-targets --locked h3_duplicate_authority_is_reset_with_h3_message_error_before_upstream
cargo test --all-targets --locked h3_raw_qpack_valid_request_is_a_positive_control
cargo test --all-targets --locked h1_head_response_without_body_is_forwarded_as_success
cargo test --all-targets --locked h1_header_line_limit_is_exact_at_the_configured_boundary
cargo test --all-targets --locked
```

全量 `cargo test --all-targets --locked` 结果为 **144 passed，0 failed**。

## 边界与残余风险

- 本记录没有使用 DSH supervisor socket，也没有独立进程映像 attestation；运行中二进制与构建来源仍未获得独立证明。
- HWA-04 的通过范围是 raw QPACK 重复伪头部；不覆盖全部 QPACK 状态机、动态表阻塞或所有 H3 实现差异。
- HWA-05 验证的是 HEAD 响应不透传正文且保留声明的长度；不等于覆盖所有上游错误、压缩与 trailers 组合。
- HWA-06 验证的是配置边界 8192/8193 B；不替代完整慢速头部、并发连接和容器边缘验证。
- H3/UDP 仍绕过 L4Wall；封禁来源仍可能先完成 TLS/QUIC 握手；H1/H2/H3 仍只声明 C3。
- 真实 Docker/HAProxy 拓扑、管理面、Safe Ops 执行器、审计写失败、QPACK 阻塞和流式背压饱和仍未验收。

因此，本轮结果支持 **0.12.0 Alpha 预发布**，不支持生产发布。DSH 对生产发布的 no-push 建议保持不变。
