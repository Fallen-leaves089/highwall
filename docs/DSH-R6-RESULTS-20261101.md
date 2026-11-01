# DSH r6 HWA-11 独立窄范围复测结果（2026-11-01）

- 状态：HWA-11 窄范围复测完成，**closed (narrow HWA-11 retest only)**；完整生产准入未完成；记录生成时未推送，脱敏后随公开仓库发布
- 被测对象：HighWall `0.12.0.dev0` 工作树中的 Rust 原生 B+D-4 数据面与 L4Wall 串联靶场
- 基线提交：`114e8f11af508c550f8a64f4ec85ed826fd964bb`（`main`，工作树包含未提交修改）
- 独立测试方：DSH（DeepSeek Harness）AI Agent
- 唯一目标：`192.0.2.10:18443` 的 TCP 和 UDP；SNI/`:authority`/Host 为 `gateway.test`（公开版使用 RFC 5737 文档地址替换实验室地址）
- 独立报告：`dsh-evidence/highwall-remediation-r6-20261101/report-r6.md`，SHA256 `7D69900B1B02FB13F56C70FB4E5450D20881C68264B7CCC37439811625E2B102`
- 机器汇总：`dsh-evidence/highwall-remediation-r6-20261101/summary-r6.json`，SHA256 `8272FA65146DD7D27F611EE5E337F0B80CE9B003A4A52E0CBA5D82F033159517`
- 证据目录：`dsh-evidence/highwall-remediation-r6-20261101/evidence-r6/`，38 个文件、433,281 B

> 本文是授权隔离靶场中的定向复测摘要，不是第三方审计、安全认证、完整生产准入或发布许可。`closed` 只适用于 HWA-11 的线路与审计断言；不能外推到其他 HWA 项、其他协议、管理面、资源饱和或真实生产拓扑。

> 公开脱敏说明：实验室私网地址已替换为 RFC 5737 文档地址；本机绝对路径、进程号、一次性浏览器配置和未被 Git 跟踪的原始证据已移除或改为逻辑路径。原始证据不随仓库发布。

## 1. 结论

- HWA-11 的五项核心断言 A–E 全部通过，DSH 判定 **closed**。
- 本轮新增 Critical、High、Medium、Low 均为 **0**，发现总数为 0。
- 畸形请求的 upstream 命中总数为 **0**；HWA-11 审计 detail 中原始 Host/authority 值泄漏为 **0**。
- 测试量为 **8 个 HTTP 请求 + 1 个无 HTTP 的 TCP 连通探针**；没有观察到 `403 HW-NATIVE-BAN-001` 或 `429` 限流响应。
- DSH 判定 `production_ready=false`、`push_recommendation=no push`。本轮结论可支持人工发布评审，但不能作为生产准入依据；公开源码与脱敏测试记录由用户另行授权，不属于生产发布。

## 2. 产物与快照证据

- 二进制副本：7,814,656 B，SHA256 `07E213C92D395616FBF9F8DB190EA2938670E0AC9C74D6EEA088AAD98D776A89`；DSH 用 `sha256sum`、`openssl dgst -sha256` 和 Python `hashlib` 三种方法独立重算，结果一致且匹配 manifest。
- native 配置：SHA256 `5DC379871C407E50211927191268D9C1E0DA029DDB8A91F428CE1F6D489C0A24`。
- L4Wall 配置：SHA256 `6605329586BCB1B190EDA7E713B4B1C8289B0C3193C80009107AB4B1BAEC6BF4`。
- 源码快照：`source-clean/` 的 87/87 个文件校验通过；清单 SHA256 为 `AFA177F2C3C8BAE4FB8E1CBADB1F649E3C288BB21C4D7FD04D87C8636A9D692D`。
- 运行审计副本：native audit 13 行、upstream 4 行、L4Wall audit 6 行；原始审计、upstream、运行日志和证书公钥均以只读方式复制到 `evidence-r6/logs/`。
- 进程绑定：维护者记录了 PID 和 native 映像哈希，但公开版不保留进程号与本机路径；这不是 DSH 的独立进程取证。

## 3. 逐项结果

| 用例 | 断言 | 观察结果 | 判定 |
|---|---|---|---|
| A | H3 同时缺失 `:authority` 和 Host | HTTP `400`，空正文；`STOP_SENDING` 270；无响应侧 `RESET_STREAM`；upstream 命中 0；审计 `HW-NATIVE-H3-AUTHORITY-001`，`response_result=sent` | **pass** |
| B | `:authority=gateway.test` 与唯一 nonce 的 Host 不一致 | HTTP `400`，空正文；`STOP_SENDING` 270；upstream 命中 0；审计 `HW-NATIVE-H3-AUTHORITY-002`，`response_result=sent`；原始不匹配 Host 和 nonce 未进入审计 | **pass** |
| C | `:authority=localhost` 与泄漏探针 Host 不一致 | HTTP `400`，空正文；`STOP_SENDING` 270；upstream 命中 0；审计 `HW-NATIVE-H3-AUTHORITY-002`；原始 Host、authority 和 nonce 均未进入审计 | **pass** |
| D | 正常 H3 `GET /ok` 阳性对照 | HTTP `200`，正文 `ok`（2 B）；upstream 命中 +1；没有 HWA-11 authority 审计事件 | **pass** |
| E | 客户端立即取消接收，强制空 400 发送失败 | 未观察到 HTTP 响应；服务端线路出现 `STOP_SENDING` 270 和 `RESET_STREAM` 270；审计 `HW-NATIVE-H3-AUTHORITY-001`，`response_result=failed`；upstream 命中 0 | **pass** |

## 4. 审计与不泄漏结论

- HWA-11 审计规则计数：`HW-NATIVE-H3-AUTHORITY-001` ×2、`HW-NATIVE-H3-AUTHORITY-002` ×2。
- A/B/C/E 的客户端状态、wire 事件和 native 审计能够逐项对账；畸形请求没有出现在 upstream 记录中。
- `gateway.test` 仅出现在独立的 TLS server-name 元数据字段 `tls_server_name`，没有出现在 `detail` 字段，也不是从请求 authority/Host 派生。
- 审计中没有出现原始 Host、authority、nonce 或完整 URL；没有观察到封禁或限流副作用。
- 一次 TCP 连通探针产生了与本项无关的 `HW-NATIVE-TLS-001`；它不改变 HWA-11 的判定。

## 5. 边界与残余风险

1. **只测 HWA-11。** 本轮没有重测 HWA-01 至 HWA-10，也没有重测管理面、Safe Ops、审计写失败、流控饱和、慢速耗尽、WebSocket/gRPC 端到端或真实容器编排。
2. **没有独立进程取证。** DSH 无法从 Kali 查询 Windows PID 或哈希运行中的 Windows 进程映像，`process_image_independent_attestation=false`；线路与审计通过不能证明运行进程执行的正好是所测副本。
3. **H3/UDP 仍绕过 L4Wall。** L4Wall 只覆盖 TCP；UDP QUIC/H3 直连原生 listener，L4Wall 的 ACL、限流、威胁评分和封禁不覆盖 UDP。必须在主机防火墙或安全组单独限制 UDP 来源。
4. **不是生产准入。** 运行配置为一次性自签名实验室证书和自声明测试主机；没有连接真实业务、真实证书、真实数据或凭据。
5. **DSH 当时建议 no push。** 该建议针对生产准入；后续用户明确授权公开源码和脱敏测试记录，但不包含 tag、二进制 release 或生产上线许可。

## 6. 发布与复现建议

进入正式生产发布评审仍需：完成运行进程/构建来源绑定、SBOM 和可复现构建证明；确认 H3/UDP 网络层限制和封禁后握手成本；完成管理面/Safe Ops/审计故障/流控饱和/真实容器拓扑的范围确认；对残留 Medium 形成书面风险接受；由人工审批人复核 r5/r6 原始证据。**DSH 对生产发布仍建议 no push。**

复现顺序：`scripts/preflight.py` → `scripts/run_baseline.py` → `scripts/run_hwa11_cases.py` → `scripts/audit_correlation.py` → `scripts/analyze_timeline.py` → `scripts/snapshot_runtime_evidence.py`。快照应在最后执行，以保持运行审计副本字节一致。

## 7. 本地收尾

- 已停止一次性 upstream、native、L4Wall、DSH supervisor/web 和专用 headless Edge；DSH 已切回 `locked`。
- 已复核 18443/18444/18445 TCP、18443 UDP、3080 和 9333 均无监听，r6 靶场进程均已退出。
- 未执行递归删除；构建缓存、测试证书/私钥和一次性浏览器配置均未纳入公开仓库，也没有上传或压缩。具体清理记录保留在未发布的维护者快照中。
