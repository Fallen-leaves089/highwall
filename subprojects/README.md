# HighWall 子项目

本目录存放与 HighWall 同仓库、但可以独立安装和测试的子系统。当前只有 L4Wall。

## L4Wall

`l4wall/` 是失败关闭的 TCP L4 防护网关，负责连接级准入、限速、超时、行为评分、封禁和审计。它不替代 HighWall 的 L7 WAF/DLP，也不替代主机防火墙、云清洗或应用自身的认证授权。

### 两种运行形态

- `lite`：L4Wall 直接串联在客户端和 HighWall 之间，适合单机、小规模和 Windows。当前 Python 实现就是这一形态。
- `standard`：HAProxy/Envoy 承担数据面，L4Wall 作为控制面，负责评分、封禁和审计。标准部署骨架见 `../deploy/standard/`，控制面进程仍在后续里程碑中。

可选共享封禁读取端已经可用：从私网 Redis 增量导入版本化 JSON，本地封禁优先，超时/坏数据/容量不足都不会清空本地封禁或拖垮数据面。自动发布端和 Controller 尚未实现。

### 独立验证

```powershell
cd subprojects/l4wall
python -m unittest discover -s tests -q
python scripts/demo.py
python -m l4wall check --config config.example.json
```

### 边界

- 只处理显式配置的 TCP listener。
- 不抗 SYN flood、带宽型 DDoS、UDP/QUIC。
- 不做 TLS 终止、SNI、JA3/JA4。
- 详细边界见 `../docs/STACK.md` 和 `l4wall/docs/THREAT_MODEL.md`。
