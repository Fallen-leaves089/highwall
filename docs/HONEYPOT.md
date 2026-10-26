# HighWall 自定义蜜罐

本文说明 `policy.honeypot` 的行为、配置和运维注意事项。蜜罐是应用层诱捕，不是高交互沙箱，也不提供反制。

## 1. 处理顺序

请求进入 HighWall 后，蜜罐判断位于以下顺序：

```text
严格 HTTP 解析
  -> 连接/限速/现有临时封禁
  -> 客户端 CIDR ACL
  -> Host 白名单
  -> 路径解码、点段检查、NFKC 规范化
  -> 蜜罐精确路径匹配
       |-- 命中：本地静态响应，审计 + 可选首击封禁 + 可选拖延，结束
       `-- 未命中：普通方法/路径/WAF/只读/路由策略 -> 上游
```

因此：

- 蜜罐路径可以捕获 `deny_path_prefixes` 中的扫描路径，例如 `/.env`，也可以位于 `allowed_path_prefixes` 之外。
- Host 和客户端 ACL 仍然优先。错误 Host 或被 ACL 拒绝的来源不会得到诱饵响应。
- 命中后不连接上游，不读取上游，不返回上游错误页。
- 蜜罐路径不套用普通 `allowed_methods`、Content-Type、Origin、只读和 WAF 规则，避免扫描器在到达诱饵前就被普通 403 挡住。

## 2. 配置

```json
{
  "policy": {
    "honeypot": {
      "enabled": true,
      "ban_seconds": 0,
      "presets": ["common"]
    }
  }
}
```

`presets` 可以只写一行就启用一组内置诱饵。建议先以 `ban_seconds=0` 观察命中与误触，再启用首击封禁。

字段：

| 字段 | 说明 |
|---|---|
| `enabled` | 默认 `false`。开启时至少需要一个 `presets` 或 `routes` 条目。 |
| `ban_seconds` | 首击封禁秒数，`0` 表示不因蜜罐命中封禁。默认 900，最大 86400。 |
| `presets` | 内置预设组或单个模板名，最大 32 项；未知名称会在启动时失败。 |
| `routes[].id` | 小写 DNS 风格标签，用于审计规则 ID：`HW-HONEY-<id>`。 |
| `routes[].path` | 规范化后的精确路径，不接受通配符、查询串、百分号转义或点段。 |
| `routes[].status` | 200–499，不允许 204/304。 |
| `routes[].content_type` | 合法 media type；默认 `text/plain; charset=utf-8`。 |
| `routes[].body` | 静态 UTF-8 文本，最多 64 KiB。 |
| `routes[].headers` | 最多 16 个安全自定义响应头。 |
| `routes[].server_header` | 诱饵 `Server` 值，默认 `HighWall`，最长 128 个可打印 ASCII 字符。 |
| `routes[].delay_ms` | 0–5000 ms 的有界延迟，默认 0。 |

禁止在 `headers` 中设置由网关托管的头，包括 `Content-Type`、`Content-Length`、`Connection`、`Set-Cookie`、`Server`、`Date`、`X-Request-ID`、hop-by-hop 头和传输编码相关头。

### 内置预设

| `presets` 名称 | 包含的模板 |
|---|---|
| `common` | `secrets`、`wordpress`、`spring`、`admin`、`devops` 的合集，共 18 条路径。 |
| `secrets` | `/.env`、`/.git/config`、`/.git/HEAD`、`/.svn/entries`。 |
| `wordpress` | `/wp-login.php`、`/xmlrpc.php`、`/wp-config.php.bak`。 |
| `spring` | `/actuator/env`、`/actuator/heapdump`、`/actuator/threaddump`。 |
| `admin` | `/admin.php`、`/phpmyadmin`、`/phpmyadmin/`、`/manager/html`。 |
| `devops` | `/server-status`、`/swagger-ui.html`、`/openapi.json`、`/_cluster/health`。 |
| `cloud` | `/.aws/credentials`、`/.kube/config`；不包含在 `common` 中。 |

也可以直接列出单个模板名，例如：

```json
{"enabled": true, "presets": ["env_probe", "git_head", "wp_login"]}
```

模板路径、状态码和参考来源见 [`HONEYPOT-TEMPLATES.md`](HONEYPOT-TEMPLATES.md)。所有模板都是合成的静态内容，不复制厂商页面，也不包含真实凭证；运行时不联网下载模板。

### 自定义路由与覆盖

需要修改诱饵内容时，在 `routes` 中写同路径条目即可覆盖预设。显式路由会整体替换该路径的预设，而不是逐字段合并：

```json
{
  "enabled": true,
  "presets": ["secrets"],
  "routes": [
    {
      "id": "env_probe",
      "path": "/.env",
      "status": 200,
      "content_type": "text/plain; charset=utf-8",
      "body": "APP_ENV=production\nDB_PASSWORD=decoy-not-a-real-secret\n",
      "headers": {"X-Decoy": "environment"},
      "server_header": "nginx",
      "delay_ms": 0
    }
  ]
}
```

显式路由之间、预设之间以及两者合并后的最终路由都必须保持路径和 ID 唯一。选择多个预设时，相同模板只展开一次。

## 3. 安全性质

- 精确路径匹配：先完成与普通请求相同的解码和规范化，再做完整字符串比较。
- 静态响应：响应体和头只来自配置，不反射 URL、查询串、Header、Cookie 或请求体。
- 模板静态化：内置预设是代码内的合成诱饵，启动时走与自定义路由相同的校验；不会在运行时下载外部页面或模板。
- 不访问上游：蜜罐响应不会经过 `UpstreamProxy`，也不会消耗上游连接或熔断状态。
- 请求体只按声明的 `Content-Length` 分块丢弃，不整段缓冲；声明长度未满足时按普通 400 处理，不触发首击封禁。
- 审计最小化：只记录方法、路径（不含查询串）、来源、状态、规则 ID、耗时和字节数；不记录请求体、Header、Cookie、Authorization 或响应体。
- 有界资源：配置路由数、单路由 Body、Header 数、延迟和启动时内存均有上限。
- 封禁有界：首击封禁使用同样有容量上限的内存表，重启即清空；不会写入持久状态。
- 默认关闭：未启用时，认证、WAF、路径拒绝等原有失败关闭行为不变。

## 4. 指标与审计

命中会写入 JSONL：

```json
{"event":"honeypot_hit","outcome":"decoy","rule_id":"HW-HONEY-env_probe","path":"/.env"}
```

管理面指标：

| 指标 | 含义 |
|---|---|
| `highwall_honeypot_hits_total` | 蜜罐响应次数。 |
| `highwall_honeypot_bans_total` | 因蜜罐命中触发的首击封禁次数。 |
| `highwall_honeypot_ban_rejections_total` | 被蜜罐封禁拒绝的请求数。 |
| `highwall_honeypot_ban_entries` | 当前仍有效的蜜罐封禁数。 |

被封禁的后续请求返回 `429` 和 `Retry-After`。封禁后的请求不会再得到诱饵页面。

## 5. 运维建议

1. 只选择确实不存在的路径，例如 `/.env`、`/admin.php`、`/wp-login.php`、`/phpmyadmin`。不要把真实业务端点做成蜜罐。
2. `common` 同时包含 WordPress、Spring、phpMyAdmin、Tomcat、Apache 和 DevOps 路径；只在确认这些路径都不属于真实业务时使用，否则选择更窄的组或单个模板。
3. 诱饵内容必须明显是假数据。不要放入真实 token、私钥、Cookie、内部凭据或可被用于横向移动的地址；`cloud` 中的 AWS/Kubernetes 值仅为公开示例或无效占位符。
4. 在共享 NAT、办公网或反向代理后面启用首击封禁前，先用 `ban_seconds=0` 观察 `honeypot_hits_total` 和审计事件，确认没有正常用户误触。
5. 需要拖延时从小值开始，例如 250–1000 ms。延迟会占用全局在途槽位，不能替代速率限制或 DDoS 清洗。
6. 不要依赖蜜罐发现所有扫描；它只覆盖显式配置的路径，攻击者可以通过指纹、路径字典差异或直接访问真实端点绕过。
7. 蜜罐不采集请求 payload。若需要高交互取证，应使用隔离虚拟机、专用传感器和独立网络，不要在本网关进程内执行不可信内容。
8. 诱导性 `server_header` 只能降低明显的产品指纹，不构成安全边界；不要把它当作规避检测的保证。

## 6. 明确不做

- 不提供真实登录、文件读取、命令执行或数据库接口。
- 不保存攻击者提交的 body、Cookie 或 Header。
- 不发起反向连接、反制、指纹追踪或第三方告警。
- 不保证能识别自动化扫描、规避已知指纹或阻止定向攻击者访问真实路径。
- 不替代主机防火墙、WAF 上游修复、认证授权、EDR、备份或网络隔离。

蜜罐的价值是提高探测成本和产生高质量本地告警，而不是让上游应用自动变安全。
