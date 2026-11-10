# HighWall 自定义蜜罐

本文说明 `policy.honeypot` 的行为、配置和运维注意事项。默认模式仍是本地静态诱饵；
可以为独立蜜罐端口配置 `listeners[].backend`，把未命中静态路径的请求转发到隔离的
HTTP 高交互后端。网关自身不执行不可信内容、不提供反制，也不把高交互后端描述成
完整业务仿真。除主代理端口上的诱饵路径外，还可以配置多个独立蜜罐监听端口。

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

配置了 `listeners` 时，每个额外端口运行在同一套运行时的 honeypot-only 模式：

```text
严格 HTTP 解析 -> 连接/限速/封禁 -> 客户端 CIDR ACL -> Host 白名单 -> 路径规范化
       |-- 蜜罐精确命中：本地静态响应
       |-- 未命中且配置了 backend：只转发到该 listener 的独立 HTTP 后端
       `-- 未命中且没有 backend：直接 404，不进入普通路由或业务上游
```

因此：

- 蜜罐路径可以捕获 `deny_path_prefixes` 中的扫描路径，例如 `/.env`，也可以位于 `allowed_path_prefixes` 之外。
- Host 和客户端 ACL 仍然优先。错误 Host 或被 ACL 拒绝的来源不会得到诱饵响应。
- 静态命中只返回配置内容，不连接任何后端；配置了 `backend` 的端口仍优先返回静态命中。
- 未命中静态路径时，有 `backend` 的端口只连接该 listener 的专用后端；没有 `backend` 时直接 404。
- 后端失败只返回 502/504，不回落业务 `upstream`，不读取或返回业务错误页。
- 蜜罐路径不套用普通 `allowed_methods`、Content-Type、Origin、只读和 WAF 规则，避免扫描器在到达诱饵前就被普通 403 挡住。

## 2. 配置

```json
{
  "policy": {
    "honeypot": {
      "enabled": true,
      "ban_seconds": 0,
      "presets": ["common"],
      "listeners": [
        {"name": "decoy-admin", "listen_host": "127.0.0.1", "listen_port": 18092},
        {
          "name": "live-admin",
          "listen_host": "127.0.0.1",
          "listen_port": 18093,
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

`presets` 可以只写一行就启用一组内置诱饵。建议先以 `ban_seconds=0` 观察命中与误触，再启用首击封禁。

字段：

| 字段 | 说明 |
|---|---|
| `enabled` | 默认 `false`。开启时至少需要一个 `presets` 或 `routes` 条目。 |
| `ban_seconds` | 首击封禁秒数，`0` 表示不因蜜罐命中封禁。默认 900，最大 86400。 |
| `presets` | 内置预设组或单个模板名，最大 32 项；未知名称会在启动时失败。 |
| `listeners` | 额外的仅蜜罐监听端口，最多 32 个。要求 `enabled=true`；名称和端口必须唯一，且不得与主代理端口、管理端口或其他蜜罐端口冲突。 |
| `listeners[].name` | 小写 DNS 风格标签，用于日志区分端口。 |
| `listeners[].listen_host` | 可选 IP 字面量，默认继承 `server.listen_host`；不接受主机名。 |
| `listeners[].listen_port` | 必填，1–65535。 |
| `listeners[].backend` | 可选。配置后，该端口未命中静态路径时转发到独立 HTTP 高交互后端；没有此字段时未命中直接 404。 |
| `backend.scheme` | 只能是 `http`；需要 HTTPS 时由蜜罐 listener 终止 TLS。 |
| `backend.host` | 回环、RFC1918 或 IPv6 ULA 的 IP 字面量；禁止公网、链路本地、云元数据地址和域名。 |
| `backend.port` | 1–65535；不得指向业务 upstream、主代理、管理面或其他蜜罐 listener。 |
| `backend.host_header` | 可选，转发给后端的 Host；省略时使用入站 Host。 |
| `backend.server_header` | 后端没有返回 `Server` 时使用的回退值，默认 `nginx`。 |
| `backend.connect_timeout` / `read_timeout` / `total_timeout` | 后端连接、单次读取和整次交换上限；默认 2/15/30 秒。 |
| `backend.max_response_bytes` | 后端响应体上限，默认 4 MiB，最大 256 MiB。 |
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
| `build` | `/.npmrc`、`/docker-compose.yml`、`/Dockerfile`、`/package.json`、`/composer.json`、`/.gitlab-ci.yml`。 |
| `infra` | `/terraform.tfstate`、`/.htpasswd`、`/.vscode/settings.json`、`/backup.sql`。 |
| `observability` | `/phpinfo.php`、`/actuator/health`、`/actuator/mappings`、`/metrics`。 |
| `expanded` / `all` | 上述全部 34 个模板；启用前必须先排除与真实业务冲突的路径。 |

也可以直接列出单个模板名，例如：

```json
{"enabled": true, "presets": ["env_probe", "git_head", "wp_login"]}
```

模板路径、状态码和参考来源见 [`HONEYPOT-TEMPLATES.md`](HONEYPOT-TEMPLATES.md)。所有模板都是合成的静态内容，不复制厂商页面，也不包含真实凭证；运行时不联网下载模板。

### 独立蜜罐端口

`listeners` 解决“只有一个应用层端口时，蜜罐必须和真实业务共用 Host/路径空间”的局限。每个额外端口仍是 honeypot-only：不会进入普通路由、业务 WAF 链路或业务 `UpstreamProxy`。

- 额外端口与主端口共享同一个 `Runtime`，因此同一来源在主端口或任意蜜罐端口命中后，蜜罐封禁立即对所有端口生效。
- 额外端口同样受客户端 CIDR ACL、Host 白名单、请求解析、每客户端速率限制和审计失败关闭策略约束。
- 每个额外端口是独立的 `GatewayServer`，有自己的连接并发槽位；全局请求速率限制、指标、审计和蜜罐封禁仍然共享。
- 没有 `backend` 的端口只返回静态精确命中，其他路径直接 404。
- 配置 `backend` 的端口优先返回静态精确命中；其他路径只转发到该 listener 的专用高交互后端。
- 蜜罐路径仍然可以位于普通 `deny_path_prefixes` 或 `allowed_path_prefixes` 之外；未命中静态路径也不会因为存在“看起来像业务”的普通路由而被转到业务上游。
- `listeners`、`backend` 都属于启动配置。修改、增加或删除端口、后端地址或超时需要重启；热重载会拒绝这类变化并提示 restart required。
- 额外端口也使用主服务的 TLS 配置。主代理启用 TLS 时，蜜罐端口同样是 HTTPS。

### 高交互后端（可选）

`listeners[].backend` 允许把一个独立蜜罐端口接到隔离的 HTTP 服务。典型做法是让
HighWall 只做入口、Host/来源控制和资源限制，真实诱饵应用运行在只读、无出网、
无宿主挂载、可重置的容器或虚拟机中。可直接使用
[`deploy/honeypot`](../deploy/honeypot/README.md) 的最小闭环。

行为边界：

- 只支持 HTTP 后端，且必须是回环、RFC1918 或 IPv6 ULA 的 IP 字面量；禁止公网、链路本地、云元数据地址和域名。
- 后端不得指向业务 `upstream`、主代理、管理面、自身端口或其他蜜罐 listener；校验不看 scheme，避免用 `https` 别名绕过。
- 静态诱饵仍然优先；只有未命中静态路径时才连接后端。后端连接失败、超时或响应非法时返回 502/504，绝不回落到业务上游或熔断状态。
- 前端仍执行严格 HTTP 解析、Host 白名单、客户端 CIDR ACL、封禁、限速、连接/在途槽位、请求体上限和审计失败关闭。
- 高交互端口不套用业务 `allowed_methods`、路径前缀、Content-Type、Origin、只读、WAF、DLP、完整性和普通路由策略；否则登录、上传和真实应用交互会被业务规则提前破坏。
- 方法、路径、查询串、请求体和除逐跳头外的 Header 会转发到后端；`Host`、`X-Forwarded-For`、`X-Forwarded-Host` 和 `X-Forwarded-Proto` 由网关重写。`Authorization`、`Cookie` 等业务值不会被审计记录。
- 后端响应会保留 `Server`、`X-Powered-By` 和自定义业务头以维持诱饵真实性，但网关会剥离会改变浏览器来源状态或固定安全策略的头，包括 CSP/CSP-Report-Only、HSTS、CORS、`Clear-Site-Data`、`NEL`/`Report-To`、`Permissions-Policy`、`X-Frame-Options`、`X-Content-Type-Options`、`Refresh` 和 `Alt-Svc`。`Set-Cookie` 只保留同源普通 Cookie，删除 `Domain` 属性并拒绝 `__Host-`/`__Secure-` 前缀；`Location` 只保留相对地址，丢弃绝对 URL、协议相对 URL、控制字符和反斜杠。
- 高交互蜜罐必须使用独立的可注册域，不要复用生产域或生产子域。不同端口不是隔离边界：Cookie 不按端口隔离，浏览器可能把生产 Cookie 发送到同主机的蜜罐端口。响应头清洗降低污染面，但不能替代域名隔离；同源 Cookie 名称冲突、浏览器缓存和同站规则仍需独立域边界。
- `policy.max_body_bytes`、`backend.max_response_bytes` 和后端超时仍然生效。需要上传或长轮询时，必须显式提高这些上限并重新评估内存和连接预算。
- `ban_seconds` 的“首击封禁”只作用于静态诱饵命中；高交互请求不会因为一次交互自动封禁来源，否则会切断持续调查。已有的蜜罐封禁仍会拒绝所有端口。
- 高交互后端是**可被攻陷资产**。网关不执行它的内容，但不能修复后端应用漏洞、容器逃逸或横向移动；必须按 [`deploy/honeypot/README.md`](../deploy/honeypot/README.md) 的隔离、资源限制、重置和取证要求部署。

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
- 静态默认不访问上游：静态蜜罐响应不经过业务 `UpstreamProxy`，也不消耗业务上游连接或熔断状态。
- 高交互隔离：只有显式配置 `backend` 的 listener 才会连接专用后端；后端失败不会回落业务上游，也不会复用业务熔断状态。
- 后端地址约束：只允许回环、RFC1918 和 IPv6 ULA 的 IP 字面量，并拒绝业务上游、主代理、管理面、自身和其他蜜罐端口。
- 请求体只按声明的 `Content-Length` 分块丢弃，不整段缓冲；声明长度未满足时按普通 400 处理，不触发首击封禁。
- 高交互请求体受 `policy.max_body_bytes` 限制，转发前不会写入审计；后端响应还受头数量、头大小、framing、编码和 `max_response_bytes` 约束。
- 审计最小化：只记录方法、路径（不含查询串）、来源、状态、规则 ID、耗时和字节数；不记录请求体、Header、Cookie、Authorization 或响应体。
- 有界资源：配置路由数、单路由 Body、Header 数、延迟和启动时内存均有上限。
- 封禁有界：首击封禁使用同样有容量上限的内存表，重启即清空；不会写入持久状态。
- 可攻陷资产：高交互后端不是可信计算基。必须只读、无出网、无 Docker socket、无宿主挂载、资源受限且可重建；响应头清洗、独立域名和网关隔离不能替代后端补丁、容器安全与宿主防护。
- 默认关闭：未启用时，认证、WAF、路径拒绝等原有失败关闭行为不变。

## 4. 指标与审计

命中会写入 JSONL：

```json
{"event":"honeypot_hit","outcome":"decoy","rule_id":"HW-HONEY-env_probe","path":"/.env"}
```

高交互请求分别记录 `honeypot_backend_forwarded` 和 `honeypot_backend_error`。

管理面指标：

| 指标 | 含义 |
|---|---|
| `highwall_honeypot_hits_total` | 蜜罐响应次数。 |
| `highwall_honeypot_bans_total` | 因蜜罐命中触发的首击封禁次数。 |
| `highwall_honeypot_ban_rejections_total` | 被蜜罐封禁拒绝的请求数。 |
| `highwall_honeypot_ban_entries` | 当前仍有效的蜜罐封禁数。 |
| `highwall_honeypot_backend_requests_total` | 发往隔离高交互后端的请求数。 |
| `highwall_honeypot_backend_errors_total` | 高交互后端连接、超时或响应错误数。 |

被封禁的后续请求返回 `429` 和 `Retry-After`。封禁后的请求不会再得到诱饵页面。

## 5. 运维建议

1. 只选择确实不存在的路径，例如 `/.env`、`/admin.php`、`/wp-login.php`、`/phpmyadmin`。不要把真实业务端点做成蜜罐。
2. `common` 同时包含 WordPress、Spring、phpMyAdmin、Tomcat、Apache 和 DevOps 路径；只在确认这些路径都不属于真实业务时使用，否则选择更窄的组或单个模板。
3. 诱饵内容必须明显是假数据。不要放入真实 token、私钥、Cookie、内部凭据或可被用于横向移动的地址；`cloud` 中的 AWS/Kubernetes 值仅为公开示例或无效占位符。
4. 在共享 NAT、办公网或反向代理后面启用首击封禁前，先用 `ban_seconds=0` 观察 `honeypot_hits_total` 和审计事件，确认没有正常用户误触。
5. 需要拖延时从小值开始，例如 250–1000 ms。延迟会占用全局在途槽位，不能替代速率限制或 DDoS 清洗。
6. 不要依赖蜜罐发现所有扫描；它只覆盖显式配置的路径，攻击者可以通过指纹、路径字典差异或直接访问真实端点绕过。
7. 默认静态模式不采集请求 payload，也不执行不可信内容。需要高交互时，优先使用 [`deploy/honeypot`](../deploy/honeypot/README.md) 这类隔离容器，把后端限制在回环/私网、无公网出网、无宿主挂载、无 Docker socket，并准备快照和重置流程。高交互入口应使用独立可注册域，不能借用生产域或生产子域。
8. 高交互端口不要直接暴露公网；前端只做入口控制和资源限制，后端应用漏洞、容器逃逸、横向移动和证据保全仍由独立部署负责。调查期间通常保持 `ban_seconds=0`，避免一次交互后切断持续观察。
9. 诱导性 `server_header`、`host_header` 只能降低明显的产品指纹，不构成安全边界；不要把它们当作规避检测的保证。

## 6. 明确不做

- 网关进程本身不提供真实登录、文件读取、命令执行或数据库接口；高交互登录只能来自显式配置的隔离后端。
- 网关不保存攻击者提交的 body、Cookie 或 Header；高交互后端会收到这些内容，其后端是否记录、保留多久以及如何取证由独立部署决定。
- 不发起反向连接、反制、指纹追踪或第三方告警。
- 不复制生产数据库、身份系统、私有数据或完整业务栈；需要完整仿真时必须另行建设隔离环境和取证流程。
- 不保证能识别自动化扫描、规避已知指纹或阻止定向攻击者访问真实路径。
- 不替代主机防火墙、WAF 上游修复、认证授权、EDR、备份或网络隔离。

蜜罐的价值是提高探测成本和产生高质量本地告警，而不是让上游应用自动变安全。
