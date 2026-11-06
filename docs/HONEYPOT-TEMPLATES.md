# HighWall 内置蜜罐模板

本文列出 `policy.honeypot.presets` 内置的 34 个模板、路径和参考来源。模板只模仿常见扫描目标的外形，页面和响应内容均为原创合成文本，不复制厂商页面，也不包含真实凭证。HighWall 在运行时不会联网获取模板。`common` 仍保留原有 18 条路径，新增模板集中在 `build`、`infra` 和 `observability` 组，也可用 `all` 一次展开全部模板。

## 1. 预设组

| 预设 | 内容 |
|---|---|
| `common` | `secrets` + `wordpress` + `spring` + `admin` + `devops`，共 18 条路径。 |
| `secrets` | 环境文件、Git/SVN 元数据和常见备份/配置文件路径。 |
| `wordpress` | WordPress 登录、XML-RPC 和配置备份路径。 |
| `spring` | Spring Boot Actuator 常见信息端点。 |
| `admin` | 通用管理页、phpMyAdmin 和 Tomcat Manager。 |
| `devops` | Apache 状态页、Swagger/OpenAPI 和 Elasticsearch 集群健康端点。 |
| `cloud` | AWS 凭据文件和 Kubernetes kubeconfig 路径；默认不并入 `common`。 |
| `build` | npm、Composer、Docker、GitLab CI 等构建和依赖清单路径。 |
| `infra` | Terraform state、htpasswd、VS Code 设置和 SQL 备份等基础设施诱饵。 |
| `observability` | phpinfo、Actuator health/mappings 和 Prometheus 指标端点。 |
| `expanded` / `all` | 全部 34 个模板的别名；默认不并入 `common`。 |

也可以直接用模板名，例如 `presets: ["env_probe", "git_head", "wp_login"]`。重复模板只展开一次；显式 `routes` 中相同路径的条目会整体覆盖预设。

## 2. 模板清单

| 模板名 | 路径 | 状态 | 内容类型 | 备注 |
|---|---|---:|---|---|
| `env_probe` | `/.env` | 200 | `text/plain` | 合成环境变量和假数据库配置。 |
| `git_config` | `/.git/config` | 200 | `text/plain` | 合成 Git 仓库配置。 |
| `git_head` | `/.git/HEAD` | 200 | `text/plain` | `ref: refs/heads/main`。 |
| `svn_entries` | `/.svn/entries` | 200 | `text/plain` | 合成 SVN 元数据。 |
| `wp_login` | `/wp-login.php` | 200 | `text/html` | 最小登录表单，不连接任何认证后端。 |
| `xmlrpc` | `/xmlrpc.php` | 405 | `text/plain` | 模拟仅接受 POST 的 XML-RPC 端点。 |
| `wp_config_bak` | `/wp-config.php.bak` | 200 | `text/plain` | 合成 PHP 配置，密码为无效占位符。 |
| `actuator_env` | `/actuator/env` | 200 | `application/json` | 合成 Spring 环境属性。 |
| `actuator_heapdump` | `/actuator/heapdump` | 200 | `application/octet-stream` | 小型文本占位，不是真实 JVM dump。 |
| `actuator_threaddump` | `/actuator/threaddump` | 200 | `application/json` | 合成线程列表。 |
| `admin_php` | `/admin.php` | 200 | `text/html` | 通用管理登录页。 |
| `phpmyadmin_root` | `/phpmyadmin` | 301 | `text/html` | 跳转到 `/phpmyadmin/`。 |
| `phpmyadmin_index` | `/phpmyadmin/` | 200 | `text/html` | phpMyAdmin 风格登录页。 |
| `tomcat_manager` | `/manager/html` | 401 | `text/html` | Basic challenge，不验证任何口令。 |
| `server_status` | `/server-status` | 200 | `text/html` | 合成 Apache 状态页。 |
| `swagger_ui` | `/swagger-ui.html` | 200 | `text/html` | 最小 Swagger UI 外形。 |
| `openapi_json` | `/openapi.json` | 200 | `application/json` | 合成 OpenAPI 文档。 |
| `elasticsearch_health` | `/_cluster/health` | 200 | `application/json` | 合成黄色集群状态。 |
| `aws_credentials` | `/.aws/credentials` | 200 | `text/plain` | AWS 官方文档中的示例键值，不是真实凭证。 |
| `kube_config` | `/.kube/config` | 200 | `application/yaml` | 指向 `.invalid` 集群的合成 kubeconfig。 |
| `npmrc` | `/.npmrc` | 200 | `text/plain` | 含无效 token 占位的合成 npm 配置。 |
| `docker_compose` | `/docker-compose.yml` | 200 | `application/yaml` | 合成 Compose 服务、假数据库变量和端口声明。 |
| `dockerfile` | `/Dockerfile` | 200 | `text/plain` | 合成 Python 镜像构建文件。 |
| `package_json` | `/package.json` | 200 | `application/json` | 合成 Node.js 项目元数据和依赖。 |
| `composer_json` | `/composer.json` | 200 | `application/json` | 合成 PHP/Composer 项目清单。 |
| `gitlab_ci` | `/.gitlab-ci.yml` | 200 | `application/yaml` | 合成 GitLab CI test/deploy 阶段。 |
| `terraform_state` | `/terraform.tfstate` | 200 | `application/json` | 合成 Terraform state，资源值均为占位符。 |
| `htpasswd` | `/.htpasswd` | 200 | `text/plain` | 合成 Basic Auth 哈希占位符，不验证口令。 |
| `phpinfo` | `/phpinfo.php` | 200 | `text/html` | 合成 phpinfo 页面，不暴露真实环境。 |
| `actuator_health` | `/actuator/health` | 200 | `application/json` | 合成 Spring 健康检查响应。 |
| `actuator_mappings` | `/actuator/mappings` | 200 | `application/json` | 合成 Spring 路由映射列表。 |
| `prometheus_metrics` | `/metrics` | 200 | `text/plain; version=0.0.4` | 合成 Prometheus 指标文本。 |
| `vscode_settings` | `/.vscode/settings.json` | 200 | `application/json` | 合成编辑器设置。 |
| `backup_sql` | `/backup.sql` | 200 | `text/plain` | 合成 SQL 备份，含无效示例邮箱。 |

所有路径都是规范化后的精确匹配；查询串不参与匹配。命中后只返回本地静态内容，不访问上游。
如果同一蜜罐 listener 配置了 `backend`，静态模板仍优先；只有未命中模板的请求才进入
隔离高交互后端。详见 [`HONEYPOT.md`](HONEYPOT.md) 和
[`deploy/honeypot`](../deploy/honeypot/README.md)。

## 3. 覆盖示例

```json
{
  "enabled": true,
  "ban_seconds": 0,
  "presets": ["secrets", "wp_login"],
  "routes": [
    {
      "id": "env_probe",
      "path": "/.env",
      "status": 200,
      "content_type": "text/plain; charset=utf-8",
      "body": "APP_ENV=production\nDB_PASSWORD=decoy-not-a-real-secret\n",
      "server_header": "nginx"
    }
  ]
}
```

## 4. 使用限制

- `common` 覆盖多个技术栈。若真实应用使用 WordPress、Spring Actuator、phpMyAdmin、Tomcat 或 Swagger，必须改为更窄的预设或删除冲突路径。
- `cloud` 包含容易触发密钥扫描器的假凭据外形，默认不并入 `common`。在会做响应 DLP 或外部告警的环境中先评估误报。
- 模板可能被攻击者通过响应细节、`Server` 头、ETag 缺失、页面结构或路径字典差异识别；模板本身仍是低交互内容，高交互能力只来自显式配置的隔离后端。
- 不保证模板路径覆盖所有扫描器。模板的价值是减少配置量和提高一致性，不是替代独立诱捕网络、主机隔离或真实业务修复。
- 所有模板都受 64 KiB Body、Header 数、路由数、延迟和封禁表上限约束。
- `all`/`expanded` 会一次启用全部 34 个模板，包含更明显的假凭据外形；在真实业务或响应 DLP 告警环境中应逐组启用，不要直接照搬。
- 这些模板只改变主代理端口上的 HTTP 诱饵路径；需要独立端口时见 [`HONEYPOT.md`](HONEYPOT.md) 的 `listeners`。

## 5. 参考来源

以下链接用于核对端点路径和响应格式。模板内容没有逐字复制这些页面。

- Spring Boot Actuator endpoints: <https://docs.spring.io/spring-boot/reference/actuator/endpoints.html>
- Apache `mod_status`: <https://httpd.apache.org/docs/2.4/mod/mod_status.html>
- phpMyAdmin setup: <https://docs.phpmyadmin.net/en/latest/setup.html>
- Git config format: <https://git-scm.com/docs/git-config>
- Swagger UI: <https://swagger.io/tools/swagger-ui/>
- Tomcat Manager: <https://tomcat.apache.org/tomcat-10.1-doc/manager-howto.html>
- WordPress `wp-login.php`: <https://developer.wordpress.org/reference/files/wp-login.php/>
- WordPress IXR server: <https://developer.wordpress.org/reference/files/wp-includes/IXR/class-IXR-server.php/>
- AWS CLI credential files: <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html>
- Kubernetes kubeconfig: <https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/>
- Elasticsearch cluster health: <https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-health.html>
- npm config: <https://docs.npmjs.com/cli/v10/configuring-npm/npmrc>
- npm package.json: <https://docs.npmjs.com/cli/v10/configuring-npm/package-json>
- Composer schema: <https://getcomposer.org/doc/04-schema.md>
- Docker Compose file: <https://docs.docker.com/compose/compose-file/>
- Dockerfile reference: <https://docs.docker.com/reference/dockerfile/>
- GitLab CI YAML: <https://docs.gitlab.com/ee/ci/yaml/>
- Terraform state: <https://developer.hashicorp.com/terraform/language/state>
- Apache htpasswd: <https://httpd.apache.org/docs/2.4/programs/htpasswd.html>
- PHP phpinfo: <https://www.php.net/manual/en/function.phpinfo.php>
- Prometheus exposition formats: <https://prometheus.io/docs/instrumenting/exposition_formats/>
- VS Code settings: <https://code.visualstudio.com/docs/configure/settings>

参考链接核对日期：2026-11-06。
