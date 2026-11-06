"""Built-in static honeypot templates and curated preset groups.

The templates are synthetic decoys. They imitate common endpoint shapes without
copying vendor pages or containing real credentials. Runtime never downloads
template content.
"""

from __future__ import annotations

import json
from typing import Any, Iterable


def _json_body(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=True) + "\n"


def _login_page(title: str, action: str) -> str:
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{title}</title></head>"
        '<body><main style="max-width:28rem;margin:4rem auto;font-family:sans-serif">'
        f'<h1>{title}</h1><form method="post" action="{action}">'
        '<label>Username <input name="username" autocomplete="username"></label><br>'
        '<label>Password <input type="password" name="password" autocomplete="current-password"></label><br>'
        '<button type="submit">Sign in</button></form></main></body></html>\n'
    )


_SERVER_STATUS_BODY = (
    "<!doctype html>\n"
    "<html><head><title>Apache Server Status for localhost</title></head><body>\n"
    "<h1>Apache Server Status for localhost (via 127.0.0.1)</h1>\n"
    "<dl><dt>Server Version: Apache/2.4.58 (Unix) OpenSSL/3.0.13</dt>\n"
    "<dt>Server MPM: event</dt><dt>Server Built: 2026-01-01 00:00:00</dt></dl>\n"
    "<p>Current Time: Monday, 01-Jan-2026 00:00:00 UTC</p>\n"
    "<p>Restart Time: Monday, 01-Jan-2026 00:00:00 UTC</p>\n"
    "<p>Parent Server Config. Generation: 1</p>\n"
    "<p>Parent Server MPM Generation: 0</p>\n"
    "<p>Server uptime: 2 days 4 hours 17 minutes 3 seconds</p>\n"
    "<p>Total accesses: 18471 - Total Traffic: 296.4 MB</p>\n"
    "<p>CPU Usage: u1.2 s0.3 cu0 cs0 - .00084% CPU load</p>\n"
    "<p>0.1 requests/sec - 1.8 kB/second - 16.4 kB/request</p>\n"
    "<table><tr><th>Srv</th><th>PID</th><th>Acc</th><th>M</th><th>SS</th><th>Req</th><th>Conn</th><th>Child</th><th>Slot</th><th>Client</th><th>VHost</th><th>Request</th></tr>\n"
    "<tr><td>0-0</td><td>1842</td><td>0/11/11</td><td>_</td><td>2</td><td>0</td><td>0.0</td><td>0.00</td><td>0.00</td><td>127.0.0.1</td><td>default</td><td>GET / HTTP/1.1</td></tr>\n"
    "</table></body></html>\n"
)


_SWAGGER_BODY = (
    "<!doctype html>\n"
    '<html lang="en"><head><meta charset="utf-8">'
    "<title>Swagger UI</title></head><body>"
    '<div id="swagger-ui"><h1>Swagger UI</h1>'
    '<p><a href="/openapi.json">/openapi.json</a></p></div>'
    "</body></html>\n"
)


HONEYPOT_TEMPLATES: dict[str, dict[str, Any]] = {
    "env_probe": {
        "id": "env_probe",
        "path": "/.env",
        "content_type": "text/plain; charset=utf-8",
        "body": (
            "APP_ENV=production\n"
            "APP_DEBUG=false\n"
            "APP_KEY=decoy-not-a-real-key\n"
            "DB_CONNECTION=mysql\n"
            "DB_HOST=db.internal.invalid\n"
            "DB_PORT=3306\n"
            "DB_DATABASE=app\n"
            "DB_USERNAME=app\n"
            "DB_PASSWORD=decoy-not-a-real-password\n"
            "REDIS_HOST=cache.internal.invalid\n"
            "REDIS_PORT=6379\n"
            "MAIL_HOST=mail.internal.invalid\n"
        ),
        "server_header": "nginx",
    },
    "git_config": {
        "id": "git_config",
        "path": "/.git/config",
        "content_type": "text/plain; charset=utf-8",
        "body": (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            "\tbare = false\n"
            "\tlogallrefupdates = true\n"
            '[remote "origin"]\n'
            "\turl = https://git.internal.invalid/example/app.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            '[branch "main"]\n'
            "\tremote = origin\n"
            "\tmerge = refs/heads/main\n"
        ),
        "server_header": "nginx",
    },
    "git_head": {
        "id": "git_head",
        "path": "/.git/HEAD",
        "content_type": "text/plain; charset=utf-8",
        "body": "ref: refs/heads/main\n",
        "server_header": "nginx",
    },
    "svn_entries": {
        "id": "svn_entries",
        "path": "/.svn/entries",
        "content_type": "text/plain; charset=utf-8",
        "body": (
            "12\n"
            "dir\n"
            "255\n"
            "https://svn.internal.invalid/repos/app\n"
            "https://svn.internal.invalid/repos/app\n"
            "2026-01-01T00:00:00.000000Z\n"
            "2\n"
            "\n"
            "trunk\n"
            "branches\n"
            "tags\n"
        ),
        "server_header": "nginx",
    },
    "wp_login": {
        "id": "wp_login",
        "path": "/wp-login.php",
        "content_type": "text/html; charset=utf-8",
        "body": _login_page("WordPress Login", "/wp-login.php"),
        "headers": {"X-Powered-By": "PHP/8.2.12"},
        "server_header": "nginx",
    },
    "xmlrpc": {
        "id": "xmlrpc",
        "path": "/xmlrpc.php",
        "status": 405,
        "content_type": "text/plain; charset=utf-8",
        "body": "XML-RPC server accepts POST requests only.\n",
        "headers": {"Allow": "POST"},
        "server_header": "nginx",
    },
    "wp_config_bak": {
        "id": "wp_config_bak",
        "path": "/wp-config.php.bak",
        "content_type": "text/plain; charset=utf-8",
        "body": (
            "<?php\n"
            "define('DB_NAME', 'wordpress');\n"
            "define('DB_USER', 'wp_user');\n"
            "define('DB_PASSWORD', 'decoy-not-a-real-password');\n"
            "define('DB_HOST', 'db.internal.invalid');\n"
            "define('DB_CHARSET', 'utf8mb4');\n"
            "define('AUTH_KEY', 'decoy-not-a-real-auth-key');\n"
            "$table_prefix = 'wp_';\n"
        ),
        "server_header": "nginx",
    },
    "actuator_env": {
        "id": "actuator_env",
        "path": "/actuator/env",
        "content_type": "application/json; charset=utf-8",
        "body": _json_body(
            {
                "activeProfiles": ["prod"],
                "propertySources": [
                    {
                        "name": "systemEnvironment",
                        "properties": {
                            "DB_HOST": {"value": "db.internal.invalid"},
                            "DB_USER": {"value": "app"},
                            "DB_PASSWORD": {"value": "decoy-not-a-real-password"},
                        },
                    }
                ],
            }
        ),
        "server_header": "nginx",
    },
    "actuator_heapdump": {
        "id": "actuator_heapdump",
        "path": "/actuator/heapdump",
        "content_type": "application/octet-stream",
        "body": "HONEYPOT_HEAP_DUMP\nThis is not a real JVM heap dump.\n",
        "server_header": "nginx",
    },
    "actuator_threaddump": {
        "id": "actuator_threaddump",
        "path": "/actuator/threaddump",
        "content_type": "application/json; charset=utf-8",
        "body": _json_body(
            {
                "threads": [
                    {
                        "threadName": "http-nio-8080-exec-1",
                        "threadState": "RUNNABLE",
                        "stackTrace": [
                            {"className": "decoy.Application", "methodName": "handle", "lineNumber": 42}
                        ],
                    }
                ]
            }
        ),
        "server_header": "nginx",
    },
    "admin_php": {
        "id": "admin_php",
        "path": "/admin.php",
        "content_type": "text/html; charset=utf-8",
        "body": _login_page("Administration", "/admin.php"),
        "headers": {"X-Powered-By": "PHP/8.2.12"},
        "server_header": "nginx",
    },
    "phpmyadmin_root": {
        "id": "phpmyadmin_root",
        "path": "/phpmyadmin",
        "status": 301,
        "content_type": "text/html; charset=utf-8",
        "body": "Redirecting to /phpmyadmin/.\n",
        "headers": {"Location": "/phpmyadmin/"},
        "server_header": "nginx",
    },
    "phpmyadmin_index": {
        "id": "phpmyadmin_index",
        "path": "/phpmyadmin/",
        "content_type": "text/html; charset=utf-8",
        "body": _login_page("phpMyAdmin", "/phpmyadmin/index.php"),
        "headers": {"X-Powered-By": "PHP/8.2.12"},
        "server_header": "nginx",
    },
    "tomcat_manager": {
        "id": "tomcat_manager",
        "path": "/manager/html",
        "status": 401,
        "content_type": "text/html; charset=utf-8",
        "body": _login_page("Tomcat Manager", "/manager/html"),
        "headers": {"WWW-Authenticate": 'Basic realm="Tomcat Manager Application"'},
        "server_header": "Apache-Coyote/1.1",
    },
    "server_status": {
        "id": "server_status",
        "path": "/server-status",
        "content_type": "text/html; charset=utf-8",
        "body": _SERVER_STATUS_BODY,
        "server_header": "Apache/2.4.58 (Unix)",
    },
    "swagger_ui": {
        "id": "swagger_ui",
        "path": "/swagger-ui.html",
        "content_type": "text/html; charset=utf-8",
        "body": _SWAGGER_BODY,
        "server_header": "nginx",
    },
    "openapi_json": {
        "id": "openapi_json",
        "path": "/openapi.json",
        "content_type": "application/json; charset=utf-8",
        "body": _json_body(
            {
                "openapi": "3.0.0",
                "info": {"title": "Internal API", "version": "1.0.0"},
                "paths": {
                    "/api/v1/items": {
                        "get": {
                            "summary": "List items",
                            "responses": {"200": {"description": "OK"}},
                        }
                    }
                },
            }
        ),
        "server_header": "nginx",
    },
    "elasticsearch_health": {
        "id": "elasticsearch_health",
        "path": "/_cluster/health",
        "content_type": "application/json; charset=utf-8",
        "body": _json_body(
            {
                "cluster_name": "highwall-decoy",
                "status": "yellow",
                "timed_out": False,
                "number_of_nodes": 3,
                "number_of_data_nodes": 3,
                "active_primary_shards": 12,
                "active_shards": 24,
                "relocating_shards": 0,
                "initializing_shards": 0,
                "unassigned_shards": 2,
            }
        ),
        "server_header": "nginx",
    },
    "aws_credentials": {
        "id": "aws_credentials",
        "path": "/.aws/credentials",
        "content_type": "text/plain; charset=utf-8",
        "body": (
            "[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "region = us-east-1\n"
        ),
        "server_header": "nginx",
    },
    "kube_config": {
        "id": "kube_config",
        "path": "/.kube/config",
        "content_type": "application/yaml; charset=utf-8",
        "body": (
            "apiVersion: v1\n"
            "kind: Config\n"
            "clusters:\n"
            "- cluster:\n"
            "    server: https://k8s.internal.invalid:6443\n"
            "    certificate-authority-data: ZGVjb3ktY2E=\n"
            "  name: decoy\n"
            "contexts:\n"
            "- context:\n"
            "    cluster: decoy\n"
            "    user: decoy\n"
            "  name: decoy\n"
            "current-context: decoy\n"
            "users:\n"
            "- name: decoy\n"
            "  user:\n"
            "    token: decoy-not-a-real-token\n"
        ),
        "server_header": "nginx",
    },
    "npmrc": {
        "id": "npmrc",
        "path": "/.npmrc",
        "content_type": "text/plain; charset=utf-8",
        "body": (
            "registry=https://registry.npmjs.org/\n"
            "//registry.npmjs.org/:_authToken=decoy-not-a-real-token\n"
            "fund=false\n"
            "audit=true\n"
        ),
        "server_header": "nginx",
    },
    "docker_compose": {
        "id": "docker_compose",
        "path": "/docker-compose.yml",
        "content_type": "application/yaml; charset=utf-8",
        "body": (
            "version: \"3.9\"\n"
            "services:\n"
            "  web:\n"
            "    image: nginx:1.27-alpine\n"
            "    environment:\n"
            "      APP_ENV: production\n"
            "      DB_HOST: db.internal.invalid\n"
            "      DB_PASSWORD: decoy-not-a-real-password\n"
            "    ports:\n"
            "      - \"8080:80\"\n"
            "  cache:\n"
            "    image: redis:7-alpine\n"
        ),
        "server_header": "nginx",
    },
    "dockerfile": {
        "id": "dockerfile",
        "path": "/Dockerfile",
        "content_type": "text/plain; charset=utf-8",
        "body": (
            "FROM python:3.12-slim\n"
            "WORKDIR /app\n"
            "COPY requirements.txt .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "COPY . .\n"
            "EXPOSE 8000\n"
            "CMD [\"python\", \"-m\", \"app\"]\n"
        ),
        "server_header": "nginx",
    },
    "package_json": {
        "id": "package_json",
        "path": "/package.json",
        "content_type": "application/json; charset=utf-8",
        "body": _json_body(
            {
                "name": "internal-console",
                "version": "2.8.1",
                "private": True,
                "scripts": {"start": "node server.js", "test": "jest --runInBand"},
                "dependencies": {"express": "^4.19.2", "pg": "^8.12.0"},
                "devDependencies": {"jest": "^29.7.0"},
            }
        ),
        "server_header": "nginx",
    },
    "composer_json": {
        "id": "composer_json",
        "path": "/composer.json",
        "content_type": "application/json; charset=utf-8",
        "body": _json_body(
            {
                "name": "example/internal-app",
                "description": "Synthetic decoy manifest",
                "require": {"php": "^8.2", "laravel/framework": "^11.0"},
                "autoload": {"psr-4": {"App\\": "app/"}},
            }
        ),
        "server_header": "nginx",
    },
    "gitlab_ci": {
        "id": "gitlab_ci",
        "path": "/.gitlab-ci.yml",
        "content_type": "application/yaml; charset=utf-8",
        "body": (
            "stages:\n"
            "  - test\n"
            "  - deploy\n"
            "test:\n"
            "  stage: test\n"
            "  image: python:3.12\n"
            "  script:\n"
            "    - pip install -r requirements.txt\n"
            "    - pytest -q\n"
            "deploy:\n"
            "  stage: deploy\n"
            "  script: ./scripts/deploy.sh\n"
        ),
        "server_header": "nginx",
    },
    "terraform_state": {
        "id": "terraform_state",
        "path": "/terraform.tfstate",
        "content_type": "application/json; charset=utf-8",
        "body": _json_body(
            {
                "version": 4,
                "terraform_version": "1.8.5",
                "serial": 17,
                "lineage": "decoy-lineage",
                "resources": [
                    {
                        "mode": "managed",
                        "type": "aws_instance",
                        "name": "app",
                        "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                        "instances": [
                            {
                                "attributes": {
                                    "ami": "ami-decoy",
                                    "instance_type": "t3.micro",
                                    "private_ip": "10.0.0.12",
                                }
                            }
                        ],
                    }
                ],
            }
        ),
        "server_header": "nginx",
    },
    "htpasswd": {
        "id": "htpasswd",
        "path": "/.htpasswd",
        "content_type": "text/plain; charset=utf-8",
        "body": "admin:{SHA}ZGVjb3ktbm90LWEtcmVhbC1oYXNo\noperator:{SHA}ZGVjb3ktbm90LWEtcmVhbC1oYXNo\n",
        "server_header": "nginx",
    },
    "phpinfo": {
        "id": "phpinfo",
        "path": "/phpinfo.php",
        "content_type": "text/html; charset=utf-8",
        "body": (
            "<!doctype html><html><head><title>phpinfo()</title></head><body>\n"
            "<h1>PHP Version 8.2.20</h1>\n"
            "<table><tr><td>System</td><td>Linux app 6.5.0 x86_64</td></tr>\n"
            "<tr><td>Server API</td><td>FPM/FastCGI</td></tr>\n"
            "<tr><td>Document Root</td><td>/var/www/html</td></tr>\n"
            "<tr><td>Configuration File</td><td>/etc/php/8.2/fpm/php.ini</td></tr></table>\n"
            "</body></html>\n"
        ),
        "server_header": "nginx",
    },
    "actuator_health": {
        "id": "actuator_health",
        "path": "/actuator/health",
        "content_type": "application/json; charset=utf-8",
        "body": _json_body(
            {
                "status": "UP",
                "components": {
                    "db": {"status": "UP", "details": {"database": "PostgreSQL"}},
                    "diskSpace": {"status": "UP", "details": {"free": 10737418240}},
                    "redis": {"status": "UP", "details": {"version": "7.2.4"}},
                },
            }
        ),
        "server_header": "nginx",
    },
    "actuator_mappings": {
        "id": "actuator_mappings",
        "path": "/actuator/mappings",
        "content_type": "application/json; charset=utf-8",
        "body": _json_body(
            {
                "contexts": {
                    "application": {
                        "mappings": {
                            "dispatcherServlets": {
                                "dispatcherServlet": [
                                    {"predicate": "{GET /api/v1/items}", "details": {"handler": "ItemsController"}},
                                    {"predicate": "{POST /api/v1/orders}", "details": {"handler": "OrderController"}},
                                ]
                            }
                        }
                    }
                }
            }
        ),
        "server_header": "nginx",
    },
    "prometheus_metrics": {
        "id": "prometheus_metrics",
        "path": "/metrics",
        "content_type": "text/plain; version=0.0.4; charset=utf-8",
        "body": (
            "# HELP http_requests_total Total HTTP requests.\n"
            "# TYPE http_requests_total counter\n"
            "http_requests_total{method=\"GET\",status=\"200\"} 18471\n"
            "http_requests_total{method=\"POST\",status=\"500\"} 23\n"
            "# HELP process_resident_memory_bytes Resident memory size.\n"
            "# TYPE process_resident_memory_bytes gauge\n"
            "process_resident_memory_bytes 1.847e+08\n"
            "process_start_time_seconds 1772323200\n"
        ),
        "server_header": "nginx",
    },
    "vscode_settings": {
        "id": "vscode_settings",
        "path": "/.vscode/settings.json",
        "content_type": "application/json; charset=utf-8",
        "body": _json_body(
            {
                "editor.tabSize": 4,
                "python.defaultInterpreterPath": "/usr/bin/python3",
                "terminal.integrated.env.linux": {"APP_ENV": "production"},
            }
        ),
        "server_header": "nginx",
    },
    "backup_sql": {
        "id": "backup_sql",
        "path": "/backup.sql",
        "content_type": "text/plain; charset=utf-8",
        "body": (
            "-- Synthetic decoy dump; no real data\n"
            "CREATE TABLE users (id integer primary key, email text, role text);\n"
            "INSERT INTO users VALUES (1, 'admin@example.invalid', 'admin');\n"
            "INSERT INTO users VALUES (2, 'operator@example.invalid', 'operator');\n"
        ),
        "server_header": "nginx",
    },
}


HONEYPOT_PRESET_GROUPS: dict[str, tuple[str, ...]] = {
    "secrets": ("env_probe", "git_config", "git_head", "svn_entries"),
    "wordpress": ("wp_login", "xmlrpc", "wp_config_bak"),
    "spring": ("actuator_env", "actuator_heapdump", "actuator_threaddump"),
    "admin": ("admin_php", "phpmyadmin_root", "phpmyadmin_index", "tomcat_manager"),
    "devops": ("server_status", "swagger_ui", "openapi_json", "elasticsearch_health"),
    "cloud": ("aws_credentials", "kube_config"),
    "build": ("npmrc", "docker_compose", "dockerfile", "package_json", "composer_json", "gitlab_ci"),
    "infra": ("terraform_state", "htpasswd", "vscode_settings", "backup_sql"),
    "observability": ("phpinfo", "actuator_health", "actuator_mappings", "prometheus_metrics"),
    "common": (
        "env_probe",
        "git_config",
        "git_head",
        "svn_entries",
        "wp_login",
        "xmlrpc",
        "wp_config_bak",
        "actuator_env",
        "actuator_heapdump",
        "actuator_threaddump",
        "admin_php",
        "phpmyadmin_root",
        "phpmyadmin_index",
        "tomcat_manager",
        "server_status",
        "swagger_ui",
        "openapi_json",
        "elasticsearch_health",
    ),
}

HONEYPOT_PRESET_GROUPS["expanded"] = (
    *HONEYPOT_PRESET_GROUPS["common"],
    *HONEYPOT_PRESET_GROUPS["cloud"],
    *HONEYPOT_PRESET_GROUPS["build"],
    *HONEYPOT_PRESET_GROUPS["infra"],
    *HONEYPOT_PRESET_GROUPS["observability"],
)
HONEYPOT_PRESET_GROUPS["all"] = HONEYPOT_PRESET_GROUPS["expanded"]


def expand_honeypot_presets(names: Iterable[str]) -> tuple[str, ...]:
    """Resolve group and individual template names while preserving order."""

    resolved: list[str] = []
    seen: set[str] = set()
    for name in names:
        if name in HONEYPOT_PRESET_GROUPS:
            selected = HONEYPOT_PRESET_GROUPS[name]
        elif name in HONEYPOT_TEMPLATES:
            selected = (name,)
        else:
            raise ValueError(f"unknown preset or template {name!r}")
        for template_name in selected:
            if template_name not in seen:
                seen.add(template_name)
                resolved.append(template_name)
    return tuple(resolved)
