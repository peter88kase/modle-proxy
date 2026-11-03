# 模型接口测试平台（Bedrock）

面向大模型供应商接入验收的 Web 平台：在服务端发起真实请求，按《新供应商引入测试标准》第 1～4 章逐项判定，
给出「达标 / 不达标 / 无法判定」的结论，并导出可直接对外交付的 PDF 报告。

平台不内置任何模型白名单，也不保存供应商 API Key——Key 只存在于当次请求的内存里。

## 1. 能做什么

- **接口测试**：填 Endpoint、API Key、模型 ID 即可发一次真实请求，支持非流式与 SSE 流式；可在线拉取上游模型列表（兼容 Base 带/不带 `/v1`）。
- **验收标准**：第 1～4 章共 **169 项**（原文 166 项 + 平台新增 3 条前置必测），覆盖连通性、接口兼容性、缓存正确性、模型与能力真实性；标准项可启用/停用、调整必测级别，修改即生成新版本，历史任务仍绑定原版本。
- **前置必测（GATE-01~03）**：优先执行，任一不通过直接判不达标、后续检查不再发起请求。
  - `GATE-01` 连通性：1 次非流式（须返回 `G1_OK`）+ 1 次流式（须有内容且正常结束）
  - `GATE-02` 缓存命中率：第 1 次请求显式写入缓存（Claude/Anthropic 用 `cache_control`，OpenAI 兼容协议自动改走 `/v1/messages`），再用相同输入连发 5 次，命中率必须 = 1
  - `GATE-03` 延时分位：连发 20 次全部成功且中位 ≤ 10s，输出 P5 / 中位 / P95 作为渠道权重依据
- **自动验收任务**：一个任务可含多个模型并按顺序执行；支持按章重测、单项重测、取消、断点重启、预算（默认 200 次请求 / 900 秒）与并发上限。
- **人工确认与证据**：无法自动判定的项进入人工确认，可上传截图/日志作为证据，历史判定留痕、不覆盖旧结论。
- **PDF 报告**：对外交付版（结论、统计、主要问题、结论说明、逐项结果、附件），不含内部编号、校验值、页码；多模型可合并为一份。
- **网络诊断**：自定义 curl、表单 curl / ping / dig，走独立低权限工作进程，默认拦截内网与云元数据地址。

## 2. 技术栈与目录

- Python 3.11+ / FastAPI / Uvicorn / SQLite（WAL）/ ReportLab（PDF）
- 前端为原生 HTML + ES Module，**无需 Node 构建**
- 无外部中间件依赖，单机即可运行

```
backend/        服务端：路由、判定引擎、检查器、任务调度、PDF 生成
frontend/       页面模板与静态资源（templates / static）
config/         测试标准定义（第 1～4 章 169 项）
assets/         内嵌中文字体（PDF 报告用，缺省回退系统字体）
shell_worker/   网络诊断工作进程（curl / ping / dig，独立低权限账号）
requirements.txt
.env.example    环境变量示例
```

> 本仓库只包含运行所需的源码。测试套件、部署脚本、打包产物、设计文档已通过 `.gitignore` 排除。

## 3. 本地快速开始

```bash
# 1) 依赖
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2) 目录与必需环境变量
mkdir -p data logs
export BEDROCK_ADMIN_PASSWORD='<至少 12 位的初始管理员密码>'   # 首次启动用它创建管理员
export SHELL_TOKEN="$(openssl rand -hex 32)"              # 网络诊断工作进程的调用令牌
export DB_PATH="$PWD/data/bedrock.db"

# 3) 启动
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

> `requirements.txt` 里也包含测试依赖（pytest、pymupdf）：pytest 只用于跑测试，pymupdf 只用于测试中读 PDF；
> 运行服务本身不需要它们，按原样安装即可。

打开 `http://127.0.0.1:8000/`，用 `admin` + 上一步设置的密码登录，登录后立即改密。

只想测模型、不需要 ping/dig 网络诊断时，可设 `SHELL_ENABLED=false`，此时不必启动工作进程。

启动网络诊断工作进程（可选；Linux 用 unix socket，Windows 自动退回 TCP）：

```bash
SHELL_TOKEN="$SHELL_TOKEN" SHELL_SOCKET=/run/bedrock/shell.sock \
SHELL_SOCKET_GROUP=bedrock python -m shell_worker.worker
```

## 4. 生产部署（Linux + systemd + Nginx）

### 4.1 账号与目录

```bash
groupadd bedrock
useradd -r -s /sbin/nologin -G bedrock bedrock
useradd -r -s /sbin/nologin -G bedrock-shell bedrock-shell   # 工作进程专用，禁止 root 运行

mkdir -p /opt/bedrock /etc/bedrock
chown -R bedrock:bedrock /opt/bedrock
```

把源码放到 `/opt/bedrock`，然后：

```bash
cd /opt/bedrock
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 4.2 环境文件 `/etc/bedrock/bedrock.env`

```ini
APP_ENV=production
BIND_HOST=127.0.0.1
BIND_PORT=8000
PUBLIC_ORIGIN=https://test.example.com     # 对外访问地址，用于 Origin 校验

DB_PATH=/opt/bedrock/data/bedrock.db
LOG_PATH=/opt/bedrock/logs/bedrock.log

COOKIE_SECURE=true                          # 上 HTTPS 后必须为 true
SESSION_IDLE_SECONDS=1800
SESSION_ABSOLUTE_SECONDS=28800

BEDROCK_ADMIN_USER=admin
BEDROCK_ADMIN_PASSWORD=                     # 仅首次启动填写，创建后清空
PASSWORD_MIN_LENGTH=12

MODEL_CONNECT_TIMEOUT=10
MODEL_FIRST_TOKEN_TIMEOUT=30
MODEL_TOTAL_TIMEOUT=60
MODEL_REQUEST_INTERVAL=2                    # 相邻请求最小间隔；撞 429 时调大
MODEL_MAX_CONCURRENCY=6
ALLOW_PRIVATE_UPSTREAM=false                # 测内网/私有化部署时才开

SHELL_ENABLED=true
SHELL_SOCKET=/run/bedrock/shell.sock
SHELL_SOCKET_GROUP=bedrock
SHELL_TOKEN=<openssl rand -hex 32 的输出>    # Web 与工作进程必须一致

TRUST_PROXY_HEADERS=true                    # 仅同机 Nginx 反代时开启
```

```bash
chown root:bedrock /etc/bedrock/bedrock.env
chmod 640 /etc/bedrock/bedrock.env
mkdir -p /opt/bedrock/data /opt/bedrock/logs
chown -R bedrock:bedrock /opt/bedrock/data /opt/bedrock/logs
```

### 4.3 systemd

`/etc/systemd/system/bedrock-shell.service`（先启动，负责创建 socket）：

```ini
[Unit]
Description=Bedrock network diagnostics worker
After=network.target

[Service]
Type=simple
User=bedrock-shell
Group=bedrock
WorkingDirectory=/opt/bedrock
EnvironmentFile=/etc/bedrock/bedrock.env
RuntimeDirectory=bedrock
RuntimeDirectoryMode=0775
ExecStart=/opt/bedrock/.venv/bin/python -m shell_worker.worker
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/bedrock.service`：

```ini
[Unit]
Description=Bedrock model API test platform
After=network.target bedrock-shell.service
Requires=bedrock-shell.service

[Service]
Type=simple
User=bedrock
Group=bedrock
WorkingDirectory=/opt/bedrock
EnvironmentFile=/etc/bedrock/bedrock.env
RuntimeDirectory=bedrock
RuntimeDirectoryMode=0775
ExecStart=/opt/bedrock/.venv/bin/uvicorn backend.main:app --host ${BIND_HOST} --port ${BIND_PORT} --workers 1
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

> **必须以单进程运行**（`--workers 1`）：任务队列、并发闸门与请求预算都在进程内维护，多 worker 会各算各的。

```bash
systemctl daemon-reload
systemctl enable --now bedrock-shell bedrock
curl -fsS http://127.0.0.1:8000/login -o /dev/null && echo OK
tail -n 50 /opt/bedrock/logs/bedrock.log
```

### 4.4 Nginx 反向代理

```nginx
server {
    listen 443 ssl http2;
    server_name test.example.com;

    ssl_certificate     /etc/letsencrypt/live/test.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/test.example.com/privkey.pem;

    client_max_body_size 20m;          # 证据上传

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;       # 长任务 / 长流式响应
        proxy_buffering off;           # SSE 不被缓冲
    }
}
```

配套设置：`PUBLIC_ORIGIN=https://test.example.com`、`COOKIE_SECURE=true`、`TRUST_PROXY_HEADERS=true`（只允许同机反代时开启）。

### 4.5 数据与备份

- 数据库是单个 SQLite 文件（`DB_PATH`），直接复制或用 `sqlite3 .backup` 备份；
- `data/` 下还有人工确认上传的证据文件，备份时一并带上；
- 升级只替换代码，**不要覆盖** `data/`、`logs/` 与 `/etc/bedrock/bedrock.env`。

## 5. 使用流程

1. `/tasks` 新建任务：填 Endpoint、API Key、模型 ID（可多个）、协议与请求间隔；
2. 平台先跑三条前置必测，任一不过即判「不达标」并停止，不会白烧后面的请求；
3. 全量执行第 1～4 章：自动项直接判定，人工项进入「待确认」；
4. 在任务详情/记录页补人工结论、上传证据，支持单项、按章、整任务重测；
5. 导出 PDF（单模型或整批合并），导出前会重新校验标准版本与任务归属。

## 6. 安全设计

- API Key 只在当次请求内存中存在，不落库、不写日志、不返回前端；表单提交后立即清空。
- 报告与日志统一脱敏（`Bearer`、`sk-*`、AK/SK、Cookie），并对超长文本截断。
- 上游地址默认禁止回环、内网、链路本地与云元数据地址，需显式开 `ALLOW_PRIVATE_UPSTREAM` 或配置白名单。
- 登录会话使用 HttpOnly/SameSite Cookie + CSRF 校验，含失败锁定、空闲与绝对超时。
- 网络诊断工作进程以独立低权限账号运行，只认 curl/ping/dig，不经过 shell，并自行复核参数与目标地址。

## 7. 常见问题

| 现象 | 处理 |
| --- | --- |
| 大量 429 / 限流 | 调大 `MODEL_REQUEST_INTERVAL`（如 3～5 秒），或减少任务内的模型数量 |
| GATE-02 命中率 0 | Claude 模型需 `cache_control` 显式写缓存（默认 5 分钟 TTL）；平台已自动改用 `/v1/messages`，若仍报 `cache_creation=0`，说明该网关未透传缓存 |
| 获取模型列表失败 | 平台会自动尝试 `/models` 与 `/v1/models`；仍失败时错误信息里会列出试过的地址 |
| 网络诊断页不可用 | 检查 `SHELL_ENABLED`、`SHELL_TOKEN` 是否与工作进程一致，`/run/bedrock/shell.sock` 属组是否为 `bedrock` |
| PDF 中文显示为方块 | 安装 Noto Sans CJK，或用 `REPORT_FONT_PATH` 指向可用的 TTF |

## 8. 版本与许可

内部使用项目，未附开源许可。标准数据（`config/*.json`）随代码一起版本化，报告结论以任务绑定的标准快照为准。

---

本仓库不含测试套件、部署脚本与交付文档；如需回归测试、验收用例或打包产物，请使用内部仓库或联系维护人。
