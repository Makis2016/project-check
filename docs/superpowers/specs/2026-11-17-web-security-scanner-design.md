# VulnLens Web 安全体检工具 · 设计文档

日期：2026-11-17
状态：已与用户确认

## 1. 产品定位

单用户、本地运行的 Web 安全体检工具，面向**自有或已获授权**的站点。输入一个根 URL，输出可执行的漏洞清单、证据与中文修复建议。

非目标：通用攻击平台、批量公网扫描器、渗透测试替代品。

### 硬性边界

- 不做弱口令、口令爆破、盲注/时间盲注、文件上传利用、后门类检测。
- 全局限速，单次扫描限制总请求数与最大爬取页面数。
- 仅监听 `127.0.0.1` 的随机端口；启动扫描前必须勾选授权声明，声明随扫描记录保存。

## 2. 扫描能力矩阵（MVP）

| 阶段 | 能力 | 说明 |
|---|---|---|
| 资产 | DNS 解析、TLS 证书与协议、常见端口 | TCP connect 探测，不依赖 nmap；默认常见端口，可自定义 |
| 接口发现 | 同源爬虫、表单提取、JS 内路径提取、robots/sitemap、Swagger/OpenAPI 探测、常见目录字典 | 支持 Cookie/Header 会话，覆盖登录后区域 |
| 配置检测 | 安全响应头、CORS、Cookie 属性、TLS 弱配置、HTTP 方法、目录列表、错误页泄露、默认页、敏感/备份文件、调试端点、SourceMap 泄露、JS 硬编码密钥 | 零风险、低误报 |
| 主动验证 | 反射型 XSS、报错型 SQLi、Open Redirect | 无害 payload、逐项开关、默认低频，只验证不利用 |
| 指纹与 CVE | 常见组件/中间件版本识别 + 内置精选 CVE 库（离线） | nginx、Apache、Tomcat、Spring、ThinkPHP、jQuery、Vue 等 |

### 统一发现模型

风险等级（critical/high/medium/low/info）、置信度（high/medium/low）、URL/参数、请求响应证据、CWE/OWASP、中文修复建议（含配置或代码示例）、参考资料。

## 3. 技术架构

- 后端：Python 3.11+、FastAPI、httpx、BeautifulSoup、dnspython；阶段管线 + 检测器插件。
- 前端：React + TypeScript + Vite；页面为新建扫描、扫描进行中、结果详情、历史记录。
- 桌面壳：pywebview 内嵌系统 WebView（Windows WebView2 / macOS WKWebView），启动本地 FastAPI 后加载界面；关窗即退出。
- 存储：SQLite（扫描记录、发现项），证据写入本地数据目录。
- 实时通信：SSE 推送阶段进度、日志与发现。
- 打包：PyInstaller 输出 .exe / .app，GitHub Actions 双平台构建。

### 目录结构

```
backend/
  app.py                 FastAPI 应用与 API
  db.py                  SQLite 持久化
  scanner/
    models.py            ScanConfig / Finding / Endpoint / ScanSnapshot
    http_client.py       限速 HTTP 客户端
    engine.py            扫描编排与事件推送
    assets.py            DNS / TLS / 端口 / 子域名
    crawler.py           爬虫与接口发现
    fingerprints.py      组件指纹
    cve_db.json          精选 CVE 库
    checks/              各检测器（可独立开关）
    report.py            Markdown 报告
frontend/                React 界面
desktop/main.py          pywebview 桌面入口
tests/                   单元与集成测试（含本地靶站）
packaging/               打包脚本与 CI
```

## 4. API 设计

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/scans` | 创建并启动扫描 |
| GET | `/api/scans` | 历史列表 |
| GET | `/api/scans/{id}` | 扫描快照（状态、进度、发现） |
| GET | `/api/scans/{id}/stream` | SSE 实时事件 |
| POST | `/api/scans/{id}/stop` | 中止扫描 |
| DELETE | `/api/scans/{id}` | 删除记录 |
| GET | `/api/scans/{id}/report.md` | 导出 Markdown 报告 |
| GET | `/api/health` | 健康检查 |

## 5. 关键流程

1. 输入 URL → 勾选授权 → 选择预设（快速/标准/深度）+ 可选会话、端口、限速。
2. 后台任务：资产探测 → 接口发现 → 检测器并发执行 → 去重聚合并落库。
3. UI 实时显示阶段、进度、请求速率与发现流，可中止。
4. 结果页按等级/类型筛选，查看证据与修复建议。
5. 导出 Markdown 报告。

## 6. 稳健性与合规

- 目标不可达/超时给出明确原因，不无限重试。
- 遇 429/403 自动降速或提示被封禁风险。
- 默认不忽略 TLS 错误，证书问题作为发现项；用户可显式忽略。
- 全局限速（默认 5 req/s），限制总请求数与最大页面数。
- 仅监听本机回环地址。

## 7. 测试策略

- 本地“故意有漏洞”的靶站 fixture，覆盖缺失安全头、反射 XSS、SQL 报错、开放重定向、暴露 .env、目录列表、CORS 通配、SourceMap 等。
- 检测器单元测试 + 扫描管线集成测试 + 浏览器 UI 冒烟测试。

## 8. 首版不做

- 盲注/时间盲注、弱口令、认证绕过、业务逻辑漏洞。
- 分布式、多用户、定时任务。
- 内置 Chromium 的 SPA 深度渲染（首版静态解析 JS 包，后续可作为可选模式）。
- HTML/PDF 报告（首版仅页面查看 + Markdown 导出）。
