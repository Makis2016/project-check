# VulnLens · Web 安全体检

输入一个自有站点地址，自动完成资产探测、接口发现、配置检测与低风险主动验证，输出可导出的 Markdown / HTML / JSON / CSV 报告，并支持两次扫描差异对比。全部计算在本机完成，不上传任何数据。

## 能力范围

- 资产：DNS 解析、常见端口探测、TLS 证书与协议、子域名枚举与 CNAME 接管指纹
- 发现：爬虫、robots/sitemap、OpenAPI/Swagger 文档解析与参数注入、表单、JS 中的接口路径
- 检测：安全响应头、Host 头注入、CORS、Cookie 标记、CSRF Token 缺失、HTTP 方法、敏感文件与备份/交换文件、目录列表、错误泄露、SourceMap、JS 密钥、JWT、GraphQL introspection、SPF/DMARC、组件指纹与内置 CVE 匹配
- 质量巡检（可选）：坏链、5xx、混合内容、静态资源与 JS 加载失败
- 主动验证（可选）：反射型 XSS、报错型 SQL 注入、开放重定向
- 登录态检测（可选）：未授权接口访问、双账号 IDOR/越权
- 高风险验证（默认关闭）：SSRF、路径穿越/文件读取、命令注入、SSTI、HTTP 请求走私、存储型 XSS
- 复现与对比：请求/响应原文、复制 cURL、HTTP/SOCKS5 代理、排除路径与域名、历史扫描 diff
- 主机巡检（可选）：通过 SSH 只读采集，检查系统 EOL、待安装安全更新、重启标记、SSH root/密码认证、防火墙、SELinux/AppArmor、UID 0 账号、Docker socket 与自动更新配置

高风险验证可能写入测试数据或影响目标，仅限已授权环境；不包含密码爆破、全量目录爆破与自动 getshell。主机巡检只执行读取类命令，不使用 sudo，不修改目标系统，SSH 密码与私钥口令不会写入本地数据库。

## 开发运行

```bash
pip install -r requirements.txt

cd frontend && npm install && npm run build && cd ..

python run.py                 # 启动并打开浏览器
python run.py --desktop       # 桌面窗口模式（需要 pywebview）
python run.py --port 8000     # 指定端口
```

前后端分离调试：

```bash
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
cd frontend && npm run dev   # http://localhost:5173，/api 已代理到 8000
```

## 测试

```bash
python tests/smoke_scan.py
```

脚本会在本机 8901 端口启动一个故意包含漏洞的靶站，扫描后断言关键检测项全部命中。

## 打包

```bash
pip install -r requirements-dev.txt
pyinstaller packaging/vulnlens.spec --noconfirm
```

产物：Windows 为 `dist/VulnLens.exe`，macOS 为 `dist/VulnLens.app`。推送到 `v*` 标签或手动触发 `.github/workflows/build.yml` 可得到双平台构建产物。

## 使用边界

仅用于扫描你拥有或已获得书面授权的目标。启动扫描前界面会要求确认授权；服务只监听 `127.0.0.1`，并默认启用请求限速与请求预算。
