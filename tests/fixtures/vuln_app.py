"""故意存在漏洞的本地靶站，仅用于验证检测器，不对外网提供服务。"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

ROOT_HTML = """<!doctype html>
<html><head><title>Acme Portal</title>
<script src="/static/jquery-1.7.1.min.js"></script>
<script src="/static/app.js"></script>
</head><body>
<h1>Acme Portal</h1>
<a href="/search?q=hello">Search</a>
<a href="/redirect?next=/page">Next</a>
<a href="/page">Page</a>
<a href="/static/">Static files</a>
<form action="/search" method="get"><input name="q" placeholder="keyword"></form>
</body></html>"""


@app.middleware("http")
async def insecure_middleware(request: Request, call_next):
    response: Response = await call_next(request)
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    if request.url.path == "/":
        response.headers.append("set-cookie", "sessionid=abc123; Path=/")
        response.headers.append(
            "set-cookie",
            "auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.abcdefghij; Path=/; HttpOnly",
        )
    return response


@app.get("/", response_class=HTMLResponse)
async def root() -> str:
    return ROOT_HTML


@app.get("/page", response_class=HTMLResponse)
async def page() -> str:
    return "<html><head><title>Page</title></head><body><a href='/'>back</a></body></html>"


@app.get("/search", response_class=HTMLResponse)
async def search(q: str = "") -> str:
    return f"<html><head><title>Search</title></head><body><h1>Results for {q}</h1></body></html>"


@app.get("/api/item")
async def item(id: str = "1"):
    if "'" in id:
        return PlainTextResponse(
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            status_code=500,
        )
    return {"id": id}


@app.get("/api/echo", response_class=HTMLResponse)
async def api_echo(message: str = "") -> str:
    return f"<html><body><p>echo: {message}</p></body></html>"


OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Acme API", "version": "1.0.0"},
    "paths": {
        "/api/echo": {
            "get": {
                "parameters": [{"name": "message", "in": "query", "schema": {"type": "string"}}],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/item": {
            "get": {
                "parameters": [{"name": "id", "in": "query", "schema": {"type": "string"}}],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/orders/{orderId}": {
            "get": {
                "parameters": [
                    {"name": "orderId", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": "expand", "in": "query", "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
}


@app.get("/openapi.json")
async def openapi_doc() -> JSONResponse:
    return JSONResponse(OPENAPI_SPEC)


@app.get("/redirect")
async def redirect(next: str = "/"):
    return RedirectResponse(url=next, status_code=302)


@app.get("/.env", response_class=PlainTextResponse)
async def env_file() -> str:
    return "DB_HOST=localhost\nDB_PASSWORD=supersecret\nAPI_KEY=abcdef1234567890\n"


@app.get("/.git/config", response_class=PlainTextResponse)
async def git_config() -> str:
    return "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"


@app.get("/static/", response_class=HTMLResponse)
async def static_dir() -> str:
    return "<html><head><title>Index of /static/</title></head><body><h1>Index of /static/</h1><a href='app.js'>app.js</a></body></html>"


@app.get("/static/app.js")
async def app_js() -> Response:
    body = (
        "const cfg = {apiKey: 'AKIAIOSFODNN7EXAMPLE'};\n"
        "fetch('/api/item?id=1');\n"
        "//# sourceMappingURL=app.js.map\n"
    )
    return Response(body, media_type="application/javascript")


@app.get("/static/app.js.map")
async def app_map() -> JSONResponse:
    return JSONResponse({"version": 3, "sources": ["src/app.ts"], "mappings": "AAAA"})


@app.get("/static/jquery-1.7.1.min.js")
async def jquery() -> Response:
    return Response("/* jquery stub */", media_type="application/javascript")


@app.get("/actuator/env")
async def actuator_env() -> JSONResponse:
    return JSONResponse({"activeProfiles": ["prod"], "propertySources": [{"name": "systemProperties"}]})


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"])
async def catch_all(path: str) -> PlainTextResponse:
    return PlainTextResponse(
        "Traceback (most recent call last):\n"
        '  File "/srv/app/main.py", line 42, in handler\n'
        '    raise RuntimeError("boom")\n'
        "RuntimeError: boom\n",
        status_code=500,
    )
