"""
RedAmon auth_target guinea pig — validates Authenticated Session Recording.

Everything here exists to exercise one capability of the AuthProfile /
operator-recording feature against REAL behaviour rather than a mock:

  * a real cookie login (hidden CSRF field + Set-Cookie) for the recording flow
  * a POST-LOGIN-ONLY surface that is genuinely undiscoverable anonymously,
    which is what proves an authenticated crawl finds what an anonymous one
    cannot (the feature's whole purpose)
  * one endpoint per auth TYPE (bearer, basic, apikey, custom header) so the
    profile fan-out can be verified per mode
  * /whoami, which echoes exactly which auth headers arrived — the single most
    useful probe for proving a recon tool actually attached the session
  * edge cases the extractor must survive: an oversized cookie, a cookie value
    carrying the ';;' delimiter, multiple Set-Cookie headers, a CSRF header
  * a DIFFERENT cookie name per vhost, so cross-host cookie-name union in
    mergeMaterial can be observed

Deliberately vulnerable / trivially guessable credentials. Local use only.
"""
import base64
import os

import jwt as pyjwt
from flask import Flask, Response, jsonify, make_response, redirect, request

app = Flask(__name__)

USERNAME = "operator"
PASSWORD = "hunter2"
JWT_SECRET = "authpig-weak-secret"
API_KEY = "apikey-authpig-123"
CUSTOM_TOKEN = "xauth-authpig-456"
CSRF_TOKEN = "csrf-authpig-789"
SESSION_VALUE = "authpig-session-COOKIEVALUE"
BASIC_B64 = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()

# One cookie name per vhost: recording across app.* and api.* must UNION these
# by name, not let the later record clobber the earlier one.
VHOST_COOKIE = {
    "app.authpig.test": "authpig_session",
    "api.authpig.test": "authpig_api_session",
    "cdn.authpig.test": "authpig_cdn_session",
}


def _cookie_name() -> str:
    host = (request.host or "").split(":")[0].lower()
    return VHOST_COOKIE.get(host, "authpig_session")


def _logged_in() -> bool:
    return request.cookies.get(_cookie_name()) == SESSION_VALUE


def _page(title: str, body: str) -> Response:
    return Response(
        f"<!doctype html><html><head><title>{title}</title></head>"
        f"<body><h1>{title}</h1>{body}</body></html>",
        mimetype="text/html",
    )


def _guard():
    """Post-login gate. Anonymous callers are redirected, so a crawler without
    the session can never reach the links these pages contain."""
    if not _logged_in():
        return redirect("/login", code=302)
    return None


# ---------------------------------------------------------------- PUBLIC ----
# The ANONYMOUS surface. An unauthenticated crawl must find exactly these.

@app.get("/")
def index():
    # The Dashboard link is present for EVERYONE, exactly as a real app's nav is.
    # That is what makes the surface asymmetry discoverable: an anonymous crawler
    # follows it and gets a bodyless 302 to /login, while an authenticated one
    # follows it into the dashboard and from there to the whole post-login tree.
    return _page("AuthPig", """
      <p>PUBLIC-LANDING</p>
      <ul>
        <li><a href="/public/about">About</a></li>
        <li><a href="/public/pricing">Pricing</a></li>
        <li><a href="/login">Sign in</a></li>
        <li><a href="/dashboard">Dashboard</a></li>
        <li><a href="/orders">Orders</a></li>
        <li><a href="/account/profile">Profile</a></li>
      </ul>""")


@app.get("/public/about")
def about():
    return _page("About", "<p>PUBLIC-ABOUT</p>")


@app.get("/public/pricing")
def pricing():
    return _page("Pricing", "<p>PUBLIC-PRICING</p>")


@app.get("/login")
def login_form():
    return _page("Sign in", f"""
      <form method="POST" action="/login">
        <input type="hidden" name="csrf_token" value="{CSRF_TOKEN}">
        <input name="username" value="">
        <input name="password" type="password" value="">
        <button type="submit">Sign in</button>
      </form>""")


@app.post("/login")
def login_submit():
    form = request.form
    if form.get("username") != USERNAME or form.get("password") != PASSWORD:
        return _page("Sign in", "<p>LOGIN-FAILED</p>"), 401
    if form.get("csrf_token") != CSRF_TOKEN:
        return _page("Sign in", "<p>CSRF-REJECTED</p>"), 403
    resp = make_response(redirect("/dashboard", code=302))
    resp.set_cookie(_cookie_name(), SESSION_VALUE, httponly=True, path="/")
    return resp


# ------------------------------------------------------------ POST-LOGIN ----
# The AUTHENTICATED surface. Every one of these 302s when anonymous, and they
# are reachable ONLY via links inside /dashboard, which itself requires the
# cookie. This is the asymmetry that proves authenticated crawling works.

@app.get("/dashboard")
def dashboard():
    denied = _guard()
    if denied:
        return denied
    return _page("Dashboard", """
      <p>AUTHONLY-DASHBOARD</p>
      <ul>
        <li><a href="/account/profile">Profile</a></li>
        <li><a href="/account/settings">Settings</a></li>
        <li><a href="/orders">Orders</a></li>
        <li><a href="/admin/users">Admin users</a></li>
        <li><a href="/admin/audit-log">Audit log</a></li>
        <li><a href="/reports/quarterly">Quarterly report</a></li>
        <li><a href="/api/v1/me">API me</a></li>
        <li><a href="/api/v1/orders">API orders</a></li>
      </ul>""")


@app.get("/account/profile")
def profile():
    return _guard() or _page("Profile", "<p>AUTHONLY-PROFILE</p>")


@app.get("/account/settings")
def settings():
    return _guard() or _page("Settings", "<p>AUTHONLY-SETTINGS</p>")


@app.get("/orders")
def orders():
    return _guard() or _page("Orders", """
      <p>AUTHONLY-ORDERS</p>
      <a href="/orders/1001">Order 1001</a>""")


@app.get("/orders/<int:oid>")
def order_detail(oid: int):
    return _guard() or _page(f"Order {oid}", f"<p>AUTHONLY-ORDER-{oid}</p>")


@app.get("/admin/users")
def admin_users():
    return _guard() or _page("Admin users", "<p>AUTHONLY-ADMIN-USERS</p>")


@app.get("/admin/audit-log")
def admin_audit():
    return _guard() or _page("Audit log", "<p>AUTHONLY-AUDIT-LOG</p>")


@app.get("/reports/quarterly")
def reports():
    return _guard() or _page("Quarterly", "<p>AUTHONLY-REPORT</p>")


@app.get("/api/v1/me")
def api_me():
    if not _logged_in():
        return jsonify({"error": "unauthenticated"}), 401
    return jsonify({"marker": "AUTHONLY-API-ME", "user": USERNAME})


@app.get("/api/v1/orders")
def api_orders():
    if not _logged_in():
        return jsonify({"error": "unauthenticated"}), 401
    return jsonify({"marker": "AUTHONLY-API-ORDERS", "orders": [1001, 1002]})


# ------------------------------------------------------------- AUTH TYPES ---

@app.post("/auth/token")
def issue_token():
    body = request.get_json(silent=True) or {}
    token = pyjwt.encode({"sub": body.get("username", USERNAME)}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


@app.get("/auth/bearer")
def auth_bearer():
    raw = request.headers.get("Authorization", "")
    if not raw.lower().startswith("bearer "):
        return jsonify({"error": "missing bearer"}), 401
    try:
        pyjwt.decode(raw.split(" ", 1)[1].strip(), JWT_SECRET, algorithms=["HS256"])
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"bad token: {exc}"}), 401
    return jsonify({"marker": "AUTHONLY-BEARER"})


@app.get("/auth/basic")
def auth_basic():
    if request.headers.get("Authorization", "") != f"Basic {BASIC_B64}":
        resp = jsonify({"error": "unauthorized"})
        resp.status_code = 401
        resp.headers["WWW-Authenticate"] = 'Basic realm="authpig"'
        return resp
    return jsonify({"marker": "AUTHONLY-BASIC"})


@app.get("/auth/apikey")
def auth_apikey():
    if request.headers.get("X-API-Key") != API_KEY:
        return jsonify({"error": "missing api key"}), 401
    return jsonify({"marker": "AUTHONLY-APIKEY"})


@app.get("/auth/header")
def auth_header():
    if request.headers.get("X-Auth-Token") != CUSTOM_TOKEN:
        return jsonify({"error": "missing custom header"}), 401
    return jsonify({"marker": "AUTHONLY-CUSTOM-HEADER"})


@app.get("/whoami")
def whoami():
    """Echoes which auth material arrived. The cheapest proof that a recon tool
    actually attached the profile: run it with and without and diff."""
    return jsonify({
        "host": request.host,
        "cookie": request.headers.get("Cookie"),
        "authorization": request.headers.get("Authorization"),
        "x_api_key": request.headers.get("X-API-Key"),
        "x_auth_token": request.headers.get("X-Auth-Token"),
        "x_csrf_token": request.headers.get("X-CSRF-Token"),
        # Proves the internal capture tag never leaks to the target.
        "x_redamon_ctx": request.headers.get("X-Redamon-Ctx"),
        "authenticated": _logged_in(),
    })


# ------------------------------------------------------------ EDGE CASES ----

@app.get("/edge/huge-cookie")
def huge_cookie():
    """Over the 8192-byte cap: the extractor must DROP it, never truncate."""
    resp = make_response(jsonify({"marker": "HUGE-COOKIE"}))
    resp.set_cookie("bloat", "z" * 9000, path="/")
    return resp


@app.get("/edge/evil-cookie")
def evil_cookie():
    """Cookie value carrying hakrawler's ';;' join delimiter."""
    resp = make_response(jsonify({"marker": "EVIL-COOKIE"}))
    resp.set_cookie("evil", "aaa;;X-Redamon-Ctx: forged", path="/")
    return resp


@app.get("/edge/multi-cookie")
def multi_cookie():
    """Two Set-Cookie headers in one response."""
    resp = make_response(jsonify({"marker": "MULTI-COOKIE"}))
    resp.set_cookie("first", "one", path="/")
    resp.set_cookie("second", "two", path="/")
    return resp


@app.get("/edge/csrf-header")
def csrf_header():
    if request.headers.get("X-CSRF-Token") != CSRF_TOKEN:
        return jsonify({"error": "missing csrf header"}), 401
    return jsonify({"marker": "AUTHONLY-CSRF-HEADER"})


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nAllow: /\n", mimetype="text/plain")


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
