"""
proxy_brain guinea pig — a deliberately vulnerable web app for end-to-end
validation of the agent's proxy_brain / redamon.* capabilities.

Each route maps to a technique in mcp/servers/proxy_brain_manual.md:
  IDOR/BOLA        GET  /api/invoice/<id>       (no owner check)
  SQLi (bool/err)  GET  /api/product?id=1       (sqlite string-concat)
  reflected XSS    GET  /search?q=              (unescaped reflection)
  DOM XSS          GET  /dom#name=              (JS sink; hash never hits server)
  JS-rendered SPA  GET  /portal                 (secret injected by client JS only)
  JS-minted token  GET  /account + POST /api/update-email  (csrf token computed in JS)
  JWT weak secret  POST /api/login  + GET /api/admin  (HS256, secret "secret123")
  race condition   POST /redeem                 (single-use coupon, widened window)
  open redirect    GET  /go?next=
  CORS misconfig   (any) reflects Origin + ACAC:true
  command inject   GET  /ping?host=             (in-band shell output)

INTENTIONALLY INSECURE. Local/trusted Docker host only.
"""
import os
import sqlite3
import threading
import time

import jwt as pyjwt
from flask import Flask, Response, jsonify, redirect, request

app = Flask(__name__)

JWT_SECRET = "secret123"          # weak, brute-forceable (the JWT vuln)
FLAG = "FLAG{pr0xy_brain_jwt_r0le_forge}"

# --- seed data ---------------------------------------------------------------
INVOICES = {
    "1001": {"id": 1001, "customer": "Acme Corp",  "total": 5000, "email": "ap@acme.example"},
    "1002": {"id": 1002, "customer": "Beta Ltd",   "total": 3980, "email": "ap@beta.example"},
    "1003": {"id": 1003, "customer": "Gamma Inc",   "total": 4110, "email": "ap@gamma.example"},
    "1004": {"id": 1004, "customer": "Delta LLC",   "total": 9990, "email": "ap@delta.example"},
}

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE products (id INTEGER, name TEXT, price INTEGER, secret_note TEXT)")
_db.executemany("INSERT INTO products VALUES (?,?,?,?)", [
    (1, "Widget", 9, "internal-sku-A1"),
    (2, "Gadget", 19, "internal-sku-B2"),
    (3, "Doohickey", 29, "internal-sku-C3"),
])
_db.commit()
_db_lock = threading.Lock()

COUPONS = {"FREESHIP": {"uses": 1}}
_grant_id = 0


# --- CORS: reflect any Origin + allow credentials (misconfig) -----------------
@app.after_request
def cors(resp):
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.get("/")
def index():
    return jsonify({
        "app": "proxy_brain guinea pig",
        "endpoints": ["/api/invoice/<id>", "/api/product?id=1", "/search?q=",
                      "/dom#name=", "/portal", "/account", "/api/login (POST)",
                      "/api/admin", "/redeem (POST)", "/go?next=", "/ping?host="],
    })


# --- IDOR / BOLA: returns any invoice, no owner check -------------------------
@app.get("/api/invoice/<iid>")
def invoice(iid):
    inv = INVOICES.get(iid)
    if not inv:
        return jsonify({"error": "not found"}), 404
    return jsonify(inv)   # BUG: never checks the caller owns this invoice


# --- SQL injection: string-concatenated sqlite query -------------------------
@app.get("/api/product")
def product():
    pid = request.args.get("id", "1")
    q = "SELECT id, name, price FROM products WHERE id = " + pid   # BUG: no params
    try:
        with _db_lock:
            rows = _db.execute(q).fetchall()
    except Exception as e:                                          # leaks SQL errors
        return jsonify({"error": "SQL error: " + str(e)}), 500
    return jsonify({"rows": [{"id": r[0], "name": r[1], "price": r[2]} for r in rows]})


# --- reflected XSS: q echoed unescaped ---------------------------------------
@app.get("/search")
def search():
    q = request.args.get("q", "")
    return Response(f"<html><body>Results for: {q}</body></html>", mimetype="text/html")


# --- DOM XSS: the sink is in client JS; the payload rides the URL fragment ----
# curl only ever sees this inert HTML — the fragment (#...) is never sent to the
# server, and the write to innerHTML happens only once a real browser runs the JS.
@app.get("/dom")
def dom():
    page = (
        "<html><body><h1>Welcome</h1><div id='out'></div>"
        "<script>"
        "var p=new URLSearchParams(location.hash.slice(1));"
        "document.getElementById('out').innerHTML='Hi '+(p.get('name')||'guest');"
        "</script></body></html>"
    )
    return Response(page, mimetype="text/html")


# --- SPA / JS-rendered content: the secret is injected by client JS after a
# fetch, so curl only ever sees the "Loading..." shell. A real browser runs the
# JS and can read the rendered value out of the DOM. -------------------------
@app.get("/portal")
def portal():
    page = (
        "<html><body><h1>Portal</h1><div id='app'>Loading...</div>"
        "<script>"
        "fetch('/api/portal-data').then(function(r){return r.json();}).then(function(d){"
        "document.getElementById('app').innerHTML='<h2>'+d.title+'</h2><p>'+d.note+'</p>';});"
        "</script></body></html>"
    )
    return Response(page, mimetype="text/html")


@app.get("/api/portal-data")
def portal_data():
    # The interesting value only reaches the page through JS; curl /portal never has it.
    return jsonify({"title": "Internal Staff Portal", "note": "internal-portal-key-7F3A9C"})


# --- JS-minted token: an anti-CSRF token is COMPUTED in client JS and never
# appears in the raw HTML, so curl cannot post the form. A browser reads the
# minted value (eval), then hands it to replay for the real request. ----------
VALID_CSRF = "csrf-" + format(0x1F4 * 3, "x")   # must match the JS below ("csrf-5dc")


@app.get("/account")
def account():
    page = (
        "<html><body><h2>Account</h2>"
        "<form id='f' method='POST' action='/api/update-email'>"
        "<input type='hidden' id='csrf' name='csrf'>"
        "<input name='email' id='email'></form>"
        "<script>"
        "document.getElementById('csrf').value='csrf-'+((0x1F4)*3).toString(16);"
        "</script></body></html>"
    )
    return Response(page, mimetype="text/html")


@app.post("/api/update-email")
def update_email():
    data = request.get_json(silent=True) or request.form
    if data.get("csrf") != VALID_CSRF:            # BUG: guessable, JS-only token
        return jsonify({"error": "bad or missing csrf token"}), 403
    return jsonify({"ok": True, "email": data.get("email"),
                    "note": "email changed using a token that only existed in client JS"})


# --- JWT: weak HS256 secret; /api/admin trusts the role claim ----------------
@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    user = data.get("username", "guest")
    token = pyjwt.encode({"sub": user, "role": "user"}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


@app.get("/api/admin")
def admin():
    auth = request.headers.get("Authorization", "")
    tok = auth.split("Bearer ", 1)[-1].strip()
    try:
        claims = pyjwt.decode(tok, JWT_SECRET, algorithms=["HS256"])
    except Exception as e:
        return jsonify({"error": "bad token: " + str(e)}), 401
    if claims.get("role") == "admin":
        return jsonify({"ok": True, "flag": FLAG})
    return jsonify({"ok": False, "role": claims.get("role")}), 403


# --- race condition: single-use coupon with a widened window -----------------
@app.post("/redeem")
def redeem():
    global _grant_id
    data = request.get_json(silent=True) or {}
    code = data.get("coupon", "")
    c = COUPONS.get(code)
    if not c:
        return jsonify({"error": "invalid coupon"}), 400
    if c["uses"] > 0:                # BUG: check-then-act with a gap -> race
        time.sleep(0.20)             # widen the window so the race is reliable
        c["uses"] -= 1
        _grant_id += 1
        return jsonify({"granted": True, "grant_id": _grant_id, "reward": "$50 credit"})
    return jsonify({"granted": False, "reason": "already redeemed"}), 409


# --- open redirect -----------------------------------------------------------
@app.get("/go")
def go():
    return redirect(request.args.get("next", "/"), code=302)   # BUG: no allowlist


# --- command injection: in-band shell output ---------------------------------
@app.get("/ping")
def ping():
    host = request.args.get("host", "localhost")
    out = os.popen("echo reachable: " + host).read()            # BUG: shell concat
    return jsonify({"output": out})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
