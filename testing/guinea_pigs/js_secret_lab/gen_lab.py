#!/usr/bin/env python3
"""Generate the js_secret_lab sites into generated/ (git-ignored), from a fixed seed.

Every planted key is ASSEMBLED FROM PARTS here, at run time: no committed file
of this lab holds a full key-shaped string, so GitHub push protection and
secret scanning stay quiet on the public repository. expected.json holds labels
and sha256(value)[:12] only, never a value.

    python3 -I gen_lab.py                    # every host; .12 uses the running canary's IP
    python3 -I gen_lab.py --canary-ip <ip>   # what up.sh runs once the canary is up
    python3 -I gen_lab.py --emit-expected    # rewrite expected.json (keeps its trufflehog column)
    python3 -I gen_lab.py --check-expected   # exit 1 when expected.json and the generator disagree
    python3 -I gen_lab.py --real-keys <api-keys-export.json> [--out-dir DIR] [--no-probe]   # E3 only

--real-keys reads RedAmon's API-keys export (`keys.<name>`, `rotation.<tool>.extraKeys`)
and writes host .15 (each real key next to its provider word, plus a copy of
.10's invented keys), its compose file and expected_real.json into
_local/internal/temp_fix/js_recon_truffle_e2e/lab_real_keys/. It prints key
NAMES and sha256(value)[:12] only. Run it immediately before E3, and delete
that folder in the E3 cleanup.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import zlib

SEED = "js-secret-lab:2026-11-01"
NET = "192.88.96"
HOST_IPS = {
    "app-modern": f"{NET}.10",
    "vendor-only": f"{NET}.11",
    "ssrf-bait": f"{NET}.12",
    "clean-control": f"{NET}.14",
    "app-realkeys": f"{NET}.15",
}
UPLOAD_HOST = "upload"

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
GEN = os.path.join(HERE, "generated")
EXPECTED = os.path.join(HERE, "expected.json")
RUNTIME = os.path.join(GEN, "expected_runtime.json")
REAL_OUT = os.path.join(REPO, "_local", "internal", "temp_fix", "js_recon_truffle_e2e", "lab_real_keys")
NODE_MODULES = os.path.join(REPO, "webapp", "node_modules")
CANARY = "jslab-canary"
TH_NET = "redamon-trufflehog-net"

# patterns._window_line scans a line over 100k characters in 100k windows that
# advance by 95k. A hit near a window's end keeps its id but loses the text after
# it, and the Supabase rule reads the token's payload from there: a planted
# module starts inside [5k, 85k] of a 95k step so its window holds it whole.
WINDOW_STEP = 95_000
SAFE_ZONE = (5_000, 85_000)
MAIN_BYTES = 1_000_000

ALNUM = string.ascii_letters + string.digits
LOWER_ALNUM = string.ascii_lowercase + string.digits
B32 = string.ascii_uppercase + "234567"
B64 = ALNUM + "+/"
B64URL = ALNUM + "-_"
HEX = "0123456789abcdef"
BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase

# Provider prefixes, split so no committed line carries one whole.
P = {
    "akia": "AK" + "IA",
    "asia": "AS" + "IA",
    "sk_live": "sk" + "_li" + "ve_",
    "pk_live": "pk" + "_li" + "ve_",
    "rk_live": "rk" + "_li" + "ve_",
    "whsec": "wh" + "sec_",
    "ghp": "gh" + "p_",
    "xoxb": "xo" + "xb-",
    "openai_mark": "T3Blb" + "kFJ",
    "anthropic": "sk-an" + "t-api03-",
    "sendgrid": "S" + "G.",
    "aiza": "AI" + "za" + "Sy",
    "sb_secret": "sb_se" + "cret_",
    "mapbox": "p" + "k.",
    "glpat": "gl" + "pat-",
    "sts": "IQoJb3Jp" + "Z2luX2Vj",
    "jfrog_ref": "cmVm" + "dGtu",
    "atlassian": "ATAT" + "T3xFfGF0",
    "okta": "0" + "0",
    "pem_begin": "-----BEGIN " + "PRIVATE KEY-----",
    "pem_end": "-----END " + "PRIVATE KEY-----",
    "cert_begin": "-----BEGIN " + "CERTIFICATE-----",
    "cert_end": "-----END " + "CERTIFICATE-----",
    "yc": "Y" + "C",
}

# Random bodies never contain another rule's prefix, so a planted value fires
# the one rule it was made for, today and after new rules land.
_RISKY = ("AKIA", "ASIA", "ABIA", "ACCA", "AIza", "6L", "AC", "SK", "AP", "YC", "re_", "hf_", "r8_",
          "sk-", "sk_", "rk_", "pk_", "pk.", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat", "xox",
          "xapp", "SG.", "dapi", "oy2", "pul-", "ico-", "API-", "api-", "sdk-", "EAA", "glpat", "glptt",
          "glc_", "gldt", "glft", "glsa", "glsoat", "gloas", "glcbt", "GR1348941", "eyJ", "LTAI", "FLW",
          "sq0", "shp", "AGE-", "AKCp", "cmVmd", "sl.", "hvs.", "hvb.", "dp.pt", "nfp_", "rnd_", "tk-us",
          "NRAK", "NRII", "NRJS", "sntry", "pplx", "gsk_", "lin_api", "sgp_", "sqa_", "PMAK", "expo_",
          "pcsk_", "xaat", "xait", "tfp_", "rdme_", "EZAK", "p8e-", "fio-u", "A3-", "ops_", "tr_", "sb_",
          "dop_", "doo_", "dor_", "v1.0-", "rzp_", "api_org", "key-", "AQVN", "dt0c01", "FlyV1", "dckr",
          "pypi-", "CLOJARS", "ATATT", "duffel_", "shippo_", "whsec", "ya29", "amzn", "sha256~")


def rng(tag):
    return random.Random(f"{SEED}:{tag}")


def body(r, alphabet, n):
    """n random characters from `alphabet`, free of every prefix in _RISKY."""
    while True:
        s = "".join(r.choice(alphabet) for _ in range(n))
        if not any(p in s for p in _RISKY):
            return s


def digits(r, n):
    return str(r.randint(1, 9)) + "".join(r.choice(string.digits) for _ in range(n - 1))


def sha12(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def fname_hash(name):
    return hashlib.sha256(f"{SEED}:file:{name}".encode()).hexdigest()[:8]


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def base62(n, width):
    out = ""
    while n:
        n, d = divmod(n, 62)
        out = BASE62[d] + out
    return out.rjust(width, "0")


# ---------------------------------------------------------------------------
# Invented, real-format keys
# ---------------------------------------------------------------------------

def aws_access_key_id(r, prefix="akia"):
    return P[prefix] + body(r, B32, 16)


def aws_secret(r):
    return body(r, ALNUM + "/+", 40)


def sts_session_token(r):
    return P["sts"] + body(r, B64, 584)


def stripe_secret(r, n=97):
    return P["sk_live"] + "51" + body(r, ALNUM, n)


def github_classic(r):
    # GitHub's format: 30 random base62 characters + base62(CRC32) of them.
    entropy = body(r, ALNUM, 30)
    return P["ghp"] + entropy + base62(zlib.crc32(entropy.encode()) & 0xFFFFFFFF, 6)


def slack_bot(r):
    return P["xoxb"] + digits(r, 12) + "-" + digits(r, 13) + "-" + body(r, ALNUM, 24)


def openai_key(r):
    return "sk" + "-" + body(r, ALNUM, 20) + P["openai_mark"] + body(r, ALNUM, 20)


def anthropic_key(r):
    return P["anthropic"] + body(r, B64URL, 93) + "AA"


def sendgrid_key(r):
    return P["sendgrid"] + body(r, ALNUM, 22) + "." + body(r, B64URL, 43)


def google_api_key(r, need_dash=False):
    while True:
        tail = body(r, B64URL, 33)
        # A dash keeps the firebaseConfig key out of the "Firebase API Key"
        # rule ([A-Za-z0-9_]{30,}): the case is GCP vs Generic, nothing else.
        if not need_dash or "-" in tail:
            return P["aiza"] + tail


def hs256_jwt(r, claims):
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
    secret = body(r, ALNUM, 40).encode()
    sig = b64url(hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def rs256_jwt(r, claims):
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": body(r, HEX, 8)},
                               separators=(",", ":")).encode())
    payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
    return f"{header}.{payload}.{body(r, B64URL, 342)}"


def mapbox_token(r):
    """(token, the part the Mapbox rule matches): `pk.` + an alphanumeric
    payload of 60+ characters, then `.` + the signature."""
    while True:
        payload = b64url(json.dumps({"u": "labshop" + body(r, string.ascii_lowercase, 5),
                                     "a": "cl" + body(r, LOWER_ALNUM, 23)},
                                    separators=(",", ":")).encode())
        if payload.isalnum() and len(payload) >= 60:
            head = P["mapbox"] + payload
            return head + "." + body(r, B64URL, 22), head


def pem_lines(r, head, nchars):
    raw = head + body(r, B64, nchars - len(head))
    return [raw[i:i + 64] for i in range(0, len(raw), 64)]


def uuid4(r):
    h = body(r, HEX, 32)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{r.choice('89ab')}{h[17:20]}-{h[20:32]}"


def jsstr(text):
    return json.dumps(text)


# ---------------------------------------------------------------------------
# Expected rows
# ---------------------------------------------------------------------------

def X(secret_type, severity, public=False, alt=None):
    """One expected js_recon finding (secret_type, severity, public_client_key)."""
    row = {"secret_type": secret_type, "severity": severity, "public_client_key": public}
    if alt:
        row["alternate_names_include"] = list(alt)
    return row


class Lab:
    def __init__(self):
        self.rows = []

    def plant(self, label, host, file, value, *, today, after, kind="key", match=None, note="",
              runtime=False):
        """Record one planted item. `today` is what js_recon reports for it on
        the code before the plan's Phase 0, `after` after Phase 0 (items 0.1-0.7);
        None = no finding. `match` is the text the rule matches when it is not
        the value itself (a keyword-anchored rule, a rule cut at a dot)."""
        self.rows.append({
            "label": label,
            "host": HOST_IPS.get(host, host),
            "file": file,
            "kind": kind,
            "value_sha12": sha12(value),
            "match_sha12": sha12(match if match is not None else value),
            "regex_today": today,
            "regex": after,
            "trufflehog": "TBD",
            "runtime": runtime,
            **({"note": note} if note else {}),
        })
        return value


# ---------------------------------------------------------------------------
# Filler: realistic minified webpack modules that match no rule
# ---------------------------------------------------------------------------

# No word containing "loca", "cmap", "woff" ...: js_recon's binary-context filter
# (patterns._BINARY_CONTEXT_RE) drops a key with one within 300 characters.
COMPONENTS = ["Product", "Cart", "Checkout", "Header", "Footer", "Banner", "Review", "Rating", "Wishlist",
              "Order", "Invoice", "Shipping", "Address", "Search", "Filter", "Sort", "Pager", "Modal",
              "Drawer", "Toast", "Avatar", "Badge", "Menu", "Tabs", "Grid", "Card", "Gallery", "Price",
              "Stock", "Promo", "Coupon", "Theme", "Layout", "Sidebar", "Breadcrumb", "Category",
              "Brand", "Story", "Video", "Basket", "Store", "Delivery", "Return", "Size", "Color"]
SUFFIXES = ["List", "Item", "View", "Panel", "Row", "Tile", "Box", "Bar", "Form", "Summary", "Picker", ""]
CLASSES = ["root", "title", "body", "item", "list", "icon", "label", "value", "wrapper", "active", "link",
           "image", "caption", "footer", "header", "row", "col", "grid", "chip", "media"]
TAGS = ["div", "span", "li", "a", "p", "section", "article", "button"]
KINDS = ["primary", "secondary", "compact", "wide", "muted", "accent", "outline", "ghost", "plain"]
PROPS = ["name", "label", "price", "sku", "title", "slug", "count", "caption"]
APIS = ["products", "cart", "orders", "reviews", "categories", "brands", "stores", "wishlist", "search",
        "promotions", "shipping/rates", "account/profile", "inventory", "returns", "gift-cards"]
LOCALES = [("en-US", "USD"), ("de-DE", "EUR"), ("it-IT", "EUR"), ("en-GB", "GBP"), ("fr-FR", "EUR")]


class Ids:
    def __init__(self, r):
        self.r, self.used = r, set()

    def __call__(self):
        while True:
            n = self.r.randint(1000, 99999)
            if n not in self.used:
                self.used.add(n)
                return n


def filler_module(r, ids):
    mid, dep = ids(), r.randint(1000, 99999)
    comp = r.choice(COMPONENTS) + r.choice(SUFFIXES)
    shape = r.randrange(4)
    if shape == 0:
        cls = f"{comp}_{r.choice(CLASSES)}__{body(r, ALNUM, 5)}"
        return (f'{mid}:(e,t,n)=>{{"use strict";n.d(t,{{Z:()=>s}});var r=n({dep}),o=n.n(r);const s=e=>{{'
                f'let{{title:t,items:a=[]}}=e;return o().createElement("{r.choice(TAGS)}",{{className:"{cls}"}},'
                f'o().createElement("h3",null,t),a.map(e=>o().createElement("span",{{key:e.id,'
                f'"data-kind":"{r.choice(KINDS)}"}},e.{r.choice(PROPS)})))}}}}')
    if shape == 1:
        return (f'{mid}:(e,t,n)=>{{"use strict";n.d(t,{{U:()=>i}});const i=async(e={{}})=>{{const t=new '
                f'URLSearchParams(e).toString(),n=await fetch("/api/{r.choice(["v1", "v2"])}/{r.choice(APIS)}"'
                f'+(t?"?"+t:""),{{credentials:"include"}});if(!n.ok)throw new Error("{comp} request failed: "'
                f'+n.status);return n.json()}}}}')
    if shape == 2:
        act = comp.upper()
        return (f'{mid}:(e,t,n)=>{{"use strict";n.d(t,{{x:()=>a}});const r={{items:[],loading:!1,'
                f'page:{r.randint(1, 9)}}};function a(e=r,t){{switch(t.type){{case"{act}/LOADED":return{{...e,'
                f'items:t.payload,loading:!1}};case"{act}/LOADING":return{{...e,loading:!0}};default:return e}}}}}}')
    loc, cur = r.choice(LOCALES)
    mul = r.choice([10, 100, 1000])
    return (f'{mid}:(e,t,n)=>{{"use strict";n.d(t,{{f:()=>o}});const r=new Intl.NumberFormat("{loc}",'
            f'{{style:"currency",currency:"{cur}"}});function o(e){{return r.format(Math.round({mul}*e)/{mul})}}}}')


def planted_module(ids, code, exports="k"):
    return f'{ids()}:(e,t,n)=>{{"use strict";n.d(t,{{{exports}:()=>c}});{code}}}'


def assemble(r, ids, planted, target, head, tail, windowed):
    """head + modules + tail, `planted` spread evenly between filler modules up
    to `target` characters."""
    parts, size = [head], len(head)
    slots = [int(target * (i + 1) / (len(planted) + 1)) for i in range(len(planted))]
    nxt = 0
    while size < target or nxt < len(planted):
        due = nxt < len(planted) and size >= slots[nxt]
        safe = not windowed or SAFE_ZONE[0] <= size % WINDOW_STEP <= SAFE_ZONE[1]
        mod = planted[nxt] if due and safe else filler_module(r, ids)
        nxt += 1 if due and safe else 0
        parts.append(mod if len(parts) == 1 else "," + mod)
        size += len(parts[-1])
    parts.append(tail)
    return "".join(parts)


# ---------------------------------------------------------------------------
# .10 app-modern: a webpack SPA
# ---------------------------------------------------------------------------

def app_paths():
    main = f"/assets/js/main.{fname_hash('main')}.js"
    return {
        "main": main,
        "map": main + ".map",
        "admin": f"/assets/js/412.{fname_hash('412')}.js",
        "checkout": f"/assets/js/checkout.{fname_hash('checkout')}.js",
    }


def build_app_modern(lab, host="app-modern"):
    paths = app_paths()
    main, admin, checkout, smap = paths["main"], paths["admin"], paths["checkout"], paths["map"]
    k = lambda label: rng(f"key:{label}")  # noqa: E731 - one stream per item: editing one moves no other
    plant = lambda label, file, value, **kw: lab.plant(label, host, file, value, **kw)  # noqa: E731
    ids = Ids(rng("ids:main"))
    mods = []

    akia, akia_secret = aws_access_key_id(k("aws-akia-id")), aws_secret(k("aws-akia-secret"))
    plant("aws-akia-id", main, akia, today=X("AWS Access Key ID", "critical"),
          after=X("AWS Access Key ID", "critical"))
    plant("aws-akia-secret", main, akia_secret, today=None, after=None,
          note="next to aws_secret_access_key: the AWS Secret Key rule allows 10 characters between "
               "aws_secret and the quote, the key name has 12; TruffleHog pairs it with the ID")
    mods.append(planted_module(ids, f'const c={{region:"eu-west-1",bucket:"labshop-uploads",'
                                    f'aws_access_key_id:{jsstr(akia)},aws_secret_access_key:{jsstr(akia_secret)}}};'
                                    f'c.sign=e=>fetch("/api/v1/uploads/sign",{{method:"POST",body:JSON.stringify('
                                    f'{{name:e,region:c.region}})}})'))

    asia, asia_secret, sts = (aws_access_key_id(k("aws-asia-id"), "asia"), aws_secret(k("aws-asia-secret")),
                              sts_session_token(k("aws-asia-session-token")))
    plant("aws-asia-id", main, asia, today=None, after=X("AWS Session Key", "high"))
    plant("aws-asia-secret", main, asia_secret, today=None, after=None)
    plant("aws-asia-session-token", main, sts, today=None, after=None)
    mods.append(planted_module(ids, f'const c={{credentials:{{accessKeyId:{jsstr(asia)},secretAccessKey:'
                                    f'{jsstr(asia_secret)},sessionToken:{jsstr(sts)}}},'
                                    f'expiration:"2026-11-01T12:00:00Z"}}'))

    sk = plant("stripe-sk-live-main", main, stripe_secret(k("stripe-sk-live-main")),
               today=X("Stripe Secret Key", "critical"), after=X("Stripe Secret Key", "critical"))
    mods.append(planted_module(ids, f'const c={{stripe:{{secretKey:{jsstr(sk)}}},currency:"eur"}}'))

    ghp = plant("github-ghp", main, github_classic(k("github-ghp")),
                today=X("GitHub Token Classic", "high"), after=X("GitHub Token Classic", "high"))
    mods.append(planted_module(ids, f'const c={{github:{{token:{jsstr(ghp)},repo:"labshop/storefront"}}}}'))

    xoxb = plant("slack-xoxb", main, slack_bot(k("slack-xoxb")),
                 today=X("Slack Bot Token", "high"), after=X("Slack Bot Token", "high"))
    mods.append(planted_module(ids, f'const c={{slack:{{botToken:{jsstr(xoxb)},channel:"#orders"}}}}'))

    oai = openai_key(k("openai-key"))
    plant("openai-key", main, oai, today=X("OpenAI API Key", "critical"),
          after=X("OpenAI API Key", "critical", alt=["Generic API Key"]))
    plant("openai-key-generic", main, oai, kind="noise", match=f"apiKey:{jsstr(oai)}",
          today=X("Generic API Key", "medium"), after=None, note="Phase 0 item 0.1: generic loses to specific")
    mods.append(planted_module(ids, f'const c={{openai:{{apiKey:{jsstr(oai)},model:"gpt-4o-mini"}}}}'))

    ant = plant("anthropic-key", main, anthropic_key(k("anthropic-key")),
                today=X("Anthropic API Key", "critical"), after=X("Anthropic API Key", "critical"))
    mods.append(planted_module(ids, f'const c={{anthropic:{{key:{jsstr(ant)},model:"claude-3-haiku"}}}}'))

    fb = google_api_key(k("firebase-apikey"), need_dash=True)
    plant("firebase-apikey-gcp", main, fb, today=X("GCP API Key", "info", True),
          after=X("GCP API Key", "info", True, alt=["Generic API Key"]))
    plant("firebase-apikey-generic", main, fb, kind="noise", match=f"apiKey:{jsstr(fb)}",
          today=X("Generic API Key", "medium"), after=None, note="Phase 0 item 0.1")
    proj = "labshop-" + body(k("firebase-project"), LOWER_ALNUM, 5)
    sender = digits(k("firebase-sender"), 12)
    mods.append(planted_module(ids, f'const c={{firebaseConfig:{{apiKey:{jsstr(fb)},authDomain:"{proj}.firebaseapp.com",'
                                    f'projectId:"{proj}",storageBucket:"{proj}.appspot.com",messagingSenderId:'
                                    f'"{sender}",appId:"1:{sender}:web:{body(k("firebase-app"), HEX, 12)}"}}}}'))

    gem = google_api_key(k("gemini-key"))
    plant("gemini-key", main, gem, match=f"gemini_api_key:{jsstr(gem)}",
          today=X("Google Gemini API Key", "critical"), after=X("Google Gemini API Key", "critical"))
    plant("gemini-key-gcp", main, gem, today=X("GCP API Key", "info", True), after=X("GCP API Key", "info", True),
          note="a Gemini key must not lose to the public GCP rule: both stay")
    plant("gemini-key-generic", main, gem, kind="noise", match=f"api_key:{jsstr(gem)}",
          today=X("Generic API Key", "medium"), after=None, note="Phase 0 item 0.1")
    mods.append(planted_module(ids, f'const c={{assistant:{{gemini_api_key:{jsstr(gem)},temperature:.2}}}}'))

    ref = body(k("supabase-ref"), string.ascii_lowercase, 20)
    anon = hs256_jwt(k("supabase-anon"), {"iss": "supabase", "ref": ref, "role": "anon",
                                          "iat": 1730419200, "exp": 2045995200})
    svc = hs256_jwt(k("supabase-service"), {"iss": "supabase", "ref": ref, "role": "service_role",
                                            "iat": 1730419200, "exp": 2045995200})
    plant("supabase-anon-jwt", main, anon, today=X("Supabase anon key", "info", True),
          after=X("Supabase anon key", "info", True))
    plant("supabase-service-jwt", main, svc, today=X("Supabase service_role key", "critical"),
          after=X("Supabase service_role key", "critical"))
    mods.append(planted_module(ids, f'const c={{supabase:{{url:"https://{ref}.supabase.co",supabaseAnonKey:'
                                    f'{jsstr(anon)},supabaseServiceKey:{jsstr(svc)}}}}}'))

    mapbox, mapbox_head = mapbox_token(k("mapbox-token"))
    plant("mapbox-token", main, mapbox, match=mapbox_head, today=X("Mapbox Token", "info", True),
          after=X("Mapbox Token", "info", True), note="the rule stops at the token's second dot")
    mods.append(planted_module(ids, f'const c={{mapbox:{{accessToken:{jsstr(mapbox)},'
                                    f'style:"mapbox://styles/labshop/streets"}}}}'))

    esc = github_classic(k("github-ghp-uescaped"))
    plant("github-ghp-uescaped", main, esc, today=None, after=None,
          note="written as \\uXXXX escapes: TruffleHog decodes them, the regex does not")
    escaped = "".join(f"\\u{ord(ch):04x}" for ch in esc)
    mods.append(planted_module(ids, f'const c={{deployHook:{{repo:"labshop/storefront",token:"{escaped}"}}}}'))

    near = github_classic(k("github-ghp-near-location"))
    plant("github-ghp-near-location", main, near, today=None, after=None,
          note="dropped by js_recon's binary-context filter: its font-table name 'loca' matches "
               "'location' within 300 characters; TruffleHog-only")
    mods.append(planted_module(ids, f'const c={{session:{{token:{jsstr(near)}}},onExpire:()=>'
                                    f'window.location.assign("/login")}}'))

    # --- noise: what a clean bundle legitimately holds ---
    ycs = []
    for i in (1, 2, 3):
        yc = P["yc"] + body(k(f"noise-yc-{i}"), B64URL, 38)
        ycs.append(yc)
        plant(f"noise-yc-{i}", main, yc, kind="noise", today=X("Yandex AWS Access Token", "high"), after=None,
              note="Phase 0 item 0.4: no 'yandex' within 120 characters")
    mods.append(planted_module(ids, 'const c={' + ",".join(f'{jsstr(y)}:()=>n.e({n}).then(n.bind(n,{ids()}))'
                                                          for y, n in zip(ycs, (412, 907, 412))) + '}'))
    for i in (1, 2):
        ident = "configure_" + body(k(f"noise-configure-{i}"), ALNUM, 20 + i)
        plant(f"noise-configure-{i}", main, ident, kind="noise", match=ident[len("configu"):],
              today=X("Resend API Key", "high"), after=None, note="Phase 0 item 0.5: re_ needs a left boundary")
        mods.append(planted_module(ids, f'function {ident}(e){{return Object.assign({{}},e,{{ready:!0}})}}'
                                        f'const c={ident}'))
    uid = uuid4(k("noise-uuid-apikey"))
    plant("noise-uuid-apikey", main, uid, kind="noise", match=f"apiKey:{jsstr(uid)}",
          today=X("Generic API Key", "medium"), after=X("Generic API Key", "low"),
          note="Phase 0 item 0.6: a bare UUIDv4 value is low")
    plant("noise-uuid-apikey-uuid", main, uid, kind="noise", today=X("UUID v4", "info"), after=X("UUID v4", "info"))
    mods.append(planted_module(ids, f'const c={{analytics:{{apiKey:{jsstr(uid)},endpoint:"/api/v1/events"}}}}'))
    plant("noise-pem-template", main, P["pem_begin"], kind="noise", today=X("Generic Private Key", "critical"),
          after=None, note="Phase 0 item 0.2: a jsrsasign-style template, no key data")
    mods.append(planted_module(ids, f'function c(n){{return"{P["pem_begin"]}\\n"+n+"\\n{P["pem_end"]}"}}'))
    cert = pem_lines(k("noise-certificate"), "MIIDdzCCAl+gAwIBAgIEb", 1260)
    plant("noise-certificate", main, P["cert_begin"], kind="noise", today=X("PKCS12 Certificate", "high"),
          after=X("PKCS12 Certificate", "info"), note="Phase 0 item 0.3: a public certificate is info")
    mods.append(planted_module(ids, f'const c={{trustedRoot:"{P["cert_begin"]}\\n' + "\\n".join(cert)
                               + f'\\n{P["cert_end"]}"}}'))
    css = {f: f"{comp}_{f}__{body(k('noise-css-' + f), ALNUM, 5)}"
           for f, comp in (("password", "LoginForm"), ("secret", "Vault"))}
    for f, cls in css.items():
        plant(f"noise-css-{f}", main, cls, kind="noise", match=f"{f}:{jsstr(cls)}", today=None, after=None,
              note="a CSS-module class name bound to a secret-looking key")
    mods.append(planted_module(ids, 'const c={' + ",".join(f"{f}:{jsstr(c)}" for f, c in css.items())
                               + f',submit:"LoginForm_submit__{body(k("noise-css-submit"), ALNUM, 5)}"}}'))

    order = rng("order:main")
    order.shuffle(mods)
    filler = rng("filler:main")
    head = (f'/*! For license information please see main.{fname_hash("main")}.js.LICENSE.txt */'
            '(()=>{var e={')
    tail = ('};var t={};function n(r){var o=t[r];if(void 0!==o)return o.exports;var a=t[r]={exports:{}};'
            'return e[r](a,a.exports,n),a.exports}n.m=e,n.d=(e,t)=>{for(var r in t)n.o(t,r)&&!n.o(e,r)&&'
            'Object.defineProperty(e,r,{enumerable:!0,get:t[r]})},n.o=(e,t)=>Object.prototype.hasOwnProperty'
            '.call(e,t),n.n=e=>{var t=e&&e.__esModule?()=>e.default:()=>e;return n.d(t,{a:t}),t},'
            f'n.u=e=>"assets/js/"+({{907:"checkout"}}[e]||e)+"."+{{412:"{fname_hash("412")}",'
            f'907:"{fname_hash("checkout")}"}}[e]+".js",n.p="/",n.e=e=>import(n.p+n.u(e));'
            'document.addEventListener("DOMContentLoaded",()=>{const e=document.getElementById("root");'
            'e&&(e.dataset.ready="1")})})();')
    main_js = assemble(filler, ids, mods, MAIN_BYTES, head, tail, windowed=True)
    main_js += f"\n//# sourceMappingURL=main.{fname_hash('main')}.js.map\n"

    # The source map exposes an original file the bundle tree-shook away.
    sk_map = plant("stripe-sk-live-sourcemap", smap + "#src/config/payments.ts",
                   stripe_secret(k("stripe-sk-live-sourcemap")),
                   today=X("Stripe Secret Key", "critical"), after=X("Stripe Secret Key", "critical"),
                   note="only in the source map's sourcesContent (a pseudo-file)")
    payments_ts = (
        'import Stripe from "stripe";\n\n'
        '// Refunds are signed here. This module was meant to stay server-side\n'
        '// (webpack.config.js "externals"), and the map still carries it.\n'
        f'export const stripe = new Stripe({jsstr(sk_map)}, {{\n'
        '  apiVersion: "2024-06-20",\n'
        '});\n\n'
        'export async function refund(chargeId: string, amount: number) {\n'
        '  return stripe.refunds.create({ charge: chargeId, amount });\n'
        '}\n')
    index_tsx = (
        'import { createRoot } from "react-dom/client";\n'
        'import { App } from "./App";\n\n'
        'createRoot(document.getElementById("root")!).render(<App />);\n')
    source_map = {
        "version": 3,
        "file": f"main.{fname_hash('main')}.js",
        "sources": ["webpack:///./src/index.tsx", "webpack:///./src/config/payments.ts",
                    "webpack:///./node_modules/react/index.js", "webpack:///webpack/bootstrap"],
        "sourcesContent": [index_tsx, payments_ts, "module.exports = require('./cjs/react.production.js');\n",
                           "// webpack bootstrap\n"],
        "names": [],
        "mappings": "AAAA,SAASA,WAAW;AACpB,MAAMC,OAAO;" * 40,
    }

    ids412, idsco = Ids(rng("ids:412")), Ids(rng("ids:checkout"))
    sg = plant("sendgrid-key", admin, sendgrid_key(k("sendgrid-key")),
               today=X("SendGrid API Key", "high"), after=X("SendGrid API Key", "high"))
    sb = plant("supabase-sb-secret", admin, P["sb_secret"] + body(k("supabase-sb-secret"), ALNUM, 31),
               today=X("Supabase Secret Key", "critical"), after=X("Supabase Secret Key", "critical"))
    key_lines = pem_lines(k("pem-private-key-full"), "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ", 1624)
    pem_value = P["pem_begin"] + "\n" + "\n".join(key_lines) + "\n" + P["pem_end"] + "\n"
    plant("pem-private-key-full", admin, pem_value, match=P["pem_begin"],
          today=X("Generic Private Key", "critical"), after=X("Generic Private Key", "critical"),
          note="Phase 0 item 0.2: key data present (\\n escapes in a JS string)")
    admin_mods = [
        planted_module(ids412, f'const c={{sendgrid:{{key:{jsstr(sg)},from:"orders"}}}}'),
        planted_module(ids412, f'const c={{SUPABASE_SECRET_KEY:{jsstr(sb)}}}'),
        planted_module(ids412, f'const c={{signing:{{alg:"RS256",privateKey:"{P["pem_begin"]}\\n'
                               + "\\n".join(key_lines) + f'\\n{P["pem_end"]}\\n"}}}}'),
        planted_module(ids412, 'const c=()=>fetch("/api/admin/users").then(e=>e.json())'),
        planted_module(ids412, 'const c=e=>fetch("/api/admin/orders/export?format="+e)'),
    ]
    admin_js = assemble(rng("filler:412"), ids412, admin_mods, 60_000,
                        '"use strict";(self.webpackChunklabshop=self.webpackChunklabshop||[]).push([[412],{',
                        "}]);", windowed=False) + "\n"

    pk = plant("stripe-pk-live", checkout, P["pk_live"] + "51" + body(k("stripe-pk-live"), ALNUM, 97),
               today=X("Stripe Publishable Key", "info", True), after=X("Stripe Publishable Key", "info", True))
    wh = P["whsec"] + body(k("stripe-whsec"), ALNUM, 32)
    plant("stripe-whsec", checkout, wh, today=None, after=X("Stripe Webhook Secret", "high", alt=["Generic Secret"]),
          note="Phase 0 item 0.7: new rule")
    plant("stripe-whsec-generic", checkout, wh, kind="noise", match=f"Secret:{jsstr(wh)}",
          today=X("Generic Secret", "medium"), after=None, note="Phase 0 item 0.1")
    hidden = stripe_secret(k("stripe-sk-live-atob"), 30)
    plant("stripe-sk-live-atob", checkout, hidden, today=None, after=None,
          note="inside atob(\"<base64>\"): TruffleHog decodes it, the regex does not")
    co_mods = [
        planted_module(idsco, f'const c={{publishableKey:{jsstr(pk)},theme:"auto"}}'),
        planted_module(idsco, f'const c={{webhookSecret:{jsstr(wh)},tolerance:300}}'),
        planted_module(idsco, f'const c={{fallback:atob({jsstr(base64.b64encode(hidden.encode()).decode())})}}'),
        planted_module(idsco, 'const c=e=>fetch("/api/v1/checkout/session",{method:"POST",body:JSON.stringify(e)})'),
    ]
    checkout_js = assemble(rng("filler:checkout"), idsco, co_mods, 60_000,
                           '"use strict";(self.webpackChunklabshop=self.webpackChunklabshop||[]).push([[907],{',
                           "}]);", windowed=False) + "\n"

    index = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
             '<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Lab Shop</title>\n'
             f'<script defer src="{main}"></script>\n<script defer src="{admin}"></script>\n'
             f'<script defer src="{checkout}"></script>\n</head>\n<body>\n<div id="root"></div>\n'
             '<noscript>You need to enable JavaScript to run this app.</noscript>\n</body>\n</html>\n')
    return {
        "index.html": index,
        main.lstrip("/"): main_js,
        smap.lstrip("/"): json.dumps(source_map, separators=(",", ":")),
        admin.lstrip("/"): admin_js,
        checkout.lstrip("/"): checkout_js,
    }


# ---------------------------------------------------------------------------
# .11 vendor-only: real open-source library files, copied at generation time
# ---------------------------------------------------------------------------

VENDOR_FILES = [
    ("lodash", "lodash/lodash.js", "lodash"),
    ("react-dom", "react-dom/cjs/react-dom-client.production.js", "react-dom-client.production"),
    ("acorn", "acorn/dist/acorn.js", "acorn"),
    ("async", "async/dist/async.js", "async"),
    ("d3-scale", "d3-scale/dist/d3-scale.js", "d3-scale"),
    ("jose", "jose/dist/webapi/lib/asn1.js", "jose-asn1"),
    ("jose", "jose/dist/webapi/key/import.js", "jose-import"),
]


def build_vendor_only():
    files, tags = {}, []
    for pkg, rel, base in VENDOR_FILES:
        src = os.path.join(NODE_MODULES, rel)
        try:
            with open(src, "rb") as fh:
                data = fh.read()
            with open(os.path.join(NODE_MODULES, pkg, "package.json"), encoding="utf-8") as fh:
                version = json.load(fh).get("version", "x")
        except OSError:
            print(f"[!] vendor-only: {rel} not found under webapp/node_modules, left out", flush=True)
            continue
        # No .min.js, /vendor/ or /lib/ in the served path: the default
        # KATANA_EXCLUDE_PATTERNS would hide those from the crawl.
        name = f"assets/js/{base}-{version}.js"
        files[name] = data
        tags.append(f'<script src="/{name}"></script>')
    files["index.html"] = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
                           '<title>Lab vendor shelf</title>\n' + "\n".join(tags) + '\n</head>\n<body>\n'
                           '<p>Library code only.</p>\n</body>\n</html>\n')
    return files


# ---------------------------------------------------------------------------
# .12 ssrf-bait: connection strings whose host is the canary
# ---------------------------------------------------------------------------

def _credentials_in_url(url):
    # The plan's rule 0.7 "Credentials in URL", to know what it will match.
    m = re.search(r"\b(?:https?|ftp|amqps?|smtp)://[^\s:/@'\"]{1,64}:[^\s@'\"]{1,128}@[^\s/'\"]+", url)
    return m.group(0) if m else url


def build_ssrf_bait(lab, canary_ip):
    c = canary_ip
    path = f"/assets/js/services.{fname_hash('services')}.js"
    k = lambda label: rng(f"key:{label}")  # noqa: E731
    pw = lambda label: body(k(label), ALNUM, 18)  # noqa: E731

    def plant(label, value, **kw):
        return lab.plant(label, "ssrf-bait", path, value, runtime=True, **kw)

    pg = plant("ssrf-postgres", f"postgres://shop_app:{pw('ssrf-postgres')}@{c}:5432/shop?sslmode=disable",
               today=X("PostgreSQL URI", "high"), after=X("PostgreSQL URI", "high"))
    my = plant("ssrf-mysql", f"mysql://report:{pw('ssrf-mysql')}@{c}:3306/reports",
               today=X("MySQL URI", "high"), after=X("MySQL URI", "high"))
    mg = plant("ssrf-mongodb", f"mongodb://sess:{pw('ssrf-mongodb')}@{c}:27017/sessions?authSource=admin",
               today=X("MongoDB URI", "high"), after=X("MongoDB URI", "high"))
    rd = plant("ssrf-redis", f"redis://default:{pw('ssrf-redis')}@{c}:6379/0",
               today=X("Redis URL", "high"), after=X("Redis URL", "high"))
    jd = plant("ssrf-jdbc", f"jdbc:sqlserver://{c}:1433;databaseName=erp;user=erp_ro;password={pw('ssrf-jdbc')}",
               today=None, after=X("JDBC with password", "high"), note="Phase 0 item 0.7: new rule")
    jm = f"jdbc:mysql://{c}:3306/reports?user=report&password={pw('ssrf-jdbc-mysql')}"
    plant("ssrf-jdbc-mysql", jm, today=None, after=X("JDBC with password", "high"),
          note="Phase 0 item 0.7; the MySQL URI hit inside it stays (specific never beats specific)")
    plant("ssrf-jdbc-mysql-uri", jm, match=jm[len("jdbc:"):], today=X("MySQL URI", "high"),
          after=X("MySQL URI", "high"))
    ftp = f"ftp://deploy:{pw('ssrf-ftp')}@{c}:21/releases/"
    plant("ssrf-ftp", ftp, match=_credentials_in_url(ftp), today=None, after=X("Credentials in URL", "high"),
          note="Phase 0 item 0.7: new rule")
    ldap_uri = f"ldap://cn=svc-ro,dc=corp,dc=lab:{pw('ssrf-ldap-uri')}@{c}:389/dc=corp,dc=lab"
    plant("ssrf-ldap-uri", ldap_uri, today=None, after=None, note="ldap is not a Credentials-in-URL scheme")
    bind_pw = pw("ssrf-ldap-bindpw")
    plant("ssrf-ldap-bindpw", bind_pw, match=f"password: {jsstr(bind_pw)}",
          today=X("Generic Secret", "medium"), after=X("Generic Secret", "medium"))
    https = f"https://reporter:{pw('ssrf-https-creds')}@{c}/api/v2/"
    plant("ssrf-https-creds", https, match=_credentials_in_url(https), today=None,
          after=X("Credentials in URL", "high"), note="Phase 0 item 0.7: new rule")
    http = f"http://metrics:{pw('ssrf-http-creds')}@{c}/metrics"
    plant("ssrf-http-creds", http, match=_credentials_in_url(http), today=None,
          after=X("Credentials in URL", "high"), note="Phase 0 item 0.7: new rule")
    jira = plant("ssrf-jira-token", P["atlassian"] + body(k("ssrf-jira-token"), B64URL, 171) + "="
                 + body(k("ssrf-jira-token-crc"), HEX.upper(), 8),
                 today=X("Atlassian API Token", "high"), after=X("Atlassian API Token", "high"))
    okta = P["okta"] + body(k("ssrf-okta-token"), B64URL, 40)
    plant("ssrf-okta-token", okta, match=f'okta: {{ orgUrl: "https://{c}", apiToken: {jsstr(okta)}',
          today=X("Okta API Token", "high"), after=X("Okta API Token", "high"))
    art = plant("ssrf-artifactory-token", P["jfrog_ref"] + body(k("ssrf-artifactory-token"), ALNUM, 56),
                today=X("JFrog Reference Token", "high"), after=X("JFrog Reference Token", "high"))
    jwt = plant("ssrf-jwt-iss", rs256_jwt(k("ssrf-jwt-iss"), {
        "iss": f"https://{c}/", "sub": "svc-reports", "aud": "labshop-reports", "scope": "reports:read",
        "iat": 1730419200, "exp": 2045995200}), today=X("JWT Token", "medium"), after=X("JWT Token", "medium"),
        note="RS256, iss on the canary: TruffleHog's JWT verifier fetches keys from iss")
    js = (
        "// Back-office service map, shipped to the browser by mistake (config/services.js).\n"
        "// Every host below is the canary on redamon-trufflehog-net: whatever dials it is logged.\n"
        "window.__SERVICES__ = {\n"
        f"  primaryDb: {jsstr(pg)},\n"
        f"  reportingDb: {jsstr(my)},\n"
        f"  sessions: {jsstr(mg)},\n"
        f"  cache: {jsstr(rd)},\n"
        f"  erpJdbc: {jsstr(jd)},\n"
        f"  reportingJdbc: {jsstr(jm)},\n"
        f"  releases: {jsstr(ftp)},\n"
        f"  directoryUri: {jsstr(ldap_uri)},\n"
        f'  directory: {{ uri: "ldap://{c}:389", user: "cn=svc-shop,ou=services,dc=corp,dc=lab", '
        f"password: {jsstr(bind_pw)} }},\n"
        f"  reportsApi: {jsstr(https)},\n"
        f"  metrics: {jsstr(http)},\n"
        f'  jira: {{ baseUrl: "https://{c}/", email: "svc.jira@shop-lab.test", apiToken: {jsstr(jira)} }},\n'
        f'  okta: {{ orgUrl: "https://{c}", apiToken: {jsstr(okta)} }},\n'
        f'  artifactory: {{ url: "http://{c}:8080/artifactory", token: {jsstr(art)} }},\n'
        f"  reportsSession: {jsstr(jwt)},\n"
        "};\n")
    index = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Lab back office</title>\n'
             f'<script src="{path}"></script>\n</head>\n<body>\n<p>Back office.</p>\n</body>\n</html>\n')
    return {"index.html": index, path.lstrip("/"): js}


# ---------------------------------------------------------------------------
# .14 clean-control and the upload file
# ---------------------------------------------------------------------------

def build_clean_control():
    path = f"/assets/js/app.{fname_hash('clean')}.js"
    js = ('(function () {\n  "use strict";\n\n'
          '  var list = document.getElementById("todo");\n'
          '  var form = document.getElementById("add");\n\n'
          '  function render(items) {\n'
          '    list.textContent = "";\n'
          '    items.forEach(function (item) {\n'
          '      var li = document.createElement("li");\n'
          '      li.textContent = item.title;\n'
          '      li.className = item.done ? "done" : "";\n'
          '      list.appendChild(li);\n'
          '    });\n'
          '  }\n\n'
          '  function load() {\n'
          '    return fetch("/api/todos").then(function (r) { return r.json(); }).then(render);\n'
          '  }\n\n'
          '  form.addEventListener("submit", function (ev) {\n'
          '    ev.preventDefault();\n'
          '    var title = form.elements.title.value.trim();\n'
          '    if (!title) { return; }\n'
          '    fetch("/api/todos", { method: "POST", headers: { "Content-Type": "application/json" },\n'
          '      body: JSON.stringify({ title: title }) }).then(load);\n'
          '  });\n\n'
          '  load();\n'
          '})();\n')
    index = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Lab todo</title>\n'
             f'<script defer src="{path}"></script>\n</head>\n<body>\n<form id="add"><input name="title">'
             '<button>Add</button></form>\n<ul id="todo"></ul>\n</body>\n</html>\n')
    return {"index.html": index, path.lstrip("/"): js}


def build_uploads(lab):
    k = lambda label: rng(f"key:{label}")  # noqa: E731
    name = "upload_keys.js"

    def plant(label, value, **kw):
        return lab.plant(label, UPLOAD_HOST, name, value, **kw)

    gl = plant("upload-gitlab-pat", P["glpat"] + body(k("upload-gitlab-pat"), ALNUM, 20),
               today=X("GitLab PAT", "high"), after=X("GitLab PAT", "high"))
    rk = plant("upload-stripe-rk", P["rk_live"] + "51" + body(k("upload-stripe-rk"), ALNUM, 40),
               today=X("Stripe Restricted Key", "critical"), after=X("Stripe Restricted Key", "critical"))
    sh = plant("upload-shodan", body(k("upload-shodan"), ALNUM, 32), today=None, after=None,
               note="no js_recon rule: TruffleHog-only (keyword shodan)")
    vt = plant("upload-virustotal", body(k("upload-virustotal"), HEX, 64), today=None, after=None,
               note="no js_recon rule: TruffleHog-only (keyword virustotal)")
    js = ("// Build-time configuration the CI pipeline left in the release bundle.\n"
          "export const ci = {\n"
          f"  gitlabToken: {jsstr(gl)},\n"
          f"  stripeRestricted: {jsstr(rk)},\n"
          "};\n\n"
          "// OSINT panel (invented keys).\n"
          "export const osint = {\n"
          f"  shodanKey: {jsstr(sh)},\n"
          f"  virustotalKey: {jsstr(vt)},\n"
          "};\n")
    return {name: js}


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def write_tree(root, files):
    """Replace root's CONTENTS with `files`. The directory itself is kept: a
    running lab container bind-mounts it, and a new inode would leave it
    serving an empty mount."""
    os.makedirs(root, exist_ok=True)
    for entry in os.listdir(root):
        path = os.path.join(root, entry)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)
    total = 0
    for rel, content in sorted(files.items()):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = content.encode("utf-8") if isinstance(content, str) else content
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        total += len(data)
        print(f"    {os.path.relpath(path, HERE)}  {len(data):,} bytes", flush=True)
    for dirpath, dirnames, _ in os.walk(root):
        for d in dirnames:
            os.chmod(os.path.join(dirpath, d), 0o755)
    os.chmod(root, 0o755)
    return total


def running_canary_ip():
    try:
        out = subprocess.run(["docker", "inspect", "-f",
                              "{{(index .NetworkSettings.Networks \"" + TH_NET + "\").IPAddress}}", CANARY],
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    ip = out.stdout.strip()
    return ip if out.returncode == 0 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip) else None


COMPARED = ("host", "file", "kind", "value_sha12", "match_sha12", "regex_today", "regex")
HOSTS_DOC = {
    f"{NET}.10": {"role": "app-modern", "rule": "every row below"},
    f"{NET}.11": {"role": "vendor-only", "rule": "no js_recon Secret of severity medium or higher after Phase 0"},
    f"{NET}.12": {"role": "ssrf-bait", "rule": "hashes depend on the canary IP: see generated/expected_runtime.json"},
    f"{NET}.14": {"role": "clean-control", "rule": "no js_recon Secret of severity medium or higher; ideally none"},
    UPLOAD_HOST: {"role": "upload", "rule": "upload://upload_keys.js, only in the partial-recon scenario (E4)"},
}


def committed_rows(rows):
    out = []
    for row in rows:
        row = {k: v for k, v in row.items() if k != "runtime"}
        if row["host"] == HOST_IPS["ssrf-bait"]:
            row["value_sha12"] = row["match_sha12"] = "runtime"
        out.append(row)
    return out


def emit_expected(rows):
    old = {}
    if os.path.exists(EXPECTED):
        with open(EXPECTED, encoding="utf-8") as fh:
            old = {r["label"]: r for r in json.load(fh).get("rows", [])}
    kept = ("trufflehog", "regex_p2")
    out = []
    for row in committed_rows(rows):
        prev = old.get(row["label"], {})
        for key in kept:
            if key in prev:
                row[key] = prev[key]
        out.append(row)
    doc = {
        "lab": "js_secret_lab",
        "seed": SEED,
        "how": "python3 -I gen_lab.py --emit-expected (keeps trufflehog and regex_p2). Values are "
               "sha256(value)[:12]; match_sha12 is the hash of the text the js_recon rule matches. "
               "regex_today = the code before the plan's Phase 0, regex = after Phase 0, "
               "regex_p2 (optional) = after Phase 2, trufflehog = TBD until plan step 1.3.",
        "hosts": HOSTS_DOC,
        "rows": out,
    }
    with open(EXPECTED, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    print(f"[+] expected.json: {len(out)} rows", flush=True)


def check_expected(rows):
    if not os.path.exists(EXPECTED):
        print("[!] expected.json is missing: run --emit-expected", flush=True)
        return False
    with open(EXPECTED, encoding="utf-8") as fh:
        have = {r["label"]: r for r in json.load(fh).get("rows", [])}
    want = {r["label"]: r for r in committed_rows(rows)}
    bad = sorted(set(have) ^ set(want))
    for label in sorted(set(have) & set(want)):
        diff = [k for k in COMPARED if have[label].get(k) != want[label].get(k)]
        if diff:
            bad.append(f"{label} ({', '.join(diff)})")
    if bad:
        print(f"[!] expected.json disagrees with the generator: {'; '.join(bad)}", flush=True)
        return False
    print(f"[+] expected.json agrees with the generator ({len(want)} rows)", flush=True)
    return True


def generate(canary_ip):
    lab = Lab()
    sites = {"app-modern": build_app_modern(lab), "vendor-only": build_vendor_only(),
             "clean-control": build_clean_control()}
    if canary_ip:
        sites["ssrf-bait"] = build_ssrf_bait(lab, canary_ip)
    uploads = build_uploads(lab)
    print(f"[*] writing {os.path.relpath(GEN, REPO)}/", flush=True)
    for host, files in sites.items():
        print(f"[*] {host} ({HOST_IPS[host]})", flush=True)
        write_tree(os.path.join(GEN, host), files)
    if not canary_ip:
        print("[-] ssrf-bait (.12) not written: no canary IP (start the canary, or pass --canary-ip)", flush=True)
    print("[*] uploads (partial recon)", flush=True)
    write_tree(os.path.join(GEN, "uploads"), uploads)
    runtime = {"seed": SEED, "canary_ip": canary_ip, "rows": [
        {k: v for k, v in r.items() if k != "runtime"} for r in lab.rows]}
    with open(RUNTIME, "w", encoding="utf-8") as fh:
        json.dump(runtime, fh, indent=1)
        fh.write("\n")
    print(f"[+] {len(lab.rows)} planted rows; runtime hashes in {os.path.relpath(RUNTIME, HERE)}", flush=True)
    return lab.rows


def rows_for_expected(canary_ip):
    """Every row, with .12 built for `canary_ip` (any address: committed .12
    hashes are 'runtime')."""
    lab = Lab()
    build_app_modern(lab)
    build_ssrf_bait(lab, canary_ip or "192.0.2.1")
    build_uploads(lab)
    return lab.rows


# ---------------------------------------------------------------------------
# --real-keys (E3 only)
# ---------------------------------------------------------------------------

PROVIDER_WORDS = (("shodan", "shodan"), ("censys", "censys"), ("criminal", "criminalip"), ("fofa", "fofa"),
                  ("netlas", "netlas"), ("alienvault", "otx"), ("otx", "otx"), ("urlscan", "urlscan"),
                  ("virustotal", "virustotal"), ("virus total", "virustotal"), ("zoomeye", "zoomeye"),
                  ("zoom eye", "zoomeye"))


def load_key_export(path):
    """[(name, value, provider hint)] from an API-keys export, values never shown."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    data = None
    for candidate in (text, *(m.group(1) for m in re.finditer(r"```(?:json)?\s*\n(.*?)\n```", text, re.S)),
                      text[text.find("{"):text.rfind("}") + 1]):
        try:
            data = json.loads(candidate)
            break
        except ValueError:
            continue
    if not isinstance(data, dict):
        raise SystemExit("[!] the export is not RedAmon's API-keys JSON (keys / rotation)")
    pairs = []
    for name, value in (data.get("keys") or {}).items():
        if isinstance(value, str) and value.strip():
            pairs.append((name, value.strip(), None))
    for tool, cfg in (data.get("rotation") or {}).items():
        for i, value in enumerate((cfg or {}).get("extraKeys") or [] if isinstance(cfg, dict) else []):
            if isinstance(value, str) and value.strip():
                pairs.append((f"rotation.{tool}.extraKeys[{i}]", value.strip(), tool))
    return pairs


def provider_word(name, hint):
    low = (hint or name).lower()
    for needle, word in PROVIDER_WORDS:
        if needle in low or needle in name.lower():
            return word
    return re.sub(r"(api|key|token|access|secret|[^a-z0-9])", "", low) or "service"


def probe_offline(site_dir):
    """TruffleHog over site_dir, no network, no verification: {sha12(Raw): DetectorName}.
    Raw stays in this process; nothing of it is printed."""
    cmd = ["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--read-only",
           "--tmpfs", "/tmp:size=256m", "-v", f"{site_dir}:/scan:ro", "--entrypoint", "trufflehog",
           "redamon-trufflehog:latest", "filesystem", "/scan", "--json", "--no-update", "--no-verification",
           "--results=verified,unknown,unverified,filtered_unverified"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"[!] offline probe did not run: {type(exc).__name__}", flush=True)
        return None
    if out.returncode not in (0, 183):
        print(f"[!] offline probe exited {out.returncode}; no detector names recorded", flush=True)
        return None
    found = {}
    for line in out.stdout.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        raw = rec.get("Raw")
        if isinstance(raw, str) and raw:
            found.setdefault(sha12(raw), set()).add(str(rec.get("DetectorName")))
    return found


def real_keys(export, out_dir, probe):
    pairs = load_key_export(export)
    if not pairs:
        raise SystemExit("[!] no non-empty key in the export")
    host = "app-realkeys"
    site = os.path.join(out_dir, "site")
    lab = Lab()
    files = build_app_modern(lab, host)
    rows, tags = [], []
    for i, (name, value, hint) in enumerate(pairs):
        word = provider_word(name, hint)
        rel = f"assets/js/osint/{word}-{i}.{hashlib.sha256(f'{SEED}:{i}'.encode()).hexdigest()[:8]}.js"
        # One key per file: TruffleHog's keyword prefilter works per chunk, so a
        # file naming one provider sends its key to that provider's verifier only.
        files[rel] = (f"/* {re.sub(r'[^A-Za-z0-9 ._-]', '', name)} | {word} lookups for the OSINT panel */\n"
                      f'(function () {{\n  "use strict";\n  var cfg = {{ provider: "{word}", {word}Key: '
                      f"{jsstr(value)} }};\n  window.__osint = window.__osint || {{}};\n"
                      f"  window.__osint.{word}{i} = cfg;\n}})();\n")
        tags.append(f'<script defer src="/{rel}"></script>')
        rows.append({"name": name, "provider": word, "value_sha12": sha12(value), "host": HOST_IPS[host],
                     "file": "/" + rel, "trufflehog_offline": None,
                     "expect": "validated, checked_by trufflehog (a provider that is down: unknown)"})
    files["index.html"] = files["index.html"].replace("</head>", "\n".join(tags) + "\n</head>")
    print(f"[*] writing {os.path.relpath(site, REPO)}/ (.15: {len(pairs)} real keys + a copy of .10)", flush=True)
    write_tree(site, files)
    compose = os.path.join(out_dir, "docker-compose.realkeys.yml")
    with open(compose, "w", encoding="utf-8") as fh:
        fh.write(
            "# E3 only, written by gen_lab.py --real-keys: lab host .15 serving the real-key bundle.\n"
            "#   up:   docker compose -f docker-compose.realkeys.yml up -d\n"
            "#   down: docker compose -f docker-compose.realkeys.yml down   (then delete this folder)\n"
            "name: redamon-js-secret-lab-realkeys\n"
            "services:\n"
            "  app-realkeys:\n"
            "    image: python:3.12-slim\n"
            "    container_name: jslab-app-realkeys\n"
            "    restart: \"no\"\n"
            "    mem_limit: 128m\n"
            "    pids_limit: 128\n"
            "    cpus: 0.5\n"
            "    read_only: true\n"
            "    environment: { PYTHONDONTWRITEBYTECODE: \"1\" }\n"
            "    command: [\"python\", \"-m\", \"http.server\", \"80\", \"--bind\", \"0.0.0.0\", \"--directory\", \"/srv\"]\n"
            "    volumes: [\"./site:/srv:ro\"]\n"
            f"    networks: {{ lab: {{ ipv4_address: {HOST_IPS[host]} }} }}\n"
            "networks:\n"
            "  lab: { name: redamon_js_secret_lab, external: true }\n")
    found = probe_offline(site) if probe else None
    for row in rows:
        if found is not None:
            row["trufflehog_offline"] = sorted(found.get(row["value_sha12"], [])) or None
    with open(os.path.join(out_dir, "expected_real.json"), "w", encoding="utf-8") as fh:
        json.dump({"seed": SEED, "probe": "offline, --no-verification" if found is not None else "not run",
                   "rows": rows, "invented_copy": committed_rows(lab.rows)}, fh, indent=1)
        fh.write("\n")
    print(f"{'name':<44} {'sha12':<12}  provider      TruffleHog offline", flush=True)
    for row in rows:
        det = ",".join(row["trufflehog_offline"] or []) if found is not None else "(probe not run)"
        print(f"{row['name'][:44]:<44} {row['value_sha12']}  {row['provider']:<12}  {det or '-'}", flush=True)
    print(f"[+] {compose}\n[+] {os.path.join(out_dir, 'expected_real.json')}", flush=True)
    print(f'[*] start .15 for E3:  docker compose -f "{compose}" up -d', flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--canary-ip", help="the canary's address on redamon-trufflehog-net (default: ask docker)")
    ap.add_argument("--emit-expected", action="store_true", help="rewrite expected.json, then exit")
    ap.add_argument("--check-expected", action="store_true", help="exit 1 if expected.json disagrees")
    ap.add_argument("--real-keys", metavar="EXPORT", help="E3 only: write host .15 from an API-keys export")
    ap.add_argument("--out-dir", default=REAL_OUT, help="where --real-keys writes (default: %(default)s)")
    ap.add_argument("--no-probe", action="store_true", help="--real-keys: skip the offline TruffleHog probe")
    args = ap.parse_args()

    if args.canary_ip and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", args.canary_ip):
        raise SystemExit("[!] --canary-ip must be an IPv4 address")
    if args.real_keys:
        os.makedirs(args.out_dir, exist_ok=True)
        real_keys(args.real_keys, os.path.abspath(args.out_dir), not args.no_probe)
        return
    if args.emit_expected:
        emit_expected(rows_for_expected(args.canary_ip))
        return
    if args.check_expected:
        sys.exit(0 if check_expected(rows_for_expected(args.canary_ip)) else 1)
    canary_ip = args.canary_ip or running_canary_ip()
    rows = generate(canary_ip)
    if canary_ip is None:
        rows = rows_for_expected(None)
    check_expected(rows)


if __name__ == "__main__":
    main()
