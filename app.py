#!/usr/bin/env python3
"""
SB Link Tracker — ওয়েবসাইট সংস্করণ (v2)
নিজের শেয়ার করা লিংকের ক্লিক অ্যানালিটিক্স, পাসওয়ার্ড-সুরক্ষিত ড্যাশবোর্ডসহ।

- ওয়েবসাইটে ঢুকতে পাসওয়ার্ড লাগে (লগইন পেজ `/login`)।
  পাসওয়ার্ড আসে ADMIN_KEY env থেকে (GitHub Actions-এ repo secret
  SB_TRACKER_ADMIN_KEY)। ADMIN_KEY না থাকলে ড্যাশবোর্ড বন্ধ থাকে —
  শুধু "পাসওয়ার্ড সেট করা হয়নি" পেজ দেখায়।
- লগইনের পর সেশন কুকি (HMAC-সাইন করা, 12 ঘণ্টা) দিয়ে ঢোকা থাকে।
- ট্র্যাকিং লিংক `/t/<code>` সবার জন্য খোলা — ওটাই এর কাজ।
  ক্লিকে IP, দেশ/শহর (ফ্রি ip-api), ISP, ব্রাউজার, OS, সময় লগ হয়,
  তারপর আসল লিংকে রিডাইরেক্ট (302) হয়।

শুধু Python stdlib — কোনো পেইড API / প্যাকেজ নেই।
চালানো:  ADMIN_KEY=... PORT=8790 python3 app.py
"""
import os, json, sqlite3, secrets, string, hmac, hashlib, time, urllib.request, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "data.db")
PORT = int(os.environ.get("PORT", "8790"))
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
SESSION_TTL = 12 * 3600

CSS = """
*{box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;margin:0;background:#0f172a;color:#e2e8f0;min-height:100vh}
.wrap{max-width:1020px;margin:0 auto;padding:20px 14px 40px}
header{display:flex;justify-content:space-between;align-items:center;padding:14px 0}
.logo{font-size:22px;font-weight:700;color:#38bdf8}.logo span{color:#e2e8f0}
a.btn,button{background:#0284c7;color:#fff;border:0;padding:9px 18px;border-radius:8px;cursor:pointer;font-size:14px;text-decoration:none}
a.btn:hover,button:hover{background:#0369a1}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px;margin:14px 0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px;text-align:center}
.stat b{display:block;font-size:28px;color:#38bdf8}.stat i{font-style:normal;color:#94a3b8;font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid #334155;padding:7px 6px;text-align:left}
th{color:#94a3b8}input[type=text],input[type=password],input[type=url]{width:100%;padding:11px;border-radius:8px;border:1px solid #475569;background:#0f172a;color:#e2e8f0;font-size:15px}
form.row{display:flex;gap:10px}form.row input{flex:1}
.loginbox{max-width:400px;margin:12vh auto;background:#1e293b;border:1px solid #334155;border-radius:14px;padding:28px;text-align:center}
.loginbox h1{font-size:22px;margin:4px 0 6px}.loginbox p{color:#94a3b8;font-size:14px}
.err{background:#7f1d1d;color:#fecaca;padding:9px;border-radius:8px;font-size:14px;margin:10px 0}
.ok{background:#14532d;color:#bbf7d0;padding:9px;border-radius:8px;font-size:14px;margin:10px 0}
small{color:#94a3b8}code{background:#0f172a;padding:2px 7px;border-radius:6px;color:#38bdf8}
"""

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS links(code TEXT PRIMARY KEY, url TEXT, created TEXT)")
    c.execute("""CREATE TABLE IF NOT EXISTS clicks(
        id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT, ts TEXT, ip TEXT,
        country TEXT, city TEXT, isp TEXT, browser TEXT, os TEXT, ua TEXT, referer TEXT)""")
    return c

def parse_ua(ua: str):
    u = ua.lower()
    browser = ("Edge" if "edg/" in u else "Chrome" if "chrome" in u else
               "Firefox" if "firefox" in u else "Safari" if "safari" in u else "Other")
    os_ = ("Android" if "android" in u else "iOS" if ("iphone" in u or "ipad" in u) else
           "Windows" if "windows" in u else "macOS" if "mac os" in u else
           "Linux" if "linux" in u else "Other")
    return browser, os_

def geo(ip: str):
    if not ip or ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "::")):
        return "", "", ""
    try:
        u = f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields=status,country,city,isp"
        with urllib.request.urlopen(u, timeout=4) as r:
            d = json.loads(r.read().decode())
        if d.get("status") == "success":
            return d.get("country", ""), d.get("city", ""), d.get("isp", "")
    except Exception:
        pass
    return "", "", ""

def esc(s): return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def make_token():
    exp = str(int(time.time()) + SESSION_TTL)
    sig = hmac.new(ADMIN_KEY.encode(), exp.encode(), hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"

def valid_token(tok: str):
    if not tok or "." not in tok or not ADMIN_KEY: return False
    exp, sig = tok.split(".", 1)
    if int(exp) < int(time.time()): return False
    good = hmac.new(ADMIN_KEY.encode(), exp.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, good)

def page(title, body):
    return f"<!doctype html><html lang=bn><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>{esc(title)}</title><style>{CSS}</style></head><body>{body}</body></html>"

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send_html(self, html, code=200, headers=None):
        b = html.encode(); self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", len(b))
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)
    def redirect(self, to, headers=None):
        self.send_response(302); self.send_header("Location", to)
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers()
    def session(self):
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            part = part.strip()
            if part.startswith("sb_session="): return valid_token(part[len("sb_session="):])
        return False
    def form(self):
        n = int(self.headers.get("Content-Length", 0))
        return urllib.parse.parse_qs(self.rfile.read(n).decode()) if n else {}

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/t/"):
            code = path[3:].strip("/")
            c = db(); row = c.execute("SELECT url FROM links WHERE code=?", (code,)).fetchone()
            if not row: c.close(); return self.send_html(page("Not found", "<div class=wrap><div class=card><h3>লিংক পাওয়া যায়নি</h3></div></div>"), 404)
            ip = (self.headers.get("CF-Connecting-IP", "").strip()
                  or self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                  or self.client_address[0])
            ua = self.headers.get("User-Agent", ""); br, os_ = parse_ua(ua)
            country, city, isp = geo(ip)
            c.execute("INSERT INTO clicks(code,ts,ip,country,city,isp,browser,os,ua,referer) VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (code, datetime.now(timezone.utc).isoformat(), ip, country, city, isp, br, os_, ua, self.headers.get("Referer", "")))
            c.commit(); c.close()
            return self.redirect(row["url"])
        if path == "/login":
            if not ADMIN_KEY:
                return self.send_html(page("Setup", "<div class=loginbox><h1>🔒 SB Link Tracker</h1><p>এই ওয়েবসাইটে এখনো পাসওয়ার্ড সেট করা হয়নি।<br>সার্ভারে ADMIN_KEY সেট করলেই লগইন চালু হবে।</p></div>"))
            if self.session(): return self.redirect("/")
            err = "<div class=err>পাসওয়ার্ড মেলেনি — আবার চেষ্টা করো</div>" if "e=1" in self.path else ""
            return self.send_html(page("Login", f"""<div class=loginbox><div style="font-size:40px">🔗</div>
<h1>SB Link Tracker</h1><p>ওয়েবসাইটে ঢুকতে পাসওয়ার্ড দাও</p>{err}
<form method=POST action=/login><input type=password name=password placeholder="পাসওয়ার্ড" required autofocus>
<div style="height:12px"></div><button style="width:100%">প্রবেশ করো</button></form>
<p><small>নিজের লিংকের ক্লিক অ্যানালিটিক্স — SB Digital Studio</small></p></div>"""))
        if path == "/logout":
            return self.redirect("/login", {"Set-Cookie": "sb_session=; Path=/; Max-Age=0; HttpOnly"})
        if path in ("/", "/dashboard"):
            if not ADMIN_KEY:
                return self.send_html(page("Setup", "<div class=loginbox><h1>🔒 SB Link Tracker</h1><p>পাসওয়ার্ড সেট করা হয়নি — ADMIN_KEY সেট করলে ওয়েবসাইট চালু হবে।</p></div>"))
            if not self.session(): return self.redirect("/login")
            c = db()
            links = c.execute("SELECT * FROM links ORDER BY created DESC").fetchall()
            clicks = c.execute("SELECT * FROM clicks ORDER BY id DESC LIMIT 200").fetchall()
            n_links = c.execute("SELECT COUNT(*) n FROM links").fetchone()["n"]
            n_clicks = c.execute("SELECT COUNT(*) n FROM clicks").fetchone()["n"]
            n_ip = c.execute("SELECT COUNT(DISTINCT ip) n FROM clicks").fetchone()["n"]
            top = c.execute("SELECT country, COUNT(*) n FROM clicks WHERE country<>'' GROUP BY country ORDER BY n DESC LIMIT 1").fetchone()
            c.close()
            host = self.headers.get("Host", "localhost"); scheme = "https" if self.headers.get("CF-Visitor", "").find("https") >= 0 or self.headers.get("X-Forwarded-Proto") == "https" else "http"
            rows = "".join(f"<tr><td>{r['ts'][:19]}</td><td>/{esc(r['code'])}</td><td>{esc(r['ip'])}</td><td>{esc(r['country'])} {esc(r['city'])}</td><td>{esc(r['isp'])}</td><td>{esc(r['browser'])}</td><td>{esc(r['os'])}</td></tr>" for r in clicks)
            lrows = "".join(f"<tr><td><code>{scheme}://{esc(host)}/t/{esc(l['code'])}</code></td><td>{esc(l['url'])}</td><td>{esc(l['created'][:19])}</td></tr>" for l in links)
            msg = "<div class=ok>নতুন ট্র্যাকিং লিংক তৈরি হয়েছে — নিচের তালিকায় দেখো</div>" if "made=1" in self.path else ""
            return self.send_html(page("Dashboard", f"""<div class=wrap>
<header><div class=logo>🔗 SB <span>Link Tracker</span></div><a class=btn href=/logout>লগআউট</a></header>
{msg}
<div class=stats>
<div class=stat><b>{n_links}</b><i>মোট লিংক</i></div>
<div class=stat><b>{n_clicks}</b><i>মোট ক্লিক</i></div>
<div class=stat><b>{n_ip}</b><i>আলাদা IP</i></div>
<div class=stat><b>{esc(top['country']) if top else '—'}</b><i>শীর্ষ দেশ</i></div>
</div>
<div class=card><h3 style="margin-top:0">নতুন ট্র্যাকিং লিংক বানাও</h3>
<form class=row method=POST action=/create><input type=url name=url placeholder="আসল লিংক দাও, যেমন https://youtube.com/watch?v=..." required><button>বানাও</button></form></div>
<div class=card><h3 style="margin-top:0">তোমার লিংকগুলো</h3><table><tr><th>ট্র্যাকিং লিংক</th><th>আসল লিংক</th><th>তৈরি</th></tr>{lrows or '<tr><td colspan=3>এখনো কোনো লিংক নেই</td></tr>'}</table></div>
<div class=card><h3 style="margin-top:0">সাম্প্রতিক ক্লিক</h3><table><tr><th>সময় (UTC)</th><th>লিংক</th><th>IP</th><th>দেশ/শহর</th><th>ISP</th><th>ব্রাউজার</th><th>OS</th></tr>{rows or '<tr><td colspan=7>এখনো কোনো ক্লিক নেই</td></tr>'}</table></div>
<p><small>শিক্ষামূলক / নিজের লিংকের অ্যানালিটিক্সের জন্য। IP দিয়ে আনুমানিক দেশ/শহর পাওয়া যায়, সঠিক GPS নয়।</small></p>
</div>"""))
        return self.send_html(page("404", "<div class=wrap><div class=card><h3>পেজ পাওয়া যায়নি</h3></div></div>"), 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/login":
            pw = self.form().get("password", [""])[0]
            if ADMIN_KEY and hmac.compare_digest(pw, ADMIN_KEY):
                return self.redirect("/", {"Set-Cookie": f"sb_session={make_token()}; Path=/; HttpOnly; SameSite=Lax"})
            return self.redirect("/login?e=1")
        if path == "/create":
            if not self.session(): return self.redirect("/login")
            url = self.form().get("url", [""])[0].strip()
            if not url.startswith(("http://", "https://")):
                return self.send_html(page("Error", "<div class=wrap><div class=card><h3>সঠিক http/https লিংক দাও</h3><p><a href='/'>ফিরে যাও</a></p></div></div>"), 400)
            code = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(6))
            c = db(); c.execute("INSERT INTO links VALUES(?,?,?)", (code, url, datetime.now(timezone.utc).isoformat())); c.commit(); c.close()
            return self.redirect("/?made=1")
        return self.send_html("Not found", 404)

if __name__ == "__main__":
    db().close(); print(f"SB Link Tracker v2 on http://127.0.0.1:{PORT} (password gate: {'ON' if ADMIN_KEY else 'OFF - set ADMIN_KEY'})")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
