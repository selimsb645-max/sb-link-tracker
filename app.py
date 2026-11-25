#!/usr/bin/env python3
"""
SB Link Tracker — ওয়েবসাইট সংস্করণ (v3, প্রিমিয়াম UI)
নিজের শেয়ার করা লিংকের ক্লিক অ্যানালিটিক্স, পাসওয়ার্ড-সুরক্ষিত ড্যাশবোর্ডসহ।

- ওয়েবসাইটে ঢুকতে পাসওয়ার্ড লাগে (লগইন পেজ `/login`)।
  পাসওয়ার্ড আসে ADMIN_KEY env থেকে (GitHub Actions-এ repo secret
  SB_TRACKER_ADMIN_KEY)। ADMIN_KEY না থাকলে ড্যাশবোর্ড বন্ধ থাকে।
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
*{box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;margin:0;color:#e2e8f0;min-height:100vh;
background:#070b16 radial-gradient(900px 500px at 15% -10%,rgba(56,189,248,.16),transparent 60%),
radial-gradient(800px 480px at 90% 0%,rgba(99,102,241,.15),transparent 60%) fixed}
.wrap{max-width:1040px;margin:0 auto;padding:18px 14px 44px}
header{display:flex;justify-content:space-between;align-items:center;padding:12px 2px 4px}
.logo{font-size:23px;font-weight:800;letter-spacing:.2px}
.logo b{background:linear-gradient(90deg,#38bdf8,#818cf8);-webkit-background-clip:text;background-clip:text;color:transparent}
.btn,button{background:linear-gradient(135deg,#0ea5e9,#6366f1);color:#fff;border:0;padding:10px 20px;border-radius:10px;cursor:pointer;font-size:14px;font-weight:600;text-decoration:none;box-shadow:0 6px 18px rgba(14,165,233,.35);transition:.15s}
.btn:hover,button:hover{transform:translateY(-1px);box-shadow:0 10px 24px rgba(99,102,241,.4)}
.ghost{background:rgba(56,189,248,.12);color:#7dd3fc;box-shadow:none;border:1px solid rgba(56,189,248,.35);padding:5px 12px;font-size:12px;border-radius:8px;white-space:nowrap}
.ghost:hover{background:rgba(56,189,248,.22);box-shadow:none;transform:none}
.card{background:linear-gradient(180deg,rgba(255,255,255,.045),rgba(255,255,255,.018));border:1px solid rgba(148,163,184,.18);border-radius:16px;padding:20px;margin:16px 0;box-shadow:0 12px 32px rgba(0,0,0,.35);backdrop-filter:blur(8px)}
.card h3{margin:0 0 14px;font-size:17px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:16px}
.stat{background:linear-gradient(180deg,rgba(255,255,255,.05),rgba(255,255,255,.02));border:1px solid rgba(148,163,184,.18);border-radius:16px;padding:18px 10px;text-align:center;box-shadow:0 10px 26px rgba(0,0,0,.3)}
.stat b{display:block;font-size:30px;font-weight:800;background:linear-gradient(90deg,#38bdf8,#a5b4fc);-webkit-background-clip:text;background-clip:text;color:transparent}
.stat i{font-style:normal;color:#94a3b8;font-size:13px}
.tbl{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:0 -6px;padding:0 6px}
table{border-collapse:collapse;width:100%;font-size:13px;min-width:520px}
td,th{border-bottom:1px solid rgba(148,163,184,.14);padding:9px 8px;text-align:left;vertical-align:top}
th{color:#94a3b8;font-weight:600;white-space:nowrap}
tr:last-child td{border-bottom:0}
input[type=text],input[type=password],input[type=url]{width:100%;padding:12px 14px;border-radius:10px;border:1px solid rgba(148,163,184,.3);background:rgba(7,11,22,.7);color:#e2e8f0;font-size:15px;outline:none;transition:.15s}
input:focus{border-color:#38bdf8;box-shadow:0 0 0 3px rgba(56,189,248,.22)}
form.row{display:flex;gap:10px}form.row input{flex:1}
.loginbox{max-width:410px;margin:11vh auto;background:linear-gradient(180deg,rgba(255,255,255,.06),rgba(255,255,255,.02));border:1px solid rgba(148,163,184,.22);border-radius:20px;padding:34px 28px;text-align:center;box-shadow:0 24px 60px rgba(0,0,0,.5),0 0 0 1px rgba(56,189,248,.06),0 0 44px rgba(56,189,248,.10)}
.loginbox h1{font-size:24px;margin:8px 0 6px}.loginbox p{color:#94a3b8;font-size:14px}
.icon{width:64px;height:64px;margin:0 auto;border-radius:18px;display:flex;align-items:center;justify-content:center;font-size:30px;background:linear-gradient(135deg,rgba(14,165,233,.25),rgba(99,102,241,.25));border:1px solid rgba(56,189,248,.35)}
.err{background:rgba(127,29,29,.5);color:#fecaca;padding:10px;border-radius:10px;font-size:14px;margin:12px 0;border:1px solid rgba(248,113,113,.3)}
.ok{background:rgba(20,83,45,.5);color:#bbf7d0;padding:10px 14px;border-radius:10px;font-size:14px;margin:14px 0 0;border:1px solid rgba(74,222,128,.3)}
small{color:#94a3b8}code{background:rgba(56,189,248,.10);padding:3px 8px;border-radius:7px;color:#7dd3fc;word-break:break-all;font-size:12px}
.pill{display:inline-block;background:rgba(99,102,241,.18);border:1px solid rgba(129,140,248,.35);color:#c7d2fe;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:700}
footer{text-align:center;color:#64748b;font-size:12px;margin-top:26px}
"""
JS = """
function cp(el,txt){
  function done(){el.textContent='✓ কপি হয়েছে';setTimeout(function(){el.textContent='কপি'},1600)}
  if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(txt).then(done).catch(function(){fallback()})}else{fallback()}
  function fallback(){var ta=document.createElement('textarea');ta.value=txt;document.body.appendChild(ta);ta.select();try{document.execCommand('copy');done()}catch(e){el.textContent='ম্যানুয়ালি কপি করো'}document.body.removeChild(ta)}
}
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
    return f"<!doctype html><html lang=bn><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>{esc(title)} · SB Link Tracker</title><style>{CSS}</style></head><body>{body}</body></html>"

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
                return self.send_html(page("Setup", "<div class=wrap><div class=loginbox><div class=icon>🔒</div><h1>SB Link Tracker</h1><p>এই ওয়েবসাইটে এখনো পাসওয়ার্ড সেট করা হয়নি।<br>সার্ভারে ADMIN_KEY সেট করলেই লগইন চালু হবে।</p></div></div>"))
            if self.session(): return self.redirect("/")
            err = "<div class=err>পাসওয়ার্ড মেলেনি — আবার চেষ্টা করো</div>" if "e=1" in self.path else ""
            return self.send_html(page("Login", f"""<div class=wrap><div class=loginbox><div class=icon>🔗</div>
<h1>SB <span style="background:linear-gradient(90deg,#38bdf8,#818cf8);-webkit-background-clip:text;background-clip:text;color:transparent">Link Tracker</span></h1><p>ওয়েবসাইটে ঢুকতে পাসওয়ার্ড দাও</p>{err}
<form method=POST action=/login><input type=password name=password placeholder="পাসওয়ার্ড" required autofocus>
<div style="height:14px"></div><button style="width:100%">প্রবেশ করো →</button></form>
<p style="margin-bottom:0"><small>নিজের লিংকের ক্লিক অ্যানালিটিক্স — SB Digital Studio</small></p></div></div>"""))
        if path == "/logout":
            return self.redirect("/login", {"Set-Cookie": "sb_session=; Path=/; Max-Age=0; HttpOnly"})
        if path in ("/", "/dashboard"):
            if not ADMIN_KEY:
                return self.send_html(page("Setup", "<div class=wrap><div class=loginbox><div class=icon>🔒</div><h1>SB Link Tracker</h1><p>পাসওয়ার্ড সেট করা হয়নি — ADMIN_KEY সেট করলে ওয়েবসাইট চালু হবে।</p></div></div>"))
            if not self.session(): return self.redirect("/login")
            c = db()
            links = c.execute("""SELECT l.*, (SELECT COUNT(*) FROM clicks k WHERE k.code=l.code) AS n
                                 FROM links l ORDER BY l.created DESC""").fetchall()
            clicks = c.execute("SELECT * FROM clicks ORDER BY id DESC LIMIT 200").fetchall()
            n_links = c.execute("SELECT COUNT(*) n FROM links").fetchone()["n"]
            n_clicks = c.execute("SELECT COUNT(*) n FROM clicks").fetchone()["n"]
            n_ip = c.execute("SELECT COUNT(DISTINCT ip) n FROM clicks").fetchone()["n"]
            top = c.execute("SELECT country, COUNT(*) n FROM clicks WHERE country<>'' GROUP BY country ORDER BY n DESC LIMIT 1").fetchone()
            c.close()
            host = self.headers.get("Host", "localhost"); scheme = "https" if self.headers.get("CF-Visitor", "").find("https") >= 0 or self.headers.get("X-Forwarded-Proto") == "https" else "http"
            rows = "".join(f"<tr><td style='white-space:nowrap'>{r['ts'][:19].replace('T',' ')}</td><td>/{esc(r['code'])}</td><td><code>{esc(r['ip'])}</code></td><td>{esc(r['country'])}<br><small>{esc(r['city'])}</small></td><td>{esc(r['isp'])}</td><td>{esc(r['browser'])}</td><td>{esc(r['os'])}</td></tr>" for r in clicks)
            lrows = ""
            for l in links:
                full = f"{scheme}://{host}/t/{l['code']}"
                lrows += (f"<tr><td><code>{esc(full)}</code></td>"
                          f"<td><button type=button class=ghost onclick=\"cp(this,'{esc(full)}')\">কপি</button></td>"
                          f"<td style='word-break:break-all'>{esc(l['url'])}</td>"
                          f"<td><span class=pill>{l['n']}</span></td>"
                          f"<td style='white-space:nowrap'>{esc(l['created'][:10])}</td></tr>")
            msg = "<div class=ok>✓ নতুন ট্র্যাকিং লিংক তৈরি হয়েছে — তালিকা থেকে কপি করে শেয়ার করো</div>" if "made=1" in self.path else ""
            return self.send_html(page("Dashboard", f"""<div class=wrap>
<header><div class=logo>🔗 <b>SB</b> Link Tracker</div><a class=btn href=/logout>লগআউট</a></header>
{msg}
<div class=stats>
<div class=stat><b>{n_links}</b><i>মোট লিংক</i></div>
<div class=stat><b>{n_clicks}</b><i>মোট ক্লিক</i></div>
<div class=stat><b>{n_ip}</b><i>আলাদা IP</i></div>
<div class=stat><b>{esc(top['country']) if top else '—'}</b><i>শীর্ষ দেশ</i></div>
</div>
<div class=card><h3>✨ নতুন ট্র্যাকিং লিংক বানাও</h3>
<form class=row method=POST action=/create><input type=url name=url placeholder="আসল লিংক দাও, যেমন https://youtube.com/watch?v=..." required><button>বানাও</button></form></div>
<div class=card><h3>🔗 তোমার লিংকগুলো</h3><div class=tbl><table><tr><th>ট্র্যাকিং লিংক</th><th></th><th>আসল লিংক</th><th>ক্লিক</th><th>তৈরি</th></tr>{lrows or '<tr><td colspan=5>এখনো কোনো লিংক নেই</td></tr>'}</table></div></div>
<div class=card><h3>📊 সাম্প্রতিক ক্লিক</h3><div class=tbl><table><tr><th>সময় (UTC)</th><th>লিংক</th><th>IP</th><th>দেশ/শহর</th><th>ISP</th><th>ব্রাউজার</th><th>OS</th></tr>{rows or '<tr><td colspan=7>এখনো কোনো ক্লিক নেই</td></tr>'}</table></div></div>
<footer>শিক্ষামূলক / নিজের লিংকের অ্যানালিটিক্সের জন্য · IP দিয়ে আনুমানিক দেশ/শহর পাওয়া যায়, সঠিক GPS নয় · SB Digital Studio</footer>
</div><script>{JS}</script>"""))
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
    db().close(); print(f"SB Link Tracker v3 on http://127.0.0.1:{PORT} (password gate: {'ON' if ADMIN_KEY else 'OFF - set ADMIN_KEY'})")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
