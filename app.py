#!/usr/bin/env python3
"""
SB Link Tracker — নিজের শেয়ার করা লিংকের ক্লিক অ্যানালিটিক্স।
ভিডিওতে দেখানো Grabify-ধাঁচের সিস্টেমের শিক্ষামূলক / নিজের-লিংক সংস্করণ:
তুমি নিজের আসল লিংক দিলে একটা ছোট ট্র্যাকিং লিংক তৈরি হয়; কেউ তাতে
ক্লিক করলে (যেকোনো ওয়েবসার্ভারের মতোই) IP, দেশ/শহর (ফ্রি ip-api),
ISP, ব্রাউজার, OS, সময় লগ হয়, তারপর আসল লিংকে রিডাইরেক্ট হয়।

শুধু Python stdlib — কোনো পেইড API / প্যাকেজ নেই।
চালানো:  python3 app.py            (ডিফল্ট পোর্ট 8790)
          PORT=8790 python3 app.py
ড্যাশবোর্ড পাসওয়ার্ড: env ADMIN_KEY (না দিলে লোকালে খোলা, পাবলিকে অবশ্যই দেবে)
"""
import os, json, sqlite3, secrets, string, time, urllib.request, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "data.db")
PORT = int(os.environ.get("PORT", "8790"))
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS links(code TEXT PRIMARY KEY, url TEXT, created TEXT)")
    c.execute("""CREATE TABLE IF NOT EXISTS clicks(
        id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT, ts TEXT, ip TEXT,
        country TEXT, city TEXT, isp TEXT, browser TEXT, os TEXT, ua TEXT, referer TEXT)""")
    return c

def parse_ua(ua: str):
    ua_l = ua.lower()
    browser = ("Edge" if "edg/" in ua_l else "Chrome" if "chrome" in ua_l else
               "Firefox" if "firefox" in ua_l else "Safari" if "safari" in ua_l else "Other")
    os_ = ("Android" if "android" in ua_l else "iOS" if ("iphone" in ua_l or "ipad" in ua_l) else
           "Windows" if "windows" in ua_l else "macOS" if "mac os" in ua_l else
           "Linux" if "linux" in ua_l else "Other")
    return browser, os_

def geo(ip: str):
    # প্রাইভেট/লোকাল IP-র জন্য লুকআপ হয় না
    if not ip or ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "::")):
        return "", "", ""
    try:
        u = f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields=status,country,city,isp"
        with urllib.request.urlopen(u, timeout=4) as r:
            d = json.loads(r.read().decode())
        if d.get("status") == "success":
            return d.get("country",""), d.get("city",""), d.get("isp","")
    except Exception:
        pass
    return "", "", ""

def esc(s): return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send_html(self, html, code=200):
        b = html.encode(); self.send_response(code)
        self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",len(b)); self.end_headers(); self.wfile.write(b)
    def authed(self):
        if not ADMIN_KEY: return True
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        return (q.get("key",[""])[0] == ADMIN_KEY) or (self.headers.get("X-Admin-Key")==ADMIN_KEY)
    def do_GET(self):
        p = urllib.parse.urlparse(self.path); path = p.path
        if path.startswith("/t/"):
            code = path[3:].strip("/")
            c = db(); row = c.execute("SELECT url FROM links WHERE code=?", (code,)).fetchone()
            if not row: return self.send_html("<h3>Link not found</h3>", 404)
            ip = (self.headers.get("CF-Connecting-IP","").strip()
                  or self.headers.get("X-Forwarded-For","").split(",")[0].strip()
                  or self.client_address[0])
            ua = self.headers.get("User-Agent",""); br, os_ = parse_ua(ua)
            country, city, isp = geo(ip)
            c.execute("INSERT INTO clicks(code,ts,ip,country,city,isp,browser,os,ua,referer) VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (code, datetime.now(timezone.utc).isoformat(), ip, country, city, isp, br, os_, ua, self.headers.get("Referer","")))
            c.commit(); c.close()
            self.send_response(302); self.send_header("Location", row["url"]); self.end_headers(); return
        if path in ("/", "/dashboard"):
            if not self.authed(): return self.send_html("<h3>ADMIN_KEY লাগবে — ?key=... দিয়ে খোলো</h3>", 403)
            c = db(); links = c.execute("SELECT * FROM links ORDER BY created DESC").fetchall()
            clicks = c.execute("SELECT * FROM clicks ORDER BY id DESC LIMIT 200").fetchall(); c.close()
            rows = "".join(f"<tr><td>{r['ts'][:19]}</td><td>/{esc(r['code'])}</td><td>{esc(r['ip'])}</td><td>{esc(r['country'])} {esc(r['city'])}</td><td>{esc(r['isp'])}</td><td>{esc(r['browser'])}</td><td>{esc(r['os'])}</td></tr>" for r in clicks)
            lrows = "".join(f"<tr><td><b>/t/{esc(l['code'])}</b></td><td>{esc(l['url'])}</td><td>{esc(l['created'][:19])}</td></tr>" for l in links)
            return self.send_html(f"""<!doctype html><meta charset=utf-8><title>SB Link Tracker</title>
<style>body{{font-family:sans-serif;max-width:1000px;margin:20px auto;padding:0 12px}}table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border:1px solid #ccc;padding:5px}}input{{width:70%;padding:8px}}button{{padding:8px 16px}}</style>
<h2>SB Link Tracker — নিজের লিংকের ক্লিক লগ</h2>
<form method=POST action=/create><input name=url placeholder="আসল লিংক দাও, যেমন https://youtube.com/watch?v=..." required><button>ট্র্যাকিং লিংক বানাও</button></form>
<h3>তোমার লিংকগুলো</h3><table><tr><th>ট্র্যাকিং</th><th>আসল</th><th>তৈরি</th></tr>{lrows or '<tr><td colspan=3>এখনো নেই</td></tr>'}</table>
<h3>সাম্প্রতিক ক্লিক ({len(clicks)})</h3><table><tr><th>সময় (UTC)</th><th>লিংক</th><th>IP</th><th>দেশ/শহর</th><th>ISP</th><th>ব্রাউজার</th><th>OS</th></tr>{rows or '<tr><td colspan=7>এখনো কোনো ক্লিক নেই</td></tr>'}</table>
<p style="color:#666;font-size:12px">শিক্ষামূলক / নিজের লিংকের অ্যানালিটিক্সের জন্য। IP দিয়ে আনুমানিক দেশ/শহর পাওয়া যায়, সঠিক GPS নয়।</p>""")
        return self.send_html("<h3>Not found</h3>", 404)
    def do_POST(self):
        if urllib.parse.urlparse(self.path).path == "/create":
            if not self.authed(): return self.send_html("<h3>Forbidden</h3>", 403)
            n = int(self.headers.get("Content-Length",0)); body = self.rfile.read(n).decode()
            url = urllib.parse.parse_qs(body).get("url",[""])[0].strip()
            if not url.startswith(("http://","https://")): return self.send_html("<h3>সঠিক http/https লিংক দাও</h3>", 400)
            code = "".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(6))
            c = db(); c.execute("INSERT INTO links VALUES(?,?,?)", (code, url, datetime.now(timezone.utc).isoformat())); c.commit(); c.close()
            host = self.headers.get("Host","localhost")
            return self.send_html(f"<p>তৈরি! তোমার ট্র্যাকিং লিংক:</p><h3>http://{esc(host)}/t/{code}</h3><p>আসল: {esc(url)}</p><p><a href='/'>ড্যাশবোর্ডে ফিরে যাও</a></p>")
        return self.send_html("<h3>Not found</h3>", 404)

if __name__ == "__main__":
    db().close(); print(f"SB Link Tracker on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
