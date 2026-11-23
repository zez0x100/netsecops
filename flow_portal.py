#!/usr/bin/env python3
"""Flow check portal: a small, separate web page where end users enter a source, a destination and a port and see
whether the network devices on the path allow it, and if not, at which step it stops.

- End users never see the firewalls: the portal holds its own read-only device logins and runs the same flow trace
  as the admin console (netops_console.py, imported from this folder). Users only see the verdict, the steps of the
  path (by the friendly names you give the devices), where it stops and a reference ID. Rule names, device addresses,
  NAT and server addresses are never sent to the browser.
- No user login: only clients from the networks you allow (--allow) can open it. Use HTTPS (--cert / --key).
- Every check is written to portal_audit.log (JSON lines) with the client address and the full hop detail; the
  network team looks a reference up with:  python flow_portal.py ref FC-261122-1A2B3C
- Device logins live in portal_logins.dat, encrypted with a passphrase (PBKDF2-SHA256 600k, HMAC-SHA256 stream +
  HMAC tag, standard library only). The passphrase is asked when the portal starts (or FLOW_PORTAL_PASSPHRASE).

  python flow_portal.py setup                      add / remove / test device logins
  python flow_portal.py serve --bind 10.0.0.5 --port 8443 --allow 10.10.0.0/16,10.20.0.0/16 --cert c.pem --key k.pem
  python flow_portal.py ref <reference>            full detail of one check from the audit log
Settings can also go in flow_portal.json next to this file (same names as the options; command line wins).
"""
import argparse
import base64
import concurrent.futures
import getpass
import hashlib
import hmac
import html
import ipaddress
import json
import os
import secrets
import socket
import ssl
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import netops_console as nc   # noqa: E402  (the flow trace engine and the device connectors)

CONFIG_FILE = os.path.join(HERE, "flow_portal.json")
VAULT_FILE = os.path.join(HERE, "portal_logins.dat")
AUDIT_FILE = os.path.join(HERE, "portal_audit.log")
AUDIT_MAX = 20 * 1024 * 1024        # rotated to .1 above this size
VENDORS = {"fortigate": "FortiGate", "paloalto": "Palo Alto", "f5": "F5 BIG-IP", "cloudflare": "Cloudflare"}
DEFAULTS = {"bind": "127.0.0.1", "port": 8443, "allow": [], "cert": "", "key": "", "logs": False,
            "within": "last 24 hours", "max_parallel": 2, "title": "Network flow check"}
KDF_ITER = 600000
LABELS = {}                          # device session name -> name shown to end users
STATE = {"logins": [], "failed": [], "busy": None, "allow": [], "cfg": dict(DEFAULTS)}
AUDIT_LOCK = threading.Lock()


# ---- encrypted device logins -------------------------------------------------------------------------------------
def _keys(pp, salt, it):
    k = hashlib.pbkdf2_hmac("sha256", pp.encode("utf-8"), salt, it, 64)
    return k[:32], k[32:]


def _stream(k, nonce, n):
    out, c = bytearray(), 0
    while len(out) < n:
        out += hmac.new(k, nonce + c.to_bytes(8, "big"), hashlib.sha256).digest()
        c += 1
    return bytes(out[:n])


def vault_seal(pp, logins):
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(16)
    ke, km = _keys(pp, salt, KDF_ITER)
    pt = json.dumps(logins).encode("utf-8")
    ct = bytes(a ^ b for a, b in zip(pt, _stream(ke, nonce, len(pt))))
    tag = hmac.new(km, b"fp1" + salt + nonce + ct, hashlib.sha256).hexdigest()
    return {"v": 1, "note": "flow portal device logins, passphrase-encrypted. Never commit this file.",
            "iter": KDF_ITER, "salt": salt.hex(), "nonce": nonce.hex(), "data": base64.b64encode(ct).decode(), "tag": tag}


def vault_open(pp, d):
    salt, nonce, ct = bytes.fromhex(d["salt"]), bytes.fromhex(d["nonce"]), base64.b64decode(d["data"])
    it = int(d.get("iter") or KDF_ITER)
    if it < 100000:
        raise ValueError("the login file uses too few key rounds")
    ke, km = _keys(pp, salt, it)
    tag = hmac.new(km, b"fp1" + salt + nonce + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag, str(d.get("tag") or "")):
        time.sleep(1)   # slows down guessing
        raise ValueError("wrong passphrase (or the login file was changed)")
    return json.loads(bytes(a ^ b for a, b in zip(ct, _stream(ke, nonce, len(ct)))).decode("utf-8"))


def vault_load(pp):
    with open(VAULT_FILE, encoding="utf-8") as f:
        return vault_open(pp, json.load(f))


def vault_save(pp, logins):
    tmp = VAULT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(vault_seal(pp, logins), f)
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    os.replace(tmp, VAULT_FILE)


# ---- setup (interactive) -----------------------------------------------------------------------------------------
def ask(prompt, default="", secret=False, required=False):
    while True:
        v = (getpass.getpass(prompt + ": ") if secret else input(prompt + (" [%s]" % default if default else "") + ": "))
        v = v.strip() or default
        if v or not required:
            return v
        print("  required")


def connect(x):
    """Connect one saved login -> (ok, message)."""
    b = dict(x)
    b.pop("label", None)
    try:
        r = nc.do_connect(b)
    except Exception as e:   # one bad device must not stop the others
        return False, "%s: %s" % (type(e).__name__, e)
    if r.get("ok"):
        LABELS[r["name"]] = x.get("label") or r["name"]
        return True, "connected"
    return False, str(r.get("error") or "failed")


def add_login():
    print("Vendors: " + ", ".join("%s (%s)" % (k, v) for k, v in VENDORS.items()))
    vendor = ask("Vendor", required=True).lower()
    if vendor not in VENDORS:
        print("  unknown vendor")
        return None
    x = {"vendor": vendor}
    x["name"] = ask("Device name (for the audit log, e.g. fw-edge-01)", required=True)[:40]
    x["label"] = ask("Name end users see (e.g. Internet firewall, Data centre firewall)", required=True)[:40]
    if vendor == "cloudflare":
        x["host"] = nc.CF_HOST
        x["apikey"] = ask("Cloudflare API token (read-only: Zone read, Analytics read, DNS read)", secret=True, required=True)
        x["account"] = ask("Account ID (optional)")
    else:
        x["host"] = ask("Management address", required=True)
        x["port"] = int(ask("HTTPS port", "443") or 443)
        x["insecure"] = ask("Skip TLS certificate check (self-signed)? y/N", "n").lower().startswith("y")
        if vendor == "fortigate":
            x["apikey"] = ask("REST API token of a read-only API admin", secret=True, required=True)
        elif vendor == "f5":
            x["username"] = ask("User name (Guest / read-only role)", required=True)
            x["password"] = ask("Password", secret=True, required=True)
        else:
            k = ask("API key (leave empty to use user name + password)", secret=True)
            if k:
                x["apikey"] = k
            else:
                x["username"] = ask("User name (read-only admin role)", required=True)
                x["password"] = ask("Password", secret=True, required=True)
    print("Testing the login ...")
    ok, msg = connect(x)
    print("  " + msg)
    if not ok and not ask("Keep it anyway? y/N", "n").lower().startswith("y"):
        return None
    return x


def do_setup():
    if os.path.exists(VAULT_FILE):
        pp = ask("Passphrase of %s" % os.path.basename(VAULT_FILE), secret=True, required=True)
        logins = vault_load(pp)
    else:
        print("No device logins yet: choose a passphrase (12+ characters). It is needed every time the portal starts.")
        while True:
            pp = ask("New passphrase", secret=True, required=True)
            if len(pp) < 12:
                print("  at least 12 characters")
            elif pp != ask("Repeat it", secret=True):
                print("  they differ")
            else:
                break
        logins = []
    print("Use read-only accounts: the portal only reads routes, policies, VIPs and virtual servers (and, with "
          "'logs', traffic logs).")
    changed = False
    while True:
        print("\nDevices:")
        for i, x in enumerate(logins, 1):
            print("  %d. %-12s %-28s users see: %s" % (i, x["vendor"], (x.get("name") or "")[:28], x.get("label") or ""))
        if not logins:
            print("  (none)")
        c = ask("[a]dd  [r]emove  [t]est all  [s]ave and quit  [q]uit without saving", "s").lower()[:1]
        if c == "a":
            x = add_login()
            if x:
                logins = [y for y in logins if nc.vault_id(y) != nc.vault_id(x)] + [x]
                changed = True
        elif c == "r":
            try:
                logins.pop(int(ask("Number to remove", required=True)) - 1)
                changed = True
            except (ValueError, IndexError):
                print("  no such number")
        elif c == "t":
            for x in logins:
                print("  %-28s %s" % (x.get("name"), connect(x)[1]))
        elif c == "s":
            if changed or not os.path.exists(VAULT_FILE):
                vault_save(pp, logins)
                print("Saved %d login(s) to %s" % (len(logins), VAULT_FILE))
            return
        elif c == "q":
            return


# ---- checks --------------------------------------------------------------------------------------------------------
REASONS = (("Policy", "no firewall rule allows this traffic, or a rule denies it"),
           ("Traffic log", "the firewall log shows this traffic being denied"),
           ("VIP", "this destination is not published (no address translation) on this firewall"),
           ("Destination NAT", "this destination is not published (no address translation) on this firewall"),
           ("Hostname", "this name is not served by the load balancer"),
           ("Virtual server", "the service is not available on the load balancer for this port (missing, disabled, "
                              "or no healthy servers)"),
           ("WAF", "the web application firewall blocked requests from this source"),
           ("DNS", "this name is not published"),
           ("Live connections", "no live connections were seen for this flow"))
ROLE = {"cloudflare": "Internet edge", "nat": "Address translation", "fortigate": "Firewall", "paloalto": "Firewall",
        "f5": "Load balancer"}


def reason_for(check):
    for k, v in REASONS:
        if str(check).startswith(k):
            return v
    return "the device does not allow this traffic"


def public_result(r):
    """The trace reduced to what an end user may see: verdict, step names and states, where it stops and why."""
    path, hops = r.get("path") or {}, (r.get("data") or {}).get("hops") or []
    steps, seen = [], {}
    for st in path.get("stages") or []:
        dev = (st.get("devices") or [""])[0]
        name = ROLE.get(st.get("vendor"), "Network device") if st.get("vendor") == "nat" else LABELS.get(dev)
        if not name:
            role = ROLE.get(st.get("vendor"), "Network device")
            seen[role] = seen.get(role, 0) + 1
            name = role + (" %d" % seen[role] if seen[role] > 1 else "")
        s = {"name": name, "state": st.get("state") if st.get("state") in ("passed", "blocked", "unclear") else "checked"}
        if s["state"] == "blocked":
            h = next((h for h in hops if h.get("state") == "blocked" and h.get("device") == dev), None)
            s["reason"] = reason_for(h.get("check") if h else "")
        steps.append(s)
    v = r.get("verdict") or {}
    blocked = [s for s in steps if s["state"] == "blocked"]
    if v.get("kind") == "bad" and blocked:
        out = {"status": "blocked", "where": blocked[0]["name"], "reason": blocked[0].get("reason", ""),
               "headline": "Blocked at: " + blocked[0]["name"],
               "detail": "The traffic stops at this step: %s. Send the reference below to the network team."
                         % blocked[0].get("reason", "")}
    elif v.get("kind") == "ok":
        out = {"status": "allowed", "headline": "No block found on the network path",
               "detail": "Every network device on the path allows this traffic. If the connection still fails, check "
                         "that the service is running on the destination and that its own (host) firewall allows it."}
    elif str(v.get("label") or "").startswith("NO DEVICE ON THIS PATH"):
        out = {"status": "not_covered", "headline": "None of the checked network devices is on this path",
               "detail": "The portal cannot see where this traffic goes. If it fails, send the reference to the network "
                         "team."}
    else:
        out = {"status": "unclear", "headline": "Could not confirm every step",
               "detail": "No block was found, but some steps could not be confirmed (marked below). Send the reference "
                         "to the network team if the connection fails."}
    out["steps"] = steps
    return out


def audit_write(rec):
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    with AUDIT_LOCK:
        try:
            if os.path.exists(AUDIT_FILE) and os.path.getsize(AUDIT_FILE) > AUDIT_MAX:
                os.replace(AUDIT_FILE, AUDIT_FILE + ".1")
        except OSError:
            pass
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(line)


def run_check(b, client):
    src = str(b.get("src") or "").strip()
    dst = str(b.get("dst") or "").strip()
    port = str(b.get("port") or "").strip()
    proto = str(b.get("proto") or "tcp").strip().lower()
    try:
        src = str(ipaddress.ip_address(src))
    except ValueError:
        return 400, {"ok": False, "error": "Enter the source as an IP address (for example your PC's address)."}
    if not dst or len(dst) > 253:
        return 400, {"ok": False, "error": "Enter the destination: an IP address or a server name."}
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return 400, {"ok": False, "error": "Enter the destination port (1-65535), for example 443."}
    if proto not in ("tcp", "udp"):
        return 400, {"ok": False, "error": "The protocol must be TCP or UDP."}
    ref = "FC-%s-%s" % (time.strftime("%y%m%d"), secrets.token_hex(3).upper())
    base = {"ref": ref, "src": src, "dst": dst, "port": port, "proto": proto,
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    if not STATE["busy"].acquire(timeout=20):
        return 429, {"ok": False, "error": "The portal is busy with other checks. Try again in a minute."}
    t0 = time.time()
    rec = {"time": base["checked_at"], "ref": ref, "client": client, "src": src, "dst": dst, "port": port, "proto": proto}
    try:
        r = nc.do_flow_trace({"src": src, "dst": dst, "port": port, "proto": proto,
                              "logs": bool(STATE["cfg"]["logs"]), "within": STATE["cfg"]["within"]})
        pub = public_result(r)
        rec.update(status=pub["status"], ms=int((time.time() - t0) * 1000), verdict=(r.get("verdict") or {}).get("label"),
                   hops=(r.get("data") or {}).get("hops"), notes=r.get("summary"), path=r.get("path"))
        audit_write(rec)
        return 200, dict(base, ok=True, **pub)
    except ValueError as e:   # input the trace engine rejects (its messages name no device)
        msg = str(e)
        if "connect at least one device" in msg:
            msg = "The portal is not connected to any network device right now. Contact the network team."
        rec.update(status="error", error=msg)
        audit_write(rec)
        return 400, dict(base, ok=False, error=msg[:300])
    except Exception as e:   # a device that did not answer, or an unexpected reply: detail only in the audit log
        rec.update(status="error", error="%s: %s" % (type(e).__name__, e), trace=traceback.format_exc()[-3000:])
        audit_write(rec)
        return 502, dict(base, ok=False, error="The check could not be completed (a network device did not answer). "
                                               "Try again, or send the reference to the network team.")
    finally:
        STATE["busy"].release()


# ---- web server ----------------------------------------------------------------------------------------------------
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = "FlowPortal"
    sys_version = ""
    timeout = 30
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):   # the audit log records the checks; no per-request console noise
        pass

    def client(self):
        return self.client_address[0]

    def allowed(self):
        try:
            ip = ipaddress.ip_address(self.client().split("%")[0])
        except ValueError:
            return False
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip.version == n.version and ip in n for n in STATE["allow"])

    def send(self, code, body, ctype):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        for k, v in (("Content-Type", ctype), ("Content-Length", str(len(body))), ("Cache-Control", "no-store"),
                     ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
                     ("X-Frame-Options", "DENY"), ("Content-Security-Policy", CSP)):
            self.send_header(k, v)
        if STATE["cfg"].get("cert"):
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.end_headers()
        self.wfile.write(body)

    def json(self, code, obj):
        self.send(code, json.dumps(obj), "application/json; charset=utf-8")

    def do_GET(self):
        if not self.allowed():
            return self.send(403, "Not available from your network.\n", "text/plain; charset=utf-8")
        p = self.path.split("?", 1)[0]
        if p == "/":
            return self.send(200, PAGE.replace("__TITLE__", html.escape(STATE["cfg"]["title"])), "text/html; charset=utf-8")
        if p == "/app.js":
            return self.send(200, JS, "text/javascript; charset=utf-8")
        if p == "/app.css":
            return self.send(200, CSS, "text/css; charset=utf-8")
        if p == "/api/me":
            with nc.LOCK:
                n = len(nc.SESSIONS)
            return self.json(200, {"ip": self.client(), "title": STATE["cfg"]["title"], "devices": n})
        self.send(404, "Not found\n", "text/plain; charset=utf-8")

    def do_POST(self):
        if not self.allowed():
            return self.send(403, "Not available from your network.\n", "text/plain; charset=utf-8")
        if self.path != "/api/check":
            return self.send(404, "Not found\n", "text/plain; charset=utf-8")
        # a custom header + JSON body: a page on another site cannot send this without a CORS preflight
        if self.headers.get("X-Flow-Portal") != "1" or not str(self.headers.get("Content-Type", "")).startswith("application/json"):
            return self.json(400, {"ok": False, "error": "bad request"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if not 0 < n <= 4096:
            return self.json(400, {"ok": False, "error": "bad request"})
        try:
            b = json.loads(self.rfile.read(n).decode("utf-8"))
            if not isinstance(b, dict):
                raise ValueError
        except ValueError:
            return self.json(400, {"ok": False, "error": "bad request"})
        code, out = run_check(b, self.client())
        self.json(code, out)


def retry_failed():
    """Devices that did not answer at start are tried again every 5 minutes."""
    while True:
        time.sleep(300)
        for x in list(STATE["failed"]):
            ok, msg = connect(x)
            if ok:
                STATE["failed"].remove(x)
                print("%s  %s reconnected" % (time.strftime("%H:%M:%S"), x.get("name")))


def load_config(a):
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
    for k in DEFAULTS:
        v = getattr(a, k, None)
        if v not in (None, ""):
            cfg[k] = v
    if isinstance(cfg["allow"], str):
        cfg["allow"] = [x for x in cfg["allow"].replace(" ", ",").split(",") if x]
    nets = [ipaddress.ip_network(x, strict=False) for x in cfg["allow"]]
    if not nets:
        if not ipaddress.ip_address(cfg["bind"]).is_loopback:
            raise SystemExit("Set the networks that may use the portal: --allow 10.10.0.0/16,10.20.0.0/16")
        nets = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
    if cfg["within"] not in nc.FLOW_PAN_PERIOD:
        raise SystemExit("within must be one of: " + ", ".join(nc.FLOW_PAN_PERIOD))
    cfg["port"], cfg["max_parallel"] = int(cfg["port"]), max(1, int(cfg["max_parallel"]))
    return cfg, nets


def do_serve(a):
    cfg, nets = load_config(a)
    STATE.update(cfg=cfg, allow=nets, busy=threading.BoundedSemaphore(cfg["max_parallel"]))
    if not os.path.exists(VAULT_FILE):
        raise SystemExit("No device logins yet: run  python flow_portal.py setup")
    pp = os.environ.pop("FLOW_PORTAL_PASSPHRASE", "") or getpass.getpass("Passphrase of %s: " % os.path.basename(VAULT_FILE))
    logins = vault_load(pp)
    del pp
    print("Connecting %d device(s) ..." % len(logins))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(8, len(logins)))) as ex:
        res = list(ex.map(connect, logins))
    for x, (ok, msg) in zip(logins, res):
        print("  %-28s %s" % (x.get("name"), "connected" if ok else "FAILED: " + msg))
        if not ok:
            STATE["failed"].append(x)
    threading.Thread(target=retry_failed, daemon=True).start()
    ThreadingHTTPServer.address_family = socket.AF_INET6 if ":" in cfg["bind"] else socket.AF_INET
    ThreadingHTTPServer.daemon_threads = True
    srv = ThreadingHTTPServer((cfg["bind"], cfg["port"]), Handler)
    scheme = "http"
    if cfg["cert"]:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cfg["cert"], cfg["key"] or None)
        # the TLS handshake runs in the request thread, so a slow client cannot hold up the others
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
        scheme = "https"
    elif not ipaddress.ip_address(cfg["bind"]).is_loopback:
        print("WARNING: no --cert / --key: the page is served over plain HTTP.")
    host = "[%s]" % cfg["bind"] if ":" in cfg["bind"] else cfg["bind"]
    print("Flow check portal on %s://%s:%d/ for %s. Audit log: %s. Ctrl+C to stop."
          % (scheme, host, cfg["port"], ", ".join(str(n) for n in nets), AUDIT_FILE))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def do_ref(ref):
    ref = ref.strip().upper()
    found = False
    for fn in (AUDIT_FILE + ".1", AUDIT_FILE):
        if not os.path.exists(fn):
            continue
        with open(fn, encoding="utf-8") as f:
            for line in f:
                if ref in line:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if rec.get("ref") == ref:
                        found = True
                        print(json.dumps(rec, indent=2, ensure_ascii=False))
    if not found:
        print("not found: " + ref)


# ---- page ----------------------------------------------------------------------------------------------------------
PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title><link rel="stylesheet" href="/app.css"></head>
<body><main>
<header><h1>__TITLE__</h1><p class="sub">Check whether the network lets your traffic through, and where it stops if it does not.</p></header>
<form id="f" class="card" novalidate>
 <div class="grid">
  <label>Source IP<input id="src" inputmode="decimal" autocomplete="off" spellcheck="false" placeholder="e.g. 10.10.5.20"><small id="srchint"></small></label>
  <label>Destination<input id="dst" autocomplete="off" spellcheck="false" placeholder="IP address or server name"><small>e.g. 10.20.1.15 or app.example.com</small></label>
  <label class="narrow">Port<input id="port" inputmode="numeric" autocomplete="off" placeholder="443"></label>
  <label class="narrow">Protocol<select id="proto"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
 </div>
 <div class="actions"><button id="go" type="submit">Check</button><span id="msg" role="status" aria-live="polite"></span></div>
</form>
<section id="res" hidden></section>
<section id="hist" class="card" hidden><h2>Recent checks (this browser tab)</h2><ul id="hl"></ul></section>
<footer id="foot"></footer>
</main><script src="/app.js"></script></body></html>
"""

CSS = """:root{--bg:#f5f6f8;--card:#fff;--fg:#1d2330;--mut:#5b6474;--line:#dfe3ea;--acc:#1f6feb;--accfg:#fff;
--ok:#137a4b;--okbg:#e7f6ee;--bad:#c42b1c;--badbg:#fdecea;--warn:#946200;--warnbg:#fff5d6;--chk:#5b6474;--chkbg:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2c3340;--acc:#4c8dff;--accfg:#fff;
--ok:#4cc38a;--okbg:#14301f;--bad:#ff7b72;--badbg:#3a1716;--warn:#e3b341;--warnbg:#332a10;--chk:#9aa3b2;--chkbg:#242a35}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:28px 16px 40px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:14px;margin:0 0 8px;color:var(--mut);font-weight:600}
.sub{margin:0 0 18px;color:var(--mut)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr) 100px 100px;gap:14px}.grid>label{min-width:0}
@media (max-width:700px){.grid{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}.grid label:not(.narrow){grid-column:1/-1}}
label{display:flex;flex-direction:column;gap:5px;font-size:13px;font-weight:600}
input,select{font:inherit;font-weight:400;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);width:100%;min-width:0}
input:focus,select:focus{outline:2px solid var(--acc);outline-offset:-1px}
small{font-weight:400;color:var(--mut);font-size:12px;min-height:1em}
.actions{display:flex;align-items:center;gap:14px;margin-top:16px;flex-wrap:wrap}
button{font:inherit;font-weight:600;border:0;border-radius:8px;padding:10px 22px;background:var(--acc);color:var(--accfg);cursor:pointer}
button:disabled{opacity:.6;cursor:progress}
button.sec{background:transparent;color:var(--acc);border:1px solid var(--line);padding:5px 12px;font-size:13px}
#msg{color:var(--mut)}#msg.err{color:var(--bad)}
.banner{border-radius:12px;padding:16px 18px;margin-bottom:14px;border:1px solid transparent}
.banner h3{margin:0 0 4px;font-size:19px}.banner p{margin:0}
.s-allowed{background:var(--okbg);color:var(--ok)}.s-blocked{background:var(--badbg);color:var(--bad)}
.s-unclear,.s-not_covered{background:var(--warnbg);color:var(--warn)}.s-error{background:var(--badbg);color:var(--bad)}
.banner p{color:var(--fg)}
.path{display:flex;align-items:stretch;gap:6px;margin:6px 0 14px}
.node{flex:1 1 0;min-width:0;border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:var(--card)}
.node .n{font-weight:600;overflow-wrap:anywhere}.node .st{font-size:12px;font-weight:600;margin-top:3px}
.node .why{font-size:12px;color:var(--mut);margin-top:4px}
.node.end{background:var(--chkbg)}.node.end .st{color:var(--mut);font-weight:400}
.node.passed{border-color:var(--ok)}.node.passed .st{color:var(--ok)}
.node.blocked{border-color:var(--bad);border-width:2px;background:var(--badbg)}.node.blocked .st{color:var(--bad)}
.node.unclear{border-color:var(--warn)}.node.unclear .st{color:var(--warn)}
.node.checked .st{color:var(--chk)}
.arrow{align-self:center;color:var(--mut);font-size:18px}
@media (max-width:700px){.path{flex-direction:column}.node{flex:0 0 auto}.arrow{transform:rotate(90deg);align-self:flex-start;margin-left:18px;line-height:1}}
.ref{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:14px}
.ref code{font:600 15px ui-monospace,Consolas,monospace;background:var(--chkbg);padding:3px 8px;border-radius:6px}
.mut{color:var(--mut);font-size:13px}
#hl{list-style:none;margin:0;padding:0}#hl li{display:flex;gap:10px;flex-wrap:wrap;padding:6px 0;border-top:1px solid var(--line);font-size:13px}
#hl li:first-child{border-top:0}#hl .tag{font-weight:600}#hl .t-allowed{color:var(--ok)}#hl .t-blocked,#hl .t-error{color:var(--bad)}
#hl .t-unclear,#hl .t-not_covered{color:var(--warn)}#hl a{color:var(--acc);cursor:pointer;text-decoration:underline}
footer{color:var(--mut);font-size:12px;margin-top:8px}
"""

JS = r"""(function(){
const $=id=>document.getElementById(id);
function el(tag,cls,txt){const e=document.createElement(tag);if(cls)e.className=cls;if(txt!=null)e.textContent=txt;return e}
const ST={passed:"Allows it",blocked:"Blocked here",unclear:"Could not confirm",checked:"Checked"};
const SN={allowed:"No block found",blocked:"Blocked",unclear:"Not confirmed",not_covered:"Not covered",error:"Error"};
let hist=[];try{hist=JSON.parse(sessionStorage.getItem("fc_hist")||"[]")}catch(e){}
fetch("/api/me").then(r=>r.json()).then(d=>{
  if(d.ip){$("srchint").textContent="This PC: "+d.ip;if(!$("src").value)$("src").value=d.ip}
  $("foot").textContent="Checks the configuration of "+d.devices+" network device(s). Every check is logged with your address."
}).catch(()=>{});
function render(d){
  const r=$("res");r.replaceChildren();r.hidden=false;
  const st=d.ok?d.status:"error";
  const b=el("div","banner s-"+st);b.appendChild(el("h3",null,d.ok?d.headline:"Check not completed"));
  b.appendChild(el("p",null,d.ok?d.detail:d.error));r.appendChild(b);
  if(d.ok){
    const c=el("div","card");c.appendChild(el("h2",null,"Path: "+d.src+" → "+d.dst+":"+d.port+"/"+d.proto.toUpperCase()));
    const p=el("div","path");
    const end=(n,s)=>{const x=el("div","node end");x.appendChild(el("div","n",n));x.appendChild(el("div","st",s));return x};
    p.appendChild(end(d.src,"Source"));
    (d.steps||[]).forEach(s=>{p.appendChild(el("span","arrow","→"));const x=el("div","node "+s.state);
      x.appendChild(el("div","n",s.name));x.appendChild(el("div","st",ST[s.state]||s.state));
      if(s.reason)x.appendChild(el("div","why",s.reason));p.appendChild(x)});
    p.appendChild(el("span","arrow","→"));p.appendChild(end(d.dst+":"+d.port,"Destination"));
    c.appendChild(p);
    if(!(d.steps||[]).length)c.appendChild(el("p","mut","No monitored network device is on this path."));
    r.appendChild(c);
  }
  if(d.ref){const c=el("div","card ref");c.appendChild(el("span",null,"Reference"));c.appendChild(el("code",null,d.ref));
    const cp=el("button","sec","Copy");cp.type="button";
    cp.onclick=()=>{const t=d.ref+" · "+d.src+" → "+d.dst+":"+d.port+"/"+(d.proto||"").toUpperCase()+" · "+(d.ok?d.headline:d.error);
      (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(()=>{cp.textContent="Copied"},()=>{cp.textContent="Select and copy"});
      setTimeout(()=>cp.textContent="Copy",2000)};
    c.appendChild(cp);c.appendChild(el("span","mut","Give this to the network team: they can see the full detail of this check."));r.appendChild(c)}
}
function drawHist(){const l=$("hl");l.replaceChildren();$("hist").hidden=!hist.length;
  hist.forEach(h=>{const li=el("li");li.appendChild(el("span","tag t-"+h.st,SN[h.st]||h.st));
    li.appendChild(el("span",null,h.src+" → "+h.dst+":"+h.port+"/"+h.proto.toUpperCase()));li.appendChild(el("span","mut",h.ref+" · "+h.at));
    const a=el("a",null,"check again");a.onclick=()=>{$("src").value=h.src;$("dst").value=h.dst;$("port").value=h.port;$("proto").value=h.proto;$("f").requestSubmit()};
    li.appendChild(a);l.appendChild(li)})}
drawHist();
$("f").addEventListener("submit",async ev=>{ev.preventDefault();
  const body={src:$("src").value.trim(),dst:$("dst").value.trim(),port:$("port").value.trim(),proto:$("proto").value};
  const m=$("msg");m.className="";
  if(!body.src||!body.dst||!body.port){m.className="err";m.textContent="Fill in the source, the destination and the port.";return}
  $("go").disabled=true;m.textContent="Checking every device on the path… this can take up to a minute.";
  let d;
  try{const r=await fetch("/api/check",{method:"POST",headers:{"Content-Type":"application/json","X-Flow-Portal":"1"},body:JSON.stringify(body)});
    d=await r.json()}catch(e){d={ok:false,error:"The portal did not answer. Try again in a moment."}}
  $("go").disabled=false;m.textContent="";render(d);
  if(d.ref){hist.unshift({ref:d.ref,src:body.src,dst:body.dst,port:body.port,proto:body.proto,st:d.ok?d.status:"error",at:(d.checked_at||"").slice(11,16)});
    hist=hist.slice(0,8);try{sessionStorage.setItem("fc_hist",JSON.stringify(hist))}catch(e){}drawHist()}
  $("res").scrollIntoView({behavior:"smooth",block:"start"});
});
})();
"""


def main():
    ap = argparse.ArgumentParser(description="Flow check portal for end users (see the top of this file).")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("setup", help="add / remove / test the device logins")
    s = sub.add_parser("serve", help="start the portal")
    s.add_argument("--bind", help="address to listen on (default 127.0.0.1)")
    s.add_argument("--port", type=int, help="port (default 8443)")
    s.add_argument("--allow", help="networks that may use it, comma separated (e.g. 10.10.0.0/16,10.20.0.0/16)")
    s.add_argument("--cert", help="TLS certificate (PEM, with the chain)")
    s.add_argument("--key", help="TLS private key (PEM)")
    s.add_argument("--logs", action="store_true", default=None, help="also search the firewall / F5 / Cloudflare logs (slower)")
    s.add_argument("--within", help="log time range with --logs (default 'last 24 hours')")
    s.add_argument("--max-parallel", dest="max_parallel", type=int, help="checks run at the same time (default 2)")
    s.add_argument("--title", help="page title")
    r = sub.add_parser("ref", help="show the full detail of one check from the audit log")
    r.add_argument("reference")
    a = ap.parse_args()
    if a.cmd == "setup":
        do_setup()
    elif a.cmd == "serve":
        do_serve(a)
    elif a.cmd == "ref":
        do_ref(a.reference)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
