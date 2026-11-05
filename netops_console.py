#!/usr/bin/env python3
"""
ITSec Ops - read-only troubleshooting for F5 BIG-IP, Palo Alto PAN-OS, FortiGate.

Run:   python3 netops_console.py            (Python 3.8+, standard library only)
Then open the URL printed in the terminal.

Design notes
- Binds to 127.0.0.1 only. A random per-launch token and Host-header check protect the
  local API from other web pages (CSRF / DNS rebinding).
- Credentials live in process memory only and are never written to disk. Packet captures
  you explicitly request are saved to ./captures next to this script.
- Saved device profiles keep only a label, vendor, management address/port, and TLS setting
  in device_profiles.json; usernames, passwords, and API keys are never saved.
- Read-only by construction: every check is a GET (F5, FortiGate) or a <show>/<test>
  operational command (PAN-OS; <test> limited to an allowlist). The raw box enforces the same rules.
- EXCEPTION: the 'F5 active tools' (log search, tcpdump) run fixed shell-command templates
  through iControl REST util/bash. They need the Administrator role and an explicit tick-box.
  The capture (and .pms key file) is kept in /var/tmp on the BIG-IP, readable by root only.
- EXCEPTION: 'Configuration backup' on F5 saves a UCS archive on the BIG-IP (same tick-box); on PAN-OS and
  FortiGate it is a read-only export with no tick-box. Backups are saved in ./captures and downloaded by the browser.
- EXCEPTION: the PAN-OS packet capture runs <debug><dataplane><packet-diag> commands (needs a tick-box). It
  clears all packet-diag settings before and after, which also ends any capture another admin has running.
- EXCEPTION: 'Download a file or folder' on F5 reads any path through util/bash (same tick-box); a folder is
  packed into a .tar.gz in /var/tmp first and removed afterwards. Files holding secrets need a second tick-box.
- The tool talks to device management APIs over HTTPS from THIS machine.
- AppSec checks (WAF / profile coverage, SSL posture, ASM request log,
  PAN log search) are read-only.
- Cloudflare: an API token (give it read permissions only). Configuration is read with REST GETs; analytics
  are POSTed to the GraphQL Analytics API, which only answers queries (the raw box refuses mutations).
"""
import argparse
import base64
import calendar
import collections
import concurrent.futures
import datetime
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape as xml_escape

TOKEN = secrets.token_urlsafe(24)
SESSIONS = {}   # id -> session dict (in memory only)
AUDIT = collections.deque(maxlen=1000)
LOCK = threading.Lock()
PARAM_RE = re.compile(r'^[A-Za-z0-9_.:/~ \-]{1,64}$')
HOST_RE = re.compile(r'^[A-Za-z0-9.\-:\[\]]{1,253}$')
# Some <test> commands act on the device (e.g. <test><vpn> starts IKE negotiation).
PAN_SAFE_TESTS = {"security-policy-match", "nat-policy-match", "routing", "url"}


def P(name, label, placeholder="", default="", required=True):
    return {"name": name, "label": label, "placeholder": placeholder,
            "default": default, "required": required}


# ----------------------------------------------------------------------------
# Check catalog. F5 / FortiGate: "path" is a GET. PAN-OS: "cmd" is an op command.
# Endpoint availability can differ by software version; use the raw box to adapt.
# ----------------------------------------------------------------------------
CATALOG = {
    "f5": [
        {"id": "version", "group": "Device", "label": "Software version", "path": "/mgmt/tm/sys/version"},
        {"id": "hardware", "group": "Device", "label": "Hardware / platform", "path": "/mgmt/tm/sys/hardware"},
        {"id": "license", "group": "Device", "label": "License", "path": "/mgmt/tm/sys/license"},
        {"id": "certs", "group": "Device", "label": "Certificates (expiry)", "path": "/mgmt/tm/sys/crypto/cert"},
        {"id": "failover", "group": "HA", "label": "Failover status", "path": "/mgmt/tm/cm/failover-status"},
        {"id": "sync", "group": "HA", "label": "Config sync status", "path": "/mgmt/tm/cm/sync-status"},
        {"id": "tgstats", "group": "HA", "label": "Traffic-group stats", "path": "/mgmt/tm/cm/traffic-group/stats"},
        {"id": "cpu", "group": "Resources", "label": "CPU", "path": "/mgmt/tm/sys/cpu"},
        {"id": "mem", "group": "Resources", "label": "Memory", "path": "/mgmt/tm/sys/memory"},
        {"id": "perf", "group": "Resources", "label": "Performance (all stats)", "path": "/mgmt/tm/sys/performance/all-stats"},
        {"id": "ifaces", "group": "Network", "label": "Interface stats", "path": "/mgmt/tm/net/interface/stats"},
        {"id": "vsall", "group": "LTM", "label": "All virtual server stats", "path": "/mgmt/tm/ltm/virtual/stats"},
        {"id": "vsone", "group": "LTM", "label": "One virtual server stats", "path": "/mgmt/tm/ltm/virtual/{vs}/stats",
         "params": [P("vs", "Virtual server", "~Common~my_vs")]},
        {"id": "polsearch", "group": "LTM", "label": "Local traffic policy search (rules and conditions)",
         "path": "/mgmt/tm/ltm/policy?expandSubcollections=true",
         "params": [P("policy", "Policy name (or part of it)", "my_policy")]},
        {"id": "poolall", "group": "LTM", "label": "All pool stats", "path": "/mgmt/tm/ltm/pool/stats"},
        {"id": "poolmem", "group": "LTM", "label": "Pool member stats", "path": "/mgmt/tm/ltm/pool/{pool}/members/stats",
         "params": [P("pool", "Pool", "~Common~my_pool")]},
    ],
    "paloalto": [
        {"id": "sysinfo", "group": "Device", "label": "System info", "cmd": "<show><system><info/></system></show>"},
        {"id": "resources", "group": "Device", "label": "System resources (top)", "cmd": "<show><system><resources/></system></show>"},
        {"id": "jobs", "group": "Device", "label": "Jobs (all)", "cmd": "<show><jobs><all/></jobs></show>"},
        {"id": "ha", "group": "HA", "label": "HA state", "cmd": "<show><high-availability><state/></high-availability></show>"},
        {"id": "ifaces", "group": "Network", "label": "Interfaces (all)", "cmd": "<show><interface>all</interface></show>"},
        {"id": "routes", "group": "Network", "label": "Routing table", "cmd": "<show><routing><route/></routing></show>"},
        {"id": "staticroutes", "group": "Network", "label": "Static routes (configured; optional filter)",
         "handler": "pan_static_routes",
         "params": [P("filter", "Destination IP/subnet, next hop, interface or name", "10.2.0.0/16", required=False)]},
        {"id": "fib", "group": "Network", "label": "FIB lookup", "cmd": "<test><routing><fib-lookup><virtual-router>{vr}</virtual-router><ip>{ip}</ip></fib-lookup></routing></test>",
         "params": [P("vr", "Virtual router", "default", "default"), P("ip", "Destination IP", "10.0.0.1")]},
        {"id": "sessions", "group": "Sessions", "label": "Session list (optional source / destination filter)",
         "handler": "pan_sessions",
         "params": [P("src", "Source IP", "10.1.1.10", required=False), P("dst", "Destination IP", "10.2.2.20", required=False),
                    P("count", "Max rows", "50", "50")]},
        {"id": "sessinfo", "group": "Sessions", "label": "Session info (counts, rates)", "cmd": "<show><session><info/></session></show>"},
        {"id": "sessbysrc", "group": "Sessions", "label": "Sessions by source IP", "cmd": "<show><session><all><filter><source>{src}</source></filter></all></session></show>",
         "params": [P("src", "Source IP", "10.1.1.10")]},
        {"id": "drops", "group": "Sessions", "label": "Global drop counters (delta)", "cmd": "<show><counter><global><filter><delta>yes</delta><severity>drop</severity></filter></global></counter></show>"},
        {"id": "nat", "group": "Policy", "label": "Destination / static NAT rules (Virtual IP equivalent; optional filter)",
         "handler": "pan_nat_rules",
         "params": [P("filter", "Name, public IP or translated IP", "203.0.113.10", required=False),
                    P("vsys", "vsys", "vsys1", "vsys1")]},
        {"id": "urlcat", "group": "Policy", "label": "URL category lookup", "cmd": "<test><url>{url}</url></test>",
         "params": [P("url", "URL or domain", "www.example.com/path")]},
    ],
    "fortigate": [
        {"id": "status", "group": "Device", "label": "System status", "path": "/api/v2/monitor/system/status"},
        {"id": "license", "group": "Device", "label": "License status", "path": "/api/v2/monitor/license/status"},
        {"id": "resources", "group": "Resources", "label": "Resource usage (CPU/mem/sessions)", "path": "/api/v2/monitor/system/resource/usage"},
        {"id": "ha", "group": "HA", "label": "HA peers", "path": "/api/v2/monitor/system/ha-peer"},
        {"id": "hachk", "group": "HA", "label": "HA checksums", "path": "/api/v2/monitor/system/ha-checksums"},
        {"id": "ifaces", "group": "Network", "label": "Interfaces", "path": "/api/v2/monitor/system/interface"},
        {"id": "routes", "group": "Network", "label": "IPv4 routing table", "path": "/api/v2/monitor/router/ipv4"},
        {"id": "staticroutes", "group": "Network", "label": "Static routes (configured; optional filter)",
         "path": "/api/v2/cmdb/router/static",
         "params": [P("filter", "Destination IP/subnet, gateway, interface or comment", "10.2.0.0/16", required=False)]},
        {"id": "vips", "group": "Policy", "label": "Virtual IPs (optional filter)", "path": "/api/v2/cmdb/firewall/vip",
         "params": [P("filter", "Name, external IP or mapped IP", "203.0.113.10", required=False)]},        {"id": "ipsec", "group": "VPN", "label": "IPsec tunnels", "path": "/api/v2/monitor/vpn/ipsec"},
        {"id": "polstats", "group": "Policy", "label": "Firewall policy hit counts", "path": "/api/v2/monitor/firewall/policy"},
        {"id": "sessions", "group": "Sessions", "label": "Session list (IPv4)", "path": "/api/v2/monitor/firewall/session?count={count}&ip_version=ipv4",
         "params": [P("count", "Max rows", "20", "20")]},
    ],
    "cloudflare": [
        {"id": "verify", "group": "Account", "label": "API token status (user-owned tokens)", "path": "/client/v4/user/tokens/verify"},
        {"id": "accounts", "group": "Account", "label": "Accounts visible to the token", "path": "/client/v4/accounts?per_page=50"},
        {"id": "zones", "group": "Zones", "label": "Zones (first 50)", "path": "/client/v4/zones?per_page=50"},
        {"id": "zone", "group": "Zones", "label": "Zone details", "path": "/client/v4/zones/{zone}",
         "params": [P("zone", "Zone name or ID", "example.com")]},
        {"id": "settings", "group": "Zones", "label": "All zone settings", "path": "/client/v4/zones/{zone}/settings",
         "params": [P("zone", "Zone name or ID", "example.com")]},
        {"id": "dns", "group": "DNS", "label": "DNS records (first 100)", "path": "/client/v4/zones/{zone}/dns_records?per_page=100",
         "params": [P("zone", "Zone name or ID", "example.com")]},
        {"id": "rulesets", "group": "Security", "label": "Rulesets of a zone", "path": "/client/v4/zones/{zone}/rulesets",
         "params": [P("zone", "Zone name or ID", "example.com")]},
        {"id": "certs", "group": "SSL/TLS", "label": "Edge certificate packs",
         "path": "/client/v4/zones/{zone}/ssl/certificate_packs?status=all", "params": [P("zone", "Zone name or ID", "example.com")]},
        {"id": "ips", "group": "Reference", "label": "Cloudflare edge IP ranges", "path": "/client/v4/ips"},
    ],
}
CATALOG_PUBLIC = CATALOG  # contains no secrets
PROFILE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_profiles.json")
HEALTH_CHECKS = {
    "f5": ("version", "failover", "cpu", "mem"),
    "paloalto": ("sysinfo", "resources", "ha"),
    "fortigate": ("status", "resources", "ha"),
    "cloudflare": ("zones", "ips"),
}


# ----------------------------------------------------------------------------
# Transport
# ----------------------------------------------------------------------------
def http_full(sess, method, path, headers=None, data=None, timeout=20):
    if not HOST_RE.match(str(sess["host"])) or not str(path).startswith("/"):
        raise ValueError("invalid host or path")
    url = "https://%s:%d%s" % (sess["host"], sess["port"], path)
    ctx = ssl.create_default_context()
    if sess["insecure"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    # HTTPS-only opener: no file:// / ftp:// handlers, regardless of the URL.
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.HTTPSHandler(context=ctx))
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def http(sess, method, path, headers=None, data=None, timeout=20):
    st, _, body = http_full(sess, method, path, headers, data, timeout)
    return st, body


def x2o(e):
    """Convert an XML element to plain JSON-able structures for display."""
    kids = list(e)
    attrs = {"@" + k: v for k, v in e.attrib.items()}
    text = (e.text or "").strip()
    if not kids:
        if attrs:
            if text:
                attrs["#text"] = text
            return attrs
        return text
    out = dict(attrs)
    for k in kids:
        v = x2o(k)
        if k.tag in out:
            if not isinstance(out[k.tag], list):
                out[k.tag] = [out[k.tag]]
            out[k.tag].append(v)
        else:
            out[k.tag] = v
    return out


def pan_op(sess, cmd):
    body = urllib.parse.urlencode({"type": "op", "cmd": cmd}).encode()
    status, raw = http(sess, "POST", "/api/", {"X-PAN-KEY": sess["key"],
                       "Content-Type": "application/x-www-form-urlencoded"}, body)
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return status, False, raw.decode("utf-8", "replace")
    return status, root.get("status") == "success", x2o(root)


def rest_get(sess, path):
    status, raw = http(sess, "GET", path, sess["hdr"])
    try:
        data = json.loads(raw)
    except ValueError:
        data = raw.decode("utf-8", "replace")
    return status, 200 <= status < 300, data


def execute(sess, spec):
    """spec = {'path': ...} or {'cmd': ...}. Returns a result dict."""
    t0 = time.time()
    if sess["vendor"] == "paloalto":
        status, ok, data = pan_op(sess, spec["cmd"])
        req = spec["cmd"]
    else:
        status, ok, data = rest_get(sess, spec["path"])
        req = "GET " + spec["path"]
    return {"ok": ok, "status": status, "data": data, "request": req,
            "ms": int((time.time() - t0) * 1000)}


def audit(sess, what):
    with LOCK:
        AUDIT.append({"t": time.strftime("%H:%M:%S"), "device": sess["name"], "action": what})


def load_profiles():
    if not os.path.exists(PROFILE_FILE):
        return []
    with open(PROFILE_FILE, "r", encoding="utf-8") as f:
        profiles = json.load(f)
    if not isinstance(profiles, list) or any(not isinstance(p, dict) for p in profiles):
        raise ValueError("saved device profiles have an invalid format")
    clean = []
    for p in profiles:
        if (not isinstance(p.get("id"), str) or not re.match(r"^[0-9a-f]{12}$", p["id"]) or
                not isinstance(p.get("name"), str) or not 1 <= len(p["name"]) <= 40 or
                not isinstance(p.get("vendor"), str) or p["vendor"] not in CATALOG or
                not isinstance(p.get("host"), str) or not HOST_RE.match(p["host"]) or
                isinstance(p.get("port"), bool) or not isinstance(p.get("port"), int) or
                not 1 <= p["port"] <= 65535 or not isinstance(p.get("insecure"), bool)):
            raise ValueError("saved device profiles have an invalid entry")
        clean.append({"id": p["id"], "name": p["name"], "vendor": p["vendor"],
                      "host": p["host"], "port": p["port"], "insecure": p["insecure"]})
    if len(clean) > 100:
        raise ValueError("saved device profiles exceed the 100-profile limit")
    return clean


def save_profiles(profiles):
    temp = PROFILE_FILE + ".tmp"
    try:
        with open(temp, "w", encoding="utf-8") as f:
            json.dump(profiles, f, indent=2)
        os.replace(temp, PROFILE_FILE)
    finally:
        if os.path.exists(temp):
            os.remove(temp)


def profile_from_request(b):
    if not isinstance(b, dict):
        raise ValueError("profile must be a JSON object")
    vendor = b.get("vendor")
    if not isinstance(vendor, str) or vendor not in CATALOG:
        raise ValueError("unknown vendor")
    name_value = b.get("name")
    host_value = b.get("host")
    if not isinstance(name_value, str) or not isinstance(host_value, str):
        raise ValueError("profile name and host must be text")
    name = name_value.strip()
    host = host_value.strip()
    if not name or len(name) > 40:
        raise ValueError("profile name must be between 1 and 40 characters")
    if not HOST_RE.match(host):
        raise ValueError("invalid host")
    try:
        port = int(b.get("port") or 443)
    except (TypeError, ValueError):
        raise ValueError("invalid port")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return {"id": secrets.token_hex(6), "name": name, "vendor": vendor,
            "host": host, "port": port, "insecure": b.get("insecure") is True}


def do_profile_save(b):
    try:
        profile = profile_from_request(b)
        with LOCK:
            profiles = load_profiles()
            if len(profiles) >= 100:
                return {"ok": False, "error": "maximum of 100 saved profiles reached"}
            profiles.append(profile)
            save_profiles(profiles)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        return {"ok": False, "error": "could not save profile: %s" % e}
    return {"ok": True, "profile": profile}


def do_profile_delete(b):
    profile_id = b.get("id")
    if not isinstance(profile_id, str) or not re.match(r"^[0-9a-f]{12}$", profile_id):
        return {"ok": False, "error": "invalid profile"}
    try:
        with LOCK:
            profiles = load_profiles()
            updated = [p for p in profiles if p.get("id") != profile_id]
            if len(updated) == len(profiles):
                return {"ok": False, "error": "saved profile not found"}
            save_profiles(updated)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        return {"ok": False, "error": "could not delete profile: %s" % e}
    return {"ok": True}


def do_health(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess:
        return {"ok": False, "error": "device not connected"}
    specs = [next(c for c in CATALOG[sess["vendor"]] if c["id"] == check)
             for check in HEALTH_CHECKS[sess["vendor"]]]
    checks = []
    for spec in specs:
        try:
            run = {"cmd": spec["cmd"]} if "cmd" in spec else {"path": spec["path"]}
            audit(sess, "health: " + spec["label"])
            result = execute(sess, run)
            checks.append({"id": spec["id"], "label": spec["label"], "ok": result["ok"],
                           "status": result["status"], "ms": result["ms"],
                           "error": "" if result["ok"] else
                           "device returned HTTP %s or an unsuccessful vendor response" % result["status"]})
        except (urllib.error.URLError, OSError) as e:
            checks.append({"id": spec["id"], "label": spec["label"], "ok": False,
                           "error": "request failed: %s" % getattr(e, "reason", e)})
    passed = sum(1 for check in checks if check["ok"])
    return {"ok": passed == len(checks), "status": 200, "ms": sum(c.get("ms", 0) for c in checks),
            "request": "health snapshot", "data": {"checks": checks},
            "verdict": {"label": "%d of %d checks responded successfully" % (passed, len(checks)),
                        "kind": "ok" if passed == len(checks) else "bad"},
            "summary": ["Reachability/API-response summary only; inspect device-specific state and thresholds separately."]}


# ----------------------------------------------------------------------------
# Actions
# ----------------------------------------------------------------------------
def do_connect(b):
    vendor = b.get("vendor")
    if vendor not in CATALOG:
        return {"ok": False, "error": "unknown vendor"}
    host = CF_HOST if vendor == "cloudflare" else (b.get("host") or "").strip()
    if not HOST_RE.match(host):
        return {"ok": False, "error": "invalid host"}
    try:
        port = 443 if vendor == "cloudflare" else int(b.get("port") or 443)
    except (TypeError, ValueError):
        return {"ok": False, "error": "invalid port"}
    if not 1 <= port <= 65535:
        return {"ok": False, "error": "port must be between 1 and 65535"}
    name = b.get("name")
    name = name.strip() if isinstance(name, str) else ""
    sess = {"vendor": vendor, "host": host, "port": port,
            "insecure": bool(b.get("insecure")) and vendor != "cloudflare",
            "name": (name or ("Cloudflare" if vendor == "cloudflare" else host))[:40]}
    user, pw, key = b.get("username", ""), b.get("password", ""), b.get("apikey", "")
    try:
        if vendor == "f5":
            if not user or not pw:
                return {"ok": False, "error": "username and password required"}
            cred = base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()
            sess["hdr"] = {"Authorization": "Basic " + cred}
            status, ok, data = rest_get(sess, "/mgmt/tm/sys/version")
            if ok and not isinstance(data, dict):
                return {"ok": False, "error": "this address did not answer like a BIG-IP (got a non-JSON "
                                              "page). Check the host/port and the selected vendor."}
        elif vendor == "fortigate":
            if not key:
                return {"ok": False, "error": "REST API token required"}
            sess["hdr"] = {"Authorization": "Bearer " + key}
            status, ok, data = rest_get(sess, "/api/v2/monitor/system/status")
            if ok and not isinstance(data, dict):
                return {"ok": False, "error": "this address did not answer like a FortiGate (got a non-JSON "
                                              "page). Check the host/port and the selected vendor."}
        elif vendor == "cloudflare":
            if not key:
                return {"ok": False, "error": "Cloudflare API token required"}
            acct = str(b.get("account") or "").strip().lower()
            if acct and not CF_ID_RE.match(acct):
                return {"ok": False, "error": "Account ID must be 32 hex characters (or leave it blank)"}
            sess["hdr"], sess["account"] = {"Authorization": "Bearer " + key}, acct
            status, ok, data = cf_get(sess, "/user/tokens/verify")
            if not ok and acct:
                status, ok, data = cf_get(sess, "/accounts/%s/tokens/verify" % acct)
            if ok and str((data.get("result") or {}).get("status")) != "active":
                return {"ok": False, "error": "the token is not active (status: %s)" % (data.get("result") or {}).get("status")}
            if not ok:   # account-owned token without an Account ID: listing zones still proves it works
                status, ok, data = cf_get(sess, "/zones?per_page=5")
            if not ok:
                return {"ok": False, "error": "Cloudflare rejected the token (%s)" % cf_errtext(status, data)}
            note = cf_load(sess)
        else:
            if not key:
                if not user or not pw:
                    return {"ok": False, "error": "API key, or username and password, required"}
                body = urllib.parse.urlencode({"type": "keygen", "user": user, "password": pw}).encode()
                st, raw = http(sess, "POST", "/api/", {"Content-Type": "application/x-www-form-urlencoded"}, body)
                root = ET.fromstring(raw)
                key = root.findtext(".//key") or ""
                if root.get("status") != "success" or not key:
                    return {"ok": False, "error": "key generation failed (HTTP %d)" % st}
            sess["key"] = key
            status, ok, data = pan_op(sess, "<show><system><info/></system></show>")
    except (urllib.error.URLError, OSError, ET.ParseError) as e:
        return {"ok": False, "error": "connection failed: %s" % getattr(e, "reason", e)}
    if not ok:
        return {"ok": False, "error": "device rejected the request (HTTP %s)" % status}
    sid = secrets.token_hex(6)
    with LOCK:
        SESSIONS[sid] = sess
    audit(sess, "connected")
    out = {"ok": True, "id": sid, "name": sess["name"], "vendor": vendor, "host": host}
    if vendor == "cloudflare":
        out.update(zones=[z["name"] for z in sess["zones"]], note=note,
                   accounts=len(sess.get("accounts") or {}))
    return out


def fill(template, params, spec, vendor):
    for p in spec.get("params", []):
        v = (params.get(p["name"]) or p["default"]).strip()
        if not v and not p.get("required", True):
            template = template.replace("{" + p["name"] + "}", "")
            continue
        if not v:
            raise ValueError("missing: " + p["label"])
        if not PARAM_RE.match(v):
            raise ValueError("invalid characters in: " + p["label"])
        v = xml_escape(v) if vendor == "paloalto" else urllib.parse.quote(v, safe="~")
        template = template.replace("{" + p["name"] + "}", v)
    return template


def do_run(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess:
        return {"ok": False, "error": "device not connected"}
    spec = next((c for c in CATALOG[sess["vendor"]] if c["id"] == b.get("check")), None)
    if not spec:
        return {"ok": False, "error": "unknown check"}
    try:
        if sess["vendor"] == "f5" and spec["id"] in ("vsone", "poolmem"):
            # Accept /Common/name, ~Common~name or a bare name (assumed to be in /Common).
            b = dict(b, params=dict(b.get("params") or {}))
            for k in ("vs", "pool"):
                raw = str(b["params"].get(k) or "").strip().replace("/", "~")
                if raw:
                    b["params"][k] = raw if raw.startswith("~") else "~Common~" + raw
        if sess["vendor"] == "cloudflare" and str((b.get("params") or {}).get("zone") or "").strip():
            b = dict(b, params=dict(b["params"], zone=cf_zones(sess, b["params"]["zone"], allow_all=False)[0]["id"]))
        if spec.get("handler"):
            vals = {}
            for p_ in spec.get("params", []):
                v = (str((b.get("params") or {}).get(p_["name"]) or "") or p_["default"]).strip()
                if v and not PARAM_RE.match(v):
                    raise ValueError("invalid characters in: " + p_["label"])
                if not v and p_.get("required", True):
                    raise ValueError("missing: " + p_["label"])
                vals[p_["name"]] = v
            audit(sess, spec["label"])
            return PAN_HANDLERS[spec["handler"]](sess, vals)
        if "cmd" in spec:
            run = {"cmd": fill(spec["cmd"], b.get("params", {}), spec, sess["vendor"])}
        else:
            run = {"path": fill(spec["path"], b.get("params", {}), spec, sess["vendor"])}
        audit(sess, spec["label"])
        result = execute(sess, run)
        if sess["vendor"] == "f5" and spec["id"] in ("vsall", "vsone") and result.get("ok"):
            rows = f5_vs_overview(sess, (b.get("params") or {}).get("vs") if spec["id"] == "vsone" else None,
                                  result.get("data"))
            if rows:
                result["data"] = {"virtual_servers": rows}
        if sess["vendor"] == "f5" and spec["id"] == "polsearch" and result.get("ok"):
            rows = f5_policy_search(sess, str((b.get("params") or {}).get("policy") or "").strip())
            result["data"] = {"policies": rows} if rows else {"policies": [], "note": "no local traffic policy matches that name"}
        if sess["vendor"] == "f5" and spec["id"] in ("poolall", "poolmem") and result.get("ok"):
            rows = f5_pool_overview(sess, (b.get("params") or {}).get("pool") if spec["id"] == "poolmem" else None)
            if rows:
                result["data"] = {"pool_members": rows}
        if sess["vendor"] == "fortigate" and spec["id"] in ("vips", "staticroutes") and result.get("ok"):
            term = str((b.get("params") or {}).get("filter") or "").strip()
            fn = fg_vip_rows if spec["id"] == "vips" else fg_static_route_rows
            result["data"] = fn(result.get("data"), term)
        if sess["vendor"] == "fortigate" and spec["id"] == "sessions" and result.get("status") == 404:
            # Newer FortiOS (7.4+/7.6) renamed the session monitor endpoint; try the variants read-only.
            tried = [result["request"] + " -> HTTP 404"]
            for alt in ("/api/v2/monitor/firewall/sessions?count=%s&ip_version=ipv4",
                        "/api/v2/monitor/firewall/sessions?count=%s",
                        "/api/v2/monitor/firewall/session?count=%s"):
                n = urllib.parse.quote((b.get("params") or {}).get("count") or "20", safe="")
                alt_res = execute(sess, {"path": alt % n})
                if alt_res.get("ok"):
                    result = alt_res
                    break
                tried.append("%s -> HTTP %s" % (alt_res["request"], alt_res["status"]))
            else:
                result["data"] = {"note": "No session-list endpoint answered on this FortiOS version.", "attempts": tried}
        if spec["id"] == "ifaces" and sess["vendor"] in ("fortigate", "paloalto") and result.get("ok"):
            result["data"] = (fg_iface_rows(sess, result.get("data")) if sess["vendor"] == "fortigate"
                              else pan_iface_rows(result.get("data")))
        if sess["vendor"] == "fortigate" and spec["id"] == "sessions" and result.get("ok"):
            result["data"] = fg_session_rows(result.get("data"))
        return result
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}


def f5_stat_status(stats):
    """{tmName: 'available' | 'offline' | 'disabled' ...} from a /stats collection (availability + enabled state)."""
    out = {}
    for e in ((stats or {}).get("entries") or {}).values() if isinstance(stats, dict) else []:
        ne = (e.get("nestedStats") or {}).get("entries") or {}

        def val(k):
            x = ne.get(k) or {}
            return str(x.get("description") if "description" in x else x.get("value", ""))
        name = val("tmName")
        if name:
            enabled = val("status.enabledState")
            out[name] = enabled if enabled and enabled != "enabled" else (val("status.availabilityState") or "unknown")
    return out


def f5_vs_overview(sess, vs, vs_stats):
    """One row per virtual server / pool member: names, member IPs and the VS, pool and member status."""
    only = "/" + vs.strip("~").replace("~", "/") if vs else None
    okv, dv = f5_get(sess, "/mgmt/tm/ltm/virtual?expandSubcollections=true")
    okp, dp = f5_get(sess, "/mgmt/tm/ltm/pool?expandSubcollections=true")
    if not okv:
        return None
    _, _, ps = rest_get(sess, "/mgmt/tm/ltm/pool/stats")
    vstat = f5_stat_status((vs_stats or {}) if isinstance(vs_stats, dict) else {})
    pstat = f5_stat_status(ps if isinstance(ps, dict) else {})
    pools = {p.get("fullPath"): p for p in (dp.get("items", []) if okp else [])}
    rows = []

    cur = {}  # destination of the virtual server being written

    def row(vname, pool, ip, vst, pst, mst, via=""):
        rows.append({"vs_name": vname, "vip": cur.get("vip", ""), "port": cur.get("port", ""),
                     "pool_name": pool, "pool_member_ip": ip,
                     "vs_status": vst, "pool_status": pst, "member_status": mst, "local_traffic_policy": via})

    def emit(vname, pool, vst, via=""):
        pst = pstat.get(pool, "")
        members = (pools.get(pool, {}).get("membersReference") or {}).get("items", [])
        if not members:
            row(vname, pool, "", vst, pst, "", via)
        for i, m in enumerate(members):
            sess_state = m.get("session") or ""
            mstat = str(m.get("state") or "") + (" / " + sess_state if sess_state not in ("", "monitor-enabled") else "")
            row(vname, pool, "%s:%s" % (strip_rd(m.get("address")), f5_member_port(m.get("name"))), vst, pst, mstat,
                via if i == 0 else "")
    for v in dv.get("items", []):
        if only and v.get("fullPath") != only:
            continue
        vname, pool = v.get("fullPath"), v.get("pool") or ""
        vst = vstat.get(vname, "")
        dest = (v.get("destination") or "").rsplit("/", 1)[-1]
        cur["vip"], cur["port"] = f5_dest_ip(v.get("destination")), f5_member_port(dest)
        if pool:
            emit(vname, pool, vst)
            continue
        # No default pool: one row naming the attached local traffic polic(ies), not one row per pooled member.
        names = [pr.get("fullPath") or "/%s/%s" % (pr.get("partition", "Common"), pr.get("name"))
                 for pr in (v.get("policiesReference") or {}).get("items", [])]
        row(vname, "", "", vst, "", "", ", ".join(names))
    return rows


def f5_member_port(name):
    name = str(name or "")
    return name.rsplit(".", 1)[-1] if name.count(":") > 1 else name.rsplit(":", 1)[-1]


def f5_pool_overview(sess, pool):
    """One row per pool member: pool, member IP:port, status, load-balancing method, current connections."""
    only = "/" + pool.strip("~").replace("~", "/") if pool else None
    okp, dp = f5_get(sess, "/mgmt/tm/ltm/pool?expandSubcollections=true")
    if not okp:
        return None
    pools = [p for p in dp.get("items", []) if not only or p.get("fullPath") == only]

    def conns(p):
        try:
            _, ok, d = rest_get(sess, "/mgmt/tm/ltm/pool/%s/members/stats" % (p.get("fullPath") or "").replace("/", "~"))
        except (urllib.error.URLError, OSError):
            return {}
        out = {}
        for e in ((d or {}).get("entries") or {}).values() if ok and isinstance(d, dict) else []:
            ne = (e.get("nestedStats") or {}).get("entries") or {}
            addr = strip_rd((ne.get("addr") or {}).get("description", ""))
            port = str((ne.get("port") or {}).get("value", ""))
            out[(addr, port)] = (ne.get("serverside.curConns") or {}).get("value", "")
        return out
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        stats = list(ex.map(conns, pools))
    rows = []
    for p, cs in zip(pools, stats):
        base = {"pool_name": p.get("fullPath"), "lb_method": p.get("loadBalancingMode", "")}
        members = (p.get("membersReference") or {}).get("items", [])
        if not members:
            rows.append(dict(base, pool_member_ip="", member_status="", current_connections=""))
        for m in members:
            addr, port, sess_state = strip_rd(m.get("address")), f5_member_port(m.get("name")), m.get("session") or ""
            rows.append({"pool_name": base["pool_name"], "pool_member_ip": "%s:%s" % (addr, port),
                         "member_status": str(m.get("state") or "") + (
                             " / " + sess_state if sess_state not in ("", "monitor-enabled") else ""),
                         "lb_method": base["lb_method"], "current_connections": cs.get((addr, port), "")})
    return rows


def do_raw(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess:
        return {"ok": False, "error": "device not connected"}
    q = (b.get("query") or "").strip()
    v = sess["vendor"]
    if v == "paloalto":
        try:
            root = ET.fromstring(q)
        except ET.ParseError:
            return {"ok": False, "error": "not well-formed XML"}
        if root.tag not in ("show", "test"):
            return {"ok": False, "error": "only <show> and <test> commands are allowed"}
        if root.tag == "test" and (len(root) != 1 or root[0].tag not in PAN_SAFE_TESTS):
            return {"ok": False, "error": "only these <test> commands are allowed: " +
                    ", ".join(sorted(PAN_SAFE_TESTS))}
        run = {"cmd": q}
    elif v == "cloudflare" and q.startswith(("{", "query")):
        if re.search(r"\b(mutation|subscription)\b", q):
            return {"ok": False, "error": "only GraphQL queries are allowed"}
        audit(sess, "raw GraphQL: " + q[:120])
        t0 = time.time()
        try:
            ok, data, errs = cf_gql(sess, q)
        except (urllib.error.URLError, OSError) as e:
            return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
        return {"ok": ok, "status": 200, "data": data if ok else {"errors": errs, "data": data},
                "request": "POST /client/v4/graphql", "ms": int((time.time() - t0) * 1000)}
    else:
        prefixes = ("/mgmt/tm/",) if v == "f5" else ("/client/v4/",) if v == "cloudflare" else \
            ("/api/v2/monitor/", "/api/v2/cmdb/")
        if not q.startswith(prefixes) or ".." in q or "\n" in q or "\r" in q:
            return {"ok": False, "error": "path must start with " + " or ".join(prefixes)}
        run = {"path": q}
    audit(sess, "raw: " + q[:120])
    try:
        return execute(sess, run)
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}


def do_disconnect(b):
    with LOCK:
        s = SESSIONS.pop(b.get("id"), None)
    if s:
        audit(s, "disconnected")
    return {"ok": True}


# ----------------------------------------------------------------------------
# IP lookup (all vendors) + F5 active tools (log search, packet capture)
# ----------------------------------------------------------------------------
CAPTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures")
F5_LOGS = ("ltm", "audit", "apm", "gtm", "tmm", "asm")
IFACE_RE = re.compile(r'^(?!-)[0-9A-Za-z_.:\-]{1,32}$')   # no leading '-': it would be read as a tcpdump option
FILE_RE = re.compile(r'^[A-Za-z0-9_.\-]{1,120}\.(pcap|pms|ucs|xml|conf)$')
DL_RE = re.compile(r'^f5file_[A-Za-z0-9_.\-]{1,200}$')   # files saved by the F5 file download (any extension)


def tok_ok(value):
    """Constant-time token check on bytes, so odd (non-ASCII) input is a plain mismatch, never an exception."""
    return secrets.compare_digest(str(value or "").encode("utf-8", "replace"), TOKEN.encode())
MAX_PCAP = 300 * 1024 * 1024
MAX_BACKUP = 2 * 1024 * 1024 * 1024


def hget(h, name):
    for k, v in (h or {}).items():
        if k.lower() == name.lower():
            return v
    return None


def as_list(x):
    return x if isinstance(x, list) else ([] if x is None else [x])


def strip_rd(a):
    return (a or "").split("%", 1)[0]


def ip_in_spec(ip, spec):
    """True if ip falls inside spec: literal IP, CIDR, 'a-b' range, or 'a.b.c.d m.m.m.m'."""
    spec = (spec or "").strip()
    if not spec:
        return False
    try:
        if "-" in spec and "/" not in spec and " " not in spec:
            a, b = [ipaddress.ip_address(x.strip()) for x in spec.split("-", 1)]
            return a <= ip <= b
        if " " in spec:
            net = ipaddress.ip_network("%s/%s" % tuple(spec.split()[:2]), strict=False)
        else:
            net = ipaddress.ip_network(spec, strict=False)
        return ip in net
    except (ValueError, TypeError):
        return False


def ip_is_exact(ip, spec):
    """True only if spec is this very address (a single-host /32 or /128 counts); never a wider CIDR or range."""
    try:
        return ipaddress.ip_address(ip) == ipaddress.ip_address(str(spec).strip()) if "/" not in str(spec) else \
            ipaddress.ip_network(str(spec).strip(), strict=False).prefixlen == ip.max_prefixlen and \
            ipaddress.ip_network(str(spec).strip(), strict=False).network_address == ip
    except (ValueError, TypeError):
        return False


def f5_dest_ip(dest):
    d = (dest or "").rsplit("/", 1)[-1]
    d = d.rsplit(".", 1)[0] if d.count(":") > 1 else d.rsplit(":", 1)[0]
    return strip_rd(d)


def num(v, lo, hi, default, label):
    v = default if v in (None, "") else v
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError(label + " must be a number")
    if not lo <= n <= hi:
        raise ValueError("%s must be %d-%d" % (label, lo, hi))
    return n


def pstr(v, label):
    v = (v or "").strip()
    if v and not PARAM_RE.match(v):
        raise ValueError("invalid characters in: " + label)
    return v


def parse_ip(v, label):
    try:
        return ipaddress.ip_address((v or "").strip())
    except ValueError:
        raise ValueError("%s is not a valid IP address" % label)


def parse_ip_or_net(v, label):
    """A single IP, or a subnet in CIDR form (10.2.64.0/24)."""
    s = (v or "").strip()
    try:
        return ipaddress.ip_network(s, strict=False) if "/" in s else ipaddress.ip_address(s)
    except ValueError:
        raise ValueError("%s is not a valid IP address or subnet (use e.g. 10.2.64.0/24)" % label)


def ip_matches(val, target):
    """True if the log value `val` is the IP, or inside the subnet, `target`."""
    try:
        a = ipaddress.ip_address(str(val).strip())
    except ValueError:
        return False
    return a in target if isinstance(target, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else a == target


# ---- F5: where does this IP appear in the configuration? --------------------
def f5_get(sess, path):
    st, ok, data = rest_get(sess, path)
    return (ok and isinstance(data, dict)), data


def f5_lookup(sess, ip):
    notes, pool_vs = [], {}
    res = {"pools": [], "nodes": [], "virtual_servers": [], "data_groups": []}
    ok, d = f5_get(sess, "/mgmt/tm/ltm/virtual?expandSubcollections=true")
    policy_vs = {}  # policy -> virtual servers it is attached to
    if ok:
        for v in d.get("items", []):
            if v.get("pool"):
                pool_vs.setdefault(v["pool"], []).append(v.get("fullPath"))
            for pr in (v.get("policiesReference") or {}).get("items", []):
                policy_vs.setdefault(pr.get("fullPath") or "/%s/%s" % (pr.get("partition", "Common"), pr.get("name")),
                                     []).append(v.get("fullPath"))
            hit = []
            if ip_in_spec(ip, f5_dest_ip(v.get("destination"))):
                hit.append("destination")
            src = v.get("source", "")
            src_net = re.sub(r"%\d+", "", src)  # drop route domain, keep the mask
            if src_net not in ("", "0.0.0.0/0", "::/0", "any", "any6") and ip_in_spec(ip, src_net):
                hit.append("source")
            if hit:
                res["virtual_servers"].append({"virtual": v.get("fullPath"), "matched": hit,
                                               "destination": v.get("destination"), "source": src,
                                               "pool": v.get("pool")})
    else:
        notes.append("could not read virtual servers")
    # Pools that local traffic policy rules forward to: pool -> [{policy, rule, virtual_servers}]
    pool_pol = {}
    okpol, dpol = f5_get(sess, "/mgmt/tm/ltm/policy?expandSubcollections=true")
    for pol in (dpol.get("items", []) if okpol else []):
        for r in (pol.get("rulesReference") or {}).get("items", []):
            for a in (r.get("actionsReference") or {}).get("items", []):
                if a.get("forward") and a.get("pool"):
                    pool_pol.setdefault(a["pool"], []).append(
                        {"policy": pol.get("fullPath"), "rule": r.get("name"),
                         "virtual_servers": policy_vs.get(pol.get("fullPath"), [])})
    ok, d = f5_get(sess, "/mgmt/tm/ltm/pool?expandSubcollections=true")
    if ok:
        for p in d.get("items", []):
            for m in (p.get("membersReference") or {}).get("items", []):
                if ip_in_spec(ip, strip_rd(m.get("address"))):
                    via = pool_pol.get(p.get("fullPath"), [])
                    res["pools"].append({"pool": p.get("fullPath"), "member": m.get("name"),
                                         "state": m.get("state"), "session": m.get("session"),
                                         "virtual_servers": pool_vs.get(p.get("fullPath"), []),
                                         "local_traffic_policies": ["%s (rule: %s)" % (x["policy"], x["rule"]) for x in via],
                                         "policy_virtual_servers": sorted({vs for x in via for vs in x["virtual_servers"]})})
    else:
        notes.append("could not read pools")
    ok, d = f5_get(sess, "/mgmt/tm/ltm/node")
    if ok:
        for n in d.get("items", []):
            if ip_in_spec(ip, strip_rd(n.get("address"))):
                res["nodes"].append({"node": n.get("fullPath"), "state": n.get("state"),
                                     "session": n.get("session")})
    else:
        notes.append("could not read nodes")
    ok, d = f5_get(sess, "/mgmt/tm/ltm/data-group/internal?expandSubcollections=true")
    if ok:
        for g in d.get("items", []):
            if g.get("type") != "ip":
                continue
            recs = [r.get("name") for r in g.get("records", [])
                    if ip_in_spec(ip, r.get("name"))
                    and not (g.get("fullPath") == "/Common/private_net" and r.get("name") == "10.0.0.0/8")]
            if recs:
                res["data_groups"].append({"data_group": g.get("fullPath"), "matching_records": recs})
    else:
        notes.append("could not read internal data groups")
    ok, d = f5_get(sess, "/mgmt/tm/ltm/data-group/external")
    if ok and d.get("items"):
        notes.append("%d external data group(s) exist and were NOT searched (file contents are not exposed here)"
                     % len(d["items"]))
    ph = f5_policy_ip_hits(sess, ip)
    if ph is None:
        notes.append("could not read local traffic policies")
    else:
        res["local_traffic_policies"] = ph
    notes.append("Local traffic policies: only rule conditions listing the IP (address, subnet or range) are matched; "
                 "iRules are not searched.")
    notes.append("Configuration lookup only: FQDN nodes are not resolved, and this does not prove live traffic.")
    res["notes"] = notes
    summary = []
    for h in res["pools"]:
        summary.append("Pool member in %s (%s, state=%s, session=%s); used by virtual(s): %s" % (
            h["pool"], h["member"], h["state"], h["session"], ", ".join(h["virtual_servers"]) or "none"))
        if h["local_traffic_policies"]:
            summary.append("  Pool %s is a forward target of local traffic policy: %s; reached through virtual(s): %s" % (
                h["pool"], ", ".join(h["local_traffic_policies"]), ", ".join(h["policy_virtual_servers"]) or
                "none (policy not attached to a virtual server)"))
    for h in res["nodes"]:
        summary.append("Node %s (state=%s, session=%s)" % (h["node"], h["state"], h["session"]))
    for h in res["virtual_servers"]:
        summary.append("Virtual server %s matches on %s" % (h["virtual"], "/".join(h["matched"])))
    for h in res["data_groups"]:
        summary.append("Data group %s has record(s): %s" % (h["data_group"], ", ".join(h["matching_records"])))
    for h in res.get("local_traffic_policies", []):
        summary.append("Local traffic policy %s, rule %s: %s -> %s (virtual(s): %s)" % (
            h["policy"], h["rule"], h["condition"], h["action"] or "no action", ", ".join(h["virtual_servers"])))
    if res["pools"]:
        verdict = {"label": "IN %d POOL MEMBERSHIP(S)" % len(res["pools"]), "kind": "ok"}
    elif summary:
        verdict = {"label": "FOUND (not as a pool member)", "kind": "ok"}
    else:
        verdict = {"label": "NOT FOUND in pools, nodes, virtuals, data groups or local traffic policies", "kind": "info"}
        summary.append("No configuration object references this IP.")
    return res, summary, verdict


def f5_rule_actions(r):
    """(readable actions, forwarded-to pool) for one LTM policy rule."""
    acts, pool = [], ""
    for a in (r.get("actionsReference") or {}).get("items", []):
        if a.get("forward") and a.get("pool"):
            pool = a["pool"]
            acts.append("forward to pool %s" % pool)
        elif a.get("forward") and a.get("virtual"):
            acts.append("forward to virtual %s" % a["virtual"])
        elif a.get("reset"):
            acts.append("reset")
        elif a.get("redirect"):
            acts.append("redirect %s" % (a.get("location") or ""))
        else:
            acts.append(next((k for k in a if a.get(k) is True and k not in ("request", "response")), "action"))
    return acts, pool


F5_COND_SKIP = {"caseInsensitive", "request", "response", "present", "not", "name", "index", "generation", "kind",
                "fullPath", "selfLink", "values", "equals", "startsWith", "endsWith", "contains", "matches", "missing",
                "ordinal"}


def f5_cond_text(c):
    """Readable text for one LTM policy rule condition, e.g. 'http host equals a.com, b.com'."""
    what = " ".join([k for k in c if c.get(k) is True and k not in F5_COND_SKIP] +
                    ([str(c["tmName"])] if c.get("tmName") else []))
    op = next((o for o in ("equals", "startsWith", "endsWith", "contains", "matches") if c.get(o)), "")
    return ("%s%s%s %s" % (what, " not" if c.get("not") else "", " " + op if op else "",
                           ", ".join(str(x) for x in (c.get("values") or [])))).strip()


def f5_policy_search(sess, term):
    """One row per rule (policy, rule, condition, action) of every local traffic policy whose name contains `term`."""
    ok, d = f5_get(sess, "/mgmt/tm/ltm/policy?expandSubcollections=true")
    if not ok:
        return None
    rows = []
    for p in d.get("items", []):
        if term.lower() not in str(p.get("fullPath", "")).lower():
            continue
        rules = sorted((p.get("rulesReference") or {}).get("items", []), key=lambda r: r.get("ordinal", 0))
        if not rules:
            rows.append({"policy_name": p.get("fullPath"), "rule": "", "condition": "", "action": ""})
        for r in rules:
            conds = [f5_cond_text(c) for c in (r.get("conditionsReference") or {}).get("items", [])]
            rows.append({"policy_name": p.get("fullPath"), "rule": r.get("name"),
                         "condition": " AND ".join(conds) if conds else "(no condition: matches every request)",
                         "action": "; ".join(f5_rule_actions(r)[0])})
    return rows


def f5_policy_ip_hits(sess, ip):
    """Local traffic policy rules with a condition whose values include `ip` (address, CIDR or range)."""
    okp, dp = f5_get(sess, "/mgmt/tm/ltm/policy?expandSubcollections=true")
    okv, dv = f5_get(sess, "/mgmt/tm/ltm/virtual?expandSubcollections=true")
    if not okp:
        return None
    by_policy = {}
    for v in (dv.get("items", []) if okv else []):
        for p in (v.get("policiesReference") or {}).get("items", []):
            by_policy.setdefault(p.get("fullPath") or "/%s/%s" % (p.get("partition", "Common"), p.get("name")),
                                 []).append(v.get("fullPath"))
    hits = []
    for p in dp.get("items", []):
        pol = p.get("fullPath")
        for r in (p.get("rulesReference") or {}).get("items", []):
            acts, pool = f5_rule_actions(r)
            for c in (r.get("conditionsReference") or {}).get("items", []):
                vals = [str(x) for x in (c.get("values") or [])]
                matched = [x for x in vals if ip_is_exact(ip, strip_rd(x))]
                if not matched:
                    continue
                hits.append({"policy": pol, "policy_status": p.get("status", ""), "rule": r.get("name"),
                             "condition": f5_cond_text(c),
                             "matched_value": ", ".join(matched), "action": "; ".join(acts),
                             "virtual_servers": by_policy.get(pol, []) or ["(policy not attached to any virtual server)"]})
    return hits


def f5_host_cond(c, host):
    """(is_host_condition, matches, text) for one LTM policy rule condition against `host`."""
    if not (c.get("httpHost") or c.get("host")) or c.get("httpUri") or c.get("path"):
        return False, False, ""
    vals = [str(x) for x in (c.get("values") or [])]
    op = next((o for o in ("equals", "startsWith", "endsWith", "contains") if c.get(o)), "")
    if not op:
        op = "matches" if c.get("matches") else ("not-equals" if c.get("notEquals") else "")
    neg = bool(c.get("not")) or op == "not-equals"
    ci = c.get("caseInsensitive", True) is not False
    h = host.lower() if ci else host

    def one(v):
        v = v.lower() if ci else v
        if op in ("equals", "not-equals"):
            return h == v
        return {"startsWith": h.startswith, "endsWith": h.endswith, "contains": lambda x: x in h}.get(
            op, lambda x: False)(v)
    hit = any(one(v) for v in vals)
    text = "%s %s %s" % ("host", ("not " if neg and op != "not-equals" else "") + (op or "?"), ", ".join(vals))
    return True, (not hit if neg else hit), text


def do_f5_host(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess or sess["vendor"] != "f5":
        return {"ok": False, "error": "connect an F5 device first"}
    t0 = time.time()
    host = (b.get("hostname") or "").strip().lower()
    if not re.match(r"^[a-z0-9_.*\-]{1,253}$", host):
        return {"ok": False, "error": "enter a hostname (letters, digits, . - _ only)"}
    audit(sess, "F5 hostname lookup in local traffic policies: " + host)
    okp, dp = f5_get(sess, "/mgmt/tm/ltm/policy?expandSubcollections=true")
    okv, dv = f5_get(sess, "/mgmt/tm/ltm/virtual?expandSubcollections=true")
    if not okp or not okv:
        return {"ok": False, "error": "could not read local traffic policies or virtual servers (HTTP %s / %s)" % (
            "ok" if okp else "failed", "ok" if okv else "failed")}
    by_policy = {}
    for v in dv.get("items", []):
        for p in (v.get("policiesReference") or {}).get("items", []):
            by_policy.setdefault(p.get("fullPath") or "/%s/%s" % (p.get("partition", "Common"), p.get("name")),
                                 []).append(v)
    rows, host_rules, unattached = [], 0, 0
    for p in dp.get("items", []):
        pol = p.get("fullPath")
        for r in (p.get("rulesReference") or {}).get("items", []):
            conds = (r.get("conditionsReference") or {}).get("items", [])
            parsed = [f5_host_cond(c, host) for c in conds]
            if not any(h for h, _, _ in parsed):
                continue
            host_rules += 1
            if not all(m for h, m, _ in parsed if h):
                continue
            acts, pool = f5_rule_actions(r)
            vss = by_policy.get(pol, [])
            if not vss:
                unattached += 1
            for v in vss or [None]:
                rows.append({"virtual_server": v.get("fullPath") if v else "(policy not attached to any virtual server)",
                             "destination": v.get("destination", "") if v else "",
                             "virtual_enabled": ("no" if v.get("disabled") else "yes") if v else "",
                             "default_pool": v.get("pool", "") if v else "",
                             "policy": pol, "policy_status": p.get("status", ""), "rule": r.get("name"),
                             "conditions": "; ".join(t for h, _, t in parsed if h),
                             "action": "; ".join(acts), "forwards_to_pool": pool})
    attached = sorted({x["virtual_server"] for x in rows if x["destination"]})
    summary = ["%d policy rule(s) with a hostname condition were checked." % host_rules]
    if unattached:
        summary.append("%d matching rule(s) are in a policy that is not attached to any virtual server." % unattached)
    summary.append("Only Local Traffic Policy host conditions are searched; iRules and SNI/client-ssl profiles are not.")
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000),
            "request": "GET /mgmt/tm/ltm/policy + /mgmt/tm/ltm/virtual",
            "verdict": {"label": "%d VIRTUAL SERVER(S) / %d RULE MATCH(ES) for %s" % (len(attached), len(rows), host),
                        "kind": "ok" if rows else "info"},
            "summary": summary, "data": {"lines": [
                "%s  ->  policy %s, rule %s  (%s)  %s" % (x["virtual_server"], x["policy"], x["rule"],
                                                          x["conditions"], x["action"]) for x in rows],
                "entries": rows}}


# ---- Palo Alto: references in policy + allow/block verdict for a flow -------
def pan_xml(sess, params, timeout=30):
    body = urllib.parse.urlencode(params).encode()
    st, raw = http(sess, "POST", "/api/", {"X-PAN-KEY": sess["key"],
                   "Content-Type": "application/x-www-form-urlencoded"}, body, timeout)
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None
    return root if root.get("status") == "success" else None


def pan_members(el):
    return [(m.text or "").strip() for m in el.findall("member")] if el is not None else []


def pan_base(vsys):
    return "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']" % vsys


def pan_section(sess, xp, tag):
    """Running-config element xp/tag, or None if absent or unreadable."""
    root = pan_xml(sess, {"type": "config", "action": "show", "xpath": xp + "/" + tag}, 60)
    if root is None:
        return None
    r = root.find("result")
    return r.find(tag) if r is not None else None


def pan_rules(sess, vsys):
    """(scope, rule element) for local and shared pre/post security rules."""
    out = []
    for label, xp in [("local", pan_base(vsys) + "/rulebase/security"),
                      ("shared-pre", "/config/shared/pre-rulebase/security"),
                      ("shared-post", "/config/shared/post-rulebase/security")]:
        node = pan_section(sess, xp, "rules")
        out.extend((label, e) for e in (node.findall("entry") if node is not None else []))
    return out


def pan_lookup(sess, ip, vsys, flow, refs=True):
    notes = []
    base = pan_base(vsys)

    def section(xp, tag):
        return pan_section(sess, xp, tag)

    scopes = [("vsys:" + vsys, base), ("shared", "/config/shared")]
    matched, groups, skipped = {}, [], 0
    for label, xp in (scopes if refs else []):
        node = section(xp, "address")
        for e in (node.findall("entry") if node is not None else []):
            for tag in ("ip-netmask", "ip-range"):
                v = e.findtext(tag)
                if v and ip_in_spec(ip, v):
                    matched[e.get("name")] = "%s %s (%s)" % (tag, v.strip(), label)
            if e.find("fqdn") is not None or e.find("ip-wildcard") is not None:
                skipped += 1
        node = section(xp, "address-group")
        for e in (node.findall("entry") if node is not None else []):
            if e.find("dynamic") is not None:
                skipped += 1
            groups.append((label, e.get("name"), pan_members(e.find("static"))))
    changed = True
    while changed:
        changed = False
        for label, n, members in groups:
            via = [m for m in members if m in matched]
            if n not in matched and via:
                matched[n] = "group containing %s (%s)" % (", ".join(via), label)
                changed = True
    rules = []
    for label, e in (pan_rules(sess, vsys) if refs else []):
        hits = []
        for fld in ("source", "destination"):
            for m in pan_members(e.find(fld)):
                if m in matched:
                    hits.append({"field": fld, "member": m, "via": matched[m]})
                elif m != "any" and ip_in_spec(ip, m):
                    hits.append({"field": fld, "member": m, "via": "literal"})
        if hits:
            rules.append({"scope": label, "rule": e.get("name"), "action": e.findtext("action"),
                          "disabled": e.findtext("disabled") or "no",
                          "from": pan_members(e.find("from")), "to": pan_members(e.find("to")),
                          "source": pan_members(e.find("source")),
                          "destination": pan_members(e.find("destination")),
                          "application": pan_members(e.find("application")),
                          "service": pan_members(e.find("service")),
                          "negate_source": e.findtext("negate-source") or "no",
                          "negate_destination": e.findtext("negate-destination") or "no",
                          "hits": hits})
    res = {"matching_objects": matched, "rules_referencing_ip": rules}
    summary = []
    if refs:
        if matched:
            summary.append("Address objects/groups containing the IP: " + ", ".join(sorted(matched)))
        else:
            summary.append("No address object or group contains this IP.")
        for r in rules:
            summary.append("Rule '%s' [%s, action=%s, disabled=%s] references it in %s" % (
                r["rule"], r["scope"], r["action"], r["disabled"], "/".join(sorted({h["field"] for h in r["hits"]}))))
        if not rules:
            summary.append("No security rule names this IP directly or via an object.")
        if skipped:
            notes.append("%d FQDN/wildcard/dynamic object(s) were not evaluated." % skipped)
        notes.append("Reference search reads the firewall's running config. Panorama-pushed rules may not appear "
                     "there; use the block check for the effective policy verdict.")
    verdict = None
    if flow:
        cmd = "<test><security-policy-match>"
        if flow["from"]:
            cmd += "<from>%s</from>" % xml_escape(flow["from"])
        if flow["to"]:
            cmd += "<to>%s</to>" % xml_escape(flow["to"])
        cmd += "<source>%s</source><destination>%s</destination>" % (xml_escape(flow["src"]), xml_escape(flow["dst"]))
        if flow["port"]:
            cmd += "<destination-port>%d</destination-port>" % flow["port"]
        cmd += "<protocol>%s</protocol></security-policy-match></test>" % xml_escape(flow["proto"])
        st, raw = http(sess, "POST", "/api/", {"X-PAN-KEY": sess["key"],
                       "Content-Type": "application/x-www-form-urlencoded"},
                       urllib.parse.urlencode({"type": "op", "cmd": cmd}).encode(), 30)
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            root = None
        err = None if root is not None and root.get("status") == "success" else \
            " ".join(t.strip() for t in root.itertext() if t.strip())[:300] if root is not None else "HTTP %s" % st
        e = root.find(".//rules/entry") if not err else None
        res["flow_test"] = {}
        if err:
            verdict = {"label": "POLICY LOOKUP FAILED", "kind": "warn"}
            notes.append("security-policy-match was rejected: %s. Check the zone names, and that the API admin may "
                         "run operational commands." % err)
        elif e is None:
            verdict = {"label": "NO RULE MATCHED (the default intrazone / interzone rule applies)", "kind": "warn"}
        else:
            act = (e.findtext("action") or "").strip().lower()
            # Older PAN-OS answers '<entry>rule-name; index: 5</entry>' instead of a name attribute.
            name = e.get("name") or (e.text or "").split(";")[0].strip()
            if not act and name:
                act = next(((r.findtext("action") or "").strip().lower() for _, r in pan_rules(sess, vsys)
                            if r.get("name") == name), "")
            res["flow_test"]["matched_rule"] = x2o(e)
            if act == "allow":
                verdict = {"label": "ALLOWED by rule '%s'" % name, "kind": "ok"}
            elif act in ("deny", "drop", "reset-client", "reset-server", "reset-both"):
                verdict = {"label": "BLOCKED (%s) by rule '%s'" % (act, name), "kind": "bad"}
            else:
                verdict = {"label": "MATCHED rule '%s' (action: %s)" % (name, act or "unknown"), "kind": "info"}
            summary.insert(0, "Flow %s -> %s port %s proto %s: rule '%s', action '%s'" % (
                flow["src"], flow["dst"], flow["port"] or "-", flow["proto"], name, act))
    res["notes"] = notes
    if verdict is None:
        verdict = {"label": "%d RULE(S) REFERENCE THIS IP" % len(rules), "kind": "info"}
    return res, summary, verdict


# ---- FortiGate: references in policy + allow/block verdict for a flow -------
def fg_cmdb(sess, name, vdom):
    path = "/api/v2/cmdb/firewall/" + name + ("?vdom=" + urllib.parse.quote(vdom) if vdom else "")
    st, ok, data = rest_get(sess, path)
    if ok and isinstance(data, dict):
        return as_list(data.get("results"))
    return None


def fg_lookup(sess, ip, vdom, flow, refs=True):
    notes = []
    addrs, grps, pols = (fg_cmdb(sess, n, vdom) if refs else [] for n in ("address", "addrgrp", "policy"))
    if pols is None:
        notes.append("could not read firewall policy list (check token profile / VDOM)")
    matched, skipped = {}, 0
    for a in addrs or []:
        n, t = a.get("name"), a.get("type", "ipmask")
        if n == "all" or a.get("subnet") == "0.0.0.0 0.0.0.0":
            continue
        if t == "ipmask" and ip_in_spec(ip, a.get("subnet")):
            matched[n] = "subnet " + a["subnet"]
        elif t == "iprange" and ip_in_spec(ip, "%s-%s" % (a.get("start-ip"), a.get("end-ip"))):
            matched[n] = "range %s-%s" % (a.get("start-ip"), a.get("end-ip"))
        elif t not in ("ipmask", "iprange"):
            skipped += 1
    changed = True
    while changed:
        changed = False
        for g in grps or []:
            via = [m.get("name") for m in as_list(g.get("member")) if m.get("name") in matched]
            if g.get("name") not in matched and via:
                matched[g["name"]] = "group containing " + ", ".join(via)
                changed = True
    names = lambda x: [i.get("name") for i in as_list(x)]
    rules = []
    for p in pols or []:
        hits = []
        for fld, key in (("source", "srcaddr"), ("destination", "dstaddr")):
            for m in names(p.get(key)):
                if m in matched:
                    hits.append({"field": fld, "member": m, "via": matched[m],
                                 "negated": p.get(key + "-negate") == "enable"})
        if hits:
            rules.append({"policyid": p.get("policyid"), "name": p.get("name"), "action": p.get("action"),
                          "status": p.get("status"), "srcintf": names(p.get("srcintf")),
                          "dstintf": names(p.get("dstintf")), "srcaddr": names(p.get("srcaddr")),
                          "dstaddr": names(p.get("dstaddr")), "service": names(p.get("service")),
                          "nat": p.get("nat"), "hits": hits})
    res = {"matching_objects": matched, "policies_referencing_ip": rules}
    summary = []
    if refs:
        summary.append("Address objects/groups containing the IP: " + (", ".join(sorted(matched)) or "none"))
        for r in rules:
            flags = " (NEGATED)" if any(h["negated"] for h in r["hits"]) else ""
            summary.append("Policy %s '%s' [action=%s, status=%s] references it in %s%s" % (
                r["policyid"], r["name"] or "", r["action"], r["status"],
                "/".join(sorted({h["field"] for h in r["hits"]})), flags))
        if not rules:
            summary.append("No IPv4 policy references this IP directly or via an object.")
        if skipped:
            notes.append("%d FQDN/geography/wildcard object(s) were not evaluated." % skipped)
        notes.append("IPv6 policies, internet-service and the built-in 'all' object are not part of the reference search.")
    verdict = None
    if flow:
        q = {"srcintf": flow["srcintf"], "sourceip": flow["src"], "dest": flow["dst"], "protocol": flow["proto"]}
        if flow["port"]:
            q["destport"] = flow["port"]
        if vdom:
            q["vdom"] = vdom
        path = "/api/v2/monitor/firewall/policy-lookup?" + urllib.parse.urlencode(q)
        st, ok, data = rest_get(sess, path)
        res["flow_test"] = {}
        r0 = data.get("results") if isinstance(data, dict) else None
        r0 = r0[0] if isinstance(r0, list) and r0 else r0
        if not ok or not isinstance(r0, dict):
            verdict = {"label": "POLICY LOOKUP FAILED (HTTP %s)" % st, "kind": "warn"}
            notes.append("policy-lookup failed (HTTP %s)%s. Check the ingress interface name and VDOM; the token "
                         "needs read access to Firewall policy." % (
                             st, ": " + str(data.get("cli_error") or data.get("error") or "")[:200]
                             if isinstance(data, dict) and (data.get("cli_error") or data.get("error")) else ""))
        else:
            pid = r0.get("policy_id")
            if pid:
                pol = fg_cmdb(sess, "policy/%d" % int(pid), vdom)
                pol = pol[0] if pol else {}
                act, pname = pol.get("action", "unknown"), pol.get("name") or ""
                res["flow_test"]["matched_policy"] = pol
                label = "policy %s %s" % (pid, ("'%s'" % pname) if pname else "")
                if act == "accept":
                    verdict = {"label": "ALLOWED by " + label.strip(), "kind": "ok"}
                elif act == "deny":
                    verdict = {"label": "BLOCKED by " + label.strip(), "kind": "bad"}
                else:
                    verdict = {"label": "MATCHED %s (action: %s)" % (label.strip(), act), "kind": "info"}
                summary.insert(0, "Flow %s -> %s port %s %s: policy %s, action '%s'" % (
                    flow["src"], flow["dst"], flow["port"] or "-", flow["proto"], pid, act))
            else:
                verdict = {"label": "NO POLICY MATCHED (implicit deny)", "kind": "bad"}
                summary.insert(0, "Policy lookup returned no policy. Confirm the ingress interface is correct.")
    res["notes"] = notes
    if verdict is None:
        verdict = {"label": "%d POLICY(IES) REFERENCE THIS IP" % len(rules), "kind": "info"}
    return res, summary, verdict


# ---- Policy search by name (PAN-OS security rules, FortiGate firewall policies) ----
POLICY_Q_RE = re.compile(r"^[^\x00-\x1f\x7f'\"<>\\]{1,100}$")


def epoch_utc3(t):
    try:
        return utc3(datetime.datetime.fromtimestamp(int(t), datetime.timezone.utc).isoformat()) if int(t) > 0 else "never"
    except (TypeError, ValueError):
        return ""


def pan_objects(sess, vsys):
    """name -> value of address, address-group, service and service-group objects (shared, then the vsys)."""
    objs = {}
    for xp in ("/config/shared", pan_base(vsys)):
        for tag in ("address", "address-group", "service", "service-group"):
            node = pan_section(sess, xp, tag)
            for e in (node.findall("entry") if node is not None else []):
                v = ""
                if tag == "address":
                    v = next((e.findtext(t).strip() for t in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard")
                              if e.findtext(t)), "")
                elif tag == "address-group":
                    v = ("group: " + ", ".join(pan_members(e.find("static")))) if e.find("static") is not None else \
                        "dynamic: " + (e.findtext("dynamic/filter") or "").strip()
                elif tag == "service":
                    v = next(("%s/%s" % (p, e.findtext("protocol/%s/port" % p) or "")
                              for p in ("tcp", "udp", "sctp") if e.find("protocol/" + p) is not None), "")
                else:
                    v = "group: " + ", ".join(pan_members(e.find("members")))
                objs[e.get("name")] = v
    return objs


def pan_policy_search(sess, q, vsys):
    objs, rows, pos = pan_objects(sess, vsys), [], collections.Counter()
    for scope, e in pan_rules(sess, vsys):
        pos[scope] += 1
        name = e.get("name") or ""
        if q.lower() not in name.lower():
            continue
        m = lambda t: pan_members(e.find(t))
        res = lambda t: ["%s = %s" % (x, objs[x]) if objs.get(x) else x for x in m(t)]
        prof = e.find("profile-setting")
        profiles = []
        if prof is not None and prof.find("group") is not None:
            profiles = ["group: " + ", ".join(pan_members(prof.find("group")))]
        elif prof is not None and prof.find("profiles") is not None:
            profiles = ["%s: %s" % (c.tag, ", ".join(pan_members(c))) for c in prof.find("profiles")]
        rows.append({"rule": name, "scope": scope, "position": pos[scope], "action": e.findtext("action") or "",
                     "enabled": "no" if (e.findtext("disabled") or "no") == "yes" else "yes",
                     "from_zone": m("from"), "to_zone": m("to"),
                     "source": res("source"), "negate_source": e.findtext("negate-source") or "no",
                     "source_user": m("source-user"), "destination": res("destination"),
                     "negate_destination": e.findtext("negate-destination") or "no",
                     "application": m("application"), "service": res("service"), "url_category": m("category"),
                     "security_profiles": profiles, "log_at_session_end": e.findtext("log-end") or "yes",
                     "tags": m("tag"), "description": (e.findtext("description") or "").strip()})
    notes = []
    if rows:   # hit counts are kept per vsys rule base
        lst = "".join("<member>%s</member>" % xml_escape(r["rule"]) for r in rows[:50])
        root = pan_xml(sess, {"type": "op", "cmd": "<show><rule-hit-count><vsys><vsys-name><entry name='%s'><rule-base>"
                              "<entry name='security'><rules><list>%s</list></rules></entry></rule-base></entry>"
                              "</vsys-name></vsys></rule-hit-count></show>" % (xml_escape(vsys), lst)}, 30)
        hits = {h.get("name"): h for h in (root.findall(".//rules/entry") if root is not None else [])}
        for r in rows:
            h = hits.get(r["rule"])
            if h is not None:
                r["hit_count"] = (h.findtext("hit-count") or "").strip()
                r["last_hit"] = epoch_utc3(h.findtext("last-hit-timestamp"))
        if root is None:
            notes.append("Hit counts could not be read (show rule-hit-count needs PAN-OS 8.1+).")
    notes.append("Searched the firewall's running config (vsys %s, shared pre / post rules). Rules pushed from "
                 "Panorama that are not in the running config are not listed." % vsys)
    return rows, notes


def fg_policy_search(sess, q, vdom):
    pols = fg_cmdb(sess, "policy", vdom)
    if pols is None:
        raise ValueError("could not read the firewall policies (check the token's profile and the VDOM)")
    vq = "?vdom=" + urllib.parse.quote(vdom) if vdom else ""
    objs = {}
    for kind, path in (("addr", "/api/v2/cmdb/firewall/address"), ("grp", "/api/v2/cmdb/firewall/addrgrp"),
                       ("svc", "/api/v2/cmdb/firewall.service/custom"), ("sgrp", "/api/v2/cmdb/firewall.service/group")):
        st, ok, d = rest_get(sess, path + vq)
        for o in as_list(d.get("results")) if ok and isinstance(d, dict) else []:
            if kind == "addr":
                t = o.get("type", "ipmask")
                v = o.get("subnet") if t == "ipmask" else "%s-%s" % (o.get("start-ip"), o.get("end-ip")) \
                    if t == "iprange" else o.get(t) or t
            elif kind == "svc":
                v = " ".join(x for x in ("tcp/" + o["tcp-portrange"] if o.get("tcp-portrange") else "",
                                         "udp/" + o["udp-portrange"] if o.get("udp-portrange") else "") if x) \
                    or str(o.get("protocol") or "")
            else:
                v = "group: " + ", ".join(m.get("name") for m in as_list(o.get("member")))
            objs[o.get("name")] = str(v or "")
    st, ok, d = rest_get(sess, "/api/v2/monitor/firewall/policy" + vq)
    stats = {s.get("policyid"): s for s in as_list(d.get("results"))} if ok and isinstance(d, dict) else {}
    names = lambda x: [i.get("name") for i in as_list(x)]
    res = lambda x: ["%s = %s" % (n, objs[n]) if objs.get(n) else n for n in names(x)]
    rows = []
    for i, p in enumerate(pols, 1):
        if not (q.lower() in str(p.get("name") or "").lower() or (q.isdigit() and str(p.get("policyid")) == q)):
            continue
        s = stats.get(p.get("policyid")) or {}
        rows.append({"policyid": p.get("policyid"), "name": p.get("name") or "", "position": i,
                     "action": p.get("action"), "enabled": "yes" if p.get("status", "enable") == "enable" else "no",
                     "srcintf": names(p.get("srcintf")), "dstintf": names(p.get("dstintf")),
                     "source": res(p.get("srcaddr")), "negate_source": p.get("srcaddr-negate", "disable"),
                     "destination": res(p.get("dstaddr")), "negate_destination": p.get("dstaddr-negate", "disable"),
                     "users_groups": names(p.get("users")) + names(p.get("groups")),
                     "internet_service": names(p.get("internet-service-name")), "service": res(p.get("service")),
                     "schedule": p.get("schedule"), "nat": p.get("nat"),
                     "security_profiles": ["%s: %s" % (k, p[k]) for k in ("av-profile", "webfilter-profile", "ips-sensor",
                                           "application-list", "ssl-ssh-profile", "dnsfilter-profile") if p.get(k)],
                     "log_traffic": p.get("logtraffic"), "hit_count": s.get("hit_count", ""),
                     "last_used": epoch_utc3(s["last_used"]) if "last_used" in s else "",
                     "active_sessions": s.get("active_sessions", ""), "comments": p.get("comments") or ""})
    notes = ["Position = order in the policy list (FortiOS evaluates top-down)." +
             ("" if stats else " Hit counts could not be read (monitor API).")]
    return rows, notes


def do_policy_search(b):
    """Security rules (PAN-OS) or firewall policies (FortiGate) whose name contains the text (or the FortiGate ID)."""
    sess = SESSIONS.get(b.get("id"))
    if not sess or sess["vendor"] not in ("paloalto", "fortigate"):
        return {"ok": False, "error": "connect a Palo Alto or FortiGate device first"}
    t0 = time.time()
    q = str(b.get("name") or "").strip()
    if not POLICY_Q_RE.match(q):
        return {"ok": False, "error": "enter a policy name (or part of it)%s, without quotes or < >" % (
            " or a policy ID" if sess["vendor"] == "fortigate" else "")}
    try:
        audit(sess, "policy search '%s'" % q)
        if sess["vendor"] == "paloalto":
            rows, notes = pan_policy_search(sess, q, pstr(b.get("vsys"), "vsys") or "vsys1")
            key = lambda r: "%s (%s, position %s)" % (r["rule"], r["scope"], r["position"])
        else:
            rows, notes = fg_policy_search(sess, q, pstr(b.get("vdom"), "VDOM"))
            key = lambda r: "Policy %s %s(position %s)" % (r["policyid"], "'%s' " % r["name"] if r["name"] else "",
                                                           r["position"])
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
    # A few matches read best one by one; many as a table.
    data = {key(r): r for r in rows} if len(rows) <= 5 else {"policies": rows}
    off = [r for r in rows if r["enabled"] == "no"]
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": "policy search " + q,
            "verdict": {"label": ("%d POLICY(IES) MATCH '%s'" % (len(rows), q)) + (" · %d DISABLED" % len(off) if off else "")
                        if rows else "NO POLICY NAME CONTAINS '%s'" % q, "kind": "info" if rows else "warn"},
            "summary": ["%s: action %s%s%s" % (key(r), r["action"], "" if r["enabled"] == "yes" else ", DISABLED",
                                                ", hits %s" % r["hit_count"] if r.get("hit_count") not in (None, "") else "")
                        for r in rows[:10]] + notes,
            "data": data}


def fg_names(x):
    return [i.get("name") if isinstance(i, dict) else str(i) for i in as_list(x)]


def fg_term_match(term, texts, specs=()):
    """Case-insensitive substring match on texts; if term is an IP/subnet, also containment in any of specs."""
    t = term.lower()
    if any(t in str(x).lower() for x in texts):
        return True
    try:
        net = ipaddress.ip_network(term, strict=False)
    except ValueError:
        return False
    for s in specs:
        s = str(s or "")
        try:
            if net.num_addresses == 1:
                if ip_in_spec(net.network_address, s):
                    return True
            elif "/" not in s and " " not in s and "-" not in s:
                if ipaddress.ip_address(s) in net:
                    return True
            elif ipaddress.ip_network(s.replace(" ", "/") if " " in s else s, strict=False).overlaps(net):
                return True
        except ValueError:
            pass
    return False


FG_SESS_KEYS = (  # output column <- candidate FortiOS field names (they differ between versions)
    ("source_ip", ("saddr", "srcip", "src", "source", "sourceip", "src_ip")),
    ("source_port", ("sport", "srcport", "src_port")),
    ("destination_ip", ("daddr", "dstip", "dst", "destination", "dest", "dst_ip")),
    ("destination_port", ("dport", "dstport", "dst_port")),
    ("protocol", ("proto", "protocol", "proto_number")),
    ("policy_id", ("policyid", "policy_id", "policy")),
    ("nat_source_ip", ("snat_addr", "tran_sip", "snat-ip", "nat_saddr")),
    ("nat_destination_ip", ("dnat_addr", "tran_dip", "dnat-ip", "nat_daddr")),
    ("ingress_interface", ("srcintf", "src_intf", "in_intf", "incoming_interface")),
    ("egress_interface", ("dstintf", "dst_intf", "out_intf", "outgoing_interface")),
    ("expires_s", ("expiry", "expire", "timeout")),
    ("bytes_sent", ("tx_bytes", "sentbyte", "bytes_sent")),
    ("bytes_received", ("rx_bytes", "rcvdbyte", "bytes_received")),
)


def fg_session_rows(data):
    """FortiGate firewall/session(s) -> rows with source/destination first; keeps unmapped fields too."""
    def find_rows(x, depth=0):
        if isinstance(x, list) and x and all(isinstance(i, dict) for i in x):
            return x
        if isinstance(x, dict) and depth < 4:
            for k in ("details", "sessions", "session", "results", "entries", "result", "entry"):
                if k in x:
                    r = find_rows(x[k], depth + 1)
                    if r:
                        return r
        return None
    items = find_rows(data) or []
    rows, seen = [], set()
    for it in items:
        row, used = {}, set()
        for out, cands in FG_SESS_KEYS:
            k = next((c for c in cands if c in it), None)
            if k is not None:
                row[out] = it[k]
                used.add(k)
        for k, v in it.items():
            if k not in used and not isinstance(v, (dict, list)):
                row[k] = v
        seen.update(it.keys())
        rows.append(row)
    summary = data.get("results", {}).get("summary") if isinstance(data, dict) and isinstance(data.get("results"), dict) else None
    out = {"sessions": rows, "count": len(rows)}
    if summary:
        out["summary"] = summary
    if not rows:
        out["note"] = "No session rows found in the response."
        out["raw"] = data
    elif not any(k in rows[0] for k in ("source_ip", "destination_ip")):
        out["note"] = "No recognised source/destination fields; raw field names: " + ", ".join(sorted(seen))
    return out


def fg_vip_rows(data, term):
    """FortiGate firewall/vip -> one readable row per Virtual IP, optionally filtered."""
    items = as_list(data.get("results")) if isinstance(data, dict) else []
    rows = []
    for v in items:
        ext = v.get("extip", "")
        mapped = ", ".join(m.get("range", "") for m in as_list(v.get("mappedip")))
        if term and not fg_term_match(term, [v.get("name"), ext, mapped, v.get("comment")],
                                      [ext] + [m.get("range") for m in as_list(v.get("mappedip"))]):
            continue
        fwd = v.get("portforward") == "enable"
        rows.append({"name": v.get("name"), "type": v.get("type"), "external_ip": ext,
                     "external_interface": v.get("extintf"), "mapped_ip": mapped,
                     "port_forward": "enable" if fwd else "disable",
                     "protocol": v.get("protocol") if fwd else "",
                     "external_port": v.get("extport") if fwd else "",
                     "mapped_port": v.get("mappedport") if fwd else "",
                     "nat_source_ip_pool": v.get("nat-source-vip"), "arp_reply": v.get("arp-reply"),
                     "src_filter": ", ".join(s.get("range", "") for s in as_list(v.get("src-filter"))),
                     "comment": v.get("comment")})
    return {"virtual_ips": rows, "count": len(rows), "total_configured": len(items),
            "note": "Policies using a VIP are found via 'Where does this IP appear' (policy references)."}


def fg_static_route_rows(data, term):
    """FortiGate router/static -> one readable row per static route, optionally filtered."""
    items = as_list(data.get("results")) if isinstance(data, dict) else []
    rows = []
    for r in items:
        dst = r.get("dst", "")
        if dst == "0.0.0.0 0.0.0.0":
            dst_txt = "0.0.0.0/0 (default)"
        else:
            try:
                dst_txt = str(ipaddress.ip_network(dst.replace(" ", "/"), strict=False)) if dst else (
                    r.get("internet-service") and "internet-service %s" % r.get("internet-service") or
                    r.get("sdwan-zone") and "sdwan" or r.get("dstaddr") and "addr " + str(r.get("dstaddr")) or "")
            except ValueError:
                dst_txt = dst
        if term and not fg_term_match(term, [dst_txt, r.get("gateway"), r.get("device"), r.get("comment"), r.get("dstaddr")],
                                      [dst] if dst else []):
            continue
        rows.append({"seq": r.get("seq-num"), "destination": dst_txt, "gateway": r.get("gateway"),
                     "interface": r.get("device"), "distance": r.get("distance"), "priority": r.get("priority"),
                     "weight": r.get("weight"), "status": r.get("status"), "blackhole": r.get("blackhole"),
                     "vrf": r.get("vrf"), "comment": r.get("comment")})
    return {"static_routes": rows, "count": len(rows), "total_configured": len(items),
            "note": "Configured routes. Whether a route is active (best path) is shown in 'IPv4 routing table'."}


def iface_out(rows, note=""):
    out = {"interfaces": rows, "count": len(rows)}
    if note:
        out["note"] = note
    return out


def fg_iface_rows(sess, data):
    """FortiGate monitor/system/interface -> name, number (SNMP ifIndex from the config) and IP."""
    res = data.get("results") if isinstance(data, dict) else None
    items = list(res.values()) if isinstance(res, dict) else as_list(res)
    idx = {}
    st, ok, cfg = rest_get(sess, "/api/v2/cmdb/system/interface")
    for c in as_list(cfg.get("results")) if ok and isinstance(cfg, dict) else []:
        if isinstance(c, dict):
            idx[c.get("name")] = c.get("snmp-index")
    rows = []
    for i in items:
        if not isinstance(i, dict):
            continue
        name = i.get("name") or i.get("id")
        ip = i.get("ip") or ""
        mask = i.get("mask")
        rows.append({"name": name, "number": idx.get(name, ""),
                     "ip": ("%s/%s" % (ip, mask) if ip and mask not in (None, "") else ip)})
    return iface_out(rows, "" if idx else "interface numbers (SNMP index) unavailable: could not read /cmdb/system/interface")


def pan_iface_rows(data):
    """PAN-OS show interface all -> name, number (interface id) and IP, from the logical (ifnet) list."""
    def entries(x):
        if isinstance(x, dict):
            e = x.get("entry")
            if e is not None:
                return [i for i in as_list(e) if isinstance(i, dict)]
            for v in x.values():
                r = entries(v)
                if r:
                    return r
        return []
    res = data.get("result") if isinstance(data, dict) else None
    ifnet = res.get("ifnet") if isinstance(res, dict) else None
    hw = res.get("hw") if isinstance(res, dict) else None
    ids = {e.get("name"): e.get("id") for e in entries(hw)}
    rows = []
    for e in entries(ifnet):
        name = e.get("name")
        ip = e.get("ip") or e.get("addr") or e.get("dyn-addr") or ""
        rows.append({"name": name, "number": e.get("id") or ids.get(name, ""),
                     "ip": "" if ip in ("N/A", "n/a") else ip})
    return iface_out(rows)


def pan_result(request, data, t0, ok=True, status=200):
    return {"ok": ok, "status": status, "data": data, "request": request, "ms": int((time.time() - t0) * 1000)}


def pan_nat_rules(sess, v):
    """Destination NAT and static (bi-directional) NAT rules: what PAN-OS has in place of FortiGate Virtual IPs."""
    t0, vsys, term = time.time(), v["vsys"], v["filter"]
    rows, total = [], 0
    for label, xp in [("local", pan_base(vsys) + "/rulebase/nat"),
                      ("shared-pre", "/config/shared/pre-rulebase/nat"),
                      ("shared-post", "/config/shared/post-rulebase/nat")]:
        node = pan_section(sess, xp, "rules")
        for e in (node.findall("entry") if node is not None else []):
            total += 1
            dt = e.find("destination-translation")
            st = e.find("source-translation/static-ip")
            if dt is None and (st is None or (st.findtext("bi-directional") or "") != "yes"):
                continue   # plain source NAT / no NAT: not a Virtual IP equivalent
            dest = pan_members(e.find("destination"))
            tr_ip = (dt.findtext("translated-address") if dt is not None else None) or \
                    (st.findtext("translated-address") if st is not None else "") or ""
            tr_port = (dt.findtext("translated-port") if dt is not None else "") or ""
            name = e.get("name")
            if term and not fg_term_match(term, [name, tr_ip, e.findtext("description"), ", ".join(dest)], dest + [tr_ip]):
                continue
            rows.append({"name": name, "scope": label, "type": "destination NAT" if dt is not None else "static NAT",
                         "from_zone": ", ".join(pan_members(e.find("from"))), "to_zone": ", ".join(pan_members(e.find("to"))),
                         "public_destination": ", ".join(dest), "service": e.findtext("service") or "",
                         "translated_ip": tr_ip, "translated_port": tr_port,
                         "source": ", ".join(pan_members(e.find("source"))),
                         "disabled": e.findtext("disabled") or "no", "description": e.findtext("description") or ""})
    return pan_result("config show %s/rulebase/nat (+ shared pre/post)" % pan_base(vsys),
                      {"virtual_ip_equivalents": rows, "count": len(rows), "nat_rules_scanned": total,
                       "note": "Address objects in 'public destination' are shown by name; use 'Where does this IP appear' to resolve them. "
                               "Panorama-pushed rules appear only if present in this device's running config."}, t0)


def pan_static_routes(sess, v):
    t0, term, rows = time.time(), v["filter"], []
    xp = "/config/devices/entry[@name='localhost.localdomain']/network"
    node = pan_section(sess, xp, "virtual-router")
    if node is None:
        return pan_result("config show " + xp + "/virtual-router",
                          {"note": "could not read virtual-router config (check key permissions)"}, t0, False, 200)
    for vr in node.findall("entry"):
        for r in vr.findall("routing-table/ip/static-route/entry"):
            nh = r.find("nexthop")
            nh_txt = ""
            if nh is not None and len(nh):
                kind, val = nh[0].tag, (nh[0].text or "").strip()
                nh_txt = val if kind == "ip-address" else ("%s (%s)" % (val, kind) if val else kind)
            dst = r.findtext("destination") or ""
            if term and not fg_term_match(term, [r.get("name"), dst, nh_txt, r.findtext("interface")], [dst]):
                continue
            rt = r.find("route-table")
            rows.append({"virtual_router": vr.get("name"), "name": r.get("name"), "destination": dst,
                         "next_hop": nh_txt, "interface": r.findtext("interface") or "",
                         "metric": r.findtext("metric") or "", "admin_distance": r.findtext("admin-dist") or "",
                         "route_table": rt[0].tag if rt is not None and len(rt) else "unicast",
                         "bfd": "yes" if r.find("bfd") is not None else "", "disabled": r.findtext("disabled") or "no"})
    return pan_result("config show " + xp + "/virtual-router",
                      {"static_routes": rows, "count": len(rows),
                       "note": "Configured routes. Active best paths are in 'Routing table'. Panorama template routes appear if pushed."}, t0)


def pan_sessions(sess, v):
    t0 = time.time()
    flt = ""
    for key, tag, label in (("src", "source", "Source IP"), ("dst", "destination", "Destination IP")):
        if v[key]:
            flt += "<%s>%s</%s>" % (tag, parse_ip(v[key], label), tag)
    n = num(v["count"], 1, 500, 50, "Max rows")
    cmd = "<show><session><all>%s</all></session></show>" % ("<filter>%s</filter>" % flt if flt else "")
    status, ok, data = pan_op(sess, cmd)
    if ok:
        out = fg_session_rows(data)   # generic row finder / field mapper (also understands PAN-OS entry lists)
        out["sessions"] = out["sessions"][:n]
        out["count"] = len(out["sessions"])
        data = out
    return pan_result(cmd, data, t0, ok, status)


PAN_HANDLERS = {"pan_nat_rules": pan_nat_rules, "pan_static_routes": pan_static_routes, "pan_sessions": pan_sessions}


def do_ipcheck(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess:
        return {"ok": False, "error": "device not connected"}
    t0 = time.time()
    try:
        ip = parse_ip(b.get("ip"), "IP address")
        v = sess["vendor"]
        audit(sess, "IP lookup " + str(ip))
        if v == "f5":
            res, summary, verdict = f5_lookup(sess, ip)
        else:
            flow = None
            mode = b.get("mode", "refs")
            if mode not in ("refs", "verdict"):
                raise ValueError("invalid mode")
            peer = (b.get("peer") or "").strip()
            if mode == "refs":
                peer = ""
            if mode == "verdict" and not peer:  # no other side: what do the traffic logs show for this IP?
                if v == "paloalto":
                    return do_pan_logs({"id": b.get("id"), "ip": str(ip), "log_type": "traffic",
                                        "period": b.get("period") or "last-24-hrs", "count": b.get("count")})
                return do_fg_logs({"id": b.get("id"), "ip": str(ip), "log_source": b.get("log_source") or "disk",
                                   "count": b.get("count"), "vdom": b.get("vdom")})
            if peer:
                peer_ip = parse_ip(peer, "Other side IP")
                role = b.get("role", "source")
                src, dst = (ip, peer_ip) if role == "source" else (peer_ip, ip)
                port = num(b.get("port"), 1, 65535, None, "port") if str(b.get("port") or "").strip() else None
                proto = pstr(b.get("proto"), "protocol").lower() or ("6" if v == "paloalto" else "tcp")
                if v == "paloalto":
                    proto = {"tcp": "6", "udp": "17", "icmp": "1"}.get(proto, proto)
                    num(proto, 0, 255, None, "protocol")
                flow = {"src": str(src), "dst": str(dst), "port": port, "proto": proto,
                        "from": pstr(b.get("from"), "from zone"), "to": pstr(b.get("to"), "to zone"),
                        "srcintf": pstr(b.get("srcintf"), "ingress interface")}
                if v == "fortigate" and not flow["srcintf"]:
                    raise ValueError("ingress interface is required for the FortiGate verdict")
            if v == "paloalto":
                res, summary, verdict = pan_lookup(sess, ip, pstr(b.get("vsys"), "vsys") or "vsys1", flow,
                                                   mode == "refs")
            else:
                res, summary, verdict = fg_lookup(sess, ip, pstr(b.get("vdom"), "VDOM"), flow, mode == "refs")
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000),
            "request": "IP lookup %s" % ip, "data": res, "summary": summary, "verdict": verdict}


# ---- F5 active tools: log search + tcpdump (shell via util/bash) ------------
def f5_bash(sess, script, timeout=30):
    body = json.dumps({"command": "run", "utilCmdArgs": "-c " + shlex.quote(script)}).encode()
    hdr = dict(sess["hdr"])
    hdr["Content-Type"] = "application/json"
    st, raw = http(sess, "POST", "/mgmt/tm/util/bash", hdr, body, timeout)
    try:
        data = json.loads(raw)
    except ValueError:
        data = {}
    out = data.get("commandResult", "") if isinstance(data, dict) else ""
    return st, 200 <= st < 300, out or "", data


def f5_bash_error(st, data, what="bash call"):
    """Error text for a failed util/bash call. A non-Administrator role (e.g. Auditor) gets HTTP 400, not 401/403."""
    msg = str(data.get("message") or "")[:200] if isinstance(data, dict) else ""
    detail = "HTTP %s%s" % (st, ": " + msg if msg else "")
    if st in (400, 401, 403):
        return "%s rejected (%s). util/bash needs the Administrator role." % (what, detail)
    return "%s failed (%s)" % (what, detail)


def _f5_gate(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess or sess["vendor"] != "f5":
        return None, {"ok": False, "error": "connect an F5 device first"}
    if not b.get("ack"):
        return None, {"ok": False, "error": "tick the confirmation box first (these tools run shell commands)"}
    return sess, None


def do_f5_logs(b):
    sess, err = _f5_gate(b)
    if err:
        return err
    t0 = time.time()
    try:
        ip = parse_ip(b.get("ip"), "IP address")
        log = b.get("log", "ltm")
        if log not in F5_LOGS:
            raise ValueError("log file not allowed")
        n = num(b.get("lines"), 1, 500, 200, "lines")
        cutoff = cutoff_epoch(b)
        nfetch = 20000 if cutoff else n   # with a time range, read more lines and cut by time afterwards
        # Exact address only: not inside a longer one (10.1.1.1 must not match 10.1.1.10, 110.1.1.1 or 10.1.1.1.5).
        ch = "0-9A-Fa-f:." if ip.version == 6 else "0-9."
        pat = shlex.quote("(^|[^%s])%s($|[^%s]|\\.($|[^0-9]))" % (ch, re.escape(str(ip)), ch))
        if b.get("rotated"):
            script = ("zgrep -hE -- %s /var/log/%s /var/log/%s.*.gz 2>/dev/null | "
                      "sort -s -k1,1M -k2,2n -k3,3 | tail -n %d" % (pat, log, log, nfetch))
        else:
            script = "grep -hE -- %s /var/log/%s 2>&1 | tail -n %d" % (pat, log, nfetch)
        audit(sess, "log search %s in /var/log/%s" % (ip, log))
        st, ok, out, data = f5_bash(sess, script, 60)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
    if not ok:
        return {"ok": False, "status": st, "error": f5_bash_error(st, data, "log search")}
    lines = [l for l in out.splitlines() if l.strip()]
    if cutoff:
        lines = [l for l in lines if (log_epoch(l[:15]) or 0) >= cutoff][-n:]
    verdict = {"label": "%d LOG LINE(S) FOR %s" % (len(lines), ip), "kind": "ok" if lines else "info"}
    return {"ok": ok, "status": st, "ms": int((time.time() - t0) * 1000), "request": "bash: " + script,
            "data": {"lines": lines}, "verdict": verdict,
            "summary": ["Showing up to the last %d matching lines from /var/log/%s%s%s." % (
                n, log, " plus rotated files" if b.get("rotated") else "",
                ", time range: " + str(b.get("within")) if cutoff else "")]}


def f5_fetch(sess, path, local, limit=MAX_PCAP):
    """Copy a file from the BIG-IP to local through the shell (base64 in 256 KB blocks), so nothing has to be
    staged in /var/local/ucs. The MD5 is checked at the end. Returns bytes written."""
    q = shlex.quote(path)
    st, ok, out, _ = f5_bash(sess, "stat -c %%s %s 2>&1; md5sum %s 2>&1 | cut -d' ' -f1" % (q, q), 30)
    lines = out.split()
    if not ok or len(lines) < 2 or not lines[0].isdigit():
        raise RuntimeError("cannot read %s on the BIG-IP: %s" % (path, out.strip()[:200]))
    size, md5 = int(lines[0]), lines[1]
    if size > limit:
        raise RuntimeError("%s is %d MB, over the %d MB limit" % (path, size >> 20, limit >> 20))
    BLK, got, h = 256 * 1024, 0, hashlib.md5()
    with open(local, "wb") as f:
        for i in range((size + BLK - 1) // BLK):
            st, ok, out, _ = f5_bash(sess, "dd if=%s bs=%d skip=%d count=1 2>/dev/null | base64 -w0" % (q, BLK, i), 60)
            if not ok:
                raise RuntimeError("read of %s failed at block %d (HTTP %s)" % (path, i, st))
            try:
                chunk = base64.b64decode(out.strip())
            except ValueError:
                raise RuntimeError("unreadable data from %s at block %d" % (path, i))
            if not chunk:
                raise RuntimeError("empty block %d from %s" % (i, path))
            f.write(chunk)
            h.update(chunk)
            got += len(chunk)
            audit(sess, "download %s: %d of %d bytes" % (os.path.basename(path), got, size))
    if got != size or h.hexdigest() != md5:
        raise RuntimeError("%s did not copy cleanly (%d of %d bytes, checksum %s)" % (
            path, got, size, "ok" if h.hexdigest() == md5 else "differs"))
    return got


def do_f5_capture(b):
    sess, err = _f5_gate(b)
    if err:
        return err
    t0 = time.time()
    keep, local, cleaned, result = None, None, False, None
    try:
        ip = parse_ip(b.get("ip"), "IP address")
        port = num(b.get("port"), 1, 65535, None, "port") if str(b.get("port") or "").strip() else None
        iface = (b.get("iface") or "0.0:nnn").strip()
        if not IFACE_RE.match(iface):
            raise ValueError("invalid interface name")
        dur = num(b.get("duration"), 5, 50, 15, "seconds")
        cnt = num(b.get("count"), 1, 50000, 10000, "max packets")
        snap = num(b.get("snaplen"), 0, 65535, 0, "snaplen")
        keep = "/var/tmp/itsec%s.pcap" % time.strftime("%Y%m%d-%H%M%S")  # the capture stays here
        flt = "host %s" % ip + (" and port %d" % port if port else "")
        want_pms = b.get("pms") is True
        ssl_opt = " --f5 ssl" if (b.get("ssl") is True or want_pms) else ""  # embeds TLS session keys
        keep_pms = keep[:-len(".pcap")] + ".pms"
        audit(sess, "tcpdump %s on %s (%ds)%s%s" % (flt, iface, dur, ssl_opt, " + tshark keylog" if want_pms else ""))
        # Run detached and poll, so no single REST call has to stay open for the whole capture.
        tlog, tdone = keep + ".log", keep + ".done"
        # SIGINT (as Ctrl-C) is tcpdump's clean stop: it flushes the file and prints the packet counts.
        # -U writes each packet at once, so nothing is lost even if it has to be killed.
        inner = "timeout -s INT -k 5 %d tcpdump -U -ni %s -s %d -c %d%s -w %s %s > %s 2>&1; chmod 600 %s 2>&1" % (
            dur, iface, snap, cnt, ssl_opt, keep, flt, tlog, keep)
        if want_pms:
            # One keylog line per entry (tshark joins several per frame with commas), duplicates dropped.
            inner += ("; tshark -r %s -Y f5ethtrailer.tls.keylog -T fields -e f5ethtrailer.tls.keylog 2>> %s "
                      "| tr ',' '\\n' | sed '/^$/d' | sort -u > %s; chmod 600 %s 2>&1") % (
                keep, tlog, keep_pms, keep_pms)
        inner += "; touch %s" % tdone
        script = "setsid nohup sh -c %s > /dev/null 2>&1 < /dev/null &" % shlex.quote(inner)
        st, ok, out, data = f5_bash(sess, script, 20)
        if not ok:
            raise ValueError(f5_bash_error(st, data, "tcpdump start"))
        poll = ("if [ -e %s ]; then echo FINISHED; cat %s; echo PCAP_BYTES=$(stat -c %%s %s 2>/dev/null); "
                "echo PMS_BYTES=$([ -e %s ] && wc -c < %s); fi") % (tdone, tlog, keep, keep_pms, keep_pms)
        deadline = time.time() + dur + 45
        while True:
            time.sleep(3)
            st, ok, out, data = f5_bash(sess, poll, 20)
            audit(sess, "capture poll: HTTP %s, %s" % (st, "finished" if "FINISHED" in out else "not finished yet"))
            if "FINISHED" in out:
                break
            if time.time() > deadline:
                _, _, diag, _ = f5_bash(sess, "ls -l %s* 2>&1; ps -ef | grep '[t]cpdump' 2>&1; cat %s 2>&1" % (
                    keep, tlog), 20)
                raise ValueError("capture did not finish within %d s. On the BIG-IP: %s" % (
                    dur + 45, " | ".join(l.strip() for l in diag.splitlines() if l.strip())[:600] or "no output"))
        tlines = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith(("FINISHED", "PCAP_", "PMS_"))]
        pm = re.search(r"PCAP_BYTES=(\d+)", out)
        if not pm:
            raise ValueError("capture produced no file. tcpdump output: " + " | ".join(tlines)[:400])
        cm = re.search(r"(\d+) packets? captured", out)
        if int(pm.group(1)) <= 24 or (cm and cm.group(1) == "0"):   # 24 bytes = pcap header only
            f5_bash(sess, "rm -f %s %s" % (keep, keep_pms), 20)
            raise ValueError(
                "no packets matched '%s' on %s in %d s, so there is nothing to download. Check that: the traffic ran "
                "during the capture; the IP is the one the BIG-IP sees (behind Cloudflare the client side shows a "
                "Cloudflare edge IP, not the real client: filter on the virtual server IP or the pool member "
                "instead); 0.0:nnnp is used to also see the server side; this unit is the active one. tcpdump: %s" % (
                    flt, iface, dur, " | ".join(tlines)[:300] or "no output"))
        os.makedirs(CAPTURE_DIR, exist_ok=True)
        safe = re.sub(r'[^A-Za-z0-9_.\-]', "_", sess["name"])
        base = "%s_%s_%s" % (safe, str(ip).replace(":", "-"), time.strftime("%Y%m%d-%H%M%S"))
        local_name = base + ".pcap"
        local = os.path.join(CAPTURE_DIR, local_name)
        audit(sess, "capture: downloading pcap")
        written = f5_fetch(sess, keep, local)
        audit(sess, "capture: pcap downloaded (%d bytes)" % written)
        downloads, saved, warns = ["/api/capture/" + local_name], [local], []
        data = {"saved_file": local, "size_bytes": written, "bigip_file": keep}
        if want_pms:
            m = re.search(r"PMS_BYTES=(\d+)", out)
            warns.append("keys file on the BIG-IP (%s): %s" % (
                keep_pms, "%s bytes" % m.group(1) if m else "size not reported"))
            if not m or int(m.group(1)) == 0:
                tl = [l.strip() for l in out.splitlines() if "tshark" in l.lower()]
                warns.append("No TLS keys were extracted, so no .pms file was downloaded. "
                             + ("tshark said: " + " | ".join(tl)[:300] if tl else
                                "The capture may hold no TLS handshakes, or this BIG-IP's tshark lacks the "
                                "f5ethtrailer.tls.keylog field."))
            else:
                local_pms = os.path.join(CAPTURE_DIR, base + ".pms")
                try:
                    audit(sess, "capture: downloading pms (%s bytes on BIG-IP)" % m.group(1))
                    pms_bytes = f5_fetch(sess, keep_pms, local_pms)
                    downloads.append("/api/capture/" + base + ".pms")
                    saved.append(local_pms)
                    data.update({"pms_file": local_pms, "pms_size_bytes": pms_bytes, "bigip_pms_file": keep_pms})
                except (RuntimeError, urllib.error.URLError, OSError) as e:
                    warns.append(".pms download FAILED: %s. The file is still on the BIG-IP at %s" % (
                        getattr(e, "reason", e), keep_pms))
                    try:
                        os.remove(local_pms)
                    except OSError:
                        pass
        stats = [l for l in out.splitlines() if "packets" in l or "tcpdump:" in l]
        result = {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000),
                  "request": "bash: " + script, "download": downloads[0], "downloads": downloads,
                  "verdict": {"label": "CAPTURE SAVED (%d bytes)%s" % (
                      written, " + TLS KEYS (.pms)" if len(saved) > 1 else ""), "kind": "ok"},
                  "summary": ["Filter: %s on %s for up to %ds / %d packets." % (flt, iface, dur, cnt)] + stats[:4]
                             + (["TLS session keys are embedded (--f5 ssl): treat these files as sensitive."]
                                if ssl_opt else [])
                             + warns + ["Saved locally: " + ", ".join(saved),
                                        "Kept on the BIG-IP: " + keep + (", " + keep_pms if len(saved) > 1 else "")],
                  "data": data}
    except (ValueError, RuntimeError) as e:
        result = {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        result = {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
    except Exception as e:  # report instead of leaving the page on "running..."
        result = {"ok": False, "error": "unexpected error in capture: %r" % e}
    finally:
        if local and not (result or {}).get("ok"):
            for p in (local, local[:-len(".pcap")] + ".pms"):
                try:
                    os.remove(p)  # drop a partial download
                except OSError:
                    pass
        if keep:
            try:
                f5_bash(sess, "rm -f %s %s" % (keep + ".log", keep + ".done"), 20)  # helper files only
            except (urllib.error.URLError, OSError):
                pass
    return result


# ---- F5 file download: any file, or a folder as .tar.gz ----------------------
MAX_F5_FILE = 500 * 1024 * 1024
# Paths that hold secrets (password hashes, private keys, the master key, encrypted passwords in the config):
# downloading them needs a second tick-box. Entries ending in '/' are folders.
F5_SENSITIVE = ("/etc/shadow", "/etc/gshadow", "/config/bigip.conf", "/config/bigip_base.conf",
                "/config/bigip_user.conf", "/config/BigDB.dat", "/config/ssl/ssl.key/", "/config/filestore/",
                "/config/bigip/kstore/", "/config/bigip/auth/", "/config/httpd/conf/ssl.key/", "/root/.ssh/",
                "/home/", "/var/local/ucs/")


def f5_sensitive(path, is_dir):
    if not is_dir:
        return path.endswith(".key") or any(path.startswith(s) for s in F5_SENSITIVE)
    d = path.rstrip("/") + "/"
    return any(s.startswith(d) or d.startswith(s) for s in F5_SENSITIVE)


def f5_list_dir(sess, real, t0):
    """Entries of one BIG-IP folder (folders first), at most 2000."""
    st, ok, out, data = f5_bash(sess, "find %s -mindepth 1 -maxdepth 1 -printf '%%y|%%s|%%TY-%%Tm-%%Td %%TH:%%TM|%%p\\n' "
                                      "2>&1 | head -2000" % shlex.quote(real), 60)
    if not ok:
        raise ValueError(f5_bash_error(st, data, "folder listing"))
    kinds = {"d": "folder", "f": "file", "l": "link"}
    rows = []
    for ln in out.splitlines():
        p = ln.split("|", 3)
        if len(p) == 4 and p[1].isdigit():
            rows.append({"type": kinds.get(p[0], p[0]), "name": p[3].rsplit("/", 1)[-1],
                         "size": cf_fmt_bytes(int(p[1])) if p[0] == "f" else "", "modified": p[2], "path": p[3]})
    rows.sort(key=lambda r: (r["type"] != "folder", r["name"].lower()))
    return {"ok": True, "status": st, "ms": int((time.time() - t0) * 1000), "request": "bash: find " + real,
            "verdict": {"label": "%d ITEM(S) IN %s" % (len(rows), real), "kind": "info"},
            "summary": ["Pick a path from the Path field's list (it now holds these entries) and press Download."]
                       + (["Only the first 2000 entries are shown."] if len(rows) >= 2000 else []),
            "data": {"entries": rows}}


def do_f5_file(b):
    """Browse a BIG-IP folder, or copy one file (or a folder as .tar.gz) to this PC through util/bash."""
    sess, err = _f5_gate(b)
    if err:
        return err
    t0 = time.time()
    path = str(b.get("path") or "").strip()
    if not path.startswith("/") or len(path) > 1024 or re.search(r"[\x00-\x1f\x7f]", path):
        return {"ok": False, "error": "enter an absolute path on the BIG-IP, e.g. /var/log/ltm"}
    tmp, local, result = None, None, None
    try:
        st, ok, out, data = f5_bash(sess, "p=$(readlink -f -- %s) && stat -c '%%F|%%s' -- \"$p\" 2>&1 && echo \"$p\""
                                    % shlex.quote(path), 30)
        if not ok:
            raise ValueError(f5_bash_error(st, data, "file lookup"))
        lines = [l for l in out.splitlines() if l.strip()]
        if len(lines) < 2 or "|" not in lines[0]:
            raise ValueError("%s: %s" % (path, (out.strip() or "no such file or folder")[:200]))
        kind, real = lines[0].split("|", 1)[0], lines[1].strip()
        is_dir = kind == "directory"
        if not is_dir and not kind.startswith("regular"):
            raise ValueError("%s is a %s, not a file or folder" % (real, kind))
        if b.get("mode") == "list":
            audit(sess, "file browser: list " + real)
            return f5_list_dir(sess, real if is_dir else real.rsplit("/", 1)[0] or "/", t0)
        if f5_sensitive(real, is_dir) and b.get("sensitive") is not True:
            raise ValueError("%s holds (or may hold) secrets: password hashes, private keys, the master key or "
                             "encrypted passwords. Tick 'Allow sensitive files' to download it anyway." % real)
        src = real
        if is_dir:
            parent, name = real.rstrip("/").rsplit("/", 1)
            if not name:
                raise ValueError("choose a folder below /, not the whole file system")
            st, ok, out, data = f5_bash(sess, "du -sb -- %s 2>/dev/null | cut -f1" % shlex.quote(real), 120)
            if ok and out.strip().isdigit() and int(out.strip()) > MAX_F5_FILE:
                raise ValueError("%s holds %d MB, over the %d MB limit; download a subfolder or single files" % (
                    real, int(out.strip()) >> 20, MAX_F5_FILE >> 20))
            # Pack it detached and poll, so no single REST call has to stay open for the whole tar.
            tmp = "/var/tmp/itsec_dl_%s.tar.gz" % time.strftime("%Y%m%d-%H%M%S")
            inner = "tar czf %s -C %s -- %s > %s.log 2>&1; echo $? > %s.rc; chmod 600 %s" % (
                tmp, shlex.quote(parent or "/"), shlex.quote(name), tmp, tmp, tmp)
            audit(sess, "file download: packing folder " + real)
            st, ok, out, data = f5_bash(sess, "setsid nohup sh -c %s > /dev/null 2>&1 < /dev/null &" % shlex.quote(inner), 20)
            if not ok:
                raise ValueError(f5_bash_error(st, data, "tar start"))
            deadline = time.time() + 600
            while True:
                time.sleep(3)
                st, ok, out, data = f5_bash(sess, "cat %s.rc 2>/dev/null && tail -c 400 %s.log" % (tmp, tmp), 20)
                rc = out.split()[0] if ok and out.split() else ""
                if rc.isdigit():
                    break
                if time.time() > deadline:
                    raise ValueError("packing %s did not finish within 10 minutes" % real)
            if rc not in ("0", "1"):   # 1 = a file changed while being read (normal for live logs)
                raise ValueError("tar failed (exit %s): %s" % (rc, " ".join(out.split()[1:])[:300]))
            src = tmp
        os.makedirs(CAPTURE_DIR, exist_ok=True)
        safe = re.sub(r'[^A-Za-z0-9_.\-]', "_", sess["name"])
        base = re.sub(r'[^A-Za-z0-9_.\-]', "_", real.rstrip("/").rsplit("/", 1)[-1])[:120] + (".tar.gz" if is_dir else "")
        local_name = "f5file_%s_%s_%s" % (safe[:40], time.strftime("%Y%m%d-%H%M%S"), base)
        local = os.path.join(CAPTURE_DIR, local_name)
        audit(sess, "file download: %s" % real)
        written = f5_fetch(sess, src, local, MAX_F5_FILE)
        audit(sess, "file download: %s saved (%d bytes)" % (real, written))
        result = {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": "bash: read " + real,
                  "download": "/api/capture/" + local_name, "downloads": ["/api/capture/" + local_name],
                  "verdict": {"label": "%s DOWNLOADED (%s)" % ("FOLDER" if is_dir else "FILE", cf_fmt_bytes(written)),
                              "kind": "ok"},
                  "summary": ["BIG-IP %s: %s%s" % ("folder" if is_dir else "file", real,
                                                    " (resolved from %s)" % path if real != path.rstrip("/") else ""),
                              "Saved locally: " + local, "Copied in 256 KB blocks over iControl REST; MD5 verified."]
                             + (["This file can hold secrets: store the copy securely."] if f5_sensitive(real, is_dir)
                                else []),
                  "data": {"bigip_path": real, "saved_file": local, "size_bytes": written}}
    except (ValueError, RuntimeError) as e:
        result = {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        result = {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
    finally:
        if local and not (result or {}).get("ok"):
            try:
                os.remove(local)  # drop a partial download
            except OSError:
                pass
        if tmp:
            try:
                f5_bash(sess, "rm -f %s %s.log %s.rc" % (tmp, tmp, tmp), 20)
            except (urllib.error.URLError, OSError):
                pass
    return result


# ----------------------------------------------------------------------------
# AppSec: WAF / security-profile coverage, SSL posture,
# F5 ASM request log, PAN log search
# ----------------------------------------------------------------------------
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SUPPORT_ID_RE = re.compile(r'^[0-9]{5,25}$')
PAN_LOG_TYPES = ("threat", "url", "traffic")
PAN_LOG_PERIODS = ("last-15-minutes", "last-hour", "last-6-hrs", "last-12-hrs", "last-24-hrs",
                   "last-7-days", "last-30-days")
PAN_PROFILE_TYPES = ("virus", "spyware", "vulnerability", "url-filtering", "wildfire-analysis", "file-blocking")
PAN_REQUIRED_PROFILES = ("virus", "spyware", "vulnerability", "url-filtering", "wildfire-analysis")
WEAK_CIPHER_RE = re.compile(r'RC4|DES|EXPORT|EXP-|NULL|MD5|ADH|AECDH|anon', re.I)


def finding(sev, obj, issue, detail=""):
    return {"severity": sev, "object": obj or "", "issue": issue, "detail": detail}


def report(t0, request, findings, inventory, notes):
    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    label = ", ".join("%d %s" % (counts[s], s.upper()) for s in ("high", "medium", "low") if counts[s])
    kind = "bad" if counts["high"] else ("info" if counts["medium"] else "ok")
    summary = ["HIGH: %s (%s)" % (f["issue"], f["object"]) for f in findings if f["severity"] == "high"][:15]
    if counts["high"] > 15:
        summary.append("…and %d more high finding(s); see the output below." % (counts["high"] - 15))
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": request,
            "verdict": {"label": label or "NO ISSUES FOUND", "kind": kind}, "summary": summary,
            "data": {"findings": findings, "inventory": inventory, "notes": list(dict.fromkeys(notes))}}


def to_epoch(v):
    """Best-effort timestamp parse: epoch s/ms/us numbers or common date strings (UTC assumed)."""
    if isinstance(v, bool) or v in (None, ""):
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.strip().isdigit()):
        n = float(v)
        while n > 1e11:  # milliseconds / microseconds
            n /= 1000.0
        return n if n > 0 else None
    s = str(v).strip()
    for fmt, n in (("%Y/%m/%d %H:%M:%S", 19), ("%Y-%m-%dT%H:%M:%S", 19), ("%Y-%m-%d %H:%M:%S", 19),
                   ("%Y/%m/%d", 10), ("%Y-%m-%d", 10)):
        try:
            return calendar.timegm(time.strptime(s[:n], fmt))
        except ValueError:
            continue
    try:
        return ssl.cert_time_to_seconds(s)  # "Jan  1 00:00:00 2030 GMT"
    except ValueError:
        return None


LOOKBACK = {"any time": None, "last 15 minutes": 900, "last hour": 3600, "last 6 hours": 21600,
            "last 12 hours": 43200, "last 24 hours": 86400}


def cutoff_epoch(b):
    """Epoch of the oldest log entry wanted, from the 'within' field (at most one day back); None = any time."""
    v = str(b.get("within") or "any time").strip().lower()
    if v not in LOOKBACK:
        raise ValueError("invalid time range")
    return time.time() - LOOKBACK[v] if LOOKBACK[v] else None


def asm_recent(it, cutoff):
    if cutoff is None:
        return True
    e = to_epoch(first(it, "requestDatetime", "occurrenceTime", "dateTime", "time"))
    return e is None or e >= cutoff


def fg_event_epoch(e):
    """FortiGate log entry time as epoch (from eventtime, which is absolute); None if the device did not send it."""
    v = str(e.get("eventtime") or "").strip()
    if v.isdigit():
        n = float(v)
        while n > 1e11:
            n /= 1000.0
        return n
    return None


def days_from_now(epoch):
    return int((epoch - time.time()) // 86400)


def first(d, *keys):
    for k in keys:
        if d.get(k) not in (None, ""):
            return d[k]
    return ""


def f5_items(sess, path, notes, what):
    ok, d = f5_get(sess, path)
    if not ok:
        notes.append("could not read " + what)
        return None
    return d.get("items", [])


def f5_virtuals(sess, notes):
    return f5_items(sess, "/mgmt/tm/ltm/virtual?expandSubcollections=true", notes, "virtual servers") or []


def f5_vs_profiles(v):
    return [x.get("fullPath") for x in (v.get("profilesReference") or {}).get("items", [])]


# ---- F5 -----------------------------------------------------------------------
def f5_waf_posture(sess):
    findings, inv, notes = [], [], []
    vss = f5_virtuals(sess, notes)
    http_profiles = {p.get("fullPath") for p in
                     f5_items(sess, "/mgmt/tm/ltm/profile/http", notes, "HTTP profiles") or []}
    pols = f5_items(sess, "/mgmt/tm/asm/policies?$select=id,name,fullPath,enforcementMode,virtualServers,active",
                    notes, "ASM / Advanced WAF policies (module not provisioned, or no permission)")
    vs_pol = {}
    for p in pols or []:
        name, attached = p.get("fullPath") or p.get("name"), p.get("virtualServers") or []
        for vs in attached:
            vs_pol.setdefault(vs, []).append(p)
        mode = p.get("enforcementMode", "unknown")
        if attached and mode != "blocking":
            findings.append(finding("high", name, "WAF policy is not blocking (mode: %s)" % mode,
                                    "attached to: " + ", ".join(attached)))
        if not attached:
            findings.append(finding("low", name, "WAF policy is not attached to any virtual server"))
    for p in (pols or [])[:50]:
        pid, name = p.get("id"), p.get("fullPath") or p.get("name")
        if not pid:
            continue
        base = "/mgmt/tm/asm/policies/" + urllib.parse.quote(pid, safe="")
        ok, d = f5_get(sess, base + "/signatures?$filter=%s&$top=1&$select=performStaging"
                       % urllib.parse.quote("performStaging eq true"))
        n = d.get("totalItems") if ok else None
        if isinstance(n, int) and n:
            findings.append(finding("medium", name, "%d attack signature(s) in staging (alarm only, not enforced)" % n))
        ok, d = f5_get(sess, base + "/suggestions?$top=1")
        n = d.get("totalItems") if ok else None
        if isinstance(n, int) and n:
            findings.append(finding("low", name, "%d learning suggestion(s) pending review" % n))
    if pols and len(pols) > 50:
        notes.append("Staging/learning counts were checked for the first 50 policies only.")
    for v in vss:
        name = v.get("fullPath")
        is_http = any(p in http_profiles for p in f5_vs_profiles(v))
        attached = vs_pol.get(name, [])
        enabled = not v.get("disabled", False)
        inv.append({"virtual": name, "destination": v.get("destination"), "enabled": enabled,
                    "http_profile": is_http,
                    "waf_policy": ", ".join(p.get("fullPath") or p.get("name") or "" for p in attached),
                    "mode": ", ".join(p.get("enforcementMode", "") for p in attached)})
        if is_http and enabled and not attached and pols is not None:
            findings.append(finding("high", name, "HTTP virtual server has no WAF policy",
                                    "destination " + str(v.get("destination"))))
    notes.append("A virtual server counts as HTTP when it has an LTM HTTP profile. Policies applied only "
                 "through iRules or a BIG-IP Next/NGINX layer are not visible here.")
    return findings, inv, notes


def f5_ssl_posture(sess, warn_days):
    findings, inv, notes = [], [], []
    usage = {}
    for v in f5_virtuals(sess, notes):
        for p in f5_vs_profiles(v):
            usage.setdefault(p, []).append(v.get("fullPath"))
    cert_users = {}
    for p in f5_items(sess, "/mgmt/tm/ltm/profile/client-ssl", notes, "client-SSL profiles") or []:
        name, used = p.get("fullPath"), usage.get(p.get("fullPath"), [])
        where = "used by: " + (", ".join(used) or "no virtual server")
        opts = p.get("options") or []
        opts = opts.split() if isinstance(opts, str) else list(opts)
        if isinstance(p.get("tmOptions"), str):
            opts += p["tmOptions"].strip("{} ").split()
        ciphers = p.get("ciphers") or ""
        tokens = [t for t in re.split(r"[:,\s]+", ciphers) if t]
        negated = {t.lstrip("!-").lower() for t in tokens if t[0] in "!-"}
        group = p.get("cipherGroup") if p.get("cipherGroup") not in (None, "", "none") else ""
        not_disabled = []
        for proto, opt, tok, sev in (("SSLv3", "no-sslv3", "sslv3", "medium"),
                                     ("TLS 1.0", "no-tlsv1", "tlsv1", "low"),
                                     ("TLS 1.1", "no-tlsv1.1", "tlsv1_1", "low")):
            if opt not in opts and tok not in negated:
                not_disabled.append(proto)
                findings.append(finding(sev if used else "info", name, proto + " is not explicitly disabled",
                                        where + "; effective protocols also depend on the cipher string/group, "
                                        "confirm with the TLS check or 'tmm --clientciphers'"))
        weak = [t for t in tokens if t[0] not in "!-" and WEAK_CIPHER_RE.search(t)]
        if weak:
            findings.append(finding("high" if used else "low", name,
                                    "Cipher string explicitly includes weak ciphers: " + ", ".join(weak), where))
        for ck in p.get("certKeyChain") or []:
            if ck.get("cert"):
                cert_users.setdefault(ck["cert"], []).append(name)
        inv.append({"type": "client-ssl", "name": name, "used_by": used, "ciphers": ciphers,
                    "cipher_group": group, "options": opts, "not_explicitly_disabled": not_disabled,
                    "certs": [ck.get("cert") for ck in p.get("certKeyChain") or []]})
    for c in f5_items(sess, "/mgmt/tm/sys/crypto/cert", notes, "certificates") or []:
        if c.get("isBundle") in (True, "true"):
            continue
        name = c.get("fullPath") or c.get("name")
        exp = to_epoch(c.get("expirationDate")) or to_epoch(c.get("expirationString"))
        left = days_from_now(exp) if exp else None
        users = cert_users.get(name, [])
        where = "used by: " + (", ".join(users) or "no client-SSL profile")
        if left is not None:
            if left < 0:
                sev, issue = "high", "Certificate EXPIRED %d day(s) ago" % -left
            elif left < 30:
                sev, issue = "high", "Certificate expires in %d day(s)" % left
            elif left < warn_days:
                sev, issue = "medium", "Certificate expires in %d day(s)" % left
            else:
                sev = None
            if sev:
                findings.append(finding(sev if users else "low", name, issue, where))
        size, ktype = c.get("keySize"), str(c.get("keyType") or "")
        if isinstance(size, int) and "rsa" in ktype.lower() and size < 2048:
            findings.append(finding("medium" if users else "low", name, "RSA key is only %d bits" % size, where))
        inv.append({"type": "certificate", "name": name, "subject": c.get("subject"),
                    "expires": c.get("expirationString"), "days_left": left, "key": "%s %s" % (ktype, size or ""),
                    "used_by": users})
    notes.append("'Used by' covers client-SSL profiles attached to virtual servers. Certificates referenced "
                 "only by server-SSL, APM, or monitors show as unused.")
    return findings, inv, notes


def f5_ref_get(sess, ref, cache):
    link = ref.get("link") if isinstance(ref, dict) else None
    u = urllib.parse.urlparse(link or "")
    if not u.path.startswith("/mgmt/tm/") or len(cache) >= 60:
        return None
    path = u.path + ("?" + u.query if u.query else "")
    if path not in cache:
        ok, d = f5_get(sess, path)
        cache[path] = d if ok else None
    return cache[path]


def f5_ref_name(sess, ref, cache):
    d = f5_ref_get(sess, ref, cache)
    return first(d, "name", "title", "id") if d else None


def asm_header_ip(it):
    """True-Client-IP value of a logged request (the real client when proxied by Cloudflare)."""
    if it.get("trueClientIp"):
        return str(it["trueClientIp"]).strip()
    # Search the whole entry (JSON-escaped CR/LF end the value) so it works wherever the device puts the headers.
    m = re.search(r"(?i)true-client-ip(?:\\\"|\")?\s*[:=]\s*(?:\\\"|\")?([0-9a-f:.]{3,45})", json.dumps(it))
    return m.group(1) if m else ""


def asm_support_id(it):
    """Support ID of a logged request; tolerant of the field being named differently or nested."""
    v = first(it, "supportId", "support_id", "supportID", "supportid")
    if v:
        return str(v)
    if re.fullmatch(r"\d{5,25}", str(it.get("id") or "")):
        return str(it["id"])  # on this BIG-IP the request's "id" field is the support ID
    for k, val in it.items():
        if "support" in k.lower() and isinstance(val, (str, int)) and str(val).strip():
            return str(val)
    m = re.search(r'(?i)"support_?id"\s*:\s*"?(\d{5,25})', json.dumps(it))
    return m.group(1) if m else ""


def asm_hostname(it):
    """Host the request was sent to: the log's own field if present, else the Host header of the raw request."""
    h = first(it, "hostname", "host", "requestHost")
    if h:
        return str(h)
    m = re.search(r"(?i)(?:^|\\r\\n|\\n|\r\n|\n)host\s*:\s*([^\s\\]+)", json.dumps(it.get("rawRequest") or ""))
    return m.group(1) if m else ""


def asm_reason(sess, it, cache):
    """Violation and sub-violation names of a logged request, e.g. 'Illegal URL; Attack signature detected (sig name)'."""
    out = []
    for v in it.get("violations") or []:
        vd = f5_ref_get(sess, v.get("violationReference"), cache) or {}
        name = vd.get("title") or vd.get("description") or vd.get("name") or ""
        sub = first(v, "subViolation", "subViolations", "subViolationName", "subViolationReference")
        if isinstance(sub, dict):
            sub = f5_ref_name(sess, sub, cache) or sub.get("name")
        elif isinstance(sub, list):
            sub = ", ".join(str(f5_ref_name(sess, s, cache) if isinstance(s, dict) else s) for s in sub)
        if name:
            out.append("%s: %s" % (name, sub) if sub else name)
    return "; ".join(out)


def utc3(ts):
    """ISO timestamp with a zone (e.g. 2026-10-20T12:02:57Z) -> 'YYYY-MM-DD HH:MM:SS' in UTC+3.
    Anything without a zone (or not ISO) is returned unchanged."""
    s = str(ts or "").strip()
    try:
        d = datetime.datetime.fromisoformat(re.sub(r"Z$", "+00:00", s))
    except ValueError:
        return ts
    if d.tzinfo is None:
        return ts
    return d.astimezone(datetime.timezone(datetime.timedelta(hours=3))).strftime("%Y-%m-%d %H:%M:%S")


def asm_row(it):
    return {"time": utc3(first(it, "requestDatetime", "occurrenceTime", "dateTime", "time")),
            "support_id": asm_support_id(it), "hostname": asm_hostname(it),
            "status": first(it, "requestStatus", "enforcementState"),
            "client": it.get("clientIp", ""),
            "true_client_ip": asm_header_ip(it),
            "method": it.get("method"), "url": first(it, "url", "uri"),
            "response_code": it.get("responseCode"), "rating": it.get("violationRating")}


# Request status names differ by TMOS version: an alerted (illegal but not blocked) request is 'illegal' on some.
ASM_STATUS = {"blocked": ("blocked",), "alerted": ("alerted", "illegal", "alarmed"), "passed": ("passed", "legal")}


def asm_status_ok(it, status):
    return not status or str(first(it, "requestStatus", "enforcementState") or "").lower() in ASM_STATUS[status]


def asm_status_flt(sess, status):
    """Device-side filter for a request status, in the name this device uses (probed once per session).
    '' when there is no status or the device accepts none; the caller then matches locally with asm_status_ok."""
    if not status:
        return ""
    cache = sess.setdefault("asm_status_flt", {})
    if status not in cache:
        accepted = []
        for v in ASM_STATUS[status]:
            f = "requestStatus eq '%s'" % v
            st, ok, d = rest_get(sess, "/mgmt/tm/asm/events/requests?$filter=%s&$top=1" % urllib.parse.quote(f))
            if ok and isinstance(d, dict):
                accepted.append(f)
                if d.get("items"):   # a name the device accepts but never uses returns nothing
                    accepted = [f]
                    break
        cache[status] = accepted[0] if accepted else ""
    return cache[status]


def asm_http(it):
    """Raw request of a logged entry -> (header lines incl. request line, [(name_lower, value)], body); empty if absent."""
    raw = it.get("rawRequest") or {}
    text = raw.get("httpRequest") if isinstance(raw, dict) else raw
    text = text if isinstance(text, str) else ""
    head, _, body = text.replace("\r\n", "\n").partition("\n\n")
    hlines = head.split("\n") if text else []
    pairs = []
    for ln in hlines[1:]:
        k, _, val = ln.partition(":")
        if val:
            pairs.append((k.strip().lower(), val.strip()))
    return hlines, pairs, body


def f5_asm_by_header(sess, b, t0):
    """Requests carrying an HTTP header (optionally whose value contains a string), newest first, matched locally
    on the raw request since arbitrary headers cannot be filtered on the device."""
    hname = (b.get("header_name") or "").strip()
    if not re.match(r"^[A-Za-z0-9!#$%&'*+.^_`|~\-]{1,100}$", hname):
        raise ValueError("enter a valid HTTP header name, e.g. User-Agent or X-Request-ID")
    hval = (b.get("header_value") or "").strip()
    if len(hval) > 500:
        raise ValueError("header value is too long (max 500 characters)")
    status = (b.get("status") or "").strip()
    if status not in ("", "blocked", "alerted", "passed"):
        raise ValueError("invalid status")
    hostq = (b.get("hostname") or "").strip().lower().replace("*", "")
    top = num(b.get("top"), 1, 200, 50, "max rows")
    scan = num(b.get("scan"), 100, 5000, 1000, "entries to scan")
    cutoff = cutoff_epoch(b)
    hkey, vq = hname.lower(), hval.lower()
    audit(sess, "ASM request log by header: %s %s %s" % (hname, ("contains '%s'" % hval) if hval else "present",
                                                           status or "any status"))
    flt = asm_status_flt(sess, status)
    base = "/mgmt/tm/asm/events/requests?" + ("$filter=%s&" % urllib.parse.quote(flt) if flt else "")
    order = "$orderby=requestDatetime%20desc&"
    st, ok0, d0 = rest_get(sess, base + order + "$top=1")
    newest_first = ok0 and isinstance(d0, dict) and bool(d0.get("items"))
    base += order if newest_first else ""

    def hdr_values(i):
        return [v for k, v in asm_http(i)[1] if k == hkey]

    matches, scanned, fetched, with_raw, prev, path, capped = [], 0, 0, 0, None, base, True
    for skip in range(0, scan, 200):
        if time.time() - t0 > 100:
            break
        path = base + "$top=%d" % min(200, scan - skip) + ("&$skip=%d" % skip if skip else "")
        st, ok, data = rest_get(sess, path)
        if not ok or not isinstance(data, dict):
            return {"ok": False, "status": st, "error": "request log query failed (HTTP %s). Is ASM / Advanced WAF "
                    "provisioned and does the account have access?" % st}
        page = data.get("items", [])
        fid = json.dumps(page[0], sort_keys=True) if page else None
        if skip and fid == prev:
            capped = False   # device ignores $skip and repeats the first page
            break
        prev = fid
        scanned += len(page)
        for i in page:
            if not asm_recent(i, cutoff) or not asm_status_ok(i, status) or (
                    hostq and asm_hostname(i) and hostq not in asm_hostname(i).lower()):
                continue
            # The list view may omit the raw request; fetch the full record (bounded by time and count).
            if not i.get("rawRequest") and fetched < 1500 and time.time() - t0 < 100 and asm_enrich(sess, i):
                fetched += 1
            if i.get("rawRequest"):
                with_raw += 1
            if hostq and hostq not in asm_hostname(i).lower():
                continue
            vals = hdr_values(i)
            if vals and (not vq or any(vq in v.lower() for v in vals)):
                matches.append(i)
            if len(matches) >= top:
                break
        if len(page) < 200 or len(matches) >= top:
            capped = False
            break
        if cutoff and newest_first and page and not asm_recent(page[-1], cutoff):
            capped = False   # reached entries older than the time range
            break
    rows = []
    for it in matches:
        hlines, pairs, body = asm_http(it)
        hdrs = dict(reversed(pairs))
        method = str(it.get("method") or (hlines[0].split(" ")[0] if hlines else "")).upper()
        rows.append({"time": utc3(first(it, "requestDatetime", "occurrenceTime", "dateTime", "time")),
                     "timezone": "UTC+3",
                     "header": hname,
                     "header_value": " | ".join(hdr_values(it)),
                     "ip": it.get("clientIp", ""),
                     "true_client_id": it.get("trueClientIp") or hdrs.get("true-client-ip") or asm_header_ip(it),
                     "hostname": asm_hostname(it) or hdrs.get("host", ""),
                     "method": method,
                     "url": str(first(it, "url", "uri") or ""),
                     "support_id": asm_support_id(it),
                     "status": first(it, "requestStatus", "enforcementState"),
                     "body": body if method == "POST" else ""})
    notes = ["Header %s %s; scanned %d log entries (%d with raw request data)%s." % (
        hname, ("value contains '%s'" % hval) if hval else "present (any value)", scanned, with_raw,
        ", status " + status if status else "")]
    if status and not flt:
        notes.append("The device accepts no status filter, so '%s' was matched locally." % status)
    if cutoff:
        notes.append("Time range: %s (applied to the request time of each entry)." % b.get("within"))
    notes.append("Times are shown in UTC+3." if newest_first else
                 "Order: device default (the device rejected $orderby=requestDatetime desc). Times are in UTC+3.")
    if capped and len(matches) < top:
        notes.append("Scan stopped at %d entries / time limit before reaching the end of the log; raise 'Entries to "
                     "scan' or add a status / hostname filter to narrow it." % scanned)
    if scanned and not with_raw:
        notes.append("No entry includes the raw request, so headers cannot be read: the logging profile may not store "
                     "request headers.")
    lines = ["%(time)s %(timezone)s  %(status)-8s %(ip)s  [True-Client-IP %(true_client_id)s]  %(method)s %(hostname)s"
             "%(url)s  %(header)s: %(header_value)s  (support ID %(support_id)s)" % r
             + ("\n    body: " + r["body"][:2000] if r["body"] else "") for r in rows]
    return {"ok": True, "status": st, "ms": int((time.time() - t0) * 1000), "request": "GET " + path,
            "verdict": {"label": "%d REQUEST(S) WITH HEADER %s" % (len(rows), hname.upper()),
                        "kind": "warn" if rows else "info"},
            "summary": notes, "data": {"lines": lines, "requests": rows}}


def asm_enrich(sess, it):
    """Merge the full request record (violations, raw request, support ID) into a list entry. True if fetched."""
    path = urllib.parse.urlparse(str(it.get("selfLink") or "")).path
    if not path.startswith("/mgmt/tm/asm/events/requests/") and re.match(r"^[A-Za-z0-9_\-]{6,64}$", str(it.get("id") or "")):
        path = "/mgmt/tm/asm/events/requests/" + str(it["id"])
    if not path.startswith("/mgmt/tm/asm/events/requests/"):
        return False
    ok, d = f5_get(sess, path)
    if not ok or not isinstance(d, dict):
        return False
    for k, v in d.items():
        if not it.get(k):
            it[k] = v
    return True


def f5_asm_top_hosts(sess, b, t0):
    """Top 10 hostnames by violating requests, each with violations, source IPs, True-Client-IPs and URLs."""
    status = (b.get("status") or "").strip()
    if status not in ("", "blocked", "alerted"):
        raise ValueError("status must be blocked, alerted or empty (both) for the top-hostnames report")
    scan = num(b.get("scan"), 100, 5000, 1000, "entries to scan")
    cutoff = cutoff_epoch(b)
    statuses = [status] if status else ["blocked", "alerted"]
    audit(sess, "ASM top hostnames by violations (%s, scan %d)" % (status or "blocked+alerted", scan))
    items, notes, last_path = [], [], ""
    for stx in statuses:
        flt = urllib.parse.quote(asm_status_flt(sess, stx))
        use_f, use_o = True, True
        prev, got, tried = None, 0, []
        for skip in range(0, scan, 200):
            if time.time() - t0 > 60:
                notes.append("Scan of '%s' stopped at the 60 s time limit." % stx)
                break
            top = min(200, scan - skip)

            def build(uf, uo):
                q = (["$filter=" + flt] if uf else []) + (["$orderby=requestDatetime%20desc"] if uo else []) + \
                    ["$top=%d" % top] + (["$skip=%d" % skip] if skip else [])
                return "/mgmt/tm/asm/events/requests?" + "&".join(q)
            if skip == 0:   # find a query form this TMOS version accepts, simplest-last
                for uf, uo in ((True, True), (True, False), (False, True), (False, False))[0 if flt else 2:]:
                    last_path = build(uf, uo)
                    st, ok, data = rest_get(sess, last_path)
                    if ok and isinstance(data, dict):
                        use_f, use_o = uf, uo
                        break
                    tried.append("HTTP %s for %s%s" % (st, last_path, (": " + str(first(data, "message"))[:160])
                                                      if isinstance(data, dict) and first(data, "message") else ""))
            else:
                last_path = build(use_f, use_o)
                st, ok, data = rest_get(sess, last_path)
            if not ok or not isinstance(data, dict):
                return {"ok": False, "status": st, "error": "request log query failed (HTTP %s). Is ASM / Advanced WAF "
                        "provisioned and does the account have access? Tried: %s" % (st, " | ".join(tried))}
            page = data.get("items", [])
            raw_n = len(page)
            fid = json.dumps(page[0], sort_keys=True) if page else None
            if skip and fid == prev:
                break          # device ignores $skip and repeats the first page
            prev = fid
            reached_old = False
            if cutoff:
                kept = [i for i in page if asm_recent(i, cutoff)]
                reached_old = use_o and len(kept) < len(page)   # newest first: everything after this is older
                page = kept
            if not use_f:
                page = [i for i in page if asm_status_ok(i, stx)]
            items += page
            got += len(page)
            if raw_n < top or reached_old:
                break
        if not use_f:
            notes.append("Device rejected the status filter, so '%s' was filtered locally over the newest %d entries "
                         "(narrower than a device-side filter)." % (stx, scan))
        if not use_o:
            notes.append("Device rejected $orderby, so 'newest first' is not guaranteed for '%s'." % stx)
            if cutoff:
                notes.append("Time range applied to the %d entries scanned only (device could not sort newest first)." % scan)
    if not items:
        return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": "GET " + last_path,
                "verdict": {"label": "NO %s REQUESTS FOUND" % "/".join(statuses).upper(), "kind": "info"},
                "summary": ["The request log has no entries with that status (or logging does not store them)."], "data": {}}
    # Resolve missing hostnames from the full record (the list view may omit the raw request).
    fetched, unresolved = 0, 0
    for it in items:
        if asm_hostname(it):
            continue
        if fetched < 300 and time.time() - t0 < 80 and asm_enrich(sess, it):
            fetched += 1
        if not asm_hostname(it):
            unresolved += 1
    by_host = collections.defaultdict(list)
    for it in items:
        by_host[(asm_hostname(it) or "(unknown)").lower()].append(it)
    ranked = sorted(by_host.items(), key=lambda kv: -len(kv[1]))[:10]
    vcache, rows, sampled = {}, [], 0
    for rank, (host, lst) in enumerate(ranked, 1):
        sample = lst[:30]
        for it in sample:
            if (not it.get("violations") or not it.get("rawRequest")) and fetched < 700 and time.time() - t0 < 100:
                if asm_enrich(sess, it):
                    fetched += 1
        viol, ips, tcis, urls = (collections.Counter() for _ in range(4))
        for it in sample:
            reason = asm_reason(sess, it, vcache) if time.time() - t0 < 115 else ""
            for v in [x for x in reason.split("; ") if x]:
                viol[v] += 1
            ips[str(it.get("clientIp") or "")] += 1
            tcis[asm_header_ip(it)] += 1
            urls[str(first(it, "url", "uri") or "")] += 1
        sampled += len(sample)
        fmt = lambda c: "; ".join("%s (%d)" % (k, n) for k, n in c.most_common(5) if k) or "-"
        rows.append({"rank": rank, "hostname": host, "requests": len(lst), "violations": fmt(viol),
                     "source_ips": fmt(ips), "true_client_ips": fmt(tcis), "urls": fmt(urls),
                     "sampled": len(sample)})
    # Overall top source IPs and True-Client-IPs across every scanned request (each with its main hostnames).
    ip_c, tci_c = collections.Counter(), collections.Counter()
    ip_h, tci_h = collections.defaultdict(collections.Counter), collections.defaultdict(collections.Counter)
    tci_seen = 0
    for it in items:
        host = (asm_hostname(it) or "(unknown)").lower()
        ip = str(it.get("clientIp") or "").strip()
        if ip:
            ip_c[ip] += 1
            ip_h[ip][host] += 1
        if not asm_header_ip(it) and not it.get("rawRequest") and fetched < 1000 and time.time() - t0 < 105:
            if asm_enrich(sess, it):
                fetched += 1
        tci = asm_header_ip(it)
        if tci or it.get("rawRequest"):
            tci_seen += 1
        if tci:
            tci_c[tci] += 1
            tci_h[tci][host] += 1

    def top_rows(c, hosts, key):
        return [{"rank": n_, key: k, "requests": v,
                 "hostnames": "; ".join("%s (%d)" % hv for hv in hosts[k].most_common(3))}
                for n_, (k, v) in enumerate(c.most_common(10), 1)]
    top_ips, top_tcis = top_rows(ip_c, ip_h, "source_ip"), top_rows(tci_c, tci_h, "true_client_ip")
    if tci_seen < len(items):
        notes.append("True-Client-IP could be read for %d of %d scanned requests (the rest were not fetched in time or "
                     "have no raw request)." % (tci_seen, len(items)))
    if cutoff:
        notes.insert(0, "Time range: %s." % (b.get("within") or "any time"))
    notes.insert(0 if not cutoff else 1, "Scanned %d %s request(s). 'requests' counts all of them per hostname; violations, IPs and URLs "
                    "are from the newest %d per hostname (counts in brackets are within that sample)." %
                 (len(items), "/".join(statuses), 30))
    if unresolved:
        notes.append("%d request(s) have no hostname in the log and are grouped as '(unknown)'." % unresolved)
    if not any(r["true_client_ips"] != "-" for r in rows):
        notes.append("No True-Client-IP header found in these requests: the logging profile may not store request headers.")
    if not any(r["violations"] != "-" for r in rows):
        notes.append("No violation names could be read; the device may not return violation details for these entries.")
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": "GET " + last_path,
            "verdict": {"label": "TOP %d HOSTNAME(S), %d SOURCE IP(S), %d TRUE-CLIENT-IP(S) BY VIOLATING REQUESTS" % (len(rows), len(top_ips), len(top_tcis)), "kind": "warn"},
            "summary": notes,
            "data": {"top_hostnames": rows, "top_source_ips": top_ips, "top_true_client_ips": top_tcis}}


def do_f5_asm(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess or sess["vendor"] != "f5":
        return {"ok": False, "error": "connect an F5 device first"}
    t0 = time.time()
    cutoff = None
    try:
        if b.get("mode") == "tophosts":
            return f5_asm_top_hosts(sess, b, t0)
        if b.get("mode") == "header":
            return f5_asm_by_header(sess, b, t0)
        cutoff = cutoff_epoch(b)
        outside = []
        if b.get("mode") == "supportid":
            sid = str(b.get("support_id") or "").strip()
            if not SUPPORT_ID_RE.match(sid):
                raise ValueError("support ID must be 5-25 digits")
            flt, top = "supportId eq '%s'" % sid, 5
        else:
            parts = []
            if str(b.get("ip") or "").strip():
                parts.append("clientIp eq '%s'" % parse_ip(b.get("ip"), "client IP"))
            status = b.get("status") or ""
            if status:
                if status not in ASM_STATUS:
                    raise ValueError("invalid status")
                if asm_status_flt(sess, status):
                    parts.append(asm_status_flt(sess, status))
            hip = ""
            if str(b.get("header_ip") or "").strip():
                hip = str(parse_ip(b.get("header_ip"), "True-Client-IP"))
            urlq = (b.get("url") or "").strip()
            if urlq and not re.match(r"^[A-Za-z0-9_./~%?=&:+,;@*\-]{1,200}$", urlq):
                raise ValueError("URL path has characters that are not allowed (no quotes, spaces or brackets)")
            hostq = (b.get("hostname") or "").strip().lower()
            if hostq and not re.match(r"^[a-z0-9_.*:\-]{1,253}$", hostq):
                raise ValueError("hostname has characters that are not allowed (letters, digits, . - _ * only)")
            hostq = hostq.replace("*", "")
            if not parts and not status and not hip and not urlq and not hostq:
                raise ValueError("enter a client IP, True-Client-IP, hostname or URL path and/or choose a status")
            flt, top = " and ".join(parts), num(b.get("top"), 1, 200, 50, "max rows")

            def hostok(i):
                return (not hostq or hostq in asm_hostname(i).lower()) and asm_status_ok(i, status)

            def hit0(i):  # local match (no time test), used to verify device-side filters
                u = str(first(i, "url", "uri") or "")
                return (not urlq or urlq.lower() in u.lower()) and (not hip or asm_header_ip(i) == hip) and hostok(i)

            def hit(i):  # local match while paging
                return hit0(i) and asm_recent(i, cutoff)
        if b.get("mode") != "supportid" and (hip or urlq or hostq or (status and not flt)):
            # The device's clientIp is Cloudflare's edge; True-Client-IP lives in the request headers and is not
            # reliably filterable server-side, so page through the log (other filters applied) and match locally.
            base = "/mgmt/tm/asm/events/requests?" + ("$filter=%s&" % urllib.parse.quote(flt) if flt else "")
            order = "$orderby=requestDatetime%20desc&"
            st0, ok0, d0 = rest_get(sess, base + order + "$top=1")
            newest_first = ok0 and isinstance(d0, dict) and bool(d0.get("items"))
            base += order if newest_first else ""
            # Prefer a server-side filter (filtered queries return newest first and reach the whole log). Accept
            # one only if the device really applied it: every returned entry must carry our True-Client-IP.
            server_filter = ""
            cands = [(f, e, hip) for f in ("trueClientIp", "xForwardedForHeaderValue")
                     for e in ("%s eq '%s'", "contains(%s,'%s')")] if hip else \
                    [("url", e, urlq) for e in ("contains(%s,'%s')", "%s eq '%s'")] if urlq else \
                    [(f, "contains(%s,'%s')", hostq) for f in ("hostname", "host")] if hostq else []
            for field, expr, val in cands:
                cand = expr % (field, val)
                cflt = "%s and %s" % (flt, cand) if flt else cand
                cs, cok, cd = rest_get(sess, "/mgmt/tm/asm/events/requests?$filter=%s&$top=20"
                                       % urllib.parse.quote(cflt))
                cit = cd.get("items", []) if cok and isinstance(cd, dict) else []
                if cit and all(hit0(i) for i in cit):
                    server_filter = cflt
                    break
            if server_filter:
                base = "/mgmt/tm/asm/events/requests?$filter=%s&" % urllib.parse.quote(server_filter)
                newest_first = True
            audit(sess, "ASM request log: True-Client-IP %s URL %s host %s %s" % (hip or "*", urlq or "*", hostq or "*", flt))
            items, scanned, st, seen_tci, has_raw = [], 0, 0, set(), 0
            limit_scan, prev_first, capped, times = 20000, None, True, []
            newest, loose_hits = [], 0
            # Also accept the IP appearing anywhere in the entry (e.g. X-Forwarded-For or another header form).
            loose = re.compile(r"(?<![\d.:])%s(?![\d.])" % re.escape(hip)) if hip else None
            for skip in range(0, limit_scan, 200):
                if time.time() - t0 > 120:
                    break
                path = base + "$top=200&$skip=%d" % skip
                st, ok, data = rest_get(sess, path)
                if not ok or not isinstance(data, dict):
                    return {"ok": False, "status": st, "error": "request log query failed (HTTP %s). Is ASM / "
                            "Advanced WAF provisioned and does the account have access?" % st}
                page = data.get("items", [])
                first_id = json.dumps(page[0], sort_keys=True) if page else None
                if skip and first_id == prev_first:
                    capped = False  # device ignores $skip and repeats the first page
                    break
                prev_first = first_id
                if page:
                    times += [str(first(page[0], "requestDatetime", "occurrenceTime", "dateTime", "time") or ""),
                              str(first(page[-1], "requestDatetime", "occurrenceTime", "dateTime", "time") or "")]
                scanned += len(page)
                for i in page:
                    if not asm_recent(i, cutoff):
                        continue
                    v = asm_header_ip(i)
                    has_raw += 1 if i.get("rawRequest") else 0
                    if v:
                        seen_tci.add(v)
                    if len(newest) < 8:
                        newest.append("%s→%s" % (i.get("clientIp", "?"), v or "none"))
                    if hit(i):
                        items.append(i)
                    elif loose and urlq == "" and hostok(i) and loose.search(json.dumps(i)):
                        items.append(i)
                        loose_hits += 1
                    elif loose and urlq and hip and hostok(i) and loose.search(json.dumps(i)) \
                            and urlq.lower() in str(first(i, "url", "uri") or "").lower():
                        items.append(i)
                        loose_hits += 1
                if len(page) < 200 or len(items) >= top:
                    capped = False
                    break
                if cutoff and newest_first and page and not asm_recent(page[-1], cutoff):
                    capped = False   # reached entries older than the time range
                    break
            items = items[:top]
            diag = ["Diagnostics: scanned %d entries, %d include raw request data, %d distinct True-Client-IP "
                    "values found%s." % (scanned, has_raw, len(seen_tci),
                                         " (e.g. " + ", ".join(sorted(seen_tci)[:5]) + ")" if seen_tci else "")]
            if loose_hits:
                diag.append("%d match(es) have the IP somewhere other than a parsed True-Client-IP header "
                            "(e.g. X-Forwarded-For); the True-Client-IP column shows what was parsed." % loose_hits)
            diag.append("Newest entries (device-seen client → parsed True-Client-IP): " + "; ".join(newest))
            if server_filter:
                diag.append("Used device-side filter: " + server_filter)
            diag.append("Order: newest first." if newest_first else
                        "Order: device default (the device rejected $orderby=requestDatetime desc).")
            if times:
                diag.append("Log time range scanned: %s  to  %s." % (times[0], times[-1]))
            if capped and not items:
                diag.append("Scan stopped at %d entries / 2 minutes before reaching the end of the log; add a "
                            "Status filter (e.g. blocked) to narrow it." % scanned)
            if hip and not seen_tci:
                diag.append("No entry contains a True-Client-IP header: the logging profile may not store request "
                            "headers, or the list API omits them. Open one request by support ID to check.")
            flt = ("%s and " % flt if flt else "") + " and ".join(
                x for x in (("True-Client-IP = %s" % hip) if hip else "", ("URL contains %s" % urlq) if urlq else "",
                            ("hostname contains %s" % hostq) if hostq else "")
                if x) + " (scanned %d log entries)" % scanned
        else:
            path = "/mgmt/tm/asm/events/requests?$filter=%s&$top=%d" % (urllib.parse.quote(flt), top)
            audit(sess, "ASM request log: " + flt)
            st, ok, data = rest_get(sess, path)
            if (not ok or not isinstance(data, dict)) and b.get("mode") == "supportid":
                data = {}  # the device may reject a supportId filter; the lookups below still find it
            elif not ok or not isinstance(data, dict):
                return {"ok": False, "status": st, "error": "request log query failed (HTTP %s). Is ASM / Advanced "
                        "WAF provisioned and does the account have access?" % st}
            items = [i for i in data.get("items", []) if asm_recent(i, cutoff)]
        if b.get("mode") == "supportid":
            # Some TMOS versions ignore $filter on this collection; never trust position, match the ID.
            def has_id(i):
                return sid in (asm_support_id(i), str(i.get("id") or "")) or ('"%s"' % sid) in json.dumps(i)
            seen = [asm_support_id(i) for i in items][:5]
            same = [i for i in items if has_id(i)]
            if not same:
                # On this BIG-IP the request's id is its support ID: fetch the record directly.
                p1 = "/mgmt/tm/asm/events/requests/" + sid
                s1, ok1, d1 = rest_get(sess, p1)
                if ok1 and isinstance(d1, dict) and has_id(d1):
                    same, path, st = [d1], p1, s1
            if not same:
                # Scan newest first: the default order is oldest first, so recent requests are never reached.
                order = "$orderby=requestDatetime%20desc&"
                s0, ok0, d0 = rest_get(sess, "/mgmt/tm/asm/events/requests?" + order + "$top=1")
                newest_first = ok0 and isinstance(d0, dict) and bool(d0.get("items"))
                base = "/mgmt/tm/asm/events/requests?" + (order if newest_first else "")
                prev_first = None
                for skip in range(0, 20000, 200):
                    if time.time() - t0 > 100:
                        break
                    path = base + "$top=200&$skip=%d" % skip
                    st, ok, data = rest_get(sess, path)
                    page = data.get("items", []) if ok and isinstance(data, dict) else []
                    first_id = json.dumps(page[0], sort_keys=True) if page else None
                    if skip and first_id == prev_first:
                        break  # device ignores $skip and repeats the first page
                    prev_first = first_id
                    seen = seen or [asm_support_id(i) for i in page][:5]
                    same = [i for i in page if has_id(i)]
                    if same or len(page) < 200:
                        break
                    if cutoff and newest_first and not asm_recent(page[-1], cutoff):
                        break  # reached entries older than the time range
            outside = [i for i in same if not asm_recent(i, cutoff)]
            items = [i for i in same if asm_recent(i, cutoff)]
        if b.get("mode") != "supportid":
            # The list view may omit the support ID; the full record of each request has it.
            filled = 0
            for it in items[:200]:
                if asm_support_id(it) and (it.get("violations") or str(first(it, "requestStatus") or "").lower() == "passed"):
                    continue
                path2 = urllib.parse.urlparse(str(it.get("selfLink") or "")).path
                if not path2.startswith("/mgmt/tm/asm/events/requests/") and re.match(
                        r"^[A-Za-z0-9_\-]{6,64}$", str(it.get("id") or "")):
                    path2 = "/mgmt/tm/asm/events/requests/" + str(it["id"])
                if path2.startswith("/mgmt/tm/asm/events/requests/") and time.time() - t0 < 100:
                    s2, ok2, d2 = rest_get(sess, path2)
                    if ok2 and isinstance(d2, dict) and d2.get("violations") and not it.get("violations"):
                        it["violations"] = d2["violations"]
                    sid2 = asm_support_id(d2) if ok2 and isinstance(d2, dict) else ""
                    if sid2 and not asm_support_id(it):
                        it["supportId"] = sid2
                        filled += 1
            vcache = {}
            rows = []
            for it in items:
                r = asm_row(it)
                r["block_reason"] = asm_reason(sess, it, vcache) if time.time() - t0 < 110 else "(time limit)"
                rows.append(r)
            lines = ["%(time)s  %(status)-8s %(client)s  [True-Client-IP %(true_client_ip)s]  %(method)s %(hostname)s%(url)s  (support ID %(support_id)s, "
                     "rating %(rating)s, HTTP %(response_code)s)  reason: %(block_reason)s" % r for r in rows]
            return {"ok": True, "status": st, "ms": int((time.time() - t0) * 1000), "request": "GET " + path,
                    "verdict": {"label": "%d REQUEST(S)" % len(rows), "kind": "warn" if rows else "info"},
                    "summary": (["Time range: %s (applied to the request time of each entry)." % (b.get("within") or "any time")]
                                if cutoff else []) + (diag if hip and not rows else [])
                    + (["No support ID found in these entries. Fields the device returned: "
                        + ", ".join(sorted(items[0].keys()))[:500]] if items and not any(r["support_id"] for r in rows)
                       else []),
                    "data": {"lines": lines, "requests": rows}}
        if not items and outside:
            when = utc3(first(outside[0], "requestDatetime", "occurrenceTime", "dateTime", "time"))
            return {"ok": True, "status": st, "ms": int((time.time() - t0) * 1000), "request": "GET " + path,
                    "verdict": {"label": "SUPPORT ID %s FOUND, BUT OUTSIDE THE TIME RANGE" % sid, "kind": "info"},
                    "summary": ["The request was logged at %s, which is older than the selected range (%s). "
                                "Choose a longer range or 'any time' to see it." % (when, b.get("within") or "any time")],
                    "data": {}}
        if not items:
            return {"ok": True, "status": st, "ms": int((time.time() - t0) * 1000), "request": "GET " + path,
                    "verdict": {"label": "NO REQUEST FOUND for support ID %s" % sid, "kind": "info"},
                    "summary": ["The request may have been purged from the local log, logged on the other HA unit "
                                "or another BIG-IP, or excluded by the logging profile."]
                    + (["Time range applied: %s." % b.get("within")] if cutoff else [])
                    + ["Support IDs the device returned (first few): " + (", ".join(seen) or "none")],
                    "data": {}}
        it, cache = items[0], {}
        hlines, pairs, body = asm_http(it)
        http_text = "\n".join(hlines)
        hdrs = dict(reversed(pairs))
        violations = []
        blocking = {}
        plink = urllib.parse.urlparse((it.get("requestPolicyReference") or {}).get("link") or "").path
        pm = re.match(r"^/mgmt/tm/asm/policies/([A-Za-z0-9_\-]+)", plink)
        if pm:
            okb, bd = f5_get(sess, "/mgmt/tm/asm/policies/%s/blocking-settings/violations?$top=500" % pm.group(1))
            for x in (bd.get("items", []) if okb else []):
                for key in (x.get("name"), x.get("description"), x.get("title")):
                    if key:
                        blocking[str(key).lower()] = x
        for v in it.get("violations") or []:
            vd = f5_ref_get(sess, v.get("violationReference"), cache) or {}
            vname = vd.get("name") or ""
            title = vd.get("title") or vd.get("description") or ""
            sub = first(v, "subViolation", "subViolations", "subViolationName", "subViolationReference")
            if isinstance(sub, dict):
                sub = f5_ref_name(sess, sub, cache) or sub.get("name")
            elif isinstance(sub, list):
                sub = ", ".join(str(f5_ref_name(sess, s, cache) if isinstance(s, dict) else s) for s in sub)
            loc = []
            for k, val in v.items():
                if k == "violationReference" or k == "subViolationReference":
                    continue
                if k.endswith("Reference"):
                    n = f5_ref_name(sess, val, cache)
                    if n:
                        loc.append("%s: %s" % (k[:-len("Reference")], n))
                elif k in ("context", "contextName", "entity", "entityName", "offendingEntity", "location",
                           "detail", "parameter", "header", "uri", "cookie") and val not in (None, ""):
                    loc.append("%s: %s" % (k, val))
            bs = blocking.get(vname.lower()) or blocking.get(title.lower())
            applied = ("  ".join("✓ " + lbl for lbl, k in (("Block", "block"), ("Alarm", "alarm"), ("Learn", "learn"))
                                 if bs.get(k) is True) or "none enabled") if bs else "(policy setting not readable)"
            violations.append({"violation": ("%s (%s)" % (title, vname)) if title and vname else (title or vname),
                               "detection_cause": title or vname,
                               "applied_blocking_settings": applied,
                               "sub_violation": sub or "", "location": "; ".join(loc)})
        xff = it.get("xForwardedForHeaderValue") or hdrs.get("x-forwarded-for") or ""
        tci = it.get("trueClientIp") or hdrs.get("true-client-ip") or ""
        status = str(first(it, "requestStatus", "enforcementState") or "").lower()
        kind = "bad" if "block" in status else "warn" if status in ASM_STATUS["alerted"] or violations else "ok"
        vip_ip = first(it, "destinationIp", "destinationIP", "destIp", "serverIp") or ""
        vip_port = first(it, "destinationPort", "destPort", "serverPort") or ""
        vip = "%s:%s" % (vip_ip, vip_port) if vip_ip and vip_port else str(vip_ip)
        vs_name = first(it, "virtualServerName", "virtualServer")
        if isinstance(vs_name, dict):
            vs_name = vs_name.get("name") or vs_name.get("fullPath")
        if vs_name:
            vip = ("%s (%s)" % (vip, vs_name)) if vip else str(vs_name)
        data = {"support_id": sid,
                "status": status,
                "time": utc3(first(it, "requestDatetime", "occurrenceTime", "dateTime", "time")) or "",
                "method": str(it.get("method") or (hlines[0].split(" ")[0] if hlines else "")).upper(),
                "cf_ray": hdrs.get("cf-ray", ""),
                "hostname": asm_hostname(it) or hdrs.get("host", ""),
                "uri": str(first(it, "url", "uri") or ""),
                "source_ip": it.get("clientIp", ""),
                "xff": xff,
                "true_client_id": tci or asm_header_ip(it),
                "vip": vip,
                "violations": violations,
                "request_headers": "\n".join(hlines) if http_text else "(not available in the log)",
                "body": body if http_text else "(not available in the log)"}
        return {"ok": True, "status": st, "ms": int((time.time() - t0) * 1000), "request": "GET " + path,
                "verdict": {"label": "REQUEST %s (support ID %s)" % (status.upper() or "FOUND", sid), "kind": kind},
                "data": data}
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}


# ---- Palo Alto ----------------------------------------------------------------
def pan_waf_posture(sess, vsys):
    findings, inv, notes = [], [], []
    groups = {}
    for xp in (pan_base(vsys), "/config/shared"):
        node = pan_section(sess, xp, "profile-group")
        for e in (node.findall("entry") if node is not None else []):
            groups[e.get("name")] = {t for t in PAN_PROFILE_TYPES if pan_members(e.find(t))}
    rules, disabled = pan_rules(sess, vsys), 0
    if not rules:
        notes.append("No security rules were readable (check vsys name and API role).")
    for scope, e in rules:
        name = "%s [%s]" % (e.get("name"), scope)
        action, is_off = e.findtext("action") or "", (e.findtext("disabled") or "no") == "yes"
        ps = e.find("profile-setting")
        grp = pan_members(ps.find("group")) if ps is not None else []
        types, prof_desc = set(), ""
        if grp:
            prof_desc = "group " + ", ".join(grp)
            for g in grp:
                if g in groups:
                    types |= groups[g]
                else:
                    types |= set(PAN_PROFILE_TYPES)  # unknown (e.g. Panorama) group: don't guess
                    notes.append("Profile group '%s' (rule %s) was not found locally; assumed complete." % (g, name))
        elif ps is not None and ps.find("profiles") is not None:
            types = {t for t in PAN_PROFILE_TYPES if pan_members(ps.find("profiles").find(t))}
            prof_desc = ", ".join(sorted(types))
        app, svc = pan_members(e.find("application")), pan_members(e.find("service"))
        src, dst = pan_members(e.find("source")), pan_members(e.find("destination"))
        log_end, log_fwd = (e.findtext("log-end") or "yes"), e.findtext("log-setting") or ""
        inv.append({"rule": e.get("name"), "scope": scope, "action": action, "disabled": is_off,
                    "profiles": prof_desc, "application": app, "service": svc, "log_forwarding": log_fwd})
        if is_off:
            disabled += 1
            continue
        if action != "allow":
            continue
        if not types:
            findings.append(finding("high", name, "Allow rule has no security profiles"))
        else:
            missing = [t for t in PAN_REQUIRED_PROFILES if t not in types]
            if missing:
                findings.append(finding("medium", name, "Missing security profiles: " + ", ".join(missing)))
        if "any" in app:
            findings.append(finding("medium", name, "Application is 'any'"))
        if "any" in svc:
            findings.append(finding("medium", name, "Service is 'any' (prefer application-default or explicit ports)"))
        if "any" in src and "any" in dst:
            findings.append(finding("medium", name, "Source and destination are both 'any'"))
        if log_end == "no":
            findings.append(finding("medium", name, "Log at session end is disabled"))
        if not log_fwd:
            findings.append(finding("low", name, "No log forwarding profile"))
    if disabled:
        notes.append("%d disabled rule(s) were skipped." % disabled)
    notes.append("Reads the firewall's running config (local + shared rules). Rules pushed from Panorama "
                 "device groups may not appear; run this against Panorama-managed config separately.")
    return findings, inv, notes


def do_pan_logs(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess or sess["vendor"] != "paloalto":
        return {"ok": False, "error": "connect a Palo Alto firewall first"}
    t0 = time.time()
    try:
        ip = parse_ip_or_net(b.get("ip"), "IP address / subnet") if str(b.get("ip") or "").strip() else ""
        dest = parse_ip_or_net(b.get("dest_ip"), "Destination IP / subnet") if str(b.get("dest_ip") or "").strip() else ""
        if not ip and not dest:
            raise ValueError("enter an IP address and/or a destination IP")
        lt = b.get("log_type") or "threat"
        period = b.get("period") or "last-24-hrs"
        if lt not in PAN_LOG_TYPES or period not in PAN_LOG_PERIODS:
            raise ValueError("invalid log type or time range")
        n = num(b.get("count"), 1, 500, 100, "max rows")
        # addr.dst is the destination the client addressed; natdst is the translated (DNAT) destination.
        dtype = b.get("dest_type") or "either"
        if dtype not in ("either", "normal", "dnat"):
            raise ValueError("invalid destination type")
        if dest and lt != "traffic":
            if dtype == "dnat":
                raise ValueError("DNAT destination search is only available for traffic logs")
            dtype = "normal"
        if dest:
            dq = {"normal": "(addr.dst in %s)" % dest, "dnat": "(natdst in %s)" % dest,
                  "either": "((addr.dst in %s) or (natdst in %s))" % (dest, dest)}[dtype]
        if ip and dest:
            addr_q = "(addr.src in %s) and %s" % (ip, dq)
        elif dest:
            addr_q = dq
        else:
            addr_q = "(addr in %s)" % ip
        query = "%s and (receive_time in %s)" % (addr_q, period)
        if b.get("blocked") is True:
            query += " and (action neq allow) and (action neq alert)"
        elif b.get("allowed") is True:
            query += " and ((action eq allow) or (action eq alert))"
        audit(sess, "%s log search %s" % (lt, query))
        root = pan_xml(sess, {"type": "log", "log-type": lt, "query": query, "nlogs": str(n), "dir": "backward"})
        job = (root.findtext(".//job") or "").strip() if root is not None else ""
        if not job:
            raise ValueError("log query was rejected (does the API admin role have log access?)")
        deadline = time.time() + 60
        while True:
            r = pan_xml(sess, {"type": "log", "action": "get", "job-id": job})
            if r is None:
                raise ValueError("could not fetch log job %s" % job)
            if (r.findtext(".//job/status") or "").strip() == "FIN":
                break
            if time.time() > deadline:
                raise ValueError("log query did not finish within 60 s (job %s)" % job)
            time.sleep(1)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
    entries = [x2o(e) for e in r.findall(".//log/logs/entry")]
    entries = [e for e in entries if isinstance(e, dict)]
    lines = []
    for e in entries:
        line = "%s %-8s %s -> %s:%s app=%s rule=%s" % (
            first(e, "receive_time", "time_generated"), e.get("action", ""), e.get("src", ""),
            e.get("dst", ""), e.get("dport", ""), e.get("app", ""), e.get("rule", ""))
        if lt == "threat":
            line += " threat=%s severity=%s" % (first(e, "threatid", "threat_name"), e.get("severity", ""))
        elif lt == "url":
            line += " url=%s category=%s" % (e.get("misc", ""), e.get("category", ""))
        lines.append(line)
    by_action = collections.Counter(e.get("action", "?") for e in entries)
    summary = ["Actions: " + (", ".join("%s=%d" % kv for kv in by_action.most_common()) or "none")]
    raw = entries
    entries = []
    for e in raw:
        row = {"time": first(e, "receive_time", "time_generated") or "", "from_zone": e.get("from", ""),
               "to_zone": e.get("to", ""), "source_ip": e.get("src", ""), "destination_ip": e.get("dst", ""),
               "to_port": e.get("dport", ""),
               "dnat_ip": e.get("natdst", "") if e.get("natdst") not in (None, "0.0.0.0") else "",
               "dnat_port": e.get("natdport", "") if e.get("natdst") not in (None, "0.0.0.0") else "",
               "application": e.get("app", ""), "action": e.get("action", ""),
               "rule": e.get("rule", ""), "session_end_reason": e.get("session_end_reason", "")}
        if lt == "threat":
            row["threat"] = first(e, "threatid", "threat_name") or ""
            row["severity"] = e.get("severity", "")
        elif lt == "url":
            row["url"] = e.get("misc", "")
            row["category"] = e.get("category", "")
        entries.append(row)
    entries_src = raw
    if lt in ("threat", "url"):
        key = "threatid" if lt == "threat" else "category"
        top = collections.Counter(str(first(e, key, "threat_name")) for e in entries_src).most_common(5)
        if top:
            summary.append("Top %s: %s" % ("threats" if lt == "threat" else "categories",
                                           ", ".join("%s (%d)" % kv for kv in top)))
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": "log query " + query,
            "verdict": {"label": "%d %s LOG ENTRIES for %s" % (
                            len(entries), lt.upper(), "%s -> %s" % (ip, dest) if ip and dest else ip or dest),
                        "kind": "bad" if any(re.match(r"(?i)(deny|denied|drop|dropped|block|blocked|block-.*|reset.*|"
                                                      r"blackhole|sinkhole)$", str(e.get("action") or ""))
                                             for e in entries_src)
                        else "ok" if entries else "info"},
            "summary": summary, "data": {"lines": lines, "entries": entries}}


FG_LOG_SOURCES = ("disk", "memory", "fortianalyzer")
FG_BLOCK_UTM = ("block", "blocked")


def fg_is_blocked(e):
    return (e.get("action") or "").lower() == "deny" or (e.get("utmaction") or "").lower() in FG_BLOCK_UTM


def do_fg_logs(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess or sess["vendor"] != "fortigate":
        return {"ok": False, "error": "connect a FortiGate first"}
    t0 = time.time()
    try:
        ip = parse_ip_or_net(b.get("ip"), "IP address / subnet") if str(b.get("ip") or "").strip() else ""
        dest = parse_ip_or_net(b.get("dest_ip"), "Destination IP / subnet") if str(b.get("dest_ip") or "").strip() else ""
        if not ip and not dest:
            raise ValueError("enter an IP address and/or a destination IP")
        src = b.get("log_source") or "disk"
        if src not in FG_LOG_SOURCES:
            raise ValueError("invalid log source")
        n = num(b.get("count"), 1, 1000, 500, "max rows")
        cutoff = cutoff_epoch(b)
        no_time = 0
        vdom = pstr(b.get("vdom"), "VDOM")
        blocked_only = b.get("blocked") is True
        allowed_only = b.get("allowed") is True
        entries, errors, notes = {}, [], []
        # dstip is the destination the client addressed; tranip is the translated (DNAT) destination.
        dtype = b.get("dest_type") or "either"
        if dtype not in ("either", "normal", "dnat"):
            raise ValueError("invalid destination type")
        dfields = {"either": ("dstip", "tranip"), "normal": ("dstip",), "dnat": ("tranip",)}[dtype]
        if dest:
            searches = [(df, ([("srcip", ip)] if ip else []) + [(df, dest)]) for df in dfields]
        else:
            searches = [("srcip", [("srcip", ip)]), ("dstip", [("dstip", ip)])]
        def fetch(conds):
            q = [("rows", str(n))] + [("filter", "%s==%s" % c) for c in conds]
            if vdom:
                q.append(("vdom", vdom))
            audit(sess, "traffic log search %s" % (" ".join("%s %s" % c for c in conds) or "(unfiltered)"))
            st, ok, data = rest_get(sess, "/api/v2/log/%s/traffic/forward?%s" % (src, urllib.parse.urlencode(q)))
            res = data.get("results") if ok and isinstance(data, dict) else None
            if isinstance(res, dict):
                res = [res]
            return st, data, ([e for e in res if isinstance(e, dict)] if isinstance(res, list) else None)

        for field, conds in searches:
            is_net = any(isinstance(v, (ipaddress.IPv4Network, ipaddress.IPv6Network)) for _, v in conds)
            st, data, res = fetch(conds)
            if is_net and not res:
                # The device may not accept a subnet in its log filter: read recent entries and match locally.
                st, data, res = fetch([])
                if res is not None:
                    notes.append("Subnet search matched locally within the newest %d log entries." % n)
            if res is None:
                errors.append("%s query failed (HTTP %s), response: %s" % (field, st, str(data)[:300]))
                continue
            for e in res:
                if cutoff:
                    ep = fg_event_epoch(e)
                    if ep is None:
                        no_time += 1
                    elif ep < cutoff:
                        continue
                if all(ip_matches(e.get(f), v) for f, v in conds):
                    entries[(e.get("logid"), e.get("sessionid"), e.get("date"), e.get("time"),
                             e.get("srcip"), e.get("dstip"), e.get("dstport"))] = e
        if len(errors) == len(searches):
            raise ValueError("log query failed. Check that logging to '%s' is enabled, the token profile has "
                             "Log & Report read access, and the VDOM is correct. (%s)" % (src, "; ".join(errors)))
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
    rows = sorted(entries.values(), key=lambda e: "%s %s" % (e.get("date", ""), e.get("time", "")), reverse=True)
    total = len(rows)
    n_blocked = sum(1 for e in rows if fg_is_blocked(e))
    if blocked_only:
        rows = [e for e in rows if fg_is_blocked(e)]
    elif allowed_only:
        rows = [e for e in rows if not fg_is_blocked(e) and (e.get("action") or "").lower() != "blocked"]
    lines = []
    for e in rows:
        line = "%s %s %-8s %s -> %s:%s service=%s policy=%s" % (
            e.get("date", ""), e.get("time", ""), e.get("action", ""), e.get("srcip", ""), e.get("dstip", ""),
            e.get("dstport", ""), e.get("service", ""), e.get("policyid", ""))
        if e.get("app"):
            line += " app=%s" % e["app"]
        if e.get("utmaction"):
            line += " utm=%s" % e["utmaction"]
        lines.append(line)
    by_action = collections.Counter(e.get("action", "?") for e in rows)
    summary = ["Actions: " + (", ".join("%s=%d" % kv for kv in by_action.most_common()) or "none")]
    top = collections.Counter(str(e.get("policyid", "?")) for e in rows if fg_is_blocked(e)).most_common(5)
    if top:
        summary.append("Blocking policy IDs: " + ", ".join("%s (%d)" % kv for kv in top))
    summary.append("Searched the newest %d entries per direction (source and destination); older entries are "
                   "not covered. Forward-traffic log only." % n)
    summary.extend(notes)
    if cutoff:
        summary.append("Time range: %s (within the newest %d entries read per direction)%s." % (
            b.get("within"), n, "; %d entr(ies) had no event time and were not filtered" % no_time if no_time else ""))
    summary.extend(errors)
    ip = ip or dest
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000),
            "request": "log query %s on %s" % (ip, src),
            "verdict": {"label": "%d BLOCKED of %d TRAFFIC LOG ENTRIES for %s" % (n_blocked, total, ip),
                        "kind": "bad" if n_blocked else "ok" if total else "info"},
            "summary": summary, "data": {"lines": lines, "entries": [
                {"date_time": ("%s %s" % (e.get("date", ""), e.get("time", ""))).strip(),
                 "source_ip": e.get("srcip", ""), "destination_ip": e.get("dstip", ""),
                 "destination_port": e.get("dstport", ""),
                 "dnat_ip": e.get("tranip", "") if e.get("tranip") not in (None, "0.0.0.0") else "",
                 "dnat_port": e.get("tranport", "") if e.get("tranip") not in (None, "0.0.0.0") else "",
                 "application": e.get("app", ""),
                 "result": "Denied" if fg_is_blocked(e) or (e.get("action") or "").lower() in ("deny", "blocked")
                           else "Allowed",
                 "policy": " / ".join(str(x) for x in (e.get("policyid"), e.get("policyname")) if x),
                 "action": e.get("action", "")} for e in rows]}}


# ---- Admin audit: who logged in to the device and what did they do -------------
ADMIN_NAME_RE = re.compile(r'^[A-Za-z0-9_.@\\\- ]{1,64}$')


def pan_log_rows(sess, lt, query, n):
    root = pan_xml(sess, {"type": "log", "log-type": lt, "query": query, "nlogs": str(n), "dir": "backward"})
    job = (root.findtext(".//job") or "").strip() if root is not None else ""
    if not job:
        raise ValueError("%s log query was rejected (does the API admin role have log access?)" % lt)
    deadline = time.time() + 60
    while True:
        r = pan_xml(sess, {"type": "log", "action": "get", "job-id": job})
        if r is None:
            raise ValueError("could not fetch log job %s" % job)
        if (r.findtext(".//job/status") or "").strip() == "FIN":
            break
        if time.time() > deadline:
            raise ValueError("%s log query did not finish within 60 s (job %s)" % (lt, job))
        time.sleep(1)
    return [e for e in (x2o(x) for x in r.findall(".//log/logs/entry")) if isinstance(e, dict)]


def adm_row(time_, user, kind, action, obj="", change="", source="", result=""):
    clip = lambda s, k: (str(s) if s is not None else "").strip()[:k]
    return {"time": clip(time_, 40), "user": clip(user, 64), "type": kind, "action": clip(action, 60),
            "object": clip(obj, 160), "change": clip(change, 200), "source": clip(source, 64),
            "result": clip(result, 80)}


def pan_obj(path):
    """Turn a PAN config xpath into 'rulebase > security > rules > Allow-Web'."""
    parts = []
    for p in str(path or "").strip("/").split("/"):
        m = re.match(r"^entry\[@name='([^']*)'\]$", p)
        parts.append(m.group(1) if m else p)
    while parts and parts[0] in ("config", "devices", "localhost.localdomain", "shared"):
        parts.pop(0)
    return " > ".join(parts)


def f5_audit_row(line, user):
    """One /var/log/audit line -> a readable row (login, or verb + object for a change)."""
    m = re.match(r"^\s*(\w{3}\s+\d+\s+[\d:]+)", line)
    when = m.group(1) if m else ""
    head, _, body = line.partition("AUDIT - ")
    src = re.search(r"\bhost=([0-9a-fA-F:.]+)", body)
    src = src.group(1) if src else ""
    if re.search(r"\b(httpd|sshd)\b", head):
        via = "SSH" if "sshd" in head else "GUI / REST"
        lvl = re.search(r"\blevel=(\w+)", body)
        att = re.search(r"\battempts=(\d+)", body)
        return adm_row(when, user, "login", "Login", via + (" (role %s)" % lvl.group(1) if lvl else ""), "",
                       src, "attempts=" + att.group(1) if att else "")
    st = re.search(r"status=\[([^\]]*)\]", body)
    cmd = re.search(r"cmd_data=(.+)$", body) or re.search(r"- object \d+ - (.+)$", body)
    text = (cmd.group(1) if cmd else body).strip()
    verb, _, rest = text.partition(" ")
    obj, brace, inner = rest.lstrip("{ ").partition(" {")
    return adm_row(when, user, "config", verb.capitalize(), obj.strip(), inner.rstrip("} ").strip() if brace else "",
                   src, st.group(1) if st else "")


def fmt_adm_row(r):
    parts = [r["time"], r["user"], r["action"], r["object"]]
    if r["change"]:
        parts.append("change: " + r["change"])
    if r["source"]:
        parts.append("from " + r["source"])
    if r["result"]:
        parts.append("result: " + r["result"])
    return "  |  ".join(p for p in parts if p)


def do_admin_audit(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess:
        return {"ok": False, "error": "connect a device first"}
    t0 = time.time()
    notes, rows = [], []
    try:
        user = (b.get("user") or "").strip()
        if not ADMIN_NAME_RE.match(user):
            raise ValueError("enter the admin user name (letters, digits and _ . @ \\ - only)")
        kw = (b.get("action") or "").strip()
        if kw and not ADMIN_NAME_RE.match(kw):
            raise ValueError("invalid characters in the action filter")
        n = num(b.get("count"), 1, 500, 100, "max rows")
        cutoff = cutoff_epoch(b) if sess["vendor"] != "paloalto" else None
        audit(sess, "admin audit search user=%s action=%s" % (user, kw or "*"))
        v = sess["vendor"]
        if v == "paloalto":
            period = b.get("period") or "last-24-hrs"
            if period not in PAN_LOG_PERIODS:
                raise ValueError("invalid time range")
            for e in pan_log_rows(sess, "config", "(admin eq '%s') and (receive_time in %s)" % (user, period), n):
                chg = e.get("after-change-detail") or e.get("before-change-detail") or ""
                rows.append(adm_row(first(e, "receive_time", "time_generated"), e.get("admin", user), "config",
                                    str(e.get("cmd", "")).capitalize(), pan_obj(e.get("path")),
                                    re.sub(r"\s+", " ", str(chg)), e.get("host", ""), e.get("result", "")))
            try:
                q = "(subtype eq auth) and (description contains '%s') and (receive_time in %s)" % (user, period)
                for e in pan_log_rows(sess, "system", q, n):
                    rows.append(adm_row(first(e, "receive_time", "time_generated"), user, "login",
                                        first(e, "eventid", "subtype").replace("-", " ").capitalize(),
                                        "Management login", e.get("opaque") or e.get("description", "")))
            except ValueError as e:
                notes.append("Login events (system log) not read: %s" % e)
        elif v == "fortigate":
            src = b.get("log_source") or "disk"
            if src not in FG_LOG_SOURCES:
                raise ValueError("invalid log source")
            q = {"rows": str(n), "filter": "user==%s" % user}
            vdom = pstr(b.get("vdom"), "VDOM")
            if vdom:
                q["vdom"] = vdom
            st, ok, data = rest_get(sess, "/api/v2/log/%s/event/system?%s" % (src, urllib.parse.urlencode(q)))
            res = data.get("results") if ok and isinstance(data, dict) else None
            if isinstance(res, dict):
                res = [res]
            if not isinstance(res, list):
                raise ValueError("event log query failed (HTTP %s). Check that logging to '%s' is enabled and the "
                                 "token profile has Log & Report read access. %s" % (st, src, str(data)[:300]))
            for e in res:
                if not isinstance(e, dict):
                    continue
                ep = fg_event_epoch(e)
                if cutoff and ep is not None and ep < cutoff:
                    continue
                desc = e.get("logdesc", "")
                kind = "login" if re.search(r"login|logout|auth", desc, re.I) else "config"
                when = ("%s %s" % (e.get("date", ""), e.get("time", ""))).strip()
                if kind == "login":
                    rows.append(adm_row(when, e.get("user", user), kind, desc or e.get("action", ""),
                                        "Management login", e.get("msg", ""), first(e, "ui", "srcip"),
                                        first(e, "status", "result")))
                else:
                    obj = " ".join(str(x) for x in (e.get("cfgpath"), e.get("cfgobj")) if x)
                    rows.append(adm_row(when, e.get("user", user), kind, str(e.get("action") or desc).capitalize(),
                                        obj or desc, e.get("cfgattr") or e.get("msg", ""),
                                        first(e, "ui", "srcip"), first(e, "status", "result")))
        elif v == "f5":
            # No REST collection exposes the audit log, so run one fixed, read-only grep through util/bash
            # (POST, needs an admin-role account). The user name is validated; backslashes are refused so nothing
            # can escape the shell quoting.
            if "\\" in user:
                raise ValueError("F5 user names cannot contain a backslash here; use the plain account name")
            audit(sess, "F5 util/bash read-only grep of /var/log/audit for user " + user)
            cmd = "cat /var/log/audit.1 /var/log/audit 2>/dev/null | grep -F -i -- '%s' | tail -n 5000" % user
            body = json.dumps({"command": "run", "utilCmdArgs": '-c "%s"' % cmd}).encode()
            hdr = dict(sess["hdr"])
            hdr["Content-Type"] = "application/json"
            st, raw = http(sess, "POST", "/mgmt/tm/util/bash", hdr, body, 60)
            try:
                res = json.loads(raw)
            except ValueError:
                res = None
            if not (200 <= st < 300 and isinstance(res, dict)):
                raise ValueError("could not read /var/log/audit through util/bash (HTTP %s). The account needs the "
                                 "Administrator role; otherwise check the log on the device or in your SIEM. %s"
                                 % (st, raw.decode("utf-8", "replace")[:200]))
            texts = str(res.get("commandResult") or "").splitlines()
            pat = re.compile(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(user), re.I)
            for line in texts:
                if pat.search(line):
                    rows.append(f5_audit_row(line, user))
            rows.reverse()  # the log is oldest first
            if cutoff:
                rows = [r for r in rows if (log_epoch(r["time"]) or 0) >= cutoff]
            seen_login, uniq = set(), []
            for r in rows:  # one GUI login writes several PAM lines in the same second; keep one
                if r["type"] == "login":
                    k = (r["time"], r["source"], r["object"])
                    if k in seen_login:
                        continue
                    seen_login.add(k)
                uniq.append(r)
            rows = uniq
            notes.append("Read from /var/log/audit and audit.1 on the device (last 5000 matching lines); older "
                         "rotated files are not searched.")
        else:
            raise ValueError("unsupported device type")
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
    if sess["vendor"] != "f5":
        rows.sort(key=lambda r: str(r["time"]), reverse=True)
    if kw:
        rows = [r for r in rows if kw.lower() in json.dumps(r).lower()]
    rows = rows[:n]
    if cutoff:
        notes.append("Time range: %s." % b.get("within"))
    lines = [fmt_adm_row(r) for r in rows]
    kinds = collections.Counter(r["type"] for r in rows)
    summary = ["Events: " + (", ".join("%s=%d" % kv for kv in kinds.most_common()) or "none")]
    top = collections.Counter(r["action"].strip() for r in rows if r["action"].strip()).most_common(5)
    if top:
        summary.append("Top actions: " + ", ".join("%s (%d)" % kv for kv in top))
    summary.extend(notes)
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000),
            "request": "admin audit user=%s%s" % (user, " action~" + kw if kw else ""),
            "verdict": {"label": "%d EVENT(S) for %s" % (len(rows), user), "kind": "ok" if rows else "info"},
            "summary": summary, "data": {"lines": lines, "events": rows}}


# ---- F5 config sync: what changed here and has it reached the peer? -------------
F5_SYNC_MARK = "=====SYNC====="


def f5_flat(node, out, key=None):
    """Flatten a stats response into (name, description) pairs."""
    if isinstance(node, dict):
        if key and isinstance(node.get("description"), str):
            out.append((key.rsplit("/", 1)[-1], node["description"]))
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                f5_flat(v, out, k)
    elif isinstance(node, list):
        for v in node:
            f5_flat(v, out, key)


def log_epoch(stamp):
    """'Oct 16 22:14:00' (syslog, no year) -> epoch; the year is the current one, or last year if that is future."""
    try:
        now = time.time()
        t = time.mktime(time.strptime("%s %d" % (stamp, time.localtime(now).tm_year), "%b %d %H:%M:%S %Y"))
        if t > now + 86400:
            t = time.mktime(time.strptime("%s %d" % (stamp, time.localtime(now).tm_year - 1), "%b %d %H:%M:%S %Y"))
        return t
    except ValueError:
        return None


def do_f5_sync(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess or sess["vendor"] != "f5":
        return {"ok": False, "error": "connect an F5 device first"}
    t0 = time.time()
    summary, rows = [], []
    try:
        hours = num(b.get("hours"), 1, 720, 24, "look-back hours")
        n = num(b.get("count"), 1, 500, 200, "max rows")
        audit(sess, "F5 config-sync review (sync-status + read-only log grep)")
        # 1. What the device itself says.
        flat = []
        ok, d = f5_get(sess, "/mgmt/tm/cm/sync-status")
        if ok:
            f5_flat(d, flat)
        info = {}
        for k, v in flat:
            info.setdefault(k, []).append(v)
        status = (info.get("status") or [""])[0]
        details = info.get("details", [])
        ok_d, dev = f5_get(sess, "/mgmt/tm/cm/device")
        for x in (dev.get("items", []) if ok_d and isinstance(dev, dict) else []):
            me = str(x.get("selfDevice")).lower() == "true"
            summary.append("%s %s (mgmt %s, config-sync IP %s)" % ("This device:" if me else "Peer:", x.get("name"),
                                                                    x.get("managementIp", "?"),
                                                                    x.get("configsyncIp", "?")))
        ok_g, grp = f5_get(sess, "/mgmt/tm/cm/device-group")
        autos = []
        for x in (grp.get("items", []) if ok_g and isinstance(grp, dict) else []):
            if x.get("type") == "sync-failover":
                autos.append("%s (auto-sync %s)" % (x.get("name"), x.get("autoSync", "?")))
                if x.get("autoSync") == "disabled":
                    summary.append("Device group %s has auto-sync DISABLED: changes stay pending until someone "
                                   "runs a manual sync." % x.get("name"))
        if autos:
            summary.append("Sync-failover groups: " + ", ".join(autos))
        summary.extend("Sync detail: " + t for t in details)
        # 2. Change history and sync events from the device logs (fixed, read-only commands).
        audit_cmd = ("cat /var/log/audit.1 /var/log/audit 2>/dev/null | grep -h -E 'cmd_data=(create|modify|delete|"
                     "run|save|load|install|reset|edit)|object [0-9]+ - (create|modify|delete)' | "
                     "grep -v 'run util bash' | tail -n 4000")
        sync_cmd = ("cat /var/log/ltm.1 /var/log/ltm 2>/dev/null | grep -i sync | "
                    "grep -v -i -E 'rsync|syncookie|async' | tail -n 400")
        body = json.dumps({"command": "run", "utilCmdArgs": '-c "%s; echo %s; %s"' % (audit_cmd, F5_SYNC_MARK,
                                                                                    sync_cmd)}).encode()
        hdr = dict(sess["hdr"])
        hdr["Content-Type"] = "application/json"
        st, raw = http(sess, "POST", "/mgmt/tm/util/bash", hdr, body, 60)
        try:
            res = json.loads(raw)
        except ValueError:
            res = None
        if not (200 <= st < 300 and isinstance(res, dict)):
            raise ValueError("could not read the device logs through util/bash (HTTP %s); the account needs the "
                             "Administrator role. %s" % (st, raw.decode("utf-8", "replace")[:200]))
        audit_txt, _, sync_txt = str(res.get("commandResult") or "").partition(F5_SYNC_MARK)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
    # 3. Last successful sync from the log, then classify every change against it.
    sync_lines = [l.strip() for l in sync_txt.splitlines() if l.strip()]
    last_sync = None
    for l in sync_lines:
        m = re.match(r"^(\w{3}\s+\d+\s+[\d:]+)", l)
        if m and re.search(r"complete|success|finish|done|received|pushed|applied", l, re.I) \
                and not re.search(r"fail|error|unable|timed? ?out", l, re.I):
            e = log_epoch(m.group(1))
            if e and (last_sync is None or e > last_sync):
                last_sync = e
    in_sync = "in sync" in status.lower()
    since = time.time() - hours * 3600
    for line in audit_txt.splitlines():
        m = re.search(r"user=(\S+)|AUDIT - user (\S+)", line)
        who = (m.group(1) or m.group(2)) if m else "?"
        r = f5_audit_row(line, who)
        ep = log_epoch(r["time"])
        if r["type"] != "config" or ep is None or ep < since:
            continue
        r["sync"] = ("synced (device reports In Sync)" if in_sync else
                     "synced" if last_sync and ep <= last_sync else
                     "PENDING" if last_sync else "unknown (no sync event found in the log)")
        r["_ep"] = ep
        rows.append(r)
    rows.sort(key=lambda r: r["_ep"], reverse=True)
    for r in rows:
        del r["_ep"]
    rows = rows[:n]
    pending = sum(1 for r in rows if r["sync"] == "PENDING")
    if last_sync:
        summary.append("Last sync event in the log: " + time.strftime("%b %d %H:%M:%S", time.localtime(last_sync)))
    else:
        summary.append("No completed-sync event was found in /var/log/ltm; per-change status is inferred from the "
                       "device's sync status only.")
    summary.append("Per-change 'synced / PENDING' is inferred by comparing each change's time with the last sync "
                   "event; the authoritative state is the sync status above.")
    if sync_lines:
        summary.append("Recent sync log lines: " + " || ".join(sync_lines[-3:])[:600])
    kind = "ok" if in_sync else "bad" if status else "info"
    lines = ["[%s]  %s" % (r["sync"], fmt_adm_row(r)) for r in rows]
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": "F5 config-sync review",
            "verdict": {"label": "%s · %d change(s) in the last %dh, %d pending" % ((status or "SYNC STATUS UNKNOWN").upper(),
                                                                                  len(rows), hours, pending),
                        "kind": kind},
            "summary": summary, "data": {"lines": lines, "changes": rows, "sync_log": sync_lines[-40:]}}


# ---- Packet capture: Palo Alto (live, via packet-diag) and FortiGate (commands) ----
CAPTURE_BUSY = threading.Lock()
PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")
CAP_PROTOS = {"any": None, "tcp": 6, "udp": 17, "icmp": 1}


def cap_filter(b):
    """Validated capture filter shared by both vendors. At least a host or a port is required."""
    src = parse_ip(b.get("src"), "source IP") if str(b.get("src") or "").strip() else None
    dst = parse_ip(b.get("dst"), "destination IP") if str(b.get("dst") or "").strip() else None
    port = num(b.get("port"), 1, 65535, None, "port") if str(b.get("port") or "").strip() else None
    proto = (b.get("proto") or "any").strip().lower()
    if proto not in CAP_PROTOS:
        raise ValueError("protocol must be any, tcp, udp or icmp")
    if not (src or dst or port):
        raise ValueError("enter at least one source IP, destination IP or port (an open capture is refused)")
    return src, dst, port, proto


def do_pan_capture(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess or sess["vendor"] != "paloalto":
        return {"ok": False, "error": "connect a Palo Alto firewall first"}
    if not b.get("ack"):
        return {"ok": False, "error": "tick the confirmation box first (this changes packet-diag state on the firewall)"}
    if not CAPTURE_BUSY.acquire(blocking=False):
        return {"ok": False, "error": "another capture is already running"}
    t0, local, steps, started = time.time(), None, [], False
    fname = "itsec%s.pcap" % time.strftime("%Y%m%d%H%M%S")
    pd = lambda inner: "<debug><dataplane><packet-diag>%s</packet-diag></dataplane></debug>" % inner

    def run(label, variants, must=True):
        last = ""
        for x in variants:
            st, ok, data = pan_op(sess, pd(x))
            if ok:
                steps.append(label + ": ok")
                return True
            last = str(data)[:200]
        steps.append("%s: FAILED (%s)" % (label, last))
        if must:
            raise ValueError("%s failed on the firewall: %s" % (label, last))
        return False

    def stop_capture():
        """Switch capture and filter off, retrying each up to 3 times. Returns the labels that never succeeded."""
        failed = []
        for label, x in (("stop capture", "<set><capture><off/></capture></set>"),
                         ("disable filter", "<set><filter><off/></filter></set>")):
            done = False
            for attempt in range(3):
                try:
                    done = run(label, [x], must=False)
                except Exception as e:  # network error: record it and carry on with the next step
                    steps.append("%s: error (%s)" % (label, getattr(e, "reason", e)))
                if done:
                    break
                time.sleep(1)
            if not done:
                failed.append(label)
        return failed

    stop_failed = []
    try:
        src, dst, port, proto = cap_filter(b)
        dur = num(b.get("duration"), 5, 60, 20, "seconds")
        cnt = num(b.get("count"), 1, 50000, 10000, "max packets")
        stage = b.get("stage") or "receive"
        if stage not in ("receive", "firewall", "transmit", "drop"):
            raise ValueError("invalid capture stage")
        m = "".join("<%s>%s</%s>" % (k, v, k) for k, v in (
            ("source", src), ("destination", dst), ("destination-port", port),
            ("protocol", CAP_PROTOS[proto])) if v)
        audit(sess, "PAN packet capture src=%s dst=%s port=%s proto=%s stage=%s %ds" % (
            src, dst, port, proto, stage, dur))
        run("clear previous packet-diag state", ["<clear><all/></clear>"], must=False)
        run("set filter", ["<set><filter><index>1</index><match>%s</match></filter></set>" % m])
        run("enable filter", ["<set><filter><on/></filter></set>"])
        run("set capture stage", ["<set><capture><stage><%s><file>%s</file></%s></stage></capture></set>" % (
            stage, fname, stage), "<set><capture><stage>%s</stage><file>%s</file></capture></set>" % (stage, fname)])
        run("set packet limit", ["<set><capture><packet-count>%d</packet-count></capture></set>" % cnt], must=False)
        started = run("start capture", ["<set><capture><on/></capture></set>"])
        deadline = time.time() + dur
        while time.time() < deadline:
            time.sleep(1)
    except ValueError as e:
        result = {"ok": False, "error": str(e), "summary": steps}
    except (urllib.error.URLError, OSError) as e:
        result = {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e), "summary": steps}
    except Exception as e:  # never leave the lock held or the capture running
        result = {"ok": False, "error": "unexpected error in capture: %r" % e, "summary": steps}
    else:
        result = None
    finally:
        # Runs on every exit path (success, error, even Ctrl+C). Each step is retried and isolated, so a
        # failure of one can never skip the other.
        stop_failed = stop_capture()
    try:
        if result is None:
            st, raw = http(sess, "GET", "/api/?" + urllib.parse.urlencode(
                {"type": "export", "category": "filter-pcap", "from": fname}), {"X-PAN-KEY": sess["key"]}, None, 120)
            if st != 200 or raw[:4] not in PCAP_MAGICS:
                raise ValueError("could not download the capture file %s (HTTP %s): %s" % (
                    fname, st, raw[:200].decode("utf-8", "replace")))
            if len(raw) > MAX_PCAP:
                raise ValueError("capture is over the %d MB limit" % (MAX_PCAP >> 20))
            os.makedirs(CAPTURE_DIR, exist_ok=True)
            safe = re.sub(r'[^A-Za-z0-9_.\-]', "_", sess["name"])
            local_name = "%s_pan_%s.pcap" % (safe, time.strftime("%Y%m%d-%H%M%S"))
            local = os.path.join(CAPTURE_DIR, local_name)
            with open(local, "wb") as f:
                f.write(raw)
            audit(sess, "PAN capture downloaded (%d bytes)" % len(raw))
            flt = " ".join("%s=%s" % kv for kv in (("src", src), ("dst", dst), ("port", port), ("proto", proto))
                           if kv[1])
            result = {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000),
                      "request": "packet-diag capture " + fname, "download": "/api/capture/" + local_name,
                      "downloads": ["/api/capture/" + local_name],
                      "verdict": {"label": "CAPTURE SAVED (%d bytes)" % len(raw), "kind": "ok"},
                      "summary": ["Filter: %s, stage %s, up to %ds / %d packets." % (flt, stage, dur, cnt),
                                  "Saved locally: " + local] + steps,
                      "data": {"saved_file": local, "size_bytes": len(raw)}}
    except ValueError as e:
        result = {"ok": False, "error": str(e), "summary": steps}
    except (urllib.error.URLError, OSError) as e:
        result = {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e), "summary": steps}
    finally:
        try:
            for x in ("<clear><filter-pcap><all/></filter-pcap></clear>",  # remove the file from the firewall
                      "<clear><all/></clear>"):  # last-resort reset of all packet-diag state
                try:
                    pan_op(sess, pd(x))
                except Exception:
                    if x.startswith("<clear><all"):
                        stop_failed = stop_failed or ["clear packet-diag state"]
            if stop_failed and result is not None:
                msg = ("WARNING: could not confirm on the firewall: %s. The capture may still be running. "
                       "Check with 'debug dataplane packet-diag show setting' and run "
                       "'debug dataplane packet-diag set capture off' manually." % ", ".join(stop_failed))
                result["warning"] = msg
                result["summary"] = [msg] + list(result.get("summary") or [])
        finally:
            CAPTURE_BUSY.release()
    return result


# ---- FortiGate ----------------------------------------------------------------
def fg_waf_posture(sess, vdom):
    findings, inv, notes = [], [], []
    pols = fg_cmdb(sess, "policy", vdom)
    if pols is None:
        raise ValueError("could not read firewall policies (check token profile / VDOM)")
    groups = {g.get("name"): g for g in fg_cmdb(sess, "profile-group", vdom) or []}
    names = lambda x: [i.get("name") for i in as_list(x)]
    keys = (("av-profile", "antivirus"), ("ips-sensor", "IPS"), ("webfilter-profile", "web filter"),
            ("application-list", "application control"))
    for p in pols:
        obj = ("policy %s %s" % (p.get("policyid"), p.get("name") or "")).strip()
        prof = groups.get(p.get("profile-group"), {}) if p.get("profile-type") == "group" else p
        present = [label for k, label in keys if prof.get(k)]
        ssl_prof = prof.get("ssl-ssh-profile") or p.get("ssl-ssh-profile") or ""
        utm = p.get("utm-status") == "enable"
        svc, srca, dsta = names(p.get("service")), names(p.get("srcaddr")), names(p.get("dstaddr"))
        inv.append({"policyid": p.get("policyid"), "name": p.get("name"), "action": p.get("action"),
                    "status": p.get("status"), "srcintf": names(p.get("srcintf")), "dstintf": names(p.get("dstintf")),
                    "service": svc, "utm": utm, "profiles": present, "waf": prof.get("waf-profile") or "",
                    "ssl_ssh_profile": ssl_prof, "logtraffic": p.get("logtraffic")})
        if p.get("action") != "accept" or p.get("status") == "disable":
            continue
        if not utm or not present:
            findings.append(finding("high", obj, "Accept policy has no security profiles"
                                    + ("" if utm else " (UTM disabled)")))
        else:
            missing = [label for k, label in keys if label not in present]
            if missing:
                findings.append(finding("medium", obj, "Missing security profiles: " + ", ".join(missing)))
            if ssl_prof in ("", "no-inspection"):
                findings.append(finding("medium", obj, "No SSL inspection profile"))
            elif ssl_prof == "certificate-inspection":
                findings.append(finding("low", obj, "Certificate inspection only (no deep inspection)",
                                        "IPS/AV/web filter cannot see inside HTTPS"))
        if p.get("logtraffic") == "disable":
            findings.append(finding("medium", obj, "Traffic logging disabled"))
        if "ALL" in svc:
            findings.append(finding("medium", obj, "Service is ALL"))
        if "all" in srca and "all" in dsta:
            findings.append(finding("medium", obj, "Source and destination are both 'all'"))
    notes.append("Covers the firewall policy table for this VDOM. Proxy, IPv6-only (pre-6.4) and "
                 "explicit-proxy policies are not included.")
    return findings, inv, notes


# ---- dispatcher -----------------------------------------------------------------
def do_appsec(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess:
        return {"ok": False, "error": "device not connected"}
    t0, check, v = time.time(), b.get("check"), sess["vendor"]
    try:
        if check == "waf":
            label = "WAF / security-profile coverage"
            audit(sess, "AppSec: " + label)
            if v == "f5":
                result = f5_waf_posture(sess)
            elif v == "paloalto":
                result = pan_waf_posture(sess, pstr(b.get("vsys"), "vsys") or "vsys1")
            else:
                result = fg_waf_posture(sess, pstr(b.get("vdom"), "VDOM"))
        elif check == "ssl" and v == "f5":
            label = "SSL / certificate posture"
            audit(sess, "AppSec: " + label)
            result = f5_ssl_posture(sess, num(b.get("days"), 1, 365, 60, "days"))
        else:
            return {"ok": False, "error": "unknown check"}
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
    return report(t0, label, *result)


# ----------------------------------------------------------------------------
# HTTP server
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
# Configuration backup (all vendors) -> saved in ./captures, then downloaded by the browser
# ----------------------------------------------------------------------------
def device_hostname(sess):
    """The device's own configured hostname, or the saved label / address if it cannot be read."""
    try:
        if sess["vendor"] == "f5":
            _, ok, d = rest_get(sess, "/mgmt/tm/sys/global-settings?$select=hostname")
            h = d.get("hostname") if ok and isinstance(d, dict) else ""
        elif sess["vendor"] == "fortigate":
            _, ok, d = rest_get(sess, "/api/v2/monitor/system/status")
            h = (d.get("results") or {}).get("hostname") if ok and isinstance(d, dict) else ""
        else:
            _, ok, d = pan_op(sess, "<show><system><info/></system></show>")
            h = (((d.get("response") or {}).get("result") or {}).get("system") or {}).get("hostname") if ok else ""
    except (urllib.error.URLError, OSError, AttributeError, ValueError):
        h = ""
    return str(h or sess["name"])


def do_backup(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess:
        return {"ok": False, "error": "connect a device first"}
    v, t0 = sess["vendor"], time.time()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    ext = {"f5": "ucs", "paloalto": "xml", "fortigate": "conf"}[v]
    devname = re.sub(r'[^A-Za-z0-9_.\-]', "_", device_hostname(sess))[:60]
    local_name = "%s_backup_%s.%s" % (devname, stamp, ext)
    summary = []
    try:
        os.makedirs(CAPTURE_DIR, exist_ok=True)
        local = os.path.join(CAPTURE_DIR, local_name)
        if v == "f5":
            sess, err = _f5_gate(b)  # needs the tick-box: this creates a UCS file on the BIG-IP and uses bash
            if err:
                return err
            remote_name = "%s_%s" % (devname, stamp)
            # A UCS save can take minutes but iControl REST / util/bash time out after ~60 s, so start tmsh in the
            # background on the BIG-IP and poll a status file until it finishes.
            log, rc = "/var/tmp/%s.log" % remote_name, "/var/tmp/%s.rc" % remote_name
            audit(sess, "backup: saving UCS " + remote_name)
            st, ok, out, res = f5_bash(sess, "nohup sh -c %s >/dev/null 2>&1 &" % shlex.quote(
                "tmsh save /sys ucs %s.ucs > %s 2>&1; echo $? > %s" % (remote_name, log, rc)), 30)
            if not ok:
                raise ValueError(f5_bash_error(st, res, "UCS save"))
            deadline, status = time.time() + 1500, ""
            while time.time() < deadline:
                time.sleep(10)
                st, ok, out, _ = f5_bash(sess, "cat %s 2>/dev/null; echo ---; cat %s 2>/dev/null" % (rc, log), 30)
                if ok and "---" in out:
                    code, _, status = out.partition("---")
                    if code.strip():
                        break
            else:
                raise ValueError("the UCS save did not finish within 25 minutes (it may still complete on the BIG-IP: "
                                 "/var/local/ucs/%s.ucs)" % remote_name)
            f5_bash(sess, "rm -f %s %s" % (log, rc), 30)
            if code.strip() != "0":
                raise ValueError("UCS save failed on the BIG-IP: %s" % (status.strip()[:300] or "exit " + code.strip()))
            remote = "/var/local/ucs/%s.ucs" % remote_name
            size = f5_fetch(sess, remote, local, MAX_BACKUP)
            summary += ["UCS archive created on the BIG-IP at %s (left in place; delete it there when no longer needed)." % remote,
                        "Copied through the shell and verified by MD5. Large archives take a while."]
        elif v == "paloalto":
            audit(sess, "backup: exporting configuration")
            st, raw = http(sess, "GET", "/api/?" + urllib.parse.urlencode({"type": "export", "category": "configuration"}),
                           {"X-PAN-KEY": sess["key"]}, None, 180)
            if st != 200 or b"<config" not in raw[:4000]:
                raise ValueError("configuration export failed (HTTP %s): %s" % (st, raw[:300].decode("utf-8", "replace")))
            with open(local, "wb") as f:
                f.write(raw)
            size = len(raw)
            summary.append("Exported the running configuration (XML). Import it on a firewall with Device > Setup > Operations.")
        else:
            q = {"scope": "global"}
            vdom = str(b.get("vdom") or "").strip()
            if vdom:
                if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,31}", vdom):
                    raise ValueError("invalid VDOM name")
                q = {"scope": "vdom", "vdom": vdom}
            audit(sess, "backup: system config backup (%s)" % q["scope"])
            st, raw = http(sess, "GET", "/api/v2/monitor/system/config/backup?" + urllib.parse.urlencode(q),
                           sess["hdr"], None, 180)
            if st != 200 or b"#config-version" not in raw[:400]:
                raise ValueError("config backup failed (HTTP %s). The API user needs the super_admin profile. %s" % (
                    st, raw[:200].decode("utf-8", "replace")))
            with open(local, "wb") as f:
                f.write(raw)
            size = len(raw)
            summary.append("Backup scope: %s. Restore it from System > Config > Backup & Restore." %
                           (("VDOM " + vdom) if vdom else "global (whole device)"))
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
    audit(sess, "backup saved (%d bytes)" % size)
    summary += ["Saved locally: " + local, "The file holds sensitive configuration (hashed passwords, keys, addresses): store it securely."]
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": "backup " + v,
            "download": "/api/capture/" + local_name, "downloads": ["/api/capture/" + local_name],
            "verdict": {"label": "BACKUP SAVED (%d bytes)" % size, "kind": "ok"}, "summary": summary,
            "data": {"saved_file": local, "size_bytes": size}}


# ----------------------------------------------------------------------------
# Cloudflare: read-only lookups with an API token. Analytics come from the GraphQL Analytics API (queries
# only), configuration from REST GETs. Lookups span every zone the token sees, or one zone.
# ----------------------------------------------------------------------------
CF_HOST = "api.cloudflare.com"
CF_ID_RE = re.compile(r"^[0-9a-f]{32}$")
CF_RAY_RE = re.compile(r"^([0-9a-f]{16})(?:-[a-z]{3})?$", re.I)
CF_WORD_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
CF_TEXT_RE = re.compile(r'^[^\x00-\x1f"\\]{1,200}$')
CF_HOSTNAME_RE = re.compile(r"^[a-z0-9*_.\-]{1,253}$")
CF_IPTOK_RE = re.compile(r"(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:/\d{1,3})?)"
                         r"(?![\w.:])", re.I)
CF_TZ = datetime.timezone(datetime.timedelta(hours=3))
CF_WITHIN = {"last 15 minutes": 900, "last hour": 3600, "last 6 hours": 21600, "last 12 hours": 43200,
             "last 24 hours": 86400, "last 3 days": 259200, "last 7 days": 604800, "last 30 days": 2592000}
CF_MAX_ZONES = 100      # analytics lookups over "all zones" (10 zones per GraphQL query)
CF_MAX_CFG_ZONES = 30   # configuration lookups over "all zones" (several REST calls per zone)
CF_EDGE = {}            # Cloudflare's published edge ranges, fetched once
CF_BLOCK = ("block", "drop", "connection_close", "force_connection_close")
# Optional output fields: those a plan or API version does not offer are dropped and the query retried.
CF_EV_FIELDS = ("action", "source", "ruleId", "rulesetId", "description", "rayName", "clientIP", "clientCountryName",
                "clientAsn", "clientASNDescription", "clientRequestHTTPHost", "clientRequestHTTPMethodName",
                "clientRequestPath", "clientRequestQuery", "userAgent", "edgeResponseStatus", "originResponseStatus",
                "edgeColoName")
CF_RQ_FIELDS = ("rayName", "clientIP", "clientCountryName", "clientAsn", "clientRequestHTTPHost",
                "clientRequestHTTPMethodName", "clientRequestPath", "clientRequestQuery", "clientRequestHTTPProtocol",
                "edgeResponseStatus", "originResponseStatus", "cacheStatus", "securityAction", "securitySource",
                "userAgent", "coloCode", "edgeTimeToFirstByteMs", "originResponseDurationMs", "clientSSLProtocol",
                "botScore", "wafAttackScore", "originIP", "edgeResponseBytes", "sampleInterval")
CF_COL = {"clientRequestHTTPHost": "host", "clientIP": "client_ip", "clientRequestPath": "path",
          "clientCountryName": "country", "clientAsn": "asn", "clientASNDescription": "asn_name",
          "userAgent": "user_agent", "edgeResponseStatus": "edge_status", "originResponseStatus": "origin_status",
          "cacheStatus": "cache", "coloCode": "colo", "edgeColoName": "colo", "securityAction": "security_action",
          "securitySource": "security_source", "clientSSLProtocol": "tls", "clientRequestHTTPProtocol": "http_version",
          "ruleId": "rule_id", "datetimeHour": "time", "datetimeFiveMinutes": "time", "date": "date",
          "clientRequestHTTPMethodName": "method", "rayName": "ray_id"}
# Group-by choices: (required dimensions, optional dimensions). "@time" picks a bucket size from the range.
CF_DIM_EV = {"action": (("action",), ()), "source": (("source",), ()),
             "rule": (("ruleId",), ("source", "description")), "client IP": (("clientIP",), ("clientCountryName",)),
             "host": (("clientRequestHTTPHost",), ()), "path": (("clientRequestPath",), ()),
             "country": (("clientCountryName",), ()), "ASN": (("clientAsn",), ("clientASNDescription",)),
             "user agent": (("userAgent",), ()), "colo": (("edgeColoName",), ()), "time": (("@time",), ())}
CF_DIM_HTTP = {"host": (("clientRequestHTTPHost",), ()), "edge status": (("edgeResponseStatus",), ()),
               "origin status": (("originResponseStatus",), ()),
               "edge + origin status": (("edgeResponseStatus", "originResponseStatus"), ()),
               "cache status": (("cacheStatus",), ()), "client IP": (("clientIP",), ()),
               "path": (("clientRequestPath",), ()), "country": (("clientCountryName",), ()),
               "ASN": (("clientAsn",), ()), "user agent": (("userAgent",), ()), "colo": (("coloCode",), ()),
               "security action": (("securityAction",), ("securitySource",)),
               "TLS version": (("clientSSLProtocol",), ()), "HTTP version": (("clientRequestHTTPProtocol",), ()),
               "time": (("@time",), ())}
CF_HTTP_METRICS = ("sum{edgeResponseBytes}", "avg{edgeTimeToFirstByteMs originResponseDurationMs}")
CF_STATUS = {"2xx": (200, 300), "3xx": (300, 400), "4xx": (400, 500), "5xx": (500, 600), "4xx + 5xx": (400, 600),
             "origin errors (520-527)": (520, 528)}
CF_SETTINGS = ("ssl", "min_tls_version", "tls_1_3", "always_use_https", "automatic_https_rewrites", "security_level",
               "browser_check", "challenge_ttl", "true_client_ip_header", "ip_geolocation", "development_mode", "0rtt",
               "http3", "websockets", "opportunistic_encryption", "cache_level")
CF_SEC_PHASES = ("http_request_firewall_custom", "http_ratelimit", "http_request_firewall_managed")


def cf_get(sess, path):
    st, ok, data = rest_get(sess, "/client/v4" + path)
    if isinstance(data, dict) and data.get("success") is False:
        ok = False
    return st, ok and isinstance(data, dict), data


def cf_errtext(st, data):
    errs = data.get("errors") if isinstance(data, dict) else None
    msg = "; ".join(("%s %s" % (e.get("code", ""), e.get("message", ""))).strip()
                    for e in errs or [] if isinstance(e, dict))
    return "HTTP %s%s" % (st, (": " + msg[:300]) if msg else "")


def cf_list(sess, path, per_page=100, max_pages=20):
    """Every result of a paged REST list -> (items, error text or '', truncated)."""
    items, sep, prev = [], "&" if "?" in path else "?", None
    for page in range(1, max_pages + 1):
        st, ok, d = cf_get(sess, "%s%spage=%d&per_page=%d" % (path, sep, page, per_page))
        if not ok:
            return items, cf_errtext(st, d), False
        res = d.get("result") or []
        res = res if isinstance(res, list) else []
        fid = json.dumps(res[0], sort_keys=True) if res else None
        if page > 1 and fid == prev:
            return items, "", False   # the endpoint ignores paging
        prev = fid
        items += res
        tp = (d.get("result_info") or {}).get("total_pages")
        if not res or (tp and page >= int(tp)) or (not tp and len(res) < per_page):
            return items, "", False
    return items, "", True


def cf_gql(sess, query):
    """One GraphQL Analytics query -> (ok, data, [error messages])."""
    body = json.dumps({"query": query}).encode()
    st, raw = http(sess, "POST", "/client/v4/graphql", dict(sess["hdr"], **{"Content-Type": "application/json"}),
                   body, timeout=60)
    try:
        d = json.loads(raw)
    except ValueError:
        return False, None, ["HTTP %s: the GraphQL API did not answer with JSON" % st]
    d = d if isinstance(d, dict) else {}
    errs = [str(e.get("message") if isinstance(e, dict) else e) for e in (d.get("errors") or [])]
    if st != 200 and not errs:
        errs = ["HTTP %s" % st]
    return not errs and d.get("data") is not None, d.get("data"), errs


def cf_gql_opt(sess, build, opt):
    """Run build(optional fields); when the schema rejects some of them (they vary by plan and API version), drop
    those and retry. -> (ok, data, errors, dropped)."""
    opt, dropped, errs = list(opt), [], []
    for _ in range(8):
        ok, data, errs = cf_gql(sess, build(opt))
        if ok:
            return ok, data, errs, dropped
        text = " ".join(errs)
        bad = [f for f in opt if any(re.search(r"[\"'`]%s[\"'`]|field %s\b" % (re.escape(n), re.escape(n)), text)
                                     for n in re.findall(r"[A-Za-z_]\w*", f))]
        if not bad:
            return ok, data, errs, dropped
        dropped += bad
        opt = [f for f in opt if f not in bad]
    return False, None, errs, dropped


def cf_gql_zones(sess, zones, sel, opt=(), chunk=10):
    """Run one zone-level selection for many zones, `chunk` per query as aliases. sel(optional fields) is the text
    inside zones(...){ }. -> ({zone id: (zone data or None, errors)}, dropped optional fields)."""
    def run(chunk):
        q = lambda f: "{viewer{%s}}" % " ".join("z%d:zones(filter:{zoneTag:%s}){%s}" % (i, json.dumps(z["id"]), sel(f))
                                                for i, z in enumerate(chunk))
        ok, data, errs, drop = cf_gql_opt(sess, q, opt)
        viewer = (data or {}).get("viewer") or {}
        got = {z["id"]: (viewer.get("z%d" % i) or [None])[0] for i, z in enumerate(chunk)}
        if not ok and len(chunk) > 1 and not any(got.values()):
            res = {}
            for z in chunk:   # one zone's error (e.g. a plan without this dataset) fails the whole query
                r1, d1 = run([z])
                res.update(r1)
                drop = drop + d1
            return res, drop
        return {zid: (zd, [] if ok or zd else errs) for zid, zd in got.items()}, drop
    out, dropped = {}, set()
    chunks = [zones[i:i + chunk] for i in range(0, len(zones), chunk)]
    if chunks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(chunks))) as ex:
            for res, drop in ex.map(run, chunks):
                out.update(res)
                dropped.update(drop)
    return out, sorted(dropped)


def cf_each(items, fn, workers=8):
    """fn(item) for each item in parallel; an item whose call fails yields {'error': ...}."""
    def safe(x):
        try:
            return fn(x)
        except (urllib.error.URLError, OSError, ValueError) as e:
            return {"error": "request failed: %s" % getattr(e, "reason", e)}
    if not items:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        return list(ex.map(safe, items))


def cf_load(sess):
    """Zones and accounts the token can see, kept in the session for zone pickers and account-level lookups."""
    items, err, trunc = cf_list(sess, "/zones", per_page=50, max_pages=40)
    sess["zones"] = [{"id": z["id"], "name": str(z.get("name") or "").lower(), "status": z.get("status", ""),
                      "plan": (z.get("plan") or {}).get("name", ""), "account": (z.get("account") or {}).get("id", "")}
                     for z in items if CF_ID_RE.match(str(z.get("id") or ""))]
    accts, _, _ = cf_list(sess, "/accounts", per_page=50, max_pages=5)
    names = {(z.get("account") or {}).get("id"): (z.get("account") or {}).get("name") for z in items}
    names.update({a.get("id"): a.get("name") for a in accts})
    sess["accounts"] = {k: str(v or k) for k, v in names.items() if CF_ID_RE.match(str(k or ""))}
    return err or ("only the first 2000 zones were loaded" if trunc else "")


def cf_zones(sess, z, allow_all=True):
    """Zones for a lookup: blank / 'all' = every zone (capped), else a zone name or ID, or a hostname in a zone."""
    z = str(z or "").strip().lower().rstrip(".")
    zones = sess.get("zones") or []
    if z in ("", "all", "all zones", "*"):
        if not allow_all:
            raise ValueError("choose a zone for this lookup")
        if not zones:
            raise ValueError("the token can see no zones (it needs Zone Read)")
        return zones[:CF_MAX_ZONES]
    for x in zones:
        if z in (x["id"], x["name"]):
            return [x]
    best = cf_zone_of_host(sess, z)
    if best:
        return [best]
    raise ValueError("zone %s is not visible to this token" % z)


def cf_zone_of_host(sess, host):
    host = host.lower().rstrip(".")
    cands = [x for x in sess.get("zones") or [] if host == x["name"] or host.endswith("." + x["name"])]
    return max(cands, key=lambda x: len(x["name"])) if cands else None


def cf_accounts(sess, zones=None):
    if sess.get("account"):
        return [sess["account"]]
    ids = list(dict.fromkeys(z["account"] for z in zones or sess.get("zones") or [] if z.get("account")))
    return ids or list(sess.get("accounts") or {})


def cf_acct_name(sess, a):
    return "account %s" % (sess.get("accounts") or {}).get(a, a)


def cf_scope(sess, zones):
    allz = sess.get("zones") or []
    if len(zones) == 1 and len(allz) != 1:
        return "Zone: %s." % zones[0]["name"]
    return "All %d zone(s) visible to the token%s." % (len(zones), "" if len(zones) == len(allz) else
                                                       " (first %d of %d; choose a zone for the rest)" %
                                                       (len(zones), len(allz)))


def cf_window(b):
    """(since, until, text) as ISO UTC strings, from the time range or custom From / To entered in UTC+3."""
    def parse(v, label):
        try:
            d = datetime.datetime.strptime(v, "%Y-%m-%d %H:%M")
        except ValueError:
            raise ValueError("%s must look like 2026-11-01 14:30 (UTC+3)" % label)
        return d.replace(tzinfo=CF_TZ).astimezone(datetime.timezone.utc)
    s, u = str(b.get("since") or "").strip(), str(b.get("until") or "").strip()
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    if s or u:
        if not s:
            raise ValueError("enter a custom From time too (or clear both)")
        since, until = parse(s, "From"), parse(u, "To") if u else now
        if since >= until:
            raise ValueError("From must be before To")
    else:
        w = str(b.get("within") or "last 24 hours").strip().lower()
        if w not in CF_WITHIN:
            raise ValueError("invalid time range")
        since, until = now - datetime.timedelta(seconds=CF_WITHIN[w]), now
    iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
    return iso(since), iso(until), "%s to %s (UTC+3)" % (utc3(iso(since)), utc3(iso(until)))


def cf_f5_within(b):
    """The F5 ASM time range closest to the Cloudflare one (F5 lookups go back at most a day)."""
    w = str(b.get("within") or "").strip().lower()
    return w if not b.get("since") and w in LOOKBACK else "any time"


def cf_text(v, label):
    v = str(v or "").strip()
    if v and not CF_TEXT_RE.match(v):
        raise ValueError("%s has characters that are not allowed (no quotes or backslashes)" % label)
    return v


def cf_lit(filters):
    """GraphQL input-object literal; values are JSON-encoded, so they cannot break out of the string."""
    return "{" + ",".join("%s:%s" % (k, json.dumps(v)) for k, v in filters.items() if v not in (None, "")) + "}"


def cf_filters(b, kind, since, until):
    """GraphQL filter from the form. kind 'ev' = firewallEventsAdaptive*, 'http' = httpRequestsAdaptive*."""
    f = {"datetime_geq": since, "datetime_leq": until}
    if str(b.get("ip") or "").strip():
        f["clientIP"] = str(parse_ip(b.get("ip"), "client IP"))
    host = str(b.get("host") or "").strip().lower()
    if host:
        if not CF_HOSTNAME_RE.match(host):
            raise ValueError("hostname has characters that are not allowed (letters, digits, . - _ * only)")
        f["clientRequestHTTPHost_like" if "*" in host else "clientRequestHTTPHost"] = host.replace("*", "%")
    path = cf_text(b.get("path"), "path")
    if path:
        f["clientRequestPath_like"] = "%" + path + "%"
    ray = str(b.get("ray") or "").strip()
    if ray:
        m = CF_RAY_RE.match(ray)
        if not m:
            raise ValueError("Ray ID must be 16 hex characters, optionally with the -ABC colo suffix")
        f["rayName"] = m.group(1).lower()
    ua = cf_text(b.get("ua"), "user agent")
    if ua:
        f["userAgent_like"] = "%" + ua + "%"
    cc = str(b.get("country") or "").strip().upper()
    if cc:
        if not re.fullmatch(r"[A-Z][A-Z0-9]", cc):
            raise ValueError("country must be a 2-letter code, e.g. US")
        f["clientCountryName"] = cc
    asn = re.sub(r"(?i)^AS", "", str(b.get("asn") or "").strip())
    if asn:
        if not asn.isdigit():
            raise ValueError("ASN must be a number, e.g. 13335 or AS13335")
        f["clientAsn"] = asn
    method = str(b.get("method") or "").strip().upper()
    if method:
        if not re.fullmatch(r"[A-Z]{3,10}", method):
            raise ValueError("invalid HTTP method")
        f["clientRequestHTTPMethodName"] = method
    for key, ev, http_ in (("action", "action", "securityAction"), ("source", "source", "securitySource")):
        v = str(b.get(key) or "").strip()
        if v:
            if not CF_WORD_RE.match(v):
                raise ValueError("invalid " + key)
            f[ev if kind == "ev" else http_] = v
    if kind == "ev" and str(b.get("rule") or "").strip():
        rule = str(b.get("rule")).strip().lower()
        if not CF_WORD_RE.match(rule):
            raise ValueError("invalid rule ID")
        f["ruleId"] = rule
    if kind == "http":
        st = str(b.get("status") or "").strip()
        if st in CF_STATUS:
            f["edgeResponseStatus_geq"], f["edgeResponseStatus_lt"] = CF_STATUS[st]
        elif re.fullmatch(r"[1-5]\d\d", st):
            f["edgeResponseStatus"] = int(st)
        elif st:
            raise ValueError("status must be a class (2xx, 5xx, ...) or a code such as 503")
        cache = str(b.get("cache") or "").strip().lower()
        if cache:
            if not CF_WORD_RE.match(cache):
                raise ValueError("invalid cache status")
            f["cacheStatus"] = cache
    return f


def cf_time_dim(since, until):
    span = to_epoch(until) - to_epoch(since)
    return "datetimeFiveMinutes" if span <= 21600 else "datetimeHour" if span <= 604800 else "date"


def cf_q_events(lit, limit):
    return lambda f: "firewallEventsAdaptive(filter:%s,limit:%d,orderBy:[datetime_DESC]){datetime %s}" % (
        lit, limit, " ".join(f))


def cf_q_requests(lit, limit):
    return lambda f: "httpRequestsAdaptive(filter:%s,limit:%d,orderBy:[datetime_DESC]){datetime %s}" % (
        lit, limit, " ".join(f))


def cf_q_groups(dataset, lit, limit, req, order="count_DESC"):
    """Grouped counts ('g') plus the overall count for the same filter ('t'). Optional tokens with '{' are
    metrics, the others dimensions."""
    return lambda f: "g:%s(filter:%s,limit:%d,orderBy:[%s]){count %s dimensions{%s}} t:%s(filter:%s,limit:1){count}" % (
        dataset, lit, limit, order, " ".join(m for m in f if "{" in m),
        " ".join(list(req) + [d for d in f if "{" not in d]), dataset, lit)


def cf_gql_notes(zones, res, dropped):
    notes, errs = [], []
    for z in zones:
        e = res.get(z["id"], (None, []))[1]
        if e:
            errs.append("%s: %s" % (z["name"], "; ".join(e)[:300]))
    if errs:
        notes.append("%d zone(s) returned errors: %s%s" % (len(errs), " | ".join(errs[:4]), " …" if len(errs) > 4 else ""))
        if any(re.search(r"(?i)time ?range|too far|older|exceed|limit|quota|authoriz|access|plan|permission", x) for x in errs):
            notes.append("Cloudflare limits which datasets, how far back and how wide one query can be by plan, and the "
                         "token needs Analytics Read. Try a shorter time range or a single zone.")
    if dropped:
        notes.append("Not offered for this account / plan, so left out: %s." % ", ".join(dropped))
    return notes


def cf_result(t0, request, label, kind, summary, data):
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": request,
            "verdict": {"label": label, "kind": kind}, "summary": [s for s in summary if s], "data": data}


def cf_url(e):
    q = str(e.get("clientRequestQuery") or "")
    return str(e.get("clientRequestPath") or "") + (q if not q or q.startswith("?") else "?" + q)


def cf_cc_asn(e):
    return " ".join(str(x) for x in (e.get("clientCountryName"), ("AS%s" % e["clientAsn"]) if e.get("clientAsn") else "",
                                     e.get("clientASNDescription")) if x)


def cf_ev_row(z, e):
    return {"time": utc3(e.get("datetime")), "cf_zone": z["name"], "action": e.get("action", ""),
            "source": e.get("source", ""), "rule_id": e.get("ruleId", ""), "description": e.get("description", ""),
            "client_ip": e.get("clientIP", ""), "country_asn": cf_cc_asn(e),
            "method": e.get("clientRequestHTTPMethodName", ""), "host": e.get("clientRequestHTTPHost", ""),
            "url": cf_url(e), "edge_origin_status": "/".join(str(e[k]) for k in ("edgeResponseStatus", "originResponseStatus")
                                                              if e.get(k)),
            "colo": e.get("edgeColoName", ""), "ray_id": e.get("rayName", ""), "ruleset_id": e.get("rulesetId", ""),
            "user_agent": e.get("userAgent", "")}


def cf_rq_row(z, e):
    sec = "/".join(str(e[k]) for k in ("securityAction", "securitySource") if e.get(k) and e[k] != "unknown")
    scores = ", ".join("%s %s" % (lbl, e[k]) for lbl, k in (("bot", "botScore"), ("WAF attack", "wafAttackScore"))
                       if e.get(k) not in (None, "", 0))
    return {"time": utc3(e.get("datetime")), "cf_zone": z["name"], "client_ip": e.get("clientIP", ""),
            "country_asn": cf_cc_asn(e), "method": e.get("clientRequestHTTPMethodName", ""),
            "host": e.get("clientRequestHTTPHost", ""), "url": cf_url(e), "edge_status": e.get("edgeResponseStatus", ""),
            "origin_status": e.get("originResponseStatus") or "", "cache": e.get("cacheStatus", ""), "security": sec,
            "ttfb_ms": e.get("edgeTimeToFirstByteMs", ""), "origin_ms": e.get("originResponseDurationMs", ""),
            "scores": scores, "tls": e.get("clientSSLProtocol", ""), "http_version": e.get("clientRequestHTTPProtocol", ""),
            "colo": e.get("coloCode", ""), "origin_ip": e.get("originIP", ""), "ray_id": e.get("rayName", ""),
            "user_agent": e.get("userAgent", "")}


def cf_rows(zones, res, dataset, rowfn, limit):
    rows = []
    for z in zones:
        for e in (res.get(z["id"], (None, []))[0] or {}).get(dataset) or []:
            rows.append((str(e.get("datetime") or ""), rowfn(z, e)))
    return [r for _, r in sorted(rows, key=lambda x: x[0], reverse=True)][:limit]


def cf_merge(zones, res, limit, time_dim):
    """Merge grouped counts ('g') across zones -> (rows, overall count from 't')."""
    acc, total = {}, 0
    for z in zones:
        zd = res.get(z["id"], (None, []))[0] or {}
        total += sum(int(t.get("count") or 0) for t in zd.get("t") or [])
        for g in zd.get("g") or []:
            d = g.get("dimensions") or {}
            a = acc.setdefault(tuple(sorted((k, str(v)) for k, v in d.items())),
                               {"d": d, "n": 0, "bytes": 0, "ttfb": 0.0, "orig": 0.0, "zones": collections.Counter()})
            n = int(g.get("count") or 0)
            a["n"] += n
            a["zones"][z["name"]] += n
            a["bytes"] += int((g.get("sum") or {}).get("edgeResponseBytes") or 0)
            av = g.get("avg") or {}
            a["ttfb"] += float(av.get("edgeTimeToFirstByteMs") or 0) * n
            a["orig"] += float(av.get("originResponseDurationMs") or 0) * n
    items = sorted(acc.values(), key=(lambda a: [str(v) for v in a["d"].values()]) if time_dim else (lambda a: -a["n"]))
    rows = []
    for a in items if time_dim else items[:limit]:
        r = {"cf_zone": ", ".join(k for k, _ in a["zones"].most_common(3)) + (" …" if len(a["zones"]) > 3 else "")}
        for k, v in a["d"].items():
            r[CF_COL.get(k, k)] = utc3(v) if k.startswith("datetime") else v
        r["count"] = a["n"]
        r["share"] = "%.1f%%" % (100.0 * a["n"] / total) if total else ""
        if a["bytes"]:
            r["bytes"] = a["bytes"]
        if a["ttfb"] and a["n"]:
            r["avg_ttfb_ms"] = round(a["ttfb"] / a["n"])
        if a["orig"] and a["n"]:
            r["avg_origin_ms"] = round(a["orig"] / a["n"])
        rows.append(r)
    return rows, total


def cf_edge_nets(sess):
    if not CF_EDGE.get("nets"):
        st, ok, d = cf_get(sess, "/ips")
        r = (d.get("result") or {}) if ok else {}
        CF_EDGE["nets"] = [ipaddress.ip_network(n) for n in (r.get("ipv4_cidrs") or []) + (r.get("ipv6_cidrs") or [])]
    return CF_EDGE["nets"]


def cf_f5_check(b, kind, value):
    """F5 ASM lookup on the F5 device chosen for cross-checks -> (rows, summary lines, verdict label)."""
    fid = b.get("f5")
    if not fid:
        return None, [], ""
    f5 = SESSIONS.get(fid)
    if not f5 or f5["vendor"] != "f5":
        return [], ["F5 cross-check skipped: that F5 device is no longer connected."], ""
    try:
        if kind == "ray":   # Cloudflare forwards the Ray ID to the origin in the CF-Ray header
            r = f5_asm_by_header(f5, {"header_name": "CF-Ray", "header_value": value, "within": cf_f5_within(b),
                                      "top": 10, "scan": 2000}, time.time())
        else:
            r = do_f5_asm({"id": fid, "mode": "search", "header_ip": value, "top": 50, "within": cf_f5_within(b)})
    except (ValueError, urllib.error.URLError, OSError) as e:
        r = {"ok": False, "error": str(getattr(e, "reason", e))}
    if not r.get("ok"):
        return [], ["F5 %s cross-check failed: %s" % (f5["name"], r.get("error"))], ""
    label = (r.get("verdict") or {}).get("label", "")
    return ((r.get("data") or {}).get("requests") or [],
            ["F5 %s (ASM, %s): %s" % (f5["name"], cf_f5_within(b), label)] +
            ["F5: " + s for s in (r.get("summary") or [])[:3]], label)


def cf_sev_verdict(findings, ok_label):
    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    label = ", ".join("%d %s" % (counts[s], s.upper()) for s in ("high", "medium", "low") if counts[s])
    return label or ok_label, "bad" if counts["high"] else "warn" if counts["medium"] else "ok"


# ---- Cloudflare configuration helpers ------------------------------------------
def cf_zone_rules(sess, where, base, cache):
    """Rules of the non-managed rulesets at base (/zones/<id> or /accounts/<id>) -> (rules, errors)."""
    st, ok, d = cf_get(sess, base + "/rulesets")
    if not ok:
        return [], ["%s rulesets: %s" % (where, cf_errtext(st, d))]
    out, errs = [], []
    for rs in d.get("result") or []:
        if rs.get("kind") == "managed" or not CF_ID_RE.match(str(rs.get("id") or "")):
            continue
        st2, ok2, d2 = cf_get(sess, "%s/rulesets/%s" % (base, rs["id"]))
        if not ok2:
            errs.append("%s ruleset %s: %s" % (where, rs.get("name"), cf_errtext(st2, d2)))
            continue
        r = d2.get("result") or {}
        cache[r.get("id")] = r
        for pos, rule in enumerate(r.get("rules") or [], 1):
            out.append({"where": where, "base": base, "phase": r.get("phase") or rs.get("phase") or "",
                        "ruleset": r.get("name") or "", "ruleset_id": r.get("id"), "pos": pos, "rule": rule})
    return out, errs


def cf_all_rules(sess, zones, accounts=True):
    """Rules of the given zones plus the account-level rulesets (WAF custom rulesets deployed from the account)."""
    cache, rules, errs = {}, [], []
    jobs = [(z["name"], "/zones/" + z["id"]) for z in zones]
    if accounts:
        jobs += [(cf_acct_name(sess, a), "/accounts/" + a) for a in cf_accounts(sess, zones)]
    for res in cf_each(jobs, lambda j: cf_zone_rules(sess, j[0], j[1], cache)):
        if isinstance(res, dict):
            errs.append(res["error"])
        else:
            rules += res[0]
            errs += res[1]
    return rules, errs, cache


def cf_rule_row(x, why=""):
    r = x["rule"]
    ap = r.get("action_parameters") or {}
    det = []
    if r.get("action") == "execute" and ap.get("id"):
        det.append("runs ruleset %s" % ap["id"])
        if ap.get("overrides"):
            det.append("overrides: " + json.dumps(ap["overrides"])[:300])
    elif ap:
        det.append(json.dumps(ap)[:300])
    rl = r.get("ratelimit")
    if rl:
        det.append("rate limit %s requests / %ss counted by %s, mitigation %ss" % (
            rl.get("requests_per_period"), rl.get("period"), ", ".join(rl.get("characteristics") or []),
            rl.get("mitigation_timeout")))
    return {"cf_zone": x["where"], "phase": x["phase"], "ruleset": x["ruleset"], "position": x["pos"],
            "rule_id": r.get("id", ""), "description": r.get("description", ""), "action": r.get("action", ""),
            "enabled": r.get("enabled", True), "expression": r.get("expression", ""), "details": "; ".join(det),
            "matched_on": why, "last_updated": utc3(r.get("last_updated", ""))}


def cf_rule_match(x, term="", ip=None, lists=()):
    r = x["rule"]
    expr = str(r.get("expression") or "")
    if ip is not None:
        for tok in CF_IPTOK_RE.findall(expr):
            if ip_in_spec(ip, tok):
                return "IP %s" % ip if tok == str(ip) else "%s contains %s" % (tok, ip)
        for name in lists:
            if re.search(r"\$%s\b" % re.escape(name), expr):
                return "list $%s (contains %s)" % (name, ip)
        return ""
    return "text '%s'" % term if term and term.lower() in json.dumps(r).lower() else ""


def cf_dns_row(z, r):
    return {"cf_zone": z["name"], "name": r.get("name", ""), "type": r.get("type", ""), "content": r.get("content", ""),
            "proxied": r.get("proxied", False), "ttl": "auto" if r.get("ttl") == 1 else r.get("ttl", ""),
            "comment": r.get("comment") or "", "tags": r.get("tags") or [], "modified": utc3(r.get("modified_on", ""))}


def cf_host_match(pattern, host):
    """Certificate-style match: '*.example.com' covers exactly one label."""
    p = str(pattern or "").lower()
    if p.startswith("*."):
        return host.endswith(p[1:]) and host.count(".") == p.count(".")
    return p == host


def cf_route_match(pattern, host):
    """Worker route / page rule target ('*example.com/api/*') -> True if its host part can match host."""
    hp = re.sub(r"^https?://", "", str(pattern or "").lower()).split("/", 1)[0].split(":", 1)[0]
    return bool(hp) and fnmatch_host(hp, host)


def fnmatch_host(pat, host):
    return re.fullmatch(".*".join(re.escape(p) for p in pat.split("*")), host) is not None


def cf_zone_settings(sess, z):
    st, ok, d = cf_get(sess, "/zones/%s/settings" % z["id"])
    if not ok:
        return None, cf_errtext(st, d)
    return {s.get("id"): s.get("value") for s in d.get("result") or [] if isinstance(s, dict)}, ""


def cf_tci_managed(sess, z):
    """True / False for the 'Add True-Client-IP headers' Managed Transform; None if it cannot be read."""
    st, ok, d = cf_get(sess, "/zones/%s/managed_headers" % z["id"])
    if not ok:
        return None
    for h in (d.get("result") or {}).get("managed_request_headers") or []:
        if h.get("id") == "add_true_client_ip_headers":
            return bool(h.get("enabled"))
    return None


def cf_settings_findings(z, s, tci_managed):
    f, n = [], z["name"]
    ssl_ = s.get("ssl")
    if ssl_ in ("off", "flexible"):
        f.append(finding("high", n, "SSL/TLS mode is '%s': Cloudflare to origin is not encrypted" % ssl_, "Use Full (strict)."))
    elif ssl_ == "full":
        f.append(finding("medium", n, "SSL/TLS mode is Full: the origin certificate is not validated", "Use Full (strict)."))
    if str(s.get("min_tls_version") or "") in ("1.0", "1.1"):
        f.append(finding("medium", n, "Minimum TLS version is %s" % s["min_tls_version"], "Set 1.2 or higher."))
    if s.get("tls_1_3") == "off":
        f.append(finding("low", n, "TLS 1.3 is off"))
    if s.get("always_use_https") == "off":
        f.append(finding("low", n, "Always Use HTTPS is off", "Plain-HTTP requests are served instead of redirected."))
    if s.get("security_level") in ("off", "essentially_off"):
        f.append(finding("medium", n, "Security level is '%s'" % s["security_level"]))
    elif s.get("security_level") == "under_attack":
        f.append(finding("info", n, "Under Attack mode is on", "Every visitor gets a challenge page."))
    if s.get("browser_check") == "off":
        f.append(finding("low", n, "Browser Integrity Check is off"))
    if s.get("development_mode") == "on":
        f.append(finding("medium", n, "Development mode is on", "The cache is bypassed for the whole zone."))
    if s.get("0rtt") == "on":
        f.append(finding("low", n, "0-RTT is on", "Early data can be replayed; keep it off for state-changing apps."))
    if s.get("true_client_ip_header") != "on" and not tci_managed:
        f.append(finding("medium", n, "True-Client-IP header is not added to requests sent to the origin",
                         "The F5 sees Cloudflare's edge as the client; ASM True-Client-IP lookups need this (Enterprise "
                         "setting, or the 'Add True-Client-IP headers' Managed Transform)."))
    return f


def cf_cert_rows(sess, z):
    rows, errs = [], []
    packs, err, _ = cf_list(sess, "/zones/%s/ssl/certificate_packs?status=all" % z["id"], per_page=50, max_pages=5)
    if err:
        errs.append("%s certificate packs: %s" % (z["name"], err))
    for p in packs:
        exps = sorted(str(c.get("expires_on")) for c in p.get("certificates") or [] if c.get("expires_on"))
        exp = exps[0] if exps else str(p.get("expires_on") or "")
        rows.append({"cf_zone": z["name"], "kind": "edge (%s)" % p.get("type", ""), "hosts": p.get("hosts") or [],
                     "status": p.get("status", ""), "authority": p.get("certificate_authority", ""),
                     "expires": utc3(exp), "days_left": days_from_now(to_epoch(exp)) if to_epoch(exp) else ""})
    custom, err, _ = cf_list(sess, "/zones/%s/custom_certificates" % z["id"], per_page=50, max_pages=2)
    if err:
        errs.append("%s custom certificates: %s" % (z["name"], err))
    for c in custom:
        exp = str(c.get("expires_on") or "")
        rows.append({"cf_zone": z["name"], "kind": "custom", "hosts": c.get("hosts") or [], "status": c.get("status", ""),
                     "authority": c.get("issuer", ""), "expires": utc3(exp),
                     "days_left": days_from_now(to_epoch(exp)) if to_epoch(exp) else ""})
    return rows, errs


def cf_cert_findings(rows, warn_days):
    f = []
    for c in rows:
        obj = "%s %s (%s)" % (c["cf_zone"], c["kind"], ", ".join(c["hosts"][:3]))
        d = c["days_left"]
        if c["status"] not in ("active", ""):
            f.append(finding("medium", obj, "Certificate status is '%s'" % c["status"]))
        if d != "" and d < 0:
            f.append(finding("high", obj, "Certificate expired %d day(s) ago" % -d))
        elif d != "" and c["kind"] == "custom" and d <= warn_days:
            f.append(finding("high" if d <= 14 else "medium", obj, "Custom certificate expires in %d day(s)" % d,
                             "Custom certificates are not renewed by Cloudflare."))
        elif d != "" and d <= 7:
            f.append(finding("medium", obj, "Edge certificate expires in %d day(s)" % d, "Check that renewal / DCV is not stuck."))
    return f


def cf_access_rules(sess, where, base, ip, extra=()):
    """IP Access Rules at base that match the IP exactly, by range, or by the given (target, value) pairs."""
    rows, errs, seen = [], [], set()
    queries = [("ip6" if ip.version == 6 else "ip", str(ip))] + list(extra)
    for tgt, val in queries:
        items, err, _ = cf_list(sess, "%s/firewall/access_rules/rules?configuration.target=%s&configuration.value=%s"
                                % (base, tgt, urllib.parse.quote(val)), per_page=100, max_pages=2)
        if err:
            errs.append("%s access rules: %s" % (where, err))
            return rows, errs
        rows += [(r, "exact") for r in items]
    ranges, err, trunc = cf_list(sess, base + "/firewall/access_rules/rules?configuration.target=ip_range",
                                 per_page=100, max_pages=30)
    if err:
        errs.append("%s access rules (ranges): %s" % (where, err))
    rows += [(r, "range") for r in ranges if ip_in_spec(ip, str((r.get("configuration") or {}).get("value") or ""))]
    out = []
    for r, how in rows:
        if r.get("id") in seen:
            continue
        seen.add(r.get("id"))
        c = r.get("configuration") or {}
        out.append({"cf_zone": where, "applies_to": (r.get("scope") or {}).get("type", ""), "mode": r.get("mode", ""),
                    "target": c.get("target", ""), "value": c.get("value", ""), "notes": r.get("notes", ""),
                    "rule_id": r.get("id", ""), "modified": utc3(r.get("modified_on", ""))})
    if trunc:
        errs.append("%s: more than 3000 IP range access rules; only the first 3000 were checked." % where)
    return out, errs


def cf_ip_lists(sess, acct, ip, deadline):
    """Account IP lists that contain the IP -> (rows, list names, errors)."""
    st, ok, d = cf_get(sess, "/accounts/%s/rules/lists" % acct)
    if not ok:
        return [], [], ["%s lists: %s" % (cf_acct_name(sess, acct), cf_errtext(st, d))]
    rows, names, errs = [], [], []
    for lst in d.get("result") or []:
        if lst.get("kind") != "ip" or not CF_ID_RE.match(str(lst.get("id") or "")):
            continue
        cursor, pages = "", 0
        while pages < 40 and time.time() < deadline:
            st2, ok2, d2 = cf_get(sess, "/accounts/%s/rules/lists/%s/items?per_page=500%s" % (
                acct, lst["id"], "&cursor=" + urllib.parse.quote(cursor) if cursor else ""))
            if not ok2:
                errs.append("list %s: %s" % (lst.get("name"), cf_errtext(st2, d2)))
                break
            for it in d2.get("result") or []:
                if ip_in_spec(ip, str(it.get("ip") or "")):
                    rows.append({"account": cf_acct_name(sess, acct)[8:], "list": lst.get("name", ""), "item": it.get("ip"),
                                 "comment": it.get("comment", ""), "added": utc3(it.get("created_on", "")),
                                 "list_items": lst.get("num_items", "")})
                    names.append(lst.get("name", ""))
            cursor = ((d2.get("result_info") or {}).get("cursors") or {}).get("after") or ""
            pages += 1
            if not cursor:
                break
        if cursor:
            errs.append("list %s was only partly checked (size / time limit)." % lst.get("name"))
    return rows, list(dict.fromkeys(names)), errs


# ---- Cloudflare lookups ---------------------------------------------------------
def cf_m_events(sess, b, t0):
    zones = cf_zones(sess, b.get("zone"))
    since, until, span = cf_window(b)
    flt = cf_filters(b, "ev", since, until)
    limit = num(b.get("top"), 1, 1000, 100, "max rows")
    audit(sess, "Cloudflare security events %s" % json.dumps({k: v for k, v in flt.items() if "datetime" not in k}))
    res, dropped = cf_gql_zones(sess, zones, cf_q_events(cf_lit(flt), limit), CF_EV_FIELDS)
    rows = cf_rows(zones, res, "firewallEventsAdaptive", cf_ev_row, limit)
    acts = collections.Counter(r["action"] for r in rows)
    label = "%d SECURITY EVENT(S)" % len(rows) + (" · " + ", ".join("%s %d" % kv for kv in acts.most_common(4)) if rows else "")
    kind = "bad" if any(a in CF_BLOCK for a in acts) else "warn" if rows else "info"
    return cf_result(t0, "GraphQL firewallEventsAdaptive", label, kind,
                     [cf_scope(sess, zones), "Time range: " + span] + cf_gql_notes(zones, res, dropped) +
                     (["Showing the newest %d; narrow the filters or raise Max rows for more." % limit] if len(rows) >= limit else []),
                     {"events": rows})


def cf_m_groups(sess, b, t0, kind):
    zones = cf_zones(sess, b.get("zone"))
    since, until, span = cf_window(b)
    flt = cf_filters(b, kind, since, until)
    dims = CF_DIM_EV if kind == "ev" else CF_DIM_HTTP
    by = str(b.get("by") or "").strip()
    if by not in dims:
        raise ValueError("choose what to group by")
    req, opt = dims[by]
    time_dim = req == ("@time",)
    if time_dim:
        req = (cf_time_dim(since, until),)
    top = num(b.get("top"), 1, 500, 20, "top N")
    dataset = "firewallEventsAdaptiveGroups" if kind == "ev" else "httpRequestsAdaptiveGroups"
    audit(sess, "Cloudflare %s by %s" % (dataset, by))
    res, dropped = cf_gql_zones(sess, zones, cf_q_groups(dataset, cf_lit(flt), 5000 if time_dim else top, req,
                                                         req[0] + "_ASC" if time_dim else "count_DESC"),
                                tuple(opt) + (CF_HTTP_METRICS if kind == "http" else ()))
    rows, total = cf_merge(zones, res, top, time_dim)
    what = "SECURITY EVENTS" if kind == "ev" else "REQUESTS"
    notes = [cf_scope(sess, zones), "Time range: " + span,
             "Total %s for these filters: %d; 'share' is each row's part of that total." % (what.lower(), total)]
    if kind == "http":
        notes.append("Counts are Cloudflare's sample-adjusted estimates (adaptive sampling).")
        errs = sum(r["count"] for r in rows if str(r.get("edge_status", "")).startswith("5"))
        if errs and by in ("edge status", "edge + origin status") and total:
            notes.append("5xx responses: %d (%.1f%% of all requests)." % (errs, 100.0 * errs / total))
    if time_dim:
        notes.append("Buckets: %s (UTC+3)." % {"datetimeFiveMinutes": "5 minutes", "datetimeHour": "1 hour",
                                                "date": "1 day, UTC dates"}[req[0]])
    return cf_result(t0, "GraphQL " + dataset, "%d %s · TOP %d BY %s" % (total, what, len(rows), by.upper()),
                     "warn" if total else "info", notes + cf_gql_notes(zones, res, dropped),
                     {("security_events_by_" if kind == "ev" else "requests_by_") + re.sub(r"\W+", "_", by.lower()): rows})


def cf_m_requests(sess, b, t0):
    zones = cf_zones(sess, b.get("zone"))
    since, until, span = cf_window(b)
    flt = cf_filters(b, "http", since, until)
    limit = num(b.get("top"), 1, 1000, 100, "max rows")
    audit(sess, "Cloudflare sampled requests %s" % json.dumps({k: v for k, v in flt.items() if "datetime" not in k}))
    res, dropped = cf_gql_zones(sess, zones, cf_q_requests(cf_lit(flt), limit), CF_RQ_FIELDS)
    rows = cf_rows(zones, res, "httpRequestsAdaptive", cf_rq_row, limit)
    e5 = sum(1 for r in rows if str(r["edge_status"]).startswith("5"))
    e4 = sum(1 for r in rows if str(r["edge_status"]).startswith("4"))
    return cf_result(t0, "GraphQL httpRequestsAdaptive", "%d SAMPLED REQUEST(S)%s" % (
                         len(rows), " · %d 5xx, %d 4xx" % (e5, e4) if e5 or e4 else ""),
                     "bad" if e5 else "warn" if e4 else "ok" if rows else "info",
                     [cf_scope(sess, zones), "Time range: " + span,
                      "These are sampled requests (adaptive sampling), not every request; use Traffic summary for totals."]
                     + cf_gql_notes(zones, res, dropped), {"requests": rows})


CF_RAW_SLICE = 86400   # the raw (non-grouped) datasets accept at most a day per query


def cf_ray_find(sess, zones, ray, since, until, deadline):
    """Search one Ray ID a day at a time, newest first, until found, the data runs out or time is up.
    -> (events oldest first, requests, {zone id: (None, errors)}, dropped fields, note on what was searched)."""
    iso = lambda x: datetime.datetime.fromtimestamp(x, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lo, hi, slices = to_epoch(since), to_epoch(until), []
    while hi > lo:
        slices.append((max(lo, hi - CF_RAW_SLICE), hi))
        hi -= CF_RAW_SLICE
    events, reqs, errs, dropped, done = [], [], {}, set(), 0
    for a, u in slices:
        if done and time.time() > deadline:
            break
        lit = cf_lit({"datetime_geq": iso(a), "datetime_leq": iso(u), "rayName": ray})
        res, d1 = cf_gql_zones(sess, zones, cf_q_events(lit, 50), CF_EV_FIELDS)
        res2, d2 = cf_gql_zones(sess, zones, cf_q_requests(lit, 5), CF_RQ_FIELDS)
        done += 1
        dropped |= set(d1) | set(d2)
        events = cf_rows(zones, res, "firewallEventsAdaptive", cf_ev_row, 50)[::-1]
        reqs = cf_rows(zones, res2, "httpRequestsAdaptive", cf_rq_row, 5)
        failed = set()
        for r in (res, res2):
            for zid, (_, e) in r.items():
                if e:
                    errs.setdefault(zid, (None, e))
                    failed.add(zid)
        if events or reqs or len(failed) == len(zones):   # found, or every zone refused (e.g. older than kept)
            break
    note = "" if len(slices) == 1 else " (searched %d of %d day(s), newest first%s)" % (
        done, len(slices), ", stopped when found" if events or reqs else "")
    return events, reqs, errs, sorted(dropped), note


def cf_m_ray(sess, b, t0):
    m = CF_RAY_RE.match(str(b.get("ray") or "").strip())
    if not m:
        raise ValueError("Ray ID must be 16 hex characters, optionally with the -ABC colo suffix")
    ray = m.group(1).lower()
    zones = cf_zones(sess, b.get("zone"))
    since, until, span = cf_window(b)
    audit(sess, "Cloudflare Ray ID lookup " + ray)
    events, reqs, res, dropped, searched = cf_ray_find(sess, zones, ray, since, until, t0 + 100)
    f5_rows, f5_notes, f5_label = cf_f5_check(b, "ray", ray)
    blocks = [e for e in events if e["action"] in CF_BLOCK]
    chall = [e for e in events if "challenge" in e["action"] and "solved" not in e["action"]]
    f5_blocked = [r for r in f5_rows or [] if "block" in str(r.get("status", "")).lower()]
    if blocks:
        e = blocks[0]
        label, kind = "BLOCKED AT CLOUDFLARE by %s rule %s%s" % (e["source"], e["rule_id"], " (%s)" % e["description"]
                                                                if e["description"] else ""), "bad"
    elif chall:
        label, kind = "CHALLENGED AT CLOUDFLARE (%s, %s)" % (chall[0]["action"], chall[0]["source"]), "warn"
    elif f5_blocked:
        label, kind = "PASSED CLOUDFLARE, BLOCKED BY F5 ASM (support ID %s)" % f5_blocked[0].get("support_id"), "bad"
    elif reqs:
        r = reqs[0]
        label = "PASSED CLOUDFLARE · edge HTTP %s, origin HTTP %s" % (r["edge_status"], r["origin_status"] or "-")
        kind = "bad" if str(r["edge_status"]).startswith("5") else "warn" if str(r["edge_status"]).startswith("4") else "ok"
    elif events:
        label, kind = "LOGGED BY CLOUDFLARE (%s), NOT BLOCKED" % ", ".join(sorted({e["action"] for e in events})), "info"
    elif f5_rows:
        label, kind = "FOUND ON F5 ONLY (%s)" % f5_label, "warn"
    else:
        label, kind = "RAY ID %s NOT FOUND" % ray, "info"
    notes = [cf_scope(sess, zones), "Time range: " + span + searched] + f5_notes
    if not events and not reqs:
        notes.append("Security events exist only for requests a security feature acted on or logged, and sampled "
                     "request data does not hold every request. Widen the time range (or enter the time the "
                     "dashboard shows as a custom From / To), or pick the zone.")
        if len(sess.get("zones") or []) > len(zones) > 1:
            notes.append("Only the first %d zones were searched; choose the zone of this request." % len(zones))
    if f5_rows is None:
        notes.append("Tip: choose an F5 device under 'Cross-check on F5' to also find this request in the ASM log "
                     "(Cloudflare sends the Ray ID to the origin in the CF-Ray header).")
    return cf_result(t0, "GraphQL firewallEventsAdaptive + httpRequestsAdaptive (rayName %s)" % ray, label, kind,
                     notes + cf_gql_notes(zones, res, dropped),
                     {"security_events": events, "request": reqs, "f5_asm_requests": f5_rows or []})


# ---- WHOIS (RDAP, with port-43 WHOIS as fallback) --------------------------------
WHOIS_BOOT = {}   # IANA RDAP bootstrap registries, loaded once per run
WHOIS_SLD = {"com", "net", "org", "gov", "edu", "co", "ac", "med", "sch", "mil", "ne", "or", "go", "gob"}


def web_get_json(url, timeout=12):
    """GET a public HTTPS JSON document (IANA bootstrap, RDAP), following up to 3 HTTPS redirects (RDAP servers
    redirect to the registry holding the record) -> (status, data or None)."""
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    for _ in range(4):
        if not url.startswith("https://"):
            return 0, None
        req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json"})
        try:
            with opener.open(req, timeout=timeout) as r:
                st, raw = r.status, r.read(2000000)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                url = urllib.parse.urljoin(url, e.headers["Location"])
                continue
            return e.code, None
        try:
            return st, json.loads(raw)
        except ValueError:
            return st, None
    return 0, None


def rdap_base(kind, key):
    """Authoritative RDAP base URL from IANA's bootstrap: kind 'dns' (key = TLD), 'ipv4' / 'ipv6' (key = address)
    or 'asn' (key = number); '' when the registry has none."""
    if kind not in WHOIS_BOOT:
        st, d = web_get_json("https://data.iana.org/rdap/%s.json" % kind)
        if not isinstance(d, dict):
            return ""
        WHOIS_BOOT[kind] = d.get("services") or []
    for entries, urls in WHOIS_BOOT[kind]:
        for e in entries:
            try:
                hit = (e.lower() == key if kind == "dns" else
                       key in ipaddress.ip_network(e, strict=False) if kind.startswith("ipv") else
                       int(e.split("-")[0]) <= key <= int(e.split("-")[-1]))
            except ValueError:
                hit = False
            if hit:
                u = next((x for x in urls if x.startswith("https://")), "")
                return u + ("" if u.endswith("/") or not u else "/")
    return ""


def whois43(query, timeout=8):
    """Plain WHOIS on TCP 43: IANA names the registry's server, which is then asked -> (server, text)."""
    def ask(srv, q):
        if not re.match(r"^[a-z0-9.\-]{1,253}$", srv):
            raise ValueError("unexpected WHOIS server name %r" % srv)
        buf = b""
        with socket.create_connection((srv, 43), timeout=timeout) as s:
            s.sendall((q + "\r\n").encode("ascii", "ignore"))
            while len(buf) < 200000:
                c = s.recv(8192)
                if not c:
                    break
                buf += c
        return buf.decode("utf-8", "replace")
    if WHOIS_BOOT.get("tcp43_down", 0) > time.time():
        raise OSError("TCP 43 outbound is unreachable from this host (remembered for 10 minutes)")
    try:
        text = ask("whois.iana.org", query)
    except OSError:
        WHOIS_BOOT["tcp43_down"] = time.time() + 600   # firewalled: do not wait for the timeout on every lookup
        raise
    m = re.search(r"(?im)^(?:refer|whois):\s*(\S+)", text)
    if not m:
        return "whois.iana.org", text
    server = m.group(1).lower()
    return server, ask(server, query)


def whois_fields(text):
    """'Key: value' lines of a WHOIS answer -> {lowercase key: 'v1; v2'}, skipping comments and notices."""
    out = {}
    for ln in text.splitlines():
        if ln.lstrip().startswith(("%", "#", ">>>", "NOTICE", "TERMS", "URL of the ICANN")):
            continue
        m = re.match(r"^\s*([A-Za-z][A-Za-z0-9 /().\-]{0,40}?)\s*:\s+(\S.*?)\s*$", ln)
        if m:
            k = m.group(1).strip().lower()
            if m.group(2) not in out.setdefault(k, []):
                out[k].append(m.group(2))
    return {k: "; ".join(v) for k, v in out.items()}


def whois_pick(f, *keys):
    return next((f[k] for k in keys if f.get(k)), "")


def rdap_entities(obj, out=None):
    """Every entity of an RDAP object, nested ones too -> {role: ['name <email>', ...]}."""
    out = {} if out is None else out
    for e in obj.get("entities") or []:
        if not isinstance(e, dict):
            continue
        name = email = ""
        for p in ((e.get("vcardArray") or [None, []])[1:2] or [[]])[0] or []:
            if isinstance(p, list) and len(p) >= 4:
                if p[0] == "fn" and not name:
                    name = str(p[3]).strip()
                elif p[0] == "email" and not email:
                    email = str(p[3]).strip()
        label = " ".join(x for x in (name or str(e.get("handle") or ""), "<%s>" % email if email else "") if x)
        for role in e.get("roles") or []:
            if label and label not in out.setdefault(role, []):
                out[role].append(label)
        rdap_entities(e, out)
    return out


def rdap_events(obj):
    return {str(e.get("eventAction")): utc3(e.get("eventDate")) for e in obj.get("events") or [] if isinstance(e, dict)}


def reg_domain(sess, host):
    """Registered domain of a hostname: its Cloudflare zone if one covers it, else the last two labels
    (three under a country second level such as com.sa or co.uk)."""
    z = cf_zone_of_host(sess, host) if sess else None
    if z:
        return z["name"]
    p = host.split(".")
    return ".".join(p[-3:] if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in WHOIS_SLD else p[-2:])


def whois_domain(domain):
    """Registration data of a domain (RDAP, else WHOIS on port 43) -> dict for display."""
    base = rdap_base("dns", domain.rsplit(".", 1)[-1])
    if base:
        st, d = web_get_json(base + "domain/" + urllib.parse.quote(domain))
        if isinstance(d, dict) and d.get("objectClassName") == "domain":
            ev, ents = rdap_events(d), rdap_entities(d)
            return {"domain": str(d.get("ldhName") or domain).lower(), "source": "RDAP " + base,
                    "registrar": ", ".join(ents.get("registrar", [])),
                    "registrant": ", ".join(ents.get("registrant", [])) or "(redacted / not published)",
                    "created": ev.get("registration", ""), "expires": ev.get("expiration", ""),
                    "updated": ev.get("last changed", ""), "status": [str(s) for s in d.get("status") or []],
                    "name_servers": [str(n.get("ldhName") or "").lower() for n in d.get("nameservers") or []
                                     if isinstance(n, dict)],
                    "dnssec": "signed" if (d.get("secureDNS") or {}).get("delegationSigned") else "not signed",
                    "abuse_contact": ", ".join(ents.get("abuse", []))}
    server, text = whois43(domain)
    f = whois_fields(text)
    ns = re.findall(r"(?im)^\s*(?:name ?servers?|nserver)\s*:\s*([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})\.?\s*$", text)
    if not ns:   # registries that list the name servers on the lines under a 'Name Servers:' heading (e.g. .sa)
        m = re.search(r"(?is)name ?servers?:\s*\n((?:[ \t]+\S+[^\n]*\n?)+)", text)
        ns = re.findall(r"(?m)^\s*([a-z0-9.\-]+\.[a-z]{2,})", m.group(1)) if m else []
    return {"domain": domain, "source": "WHOIS %s (port 43; the registry has no RDAP)" % server,
            "registrar": whois_pick(f, "registrar", "sponsoring registrar", "registrar name"),
            "registrant": whois_pick(f, "registrant organization", "registrant", "org", "registrant name"),
            "created": whois_pick(f, "creation date", "created", "created on", "registered on", "registration date",
                                  "registered"),
            "expires": whois_pick(f, "registry expiry date", "expiry date", "expiration date", "expires",
                                  "expires on", "paid-till", "registrar registration expiration date"),
            "updated": whois_pick(f, "updated date", "last updated", "last modified", "changed", "updated"),
            "status": whois_pick(f, "domain status", "status", "state"),
            "name_servers": sorted({n.lower().rstrip(".") for n in ns}),
            "whois_text": text.strip()[:8000]}


def whois_ip(ip):
    """Registration data of an IP address (RDAP from its RIR, else WHOIS on port 43) -> dict for display."""
    base = rdap_base("ipv%d" % ip.version, ip)
    if base:
        st, d = web_get_json(base + "ip/" + str(ip))
        if isinstance(d, dict) and d.get("objectClassName") == "ip network":
            ev, ents = rdap_events(d), rdap_entities(d)
            return {"ip": str(ip), "source": "RDAP " + base,
                    "network_name": d.get("name", ""), "handle": d.get("handle", ""),
                    "range": "%s - %s" % (d.get("startAddress", "?"), d.get("endAddress", "?")),
                    "cidr": ["%s/%s" % (c.get("v4prefix") or c.get("v6prefix"), c.get("length"))
                             for c in d.get("cidr0_cidrs") or [] if isinstance(c, dict)],
                    "type": d.get("type", ""), "country": d.get("country", ""),
                    "organisation": ", ".join(ents.get("registrant") or ents.get("administrative") or []),
                    "abuse_contact": ", ".join(ents.get("abuse", [])),
                    "registered": ev.get("registration", ""), "updated": ev.get("last changed", ""),
                    "parent": d.get("parentHandle", ""),
                    "remarks": " ".join(" ".join(str(x) for x in r.get("description") or [])
                                        for r in d.get("remarks") or [] if isinstance(r, dict))[:400]}
    server, text = whois43(str(ip))
    f = whois_fields(text)
    return {"ip": str(ip), "source": "WHOIS %s (port 43)" % server,
            "network_name": whois_pick(f, "netname", "network name", "netname"),
            "range": whois_pick(f, "inetnum", "inet6num", "netrange", "cidr"),
            "country": whois_pick(f, "country"),
            "organisation": whois_pick(f, "org-name", "orgname", "organization", "descr", "owner"),
            "abuse_contact": whois_pick(f, "abuse-mailbox", "orgabuseemail", "abuse-c", "e-mail"),
            "whois_text": text.strip()[:8000]}


def whois_asn(asn):
    """Holder of an autonomous system number (RDAP) -> dict for display, {} if unavailable."""
    base = rdap_base("asn", asn)
    st, d = web_get_json(base + "autnum/%d" % asn) if base else (0, None)
    if not isinstance(d, dict) or d.get("objectClassName") != "autnum":
        return {}
    ents = rdap_entities(d)
    return {"asn": "AS%d" % asn, "name": d.get("name", ""), "country": d.get("country", ""),
            "holder": ", ".join(ents.get("registrant") or ents.get("administrative") or []),
            "abuse_contact": ", ".join(ents.get("abuse", [])), "source": "RDAP " + base}


def whois_safe(fn, arg):
    try:
        return fn(arg)
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"error": "WHOIS lookup failed: %s (RDAP needs HTTPS to the registries; the fallback needs TCP 43 "
                         "outbound)" % getattr(e, "reason", e)}


def whois_domain_cf(sess, dom):
    """Domain WHOIS; when the registry cannot be reached (no RDAP for the TLD and TCP 43 blocked, e.g. .sa),
    fall back to what Cloudflare's zone record holds about the registration."""
    w = whois_safe(whois_domain, dom)
    z = next((x for x in (sess or {}).get("zones") or [] if x["name"] == dom), None) if w.get("error") else None
    if not z:
        return w
    st, ok, d = cf_get(sess, "/zones/" + z["id"])
    r = (d.get("result") or {}) if ok else {}
    if not r:
        return w
    return {"domain": dom, "source": "Cloudflare zone record (registry WHOIS unreachable: %s)" % w["error"][21:],
            "registrar": r.get("original_registrar") or "", "original_dns_host": r.get("original_dnshost") or "",
            "name_servers": r.get("name_servers") or [], "original_name_servers": r.get("original_name_servers") or [],
            "zone_added_to_cloudflare": utc3(r.get("created_on")), "zone_activated": utc3(r.get("activated_on")),
            "zone_status": r.get("status", "")}


def whois_findings(w, warn_days):
    """Findings from a domain's registration data: expiry, registry holds, missing transfer lock."""
    f, dom = [], w.get("domain", "")
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", str(w.get("expires") or ""))
    if m:
        left = (datetime.date(*map(int, m.groups())) - datetime.date.today()).days
        if left < 0:
            f.append(finding("high", dom, "Domain registration expired %d day(s) ago" % -left))
        elif left <= warn_days:
            f.append(finding("high" if left <= 14 else "medium", dom, "Domain registration expires in %d day(s)" % left,
                             "Renew it at the registrar (%s)." % (w.get("registrar") or "?")))
    st = " ".join(w["status"]) if isinstance(w.get("status"), list) else str(w.get("status") or "")
    st = st.lower().replace(" ", "")
    if re.search(r"hold|redemption|pendingdelete", st):
        f.append(finding("high", dom, "Domain status is %s" % st, "The domain may stop resolving."))
    elif st and "transferprohibited" not in st and "rdap" in str(w.get("source", "")).lower():
        f.append(finding("low", dom, "No transfer lock (clientTransferProhibited) on the domain",
                         "Ask the registrar to lock it against unauthorised transfers."))
    return f


def cf_m_whois(sess, b, t0):
    """WHOIS of a hostname's registered domain and / or an IP: owner, registrar, dates, name servers, abuse."""
    ipv, host = str(b.get("ip") or "").strip(), str(b.get("host") or "").strip().lower().rstrip(".")
    if not ipv and not host:
        raise ValueError("enter an IP and / or a hostname")
    warn_days = num(b.get("days"), 1, 365, 30, "certificate warning days")
    data, notes, parts, findings = {}, [], [], []
    if host:
        if "*" in host or not CF_HOSTNAME_RE.match(host):
            raise ValueError("enter a hostname, e.g. app.example.com")
        dom = reg_domain(sess, host)
        audit(sess, "WHOIS domain " + dom)
        w = data["whois_domain"] = whois_domain_cf(sess, dom)
        if w.get("error"):
            notes.append("%s: %s" % (dom, w["error"]))
        else:
            findings += whois_findings(w, warn_days)
            parts.append("%s · registrar %s%s" % (dom, w.get("registrar") or "?",
                                                  " · expires " + w["expires"] if w.get("expires") else ""))
            if dom != host:
                notes.append("%s is under the registered domain %s." % (host, dom))
    if ipv:
        ip = parse_ip(ipv, "IP address")
        if not ip.is_global:
            notes.append("%s is a private / reserved address: it has no public registration." % ip)
        else:
            audit(sess, "WHOIS IP %s" % ip)
            w = data["whois_ip"] = whois_safe(whois_ip, ip)
            if w.get("error"):
                notes.append("%s: %s" % (ip, w["error"]))
            else:
                parts.append("%s · %s (%s)" % (ip, w.get("organisation") or w.get("network_name") or "?",
                                               w.get("country") or "?"))
            if any(ip in n for n in cf_edge_nets(sess) if n.version == ip.version):
                notes.append("%s is a Cloudflare edge address; the real client is in True-Client-IP." % ip)
    if findings:
        data = dict({"findings": findings}, **data)
    label, kind = cf_sev_verdict(findings, "")
    return cf_result(t0, "WHOIS (RDAP / port 43)", "WHOIS · " + " · ".join(parts) + (" · " + label if label else "")
                     if parts else "WHOIS · NOTHING FOUND", kind if parts else "info",
                     ["HIGH: %s (%s)" % (f["issue"], f["object"]) for f in findings if f["severity"] == "high"] + notes,
                     data)


def cf_m_ip(sess, b, t0):
    ip = parse_ip(b.get("ip"), "IP address")
    zones = cf_zones(sess, b.get("zone"))
    since, until, span = cf_window(b)
    audit(sess, "Cloudflare IP investigation %s" % ip)
    notes, data, deadline = [cf_scope(sess, zones), "Events and traffic: " + span], {}, t0 + 110
    if any(ip in n for n in cf_edge_nets(sess) if n.version == ip.version):
        notes.insert(0, "%s is a Cloudflare edge address. On the F5 it shows as the device-seen client; the real "
                        "client is in True-Client-IP / CF-Connecting-IP." % ip)
    # Analytics: what Cloudflare did with this client, and what it requested.
    lit = cf_lit({"datetime_geq": since, "datetime_leq": until, "clientIP": str(ip)})
    res, dropped = cf_gql_zones(sess, zones, lambda f: cf_q_groups(
        "firewallEventsAdaptiveGroups", lit, 50, ("action", "source", "clientRequestHTTPHost"))(()) + " " +
        "e:" + cf_q_events(lit, 20)(f), CF_EV_FIELDS)
    actions, _ = cf_merge(zones, res, 50, False)
    events, extra = [], set()
    for z in zones:
        zd = res.get(z["id"], (None, []))[0] or {}
        for e in zd.get("e") or []:
            events.append((str(e.get("datetime") or ""), cf_ev_row(z, e)))
            if e.get("clientAsn"):   # access rules can also target the client's ASN or country
                extra.add(("asn", "AS%s" % e["clientAsn"]))
            if e.get("clientCountryName"):
                extra.add(("country", e["clientCountryName"]))
    events = [r for _, r in sorted(events, key=lambda x: x[0], reverse=True)][:25]
    res2, _ = cf_gql_zones(sess, zones, cf_q_groups("httpRequestsAdaptiveGroups", lit, 30,
                                                    ("clientRequestHTTPHost", "edgeResponseStatus")))
    traffic, total_req = cf_merge(zones, res2, 30, False)
    data["security_actions"], data["latest_security_events"], data["traffic_by_host_status"] = actions, events, traffic
    notes += cf_gql_notes(zones, res, dropped) + cf_gql_notes(zones, res2, [])
    # Configuration: access rules, IP lists, rules and DNS records that involve the IP.
    active = {r["cf_zone"] for r in events} | {k.strip() for r in actions + traffic for k in r["cf_zone"].split(",")}
    cfg = [z for z in zones if z["name"] in active] or zones[:CF_MAX_CFG_ZONES]
    if len(zones) > 1:
        notes.append("Configuration was checked in %d zone(s)%s." % (len(cfg), " where this IP was active" if active
                                                                      else " (the first ones; choose a zone for others)"))
    extra = sorted(extra)
    accts = cf_accounts(sess, cfg)
    jobs = [(z["name"], "/zones/" + z["id"]) for z in cfg] + [(cf_acct_name(sess, a), "/accounts/" + a) for a in accts]
    access, errs = [], []
    for r in cf_each(jobs, lambda j: cf_access_rules(sess, j[0], j[1], ip, extra)):
        if isinstance(r, dict):
            errs.append(r["error"])
        else:
            access += r[0]
            errs += r[1]
    lists, lnames = [], []
    for a in accts:
        rows, names, e = cf_ip_lists(sess, a, ip, deadline)
        lists, lnames, errs = lists + rows, lnames + names, errs + e
    rules, rerrs, _ = cf_all_rules(sess, cfg)
    hits = [cf_rule_row(x, why) for x in rules for why in [cf_rule_match(x, ip=ip, lists=lnames)] if why]
    dns = []
    for z, r in zip(zones, cf_each(zones, lambda z: cf_list(sess, "/zones/%s/dns_records?content=%s" % (
            z["id"], urllib.parse.quote(str(ip))), per_page=100, max_pages=2))):
        if isinstance(r, dict):
            errs.append(r["error"])
            continue
        if r[1]:
            errs.append("%s DNS: %s" % (z["name"], r[1]))
        dns += [cf_dns_row(z, x) for x in r[0] if str(x.get("content")) == str(ip)]
    data.update({"ip_access_rules": access, "ip_lists_containing_ip": lists, "rules_referencing_ip": hits,
                 "dns_records_pointing_to_ip": dns})
    errs += rerrs
    if errs:
        notes.append("Some configuration could not be read (token permission or plan): " + " | ".join(errs[:5]) +
                     (" …" if len(errs) > 5 else ""))
    f5_rows, f5_notes, _ = cf_f5_check(b, "ip", str(ip))
    if f5_rows is not None:
        data["f5_asm_requests_true_client_ip"] = f5_rows
    notes += f5_notes
    if ip.is_global:   # who holds the address (and the client's ASN, from the events)
        w = data["whois_ip"] = whois_safe(whois_ip, ip)
        notes.append("WHOIS: " + (w.get("error") or "%s, %s (%s)%s." % (
            w.get("organisation") or "?", w.get("network_name") or "?", w.get("country") or "?",
            ", abuse " + w["abuse_contact"] if w.get("abuse_contact") else "")))
        asns = [int(v[2:]) for k, v in extra if k == "asn" and v[2:].isdigit()]
        if asns:
            a = whois_safe(whois_asn, asns[0])
            if a and not a.get("error"):
                data["whois_asn"] = a
    if dns:
        notes.append("%s is the origin for %d DNS record(s); %d of them are proxied." % (
            ip, len(dns), sum(1 for r in dns if r["proxied"])))
    # Verdict
    deny = [r for r in access if r["mode"] in ("block", "challenge", "js_challenge", "managed_challenge")]
    allow = [r for r in access if r["mode"] == "whitelist"]
    blocked = sum(r["count"] for r in actions if r.get("action") in CF_BLOCK)
    challenged = sum(r["count"] for r in actions if "challenge" in str(r.get("action")) and "solved" not in str(r.get("action")))
    parts, kind = [], "info"
    if deny:
        parts.append("IP ACCESS RULE: %s (%s)" % (deny[0]["mode"].upper(), deny[0]["cf_zone"]))
        kind = "bad"
    if blocked:
        parts.append("BLOCKED %d TIME(S)" % blocked)
        kind = "bad"
    if challenged:
        parts.append("CHALLENGED %d TIME(S)" % challenged)
        kind = "bad" if kind == "bad" else "warn"
    if allow:
        parts.append("ALLOWLISTED by an IP Access Rule (%s)" % allow[0]["cf_zone"])
    if lists:
        parts.append("IN %d IP LIST(S)" % len(lists))
    if hits:
        parts.append("%d RULE(S) REFERENCE IT" % len(hits))
    if not parts:
        parts.append("%d REQUEST(S), NOTHING BLOCKED" % total_req if total_req else "NO ACTIVITY OR CONFIGURATION FOUND")
        kind = "ok" if total_req else "info"
    return cf_result(t0, "Cloudflare IP investigation %s" % ip, "%s · %s" % (ip, " · ".join(parts)), kind, notes, data)


def cf_m_host(sess, b, t0):
    host = str(b.get("host") or "").strip().lower().rstrip(".")
    if not host or "*" in host or not CF_HOSTNAME_RE.match(host):
        raise ValueError("enter a hostname, e.g. app.example.com")
    zone = cf_zone_of_host(sess, host)
    if not zone:
        raise ValueError("no zone visible to this token covers %s" % host)
    zid, zn = zone["id"], zone["name"]
    since, until, span = cf_window(b)
    warn_days = num(b.get("days"), 1, 365, 30, "certificate warning days")
    audit(sess, "Cloudflare hostname investigation " + host)
    notes = ["Zone: %s (%s, %s)." % (zn, zone.get("plan") or "plan unknown", zone.get("status") or "status unknown"),
             "Traffic and events: " + span]
    findings, data, errs = [], {}, []
    recs, err, _ = cf_list(sess, "/zones/%s/dns_records?name=%s" % (zid, urllib.parse.quote(host)), per_page=100, max_pages=2)
    if not recs and not err and host != zn:
        wc = "*." + host.split(".", 1)[1]
        recs, err, _ = cf_list(sess, "/zones/%s/dns_records?name=%s" % (zid, urllib.parse.quote(wc)), per_page=100, max_pages=2)
        if recs:
            notes.append("No record for %s itself; it is answered by the wildcard %s." % (host, wc))
    if err:
        errs.append("DNS: " + err)
    data["dns_records"] = [cf_dns_row(zone, r) for r in recs]
    if not recs and not err:
        findings.append(finding("high", host, "No DNS record for this hostname in the zone",
                                "Requests for it do not reach Cloudflare through this zone (unless a SaaS / Worker "
                                "custom hostname serves it)."))
    for r in recs:
        if r.get("type") in ("A", "AAAA", "CNAME") and not r.get("proxied"):
            findings.append(finding("medium", "%s %s" % (r.get("type"), r.get("name")),
                                    "DNS-only (grey cloud): requests bypass Cloudflare security, and the origin %s is "
                                    "public" % r.get("content")))
    proxied = any(r.get("proxied") for r in recs)
    s, err = cf_zone_settings(sess, zone)
    if s:
        findings += cf_settings_findings(zone, s, cf_tci_managed(sess, zone))
    elif err:
        errs.append("zone settings: " + err)
    certs, cerrs = cf_cert_rows(sess, zone)
    errs += cerrs
    cov = [c for c in certs if any(cf_host_match(h, host) for h in c["hosts"])]
    if proxied and not cerrs and not any(c["status"] == "active" for c in cov):
        findings.append(finding("high", host, "No active edge certificate covers this hostname",
                                "HTTPS visitors get a TLS handshake failure (e.g. a sub-subdomain that a "
                                "*.%s certificate does not cover)." % zn))
    findings += cf_cert_findings(cov, warn_days)
    rules, rerrs, _ = cf_all_rules(sess, [zone])
    errs += rerrs
    data["rules_mentioning_host"] = [cf_rule_row(x, why) for x in rules for why in [cf_rule_match(x, host)] if why]
    wide = sum(1 for x in rules if x["phase"] in CF_SEC_PHASES and x["rule"].get("enabled", True)
               and "host" not in str(x["rule"].get("expression") or "") and x["base"].startswith("/zones/"))
    if wide:
        notes.append("%d enabled security rule(s) in the zone do not mention a hostname, so they also apply to %s "
                     "(Search rules with the zone selected lists them)." % (wide, host))
    st, ok, d = cf_get(sess, "/zones/%s/workers/routes" % zid)
    if ok:
        data["worker_routes"] = [{"pattern": r.get("pattern"), "worker": r.get("script") or "(none: route disables Workers)"}
                                 for r in d.get("result") or [] if cf_route_match(r.get("pattern"), host)]
    st, ok, d = cf_get(sess, "/zones/%s/pagerules" % zid)
    if ok:
        data["page_rules"] = [{"target": t.get("constraint", {}).get("value"), "status": p.get("status"),
                               "priority": p.get("priority"), "actions": [a.get("id") for a in p.get("actions") or []]}
                              for p in d.get("result") or [] for t in p.get("targets") or []
                              if cf_route_match((t.get("constraint") or {}).get("value"), host)]
    st, ok, d = cf_get(sess, "/zones/%s/load_balancers" % zid)
    if ok:
        data["load_balancers"] = [{"name": x.get("name"), "enabled": x.get("enabled"), "proxied": x.get("proxied"),
                                   "steering": x.get("steering_policy"), "default_pools": x.get("default_pools"),
                                   "fallback_pool": x.get("fallback_pool")}
                                  for x in d.get("result") or [] if str(x.get("name", "")).lower() == host]
    if data.get("load_balancers"):
        notes.append("This hostname is a Cloudflare load balancer: run 'Load balancers & health' for origin health.")
    flt = cf_lit({"datetime_geq": since, "datetime_leq": until, "clientRequestHTTPHost": host})
    res, _ = cf_gql_zones(sess, [zone], cf_q_groups("httpRequestsAdaptiveGroups", flt, 20,
                                                    ("edgeResponseStatus", "originResponseStatus")))
    traffic, total = cf_merge([zone], res, 20, False)
    res2, _ = cf_gql_zones(sess, [zone], cf_q_groups("firewallEventsAdaptiveGroups", flt, 20, ("action", "source")))
    sec, sec_total = cf_merge([zone], res2, 20, False)
    data["traffic_by_status"], data["security_events_by_action"] = traffic, sec
    notes += cf_gql_notes([zone], res, []) + cf_gql_notes([zone], res2, [])
    if total:
        e5 = sum(r["count"] for r in traffic if str(r.get("edge_status", "")).startswith("5"))
        o52 = sum(r["count"] for r in traffic if 520 <= int(r.get("edge_status") or 0) <= 527)
        notes.append("%d request(s), %d security event(s) in the range; %.1f%% ended in 5xx." % (
            total, sec_total, 100.0 * e5 / total))
        if e5 * 20 > total:
            findings.append(finding("medium", host, "%.1f%% of requests ended in a 5xx error" % (100.0 * e5 / total)))
        if o52:
            findings.append(finding("medium", host, "%d request(s) got a Cloudflare 52x origin error" % o52,
                                    "Cloudflare could not connect to, or got no valid answer from, the origin (F5)."))
    elif not res.get(zid, (None, []))[1]:
        notes.append("No requests for this hostname in the range.")
    if errs:
        notes.append("Some parts could not be read (token permission or plan): " + " | ".join(errs[:5]))
    w = data["whois_domain"] = whois_domain_cf(sess, zn)
    if w.get("error"):
        notes.append("WHOIS %s: %s" % (zn, w["error"]))
    else:
        findings += whois_findings(w, warn_days)
        notes.append("WHOIS %s: registrar %s, expires %s, name servers %s." % (
            zn, w.get("registrar") or "?", w.get("expires") or "?", ", ".join(w.get("name_servers") or []) or "?"))
    label, kind = cf_sev_verdict(findings, "NO ISSUES FOUND")
    data = dict({"findings": findings}, **data)
    return cf_result(t0, "Cloudflare hostname investigation " + host, "%s · %s" % (host, label), kind,
                     ["HIGH: %s (%s)" % (f["issue"], f["object"]) for f in findings if f["severity"] == "high"] + notes, data)


def cf_m_rules(sess, b, t0):
    q = cf_text(b.get("q"), "search text")
    zones = cf_zones(sess, b.get("zone"))[:CF_MAX_CFG_ZONES]
    try:
        ip = ipaddress.ip_address(q) if q else None
    except ValueError:
        ip = None
    rid = q.lower() if re.fullmatch(r"[0-9a-fA-F]{32}", q) else ""
    audit(sess, "Cloudflare rule search '%s'" % q)
    rules, errs, cache = cf_all_rules(sess, zones)
    if not q:
        hits = [cf_rule_row(x) for x in rules if x["phase"] in CF_SEC_PHASES or x["rule"].get("action") == "execute"]
    elif rid:
        hits = [cf_rule_row(x, "rule ID" if x["rule"].get("id") == rid else "ruleset ID") for x in rules
                if rid in (x["rule"].get("id"), x["ruleset_id"])]
    else:
        hits = [cf_rule_row(x, why) for x in rules for why in [cf_rule_match(x, q, ip)] if why]
        if ip is not None:
            hits += [cf_rule_row(x, why) for x in rules for why in [cf_rule_match(x, q)]
                     if why and not cf_rule_match(x, ip=ip)]
    managed = []
    if rid and not hits:
        # Not one of ours: look for it in the managed rulesets the zones run (e.g. Cloudflare Managed / OWASP).
        execs = [x for x in rules if x["rule"].get("action") == "execute"
                 and CF_ID_RE.match(str((x["rule"].get("action_parameters") or {}).get("id") or ""))]
        seen = {}
        for x in execs:
            mid = x["rule"]["action_parameters"]["id"]
            if mid not in seen and time.time() - t0 < 90:
                st, ok, d = cf_get(sess, "%s/rulesets/%s" % (x["base"], mid))
                seen[mid] = (d.get("result") or {}) if ok else {}
            mr = seen.get(mid) or {}
            for rule in mr.get("rules") or []:
                if rule.get("id") != rid:
                    continue
                ov = [o for o in ((x["rule"].get("action_parameters") or {}).get("overrides") or {}).get("rules") or []
                      if o.get("id") == rid]
                managed.append({"cf_zone": x["where"], "managed_ruleset": mr.get("name", mid), "rule_id": rid,
                                "description": rule.get("description", ""), "default_action": rule.get("action", ""),
                                "enabled_by_default": rule.get("enabled", True),
                                "categories": rule.get("categories") or [],
                                "zone_override": json.dumps(ov[0]) if ov else "none (ruleset / category settings apply)",
                                "deployed_by": "%s rule %s (%s)" % (x["phase"], x["pos"], x["rule"].get("description", ""))})
    notes = [cf_scope(sess, zones).replace("All", "Zones searched: all", 1),
             "Searched %d rule(s) in custom, rate limiting, managed-deployment, transform, redirect, origin, cache and "
             "configuration rulesets of the zones and their account(s)." % len(rules)]
    if rid and not hits and not managed:
        notes.append("Rule ID not found. Managed rules can only be found in rulesets that a zone deploys.")
    if errs:
        notes.append("Some rulesets could not be read (token needs Zone WAF / Account Rulesets read): " +
                     " | ".join(errs[:5]))
    return cf_result(t0, "GET /zones/<id>/rulesets", "%d MATCHING RULE(S)" % (len(hits) + len(managed)),
                     "warn" if hits or managed else "info", notes,
                     {"managed_rule": managed, "rules": hits})


def cf_m_dns(sess, b, t0):
    name = cf_text(b.get("name"), "name").lower()
    content = cf_text(b.get("content"), "content")
    rtype = str(b.get("type") or "").strip().upper()
    if rtype and not re.fullmatch(r"[A-Z]{1,10}", rtype):
        raise ValueError("invalid record type")
    if not (name or content or rtype):
        raise ValueError("enter a name and/or content to search for, or choose a record type")
    zones = cf_zones(sess, b.get("zone"))
    audit(sess, "Cloudflare DNS search name~%s content~%s %s" % (name, content, rtype))

    def one(z):
        q = [k + "=" + urllib.parse.quote(v) for k, v in (("name.contains", name), ("content.contains", content),
                                                          ("type", rtype)) if v]
        items, err, trunc = cf_list(sess, "/zones/%s/dns_records?%s" % (z["id"], "&".join(q)), per_page=500, max_pages=10)
        if err and (name or content):   # older API without .contains filters: fetch and filter here
            items, err, trunc = cf_list(sess, "/zones/%s/dns_records%s" % (z["id"], "?type=" + rtype if rtype else ""),
                                        per_page=500, max_pages=10)
        hit = [cf_dns_row(z, r) for r in items if (not name or name in str(r.get("name", "")).lower())
               and (not content or content.lower() in str(r.get("content", "")).lower())
               and (not rtype or r.get("type") == rtype)]
        return {"rows": hit, "error": err, "trunc": trunc}
    rows, errs, trunc = [], [], []
    for z, r in zip(zones, cf_each(zones, one)):
        rows += r.get("rows") or []
        if r.get("error"):
            errs.append("%s: %s" % (z["name"], r["error"]))
        if r.get("trunc"):
            trunc.append(z["name"])
    notes = [cf_scope(sess, zones)]
    if errs:
        notes.append("Errors: " + " | ".join(errs[:5]))
    if trunc:
        notes.append("Only the first 5000 records were searched in: " + ", ".join(trunc))
    exposed = [r for r in rows if r["type"] in ("A", "AAAA", "CNAME") and not r["proxied"]]
    if exposed:
        notes.append("%d matching A/AAAA/CNAME record(s) are DNS-only (not proxied through Cloudflare)." % len(exposed))
    return cf_result(t0, "GET /zones/<id>/dns_records", "%d DNS RECORD(S)" % len(rows), "ok" if rows else "info",
                     notes, {"dns_records": sorted(rows, key=lambda r: (r["cf_zone"], r["name"], r["type"]))})


def cf_m_posture(sess, b, t0):
    zones = cf_zones(sess, b.get("zone"))[:CF_MAX_CFG_ZONES]
    warn_days = num(b.get("days"), 1, 365, 30, "certificate warning days")
    audit(sess, "Cloudflare security posture (%d zones)" % len(zones))

    def one(z):
        s, err = cf_zone_settings(sess, z)
        certs, cerrs = cf_cert_rows(sess, z)
        recs, derr, _ = cf_list(sess, "/zones/%s/dns_records" % z["id"], per_page=500, max_pages=10)
        return {"s": s, "err": [e for e in [err, derr and "DNS: " + derr] if e] + cerrs, "certs": certs,
                "recs": recs, "tci": cf_tci_managed(sess, z) if s else None}
    findings, inv, notes, certs = [], [], [cf_scope(sess, zones)], []
    for z, r in zip(zones, cf_each(zones, one, workers=6)):
        if r.get("error"):
            notes.append("%s: %s" % (z["name"], r["error"]))
            continue
        s, zc = r["s"] or {}, r["certs"]
        notes += [e if e.startswith(z["name"]) else "%s: %s" % (z["name"], e) for e in r["err"]]
        if r["s"]:
            findings += cf_settings_findings(z, s, r["tci"])
        findings += cf_cert_findings(zc, warn_days)
        certs += zc
        prox = [x for x in r["recs"] if x.get("type") in ("A", "AAAA", "CNAME")]
        grey = [x for x in prox if not x.get("proxied")]
        if grey:
            findings.append(finding("low", z["name"], "%d of %d A/AAAA/CNAME record(s) are DNS-only" % (len(grey), len(prox)),
                                    "e.g. " + ", ".join(x.get("name", "") for x in grey[:5])))
        if z.get("status") not in ("active", ""):
            findings.append(finding("medium", z["name"], "Zone status is '%s'" % z.get("status")))
        days = [c["days_left"] for c in zc if c["days_left"] != ""]
        inv.append({"cf_zone": z["name"], "plan": z.get("plan"), "status": z.get("status"), "ssl": s.get("ssl", ""),
                    "min_tls": s.get("min_tls_version", ""), "tls_1_3": s.get("tls_1_3", ""),
                    "always_https": s.get("always_use_https", ""), "security_level": s.get("security_level", ""),
                    "true_client_ip": "on" if s.get("true_client_ip_header") == "on" or r["tci"] else
                    ("off" if r["s"] else ""), "dev_mode": s.get("development_mode", ""),
                    "dns_only_records": "%d of %d" % (len(grey), len(prox)),
                    "certs": "%d (soonest expiry %s days)" % (len(zc), min(days)) if days else len(zc)})
    label, kind = cf_sev_verdict(findings, "NO ISSUES FOUND")
    return cf_result(t0, "GET /zones/<id>/settings, ssl, dns_records", label, kind,
                     ["HIGH: %s (%s)" % (f["issue"], f["object"]) for f in findings if f["severity"] == "high"][:15] + notes,
                     {"findings": findings, "zones": inv, "certificates": certs})


def cf_m_lb(sess, b, t0):
    zones = cf_zones(sess, b.get("zone"))[:CF_MAX_CFG_ZONES]
    audit(sess, "Cloudflare load balancer / health check status")
    notes, errs = [cf_scope(sess, zones)], []
    lbs, checks = [], []
    for z, r in zip(zones, cf_each(zones, lambda z: (cf_get(sess, "/zones/%s/load_balancers" % z["id"]),
                                                     cf_get(sess, "/zones/%s/healthchecks" % z["id"])))):
        if isinstance(r, dict):
            errs.append(r["error"])
            continue
        (st, ok, d), (st2, ok2, d2) = r
        if ok:
            lbs += [dict(x, _zone=z["name"]) for x in d.get("result") or []]
        else:
            errs.append("%s load balancers: %s" % (z["name"], cf_errtext(st, d)))
        if ok2:
            checks += [{"cf_zone": z["name"], "name": h.get("name"), "address": h.get("address"), "type": h.get("type"),
                        "status": h.get("status"), "failure_reasons": h.get("failure_reason") or h.get("failure_reasons") or "",
                        "interval_s": h.get("interval"), "regions": h.get("check_regions") or []}
                       for h in d2.get("result") or []]
    used_by = collections.defaultdict(list)
    for x in lbs:
        for p in (x.get("default_pools") or []) + [x.get("fallback_pool")]:
            if p and x.get("name") not in used_by[p]:
                used_by[p].append(x.get("name"))
    pools = []
    for a in cf_accounts(sess, zones):
        st, ok, d = cf_get(sess, "/accounts/%s/load_balancers/pools" % a)
        if ok:
            pools += [(a, p) for p in d.get("result") or [] if CF_ID_RE.match(str(p.get("id") or ""))]
        else:
            errs.append("%s pools: %s" % (cf_acct_name(sess, a), cf_errtext(st, d)))
    healths = cf_each(pools[:60], lambda ap: cf_get(sess, "/accounts/%s/load_balancers/pools/%s/health" % (ap[0], ap[1]["id"])))
    rows, bad = [], 0
    for (a, p), h in zip(pools[:60], healths):
        stats = {}
        if not isinstance(h, dict) and h[1]:
            for region, v in ((h[2].get("result") or {}).get("pop_health") or {}).items():
                for o in (v or {}).get("origins") or []:
                    for addr, oh in (o or {}).items():
                        s = stats.setdefault(addr, {"ok": 0, "n": 0, "why": collections.Counter(),
                                                    "code": collections.Counter(), "rtt": ""})
                        s["n"] += 1
                        s["ok"] += 1 if oh.get("healthy") else 0
                        if oh.get("failure_reason") and oh["failure_reason"] != "No failures":
                            s["why"][oh["failure_reason"]] += 1
                        if oh.get("response_code"):
                            s["code"][str(oh["response_code"])] += 1
                        s["rtt"] = oh.get("rtt") or s["rtt"]
        for o in p.get("origins") or []:
            s = stats.get(o.get("address")) or stats.get(o.get("name")) or {}
            unhealthy = s and s["ok"] < s["n"]
            bad += 1 if unhealthy and o.get("enabled", True) and p.get("enabled", True) else 0
            rows.append({"pool": p.get("name"), "pool_enabled": p.get("enabled"), "origin": o.get("name"),
                         "address": o.get("address"), "origin_enabled": o.get("enabled", True), "weight": o.get("weight"),
                         "health": ("healthy" if not unhealthy else "unhealthy") + " in %d of %d region(s)" % (s["ok"], s["n"])
                         if s else "no health data (no monitor?)",
                         "failure_reason": "; ".join("%s (%d)" % kv for kv in s["why"].most_common(3)) if s else "",
                         "response_codes": ", ".join(s["code"]) if s else "", "rtt": s.get("rtt", "") if s else "",
                         "used_by": used_by.get(p.get("id")) or [], "monitor": p.get("monitor") or ""})
    lb_rows = [{"cf_zone": x["_zone"], "name": x.get("name"), "enabled": x.get("enabled"), "proxied": x.get("proxied"),
                "steering": x.get("steering_policy"), "session_affinity": x.get("session_affinity"),
                "pools": [next((p.get("name") for _, p in pools if p.get("id") == i), i) for i in x.get("default_pools") or []],
                "fallback": next((p.get("name") for _, p in pools if p.get("id") == x.get("fallback_pool")), x.get("fallback_pool"))}
               for x in lbs]
    bad += sum(1 for c in checks if c["status"] not in ("healthy", "suspended"))
    if len(pools) > 60:
        notes.append("Health was read for the first 60 of %d pools." % len(pools))
    if errs:
        notes.append("Some parts could not be read (Load Balancing / Health Checks read permissions): " + " | ".join(errs[:5]))
    return cf_result(t0, "GET load_balancers, pools/<id>/health, healthchecks",
                     "%d UNHEALTHY ORIGIN(S) / HEALTH CHECK(S)" % bad if bad else
                     "%d LOAD BALANCER(S), %d POOL(S), %d HEALTH CHECK(S): ALL HEALTHY" % (len(lb_rows), len(pools), len(checks)),
                     "bad" if bad else "ok" if rows or checks else "info", notes,
                     {"load_balancers": lb_rows, "pool_origins": rows, "health_checks": checks})


def cf_m_audit(sess, b, t0):
    zones = cf_zones(sess, b.get("zone"))
    since, until, span = cf_window(b)
    email = str(b.get("email") or "").strip()
    if email and not re.fullmatch(r"[^\s@\"\\]{1,64}@[A-Za-z0-9.\-]{1,190}", email):
        raise ValueError("invalid e-mail address")
    actq, resq = cf_text(b.get("action"), "action").lower(), cf_text(b.get("resource"), "resource").lower()
    limit = num(b.get("top"), 1, 1000, 100, "max rows")
    one_zone = zones[0]["name"] if len(zones) == 1 and len(sess.get("zones") or []) != 1 else ""
    audit(sess, "Cloudflare audit log %s %s" % (email or "*", one_zone or "all zones"))
    rows, errs = [], []
    for a in cf_accounts(sess, zones):
        q = {"since": since, "before": until, "direction": "desc", "per_page": 100}
        if email:
            q["actor.email"] = email
        if one_zone:
            q["zone.name"] = one_zone
        for page in range(1, 21):
            q["page"] = page
            st, ok, d = cf_get(sess, "/accounts/%s/audit_logs?%s" % (a, urllib.parse.urlencode(q)))
            if not ok:
                errs.append("%s: %s" % (cf_acct_name(sess, a), cf_errtext(st, d)))
                break
            res = d.get("result") or []
            for x in res:
                act, rsc, meta = x.get("action") or {}, x.get("resource") or {}, x.get("metadata") or {}
                actor = x.get("actor") or {}
                text = json.dumps(x).lower()
                if actq and actq not in str(act.get("type", "")).lower() and actq not in text:
                    continue
                if resq and resq not in text:
                    continue
                rows.append({"time": utc3(x.get("when", "")), "account": cf_acct_name(sess, a)[8:],
                             "actor": actor.get("email") or actor.get("type", ""), "actor_ip": actor.get("ip", ""),
                             "action": act.get("type", ""), "result": "success" if act.get("result") else "failed",
                             "resource": "%s %s" % (rsc.get("type", ""), rsc.get("id", "")),
                             "cf_zone": meta.get("zone_name", ""), "interface": x.get("interface", ""),
                             "new_value": json.dumps(x.get("newValue"))[:300] if x.get("newValue") not in (None, "") else "",
                             "old_value": json.dumps(x.get("oldValue"))[:300] if x.get("oldValue") not in (None, "") else ""})
            if len(res) < 100 or len(rows) >= limit or time.time() - t0 > 100:
                break
    rows = sorted(rows, key=lambda r: r["time"], reverse=True)[:limit]
    notes = ["Time range: " + span, "Accounts: " + ", ".join(cf_acct_name(sess, a)[8:] for a in cf_accounts(sess, zones))]
    if one_zone:
        notes.append("Zone: " + one_zone)
    if errs:
        notes.append("Could not read the audit log (token needs Account Settings Read / Audit Logs Read): " + " | ".join(errs[:3]))
    failed = sum(1 for r in rows if r["result"] == "failed")
    return cf_result(t0, "GET /accounts/<id>/audit_logs", "%d CHANGE(S) / EVENT(S)%s" % (
                         len(rows), " · %d FAILED" % failed if failed else ""), "warn" if failed else "ok" if rows else "info",
                     notes, {"audit_log": rows})


CF_TTFB = ("edgeTimeToFirstByteMsP50", "edgeTimeToFirstByteMsP95", "edgeTimeToFirstByteMsP99")
CF_CACHE_KEYS = ("hit", "miss", "dynamic", "bypass", "none", "expired")   # the rest is shown as "other"
CF_CACHED = ("hit", "stale", "updating", "revalidated")
CF_DASH_TOPS = (("tp", "Top paths", "path", "clientRequestPath"), ("tc", "Top countries", "country", "clientCountryName"),
                ("ti", "Top client IPs", "client_ip", "clientIP"), ("ta", "Top ASNs", "asn", "clientAsn"),
                ("th", "Top hosts", "host", "clientRequestHTTPHost"), ("tr", "Top referrers", "referrer", "clientRefererHost"))


def cf_fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1000 or unit == "TB":
            return ("%d %s" if unit == "B" else "%.2f %s") % (n, unit)
        n /= 1000.0


def cf_m_dashboard(sess, b, t0):
    """Cloudflare-style traffic dashboard: headline tiles (vs the previous period of the same length), requests,
    data transfer, status codes, cache status and edge TTFB over time, and top-N lists. One query per 2 zones."""
    zones = cf_zones(sess, b.get("zone"))
    since, until, span = cf_window(b)
    cur = cf_filters(b, "http", since, until)
    s0, s1 = to_epoch(since), to_epoch(until)
    iso = lambda e: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e))
    prev = dict(cur, datetime_geq=iso(2 * s0 - s1), datetime_leq=iso(s0 - 1))
    secs = s1 - s0
    dim, bucket = (("datetimeMinute", "1 minute") if secs <= 10800 else ("datetimeFiveMinutes", "5 minutes")
                   if secs <= 86400 else ("datetimeHour", "1 hour") if secs <= 604800 else ("date", "1 day (UTC dates)"))
    audit(sess, "Cloudflare traffic dashboard %s" % json.dumps({k: v for k, v in cur.items() if "datetime" not in k}))
    G, cl, pl = "httpRequestsAdaptiveGroups", cf_lit(cur), cf_lit(prev)
    q_tok = "quantiles{%s}" % " ".join(CF_TTFB)

    def sel(f):
        q = q_tok if q_tok in f else ""
        sm = "sum{edgeResponseBytes%s}" % (" visits" if "visits" in f else "")
        parts = ["tot:%s(filter:%s,limit:1){count %s %s}" % (G, cl, sm, q),
                 "prev:%s(filter:%s,limit:1){count %s %s}" % (G, pl, sm, q),
                 "pst:%s(filter:%s,limit:100,orderBy:[count_DESC]){count dimensions{edgeResponseStatus}}" % (G, pl),
                 "pca:%s(filter:%s,limit:50,orderBy:[count_DESC]){count dimensions{cacheStatus}}" % (G, pl),
                 "ts:%s(filter:%s,limit:5000,orderBy:[%s_ASC]){count %s %s dimensions{%s}}" % (G, cl, dim, sm, q, dim),
                 "st:%s(filter:%s,limit:10000,orderBy:[%s_ASC]){count dimensions{%s edgeResponseStatus}}" % (G, cl, dim, dim),
                 "ca:%s(filter:%s,limit:10000,orderBy:[%s_ASC]){count dimensions{%s cacheStatus}}" % (G, cl, dim, dim)]
        for alias, _, _, field in CF_DASH_TOPS:
            if field == "clientRefererHost" and field not in f:
                continue
            extra = " clientASNDescription" if field == "clientAsn" and "clientASNDescription" in f else ""
            parts.append("%s:%s(filter:%s,limit:10,orderBy:[count_DESC]){count dimensions{%s%s}}" % (
                alias, G, cl, field, extra))
        return " ".join(parts)
    res, dropped = cf_gql_zones(sess, zones, sel, ("visits", q_tok, "clientASNDescription", "clientRefererHost"), chunk=2)

    def acc():
        return {"n": 0, "bytes": 0, "visits": 0, "q": [0.0, 0.0, 0.0], "qn": 0}

    def add(a, g):
        n = int(g.get("count") or 0)
        a["n"] += n
        a["bytes"] += int((g.get("sum") or {}).get("edgeResponseBytes") or 0)
        a["visits"] += int((g.get("sum") or {}).get("visits") or 0)
        q = g.get("quantiles") or {}
        if q and n:   # several zones: count-weighted mean of each zone's percentile (an approximation)
            for i, k in enumerate(CF_TTFB):
                a["q"][i] += float(q.get(k) or 0) * n
            a["qn"] += n

    def scls(code):
        try:
            return "%dxx" % (int(code) // 100) if 100 <= int(code) < 600 else "other"
        except (TypeError, ValueError):
            return "other"
    tot, prv, ts = acc(), acc(), {}
    st, ca = collections.defaultdict(collections.Counter), collections.defaultdict(collections.Counter)
    pst, pca, tops, asn_names = collections.Counter(), collections.Counter(), collections.defaultdict(collections.Counter), {}
    for z in zones:
        zd = res.get(z["id"], (None, []))[0] or {}
        for g in zd.get("tot") or []:
            add(tot, g)
        for g in zd.get("prev") or []:
            add(prv, g)
        for g in zd.get("ts") or []:
            add(ts.setdefault(str((g.get("dimensions") or {}).get(dim)), acc()), g)
        for g in zd.get("st") or []:
            d = g.get("dimensions") or {}
            st[str(d.get(dim))][scls(d.get("edgeResponseStatus"))] += int(g.get("count") or 0)
        for g in zd.get("ca") or []:
            d = g.get("dimensions") or {}
            c = str(d.get("cacheStatus") or "none").lower()
            ca[str(d.get(dim))][c] += int(g.get("count") or 0)
        for g in zd.get("pst") or []:
            pst[scls((g.get("dimensions") or {}).get("edgeResponseStatus"))] += int(g.get("count") or 0)
        for g in zd.get("pca") or []:
            pca[str((g.get("dimensions") or {}).get("cacheStatus") or "none").lower()] += int(g.get("count") or 0)
        for alias, _, _, field in CF_DASH_TOPS:
            for g in zd.get(alias) or []:
                d = g.get("dimensions") or {}
                tops[alias][str(d.get(field) if d.get(field) not in (None, "") else "(none)")] += int(g.get("count") or 0)
                if field == "clientAsn" and d.get("clientASNDescription"):
                    asn_names[str(d.get(field))] = d["clientASNDescription"]
    keys = sorted(set(ts) | set(st) | set(ca))
    labels = [k if dim == "date" else utc3(k) for k in keys]
    sc_tot, ca_tot = collections.Counter(), collections.Counter()
    for k in keys:
        sc_tot.update(st[k])
        ca_tot.update(ca[k])

    def rate(c, which):
        n = sum(c.values())
        return 100.0 * sum(c[x] for x in which) / n if n else None

    def ttfb(a, i):
        return a["q"][i] / a["qn"] if a["qn"] else None
    has_q, has_v = q_tok not in dropped, "visits" not in dropped
    spark_rate = lambda which, src: [rate(src[k], which) or 0 for k in keys]
    tiles = [{"label": "Total requests", "value": tot["n"], "prev": prv["n"], "fmt": "num",
              "spark": [ts[k]["n"] if k in ts else 0 for k in keys]},
             {"label": "Total data transfer", "value": tot["bytes"], "prev": prv["bytes"], "fmt": "bytes",
              "spark": [ts[k]["bytes"] if k in ts else 0 for k in keys]}]
    if has_v:
        tiles.append({"label": "Total visits", "value": tot["visits"], "prev": prv["visits"], "fmt": "num",
                      "spark": [ts[k]["visits"] if k in ts else 0 for k in keys]})
    tiles += [{"label": "Cache hit rate", "value": rate(ca_tot, CF_CACHED), "prev": rate(pca, CF_CACHED), "fmt": "pct",
               "spark": spark_rate(CF_CACHED, ca)},
              {"label": "5xx error rate", "value": rate(sc_tot, ("5xx",)), "prev": rate(pst, ("5xx",)), "fmt": "pct",
               "spark": spark_rate(("5xx",), st)}]
    if has_q:
        tiles.append({"label": "Edge TTFB (p95)", "value": ttfb(tot, 1), "prev": ttfb(prv, 1), "fmt": "ms",
                      "spark": [ttfb(ts[k], 1) or 0 if k in ts else 0 for k in keys]})
    st_keys = [k for k in ("2xx", "3xx", "4xx", "5xx", "1xx", "other") if sc_tot[k]]
    other = [c for c in ca_tot if c not in CF_CACHE_KEYS]
    ca_keys = [c for c in CF_CACHE_KEYS if ca_tot[c]] + (["other"] if other else [])
    cache_series = {c: [sum(ca[k][x] for x in other) if c == "other" else ca[k][c] for k in keys] for c in ca_keys}
    top_lists = []
    for alias, title, col, field in CF_DASH_TOPS:
        if tops[alias]:
            top_lists.append([title, [[("AS%s %s" % (n, asn_names.get(n, ""))).strip() if field == "clientAsn" else n, v]
                                      for n, v in tops[alias].most_common(10)]])
    dash = {"bucket": bucket, "tiles": tiles, "t": labels,
            "requests": [ts[k]["n"] if k in ts else 0 for k in keys],
            "bytes": [ts[k]["bytes"] if k in ts else 0 for k in keys],
            "status": [[s, [st[k][s] for k in keys]] for s in st_keys],
            "cache": [[c, cache_series[c]] for c in ca_keys],
            "ttfb": [[p, [round(ttfb(ts[k], i) or 0) if k in ts else 0 for k in keys]]
                     for i, p in enumerate(("p50", "p95", "p99"))] if has_q else [], "tops": top_lists}
    # The same numbers as tables: the table view, and what Copy / CSV / HTML report export.
    chg = lambda v, p: "" if v is None or not p else " (%+.1f%% vs previous period)" % (100.0 * (v - p) / p)
    shown = {"num": lambda v: "{:,}".format(v), "bytes": cf_fmt_bytes, "pct": lambda v: "%.2f%%" % v,
             "ms": lambda v: "%d ms" % round(v)}
    data = {"headline": {t["label"]: (shown[t["fmt"]](t["value"]) if t["value"] is not None else "n/a") +
                         chg(t["value"], t["prev"]) for t in tiles}}
    for alias, title, col, field in CF_DASH_TOPS:
        for t_, rows in top_lists:
            if t_ == title:
                data[re.sub(r"\W+", "_", title.lower())] = [
                    {col: n, "requests": v, "share": "%.1f%%" % (100.0 * v / tot["n"]) if tot["n"] else ""} for n, v in rows]
    data["timeline"] = [dict([("time", lbl), ("requests", ts[k]["n"] if k in ts else 0),
                              ("data_transfer", cf_fmt_bytes(ts[k]["bytes"] if k in ts else 0))] +
                             [(s, st[k][s]) for s in ("2xx", "3xx", "4xx", "5xx") if s in st_keys] +
                             ([("ttfb_%s_ms" % p, round(ttfb(ts[k], i) or 0) if k in ts else 0)
                               for i, p in enumerate(("p50", "p95", "p99"))] if has_q else []))
                        for k, lbl in zip(keys, labels)]
    notes = [cf_scope(sess, zones), "Time range: %s; buckets of %s; changes compare with the previous %s." % (
        span, bucket, re.sub(r"^last ", "", str(b.get("within") or "period")) if not b.get("since") else "period of the same length"),
             "Counts are Cloudflare's sample-adjusted estimates, so they can differ slightly from the Cloudflare dashboard."]
    if len(zones) > 1 and has_q:
        notes.append("TTFB percentiles across several zones are count-weighted averages of each zone's percentile (approximate).")
    r = cf_result(t0, "GraphQL httpRequestsAdaptiveGroups (dashboard)", "%s REQUESTS · %s · 5xx %s" % (
        "{:,}".format(tot["n"]), cf_fmt_bytes(tot["bytes"]),
        "%.2f%%" % rate(sc_tot, ("5xx",)) if sc_tot else "n/a"),
        "bad" if (rate(sc_tot, ("5xx",)) or 0) >= 5 else "ok" if tot["n"] else "info",
        notes + cf_gql_notes(zones, res, dropped), data)
    r["dashboard"] = dash
    return r


CF_Q_EDGE = "edgeTimeToFirstByteMsP50 edgeTimeToFirstByteMsP95 edgeTimeToFirstByteMsP99"
CF_Q_ORIGIN = "originResponseDurationMsP50 originResponseDurationMsP95 originResponseDurationMsP99"
CF_ORIGIN_PHASES = (("originDNSResponseTimeMs", "dns_ms"), ("originTCPHandshakeDurationMs", "tcp_ms"),
                    ("originTLSHandshakeDurationMs", "tls_ms"), ("originResponseHeaderReceiveDurationMs", "origin_headers_ms"))


def cf_parse_url(u):
    """'https://host/path?q' or 'host/path' -> (host, path, query)."""
    u = str(u or "").strip()
    if not u:
        raise ValueError("enter a URL, e.g. https://app.example.com/api/login")
    p = urllib.parse.urlsplit(u if re.match(r"^[a-z][a-z0-9+.\-]*://", u, re.I) else "https://" + u)
    host, path = (p.hostname or "").lower(), p.path or "/"
    if not host or "*" in host or not CF_HOSTNAME_RE.match(host):
        raise ValueError("the URL has no valid hostname")
    if not CF_TEXT_RE.match(path):
        raise ValueError("the URL path has characters that are not allowed (no quotes or backslashes)")
    return host, path, p.query


def cf_m_url(sess, b, t0):
    """Edge TTFB and origin response time for one URL (exact path, prefix or contains): percentiles, timeline,
    breakdowns by status / cache / colo / method / path, and the slowest sampled requests."""
    host, path, query = cf_parse_url(b.get("url"))
    match = str(b.get("match") or "exact").strip()
    if match not in ("exact", "starts with", "contains"):
        raise ValueError("invalid path match")
    zone = cf_zone_of_host(sess, host)
    if not zone:
        raise ValueError("no zone visible to this token covers %s" % host)
    since, until, span = cf_window(b)
    flt = cf_filters({k: b.get(k) for k in ("ip", "status", "cache")}, "http", since, until)
    flt["clientRequestHTTPHost"] = host
    flt[{"exact": "clientRequestPath", "starts with": "clientRequestPath_like",
         "contains": "clientRequestPath_like"}[match]] = {"exact": path, "starts with": path + "%",
                                                          "contains": "%" + path + "%"}[match]
    limit = num(b.get("top"), 1, 500, 50, "slowest requests")
    secs = to_epoch(until) - to_epoch(since)
    dim, bucket = (("datetimeMinute", "1 minute") if secs <= 10800 else ("datetimeFiveMinutes", "5 minutes")
                   if secs <= 86400 else ("datetimeHour", "1 hour") if secs <= 604800 else ("date", "1 day (UTC dates)"))
    audit(sess, "Cloudflare URL timing %s%s (%s)" % (host, path, match))
    G, lit = "httpRequestsAdaptiveGroups", cf_lit(flt)

    def metrics(f):
        q = " ".join(x for x in (CF_Q_EDGE, CF_Q_ORIGIN) if x in f)
        a = " ".join(x for x in ("edgeTimeToFirstByteMs", "originResponseDurationMs") if x in f)
        return "count%s%s" % (" quantiles{%s}" % q if q else "", " avg{%s}" % a if a else "")

    def sel(f):
        m = metrics(f)
        parts = ["tot:%s(filter:%s,limit:1){%s}" % (G, lit, m),
                 "ts:%s(filter:%s,limit:5000,orderBy:[%s_ASC]){%s dimensions{%s}}" % (G, lit, dim, m, dim)]
        for alias, dims, n in (("bs", "edgeResponseStatus originResponseStatus", 30), ("bc", "cacheStatus", 20),
                               ("bl", "coloCode", 15), ("bm", "clientRequestHTTPMethodName", 10),
                               ("bp", "clientRequestPath", 25)):
            if alias != "bp" or match != "exact":
                parts.append("%s:%s(filter:%s,limit:%d,orderBy:[count_DESC]){%s dimensions{%s}}" % (alias, G, lit, n, m, dims))
        return " ".join(parts)
    res, dropped = cf_gql_zones(sess, [zone], sel, (CF_Q_EDGE, CF_Q_ORIGIN, "edgeTimeToFirstByteMs", "originResponseDurationMs"))
    zd = res.get(zone["id"], (None, []))[0] or {}
    tot = (zd.get("tot") or [{}])[0]
    total = int(tot.get("count") or 0)

    def ms(v):
        return int(round(float(v))) if v not in (None, "") else ""

    def stats(g):
        q, a = g.get("quantiles") or {}, g.get("avg") or {}
        return [("edge_p50_ms", ms(q.get("edgeTimeToFirstByteMsP50"))), ("edge_p95_ms", ms(q.get("edgeTimeToFirstByteMsP95"))),
                ("edge_p99_ms", ms(q.get("edgeTimeToFirstByteMsP99"))), ("origin_p50_ms", ms(q.get("originResponseDurationMsP50"))),
                ("origin_p95_ms", ms(q.get("originResponseDurationMsP95"))),
                ("origin_p99_ms", ms(q.get("originResponseDurationMsP99"))),
                ("edge_avg_ms", ms(a.get("edgeTimeToFirstByteMs"))), ("origin_avg_ms", ms(a.get("originResponseDurationMs")))]

    def breakdown(alias, cols):
        rows = []
        for g in zd.get(alias) or []:
            d, n = g.get("dimensions") or {}, int(g.get("count") or 0)
            st = dict(stats(g))
            rows.append(dict([(c, d.get(k) if d.get(k) not in (None, "") else "-") for k, c in cols] +
                             [("requests", n), ("share", "%.1f%%" % (100.0 * n / total) if total else "")] +
                             [(k, st[k]) for k in ("edge_avg_ms", "edge_p95_ms", "origin_avg_ms", "origin_p95_ms") if st[k] != ""]))
        return rows
    s = dict(stats(tot))
    data = {"url_timing": dict([("url", "%s%s%s" % (host, path, " (%s)" % match if match != "exact" else "")),
                                ("requests", total)] +
                               [(k.replace("edge_", "edge_TTFB_")[:-3], "%s ms" % v) for k, v in stats(tot) if v != ""])}
    if s["edge_p50_ms"] != "" and s["origin_p50_ms"] != "":
        data["url_timing"]["not_origin_time_p50"] = "%d ms of the edge TTFB is spent outside the origin" % max(
            0, s["edge_p50_ms"] - s["origin_p50_ms"])
    keys = [str((g.get("dimensions") or {}).get(dim)) for g in zd.get("ts") or []]
    tsd = [dict(stats(g), requests=int(g.get("count") or 0)) for g in zd.get("ts") or []]
    labels = [k if dim == "date" else utc3(k) for k in keys]
    charts = []
    series = [[lbl, [r[k] or 0 for r in tsd]] for lbl, k in (("Edge TTFB p50", "edge_p50_ms"), ("Edge TTFB p95", "edge_p95_ms"),
                                                              ("Origin p50", "origin_p50_ms"), ("Origin p95", "origin_p95_ms"))
              if any(r[k] != "" for r in tsd)]
    if series:
        charts.append({"title": "Edge TTFB vs origin response time", "t": labels, "fmt": "ms", "series": series})
    charts.append({"title": "Requests", "t": labels, "fmt": "num", "series": [["Requests", [r["requests"] for r in tsd]]]})
    data["timeline"] = [dict([("time", lbl), ("requests", r["requests"])] + [(k, r[k]) for k in
                             ("edge_p50_ms", "edge_p95_ms", "origin_p50_ms", "origin_p95_ms", "edge_avg_ms", "origin_avg_ms") if r[k] != ""])
                        for lbl, r in zip(labels, tsd)]
    data["by_status"] = breakdown("bs", (("edgeResponseStatus", "edge_status"), ("originResponseStatus", "origin_status")))
    data["by_cache_status"] = breakdown("bc", (("cacheStatus", "cache"),))
    data["by_colo"] = breakdown("bl", (("coloCode", "colo"),))
    data["by_method"] = breakdown("bm", (("clientRequestHTTPMethodName", "method"),))
    if match != "exact":
        data["by_path"] = breakdown("bp", (("clientRequestPath", "path"),))
    # Slowest individual (sampled) requests, with the origin time split into DNS / TCP / TLS / response headers.
    rq_opt = ("rayName", "clientIP", "clientCountryName", "clientRequestHTTPMethodName", "clientRequestPath",
              "clientRequestQuery", "edgeResponseStatus", "originResponseStatus", "cacheStatus", "edgeTimeToFirstByteMs",
              "originResponseDurationMs") + tuple(k for k, _ in CF_ORIGIN_PHASES) + ("coloCode", "upperTierColoName", "originIP")
    sorted_by = "origin response time"
    r2, d2 = cf_gql_zones(sess, [zone], lambda f: "httpRequestsAdaptive(filter:%s,limit:%d,orderBy:[originResponseDurationMs_DESC]){datetime %s}"
                          % (lit, limit, " ".join(f)), rq_opt)
    if not (r2.get(zone["id"], (None, []))[0] or {}).get("httpRequestsAdaptive") and r2.get(zone["id"], (None, []))[1]:
        sorted_by = "origin response time, among the newest 500 sampled requests (the API could not sort by it)"
        r2, d2 = cf_gql_zones(sess, [zone], lambda f: "httpRequestsAdaptive(filter:%s,limit:500,orderBy:[datetime_DESC]){datetime %s}"
                              % (lit, " ".join(f)), rq_opt)
    slow = []
    for e in (r2.get(zone["id"], (None, []))[0] or {}).get("httpRequestsAdaptive") or []:
        slow.append(dict([("time", utc3(e.get("datetime"))), ("cf_zone", zone["name"]), ("client_ip", e.get("clientIP", "")),
                          ("country", e.get("clientCountryName", "")), ("method", e.get("clientRequestHTTPMethodName", "")),
                          ("url", cf_url(e)), ("edge_status", e.get("edgeResponseStatus", "")),
                          ("origin_status", e.get("originResponseStatus") or ""), ("cache", e.get("cacheStatus", "")),
                          ("edge_ttfb_ms", e.get("edgeTimeToFirstByteMs", "")), ("origin_ms", e.get("originResponseDurationMs", ""))] +
                         [(c, e.get(k, "")) for k, c in CF_ORIGIN_PHASES] +
                         [("colo", e.get("coloCode", "")), ("upper_tier", e.get("upperTierColoName") or ""),
                          ("origin_ip", e.get("originIP", "")), ("ray_id", e.get("rayName", ""))]))
    slow.sort(key=lambda r: -(float(r["origin_ms"] or 0)))
    data["slowest_requests"] = slow[:limit]
    notes = ["Zone: %s. Time range: %s; buckets of %s." % (zone["name"], span, bucket),
             "Edge TTFB = from Cloudflare receiving the request to sending the first byte to the client (includes the wait "
             "for the origin). Origin response time = how long Cloudflare waited for the origin (e.g. the F5) to answer; it "
             "is 0 for cache hits, so see 'by cache status' for misses and dynamic requests on their own.",
             "Slowest requests: sampled requests sorted by %s." % sorted_by]
    if query:
        notes.append("The query string (?%s) is not used to filter; all queries of this path are included." % query[:80])
    for k, c in CF_ORIGIN_PHASES:
        if k in d2:
            notes.append("The origin DNS / TCP / TLS / header timings are not offered for this zone or plan.")
            break
    notes += cf_gql_notes([zone], res, [x for x in dropped]) + cf_gql_notes([zone], r2, [x for x in d2 if x not in dict(CF_ORIGIN_PHASES)])
    e95, o95 = s["edge_p95_ms"], s["origin_p95_ms"]
    e5 = sum(r["requests"] for r in data["by_status"] if str(r.get("edge_status", "")).startswith("5"))
    if not total:
        label, kind = "NO REQUESTS FOR %s%s IN THIS RANGE" % (host, path), "info"
    else:
        label = "%s%s · %s REQUESTS · EDGE TTFB p95 %s · ORIGIN p95 %s" % (
            host, path, "{:,}".format(total), "%s ms" % e95 if e95 != "" else "n/a", "%s ms" % o95 if o95 != "" else "n/a")
        kind = ("bad" if (o95 != "" and o95 >= 5000) or e5 * 20 >= total else
                "warn" if (o95 != "" and o95 >= 1000) or (e95 != "" and e95 >= 1500) else "ok")
        if e5:
            notes.insert(0, "%d request(s) (%.1f%%) ended in a 5xx error." % (e5, 100.0 * e5 / total))
    order = ("url_timing", "slowest_requests", "by_status", "by_cache_status", "by_path", "by_colo", "by_method", "timeline")
    data = {k: data[k] for k in order if k in data}
    r = cf_result(t0, "GraphQL httpRequestsAdaptiveGroups + httpRequestsAdaptive (%s%s)" % (host, path), label, kind, notes, data)
    r["charts"] = charts
    return r


def cf_epoch3(s):
    """'YYYY-MM-DD HH:MM:SS' shown in UTC+3 -> epoch; None if it does not parse."""
    try:
        return datetime.datetime.strptime(str(s)[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=CF_TZ).timestamp()
    except ValueError:
        return None


def cf_lookback_for(t):
    """The narrowest F5 time range that still reaches back to epoch t (plus 5 minutes)."""
    age = time.time() - t + 300
    fits = [(s, k) for k, s in LOOKBACK.items() if s and s >= age]
    return min(fits)[1] if fits else "any time"


def fg_trace_logs(fg, src, vdom, dst, srcip, t_center, window, max_pages=5):
    """FortiGate forward-traffic sessions to dst (optionally from srcip) within +-window s of t_center, paging back
    from the newest entries. -> (entries, notes, oldest epoch read) or (None, [error], None)."""
    conds = [("dstip", dst)] + ([("srcip", srcip)] if srcip else [])
    rows, notes, oldest, prev = [], [], None, None
    for page in range(max_pages):
        q = [("start", str(page * 1000)), ("rows", "1000")] + [("filter", "%s==%s" % c) for c in conds]
        if vdom:
            q.append(("vdom", vdom))
        st, ok, data = rest_get(fg, "/api/v2/log/%s/traffic/forward?%s" % (src, urllib.parse.urlencode(q)))
        res = data.get("results") if ok and isinstance(data, dict) else None
        if res is None:
            return None, ["FortiGate log query failed (HTTP %s). Check that logging to '%s' is enabled, the token has "
                          "Log & Report read access and the VDOM is right." % (st, src)], None
        res = [e for e in as_list(res) if isinstance(e, dict)]
        fid = json.dumps(res[0], sort_keys=True) if res else None
        if page and fid == prev:
            notes.append("The FortiGate ignored paging, so only its newest 1000 matching entries were read.")
            break
        prev = fid
        eps = [fg_event_epoch(e) for e in res]
        for e, ep in zip(res, eps):
            if ep is not None and abs(ep - t_center) <= window and all(ip_matches(e.get(f), v) for f, v in conds):
                rows.append((ep, e))
        known = [x for x in eps if x]
        if known:
            oldest = min(known + ([oldest] if oldest else []))
        if len(res) < 1000 or (known and min(known) < t_center - window):
            break
    return rows, notes, oldest


def cf_m_trace(sess, b, t0, ray=None, f5_hint=None, ident=""):
    """Follow one request through Cloudflare -> FortiGate -> F5 ASM and say where it stopped. By Ray ID, or from
    cf_trace_pivot / cf_m_trace_client with the Ray ID found another way ('' if none) and the F5 entry known."""
    if ray is None:
        m = CF_RAY_RE.match(str(b.get("ray") or "").strip())
        if not m:
            raise ValueError("Ray ID must be 16 hex characters, optionally with the -ABC colo suffix")
        ray = m.group(1).lower()
    ident = ident or "Ray ID %s" % ray
    window = num(b.get("window"), 10, 900, 120, "time window (seconds)")
    fg_id, f5_id = b.get("fg"), b.get("f5")
    fg = SESSIONS.get(fg_id) if fg_id else None
    f5 = SESSIONS.get(f5_id) if f5_id else None
    if fg_id and (not fg or fg["vendor"] != "fortigate"):
        raise ValueError("the FortiGate chosen for the trace is no longer connected")
    if f5_id and (not f5 or f5["vendor"] != "f5"):
        raise ValueError("the F5 chosen for the trace is no longer connected")
    fg_src = b.get("fg_source") or "disk"
    if fg_src not in FG_LOG_SOURCES:
        raise ValueError("invalid FortiGate log source")
    fg_vdom = pstr(b.get("fg_vdom"), "VDOM")
    origin_override = str(parse_ip(b.get("origin_ip"), "origin IP")) if str(b.get("origin_ip") or "").strip() else ""
    audit(sess, "trace " + ident)
    notes, data, hops = [], {}, []
    # 1. Cloudflare
    cf = cf_m_ray(sess, dict(b, ray=ray, f5=""), t0) if ray else {
        "summary": ["No Ray ID for this request (no CF-Ray header in the F5 log, nothing matching in Cloudflare's "
                    "sampled data), so the Cloudflare hop is unknown."]}
    cfd = cf.get("data") or {}
    events, reqs = cfd.get("security_events") or [], cfd.get("request") or []
    req = reqs[0] if reqs else {}
    notes += [s for s in cf.get("summary") or [] if not s.startswith("Tip:")]
    t_req = cf_epoch3(req.get("time") or (events[-1]["time"] if events else "") or (f5_hint or {}).get("time", ""))
    host = req.get("host") or (events[0]["host"] if events else "")
    cf_block = next((e for e in events if e["action"] in CF_BLOCK), None)
    cf_chal = next((e for e in events if "challenge" in e["action"] and "solved" not in e["action"]), None)
    # A security event that only logged / skipped the request still proves Cloudflare saw it (and let it through),
    # even when the sampled request record is missing; it carries the client, URL and statuses too.
    ev = events[0] if events else {}
    seen = req or ev
    ev_status = str(ev.get("edge_origin_status") or "").split("/")
    edge = str(req.get("edge_status") or (ev_status[0] if ev else ""))
    origin_st = str(req.get("origin_status") or (ev_status[1] if len(ev_status) > 1 else ""))
    rule_txt = lambda e: "%s by %s rule %s%s" % (e["action"], e["source"], e["rule_id"],
                                                 " (%s)" % e["description"] if e["description"] else "")
    if cf_block or cf_chal:
        cf_res = rule_txt(cf_block or cf_chal)
    elif req and edge.startswith("52") and len(edge) == 3:
        cf_res = "edge HTTP %s · Cloudflare got no valid answer from the origin (after %s ms)" % (edge, req.get("ttfb_ms", "?"))
    elif req:
        cf_res = "passed · edge HTTP %s, origin HTTP %s, edge TTFB %s ms, origin %s ms" % (
            req.get("edge_status"), req.get("origin_status") or "-", req.get("ttfb_ms", "?"), req.get("origin_ms", "?"))
    elif ev:
        cf_res = "passed (not blocked) · %s%s" % (rule_txt(ev), "; edge HTTP %s" % edge if edge else "")
    else:
        cf_res = "not found in Cloudflare data (sampled; widen the time range)"
    hops.append({"hop": "1 · Cloudflare", "seen_at": seen.get("time", ""),
                 "result": cf_res, "details": " ".join(x for x in (
                     "client %s" % seen.get("client_ip") if seen.get("client_ip") else "",
                     "%s %s%s" % (seen.get("method", ""), host, seen.get("url", "")) if seen else "",
                     "colo %s" % seen["colo"] if seen.get("colo") else "") if x)})
    # 2. F5 ASM (via the CF-Ray header, or the entry already found), before the FortiGate so its client IP can pin
    # the exact FortiGate session.
    f5_rows, f5_ip, f5_blocked, viol = [], "", False, []
    if f5:
        within = cf_lookback_for(t_req) if t_req else cf_f5_within(b)
        if f5_hint:
            r5 = {"ok": True, "data": {"requests": [{k: v for k, v in f5_hint.items() if k != "violations"}]}}
            viol = f5_hint.get("violations") or []
        elif not ray:
            r5 = {"ok": True, "data": {}}
        else:
            try:
                r5 = f5_asm_by_header(f5, {"header_name": "CF-Ray", "header_value": ray, "within": within, "top": 5,
                                           "scan": 3000}, time.time())
            except (ValueError, urllib.error.URLError, OSError) as e:
                r5 = {"ok": False, "error": str(getattr(e, "reason", e))}
        if r5.get("ok"):
            f5_rows = (r5.get("data") or {}).get("requests") or []
            notes += ["F5: " + s for s in (r5.get("summary") or [])[:2]]
        else:
            notes.append("F5 %s lookup failed: %s" % (f5["name"], r5.get("error")))
        if f5_rows:
            x = f5_rows[0]
            f5_ip, f5_blocked = str(x.get("ip") or ""), "block" in str(x.get("status", "")).lower()
            if x.get("support_id") and f5_blocked and not viol:
                try:
                    d5 = do_f5_asm({"id": f5_id, "mode": "supportid", "support_id": x["support_id"], "within": "any time"})
                    viol = (d5.get("data") or {}).get("violations") or [] if d5.get("ok") else []
                except (ValueError, urllib.error.URLError, OSError):
                    viol = []
            hops.append({"hop": "3 · F5 ASM (%s)" % f5["name"], "seen_at": x.get("time", ""),
                         "result": "%s · support ID %s" % (str(x.get("status") or "?"), x.get("support_id") or "-"),
                         "details": "from %s (True-Client-IP %s) %s %s%s%s" % (
                             f5_ip or "?", x.get("true_client_id") or "-", x.get("method", ""), x.get("hostname", ""),
                             x.get("url", ""), "; " + "; ".join(v.get("violation", "") for v in viol[:3]) if viol else "")})
        else:
            hops.append({"hop": "3 · F5 ASM (%s)" % f5["name"], "seen_at": "", "result": "not found",
                         "details": "no ASM log entry with CF-Ray %s (%s)" % (ray, within)})
    else:
        hops.append({"hop": "3 · F5 ASM", "seen_at": "", "result": "not checked",
                     "details": "choose an F5 under 'Cross-check on F5'"})
    if f5_rows:   # Cloudflare's sampled data may lack the request; the F5 log has its time and host
        t_req = t_req or cf_epoch3(f5_rows[0].get("time"))
        host = host or str(f5_rows[0].get("hostname") or "")
        if ray and not seen:   # the request certainly passed Cloudflare, so a wider time range would not help
            hops[0]["result"] = ("Ray ID %s passed Cloudflare (it reached the F5) but is not in Cloudflare's data: no "
                                 "security rule acted on or logged it, and it was not in the sampled requests" % ray)
            notes = [s for s in notes if not s.startswith("Security events exist only")]
    # Origin IP Cloudflare connected to: from the request, an override, or the hostname's DNS record.
    origin = origin_override or str(req.get("origin_ip") or "")
    if fg and not origin and host:   # only the FortiGate lookup needs it
        z = cf_zone_of_host(sess, host)
        if z:
            recs, _, _ = cf_list(sess, "/zones/%s/dns_records?name=%s" % (z["id"], urllib.parse.quote(host)), per_page=20, max_pages=1)
            origin = next((str(r.get("content")) for r in recs if r.get("type") in ("A", "AAAA")), "")
            if origin:
                notes.append("Origin IP %s taken from the DNS record of %s." % (origin, host))
    # 3. FortiGate sessions from Cloudflare to the origin IP around the request time.
    fg_hits, fg_how = [], ""
    if fg and origin and t_req:
        dst = ipaddress.ip_address(origin)
        src_ip = ipaddress.ip_address(f5_ip) if f5_ip and re.match(r"^[0-9a-fA-F:.]+$", f5_ip) else None
        try:
            got, fn, oldest = fg_trace_logs(fg, fg_src, fg_vdom, dst, src_ip, t_req, window)
        except (urllib.error.URLError, OSError) as e:
            got, fn, oldest = None, ["FortiGate request failed: %s" % getattr(e, "reason", e)], None
        notes += fn
        if got is not None:
            nets = cf_edge_nets(sess)
            if src_ip:
                fg_how = "exact: the Cloudflare edge IP the F5 logged (%s) + time" % src_ip
            else:
                got = [(ep, e) for ep, e in got if any(ip_matches(e.get("srcip"), n_) for n_ in nets)]
                fg_how = "approximate: any Cloudflare edge IP to %s within ±%ds" % (dst, window)
            fg_hits = sorted(got, key=lambda x: abs(x[0] - t_req))
            if oldest and oldest > t_req - window and not fg_hits:
                notes.append("FortiGate: its log entries read only reach back to %s, after the request; older sessions "
                             "were not covered." % utc3(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(oldest))))
    fg_rows = [{"time": utc3(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ep))), "offset_s": int(round(ep - t_req)),
                "source": "%s:%s" % (e.get("srcip", ""), e.get("srcport", "")),
                "destination": "%s:%s" % (e.get("dstip", ""), e.get("dstport", "")),
                "dnat": "%s:%s" % (e.get("tranip"), e.get("tranport")) if e.get("tranip") not in (None, "", "0.0.0.0") else "",
                "action": e.get("action", ""), "policy": " / ".join(str(x) for x in (e.get("policyid"), e.get("policyname")) if x),
                "duration_s": e.get("duration", ""), "sent_bytes": e.get("sentbyte", ""), "received_bytes": e.get("rcvdbyte", "")}
               for ep, e in fg_hits[:50]]
    fg_deny = [r for r in fg_rows if r["action"].lower() in ("deny", "blocked")]
    fg_bad = [r for r in fg_rows if r["action"].lower() in ("timeout", "server-rst", "client-rst", "ip-conn")]
    if not fg:
        hop2 = None   # no FortiGate chosen: the trace is Cloudflare -> F5 -> origin
    elif not origin:
        hop2 = ("not checked", "origin IP unknown (not in the sampled request, no A record); enter it as Origin IP")
    elif not t_req:
        hop2 = ("not checked", "request time unknown (Ray ID not found at Cloudflare)")
    elif not fg_rows:
        hop2 = ("no matching session", "no forward-traffic log to %s within ±%ds (is 'log all sessions' on for that policy?)"
                % (origin, window))
    else:
        acts = collections.Counter(r["action"] for r in fg_rows)
        hop2 = ("%d session(s): %s" % (len(fg_rows), ", ".join("%s %d" % kv for kv in acts.most_common())),
                "%s; closest %+ds, policy %s" % (fg_how, fg_rows[0]["offset_s"], fg_rows[0]["policy"] or "?"))
    if hop2:
        hops.insert(1, {"hop": "2 · FortiGate (%s)" % fg["name"], "seen_at": fg_rows[0]["time"] if fg_rows else "",
                        "result": hop2[0], "details": hop2[1]})
    # 4. Origin / application, as seen by Cloudflare.
    if not (cf_block or cf_chal) and (fg_deny or f5_blocked):
        # Cloudflare's "origin" is the F5 virtual server, so its status is the F5 blocking page, not the app.
        hops.append({"hop": "4 · Origin / app", "seen_at": "", "result": "not reached",
                     "details": "denied at the FortiGate" if fg_deny else "blocked by F5 ASM" + (
                         "; the HTTP %s Cloudflare saw is the F5 blocking page" % (origin_st or edge) if origin_st or edge
                         else "")})
    elif seen and not (cf_block or cf_chal):
        hops.append({"hop": "4 · Origin / app", "seen_at": "", "result": "origin HTTP %s" % (origin_st or "none"),
                     "details": ("origin response %s ms" % req.get("origin_ms", "?") if req else "from the Cloudflare security event")
                     + (" (Cloudflare got no valid answer)" if edge.startswith("52") else "")})
    # Verdict: where did the request stop?
    e52 = edge.startswith("52") and len(edge) == 3
    if cf_block:
        label, kind = "STOPPED AT CLOUDFLARE · %s" % cf_res, "bad"
    elif cf_chal:
        label, kind = "CHALLENGED AT CLOUDFLARE · %s" % cf_res, "warn"
    elif fg_deny:
        label, kind = "STOPPED AT FORTIGATE · denied by policy %s" % (fg_deny[0]["policy"] or "?"), "bad"
    elif f5_blocked:
        label, kind = "STOPPED AT F5 ASM · support ID %s%s" % (f5_rows[0].get("support_id"), " (%s)" % viol[0].get("violation")
                                                                if viol else ""), "bad"
    elif e52 and fg_bad and not f5_rows:
        label, kind = "CONNECTION FAILED BETWEEN FORTIGATE AND F5 · FortiGate %s (Cloudflare HTTP %s)" % (fg_bad[0]["action"], edge), "bad"
    elif e52 and f5_rows:
        label, kind = "REACHED F5, ORIGIN DID NOT ANSWER IN TIME · Cloudflare HTTP %s" % edge, "bad"
    elif e52:
        label, kind = "CLOUDFLARE COULD NOT REACH THE ORIGIN · HTTP %s%s" % (
            edge, ""), "bad"
    elif seen and edge.startswith("5"):
        label, kind = "ORIGIN / APP ERROR · origin HTTP %s" % (origin_st or edge), "bad"
    elif seen and edge.startswith("4"):
        label, kind = "APP ANSWERED %s · nothing blocked on the way" % edge, "warn"
    elif req:
        label, kind = "SUCCEEDED END TO END · edge HTTP %s in %s ms" % (edge, req.get("ttfb_ms", "?")), "ok"
    elif ev:
        label = "PASSED CLOUDFLARE (%s only, not blocked)%s%s" % (
            ev["action"], " · F5 ASM %s (support ID %s)" % (f5_rows[0].get("status", ""), f5_rows[0].get("support_id"))
            if f5_rows else "", " · edge HTTP %s" % edge if edge else "")
        kind = "ok" if edge[:1] in ("2", "3") else "info"
    elif f5_rows:
        label, kind = "NOT IN CLOUDFLARE DATA, FOUND ON F5 · %s" % f5_rows[0].get("status", ""), "warn"
    else:
        label, kind = "%s NOT FOUND" % ident.upper(), "info"
    hops.sort(key=lambda h: h["hop"])
    for i, h in enumerate(hops):   # number the hops actually shown
        h["hop"] = "%d · %s" % (i + 1, h["hop"].split(" · ", 1)[1])
    data["trace"] = hops
    if events:
        data["cloudflare_security_events"] = events
    if reqs:
        data["cloudflare_request"] = reqs
    if fg_rows:
        data["fortigate_sessions"] = fg_rows
    if f5_rows:
        data["f5_asm_request"] = f5_rows
    if viol:
        data["f5_violations"] = viol
    notes.insert(0, "Matching: Cloudflare ↔ F5 %s%s." % (
        "via the F5 entry found first" if f5_hint else "by the CF-Ray header (exact)",
        "; FortiGate by " + (fg_how or "Cloudflare edge IP + origin IP + time") if fg else ""))
    return cf_result(t0, "Trace %s: Cloudflare → %sF5" % (ident, "FortiGate → " if fg else ""), label, kind, notes, data)


def cf_iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cf_trace_window(t, pad=600):
    """Custom From / To (UTC+3 form values) pad seconds around epoch t, to pin lookups to one request."""
    f = lambda x: datetime.datetime.fromtimestamp(x, CF_TZ).strftime("%Y-%m-%d %H:%M")
    return {"since": f(t - pad), "until": f(min(t + pad, time.time() + 60))}


def cf_closest(rows, t):
    """The row whose time is nearest epoch t; the first (newest) when t is None."""
    if not rows:
        return None
    return rows[0] if t is None else min(rows, key=lambda r: abs((cf_epoch3(r.get("time")) or 0) - t))


def cf_client_find(sess, zones, ip, host, path, since, until, like):
    """Cloudflare's records of one client (optionally host and path, exact or contains), newest first
    -> (security events, sampled requests, {zone id: (None, errors)}, dropped fields)."""
    lit = cf_lit({"datetime_geq": since, "datetime_leq": until, "clientIP": ip, "clientRequestHTTPHost": host,
                  ("clientRequestPath_like" if like else "clientRequestPath"): ("%" + path + "%" if like else path)
                  if path else ""})
    res, d1 = cf_gql_zones(sess, zones, cf_q_events(lit, 50), CF_EV_FIELDS)
    res2, d2 = cf_gql_zones(sess, zones, cf_q_requests(lit, 50), CF_RQ_FIELDS)
    errs = {zid: v for r in (res, res2) for zid, v in r.items() if v[1]}
    return (cf_rows(zones, res, "firewallEventsAdaptive", cf_ev_row, 50),
            cf_rows(zones, res2, "httpRequestsAdaptive", cf_rq_row, 50), errs, sorted(set(d1) | set(d2)))


def f5_trace_hint(f5_id, sid):
    """F5 ASM entry of a support ID as a trace row (with its violations) -> (row or None, lookup result)."""
    d5 = do_f5_asm({"id": f5_id, "mode": "supportid", "support_id": sid, "within": "any time"})
    d = d5.get("data") or {}
    if not d5.get("ok") or not d.get("support_id"):
        return None, d5
    return {"time": d.get("time", ""), "status": d.get("status", ""), "support_id": sid, "ip": d.get("source_ip", ""),
            "true_client_id": d.get("true_client_id", ""), "method": d.get("method", ""),
            "hostname": d.get("hostname", ""), "url": d.get("uri", ""), "cf_ray": d.get("cf_ray", ""),
            "violations": d.get("violations") or []}, d5


def cf_pin_zone(sess, b, host, notes):
    """With no zone chosen, search only the zone of the request's hostname: 'all zones' is capped and may skip it."""
    z = cf_zone_of_host(sess, str(host or "")) if host and not str(b.get("zone") or "").strip() else None
    if not z:
        return b
    notes.append("Cloudflare searched in zone %s (the zone of %s)." % (z["name"], host))
    return dict(b, zone=z["name"])


def cf_trace_pivot(sess, b, t0, hint, ident, notes):
    """Trace from a known F5 entry: its CF-Ray header gives the Ray ID; without one, Cloudflare's data is searched
    for the same client, host and path nearest the F5 time."""
    window = num(b.get("window"), 10, 900, 120, "time window (seconds)")
    b = cf_pin_zone(sess, b, hint.get("hostname"), notes)
    t = cf_epoch3(hint["time"])
    m = CF_RAY_RE.match(str(hint.get("cf_ray") or "").strip())
    ray = m.group(1).lower() if m else ""
    try:
        tci = str(ipaddress.ip_address(str(hint.get("true_client_id") or "").strip()))
    except ValueError:
        tci = ""
    if ray:
        notes.append("Ray ID %s taken from the CF-Ray header in the F5 log (exact)." % ray)
    elif t and tci:
        zones = cf_zones(sess, b.get("zone"))
        path = str(hint.get("url") or "").split("?")[0]
        ev, rq, errs, dropped = cf_client_find(sess, zones, tci, str(hint.get("hostname") or "").lower(), path,
                                               cf_iso(t - window), cf_iso(t + window), False)
        cands = [r for r in rq + ev if r.get("ray_id")]
        best = cf_closest(cands, t)
        if best:
            ray = best["ray_id"].lower()
            notes.append("No CF-Ray header in the F5 log; Ray ID %s is Cloudflare's request from %s to %s%s nearest "
                         "the F5 time (%+ds, %d candidate(s) within ±%ds). Approximate: check the time and URL."
                         % (ray, tci, best.get("host", ""), best.get("url", ""),
                            int((cf_epoch3(best["time"]) or t) - t), len({r["ray_id"] for r in cands}), window))
        else:
            notes.append("No CF-Ray header in the F5 log, and Cloudflare's sampled data has no request from %s to "
                         "%s%s within ±%ds of the F5 time." % (tci, hint.get("hostname", ""), path, window))
        notes += cf_gql_notes(zones, errs, dropped)
    else:
        notes.append("No CF-Ray header in the F5 log and no True-Client-IP to search Cloudflare by. Make the logging "
                     "profile store request headers to get the exact Ray ID.")
    r = cf_m_trace(sess, dict(b, **cf_trace_window(t)) if t else b, t0, ray=ray, f5_hint=hint, ident=ident)
    r["summary"] = notes + r.get("summary", [])
    return r


def cf_m_trace_sid(sess, b, t0):
    """Trace a request from the F5 support ID on its block page: the F5 entry (kept in full, not sampled) gives the
    time, Cloudflare edge IP, True-Client-IP and CF-Ray header that pin the other hops."""
    sid = str(b.get("support_id") or "").strip()
    if not SUPPORT_ID_RE.match(sid):
        raise ValueError("support ID must be 5-25 digits")
    f5 = SESSIONS.get(b.get("f5") or "")
    if not f5 or f5["vendor"] != "f5":
        raise ValueError("choose the F5 device under 'Cross-check on F5' to trace by support ID")
    hint, d5 = f5_trace_hint(b["f5"], sid)
    if not d5.get("ok"):
        return d5
    if not hint:
        return cf_result(t0, "F5 ASM support ID %s" % sid, (d5.get("verdict") or {}).get("label", ""), "info",
                         d5.get("summary") or [], {})
    return cf_trace_pivot(sess, b, t0, hint, "support ID %s" % sid, ["Started from F5 support ID %s." % sid])


def cf_m_trace_client(sess, b, t0):
    """Trace a request that has no ID: by client IP (plus host / path) around a time, in Cloudflare's sampled data,
    else in the F5 log by True-Client-IP. Traces the candidate nearest the time and lists the others."""
    ip = str(parse_ip(b.get("ip"), "client IP"))
    host = str(b.get("host") or "").strip().lower()
    if host and ("*" in host or not CF_HOSTNAME_RE.match(host)):
        raise ValueError("enter an exact hostname (letters, digits, . - _ only)")
    path = cf_text(b.get("path"), "path")
    window = num(b.get("window"), 10, 900, 120, "time window (seconds)")
    at, t = str(b.get("at") or "").strip(), None
    if at:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
            try:
                t = datetime.datetime.strptime(at, fmt).replace(tzinfo=CF_TZ).timestamp()
                break
            except ValueError:
                pass
        if t is None:
            raise ValueError("request time must look like 2026-11-02 08:48 (UTC+3)")
        since, until, span = cf_iso(t - window), cf_iso(t + 60 + window), "±%ds around %s (UTC+3)" % (window, at)
    else:
        since, until, span = cf_window(b)
        if to_epoch(until) - to_epoch(since) > CF_RAW_SLICE:
            since = cf_iso(to_epoch(until) - CF_RAW_SLICE)
            span = "the last 24 hours of the scope range (enter a request time to search another moment)"
    what = "%s%s%s" % (ip, " → " + host if host else "", " path contains " + path if path else "")
    audit(sess, "trace by client " + what)
    notes = ["Started from client %s, %s." % (what, span)]
    b = cf_pin_zone(sess, b, host, notes)
    zones = cf_zones(sess, b.get("zone"))
    ev, rq, errs, dropped = cf_client_find(sess, zones, ip, host, path, since, until, True)
    notes += cf_gql_notes(zones, errs, dropped)
    cands = {}
    for r in rq + ev:
        if r.get("ray_id") and r["ray_id"] not in cands:
            cands[r["ray_id"]] = {"time": r["time"], "ray_id": r["ray_id"], "method": r.get("method", ""),
                                  "host": r.get("host", ""), "url": r.get("url", ""),
                                  "cloudflare": r.get("action") or "edge %s / origin %s" % (
                                      r.get("edge_status", ""), r.get("origin_status") or "-")}
    cands = sorted(cands.values(), key=lambda r: r["time"], reverse=True)
    best, f5_cands = cf_closest(cands, t), []
    if best:
        notes.append("%d Cloudflare request(s) matched; traced Ray ID %s, the %s. Trace another one by its Ray ID."
                     % (len(cands), best["ray_id"], "nearest the time given" if t else "newest"))
        r = cf_m_trace(sess, dict(b, **cf_trace_window(cf_epoch3(best["time"]) or time.time())), t0,
                       ray=best["ray_id"].lower(), ident="client %s (Ray ID %s)" % (ip, best["ray_id"]))
    elif b.get("f5"):
        notes.append("Nothing in Cloudflare's sampled data; searched the F5 log by True-Client-IP %s instead." % ip)
        try:
            r5 = do_f5_asm({"id": b["f5"], "mode": "search", "header_ip": ip, "url": path, "hostname": host, "top": 50,
                            "within": cf_lookback_for(t) if t else cf_f5_within(b)})
        except (ValueError, urllib.error.URLError, OSError) as e:
            r5 = {"ok": False, "error": str(getattr(e, "reason", e))}
        f5_cands = [x for x in (r5.get("data") or {}).get("requests") or [] if x.get("support_id") and (
            t is None or abs((cf_epoch3(x.get("time")) or 0) - t) <= window + 60)]
        b5 = cf_closest(f5_cands, t)
        hint = f5_trace_hint(b["f5"], b5["support_id"])[0] if b5 else None
        if hint:
            notes.append("%d F5 request(s) matched; traced support ID %s, the %s." % (
                len(f5_cands), b5["support_id"], "nearest the time given" if t else "newest"))
            r = cf_trace_pivot(sess, b, t0, hint, "client %s (support ID %s)" % (ip, b5["support_id"]), [])
        else:
            notes.append("F5: " + ((r5.get("verdict") or {}).get("label") or r5.get("error") or "no match")
                         + ("" if t is None else " within ±%ds of %s" % (window, at)) + ".")
            r = cf_result(t0, "Trace client %s" % what, "NO REQUEST FROM %s FOUND" % ip, "info", [], {})
    else:
        notes.append("Nothing in Cloudflare's sampled data. Choose an F5 under 'Cross-check on F5' to search its log "
                     "(it keeps every logged request, not a sample).")
        r = cf_result(t0, "Trace client %s" % what, "NO REQUEST FROM %s FOUND" % ip, "info", [], {})
    r["summary"] = notes + r.get("summary", [])
    if cands:
        r["data"]["candidates_cloudflare"] = cands[:50]
    if f5_cands:
        r["data"]["candidates_f5"] = f5_cands[:50]
    return r


CF_MODES = {"events": cf_m_events, "event_top": lambda s, b, t: cf_m_groups(s, b, t, "ev"),
            "traffic": lambda s, b, t: cf_m_groups(s, b, t, "http"), "requests": cf_m_requests, "ray": cf_m_ray,
            "ip": cf_m_ip, "host": cf_m_host, "rules": cf_m_rules, "dns": cf_m_dns, "posture": cf_m_posture,
            "lb": cf_m_lb, "audit": cf_m_audit, "dashboard": cf_m_dashboard, "url": cf_m_url, "trace": cf_m_trace,
            "trace_sid": cf_m_trace_sid, "trace_client": cf_m_trace_client, "whois": cf_m_whois}


def do_cf(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess or sess["vendor"] != "cloudflare":
        return {"ok": False, "error": "connect a Cloudflare account first"}
    fn = CF_MODES.get(b.get("mode"))
    if not fn:
        return {"ok": False, "error": "unknown Cloudflare lookup"}
    try:
        return fn(sess, b, time.time())
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}


class Handler(BaseHTTPRequestHandler):
    server_version = "ITSecOps"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self):
        return self.headers.get("Host", "") in self.server.allowed_hosts

    def _tok_ok(self):
        return tok_ok(self.headers.get("X-Token", ""))

    def _serve_capture(self, name):
        name = urllib.parse.unquote(name)
        path = os.path.join(CAPTURE_DIR, name)
        dl = bool(DL_RE.fullmatch(name))
        if not (FILE_RE.fullmatch(name) or dl) or not os.path.isfile(path):
            return self._send(404, {"error": "not found"})
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream" if dl else "application/vnd.tcpdump.pcap"
                         if name.endswith(".pcap") else "text/plain" if name.endswith((".pms", ".conf"))
                         else "application/octet-stream")
        self.send_header("Content-Disposition", 'attachment; filename="%s"' % (name[len("f5file_"):] if dl else name))
        self.send_header("Content-Length", str(os.path.getsize(path)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        u = urllib.parse.urlparse(self.path)
        if u.path == "/":
            t = urllib.parse.parse_qs(u.query).get("t", [""])[0]
            if not tok_ok(t):
                return self._send(403, "Open the URL printed in the terminal.", "text/plain")
            return self._send(200, PAGE.replace("__TOKEN__", TOKEN), "text/html")
        if u.path.startswith("/api/capture/"):
            t = urllib.parse.parse_qs(u.query).get("t", [""])[0]
            if not tok_ok(t):
                return self._send(403, {"error": "bad token"})
            return self._serve_capture(u.path[len("/api/capture/"):])
        if not self._tok_ok():
            return self._send(403, {"error": "bad token"})
        if u.path == "/api/catalog":
            return self._send(200, CATALOG_PUBLIC)
        if u.path == "/api/profiles":
            try:
                with LOCK:
                    profiles = load_profiles()
                return self._send(200, profiles)
            except (OSError, ValueError, json.JSONDecodeError) as e:
                return self._send(500, {"error": "could not load saved profiles: %s" % e})
        if u.path == "/api/audit":
            with LOCK:
                return self._send(200, list(AUDIT)[-200:])
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok() or not self._tok_ok():
            return self._send(403, {"error": "forbidden"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(max(0, min(n, 1_000_000))) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        if not isinstance(body, dict):
            return self._send(400, {"error": "body must be a JSON object"})
        routes = {"/api/connect": do_connect, "/api/run": do_run,
                  "/api/raw": do_raw, "/api/disconnect": do_disconnect,
                  "/api/ipcheck": do_ipcheck, "/api/f5host": do_f5_host, "/api/f5logs": do_f5_logs,
                  "/api/f5capture": do_f5_capture, "/api/f5file": do_f5_file, "/api/policy": do_policy_search, "/api/profile/save": do_profile_save,
                  "/api/profile/delete": do_profile_delete, "/api/health": do_health,
                  "/api/appsec": do_appsec, "/api/f5asm": do_f5_asm, "/api/panlogs": do_pan_logs,
                  "/api/fglogs": do_fg_logs, "/api/adminaudit": do_admin_audit, "/api/f5sync": do_f5_sync, "/api/pancapture": do_pan_capture,
                  "/api/backup": do_backup, "/api/cf": do_cf}
        fn = routes.get(self.path)
        if not fn:
            return self._send(404, {"error": "not found"})
        try:
            result = fn(body)
        except Exception as e:  # keep the UI responsive on unexpected input/device replies
            result = {"ok": False, "error": "internal error: %s: %s" % (type(e).__name__, e)}
        self._send(200, result)


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ITSec Ops</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 36 36'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%232EE6C5'/%3E%3Cstop offset='.6' stop-color='%237C6CFF'/%3E%3Cstop offset='1' stop-color='%23FF7A59'/%3E%3C/linearGradient%3E%3C/defs%3E%3Cpath d='M18 2.5 31.5 7.5v9.5c0 8-5.6 13.6-13.5 16.5C10.1 30.6 4.5 25 4.5 17V7.5Z' fill='%2314132a' stroke='url(%23g)' stroke-width='2.2' stroke-linejoin='round'/%3E%3Cpath d='m12 13 6 5-6 5' fill='none' stroke='%232EE6C5' stroke-width='2.6' stroke-linecap='round' stroke-linejoin='round'/%3E%3Cpath d='M20.5 24h5' stroke='%23FF7A59' stroke-width='2.6' stroke-linecap='round'/%3E%3C/svg%3E">
<style>
:root{--bg:#0B0A17;--panel:#14132a;--panel2:#1b1a38;--line:#2a2850;--text:#e9e8ff;--dim:#8f8cb8;
--mint:#2EE6C5;--coral:#FF7A59;--violet:#7C6CFF}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#1d1a4a55,transparent),var(--bg);
color:var(--text);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;min-height:100vh}
h1{margin:0;font-size:22px;background:linear-gradient(90deg,var(--mint),var(--violet) 60%,var(--coral));
-webkit-background-clip:text;background-clip:text;color:transparent}
header{padding:14px 24px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px}
header .logo{width:38px;height:38px;flex:none;filter:drop-shadow(0 0 8px #7C6CFF55)}
header small{color:var(--dim)}
.wrap{display:grid;grid-template-columns:320px 1fr;gap:18px;padding:18px 24px}
@media(max-width:900px){.wrap{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:16px}
.card h3{margin:0 0 10px;font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim)}
label{display:block;font-size:12px;color:var(--dim);margin:8px 0 3px}
input,select{width:100%;background:var(--panel2);color:var(--text);border:1px solid var(--line);
border-radius:8px;padding:8px 10px;font:inherit}
input:focus,select:focus{outline:none;border-color:var(--violet);box-shadow:0 0 0 3px #7C6CFF33}
button{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:8px;
padding:7px 12px;font:inherit;cursor:pointer}
button:hover{border-color:var(--mint);box-shadow:0 0 12px #2EE6C533}
button.primary{background:linear-gradient(90deg,#2EE6C5,#7C6CFF);color:#08071a;border:0;font-weight:600}
.row{display:flex;gap:8px}.row>*{flex:1}
.chk{display:flex;gap:8px;align-items:center;margin-top:10px;color:var(--dim)}
.chk input{width:auto}
.dev{display:flex;justify-content:space-between;align-items:center;padding:8px 10px;border-radius:8px;
border:1px solid transparent;cursor:pointer}
.dev:hover{background:var(--panel2)}
.dev.sel{border-color:var(--violet);background:var(--panel2);box-shadow:0 0 14px #7C6CFF33}
.tag{font-size:11px;padding:1px 7px;border-radius:99px;margin-left:6px}
.f5{background:#FF7A5922;color:var(--coral)}.paloalto{background:#2EE6C522;color:var(--mint)}
.fortigate{background:#7C6CFF33;color:#b3a9ff}.cloudflare{background:#F3802022;color:#F38020}
.grp{margin:12px 0 4px;color:var(--mint);font-size:12px;letter-spacing:.1em;text-transform:uppercase}
.chkrow{display:flex;gap:8px;align-items:center;padding:5px 0;border-bottom:1px dashed #2a285088;flex-wrap:wrap}
.chkrow .lbl{flex:1 1 220px}
.chkrow input{width:130px;padding:5px 8px}
pre{margin:0;background:#07061380;border:1px solid var(--line);border-radius:10px;padding:12px;
max-height:560px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12.5px/1.5 ui-monospace,Menlo,Consolas,monospace}
.meta{display:flex;gap:10px;align-items:center;margin-bottom:8px;flex-wrap:wrap;color:var(--dim);font-size:12px}
.ok{color:var(--mint)}.bad{color:var(--coral)}
.err{color:var(--coral);margin-top:8px}
.muted{color:var(--dim)}
.row3{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px}
.badge{display:inline-block;padding:8px 16px;border-radius:10px;font-weight:700;font-size:15px;margin:2px 0 8px;letter-spacing:.03em}
.badge.ok{background:#2EE6C51f;color:var(--mint);border:1px solid var(--mint);box-shadow:0 0 18px #2EE6C544}
.badge.bad{background:#FF7A591f;color:var(--coral);border:1px solid var(--coral);box-shadow:0 0 18px #FF7A5944}
.badge.warn{background:#FFD84D1f;color:#FFD84D;border:1px solid #FFD84D;box-shadow:0 0 18px #FFD84D44}
.badge.info{background:#7C6CFF22;color:#b3a9ff;border:1px solid var(--violet);box-shadow:0 0 18px #7C6CFF44}
ul.sum{margin:0 0 10px 18px;padding:0}
a.dl{color:var(--mint);display:inline-block;margin-bottom:8px}
#pretty{max-height:620px;overflow:auto;background:#07061380;border:1px solid var(--line);border-radius:10px;padding:12px;font-size:13px}
#pretty .kv{display:flex;flex-direction:column;gap:2px}
#pretty .kvr{display:flex;gap:12px;padding:4px 0;border-bottom:1px dashed #2a285088;align-items:flex-start}
#pretty .kvr:last-child{border-bottom:0}
#pretty .k{flex:0 0 190px;color:var(--mint);word-break:break-word}
#pretty .v{flex:1 1 auto;min-width:0;word-break:break-word}
#pretty .sv{white-space:pre-wrap}
#pretty .nv{color:var(--dim)}
#pretty details{margin:4px 0;border-left:2px solid var(--line);padding-left:10px}
#pretty summary{cursor:pointer;color:var(--mint);padding:3px 0}
#pretty .tw{overflow:auto;max-width:100%}
#pretty table{border-collapse:collapse;width:100%;font-size:12.5px}
#pretty th{text-align:left;color:var(--mint);font-weight:600;border-bottom:1px solid var(--line);padding:5px 8px;white-space:nowrap;position:sticky;top:0;background:#0d0b22}
#pretty td{padding:6px 10px;border-bottom:1px dashed #2a285088;vertical-align:top;overflow-wrap:break-word;line-height:1.5}
#pretty th{padding:6px 10px}
#pretty tr:nth-child(even) td{background:#ffffff05}
#pretty tr:hover td{background:#7C6CFF14}
#pretty .pill{display:inline-block;padding:1px 10px;border-radius:99px;font-size:12px;border:1px solid currentColor;white-space:nowrap}
#pretty .pill.info{color:#b3a9ff}
#pretty tr.deny td{background:#FF7A5920!important;color:var(--coral)}#pretty .logln.deny,#pretty .kvr.deny .v{color:var(--coral);font-weight:600}
#pretty .chip{display:inline-block;margin:2px 4px 2px 0;padding:1px 8px;border-radius:6px;background:var(--panel2);white-space:nowrap}
#pretty td:has(.chip){min-width:180px}#pretty .sev-high{color:var(--coral);font-weight:700}#pretty .sev-medium{color:#ffc857;font-weight:700}#pretty .sev-low{color:var(--dim)}
#pretty .sec{color:var(--dim);font-size:12px;letter-spacing:.1em;text-transform:uppercase;margin:0 0 6px}
#pretty .rsec{margin-bottom:16px;padding-bottom:4px}
#pretty .tx{white-space:pre-wrap;word-break:break-word;font:12.5px/1.5 ui-monospace,Menlo,Consolas,monospace;border:1px solid var(--line);border-radius:8px;padding:10px;max-height:340px;overflow:auto}
#pretty ul.sum{margin:0 0 0 18px}
.warnbox{border-color:var(--coral);box-shadow:0 0 18px #FF7A5922}
#pretty .dash{display:flex;flex-direction:column;gap:12px;margin-bottom:18px}
#pretty .dtiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px}
#pretty .dtile{border:1px solid var(--line);border-radius:10px;padding:8px 10px;background:var(--panel)}
#pretty .dtile .dl{color:var(--dim);font-size:12px}#pretty .dtile .dv{font-size:20px;font-weight:600}
#pretty .dtile .dc{color:var(--dim);font-size:12px;margin-left:6px;font-weight:400}
#pretty.tall{max-height:none}
#pretty .dgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(440px,1fr));gap:12px}
#pretty .dgrid.tops{grid-template-columns:repeat(auto-fit,minmax(300px,1fr))}
@media(max-width:700px){#pretty .dgrid{grid-template-columns:1fr}}
#pretty .dcard{border:1px solid var(--line);border-radius:10px;padding:10px;background:var(--panel);min-width:0}
#pretty .dcard svg{width:100%;height:auto;display:block}
#pretty .dleg{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12px;color:var(--dim);margin:2px 0 6px}
#pretty .dleg i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;vertical-align:-1px}
#pretty .dleg b{color:var(--text);font-weight:600;margin-left:4px}
#pretty svg .hv{fill:transparent}#pretty svg .hv:hover{fill:#ffffff12}
#pretty .dtop{display:grid;grid-template-columns:minmax(0,1fr) 30% auto;gap:6px 10px;align-items:center;font-size:12.5px}
#pretty .dtop .dn{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}#pretty .dtop .dn.lnk{cursor:pointer;color:var(--mint)}
#pretty .dtop .db{height:6px;border-radius:3px;background:var(--panel2)}#pretty .dtop .db span{display:block;height:6px;border-radius:3px;background:#3987e5}
#pretty .dtop .dvv{text-align:right;color:var(--dim);font-variant-numeric:tabular-nums}
</style></head><body>
<header><svg class="logo" viewBox="0 0 36 36" role="img" aria-label="ITSec Ops logo"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2EE6C5"/><stop offset=".6" stop-color="#7C6CFF"/><stop offset="1" stop-color="#FF7A59"/></linearGradient></defs><path d="M18 2.5 31.5 7.5v9.5c0 8-5.6 13.6-13.5 16.5C10.1 30.6 4.5 25 4.5 17V7.5Z" fill="#14132a" stroke="url(#lg)" stroke-width="2.2" stroke-linejoin="round"/><path d="m12 13 6 5-6 5" fill="none" stroke="#2EE6C5" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M20.5 24h5" stroke="#FF7A59" stroke-width="2.6" stroke-linecap="round"/></svg><h1>ITSec Ops</h1><small>read-only troubleshooting · F5 · Palo Alto · FortiGate · Cloudflare · local only</small></header>
<div class="wrap">
<div>
  <div class="card"><h3>Saved device profiles</h3>
    <select id="profiles"><option value="">Loading profiles…</option></select>
    <div class="row" style="margin-top:8px"><button onclick="useProfile()">Use</button>
    <button onclick="deleteProfile()">Delete</button></div>
    <div style="margin-top:8px"><button onclick="saveProfile()">Save current form</button></div>
    <div id="perr" class="err"></div>
    <p class="muted" style="margin:8px 0 0">Only device details are saved locally. Passwords, usernames, and API keys are never stored in profiles.</p>
  </div>
  <div class="card"><h3>Devices</h3><div id="devs" class="muted">No devices connected.</div></div>
  <div class="card"><h3>Connect</h3>
    <label>Vendor</label>
    <select id="vendor"><option value="f5">F5 BIG-IP (iControl REST)</option>
    <option value="paloalto">Palo Alto (PAN-OS XML API)</option>
    <option value="fortigate">FortiGate (REST API)</option>
    <option value="cloudflare">Cloudflare (API token)</option></select>
    <label>Display name (optional)</label><input id="name" placeholder="e.g. edge-fw-01">
    <div class="row" id="f-host"><div><label>Mgmt host / IP</label><input id="host"></div>
    <div style="max-width:90px"><label>Port</label><input id="port" value="443"></div></div>
    <div id="f-user"><label>Username</label><input id="username" autocomplete="off"></div>
    <div id="f-pass"><label>Password</label><input id="password" type="password" autocomplete="off"></div>
    <div id="f-key"><label id="keylbl">API key</label><input id="apikey" type="password" autocomplete="off"></div>
    <div id="f-acct" style="display:none"><label>Account ID (optional; needed for account-owned tokens)</label><input id="account" autocomplete="off" placeholder="32 hex characters"></div>
    <div class="chk" id="f-ins"><input type="checkbox" id="insecure"><span>Skip TLS verification (self-signed mgmt cert). Credentials are then sent to whatever answers at that address: use only on a trusted network.</span></div>
    <div style="margin-top:12px"><button class="primary" onclick="connect()">Connect</button></div>
    <div id="cerr" class="err"></div>
  </div>
  <div class="card"><h3>Session</h3>
    <button onclick="showAudit()">View audit log</button>
    <p class="muted" style="margin:8px 0 0">Credentials stay in memory of the Python process. Closing it clears everything.</p></div>
</div>
<div>
  <div id="cftools"></div><div id="appsec"></div>
  <div id="iplookup"></div><div id="f5tools"></div>
  <div id="health"></div>
  <div class="card" id="main"><h3>Checks</h3><div class="muted">Connect a device to begin.</div></div>
  <div class="card"><h3>Raw read-only query</h3>
    <div class="row"><input id="raw" placeholder="" style="flex:5"><button style="flex:1" onclick="runRaw()">Run</button></div>
    <div id="rawhint" class="muted" style="margin-top:6px"></div></div>
  <div class="card"><h3>Output</h3>
    <div class="meta"><span id="ometa">nothing run yet</span>
    <span id="fcount" class="muted" style="margin-left:auto"></span>
    <select id="stscope" style="display:none;max-width:150px" onchange="renderOut()" title="Which status column to test"><option value="">any status column</option><option value="vs">VS status</option><option value="pool">Pool status</option><option value="member">Member status</option></select>
    <select id="stval" style="display:none;max-width:150px" onchange="renderOut()" title="Show only rows in this state"><option value="">all states</option><option value="up">up / available</option><option value="down">down / offline</option><option value="unknown">unknown</option><option value="disabled">disabled</option></select>
    <input id="filter" placeholder="filter: word word -exclude" title="Words are ANDed; prefix a word with - to exclude it" style="max-width:240px" oninput="renderOut()">
    <button onclick="copyOut()">Copy</button>
    <button onclick="exportCsv()">Findings CSV</button><button onclick="exportHtml()">HTML report</button></div>
    <div id="verdict"></div><div id="pretty"></div></div>
</div></div>
<script>
const T="__TOKEN__";const $=s=>document.querySelector(s);let catalog={},devices=[],cur=null,last=null;
const hints={f5:"GET path, e.g. /mgmt/tm/ltm/virtual?$select=name,destination",
paloalto:"XML op command starting with <show> or <test>, e.g. <show><clock/></show>",
fortigate:"GET path, e.g. /api/v2/monitor/system/status",
cloudflare:"GET path, e.g. /client/v4/zones?per_page=50 — or a GraphQL query starting with { or query"};
async function api(p,b){const o={headers:{"X-Token":T,"Content-Type":"application/json"}};
 if(b){o.method="POST";o.body=JSON.stringify(b)}const r=await fetch(p,o);return r.json()}
let profiles=[];
async function loadProfiles(){const r=await api("/api/profiles");if(!Array.isArray(r)){
 $("#perr").textContent=r.error||"Could not load saved profiles.";profiles=[]}
 else{profiles=r;renderProfiles()}}
function renderProfiles(){const s=$("#profiles");s.innerHTML="";
 if(!profiles.length){const o=document.createElement("option");o.value="";o.textContent="No saved profiles";s.appendChild(o);return}
 profiles.forEach(p=>{const o=document.createElement("option");o.value=p.id;
  o.textContent=p.name+" · "+p.vendor+" · "+p.host+":"+p.port;s.appendChild(o)})}
async function saveProfile(){const r=await api("/api/profile/save",{name:$("#name").value,vendor:$("#vendor").value,
 host:$("#host").value,port:$("#port").value,insecure:$("#insecure").checked});
 if(!r.ok){$("#perr").textContent=r.error;return}
 $("#perr").textContent="Profile saved locally (credentials were not saved).";
 profiles.push(r.profile);renderProfiles();$("#profiles").value=r.profile.id}
function useProfile(){const p=profiles.find(x=>x.id===$("#profiles").value);if(!p)return;
 $("#name").value=p.name;$("#vendor").value=p.vendor;fields();$("#host").value=p.host;
 $("#port").value=p.port;$("#insecure").checked=p.insecure;
 $("#username").value="";$("#password").value="";$("#apikey").value="";
 $("#perr").textContent="Profile loaded. Enter credentials to connect."}
async function deleteProfile(){const id=$("#profiles").value;if(!id)return;
 const r=await api("/api/profile/delete",{id});if(!r.ok){$("#perr").textContent=r.error;return}
 profiles=profiles.filter(p=>p.id!==id);renderProfiles();$("#perr").textContent="Profile deleted."}
function fields(){const v=$("#vendor").value,cf=v==="cloudflare";
 $("#f-user").style.display=v==="fortigate"||cf?"none":"";
 $("#f-pass").style.display=v==="fortigate"||cf?"none":"";
 $("#f-key").style.display=v==="f5"?"none":"";
 $("#f-host").style.display=$("#f-ins").style.display=cf?"none":"";
 $("#f-acct").style.display=cf?"":"none";
 if(cf){$("#host").value="api.cloudflare.com";$("#port").value="443";$("#insecure").checked=false}
 else if($("#host").value==="api.cloudflare.com")$("#host").value="";
 $("#keylbl").textContent=cf?"API token (read-only permissions)":v==="fortigate"?"REST API token":"API key (or leave blank and use user/password)"}
$("#vendor").onchange=fields;fields();
async function connect(){$("#cerr").textContent="Connecting…";
 const b={vendor:$("#vendor").value,name:$("#name").value,host:$("#host").value,port:$("#port").value,
 username:$("#username").value,password:$("#password").value,apikey:$("#apikey").value,insecure:$("#insecure").checked,account:$("#account").value};
 const r=await api("/api/connect",b);
 if(!r.ok){$("#cerr").textContent=r.error;return}
 $("#cerr").textContent=r.vendor==="cloudflare"?"Token sees "+r.zones.length+" zone(s) in "+r.accounts+" account(s)."+(r.note?" Note: "+r.note:""):"";
 $("#password").value="";$("#apikey").value="";
 devices.push(r);select(r.id)}
async function disconnect(id,ev){ev.stopPropagation();await api("/api/disconnect",{id});
 devices=devices.filter(d=>d.id!==id);if(cur===id)cur=devices.length?devices[0].id:null;renderAll()}
function select(id){cur=id;renderAll()}
function dev(){return devices.find(d=>d.id===cur)}
function renderAll(){renderDevs();renderChecks();renderCf();renderAppsec();renderIp();renderF5();renderHealth();const d=dev();
 $("#raw").placeholder=d?hints[d.vendor]:"";$("#rawhint").textContent=d?hints[d.vendor]:""}
function renderDevs(){const el=$("#devs");el.innerHTML="";
 if(!devices.length){el.textContent="No devices connected.";return}
 devices.forEach(d=>{const x=document.createElement("div");x.className="dev"+(d.id===cur?" sel":"");
  x.onclick=()=>select(d.id);
  const l=document.createElement("span");l.textContent=d.name+" ";
  const t=document.createElement("span");t.className="tag "+d.vendor;t.textContent=d.vendor;l.appendChild(t);
  const h=document.createElement("small");h.className="muted";h.textContent=" "+d.host;l.appendChild(h);
  const b=document.createElement("button");b.textContent="✕";b.onclick=e=>disconnect(d.id,e);
  x.appendChild(l);x.appendChild(b);el.appendChild(x)})}
function renderHealth(){const box=$("#health");box.innerHTML="";const d=dev();if(!d)return;
 const card=document.createElement("div");card.className="card";
 const title=document.createElement("h3");title.textContent="Read-only health snapshot";card.appendChild(title);
 const note=document.createElement("p");note.className="muted";
 note.textContent="Runs a small vendor-specific check set. This reports API response success, not whether device metrics meet your operational thresholds.";
 card.appendChild(note);const button=document.createElement("button");button.className="primary";
 button.textContent="Run snapshot";button.onclick=runHealth;card.appendChild(button);box.appendChild(card)}
async function runHealth(){setBusy("health snapshot");const r=await api("/api/health",{id:cur});show(r,"health snapshot")}
function renderChecks(){const m=$("#main");m.innerHTML="<h3>Checks</h3>";const d=dev();
 if(!d){m.innerHTML+="<div class='muted'>Connect a device to begin.</div>";return}
 const list=catalog[d.vendor];const groups=[...new Set(list.map(c=>c.group))];
 groups.forEach(g=>{const h=document.createElement("div");h.className="grp";h.textContent=g;m.appendChild(h);
  list.filter(c=>c.group===g).forEach(c=>{const r=document.createElement("div");r.className="chkrow";
   const l=document.createElement("span");l.className="lbl";l.textContent=c.label;r.appendChild(l);
   const ins={};(c.params||[]).forEach(p=>{const i=document.createElement("input");
    i.placeholder=p.label+(p.placeholder?" ("+p.placeholder+")":"");i.value=p.default||"";ins[p.name]=i;r.appendChild(i)});
   const b=document.createElement("button");b.textContent="Run";
   b.onclick=()=>run(c,ins);r.appendChild(b);m.appendChild(r)})})}
async function run(c,ins){const p={};for(const k in ins)p[k]=ins[k].value;
 setBusy(c.label);const r=await api("/api/run",{id:cur,check:c.id,params:p});show(r,c.label)}
async function runRaw(){const q=$("#raw").value;if(!q)return;setBusy("raw query");
 const r=await api("/api/raw",{id:cur,query:q});show(r,"raw")}
function setBusy(l){$("#ometa").textContent="running "+l+"…";$("#pretty").textContent="";$("#verdict").innerHTML=""}
let lastCtx={label:"",device:"",time:""};
function show(r,l){last=r;const m=$("#ometa");m.textContent="";
 lastCtx={label:l,device:l==="TLS / header check"?"":((dev()||{}).name||""),time:new Date().toISOString()};
 const s=document.createElement("span");
 if(r.error){s.className="bad";s.textContent=l+" · error: "+r.error}
 else{s.className=r.ok?"ok":"bad";s.textContent=l+" · "+(r.ok?"OK":"FAILED")+" · HTTP "+r.status+" · "+r.ms+" ms"}
 m.appendChild(s);renderVerdict(r);renderOut()}
// ---- One report layout for every check: titled sections of key/value rows, tables, lists or text. ----
const ACR={ip:"IP",ipv4:"IPv4",ipv6:"IPv6",cpu:"CPU",id:"ID",url:"URL",uri:"URI",ha:"HA",ssl:"SSL",tls:"TLS",vs:"VS",tmm:"TMM",
 dns:"DNS",vpn:"VPN",nat:"NAT",fqdn:"FQDN",vdom:"VDOM",vsys:"vSys",xff:"XFF",http:"HTTP",https:"HTTPS",mac:"MAC",vlan:"VLAN",
 asm:"ASM",waf:"WAF",tcp:"TCP",udp:"UDP",icmp:"ICMP",snmp:"SNMP",ntp:"NTP",os:"OS",uuid:"UUID",pid:"PID",hw:"HW",sw:"SW",
 san:"SAN",cn:"CN",pcap:"PCAP",ms:"ms",sip:"SIP",asn:"ASN",ray:"Ray",ttl:"TTL",ttfb:"TTFB",lb:"LB",ua:"UA"};
const LABEL={t:"Time",fullPath:"Name",vip:"VS",body:"Request body",request_headers:"Request headers",cf_zone:"Zone"};
function hum(k){if(LABEL[k])return LABEL[k];k=String(k).replace(/^[@#]/,"");
 const w=k.replace(/([a-z0-9])([A-Z])/g,"$1 $2").replace(/[_\-.:\/]+/g," ").trim().split(/\s+/).filter(Boolean);
 return w.map(x=>ACR[x.toLowerCase()]||x[0].toUpperCase()+x.slice(1)).join(" ")||k}
const NOISE=/^(kind|selfLink|generation|lastUpdateMicros|isSubcollection|link|links|@status|@code)$/;
const UNW=/^(value|description|entries|nestedStats|items|result|entry|#text)$/;
function isRef(v){return isObj(v)&&Object.keys(v).length>0&&Object.keys(v).every(x=>x==="link"||x==="isSubcollection")}
function noisy(k,v){return NOISE.test(k)||isRef(v)}
function unwrap(v){while(isObj(v)){const ks=Object.keys(v).filter(k=>!noisy(k,v[k]));
 if(ks.length===1&&UNW.test(ks[0]))v=v[ks[0]];else break}return v}
function blank(v){return v===null||v===undefined||v===""||(Array.isArray(v)&&!v.length)||(isObj(v)&&!Object.keys(v).some(k=>!noisy(k,v[k])))}
function isLong(v){return typeof v==="string"&&(v.indexOf("\n")>=0||v.length>160)}
function flat(v){v=unwrap(v);if(v===null||v===undefined)return "";
 if(Array.isArray(v))return v.map(flat).filter(x=>x!=="").join(", ");
 if(isObj(v))return Object.keys(v).filter(k=>!noisy(k,v[k])).map(k=>{const s=flat(v[k]);return s===""?"":hum(k)+": "+s}).filter(Boolean).join("; ");
 return String(v)}
function cellv(v){v=unwrap(v);if(v===null||v===undefined)return "";return typeof v!=="object"?v:flat(v)}
function urlName(u){let p=u.split("?")[0].split("/").filter(Boolean);if(p[p.length-1]==="stats")p.pop();
 let s=p[p.length-1]||u;if(/^\d+$/.test(s)&&p.length>1)s=p[p.length-2]+" "+s;
 try{s=decodeURIComponent(s)}catch(e){}return s.replace(/~/g,"/")}
function metricsOf(o){const u=unwrap(o);if(!isObj(u))return {Value:cellv(u)};
 const r={};Object.keys(u).forEach(k=>{if(!noisy(k,u[k]))r[k]=cellv(u[k])});return r}
function tableSec(title,rows){
 let cols=[...new Set(rows.flatMap(r=>Object.keys(r)))].filter(c=>rows.some(r=>!noisy(c,r[c])));
 if(cols.includes("fullPath"))cols=cols.filter(c=>!["name","partition","subPath"].includes(c));
 const data=rows.map(r=>{const o={};cols.forEach(c=>o[c]=cellv(r[c]));return o});
 cols=cols.filter(c=>data.some(r=>r[c]!==""));
 if(cols.includes("vs_name")||cols.includes("pool_member_ip")||cols.includes("policy_name")||cols.includes("cf_zone")||cols.includes("pool_enabled"))return {t:"table",title,cols,data};  // F5 VS overview, Cloudflare: keep the column order given
 const lead=/^(name|fullPath|@name|label|object|rule|policy|id|policyid|time|t|severity|support_id|hostname|block_reason)$/i;
 const head=cols.filter(c=>lead.test(c)),rest=cols.filter(c=>!lead.test(c));
 const pr=/(status|state|avail|enabled|conn|bits|pkts|cpu|usage|used|total|address|ip|action|port|type)/i;
 cols=head.concat(rest.filter(c=>pr.test(c)),rest.filter(c=>!pr.test(c))).slice(0,10);
 return {t:"table",title,cols,data}}
function toSections(v,title,out,depth){
 v=unwrap(v);if(blank(v))return;
 if(typeof v!=="object"){out.push(isLong(v)?{t:"text",title:title||"Output",text:String(v)}:{t:"kv",title:title||"Details",rows:[[title||"Value",v]]});return}
 if(Array.isArray(v)){
  if(v.every(isObj)){out.push(tableSec(title||"Results",v));return}
  if(v.every(x=>x===null||typeof x!=="object")){out.push({t:"list",title:title||"Results",items:v.map(String)});return}
  v.forEach((x,i)=>toSections(x,(title||"Item")+" #"+(i+1),out,depth+1));return}
 const ks=Object.keys(v);
 if(ks.length&&ks.every(k=>/^(https?:\/\/|\/mgmt\/)/.test(k))){
  const items=ks.map(k=>Object.assign({Name:urlName(k)},metricsOf(v[k])));
  if(items.length===1)out.push({t:"kv",title:title||"Details",rows:Object.keys(items[0]).map(k=>[hum(k),items[0][k]]).filter(r=>r[1]!=="")});
  else out.push(tableSec(title||"Results",items));
  return}
 const rows=[],kids=[];
 const skipLines=Array.isArray(v.lines)&&!!(v.requests||v.entries||v.findings);
 ks.forEach(k=>{const x=v[k];if(noisy(k,x)||(k==="lines"&&skipLines))return;
  const u=unwrap(x);if(blank(u))return;
  if(typeof u!=="object"){if(isLong(u)||k==="body"||k==="request_headers")kids.push([k,u]);else rows.push([hum(k),u])}
  else if(Array.isArray(u)&&k!=="lines"&&u.every(y=>y===null||typeof y!=="object")&&u.join(", ").length<=120)rows.push([hum(k),u]);
  else kids.push([k,u])});
 if(rows.length)out.push({t:"kv",title:title||"Details",rows});
 kids.forEach(([k,x])=>{
  if(k==="lines"&&Array.isArray(x))out.push({t:"text",title:"Log lines",text:x.join("\n"),lines:x.map(String)});
  else toSections(x,(depth&&title?title+" › ":"")+hum(k),out,depth+1)})}
function buildSections(d){const out=[];
 if(isObj(d)&&("results" in d)&&("http_method" in d||"serial" in d)){
  const m=[];[["version","Firmware"],["build","Build"],["serial","Serial"],["vdom","VDOM"]].forEach(([k,l])=>{if(d[k]!==undefined&&d[k]!=="")m.push([l,d[k]])});
  if(m.length)out.push({t:"kv",title:"Device",rows:m});d=d.results}
 toSections(d,"",out,0);return out}
function cellNode(v){
 if(Array.isArray(v)){const s=mk("span");v.forEach(x=>s.appendChild(mk("span","chip",String(x))));return s}
 return scalarNode(v)}
function secNode(s){const w=mk("div","rsec");
 if(s.title)w.appendChild(mk("div","sec",s.title+(s.t==="table"?" ("+s.data.length+")":s.t==="list"?" ("+s.items.length+")":"")));
 if(s.t==="kv"){const b=mk("div","kv");s.rows.forEach(([k,v])=>{const r=mk("div","kvr");r.appendChild(mk("div","k",k));
   const c=mk("div","v");c.appendChild(cellNode(v));r.appendChild(c);b.appendChild(r)});w.appendChild(b)}
 else if(s.t==="table"){const box=mk("div","tw"),t=mk("table"),h=mk("tr");
  s.cols.forEach(c=>h.appendChild(mk("th",null,hum(c))));t.appendChild(h);
  s.data.forEach(r=>{const tr=mk("tr");s.cols.forEach(c=>{const td=mk("td");
   if(c==="severity"&&r[c])td.appendChild(mk("span","sev-"+String(r[c]).toLowerCase(),String(r[c]).toUpperCase()));
   else td.appendChild(cellNode(r[c]));tr.appendChild(td)});t.appendChild(tr)});
  box.appendChild(t);w.appendChild(box)}
 else if(s.t==="list"){const u=mk("ul","sum");s.items.forEach(i=>u.appendChild(mk("li",null,i)));w.appendChild(u)}
 else if(s.lines){const b=mk("div","tx");s.lines.forEach(l=>b.appendChild(mk("div","logln",l)));w.appendChild(b)}
 else{const b=mk("div","tx");String(s.text).split("\n").forEach(l=>b.appendChild(mk("div","logln",l||" ")));w.appendChild(b)}
 return w}
function renderOut(){const box=$("#pretty");box.textContent="";if(!last)return;
 if(last.error){box.appendChild(mk("div","bad",last.error));return}
 box.classList.toggle("tall",!!(last.dashboard||last.charts));
 if(last.dashboard)box.appendChild(dashNode(last.dashboard));  // charts first; the tables below are the table view
 if(Array.isArray(last.charts)&&last.charts.length)box.appendChild(chartsNode(last.charts));
 buildSections(last.data).forEach(s=>box.appendChild(secNode(s)));
 if(!box.childNodes.length)box.appendChild(mk("div","nv","Nothing to show for this check."));
 // Blocked / denied traffic in red: table rows with a deny-type cell, and log lines whose action precedes " -> ".
 const DENY=/^(deny|denied|drop|dropped|block|blocked|block-\w+|reset|reset-\w+|blackhole|sinkhole)$/i,DENYW=/\b(deny|denied|drop|dropped|block|blocked|block-\w+|reset-\w+)\b/i;
 box.querySelectorAll("tr:not(:first-child)").forEach(tr=>{if([...tr.children].some(td=>DENY.test(td.textContent.trim())))tr.classList.add("deny")});
 box.querySelectorAll(".logln").forEach(l=>{if(DENYW.test(l.textContent.split(" -> ")[0]))l.classList.add("deny")});
 box.querySelectorAll(".kvr").forEach(r=>{const v=r.querySelector(".v");if(v&&DENY.test(v.textContent.trim()))r.classList.add("deny")});
 // Filter: words are ANDed, a leading "-" excludes a word (e.g.  certificate -expired). Applies to log lines,
 // table rows, key/value rows and list items.
 const terms=$("#filter").value.toLowerCase().split(/\s+/).filter(Boolean),fc=$("#fcount");
 const inc=terms.filter(t=>t[0]!=="-"||t.length===1),exc=terms.filter(t=>t[0]==="-"&&t.length>1).map(t=>t.slice(1));
 // Status filter (only for tables that have *status columns, e.g. the F5 virtual server / pool tables).
 const hasSt=[...box.querySelectorAll("th")].some(t=>/status/i.test(t.textContent));
 $("#stscope").style.display=$("#stval").style.display=hasSt?"":"none";
 const stScope=$("#stscope").value,stVal=hasSt?$("#stval").value:"";
 const SV={up:/^(available|up)\b/i,down:/^(offline|down|unavailable|forced|disconnected)/i,unknown:/^unknown/i,disabled:/disabled/i};
 const stCols=new Map();
 function stOk(tr){if(!stVal||tr.tagName!=="TR")return true;const t=tr.closest("table");
  if(!stCols.has(t))stCols.set(t,[...t.rows[0].cells].map((c,i)=>[c.textContent.toLowerCase(),i]).filter(([h])=>/status/.test(h)&&(!stScope||h.startsWith(stScope))).map(x=>x[1]));
  const idx=stCols.get(t);return !idx.length||idx.some(i=>tr.cells[i]&&SV[stVal].test(tr.cells[i].textContent.trim()))}
 const rows=box.querySelectorAll(".logln,.kvr,tr:not(:first-child),li");let shown=0;
 rows.forEach(x=>{const s=x.textContent.toLowerCase();
  const ok=inc.every(t=>s.includes(t))&&!exc.some(t=>s.includes(t))&&stOk(x);x.style.display=ok?"":"none";if(ok)shown++});
 if(fc)fc.textContent=(terms.length||stVal)&&rows.length?shown+" of "+rows.length+" shown":""}
function isObj(v){return v!==null&&typeof v==="object"&&!Array.isArray(v)}
function mk(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
const GOOD=/^(up|active|enabled|enable|available|online|success|accept|allow|ok|green|true|established|established\(.*\)|in-sync|synchronized|standalone|passed?)$/i;
const BAD=/^(down|disabled|disable|offline|failed|fail|deny|denied|drop|dropped|error|red|false|unavailable|forced-offline|disconnected|block|blocked|block-\w+|reset-\w+)$/i;
function scalarNode(v){
 if(v===null||v===undefined||v==="")return mk("span","nv","—");
 if(typeof v==="boolean")return mk("span","pill "+(v?"ok":"bad"),v?"yes":"no");
 const s=String(v);
 if(GOOD.test(s))return mk("span","pill ok",s);
 if(BAD.test(s))return mk("span","pill bad",s);
 return mk("span","sv",s)}
function copyOut(){navigator.clipboard.writeText($("#pretty").innerText)}
async function showAudit(){const r=await api("/api/audit");last={ok:true,status:200,ms:0,data:r};
 show(last,"audit log")}
function fld(id,l,ph,v){return '<div><label>'+l+'</label><input id="'+id+'" placeholder="'+ph+'" value="'+(v||'')+'"></div>'}
function g(i){const e=$("#"+i);return e?e.value:""}
function renderIp(){const box=$("#iplookup");box.innerHTML="";const d=dev();if(!d||d.vendor==="cloudflare")return;const v=d.vendor;
 let h='<div class="card"><h3>IP lookup · '+(v==="f5"?"pools, nodes, virtual servers, data groups, local traffic policies":"policy references")+'</h3><div class="row3">'+fld("ip_ip","IP address","203.0.113.7");
 if(v!=="f5"){
  h+=v==="paloalto"?fld("ip_vsys","vsys","vsys1","vsys1"):fld("ip_vdom","VDOM (optional)","root");
 }
 h+='</div><div style="margin-top:10px"><button class="primary" onclick="ipLookup()">Check</button></div></div>';
 if(v!=="f5"){const pan=v==="paloalto";
  h+='<div class="card"><h3>Policy lookup · find a '+(pan?"security rule":"firewall policy")+' by name, or which one allows or blocks a flow</h3>'+
   '<div class="grp">By name</div><div class="row3">'+fld("pm_name",pan?"Rule name (or part of it)":"Policy name (or part of it) or policy ID",pan?"allow-web":"web-in or 12")+'</div>'+
   '<div style="margin-top:10px"><button class="primary" onclick="policyByName()">Find policy</button></div>'+
   '<div class="grp">By flow</div><div class="row3">'+
   fld("pm_src","Source IP","198.51.100.9")+fld("pm_dst","Destination IP","203.0.113.10")+fld("pm_port","Destination port (optional)","443")+
   '<div><label>Protocol</label><select id="pm_proto"><option>tcp</option><option>udp</option><option>icmp</option></select></div>'+
   (pan?fld("pm_from","From zone (optional)","untrust")+fld("pm_to","To zone (optional)","trust")+fld("pm_vsys","vsys","vsys1","vsys1")
       :fld("pm_if","Ingress interface (required)","port1")+fld("pm_vdom","VDOM (optional)","root"))+
   '</div><div style="margin-top:10px"><button class="primary" onclick="policyLookup()">Look up policy</button></div>'+
   '<p class="muted" style="margin:8px 0 0">'+(pan?"Runs 'test security-policy-match' (as Device &gt; Test Policy Match), so it also covers Panorama-pushed rules. Zones narrow the match; leave them blank to let the firewall evaluate all rules.":
    "Runs FortiOS policy lookup (as Policy &amp; Objects &gt; Policy Lookup). The ingress interface is the one the first packet arrives on, e.g. port1 or a VLAN interface.")+
   ' Read-only: nothing is changed on the device.</p></div>'}
 if(v==="f5")h+='<div class="card"><h3>Hostname lookup · virtual server and local traffic policy</h3><div class="row3">'+fld("fh_host","Hostname","app.example.com")+
  '</div><div style="margin-top:10px"><button class="primary" onclick="f5Host()">Find virtual server / policy</button></div></div>';
 box.innerHTML=h}
async function f5Host(){setBusy("hostname lookup");
 const r=await api("/api/f5host",{id:cur,hostname:g("fh_host")});show(r,"hostname lookup")}
async function ipLookup(){setBusy("IP lookup");
 const r=await api("/api/ipcheck",{id:cur,ip:g("ip_ip"),mode:"refs",vsys:g("ip_vsys"),vdom:g("ip_vdom")});show(r,"IP lookup")}
async function policyByName(){setBusy("policy search");
 const r=await api("/api/policy",{id:cur,name:g("pm_name"),vsys:g("pm_vsys"),vdom:g("pm_vdom")});show(r,"policy search")}
async function policyLookup(){if(!g("pm_src").trim()||!g("pm_dst").trim())return show({ok:false,error:"enter both the source and the destination IP"},"policy lookup");
 setBusy("policy lookup");
 const r=await api("/api/ipcheck",{id:cur,mode:"verdict",ip:g("pm_src"),peer:g("pm_dst"),role:"source",port:g("pm_port"),proto:g("pm_proto"),
  from:g("pm_from"),to:g("pm_to"),vsys:g("pm_vsys"),srcintf:g("pm_if"),vdom:g("pm_vdom")});show(r,"policy lookup")}
function renderF5(){const box=$("#f5tools");box.innerHTML="";const d=dev();if(!d||d.vendor!=="f5")return;
 box.innerHTML='<div class="card warnbox"><h3>F5 active tools · run shell commands on the BIG-IP</h3>'+
 '<p class="muted" style="margin:0 0 8px">Uses POST /mgmt/tm/util/bash (Administrator role). Commands are fixed templates and only validated values are inserted. tcpdump adds CPU load, and captures may contain sensitive data.</p>'+
 '<div class="chk"><input type="checkbox" id="f5ack"><span>I understand, and this is approved for this device</span></div>'+
 '<div class="grp">Search a log for an IP</div><div class="row3">'+fld("lg_ip","IP address","203.0.113.7")+
 '<div><label>Log file (/var/log/…)</label><select id="lg_log"><option>ltm</option><option>audit</option><option>apm</option><option>gtm</option><option>tmm</option><option>asm</option></select></div>'+
 fld("lg_n","Max lines","200","200")+wsel("lg_w")+'</div>'+
 '<div class="chk"><input type="checkbox" id="lg_rot"><span>Include rotated logs (.gz)</span></div>'+
 '<div style="margin-top:8px"><button onclick="f5Logs()">Search log</button></div>'+
 '<div class="grp">Packet capture (tcpdump), then download</div><div class="row3">'+
 fld("tc_ip","IP address","203.0.113.7")+fld("tc_port","Port (optional)","443")+'<div><label>Interface (pick or type)</label><input id="tc_if" list="tc_ifs" value="0.0:nnn" placeholder="0.0:nnn"><datalist id="tc_ifs"><option value="0.0:nnn"><option value="0.0:nnnp"><option value="0.0"><option value="1.1"><option value="1.2"></datalist></div>'+
 fld("tc_dur","Seconds (5-50)","15","15")+fld("tc_cnt","Max packets","10000","10000")+fld("tc_snap","Snaplen (0 = full)","0","0")+'</div>'+
 '<p class="muted" style="margin:6px 0 0">0.0:nnn = all VLANs, 0.0:nnnp = also the peer (server-side) flow of each connection.</p>'+
 '<div class="chk"><input type="checkbox" id="tc_pms"><span>Also extract the TLS keys to a .pms file with tshark (f5ethtrailer.tls.keylog) and download both. Implies --f5 ssl.</span></div>'+
 '<div class="chk"><input type="checkbox" id="tc_ssl"><span>Include TLS session keys (--f5 ssl) so Wireshark can decrypt. The saved file can expose decrypted traffic; handle it as sensitive.</span></div>'+
 '<div style="margin-top:8px"><button class="primary" onclick="f5Capture()">Capture &amp; download</button></div>'+
 '<div class="grp">Download a file or folder from the BIG-IP</div><div class="row3">'+
 '<div><label>Path on the BIG-IP (file or folder)</label><input id="fd_path" list="fd_paths" placeholder="/var/log/ltm"><datalist id="fd_paths"></datalist></div></div>'+
 '<div class="chk"><input type="checkbox" id="fd_sens"><span>Allow sensitive files (password hashes, private keys, master key, bigip.conf, UCS archives). Protect the copy on this PC.</span></div>'+
 '<div class="row" style="margin-top:8px"><button onclick="f5Files(\'list\')">List folder</button><button class="primary" onclick="f5Files(\'get\')">Download</button></div>'+
 '<p class="muted" style="margin:6px 0 0">List folder fills the Path field\'s drop-down with that folder\'s entries. A folder downloads as .tar.gz. Up to 500 MB, read in 256 KB blocks over iControl REST (no SSH needed) and checked with MD5. Every download is in the audit log.</p></div>'}
async function f5Files(m){const p=g("fd_path");setBusy(m==="list"?"listing "+p:"downloading "+p+" (large files take a while)");
 const r=await api("/api/f5file",{id:cur,ack:$("#f5ack").checked,mode:m,path:p,sensitive:$("#fd_sens").checked});
 show(r,m==="list"?"BIG-IP folder":"BIG-IP file download");
 if(r&&r.ok&&m==="list"){const dl=$("#fd_paths");if(dl)dl.innerHTML=(r.data.entries||[]).map(e=>'<option value="'+esc(e.path)+'">').join("")}
 if(r&&r.ok&&r.download){const a=document.createElement("a");a.href=r.download+"?t="+T;a.click()}}
async function f5Logs(){setBusy("log search");
 const r=await api("/api/f5logs",{id:cur,ack:$("#f5ack").checked,ip:g("lg_ip"),log:g("lg_log"),lines:g("lg_n"),within:g("lg_w"),rotated:$("#lg_rot").checked});show(r,"log search")}
async function f5Capture(){setBusy("packet capture (up to "+g("tc_dur")+"s, then download)");
 const r=await api("/api/f5capture",{id:cur,ack:$("#f5ack").checked,ip:g("tc_ip"),port:g("tc_port"),iface:g("tc_if"),duration:g("tc_dur"),count:g("tc_cnt"),snaplen:g("tc_snap"),ssl:$("#tc_ssl").checked,pms:$("#tc_pms").checked});show(r,"packet capture")}
function renderVerdict(r){const v=$("#verdict");v.innerHTML="";
 if(r.verdict){const b=document.createElement("div");b.className="badge "+r.verdict.kind;b.textContent=r.verdict.label;v.appendChild(b)}
 if(r.summary&&r.summary.length){const u=document.createElement("ul");u.className="sum";
  r.summary.forEach(x=>{const li=document.createElement("li");li.textContent=x;u.appendChild(li)});v.appendChild(u)}
 (r.downloads||(r.download?[r.download]:[])).forEach(d=>{const a=document.createElement("a");a.className="dl";a.href=d+"?t="+T;a.textContent="⬇ Download "+d.split("/").pop();v.appendChild(a)})}
const WITHIN=["any time","last 15 minutes","last hour","last 6 hours","last 12 hours","last 24 hours"];
function wsel(id){return sel(id,"Time range (up to 1 day)",WITHIN,"any time")}
function sel(id,label,opts,def){return '<div><label>'+label+'</label><select id="'+id+'">'+
 opts.map(o=>'<option'+(o===def?' selected':'')+'>'+o+'</option>').join("")+'</select></div>'}
function renderAppsec(){const box=$("#appsec");box.innerHTML="";const d=dev();if(!d||d.vendor==="cloudflare")return;const v=d.vendor;
 let h='<div class="card"><h3>AppSec checks · read-only</h3><div class="row3">';
 if(v==="paloalto")h+=fld("as_vsys","vsys","vsys1","vsys1");
 if(v==="fortigate")h+=fld("as_vdom","VDOM (optional)","root");
 if(v==="f5")h+=fld("as_days","Cert warning (days)","60","60");
 h+='</div><div class="row" style="margin-top:10px;flex-wrap:wrap">'+
  '<button onclick="appsec(\'waf\')">'+(v==="f5"?"WAF posture":"Security-profile coverage")+'</button>'+
  (v==="f5"?'<button onclick="appsec(\'ssl\')">SSL / cert posture</button>':'')+'</div>';
 if(v==="f5"){
  h+='<div class="grp">ASM / Advanced WAF request log</div><div class="row3">'+fld("asm_sid","Support ID (from block page)","1234567890123456789")+wsel("asm_sw")+
  '</div><div style="margin-top:8px"><button class="primary" onclick="asmLookup(\'supportid\')">Look up support ID</button></div>'+
  '<div class="row3" style="margin-top:8px">'+fld("asm_ip","Client IP (device-seen)","203.0.113.7")+
  fld("asm_tci","True-Client-IP (behind Cloudflare)","198.51.100.9")+fld("asm_host","Hostname contains","app.example.com")+fld("asm_url","URL path contains","/login")+
  sel("asm_st","Status",["","blocked","alerted","passed"],"")+fld("asm_top","Max rows","50","50")+wsel("asm_w")+
  '</div><div style="margin-top:8px"><button onclick="asmLookup(\'search\')">Search requests</button></div>'+
  '<div class="grp" style="margin-top:14px">Requests by HTTP header</div><div class="row3">'+
  fld("asm_hn","Header name","X-Request-ID")+fld("asm_hv","Value contains (blank = any)","abc123")+
  fld("asm_hh","Hostname contains (optional)","app.example.com")+sel("asm_hst","Status",["","blocked","alerted","passed"],"")+
  fld("asm_htop","Max rows","50","50")+fld("asm_hscan","Entries to scan","1000","1000")+wsel("asm_hw")+
  '</div><div style="margin-top:8px"><button onclick="asmLookup(\'header\')">Search by header</button> '+
  '<span class="muted">(shows header value, IP, True-Client-IP, hostname, URL, time, support ID, POST body)</span></div>'+
  '<div class="grp" style="margin-top:14px">Top 10 hostnames by violations</div><div class="row3">'+
  sel("asm_tst","Status",["","blocked","alerted"],"")+fld("asm_scan","Entries to scan","1000","1000")+wsel("asm_tw")+
  '</div><div style="margin-top:8px"><button onclick="asmLookup(\'tophosts\')">Top 10 hostnames by violations</button> '+
  '<span class="muted">(Status blank = blocked + alerted)</span></div>'}
 if(v==="paloalto"){
  h+='<div class="grp">Log search (threat / URL / traffic)</div><div class="row3">'+fld("pl_ip","IP or subnet (src or dst)","203.0.113.7 or 10.2.64.0/24")+fld("pl_dst","Destination IP or subnet (optional)","198.51.100.0/24")+sel("pl_dtype","Destination is",["either","normal destination","DNAT (translated) destination"],"either")+
  sel("pl_type","Log type",["threat","url","traffic"],"threat")+
  sel("pl_period","Time range",["last-15-minutes","last-hour","last-6-hrs","last-12-hrs","last-24-hrs","last-7-days","last-30-days"],"last-24-hrs")+
  fld("pl_n","Max rows","100","100")+sel("pl_blocked","Show",["all entries","blocked only","allowed only"],"blocked only")+
  '</div><div style="margin-top:8px"><button class="primary" onclick="panLogs()">Search logs</button></div>'+
  '<p class="muted" style="margin:8px 0 0">URL category lookup is under Checks → Policy.</p>'}
 if(v==="fortigate"){
  h+='<div class="grp">Traffic log search (is this IP being blocked?)</div><div class="row3">'+fld("fl_ip","IP or subnet (src or dst)","203.0.113.7 or 10.2.64.0/24")+
  fld("fl_dst","Destination IP or subnet (optional)","198.51.100.0/24")+
  sel("fl_dtype","Destination is",["either","normal destination","DNAT (translated) destination"],"either")+
  sel("fl_src","Log source",["disk","memory","fortianalyzer"],"disk")+fld("fl_n","Max rows per direction","500","500")+wsel("fl_w")+
  sel("fl_blocked","Show",["all entries","blocked only","allowed only"],"blocked only")+fld("fl_vdom","VDOM (optional)","root")+
  '</div><div style="margin-top:8px"><button class="primary" onclick="fgLogs()">Search traffic logs</button></div>'}
 if(v==="f5")h+='<div class="grp">Config sync · changes made here and whether the peer has them</div><div class="row3">'+
  fld("sy_h","Look back (hours)","24","24")+fld("sy_n","Max rows","200","200")+
  '</div><div style="margin-top:8px"><button class="primary" onclick="f5Sync()">Review config sync</button></div>';
 if(v==="paloalto"){
  h+='<div class="grp">Packet capture (live, then download .pcap)</div>'+
  '<div class="chk"><input type="checkbox" id="pc_ack"><span>I understand this turns on packet-diag capture on the firewall for a short time, clears all packet-diag settings (ending any capture another admin has running) and may expose traffic; approved for this device</span></div>'+
  '<div class="row3">'+fld("pc_src","Source IP","203.0.113.7")+fld("pc_dst","Destination IP","198.51.100.9")+fld("pc_port","Port","443")+
  sel("pc_proto","Protocol",["any","tcp","udp","icmp"],"tcp")+
  fld("pc_dur","Seconds (5-60)","20","20")+fld("pc_cnt","Max packets","10000","10000")+sel("pc_stage","Stage",["receive","firewall","transmit","drop"],"receive")+
  '</div><p class="muted" style="margin:6px 0 0">At least one IP or port is required.</p><div style="margin-top:8px"><button class="primary" onclick="capture()">Capture &amp; download</button></div>'}
 h+='<div class="grp">Configuration backup (saved, then downloaded to this PC)</div>'+
  (v==="f5"?'<div class="chk"><input type="checkbox" id="bk_ack"><span>I understand this creates a UCS archive on the BIG-IP and copies it through the shell (Administrator role); approved for this device</span></div>':'')+
  (v==="fortigate"?'<div class="row3">'+fld("bk_vdom","VDOM (optional, blank = whole device)","root")+'</div>':'')+
  '<div style="margin-top:8px"><button class="primary" onclick="backup()">Back up &amp; download</button></div>';
 h+='<div class="grp">Admin audit · who logged in and what they did</div><div class="row3">'+fld("au_user","Admin user name","admin")+
  fld("au_act","Action contains (optional)","delete, commit, edit")+fld("au_n","Max rows","100","100")+
  (v==="paloalto"?sel("au_period","Time range",["last-15-minutes","last-hour","last-6-hrs","last-12-hrs","last-24-hrs","last-7-days","last-30-days"],"last-24-hrs"):"")+
  (v==="fortigate"?sel("au_src","Log source",["disk","memory","fortianalyzer"],"disk")+fld("au_vdom","VDOM (optional)","root"):"")+
  (v!=="paloalto"?wsel("au_w"):"")+
  '</div><div style="margin-top:8px"><button class="primary" onclick="adminAudit()">Search admin activity</button></div>';
 box.innerHTML=h+'</div>'}
async function capture(){setBusy("packet capture (up to "+g("pc_dur")+"s, then download)");
 const r=await api("/api/pancapture",{id:cur,ack:$("#pc_ack").checked,src:g("pc_src"),dst:g("pc_dst"),port:g("pc_port"),proto:g("pc_proto"),
  duration:g("pc_dur"),count:g("pc_cnt"),stage:g("pc_stage")});show(r,"packet capture")}
async function backup(){setBusy("configuration backup (F5 archives can take several minutes)");
 const r=await api("/api/backup",{id:cur,ack:!!($("#bk_ack")&&$("#bk_ack").checked),vdom:g("bk_vdom")});show(r,"configuration backup");
 if(r&&r.ok&&r.download){const a=document.createElement("a");a.href=r.download+"?t="+T;a.click()}}
async function f5Sync(){setBusy("config sync review");
 const r=await api("/api/f5sync",{id:cur,hours:g("sy_h"),count:g("sy_n")});show(r,"config sync review")}
async function adminAudit(){setBusy("admin audit (can take up to a minute)");
 const r=await api("/api/adminaudit",{id:cur,user:g("au_user"),action:g("au_act"),count:g("au_n"),period:g("au_period"),within:g("au_w"),log_source:g("au_src"),vdom:g("au_vdom")});show(r,"admin audit")}
async function appsec(c){const names={waf:"coverage",ssl:"SSL posture"};setBusy(names[c]);
 const r=await api("/api/appsec",{id:cur,check:c,vsys:g("as_vsys"),vdom:g("as_vdom"),days:g("as_days")});show(r,names[c])}
async function asmLookup(m){setBusy("ASM request log");
 if(m==="header"){const r=await api("/api/f5asm",{id:cur,mode:m,header_name:g("asm_hn"),header_value:g("asm_hv"),hostname:g("asm_hh"),
  status:g("asm_hst"),top:g("asm_htop"),scan:g("asm_hscan"),within:g("asm_hw")});return show(r,"ASM requests by header")}
 const r=await api("/api/f5asm",{id:cur,mode:m,support_id:g("asm_sid"),ip:g("asm_ip"),header_ip:g("asm_tci"),hostname:g("asm_host"),url:g("asm_url"),status:m==="tophosts"?g("asm_tst"):g("asm_st"),top:g("asm_top"),scan:g("asm_scan"),within:m==="tophosts"?g("asm_tw"):m==="supportid"?g("asm_sw"):g("asm_w")});
 show(r,m==="supportid"?"support ID lookup":m==="tophosts"?"top hostnames by violations":"ASM request search")}
const CFW=["last 15 minutes","last hour","last 6 hours","last 12 hours","last 24 hours","last 3 days","last 7 days","last 30 days"];
const CF_ACT=["","block","managed_challenge","challenge","jschallenge","log","skip","allow","bypass","connection_close"];
const CF_EVBY=["action","source","rule","client IP","host","path","country","ASN","user agent","colo","time"];
const CF_HTBY=["host","edge status","origin status","edge + origin status","cache status","client IP","path","country","ASN","user agent","colo","security action","TLS version","HTTP version","time"];
const CF_ST=["","2xx","3xx","4xx","5xx","4xx + 5xx","origin errors (520-527)"];
function renderCf(){const box=$("#cftools");box.innerHTML="";const d=dev();if(!d||d.vendor!=="cloudflare")return;
 const f5=devices.filter(x=>x.vendor==="f5");
 let h='<div class="card"><h3>Cloudflare · scope for every lookup below</h3><div class="row3">'+
  '<div><label>Zone (blank = all zones)</label><input id="cf_zone" list="cf_zl" placeholder="example.com"><datalist id="cf_zl">'+
  (d.zones||[]).map(z=>'<option value="'+esc(z)+'">').join("")+'</datalist></div>'+
  sel("cf_w","Time range",CFW,"last 24 hours")+fld("cf_since","Custom from (UTC+3, optional)","2026-11-01 08:00")+
  fld("cf_until","Custom to (UTC+3, optional)","2026-11-01 09:00")+
  '<div><label>Cross-check on F5 (optional)</label><select id="cf_f5"><option value="">none</option>'+
  f5.map(x=>'<option value="'+esc(x.id)+'">'+esc(x.name)+'</option>').join("")+'</select></div></div>'+
  '<p class="muted" style="margin:8px 0 0">How far back you can query, and which datasets exist, depends on the zone plan. Times are shown in UTC+3.'+
  (f5.length?'':' Connect an F5 device to cross-check Ray IDs and IPs against the ASM request log.')+'</p></div>';
 h+='<div class="card"><h3>WHOIS · IP and domain registration</h3><div class="row3">'+
  fld("cf_w_ip","IP address","198.51.100.9")+fld("cf_w_host","Domain or hostname","app.example.com")+
  '</div><div style="margin-top:8px"><button class="primary" onclick="cfWhois()">WHOIS lookup</button></div>'+
  '<p class="muted" style="margin:8px 0 0">IP: network, range, owner organisation, country, abuse contact (RDAP from the regional registry). Domain: registrar, registrant, created / expiry dates, status, name servers, DNSSEC. Fill one or both.</p></div>';
 h+='<div class="card"><h3>Investigate · everything Cloudflare knows</h3><div class="row3">'+
  fld("cf_ip","Client or origin IP","198.51.100.9")+fld("cf_host","Hostname","app.example.com")+fld("cf_ray","Ray ID","8d3c1a2b3c4d5e6f-FRA")+
  fld("cf_days","Cert warning (days)","30","30")+fld("cf_win","Trace window ± seconds","120","120")+'</div><div class="row" style="margin-top:8px;flex-wrap:wrap">'+
  '<button class="primary" onclick="cfIp()">Investigate IP</button><button class="primary" onclick="cfHost()">Investigate hostname</button>'+
  '<button class="primary" onclick="cfRay()">Look up Ray ID</button><button class="primary" onclick="cfTrace()">Trace Ray ID: Cloudflare → F5</button></div>'+
  '<p class="muted" style="margin:8px 0 0">IP: security events, traffic, IP Access Rules, IP lists, rules and DNS records that involve it. Hostname: DNS, proxy status, certificates, settings, rules, Workers, page rules, load balancers, errors. Ray ID: what Cloudflare did with that one request (plus the F5 ASM entry via the CF-Ray header).</p></div>';
 h+='<div class="card"><h3>URL response time · edge vs origin</h3><div class="row3">'+
  fld("cf_u_url","URL","https://app.example.com/api/login")+sel("cf_u_match","Path match",["exact","starts with","contains"],"exact")+
  sel("cf_u_st","Edge status",CF_ST,"")+fld("cf_u_cache","Cache status (optional)","miss, dynamic")+fld("cf_u_ip","Client IP (optional)","198.51.100.9")+
  fld("cf_u_n","Slowest requests to list","50","50")+'</div><div style="margin-top:8px"><button class="primary" onclick="cfUrl()">Look up URL timing</button></div>'+
  '<p class="muted" style="margin:8px 0 0">Edge TTFB and origin (e.g. F5) response time: p50 / p95 / p99, a timeline, breakdowns by status, cache, colo and method, and the slowest requests with DNS / TCP / TLS / header timings to the origin. Uses the scope time range.</p></div>';
 h+='<div class="card"><h3>Security events · WAF, rate limiting, bots, IP rules</h3><div class="row3">'+
  fld("cf_e_ip","Client IP","198.51.100.9")+fld("cf_e_host","Host (* wildcard)","app.example.com")+fld("cf_e_path","Path contains","/login")+
  fld("cf_e_ray","Ray ID","8d3c1a2b3c4d5e6f")+sel("cf_e_act","Action",CF_ACT,"")+
  '<div><label>Source (security product)</label><input id="cf_e_src" list="cf_srcl" placeholder="firewallManaged"><datalist id="cf_srcl">'+
  ["firewallManaged","firewallCustom","ratelimit","waf","firewallRules","botFight","botManagement","bic","hot","l7ddos","securitylevel","uablock","zonelockdown","ip","iprange","asn","country","validation","apiShield","dlp"].map(x=>'<option value="'+x+'">').join("")+'</datalist></div>'+
  fld("cf_e_rule","Rule ID","")+fld("cf_e_cc","Country (2 letters)","US")+fld("cf_e_asn","ASN","13335")+fld("cf_e_ua","User agent contains","curl")+
  fld("cf_e_m","Method","POST")+fld("cf_e_n","Max rows","100","100")+'</div><div class="row" style="margin-top:8px;flex-wrap:wrap">'+
  '<button class="primary" onclick="cfEvents()">Search events</button></div><div class="row3" style="margin-top:8px">'+sel("cf_e_by","Top: group by",CF_EVBY,"action")+fld("cf_e_top","Top N","20","20")+
  '</div><div style="margin-top:8px"><button onclick="cfEventTop()">Top events</button> <span class="muted">(same filters; "time" gives a timeline)</span></div></div>';
 h+='<div class="card"><h3>HTTP traffic · requests, status codes, cache, origin errors</h3><div class="row3">'+
  fld("cf_t_host","Host (* wildcard)","app.example.com")+fld("cf_t_ip","Client IP","198.51.100.9")+fld("cf_t_path","Path contains","/api")+
  sel("cf_t_st","Edge status",CF_ST,"")+fld("cf_t_cache","Cache status","hit, miss, dynamic")+fld("cf_t_ray","Ray ID (sampled requests)","")+
  sel("cf_t_by","Summary: group by",CF_HTBY,"edge status")+fld("cf_t_top","Top N","20","20")+fld("cf_t_n","Max sampled rows","100","100")+
  '</div><div class="row" style="margin-top:8px;flex-wrap:wrap"><button class="primary" onclick="cfTraffic()">Traffic summary</button>'+
  '<button onclick="cfRequests()">Sampled requests</button><button onclick="cfDash()">Traffic dashboard</button></div></div>';
 h+='<div class="card"><h3>Configuration</h3><div class="row3">'+fld("cf_r_q","Rules: text, IP, $list, rule or ruleset ID","/login or 203.0.113.7")+
  '</div><div style="margin-top:8px"><button onclick="cfRules()">Search rules</button> <span class="muted">(blank = list all security rules)</span></div>'+
  '<div class="row3" style="margin-top:10px">'+fld("cf_d_name","DNS name contains","app")+fld("cf_d_content","DNS content contains","203.0.113.10")+
  sel("cf_d_type","Record type",["","A","AAAA","CNAME","TXT","MX","NS","CAA","SRV"],"")+'</div><div style="margin-top:8px"><button onclick="cfDns()">Search DNS</button></div>'+
  '<div class="row" style="margin-top:10px;flex-wrap:wrap"><button onclick="cfPosture()">Security posture (settings, TLS, certificates)</button>'+
  '<button onclick="cfLb()">Load balancers &amp; health checks</button></div></div>';
 h+='<div class="card"><h3>Audit log · who changed what</h3><div class="row3">'+fld("cf_a_email","Actor e-mail","admin@example.com")+
  fld("cf_a_act","Action contains","change, delete, login")+fld("cf_a_res","Resource / text contains","firewall")+fld("cf_a_n","Max rows","100","100")+
  '</div><div style="margin-top:8px"><button class="primary" onclick="cfAudit()">Search audit log</button> <span class="muted">(uses the scope zone and time range)</span></div></div>';
 box.innerHTML=h}
async function cfRun(mode,label,extra){setBusy(label+(g("cf_f5")&&(mode==="ip"||mode==="ray")?" + F5 cross-check (up to a few minutes)":""));
 const r=await api("/api/cf",Object.assign({id:cur,mode,zone:g("cf_zone"),within:g("cf_w"),since:g("cf_since"),until:g("cf_until"),f5:g("cf_f5")},extra));show(r,label)}
function cfIp(){cfRun("ip","Cloudflare IP investigation",{ip:g("cf_ip")})}
function cfHost(){cfRun("host","Cloudflare hostname investigation",{host:g("cf_host"),days:g("cf_days")})}
function cfRay(){cfRun("ray","Cloudflare Ray ID lookup",{ray:g("cf_ray")})}
function cfWhois(){cfRun("whois","WHOIS",{ip:g("cf_w_ip"),host:g("cf_w_host"),days:g("cf_days")})}
function cfTraceBy(m,label,extra){setBusy(label+": Cloudflare → F5 (can take a few minutes)");
 api("/api/cf",Object.assign({id:cur,mode:m,zone:g("cf_zone"),within:g("cf_w"),since:g("cf_since"),until:g("cf_until"),
  f5:g("cf_f5"),window:g("cf_win")},extra)).then(r=>show(r,label))}
function cfTrace(){cfTraceBy("trace","Ray ID trace",{ray:g("cf_ray")})}function cfEvF(){return {ip:g("cf_e_ip"),host:g("cf_e_host"),path:g("cf_e_path"),ray:g("cf_e_ray"),action:g("cf_e_act"),source:g("cf_e_src"),
 rule:g("cf_e_rule"),country:g("cf_e_cc"),asn:g("cf_e_asn"),ua:g("cf_e_ua"),method:g("cf_e_m")}}
function cfEvents(){cfRun("events","Cloudflare security events",Object.assign(cfEvF(),{top:g("cf_e_n")}))}
function cfEventTop(){cfRun("event_top","Cloudflare top security events",Object.assign(cfEvF(),{by:g("cf_e_by"),top:g("cf_e_top")}))}
function cfHtF(){return {host:g("cf_t_host"),ip:g("cf_t_ip"),path:g("cf_t_path"),status:g("cf_t_st"),cache:g("cf_t_cache")}}
function cfTraffic(){cfRun("traffic","Cloudflare traffic summary",Object.assign(cfHtF(),{by:g("cf_t_by"),top:g("cf_t_top")}))}
function cfRequests(){cfRun("requests","Cloudflare sampled requests",Object.assign(cfHtF(),{ray:g("cf_t_ray"),top:g("cf_t_n")}))}
// Dashboard drill-down: filters added by clicking the dashboard (kept until the Traffic dashboard button is pressed).
let dashX={};
function cfDash(x){dashX=x||{};
 const f=Object.keys(dashX).filter(k=>k!=="until").map(k=>k==="since"?dashX.since+" → "+dashX.until+" (UTC+3)":k+" "+dashX[k]);
 cfRun("dashboard","Cloudflare traffic dashboard"+(f.length?" · "+f.join(" · "):""),Object.assign(cfHtF(),dashX))}
function dashDrill(k,v){cfDash(Object.assign({},dashX,{[k]:v}))}
function setRun(id,v,fn){const i=$("#"+id);if(i){i.value=v;fn()}}
const DTOP_ACT={"Top client IPs":["Investigate this IP",n=>setRun("cf_ip",n,cfIp)],
 "Top hosts":["Investigate this hostname",n=>setRun("cf_host",n,cfHost)],
 "Top paths":["Filter the dashboard to this path",n=>dashDrill("path",n)],
 "Top countries":["Filter the dashboard to this country",n=>dashDrill("country",n)],
 "Top ASNs":["Filter the dashboard to this ASN",n=>dashDrill("asn",(String(n).match(/^AS(\d+)/)||[])[1]||n)],
 "Top referrers":["WHOIS this domain",n=>{const i=$("#cf_w_ip");if(i)i.value="";setRun("cf_w_host",n,cfWhois)}]};
const DBUCKET={"1 minute":60,"5 minutes":300,"1 hour":3600};
function u3(ms){return new Date(ms+108e5).toISOString().slice(0,16).replace("T"," ")}
function dashPick(label,bucket){const secs=DBUCKET[bucket],t=Date.parse(String(label).slice(0,16).replace(" ","T")+":00+03:00");
 if(!secs||isNaN(t))return;const since=u3(t),until=u3(t+secs*1e3);
 if(secs===60)cfRun("requests","Cloudflare sampled requests · "+since+" → "+until+" (UTC+3)",Object.assign(cfHtF(),dashX,{since,until,top:g("cf_t_n")}));
 else cfDash(Object.assign({},dashX,{since,until}))}
function cfUrl(){cfRun("url","Cloudflare URL response time",{url:g("cf_u_url"),match:g("cf_u_match"),status:g("cf_u_st"),cache:g("cf_u_cache"),ip:g("cf_u_ip"),top:g("cf_u_n")})}
function chartsNode(list){const grid=mk("div","dgrid");grid.style.marginBottom="16px";
 list.forEach(c=>grid.appendChild(dChart(c.title,c.t,c.series.map(([n,v],i)=>({name:n,color:DC[i],vals:v})),
  {fmt:DFMT[c.fmt]||dNum,noTotal:c.fmt!=="num"})));return grid}
// ---- Cloudflare traffic dashboard: inline SVG charts (palette validated for the dark chart surface) ----
const DC=["#3987e5","#d95926","#199e70","#c98500","#d55181","#008300"],DOTHER="#8f8cb8";
const DKEYS={status:["2xx","3xx","4xx","5xx","1xx"],cache:["hit","miss","dynamic","bypass","none","expired"],ttfb:["p50","p95","p99"]};
function dColor(kind,name){const i=(DKEYS[kind]||[]).indexOf(name);return i<0?DOTHER:DC[i]}
function dNum(n){n=+n||0;const a=Math.abs(n);return a>=1e9?(n/1e9).toFixed(2)+"B":a>=1e6?(n/1e6).toFixed(2)+"M":a>=1e3?(n/1e3).toFixed(2)+"k":String(Math.round(n))}
function dBytes(n){n=+n||0;const u=["B","KB","MB","GB","TB"];let i=0;while(Math.abs(n)>=1000&&i<4){n/=1000;i++}return (i?n.toFixed(2):n)+" "+u[i]}
function dMs(n){n=+n||0;return n>=1000?(n/1000).toFixed(1)+" s":Math.round(n)+" ms"}
const DFMT={num:dNum,bytes:dBytes,pct:v=>(+v||0).toFixed(2)+"%",ms:dMs};
function dNice(m){if(m<=0)return 1;const p=Math.pow(10,Math.floor(Math.log10(m))),f=m/p;return (f<=1?1:f<=2?2:f<=5?5:10)*p}
function dShort(lbls){const days=new Set(lbls.map(l=>String(l).slice(0,10)));
 return lbls.map(l=>{l=String(l);return l.length<16?l:days.size>1?l.slice(5,16):l.slice(11,16)})}
function dSpark(vals){const W=160,H=30,n=vals.length,m=Math.max(...vals,0)||1;if(n<2)return "";
 const pts=vals.map((v,i)=>(i*(W/(n-1))).toFixed(1)+","+(H-2-(v/m)*(H-4)).toFixed(1)).join(" ");
 return '<svg viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none" style="height:30px" aria-hidden="true"><polyline points="'+pts+'" fill="none" stroke="#3987e5" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>'}
function dChart(title,labels,series,o){
 const W=640,H=220,L=60,R=8,T=8,B=24,pw=W-L-R,ph=H-T-B,n=labels.length,fmt=o.fmt||dNum,sl=dShort(labels);
 const card=mk("div","dcard");card.appendChild(mk("div","sec",title));
 if(series.length>1){const lg=mk("div","dleg");series.forEach(s=>{const x=mk("span");const sw=mk("i");sw.style.background=s.color;
  x.appendChild(sw);x.appendChild(document.createTextNode(s.name));
  if(!o.noTotal)x.appendChild(mk("b",null,fmt(s.vals.reduce((a,b)=>a+b,0))));lg.appendChild(x)});card.appendChild(lg)}
 if(!n){card.appendChild(mk("div","nv","No data in this range."));return card}
 let max=0;for(let i=0;i<n;i++){max=o.stack?Math.max(max,series.reduce((a,s)=>a+(s.vals[i]||0),0)):Math.max(max,...series.map(s=>s.vals[i]||0))}
 max=dNice(max);const y=v=>T+ph-(v/max)*ph,step=pw/n;
 let s='<svg viewBox="0 0 '+W+' '+H+'" role="img" aria-label="'+esc(title)+'">';
 for(let k=0;k<=4;k++){const v=max*k/4,yy=y(v).toFixed(1);
  s+='<line x1="'+L+'" x2="'+(W-R)+'" y1="'+yy+'" y2="'+yy+'" stroke="#2a2850" stroke-width="1"/>'+
   '<text x="'+(L-6)+'" y="'+(+yy+4)+'" text-anchor="end" font-size="12" fill="#8f8cb8">'+esc(fmt(v))+'</text>'}
 const ticks=Math.min(6,n);for(let k=0;k<ticks;k++){const i=Math.round(k*(n-1)/Math.max(1,ticks-1));
  const last=k===ticks-1&&ticks>1;  // keep the last label inside the plot
  s+='<text x="'+(last?W-R:L+step*i+step/2).toFixed(1)+'" y="'+(H-6)+'" text-anchor="'+(last?"end":"middle")+'" font-size="12" fill="#8f8cb8">'+esc(sl[i])+'</text>'}
 if(o.stack){const bw=Math.max(1,step-(step>4?2:0));
  for(let i=0;i<n;i++){let base=0;const x=(L+step*i+(step-bw)/2).toFixed(1);
   series.forEach(sr=>{const v=sr.vals[i]||0;if(!v)return;const y1=y(base+v),seg=y(base)-y1,gap=base&&seg>3?1:0;  // 1px surface gap between segments
    s+='<rect x="'+x+'" y="'+y1.toFixed(1)+'" width="'+bw.toFixed(1)+'" height="'+Math.max(0,seg-gap).toFixed(1)+'" fill="'+sr.color+'"/>';base+=v})}}
 else series.forEach(sr=>{const pts=sr.vals.map((v,i)=>(L+step*i+step/2).toFixed(1)+","+y(v||0).toFixed(1)).join(" ");
  s+='<polyline points="'+pts+'" fill="none" stroke="'+sr.color+'" stroke-width="2" stroke-linejoin="round"/>'});
 for(let i=0;i<n;i++){const tip=labels[i]+"\n"+series.map(sr=>sr.name+": "+fmt(sr.vals[i]||0)).join("\n")+(o.pick?"\n"+o.pickTip:"");
  s+='<rect class="hv" data-i="'+i+'" x="'+(L+step*i).toFixed(1)+'" y="'+T+'" width="'+Math.max(step,1).toFixed(1)+'" height="'+ph+'"'+
   (o.pick?' style="cursor:pointer"':'')+'><title>'+esc(tip)+'</title></rect>'}
 const box=mk("div");box.innerHTML=s+'</svg>';card.appendChild(box);
 if(o.pick)box.querySelectorAll("rect.hv").forEach(r=>r.onclick=()=>o.pick(labels[+r.dataset.i]));
 return card}
function dTop(title,rows){const card=mk("div","dcard");card.appendChild(mk("div","sec",title));
 const g=mk("div","dtop"),m=Math.max(...rows.map(r=>r[1]),1),act=DTOP_ACT[title];
 rows.forEach(([name,v])=>{const ok=act&&name!==""&&name!=null&&!/^(unknown|none|null)$/i.test(name);
  const nm=mk("div","dn"+(ok?" lnk":""),name);nm.title=ok?act[0]+": "+name:name;
  if(ok)nm.onclick=()=>act[1](name);
  const bar=mk("div","db"),fill=mk("span");fill.style.width=(100*v/m).toFixed(1)+"%";bar.appendChild(fill);
  g.appendChild(nm);g.appendChild(bar);g.appendChild(mk("div","dvv",dNum(v)))});card.appendChild(g);return card}
function dashNode(d){const w=mk("div","dash");
 const tiles=mk("div","dtiles");d.tiles.forEach(t=>{const x=mk("div","dtile");x.appendChild(mk("div","dl",t.label));
  const v=mk("div","dv",t.value==null?"n/a":DFMT[t.fmt](t.value));
  if(t.value!=null&&t.prev){const c=100*(t.value-t.prev)/t.prev;v.appendChild(mk("span","dc",(c>=0?"↗ ":"↘ ")+Math.abs(c).toFixed(1)+"%"))}
  x.appendChild(v);const sp=mk("div");sp.innerHTML=dSpark(t.spark||[]);x.appendChild(sp);tiles.appendChild(x)});
 w.appendChild(tiles);
 const sec=DBUCKET[d.bucket],pk=sec?{pick:l=>dashPick(l,d.bucket),pickTip:sec===60?"Click: sampled requests in this minute":"Click: zoom in to this "+d.bucket}:{};
 const hint=mk("div","muted","↗ / ↘ = change vs the previous period of the same length · buckets: "+d.bucket+" · hover a chart for values"+
  (sec?", click a column to "+(sec===60?"list its sampled requests":"zoom in"):"")+" · click a top-list entry to look it up or filter by it");
 if(Object.keys(dashX).length){const c=mk("span","lnk"," · clear filters");c.style.cursor="pointer";c.style.color="var(--mint)";c.onclick=()=>cfDash();hint.appendChild(c)}
 w.appendChild(hint);
 const grid=mk("div","dgrid");
 grid.appendChild(dChart("Requests over time",d.t,[{name:"Requests",color:DC[0],vals:d.requests}],Object.assign({},pk)));
 grid.appendChild(dChart("Data transfer",d.t,[{name:"Data transfer",color:DC[0],vals:d.bytes}],Object.assign({fmt:dBytes},pk)));
 grid.appendChild(dChart("Requests by status code",d.t,d.status.map(([k,v])=>({name:k,color:dColor("status",k),vals:v})),Object.assign({stack:true},pk)));
 grid.appendChild(dChart("Requests by cache status",d.t,d.cache.map(([k,v])=>({name:k,color:dColor("cache",k),vals:v})),Object.assign({stack:true},pk)));
 if(d.ttfb.length)grid.appendChild(dChart("Edge TTFB percentiles",d.t,d.ttfb.map(([k,v])=>({name:k,color:dColor("ttfb",k),vals:v})),Object.assign({fmt:dMs,noTotal:true},pk)));
 w.appendChild(grid);
 if(d.tops.length){const tg=mk("div","dgrid tops");d.tops.forEach(([t,rows])=>tg.appendChild(dTop(t,rows)));w.appendChild(tg)}
 return w}
function cfRules(){cfRun("rules","Cloudflare rule search",{q:g("cf_r_q")})}
function cfDns(){cfRun("dns","Cloudflare DNS search",{name:g("cf_d_name"),content:g("cf_d_content"),type:g("cf_d_type")})}
function cfPosture(){cfRun("posture","Cloudflare security posture",{days:g("cf_days")})}
function cfLb(){cfRun("lb","Cloudflare load balancers & health",{})}
function cfAudit(){cfRun("audit","Cloudflare audit log",{email:g("cf_a_email"),action:g("cf_a_act"),resource:g("cf_a_res"),top:g("cf_a_n")})}
async function panLogs(){setBusy("log search (can take up to a minute)");
 const r=await api("/api/panlogs",{id:cur,ip:g("pl_ip"),dest_ip:g("pl_dst"),dest_type:{"normal destination":"normal","DNAT (translated) destination":"dnat"}[g("pl_dtype")]||"either",log_type:g("pl_type"),period:g("pl_period"),count:g("pl_n"),blocked:g("pl_blocked")==="blocked only",allowed:g("pl_blocked")==="allowed only"});show(r,"log search")}
async function fgLogs(){setBusy("traffic log search");
 const r=await api("/api/fglogs",{id:cur,ip:g("fl_ip"),dest_ip:g("fl_dst"),dest_type:{"normal destination":"normal","DNAT (translated) destination":"dnat"}[g("fl_dtype")]||"either",log_source:g("fl_src"),count:g("fl_n"),within:g("fl_w"),vdom:g("fl_vdom"),blocked:g("fl_blocked")==="blocked only",allowed:g("fl_blocked")==="allowed only"});show(r,"traffic log search")}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function cell(v){return v!==null&&typeof v==="object"?JSON.stringify(v):String(v==null?"":v)}
function findingsOf(){if(last&&last.data&&Array.isArray(last.data.findings))return last.data.findings;
 alert("Run an AppSec or SSL check first; the current output has no findings.");return null}
function dlText(name,type,text){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([text],{type}));a.download=name;a.click()}
function fname(ext){return "itsecops-"+(lastCtx.label||"report").replace(/[^a-z0-9]+/gi,"-").toLowerCase()+"-"+lastCtx.time.slice(0,10)+"."+ext}
function csvCell(v){let s=cell(v);if(/^[=+\-@\t\r]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"'}
function hasFindings(){return !!(last&&last.data&&Array.isArray(last.data.findings))}
function plain(v){return Array.isArray(v)?v.join(", "):cell(cellv(v))}
const NL=String.fromCharCode(10),CRLF=String.fromCharCode(13,10);
function exportCsv(){if(!last||last.error||!last.data){alert("Run a check first.");return}
 let rows;
 if(hasFindings())rows=[["severity","object","issue","detail"]].concat(last.data.findings.map(x=>[x.severity,x.object,x.issue,x.detail]));
 else{rows=[];buildSections(last.data).forEach(s=>{if(rows.length)rows.push([]);if(s.title)rows.push([s.title]);
  if(s.t==="kv")s.rows.forEach(([k,v])=>rows.push([k,plain(v)]));
  else if(s.t==="table"){rows.push(s.cols.map(hum));s.data.forEach(r=>rows.push(s.cols.map(c=>plain(r[c]))))}
  else if(s.t==="list")s.items.forEach(i=>rows.push([i]));
  else String(s.text||"").split(NL).forEach(l=>rows.push([l]))})}
 dlText(fname("csv"),"text/csv",rows.map(r=>r.map(csvCell).join(",")).join(CRLF))}
function sectionsHtml(){return buildSections(last.data).map(s=>{let h=s.title?"<h2>"+esc(s.title)+"</h2>":"";
 if(s.t==="kv")h+="<table>"+s.rows.map(([k,v])=>"<tr><th>"+esc(k)+"</th><td>"+esc(plain(v))+"</td></tr>").join("")+"</table>";
 else if(s.t==="table")h+="<table><tr>"+s.cols.map(c=>"<th>"+esc(hum(c))+"</th>").join("")+"</tr>"+s.data.map(r=>
   "<tr>"+s.cols.map(c=>"<td>"+esc(plain(r[c]))+"</td>").join("")+"</tr>").join("")+"</table>";
 else if(s.t==="list")h+="<ul>"+s.items.map(i=>"<li>"+esc(i)+"</li>").join("")+"</ul>";
 else h+="<pre>"+esc(s.text)+"</pre>";return h}).join("")}
function table(rows){if(!rows||!rows.length)return "<p>None.</p>";const cols=[...new Set(rows.flatMap(r=>Object.keys(r)))];
 return "<table><tr>"+cols.map(c=>"<th>"+esc(c)+"</th>").join("")+"</tr>"+rows.map(r=>"<tr>"+cols.map(c=>
  "<td"+(c==="severity"?' class="'+esc(r[c])+'"':"")+">"+esc(cell(r[c]))+"</td>").join("")+"</tr>").join("")+"</table>"}
function exportHtml(){if(!last||last.error||!last.data){alert("Run a check first.");return}
 const f=hasFindings()?last.data.findings:null,d=last.data,v=last.verdict||{};
 const html='<!doctype html><html><head><meta charset="utf-8"><title>'+esc(lastCtx.label)+' report</title><style>'+
 'body{font:14px system-ui,sans-serif;margin:24px;color:#111}table{border-collapse:collapse;width:100%;margin:8px 0 20px}'+
 'th,td{border:1px solid #ccc;padding:5px 8px;text-align:left;vertical-align:top;font-size:13px;word-break:break-word}th{background:#f2f2f2}'+
 'pre{white-space:pre-wrap;background:#f7f7f7;padding:8px;border:1px solid #ddd}td.high{color:#b00020;font-weight:700}td.medium{color:#a35200;font-weight:700}td.low{color:#555}</style></head><body>'+
 '<h1>'+esc(lastCtx.label)+'</h1><p>Device: '+esc(lastCtx.device||"n/a")+' · Generated: '+esc(lastCtx.time)+' · ITSec Ops</p>'+
 '<h2>Result: '+esc(v.label||"")+'</h2>'+(last.request?'<p>Scope: '+esc(last.request)+'</p>':'')+
 (last.summary&&last.summary.length?"<ul>"+last.summary.map(x=>"<li>"+esc(x)+"</li>").join("")+"</ul>":"")+
 (f?'<h2>Findings</h2>'+table(f)+'<h2>Inventory</h2>'+table(d.inventory)+
 '<h2>Notes</h2>'+(d.notes||[]).map(n=>"<p>"+esc(n)+"</p>").join(""):sectionsHtml())+'</body></html>';
 dlText(fname("html"),"text/html",html)}
api("/api/catalog").then(c=>catalog=c);loadProfiles();
</script></body></html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    srv.allowed_hosts = {"127.0.0.1:%d" % a.port, "localhost:%d" % a.port}
    url = "http://127.0.0.1:%d/?t=%s" % (a.port, TOKEN)
    print("ITSec Ops (read-only). Open:\n  " + url + "\nCtrl+C to stop; credentials are cleared on exit.")
    if not a.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
