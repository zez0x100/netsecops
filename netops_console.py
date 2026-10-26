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
- The tool talks to device management APIs over HTTPS from THIS machine.
- AppSec checks (WAF / profile coverage, SSL posture, ASM request log,
  PAN log search) are read-only.
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
        {"id": "polmatch", "group": "Policy", "label": "Security policy match (test)", "cmd": "<test><security-policy-match><source>{src}</source><destination>{dst}</destination><destination-port>{port}</destination-port><protocol>{proto}</protocol></security-policy-match></test>",
         "params": [P("src", "Source IP", "10.1.1.10"), P("dst", "Destination IP", "10.2.2.20"),
                    P("port", "Dest port", "443", "443"), P("proto", "Protocol #", "6 = TCP", "6")]},
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
         "params": [P("filter", "Name, external IP or mapped IP", "203.0.113.10", required=False)]},
        {"id": "ipsec", "group": "VPN", "label": "IPsec tunnels", "path": "/api/v2/monitor/vpn/ipsec"},
        {"id": "polstats", "group": "Policy", "label": "Firewall policy hit counts", "path": "/api/v2/monitor/firewall/policy"},
        {"id": "sessions", "group": "Sessions", "label": "Session list (IPv4)", "path": "/api/v2/monitor/firewall/session?count={count}&ip_version=ipv4",
         "params": [P("count", "Max rows", "20", "20")]},
        {"id": "pollookup", "group": "Policy", "label": "Policy lookup", "path": "/api/v2/monitor/firewall/policy-lookup?srcintf={srcintf}&sourceip={src}&dest={dst}&protocol={proto}&destport={port}",
         "params": [P("srcintf", "Source interface", "port1"), P("src", "Source IP", "10.1.1.10"),
                    P("dst", "Destination IP", "10.2.2.20"), P("proto", "Protocol", "tcp", "tcp"),
                    P("port", "Dest port", "443", "443")]},
    ],
}
CATALOG_PUBLIC = CATALOG  # contains no secrets
PROFILE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_profiles.json")
HEALTH_CHECKS = {
    "f5": ("version", "failover", "cpu", "mem"),
    "paloalto": ("sysinfo", "resources", "ha"),
    "fortigate": ("status", "resources", "ha"),
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
    host = (b.get("host") or "").strip()
    if not HOST_RE.match(host):
        return {"ok": False, "error": "invalid host"}
    try:
        port = int(b.get("port") or 443)
    except (TypeError, ValueError):
        return {"ok": False, "error": "invalid port"}
    if not 1 <= port <= 65535:
        return {"ok": False, "error": "port must be between 1 and 65535"}
    name = b.get("name")
    name = name.strip() if isinstance(name, str) else ""
    sess = {"vendor": vendor, "host": host, "port": port,
            "insecure": bool(b.get("insecure")), "name": (name or host)[:40]}
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
    return {"ok": True, "id": sid, "name": sess["name"], "vendor": vendor, "host": host}


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
    else:
        prefixes = ("/mgmt/tm/",) if v == "f5" else ("/api/v2/monitor/", "/api/v2/cmdb/")
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
        root = pan_xml(sess, {"type": "op", "cmd": cmd}, 30)
        e = root.find(".//rules/entry") if root is not None else None
        res["flow_test"] = {}
        if root is None:
            notes.append("security-policy-match test failed or was rejected; no verdict.")
        elif e is None:
            verdict = {"label": "NO RULE RETURNED for this flow", "kind": "info"}
        else:
            act = (e.findtext("action") or "").strip().lower()
            name = e.get("name")
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
            notes.append("policy-lookup failed (HTTP %s); endpoint/parameters vary by FortiOS version." % st)
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
        inner = "timeout -k 5 %d tcpdump -ni %s -s %d -c %d%s -w %s %s > %s 2>&1; chmod 600 %s 2>&1" % (
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
        poll = ("if [ -e %s ]; then echo FINISHED; cat %s; ls -l %s 2>&1; "
                "echo PMS_BYTES=$(wc -c < %s 2>/dev/null); fi") % (tdone, tlog, keep, keep_pms)
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
        if os.path.basename(keep) not in out or "No such file" in out or "cannot access" in out:
            raise ValueError("capture produced no file. tcpdump output: " + out.strip()[:400])
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
        flt = urllib.parse.quote("requestStatus eq '%s'" % stx)
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
                for uf, uo in ((True, True), (True, False), (False, True), (False, False)):
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
                page = [i for i in page if str(i.get("requestStatus") or "").lower() == stx]
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
                if status not in ("blocked", "alerted", "passed"):
                    raise ValueError("invalid status")
                parts.append("requestStatus eq '%s'" % status)
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
            if not parts and not hip and not urlq and not hostq:
                raise ValueError("enter a client IP, True-Client-IP, hostname or URL path and/or choose a status")
            flt, top = " and ".join(parts), num(b.get("top"), 1, 200, 50, "max rows")

            def hostok(i):
                return not hostq or hostq in asm_hostname(i).lower()

            def hit0(i):  # local match (no time test), used to verify device-side filters
                u = str(first(i, "url", "uri") or "")
                return (not urlq or urlq.lower() in u.lower()) and (not hip or asm_header_ip(i) == hip) and hostok(i)

            def hit(i):  # local match while paging
                return hit0(i) and asm_recent(i, cutoff)
        if b.get("mode") != "supportid" and (hip or urlq or hostq):
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
                    [(f, "contains(%s,'%s')", hostq) for f in ("hostname", "host")]
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
            if not ok or not isinstance(data, dict):
                return {"ok": False, "status": st, "error": "request log query failed (HTTP %s). Is ASM / Advanced "
                        "WAF provisioned and does the account have access?" % st}
            items = [i for i in data.get("items", []) if asm_recent(i, cutoff)]
        if b.get("mode") == "supportid":
            # Some TMOS versions ignore $filter on this collection; never trust position, match the ID.
            def has_id(i):
                return str(i.get("supportId")) == sid or ('"%s"' % sid) in json.dumps(i)
            seen = [str(i.get("supportId")) for i in items][:5]
            same = [i for i in items if has_id(i)]
            if not same:
                for skip in range(0, 1000, 200):
                    path = "/mgmt/tm/asm/events/requests?$top=200&$skip=%d" % skip
                    st, ok, data = rest_get(sess, path)
                    page = data.get("items", []) if ok and isinstance(data, dict) else []
                    seen = seen or [str(i.get("supportId")) for i in page][:5]
                    same = [i for i in page if has_id(i)]
                    if same or len(page) < 200:
                        break
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
        raw = it.get("rawRequest") or {}
        http_text = raw.get("httpRequest") if isinstance(raw, dict) else raw
        http_text = http_text if isinstance(http_text, str) else ""
        head, _, body = http_text.replace("\r\n", "\n").partition("\n\n")
        hlines = head.split("\n")
        hdrs = {}
        for ln in hlines[1:]:
            k, _, val = ln.partition(":")
            if val:
                hdrs.setdefault(k.strip().lower(), val.strip())
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
        kind = "bad" if "block" in status else "warn" if "alert" in status or violations else "ok"
        vip_ip = first(it, "destinationIp", "destinationIP", "destIp", "serverIp") or ""
        vip_port = first(it, "destinationPort", "destPort", "serverPort") or ""
        vip = "%s:%s" % (vip_ip, vip_port) if vip_ip and vip_port else str(vip_ip)
        vs_name = first(it, "virtualServerName", "virtualServer")
        if isinstance(vs_name, dict):
            vs_name = vs_name.get("name") or vs_name.get("fullPath")
        if vs_name:
            vip = ("%s (%s)" % (vip, vs_name)) if vip else str(vs_name)
        data = {"support_id": sid,
                "time": utc3(first(it, "requestDatetime", "occurrenceTime", "dateTime", "time")) or "",
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
        if not FILE_RE.fullmatch(name) or not os.path.isfile(path):
            return self._send(404, {"error": "not found"})
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.tcpdump.pcap" if name.endswith(".pcap") else
                         "text/plain" if name.endswith((".pms", ".conf")) else "application/octet-stream")
        self.send_header("Content-Disposition", 'attachment; filename="%s"' % name)
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
                  "/api/f5capture": do_f5_capture, "/api/profile/save": do_profile_save,
                  "/api/profile/delete": do_profile_delete, "/api/health": do_health,
                  "/api/appsec": do_appsec, "/api/f5asm": do_f5_asm, "/api/panlogs": do_pan_logs,
                  "/api/fglogs": do_fg_logs, "/api/adminaudit": do_admin_audit, "/api/f5sync": do_f5_sync, "/api/pancapture": do_pan_capture,
                  "/api/backup": do_backup}
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
.fortigate{background:#7C6CFF33;color:#b3a9ff}
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
</style></head><body>
<header><svg class="logo" viewBox="0 0 36 36" role="img" aria-label="ITSec Ops logo"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2EE6C5"/><stop offset=".6" stop-color="#7C6CFF"/><stop offset="1" stop-color="#FF7A59"/></linearGradient></defs><path d="M18 2.5 31.5 7.5v9.5c0 8-5.6 13.6-13.5 16.5C10.1 30.6 4.5 25 4.5 17V7.5Z" fill="#14132a" stroke="url(#lg)" stroke-width="2.2" stroke-linejoin="round"/><path d="m12 13 6 5-6 5" fill="none" stroke="#2EE6C5" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M20.5 24h5" stroke="#FF7A59" stroke-width="2.6" stroke-linecap="round"/></svg><h1>ITSec Ops</h1><small>read-only troubleshooting · F5 · Palo Alto · FortiGate · local only</small></header>
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
    <option value="fortigate">FortiGate (REST API)</option></select>
    <label>Display name (optional)</label><input id="name" placeholder="e.g. edge-fw-01">
    <div class="row"><div><label>Mgmt host / IP</label><input id="host"></div>
    <div style="max-width:90px"><label>Port</label><input id="port" value="443"></div></div>
    <div id="f-user"><label>Username</label><input id="username" autocomplete="off"></div>
    <div id="f-pass"><label>Password</label><input id="password" type="password" autocomplete="off"></div>
    <div id="f-key"><label id="keylbl">API key</label><input id="apikey" type="password" autocomplete="off"></div>
    <div class="chk"><input type="checkbox" id="insecure"><span>Skip TLS verification (self-signed mgmt cert). Credentials are then sent to whatever answers at that address: use only on a trusted network.</span></div>
    <div style="margin-top:12px"><button class="primary" onclick="connect()">Connect</button></div>
    <div id="cerr" class="err"></div>
  </div>
  <div class="card"><h3>Session</h3>
    <button onclick="showAudit()">View audit log</button>
    <p class="muted" style="margin:8px 0 0">Credentials stay in memory of the Python process. Closing it clears everything.</p></div>
</div>
<div>
  <div id="appsec"></div>
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
fortigate:"GET path, e.g. /api/v2/monitor/system/status"};
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
function fields(){const v=$("#vendor").value;
 $("#f-user").style.display=v==="fortigate"?"none":"";
 $("#f-pass").style.display=v==="fortigate"?"none":"";
 $("#f-key").style.display=v==="f5"?"none":"";
 $("#keylbl").textContent=v==="fortigate"?"REST API token":"API key (or leave blank and use user/password)"}
$("#vendor").onchange=fields;fields();
async function connect(){$("#cerr").textContent="Connecting…";
 const b={vendor:$("#vendor").value,name:$("#name").value,host:$("#host").value,port:$("#port").value,
 username:$("#username").value,password:$("#password").value,apikey:$("#apikey").value,insecure:$("#insecure").checked};
 const r=await api("/api/connect",b);
 if(!r.ok){$("#cerr").textContent=r.error;return}
 $("#cerr").textContent="";$("#password").value="";$("#apikey").value="";
 devices.push(r);select(r.id)}
async function disconnect(id,ev){ev.stopPropagation();await api("/api/disconnect",{id});
 devices=devices.filter(d=>d.id!==id);if(cur===id)cur=devices.length?devices[0].id:null;renderAll()}
function select(id){cur=id;renderAll()}
function dev(){return devices.find(d=>d.id===cur)}
function renderAll(){renderDevs();renderChecks();renderAppsec();renderIp();renderF5();renderHealth();const d=dev();
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
 san:"SAN",cn:"CN",pcap:"PCAP",ms:"ms",sip:"SIP"};
const LABEL={t:"Time",fullPath:"Name",vip:"VS",body:"Request body",request_headers:"Request headers"};
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
 if(cols.includes("vs_name")||cols.includes("pool_member_ip")||cols.includes("policy_name"))return {t:"table",title,cols,data};  // F5 VS overview: keep the column order given
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
function renderIp(){const box=$("#iplookup");box.innerHTML="";const d=dev();if(!d)return;const v=d.vendor;
 let h='<div class="card"><h3>IP lookup · '+(v==="f5"?"pools, nodes, virtual servers, data groups, local traffic policies":"policy references")+'</h3><div class="row3">'+fld("ip_ip","IP address","203.0.113.7");
 if(v!=="f5"){
  h+=v==="paloalto"?fld("ip_vsys","vsys","vsys1","vsys1"):fld("ip_vdom","VDOM (optional)","root");
 }
 h+='</div><div style="margin-top:10px"><button class="primary" onclick="ipLookup()">Check</button></div></div>';
 if(v==="f5")h+='<div class="card"><h3>Hostname lookup · virtual server and local traffic policy</h3><div class="row3">'+fld("fh_host","Hostname","app.example.com")+
  '</div><div style="margin-top:10px"><button class="primary" onclick="f5Host()">Find virtual server / policy</button></div></div>';
 box.innerHTML=h}
async function f5Host(){setBusy("hostname lookup");
 const r=await api("/api/f5host",{id:cur,hostname:g("fh_host")});show(r,"hostname lookup")}
async function ipLookup(){setBusy("IP lookup");
 const r=await api("/api/ipcheck",{id:cur,ip:g("ip_ip"),mode:"refs",vsys:g("ip_vsys"),vdom:g("ip_vdom")});show(r,"IP lookup")}
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
 '<div style="margin-top:8px"><button class="primary" onclick="f5Capture()">Capture &amp; download</button></div></div>'}
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
function renderAppsec(){const box=$("#appsec");box.innerHTML="";const d=dev();if(!d)return;const v=d.vendor;
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
 const r=await api("/api/f5asm",{id:cur,mode:m,support_id:g("asm_sid"),ip:g("asm_ip"),header_ip:g("asm_tci"),hostname:g("asm_host"),url:g("asm_url"),status:m==="tophosts"?g("asm_tst"):g("asm_st"),top:g("asm_top"),scan:g("asm_scan"),within:m==="tophosts"?g("asm_tw"):m==="supportid"?g("asm_sw"):g("asm_w")});
 show(r,m==="supportid"?"support ID lookup":m==="tophosts"?"top hostnames by violations":"ASM request search")}
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
