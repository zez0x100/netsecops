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
  in device_profiles.json; usernames, passwords, and API keys are never saved there.
- Optional saved logins (opt-in per device): credentials encrypted with Windows DPAPI, bound to the Windows
  account AND to a passphrase, in saved_logins.dat (git-ignored). One passphrase reconnects every device.
- Read-only by construction: every check is a GET (F5, FortiGate) or a <show>/<test>
  operational command (PAN-OS; <test> limited to an allowlist). The raw box enforces the same rules.
- EXCEPTION: the 'F5 active tools' (log search, tcpdump) run fixed shell-command templates
  through iControl REST util/bash. They need the Administrator role and an explicit tick-box.
  The capture (and .pms key file) is kept in /var/tmp on the BIG-IP, readable by root only.
- EXCEPTION: 'Configuration backup' on F5 saves a UCS archive on the BIG-IP (same tick-box); on PAN-OS and
  FortiGate it is a read-only export with no tick-box. Backups are saved in ./captures and downloaded by the browser.
- PAN-OS packet capture (<debug><dataplane><packet-diag>) is DISABLED (PAN_CAPTURE_ENABLED = False): the API
  refuses it and the page does not offer it, so nothing on a Palo Alto is changed by this console.
- EXCEPTION: 'Download a file or folder' on F5 reads any path through util/bash (same tick-box); a folder is
  packed into a .tar.gz in /var/tmp first and removed afterwards. Files holding secrets need a second tick-box.
- SSH (F5, FortiGate, Palo Alto) runs this PC's own OpenSSH client (ssh -p <port> -l <user> <device>), either in
  a terminal inside the page (a Windows pseudo-console, ConPTY, relayed to the page) or in a separate window. In the
  page, keystrokes, the password too, pass through this process to ssh: they are never stored, logged or shown to the
  AI, and only "opened" / "closed" go to the audit log. What is done in that session is up to the person typing:
  it is not read-only. The AI assistant has no SSH tool.
- The tool talks to device management APIs over HTTPS from THIS machine.
- AppSec checks (WAF / profile coverage, SSL posture, ASM request log,
  PAN log search) are read-only.
- Cloudflare: an API token (give it read permissions only). Configuration is read with REST GETs; analytics
  are POSTed to the GraphQL Analytics API, which only answers queries (the raw box refuses mutations).
"""
import argparse
import atexit
import base64
import calendar
import codecs
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
import shutil
import socket
import ssl
import struct
import subprocess
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
        {"id": "perf", "group": "Resources", "label": "Performance (all stats)", "path": "/mgmt/tm/sys/performance/all-stats"},
        {"id": "resutil", "group": "Resources", "label": "Performance dashboard (CPU per core, memory, subsystems, top processes, "
         "disk; history and processes need the active-tools tick-box)", "handler": "f5_perf",
         "params": [P("range", "Time range: 30m-24h", "6h", "1h", required=False)]},
        {"id": "ifaces", "group": "Network", "label": "Interface stats", "path": "/mgmt/tm/net/interface/stats"},
        {"id": "vstop", "group": "LTM", "label": "Top virtual servers by connections / traffic (busiest first: current, "
         "total and max connections, bits in/out)", "handler": "f5_vs_top",
         "params": [P("by", "Sort by: current, total, max, bits or packets", "current", "current", required=False),
                    P("top", "How many (1-500)", "20", "20", required=False)]},
        {"id": "vsall", "group": "LTM", "label": "All virtual servers: names, IPs, pools and up/down status (no connection "
         "counts)", "path": "/mgmt/tm/ltm/virtual/stats"},
        {"id": "vsone", "group": "LTM", "label": "One virtual server stats", "path": "/mgmt/tm/ltm/virtual/{vs}/stats",
         "params": [P("vs", "Virtual server", "~Common~my_vs")]},
        {"id": "polsearch", "group": "LTM", "label": "Local traffic policy search (rules and conditions)",
         "path": "/mgmt/tm/ltm/policy?expandSubcollections=true",
         "params": [P("policy", "Policy name (or part of it)", "my_policy")]},
        {"id": "snat", "group": "LTM", "label": "Source NAT for an IP (standalone SNAT objects whose origins include it)",
         "handler": "f5_snat", "params": [P("ip", "Source IP", "10.1.1.10")]},
        {"id": "poolall", "group": "LTM", "label": "All pool stats", "path": "/mgmt/tm/ltm/pool/stats"},
        {"id": "poolmem", "group": "LTM", "label": "Pool member stats", "path": "/mgmt/tm/ltm/pool/{pool}/members/stats",
         "params": [P("pool", "Pool", "~Common~my_pool")]},
        {"id": "conns", "group": "LTM", "label": "Live connections by client IP (which pool member a client is on: "
         "tmsh show sys connection)", "handler": "f5_conns",
         "params": [P("ip", "Client IP", "203.0.113.5"), P("vip", "Virtual server IP (optional)", "10.1.1.10", required=False)]},
    ],
    "paloalto": [
        {"id": "sysinfo", "group": "Device", "label": "System info", "cmd": "<show><system><info/></system></show>"},
        {"id": "resutil", "group": "Device", "label": "Resource utilization (management / dataplane CPU, memory, sessions, packet buffers, disk)",
         "handler": "pan_resources",
         "params": [P("range", "Time range: 1h-24h, 1d-7d or 1w-13w", "3d", "1h", required=False)]},
        {"id": "resources", "group": "Device", "label": "System resources (top)", "cmd": "<show><system><resources/></system></show>"},
        {"id": "apptraffic", "group": "Traffic", "label": "Application traffic volume over a period (full period from the "
         "summary database: sessions, bytes, average per hour and Mbit/s; e.g. web-browsing = HTTP, ssl = HTTPS)",
         "handler": "pan_app_traffic",
         "params": [P("period", "Time range: last-hour, last-6-hrs, last-12-hrs, last-24-hrs, last-7-days, last-30-days",
                      "last-24-hrs", "last-24-hrs", required=False),
                    P("app", "Application (or part of it; 'http' = web-browsing and http-*)", "web-browsing", required=False),
                    P("top", "How many applications (1-500)", "50", "50", required=False)]},
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
        {"id": "snat", "group": "Policy", "label": "Source NAT for an IP (what the IP is translated to as source; "
         "optional destination for the rule the firewall uses)", "handler": "pan_snat",
         "params": [P("ip", "Source IP", "10.1.1.10"), P("dst", "Destination IP (optional: the rule actually used)", "203.0.113.10", required=False),
                    P("port", "Destination port (optional)", "443", required=False),
                    P("proto", "Protocol: tcp, udp or icmp", "tcp", "tcp", required=False),
                    P("from", "Source zone (optional)", "trust", required=False),
                    P("to", "Destination zone (optional)", "untrust", required=False),
                    P("vsys", "vsys", "vsys1", "vsys1")]},
        {"id": "urlcat", "group": "Policy", "label": "URL category lookup", "cmd": "<test><url>{url}</url></test>",
         "params": [P("url", "URL or domain", "www.example.com/path")]},
    ],
    "fortigate": [
        {"id": "status", "group": "Device", "label": "System status", "path": "/api/v2/monitor/system/status"},
        {"id": "license", "group": "Device", "label": "License status", "path": "/api/v2/monitor/license/status"},
        {"id": "resutil", "group": "Resources", "label": "Resource utilization (CPU, memory / conserve mode, disk, sessions, setup rate)",
         "handler": "fg_resources",
         "params": [P("range", "Time range: up to 24h charted; longer adds conserve-mode history", "3d", "1h", required=False)]},
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
        {"id": "snat", "group": "Policy", "label": "Source NAT for an IP (what the IP is translated to as source: "
         "policy NAT / IP pools, central SNAT, VIP nat-source-vip; optional destination for the policy used)",
         "handler": "fg_snat",
         "params": [P("ip", "Source IP", "10.1.1.10"), P("dst", "Destination IP (optional: the rule actually used)", "203.0.113.10", required=False),
                    P("port", "Destination port (optional)", "443", required=False),
                    P("proto", "Protocol: tcp, udp or icmp", "tcp", "tcp", required=False),
                    P("vdom", "VDOM (optional)", "root", required=False)]},
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
# contains no secrets; entries marked "hidden" are not listed in the page
CATALOG_PUBLIC = {v: [c for c in cs if not c.get("hidden")] for v, cs in CATALOG.items()}
PROFILE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_profiles.json")



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


def rest_get(sess, path, timeout=None):
    # Large reads (expanded sub-collections) on a big device can take well over 20 s.
    status, raw = http(sess, "GET", path, sess["hdr"], timeout=timeout or (60 if "expandSubcollections" in path else 20))
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


# ---- SSH: open this PC's OpenSSH client in a new terminal window (nothing runs through the console) ----------
SSH_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._@\\-]{0,63}$")


# Always added: hmac-sha1, which older TMOS / FortiOS / PAN-OS SSH servers still need and OpenSSH 10 no longer offers by
# default. '+' appends to OpenSSH's list, so a device that supports SHA-2 MACs still negotiates those.
SSH_ALWAYS = ["-o", "MACs=+hmac-sha1"]
# Added to this one connection only when 'Allow older algorithms' is ticked (old FortiOS / PAN-OS / TMOS SSH servers).
# MD5, DH group 1, 3DES and DSA are left out on purpose. (No MACs here: the first -o for an option wins.)
SSH_LEGACY = ["-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1",
              "-o", "HostKeyAlgorithms=+ssh-rsa", "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
              "-o", "Ciphers=+aes128-cbc,aes256-cbc"]


def ssh_client():
    """Path of the OpenSSH client: Windows' built-in one first, then whatever 'ssh' is on PATH."""
    win = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "OpenSSH", "ssh.exe")
    return win if os.name == "nt" and os.path.isfile(win) else shutil.which("ssh")


def do_ssh(b):
    try:
        sess, argv, shown = ssh_request(b)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    host = argv[-1]
    exe = ssh_client()
    if not exe:
        return {"ok": False, "error": "no OpenSSH client found on this PC. On Windows: Settings > System > Optional "
                                      "features > OpenSSH Client. Or run it yourself: " + shown}
    if os.name != "nt":
        return {"ok": True, "launched": False, "command": shown,
                "verdict": {"label": "Run this in a terminal: " + shown, "kind": "info"}, "summary": [
                    "Opening a terminal window is only automatic on Windows; copy the command above."]}
    # Run inside cmd /k so the window stays open when ssh ends: a refused or failed connection would otherwise close
    # it at once and the error would never be seen. Only validated characters reach this line (no cmd metacharacters).
    cmd = os.environ.get("ComSpec") or os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
    line = ('"%s" /k title SSH %s & "%s" %s & echo. & echo ssh ended. Type exit or close this window.'
            % (cmd, host, exe, " ".join(argv)))
    try:
        subprocess.Popen(line, creationflags=subprocess.CREATE_NEW_CONSOLE, close_fds=True)
    except OSError as e:
        return {"ok": False, "error": "could not start ssh: %s. Run it yourself: %s" % (e, shown)}
    audit(sess, "SSH window opened: %s" % shown)
    return {"ok": True, "launched": True, "command": shown,
            "verdict": {"label": "SSH window opened: " + shown, "kind": "ok"},
            "summary": ["Look for the new window titled 'SSH %s' (check the taskbar if it opened behind the browser)."
                        % host,
                        "Type the password in that window (the console never sees it). If the connection fails, the "
                        "error stays in the window.",
                        "The first connection asks you to confirm the device's host key: check the fingerprint.",
                        "Everything typed in that window goes straight to the device, outside the console's "
                        "read-only checks."] + (["Older algorithms (SHA-1 key exchange, ssh-rsa, AES-CBC) were "
                                                 "allowed for this connection only."] if b.get("legacy") else
                                                ["If it says 'Unable to negotiate ... no matching key exchange / host key "
                                                 "type / cipher found', tick 'Allow older algorithms' and open it again."])}


# ---- In-page SSH terminal: this PC's ssh on a Windows pseudo-console (ConPTY), relayed to the page ------------------
# Keystrokes (the password too) pass through this process on their way to ssh; they are never stored, logged or shown
# to the AI. Only "opened" / "closed" go to the audit log. Standard library only (ctypes), Windows 10 1809 or later.
TERMS = {}
TERM_LOCK = threading.Lock()
TERM_MAX = 6            # open terminals at a time
TERM_KEEP = 2_000_000   # characters of output kept for the page to fetch
TERM_IDLE = 180         # seconds without the page polling (tab closed) before the session is ended


class ConPty:
    """One process attached to a Windows pseudo-console: write() keystrokes, read() its VT output."""

    def __init__(self, cmdline, cols, rows):
        import ctypes
        from ctypes import wintypes as W
        self.ct, k = ctypes, ctypes.WinDLL("kernel32", use_last_error=True)
        self.k = k

        class COORD(ctypes.Structure):
            _fields_ = [("X", W.SHORT), ("Y", W.SHORT)]

        class SI(ctypes.Structure):
            _fields_ = [("cb", W.DWORD), ("lpReserved", W.LPWSTR), ("lpDesktop", W.LPWSTR), ("lpTitle", W.LPWSTR),
                        ("dwX", W.DWORD), ("dwY", W.DWORD), ("dwXSize", W.DWORD), ("dwYSize", W.DWORD),
                        ("dwXCountChars", W.DWORD), ("dwYCountChars", W.DWORD), ("dwFillAttribute", W.DWORD),
                        ("dwFlags", W.DWORD), ("wShowWindow", W.WORD), ("cbReserved2", W.WORD),
                        ("lpReserved2", ctypes.c_void_p), ("hStdInput", W.HANDLE), ("hStdOutput", W.HANDLE),
                        ("hStdError", W.HANDLE)]

        class SIEX(ctypes.Structure):
            _fields_ = [("StartupInfo", SI), ("lpAttributeList", ctypes.c_void_p)]

        class PI(ctypes.Structure):
            _fields_ = [("hProcess", W.HANDLE), ("hThread", W.HANDLE), ("dwProcessId", W.DWORD), ("dwThreadId", W.DWORD)]
        self.COORD = COORD
        H, P, vp = W.HANDLE, ctypes.POINTER, ctypes.c_void_p
        k.CreatePipe.argtypes = [P(H), P(H), vp, W.DWORD]
        k.CreatePseudoConsole.argtypes = [COORD, H, H, W.DWORD, P(vp)]
        k.CreatePseudoConsole.restype = ctypes.c_long
        k.ResizePseudoConsole.argtypes = [vp, COORD]
        k.ResizePseudoConsole.restype = ctypes.c_long
        k.ClosePseudoConsole.argtypes = [vp]
        k.ClosePseudoConsole.restype = None
        k.InitializeProcThreadAttributeList.argtypes = [vp, W.DWORD, W.DWORD, P(ctypes.c_size_t)]
        k.UpdateProcThreadAttribute.argtypes = [vp, W.DWORD, ctypes.c_size_t, vp, ctypes.c_size_t, vp, vp]
        k.DeleteProcThreadAttributeList.argtypes = [vp]
        k.CreateProcessW.argtypes = [W.LPCWSTR, W.LPWSTR, vp, vp, W.BOOL, W.DWORD, vp, W.LPCWSTR, P(SIEX), P(PI)]
        k.ReadFile.argtypes = [H, vp, W.DWORD, P(W.DWORD), vp]
        k.WriteFile.argtypes = [H, vp, W.DWORD, P(W.DWORD), vp]
        k.CloseHandle.argtypes = [H]
        k.TerminateProcess.argtypes = [H, W.UINT]
        k.WaitForSingleObject.argtypes = [H, W.DWORD]
        k.WaitForSingleObject.restype = W.DWORD
        k.GetExitCodeProcess.argtypes = [H, P(W.DWORD)]
        self.W = W
        in_r, in_w, out_r, out_w = H(), H(), H(), H()
        if not k.CreatePipe(ctypes.byref(in_r), ctypes.byref(in_w), None, 0) or \
                not k.CreatePipe(ctypes.byref(out_r), ctypes.byref(out_w), None, 0):
            raise OSError("CreatePipe failed (%d)" % ctypes.get_last_error())
        self.hpc = vp()
        hr = k.CreatePseudoConsole(COORD(cols, rows), in_r, out_w, 0, ctypes.byref(self.hpc))
        if hr != 0:
            for h in (in_r, in_w, out_r, out_w):
                k.CloseHandle(h)
            raise OSError("this Windows has no pseudo-console (needs Windows 10 1809 or later): HRESULT 0x%08X"
                          % (hr & 0xFFFFFFFF))
        size = ctypes.c_size_t()
        k.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        self._attr = ctypes.create_string_buffer(size.value)
        si = SIEX()
        si.StartupInfo.cb = ctypes.sizeof(SIEX)
        si.StartupInfo.dwFlags = 0x100   # STARTF_USESTDHANDLES with none: the child must use the pseudo-console only
        si.lpAttributeList = ctypes.cast(self._attr, vp)
        if not k.InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, ctypes.byref(size)) or \
                not k.UpdateProcThreadAttribute(si.lpAttributeList, 0, 0x00020016, self.hpc, ctypes.sizeof(vp), None, None):
            raise OSError("pseudo-console attribute failed (%d)" % ctypes.get_last_error())
        pi = PI()
        buf = ctypes.create_unicode_buffer(cmdline)
        ok = k.CreateProcessW(None, buf, None, None, False, 0x00080000 | 0x00000400, None, None,  # EXTENDED_STARTUPINFO, UNICODE_ENV
                              ctypes.byref(si), ctypes.byref(pi))
        err = ctypes.get_last_error()
        k.DeleteProcThreadAttributeList(si.lpAttributeList)
        k.CloseHandle(in_r)    # the pseudo-console holds its own copies
        k.CloseHandle(out_w)
        if not ok:
            k.ClosePseudoConsole(self.hpc)
            k.CloseHandle(in_w)
            k.CloseHandle(out_r)
            raise OSError("could not start ssh (%d)" % err)
        k.CloseHandle(pi.hThread)
        self.proc, self.pid, self.inw, self.outr = pi.hProcess, pi.dwProcessId, in_w, out_r
        self.closed = False

    def read(self):
        """Blocking read of the next chunk of output; b'' when the pseudo-console has closed."""
        buf = self.ct.create_string_buffer(8192)
        n = self.W.DWORD()
        if not self.k.ReadFile(self.outr, buf, 8192, self.ct.byref(n), None) or n.value == 0:
            return b""
        return buf.raw[:n.value]

    def write(self, data):
        n = self.W.DWORD()
        while data and not self.closed:
            if not self.k.WriteFile(self.inw, data, len(data), self.ct.byref(n), None):
                return
            data = data[n.value:]

    def resize(self, cols, rows):
        if not self.closed:
            self.k.ResizePseudoConsole(self.hpc, self.COORD(cols, rows))

    def wait(self):
        """Block until the process ends; -> exit code."""
        self.k.WaitForSingleObject(self.proc, 0xFFFFFFFF)
        code = self.W.DWORD()
        self.k.GetExitCodeProcess(self.proc, self.ct.byref(code))
        return code.value

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.k.TerminateProcess(self.proc, 1)
        self.k.ClosePseudoConsole(self.hpc)   # ends the output pipe, so the reader thread stops
        self.k.CloseHandle(self.inw)          # the process handle is closed by term_waiter once the wait returns


def term_reader(t):
    dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
    while True:
        try:
            chunk = t["pty"].read()
        except OSError:
            chunk = b""
        text = dec.decode(chunk, final=not chunk)
        with t["cond"]:
            if text:
                t["buf"] += text
                if len(t["buf"]) > TERM_KEEP:
                    cut = len(t["buf"]) - TERM_KEEP
                    t["buf"], t["base"] = t["buf"][cut:], t["base"] + cut
            if not chunk:
                t["alive"] = False
            t["cond"].notify_all()
        if not chunk:
            break
    t["pty"].k.CloseHandle(t["pty"].outr)


def term_waiter(t):
    code = t["pty"].wait()
    with t["cond"]:
        t["exit"] = code
    t["pty"].close()   # the reader sees the end of output and marks the session ended
    t["pty"].k.CloseHandle(t["pty"].proc)
    audit(t["sess"], "SSH terminal closed (%s, exit code %s)" % (t["shown"], code))


def term_reap():
    """End sessions the page stopped polling (tab or console page closed)."""
    now = time.time()
    with TERM_LOCK:
        idle = [tid for tid, t in TERMS.items() if now - t["seen"] > TERM_IDLE or (not t["alive"] and now - t["seen"] > 60)]
        gone = [TERMS.pop(tid) for tid in idle]
    for t in gone:
        t["pty"].close()


def ssh_request(b):
    """Validated (session, ssh arguments, shown command) from an SSH request, or raises ValueError."""
    sess = SESSIONS.get(b.get("id"))
    if not sess or sess["vendor"] not in ("f5", "fortigate", "paloalto"):
        raise ValueError("select a connected F5, FortiGate or Palo Alto")
    user = str(b.get("user") or "").strip()
    if not SSH_USER_RE.match(user):
        raise ValueError("enter the SSH user name (letters, digits, . _ - @ \\; up to 64)")
    port = num(b.get("port") or "22", 1, 65535, 22, "SSH port")
    host = sess["host"].strip("[]")
    if host.startswith("-") or not HOST_RE.match(host):
        raise ValueError("invalid device address")
    argv = (["-p", str(port), "-l", user, "-o", "ServerAliveInterval=30"] + SSH_ALWAYS
            + (SSH_LEGACY if b.get("legacy") else []) + [host])
    if re.search(r'[%^|<>&"]', " ".join(argv)):
        raise ValueError("invalid characters for the SSH command")
    return sess, argv, "ssh " + " ".join(argv)


def do_term_open(b):
    term_reap()
    if os.name != "nt":
        return {"ok": False, "error": "the in-page terminal needs Windows; use 'Open in a separate window'"}
    try:
        sess, argv, shown = ssh_request(b)
        cols = num(b.get("cols") or "120", 20, 400, 120, "columns")
        rows = num(b.get("rows") or "30", 5, 200, 30, "rows")
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    exe = ssh_client()
    if not exe:
        return {"ok": False, "error": "no OpenSSH client found on this PC (Settings > System > Optional features > "
                                      "OpenSSH Client)"}
    with TERM_LOCK:
        if sum(1 for t in TERMS.values() if t["alive"]) >= TERM_MAX:
            return {"ok": False, "error": "%d terminals are already open: close one first" % TERM_MAX}
    try:
        pty = ConPty(subprocess.list2cmdline([exe] + argv), cols, rows)
    except OSError as e:
        return {"ok": False, "error": str(e)}
    tid = secrets.token_hex(8)
    t = {"pty": pty, "sess": sess, "shown": shown, "buf": "", "base": 0, "alive": True, "exit": None,
         "cond": threading.Condition(), "seen": time.time(), "title": "%s (%s)" % (sess["name"], sess["host"])}
    with TERM_LOCK:
        TERMS[tid] = t
    threading.Thread(target=term_reader, args=(t,), daemon=True).start()
    threading.Thread(target=term_waiter, args=(t,), daemon=True).start()
    audit(sess, "SSH terminal opened in the page: %s" % shown)
    return {"ok": True, "tid": tid, "title": t["title"], "command": shown}


def term_get(b):
    with TERM_LOCK:
        t = TERMS.get(str(b.get("tid") or ""))
    if not t:
        raise ValueError("this terminal session has ended")
    t["seen"] = time.time()
    return t


def do_term_read(b):
    """Output after position 'pos'; waits up to ~1.5 s for new output (long poll)."""
    try:
        t = term_get(b)
        pos = int(b.get("pos") or 0)
    except (ValueError, TypeError) as e:
        return {"ok": False, "error": str(e)}
    with t["cond"]:
        if pos >= t["base"] + len(t["buf"]) and t["alive"]:
            t["cond"].wait(1.5)
        start = max(pos, t["base"])
        data = t["buf"][start - t["base"]:]
        return {"ok": True, "data": data, "pos": t["base"] + len(t["buf"]), "lost": start > pos,
                "alive": t["alive"], "exit": t["exit"]}


def do_term_write(b):
    try:
        t = term_get(b)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    data = str(b.get("data") or "")[:65536]
    if data and t["alive"]:
        t["pty"].write(data.encode("utf-8"))
    return {"ok": True}


def do_term_resize(b):
    try:
        t = term_get(b)
        t["pty"].resize(num(b.get("cols"), 20, 400, 120, "columns"), num(b.get("rows"), 5, 200, 30, "rows"))
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True}


def do_term_close(b):
    with TERM_LOCK:
        t = TERMS.pop(str(b.get("tid") or ""), None)
    if t:
        t["pty"].close()
    return {"ok": True}


def term_close_all():
    with TERM_LOCK:
        ts = list(TERMS.values())
        TERMS.clear()
    for t in ts:
        t["pty"].close()


if not globals().get("_HOT_RELOADING"):
    atexit.register(term_close_all)


# ---- Saved logins: credentials encrypted with Windows DPAPI (current user) + a passphrase-derived entropy ---------
# Without the passphrase, or under another Windows account / on another PC, the file cannot be decrypted.
VAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_logins.dat")
VAULT = {"key": None, "logins": None}   # in memory only while unlocked
VAULT_FIELDS = ("vendor", "name", "host", "port", "insecure", "account", "username", "password", "apikey")
VAULT_LOCK = threading.Lock()


def dpapi(data, entropy, protect):
    if os.name != "nt":
        raise ValueError("saved logins need Windows (DPAPI)")
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
    bufs = [ctypes.create_string_buffer(x, len(x)) for x in (data, entropy)]
    bi, be, bo = (BLOB(len(data), ctypes.cast(bufs[0], ctypes.POINTER(ctypes.c_char))),
                  BLOB(len(entropy), ctypes.cast(bufs[1], ctypes.POINTER(ctypes.c_char))), BLOB())
    c32 = ctypes.windll.crypt32
    if protect:
        ok = c32.CryptProtectData(ctypes.byref(bi), ctypes.c_wchar_p("netsecops"), ctypes.byref(be), None, None,
                                  0x1, ctypes.byref(bo))
    else:
        ok = c32.CryptUnprotectData(ctypes.byref(bi), None, ctypes.byref(be), None, None, 0x1, ctypes.byref(bo))
    if not ok:
        raise ValueError("wrong passphrase" if not protect else "encryption failed")
    try:
        return ctypes.string_at(bo.pbData, bo.cbData)
    finally:
        k32 = ctypes.windll.kernel32
        k32.LocalFree.argtypes = [ctypes.c_void_p]
        k32.LocalFree(ctypes.cast(bo.pbData, ctypes.c_void_p))


def vault_key(passphrase, salt):
    return hashlib.pbkdf2_hmac("sha256", str(passphrase).encode("utf-8"), salt, 300000)


def vault_read():
    with open(VAULT_FILE, encoding="utf-8") as f:
        d = json.load(f)
    return bytes.fromhex(d["salt"]), base64.b64decode(d["data"])


def vault_write(key, salt, logins):
    blob = dpapi(json.dumps(logins).encode("utf-8"), key, True)
    tmp = VAULT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"v": 1, "note": "netsecops saved logins: DPAPI (this Windows user) + passphrase. Not in git.",
                   "salt": salt.hex(), "data": base64.b64encode(blob).decode()}, f)
    os.replace(tmp, VAULT_FILE)


def vault_unlock(passphrase):
    salt, blob = vault_read()
    key = vault_key(passphrase, salt)
    try:
        logins = json.loads(dpapi(blob, key, False).decode("utf-8"))
    except ValueError:
        time.sleep(1)   # slows down guessing
        raise ValueError("wrong passphrase (or the file was saved under another Windows account)")
    VAULT.update(key=(key, salt), logins=logins)
    return logins


def vault_id(x):
    return "%s|%s|%s" % (x.get("vendor"), str(x.get("host") or "").lower(), x.get("port") or 443)


def vault_public():
    return [{"id": vault_id(x), "name": x.get("name") or x.get("host"), "vendor": x.get("vendor"), "host": x.get("host")}
            for x in VAULT["logins"] or []]


def vault_remember(b):
    """Add or replace one login (a successful connect body). Unlocks or creates the store with the passphrase."""
    pp = str(b.get("vault_pass") or "")
    with VAULT_LOCK:
        if VAULT["key"] is None:
            if os.path.exists(VAULT_FILE):
                if not pp:
                    raise ValueError("enter the saved-logins passphrase")
                vault_unlock(pp)
            else:
                if len(pp) < 8:
                    raise ValueError("choose a passphrase of at least 8 characters for the saved logins")
                salt = secrets.token_bytes(16)
                VAULT.update(key=(vault_key(pp, salt), salt), logins=[])
        x = {k: b.get(k) for k in VAULT_FIELDS if b.get(k) not in (None, "")}
        x["vendor"] = b.get("vendor")
        if x["vendor"] == "cloudflare":
            x["host"] = CF_HOST
        VAULT["logins"] = [y for y in VAULT["logins"] if vault_id(y) != vault_id(x)] + [x]
        vault_write(VAULT["key"][0], VAULT["key"][1], VAULT["logins"])


def vault_connect_all():
    """Connect every saved login that is not connected yet, in parallel -> [connect results]."""
    with LOCK:
        live = {vault_id(s_) for s_ in SESSIONS.values()}
    todo = [x for x in VAULT["logins"] or [] if vault_id(x) not in live]

    def one(x):
        try:
            r = do_connect(dict(x))
        except Exception as e:   # one bad device must not stop the others
            r = {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
        if not r.get("ok"):
            r = {"ok": False, "error": r.get("error"), "name": x.get("name") or x.get("host")}
        return r
    if not todo:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(todo))) as ex:
        return list(ex.map(one, todo))


def do_vault(b):
    a = str(b.get("action") or "status")
    try:
        if a == "status":
            pass
        elif a == "unlock":
            with VAULT_LOCK:
                vault_unlock(str(b.get("passphrase") or ""))
            return dict(do_vault({}), results=vault_connect_all())
        elif a == "connect":
            if VAULT["key"] is None:
                raise ValueError("unlock the saved logins first")
            return dict(do_vault({}), results=vault_connect_all())
        elif a == "forget":
            with VAULT_LOCK:
                if VAULT["key"] is None:
                    raise ValueError("unlock the saved logins first")
                VAULT["logins"] = [x for x in VAULT["logins"] if vault_id(x) != b.get("id")]
                vault_write(VAULT["key"][0], VAULT["key"][1], VAULT["logins"])
        elif a == "lock":
            VAULT.update(key=None, logins=None)
        elif a == "reset":   # forgotten passphrase: delete the file
            with VAULT_LOCK:
                VAULT.update(key=None, logins=None)
                if os.path.exists(VAULT_FILE):
                    os.remove(VAULT_FILE)
        else:
            raise ValueError("unknown action")
    except (OSError, ValueError, KeyError) as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "windows": os.name == "nt", "exists": os.path.exists(VAULT_FILE),
            "unlocked": VAULT["key"] is not None, "logins": vault_public() if VAULT["key"] is not None else []}


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
    if vendor in ("f5", "paloalto") and SSH_USER_RE.match(str(user or "")):
        sess["user"] = user   # the login name only, as the default for SSH
    sid = secrets.token_hex(6)
    with LOCK:
        SESSIONS[sid] = sess
    audit(sess, "connected")
    out = {"ok": True, "id": sid, "name": sess["name"], "vendor": vendor, "host": host, "user": sess.get("user", "")}
    if b.get("remember"):
        try:
            vault_remember(b)
            out["remembered"] = True
        except (OSError, ValueError, KeyError) as e:
            out["remember_error"] = str(e)
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
            vals["_ack"] = bool(b.get("ack"))   # F5 performance: util/bash only with the active-tools tick-box
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
        if sess["vendor"] == "f5" and spec["id"] == "certs" and result.get("ok") and isinstance(result.get("data"), dict):
            result["data"] = {"certificates": f5_cert_rows(result["data"].get("items") or [], sess)}
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
BRAND_DIR = os.path.dirname(os.path.abspath(__file__))
BRAND_FILES = (("brand_logo.svg", "image/svg+xml"), ("brand_logo.png", "image/png"))
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


def spec_range(spec):
    """(first, last) address of a literal IP, CIDR, 'a-b' range or 'a.b.c.d m.m.m.m'; raises ValueError."""
    spec = spec.strip()
    if "-" in spec and "/" not in spec and " " not in spec:
        a, b = [ipaddress.ip_address(x.strip()) for x in spec.split("-", 1)]
        return a, b
    net = ipaddress.ip_network("%s/%s" % tuple(spec.split()[:2]) if " " in spec else spec, strict=False)
    return net.network_address, net.broadcast_address


def ip_in_spec(ip, spec):
    """True if ip falls inside spec: literal IP, CIDR, 'a-b' range, or 'a.b.c.d m.m.m.m'.
    ip may also be a subnet (ip_network): then True if spec and the subnet share any address."""
    spec = (spec or "").strip()
    if not spec:
        return False
    try:
        a, b = spec_range(spec)
        if isinstance(ip, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return ip.version == a.version and a <= ip.broadcast_address and b >= ip.network_address
        return ip.version == a.version and a <= ip <= b
    except (ValueError, TypeError):
        return False


def spec_relation(ip, spec):
    """For a subnet lookup: how the object relates to the subnet."""
    if not isinstance(ip, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return ""
    try:
        a, b = spec_range(spec)
    except (ValueError, TypeError):
        return ""
    lo, hi = ip.network_address, ip.broadcast_address
    if a == lo and b == hi:
        return " · same as the subnet"
    if a <= lo and b >= hi:
        return " · contains the subnet"
    if a >= lo and b <= hi:
        return " · inside the subnet"
    return " · partly overlaps the subnet"


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


F5_HOST_CACHE = {}   # (session id, hostname) -> (time, result): the flow trace asks each F5 more than once


def do_f5_host(b):
    k = (b.get("id"), str(b.get("hostname") or "").strip().lower())
    hit = F5_HOST_CACHE.get(k)
    if hit and time.time() - hit[0] < 60:
        return hit[1]
    r = f5_host_lookup(b)
    if r.get("ok"):
        F5_HOST_CACHE[k] = (time.time(), r)
        for x in [x for x, v in F5_HOST_CACHE.items() if time.time() - v[0] > 60]:
            F5_HOST_CACHE.pop(x, None)
    return r


def f5_host_lookup(b):
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

    if refs:
        addrs, groups, skipped = pan_addr_db(sess, vsys)
        matched = pan_addr_match(ip, addrs, groups)
    else:
        matched, skipped = {}, 0
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
        # The matching objects and rules are shown as tables, so the summary only reports when there are none.
        if not matched:
            summary.append("No address object or group contains this IP.")
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
        verdict = {"label": "%d RULE(S) REFERENCE THIS %s" % (len(rules), ("SUBNET" if isinstance(ip, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else "IP")), "kind": "info"}
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
    matched, skipped = fg_addr_match(ip, addrs, grps)
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
        # The matching objects and policies are shown as tables, so the summary only reports when there are none.
        if not matched:
            summary.append("No address object or group contains this IP.")
        if not rules:
            summary.append("No IPv4 policy references this IP directly or via an object.")
        if skipped:
            notes.append("%d FQDN/geography/wildcard object(s) were not evaluated." % skipped)
        notes.append("IPv6 policies, internet-service and the built-in 'all' object are not part of the reference search.")
    verdict = None
    if flow and not flow["srcintf"]:
        # No ingress interface given: use the interface of the route back to the source (as the GUI suggests).
        rq = {"destination": flow["src"]}
        if vdom:
            rq["vdom"] = vdom
        st, ok, rd = rest_get(sess, "/api/v2/monitor/router/lookup?" + urllib.parse.urlencode(rq))
        rr = rd.get("results") if ok and isinstance(rd, dict) else None
        rr = rr[0] if isinstance(rr, list) and rr else rr
        intf = str((rr or {}).get("interface") or "") if isinstance(rr, dict) else ""
        if not intf:
            res["notes"] = notes + ["Could not find the route to %s (HTTP %s); enter the ingress interface." % (flow["src"], st)]
            return res, summary, {"label": "INGRESS INTERFACE NOT FOUND", "kind": "warn"}
        flow["srcintf"] = intf
        notes.append("Ingress interface %s was taken from the route to the source %s%s." % (
            intf, flow["src"], (" via " + str(rr.get("gateway"))) if rr.get("gateway") else ""))
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
                summary.insert(0, "Flow %s -> %s port %s %s (ingress %s): policy %s, action '%s'" % (
                    flow["src"], flow["dst"], flow["port"] or "-", flow["proto"], flow["srcintf"], pid, act))
            else:
                verdict = {"label": "NO POLICY MATCHED (implicit deny)", "kind": "bad"}
                summary.insert(0, "Policy lookup returned no policy. Confirm the ingress interface is correct.")
    res["notes"] = notes
    if verdict is None:
        verdict = {"label": "%d POLICY(IES) REFERENCE THIS %s" % (len(rules), ("SUBNET" if isinstance(ip, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else "IP")), "kind": "info"}
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
    root, hits = None, {}
    for i in range(0, len(rows), 50):   # hit counts are kept per vsys rule base
        lst = "".join("<member>%s</member>" % xml_escape(r["rule"]) for r in rows[i:i + 50])
        root = pan_xml(sess, {"type": "op", "cmd": "<show><rule-hit-count><vsys><vsys-name><entry name='%s'><rule-base>"
                              "<entry name='security'><rules><list>%s</list></rules></entry></rule-base></entry>"
                              "</vsys-name></vsys></rule-hit-count></show>" % (xml_escape(vsys), lst)}, 30)
        if root is None:
            break
        hits.update((h.get("name"), h) for h in root.findall(".//rules/entry"))
    if rows:
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
    q = "" if b.get("all") else str(b.get("name") or "").strip()
    if q and not POLICY_Q_RE.match(q) or not q and not b.get("all"):
        return {"ok": False, "error": "enter a policy name (or part of it)%s, without quotes or < >" % (
            " or a policy ID" if sess["vendor"] == "fortigate" else "")}
    try:
        audit(sess, "policy search '%s'" % q if q else "list all policies")
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
    # Negate flags as yes / no ("disable" would show as a red pill), moved to the end so source, destination and
    # service sit next to each other.
    for i, r in enumerate(rows):
        neg = {k: ("yes" if str(r.get(k)) in ("yes", "enable") else "no") for k in ("negate_source", "negate_destination")}
        rows[i] = dict([(k, x) for k, x in r.items() if k not in neg] + list(neg.items()))
    # A few matches read best one by one; many as a table.
    data = {key(r): r for r in rows} if q and len(rows) <= 5 else {"policies": rows}
    off = [r for r in rows if r["enabled"] == "no"]
    label = ("%d POLICY(IES) MATCH '%s'" % (len(rows), q)) if q else "%d POLICY(IES) IN TOTAL" % len(rows)
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": "policy search " + q if q else "all policies",
            "verdict": {"label": label + (" · %d DISABLED" % len(off) if off else "")
                        if rows else "NO POLICY NAME CONTAINS '%s'" % q if q else "NO POLICIES FOUND", "kind": "info" if rows else "warn"},
            "summary": ["%s: action %s%s%s" % (key(r), r["action"], "" if r["enabled"] == "yes" else ", DISABLED",
                                                ", hits %s" % r["hit_count"] if r.get("hit_count") not in (None, "") else "")
                        for r in (rows[:10] if q else [])] + notes,
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


# ---- Source NAT lookup: what an IP is translated to when it is the source (PAN-OS, FortiGate, F5) ----------------
def pan_addr_db(sess, vsys):
    """Address objects (ip-netmask / ip-range) and static groups of the vsys and shared -> (addrs, groups, skipped)."""
    addrs, groups, skipped = [], [], 0
    for label, xp in [("vsys:" + vsys, pan_base(vsys)), ("shared", "/config/shared")]:
        node = pan_section(sess, xp, "address")
        for e in (node.findall("entry") if node is not None else []):
            for tag in ("ip-netmask", "ip-range"):
                v = e.findtext(tag)
                if v:
                    addrs.append((label, e.get("name"), tag, v.strip()))
            if e.find("fqdn") is not None or e.find("ip-wildcard") is not None:
                skipped += 1
        node = pan_section(sess, xp, "address-group")
        for e in (node.findall("entry") if node is not None else []):
            if e.find("dynamic") is not None:
                skipped += 1
            groups.append((label, e.get("name"), pan_members(e.find("static"))))
    return addrs, groups, skipped


def pan_addr_match(ip, addrs, groups):
    """{object or group name: why it contains ip}."""
    matched = {}
    for label, n, tag, v in addrs:
        if ip_in_spec(ip, v):
            matched[n] = "%s %s (%s)%s" % (tag, v, label, spec_relation(ip, v))
    changed = True
    while changed:
        changed = False
        for label, n, members in groups:
            via = [m for m in members if m in matched]
            if n not in matched and via:
                matched[n] = "group containing %s (%s)" % (", ".join(via), label)
                changed = True
    return matched


def fg_addr_match(ip, addrs, grps):
    """FortiGate address objects / groups containing ip -> ({name: why}, objects not evaluated)."""
    matched, skipped = {}, 0
    for a in addrs or []:
        n, t = a.get("name"), a.get("type", "ipmask")
        if n == "all" or a.get("subnet") == "0.0.0.0 0.0.0.0":
            continue
        if t == "ipmask" and ip_in_spec(ip, a.get("subnet")):
            matched[n] = "subnet " + a["subnet"] + spec_relation(ip, a["subnet"])
        elif t == "iprange" and ip_in_spec(ip, "%s-%s" % (a.get("start-ip"), a.get("end-ip"))):
            rng = "%s-%s" % (a.get("start-ip"), a.get("end-ip"))
            matched[n] = "range " + rng + spec_relation(ip, rng)
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
    return matched, skipped


def snat_hit(members, ip, matched, anyname):
    """How a rule's address list covers ip: 'any', an object (with why) or a literal; '' if it does not."""
    for m in members:
        if m == anyname:
            return m
        if m in matched:
            return "%s: %s" % (m, matched[m])
        if ip_in_spec(ip, m):
            return m + " (literal)"
    return ""


def snat_flow_args(v, pan):
    ip = parse_ip(v.get("ip"), "Source IP")
    dst = parse_ip(v["dst"], "Destination IP") if v.get("dst") else None
    port = num(v["port"], 1, 65535, None, "port") if v.get("port") else None
    proto = (v.get("proto") or "tcp").lower()
    if pan:
        proto = {"tcp": "6", "udp": "17", "icmp": "1"}.get(proto, proto)
        num(proto, 0, 255, None, "protocol")
    elif proto not in ("tcp", "udp", "icmp") and not proto.isdigit():
        raise ValueError("protocol must be tcp, udp, icmp or a number")
    return ip, dst, port, proto


def pan_snat(sess, v):
    t0, vsys = time.time(), v.get("vsys") or "vsys1"
    ip, dst, port, proto = snat_flow_args(v, True)
    addrs, groups, skipped = pan_addr_db(sess, vsys)
    m_src = pan_addr_match(ip, addrs, groups)
    m_dst = pan_addr_match(dst, addrs, groups) if dst else {}
    vals = {n: val for _, n, _, val in addrs}
    show = lambda names: ", ".join("%s (%s)" % (n, vals[n]) if n in vals else n for n in names)
    rows, pos, total = [], 0, 0
    for label, xp in [("shared-pre", "/config/shared/pre-rulebase/nat"), ("local", pan_base(vsys) + "/rulebase/nat"),
                      ("shared-post", "/config/shared/post-rulebase/nat")]:   # the order PAN-OS evaluates them
        node = pan_section(sess, xp, "rules")
        for e in (node.findall("entry") if node is not None else []):
            pos += 1
            total += 1
            src_m, dst_m = pan_members(e.find("source")), pan_members(e.find("destination"))
            sv = snat_hit(src_m, ip, m_src, "any")
            dv = snat_hit(dst_m, dst, m_dst, "any") if dst else ""
            if not sv or (dst and not dv):
                continue
            st = e.find("source-translation")
            dipp = st.find("dynamic-ip-and-port") if st is not None else None
            dip = st.find("dynamic-ip") if st is not None else None
            sip = st.find("static-ip") if st is not None else None
            if dipp is not None and dipp.find("interface-address") is not None:
                ia = dipp.find("interface-address")
                kind = "dynamic IP and port (interface address)"
                to = "interface %s, address %s" % (ia.findtext("interface") or "?",
                                                   show([ia.findtext("ip")]) if ia.findtext("ip") else "(its primary IP)")
            elif dipp is not None:
                kind, to = "dynamic IP and port", show(pan_members(dipp.find("translated-address")))
            elif dip is not None:
                kind, to = "dynamic IP", show(pan_members(dip.find("translated-address")))
                fb = dip.find("fallback")
                if fb is not None:
                    to += " (fallback configured)"
            elif sip is not None:
                kind = "static IP" + (" (bi-directional)" if (sip.findtext("bi-directional") or "") == "yes" else "")
                to = show([sip.findtext("translated-address") or "?"])
            else:
                kind, to = "none: no source translation (this rule keeps the source)", "unchanged"
            rows.append({"order": pos, "rule": e.get("name"), "scope": label, "source_nat": kind, "translated_to": to,
                         "disabled": e.findtext("disabled") or "no",
                         "from_zone": ", ".join(pan_members(e.find("from"))), "to_zone": ", ".join(pan_members(e.find("to"))),
                         "to_interface": e.findtext("to-interface") or "any", "source": ", ".join(src_m),
                         "source_match": sv, "destination": ", ".join(dst_m), "service": e.findtext("service") or "any",
                         "destination_nat": "yes" if e.find("destination-translation") is not None else "no"})
    live = [r for r in rows if r["disabled"] != "yes"]
    summary, notes, verdict, test = [], [], None, None
    if dst:
        cmd = "<test><nat-policy-match>"
        for k in ("from", "to"):
            if v.get(k):
                cmd += "<%s>%s</%s>" % (k, xml_escape(v[k]), k)
        cmd += "<source>%s</source><destination>%s</destination>" % (ip, dst)
        if port:
            cmd += "<destination-port>%d</destination-port>" % port
        cmd += "<protocol>%s</protocol></nat-policy-match></test>" % proto
        st_, raw = http(sess, "POST", "/api/", {"X-PAN-KEY": sess["key"], "Content-Type": "application/x-www-form-urlencoded"},
                        urllib.parse.urlencode({"type": "op", "cmd": cmd}).encode(), 30)
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            root = None
        if root is not None and root.get("status") == "success":
            e = root.find(".//rules/entry")
            e = root.find(".//entry") if e is None else e
            name = "" if e is None else (e.get("name") or (e.text or "").split(";")[0].strip())
            test = {"matched_rule": name or None}
            r = next((x for x in rows if x["rule"] == name), None)
            if not name:
                verdict = {"label": "NO NAT RULE MATCHES: %s leaves with its own address" % ip, "kind": "ok"}
            elif r and r["translated_to"] != "unchanged":
                verdict = {"label": "SOURCE NAT by rule '%s': %s -> %s" % (name, ip, r["translated_to"]), "kind": "info"}
            elif r:
                verdict = {"label": "NAT rule '%s' matches: source not translated" % name, "kind": "ok"}
            else:
                verdict = {"label": "NAT rule '%s' matches (not in the running config read here)" % name, "kind": "warn"}
            summary.append("Firewall test (nat-policy-match %s -> %s%s, protocol %s%s): %s" % (
                ip, dst, ":%d" % port if port else "", proto,
                "".join(", %s zone %s" % (k, v[k]) for k in ("from", "to") if v.get(k)), name or "no NAT rule"))
        else:
            err = (" ".join(t.strip() for t in root.itertext() if t.strip())[:300] if root is not None else "HTTP %s" % st_)
            notes.append("nat-policy-match was rejected: %s. Enter the source and destination zones (from / to) if the "
                         "firewall needs them; the table below is from the configuration." % err)
    if verdict is None and dst:
        f = live[0] if live else None
        verdict = ({"label": "NO NAT RULE COVERS %s -> %s: the source is not translated" % (ip, dst), "kind": "ok"} if not f
                   else {"label": "FIRST MATCHING NAT RULE (config, zones / service not checked): '%s': %s" % (
                       f["rule"], "source not translated" if f["translated_to"] == "unchanged" else
                       "%s -> %s" % (ip, f["translated_to"])), "kind": "info" if f["translated_to"] != "unchanged" else "ok"})
    if verdict is None:
        tr = [r for r in live if r["translated_to"] != "unchanged"]
        verdict = ({"label": "NO NAT RULE TRANSLATES %s as source" % ip, "kind": "ok"} if not tr else
                   {"label": "%d NAT RULE(S) TRANSLATE THIS SOURCE · first: '%s' -> %s" % (len(tr), tr[0]["rule"],
                                                                                            tr[0]["translated_to"]),
                    "kind": "info"})
        if tr and tr[0] is not live[0]:
            summary.append("Rule '%s' comes earlier and keeps the source unchanged for the traffic it matches (destination "
                           "%s)." % (live[0]["rule"], live[0]["destination"] or "any"))
        if live:
            summary.append("Without a destination the zones and destination of each rule are not checked: the first "
                           "rule in the list is the first candidate, not necessarily the one used. Enter the "
                           "destination for the firewall's own answer.")
    if skipped:
        notes.append("%d FQDN / wildcard / dynamic object(s) were not evaluated." % skipped)
    notes.append("Rules in evaluation order (shared pre-rules, local, shared post-rules); the first match applies. "
                 "Panorama-pushed rules appear only if present in this device's running config.")
    data = {"source_nat_rules": rows, "count": len(rows), "nat_rules_scanned": total, "objects_containing_ip": m_src,
            "notes": notes}
    if test:
        data["firewall_test"] = test
    return dict(pan_result("source NAT for %s%s (vsys %s)" % (ip, " -> %s" % dst if dst else "", vsys), data, t0),
                verdict=verdict, summary=summary)


def fg_snat(sess, v):
    t0, vdom = time.time(), v.get("vdom") or ""
    ip, dst, port, proto = snat_flow_args(v, False)
    vq = ("?vdom=" + urllib.parse.quote(vdom)) if vdom else ""
    st, ok, sd = rest_get(sess, "/api/v2/cmdb/system/settings" + vq)
    res0 = sd.get("results") if isinstance(sd, dict) else None
    central = isinstance(res0, dict) and res0.get("central-nat") == "enable"
    addrs, grps = fg_cmdb(sess, "address", vdom), fg_cmdb(sess, "addrgrp", vdom)
    m_src, skipped = fg_addr_match(ip, addrs, grps)
    m_dst = fg_addr_match(dst, addrs, grps)[0] if dst else {}
    pools = {p.get("name"): p for p in fg_cmdb(sess, "ippool", vdom) or []}
    names = lambda x: [i.get("name") for i in as_list(x) if isinstance(i, dict)]
    ifip = {}

    def egress(intfs):
        out = []
        for n in intfs:
            if n not in ifip:
                s2, ok2, d2 = rest_get(sess, "/api/v2/cmdb/system/interface/" + urllib.parse.quote(n, safe="") + vq)
                r2 = d2.get("results") if ok2 and isinstance(d2, dict) else None
                r2 = r2[0] if isinstance(r2, list) and r2 else r2
                a = str((r2 or {}).get("ip") or "").split() if isinstance(r2, dict) else []
                ifip[n] = a[0] if a and a[0] != "0.0.0.0" else ""
            out.append("%s address%s" % (n, " " + ifip[n] if ifip[n] else ""))
        return "egress interface: " + (", ".join(out) or "?")

    def pool_txt(pn):
        out = []
        for n in pn:
            p = pools.get(n) or {}
            out.append("%s (%s%s, %s)" % (n, p.get("startip", "?"), "-" + p["endip"] if p.get("endip") and
                                          p.get("endip") != p.get("startip") else "", p.get("type", "?")) if p else n)
        return "IP pool " + ", ".join(out)
    rows = []
    if central:
        for r in fg_cmdb(sess, "central-snat-map", vdom) or []:
            sv = snat_hit(names(r.get("orig-addr")), ip, m_src, "all")
            dv = snat_hit(names(r.get("dst-addr")), dst, m_dst, "all") if dst else ""
            if not sv or (dst and not dv):
                continue
            nat = r.get("nat", "enable") == "enable"
            pn = names(r.get("nat-ippool"))
            rows.append({"rule": "central SNAT %s" % r.get("policyid"), "status": r.get("status", "enable"),
                         "srcintf": ", ".join(names(r.get("srcintf"))), "dstintf": ", ".join(names(r.get("dstintf"))),
                         "source": ", ".join(names(r.get("orig-addr"))), "source_match": sv,
                         "destination": ", ".join(names(r.get("dst-addr"))),
                         "translated_to": (pool_txt(pn) if pn else egress(names(r.get("dstintf")))) if nat else "unchanged (nat disable)",
                         "_id": r.get("policyid")})
    pol_rows = []
    for p in fg_cmdb(sess, "policy", vdom) or []:
        if p.get("action") != "accept" or p.get("srcaddr-negate") == "enable":
            continue
        sv = snat_hit(names(p.get("srcaddr")), ip, m_src, "all")
        dv = snat_hit(names(p.get("dstaddr")), dst, m_dst, "all") if dst else ""
        if not sv or (dst and p.get("dstaddr-negate") != "enable" and not dv):
            continue
        nat = p.get("nat") == "enable"
        pn = names(p.get("poolname")) if p.get("ippool") == "enable" else []
        pol_rows.append({"rule": "policy %s%s" % (p.get("policyid"), " '%s'" % p["name"] if p.get("name") else ""),
                         "status": p.get("status", "enable"), "srcintf": ", ".join(names(p.get("srcintf"))),
                         "dstintf": ", ".join(names(p.get("dstintf"))), "source": ", ".join(names(p.get("srcaddr"))),
                         "source_match": sv, "destination": ", ".join(names(p.get("dstaddr"))),
                         "translated_to": ("(central NAT: see the central SNAT rows)" if central else
                                           (pool_txt(pn) if pn else egress(names(p.get("dstintf")))) if nat
                                           else "unchanged (nat disable)"),
                         "_id": p.get("policyid")})
    if not central:
        rows = pol_rows
    for x in fg_cmdb(sess, "vip", vdom) or []:
        if x.get("nat-source-vip") == "enable" and any(ip_in_spec(ip, strip_rd(str(m.get("range", ""))))
                                                       for m in as_list(x.get("mappedip"))):
            rows.append({"rule": "VIP %s (nat-source-vip)" % x.get("name"), "status": "enable",
                         "srcintf": "", "dstintf": x.get("extintf", ""), "source": ", ".join(
                             str(m.get("range")) for m in as_list(x.get("mappedip"))), "source_match": "mapped IP",
                         "destination": "any", "translated_to": str(x.get("extip") or ""), "_id": None})
    summary, notes, verdict, test = [], [], None, None
    if dst:
        res, _, vd = fg_lookup(sess, ip, vdom, {"src": str(ip), "dst": str(dst), "port": port, "proto": proto,
                                                "srcintf": v.get("srcintf") or ""}, refs=False)
        pol = (res.get("flow_test") or {}).get("matched_policy") or {}
        notes += res.get("notes") or []
        test = {"policy_lookup": vd.get("label"), "matched_policy": pol.get("policyid")}
        if pol.get("policyid") is not None and not central:
            r = next((x for x in rows if x["_id"] == pol.get("policyid")), None)
            if r and r["translated_to"].startswith("unchanged"):
                verdict = {"label": "Policy %s matches: no source NAT, %s keeps its address" % (pol["policyid"], ip), "kind": "ok"}
            elif r:
                verdict = {"label": "SOURCE NAT by %s: %s -> %s" % (r["rule"], ip, r["translated_to"]), "kind": "info"}
        elif pol.get("policyid") is not None and central:
            f = next((x for x in rows if x["status"] != "disable" and x["_id"] is not None), None)
            verdict = ({"label": "Policy %s matches; first central SNAT rule for this flow: %s -> %s" % (
                pol["policyid"], f["rule"], f["translated_to"]), "kind": "info"} if f else
                {"label": "Policy %s matches; no central SNAT rule covers it: the source is not translated" % pol["policyid"],
                 "kind": "ok"})
            if f:
                notes.append("Central NAT: the first enabled central SNAT rule whose interfaces and addresses match is "
                             "used; the interfaces are not compared here.")
        else:
            verdict = {"label": "POLICY LOOKUP: %s" % vd.get("label"), "kind": vd.get("kind", "warn")}
    if verdict is None:
        live = [r for r in rows if r["status"] != "disable"]
        nat = [r for r in live if not r["translated_to"].startswith("unchanged")]
        verdict = ({"label": "NO SOURCE NAT COVERS %s: the source is not translated" % ip, "kind": "ok"} if not nat else
                   {"label": "%d RULE(S) TRANSLATE THIS SOURCE · first: %s -> %s" % (len(nat), nat[0]["rule"],
                                                                                     nat[0]["translated_to"]), "kind": "info"})
        if live and not dst:
            summary.append("Without a destination every policy / rule that covers the source is listed in order; enter "
                           "the destination for the one that is used.")
    if skipped:
        notes.append("%d FQDN / geography / wildcard object(s) were not evaluated." % skipped)
    notes.append("NAT mode: %s." % ("central NAT (central SNAT map)" if central else "policy NAT (nat enable on the policy)"))
    for r in rows:
        r.pop("_id", None)
    data = {"source_nat": rows, "count": len(rows), "objects_containing_ip": m_src, "notes": notes}
    if test:
        data["firewall_test"] = test
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "verdict": verdict, "summary": summary,
            "request": "source NAT for %s%s%s" % (ip, " -> %s" % dst if dst else "", " (vdom %s)" % vdom if vdom else ""),
            "data": data}


def f5_snat_lookup(sess, v):
    t0 = time.time()
    ip = parse_ip(v.get("ip"), "Source IP")
    ok, d = f5_get(sess, "/mgmt/tm/ltm/snat")
    if not ok:
        return {"ok": False, "error": "could not read /mgmt/tm/ltm/snat"}
    rows = []
    for s in (d.get("items") if isinstance(d, dict) else None) or []:
        origins = [strip_rd(str(o.get("name") or "")) for o in as_list(s.get("origins")) if isinstance(o, dict)]
        hit = next((o for o in origins if o in ("0.0.0.0/0", "0.0.0.0/0.0.0.0", "any", "any6") or ip_in_spec(ip, o)), "")
        if not hit:
            continue
        to = ("automap" if s.get("automap") is not None else "SNAT pool " + str(s["snatpool"]) if s.get("snatpool")
              else strip_rd(str(s.get("translation") or "?").rsplit("/", 1)[-1]))
        rows.append({"snat": s.get("fullPath") or s.get("name"), "origin_match": hit, "translated_to": to,
                     "vlans": ", ".join(as_list(s.get("vlans"))) or "all",
                     "vlans_mode": "enabled on" if s.get("vlansEnabled") is not None else "disabled on" if s.get("vlansDisabled") is not None else "all"})
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": "GET /mgmt/tm/ltm/snat",
            "verdict": ({"label": "SNAT %s: %s -> %s" % (rows[0]["snat"], ip, rows[0]["translated_to"]), "kind": "info"} if rows
                        else {"label": "NO STANDALONE SNAT COVERS %s" % ip, "kind": "ok"}),
            "summary": ["Virtual-server SNAT (automap / SNAT pool on the virtual server) applies to every client of "
                        "that virtual server and is not listed here: see the flow trace or the virtual server."],
            "data": {"snats": rows, "count": len(rows)}}


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


# ---- Resource utilization (PAN-OS / FortiGate): CPU, memory, sessions, buffers, disk, with thresholds ---------
def ru_sev(v, hi, med):
    return None if v is None else "high" if v >= hi else "medium" if v >= med else None


def ru_tile(label, v, sub="", hi=90, med=80, fmt="pct", spark=None):
    sev = ru_sev(v, hi, med) if fmt == "pct" else None
    return {"label": label, "value": None if v is None else round(float(v), 1), "fmt": fmt, "sub": sub,
            "kind": {"high": "bad", "medium": "warn"}.get(sev, ""), "spark": spark or []}


def ru_float(v):
    try:
        return float(str(v).strip().rstrip("%"))
    except (TypeError, ValueError):
        return None


def ru_result(t0, request, tiles, charts, findings, data, notes, label):
    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
    hi = [f for f in findings if f["severity"] == "high"]
    kind = "bad" if hi else "info" if any(f["severity"] == "medium" for f in findings) else "ok"
    out = collections.OrderedDict([("findings", findings)])
    out.update(data)
    out["notes"] = [n for n in notes if n]
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": request,
            "verdict": {"label": label, "kind": kind},
            "summary": ["%s: %s (%s)" % (f["severity"].upper(), f["issue"], f["object"]) for f in findings[:10]] or
                       ["No resource above its warning threshold."],
            "data": out, "tiles": tiles, "charts": charts}


RU_RANGE_RE = re.compile(r"^(\d{1,3})\s*(m|min|mins|minutes?|h|hr|hrs|hours?|d|days?|w|weeks?)$")
RU_UNIT_S = {"m": 60, "h": 3600, "d": 86400, "w": 604800}


def ru_range(v):
    """'3d', '24h', '2 weeks' ... -> seconds."""
    m = RU_RANGE_RE.match(str(v or "1h").strip().lower())
    if not m or int(m.group(1)) < 1:
        raise ValueError("time range must look like 30m, 6h, 3d or 2w")
    return int(m.group(1)) * RU_UNIT_S[m.group(2)[0]]


def ru_span(secs):
    """'last 3 days', 'last 24 hours', 'last 2 weeks': the largest unit that gives a whole number of at least 2."""
    if secs == 3600:
        return "last hour"
    for s_, name in ((604800, "week"), (86400, "day"), (3600, "hour"), (60, "minute")):
        if secs % s_ == 0 and secs // s_ >= 2:
            return "last %d %ss" % (secs // s_, name)
    return "last %d s" % secs


def ru_labels(n, step):
    """Labels for the last n buckets of `step` seconds (oldest first), on this PC's clock."""
    now = int(time.time() // step * step)
    fmt = {60: "%H:%M", 3600: "%m-%d %H:00", 86400: "%Y-%m-%d", 604800: "%Y-%m-%d"}.get(step, "%m-%d %H:%M")
    return [time.strftime(fmt, time.localtime(now - step * (n - 1 - i))) for i in range(n)]


# PAN-OS resource monitor history: (granularity, seconds per value, most values kept)
PAN_RM_GRAN = (("minute", 60, 60), ("hour", 3600, 24), ("day", 86400, 7), ("week", 604800, 13))


def pan_rm_pick(secs):
    """The finest resource-monitor granularity that covers `secs` -> (granularity, step, number of values)."""
    for g, step, most in PAN_RM_GRAN:
        if secs <= step * most:
            return g, step, max(1, -(-secs // step))
    raise ValueError("PAN-OS keeps dataplane history for at most 13 weeks (60 minutes per minute, 24 hours per hour, "
                     "7 days per day, 13 weeks per week)")


def pan_top_parse(text):
    """Management-plane 'show system resources' (Linux top) -> cpu %, memory %, load, uptime, top processes."""
    out = {}
    m = re.search(r"load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)", text)
    if m:
        out["load"] = [float(x) for x in m.groups()]
    m = re.search(r"\bup\s+(.+?),\s+\d+\s+users?", text)
    if m:
        out["uptime"] = m.group(1).strip()
    m = re.search(r"Cpu\(s\):(.*)", text)
    if m:
        f = {k: float(v) for v, k in re.findall(r"([\d.]+)\s*%?\s*(us|sy|ni|id|wa|hi|si|st)\b", m.group(1))}
        if "id" in f:
            out["cpu"] = max(0.0, 100.0 - f["id"])
            out["cpu_parts"] = f
    m = re.search(r"^\s*(KiB|MiB|GiB)?\s*Mem\s*:(.*)$", text, re.M)
    if m:
        f = {k: float(v) for v, k in re.findall(r"([\d.]+)k?\s+(total|free|used|buff/cache|buffers|cached)", m.group(2))}
        if f.get("total"):
            used = f.get("used", 0.0)
            if "buff/cache" not in f:   # older top: 'used' includes buffers and the page cache
                c = re.search(r"Swap:.*?([\d.]+)k?\s+cached", text)
                used -= f.get("buffers", 0.0) + (float(c.group(1)) if c else 0.0)
            gib = {"KiB": 1048576.0, "MiB": 1024.0, "GiB": 1.0}[m.group(1) or "KiB"]
            out.update(mem=100.0 * max(used, 0.0) / f["total"], mem_total_gib=f["total"] / gib,
                       mem_used_gib=max(used, 0.0) / gib)
    lines = text.splitlines()
    hdr = next((i for i, l in enumerate(lines) if re.match(r"^\s*PID\s+USER\b", l)), None)
    if hdr is not None:
        cols = lines[hdr].split()
        procs = []
        for l in lines[hdr + 1:]:
            parts = l.split(None, len(cols) - 1)
            if len(parts) == len(cols):
                procs.append(dict(zip(cols, parts)))
        procs.sort(key=lambda p: ru_float(p.get("%CPU")) or 0, reverse=True)
        out["procs"] = [{"pid": p.get("PID"), "process": p.get("COMMAND"), "user": p.get("USER"),
                         "cpu_pct": p.get("%CPU"), "mem_pct": p.get("%MEM"), "resident": p.get("RES")}
                        for p in procs[:10]]
        out["procs_mem"] = sorted(({"process": p.get("COMMAND"), "pid": p.get("PID"), "bytes": f5_size(p.get("RES")) or 0}
                                   for p in procs), key=lambda p: -p["bytes"])[:10]
    return out


def pan_dp_parse(data, gran="minute"):
    """'show running resource-monitor <gran>' -> per data processor: cores (values oldest first) and utilization."""
    res = data.get("result") if isinstance(data, dict) else None
    dps = ((res if isinstance(res, dict) else {}).get("resource-monitor") or {}).get("data-processors") or {}
    vals = lambda s: [acc_int(x) for x in str(acc_scalar(s) or "").split(",") if x.strip() != ""][::-1]
    out = []
    for dp, d in sorted(dps.items()) if isinstance(dps, dict) else []:
        mn = (d if isinstance(d, dict) else {}).get(gran) or {}
        cores = [(str(e.get("coreid")), vals(e.get("value"))) for e in as_list((mn.get("cpu-load-average") or {}).get("entry"))
                 if isinstance(e, dict)]
        peak = [(str(e.get("coreid")), vals(e.get("value"))) for e in as_list((mn.get("cpu-load-maximum") or {}).get("entry"))
                if isinstance(e, dict)]
        util = collections.OrderedDict((str(e.get("name")), vals(e.get("value")))
                                       for e in as_list((mn.get("resource-utilization") or {}).get("entry")) if isinstance(e, dict))
        out.append({"dp": dp, "cores": cores, "peak": peak, "util": util})
    return out


def pan_disk_parse(text):
    rows = []
    for l in text.splitlines():
        m = re.match(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+(\S+)\s*$", l.strip())
        if m:
            rows.append({"mounted_on": m.group(6), "filesystem": m.group(1), "size": m.group(2), "used": m.group(3),
                         "available": m.group(4), "use_pct": int(m.group(5))})
    return rows


def pan_resources(sess, v):
    t0 = time.time()
    secs = ru_range(v.get("range"))
    gran, step, nb = pan_rm_pick(secs)
    span = ru_span(nb * step)
    per = "per-%s averages" % gran
    cmds = collections.OrderedDict([
        ("mgmt", "<show><system><resources/></system></show>"),
        ("dp", "<show><running><resource-monitor><%s><last>%d</last></%s></resource-monitor></running></show>" % (gran, nb, gran)),
        ("sess", "<show><session><info/></session></show>"),
        ("disk", "<show><system><disk-space/></system></show>")])
    with concurrent.futures.ThreadPoolExecutor(4) as ex:
        futs = {k: ex.submit(pan_op, sess, c) for k, c in cmds.items()}
    got, notes = {}, []
    for k, f in futs.items():
        try:
            st, ok, data = f.result()
        except (urllib.error.URLError, OSError) as e:
            st, ok, data = 0, False, str(getattr(e, "reason", e))
        if ok:
            got[k] = data
        else:
            notes.append("%s: no answer (HTTP %s) %s" % (cmds[k], st, str(data)[:200]))
    if not got:
        return {"ok": False, "error": "no resource command answered. " + " ".join(notes)}
    tiles, charts, findings, data = [], [], [], collections.OrderedDict()
    heats, bars = [], []
    text = lambda d: str(acc_scalar((d or {}).get("result")) or "")
    rows = []

    def row(resource, current, detail="", hi=None, med=None, obj=None, issue=None):
        sev = ru_sev(current, hi, med) if hi is not None else None
        rows.append({"resource": resource, "current": "" if current is None else
                     ("%.1f%%" % current if hi is not None else current), "detail": detail,
                     "status": {"high": "HIGH", "medium": "warning"}.get(sev, "ok") if hi is not None else ""})
        if sev:
            findings.append(finding(sev, obj or resource, issue or "%s at %.1f%%" % (resource, current), detail))
    top = pan_top_parse(text(got.get("mgmt"))) if "mgmt" in got else {}
    if top.get("cpu") is not None:
        p = top.get("cpu_parts", {})
        row("Management CPU", top["cpu"], "user %.1f%% · system %.1f%% · iowait %.1f%% (one sample)" % (
            p.get("us", 0), p.get("sy", 0), p.get("wa", 0)), 90, 80)
        tiles.append(ru_tile("Management CPU", top["cpu"], "now (one sample)"))
    if top.get("mem") is not None:
        d = "%.1f of %.1f GiB used, excluding cache" % (top["mem_used_gib"], top["mem_total_gib"])
        row("Management memory", top["mem"], d, 95, 90)
        tiles.append(ru_tile("Management memory", top["mem"], d, 95, 90))
    if top.get("load"):
        rows.append({"resource": "Management load average", "current": " / ".join("%.2f" % x for x in top["load"]),
                     "detail": "1 / 5 / 15 minutes", "status": ""})
    if top.get("uptime"):
        rows.append({"resource": "Uptime", "current": top["uptime"], "detail": "", "status": ""})

    for dp in pan_dp_parse(got.get("dp"), gran) if "dp" in got else []:
        cores = [(c, vals) for c, vals in dp["cores"] if vals]
        active = [(c, vals) for c, vals in cores if any(vals)] or cores
        if active:
            n = min(len(vals) for _, vals in active)
            avg = [sum(vals[-n:][i] for _, vals in active) / float(len(active)) for i in range(n)]
            busiest = max(active, key=lambda cv: cv[1][-1])
            cur, mean, pk = avg[-1], sum(avg) / n, max(avg)
            pk_cores = [x for _, x in dp["peak"] if x and any(x)]   # cpu-load-maximum: each core's highest value per bucket
            m_ = min([n] + [len(x) for x in pk_cores])
            pmax = [max(x[-m_:][i] for x in pk_cores) for i in range(m_)] if pk_cores else []
            row("Dataplane CPU (%s)" % dp["dp"], cur, "average of %d active cores, %s · %s: mean %.1f%%, highest %s %.1f%%%s · "
                "busiest core in the latest %s: %s at %d%%" % (
                    len(active), per, span, mean, gran, pk,
                    ", highest single-core maximum %d%%" % max(pmax) if pmax else "", gran, busiest[0], busiest[1][-1]),
                90, 80, issue="Dataplane CPU %s at %.1f%% (latest %s)" % (dp["dp"], cur, gran))
            if ru_sev(cur, 90, 80) is None and pk >= (95 if gran == "minute" else 85):
                findings.append(finding("medium", "Dataplane CPU (%s)" % dp["dp"],
                                        "Dataplane CPU averaged %.1f%% over one %s in the %s" % (pk, gran, span)))
            tiles.append(ru_tile("Dataplane CPU %s" % dp["dp"], cur, "%s: mean %.0f%% · highest %s %.0f%%" % (span, mean, gran, pk),
                                 spark=avg))
            charts.append({"title": "Dataplane CPU %s · %s · %s (%%)" % (dp["dp"], span, per), "t": ru_labels(n, step),
                           "fmt": "pct", "series": [["Average of active cores", [round(x, 1) for x in avg]],
                                                    ["Busiest core (%s)" % busiest[0], busiest[1][-n:]]] +
                                                   ([["Highest core maximum", [0] * (n - m_) + pmax]] if pmax else [])})
            hc = sorted([(c, v) for c, v in cores if len(v) >= n], key=lambda cv: int(cv[0]) if cv[0].isdigit() else 9999)
            heats.append({"title": "Dataplane cores %s · %s · %s (%% load per core)" % (dp["dp"], span, per),
                          "t": ru_labels(n, step), "rows": [["core %s" % c, v[-n:]] for c, v in hc]})
            data["dataplane_cores_%s" % dp["dp"]] = [
                {"core": c, "now_pct": vals[-1], "mean_pct": round(sum(vals) / float(len(vals)), 1), "peak_pct": max(vals),
                 "note": "" if any(vals) else "idle all period (reserved / not used for traffic); left out of the average"}
                for c, vals in cores]
        lim = {"session": (90, 80), "packet buffer": (80, 50), "packet descriptor": (80, 50),
               "packet descriptor (on-chip)": (80, 50)}
        series = []
        for name, vals in dp["util"].items():
            if not vals:
                continue
            hi, med = lim.get(name.lower(), (90, 80))
            row("%s (%s)" % (name.capitalize(), dp["dp"]), float(vals[-1]),
                "latest %s · %s: mean %.1f%%, highest %s %d%%" % (gran, span, sum(vals) / float(len(vals)), gran, max(vals)),
                hi, med)
            if name.lower() in lim:
                series.append([name, vals])
            if name.lower() == "packet buffer":
                tiles.append(ru_tile("Packet buffer %s" % dp["dp"], vals[-1], "highest %s %d%% (%s)" % (gran, max(vals), span),
                                     80, 50, spark=vals))
        if series:
            n = min(len(s[1]) for s in series)
            charts.append({"title": "Dataplane resources %s · %s · %s (%%)" % (dp["dp"], span, per), "t": ru_labels(n, step),
                           "fmt": "pct",
                           "series": [[s[0], s[1][-n:]] for s in series]})
    if "dp" in got and not any(r["resource"].startswith("Dataplane CPU") for r in rows):
        notes.append("The resource monitor returned no dataplane CPU data (some VM / Panorama models have none).")

    si = (got.get("sess") or {}).get("result") if "sess" in got else None
    if isinstance(si, dict):
        si = acc_flat(si)
        act, mx = ru_float(si.get("num-active")), ru_float(si.get("num-max"))
        if act is not None and mx:
            pct = 100.0 * act / mx
            row("Session table", pct, "{:,} of {:,} sessions (TCP {} · UDP {} · ICMP {})".format(
                int(act), int(mx), si.get("num-tcp", "?"), si.get("num-udp", "?"), si.get("num-icmp", "?")), 90, 80)
            tiles.append(ru_tile("Session table", pct, "{:,} of {:,}".format(int(act), int(mx))))
        for k, lbl in (("cps", "Connections per second"), ("kbps", "Throughput (kbps)"), ("pps", "Packets per second")):
            if si.get(k) not in (None, ""):
                rows.append({"resource": lbl, "current": si[k], "detail": "", "status": ""})
                tiles.append(ru_tile(lbl, ru_float(si[k]), "now", fmt="num"))
    disks = pan_disk_parse(text(got.get("disk"))) if "disk" in got else []
    for d in disks:
        sev = ru_sev(d["use_pct"], 90, 80)
        d["status"] = {"high": "HIGH", "medium": "warning"}.get(sev, "ok")
        if sev:
            findings.append(finding(sev, "Disk %s" % d["mounted_on"], "Disk %s is %d%% full" % (d["mounted_on"], d["use_pct"]),
                                    "%s used of %s, %s free" % (d["used"], d["size"], d["available"])))
    if disks:
        worst = max(disks, key=lambda d: d["use_pct"])
        tiles.append(ru_tile("Fullest disk", worst["use_pct"], worst["mounted_on"]))
    if top.get("procs"):
        bars.append({"title": "Top 10 management-plane processes by CPU", "fmt": "pct",
                     "rows": [["%s (%s)" % (p["process"], p["pid"]), ru_float(p["cpu_pct"]) or 0] for p in top["procs"]]})
    if top.get("procs_mem"):
        bars.append({"title": "Top 10 management-plane processes by memory (resident)", "fmt": "bytes",
                     "rows": [["%s (%s)" % (p["process"], p["pid"]), p["bytes"]] for p in top["procs_mem"] if p["bytes"]]})
    if disks:
        bars.append({"title": "Disk use by partition", "fmt": "pct",
                     "rows": [[d["mounted_on"], d["use_pct"]] for d in sorted(disks, key=lambda d: -d["use_pct"])]})
    data = collections.OrderedDict([("utilization", rows)] + list(data.items()))
    if top.get("procs"):
        data["top_processes_management_plane"] = top["procs"]
    if disks:
        data["disk"] = disks
    notes.insert(0, "Dataplane history: %s, %s from the resource monitor (the latest bucket is still filling). Management "
                    "CPU / memory, the session table, CPS / throughput and disk are current values: PAN-OS keeps no history "
                    "of them in the API." % (span, per))
    if secs != nb * step:
        notes.insert(0, "Asked for %s; shown: %s (whole %ss)." % (ru_span(secs), span, gran))
    notes.append("Thresholds: CPU / sessions warn at 80%, high at 90%; packet buffers / descriptors warn at 50%, high at 80%; "
                 "management memory warn at 90%, high at 95% (cache excluded); disk warn at 80%, high at 90%.")
    pick = lambda pre: next((r["current"] for r in rows if r["resource"].startswith(pre)), "n/a")
    label = "MGMT CPU %s · DP CPU %s · MGMT MEM %s · SESSIONS %s · PKT BUFFER %s · %s" % (
        pick("Management CPU"), pick("Dataplane CPU"), pick("Management memory"), pick("Session table"), pick("Packet buffer"),
        span.upper())
    out = ru_result(t0, " + ".join(cmds[k] for k in cmds), tiles, charts, findings, data, notes, label)
    out["heat"], out["bars"] = heats, bars
    return out


FG_RES_LABELS = collections.OrderedDict([
    ("cpu", ("CPU", "pct")), ("mem", ("Memory", "pct")), ("disk", ("Log disk", "pct")),
    ("session", ("Sessions (IPv4)", "num")), ("session6", ("Sessions (IPv6)", "num")),
    ("setuprate", ("Session setup rate /s (IPv4)", "num")), ("setuprate6", ("Session setup rate /s (IPv6)", "num")),
    ("npu_session", ("NPU sessions (IPv4)", "num")), ("npu_session6", ("NPU sessions (IPv6)", "num")),
    ("nturbo_session", ("nTurbo sessions", "num")), ("disk_lograte", ("Disk log rate /s", "num")),
    ("faz_lograte", ("FortiAnalyzer log rate /s", "num")), ("forticloud_lograte", ("FortiCloud log rate /s", "num")),
    ("gtp_tunnel", ("GTP tunnels", "num")), ("gtp_tunnel_setup_rate", ("GTP tunnel setup rate /s", "num"))])


def fg_hist(item, interval):
    """(points oldest first [(epoch, value)], average, max) from a resource/usage 'historical' block."""
    h = (item or {}).get("historical") if isinstance(item, dict) else None
    if not isinstance(h, dict) or not h:
        return [], None, None
    h = h.get(interval) or next(iter(h.values()))
    pts = []
    for p in (h.get("values") if isinstance(h, dict) else None) or []:
        if isinstance(p, (list, tuple)) and len(p) >= 2 and ru_float(p[1]) is not None:
            pts.append((to_epoch(p[0]) or 0, ru_float(p[1])))
        elif isinstance(p, dict) and ru_float(first(p, "value", "v")) is not None:
            pts.append((to_epoch(first(p, "timestamp", "time", "t")) or 0, ru_float(first(p, "value", "v"))))
    pts.sort(key=lambda x: x[0])
    return pts, ru_float(h.get("average")) if isinstance(h, dict) else None, ru_float(h.get("max")) if isinstance(h, dict) else None


# FortiOS resource/usage history windows (the longest is 24 hours)
FG_RES_INTERVALS = (("1-min", 60), ("10-min", 600), ("30-min", 1800), ("1-hour", 3600), ("12-hour", 43200),
                    ("24-hour", 86400))


def fg_conserve_events(sess, secs):
    """Memory conserve-mode enter / leave events from the system event log within the last `secs` seconds."""
    cutoff, notes = time.time() - secs, []
    for src in ("disk", "memory"):
        res = None
        for q in ([("rows", "1000"), ("filter", "msg=@conserve")], [("rows", "1000")]):
            st, ok, data = rest_get(sess, "/api/v2/log/%s/event/system?%s" % (src, urllib.parse.urlencode(q)))
            res = data.get("results") if ok and isinstance(data, dict) else None
            if isinstance(res, list):
                if len(q) == 1:
                    notes.append("The event log filter was not accepted; matched 'conserve' locally in the newest 1000 "
                                 "system events (%s), which may not reach back over the whole range." % src)
                break
        if not isinstance(res, list):
            continue
        rows, oldest = [], None
        for e in (acc_flat(x) for x in res if isinstance(x, dict)):
            ep = fg_event_epoch(e)
            if ep is not None:
                oldest = ep if oldest is None else min(oldest, ep)
                if ep < cutoff:
                    continue
            msg = str(first(e, "msg", "logdesc"))
            if "conserve" not in (msg + " " + str(e.get("logdesc") or "")).lower():
                continue
            low = msg.lower()
            rows.append({"time": ("%s %s" % (e.get("date") or "", e.get("time") or "")).strip(),
                         "event": "entered" if "enter" in low else "left" if ("leave" in low or "exit" in low) else "",
                         "message": msg, "level": e.get("level", ""), "_t": ep or 0})
        rows.sort(key=lambda r: r["_t"])
        for r in rows:
            r.pop("_t", None)
        if len(res) >= 1000 and oldest is not None and oldest > cutoff:
            notes.append("1000 system events were read (%s) and they only reach back to %s; older conserve-mode events "
                         "in the range are not shown." % (src, time.strftime("%Y-%m-%d %H:%M", time.localtime(oldest))))
        return rows, src, notes
    return None, None, notes + ["Could not read the system event log (disk or memory); needs Log & Report read access."]


def fg_resources(sess, v):
    t0 = time.time()
    secs = ru_range(v.get("range"))
    interval, isecs = next((x for x in FG_RES_INTERVALS if x[1] >= secs), FG_RES_INTERVALS[-1])
    span = ru_span(isecs)
    paths = collections.OrderedDict([
        ("usage", "/api/v2/monitor/system/resource/usage?interval=%s" % interval),
        ("perf", "/api/v2/monitor/system/performance/status"),
        ("glob", "/api/v2/cmdb/system/global"),
        ("status", "/api/v2/monitor/system/status")])
    with concurrent.futures.ThreadPoolExecutor(5) as ex:
        futs = {k: ex.submit(rest_get, sess, p) for k, p in paths.items()}
        f_cons = ex.submit(fg_conserve_events, sess, secs)
    got, notes = {}, []
    for k, f in futs.items():
        try:
            st, ok, data = f.result()
        except (urllib.error.URLError, OSError) as e:
            st, ok, data = 0, False, str(getattr(e, "reason", e))
        if ok and isinstance(data, dict):
            got[k] = data.get("results") if data.get("results") is not None else data
        elif k in ("usage", "perf"):
            notes.append("GET %s: HTTP %s (not available on this FortiOS version or no access)" % (paths[k], st))
    if "usage" not in got:   # older FortiOS may not accept the interval parameter
        st, ok, data = rest_get(sess, "/api/v2/monitor/system/resource/usage")
        if ok and isinstance(data, dict):
            got["usage"] = data.get("results")
    if "usage" not in got and "perf" not in got:
        return {"ok": False, "error": "no resource endpoint answered. Does the API admin profile have read access to "
                                      "System? " + " ".join(notes)}
    tiles, charts, findings, rows = [], [], [], []
    g = got.get("glob") if isinstance(got.get("glob"), dict) else {}
    red = ru_float(g.get("memory-use-threshold-red")) or 88.0
    extreme = ru_float(g.get("memory-use-threshold-extreme")) or 95.0
    green = ru_float(g.get("memory-use-threshold-green")) or 82.0
    usage = got.get("usage") if isinstance(got.get("usage"), dict) else {}
    series_pct, t_labels = [], []
    tfmt = "%H:%M" if isecs <= 3600 else "%m-%d %H:%M"
    for key, item in usage.items():
        item0 = item[0] if isinstance(item, list) and item else item
        if not isinstance(item0, dict):
            continue
        cur = ru_float(item0.get("current"))
        pts, avg, mx = fg_hist(item0, interval)
        label, fmt = FG_RES_LABELS.get(key, (key.replace("_", " ").capitalize(), "num"))
        detail = "%s: average %s, max %s" % (span,
            "n/a" if avg is None else ("%.1f%%" % avg if fmt == "pct" else "{:,.0f}".format(avg)),
            "n/a" if mx is None else ("%.1f%%" % mx if fmt == "pct" else "{:,.0f}".format(mx))) if (avg is not None or mx is not None) else ""
        status = ""
        if key == "mem" and cur is not None:
            sev = "high" if cur >= red else "medium" if cur >= green else None
            status = {"high": "HIGH", "medium": "warning"}.get(sev, "ok")
            if cur >= extreme:
                findings.append(finding("high", "Memory", "Memory at %.0f%%: at or above the extreme conserve-mode threshold "
                                        "(%.0f%%); new sessions are being dropped" % (cur, extreme)))
            elif cur >= red:
                findings.append(finding("high", "Memory", "Memory at %.0f%%: at or above the red threshold (%.0f%%); the "
                                        "FortiGate enters conserve mode and stops proxy / UTM inspection of new sessions" % (cur, red)))
            elif cur >= green:
                findings.append(finding("medium", "Memory", "Memory at %.0f%%: above the green threshold (%.0f%%); if conserve "
                                        "mode was entered it has not left it yet, and it is close to the red threshold (%.0f%%)"
                                        % (cur, green, red)))
            detail = (detail + "; " if detail else "") + "conserve mode at %.0f%% (red), extreme at %.0f%%, leaves at %.0f%% (green)" % (
                red, extreme, green)
            tiles.append({"label": "Memory", "value": round(cur, 1), "fmt": "pct", "sub": "conserve mode at %.0f%%" % red,
                          "kind": {"high": "bad", "medium": "warn"}.get(sev, ""), "spark": [p[1] for p in pts]})
        elif fmt == "pct" and cur is not None:
            hi, med = (90, 80)
            sev = ru_sev(cur, hi, med)
            status = {"high": "HIGH", "medium": "warning"}.get(sev, "ok")
            if sev:
                findings.append(finding(sev, label, "%s at %.1f%%" % (label, cur), detail))
            elif key == "cpu" and mx is not None and mx >= 95:
                findings.append(finding("medium", label, "CPU peaked at %.0f%% in the %s" % (mx, span), detail))
            tiles.append(ru_tile(label, cur, detail, spark=[p[1] for p in pts]))
        elif cur is not None and key in ("session", "setuprate", "disk_lograte", "faz_lograte", "npu_session"):
            if cur or key in ("session", "setuprate"):
                tiles.append(ru_tile(label, cur, detail, fmt="num", spark=[p[1] for p in pts]))
        rows.append({"resource": label, "current": "" if cur is None else ("%.1f%%" % cur if fmt == "pct" else "{:,.0f}".format(cur)),
                     "detail": detail, "status": status})
        if fmt == "pct" and len(pts) > 1:
            series_pct.append([label, [round(p[1], 1) for p in pts]])
            if len(pts) > len(t_labels):
                t_labels = [time.strftime(tfmt, time.localtime(p[0])) if p[0] else "" for p in pts]
        if key in ("session", "setuprate") and len(pts) > 1:
            charts.append({"title": "%s · %s" % (label, span), "fmt": "num",
                           "t": [time.strftime(tfmt, time.localtime(p[0])) if p[0] else "" for p in pts],
                           "series": [[label, [p[1] for p in pts]]]})
    if series_pct:
        n = min(len(s[1]) for s in series_pct)
        charts.insert(0, {"title": "CPU / memory / log disk · %s (%%)" % span, "fmt": "pct", "t": t_labels[-n:],
                          "series": [[s[0], s[1][-n:]] for s in series_pct]})
    try:
        cons, cons_src, cons_notes = f_cons.result()
    except (ValueError, urllib.error.URLError, OSError) as e:
        cons, cons_src, cons_notes = None, None, ["Could not read the system event log: %s" % getattr(e, "reason", e)]
    notes.extend(cons_notes)
    if cons is not None:
        entered = sum(1 for r in cons if r["event"] == "entered")
        tiles.append({"label": "Conserve-mode entries", "value": entered, "fmt": "num", "sub": ru_span(secs),
                      "kind": "bad" if entered else "", "spark": []})
        rows.append({"resource": "Memory conserve mode", "current": "%d entr%s" % (entered, "y" if entered == 1 else "ies"),
                     "detail": "%s, from the system event log (%s)" % (ru_span(secs), cons_src),
                     "status": "HIGH" if entered else "ok"})
        if entered:
            findings.append(finding("high", "Memory", "Entered memory conserve mode %d time(s) in the %s" % (entered, ru_span(secs)),
                                    "latest: %s" % next((r["time"] for r in reversed(cons) if r["event"] == "entered"), "")))
    data = collections.OrderedDict([("utilization", rows)])
    if cons:
        data["conserve_mode_events"] = cons
    perf = got.get("perf") if isinstance(got.get("perf"), dict) else {}
    cpu = perf.get("cpu") if isinstance(perf.get("cpu"), dict) else {}
    cores = [c for c in as_list(cpu.get("cores")) if isinstance(c, dict)]
    if cores:
        data["cpu_cores"] = [{"core": i, "used_pct": round(100 - (ru_float(c.get("idle")) or 0), 1),
                              "user_pct": c.get("user"), "system_pct": c.get("system"), "iowait_pct": c.get("iowait"),
                              "irq_pct": c.get("irq"), "softirq_pct": c.get("softirq")} for i, c in enumerate(cores)]
        busy = max(data["cpu_cores"], key=lambda c: c["used_pct"])
        if busy["used_pct"] >= 95 and len(cores) > 1:
            findings.append(finding("medium", "CPU core %s" % busy["core"], "One CPU core at %.0f%%" % busy["used_pct"],
                                    "a single busy core can bottleneck a process (e.g. IPS engine, WAD) while the average looks fine"))
        if not any(r["resource"] == "CPU" for r in rows) and cpu.get("idle") is not None:
            cur = 100 - (ru_float(cpu.get("idle")) or 0)
            rows.insert(0, {"resource": "CPU", "current": "%.1f%%" % cur, "detail": "from performance status",
                            "status": {"high": "HIGH", "medium": "warning"}.get(ru_sev(cur, 90, 80), "ok")})
            tiles.insert(0, ru_tile("CPU", cur))
    mem = perf.get("mem") if isinstance(perf.get("mem"), dict) else {}
    if ru_float(mem.get("total")):
        tot, used = ru_float(mem.get("total")), ru_float(mem.get("used")) or 0
        scale = 1073741824.0 if tot > 1e8 else 1048576.0 if tot > 1e5 else 1024.0   # bytes / KiB / MiB
        rows.append({"resource": "Memory size", "current": "%.1f GiB" % (tot / scale),
                     "detail": "used %.1f GiB · freeable %.1f GiB" % (used / scale, (ru_float(mem.get("freeable")) or 0) / scale),
                     "status": ""})
    st = got.get("status") if isinstance(got.get("status"), dict) else {}
    if st.get("model_name") or st.get("hostname"):
        notes.insert(0, "Device: %s" % " ".join(str(x) for x in (st.get("hostname"), st.get("model_name"),
                                                                    st.get("model_number") or st.get("model")) if x))
    notes.append("Thresholds: CPU / log disk warn at 80%%, high at 90%%; memory warn at the green conserve-mode threshold "
                 "(%.0f%%), high at the red one (%.0f%%), read from 'config system global'." % (green, red))
    if "glob" not in got:
        notes.append("Could not read config system global; default conserve-mode thresholds were used.")
    if secs > isecs:
        notes.insert(0, "FortiOS keeps resource history for at most 24 hours, so the charts and averages cover the %s. "
                        "Conserve-mode events cover the whole %s (system event log). For longer CPU / memory history use "
                        "FortiAnalyzer or SNMP monitoring." % (span, ru_span(secs)))
    else:
        notes.insert(0, "Charts and averages: the %s (FortiOS '%s' history)." % (span, interval))
    pick = lambda name: next((r["current"] for r in rows if r["resource"] == name), "n/a")
    label = "CPU %s · MEMORY %s · LOG DISK %s · SESSIONS %s · CONSERVE MODE %s · %s" % (
        pick("CPU"), pick("Memory"), pick("Log disk"), pick("Sessions (IPv4)"), pick("Memory conserve mode").upper(),
        ru_span(secs).upper())
    return ru_result(t0, " + ".join("GET " + p for p in paths.values()), tiles, charts, findings, data, notes, label)


# ---- F5 performance dashboard: CPU per core, memory, subsystems, top processes, disk, history up to 24 hours -----
F5_PERF_MAX = 86400
# Process name -> BIG-IP subsystem (module); first match wins
F5_SUBSYS = (
    ("tmm (traffic)", re.compile(r"^tmm")),
    ("waf (ASM)", re.compile(r"^(bd|bd_agent|bd_\w+|asm\w*|pabnagd|policy_engine|anomaly_engine)")),
    ("l7_dos", re.compile(r"^(dosl7d|admd)")),
    ("log_analytics (AVR)", re.compile(r"^(avrd|avr\w+|monpd)")),
    ("fw (AFM)", re.compile(r"^(pccd|autodosd|dwbld|iprepd|bdosd)")),
    ("APM", re.compile(r"^(apmd|websso|eam|oauth|localdbmgr|vdi|rba|acctd)")),
    ("DNS / GTM", re.compile(r"^(gtmd|big3d|zxfrd|named|zrd)")),
    ("control plane", re.compile(r"^(mcpd|restjavad|restnoded|java|httpd|tomcat|icrd\w*|iControl\w*|scriptd|tmrouted|"
                                 r"sod|bigd|statsd|merged|alertd|syslog\w*|devmgmtd|csyncd|chmand|lind|lopd|qkview|"
                                 r"mysqld|tmsh|bcm56xxd|snmpd|sshd|systemd|rsyslogd|auditd|crond|ntpd|mgmt\w*)")),
)
CPU_STATES = ("softirq", "iowait", "stolen", "system", "steal", "user", "nice", "idle", "irq", "sys")


def f5_subsys(name):
    return next((s for s, rx in F5_SUBSYS if rx.match(name or "")), "other")


def f5_bytes(n):
    n = float(n or 0)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or u == "TiB":
            return ("%.0f %s" if u == "B" else "%.2f %s") % (n, u)
        n /= 1024.0


def f5_stat_rows(node, out=None):
    """Every 'entries' block of a stats response as one flat {field: value} row."""
    out = [] if out is None else out
    if isinstance(node, dict):
        ents = node.get("entries")
        if isinstance(ents, dict):
            row = {}
            for k, v in ents.items():
                if isinstance(v, dict) and ("value" in v or "description" in v) and len(v) <= 2:
                    row[k.rsplit("/", 1)[-1]] = v.get("value", v.get("description"))
            if row:
                out.append(row)
        for v in node.values():
            if isinstance(v, (dict, list)):
                f5_stat_rows(v, out)
    elif isinstance(node, list):
        for v in node:
            f5_stat_rows(v, out)
    return out


def f5_size(v):
    """top RES column ('123456' KiB, '1.2g', '512m', '3.1t') -> bytes."""
    m = re.match(r"^([\d.]+)([kmgtp]?)$", str(v or "").strip().lower())
    if not m:
        return None
    try:
        return float(m.group(1)) * {"": 1024, "k": 1024, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40, "p": 1 << 50}[m.group(2)]
    except ValueError:
        return None


def f5_top_parse(text_):
    """Process rows from `top -b`: [{pid, user, name, cpu_pct, res_bytes, mem_pct}]."""
    procs, cols = [], None
    for line in text_.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "PID" and "COMMAND" in parts:
            cols = {c: i for i, c in enumerate(parts)}
            continue
        if cols and parts[0].isdigit() and len(parts) >= len(cols):
            g = lambda c: parts[cols[c]] if c in cols else ""
            procs.append({"pid": int(parts[0]), "user": g("USER"), "name": " ".join(parts[cols["COMMAND"]:]),
                          "cpu_pct": ru_float(g("%CPU")) or 0.0, "res_bytes": f5_size(g("RES")) or 0.0,
                          "mem_pct": ru_float(g("%MEM")) or 0.0})
    return procs


def f5_df_parse(text_):
    out = []
    for line in text_.splitlines()[1:]:
        p = line.split()
        if len(p) < 6 or not p[1].isdigit() or p[0] in ("tmpfs", "devtmpfs", "none", "shm", "udev"):
            continue
        if int(p[1]) == 0 or p[5].startswith(("/dev", "/run", "/sys", "/proc")):
            continue
        out.append({"mounted_on": p[5], "size": f5_bytes(int(p[1]) * 1024), "used": f5_bytes(int(p[2]) * 1024),
                    "available": f5_bytes(int(p[3]) * 1024), "use_pct": int(ru_float(p[4]) or 0), "filesystem": p[0]})
    return out


def f5_rrd_parse(text_):
    """`rrdtool fetch` output -> (data source names, [(epoch, [value or None, ...])])."""
    names, rows = [], []
    for line in text_.splitlines():
        head = line.split(":", 1)[0].strip()
        if ":" in line and head.isdigit():
            vs = []
            for x in line.split(":", 1)[1].split():
                try:
                    f = float(x)
                    vs.append(None if f != f else f)   # nan
                except ValueError:
                    vs.append(None)
            rows.append((int(head), vs))
        elif line.strip() and not names and not rows:
            names = line.split()
    return names, rows


def f5_rrd_series(fname, names, rows):
    """Percentage series from one RRD file: CPU (user / system / idle ... states, one series per group of states)
    or memory (used / total). Returns ([(kind, label, {epoch: pct})], recognised)."""
    low = [n.lower() for n in names]
    groups = collections.OrderedDict()
    for i, n in enumerate(low):
        st = next((s for s in CPU_STATES if s in n), None)
        if st:
            groups.setdefault(n.replace(st, "", 1).strip("_- "), {})[st] = i
    out = []
    for grp, idx in groups.items():
        if "idle" not in idx or len(idx) < 3:
            continue
        pts = {}
        for ts, vs in rows:
            parts = [vs[i] for i in idx.values() if i < len(vs) and vs[i] is not None]
            tot = sum(parts)
            if len(parts) == len(idx) and tot > 0:
                idle = vs[idx["idle"]] + (vs[idx["iowait"]] if "iowait" in idx else 0)
                pts[ts] = max(0.0, min(100.0, 100.0 * (tot - idle) / tot))
        out.append(("cpu", (fname + " " + (grp if len(grp) > 1 else "")).strip(), pts))
    mem = collections.OrderedDict()
    for i, n in enumerate(low):
        for key, role in (("used", "used"), ("total", "total"), ("size", "total")):
            if key in n:
                mem.setdefault(n.replace(key, "", 1).strip("_- "), {})[role] = i
                break
    for grp, idx in mem.items():
        if "used" in idx and "total" in idx:
            pts = {}
            for ts, vs in rows:
                u = vs[idx["used"]] if idx["used"] < len(vs) else None
                t = vs[idx["total"]] if idx["total"] < len(vs) else None
                if u is not None and t:
                    pts[ts] = max(0.0, min(100.0, 100.0 * u / t))
            name = next((n for k, n in (("tmm", "TMM"), ("other", "other (control plane)"), ("swap", "swap"))
                         if k in grp), grp if len(grp) > 1 else "")
            out.append(("mem", (fname + " " + name).strip(), pts))
    return [s for s in out if s[2]], bool(out)


def f5_downsample(ts_list, series, maxn=240):
    """Average blocks so a chart has at most maxn points. series: [[name, [values]]]."""
    n = len(ts_list)
    if n <= maxn:
        return ts_list, series
    k = -(-n // maxn)
    out = []
    for name, vals in series:
        v2 = []
        for i in range(0, n, k):
            blk = [x for x in vals[i:i + k] if x is not None]
            v2.append(sum(blk) / len(blk) if blk else None)
        out.append([name, v2])
    return [ts_list[i] for i in range(0, n, k)], out


def f5_hist_chart(title, sers, maxlines=6):
    """Line chart over the union of timestamps; with more than maxlines series: average, busiest and quietest."""
    allts = sorted(set(ts for _, pts in sers for ts in pts))
    if len(allts) < 2:
        return None
    series = [[lbl, [pts.get(ts) for ts in allts]] for lbl, pts in sers]
    if len(series) > maxlines:
        cols = list(zip(*[s[1] for s in series]))

        def agg(fn):
            return [fn([x for x in c if x is not None]) if any(x is not None for x in c) else None for c in cols]
        series = [["average of %d cores" % len(series), agg(lambda xs: sum(xs) / len(xs))],
                  ["busiest core", agg(max)], ["quietest core", agg(min)]]
    ts2, series = f5_downsample(allts, series)
    return {"title": title, "fmt": "pct", "t": [time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) for t in ts2],
            "series": [[n, [None if x is None else round(x, 1) for x in v]] for n, v in series]}


def f5_perf(sess, v):
    t0 = time.time()
    secs = ru_range(v.get("range"))
    if secs > F5_PERF_MAX:
        raise ValueError("BIG-IP performance history: up to 24 hours (24h)")
    span, use_bash = ru_span(secs), bool(v.get("_ack"))
    paths = collections.OrderedDict([("cpu", "/mgmt/tm/sys/cpu"), ("host", "/mgmt/tm/sys/host-info"),
                                     ("mem", "/mgmt/tm/sys/memory"), ("perf", "/mgmt/tm/sys/performance/all-stats"),
                                     ("version", "/mgmt/tm/sys/version")])
    if not use_bash:
        paths["proc"] = "/mgmt/tm/sys/proc-info"
    script = ("echo '### NPROC'; nproc 2>/dev/null; "
              "echo '### TOP'; COLUMNS=250 top -b -n 2 -d 1 2>/dev/null | awk '/^top -/{n++} n==2' | head -n 600; "
              "echo '### DF'; df -P -k 2>/dev/null; "
              "echo '### RRDLIST'; ls -1 /var/rrd 2>/dev/null | head -n 400; "
              "for f in $(ls -1 /var/rrd 2>/dev/null | grep -iE 'cpu|mem' | head -n 64); do echo \"### RRD $f\"; "
              "rrdtool fetch \"/var/rrd/$f\" AVERAGE -r %d -s -%d -e now 2>&1 | head -n 400; done"
              % (max(10, secs // 240), secs))
    with concurrent.futures.ThreadPoolExecutor(7) as ex:
        futs = {k: ex.submit(rest_get, sess, p) for k, p in paths.items()}
        f_bash = ex.submit(f5_bash, sess, script, 90) if use_bash else None
    got, notes, tiles, charts, bars, findings = {}, [], [], [], [], []
    for k, f in futs.items():
        try:
            st, ok, body = f.result()
        except (urllib.error.URLError, OSError) as e:
            st, ok, body = 0, False, str(getattr(e, "reason", e))
        if ok and isinstance(body, dict):
            got[k] = body
        elif k not in ("proc", "host"):
            notes.append("GET %s: HTTP %s" % (paths[k], st))
    sections = {}
    if f_bash:
        audit(sess, "F5 util/bash read-only performance read (top, df, rrdtool fetch, %s)" % span)
        try:
            st, ok, out, bdata = f_bash.result()
        except (urllib.error.URLError, OSError) as e:
            st, ok, out, bdata = 0, False, "", {"message": str(getattr(e, "reason", e))}
        if ok:
            cur_key, buf = None, {}
            for line in out.splitlines():
                if line.startswith("### "):
                    cur_key = line[4:].strip()
                    buf[cur_key] = []
                elif cur_key:
                    buf[cur_key].append(line)
            sections = {k: "\n".join(x) for k, x in buf.items()}
        else:
            notes.append(f5_bash_error(st, bdata, "util/bash performance read") + " History, processes, subsystems and "
                         "disk are skipped; the current values come from read-only REST.")
    if not got and not sections:
        return {"ok": False, "error": "no performance data answered. " + " ".join(notes)}
    data, rows = collections.OrderedDict(), []

    # CPU now, per core: sys/cpu (or host-info) 5 s / 1 min / 5 min average idle %
    cores = {}
    for src in ("cpu", "host"):
        for r in f5_stat_rows(got.get(src)):
            if "cpuId" in r and ru_float(r.get("fiveSecAvgIdle")) is not None:
                cid = int(ru_float(r["cpuId"]) or 0)
                cores.setdefault(cid, {"core": cid, "now_pct": round(100 - ru_float(r["fiveSecAvgIdle"]), 1),
                                       "1min_pct": round(100 - (ru_float(r.get("oneMinAvgIdle")) or 100), 1),
                                       "5min_pct": round(100 - (ru_float(r.get("fiveMinAvgIdle")) or 100), 1),
                                       "user_pct": r.get("fiveSecAvgUser", ""), "system_pct": r.get("fiveSecAvgSystem", ""),
                                       "iowait_pct": r.get("fiveSecAvgIowait", "")})
        if cores:
            break
    cores = [cores[k] for k in sorted(cores)]
    ncpu = len(cores) or int(ru_float((sections.get("NPROC") or "").strip()) or 0) or None
    if cores:
        avg = sum(c["now_pct"] for c in cores) / len(cores)
        avg5 = sum(c["5min_pct"] for c in cores) / len(cores)
        busy = max(cores, key=lambda c: c["now_pct"])
        tiles.append(ru_tile("Avg. CPU utilization", avg, "%d cores · 5 min average %.1f%%" % (len(cores), avg5)))
        tiles.append(ru_tile("Busiest core", busy["now_pct"], "core %s · 5 min average %.1f%%" % (busy["core"], busy["5min_pct"])))
        sev = ru_sev(avg5, 90, 80)
        rows.append({"resource": "CPU (all cores)", "current": "%.1f%%" % avg, "detail": "5 min average %.1f%%" % avg5,
                     "status": {"high": "HIGH", "medium": "warning"}.get(sev, "ok")})
        if sev:
            findings.append(finding(sev, "CPU", "Average CPU at %.0f%% over 5 minutes" % avg5))
        if busy["5min_pct"] >= 95 and len(cores) > 1:
            findings.append(finding("medium", "CPU core %s" % busy["core"], "One core at %.0f%% over 5 minutes" % busy["5min_pct"],
                                    "each TMM thread is pinned to a core: one busy TMM can drop traffic while the "
                                    "average looks fine"))
        bars.append({"title": "CPU per core · now (5 s average)", "fmt": "pct",
                     "rows": [["core %s" % c["core"], c["now_pct"]] for c in cores]})
        data["cpu_cores"] = cores

    # memory
    mrow = next((r for src in ("mem", "host") for r in f5_stat_rows(got.get(src))
                 if "memoryTotal" in r and "memoryUsed" in r), None)
    mem_total = ru_float(mrow["memoryTotal"]) if mrow else None
    for lbl, u, t, hi, med in (("Memory utilization", "memoryUsed", "memoryTotal", 95, 90),
                               ("TMM memory", "tmmMemoryUsed", "tmmMemoryTotal", 95, 85),
                               ("Other (control plane) memory", "otherMemoryUsed", "otherMemoryTotal", 95, 90),
                               ("Swap", "swapUsed", "swapTotal", 50, 20)):
        uu, tt = ru_float((mrow or {}).get(u)), ru_float((mrow or {}).get(t))
        if uu is None or not tt:
            continue
        pct = 100.0 * uu / tt
        sev = ru_sev(pct, hi, med)
        rows.append({"resource": lbl, "current": "%.1f%%" % pct, "detail": "%s of %s" % (f5_bytes(uu), f5_bytes(tt)),
                     "status": {"high": "HIGH", "medium": "warning"}.get(sev, "ok")})
        tiles.append(ru_tile(lbl, pct, "%s of %s" % (f5_bytes(uu), f5_bytes(tt)), hi, med))
        if sev:
            findings.append(finding(sev, lbl, "%s at %.0f%%" % (lbl, pct),
                                    "swap in use means the control plane is short of memory" if u == "swapUsed" else ""))

    # read-only averages (current / 3 hours / 24 hours / ...) from sys performance all-stats
    perf_rows = [r for r in f5_stat_rows(got.get("perf")) if any(isinstance(x, str) for x in r.values())]
    if perf_rows:
        data["performance_averages"] = perf_rows

    # processes and subsystems
    procs, proc_src = (f5_top_parse(sections["TOP"]) if "TOP" in sections else []), "top, 1 s sample"
    if not procs and got.get("proc"):
        for r in f5_stat_rows(got["proc"]):
            name = first(r, "procName", "name", "command")
            if not name:
                continue
            cpu_k = next((k for k in r if re.match(r"cpuUsage(Recent|5sec|Now|Current)", k)), None) or \
                next((k for k in r if k.lower().startswith("cpu")), None)
            mem_k = next((k for k in r if k.lower() in ("rss", "residentsetsize", "memoryusage", "rssbytes")), None) or \
                next((k for k in r if k.lower() in ("vsize", "virtualsize")), None)
            procs.append({"pid": r.get("pid", ""), "user": "", "name": str(name),
                          "cpu_pct": ru_float(r.get(cpu_k)) or 0.0, "res_bytes": ru_float(r.get(mem_k)) or 0.0})
        proc_src = "sys proc-info"
    if procs:
        bars.append({"title": "Top 10 processes by CPU (% of one core, " + proc_src + ")", "fmt": "pct",
                     "rows": [["%s (%s)" % (p["name"], p["pid"]), round(p["cpu_pct"], 1)]
                              for p in sorted(procs, key=lambda p: -p["cpu_pct"])[:10]]})
        bars.append({"title": "Top 10 processes by memory (resident)", "fmt": "bytes",
                     "rows": [["%s (%s)" % (p["name"], p["pid"]), p["res_bytes"]]
                              for p in sorted(procs, key=lambda p: -p["res_bytes"])[:10]]})
        sub_cpu, sub_mem = collections.Counter(), collections.Counter()
        for p in procs:
            s = f5_subsys(p["name"])
            sub_cpu[s] += p["cpu_pct"]
            sub_mem[s] += p["res_bytes"]
        div = float(ncpu or 1)
        crow = [[k, round(x / div, 2)] for k, x in sub_cpu.most_common() if x > 0]
        crow.append(["idle", round(max(0.0, 100 - sum(sub_cpu.values()) / div), 2)])
        bars.append({"title": "Subsystem CPU utilization (%% of all %s cores)" % (ncpu or "?"), "fmt": "pct", "rows": crow})
        mrows = [[k, x] for k, x in sub_mem.most_common() if x > 0]
        if mem_total:
            mrows.append(["not resident in a process (free, cache)", max(0.0, mem_total - sum(sub_mem.values()))])
        bars.append({"title": "Subsystem memory utilization (resident)", "fmt": "bytes", "rows": mrows})
        data["top_processes"] = [{"process": p["name"], "pid": p["pid"], "user": p["user"], "cpu_pct": round(p["cpu_pct"], 1),
                                  "resident": f5_bytes(p["res_bytes"]), "subsystem": f5_subsys(p["name"])}
                                 for p in sorted(procs, key=lambda p: -p["cpu_pct"])[:25]]
        notes.append("Subsystems are grouped by process name: tmm = traffic, bd / asm = waf, dosl7d = l7_dos, avrd / monpd "
                     "= log_analytics, pccd / autodosd = fw, mcpd / restjavad ... = control plane. TMM busy-polls on "
                     "Virtual Edition, so top can show it busier than the TMM CPU in 'show sys tmm-info'.")

    # disk
    disks = f5_df_parse(sections["DF"]) if "DF" in sections else []
    for d in disks:
        sev = ru_sev(d["use_pct"], 90, 80)
        d["status"] = {"high": "HIGH", "medium": "warning"}.get(sev, "ok")
        if sev:
            findings.append(finding(sev, "Disk %s" % d["mounted_on"], "%s is %d%% full" % (d["mounted_on"], d["use_pct"]),
                                    "%s used of %s, %s free" % (d["used"], d["size"], d["available"])))
    if disks:
        worst = max(disks, key=lambda d: d["use_pct"])
        tiles.append(ru_tile("Disk use (fullest)", worst["use_pct"], worst["mounted_on"]))
        bars.append({"title": "Disk use by partition", "fmt": "pct",
                     "rows": [[d["mounted_on"], d["use_pct"]] for d in sorted(disks, key=lambda d: -d["use_pct"])]})

    # history from the BIG-IP's own RRD files (the data behind the GUI performance graphs)
    cpu_s, mem_s, unknown = [], [], []
    for key, txt in sections.items():
        if key.startswith("RRD "):
            names, rrows = f5_rrd_parse(txt)
            if not rrows:
                continue
            ser, known = f5_rrd_series(key[4:], names, rrows)
            for kind, label, pts in ser:
                (cpu_s if kind == "cpu" else mem_s).append((label, pts))
            if not known:
                unknown.append("%s (%s)" % (key[4:], ", ".join(names[:8])))
    if cpu_s:
        total = [s for s in cpu_s if not re.search(r"\d", s[0])][:1]
        per = sorted([s for s in cpu_s if re.search(r"\d", s[0])],
                     key=lambda s: [int(x) for x in re.findall(r"\d+", s[0])])
        c = f5_hist_chart("CPU utilization · %s (%%)" % span, total + per if len(per) <= 5 else per)
        if c:
            charts.append(c)
        hist = [{"cpu": lbl, "average_pct": round(sum(p.values()) / len(p), 1), "max_pct": round(max(p.values()), 1)}
                for lbl, p in total + per if p]
        if hist:
            data["cpu_history"] = hist
            hot = max(hist, key=lambda h: h["max_pct"])
            if hot["max_pct"] >= 95:
                findings.append(finding("medium", hot["cpu"], "Peaked at %.0f%% in the %s" % (hot["max_pct"], span),
                                        "average %.1f%%" % hot["average_pct"]))
        src = total[0][1] if total else (c and dict(zip(range(len(c["t"])), c["series"][0][1])))
        if src:
            spark = [x for _, x in sorted(src.items()) if x is not None][-120:]
            for t_ in tiles:
                if t_["label"] == "Avg. CPU utilization":
                    t_["spark"] = [round(x, 1) for x in spark]
    if mem_s:
        c = f5_hist_chart("Memory utilization · %s (%%)" % span, mem_s)
        if c:
            charts.append(c)
            for t_ in tiles:
                if t_["label"] == "Memory utilization":
                    t_["spark"] = [x for x in c["series"][0][1] if x is not None][-120:]
    if unknown:
        notes.append("RRD files read but not charted (data source names not recognised): %s." % "; ".join(unknown[:12]))
    if sections and not cpu_s and not mem_s:
        notes.append("No CPU / memory history found in /var/rrd (files: %s)." %
                     (", ".join((sections.get("RRDLIST") or "").split()[:40]) or "none"))

    data = collections.OrderedDict([("utilization", rows)] + list(data.items()))
    if disks:
        data["disk"] = disks
    ver = next((r for r in f5_stat_rows(got.get("version")) if "Version" in r), None)
    if ver:
        notes.insert(0, "%s %s (build %s)" % (ver.get("Product") or "BIG-IP", ver.get("Version", ""), ver.get("Build", "")))
    if use_bash:
        notes.insert(0, "History: the %s from the BIG-IP's own RRD files (/var/rrd, the data behind the GUI performance "
                        "graphs), read with fixed read-only commands (rrdtool fetch, top, df) through util/bash." % span)
    else:
        notes.insert(0, "Read-only REST only: current CPU per core, memory and the performance averages. Tick the "
                        "confirmation box in 'F5 active tools' (Administrator role) to add the %s of CPU / memory "
                        "history, top processes, subsystem CPU / memory and disk use; that runs fixed, read-only "
                        "commands (rrdtool fetch, top, df) through util/bash." % span)
    notes.append("Thresholds: average CPU (5 min) warn at 80%, high at 90%; memory warn at 90%, high at 95%; TMM memory "
                 "warn at 85%; swap warn at 20%; disk warn at 80%, high at 90%.")
    pick = lambda name: next((r["current"] for r in rows if r["resource"] == name), "n/a")
    label = "CPU %s · MEMORY %s · TMM MEMORY %s · %s" % (pick("CPU (all cores)"), pick("Memory utilization"),
                                                        pick("TMM memory"), span.upper())
    reqs = ["GET " + p for p in paths.values()] + (["bash: " + script] if use_bash else [])
    out = ru_result(t0, " + ".join(reqs), tiles, charts, findings, data, notes, label)
    out["bars"] = bars
    return out


F5_VS_SORT = {"current": "clientside.curConns", "total": "clientside.totConns", "max": "clientside.maxConns",
              "bits": "_bits", "packets": "_pkts"}


def f5_vs_top(sess, v):
    """Virtual servers ranked by connections or traffic, from /mgmt/tm/ltm/virtual/stats (counters since last reset)."""
    t0 = time.time()
    by = str(v.get("by") or "current").strip().lower()
    if by not in F5_VS_SORT:
        raise ValueError("sort by one of: " + ", ".join(F5_VS_SORT))
    top = num(v.get("top") or "20", 1, 500, 20, "how many")
    ok, d = f5_get(sess, "/mgmt/tm/ltm/virtual/stats")
    if not ok:
        raise ValueError("could not read virtual server stats (%s)" % str(d)[:200])

    def n(x):
        try:
            return int(float(x))
        except (TypeError, ValueError):
            return 0
    rows = []
    for r in f5_stat_rows(d):
        name = r.get("tmName")
        if not name or "clientside.curConns" not in r:
            continue
        bits = n(r.get("clientside.bitsIn")) + n(r.get("clientside.bitsOut"))
        pkts = n(r.get("clientside.pktsIn")) + n(r.get("clientside.pktsOut"))
        dest = str(r.get("destination") or "").rsplit("/", 1)[-1]
        rows.append({"vs_name": name, "destination": re.sub(r"%\d+", "", dest),
                     "current_connections": n(r.get("clientside.curConns")),
                     "max_connections": n(r.get("clientside.maxConns")),
                     "total_connections": n(r.get("clientside.totConns")),
                     "traffic_in": cf_fmt_bytes(n(r.get("clientside.bitsIn")) // 8),
                     "traffic_out": cf_fmt_bytes(n(r.get("clientside.bitsOut")) // 8),
                     "availability": r.get("status.availabilityState", ""), "enabled": r.get("status.enabledState", ""),
                     "_bits": bits, "_pkts": pkts})
    key = F5_VS_SORT[by]
    keymap = {"clientside.curConns": "current_connections", "clientside.totConns": "total_connections",
              "clientside.maxConns": "max_connections"}
    rows.sort(key=lambda x: x[keymap.get(key, key)], reverse=True)
    total = len(rows)
    rows = rows[:top]
    for i, x in enumerate(rows, 1):
        x["rank"] = i
        x.pop("_bits"), x.pop("_pkts")
    rows = [dict([("rank", x.pop("rank"))] + list(x.items())) for x in rows]
    what = {"current": "current connections", "total": "total connections", "max": "max connections",
            "bits": "traffic (bits in + out)", "packets": "packets (in + out)"}[by]
    summary = []
    if rows:
        summary.append("Busiest by %s: %s (%s current, %s total connections) out of %d virtual server(s)." % (
            what, rows[0]["vs_name"], rows[0]["current_connections"], rows[0]["total_connections"], total))
    summary.append("Total, max and traffic counters run since the last stats reset or reboot; current connections are live.")
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": "GET /mgmt/tm/ltm/virtual/stats",
            "data": {"virtual_servers": rows}, "summary": summary,
            "verdict": {"label": "TOP %d OF %d VIRTUAL SERVERS BY %s" % (len(rows), total, what.upper()), "kind": "info"}}


PAN_REPORT_PERIODS = collections.OrderedDict([("last-15-minutes", 900), ("last-hour", 3600), ("last-6-hrs", 21600),
                                             ("last-12-hrs", 43200), ("last-24-hrs", 86400), ("last-7-days", 604800),
                                             ("last-30-days", 2592000)])


def pan_report(sess, name, period, topn, timeout=120):
    """PAN-OS dynamic report (ACC summary database) -> list of {field: text} entries. Waits for the job if the
    firewall answers asynchronously."""
    q = {"type": "report", "reporttype": "dynamic", "reportname": name, "period": period, "topn": str(topn)}
    st, raw = http(sess, "POST", "/api/", {"X-PAN-KEY": sess["key"], "Content-Type": "application/x-www-form-urlencoded"},
                   urllib.parse.urlencode(q).encode(), timeout)
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        raise ValueError("the firewall's answer to the %s report was not XML (HTTP %s)" % (name, st))
    if root.get("status") == "error":
        raise ValueError("the firewall refused the %s report: %s" % (
            name, " ".join(t.strip() for t in root.itertext() if t.strip())[:300]))
    job = root.findtext(".//job")
    end = time.time() + timeout
    while job and root.find(".//entry") is None and time.time() < end:
        time.sleep(2)
        st, raw = http(sess, "POST", "/api/", {"X-PAN-KEY": sess["key"],
                       "Content-Type": "application/x-www-form-urlencoded"},
                       urllib.parse.urlencode({"type": "report", "action": "get", "job-id": job}).encode(), timeout)
        root = ET.fromstring(raw)
        if (root.findtext(".//status") or "").upper() == "FIN":
            break
    return [{c.tag: (c.text or "").strip() for c in e} for e in root.iter("entry")]


def pan_app_traffic(sess, v):
    """Sessions and bytes per application over the whole period, from the summary database (not a log sample)."""
    t0 = time.time()
    period = str(v.get("period") or "last-24-hrs").strip()
    if period not in PAN_REPORT_PERIODS:
        raise ValueError("time range: one of " + ", ".join(PAN_REPORT_PERIODS))
    app = str(v.get("app") or "").strip().lower()
    if app and not re.match(r"^[\w.+-]{1,64}$", app):
        raise ValueError("invalid application name")
    top = num(v.get("top") or "50", 1, 500, 50, "how many")
    ents = pan_report(sess, "top-app-summary", period, 500 if app else top)
    secs = PAN_REPORT_PERIODS[period]

    def n(e, *keys):
        for k in keys:
            try:
                return int(float(e.get(k) or ""))
            except ValueError:
                pass
        return 0
    rows, total_b, total_s = [], 0, 0
    for e in ents:
        name = e.get("name") or e.get("app") or e.get("application") or ""
        if not name:
            continue
        b, ss = n(e, "nbytes", "bytes"), n(e, "nsess", "sessions", "count", "repeatcnt")
        total_b, total_s = total_b + b, total_s + ss
        if app and not (app in name.lower() or (app == "http" and (name == "web-browsing" or name.startswith("http")))):
            continue
        rows.append({"application": name, "sessions": ss, "bytes": cf_fmt_bytes(b),
                     "average_per_hour": cf_fmt_bytes(b * 3600 // secs) if b else "0",
                     "average_rate": "%.2f Mbit/s" % (b * 8.0 / secs / 1e6),
                     "share_of_traffic": "", "category": e.get("app-category") or e.get("category") or "",
                     "risk": e.get("risk") or e.get("risk-of-app") or "", "_b": b})
    rows.sort(key=lambda r: r["_b"], reverse=True)
    rows = rows[:top]
    for r in rows:
        r["share_of_traffic"] = "%.1f%%" % (100.0 * r["_b"] / total_b) if total_b else ""
        r.pop("_b")
    summary = ["Period %s (%d h). Totals from the firewall's summary database, so the whole period is counted, not a "
               "log sample." % (period, secs // 3600 or 1)]
    if rows:
        r0 = rows[0]
        summary.insert(0, "%s: %s in %s sessions, on average %s per hour (%s)." % (
            r0["application"], r0["bytes"], "{:,}".format(r0["sessions"]), r0["average_per_hour"], r0["average_rate"]))
    if app == "http" or "web-browsing" in app:
        summary.append("HTTP is the application web-browsing; HTTPS that is not decrypted is 'ssl' (look it up with "
                       "application ssl).")
    if not ents:
        summary.append("The report came back empty: the summary database may be disabled, or the account may not "
                       "read reports.")
    label = ("%s · %s" % (rows[0]["application"].upper(), rows[0]["bytes"]) if app and rows else
             "NO TRAFFIC FOR APPLICATION '%s'" % app.upper() if app else "TOP %d APPLICATIONS" % len(rows))
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000),
            "request": "report top-app-summary " + period, "data": {"applications": rows}, "summary": summary,
            "verdict": {"label": label + " · " + period.upper(), "kind": "info" if rows else "warn"}}


def f5_addr_port(x):
    """'10.1.1.1:443', '10.1.1.1%2:443' or IPv6 '2001:db8::1.443' -> (address, port) or (x, '')."""
    x = str(x or "")
    m = re.match(r"^([0-9.]+)(?:%\d+)?:(\d+|any)$", x) or re.match(r"^([0-9a-fA-F:]+)(?:%\d+)?\.(\d+|any)$", x)
    return (m.group(1), m.group(2)) if m else (x, "")


def f5_ha_state(sess):
    """'ACTIVE', 'STANDBY', ... from cm failover-status, or '' when it cannot be read."""
    try:
        ok, d = f5_get(sess, "/mgmt/tm/cm/failover-status")
    except (urllib.error.URLError, OSError, ValueError):
        return ""
    stack = [d] if ok else []
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            st = x.get("status")
            if isinstance(st, dict) and st.get("description"):
                return str(st["description"]).upper()
            stack += list(x.values())
        elif isinstance(x, list):
            stack += x
    return ""


def f5_connections(sess, client="", vip="", diag=None):
    """Live connections from the F5 connection table (read-only 'tmsh show sys connection', filtered on the F5) ->
    rows: client, virtual server, F5 source address (self IP / SNAT), pool member. diag (a dict) receives the request
    and the lines that could not be read, to explain an empty answer."""
    opts = []
    for k, v in (("cs-client-addr", client), ("cs-server-addr", vip)):
        if v:
            opts += [k, str(ipaddress.ip_address(v))]
    if not opts:
        raise ValueError("enter the client IP")
    path = "/mgmt/tm/sys/connection?options=" + "+".join(opts)
    ok, d = f5_get(sess, path)
    if not ok:
        raise ValueError("could not read the connection table (%s)" % (str(d)[:200] if d else "no answer"))
    raw = str(((d.get("apiRawValues") or {}).get("apiAnonymous")) or "")
    if diag is not None:
        diag.update(request=path, unread=[], other=[] if raw else [json.dumps(d, default=str)[:300]])
    rows = []
    for line in raw.splitlines():
        m = re.match(r"^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+\(tmm:\s*(\d+)\)", line)
        if not m:
            if diag is not None and line.strip() and not re.match(r"^\s*(Sys::Connections|Total records returned)", line):
                diag["unread"].append(line.strip()[:200])
            continue
        (ca, cp), (va, vp), (sa, sp), (pa, pp) = (f5_addr_port(m.group(i)) for i in (1, 2, 3, 4))
        rows.append({"client": ca, "client_port": cp, "virtual_server": va, "virtual_port": vp, "f5_source": sa,
                     "f5_source_port": sp, "pool_member": pa, "member_port": pp, "protocol": m.group(5),
                     "idle_seconds": int(m.group(6)), "tmm": m.group(7)})
        if len(rows) >= 1000:
            break
    return rows


def f5_conns(sess, v):
    t0 = time.time()
    rows = f5_connections(sess, v.get("ip", ""), v.get("vip", ""))
    ha = "" if rows else f5_ha_state(sess)
    per = collections.Counter((r["virtual_server"] + ":" + r["virtual_port"], r["pool_member"] + ":" + r["member_port"])
                              for r in rows)
    summary = ["%s -> pool member %s: %d connection(s)" % (vs, mem, c) for (vs, mem), c in per.most_common(20)]
    return dict(pan_result("show sys connection cs-client-addr %s%s" % (v.get("ip"), " cs-server-addr %s" % v["vip"]
                                                                          if v.get("vip") else ""),
                           {"connections": rows, "count": len(rows),
                            "note": "Live connections only (the client must be connected now). Behind a proxy such as "
                                    "Cloudflare the F5 sees the proxy's addresses, not the client's."}, t0),
                summary=summary or ["No live connection from %s on this F5 right now%s." % (v.get("ip"), (
                    ": this unit is %s, the connections are on the active unit" % ha) if ha and ha != "ACTIVE" else
                    " (%s)" % ha if ha else "")])


PAN_HANDLERS = {"pan_nat_rules": pan_nat_rules, "pan_static_routes": pan_static_routes, "pan_sessions": pan_sessions,
                "pan_resources": pan_resources, "fg_resources": fg_resources,
                "f5_perf": f5_perf, "f5_vs_top": f5_vs_top, "pan_app_traffic": pan_app_traffic,
                "pan_snat": pan_snat, "fg_snat": fg_snat, "f5_snat": f5_snat_lookup, "f5_conns": f5_conns}


def do_ipcheck(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess:
        return {"ok": False, "error": "device not connected"}
    t0 = time.time()
    try:
        v = sess["vendor"]
        if v in ("paloalto", "fortigate") and b.get("mode", "refs") == "refs" and "/" in str(b.get("ip") or ""):
            ip = parse_ip_or_net(b.get("ip"), "IP address")   # a subnet: objects / rules that overlap it
            if ip.prefixlen == ip.max_prefixlen:
                ip = ip.network_address
        elif "/" in str(b.get("ip") or ""):
            raise ValueError("a subnet works for the Palo Alto / FortiGate reference lookup only; enter one IP address here")
        else:
            ip = parse_ip(b.get("ip"), "IP address")
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


# ---- Flow trace: one flow through the connected devices it crosses, found from their own configuration ------------
# Not tied to device names, vendors or order: edge (Cloudflare) -> optional upstream 1:1 NAT -> the firewall that
# translates the destination (FortiGate VIP / Palo Alto NAT) -> the F5 with the virtual server -> firewalls before the
# servers. Each device is tested with the addresses it really sees (after proxying, NAT and the F5's SNAT).
FLOW_STAGE = {"cloudflare": (1, "1 Edge · Cloudflare"), "nat": (1.5, "Upstream NAT · 1:1 NAT"),
              "fortigate": (2, "2 Firewall · FortiGate"), "f5": (3, "3 Load balancer · F5"),
              "paloalto": (4, "4 Firewall · Palo Alto")}
# Optional step for environments where a public IP is 1:1 NAT'ed to a private IP before the first firewall (a cloud
# provider's public IPs, an edge router). It only appears when it applies: the public IP is in nat_map.txt, or it can
# be inferred without doubt from the F5 virtual server and the FortiGate VIP that maps to it. Elsewhere it never shows.
NAT_SESS = {"vendor": "nat", "name": "Upstream NAT", "host": "nat"}   # not a connected device
NAT_MAP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nat_map.txt")


def nat_map_parse(text):
    """'public private  # comment' lines -> ([(public, private, comment)], [errors])."""
    rows, errs = [], []
    for n, line in enumerate(str(text or "").splitlines(), 1):
        body, _, com = line.partition("#")
        parts = body.split()
        if not parts:
            continue
        try:
            if len(parts) != 2:
                raise ValueError
            pub, priv = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
        except ValueError:
            errs.append("line %d: expected 'public-IP private-IP', got %r" % (n, body.strip()[:60]))
            continue
        rows.append((str(pub), str(priv), com.strip()[:100]))
    return rows, errs


def nat_map_rows():
    try:
        with open(NAT_MAP_FILE, encoding="utf-8") as f:
            return nat_map_parse(f.read())[0]
    except OSError:
        return []


def nat_map_text(rows):
    return "".join("%s %s%s\n" % (a, c, ("  # " + m) if m else "") for a, c, m in rows)


def do_nat_map(b):
    """Read, or replace, the optional upstream NAT list (public IP -> private IP) used by the flow trace."""
    if b.get("set"):
        rows, errs = nat_map_parse(str(b.get("text") or "")[:100000])
        if errs:
            return {"ok": False, "error": "; ".join(errs[:5])}
        tmp = NAT_MAP_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("# Upstream NAT: public IP -> private IP (1:1), one pair per line. Used by the flow trace. "
                    "Not in git.\n" + nat_map_text(rows))
        os.replace(tmp, NAT_MAP_FILE)
    rows = nat_map_rows()
    return {"ok": True, "count": len(rows), "text": nat_map_text(rows)}


NAT_PRIVATE = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]


def nat_private(ip):
    """Inside address (RFC 1918, carrier-grade NAT, IPv6 ULA): the side a 1:1 NAT translates public addresses to."""
    return any(ip.version == net.version and ip in net for net in NAT_PRIVATE)


# Optional VIP list: one row per published service, "name  FortiGate-VIP  F5-VIP[:port]", pasted from a spreadsheet.
# The name may be a hostname or a label such as "Shop portal VIP": its words are matched against the hostname traced.
# It tells the trace which FortiGate VIP belongs to a hostname, which the devices themselves do not record.
VIP_MAP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vip_map.txt")
VIP_NAME_STOP = {"vip", "vips", "vs", "virtual", "server", "fg", "fgt", "fortigate", "f5", "fw", "nat", "public", "pub",
                 "external", "ext", "prod", "production", "the", "and", "new", "old"}


def vip_map_ip(tok):
    """'10.1.1.1' or '10.1.1.1:443' -> (ip, port) or None."""
    tok = tok.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(tok)), ""
    except ValueError:
        pass
    a, _, b = tok.rpartition(":")
    try:
        if b.isdigit() and 0 < int(b) < 65536:
            return str(ipaddress.ip_address(a.strip("[]"))), b
    except ValueError:
        pass
    return None


def vip_map_parse(text):
    """Lines 'name<tab>fortigate-vip<tab>f5-vip[:port][<tab>anything]' (tabs, commas or spaces; a header row and extra
    columns are ignored) -> ([(name, fg_ip, f5_ip, f5_port)], [errors])."""
    rows, errs = [], []
    for n, line in enumerate(str(text or "").splitlines(), 1):
        body = line.split("#", 1)[0]
        toks = [t for t in re.split(r"[\t,;\s]+", body) if t]
        if not toks:
            continue
        i = next((j for j, t in enumerate(toks) if vip_map_ip(t)), None)
        if i is None:
            continue   # a header row or a note: no address on it
        ips = [vip_map_ip(t) for t in toks[i:i + 2]]
        if len(ips) < 2 or not ips[1] or ips[0][1]:
            errs.append("line %d: expected 'name  FortiGate-VIP  F5-VIP', got %r" % (n, body.strip()[:80]))
            continue
        rows.append((" ".join(toks[:i])[:100], ips[0][0], ips[1][0], ips[1][1]))
    return rows, errs


def vip_map_rows():
    try:
        with open(VIP_MAP_FILE, encoding="utf-8") as f:
            return vip_map_parse(f.read())[0]
    except OSError:
        return []


def vip_map_text(rows):
    return "".join("%s\t%s\t%s%s\n" % (nm or "-", fg, f5, ":" + fp if fp else "") for nm, fg, f5, fp in rows)


def do_vip_map(b):
    """Read, or replace, the optional VIP list (name / hostname -> FortiGate VIP -> F5 VIP) used by the flow trace."""
    if b.get("set"):
        rows, errs = vip_map_parse(str(b.get("text") or "")[:300000])
        if errs:
            return {"ok": False, "error": "; ".join(errs[:5])}
        tmp = VIP_MAP_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("# VIP list: name or hostname <tab> FortiGate VIP <tab> F5 VIP[:port]. Used by the flow trace. "
                    "Not in git.\n" + vip_map_text(rows))
        os.replace(tmp, VIP_MAP_FILE)
    rows = vip_map_rows()
    return {"ok": True, "count": len(rows), "text": vip_map_text(rows)}


def vip_name_hit(name, host):
    """How well a VIP list name fits a hostname: 0 = no match, higher = more specific."""
    n = str(name or "").strip().lower().rstrip(".")
    if not n or n == "-" or not host:
        return 0
    if n == host:
        return 1000
    ht = {t for t in re.split(r"[^a-z0-9]+", host) if t}
    words = [w for w in re.split(r"[^a-z0-9]+", n) if w and w not in VIP_NAME_STOP]
    if words and (all(w in ht for w in words) or "".join(words) in ht):
        return len(words)
    return 0


def vip_list_named(rows, host):
    """Rows of the VIP list whose name fits the hostname best."""
    sc = [(vip_name_hit(r[0], host), r) for r in rows]
    best = max([x for x, _ in sc] or [0])
    return [r for x, r in sc if best and x == best]


def flow_nat_list(rows, d, leg, host, fg, vips, vs_ips):
    """Upstream NAT from the VIP list -> (hop, next leg, {private: (f5 ip, f5 port)}) or None when no row applies."""
    named = vip_list_named(rows, host)
    live = {a for a, _ in vs_ips()}
    onf5 = [r for r in rows if r[2] in live]
    both = [r for r in named if r in onf5]
    cand = [r for r in (both or named or onf5) if nat_private(ipaddress.ip_address(r[1]))]
    if not cand:
        return None
    nm = lambda rs: ", ".join(dict.fromkeys(r[0] or r[1] for r in rs))
    how = ("its name matches %s and its F5 VIP is the F5 virtual server of %s" % (host, host) if both else
           "its name matches %s" % host if named and cand[0] in named else "its F5 VIP is the F5 virtual server of %s" % host)
    privs = list(dict.fromkeys(r[1] for r in cand))
    if len(privs) > 1:
        return (flow_hop(NAT_SESS, "Public IP %s" % d, {"ok": True, "verdict": {
            "label": "AMBIGUOUS: public %s may be NAT'ed to %s (VIP list: %s)" % (d, " or ".join(privs[:4]), nm(cand)[:120]),
            "kind": "warn"}}, ["Several rows of the VIP list fit %s (%s). Make the names more specific, or add the right "
                               "'public private' pair to the upstream NAT list." % (host, how)]), leg, {})
    p = privs[0]
    rs = [r for r in cand if r[1] == p]
    det, kind = ["VIP list row %s: FortiGate VIP %s -> F5 VIP %s (%s)" % (
        nm(rs), p, ", ".join(r[2] + (":" + r[3] if r[3] else "") for r in rs), how)], "ok"
    if fg:
        pip = ipaddress.ip_address(p)
        lv = [v for v in vips() if ip_in_spec(pip, str(v.get("extip") or ""))]
        mapped = {strip_rd(str(m.get("range", ""))).split("-")[0].strip() for v in lv for m in as_list(v.get("mappedip"))}
        if not lv:
            kind = "warn"
            det.append("no FortiGate VIP has the external IP %s: the list may be out of date" % p)
        elif not any(r[2] in mapped for r in rs):
            kind = "warn"
            det.append("on the FortiGate, VIP %s maps %s to %s, not to the listed F5 VIP" % (
                ", ".join(str(v.get("name")) for v in lv), p, ", ".join(sorted(mapped)) or "?"))
        else:
            det.append("confirmed on the FortiGate: VIP %s maps %s to %s" % (
                ", ".join(str(v.get("name")) for v in lv), p, ", ".join(sorted(mapped))))
    else:
        det.append("FortiGate not connected: the row is not checked against the device")
    if live and not any(r[2] in live for r in rs):
        kind = "warn"
        det.append("the F5 virtual server of %s is on %s, not on the listed F5 VIP" % (host, ", ".join(sorted(live))))
    lab = "public %s -> private %s (VIP list: %s)" % (d, p, nm(rs)[:120])
    return (flow_hop(NAT_SESS, "Public IP %s" % d, {"ok": True, "verdict": {
        "label": lab if kind == "ok" else "CHECK: " + lab, "kind": kind}}, det),
        flow_leg(leg["src"], p, leg["port"], "upstream NAT %s -> %s (VIP list: %s)" % (d, p, nm(rs)[:80])),
        {p: (rs[0][2], rs[0][3], nm(rs))})


def flow_list_resolve(src, host, port):
    """Hostname -> legs to the FortiGate VIP of the best-matching VIP list rows (when nothing else resolved it)."""
    rs = vip_list_named(vip_map_rows(), host)
    return [flow_leg(src, fg, port, "VIP list: %s is %s" % (host, nm or fg)) for nm, fg in
            dict.fromkeys((r[0], r[1]) for r in rs)][:FLOW_MAX_LEGS]


def flow_trace_nat(by, legs, host, port):
    """Public destination -> the private IP the first firewall really sees, when a 1:1 NAT sits in front of it.
    -> (hops, legs, {private IP: (F5 VIP, port, name)} from the VIP list). No hop and no change when nothing
    indicates such a NAT. Evidence, strongest first: upstream NAT list, VIP list, inference from the devices."""
    nat = {a: c for a, c, _ in nat_map_rows()}
    rev = {c: a for a, c in nat.items()}
    vrows = vip_map_rows()
    hops, out, f5map, cache = [], [], {}, {}

    def vips():
        if "vips" not in cache:
            cache["vips"] = []
            for k, s_ in by("fortigate"):
                try:
                    cache["vips"] += fg_cmdb(s_, "vip", "") or []
                except (urllib.error.URLError, OSError, ValueError):
                    pass   # an unreachable FortiGate: its VIPs are not used here, and its own step reports the error
        return cache["vips"]

    def vs_ips():
        if "vs" not in cache:
            def one(x):
                try:
                    r = do_f5_host({"id": x[0], "hostname": host})
                except (urllib.error.URLError, OSError, ValueError):
                    return []
                return [(f5_dest_ip(e["destination"]), str(e["destination"]).rsplit(":", 1)[-1])
                        for e in (r.get("data") or {}).get("entries") or [] if e.get("destination")]
            items = by("f5") if host else []
            cache["vs"] = []
            if items:
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(items))) as ex:
                    for lst in ex.map(one, items):
                        cache["vs"] += lst
        return cache["vs"]
    for leg in legs[:FLOW_MAX_LEGS]:
        d = leg["dst"]
        try:
            ip = ipaddress.ip_address(d)
        except ValueError:
            out.append(leg)
            continue
        if d in nat:
            hops.append(flow_hop(NAT_SESS, "Public IP %s" % d, {"ok": True, "verdict": {
                "label": "public %s -> private %s" % (d, nat[d]), "kind": "ok"}}, ["from the upstream NAT list"]))
            out.append(flow_leg(leg["src"], nat[d], leg["port"], "upstream NAT %s -> %s" % (d, nat[d])))
            continue
        if d in rev:
            hops.append(flow_hop(NAT_SESS, "Private IP %s" % d, {"ok": True, "verdict": {
                "label": "private %s is public %s" % (d, rev[d]), "kind": "ok"}}, ["from the upstream NAT list"]))
            out.append(leg)
            continue
        fg = bool(by("fortigate"))
        if nat_private(ip) or (fg and flow_fg_vip(vips(), leg)[0]):
            out.append(leg)   # already private, or the FortiGate has a VIP on the public address itself: no NAT
            continue
        if vrows and host:
            r = flow_nat_list(vrows, d, leg, host, fg, vips, vs_ips)
            if r:
                hops.append(r[0])
                out.append(r[1])
                f5map.update(r[2])
                continue
        if not fg:
            out.append(leg)
            continue
        cands = []
        for v in vips():
            ext = str(v.get("extip") or "")
            if not ext or "-" in ext:
                continue
            try:
                if not nat_private(ipaddress.ip_address(ext)):
                    continue
            except ValueError:
                continue
            for m in as_list(v.get("mappedip")):
                mip = strip_rd(str(m.get("range", ""))).split("-")[0].strip()
                if any(mip == a and (not port or v.get("portforward") != "enable" or
                                     str(v.get("mappedport") or "").split("-")[0] in ("", vport)) for a, vport in vs_ips()):
                    cands.append((ext, v.get("name")))
        cands = list(dict.fromkeys(cands))
        privs = list(dict.fromkeys(c[0] for c in cands))
        if len(privs) == 1:
            hops.append(flow_hop(NAT_SESS, "Public IP %s" % d, {"ok": True, "verdict": {
                "label": "INFERRED: public %s -> private %s" % (d, privs[0]), "kind": "warn"}},
                ["%s is the external IP of FortiGate VIP %s, which maps to the F5 virtual server of %s. Add '%s %s' to "
                 "the upstream NAT list in the flow trace card to confirm it." % (
                     privs[0], ", ".join(str(c[1]) for c in cands), host, d, privs[0])]))
            out.append(flow_leg(leg["src"], privs[0], leg["port"], "upstream NAT %s -> %s (inferred)" % (d, privs[0])))
        elif privs:
            hops.append(flow_hop(NAT_SESS, "Public IP %s" % d, {"ok": True, "verdict": {
                "label": "AMBIGUOUS: public %s may be NAT'ed to %s" % (d, " or ".join(privs[:4])), "kind": "warn"}},
                ["Several FortiGate VIPs map to the F5 virtual server of %s. Add the right 'public private' pair to the "
                 "upstream NAT list in the flow trace card." % host]))
            out.append(leg)
        else:
            out.append(leg)   # nothing points to a NAT: the address is passed on unchanged, as before
    return hops, out + legs[FLOW_MAX_LEGS:], f5map
FLOW_PAN_PERIOD = {"last 15 minutes": "last-15-minutes", "last hour": "last-hour", "last 6 hours": "last-6-hrs",
                   "last 12 hours": "last-12-hrs", "last 24 hours": "last-24-hrs"}
FLOW_MAX_LEGS = 3   # address pairs carried to the next device (several origin IPs, VIPs or pool members)


def flow_hop(sess, check, r, details=None):
    """One row of the trace from a lookup result."""
    v = r.get("verdict") if isinstance(r.get("verdict"), dict) else {}
    ok = bool(r.get("ok"))
    st = FLOW_STAGE.get(sess["vendor"], (9, "?"))
    return {"order": st[0], "layer": st[1], "device": sess.get("name") or sess["host"], "vendor": sess["vendor"],
            "check": check, "result": v.get("label", "") if ok else "NOT CHECKED: %s" % str(r.get("error") or "failed")[:300],
            "state": (v.get("kind") or "info") if ok else "warn",
            "details": "; ".join(str(x) for x in (details or [])[:6] if x)[:900]}


def flow_leg(src, dst, port, via=""):
    return {"src": src or "", "dst": dst, "port": str(port or ""), "via": via}


def flow_to(l):
    return l["dst"] + (":" + l["port"] if l["port"] else "")


def flow_txt(l):
    return "%s -> %s" % (l["src"] or "?", flow_to(l))


def flow_dedupe(legs):
    out, seen = [], set()
    for l in legs:
        k = (l["src"], l["dst"], l["port"])
        if k not in seen:
            seen.add(k)
            out.append(l)
    return out


def flow_trace_cf(sess, sid, src, host, within):
    """-> (hops, origin IPs, Cloudflare edge address if the host is proxied, else '')"""
    hops, ips, edge = [], [], ""
    if host:
        r = do_cf({"id": sid, "mode": "dns", "name": host})
        recs = [x for x in ((r.get("data") or {}).get("dns_records") or []) if str(x.get("name")).lower() == host]
        prox = any(x.get("proxied") for x in recs if x.get("type") in ("A", "AAAA", "CNAME"))
        if r.get("ok"):
            r["verdict"] = ({"label": "%s: %d DNS record(s), %s" % (host, len(recs), "PROXIED through Cloudflare" if prox
                                                                      else "DNS only (not proxied)"), "kind": "ok"} if recs else
                            {"label": "%s is not in the Cloudflare zones this token sees" % host, "kind": "info"})
            ips += [x["content"] for x in recs if x.get("type") in ("A", "AAAA")]
        if prox:
            try:
                nets = [n for n in cf_edge_nets(sess) if n.version == 4] or cf_edge_nets(sess)
                edge = str(nets[0].network_address + 1) if nets else ""
            except (urllib.error.URLError, OSError, ValueError, KeyError):
                edge = ""
            edge = edge or "173.245.48.1"   # in Cloudflare's long-published 173.245.48.0/20 edge range
        hops.append(flow_hop(sess, "DNS record", r, ["%s %s -> %s%s" % (x["name"], x["type"], x["content"],
                                                                        " (proxied)" if x.get("proxied") else "")
                                                     for x in recs]))
    if src:
        r = do_cf(dict({"id": sid, "mode": "events", "ip": src, "within": within, "top": "50"},
                       **({"host": host} if host else {})))
        ev = (r.get("data") or {}).get("events") or []
        if r.get("ok"):
            blocked = [e for e in ev if e.get("action") in CF_BLOCK]
            r["verdict"] = ({"label": "BLOCKED: %d of %d security event(s) for %s are blocks" % (len(blocked), len(ev), src),
                             "kind": "bad"} if blocked else
                            {"label": "%d security event(s) for %s, none blocking" % (len(ev), src), "kind": "ok"} if ev else
                            {"label": "no security events for %s (%s)" % (src, within), "kind": "ok"})
        hops.append(flow_hop(sess, "WAF / firewall events", r, ["%s %s %s (rule %s, ray %s)" % (
            e.get("time", ""), e.get("action", ""), e.get("url") or e.get("host", ""), e.get("description") or e.get("rule_id", ""),
            e.get("ray_id", "")) for e in sorted(ev, key=lambda e: e.get("action") not in CF_BLOCK)]))
    return hops, ips, edge


def flow_fw_verdict(sess, sid, leg, proto, within, logs, log_src=True):
    """Policy verdict (+ traffic log) of one firewall for one leg -> (hops, matched policy / rule dict)."""
    v = sess["vendor"]
    if not leg["src"]:
        return [flow_hop(sess, "Policy ? -> %s" % flow_to(leg), {"ok": False, "error": "source IP unknown: enter the client IP"})], {}
    r = do_ipcheck({"id": sid, "ip": leg["src"], "peer": leg["dst"], "mode": "verdict", "role": "source",
                    "port": leg["port"], "proto": proto})
    ft = (r.get("data") or {}).get("flow_test") or {}
    pol = ft.get("matched_policy") or ft.get("matched_rule") or {}
    hops = [flow_hop(sess, "Policy " + flow_txt(leg), r, ([leg["via"]] if leg["via"] else []) + list(r.get("summary") or [])
                     + list((r.get("data") or {}).get("notes") or []))]
    if logs:
        q = {"id": sid, "dest_ip": leg["dst"], "count": "50"}
        if log_src:
            q["ip"] = leg["src"]
        lr = (do_pan_logs(dict(q, log_type="traffic", period=FLOW_PAN_PERIOD.get(within, "last-24-hrs"))) if v == "paloalto"
              else fg_auto_logs(do_fg_logs, dict(q, within=within)))
        ent = (lr.get("data") or {}).get("entries") or []
        hops.append(flow_hop(sess, "Traffic log %s -> %s" % (leg["src"] if log_src else "any", leg["dst"]), lr, [
            "%s %s -> %s:%s %s %s" % (e.get("time") or e.get("date_time", ""), e.get("source_ip", ""), e.get("destination_ip", ""),
                                      e.get("to_port") or e.get("destination_port", ""), e.get("action") or e.get("result", ""),
                                      e.get("rule") or e.get("policy", "")) for e in ent]))
    return hops, pol


def flow_fg_vip(vips, leg):
    """FortiGate Virtual IP whose external address (and port, with port forwarding) matches the leg -> (vip, next leg)."""
    try:
        ip = ipaddress.ip_address(leg["dst"])
    except ValueError:
        return None, None
    for v in vips or []:
        if not ip_in_spec(ip, str(v.get("extip") or "")):
            continue
        fwd = v.get("portforward") == "enable"
        if fwd and leg["port"]:
            lo, _, hi = str(v.get("extport") or "").partition("-")
            if not (lo.strip().isdigit() and int(lo) <= int(leg["port"]) <= int(hi or lo)):
                continue
        mapped = [str(m.get("range", "")) for m in as_list(v.get("mappedip")) if m.get("range")]
        if not mapped:
            continue
        mip = mapped[0].split("-")[0].strip()
        mport = str(v.get("mappedport") or "").split("-")[0].strip() if fwd and v.get("mappedport") else leg["port"]
        nxt = flow_leg(leg["src"], mip, mport)
        nxt["via"] = "FortiGate VIP %s: %s -> %s" % (v.get("name"), flow_to(leg), flow_to(nxt))
        return v, nxt
    return None, None


def flow_trace_fg(sess, sid, legs, proto, within, logs, proxied, vips=False):
    hops, out = [], []
    if vips is False:
        vips = fg_cmdb(sess, "vip", "")
    for leg in legs[:FLOW_MAX_LEGS]:
        h, pol = flow_fw_verdict(sess, sid, leg, proto, within, logs, log_src=not proxied)
        if pol.get("nat") == "enable":
            h[0]["details"] = ("Policy also does source NAT (nat enable): the F5 sees the FortiGate's address. "
                               + h[0]["details"])[:900]
        hops += h
        v, nxt = flow_fg_vip(vips, leg)
        if vips is None:
            hops.append(flow_hop(sess, "VIP for %s" % flow_to(leg), {"ok": False, "error": "could not read firewall/vip"}))
        elif v:
            hops.append(flow_hop(sess, "VIP for %s" % flow_to(leg), {"ok": True, "verdict": {
                "label": "VIP %s maps %s -> %s" % (v.get("name"), flow_to(leg), flow_to(nxt)), "kind": "ok"}},
                ["external interface %s" % v.get("extintf"), "port forward %s" % (v.get("portforward") or "disable"),
                 v.get("comment")]))
        else:
            hops.append(flow_hop(sess, "VIP for %s" % flow_to(leg), {"ok": True, "verdict": {
                "label": "no VIP for %s: destination passed on unchanged" % flow_to(leg), "kind": "info"}}))
        out.append(nxt or leg)
    return hops, out


def flow_f5_snat(sess, v, member_ip, fallback):
    """The source address the F5 uses towards a pool member -> (ip, how)."""
    sat = v.get("sourceAddressTranslation") or {}
    t = str(sat.get("type") or "none")
    if t == "automap":
        ok, d = f5_get(sess, "/mgmt/tm/net/self")

        def self_for(ip):
            best = None
            for s in (d.get("items") or []) if ok else []:
                a = str(s.get("address") or "")
                ipm = strip_rd(a.split("/")[0]) + ("/" + a.split("/")[1] if "/" in a else "")
                try:
                    net = ipaddress.ip_interface(ipm)
                    if ipaddress.ip_address(ip) in net.network:
                        cand = (s.get("floating") == "enabled", str(net.ip))
                        best = max(best, cand) if best else cand
                except ValueError:
                    continue
            return best
        best = self_for(member_ip)
        if best:
            return best[1], "SNAT automap (%s self IP %s)" % ("floating" if best[0] else "non-floating", best[1])
        # Routed pool member: automap uses the self IP on the VLAN towards the route's gateway.
        try:
            r = f5_route(sess, member_ip)
        except (urllib.error.URLError, OSError, ValueError):
            r = None
        best = self_for(r[2]) if r and r[2] else None
        if best:
            return best[1], "SNAT automap (%s self IP %s, towards gateway %s)" % (
                "floating" if best[0] else "non-floating", best[1], r[2])
        return "", "SNAT automap, but no self IP is in the pool member's subnet (routed): the source address is not known"
    if t == "snat" and sat.get("pool"):
        ok, d = f5_get(sess, "/mgmt/tm/ltm/snatpool/" + str(sat["pool"]).replace("/", "~"))
        mem = [strip_rd(str(m).rsplit("/", 1)[-1]) for m in as_list(d.get("members"))] if ok else []
        if mem:
            return mem[0], "SNAT pool %s (%s)" % (sat["pool"], ", ".join(mem[:4]))
        return "", "SNAT pool %s could not be read" % sat["pool"]
    return fallback, "no SNAT: the source address is passed on unchanged"


def flow_trace_f5(sess, sid, legs, src, host, within, logs, proxied):
    hops, out, hp = [], [], {}
    if host:
        r = do_f5_host({"id": sid, "hostname": host})
        ent = [e for e in ((r.get("data") or {}).get("entries") or []) if e.get("destination")]
        hp = {e["virtual_server"]: e.get("forwards_to_pool") for e in ent if e.get("forwards_to_pool")}
        hops.append(flow_hop(sess, "Hostname -> virtual server", r, ["%s (%s) pool %s" % (
            e["virtual_server"], e["destination"], e.get("forwards_to_pool") or e.get("default_pool") or "-") for e in ent]))
    ok, dv = f5_get(sess, "/mgmt/tm/ltm/virtual")
    if not ok:
        return hops + [flow_hop(sess, "Virtual server", {"ok": False, "error": "could not read virtual servers"})], legs
    for leg in legs[:FLOW_MAX_LEGS]:
        vss = [v for v in dv.get("items") or [] if f5_dest_ip(v.get("destination")) == leg["dst"]
               and (not leg["port"] or f5_member_port(v.get("destination")) in (leg["port"], "0", "any"))]
        if not vss:
            hops.append(flow_hop(sess, "Virtual server for %s" % flow_to(leg), {"ok": True, "verdict": {
                "label": "no virtual server listens on %s: the F5 is not in this path, or the address is wrong" % flow_to(leg),
                "kind": "warn"}}, [leg["via"]]))
            out.append(leg)
            continue
        for v in vss[:2]:
            pool = hp.get(v.get("fullPath")) or v.get("pool") or ""
            mem = []
            if pool:
                okm, dm = f5_get(sess, "/mgmt/tm/ltm/pool/%s/members" % pool.replace("/", "~"))
                mem = (dm.get("items") or []) if okm else []
            up = [m for m in mem if str(m.get("state", "")).lower() in ("up", "unchecked", "checking")
                  and "disabled" not in str(m.get("session", ""))]
            off = v.get("disabled") is True or v.get("enabled") is False
            label = "%s (%s) %s · pool %s: %d of %d member(s) up" % (
                v.get("fullPath"), v.get("destination"), "DISABLED" if off else "enabled", pool or "(none)", len(up), len(mem))
            kind = "bad" if off or (mem and not up) or not pool else "warn" if len(up) < len(mem) else "ok"
            first_ip = strip_rd(str((up or mem or [{}])[0].get("address") or ""))
            snat, how = flow_f5_snat(sess, v, first_ip, leg["src"]) if first_ip else ("", "")
            hops.append(flow_hop(sess, "Virtual server for %s" % flow_to(leg),
                                 {"ok": True, "verdict": {"label": label, "kind": kind}},
                                 ([leg["via"]] if leg["via"] else []) + [how] +
                                 ["member %s state %s %s" % (m.get("name"), m.get("state"), m.get("session", "")) for m in mem]))
            # The pool member the client is really on (persistence / load balancing): its live connections.
            live = []
            if src and not proxied:
                vip = f5_dest_ip(v.get("destination"))
                try:
                    # the same query as 'show sys connection cs-client-addr <client>', filtered here afterwards
                    diag = {}
                    allc = f5_connections(sess, src, diag=diag)
                    cr = [c for c in allc
                          if c["virtual_server"] == vip and (not leg["port"] or c["virtual_port"] in (leg["port"], "any"))]
                    pairs = collections.Counter((c["f5_source"], c["pool_member"], c["member_port"]) for c in cr)
                    live = [k for k, _ in pairs.most_common(FLOW_MAX_LEGS)]
                    line = lambda c: "%s:%s -> %s:%s -> %s:%s -> %s:%s %s idle %ss" % (
                        c["client"], c["client_port"], c["virtual_server"], c["virtual_port"], c["f5_source"],
                        c["f5_source_port"], c["pool_member"], c["member_port"], c["protocol"], c["idle_seconds"])
                    if live:
                        lab = "client %s is on pool member %s (%d live connection(s), F5 source %s)" % (
                            src, ", ".join("%s:%s" % (k[1], k[2]) for k in live), len(cr), ", ".join(dict.fromkeys(k[0] for k in live)))
                        det = [line(c) for c in cr]
                    else:   # say why: standby unit, connections to another virtual server, or an answer not understood
                        ha = f5_ha_state(sess)
                        vss_seen = sorted({"%s:%s" % (c["virtual_server"], c["virtual_port"]) for c in allc})
                        if allc:
                            lab = ("client %s has %d live connection(s) on this F5, but none to %s: they go to %s" % (
                                src, len(allc), flow_to(leg), ", ".join(vss_seen[:4])))
                        elif ha and ha != "ACTIVE":
                            lab = ("no live connection from %s on this unit: it is %s, so the connections are on the "
                                   "active unit (connect the active F5)" % (src, ha))
                        elif diag.get("unread") or diag.get("other"):
                            lab = "the connection table answered in a form the console could not read (see details)"
                        else:
                            lab = "no live connection from %s on this F5%s right now" % (src, " (%s)" % ha if ha else "")
                        det = ([line(c) for c in allc] + ["request: " + diag.get("request", "")] +
                               ["not read: " + x for x in (diag.get("unread") or [])[:5]] +
                               ["answer: " + x for x in (diag.get("other") or [])[:1]])
                    hops.append(flow_hop(sess, "Live connections from %s" % src, {"ok": True, "verdict": {
                        "label": lab, "kind": "ok" if live else "info"}}, det))
                except (urllib.error.URLError, OSError, ValueError) as e:
                    hops.append(flow_hop(sess, "Live connections from %s" % src, {"ok": True, "verdict": {
                        "label": "connection table not read: %s" % str(getattr(e, "reason", e))[:150], "kind": "info"}}))
            if live:   # follow the real connection: F5 source address -> the member the client is on
                for sa, ma, mp in live:
                    out.append(flow_leg(sa, ma, mp, "F5 %s -> pool member %s:%s (live connection of %s)" % (
                        v.get("fullPath"), ma, mp, src)))
                continue
            for m in (up or mem)[:FLOW_MAX_LEGS]:
                out.append(flow_leg(snat, strip_rd(str(m.get("address") or "")), f5_member_port(m.get("name")),
                                    "F5 %s -> pool member %s (%s)" % (v.get("fullPath"), m.get("name"), how)))
    if src and logs:
        # Behind Cloudflare the F5 sees Cloudflare's address; the client is in a header (X-Forwarded-For / True-Client-IP).
        q = {"id": sid, "mode": "search", "top": "50", "within": within, ("header_ip" if proxied else "ip"): src}
        if host:
            q["hostname"] = host
        r = do_f5_asm(q)
        rq = (r.get("data") or {}).get("requests") or []
        if r.get("ok"):
            bl = [x for x in rq if str(x.get("status", "")).lower() == "blocked"]
            r["verdict"] = ({"label": "BLOCKED: %d of %d WAF request(s) from %s" % (len(bl), len(rq), src), "kind": "bad"}
                            if bl else {"label": "%d WAF request(s) from %s, none blocked" % (len(rq), src), "kind": "ok"})
        hops.append(flow_hop(sess, "WAF (ASM) log", r, ["%s %s %s%s support ID %s: %s" % (
            x.get("time", ""), x.get("status", ""), x.get("hostname", ""), x.get("url", ""), x.get("support_id", ""),
            x.get("block_reason", "")) for x in sorted(rq, key=lambda x: str(x.get("status", "")).lower() != "blocked")]))
    return hops, out


def flow_trace_pa(sess, sid, legs, proto, within, logs):
    hops = []
    for leg in legs[:FLOW_MAX_LEGS]:
        hops += flow_fw_verdict(sess, sid, leg, proto, within, logs)[0]
    return hops, legs


def flow_resolve_host(by, src, host, port):
    """No Cloudflare answer: start from the F5 virtual server of the hostname, mapped back through the FortiGate VIP."""
    legs = []
    for k, s in by("f5"):
        try:
            r = do_f5_host({"id": k, "hostname": host})
        except (urllib.error.URLError, OSError, ValueError):
            continue
        for e in (r.get("data") or {}).get("entries") or []:
            if e.get("destination"):
                legs.append(flow_leg(src, f5_dest_ip(e["destination"]), port, "F5 virtual server %s" % e["virtual_server"]))
    for k, s in by("fortigate"):
        try:
            vips = fg_cmdb(s, "vip", "") or []
        except (urllib.error.URLError, OSError, ValueError):
            continue
        for i, l in enumerate(legs):
            for v in vips:
                ext = str(v.get("extip") or "")
                if ext and "-" not in ext and any(strip_rd(str(m.get("range", ""))).split("-")[0].strip() == l["dst"]
                                                  for m in as_list(v.get("mappedip"))):
                    legs[i] = flow_leg(src, ext, port, "external address of FortiGate VIP %s" % v.get("name"))
    return legs


# ---- Which devices a flow crosses -----------------------------------------------------------------------------------
# A firewall is on the path when its routes to the source and to the destination leave through different interfaces.
# Read-only: FortiOS GET /api/v2/monitor/router/lookup, PAN-OS 'test routing fib-lookup' on each virtual router.
FLOW_ROLE = {"cloudflare": "Edge", "nat": "Upstream NAT", "fortigate": "Firewall", "f5": "Load balancer",
             "paloalto": "Firewall"}
FLOW_VNAME = {"cloudflare": "Cloudflare", "nat": "1:1 NAT", "fortigate": "FortiGate", "f5": "F5", "paloalto": "Palo Alto"}
PAN_VRS = {}


def flow_is_ip(x):
    try:
        ipaddress.ip_address(x)
        return True
    except ValueError:
        return False


def fg_route(sess, ip):
    """-> (egress interface, directly connected?, gateway) or None."""
    st, ok, rd = rest_get(sess, "/api/v2/monitor/router/lookup?" + urllib.parse.urlencode({"destination": ip}))
    rr = rd.get("results") if ok and isinstance(rd, dict) else None
    rr = rr[0] if isinstance(rr, list) and rr else rr
    if not isinstance(rr, dict) or not rr.get("interface"):
        return None
    gw = str(rr.get("gateway") or "")
    gw = gw if flow_is_ip(gw) and gw not in ("0.0.0.0", "::", ip) else ""
    return str(rr["interface"]), not gw, gw


def pan_vrs(sess):
    k = (sess["host"], sess.get("port"))
    if k not in PAN_VRS:
        root = pan_xml(sess, {"type": "config", "action": "get",
                              "xpath": "/config/devices/entry/network/virtual-router"}, 20)
        names = [e.get("name") for e in root.findall("./result/virtual-router/entry")] if root is not None else []
        PAN_VRS[k] = [n_ for n_ in names if n_] or ["default"]
    return PAN_VRS[k]


def pan_route(sess, ip):
    """-> ('vr/interface', directly connected?) or None, from the first virtual router that has a route."""
    for vr in pan_vrs(sess)[:8]:
        root = pan_xml(sess, {"type": "op", "cmd": "<test><routing><fib-lookup><virtual-router>%s</virtual-router><ip>%s"
                                                   "</ip></fib-lookup></routing></test>" % (xml_escape(vr), xml_escape(ip))}, 20)
        intf = (root.findtext(".//interface") or "").strip() if root is not None else ""
        if intf:
            nh, nxt = (root.findtext(".//nh") or "").strip(), (root.findtext(".//ip") or "").strip()
            gw = next((x for x in (nxt, nh) if flow_is_ip(x) and x not in ("0.0.0.0", "::", ip)), "")
            return "%s/%s" % (vr, intf), not gw, gw
    return None


def f5_route(sess, ip):
    """F5: a self IP subnet holding the address (connected), else the longest matching static route."""
    a = ipaddress.ip_address(ip)
    ok, d = f5_get(sess, "/mgmt/tm/net/self")
    for x in (d.get("items") or []) if ok else []:
        try:
            ad = str(x.get("address") or "").split("/")
            if a in ipaddress.ip_network(strip_rd(ad[0]) + "/" + ad[1], strict=False):
                return str(x.get("vlan") or x.get("name")), True, ""
        except (ValueError, IndexError):
            continue
    ok, d = f5_get(sess, "/mgmt/tm/net/route")
    best = None
    for x in (d.get("items") or []) if ok else []:
        n_ = str(x.get("network") or "")
        n_ = {"default": "0.0.0.0/0", "default-inet6": "::/0"}.get(strip_rd(n_), strip_rd(n_.split("/")[0]) + (
            "/" + n_.split("/")[1] if "/" in n_ else ""))
        try:
            net = ipaddress.ip_network(n_, strict=False)
        except ValueError:
            continue
        gw = strip_rd(str(x.get("gw") or ""))
        if net.version == a.version and a in net and flow_is_ip(gw) and (best is None or net.prefixlen > best[0].prefixlen):
            best = (net, gw, str(x.get("name")))
    return (best[2], False, best[1]) if best else None


def flow_dev_ips(sess):
    """Interface addresses of a device, to find which device owns a gateway address."""
    out, v = [], sess["vendor"]
    if v == "fortigate":
        st, ok, d = rest_get(sess, "/api/v2/cmdb/system/interface")
        for x in as_list(d.get("results")) if ok and isinstance(d, dict) else []:
            out += [str(x.get("ip") or "").split(" ")[0]] + [str(y.get("ip") or "").split(" ")[0] for y in as_list(x.get("secondaryip"))]
    elif v == "paloalto":
        root = pan_xml(sess, {"type": "op", "cmd": "<show><interface>all</interface></show>"}, 20)
        out += [(e.findtext("ip") or "").split("/")[0] for e in (root.findall(".//ifnet/entry") if root is not None else [])]
    elif v == "f5":
        ok, d = f5_get(sess, "/mgmt/tm/net/self")
        out += [strip_rd(str(x.get("address") or "").split("/")[0]) for x in (d.get("items") or []) if ok]
    return [x for x in out if flow_is_ip(x) and x not in ("0.0.0.0", "::")]


def flow_route(sess, ip, cache):
    k = (sess["host"], sess.get("port"), ip)
    if k not in cache:
        try:
            cache[k] = {"fortigate": fg_route, "paloalto": pan_route, "f5": f5_route}[sess["vendor"]](sess, ip)
        except (urllib.error.URLError, OSError, ValueError, ET.ParseError, KeyError):
            cache[k] = None
    return cache[k]


def flow_on_path(sess, leg, cache):
    """-> (True on the path / False not / None cannot tell, reason, order: 0 faces the source, 2 the destination)."""
    a, b = flow_route(sess, leg["src"], cache), flow_route(sess, leg["dst"], cache)
    if not a or not b:
        return None, "route lookup for %s failed" % (leg["src"] if not a else leg["dst"]), 1
    if a[0] == b[0]:
        return False, "%s and %s are both reached via %s, so the flow does not cross it" % (leg["src"], leg["dst"], a[0]), 1
    return True, "%s via %s, %s via %s" % (leg["src"], a[0], leg["dst"], b[0]), 0 if a[1] else 2 if b[1] else 1


def flow_chain(start, dst, smap, owner, cache):
    """Follow the next hops from device 'start' towards dst: the gateway of each route is an interface address of the
    next connected device. -> ([device ids after start], complete: the destination was reached on a connected subnet)."""
    out, cur = [], start
    for _ in range(8):
        r = flow_route(smap[cur], dst, cache)
        if not r:
            return out, False
        if r[1]:
            return out, True
        nxt = owner.get(r[2])
        if not nxt or nxt == cur or nxt in out or nxt == start:
            return out, False   # the next hop is not one of the connected devices: the path leaves what we can see
        out.append(nxt)
        cur = nxt
    return out, False


def pan_dnat_rules(sess):
    """Enabled destination NAT and bi-directional static NAT rules, in evaluation order -> (rules, addrs, groups)."""
    vsys = sess.get("vsys") or "vsys1"
    addrs, groups, _ = pan_addr_db(sess, vsys)
    vals = {n: v for _, n, _, v in addrs}
    val = lambda x: vals.get(x, x)
    out = []
    for label, xp in [("shared-pre", "/config/shared/pre-rulebase/nat"), ("local", pan_base(vsys) + "/rulebase/nat"),
                      ("shared-post", "/config/shared/post-rulebase/nat")]:
        node = pan_section(sess, xp, "rules")
        for e in (node.findall("entry") if node is not None else []):
            if (e.findtext("disabled") or "") == "yes":
                continue
            dt, sip = e.find("destination-translation"), e.find("source-translation/static-ip")
            if dt is not None and dt.findtext("translated-address"):
                out.append({"name": e.get("name"), "scope": label, "dst": pan_members(e.find("destination")),
                            "to": val(dt.findtext("translated-address")), "port": dt.findtext("translated-port") or "",
                            "service": e.findtext("service") or "any"})
            elif sip is not None and (sip.findtext("bi-directional") or "") == "yes" and pan_members(e.find("source")):
                # static bi-directional NAT: traffic to the translated (public) address goes to the source address
                out.append({"name": e.get("name"), "scope": label, "dst": [sip.findtext("translated-address") or ""],
                            "to": val(pan_members(e.find("source"))[0]), "port": "", "service": "any"})
    return out, addrs, groups


def pan_dnat_for(db, leg):
    """The first destination NAT rule for leg's destination -> (rule, next leg) or (None, None)."""
    rules, addrs, groups = db
    try:
        ip = ipaddress.ip_address(leg["dst"])
    except ValueError:
        return None, None
    matched = pan_addr_match(ip, addrs, groups)
    for r in rules:
        if r["dst"] == ["any"] or not snat_hit(r["dst"], ip, matched, "any"):
            continue
        to = str(r["to"]).split("/")[0].split("-")[0].strip()
        if not flow_is_ip(to):
            continue
        nxt = flow_leg(leg["src"], to, r["port"] or leg["port"])
        nxt["via"] = "Palo Alto NAT rule %s: %s -> %s" % (r["name"], flow_to(leg), flow_to(nxt))
        return r, nxt
    return None, None


def flow_trace_pa_edge(sess, sid, legs, db, proto, within, logs, proxied):
    """Palo Alto that translates the destination: policy verdict, then the NAT rule (its FortiGate VIP equivalent)."""
    hops, out = [], []
    for leg in legs[:FLOW_MAX_LEGS]:
        hops += flow_fw_verdict(sess, sid, leg, proto, within, logs, log_src=not proxied)[0]
        r, nxt = pan_dnat_for(db, leg)
        if r:
            hops.append(flow_hop(sess, "Destination NAT for %s" % flow_to(leg), {"ok": True, "verdict": {
                "label": "NAT rule %s maps %s -> %s" % (r["name"], flow_to(leg), flow_to(nxt)), "kind": "ok"}},
                ["%s rulebase; service %s (not compared with the port)" % (r["scope"], r["service"])]))
        out.append(nxt or leg)
    return hops, out


def flow_logs_seen(sess, sid, leg, within):
    """With 'Also search logs': does the device's traffic log show this source -> destination?"""
    q = {"id": sid, "ip": leg["src"], "dest_ip": leg["dst"], "count": "5"}
    r = (do_pan_logs(dict(q, log_type="traffic", period=FLOW_PAN_PERIOD.get(within, "last-24-hrs")))
         if sess["vendor"] == "paloalto" else fg_auto_logs(do_fg_logs, dict(q, within=within)))
    return bool((r.get("data") or {}).get("entries"))


def do_flow_trace(b):
    t0 = time.time()
    src = str(b.get("src") or "").strip()
    if src:
        src = str(parse_ip(src, "Source IP"))
    dst = str(b.get("dst") or "").strip().lower().rstrip(".")
    if not dst:
        raise ValueError("enter the destination: an IP address or a hostname")
    try:
        dst_ip, host = str(ipaddress.ip_address(dst)), ""
    except ValueError:
        if not re.match(r"^[a-z0-9_\-]+(\.[a-z0-9_\-]+)+$", dst):
            raise ValueError("the destination must be an IP address or a hostname such as shop.example.com")
        dst_ip, host = "", dst
    port = str(num(b.get("port"), 1, 65535, None, "port")) if str(b.get("port") or "").strip() else ""
    proto = pstr(b.get("proto"), "protocol").lower() or "tcp"
    within = str(b.get("within") or "last 24 hours").strip().lower()
    if within not in FLOW_PAN_PERIOD:
        raise ValueError("invalid time range")
    logs = bool(b.get("logs"))
    with LOCK:
        sess = [(k, s) for k, s in SESSIONS.items() if s["vendor"] in FLOW_STAGE]
    if not sess:
        raise ValueError("connect at least one device first")
    for _, s in sess:
        audit(s, "flow trace %s -> %s%s %s%s" % (src or "?", dst, ":" + port if port else "", proto, " +logs" if logs else ""))
    by = lambda v: [(k, s) for k, s in sess if s["vendor"] == v]

    smap = dict(sess)

    def pmap(items, fn):
        """fn(sid, sess) on each (sid, sess) in parallel -> [(hops, extra)]; a failing device gives a 'not checked' row."""
        def one(x):
            try:
                return fn(x[0], x[1])
            except (urllib.error.URLError, OSError, ValueError) as e:
                return [flow_hop(x[1], "lookup", {"ok": False, "error": str(getattr(e, "reason", e))})], None
            except Exception as e:   # an unexpected reply from one device must not stop the trace on the others
                return [flow_hop(x[1], "lookup", {"ok": False, "error": "unexpected reply: %s: %s" % (type(e).__name__, e)})], None
        if not items:
            return []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(items))) as ex:
            return list(ex.map(one, items))

    each = lambda vendor, fn: pmap(by(vendor), fn)
    # The path is built as an ordered list of nodes, one per device the flow crosses; the others are only listed.
    nodes, hidden, rcache = [], {}, {}

    def placed(sid):
        return any(nd["sid"] == sid for nd in nodes)

    def place(sid, s_, vendor, sees, hs):
        nodes.append({"sid": sid, "sess": s_, "vendor": vendor, "sees": list(sees or []), "hops": list(hs)})
        hidden.pop(sid, None)

    def hide(sid, reason):
        if not placed(sid):
            hidden[sid] = reason

    hops, notes = [], []
    legs = [flow_leg(src, dst_ip, port, "destination entered")] if dst_ip else []
    # 1. Cloudflare, only for a hostname or a Cloudflare address: the origin IP from DNS; when proxied, the next
    #    devices see a Cloudflare edge address as source.
    proxied, edge, origin = False, "", []
    cf_rel = bool(host)
    if not cf_rel and dst_ip and by("cloudflare"):
        try:
            dip = ipaddress.ip_address(dst_ip)
            cf_rel = any(n_.version == dip.version and dip in n_ for n_ in cf_edge_nets(by("cloudflare")[0][1]))
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            cf_rel = True   # cannot tell: keep it
    if cf_rel:
        for (k, s_), (h, extra) in zip(by("cloudflare"), each("cloudflare", lambda k, s: (lambda r: (r[0], r[1:]))(
                flow_trace_cf(s, k, src, host, within)))):
            if extra:
                origin += extra[0]
                if extra[1]:
                    proxied, edge = True, extra[1]
            if ((extra and extra[0]) or any(x["state"] in ("bad", "warn") for x in h) or
                    any(x["check"].startswith("WAF") and not x["result"].startswith("no security events") for x in h)):
                place(k, s_, "cloudflare", [flow_leg(src, host or dst_ip, port)], h)
            else:
                hide(k, "%s is not in its zones and it has no security events for the client" % (host or dst_ip))
    else:
        for k, _ in by("cloudflare"):
            hide(k, "%s is not a Cloudflare hostname or address" % dst_ip)
    if proxied:
        notes.append("%s is proxied by Cloudflare: past the edge the source is a Cloudflare address (tested as %s, from "
                     "Cloudflare's published ranges); the client IP only travels in headers." % (host, edge or "unknown"))
    if host and origin:
        legs = [flow_leg(edge if proxied else src, ip, port, "Cloudflare DNS origin for %s" % host)
                for ip in dict.fromkeys(origin)]
    if host and not legs:
        legs = flow_resolve_host(by, src, host, port)
        if legs:
            notes.append("%s was resolved through the F5 virtual server%s, not Cloudflare." % (
                host, " and the FortiGate VIP" if any("VIP" in l["via"] for l in legs) else ""))
    if host and not legs:
        legs = flow_list_resolve(src, host, port)
        if legs:
            notes.append("%s was resolved from the VIP list (name match), not from a device." % host)
    legs = flow_dedupe(legs)
    if not legs:
        notes.append("Could not resolve %s on any connected device: enter the destination IP instead." % host)
    if len(legs) > FLOW_MAX_LEGS:
        notes.append("Only the first %d addresses were followed." % FLOW_MAX_LEGS)
    # 1b. Optional upstream 1:1 NAT (public -> private) in front of the FortiGate: from the lists or inferred.
    f5map = {}
    if legs:
        before = list(legs)
        nh, legs, f5map = flow_trace_nat(by, legs, host, port)
        if nh:
            place("nat", NAT_SESS, "nat", before, nh)
        legs = flow_dedupe(legs)

    fws = by("fortigate") + by("paloalto")
    dmap = dict(fws + by("f5"))
    nm = lambda k: str(dmap[k].get("name") or dmap[k]["host"]) if k in dmap else str(k)
    owner_box = {}

    def owners_of_ips():
        """{interface address: device id} of every connected firewall and F5, read once per trace."""
        if "m" not in owner_box:
            def ips(x):
                try:
                    return flow_dev_ips(x[1])
                except Exception:
                    return []
            items = list(dmap.items())
            with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(8, len(items)))) as ex:
                res = list(ex.map(ips, items))
            owner_box["m"] = {}
            for (k, _), lst in zip(items, res):
                for ip in lst:
                    owner_box["m"].setdefault(ip, k)
        return owner_box["m"]

    def warm(devs, ips):
        pairs = [(s_, ip) for _, s_ in devs for ip in ips if ip]
        if pairs:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(pairs))) as ex:
                list(ex.map(lambda x: flow_route(x[0], x[1], rcache), pairs))

    def fw_find(cands, seg, anchor=None, after=False, fallback=True):
        """The firewalls among cands that this part of the flow crosses: tested and placed in path order.
        Evidence, strongest first (no device names or vendor roles are assumed):
        - the next-hop chain from the anchor (the edge firewall or the F5) when it reaches the destination
        - the flow crosses the firewall (its routes to the source and the destination use different interfaces)
          AND the firewall is directly connected to the destination's subnet, or, when there is no anchor, the source's
        - with 'Also search logs': its traffic log shows the flow
        - only when nothing else is found and fallback is allowed: any firewall the flow crosses."""
        seg = [l for l in seg[:FLOW_MAX_LEGS] if l["src"]]
        cands = [x for x in cands if x[0] != anchor]
        cset = dict(cands)
        if not cands or not seg:
            return
        warm(cands + ([(anchor, dmap[anchor])] if anchor in dmap else []), [ip for l in seg for ip in (l["src"], l["dst"])])
        pick = {}
        for l in seg:
            got = {}
            chain, done = flow_chain(anchor, l["dst"], dmap, owners_of_ips(), rcache) if anchor in dmap else ([], False)
            for i, k in enumerate(chain):
                if k in cset:
                    got[k] = ("next hop on the route from %s to %s" % (nm(anchor), l["dst"]), 1 + i)
            if not done:
                for k, s_ in cands:
                    ra, rb = flow_route(s_, l["src"], rcache), flow_route(s_, l["dst"], rcache)
                    if k in got or not ra or not rb or ra[0] == rb[0]:
                        continue
                    if rb[1]:
                        got[k] = ("%s is directly connected to it (%s); %s is reached via %s" % (l["dst"], rb[0], l["src"], ra[0]), 90)
                    elif ra[1] and not after:
                        got[k] = ("%s is directly connected to it (%s); %s is reached via %s" % (l["src"], ra[0], l["dst"], rb[0]), 0)
                if not after:   # middle hops: follow the routes from the firewall the source is connected to
                    for k0 in [k for k, (_, key) in got.items() if key == 0]:
                        for i, k in enumerate(flow_chain(k0, l["dst"], dmap, owners_of_ips(), rcache)[0]):
                            if k in cset:
                                got.setdefault(k, ("next hop on the route from %s to %s" % (nm(k0), l["dst"]), 1 + i))
            if logs:
                for k, s_ in cands:
                    if k not in got:
                        try:
                            if flow_logs_seen(s_, k, l, within):
                                got[k] = ("its traffic log shows %s" % flow_txt(l), 50)
                        except Exception:
                            pass
            if not got and not done and fallback:
                for k, s_ in cands:
                    on, why, key = flow_on_path(s_, l, rcache)
                    if on:
                        got[k] = (why + "; no firewall is directly connected to either end, so this is from the routes "
                                        "alone", 50 + key)
            for k, (why, key) in got.items():
                pick.setdefault(k, []).append((l, why, key))
        grp = sorted(((min(x[2] for x in v), nm(k), k, cset[k], v) for k, v in pick.items()), key=lambda g: g[:2])

        def test(k, s_):
            hs = []
            for l, why, _ in next(g[4] for g in grp if g[2] == k):
                h = flow_fw_verdict(s_, k, l, proto, within, logs, log_src=not (proxied and l["src"] == edge))[0]
                h[0]["details"] = ("On the path: %s. " % why + h[0]["details"])[:900]
                hs += h
            return hs, None
        for g, (hs, _) in zip(grp, pmap([(g[2], g[3]) for g in grp], test)):
            place(g[2], g[3], g[3]["vendor"], [x[0] for x in g[4]], hs)

    # 2. Edge firewall: whichever connected firewall translates the destination (FortiGate VIP, Palo Alto NAT rule).
    L1 = list(legs)
    nl = len(L1[:FLOW_MAX_LEGS])
    fgv, pdb, own = {}, {}, [[] for _ in range(nl)]

    def dnat_read(x):
        try:
            return fg_cmdb(x[1], "vip", "") if x[1]["vendor"] == "fortigate" else pan_dnat_rules(x[1])
        except Exception:   # an unreachable firewall: not an edge here
            return None
    if L1 and fws:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(fws))) as ex:
            for (k, s_), d in zip(fws, ex.map(dnat_read, fws)):
                (fgv if s_["vendor"] == "fortigate" else pdb)[k] = d
        for i, l in enumerate(L1[:FLOW_MAX_LEGS]):
            own[i] = ([k for k, v in fgv.items() if isinstance(v, list) and flow_fg_vip(v, l)[0]] +
                      [k for k, v in pdb.items() if v and pan_dnat_for(v, l)[0]])
    owners = [x for x in fws if any(x[0] in o for o in own)]
    others = [x for x in fws if x not in owners]
    # a flow without a destination NAT (internal, or a public IP no firewall translates): firewalls by the routes
    free = [l for i, l in enumerate(L1[:FLOW_MAX_LEGS]) if not own[i]]
    fw_find(others, [l for l in free if l["dst"] not in f5map])
    # the VIP list knows this address's VIP firewall, which is not connected: no guessing from routes alone
    fw_find(others, [l for l in free if l["dst"] in f5map], fallback=False)
    L2 = L1
    if owners:
        def edge_one(k, s_):
            mine = [l for i, l in enumerate(L1[:FLOW_MAX_LEGS]) if k in own[i]]
            if s_["vendor"] == "fortigate":
                h, out = flow_trace_fg(s_, k, mine, proto, within, logs, proxied, fgv.get(k))
            else:
                h, out = flow_trace_pa_edge(s_, k, mine, pdb[k], proto, within, logs, proxied)
            return h, (mine, out)
        nxt, after = [], []
        for (k, s_), (h, extra) in zip(owners, pmap(owners, edge_one)):
            place(k, s_, s_["vendor"], extra[0] if extra else L1, h)
            out = (extra[1] if extra else []) or []
            nxt += out
            after.append((k, [l for l in out if l not in L1]))
        L2 = flow_dedupe(nxt + [l for i, l in enumerate(L1[:FLOW_MAX_LEGS]) if not own[i]])
        for k, ls in after:   # between the edge firewall and the translated address (the F5 VIP, or a server)
            fw_find([x for x in others if not placed(x[0])], ls, anchor=k, after=True, fallback=False)
    if L2 and f5map:   # the VIP was not found on a connected firewall: use the F5 VIP from the VIP list
        L2 = flow_dedupe([flow_leg(l["src"], f5map[l["dst"]][0], f5map[l["dst"]][1] or l["port"],
                                   "VIP list %s: %s -> F5 VIP %s" % (f5map[l["dst"]][2], l["dst"], f5map[l["dst"]][0]))
                          if l["dst"] in f5map else l for l in L2])
    # 3. Load balancer: the F5 that has the virtual server; pool members and the source address (SNAT) it uses.
    L3, f5out = L2, []
    if (L2 or host) and by("f5"):
        nxt = []
        for (k, s_), (h, out) in zip(by("f5"), each("f5", lambda k, s: flow_trace_f5(s, k, L2, src, host, within, logs, proxied))):
            out = out or []
            hit = any(l["via"].startswith("F5 ") for l in out)
            waf = any(x["check"].startswith("WAF") and x["details"] for x in h)
            failed = any(x["result"].startswith("NOT CHECKED") for x in h)
            if hit or waf or failed:
                place(k, s_, "f5", L2, [x for x in h if not (hit and x["result"].startswith("no virtual server listens"))])
                mine = [l for l in out if l["via"].startswith("F5 ")]
                nxt += mine
                f5out.append((k, mine))
        if nxt:
            L3 = flow_dedupe(nxt)
    # 4. Firewalls between the F5 and the servers (a DC firewall), from the F5's routes and the servers' subnets.
    for k, ls in f5out:
        fw_find(fws, ls, anchor=k, after=True, fallback=False)
    legs = L3
    # Only the devices on the path are shown: one that did not answer at all is left out (its place is unknown).
    for nd in [x for x in nodes if x["vendor"] != "nat" and x["hops"]
               and all(h["result"].startswith("NOT CHECKED") for h in x["hops"])]:
        nodes.remove(nd)
    for i, nd in enumerate(nodes):
        for h in nd["hops"]:
            h["order"], h["layer"] = i, "%d %s · %s" % (i + 1, FLOW_ROLE[nd["vendor"]], FLOW_VNAME[nd["vendor"]])
        hops += nd["hops"]
    if not src:
        notes.append("No client IP given: Cloudflare events and the firewall verdicts were not checked for the client.")
    notes.append("Path found from the devices' routes, VIPs and virtual servers; policy-based routing and SD-WAN rules "
                 "are not taken into account.")
    if not logs:
        notes.append("Configuration only: tick 'Also search logs' to add the F5 WAF log and firewall traffic logs.")
    bad = [h for h in hops if h["state"] == "bad"]
    unk = [h for h in hops if h["state"] == "warn"]
    if bad:
        verdict = {"label": "STOPS AT %s (%s): %s" % (bad[0]["device"], bad[0]["layer"], bad[0]["result"]), "kind": "bad"}
    elif unk:
        verdict = {"label": "NO BLOCK FOUND, %d check(s) not conclusive" % len(unk), "kind": "warn"}
    elif hops:
        verdict = {"label": "NO BLOCK FOUND on %d device(s)" % len({h["device"] for h in hops}), "kind": "ok"}
    elif not src and fws:
        verdict = {"label": "ENTER THE CLIENT IP: the firewalls need a source address to be tested", "kind": "warn"}
    else:
        verdict = {"label": "NO DEVICE ON THIS PATH: none of the connected devices is crossed by this flow", "kind": "warn"}
    summary = ["%s · %s · %s: %s" % (h["layer"], h["device"], h["check"], h["result"]) for h in hops]
    stages = []
    for nd in nodes:
        hs, v = nd["hops"], nd["vendor"]
        stt = ("blocked" if any(h["state"] == "bad" for h in hs) else "unclear" if any(h["state"] == "warn" for h in hs)
               else "passed" if any(h["state"] == "ok" for h in hs) else "checked")
        stages.append({"vendor": v, "layer": "%s · %s" % (FLOW_ROLE[v], FLOW_VNAME[v]), "state": stt,
                       "devices": ["public → private"] if v == "nat" else [nd["sess"].get("name") or nd["sess"]["host"]],
                       "sees": [flow_txt(l) for l in nd["sees"][:3]],
                       "checks": ["%s: %s" % (h["check"], h["result"]) for h in hs][:8]})
    path = {"client": src or "client", "target": dst + (":" + port if port else ""), "proto": proto, "stages": stages,
            "servers": [flow_to(l) for l in legs[:3]], "verdict": verdict["kind"]}
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "path": path,
            "request": "flow trace %s -> %s%s/%s on %d device(s)" % (src or "?", dst, ":" + port if port else "", proto, len(sess)),
            "verdict": verdict, "summary": summary + notes,
            "data": {"hops": [dict({k: h[k] for k in ("layer", "device", "check", "result", "details")},
                                   state={"bad": "blocked", "warn": "unclear"}.get(h["state"], h["state"])) for h in hops]}}


def do_flow_trace_api(b):
    try:
        return do_flow_trace(b)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "a device did not answer in time (%s). Check that every connected device is "
                                      "reachable, or disconnect the one that is not, and run the trace again."
                                      % getattr(e, "reason", e)}


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


def f5_cert_key(name):
    """'/Common/site.crt', 'site.crt', '~Common~site' -> 'common/site' (to match profile and certificate-store names)."""
    n = str(name or "").strip().replace("~", "/").lower()
    n = n if n.startswith("/") else "/common/" + n
    return re.sub(r"\.(crt|cer|pem)$", "", n).strip("/")


def f5_cert_exp(c):
    """Expiry epoch of a certificate item. TMOS puts it in different places by endpoint and version:
    expirationDate / expirationString (sys file ssl-cert), expiration or apiRawValues.expiration (sys crypto cert)."""
    raw = c.get("apiRawValues") if isinstance(c.get("apiRawValues"), dict) else {}
    for v in (c.get("expirationDate"), c.get("expirationString"), c.get("expiration"), raw.get("expiration")):
        e = to_epoch(v)
        if e:
            return e
    return None


def f5_exp_text(c, epoch):
    raw = c.get("apiRawValues") if isinstance(c.get("apiRawValues"), dict) else {}
    s = str(c.get("expirationString") or c.get("expiration") or raw.get("expiration") or "").strip()
    return s if s and epoch else (time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(epoch)) if epoch else "")


def f5_cert_rows(items, sess=None):
    """Certificate object, Common Name, SAN and expiry date; soonest expiry first, expired ones marked EXPIRED.
    Items without an expiry are completed from the 'sys file ssl-cert' list, which always has expirationDate."""
    if sess and any(not f5_cert_exp(c) for c in items):
        ok, d = f5_get(sess, "/mgmt/tm/sys/file/ssl-cert")
        files = {f5_cert_key(f.get("fullPath") or f.get("name")): f
                 for f in ((d.get("items") if ok and isinstance(d, dict) else None) or [])}
        items = [dict(files.get(f5_cert_key(c.get("fullPath") or c.get("name")), {}), **{k: v for k, v in c.items() if v not in (None, "")})
                 if not f5_cert_exp(c) else c for c in items]
    rows = []
    for c in items:
        exp = f5_cert_exp(c)
        left = days_from_now(exp) if exp else None
        cn = c.get("commonName") or next((x.strip()[3:] for x in re.split(r"(?<!\\),", str(c.get("subject") or ""))
                                          if x.strip().upper().startswith("CN=")), "")
        san = ", ".join(x.strip().split(":", 1)[-1] for x in str(c.get("subjectAlternativeName") or "").split(",") if x.strip())
        date = f5_exp_text(c, exp)
        if left is not None and left < 0:
            date += " · EXPIRED"
        rows.append({"certificate": c.get("fullPath") or c.get("name") or "", "common_name": cn, "san": san,
                     "expiry_date": date, "_e": exp or float("inf")})
    rows.sort(key=lambda r: r["_e"])
    for r in rows:
        r.pop("_e")
    return rows


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
    cert_exp = {}   # normalised name -> (expiry text, days left), bundles included
    for c in f5_items(sess, "/mgmt/tm/sys/crypto/cert", notes, "certificates") or []:
        name = c.get("fullPath") or c.get("name")
        exp = f5_cert_exp(c)
        left = days_from_now(exp) if exp else None
        cert_exp[f5_cert_key(name)] = (f5_exp_text(c, exp), left)
        if c.get("isBundle") in (True, "true"):
            continue
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
                    "status": "" if left is None else "EXPIRED" if left < 0 else "valid",
                    "expires": f5_exp_text(c, exp), "days_left": left, "key": "%s %s" % (ktype, size or ""),
                    "used_by": users})
    # certificate expiry next to each profile's certificates; names not in the list are read one by one
    # (profiles reference 'sys file ssl-cert' objects, which the crypto list does not always show under the same name)
    need = lambda: sorted({c for r in inv if r["type"] == "client-ssl" for c in r["certs"]
                           if c and not cert_exp.get(f5_cert_key(c), ("",))[0]})
    if need():
        for c in f5_items(sess, "/mgmt/tm/sys/file/ssl-cert", notes, "certificate files") or []:
            exp = f5_cert_exp(c)
            k = f5_cert_key(c.get("fullPath") or c.get("name"))
            if exp and not cert_exp.get(k, ("",))[0]:
                cert_exp[k] = (f5_exp_text(c, exp), days_from_now(exp))
    failed = []
    for c in need()[:30]:
        ref = urllib.parse.quote(c.replace("/", "~"))
        for base in ("/mgmt/tm/sys/file/ssl-cert/", "/mgmt/tm/sys/crypto/cert/"):
            st, ok, d = rest_get(sess, base + ref)
            exp = f5_cert_exp(d) if ok and isinstance(d, dict) else None
            if exp:
                cert_exp[f5_cert_key(c)] = (f5_exp_text(d, exp), days_from_now(exp))
                break
        else:
            failed.append("%s (HTTP %s)" % (c, st))
    if failed:
        notes.append("Could not read the expiry of: %s. The account needs read access to System > File Management "
                     "(sys file ssl-cert / sys crypto cert)." % ", ".join(failed))
    for r in inv:
        if r["type"] == "client-ssl":
            out = []
            for c in r["certs"]:
                if not c:
                    continue
                txt, left = cert_exp.get(f5_cert_key(c), ("", None))
                out.append("%s: %s" % (c, "expiry not readable (see notes)" if not txt else
                                       txt if left is None else "%s (%s)" % (txt, "EXPIRED %d day(s) ago" % -left if left < 0
                                                                             else "%d day(s) left" % left)))
            r["cert_expiry"] = out
    # The inventory shows profile, use, certificates and expiry only; cipher / option issues are in the findings.
    for r in inv:
        for k in ("ciphers", "cipher_group", "status", "options", "not_explicitly_disabled"):
            r.pop(k, None)
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
    ipq = str(parse_ip(b.get("ip"), "client IP")) if str(b.get("ip") or "").strip() else ""
    hip = str(parse_ip(b.get("header_ip"), "True-Client-IP")) if str(b.get("header_ip") or "").strip() else ""
    urlq = (b.get("url") or "").strip().lower()
    if len(urlq) > 200:
        raise ValueError("URL path is too long (max 200 characters)")
    top = num(b.get("top"), 1, 200, 50, "max rows")
    scan = num(b.get("scan"), 100, 5000, 1000, "entries to scan")
    cutoff = cutoff_epoch(b)
    hkey, vq = hname.lower(), hval.lower()
    audit(sess, "ASM request log by header: %s %s %s" % (hname, ("contains '%s'" % hval) if hval else "present",
                                                           status or "any status"))
    flt = " and ".join(x for x in (asm_status_flt(sess, status), ("clientIp eq '%s'" % ipq) if ipq else "") if x)
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
                    hostq and asm_hostname(i) and hostq not in asm_hostname(i).lower()) or (
                    ipq and i.get("clientIp") and i.get("clientIp") != ipq):
                continue
            # The list view may omit the raw request; fetch the full record (bounded by time and count).
            if not i.get("rawRequest") and fetched < 1500 and time.time() - t0 < 100 and asm_enrich(sess, i):
                fetched += 1
            if i.get("rawRequest"):
                with_raw += 1
            if hostq and hostq not in asm_hostname(i).lower():
                continue
            if urlq and urlq not in str(first(i, "url", "uri") or "").lower():
                continue
            if hip and hip not in (str(i.get("trueClientIp") or ""), asm_header_ip(i)):
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
    if status and not asm_status_flt(sess, status):
        notes.append("The device accepts no status filter, so '%s' was matched locally." % status)
    extra = ["client IP " + ipq] * bool(ipq) + ["True-Client-IP " + hip] * bool(hip) + ["URL contains '%s'" % urlq] * bool(urlq)         + ["hostname contains '%s'" % hostq] * bool(hostq)
    if extra:
        notes.append("Also filtered by " + ", ".join(extra) + ".")
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
# Automatic lookups (the AI assistant and the flow trace) never read the FortiGate's disk log store.
FG_AUTO_LOG_SOURCES = ("memory", "fortianalyzer")


def fg_auto_logs(fn, b):
    """Run a FortiGate log reader (do_fg_logs / do_acc) on memory, then FortiAnalyzer: never on disk.
    The first source that has entries wins; otherwise the first one that answered."""
    first, errs = None, []
    for src in FG_AUTO_LOG_SOURCES:
        r = fn(dict(b, log_source=src))
        if r.get("ok"):
            d = r.get("data") or {}
            if d.get("entries") or d.get("lines") or d.get("timeline"):
                return r
            first = first or r
        else:
            errs.append("%s: %s" % (src, r.get("error")))
    if first:
        return first
    return {"ok": False, "error": "log query failed on memory and FortiAnalyzer (disk is not used for automatic "
                                  "lookups). %s" % " | ".join(errs)}
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


def pan_log_rows(sess, lt, query, n, skip=0):
    params = {"type": "log", "log-type": lt, "query": query, "nlogs": str(n), "dir": "backward"}
    if skip:
        params["skip"] = str(skip)
    root = pan_xml(sess, params)
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


# ---- ACC: Application Command Center-style activity dashboard (PAN-OS / FortiGate) ---------------------------
# Built from the firewall's own logs with read-only log queries. Filters are pushed into the device query where the
# log API supports it and are always applied again locally, so a filter the device ignores cannot widen the result.
ACC_VAL_RE = re.compile(r"^[A-Za-z0-9_.:/@\\\- ]{1,80}$")
# filter key -> (label, PAN-OS query term, FortiGate log field)
ACC_FILTERS = collections.OrderedDict([
    ("src", ("Source IP", "(addr.src in {v})", "srcip")),
    ("dst", ("Destination IP", "(addr.dst in {v})", "dstip")),
    ("app", ("Application", "(app eq '{v}')", "app")),
    ("user", ("User", "(user.src eq '{v}')", "user")),
    ("rule", ("Rule / policy", "(rule eq '{v}')", "policyid")),
    ("from_zone", ("Source zone / interface", "(zone.src eq '{v}')", "srcintf")),
    ("to_zone", ("Destination zone / interface", "(zone.dst eq '{v}')", "dstintf")),
    ("port", ("Destination port", "(port.dst eq {v})", "dstport")),
])
ACC_REC_KEY = {"from_zone": "from", "to_zone": "to"}
ACC_PERIODS = collections.OrderedDict([("last-15-minutes", 900), ("last-hour", 3600), ("last-6-hrs", 21600),
                                       ("last-12-hrs", 43200), ("last-24-hrs", 86400), ("last-7-days", 604800)])
ACC_BUCKETS = ((60, "1 minute"), (300, "5 minutes"), (900, "15 minutes"), (1800, "30 minutes"), (3600, "1 hour"),
               (10800, "3 hours"), (21600, "6 hours"), (43200, "12 hours"), (86400, "1 day"))
ACC_SEVERITIES = ("critical", "high", "medium", "low", "informational")
PAN_ALLOW_ACTIONS = ("", "allow", "alert")
FG_PASS_ACTIONS = ("", "detected", "pass_session", "passthrough", "monitored", "allowed", "accept", "pass", "log-only")
FG_ACC_LOGS = (("traffic", "traffic/forward"), ("threat", "utm/ips"), ("virus", "utm/virus"), ("url", "utm/webfilter"))
ACC_DEADLINE = 150   # seconds for all log reads of one ACC run


def acc_filters(b):
    raw = b.get("filters") if isinstance(b.get("filters"), dict) else {}
    out = collections.OrderedDict()
    for k, (label, _, _) in ACC_FILTERS.items():
        v = str(raw.get(k) or "").strip()
        if not v:
            continue
        if k in ("src", "dst"):
            out[k] = parse_ip_or_net(v, label)
        elif k == "port":
            out[k] = num(v, 0, 65535, 0, label)
        elif not ACC_VAL_RE.match(v):
            raise ValueError("invalid characters in: " + label)
        else:
            out[k] = v
    return out


def acc_drill_ok(k, v):
    """True if v can be used as filter k (so a dashboard click never sends a value the filter would refuse)."""
    v = str(v or "").strip()
    if not v or not k:
        return False
    if k in ("src", "dst"):
        try:
            ipaddress.ip_address(v)
            return True
        except ValueError:
            return False
    if k == "port":
        return v.isdigit() and int(v) <= 65535
    return bool(ACC_VAL_RE.match(v))


def acc_keep(r, flt):
    for k, want in flt.items():
        if k in ("src", "dst"):
            if not ip_matches(r.get(k), want):
                return False
        elif k == "rule":
            if str(want).lower() not in (str(r.get("rule_v") or "").lower(), str(r.get("rule_name") or "").lower()):
                return False
        elif str(r.get(ACC_REC_KEY.get(k, k)) or "").strip().lower() != str(want).lower():
            return False
    return True


def acc_int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def acc_host(url):
    u = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", str(url or "").strip().strip('"'), flags=re.I)
    return re.sub(r":\d+$", "", u.split("/")[0].split("?")[0]).lower()


def acc_sev(v):
    v = str(v or "").strip().lower()
    return "informational" if v in ("info", "information") else v


def acc_scalar(v):
    """A log field as plain text. PAN-OS fields with XML attributes arrive as dicts
    (e.g. <srcloc cc="US">United States</srcloc> -> {"@cc": "US", "#text": "United States"})."""
    if isinstance(v, dict):
        if v.get("#text") not in (None, ""):
            return acc_scalar(v["#text"])
        vals = [acc_scalar(x) for x in v.values()]
        return next((x for x in vals if x not in (None, "")), "")
    if isinstance(v, list):
        return ", ".join(str(acc_scalar(x)) for x in v if acc_scalar(x) not in (None, ""))
    return v


def acc_flat(e):
    return {k: acc_scalar(v) for k, v in e.items()}


def acc_pan_rec(lt, e):
    e = acc_flat(e)
    act = str(e.get("action") or "").lower()
    rule = str(e.get("rule") or "")
    r = {"t": to_epoch(first(e, "receive_time", "time_generated")), "src": e.get("src") or "", "dst": e.get("dst") or "",
         "port": str(e.get("dport") or ""), "app": e.get("app") or "", "user": e.get("srcuser") or "",
         "rule": rule, "rule_v": rule, "rule_name": rule, "from": e.get("from") or "", "to": e.get("to") or "",
         "action": act, "blocked": act not in PAN_ALLOW_ACTIONS, "bytes": 0}
    if lt == "traffic":
        r.update(bytes=acc_int(e.get("bytes")), srcloc=e.get("srcloc") or "", dstloc=e.get("dstloc") or "",
                 category=e.get("category") or "", risk="")
    elif lt == "threat":
        r.update(name=str(first(e, "threatid", "threat_name")), severity=acc_sev(e.get("severity")),
                 kind=e.get("subtype") or "")
    else:
        url = str(e.get("misc") or "")
        r.update(url=url, host=acc_host(url), category=e.get("category") or "")
    return r


def acc_fg_rec(kind, e):
    e = acc_flat(e)
    pid, pname = str(e.get("policyid") if e.get("policyid") is not None else ""), str(e.get("policyname") or "")
    act = str(e.get("action") or "").lower()
    r = {"t": to_epoch(("%s %s" % (e.get("date") or "", e.get("time") or "")).strip()),
         "src": e.get("srcip") or "", "dst": e.get("dstip") or "", "port": str(e.get("dstport") or ""),
         "app": e.get("app") or "", "user": first(e, "user", "unauthuser"),
         "rule": "%s · %s" % (pid, pname) if pid and pname else pid or pname, "rule_v": pid, "rule_name": pname,
         "from": e.get("srcintf") or "", "to": e.get("dstintf") or "", "action": act, "bytes": 0}
    if kind == "traffic":
        r.update(bytes=acc_int(e.get("sentbyte")) + acc_int(e.get("rcvdbyte")), srcloc=e.get("srccountry") or "",
                 dstloc=e.get("dstcountry") or "", category=e.get("appcat") or "",
                 risk=str(e.get("apprisk") or "").lower(), blocked=fg_is_blocked(e), service=e.get("service") or "")
    elif kind in ("threat", "virus"):
        r.update(name=str(first(e, "attack", "virus", "msg")), severity=acc_sev(first(e, "severity", "crlevel")),
                 kind=e.get("subtype") or ("virus" if kind == "virus" else "ips"), blocked=act not in FG_PASS_ACTIONS)
    else:
        r.update(url="%s%s" % (e.get("hostname") or "", e.get("url") or ""), host=str(e.get("hostname") or "").lower(),
                 category=first(e, "catdesc", "cat"), blocked=act == "blocked")
    return r


def acc_fmt_t(t):
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(t))


def acc_cover(what, n_read, scan, recs, limit_hit):
    ts = [r["t"] for r in recs if r.get("t")]
    s = "%s: %s log entries read, %s kept after filters%s" % (
        what, "{:,}".format(n_read), "{:,}".format(len(recs)),
        " (%s → %s device time)" % (acc_fmt_t(min(ts)), acc_fmt_t(max(ts))) if ts else "")
    if limit_hit:
        s += ("; the read limit (%s per log type) was reached, so older entries in the time range are not counted. "
              "Add a filter or raise 'Log entries to read' to cover more." % "{:,}".format(scan))
    return s + "."


def acc_pan_collect(sess, flt, period, scan):
    query = " and ".join([ACC_FILTERS[k][1].format(v=v) for k, v in flt.items()] + ["(receive_time in %s)" % period])
    deadline = time.time() + ACC_DEADLINE

    def one(lt):
        rows, skip = [], 0
        while skip < scan and time.time() < deadline:
            k = min(5000, scan - skip)   # PAN-OS returns at most 5000 entries per log query
            got = pan_log_rows(sess, lt, query, k, skip)
            rows.extend(got)
            if len(got) < k:
                return rows, False
            skip += k
        return rows, True
    recs, notes, errors = {}, [], []
    with concurrent.futures.ThreadPoolExecutor(3) as ex:
        futs = [(lt, ex.submit(one, lt)) for lt in ("traffic", "threat", "url")]
        for lt, f in futs:
            try:
                raw, hit = f.result()
            except (ValueError, urllib.error.URLError, OSError) as e:
                errors.append("%s log: %s" % (lt, getattr(e, "reason", e)))
                recs[lt] = []
                continue
            # Session-start logs (log at session start) would count a session twice.
            rs = [acc_pan_rec(lt, e) for e in raw
                  if not (lt == "traffic" and str(e.get("subtype") or "").lower() == "start")]
            recs[lt] = [r for r in rs if acc_keep(r, flt)]
            notes.append(acc_cover({"traffic": "Traffic", "threat": "Threat", "url": "URL"}[lt], len(raw), scan, recs[lt], hit))
    return recs, notes, errors, "log query " + query


def acc_fg_collect(sess, flt, period, scan, src, vdom):
    cutoff = time.time() - ACC_PERIODS[period]
    conds = []
    for k, v in flt.items():
        # Subnets, names with spaces and policy names are matched locally only.
        if isinstance(v, (ipaddress.IPv4Network, ipaddress.IPv6Network)) or " " in str(v) or \
                (k == "rule" and not str(v).isdigit()):
            continue
        conds.append((ACC_FILTERS[k][2], v))
    deadline = time.time() + ACC_DEADLINE

    def one(path):
        out, start = [], 0
        while start < scan and time.time() < deadline:
            k = min(1000, scan - start)
            q = [("start", str(start)), ("rows", str(k))] + [("filter", "%s==%s" % c) for c in conds]
            if vdom:
                q.append(("vdom", vdom))
            st, ok, data = rest_get(sess, "/api/v2/log/%s/%s?%s" % (src, path, urllib.parse.urlencode(q)))
            res = data.get("results") if ok and isinstance(data, dict) else None
            if isinstance(res, dict):
                res = [res]
            if not isinstance(res, list):
                if not out:
                    raise ValueError("HTTP %s, response: %s" % (st, str(data)[:200]))
                return out, False
            res = [e for e in res if isinstance(e, dict)]
            out.extend(res)
            if len(res) < k:
                return out, False
            eps = [x for x in (fg_event_epoch(e) for e in res) if x]
            if eps and min(eps) < cutoff:   # newest first: everything after this page is older than the range
                return out, False
            start += k
        return out, True
    audit(sess, "ACC log reads %s" % (" ".join("%s==%s" % c for c in conds) or "(unfiltered)"))
    recs, notes, errors = {"traffic": [], "threat": [], "url": []}, [], []
    with concurrent.futures.ThreadPoolExecutor(4) as ex:
        futs = [(kind, path, ex.submit(one, path)) for kind, path in FG_ACC_LOGS]
        for kind, path, f in futs:
            try:
                raw, hit = f.result()
            except (ValueError, urllib.error.URLError, OSError) as e:
                errors.append("%s log (%s): %s" % (path, src, getattr(e, "reason", e)))
                continue
            raw_in = [e for e in raw if (fg_event_epoch(e) or cutoff) >= cutoff]
            rs = [r for r in (acc_fg_rec(kind, e) for e in raw_in) if acc_keep(r, flt)]
            recs["threat" if kind == "virus" else kind].extend(rs)
            notes.append(acc_cover({"traffic": "Traffic", "threat": "IPS", "virus": "Antivirus",
                                    "url": "Web filter"}[kind], len(raw), scan, rs, hit))
    return recs, notes, errors, "log reads /api/v2/log/%s/{%s}" % (src, ",".join(p for _, p in FG_ACC_LOGS))


def acc_top(recs, key, sort, drill=None, pred=None, label_key=None, value_key=None, n=10):
    cnt, byt, lab = collections.Counter(), collections.Counter(), {}
    for r in recs:
        if pred and not pred(r):
            continue
        v = r.get(value_key or key)
        if not isinstance(v, (str, int, float)):
            v = acc_scalar(v)
            v = "" if v is None else str(v)
        if v in (None, ""):
            continue
        cnt[v] += 1
        byt[v] += r.get("bytes") or 0
        if label_key:
            lab[v] = r.get(label_key) or v
    order = byt if sort == "bytes" and any(byt.values()) else cnt
    return [[str(lab.get(v, v)), cnt[v], byt[v], str(v) if acc_drill_ok(drill, v) else ""]
            for v, _ in order.most_common(n)]


def do_acc(b):
    sess = SESSIONS.get(b.get("id"))
    if not sess or sess["vendor"] not in ("paloalto", "fortigate"):
        return {"ok": False, "error": "connect a Palo Alto firewall or a FortiGate first"}
    t0 = time.time()
    pan = sess["vendor"] == "paloalto"
    try:
        flt = acc_filters(b)
        period = b.get("period") or "last-hour"
        if period not in ACC_PERIODS:
            raise ValueError("invalid time range")
        sort = "sessions" if b.get("sort") == "sessions" else "bytes"
        scan = num(b.get("scan"), 100, 50000, 5000, "log entries to read per log type")
        audit(sess, "ACC %s %s" % (period, json.dumps({k: str(v) for k, v in flt.items()})))
        if pan:
            recs, notes, errors, request = acc_pan_collect(sess, flt, period, scan)
        else:
            src = b.get("log_source") or "disk"
            if src not in FG_LOG_SOURCES:
                raise ValueError("invalid log source")
            recs, notes, errors, request = acc_fg_collect(sess, flt, period, scan, src, pstr(b.get("vdom"), "VDOM"))
        if errors and not notes:
            raise ValueError("every log read failed. Check that the API account has log read access%s. (%s)" % (
                "" if pan else ", logging to the chosen log source is enabled and the VDOM is correct",
                "; ".join(errors)))
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
    tr, th, ur = recs.get("traffic", []), recs.get("threat", []), recs.get("url", [])

    # Timeline: one bucket size for every chart, about 60 columns over the time the logs cover.
    ts = [r["t"] for r in tr + th + ur if r.get("t")]
    keys, bs, bucket = [], 60, "1 minute"
    if ts:
        lo, hi = min(ts), max(ts)
        bs, bucket = next((x for x in ACC_BUCKETS if (hi - lo) / x[0] <= 60), ACC_BUCKETS[-1])
        keys = list(range(int(lo // bs * bs), int(hi // bs * bs) + 1, bs))
    idx = {k: i for i, k in enumerate(keys)}

    def S(rs, pred=None, val=None):
        out = [0] * len(keys)
        for r in rs:
            if r.get("t") and (not pred or pred(r)):
                i = idx.get(int(r["t"] // bs * bs))
                if i is not None:
                    out[i] += val(r) if val else 1
        return out
    blocked, allowed = (lambda r: r["blocked"]), (lambda r: not r["blocked"])
    hi_sev = lambda r: r.get("severity") in ("critical", "high")
    nbytes = lambda r: r.get("bytes") or 0
    n_tr, n_bl, n_th, n_hi = len(tr), sum(1 for r in tr if r["blocked"]), len(th), sum(1 for r in th if hi_sev(r))
    tot_bytes = sum(nbytes(r) for r in tr)
    tiles = [{"label": "Sessions", "value": n_tr, "fmt": "num", "spark": S(tr)},
             {"label": "Data", "value": tot_bytes, "fmt": "bytes", "spark": S(tr, val=nbytes)},
             {"label": "Applications", "value": len({r["app"] for r in tr if r["app"]}), "fmt": "num"},
             {"label": "Source IPs", "value": len({r["src"] for r in tr if r["src"]}), "fmt": "num"},
             {"label": "Blocked sessions", "value": n_bl, "fmt": "num", "spark": S(tr, blocked),
              "sub": "%.1f%% of sessions" % (100.0 * n_bl / n_tr) if n_tr else ""},
             {"label": "Threats", "value": n_th, "fmt": "num", "spark": S(th),
              "sub": "%d blocked" % sum(1 for r in th if r["blocked"]) if n_th else ""},
             {"label": "Critical / high threats", "value": n_hi, "fmt": "num", "spark": S(th, hi_sev)},
             {"label": "Blocked URLs", "value": sum(1 for r in ur if r["blocked"]), "fmt": "num", "spark": S(ur, blocked),
              "sub": "of %s URL log entries" % "{:,}".format(len(ur)) if ur else ""}]

    def T(title, rs, key, drill=None, pred=None, traffic=False, **kw):
        return {"title": title, "drill": drill, "metric": "traffic" if traffic else "count",
                "rows": acc_top(rs, key, sort if traffic else "sessions", drill, pred, **kw)}
    rule_kw = {"label_key": "rule", "value_key": "rule_v"}
    rules = "Rules" if pan else "Policies"
    zf, zt = ("Source zones", "Destination zones") if pan else ("Source interfaces", "Destination interfaces")
    sevs = [s for s in ACC_SEVERITIES if any(r.get("severity") == s for r in th)]
    sevs += sorted({r.get("severity") for r in th if r.get("severity") and r.get("severity") not in ACC_SEVERITIES})
    tabs = [
        {"title": "Network activity", "count": n_tr, "charts": [
            {"title": "Sessions over time", "stack": True, "fmt": "num",
             "series": [["Allowed", S(tr, allowed)], ["Blocked", S(tr, blocked)]]},
            {"title": "Data over time", "fmt": "bytes", "series": [["Data", S(tr, val=nbytes)]]}],
         "tops": [T("Applications", tr, "app", "app", traffic=True), T("Source IPs", tr, "src", "src", traffic=True),
                  T("Destination IPs", tr, "dst", "dst", traffic=True), T("Users", tr, "user", "user", traffic=True),
                  T(rules, tr, "rule", "rule", traffic=True, **rule_kw),
                  T(zf, tr, "from", "from_zone", traffic=True), T(zt, tr, "to", "to_zone", traffic=True),
                  T("Destination ports", tr, "port", "port", traffic=True),
                  T("Destination countries", tr, "dstloc", traffic=True),
                  T("URL categories" if pan else "Application categories", tr, "category", traffic=True)] +
                 ([] if pan else [T("Services", tr, "service", traffic=True),
                                  T("High / critical risk applications", tr, "app", "app", traffic=True,
                                    pred=lambda r: r.get("risk") in ("critical", "high"))])},
        {"title": "Threat activity", "count": n_th, "charts": [
            {"title": "Threats over time by severity", "stack": True, "fmt": "num",
             "series": [[s, S(th, lambda r, s=s: r.get("severity") == s)] for s in sevs]}],
         "tops": [T("Threats", th, "name"), T("Severity", th, "severity"), T("Threat types", th, "kind"),
                  T("Attackers (source)", th, "src", "src"), T("Victims (destination)", th, "dst", "dst"),
                  T("Applications", th, "app", "app"), T(rules, th, "rule", "rule", **rule_kw), T("Actions", th, "action")]},
        {"title": "Blocked activity", "count": n_bl + sum(1 for r in th + ur if r["blocked"]), "charts": [
            {"title": "Blocked over time", "fmt": "num",
             "series": [["Sessions", S(tr, blocked)], ["Threats", S(th, blocked)], ["URLs", S(ur, blocked)]]}],
         "tops": [T("Blocked applications", tr, "app", "app", blocked), T("Blocked sources", tr, "src", "src", blocked),
                  T("Blocked destinations", tr, "dst", "dst", blocked), T("Blocked ports", tr, "port", "port", blocked),
                  T("Blocking " + rules.lower(), tr, "rule", "rule", blocked, **rule_kw),
                  T("Blocked threats", th, "name", None, blocked), T("Blocked URL categories", ur, "category", None, blocked),
                  T("Blocked web hosts", ur, "host", None, blocked)]},
        {"title": "URL activity", "count": len(ur), "charts": [
            {"title": "URL requests over time", "stack": True, "fmt": "num",
             "series": [["Allowed", S(ur, allowed)], ["Blocked", S(ur, blocked)]]}],
         "tops": [T("URL categories", ur, "category"), T("Web hosts", ur, "host"), T("Users", ur, "user", "user"),
                  T("Source IPs", ur, "src", "src")]}]
    applied = collections.OrderedDict((k, {"label": ACC_FILTERS[k][0], "value": str(v)}) for k, v in flt.items())
    dash = {"vendor": sess["vendor"], "bucket": bucket, "sort": sort, "t": [acc_fmt_t(k) for k in keys],
            "tiles": tiles, "tabs": tabs, "filters": applied}

    # The same numbers as tables: the table view, and what Copy / CSV / HTML report export.
    shown = {"num": lambda v: "{:,}".format(v), "bytes": cf_fmt_bytes}
    data = {"headline": {t["label"]: shown[t["fmt"]](t["value"]) + (" (%s)" % t["sub"] if t.get("sub") else "")
                         for t in tiles}}
    for tab in tabs:
        for tp in tab["tops"]:
            if tp["rows"]:
                data[re.sub(r"\W+", "_", "%s %s" % (tab["title"].split()[0], tp["title"])).lower().strip("_")] = [
                    ({"name": r[0], "sessions": r[1], "data": cf_fmt_bytes(r[2]),
                      "share": "%.1f%%" % (100.0 * r[1] / n_tr) if n_tr else ""} if tp["metric"] == "traffic"
                     else {"name": r[0], "log_entries": r[1]}) for r in tp["rows"]]
    tl_b, tl_d, tl_bl, tl_th, tl_ur = S(tr), S(tr, val=nbytes), S(tr, blocked), S(th), S(ur)
    data["timeline"] = [{"time": acc_fmt_t(k), "sessions": tl_b[i], "blocked_sessions": tl_bl[i],
                         "data": cf_fmt_bytes(tl_d[i]), "threats": tl_th[i], "url_entries": tl_ur[i]}
                        for i, k in enumerate(keys)]
    summary = (["Filters: " + " · ".join("%s %s" % (f["label"], f["value"]) for f in applied.values())] if applied else []) + \
        ["Time range: %s. Charts use %s buckets; times are the firewall's own clock." % (period, bucket)] + notes + \
        ["Built from the logs (like ACC): only traffic that matches a rule with logging enabled is counted. "
         "Each log entry counts as one session or event" + ("; session-start logs are skipped." if pan else ".")] + errors
    label = "ACC · %s SESSIONS · %s · %s BLOCKED · %s THREATS (%d CRITICAL/HIGH)" % (
        "{:,}".format(n_tr), cf_fmt_bytes(tot_bytes), "%.1f%%" % (100.0 * n_bl / n_tr) if n_tr else "0%",
        "{:,}".format(n_th), n_hi)
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "request": request,
            "verdict": {"label": label, "kind": "bad" if n_hi else "ok" if n_tr or n_th or ur else "info"},
            "summary": summary, "data": data, "acc": dash}


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
# PAN-OS packet capture is DISABLED: it changes packet-diag state on the firewall. The API refuses it before
# anything is sent and the page does not show it. (F5 tcpdump and FortiGate are not affected.)
PAN_CAPTURE_ENABLED = False
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
    if not PAN_CAPTURE_ENABLED:
        return {"ok": False, "error": "packet capture is disabled for Palo Alto firewalls in this console"}
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
                     "request data does not hold every request; only the last 24 hours are searched. 'Trace Ray ID: "
                     "Cloudflare → F5' also searches the F5 log, which keeps every logged request.")
        if len(sess.get("zones") or []) > len(zones) > 1:
            notes.append("Only the first %d zones were searched." % len(zones))
    if f5_rows is None:
        notes.append("Tip: 'Trace Ray ID: Cloudflare → F5' also finds this request in the ASM log of the connected F5 "
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
        cf_res = "not found in Cloudflare data (sampled, last 24 hours)"
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
                     "details": "no F5 connected"})
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
        raise ValueError("connect the F5 device to trace by support ID")
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
            span = "the last 24 hours (enter a request time to search another moment)"
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
        notes.append("Nothing in Cloudflare's sampled data. Connect the F5 to search its log "
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


# ---- Local LLM assistant: explain the current output, chat about it, or let the model run read-only checks --------
# Talks to an OpenAI-compatible chat API (Ollama, LM Studio, llama.cpp server, vLLM). Settings live in memory only.
# Sent only to this PC or an approved host (LLM_APPROVED); secrets are masked and large output trimmed before sending.
LLM_CFG = {"url": "http://127.0.0.1:11434/v1", "model": "", "key": "", "budget": 24000}
LLM_LOCAL = ("127.0.0.1", "localhost", "::1")
# The only model servers device data may be sent to, besides this PC: exact host names, no wildcards, one per line in
# llm_approved.txt next to this script (not in git: lines starting with # are comments). Any other address is refused,
# so prompts with device output cannot leave the environment. Add a host only when that model server is approved.
def llm_load_approved():
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "llm_approved.txt"), encoding="utf-8") as f:
            return tuple(dict.fromkeys(h for h in (x.split("#")[0].strip().lower().rstrip(".") for x in f)
                                       if re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", h)))
    except OSError:
        return ()


LLM_APPROVED = llm_load_approved()
LLM_SECRET_KEY = re.compile(r"(passw|passphrase|secret|token|api[_-]?key|apikey|private[_-]?key|\bpsk\b|pre-?shared|"
                            r"community|cookie|authorization|auth[_-]?hash|x-api-key|session[_-]?id)", re.I)
LLM_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?(-----END [A-Z0-9 ]+-----|$)", re.S)
LLM_HASH = re.compile(r"\$(1|2[abxy]?|5|6|y|sha512|md5)\$[^\s\"',;]{8,}")
LLM_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}")
LLM_SYSTEM = (
    "You are a network-security troubleshooting assistant inside ITSec Ops, a read-only console for F5 BIG-IP, "
    "Palo Alto PAN-OS, FortiGate and Cloudflare. Answer only from the data you are given or that tools return, and quote "
    "the values that matter (IPs, rule / policy names, times, percentages, counts). If the data does not show something, "
    "say so and name the check that would show it. Start with the conclusion, then the evidence, then next steps; keep it "
    "short and use plain markdown (short paragraphs, '-' bullets, **bold**, `code`). Never invent device output. Data may "
    "be trimmed ('_trimmed' marks it) and values shown as [redacted] were hidden on purpose. For 'top / most / highest / "
    "lowest' questions read the ranking from the tables and top lists in the data and copy the names and numbers "
    "exactly; if the data does not contain the answer, say that instead of guessing. Every name you write (virtual "
    "server, pool, rule, policy, object, host, IP) must appear character for character in the data; never write an "
    "example or typical name.")


def llm_url_ok(url):
    u = urllib.parse.urlparse(str(url or "").strip())
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ValueError("model address must look like https://%s/v1 or http://127.0.0.1:11434/v1"
                         % (LLM_APPROVED[0] if LLM_APPROVED else "<approved-host>"))
    host = u.hostname.lower().rstrip(".")
    if host not in LLM_LOCAL and host not in LLM_APPROVED:
        raise ValueError("%s is not an approved model server, so device data will not be sent to it. Approved: %s "
                         "(or this PC: 127.0.0.1 / localhost). Approved hosts are listed in llm_approved.txt next to netops_console.py."
                         % (u.hostname, ", ".join(LLM_APPROVED) or "none"))
    # The full endpoint pasted from API docs (…/v1/chat/completions) is cut back to the API base (…/v1).
    return re.sub(r"/(chat/completions|completions|models)$", "", str(url).strip().rstrip("/"))


LLM_WAIT = 600   # seconds the model may stay silent (loading, reading the prompt) before we give up


class LlmNoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could carry the prompt or the API key to another host: stop instead of following it."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("the model server answered with a redirect (HTTP %s) to %s; not followed, so nothing was sent "
                         "there. Use the final address of the API as the model server." % (code, newurl[:200]))


def llm_route():
    host = (urllib.parse.urlparse(LLM_CFG["url"]).hostname or "").lower().rstrip(".")
    return "%s · %s · direct (no proxy) · redirects blocked" % (
        host or "?", "this PC" if host in LLM_LOCAL else "approved" if host in LLM_APPROVED else "NOT approved")


def llm_http(method, path, body=None, timeout=60, root=False, stream=False):
    base = llm_url_ok(LLM_CFG["url"])   # checked before every request, not only when saved
    if root:   # the server's own API next to /v1, e.g. Ollama /api/tags
        base = re.sub(r"/v1$", "", base)
    hdr = {"Content-Type": "application/json"}
    if LLM_CFG["key"]:
        hdr["Authorization"] = "Bearer " + LLM_CFG["key"]
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                 method=method, headers=hdr)
    # Always direct (no system / cloud web proxy may see the prompt) and never redirected to another address.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), LlmNoRedirect())
    try:
        if stream:   # Ollama NDJSON: the timeout applies to each read, so a long answer is never cut off while it flows
            with opener.open(req, timeout=LLM_WAIT) as r:
                out, text, calls = {}, [], []
                for line in r:
                    if not line.strip():
                        continue
                    d = json.loads(line)
                    if d.get("error"):
                        return 500, {"error": d["error"]}
                    m = d.get("message") or {}
                    text.append(m.get("content") or "")
                    calls += m.get("tool_calls") or []
                    if d.get("done"):
                        out = d
                out["message"] = {"role": "assistant", "content": "".join(text)}
                if calls:
                    out["message"]["tool_calls"] = calls
                return r.status, out
        with opener.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()[:600].decode("utf-8", "replace")
        try:
            raw = (json.loads(raw).get("error") or {}).get("message") or raw
        except (ValueError, AttributeError):
            pass
        return e.code, {"error": str(raw)}


def llm_redact(x, depth=0):
    if depth > 30:
        return "[nested too deep]"
    if isinstance(x, dict):
        return collections.OrderedDict((k, "[redacted]" if LLM_SECRET_KEY.search(str(k)) and x[k] not in (None, "", [], {})
                                        and not isinstance(x[k], bool) else llm_redact(x[k], depth + 1)) for k in x)
    if isinstance(x, list):
        return [llm_redact(v, depth + 1) for v in x]
    if isinstance(x, str):
        x = LLM_PEM.sub("[redacted PEM block]", x)
        x = LLM_HASH.sub("[redacted hash]", x)
        return LLM_BEARER.sub(r"\1 [redacted]", x)
    return x


def llm_trim(x, cap, depth=0):
    if isinstance(x, dict):
        return collections.OrderedDict((k, llm_trim(v, cap, depth + 1)) for k, v in x.items())
    if isinstance(x, list):
        out = [llm_trim(v, cap, depth + 1) for v in x[:cap]]
        if len(x) > cap:
            out.append({"_trimmed": "%d more item(s) not shown" % (len(x) - cap)})
        return out
    if isinstance(x, str) and len(x) > max(300, cap * 40):
        return x[:max(300, cap * 40)] + " …[_trimmed]"
    return x


def llm_series(name, vals):
    v = [float(x) for x in vals or [] if isinstance(x, (int, float))]
    if not v:
        return {"name": name, "points": 0}
    return {"name": name, "points": len(vals), "first": round(v[0], 2), "min": round(min(v), 2),
            "avg": round(sum(v) / len(v), 2), "max": round(max(v), 2), "last": round(v[-1], 2)}


def llm_view(r):
    """The parts of a result a model needs: verdict, summary, tiles, charts as statistics, top lists, data tables."""
    if not isinstance(r, dict):
        return {"output": r}
    out = collections.OrderedDict()
    for k in ("error", "request", "verdict", "summary"):
        if r.get(k):
            out[k] = r[k]
    if r.get("tiles"):
        out["tiles"] = [{"label": t.get("label"), "value": t.get("value"), "unit": "%" if t.get("fmt") == "pct" else "",
                         "detail": t.get("sub"), "state": t.get("kind") or "ok"} for t in r["tiles"] if isinstance(t, dict)]
    if "data" in r:   # the tables hold the answers: keep them ahead of the chart statistics
        out["data"] = r["data"]
    if r.get("charts"):
        out["charts"] = [{"title": c.get("title"), "from": (c.get("t") or [""])[0], "to": (c.get("t") or [""])[-1],
                          "series": [llm_series(s[0], s[1]) for s in c.get("series") or [] if len(s) > 1]}
                         for c in r["charts"] if isinstance(c, dict)]
    if r.get("heat"):
        out["per_core_load"] = [{"title": h.get("title"), "cores": [llm_series(n, v) for n, v in h.get("rows") or []]}
                                for h in r["heat"] if isinstance(h, dict)]
    if r.get("bars"):
        out["top_lists"] = [{"title": b.get("title"), "rows": b.get("rows")} for b in r["bars"] if isinstance(b, dict)]
    a = r.get("acc")
    if isinstance(a, dict):
        out["acc"] = {"tiles": [{"label": t.get("label"), "value": t.get("value")} for t in a.get("tiles") or []],
                      "filters": a.get("filters"),
                      "tabs": [{"tab": t.get("title"), "top_lists": [{"title": p.get("title"), "rows": p.get("rows")}
                                                                    for p in t.get("tops") or []]} for t in a.get("tabs") or []]}
    d = r.get("dashboard")
    if isinstance(d, dict):
        out["dashboard"] = {"tiles": [{"label": t.get("label"), "value": t.get("value"), "previous": t.get("prev")}
                                      for t in d.get("tiles") or []],
                            "requests": llm_series("requests", d.get("requests")),
                            "status": [llm_series(k, v) for k, v in d.get("status") or []],
                            "top_lists": [{"title": t, "rows": rows} for t, rows in d.get("tops") or []]}
    if "data" in out:
        out.move_to_end("data", last=False)
        for k in ("tiles", "summary", "verdict", "request", "error"):
            if k in out:
                out.move_to_end(k, last=False)
    return out


def llm_lists(x, path=(), out=None):
    """Every list in x with its path and JSON size."""
    out = [] if out is None else out
    if isinstance(x, dict):
        for k, v in x.items():
            llm_lists(v, path + (k,), out)
    elif isinstance(x, list):
        out.append((len(json.dumps(x, default=str)), path, x))
        for i, v in enumerate(x):
            llm_lists(v, path + (i,), out)
    return out


def llm_pack(r, budget):
    """Redacted, trimmed JSON of a result that fits `budget` characters. Returns (text, trimmed?)."""
    v = llm_redact(llm_view(r))
    full = json.dumps(v, default=str)
    if len(full) <= budget:
        return full, False
    # Halve the biggest list first (usually a per-minute timeline or a long log table), so short ranked lists
    # such as a top 10 stay complete; then shorten long strings; cutting the text is the last resort.
    v = json.loads(full, object_pairs_hook=collections.OrderedDict)
    size = len(full)
    for _ in range(400):
        if size <= budget:
            break
        cand = [c for c in llm_lists(v) if len([y for y in c[2] if not (isinstance(y, dict) and "_trimmed" in y)]) > 3]
        if not cand:
            break
        _, path, lst = max(cand, key=lambda c: c[0])
        real = [y for y in lst if not (isinstance(y, dict) and "_trimmed" in y)]
        total = real and next((int(y["_n"]) for y in lst if isinstance(y, dict) and "_n" in y), len(real))
        keep = max(3, len(real) // 2)
        lst[:] = real[:keep] + [{"_trimmed": "%d of %d item(s) not shown" % (total - keep, total), "_n": total}]
        size = len(json.dumps(v, default=str))
    t = json.dumps(v, default=str)
    if len(t) > budget:
        t = json.dumps(llm_trim(v, 10 ** 6), default=str)   # shorten very long strings
    if len(t) > budget:
        t = t[:budget] + " …[_trimmed]"
    return t, True


def llm_is_ollama():
    """Is the model server Ollama? (asked once per address)"""
    if LLM_CFG.get("_probe") != LLM_CFG["url"]:
        LLM_CFG["_probe"], LLM_CFG["_ollama"] = LLM_CFG["url"], False
        try:
            st, d = llm_http("GET", "/api/version", timeout=5, root=True)
            LLM_CFG["_ollama"] = st == 200 and isinstance(d, dict) and "version" in d
        except (urllib.error.URLError, OSError, ValueError):
            pass
    return LLM_CFG["_ollama"]


def llm_chat_ollama(messages, tools, est):
    """Ollama's own /api/chat: unlike its /v1 API it takes num_ctx, so the input is not cut to the default
    2k-4k token window (which made answers ignore the output)."""
    # A few fixed sizes: every change of num_ctx makes Ollama reload the model, which costs minutes on a laptop.
    ctx = next((c for c in (8192, 16384, 32768) if est + 2048 <= c), 32768)
    nm = []
    for m in messages:
        m = dict(m)
        if m.get("tool_calls"):
            calls = []
            for c in m["tool_calls"]:
                fn = c.get("function") or {}
                a = fn.get("arguments")
                try:
                    a = json.loads(a) if isinstance(a, str) else (a or {})
                except ValueError:
                    a = {}
                calls.append({"function": {"name": fn.get("name"), "arguments": a}})
            m["tool_calls"] = calls
        if m["role"] == "tool":
            m = {"role": "tool", "content": m["content"], "tool_name": m.get("name")}
        nm.append(m)
    body = {"model": LLM_CFG["model"], "messages": nm, "stream": True, "keep_alive": "30m",
            "options": {"num_ctx": ctx, "temperature": 0.2}}
    if tools:
        body["tools"] = tools
    st, d = llm_http("POST", "/api/chat", body, root=True, stream=True)
    if st >= 300 or not isinstance(d, dict) or not isinstance(d.get("message"), dict):
        err = (d or {}).get("error") if isinstance(d, dict) else d
        if tools and st in (400, 422, 500):
            raise ValueError("Ollama rejected tool calling for %s (HTTP %s: %s). Use a model that supports tools "
                             "(e.g. qwen2.5 / qwen3, llama3.1+, mistral-nemo) or ask without running checks."
                             % (LLM_CFG["model"], st, err))
        raise ValueError(llm_404(st, " (Ollama /api/chat)", d))
    msg = dict(d["message"])
    if msg.get("tool_calls"):
        msg["tool_calls"] = [{"id": "call_%d" % i, "type": "function",
                              "function": {"name": (c.get("function") or {}).get("name"),
                                           "arguments": json.dumps((c.get("function") or {}).get("arguments") or {})}}
                             for i, c in enumerate(msg["tool_calls"])]
    pt, ct = d.get("prompt_eval_count") or 0, d.get("eval_count") or 0
    return msg, {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct, "num_ctx": ctx, "_est": est}


def llm_text(msg):
    """The answer text of a reply: content as a string or as parts, without a reasoning model's <think> block
    (also one cut off before </think>, which holds no answer)."""
    c = msg.get("content")
    if isinstance(c, list):
        c = "".join(str(p.get("text") or "") for p in c if isinstance(p, dict))
    c = re.sub(r"(?s)<think>.*?</think>", "", str(c or ""))
    return re.sub(r"(?s)^\s*<think>.*", "", c).strip()


def llm_retry_msgs(messages):
    """For a second try after an empty answer: Qwen3's soft switch to answer without thinking first."""
    out = [dict(m) for m in messages]
    if "qwen3" in str(LLM_CFG["model"]).lower():
        for m in reversed(out):
            if m.get("role") == "user" and isinstance(m.get("content"), str):
                m["content"] += " /no_think"
                break
    return out


LLM_RETRY_TOKENS = 12000   # room for the second try: a reasoning model may need thousands of tokens before it answers


def llm_empty_note(usage):
    fin = usage.get("_finish") or "unknown"
    ct, pt = usage.get("completion_tokens"), usage.get("prompt_tokens")
    if ct and usage.get("_max") and ct >= usage["_max"] * 0.98:
        why = ("The model used its whole output allowance (%d tokens) on reasoning that the server does not send back "
               "(Qwen3 'thinking'), so no answer was left. Ask a narrower question, or ask the model server admin to "
               "turn thinking off for this model (enable_thinking: false) or raise its output token limit." % ct)
    elif fin == "length" or usage.get("_reasoning"):
        why = "It used its whole output allowance on reasoning before writing the answer."
    elif ct == 0:
        why = ("The server says the model generated 0 tokens: the request most likely did not reach the model as sent "
               "(prompt too long for the model's context, or filtered by the server / gateway).")
    elif ct:
        why = ("The server counted %s generated tokens but sent no text back: the gateway in front of the model "
               "(e.g. LiteLLM) may be dropping the reply. Open 'model reply (raw)' below to see what came back." % ct)
    else:
        why = "The server did not say how many tokens it generated."
    return ("(The model returned no answer text (finish reason: %s%s). %s Try again, ask a shorter question, or lower "
            "the context budget in the AI settings.)" % (fin, ", prompt tokens: %s" % pt if pt else "", why))


def llm_fallback(msg, usage):
    """After two empty answers: the model's reasoning if it wrote any (better than nothing), else an explanation."""
    r = msg.get("reasoning_content") or msg.get("reasoning") or ""
    if not r:
        c = msg.get("content")
        if isinstance(c, list):
            c = "".join(str(p.get("text") or "") for p in c if isinstance(p, dict))
        m = re.search(r"(?s)<think>(.*?)(</think>|$)", str(c or ""))
        r = m.group(1) if m else ""
    r = str(r).strip()
    if r:
        return ("**The model wrote no separate answer. This is its reasoning, which may contain the answer:**\n\n"
                + (r if len(r) <= 8000 else r[:8000] + " …"))
    return llm_empty_note(usage)


def llm_chat(messages, tools=None, max_tokens=None):
    est = (sum(len(json.dumps(m, default=str)) for m in messages) + (len(json.dumps(tools)) if tools else 0)) // 3
    if llm_is_ollama():
        return llm_chat_ollama(messages, tools, est)
    body = {"model": LLM_CFG["model"], "messages": messages, "temperature": 0.2, "stream": False}
    if max_tokens:
        body["max_tokens"] = max_tokens
    if tools:
        body["tools"], body["tool_choice"] = tools, "auto"
    # Qwen3 thinks before it answers, and some servers drop the thinking from the reply, so a long think can leave no
    # answer at all. Switch thinking off the way vLLM-style servers understand; if the server rejects the extra field,
    # send without it from then on (remembered per model address and model).
    who = (LLM_CFG["url"], LLM_CFG["model"])
    extra = "qwen3" in str(LLM_CFG["model"]).lower() and LLM_CFG.get("_no_extra") != who
    if extra:
        body["chat_template_kwargs"] = {"enable_thinking": False}
    st, d = llm_http("POST", "/chat/completions", body, timeout=LLM_WAIT)
    if extra and st in (400, 422):
        LLM_CFG["_no_extra"] = who
        body.pop("chat_template_kwargs", None)
        st, d = llm_http("POST", "/chat/completions", body, timeout=LLM_WAIT)
    if st >= 300 or not isinstance(d, dict) or not d.get("choices"):
        err = (d or {}).get("error") if isinstance(d, dict) else d
        if tools and st in (400, 422, 500):
            raise ValueError("the model server rejected tool calling (HTTP %s: %s). Use a model that supports tools "
                             "(e.g. qwen2.5 / qwen3, llama3.1+, mistral-nemo) or ask without running checks." % (st, err))
        raise ValueError(llm_404(st, "/chat/completions", d))
    ch = d["choices"][0]
    msg = ch.get("message") or {}
    return msg, dict(d.get("usage") or {}, _est=est, _finish=ch.get("finish_reason") or "",
                     _reasoning=bool(msg.get("reasoning_content") or msg.get("reasoning")),
                     _raw=json.dumps(ch, default=str, ensure_ascii=False)[:6000], _max=max_tokens or 0)


# Agent tools: only the console's own read-only lookups, on every connected device (tool names start with the vendor:
# pa_, fg_, f5_, cf_; a 'device' field picks one when several of a vendor are connected). Active tools (tcpdump,
# file download, backups, packet capture, F5 shell) are never offered.
LLM_PFX = {"paloalto": "pa", "fortigate": "fg", "f5": "f5", "cloudflare": "cf"}
LLM_VNAME = {"paloalto": "Palo Alto", "fortigate": "FortiGate", "f5": "F5 BIG-IP", "cloudflare": "Cloudflare"}


def llm_devices():
    """Connected devices for the agent: {label: (sid, sess)}; label = device name (address added if names repeat)."""
    with LOCK:
        items = sorted(SESSIONS.items(), key=lambda x: (x[1]["vendor"], str(x[1].get("name") or x[1]["host"])))
    names = [str(s.get("name") or s["host"]) for _, s in items]
    return {(nm if names.count(nm) == 1 else "%s (%s)" % (nm, s["host"])): (k, s) for (k, s), nm in zip(items, names)}


def llm_tools():
    devs, tools = llm_devices(), []

    def tool(name, desc, props, req=()):
        tools.append({"type": "function", "function": {"name": name, "description": desc, "parameters": {
            "type": "object", "properties": props, "required": list(req)}}})
    S = lambda d, **k: dict({"type": "string", "description": d}, **k)
    if not devs:
        return tools
    conn = ["%s (%s)" % (l, s["vendor"]) for l, (_, s) in devs.items()]
    tool("flow_trace", "Follow ONE flow hop by hop through the connected devices it actually crosses (%s), found from "
         "their routes, VIPs and virtual servers; devices not on the path are only listed. Checks Cloudflare DNS + WAF "
         "events, FortiGate policy + VIP mapping, F5 virtual server / pool "
         "members / SNAT (+ WAF log), Palo Alto policy for F5 SNAT -> pool member (+ traffic logs); a public IP that "
         "is 1:1 NAT'ed to a private IP before the FortiGate is followed (upstream NAT list, or inferred). Use it first for "
         "internet-facing flows: a public client IP or a published hostname ('can client X reach shop.example.com', "
         "'why is X blocked on our site'), and for internal flows when the user wants the path. Returns one row per "
         "device and check, and where it stops. For a plain rule check between two internal addresses on every "
         "firewall, use policy_check." % "; ".join(conn),
         {"src": S("client / source IP (needed for firewall verdicts and WAF logs)"),
          "dst": S("destination IP or hostname, e.g. shop.example.com"), "port": S("destination port, e.g. 443"),
          "proto": S("tcp, udp or icmp (default tcp)"), "logs": {"type": "boolean", "description": "also search the F5 WAF "
                                                                 "log and firewall traffic logs (slower)"},
          "within": S("time range for events and logs", enum=list(FLOW_PAN_PERIOD))}, ["dst"])
    fws = [l for l, (_, s) in devs.items() if s["vendor"] in ("paloalto", "fortigate")]
    if fws:
        tool("policy_check", "Ask every connected firewall (%s) which security rule / policy matches the flow src -> "
             "dst:port and whether it allows or blocks it (PAN-OS 'test security-policy-match', FortiGate policy lookup). "
             "Use it for 'can A reach B', 'is there a rule that allows A to B', 'is A blocked to B' between two IP "
             "addresses, e.g. internal ones." % ", ".join(fws),
             {"src": S("source IP"), "dst": S("destination IP"), "port": S("destination port (if the user gave none, "
                                                                          "leave it empty and say so)"),
              "proto": S("tcp, udp or icmp (default tcp)"),
              "device": S("only this firewall; empty = all connected firewalls", enum=fws)}, ["src", "dst"])
    for v in ("paloalto", "fortigate", "f5", "cloudflare"):
        labels = [l for l, (_, s) in devs.items() if s["vendor"] == v]
        if not labels:
            continue
        p, vn = LLM_PFX[v], LLM_VNAME[v]
        D = {"device": S("which %s (default: %s)" % (vn, labels[0]), enum=labels)}

        def vt(name, desc, props, req=()):
            tool(p + "_" + name, "%s (%s): %s" % (vn, ", ".join(labels), desc), dict(D, **props), req)
        cat = CATALOG[v]
        vt("run_check", "run one read-only check from the console catalog. Checks: %s" % "; ".join(
            "%s = %s%s" % (c["id"], c["label"], " (params: %s)" % ", ".join(
                x["name"] + ("" if x.get("required", True) else "?") for x in c.get("params", [])) if c.get("params") else "")
            for c in cat), {"check": S("check id", enum=[c["id"] for c in cat]),
                            "params": {"type": "object", "description": "parameters of the check by name"}}, ["check"])
        if v in ("paloalto", "fortigate"):
            vt("ip_lookup", "rules / objects that reference an IP or a subnet (CIDR, e.g. 10.1.2.32/28: anything that "
               "overlaps it); with 'peer' (single IPs only, plus port / protocol) the policy verdict on this firewall "
               "for the flow ip -> peer.",
               {"ip": S("source IP, or the IP / CIDR subnet to look up"), "peer": S("destination IP (optional)"),
                "port": S("destination port"), "proto": S("tcp, udp, icmp or a protocol number"),
                "from_zone": S("PAN-OS source zone"), "to_zone": S("PAN-OS destination zone"),
                "ingress_interface": S("FortiGate ingress interface (optional: taken from the route to the source IP)")},
               ["ip"])
            vt("policy_by_name", "find a security rule / policy by name (or FortiGate policy ID): position, action, "
               "objects resolved, profiles, hit count.", {"name": S("rule name, part of it, or policy ID")}, ["name"])
            vt("log_search", "search the firewall logs for an IP (source or destination).",
               dict({"ip": S("IP address"), "dest_ip": S("destination IP (optional)"),
                     "blocked_only": {"type": "boolean"}, "count": S("max rows, default 50")},
                    **({"log_type": S("threat, url or traffic", enum=list(PAN_LOG_TYPES)),
                        "period": S("time range", enum=list(PAN_LOG_PERIODS))} if v == "paloalto" else {})), ["ip"])
            vt("acc", "Application Command Center summary from the logs: top applications, sources, destinations, "
               "threats, blocked traffic and URLs, optionally filtered.",
               {"period": S("time range", enum=list(ACC_PERIODS)),
                "filters": {"type": "object", "description": "optional: src, dst, app, user, rule, from_zone, to_zone, port"}})
        if v == "f5":
            vt("ip_lookup", "where an IP appears on the BIG-IP: pools, nodes, virtual servers, data groups, policies.",
               {"ip": S("IP address")}, ["ip"])
            vt("hostname_lookup", "which virtual servers / policies / iRules handle a hostname.",
               {"hostname": S("host name")}, ["hostname"])
            vt("waf_log_search", "search the ASM / WAF request log by client IP, support ID, hostname, URL or status.",
               {"ip": S("client IP"), "support_id": S("ASM support ID"), "hostname": S("host"), "url": S("URL path"),
                "status": S("request status, e.g. blocked"), "within": S("time range", enum=[k for k in LOOKBACK])})
        if v == "cloudflare":
            vt("lookup", "lookups over all zones the token sees. modes: ip {ip}, host {host, days}, ray {ray}, "
               "whois {ip | host}, events {ip, host, path, ray, action, top}, event_top {by: action|source|rule|ip|host|"
               "path|country|asn, top}, traffic {host, ip, path, status, by, top}, rules {q}, dns {name, content, type}, "
               "posture {}.",
               {"mode": S("lookup", enum=["ip", "host", "ray", "whois", "events", "event_top", "traffic", "rules", "dns",
                                          "posture"]),
                "args": {"type": "object", "description": "arguments of the mode"}}, ["mode"])
    return tools


def llm_run_tool(name, a):
    """Run one agent tool -> result dict. Each call is written to the audit log of the device(s) it reads."""
    a = a if isinstance(a, dict) else {}
    s = lambda k: str(a.get(k) or "").strip()
    devs = llm_devices()
    if name in ("flow_trace", "policy_check"):
        for _, d in devs.values():
            audit(d, "LLM agent ran " + llm_label(name, a))
        if name == "flow_trace":
            return do_flow_trace_api({"src": s("src"), "dst": s("dst"), "port": s("port"), "proto": s("proto"),
                                      "logs": a.get("logs") is True, "within": s("within") or "last 24 hours"})
        return do_policy_check_all({"src": s("src"), "dst": s("dst"), "port": s("port"), "proto": s("proto"),
                                    "device": s("device")})
    pfx, _, name = name.partition("_")
    v = {x: k for k, x in LLM_PFX.items()}.get(pfx)
    mine = [(l, ks) for l, ks in devs.items() if ks[1]["vendor"] == v] if v else []
    if not mine:
        return {"ok": False, "error": "tool %s_%s: no such device type is connected" % (pfx, name)}
    want = s("device")
    pick = ([ks for l, ks in mine if l == want] or [ks for l, ks in mine if want.lower() in l.lower()]) if want else [mine[0][1]]
    if not pick:
        return {"ok": False, "error": "no connected %s named '%s'; connected: %s" % (LLM_VNAME[v], want,
                                                                                      ", ".join(l for l, _ in mine))}
    sid, sess = pick[0]
    audit(sess, "LLM agent ran %s_%s" % (pfx, llm_label(name, a)))
    if name == "run_check":
        return do_run({"id": sid, "check": s("check"), "params": a.get("params") if isinstance(a.get("params"), dict) else {}})
    if name == "ip_lookup":
        if v == "f5":
            return do_ipcheck({"id": sid, "ip": s("ip")})
        return do_ipcheck({"id": sid, "ip": s("ip"), "mode": "verdict" if s("peer") else "refs", "peer": s("peer"),
                           "role": "source", "port": s("port"), "proto": s("proto"), "from": s("from_zone"),
                           "to": s("to_zone"), "srcintf": s("ingress_interface")})
    if name == "policy_by_name" and v in ("paloalto", "fortigate"):
        return do_policy_search({"id": sid, "name": s("name")})
    if name == "log_search" and v in ("paloalto", "fortigate"):
        b = {"id": sid, "ip": s("ip"), "dest_ip": s("dest_ip"), "count": s("count") or "50", "blocked": bool(a.get("blocked_only"))}
        if v == "paloalto":
            b.update(log_type=s("log_type") or "traffic", period=s("period") or "last-24-hrs")
            return do_pan_logs(b)
        return fg_auto_logs(do_fg_logs, b)
    if name == "acc" and v in ("paloalto", "fortigate"):
        f = a.get("filters") if isinstance(a.get("filters"), dict) else {}
        b = {"id": sid, "period": s("period") or "last-hour", "sort": "bytes", "scan": "5000",
             "filters": {k: str(x) for k, x in f.items() if x not in (None, "")}}
        return fg_auto_logs(do_acc, b) if v == "fortigate" else do_acc(b)
    if name == "hostname_lookup" and v == "f5":
        return do_f5_host({"id": sid, "hostname": s("hostname")})
    if name == "waf_log_search" and v == "f5":
        return do_f5_asm({"id": sid, "mode": "supportid" if s("support_id") else "search", "support_id": s("support_id"),
                          "ip": s("ip"), "hostname": s("hostname"), "url": s("url"), "status": s("status"),
                          "within": s("within") or "last 24 hours", "top": "50"})
    if name == "lookup" and v == "cloudflare":
        args = a.get("args") if isinstance(a.get("args"), dict) else {}
        return do_cf(dict({k: str(x) for k, x in args.items()}, id=sid, mode=s("mode")))
    return {"ok": False, "error": "tool %s_%s is not available" % (pfx, name)}


def do_policy_check_all(b):
    """Policy verdict for src -> dst:port on every connected firewall (or the one named), in parallel."""
    src, dst = str(parse_ip(b.get("src"), "Source IP")), str(parse_ip(b.get("dst"), "Destination IP"))
    port = str(num(b.get("port"), 1, 65535, None, "port")) if str(b.get("port") or "").strip() else ""
    proto = pstr(b.get("proto"), "protocol").lower() or "tcp"
    want = str(b.get("device") or "").strip().lower()
    with LOCK:
        fws = [(k, s) for k, s in SESSIONS.items() if s["vendor"] in ("paloalto", "fortigate")]
    if want:
        fws = [(k, s) for k, s in fws if want in str(s.get("name") or "").lower() or want == s["host"].lower()]
    if not fws:
        raise ValueError("no connected firewall%s: connect the Palo Alto / FortiGate first" % (" matches '%s'" % want if want else ""))

    def one(x):
        k, s = x
        nm = "%s (%s)" % (s.get("name") or s["host"], s["vendor"])
        try:
            r = do_ipcheck({"id": k, "ip": src, "peer": dst, "mode": "verdict", "role": "source", "port": port, "proto": proto})
        except (urllib.error.URLError, OSError, ValueError) as e:
            r = {"ok": False, "error": str(getattr(e, "reason", e))}
        except Exception as e:
            r = {"ok": False, "error": "unexpected reply: %s: %s" % (type(e).__name__, e)}
        vd = r.get("verdict") if isinstance(r.get("verdict"), dict) else {}
        return {"device": nm, "verdict": vd.get("label") or ("NOT CHECKED: " + str(r.get("error") or "no answer")),
                "kind": vd.get("kind") or "warn", "summary": list(r.get("summary") or []),
                "notes": list((r.get("data") or {}).get("notes") or []),
                "flow_test": (r.get("data") or {}).get("flow_test")}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(fws))) as ex:
        rows = list(ex.map(one, fws))
    flow = "%s -> %s%s/%s" % (src, dst, ":" + port if port else "", proto)
    bad = [r for r in rows if r["kind"] == "bad"]
    unk = [r for r in rows if r["kind"] not in ("ok", "bad")]
    verdict = ({"label": "BLOCKED on %s" % ", ".join(r["device"] for r in bad), "kind": "bad"} if bad else
               {"label": "NOT CONCLUSIVE on %s" % ", ".join(r["device"] for r in unk), "kind": "warn"} if unk else
               {"label": "ALLOWED on %d firewall(s)" % len(rows), "kind": "ok"})
    return {"ok": True, "status": 200, "request": "policy check " + flow, "verdict": verdict,
            "summary": ["%s: %s" % (r["device"], r["verdict"]) for r in rows] +
                       ([] if port else ["No port given: checked without a port, so a port-specific rule may not match."]) +
                       ["Each firewall is checked on its own policy only; whether the traffic actually passes through it "
                        "(routing) is not checked."],
            "data": {"firewalls": rows}}


def llm_label(name, a):
    a = a if isinstance(a, dict) else {}
    bits = ["%s=%s" % (k, json.dumps(x) if isinstance(x, (dict, list)) else x) for k, x in a.items() if x not in (None, "", {}, [])]
    return "%s(%s)" % (name, ", ".join(bits))[:300]


def do_llm_config(b):
    if b.get("set"):
        url = llm_url_ok(b.get("url") or LLM_CFG["url"])
        model = str(b.get("model") or "").strip()
        if model and not re.match(r"^[\w.:/@+-]{1,128}$", model):
            raise ValueError("invalid model name")
        LLM_CFG.update(url=url, model=model,
                       budget=num(b.get("budget"), 4000, 400000, 24000, "context budget"))
        if b.get("key") is not None and str(b.get("key")) != "":
            LLM_CFG["key"] = str(b["key"]).strip()
        if b.get("clear_key"):
            LLM_CFG["key"] = ""
    return {"ok": True, "url": LLM_CFG["url"], "model": LLM_CFG["model"], "route": llm_route(), "approved": list(LLM_APPROVED),
            "budget": LLM_CFG["budget"], "has_key": bool(LLM_CFG["key"])}


def do_llm_models(b):
    st, d = llm_http("GET", "/models", timeout=15)
    if st == 404 and not LLM_CFG["url"].endswith("/v1"):   # address entered without /v1
        old = LLM_CFG["url"]
        LLM_CFG["url"] = old + "/v1"
        st, d = llm_http("GET", "/models", timeout=15)
        if st == 404:
            st2, _ = llm_http("GET", "/api/tags", timeout=15, root=True)
            if st2 >= 300:
                LLM_CFG["url"] = old
    if st == 404:   # older Ollama has /v1/chat/completions but not /v1/models: use its own model list
        st2, d2 = llm_http("GET", "/api/tags", timeout=15, root=True)
        if st2 < 300 and isinstance(d2, dict):
            return {"ok": True, "url": LLM_CFG["url"], "models": sorted(str(m.get("name")) for m in d2.get("models") or []
                                                                        if isinstance(m, dict) and m.get("name"))}
    if st >= 300:
        raise ValueError(llm_404(st, "/models", d))
    ids = sorted(str(m.get("id")) for m in (d.get("data") or []) if isinstance(m, dict) and m.get("id"))
    return {"ok": True, "url": LLM_CFG["url"], "models": ids}


def llm_404(st, path, d):
    err = (d or {}).get("error") if isinstance(d, dict) else d
    if st == 404 and path != "/models":
        return ("%s%s was not found (HTTP 404). The address must be the base of an OpenAI-compatible API, ending in /v1 "
                "(Ollama: http://127.0.0.1:11434/v1, LM Studio: http://127.0.0.1:1234/v1); for Ollama, check the model name "
                "with 'ollama list' and update Ollama if it is old. Server said: %s" % (LLM_CFG["url"], path, err))
    if st == 404 and path == "/models":
        return ("%s does not list its models (HTTP 404). Type the model name in Model (e.g. oci/Qwen3-8-27B) and Save."
                % LLM_CFG["url"])
    if st in (401, 403):
        return ("the model server refused the access token (HTTP %s). Paste a valid token in API key and Save. "
                "Server said: %s" % (st, err))
    return "model server answered HTTP %s: %s" % (st, err)


LLM_NAME_TOKEN = re.compile(r"[A-Za-z0-9](?:[\w.:/@-]|,(?=\d{3}))*[\w]")   # 5,000 stays one token
LLM_IP_TOKEN = re.compile(r"\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?(:\d{1,5})?")


def llm_unseen_names(answer, corpus):
    """Names / IPs the answer states that appear nowhere in what the model was given (a sign it invented them).
    Checked: `code` spans and **bold** values without spaces, and any token that holds a digit or '_' (rule names,
    IPs, virtual servers like vs_web01). Plain words are not checked, so ordinary prose is never flagged."""
    low = corpus.lower()
    cands = set(re.findall(r"`([^`\s]{3,80})`", answer)) | set(re.findall(r"\*\*([^*\s:]{3,80})\*\*", answer))
    cands |= {t for t in LLM_NAME_TOKEN.findall(re.sub(r"`[^`]*`", " ", answer)) if re.search(r"[\d_]", t) and len(t) >= 4}
    out = []
    for c in sorted(cands):
        c = c.strip(".,;:()[]'\"")
        if not re.search(r"[\d_./:-]", c):
            continue   # a plain word (a heading such as **Conclusion**, or `tmsh`) is not a device name
        if not LLM_IP_TOKEN.fullmatch(c) and re.fullmatch(r"[\d.,%/:-]+(-?[a-z]+)?", c, re.I):
            continue   # numbers, sizes, durations, '5,000-entry', '24-hour': often computed, not copied (IPs are checked)
        if len(c) < 3:
            continue
        if c.lower() not in low and c.lower().replace("\\", "") not in low:
            out.append(c)
    return out[:8]


def do_llm_chat(b):
    t0 = time.time()
    if not LLM_CFG["model"]:
        raise ValueError("pick a model first (List models, then Save)")
    mode = b.get("mode") or "chat"
    if mode not in ("explain", "chat", "agent"):
        raise ValueError("invalid mode")
    sid = b.get("id")
    sess = SESSIONS.get(sid)
    budget = LLM_CFG["budget"]
    sysmsg = LLM_SYSTEM
    if sess:
        sysmsg += "\nSelected device: %s (%s, %s)." % (sess.get("name") or sess["host"], sess["vendor"], sess["host"])
    alldev = llm_devices()
    if alldev:
        sysmsg += "\nConnected devices: %s." % "; ".join("%s (%s, %s)" % (l, d["vendor"], d["host"])
                                                         for l, (_, d) in alldev.items())
    msgs, trimmed, sent = [{"role": "system", "content": sysmsg}], False, ""
    ctx = b.get("context")
    if isinstance(ctx, dict) and (ctx.get("data") is not None or ctx.get("summary") or ctx.get("error")):
        txt, trimmed = llm_pack(ctx, budget if mode != "agent" else budget // 2)
        sent = txt
        odev = str(b.get("device") or "")[:100]
        sname = (sess.get("name") or sess["host"]) if sess else ""
        other = (" NOTE: this output is from %s, not from the selected device %s; say so if it matters." % (odev, sname)
                 if odev and sname and odev != sname else "")
        msgs.append({"role": "user", "content": "Current console output: %s%s (run %s).%s\n```json\n%s\n```" % (
            str(b.get("label") or "check")[:200], (" from device %s" % odev) if odev else "", str(b.get("time") or "")[:40],
            other, txt)})
        msgs.append({"role": "assistant", "content": "I have the output and will answer from it."})
    hist = [m for m in (b.get("history") or []) if isinstance(m, dict) and m.get("role") in ("user", "assistant")][-12:]
    msgs += [{"role": m["role"], "content": str(m.get("content") or "")[:8000]} for m in hist]
    q = str(b.get("question") or "").strip()[:4000]
    if mode == "explain" and not q:
        q = ("Explain this output for a network / security engineer: what it shows, what is wrong or unusual (with the "
             "values), the likely cause, and the next checks to run in this console.")
    if not q:
        raise ValueError("type a question")
    msgs.append({"role": "user", "content": q})
    steps, usage, seen_txt = [], {}, []
    for _, d in (alldev.values() if mode == "agent" else ([(sid, sess)] if sess else [])):
        audit(d, "LLM %s (%s): %s" % (mode, LLM_CFG["model"], q[:200]))
    if mode != "agent":
        msgs[0]["content"] += ("\nAnswer only from the console output and the conversation. If they do not contain what is "
                               "needed (e.g. a question about a rule, flow or log that is not in the output), say so in one "
                               "sentence and suggest the 'Ask & run checks' button, which can query the device.")
        msg, usage = llm_chat(msgs)
        answer = llm_text(msg)
        if not answer:   # e.g. a reasoning model spent its output on thinking: once more, with room and no thinking
            msg, usage = llm_chat(llm_retry_msgs(msgs), max_tokens=LLM_RETRY_TOKENS)
            answer = llm_text(msg) or llm_fallback(msg, usage)
    else:
        if not alldev:
            raise ValueError("connect a device first: the model runs its checks on the connected devices")
        tools, answer, seen = llm_tools(), "", set()
        msgs[0]["content"] += ("\nYou can run read-only checks on ALL the connected devices listed above with the tools, "
                               "whichever device is selected. Tool names start with the device type: pa_ = Palo Alto, "
                               "fg_ = FortiGate, f5_ = F5 BIG-IP, cf_ = Cloudflare; pick the device with the 'device' "
                               "field when several of a type are connected. Decide which devices and checks the question "
                               "needs, combine them across devices when needed (e.g. Cloudflare event -> F5 WAF log -> "
                               "firewall log for the same IP), and run only what you need (at most 8 calls; several "
                               "independent calls may be made at once). Never repeat a call with the same arguments. "
                               "For 'can A reach B' / 'is there a rule allowing A to B' between two IP addresses (e.g. "
                               "internal ones), call policy_check: it asks every connected firewall. For an internet "
                               "client or a published hostname, call flow_trace (Cloudflare -> FortiGate -> F5 -> Palo "
                               "Alto). For 'top / most / highest' questions use a check that ranks (e.g. f5_run_check "
                               "vstop); ACC and log searches read a sample of recent log entries; for traffic volume or "
                               "totals over hours or days on Palo Alto use pa_run_check apptraffic (whole period). If no "
                               "result holds what was asked, say so. The console output shown above may be about "
                               "something else: if it does not answer the question, run checks instead of saying the "
                               "data is missing. Answer from the results, per device with the rule / object names, and "
                               "say which checks you ran. Nothing can be changed on any device.")
        for rnd in range(9):
            msg, usage = llm_chat(msgs, tools if rnd < 8 else None)
            calls = msg.get("tool_calls") or []
            if not calls:
                answer = llm_text(msg)
                if not answer:   # same as above: one more try for the final answer, without tools
                    msg, usage = llm_chat(llm_retry_msgs(msgs), max_tokens=LLM_RETRY_TOKENS)
                    answer = llm_text(msg) or llm_fallback(msg, usage)
                break
            msgs.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
            for c in calls[:4]:
                fn = c.get("function") or {}
                name, raw = str(fn.get("name") or ""), fn.get("arguments")
                try:
                    args = json.loads(raw) if isinstance(raw, str) else (raw or {})
                except ValueError:
                    args = {}
                key = name + json.dumps(args, sort_keys=True, default=str)
                if key in seen or len(steps) >= 8:
                    res = {"ok": False, "error": "not run: repeated call or the 8-check limit was reached"}
                else:
                    seen.add(key)
                    try:
                        res = llm_run_tool(name, args)
                    except ValueError as e:
                        res = {"ok": False, "error": str(e)}
                    except (urllib.error.URLError, OSError) as e:
                        res = {"ok": False, "error": "request failed: %s" % getattr(e, "reason", e)}
                    steps.append({"call": llm_label(name, args), "ok": bool(res.get("ok")),
                                  "verdict": (res.get("verdict") or {}).get("label", "") if isinstance(res.get("verdict"), dict) else "",
                                  "error": res.get("error", ""),
                                  "result": res if len(json.dumps(res, default=str)) < 3000000 else None})
                txt, tr = llm_pack(res, max(3000, budget // 4))
                seen_txt.append(txt)
                trimmed = trimmed or tr
                msgs.append({"role": "tool", "tool_call_id": c.get("id") or name, "name": name, "content": txt})
        if not answer:
            answer = "(The model stopped without a final answer.)"
    answer = llm_text({"content": answer}) or answer
    warn = ""
    pt, est = usage.get("prompt_tokens") or 0, usage.pop("_est", 0)
    usage.pop("_finish", None)
    usage.pop("_reasoning", None)
    raw_reply = usage.pop("_raw", "")
    usage.pop("_max", None)
    if pt and est and pt < est * 0.5 and not usage.get("num_ctx"):
        warn = ("The model server read only about %d of the roughly %d tokens sent: its context window is too small, so "
                "the answer may not be based on the output. Raise the model's context length (LM Studio: Context "
                "Length in the model settings; llama.cpp: -c) or lower the context budget here." % (pt, est))
    corpus = "\n".join([m.get("content") or "" for m in msgs if isinstance(m.get("content"), str)] + seen_txt +
                        [json.dumps(t, default=str) for t in (llm_tools() if mode == "agent" else [])])
    unseen = llm_unseen_names(answer, corpus)
    if unseen:
        warn = ((warn + " ") if warn else "") + (
            "Not found in the data the model was given: %s. The model may have made these up, so do not rely on them; "
            "check the output panel or run the check yourself." % ", ".join(unseen))
    return {"ok": True, "status": 200, "ms": int((time.time() - t0) * 1000), "answer": answer, "steps": steps,
            "model": LLM_CFG["model"], "trimmed": trimmed, "usage": usage, "warning": warn, "sent": sent,
            "unseen": unseen,
            # what the server sent back, when it held no usable answer (to see why)
            "raw": raw_reply if answer.startswith(("(The model returned no answer", "**The model wrote no separate")) else ""}


def llm_wrap(fn):
    def run(b):
        try:
            return fn(b)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        except (urllib.error.URLError, OSError) as e:
            if isinstance(e, socket.timeout) or isinstance(getattr(e, "reason", None), socket.timeout):
                return {"ok": False, "error": "the model server is running but %s sent nothing for %d s, so the request was "
                        "stopped. The model is too slow on this PC: run 'ollama ps' (100%% CPU means no GPU is used), "
                        "try a smaller model such as qwen2.5:7b, or lower the context budget in Model settings."
                        % (LLM_CFG["model"] or "the model", LLM_WAIT)}
            return {"ok": False, "error": "cannot reach the model server at %s: %s. Is it running (e.g. 'ollama serve')?"
                                          % (LLM_CFG["url"], getattr(e, "reason", e))}
    return run


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

    def _serve_brand(self):
        """Optional organisation logo for the header: brand_logo.svg or brand_logo.png next to this
        script (git-ignored, so an organisation's logo is never published with the tool)."""
        for name, ctype in BRAND_FILES:
            path = os.path.join(BRAND_DIR, name)
            try:
                if not os.path.isfile(path) or os.path.getsize(path) > 1024 * 1024:
                    continue
                with open(path, "rb") as f:
                    data = f.read()
            except OSError:
                continue
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(data)
            return
        self._send(404, {"error": "no brand logo"})

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
        if u.path == "/brand-logo":
            if not tok_ok(urllib.parse.parse_qs(u.query).get("t", [""])[0]):
                return self._send(403, {"error": "bad token"})
            return self._serve_brand()
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
        if u.path == "/api/monitor":
            return self._send(200, do_monitor_get(u.query))
        if u.path == "/api/devices":   # the sessions this console holds, so a reloaded page shows them again
            return self._send(200, devices_public())
        if u.path == "/api/version":
            return self._send(200, {"gen": HOT["gen"], "page": HOT["page"], "error": HOT["error"], "time": HOT["time"]})
        if u.path == "/api/audit":
            with LOCK:
                return self._send(200, list(AUDIT)[-200:])
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok() or not self._tok_ok():
            return self._send(403, {"error": "forbidden"})
        if self.path == "/api/pcap":   # raw capture file in the body (kept in memory only)
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = 0
            if n <= 0:
                return self._send(200, {"ok": False, "error": "the file is empty"})
            if n > PCAP_MAX:
                self.close_connection = True
                return self._send(200, {"ok": False, "error": "the file is %.1f MB; the limit is %d MB. Cut it down first "
                                        "(e.g. Wireshark: File > Export Specified Packets, or editcap -r)"
                                        % (n / 1048576, PCAP_MAX // 1048576)})
            raw = self.rfile.read(n)
            try:
                result = do_pcap_upload(raw, self.headers.get("X-Filename", ""))
            except Exception as e:  # noqa: BLE001 - a malformed capture must not break the console
                result = {"ok": False, "error": "could not analyse the capture: %s: %s" % (type(e).__name__, e)}
            return self._send(200, result)
        try:
            n = int(self.headers.get("Content-Length", "0"))
            lim = 20_000_000 if self.path == "/api/llm/chat" else 1_000_000   # the chat carries the current output
            body = json.loads(self.rfile.read(max(0, min(n, lim))) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        if not isinstance(body, dict):
            return self._send(400, {"error": "body must be a JSON object"})
        routes = {"/api/connect": do_connect, "/api/run": do_run, "/api/ssh": do_ssh, "/api/term/open": do_term_open, "/api/term/read": do_term_read,
                  "/api/term/write": do_term_write, "/api/term/resize": do_term_resize, "/api/term/close": do_term_close,
                  "/api/raw": do_raw, "/api/disconnect": do_disconnect, "/api/vault": do_vault,
                  "/api/ipcheck": do_ipcheck, "/api/flowtrace": do_flow_trace_api, "/api/natmap": do_nat_map, "/api/vipmap": do_vip_map, "/api/f5host": do_f5_host, "/api/f5logs": do_f5_logs,
                  "/api/f5capture": do_f5_capture, "/api/f5file": do_f5_file, "/api/policy": do_policy_search, "/api/profile/save": do_profile_save,
                  "/api/profile/delete": do_profile_delete, 
                  "/api/appsec": do_appsec, "/api/f5asm": do_f5_asm, "/api/panlogs": do_pan_logs,
                  "/api/fglogs": do_fg_logs, "/api/adminaudit": do_admin_audit, "/api/f5sync": do_f5_sync, "/api/pancapture": do_pan_capture,
                  "/api/backup": do_backup, "/api/cf": do_cf, "/api/acc": do_acc,
                  "/api/monitor": do_monitor_set, "/api/llm/config": llm_wrap(do_llm_config), "/api/llm/models": llm_wrap(do_llm_models),
                  "/api/llm/chat": llm_wrap(do_llm_chat)}
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
--mint:#2EE6C5;--coral:#FF7A59;--violet:#7C6CFF;--ok:var(--mint);--bad:var(--coral)}
*{box-sizing:border-box}
.fdwrap{margin:0 0 16px;padding:10px 10px 8px;border:1px solid var(--line);border-radius:14px;overflow-x:auto;
background:radial-gradient(700px 220px at 85% 110%,#7C6CFF14,transparent),var(--panel2)}
.fdsvg{width:100%;height:auto;display:block}.fdbase{fill:none;stroke:#2a2850;stroke-width:2}
.fdflow{fill:none;stroke-width:2.4;stroke-linecap:round;stroke-dasharray:4 14;animation:fdmove 1.1s linear infinite;opacity:.95}
@keyframes fdmove{to{stroke-dashoffset:-18}}@media (prefers-reduced-motion:reduce){.fdflow{animation:none;stroke-dasharray:none;opacity:.6}}
.fdcard{fill:#1b1a38;stroke-width:1.2}.fdcard.nc{stroke-dasharray:4 4;fill:#16152e}.fdic{fill:#0B0A17;stroke-width:1.2}
.fdglyph{fill:none;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
.fdt{fill:#e9e8ff;font:600 13.5px 'Segoe UI',system-ui,sans-serif}.fdr{fill:#8f8cb8;font:600 9px 'Segoe UI',system-ui,sans-serif;letter-spacing:.08em;text-transform:uppercase}.fds{fill:#8f8cb8;font:11px 'Segoe UI',system-ui,sans-serif}
.fdpill{font:600 9.5px 'Segoe UI',system-ui,sans-serif;letter-spacing:.04em;text-transform:uppercase}
.fdlab{fill:#b9b6e6;font:10.5px Consolas,'Cascadia Mono',monospace}
.fdnode.dim{opacity:.38}.fdnode{cursor:default}
.fdleg{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12px;color:var(--dim);padding:4px 6px 0}
.fdleg i{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:0}
.termcard{padding:12px 14px}.termcard .thd{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.termcard .thd b{font-size:14px}.termcard .thd .st{flex:1;font-size:12px;color:var(--dim)}
.term{background:#0a0a12;color:#d6d6e6;font:13px/1.25 Consolas,'Cascadia Mono','Courier New',monospace;
border:1px solid var(--line);border-radius:8px;padding:6px 8px;overflow-y:auto;overflow-x:hidden;white-space:pre;outline:none;cursor:text}
.term:focus{border-color:var(--mint);box-shadow:0 0 0 1px #2EE6C555}.term .tl{height:1.25em}
.term .cur{background:#d6d6e6;color:#0a0a12}.term .curoff{outline:1px solid #d6d6e6}
body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#1d1a4a55,transparent),var(--bg);
color:var(--text);font:14px/1.5 'Segoe UI',system-ui,Roboto,sans-serif;min-height:100vh}
h1{margin:0;font-size:22px;background:linear-gradient(90deg,var(--mint),var(--violet) 60%,var(--coral));
-webkit-background-clip:text;background-clip:text;color:transparent}
header{padding:14px 24px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px}
header .logo{width:38px;height:38px;flex:none;filter:drop-shadow(0 0 8px #7C6CFF55)}
header small{color:var(--dim)}
.wrap{display:grid;grid-template-columns:320px 1fr;gap:18px;padding:18px 24px}
.wrap>.outcard{grid-column:1/-1;min-width:0;margin-bottom:0}  /* Output spans the full width below both columns */
@media(max-width:900px){.wrap{grid-template-columns:1fr}}
/* Decorative emblem in the empty space below the sidebar; stays in view while the right column scrolls. */
.bglogo{position:sticky;top:24px;margin:28px 12px 0;opacity:.6;pointer-events:none;user-select:none}
.bglogo svg{width:100%;height:auto;display:block;font-family:'Segoe UI',system-ui,Roboto,sans-serif}
.bglogo .sweep{transform-origin:140px 150px;animation:bglspin 9s linear infinite}
@keyframes bglspin{to{transform:rotate(360deg)}}
@media(prefers-reduced-motion:reduce){.bglogo .sweep{animation:none}}
@media(max-width:900px){.bglogo{display:none}}
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
.ok{color:var(--ok)}.bad{color:var(--bad)}
.err{color:var(--bad);margin-top:8px}
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
#pretty .tw{overflow:auto;max-width:100%}#pretty table.wide td{min-width:90px}#pretty table.wide td:nth-child(n+6){min-width:140px}
#pretty table{border-collapse:collapse;width:100%;font-size:12.5px}
#pretty th{text-align:left;color:var(--mint);font-weight:600;border-bottom:1px solid var(--line);padding:5px 8px;white-space:nowrap;position:sticky;top:0;background:#0d0b22}
#pretty td{padding:6px 10px;border-bottom:1px dashed #2a285088;vertical-align:top;overflow-wrap:break-word;line-height:1.5}
#pretty th{padding:6px 10px}
#pretty tr:nth-child(even) td{background:#ffffff05}
#pretty tr:hover td{background:#7C6CFF14}
#pretty .pill{display:inline-block;padding:1px 10px;border-radius:99px;font-size:12px;border:1px solid currentColor;white-space:nowrap}
#pretty .pill.info{color:#b3a9ff}
#pretty td .expired{color:var(--coral);font-weight:600}#pretty .chip.expired{background:#FF7A5926;border-color:var(--coral);color:var(--coral);font-weight:600}
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
#pretty .dtabs{display:flex;gap:6px;flex-wrap:wrap}#pretty .dtabs button.on{border-color:var(--violet);box-shadow:0 0 12px #7C6CFF33;color:var(--mint)}
#aicard{position:fixed;right:20px;bottom:84px;z-index:60;width:min(420px,calc(100vw - 32px));height:min(640px,calc(100vh - 110px));margin:0;padding:0;display:flex;flex-direction:column;background:#fff;color:#1d1d1f;border:0;border-radius:14px;overflow:hidden;box-shadow:0 16px 48px #000a}
#aicard[hidden]{display:none}
#aicard .aihead{display:flex;align-items:center;gap:12px;padding:12px 14px;background:#2b2b2e;color:#fff;flex:0 0 auto}
#aicard .aihead .aititle{flex:1;min-width:0}#aicard .aihead b{display:block;font-size:15px;font-weight:600}
#aicard .aihead small{display:block;font-size:12px;color:#b8b8c0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#aicard .aihead button{background:transparent;border:0;color:#d8d8de;font-size:16px;padding:4px 8px;border-radius:6px;box-shadow:none}
#aicard .aihead button:hover{background:#ffffff1a;color:#fff}
.aiav{position:relative;flex:0 0 auto;width:34px;height:34px;border-radius:50%;display:grid;place-items:center;font-size:16px;color:#04201c;background:linear-gradient(135deg,#1f8a7a,#2EE6C5)}
.aiav.big::after{content:"";position:absolute;right:-1px;bottom:-1px;width:10px;height:10px;border-radius:50%;background:#22c55e;border:2px solid #2b2b2e}
.aiav.big.off::after{background:#9ca3af}
#aicard .aibody{overflow:auto;padding:14px 14px 6px;flex:1;min-height:0;background:#fff}
#ai_log{margin:0}
.airow{display:flex;gap:8px;align-items:flex-end;margin:8px 0}.airow.user{justify-content:flex-end}
.airow .aiav{width:30px;height:30px;font-size:14px}
.aimsg{padding:10px 14px;border-radius:16px;line-height:1.5;font-size:14px;max-width:85%;overflow-wrap:anywhere;min-width:0}
.aimsg.bot{background:#f0f2f5;color:#1d1d1f;border-bottom-left-radius:4px}
.aimsg.user{background:#2b2b2e;color:#fff;white-space:pre-wrap;border-bottom-right-radius:4px}
.aimsg.err{background:#fff1f1;color:#b42318;border:1px solid #f3b4ae;border-bottom-left-radius:4px}
.aimsg.aiwait{padding:12px 16px}
.aimsg p{margin:4px 0}.aimsg ul{margin:4px 0 4px 20px;padding:0}.aimsg .aih{font-weight:600;margin:10px 0 2px}
.aimsg pre{white-space:pre-wrap;background:#e4e7ec;color:#1d1d1f;padding:8px;border-radius:6px;font-size:12.5px}
.aimsg code{background:#e4e7ec;color:#1d1d1f;padding:0 4px;border-radius:4px;font-size:12.5px}
.aiwarn{background:#fff7e6;color:#8a4b00;border:1px solid #f5c26b;border-radius:8px;padding:6px 10px;margin:0 0 8px;font-size:12.5px;line-height:1.4}
.aimeta{font-size:11.5px;color:#6b7280;margin-top:6px}.aimeta.bad{color:#b42318}.aimeta.lnk{color:#0b7a6a!important;text-decoration:underline}
.aistep{font-size:12.5px;display:flex;gap:6px;align-items:center;margin:2px 0 6px;flex-wrap:wrap}.aistep .ok{color:#15803d}.aistep .bad{color:#b42318}.aistep .muted{color:#6b7280}
#aicard .aistep button{padding:1px 10px;font-size:12px;background:#fff;color:#1d1d1f;border:1px solid #c4c8cf;border-radius:6px;box-shadow:none}
.aidots{display:inline-flex;gap:5px}.aidots i{width:8px;height:8px;border-radius:50%;background:#6b7280;opacity:.25;animation:aidot 1.2s infinite ease-in-out}
.aidots i:nth-child(2){animation-delay:.2s}.aidots i:nth-child(3){animation-delay:.4s}
@keyframes aidot{0%,80%,100%{opacity:.25;transform:scale(.8)}40%{opacity:1;transform:scale(1.1)}}
#ai_chips{display:flex;flex-direction:column;align-items:flex-end;gap:8px;margin:12px 0 6px}
#aicard #ai_chips button{background:#fff;color:#1d1d1f;border:1.5px solid #2b2b2e;border-radius:10px;padding:8px 14px;font-size:14px;font-weight:400;box-shadow:none;width:auto}
#aicard #ai_chips button:hover{background:#2b2b2e;color:#fff}
#aicard.busy #ai_chips{display:none}
#aicard button:disabled{opacity:.45;cursor:wait}
#ai_cfg{background:#f7f7f9;border:1px solid #e3e5e8;border-radius:10px;padding:4px 12px 12px;margin-bottom:10px}
#ai_cfg:not([open]){display:none}#ai_cfg summary{cursor:pointer;color:#4b5563;font-size:13px;padding:6px 0;font-weight:600}
#aicard #ai_cfg label{color:#4b5563}#aicard #ai_cfg .chk{color:#4b5563;font-size:13px}#aicard #ai_cfg .row3{grid-template-columns:1fr 1fr}
#aicard #ai_cfg input{background:#fff;color:#1d1d1f;border:1px solid #c4c8cf}
#aicard #ai_cfg button{background:#fff;color:#1d1d1f;border:1px solid #c4c8cf;box-shadow:none;padding:6px 12px}
#aicard #ai_cfg button.primary{background:#2b2b2e;color:#fff;border-color:#2b2b2e}
#aicard #ai_cfg .row{align-items:center}#aicard #ai_cfg .row button{flex:0 0 auto;width:auto;min-width:110px}
#ai_cfgmsg{font-size:12.5px;margin-top:8px}#ai_cfgmsg:empty{display:none}
#ai_mlist{display:flex;flex-direction:column;gap:4px;margin-top:6px}#ai_mlist:empty{display:none}
#aicard #ai_mlist button{text-align:left;width:100%;padding:6px 10px;font-size:13px;background:#fff;color:#1d1d1f;border:1px solid #d0d5dd;border-radius:8px;box-shadow:none;font-family:ui-monospace,Consolas,monospace}
#aicard #ai_mlist button:hover{border-color:#2b2b2e}#aicard #ai_mlist button.cur{border-color:#1f8a7a;background:#ecfdf8;font-weight:600}
#ai_cfgmsg.ok{color:#15803d}#ai_cfgmsg.bad{color:#b42318}#ai_cfgmsg.muted{color:#6b7280}
#aicard .aifoot{flex:0 0 auto;border-top:1px solid #e5e7eb;background:#fff;padding:10px 12px 6px}
#aicard .aiinput{display:flex;gap:8px;align-items:flex-end}
#aicard textarea{flex:1;box-sizing:border-box;height:42px;min-height:42px;max-height:140px;resize:none;overflow-y:hidden;scrollbar-width:thin;line-height:20px;background:#fff;color:#1d1d1f;border:1px solid #d0d5dd;border-radius:10px;padding:10px 12px;font:inherit;font-size:14px}
#aicard textarea:focus{outline:none;border-color:#2b2b2e}
#aicard #ai_send{flex:0 0 auto;width:42px;height:42px;padding:0;border-radius:50%;border:0;background:#2b2b2e;color:#fff;font-size:17px;box-shadow:none}
#aicard #ai_send:hover{background:#1f8a7a}
#aicard #ai_att{flex:0 0 auto;width:42px;height:42px;padding:0;border-radius:50%;background:#fff;color:#1d1d1f;border:1px solid #d0d5dd;font-size:17px;box-shadow:none}
#aicard #ai_att:hover{border-color:#2b2b2e}
#aicard .aimsg.bot>button{background:#fff;color:#1d1d1f;border:1.5px solid #2b2b2e;border-radius:10px;padding:7px 14px;font-size:14px;box-shadow:none}
#aicard .aimsg.bot>button:hover{background:#2b2b2e;color:#fff}
[data-theme=light] #aicard .aimsg.bot>button{border-color:#0b6fd0;color:#0b6fd0}[data-theme=light] #aicard .aimsg.bot>button:hover{background:#0b6fd0;color:#fff}
#aicard .aiby{text-align:center;font-size:11.5px;color:#6b7280;padding:6px 0 2px}#aicard .aiby b{color:#1f8a7a;font-weight:600}
#aifab{position:fixed;right:20px;bottom:20px;z-index:61;width:auto;height:52px;padding:0 20px;border-radius:26px;border:0;display:flex;flex-direction:row;align-items:center;gap:8px;background:linear-gradient(135deg,#1f8a7a,#2EE6C5);color:#04201c;box-shadow:0 6px 20px #0009;cursor:pointer;font-weight:700;font-size:15px;letter-spacing:.06em}
#aifab:hover{filter:brightness(1.1);transform:translateY(-2px)}#aifab .fi{font-size:18px}
@media(max-width:700px){#aicard{right:52px;width:calc(100vw - 68px)}#aicard #ai_cfg .row3{grid-template-columns:1fr}}
#pretty .dwide{grid-column:span 2}@media(max-width:1180px){#pretty .dwide{grid-column:auto}}
#pretty .dgauge{max-width:150px;margin:2px auto 0}#pretty .dgauge svg{width:100%;height:auto;display:block}
#pretty .dtile.bad{border-color:var(--coral);box-shadow:0 0 10px #FF7A5933}#pretty .dtile.warn{border-color:#c98500}
#pretty .fchip{display:inline-block;border:1px solid var(--line);border-radius:99px;padding:0 9px;margin:0 0 4px 6px;cursor:pointer;color:var(--mint)}
#pretty .fchip:hover{border-color:var(--coral)}
#pretty .dtop .dvv{text-align:right;color:var(--dim);font-variant-numeric:tabular-nums}
#hotbar{position:fixed;top:12px;left:50%;transform:translateX(-50%);z-index:80;display:flex;gap:10px;align-items:center;max-width:min(860px,calc(100vw - 32px));padding:10px 12px 10px 16px;border-radius:10px;border:1px solid var(--line);background:var(--panel);color:var(--text);box-shadow:0 8px 28px #0006;font-size:13.5px}
#hotbar[hidden]{display:none}
/* ---- Device monitor: bell, panel, pop-ups ---- */
#monbtn{position:relative}#monbtn:not([hidden])+.themebtn{margin-left:8px}#monbtn.alert{border-color:var(--bad);box-shadow:0 0 0 3px #e5484d33}
#monbadge{position:absolute;top:-6px;right:-6px;min-width:18px;height:18px;padding:0 5px;border-radius:9px;background:#d92d20;color:#fff;font-size:11px;font-weight:700;line-height:18px}
#monpanel{position:fixed;top:64px;right:16px;z-index:70;width:min(460px,calc(100vw - 32px));max-height:calc(100vh - 90px);overflow:auto;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:12px;box-shadow:0 16px 40px #0005;padding:12px 14px}
#monpanel[hidden]{display:none}#monpanel h3{margin:0 0 8px;font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--mint)}
#monpanel .mrow{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:6px 0}#monpanel .mrow select{width:auto}
#monpanel .mrow label{margin:0;display:flex;gap:6px;align-items:center;font-size:13px;color:var(--text)}#monpanel .mrow input{width:auto}
#monpanel .msec{margin:10px 0 4px;font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em}
#monpanel .mline{font-size:12.5px;padding:4px 0;border-bottom:1px dashed var(--line)}#monpanel .mline:last-child{border-bottom:0}
#monpanel .mline.offline,#monpanel .mline.pooldown,#monpanel .mline.error,#monpanel .mline.ha{color:var(--bad)}#monpanel .mline.recovered{color:var(--ok)}#monpanel .mline.admin{color:#b26b00}
#montoasts{position:fixed;left:16px;bottom:16px;z-index:75;display:flex;flex-direction:column;gap:8px;width:min(440px,calc(100vw - 32px));pointer-events:none}
.mtoast{pointer-events:auto;background:var(--panel);color:var(--text);border:1px solid var(--line);border-left:5px solid var(--bad);border-radius:10px;box-shadow:0 10px 30px #0006;padding:10px 12px;font-size:13px;animation:mtin .25s ease-out}
.mtoast.recovered{border-left-color:var(--ok)}.mtoast.admin,.mtoast.error{border-left-color:#d08700}
.mtoast .mth{display:flex;align-items:center;gap:8px;font-weight:700;margin-bottom:3px}.mtoast .mth span{flex:1}
.mtoast .mth button{padding:0 8px;font-size:13px;box-shadow:none}.mtoast .mtv{color:var(--dim);font-size:12px;margin-top:3px}
@keyframes mtin{from{transform:translateY(12px);opacity:0}}
#hotbar.new{border-color:var(--mint)}#hotbar.bad{border-color:var(--bad);color:var(--bad)}#hotbar.ok{border-color:var(--ok)}
#hotbar button{flex:none;padding:4px 10px}
header .brand{height:34px;width:auto;flex:none}header .bsep{width:1px;height:30px;background:var(--line);flex:none}
.themebtn{margin-left:auto;flex:none;width:34px;height:34px;padding:0;border-radius:50%;font-size:16px;line-height:1}
/* ---- Light "portal" theme: white cards, blue accent, orange/purple highlights (toggle in the header) ---- */
:root[data-theme=light]{--bg:#f4f6fa;--panel:#fff;--panel2:#f6f8fb;--line:#e1e6ee;--text:#1c2733;--dim:#5f6b7a;
--mint:#0b6fd0;--coral:#e8572a;--violet:#6c3fc4;--ok:#16803c;--bad:#c62828;color-scheme:light}
[data-theme=light] body{background:radial-gradient(900px 420px at 10% 108%,#dedcf4,transparent),radial-gradient(1000px 520px at 92% 112%,#d8e7f7,transparent),var(--bg);background-attachment:fixed}
[data-theme=light] header{background:#fff;position:relative;padding:12px 28px}
[data-theme=light] header::after{content:"";position:absolute;left:50%;bottom:-4px;width:100px;height:4px;transform:translateX(-50%);
background:linear-gradient(90deg,#0b6fd0 0 58%,#f26b38 58% 76%,#6c3fc4 76%)}
[data-theme=light] h1{background:none;color:var(--text);font-weight:600;letter-spacing:-.01em}
[data-theme=light] header .logo{filter:none}
[data-theme=light] .card{border-color:var(--line);box-shadow:0 1px 2px #1c27330a,0 8px 24px #1c27330d}
[data-theme=light] .card h3,[data-theme=light] .grp{color:var(--mint);font-weight:600;letter-spacing:.14em}
[data-theme=light] label{color:#2b3644;font-weight:600}
[data-theme=light] input,[data-theme=light] select{background:#fff;border-color:#cfd7e3}
[data-theme=light] input:focus,[data-theme=light] select:focus{border-color:var(--mint);box-shadow:0 0 0 3px #0b6fd022}
[data-theme=light] button{background:#0b6fd0;border-color:#0b6fd0;font-weight:600;color:#fff}
[data-theme=light] .dev{font-weight:600}[data-theme=light] .dev .muted,[data-theme=light] .dev small{font-weight:400}
[data-theme=light] button:hover{background:#095db0;border-color:#095db0;color:#fff;box-shadow:none}
[data-theme=light] button:disabled{background:#8db9e6;border-color:#8db9e6;cursor:default}
/* small controls stay light: close buttons, round header buttons, dashboard tabs (the selected one is blue) */
[data-theme=light] .themebtn,[data-theme=light] .dev button,[data-theme=light] .mtoast button,[data-theme=light] #hotbar button:not(.primary),
[data-theme=light] #pretty .dtabs button{background:#fff;border-color:#cfd7e3;color:#1c2733}
[data-theme=light] .themebtn:hover,[data-theme=light] .dev button:hover,[data-theme=light] .mtoast button:hover,
[data-theme=light] #hotbar button:not(.primary):hover,[data-theme=light] #pretty .dtabs button:hover{background:#eef5fd;border-color:var(--mint);color:var(--mint)}
[data-theme=light] button.primary{background:#0b6fd0;color:#fff;border:0}
[data-theme=light] button.primary:hover{background:#095db0;color:#fff}
[data-theme=light] .dev.sel{border-color:var(--mint);background:#eef5fd;box-shadow:none}
[data-theme=light] .f5{background:#fdeee8;color:#c2410c}[data-theme=light] .paloalto{background:#e6f4ee;color:#0f7a4f}
[data-theme=light] .fortigate{background:#efeafb;color:#5b34b0}[data-theme=light] .cloudflare{background:#fef1e4;color:#b45309}
[data-theme=light] .chkrow{border-bottom-color:var(--line)}
[data-theme=light] .chkrow .lbl{font-size:13.5px;color:#1c2733}
/* Semibold Segoe UI everywhere in the light theme (the portal look); the SSH terminal keeps its regular weight */
[data-theme=light] body,[data-theme=light] #pretty,[data-theme=light] pre,[data-theme=light] #aicard,[data-theme=light] .aimsg{font-weight:600}
[data-theme=light] .term{font-weight:400}
[data-theme=light] pre,[data-theme=light] #pretty{background:#fff}
[data-theme=light] pre{background:var(--panel2)}
[data-theme=light] .badge{box-shadow:none}
[data-theme=light] .badge.ok{background:#e8f5ec;color:var(--ok);border-color:var(--ok)}
[data-theme=light] .badge.bad{background:#fdecec;color:var(--bad);border-color:var(--bad)}
[data-theme=light] .badge.warn{background:#fff4e0;color:#975a00;border-color:#e0a03a}
[data-theme=light] .badge.info{background:#efeafb;color:var(--violet);border-color:var(--violet)}
[data-theme=light] .warnbox{border-color:var(--bad);box-shadow:none}
[data-theme=light] #pretty .kvr,[data-theme=light] #pretty td{border-bottom-color:var(--line)}
[data-theme=light] #pretty th{background:#f1f4f8;color:#3a4655}
[data-theme=light] #pretty tr:nth-child(even) td{background:#f9fafc}
[data-theme=light] #pretty tr:hover td{background:#eef5fd}
[data-theme=light] #pretty .pill.info{color:var(--violet)}
[data-theme=light] #pretty td .expired,[data-theme=light] #pretty .sev-high{color:var(--bad)}
[data-theme=light] #pretty .chip.expired{background:#fdecec;border-color:var(--bad);color:var(--bad)}
[data-theme=light] #pretty tr.deny td{background:#fdecec!important;color:var(--bad)}
[data-theme=light] #pretty .logln.deny,[data-theme=light] #pretty .kvr.deny .v{color:var(--bad)}
[data-theme=light] #pretty .chip{background:#eef2f7}[data-theme=light] #pretty .sev-medium{color:#975a00}
[data-theme=light] #pretty .dtile.bad{border-color:var(--bad);box-shadow:none}
[data-theme=light] #pretty svg .hv:hover{fill:#0b6fd012}
[data-theme=light] #pretty .dtabs button.on{background:#0b6fd0;border-color:#0b6fd0;box-shadow:none;color:#fff}
[data-theme=light] svg [fill="#8f8cb8"]{fill:#5f6b7a}[data-theme=light] svg [stroke="#2a2850"]{stroke:#e1e6ee}
[data-theme=light] svg [fill="#14132a"]{fill:#fff}
[data-theme=light] svg stop[stop-color="#2EE6C5"]{stop-color:#0b6fd0}[data-theme=light] svg stop[stop-color="#7C6CFF"]{stop-color:#6c3fc4}
[data-theme=light] svg stop[stop-color="#FF7A59"]{stop-color:#f26b38}[data-theme=light] svg [stroke="#2EE6C5"]{stroke:#0b6fd0}
[data-theme=light] svg [stroke="#FF7A59"]{stroke:#f26b38}[data-theme=light] svg [stroke="#7C6CFF"]{stroke:#6c3fc4}
[data-theme=light] .fdwrap{background:radial-gradient(700px 220px at 85% 110%,#6c3fc40d,transparent),#fbfcfe}
[data-theme=light] .fdbase{stroke:#e1e6ee}[data-theme=light] .fdcard{fill:#fff}[data-theme=light] .fdcard.nc{fill:var(--panel2)}
[data-theme=light] .fdic{fill:#f4f6fa}[data-theme=light] .fdt{fill:var(--text)}
[data-theme=light] .fdr,[data-theme=light] .fds{fill:var(--dim)}[data-theme=light] .fdlab{fill:#46536a}
[data-theme=light] #fdsh feDropShadow{flood-color:#1c2733;flood-opacity:.10}
[data-theme=light] #aicard{box-shadow:0 16px 48px #1c273340}
[data-theme=light] #aicard .aihead{background:#0b2545}[data-theme=light] .aiav.big::after{border-color:#0b2545}
[data-theme=light] .aiav{background:linear-gradient(135deg,#0b6fd0,#5aa3ec);color:#fff}
[data-theme=light] .aimsg.user{background:#0b2545}
[data-theme=light] #aicard #ai_send,[data-theme=light] #aicard #ai_cfg button.primary{background:#0b6fd0;border-color:#0b6fd0}
[data-theme=light] #aicard #ai_send:hover{background:#095db0}
[data-theme=light] #aicard #ai_chips button{border-color:#0b6fd0;color:#0b6fd0}
[data-theme=light] #aicard #ai_chips button:hover{background:#0b6fd0;color:#fff}
[data-theme=light] #aicard textarea:focus{border-color:#0b6fd0}[data-theme=light] #aicard .aiby b{color:#0b6fd0}
[data-theme=light] #aifab{background:linear-gradient(135deg,#0b6fd0,#3b8ee8);color:#fff;box-shadow:0 6px 20px #0b6fd055}
</style>
<script>try{document.documentElement.dataset.theme=localStorage.getItem("theme")||"light"}catch(e){document.documentElement.dataset.theme="light"}</script>
</head><body>
<header><img class="brand" src="/brand-logo?t=__TOKEN__" alt="" onload="this.nextElementSibling.hidden=false" onerror="this.remove()"><span class="bsep" hidden></span><svg class="logo" viewBox="0 0 36 36" role="img" aria-label="ITSec Ops logo"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2EE6C5"/><stop offset=".6" stop-color="#7C6CFF"/><stop offset="1" stop-color="#FF7A59"/></linearGradient></defs><path d="M18 2.5 31.5 7.5v9.5c0 8-5.6 13.6-13.5 16.5C10.1 30.6 4.5 25 4.5 17V7.5Z" fill="#14132a" stroke="url(#lg)" stroke-width="2.2" stroke-linejoin="round"/><path d="m12 13 6 5-6 5" fill="none" stroke="#2EE6C5" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M20.5 24h5" stroke="#FF7A59" stroke-width="2.6" stroke-linecap="round"/></svg><h1>ITSec Ops</h1><button class="themebtn" id="monbtn" onclick="monPanel()" title="Device monitor" aria-label="Device monitor" hidden>🔔<span id="monbadge" hidden></span></button><button class="themebtn" onclick="themeToggle()" title="Switch light / dark theme" aria-label="Switch light / dark theme">◐</button></header>
<div id="monpanel" hidden></div><div id="montoasts" aria-live="assertive"></div>
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
  <div class="card"><h3>Devices</h3><div id="vault"></div><div id="devs" class="muted">No devices connected.</div></div>
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
    <div class="chk" id="f-rem"><input type="checkbox" id="remember" onchange="remUi()"><span>Remember this login on this PC (encrypted for your Windows account and a passphrase; saved_logins.dat, not in git)</span></div>
    <div id="f-vpass" style="display:none"><label id="vpasslbl">Saved-logins passphrase</label><input id="vpass" type="password" autocomplete="new-password"></div>
    <div style="margin-top:12px"><button class="primary" onclick="connect()">Connect</button></div>
    <div id="cerr" class="err"></div>
  </div>
  <div class="card"><h3>Session</h3>
    <button onclick="showAudit()">View audit log</button>
    <p class="muted" style="margin:8px 0 0">Credentials stay in memory of the Python process. Closing it clears everything.</p></div>
  <div class="bglogo" aria-hidden="true"><svg viewBox="0 0 280 350">
    <defs><linearGradient id="bgl-g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2EE6C5"/><stop offset=".6" stop-color="#7C6CFF"/><stop offset="1" stop-color="#FF7A59"/></linearGradient>
    <linearGradient id="bgl-sw" x1="1" y1="0" x2="0" y2="0"><stop offset="0" stop-color="#2EE6C5" stop-opacity=".28"/><stop offset="1" stop-color="#2EE6C5" stop-opacity="0"/></linearGradient></defs>
    <g fill="none" stroke="#2a2850" stroke-width="1.2"><circle cx="140" cy="150" r="60"/><circle cx="140" cy="150" r="95" stroke-dasharray="3 5"/><circle cx="140" cy="150" r="130"/></g>
    <path class="sweep" d="M140 150 L270 150 A130 130 0 0 0 239.6 66.4 Z" fill="url(#bgl-sw)"/>
    <g stroke="#7C6CFF" stroke-opacity=".45" stroke-width="1.2" stroke-dasharray="2 4"><path d="M88 120 50 98M192 120 230 98M192 180 230 202M88 180 50 202"/></g>
    <g font-size="9" font-weight="600" text-anchor="middle" fill="#8f8cb8" letter-spacing=".08em">
      <circle cx="38" cy="91" r="16" fill="#14132a" stroke="url(#bgl-g)" stroke-width="1.5"/><text x="38" y="94.5">F5</text>
      <circle cx="242" cy="91" r="16" fill="#14132a" stroke="url(#bgl-g)" stroke-width="1.5"/><text x="242" y="94.5">PAN</text>
      <circle cx="242" cy="209" r="16" fill="#14132a" stroke="url(#bgl-g)" stroke-width="1.5"/><text x="242" y="212.5">FGT</text>
      <circle cx="38" cy="209" r="16" fill="#14132a" stroke="url(#bgl-g)" stroke-width="1.5"/><text x="38" y="212.5">CF</text></g>
    <g transform="translate(82.4 92.4) scale(3.2)"><path d="M18 2.5 31.5 7.5v9.5c0 8-5.6 13.6-13.5 16.5C10.1 30.6 4.5 25 4.5 17V7.5Z" fill="#14132a" stroke="url(#bgl-g)" stroke-width="1.4" stroke-linejoin="round"/>
    <path d="m12 13 6 5-6 5" fill="none" stroke="#2EE6C5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M20.5 24h5" stroke="#FF7A59" stroke-width="2" stroke-linecap="round"/></g>
    <text x="140" y="318" text-anchor="middle" font-size="22" font-weight="700" fill="url(#bgl-g)">ITSec Ops</text>
    <text x="140" y="340" text-anchor="middle" font-size="10" fill="#8f8cb8" letter-spacing=".25em">OBSERVE · TRACE · VERIFY</text>
  </svg></div>
</div>
<div>
  <div id="sshtool"></div><div id="terms"></div><div id="flowtrace"></div><div id="cftools"></div><div id="acc"></div><div id="appsec"></div>
  <div id="iplookup"></div><div id="f5tools"></div>
  <div class="card" id="main"><h3>Checks</h3><div class="muted">Connect a device to begin.</div></div>
  <div class="card"><h3>Raw read-only query</h3>
    <div class="row"><input id="raw" placeholder="" style="flex:5"><button style="flex:1" onclick="runRaw()">Run</button></div>
    <div id="rawhint" class="muted" style="margin-top:6px"></div></div>
</div>
  <div class="card outcard" id="outcard"><h3>Output</h3>
    <div class="meta"><span id="ometa">nothing run yet</span>
    <span id="fcount" class="muted" style="margin-left:auto"></span>
    <select id="stscope" style="display:none;max-width:150px" onchange="renderOut()" title="Which status column to test"><option value="">any status column</option><option value="vs">VS status</option><option value="pool">Pool status</option><option value="member">Member status</option></select>
    <select id="stval" style="display:none;max-width:150px" onchange="renderOut()" title="Show only rows in this state"><option value="">all states</option><option value="up">up / available</option><option value="down">down / offline</option><option value="unknown">unknown</option><option value="disabled">disabled</option></select>
    <input id="filter" placeholder="filter: word word -exclude" title="Words are ANDed; prefix a word with - to exclude it" style="max-width:240px" oninput="renderOut()">
    <button onclick="copyOut()">Copy</button>
    <button onclick="exportCsv()">Findings CSV</button><button onclick="exportHtml()">HTML report</button></div>
    <div id="verdict"></div><div id="pretty"></div></div>
</div>
  <div id="aicard" role="dialog" aria-label="AI assistant" hidden>
    <div class="aihead"><span class="aiav big off" id="ai_av">✦</span>
      <div class="aititle"><b>ITSec Assistant</b><small id="ai_sub">local LLM · no model set</small></div>
      <button onclick="aiCfg()" title="Model settings" aria-label="Model settings">⚙</button>
      <button onclick="aiClear()" title="New conversation" aria-label="New conversation">↻</button>
      <button onclick="aiToggle(false)" title="Close (Esc)" aria-label="Close">✕</button></div>
    <div class="aibody">
    <details id="ai_cfg"><summary>Model settings</summary>
      <div class="row3" style="margin-top:4px">
        <div><label>Model server (OpenAI-compatible API)</label><input id="ai_url" placeholder="http://127.0.0.1:11434/v1"></div>
        <div><label>Model</label><input id="ai_model" list="ai_models" placeholder="qwen2.5:7b"><datalist id="ai_models"></datalist></div>
        <div><label>API key (optional, kept in memory only)</label><input id="ai_key" type="password" placeholder="(none)" autocomplete="off"></div>
        <div><label>Context budget (characters sent per output)</label><input id="ai_budget" value="24000"></div>
      </div>
      <div id="ai_route" class="muted" style="font-size:12.5px;margin-top:6px"></div>
      <div class="row" style="margin-top:8px;flex-wrap:wrap;gap:6px"><button onclick="aiModels()">List models</button><button class="primary" onclick="aiSave(true)">Save</button></div>
      <div id="ai_cfgmsg" class="muted"></div><div id="ai_mlist"></div>
    </details>
    <div id="ai_log"></div>
    <div id="ai_chips"><button onclick="aiAsk('explain')">Explain the current output</button><button onclick="aiAsk('chat')">Ask about the current output</button><button onclick="aiAsk('agent')">Ask &amp; run read-only checks</button><button onclick="$('#ai_file').click()">Analyse a packet capture (.pcap)</button><button onclick="aiClear()">Start a new conversation</button></div>
    </div>
    <div class="aifoot"><div class="aiinput"><button id="ai_att" onclick="$('#ai_file').click()" title="Attach a packet capture (.pcap / .pcapng) to analyse" aria-label="Attach a packet capture">📎</button><input type="file" id="ai_file" accept=".pcap,.pcapng,.cap" hidden onchange="aiPcap(this.files&&this.files[0]);this.value=''"><textarea id="ai_q" rows="1" placeholder="Type your message…" title="Enter sends, Shift+Enter adds a new line"></textarea>
      <button id="ai_send" onclick="aiSend()" title="Send" aria-label="Send">➤</button></div>
      <div class="aiby">Powered by <b>✦ <span id="ai_by">local LLM</span></b> · read-only</div></div>
  </div>
<button id="aifab" onclick="aiToggle()" title="AI assistant (local LLM)" aria-label="AI assistant"><span class="fi">✦</span><span class="ft">AI</span></button>
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
let vault={};
async function vaultLoad(){vault=await api("/api/vault",{action:"status"});renderVault();remUi()}
function remUi(){const on=$("#remember").checked,need=on&&!vault.unlocked;$("#f-vpass").style.display=need?"":"none";
 $("#vpasslbl").textContent=vault.exists?"Saved-logins passphrase":"Choose a passphrase for saved logins (8+ characters; needed after every restart)";
 if(vault.ok&&!vault.windows)$("#f-rem").style.display="none"}
function renderVault(){const el=$("#vault");el.innerHTML="";if(!vault.ok||!vault.exists)return;
 if(!vault.unlocked){el.innerHTML='<div class="row" style="gap:8px;align-items:center;margin-bottom:10px"><input id="vunlock" type="password" placeholder="Saved-logins passphrase" style="flex:1" onkeydown="if(event.key===\'Enter\')vaultUnlock()">'+
  '<button class="primary" onclick="vaultUnlock()">Unlock & connect all</button></div><div id="verr" class="err"></div>'+
  '<p class="muted" style="margin:0 0 10px"><a href="#" onclick="vaultReset(event)">Forgot the passphrase? Delete the saved logins</a></p>';return}
 const l=vault.logins||[];
 el.innerHTML='<p class="muted" style="margin:0 0 6px">Saved logins ('+l.length+'): '+l.map(x=>'<span class="tag '+esc(x.vendor)+'">'+esc(x.name)+
  '</span> <a href="#" title="forget this login" onclick="vaultForget(event,\''+esc(x.id)+'\')">✕</a>').join(" ")+'</p>'+
  '<div class="row" style="gap:8px;margin-bottom:10px"><button onclick="vaultConnect()">Connect all saved</button><button onclick="vaultLock()">Lock</button></div><div id="verr" class="err"></div>'}
function vaultAdd(r){(r.results||[]).forEach(x=>{if(x.ok&&!devices.some(d=>d.id===x.id))devices.push(x)});
 const bad=(r.results||[]).filter(x=>!x.ok);if(devices.length&&!cur)cur=devices[0].id;vault=r;renderVault();renderAll();remUi();
 const e=$("#verr");if(e)e.textContent=bad.length?"Not connected: "+bad.map(x=>x.name+" ("+x.error+")").join("; "):""}
async function vaultUnlock(){const e=$("#verr");e.textContent="Unlocking and connecting…";
 const r=await api("/api/vault",{action:"unlock",passphrase:$("#vunlock").value});if(!r.ok){e.textContent=r.error;return}vaultAdd(r)}
async function vaultConnect(){$("#verr").textContent="Connecting…";const r=await api("/api/vault",{action:"connect"});
 if(!r.ok){$("#verr").textContent=r.error;return}vaultAdd(r)}
async function vaultForget(ev,id){ev.preventDefault();if(!confirm("Forget this saved login?"))return;
 const r=await api("/api/vault",{action:"forget",id});if(r.ok){vault=r;renderVault()}else $("#verr").textContent=r.error}
async function vaultLock(){vault=await api("/api/vault",{action:"lock"});renderVault();remUi()}
async function vaultReset(ev){ev.preventDefault();if(!confirm("Delete all saved logins? You will have to log in to each device again."))return;
 vault=await api("/api/vault",{action:"reset"});renderVault();remUi()}
async function connect(){$("#cerr").textContent="Connecting…";
 const b={vendor:$("#vendor").value,name:$("#name").value,host:$("#host").value,port:$("#port").value,
 username:$("#username").value,password:$("#password").value,apikey:$("#apikey").value,insecure:$("#insecure").checked,account:$("#account").value};
 if($("#remember").checked){b.remember=true;b.vault_pass=$("#vpass").value}
 const r=await api("/api/connect",b);
 if(!r.ok){$("#cerr").textContent=r.error;return}
 $("#cerr").textContent=(r.vendor==="cloudflare"?"Token sees "+r.zones.length+" zone(s) in "+r.accounts+" account(s)."+(r.note?" Note: "+r.note:""):"")+
  (r.remember_error?" Connected, but the login was not saved: "+r.remember_error:r.remembered?" Login saved (encrypted).":"");
 $("#password").value="";$("#apikey").value="";$("#vpass").value="";
 devices.push(r);select(r.id);if(r.remembered)vaultLoad()}
async function disconnect(id,ev){ev.stopPropagation();await api("/api/disconnect",{id});
 devices=devices.filter(d=>d.id!==id);if(cur===id)cur=devices.length?devices[0].id:null;renderAll()}
function select(id){cur=id;try{sessionStorage.setItem("cur",id||"")}catch(e){}renderAll()}
function dev(){return devices.find(d=>d.id===cur)}
function renderAll(){renderDevs();renderChecks();renderSsh();renderCf();renderAcc();renderAppsec();renderIp();renderF5();const d=dev();
 $("#raw").placeholder=d?hints[d.vendor]:"";$("#rawhint").textContent=d?hints[d.vendor]:""}
function renderFlow(){const box=$("#flowtrace");if(!devices.length){box.innerHTML="";return}
 const vs=[...new Set(devices.map(d=>d.vendor))].map(v=>({cloudflare:"Cloudflare",f5:"F5",paloalto:"Palo Alto",fortigate:"FortiGate"})[v]||v).join(" · ");
 if(!$("#ft_dst")){box.innerHTML='<div class="card"><h3>Flow trace · one flow on every connected device</h3><div class="row3">'+
  fld("ft_src","Source / client IP","203.0.113.5")+fld("ft_dst","Destination IP or hostname","shop.example.com or 10.5.1.20")+
  fld("ft_port","Destination port (optional)","443")+
  '<div><label>Protocol</label><select id="ft_proto"><option>tcp</option><option>udp</option><option>icmp</option></select></div>'+
  '<div><label>Events / logs time range</label><select id="ft_within"><option>last 15 minutes</option><option>last hour</option><option>last 6 hours</option><option>last 12 hours</option><option selected>last 24 hours</option></select></div></div>'+
  '<div class="chk"><input type="checkbox" id="ft_logs"><span>Also search logs (F5 WAF log, Palo Alto / FortiGate traffic logs). Slower: up to a few minutes.</span></div>'+
  '<div class="row" style="margin-top:10px"><button class="primary" onclick="flowTrace()">Trace flow</button></div>'+
  '<p class="muted" style="margin:8px 0 0" id="ft_note"></p>'+
  '<details style="margin-top:10px" ontoggle="if(this.open)natLoad()"><summary class="muted" style="cursor:pointer">Upstream NAT (optional): public → private IP in front of the firewall</summary>'+
  '<textarea id="nat_text" rows="5" spellcheck="false" style="width:100%;margin-top:8px;font-family:Consolas,monospace" placeholder="203.0.113.10 10.20.1.15   # shop"></textarea>'+
  '<div class="row" style="margin-top:6px;gap:10px;align-items:center"><button onclick="natSave()">Save list</button><span id="nat_msg" class="muted"></span></div>'+
  '<p class="muted" style="margin:6px 0 0">Only needed where a public IP is 1:1 NAT\'ed to a private IP before the first firewall (e.g. cloud public IPs). '+
  'One "public-IP private-IP" pair per line, # for comments; saved in nat_map.txt next to the console, kept out of git. Without an entry, the trace '+
  'infers the private IP when exactly one FortiGate VIP maps to the F5 virtual server of the hostname, and marks it as inferred.</p></details>'+
  '<details style="margin-top:8px" ontoggle="if(this.open)vipLoad()"><summary class="muted" style="cursor:pointer">VIP list (optional): name or hostname → FortiGate VIP → F5 VIP</summary>'+
  '<textarea id="vip_text" rows="6" spellcheck="false" style="width:100%;margin-top:8px;font-family:Consolas,monospace" placeholder="Shop portal VIP\t10.20.1.15\t10.30.1.20"></textarea>'+
  '<div class="row" style="margin-top:6px;gap:10px;align-items:center"><button onclick="vipSave()">Save list</button><span id="vip_msg" class="muted"></span></div>'+
  '<p class="muted" style="margin:6px 0 0">Paste the rows straight from a spreadsheet: name, FortiGate VIP, F5 VIP (optionally :port). A header row and extra columns are ignored. '+
  'The name can be a hostname or a label: its words are matched against the hostname you trace (VIP, F5, FG and similar words are ignored). '+
  'Tells the trace which FortiGate VIP belongs to a hostname; each row is checked against the live FortiGate and F5. Saved in vip_map.txt next to the console, kept out of git.</p></details></div>'}
 $("#ft_note").textContent="Finds the path through the "+devices.length+" connected device(s) ("+vs+") from their own configuration: the firewall that translates the address (FortiGate VIP or Palo Alto NAT), the F5 with the virtual server, any firewall between it and the servers, and Cloudflare for its hostnames. Only the devices the flow crosses are shown, each tested with the addresses it sees. Read-only."}
async function natLoad(){const r=await api("/api/natmap",{});if(r.ok){$("#nat_text").value=r.text;$("#nat_msg").textContent=r.count+" pair(s)"}}
async function natSave(){const m=$("#nat_msg"),r=await api("/api/natmap",{set:true,text:$("#nat_text").value});
 m.className=r.ok?"ok":"bad";m.textContent=r.ok?"saved · "+r.count+" pair(s)":"error: "+r.error;if(r.ok)$("#nat_text").value=r.text}
async function vipLoad(){const r=await api("/api/vipmap",{});if(r.ok){$("#vip_text").value=r.text;$("#vip_msg").textContent=r.count+" row(s)"}}
async function vipSave(){const m=$("#vip_msg"),r=await api("/api/vipmap",{set:true,text:$("#vip_text").value});
 m.className=r.ok?"ok":"bad";m.textContent=r.ok?"saved · "+r.count+" row(s)":"error: "+r.error;if(r.ok)$("#vip_text").value=r.text}
async function flowTrace(){if(!g("ft_dst").trim())return show({ok:false,error:"enter the destination IP or hostname"},"flow trace");
 setBusy("flow trace on "+devices.length+" device(s)"+($("#ft_logs").checked?" + logs (up to a few minutes)":""));
 show(await api("/api/flowtrace",{src:g("ft_src").trim(),dst:g("ft_dst").trim(),port:g("ft_port"),proto:g("ft_proto"),
  within:g("ft_within"),logs:$("#ft_logs").checked}),"flow trace (all devices)")}
function renderDevs(){const el=$("#devs");el.innerHTML="";renderFlow();
 if(!devices.length){el.textContent="No devices connected.";return}
 devices.forEach(d=>{const x=document.createElement("div");x.className="dev"+(d.id===cur?" sel":"");
  x.onclick=()=>select(d.id);
  const l=document.createElement("span");l.textContent=d.name+" ";
  const t=document.createElement("span");t.className="tag "+d.vendor;t.textContent=d.vendor;l.appendChild(t);
  const h=document.createElement("small");h.className="muted";h.textContent=" "+d.host;l.appendChild(h);
  const b=document.createElement("button");b.textContent="✕";b.onclick=e=>disconnect(d.id,e);
  x.appendChild(l);x.appendChild(b);el.appendChild(x)})}
function renderSsh(){const box=$("#sshtool");if(!box)return;box.innerHTML="";const d=dev();
 if(!d||!["f5","fortigate","paloalto"].includes(d.vendor))return;
 box.innerHTML='<div class="card"><h3>SSH · '+esc(d.name)+'</h3><div class="row3">'+
  fld("ssh_user","SSH user name",d.vendor==="fortigate"?"admin":"admin",d.user||"")+fld("ssh_port","SSH port","22","22")+
  '<div><label>&nbsp;</label><div class="row" style="gap:8px;flex-wrap:wrap"><button class="primary" onclick="termOpen()">Open SSH in this page</button>'+
  '<button onclick="sshOpen()">Open in a separate window</button></div></div></div>'+
  '<div class="chk"><input type="checkbox" id="ssh_legacy"><span>Allow older algorithms for this connection (old devices that answer &quot;Unable to negotiate&quot;: SHA-1 key exchange, ssh-rsa, AES-CBC; the hmac-sha1 MAC is always allowed)</span></div>'+
  '<p class="muted" style="margin:8px 0 0">Connects to '+esc(d.host)+' with this PC\'s <code>ssh</code>. In the page, click the terminal to type; keystrokes (the password too) pass through the console '+
  'to ssh and are never stored, logged or shown to the AI. The session is a normal CLI session: it is not read-only.</p>'+
  '<p id="ssh_msg" class="muted" style="margin:6px 0 0"></p></div>'}
// ---- In-page SSH terminal: a small VT emulator fed by the console's pseudo-console relay ----
const VTPAL=["#1e1e2a","#e05561","#7ccf7a","#e6c07b","#61afef","#c678dd","#56b6c2","#d6d6e6",
 "#5c6370","#ff6b7a","#98e08f","#ffd68a","#7cc4ff","#e19bff","#7fe0ea","#ffffff"];
function vtColor(n){if(n<16)return VTPAL[n];if(n>=232){const v=8+(n-232)*10;return "rgb("+v+","+v+","+v+")"}
 n-=16;const c=x=>x?55+x*40:0;return "rgb("+c(Math.floor(n/36))+","+c(Math.floor(n/6)%6)+","+c(n%6)+")"}
class VT{
 constructor(cols,rows){this.cols=cols;this.rows=rows;this.sb=[];this.reset()}
 reset(){this.x=0;this.y=0;this.a={fg:null,bg:null,b:0,i:0,u:0};this.top=0;this.bot=this.rows-1;this.saved=[0,0];
  this.vis=true;this.st=0;this.ps="";this.alt=null;this.scr=[];for(let r=0;r<this.rows;r++)this.scr.push(this.blank());this.out=""}
 blank(){const l=[];for(let c=0;c<this.cols;c++)l.push([" ",null]);return l}
 key(){const a=this.a;return a.fg===null&&a.bg===null&&!a.b&&!a.i&&!a.u?null:a.fg+"|"+a.bg+"|"+a.b+"|"+a.i+"|"+a.u}
 resize(cols,rows){if(cols===this.cols&&rows===this.rows)return;this.cols=cols;
  const fit=l=>{while(l.length<cols)l.push([" ",null]);l.length=cols;return l};
  this.scr=this.scr.map(fit);if(this.alt)this.alt.scr=this.alt.scr.map(fit);
  while(this.scr.length<rows)this.scr.push(this.blank());
  while(this.scr.length>rows){const l=this.scr.shift();if(!this.alt)this.sb.push(l);this.y=Math.max(0,this.y-1)}
  this.rows=rows;this.top=0;this.bot=rows-1;this.x=Math.min(this.x,cols-1);this.y=Math.min(this.y,rows-1)}
 up(top,bot,n){for(let k=0;k<n;k++){const l=this.scr.splice(top,1)[0];if(top===0&&!this.alt){this.sb.push(l);if(this.sb.length>3000)this.sb.shift()}
  this.scr.splice(bot,0,this.blank())}}
 down(top,bot,n){for(let k=0;k<n;k++){this.scr.splice(bot,1);this.scr.splice(top,0,this.blank())}}
 lf(){if(this.y===this.bot)this.up(this.top,this.bot,1);else if(this.y<this.rows-1)this.y++}
 put(ch){if(this.x>=this.cols){this.x=0;this.lf()}this.scr[this.y][this.x]=[ch,this.key()];this.x++}
 erase(l,a,b){for(let c=Math.max(0,a);c<Math.min(this.cols,b);c++)l[c]=[" ",null]}
 write(s){for(const ch of s){const c=ch.charCodeAt(0);
  if(this.st===0){
   if(c===27)this.st=1;else if(c===13)this.x=0;else if(c===10||c===11||c===12)this.lf();
   else if(c===8)this.x=Math.max(0,Math.min(this.x,this.cols)-1);else if(c===9)this.x=Math.min(this.cols-1,(this.x>>3)*8+8);
   else if(c>=32&&c!==127)this.put(ch)}
  else if(this.st===1){this.st=0;
   if(ch==="["){this.st=2;this.ps=""}else if(ch==="]")this.st=3;else if(ch==="("||ch===")"||ch==="#")this.st=4;
   else if(ch==="7")this.saved=[this.x,this.y];else if(ch==="8"){[this.x,this.y]=this.saved}
   else if(ch==="M"){if(this.y===this.top)this.down(this.top,this.bot,1);else if(this.y>0)this.y--}
   else if(ch==="D")this.lf();else if(ch==="E"){this.x=0;this.lf()}else if(ch==="c")this.reset()}
  else if(this.st===2){if(c>=0x40&&c<=0x7e){this.st=0;this.csi(ch,this.ps)}else this.ps+=ch;if(this.ps.length>64)this.st=0}
  else if(this.st===3){if(c===7)this.st=0;else if(c===27)this.st=5}
  else if(this.st===4)this.st=0;
  else if(this.st===5)this.st=0}}
 csi(f,ps){const priv=ps[0]==="?";const p=(priv?ps.slice(1):ps).split(";").map(x=>parseInt(x,10));
  const n=(i,d)=>isNaN(p[i])||p[i]===0?(d===undefined?1:d):p[i],cl=(v,a,b)=>Math.max(a,Math.min(b,v));
  const L=this.scr[this.y];
  switch(f){
   case"A":this.y=cl(this.y-n(0),this.y>=this.top?this.top:0,this.rows-1);break;
   case"B":this.y=cl(this.y+n(0),0,this.y<=this.bot?this.bot:this.rows-1);break;
   case"C":this.x=cl(this.x+n(0),0,this.cols-1);break;case"D":this.x=cl(Math.min(this.x,this.cols-1)-n(0),0,this.cols-1);break;
   case"E":this.x=0;this.y=cl(this.y+n(0),0,this.rows-1);break;case"F":this.x=0;this.y=cl(this.y-n(0),0,this.rows-1);break;
   case"G":case"`":this.x=cl(n(0)-1,0,this.cols-1);break;case"d":this.y=cl(n(0)-1,0,this.rows-1);break;
   case"H":case"f":this.y=cl(n(0)-1,0,this.rows-1);this.x=cl(n(1)-1,0,this.cols-1);break;
   case"J":{const m=isNaN(p[0])?0:p[0];
    if(m===0){this.erase(L,this.x,this.cols);for(let r=this.y+1;r<this.rows;r++)this.scr[r]=this.blank()}
    else if(m===1){this.erase(L,0,this.x+1);for(let r=0;r<this.y;r++)this.scr[r]=this.blank()}
    else{for(let r=0;r<this.rows;r++)this.scr[r]=this.blank();if(m===3)this.sb=[]}break}
   case"K":{const m=isNaN(p[0])?0:p[0];if(m===0)this.erase(L,this.x,this.cols);else if(m===1)this.erase(L,0,this.x+1);else this.erase(L,0,this.cols);break}
   case"X":this.erase(L,this.x,this.x+n(0));break;
   case"P":{const k=Math.min(n(0),this.cols-this.x);L.splice(this.x,k);for(let i=0;i<k;i++)L.push([" ",null]);break}
   case"@":{const k=Math.min(n(0),this.cols-this.x);for(let i=0;i<k;i++)L.splice(this.x,0,[" ",null]);L.length=this.cols;break}
   case"L":if(this.y>=this.top&&this.y<=this.bot)this.down(this.y,this.bot,Math.min(n(0),this.bot-this.y+1));break;
   case"M":if(this.y>=this.top&&this.y<=this.bot)this.up(this.y,this.bot,Math.min(n(0),this.bot-this.y+1));break;
   case"S":this.up(this.top,this.bot,n(0));break;case"T":this.down(this.top,this.bot,n(0));break;
   case"r":this.top=cl(n(0)-1,0,this.rows-1);this.bot=cl(n(1,this.rows)-1,this.top,this.rows-1);this.x=0;this.y=0;break;
   case"s":this.saved=[this.x,this.y];break;case"u":[this.x,this.y]=this.saved;break;
   case"n":if(p[0]===6)this.out+="\x1b["+(this.y+1)+";"+(this.x+1)+"R";break;
   case"m":this.sgr(ps===""?[0]:p);break;
   case"h":case"l":if(priv){const on=f==="h";p.forEach(m=>{
     if(m===25)this.vis=on;
     else if(m===1049||m===1047||m===47){if(on&&!this.alt){this.alt={scr:this.scr,x:this.x,y:this.y};this.scr=[];for(let r=0;r<this.rows;r++)this.scr.push(this.blank())}
      else if(!on&&this.alt){this.scr=this.alt.scr;this.x=this.alt.x;this.y=this.alt.y;this.alt=null;this.resize(this.cols,this.rows)}}})}break}}
 sgr(p){const a=this.a;for(let i=0;i<p.length;i++){const v=isNaN(p[i])?0:p[i];
  if(v===0){a.fg=null;a.bg=null;a.b=0;a.i=0;a.u=0}else if(v===1)a.b=1;else if(v===22)a.b=0;else if(v===4)a.u=1;else if(v===24)a.u=0;
  else if(v===7)a.i=1;else if(v===27)a.i=0;else if(v>=30&&v<=37)a.fg=VTPAL[v-30];else if(v===39)a.fg=null;
  else if(v>=40&&v<=47)a.bg=VTPAL[v-40];else if(v===49)a.bg=null;else if(v>=90&&v<=97)a.fg=VTPAL[v-82];else if(v>=100&&v<=107)a.bg=VTPAL[v-92];
  else if(v===38||v===48){let col=null;if(p[i+1]===5){col=vtColor(p[i+2]||0);i+=2}else if(p[i+1]===2){col="rgb("+(p[i+2]||0)+","+(p[i+3]||0)+","+(p[i+4]||0)+")";i+=4}
   if(v===38)a.fg=col;else a.bg=col}}}
 lineHtml(l,cur){let h="",run="",k;const flush=()=>{if(!run)return;
   if(k==null)h+=esc(run);else{const [fg,bg,b,inv,u]=k.split("|");let f=fg==="null"?null:fg,g=bg==="null"?null:bg;
    if(inv==="1"){const t=f;f=g||"#0a0a12";g=t||"#d6d6e6"}
    h+='<span style="'+(f?"color:"+f+";":"")+(g?"background:"+g+";":"")+(b==="1"?"font-weight:700;":"")+(u==="1"?"text-decoration:underline;":"")+'">'+esc(run)+"</span>"}run=""};
  for(let c=0;c<l.length;c++){if(c===cur){flush();h+='<span class="cur">'+esc(l[c][0])+"</span>";k=undefined;continue}
   if(l[c][1]!==k){flush();k=l[c][1]}run+=l[c][0]}flush();return h}}
const TERMS={};
function termSize(el){const m=document.createElement("span");m.textContent="MMMMMMMMMM";m.style.visibility="hidden";el.appendChild(m);
 const w=m.getBoundingClientRect().width/10||7.7;m.remove();return Math.max(40,Math.min(300,Math.floor((el.clientWidth-18)/w)))}
async function termOpen(){const d=dev(),m=$("#ssh_msg");if(!d)return;m.className="muted";m.textContent="opening…";
 const card=mk("div","card termcard"),hd=mk("div","thd"),title=mk("b",null,"SSH · "+d.name+" ("+d.host+")"),st=mk("span","st","starting…");
 const bx=mk("button",null,"Disconnect"),body=mk("div","term");body.tabIndex=0;hd.append(title,st,bx);card.append(hd,body);$("#terms").prepend(card);
 const rows=30;body.style.height="calc("+rows+" * 1.25em + 14px)";const cols=termSize(body);
 let r;try{r=await api("/api/term/open",{id:cur,user:g("ssh_user"),port:g("ssh_port"),legacy:$("#ssh_legacy").checked,cols,rows})}catch(e){r={ok:false,error:e.message}}
 if(!r.ok){card.remove();m.className="bad";m.textContent="Error: "+r.error;return}
 m.className="ok";m.textContent="Opened below: click inside the terminal to type.";
 const t={tid:r.tid,vt:new VT(cols,rows),body,st,pos:0,alive:true,q:"",sending:false,raf:0};TERMS[r.tid]=t;
 st.textContent=r.command+" · click inside to type";
 bx.onclick=async()=>{if(t.alive){t.alive=false;await api("/api/term/close",{tid:t.tid});st.textContent="disconnected";bx.textContent="Close"}else{card.remove();delete TERMS[t.tid]}};
 body.addEventListener("keydown",e=>termKey(t,e));
 body.addEventListener("paste",e=>{e.preventDefault();termSend(t,(e.clipboardData.getData("text")||"").replace(/\r?\n/g,"\r"))});
 body.addEventListener("focus",()=>termDraw(t));body.addEventListener("blur",()=>termDraw(t));
 termDraw(t);body.focus();termPoll(t)}
function termDraw(t){if(t.raf)return;t.raf=requestAnimationFrame(()=>{t.raf=0;const vt=t.vt,b=t.body;
 const atEnd=b.scrollHeight-b.scrollTop-b.clientHeight<30,foc=document.activeElement===b;
 const sbh=vt.sb.slice(-1500).map(l=>'<div class="tl">'+vt.lineHtml(l,-1)+"</div>").join("");
 const scr=vt.scr.map((l,r)=>'<div class="tl">'+vt.lineHtml(l,t.alive&&vt.vis&&foc&&r===vt.y?Math.min(vt.x,vt.cols-1):-1)+"</div>").join("");
 b.innerHTML=sbh+scr;if(atEnd)b.scrollTop=b.scrollHeight})}
async function termPoll(t){while(TERMS[t.tid]===t){let r;
  try{r=await api("/api/term/read",{tid:t.tid,pos:t.pos})}catch(e){await new Promise(z=>setTimeout(z,1000));continue}
  if(!r.ok){t.alive=false;t.st.textContent="ended: "+r.error;break}
  if(r.data){t.vt.write(r.data);if(t.vt.out){termSend(t,t.vt.out);t.vt.out=""}termDraw(t)}t.pos=r.pos;
  if(!r.alive){t.alive=false;t.st.textContent="session ended"+(r.exit!=null?" (exit code "+r.exit+")":"")+" · press Disconnect to close";termDraw(t);break}}}
function termSend(t,s){if(!s||!t.alive)return;t.q+=s;if(t.sending)return;t.sending=true;
 (async()=>{while(t.q){const d=t.q;t.q="";try{await api("/api/term/write",{tid:t.tid,data:d})}catch(e){}}t.sending=false})()}
const TKEYS={Enter:"\r",Backspace:"\x7f",Tab:"\t",Escape:"\x1b",ArrowUp:"\x1b[A",ArrowDown:"\x1b[B",ArrowRight:"\x1b[C",ArrowLeft:"\x1b[D",
 Home:"\x1b[H",End:"\x1b[F",Delete:"\x1b[3~",Insert:"\x1b[2~",PageUp:"\x1b[5~",PageDown:"\x1b[6~",F1:"\x1bOP",F2:"\x1bOQ",F3:"\x1bOR",F4:"\x1bOS"};
function termKey(t,e){if(e.isComposing)return;
 if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="c"&&String(getSelection()).length)return;   // copy the selection
 if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="v")return;                                  // paste event sends it
 let s=null;
 if(TKEYS[e.key])s=(e.shiftKey&&e.key==="Tab")?"\x1b[Z":TKEYS[e.key];
 else if(e.ctrlKey&&!e.altKey&&e.key.length===1){const c=e.key.toUpperCase().charCodeAt(0);
  if(c>=64&&c<=95)s=String.fromCharCode(c-64);else if(e.key===" ")s="\x00"}
 else if(e.key.length===1&&!e.metaKey)s=(e.altKey?"\x1b":"")+e.key;
 if(s===null)return;e.preventDefault();termSend(t,s);t.body.scrollTop=t.body.scrollHeight}
let termRT=0;window.addEventListener("resize",()=>{clearTimeout(termRT);termRT=setTimeout(()=>{Object.values(TERMS).forEach(t=>{if(!t.alive)return;
 const c=termSize(t.body);if(c!==t.vt.cols){t.vt.resize(c,t.vt.rows);api("/api/term/resize",{tid:t.tid,cols:c,rows:t.vt.rows});termDraw(t)}})},300)});
async function sshOpen(){const m=$("#ssh_msg");m.className="muted";m.textContent="opening…";
 let r;try{r=await api("/api/ssh",{id:cur,user:g("ssh_user"),port:g("ssh_port"),legacy:$("#ssh_legacy").checked})}catch(e){r={ok:false,error:e.message}}
 m.className=r.ok?"ok":"bad";
 m.textContent=r.ok?(r.launched?"Opened a window titled 'SSH "+(dev()||{}).host+"': check the taskbar if you do not see it. Any connection error stays in that window.":"Run in a terminal: "+r.command):"Error: "+(r.error||"no answer");
 show(r,"SSH")}
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
 setBusy(c.label);const r=await api("/api/run",{id:cur,check:c.id,params:p,ack:!!($("#f5ack")&&$("#f5ack").checked)});show(r,c.label)}
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
 if(cols.includes("negate_destination"))return {t:"table",title,cols,data,wide:true};  // PAN / FortiGate policies: every column, in rule order (source, destination, service, ...)
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
 else if(s.t==="table"){const box=mk("div","tw"),t=mk("table",s.wide?"wide":null),h=mk("tr");
  s.cols.forEach(c=>h.appendChild(mk("th",null,hum(c))));t.appendChild(h);
  s.data.forEach(r=>{const tr=mk("tr");s.cols.forEach(c=>{const td=mk("td");
   if(c==="severity"&&r[c])td.appendChild(mk("span","sev-"+String(r[c]).toLowerCase(),String(r[c]).toUpperCase()));
   else td.appendChild(cellNode(r[c]));tr.appendChild(td)});t.appendChild(tr)});
  box.appendChild(t);w.appendChild(box)}
 else if(s.t==="list"){const u=mk("ul","sum");s.items.forEach(i=>u.appendChild(mk("li",null,i)));w.appendChild(u)}
 else if(s.lines){const b=mk("div","tx");s.lines.forEach(l=>b.appendChild(mk("div","logln",l)));w.appendChild(b)}
 else{const b=mk("div","tx");String(s.text).split("\n").forEach(l=>b.appendChild(mk("div","logln",l||" ")));w.appendChild(b)}
 return w}
// ---- Flow trace diagram: client -> Cloudflare -> FortiGate -> F5 -> Palo Alto -> server, with where it stops ----
const FD_ICON={
 client:'<rect x="-9" y="-8" width="18" height="12" rx="2"/><path d="M-4 8h8M0 4v4"/>',
 cloudflare:'<path d="M-9 5h17a4.5 4.5 0 0 0 0-9 6.5 6.5 0 0 0-12.4-1.6A4.6 4.6 0 0 0-9 5z"/>',
 fortigate:'<rect x="-9" y="-8" width="18" height="16" rx="1.5"/><path d="M-9-2.7h18M-9 2.7h18M-3-8v5.3M3-2.7v5.4M-3 2.7V8"/>',
 f5:'<circle cx="-6" cy="0" r="2.6"/><circle cx="7" cy="-6" r="2.2"/><circle cx="7" cy="0" r="2.2"/><circle cx="7" cy="6" r="2.2"/><path d="M-3.4 0H4.8M-3.6-1.2 4.9-5M-3.6 1.2 4.9 5"/>',
 paloalto:'<path d="M0-9 8-6v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10v-5z"/><path d="M-3.5 0l2.5 2.6 4.6-5"/>',
 nat:'<path d="M-9-4h13M1-7.5 4.5-4 1-.5M9 4H-4M-1 .5-4.5 4-1 7.5"/>',
 server:'<rect x="-8" y="-9" width="16" height="7" rx="1.5"/><rect x="-8" y="2" width="16" height="7" rx="1.5"/><path d="M-4.5-5.5h.1M-4.5 5.5h.1"/>'};
const FD_DARK={passed:"#2EE6C5",blocked:"#FF5C7A",unclear:"#FFB547",checked:"#7C6CFF","not connected":"#5d5a88",client:"#7C6CFF",server:"#7C6CFF",skipped:"#3a3866",nclink:"#8f8cb8",end:"#3b3970"};
const FD_LIGHT={passed:"#16a34a",blocked:"#dc2626",unclear:"#d97706",checked:"#0b6fd0","not connected":"#9aa5b4",client:"#6c3fc4",server:"#6c3fc4",skipped:"#c7cfdb",nclink:"#9aa5b4",end:"#cfd7e3"};
const isLight=()=>document.documentElement.dataset.theme==="light";
let FD_COL=isLight()?FD_LIGHT:FD_DARK;
function themeToggle(){const t=isLight()?"dark":"light";document.documentElement.dataset.theme=t;try{localStorage.setItem("theme",t)}catch(e){}
 FD_COL=t==="light"?FD_LIGHT:FD_DARK;try{renderOut()}catch(e){}}  // redraw diagrams/heatmaps in the new colours
function flowDiagram(p){
 const stages=p.stages||[],nodes=[{kind:"client",role:"Source",title:"Client",sub:p.client,state:"client"}];
 stages.forEach(s=>{const [role,vend]=String(s.layer).split(" · ");
  nodes.push({kind:s.vendor,role,title:vend||s.layer,sub:s.devices.length?s.devices.join(", "):"not connected",state:s.state,checks:s.checks,sees:s.sees})});
 nodes.push({kind:"server",role:"Destination",title:"Server",sub:(p.servers&&p.servers.length?p.servers.join(", "):p.target),state:"server"});
 // traffic gets as far as the first device that blocks it; after that the path is greyed out
 const stop=nodes.findIndex(n=>n.state==="blocked");
 const NW=168,NH=86,W=Math.max(1240,24+NW+(nodes.length-1)*190),gap=(W-24-NW)/(nodes.length-1),TOP=44,LOW=124,H=LOW+NH+44;
 const xs=nodes.map((_,i)=>12+i*gap),ys=nodes.map((_,i)=>i%2?LOW:TOP);
 const e=s=>esc(s),cut=(s,n)=>{s=String(s||"");return s.length>n?s.slice(0,n-1)+"…":s};
 let svg='<svg class="fdsvg" viewBox="0 0 '+W+' '+H+'"'+(W>1240?' style="min-width:'+Math.round(W*.72)+'px"':'')+' role="img" aria-label="Flow trace path"><defs>'+
  '<filter id="fdsh" x="-20%" y="-20%" width="140%" height="160%"><feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000" flood-opacity=".45"/></filter></defs>';
 for(let i=0;i<nodes.length-1;i++){
  const x1=xs[i]+NW,y1=ys[i]+NH/2,x2=xs[i+1],y2=ys[i+1]+NH/2,mx=(x1+x2)/2,d="M"+x1+" "+y1+" C"+mx+" "+y1+" "+mx+" "+y2+" "+x2+" "+y2;
  const after=stop>=0&&i>=stop,nx=nodes[i+1].state,col=nx==="blocked"?FD_COL.blocked:nx==="unclear"?FD_COL.unclear:nx==="not connected"?FD_COL.nclink:FD_COL.passed;
  svg+='<path d="'+d+'" class="fdbase"/>'+(after?"":'<path d="'+d+'" class="fdflow" style="stroke:'+col+'"/>')}
 nodes.forEach((n,i)=>{const x=xs[i],y=ys[i],c=FD_COL[n.state]||FD_COL.checked,dim=stop>=0&&i>stop,nc=n.state==="not connected",end=n.state==="client"||n.state==="server";
  svg+='<g class="fdnode'+(dim?" dim":"")+'" transform="translate('+x+' '+y+')"><title>'+e(n.role+" · "+n.title+" · "+n.sub+(n.sees&&n.sees.length?"\nsees: "+n.sees.join(", "):"")+(n.checks&&n.checks.length?"\n"+n.checks.join("\n"):""))+'</title>'+
   '<rect width="'+NW+'" height="'+NH+'" rx="14" class="fdcard'+(nc?" nc":"")+'" style="stroke:'+(end?FD_COL.end:c)+'" filter="url(#fdsh)"/>'+
   '<g transform="translate(27 '+(NH/2)+')"><circle r="17" class="fdic" style="stroke:'+c+'"/><g class="fdglyph" style="stroke:'+c+'">'+(FD_ICON[n.kind]||"")+'</g></g>'+
   '<text x="54" y="21" class="fdr">'+e(cut(n.role,22))+'</text><text x="54" y="39" class="fdt">'+e(cut(n.title,14))+'</text>'+
   '<text x="54" y="55" class="fds">'+e(cut(n.sub,19))+'</text>';
  if(!end)svg+='<g transform="translate(54 63)"><rect width="'+(n.state.length*6.2+14)+'" height="15" rx="7.5" style="fill:'+c+'22;stroke:'+c+'66"/>'+
   '<text x="7" y="11" class="fdpill" style="fill:'+c+'">'+e(n.state)+'</text></g>';
  // the addresses this device sees: above the top-row cards, below the bottom-row ones (clear of the lines)
  const see=n.sees&&n.sees[0]?n.sees[0].split(" -> "):null;
  if(see&&!dim){const ty=i%2?NH+16:-22;
   svg+='<text class="fdlab" x="'+(NW/2)+'" y="'+ty+'" text-anchor="middle">'+e(cut(see[0],24))+'</text>'+
    '<text class="fdlab" x="'+(NW/2)+'" y="'+(ty+13)+'" text-anchor="middle">→ '+e(cut(see[1]||"",24))+(n.sees.length>1?" +"+(n.sees.length-1):"")+'</text>'}
  svg+='</g>'});
 svg+='</svg>';
 const wrap=mk("div","fdwrap");wrap.innerHTML=svg;
 const leg=mk("div","fdleg");[["passed","allowed"],["blocked","blocks it"],["unclear","not conclusive / inferred"]].forEach(([k,t])=>{
  const s=mk("span");s.innerHTML='<i style="background:'+FD_COL[k]+'"></i>'+esc(t);leg.appendChild(s)});
 leg.appendChild(mk("span","muted","Next to each device: the source → destination it sees (after Cloudflare proxying, VIP mapping and SNAT). Hover a device for its checks."));
 wrap.appendChild(leg);return wrap}
function renderOut(){const box=$("#pretty");box.textContent="";if(!last)return;
 if(last.error){box.appendChild(mk("div","bad",last.error));return}
 if(last.path&&Array.isArray(last.path.stages))box.appendChild(flowDiagram(last.path));
 box.classList.toggle("tall",!!(last.dashboard||last.charts||last.acc||last.tiles||last.bars));
 if(Array.isArray(last.tiles)&&last.tiles.length)box.appendChild(tilesNode(last.tiles));
 if(Array.isArray(last.charts)&&last.charts.length&&last.bars)box.appendChild(chartsNode(last.charts,last.heat));
 if(Array.isArray(last.bars)&&last.bars.length)box.appendChild(barsNode(last.bars));
 if(last.dashboard)box.appendChild(dashNode(last.dashboard));
 if(last.acc)box.appendChild(accNode(last.acc));  // charts first; the tables below are the table view
 if(Array.isArray(last.charts)&&last.charts.length&&!last.bars)box.appendChild(chartsNode(last.charts,last.heat));
 buildSections(last.data).forEach(s=>box.appendChild(secNode(s)));
 if(!box.childNodes.length)box.appendChild(mk("div","nv","Nothing to show for this check."));
 // Blocked / denied traffic in red: table rows with a deny-type cell, and log lines whose action precedes " -> ".
 const DENY=/^(deny|denied|drop|dropped|block|blocked|block-\w+|reset|reset-\w+|blackhole|sinkhole)$/i,DENYW=/\b(deny|denied|drop|dropped|block|blocked|block-\w+|reset-\w+)\b/i;
 box.querySelectorAll("tr:not(:first-child)").forEach(tr=>{if([...tr.children].some(td=>DENY.test(td.textContent.trim())))tr.classList.add("deny")});
 box.querySelectorAll(".logln").forEach(l=>{if(DENYW.test(l.textContent.split(" -> ")[0]))l.classList.add("deny")});
 // Expired certificates: the row when a cell says EXPIRED, only the chip when one entry of a list is expired
 box.querySelectorAll("td").forEach(td=>{const t=td.textContent.trim();if(t==="EXPIRED"){td.parentElement.classList.add("deny");return}
  if(/\bEXPIRED\b/.test(t)&&!td.querySelector(".chip")){td.textContent="";t.split(/, (?=\/)/).forEach(x=>td.appendChild(mk("div",/\bEXPIRED\b/.test(x)?"expired":"",x)))}});
 box.querySelectorAll(".chip").forEach(c=>{if(/\bEXPIRED\b/.test(c.textContent))c.classList.add("expired")});
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
 if(v==="paloalto"||v==="fortigate"){const pan=v==="paloalto";
  box.innerHTML='<div class="card"><h3>Policy lookup · by IP, by '+(pan?'rule name, or list all security rules':'policy name or ID, or list all firewall policies')+'</h3><div class="row3">'+
  (pan?fld("pl_q","IP, subnet or rule name (blank = all rules)","10.1.1.10, 10.1.2.32/28 or allow-web")+fld("pl_vsys","vsys","vsys1","vsys1")
      :fld("pl_q","IP, subnet, policy name or ID (blank = all policies)","10.1.1.10, 10.1.2.32/28, web-in or 12")+fld("pl_vdom","VDOM (optional)","root"))+'</div>'+
  '<div class="row" style="margin-top:10px"><button class="primary" onclick="fwLookup()">Look up</button><button onclick="fwLookup(true)">List all policies</button></div>'+
  '<p class="muted" style="margin:8px 0 0">An IP or subnet shows the address objects and '+(pan?'rules':'policies')+' that reference or overlap it; '+(pan?'any other text finds rules whose name contains it':'a number finds that policy ID, any other text finds policies whose name contains it')+'. Reads the running config (read-only).</p></div>'+
  '<div class="card"><h3>Flow check · which '+(pan?'rule':'policy')+' allows or blocks source → destination</h3><div class="row3">'+
  fld("fc_src","Source IP","10.1.1.10")+fld("fc_dst","Destination IP","203.0.113.10")+fld("fc_port","Destination port (optional)","443")+
  '<div><label>Protocol</label><select id="fc_proto"><option>tcp</option><option>udp</option><option>icmp</option></select></div>'+
  (pan?fld("fc_from","From zone (optional)","trust")+fld("fc_to","To zone (optional)","untrust")
      :fld("fc_if","Ingress interface (optional, auto from route)","port1"))+'</div>'+
  '<div class="row" style="margin-top:10px"><button class="primary" onclick="flowCheck()">Check flow</button></div>'+
  '<p class="muted" style="margin:8px 0 0">'+(pan?"Runs 'test security-policy-match' (as Device &gt; Test Policy Match), so Panorama-pushed rules are covered. Leave the zones blank to let the firewall evaluate all rules; vsys is taken from the box above.":
   "Runs FortiOS policy lookup (as Policy &amp; Objects &gt; Policy Lookup). Leave the ingress interface blank to use the interface of the route back to the source; VDOM is taken from the box above.")+
  ' Read-only.</p></div>';return}
 let h='<div class="card"><h3>IP lookup · pools, nodes, virtual servers, data groups, local traffic policies</h3><div class="row3">'+fld("ip_ip","IP address","203.0.113.7");
 h+='</div><div style="margin-top:10px"><button class="primary" onclick="ipLookup()">Check</button></div></div>';
 if(v==="f5")h+='<div class="card"><h3>Hostname lookup · virtual server and local traffic policy</h3><div class="row3">'+fld("fh_host","Hostname","app.example.com")+
  '</div><div style="margin-top:10px"><button class="primary" onclick="f5Host()">Find virtual server / policy</button></div></div>';
 box.innerHTML=h}
async function f5Host(){setBusy("hostname lookup");
 const r=await api("/api/f5host",{id:cur,hostname:g("fh_host")});show(r,"hostname lookup")}
async function ipLookup(){setBusy("IP lookup");
 const r=await api("/api/ipcheck",{id:cur,ip:g("ip_ip"),mode:"refs",vsys:g("ip_vsys"),vdom:g("ip_vdom")});show(r,"IP lookup")}
async function flowCheck(){if(!g("fc_src").trim()||!g("fc_dst").trim())return show({ok:false,error:"enter both the source and the destination IP"},"flow check");
 setBusy("flow check");
 show(await api("/api/ipcheck",{id:cur,mode:"verdict",ip:g("fc_src").trim(),peer:g("fc_dst").trim(),role:"source",port:g("fc_port"),proto:g("fc_proto"),
  from:g("fc_from"),to:g("fc_to"),srcintf:g("fc_if"),vsys:g("pl_vsys"),vdom:g("pl_vdom")}),"flow check")}
async function fwLookup(all){const q=g("pl_q").trim(),vs=g("pl_vsys"),vd=g("pl_vdom");
 if(all||!q){setBusy("all policies");return show(await api("/api/policy",{id:cur,all:true,vsys:vs,vdom:vd}),"all policies")}
 if(/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(q)||/^[0-9a-f]*:[0-9a-f]*:[0-9a-f:.]*(\/\d{1,3})?$/i.test(q)){setBusy("IP lookup");
  return show(await api("/api/ipcheck",{id:cur,ip:q,mode:"refs",vsys:vs,vdom:vd}),"IP lookup")}
 setBusy("policy search");show(await api("/api/policy",{id:cur,name:q,vsys:vs,vdom:vd}),"policy search")}
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
  '<div class="grp" style="margin-top:14px">Search requests</div><div class="row3">'+fld("asm_ip","Client IP","203.0.113.7")+
  fld("asm_tci","True-Client-IP","198.51.100.9")+fld("asm_host","Hostname contains","app.example.com")+fld("asm_url","URL path contains","/login")+
  fld("asm_hn","HTTP header name","X-Request-ID")+fld("asm_hv","Header value contains","abc123")+
  sel("asm_st","Status",["","blocked","alerted","passed"],"")+fld("asm_top","Max rows","50","50")+fld("asm_hscan","Entries to scan","1000","1000")+sel("asm_w","Time range",WITHIN,"any time")+
  '</div><div style="margin-top:8px"><button class="primary" onclick="asmLookup(\'search\')">Search requests</button> '+
  '<p class="muted" style="margin:6px 0 0">Fill any combination. Client IP is the address the F5 sees; True-Client-IP is the real client behind Cloudflare. '+
  'Header name and value are optional (blank value = any); with a header name the result also shows its value and the POST body, '+
  'and "Entries to scan" limits that search. Time range goes back at most 1 day.</p></div>'+
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
async function backup(){setBusy("configuration backup (F5 archives can take several minutes)");
 const r=await api("/api/backup",{id:cur,ack:!!($("#bk_ack")&&$("#bk_ack").checked),vdom:g("bk_vdom")});show(r,"configuration backup");
 if(r&&r.ok&&r.download){const a=document.createElement("a");a.href=r.download+"?t="+T;a.click()}}
async function f5Sync(){setBusy("config sync review");
 const r=await api("/api/f5sync",{id:cur,hours:g("sy_h"),count:g("sy_n")});show(r,"config sync review")}
async function adminAudit(){setBusy("admin audit (can take up to a minute)");
 const r=await api("/api/adminaudit",{id:cur,user:g("au_user"),action:g("au_act"),count:g("au_n"),period:g("au_period"),within:g("au_w"),log_source:g("au_src"),vdom:g("au_vdom")});show(r,"admin audit")}
async function appsec(c){const names={waf:"coverage",ssl:"SSL posture"};setBusy(names[c]);
 const r=await api("/api/appsec",{id:cur,check:c,vsys:g("as_vsys"),vdom:g("as_vdom"),days:g("as_days")});show(r,names[c])}
async function asmLookup(m){
 if(m==="search"&&g("asm_hv").trim()&&!g("asm_hn").trim())return show({ok:false,error:"enter the HTTP header name for the header value"},"ASM request search");
 setBusy("ASM request log");
 if(m==="search"&&g("asm_hn").trim()){const r=await api("/api/f5asm",{id:cur,mode:"header",header_name:g("asm_hn"),header_value:g("asm_hv"),
  hostname:g("asm_host"),ip:g("asm_ip"),header_ip:g("asm_tci"),url:g("asm_url"),status:g("asm_st"),top:g("asm_top"),scan:g("asm_hscan"),within:g("asm_w")});
  return show(r,"ASM requests · header "+g("asm_hn"))}
 const r=await api("/api/f5asm",{id:cur,mode:m,support_id:g("asm_sid"),ip:g("asm_ip"),header_ip:g("asm_tci"),hostname:g("asm_host"),url:g("asm_url"),status:m==="tophosts"?g("asm_tst"):g("asm_st"),top:g("asm_top"),scan:g("asm_scan"),within:m==="tophosts"?g("asm_tw"):m==="supportid"?g("asm_sw"):g("asm_w")});
 show(r,m==="supportid"?"support ID lookup":m==="tophosts"?"top hostnames by violations":"ASM request search")}
const CFW=["last 15 minutes","last hour","last 6 hours","last 12 hours","last 24 hours","last 3 days","last 7 days","last 30 days"];
const CF_ACT=["","block","managed_challenge","challenge","jschallenge","log","skip","allow","bypass","connection_close"];
const CF_EVBY=["action","source","rule","client IP","host","path","country","ASN","user agent","colo","time"];
const CF_HTBY=["host","edge status","origin status","edge + origin status","cache status","client IP","path","country","ASN","user agent","colo","security action","TLS version","HTTP version","time"];
const CF_ST=["","2xx","3xx","4xx","5xx","4xx + 5xx","origin errors (520-527)"];
function renderCf(){const box=$("#cftools");box.innerHTML="";const d=dev();if(!d||d.vendor!=="cloudflare")return;
 let h='';   // no scope card: every lookup uses all zones, the last 24 hours, no F5 cross-check
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
  '<p class="muted" style="margin:8px 0 0">Edge TTFB and origin (e.g. F5) response time: p50 / p95 / p99, a timeline, breakdowns by status, cache, colo and method, and the slowest requests with DNS / TCP / TLS / header timings to the origin. Covers the last 24 hours.</p></div>';
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
  '</div><div style="margin-top:8px"><button class="primary" onclick="cfAudit()">Search audit log</button> <span class="muted">(all zones, last 24 hours)</span></div></div>';
 box.innerHTML=h}
async function cfRun(mode,label,extra){setBusy(label);
 const r=await api("/api/cf",Object.assign({id:cur,mode},extra));show(r,label)}
function cfIp(){cfRun("ip","Cloudflare IP investigation",{ip:g("cf_ip")})}
function cfHost(){cfRun("host","Cloudflare hostname investigation",{host:g("cf_host"),days:g("cf_days")})}
function cfRay(){cfRun("ray","Cloudflare Ray ID lookup",{ray:g("cf_ray")})}
function cfWhois(){cfRun("whois","WHOIS",{ip:g("cf_w_ip"),host:g("cf_w_host"),days:g("cf_days")})}
// The trace follows the request into the connected F5 (the first one, if several are connected).
function cfTraceBy(m,label,extra){const f5=devices.find(x=>x.vendor==="f5");
 setBusy(label+(f5?": Cloudflare → F5 "+f5.name+" (can take a few minutes)":": Cloudflare only (no F5 connected)"));
 api("/api/cf",Object.assign({id:cur,mode:m,f5:f5?f5.id:"",window:g("cf_win")},extra)).then(r=>show(r,label))}
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
function chartsNode(list,heat){const grid=mk("div","dgrid");grid.style.marginBottom="16px";
 grid.style.gridTemplateColumns="repeat(auto-fill,minmax(min(100%,520px),1fr))";  // a lone chart keeps a column's width instead of stretching
 list.forEach(c=>grid.appendChild(dChart(c.title,c.t,c.series.map(([n,v],i)=>({name:n,color:DC[i%DC.length],vals:v})),
  {fmt:DFMT[c.fmt]||dNum,noTotal:c.fmt!=="num",gaps:true})));
 (heat||[]).forEach(h=>grid.appendChild(dHeat(h)));return grid}
// Heatmap: one row per core, one column per time bucket, colour = load (dark = idle, blue -> amber -> red)
function dHeatColor(v){if(v==null)return "transparent";const lt=isLight();if(v<1)return lt?"#eef2f7":"#1d1b3a";
 const st=[[0,lt?[226,234,244]:[29,27,58]],[30,[57,135,229]],[70,[201,133,0]],[100,[217,89,38]]];v=Math.min(100,v);
 for(let i=1;i<st.length;i++)if(v<=st[i][0]){const [a,ca]=st[i-1],[b,cb]=st[i],f=(v-a)/(b-a);
  return "rgb("+ca.map((x,k)=>Math.round(x+(cb[k]-x)*f)).join(",")+")"}return "rgb(217,89,38)"}
function dHeat(h){const card=mk("div","dcard dwide");card.appendChild(mk("div","sec",h.title));
 const rows=h.rows,n=h.t.length;if(!rows.length||!n){card.appendChild(mk("div","nv","No data."));return card}
 const W=1280,L=64,R=8,T=4,rh=Math.max(5,Math.min(40,200/rows.length)),H=T+rh*rows.length+24,cw=(W-L-R)/n,sl=dShort(h.t);
 let s='<svg viewBox="0 0 '+W+' '+H+'" role="img" aria-label="'+esc(h.title)+'">';
 rows.forEach(([name,vals],r)=>{const y=T+r*rh;
  if(rh>=9||r%Math.ceil(9/rh)===0)s+='<text x="'+(L-6)+'" y="'+(y+rh/2+4).toFixed(1)+'" text-anchor="end" font-size="11" fill="#8f8cb8">'+esc(name)+'</text>';
  vals.forEach((v,i)=>{s+='<rect x="'+(L+i*cw).toFixed(1)+'" y="'+y.toFixed(1)+'" width="'+Math.max(0.5,cw-(cw>4?1:0)).toFixed(1)+'" height="'+Math.max(1,rh-1).toFixed(1)+'" fill="'+dHeatColor(v)+'"><title>'+esc(name+" · "+h.t[i]+": "+(v==null?"n/a":v+"%"))+'</title></rect>'})});
 const ticks=Math.min(6,n);for(let k=0;k<ticks;k++){const i=Math.round(k*(n-1)/Math.max(1,ticks-1)),last=k===ticks-1&&ticks>1;
  s+='<text x="'+(last?W-R:L+cw*i+cw/2).toFixed(1)+'" y="'+(H-6)+'" text-anchor="'+(last?"end":"middle")+'" font-size="12" fill="#8f8cb8">'+esc(sl[i])+'</text>'}
 const box=mk("div");box.innerHTML=s+'</svg>';card.appendChild(box);
 const lg=mk("div","dleg");[["idle",0],["30%",30],["70%",70],["100%",100]].forEach(([l,v])=>{const x=mk("span"),sw=mk("i");sw.style.background=dHeatColor(v||0.5);
  if(!v)sw.style.background=dHeatColor(0);x.appendChild(sw);x.appendChild(document.createTextNode(l));lg.appendChild(x)});card.appendChild(lg);
 return card}
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
 else series.forEach(sr=>{let seg=[];const flush=()=>{if(seg.length)s+='<polyline points="'+seg.join(" ")+'" fill="none" stroke="'+sr.color+'" stroke-width="2" stroke-linejoin="round"/>';seg=[]};
  sr.vals.forEach((v,i)=>{if(v==null&&o.gaps)return flush();seg.push((L+step*i+step/2).toFixed(1)+","+y(v||0).toFixed(1))});flush()});
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
// ---- ACC (PAN-OS / FortiGate): Application Command Center-style dashboard built from the firewall's logs ----
// [filter key, PAN-OS label, FortiGate label, placeholder]
const ACC_F=[["src","Source IP","Source IP","10.1.1.10 or 10.1.0.0/16"],["dst","Destination IP","Destination IP","198.51.100.9"],
 ["app","Application","Application","ssl"],["user","User","User","corp\alice"],["rule","Rule","Policy ID or name","allow-web"],
 ["from_zone","Source zone","Source interface","trust"],["to_zone","Destination zone","Destination interface","untrust"],["port","Destination port","Destination port","443"]];
const ACC_C={allowed:DC[0],blocked:DC[1],critical:DC[1],high:DC[3],medium:DC[4],low:DC[0],informational:DOTHER};
let accTab=0;
function renderAcc(){const box=$("#acc");box.innerHTML="";const d=dev();if(!d||(d.vendor!=="paloalto"&&d.vendor!=="fortigate"))return;const pan=d.vendor==="paloalto";
 box.innerHTML='<div class="card"><h3>ACC · Application Command Center · read-only, from the logs</h3><div class="row3">'+
  sel("acc_period","Time range",["last-15-minutes","last-hour","last-6-hrs","last-12-hrs","last-24-hrs","last-7-days"],"last-hour")+
  sel("acc_sort","Rank network lists by",["bytes","sessions"],"bytes")+fld("acc_scan","Log entries to read per log type","5000","5000")+
  (pan?"":sel("acc_src","Log source",["disk","memory","fortianalyzer"],"disk")+fld("acc_vdom","VDOM (optional)","root"))+
  '</div><div class="grp">Global filters (optional · click any entry in the dashboard to add one)</div><div class="row3">'+
  ACC_F.map(([k,pl,fl,ph])=>fld("acc_f_"+k,pan?pl:fl,ph)).join("")+
  '</div><div class="row" style="margin-top:10px;flex-wrap:wrap"><button class="primary" onclick="accRun()">Run ACC</button><button onclick="accClear()">Clear filters &amp; run</button></div>'+
  '<p class="muted" style="margin:8px 0 0">Reads the newest '+(pan?'traffic, threat and URL':'traffic, IPS, antivirus and web-filter')+
  ' logs in the time range (filters are applied by the firewall) and summarises them: network, threat, blocked and URL activity. '+
  'On a busy firewall the read limit can cover less than the whole range; the output says how much was covered.</p></div>'}
// Arc gauge (240 degrees) for a percentage tile: green, amber at the warning threshold, red at the high one
function dGauge(v,kind){const cx=60,cy=56,r=44,A0=210,SW=240,p=Math.max(0,Math.min(100,v))/100;
 const pt=a=>[(cx+r*Math.cos(a*Math.PI/180)).toFixed(2),(cy-r*Math.sin(a*Math.PI/180)).toFixed(2)];
 const arc=(a1,a2)=>{const s=pt(a1),e=pt(a2);return "M"+s[0]+" "+s[1]+" A"+r+" "+r+" 0 "+(a1-a2>180?1:0)+" 1 "+e[0]+" "+e[1]};
 const col=kind==="bad"?DC[1]:kind==="warn"?DC[3]:DC[2];
 return '<svg viewBox="0 0 120 92" role="img" aria-label="'+v.toFixed(1)+'%">'+
  '<path d="'+arc(A0,A0-SW)+'" fill="none" stroke="#2a2850" stroke-width="9" stroke-linecap="round"/>'+
  (p>0.004?'<path d="'+arc(A0,A0-SW*p)+'" fill="none" stroke="'+col+'" stroke-width="9" stroke-linecap="round"/>':'')+
  '<text x="'+cx+'" y="'+(cy+7)+'" text-anchor="middle" font-size="19" font-weight="600" fill="'+col+'">'+v.toFixed(1)+'%</text>'+
  '<text x="'+(cx-34)+'" y="88" text-anchor="middle" font-size="9" fill="#8f8cb8">0</text><text x="'+(cx+34)+'" y="88" text-anchor="middle" font-size="9" fill="#8f8cb8">100</text></svg>'}
function tilesNode(list){const w=mk("div","dtiles");w.style.marginBottom="12px";
 list.forEach(t=>{const x=mk("div","dtile"+(t.kind?" "+t.kind:""));x.appendChild(mk("div","dl",t.label));
  if(t.fmt==="pct"&&t.value!=null){const gg=mk("div","dgauge");gg.innerHTML=dGauge(+t.value,t.kind);x.appendChild(gg)}
  else x.appendChild(mk("div","dv",t.value==null?"n/a":t.fmt==="pct"?(+t.value).toFixed(1)+"%":(DFMT[t.fmt]||dNum)(t.value)));
  if(t.sub)x.appendChild(mk("div","dl",t.sub));
  if(t.spark&&t.spark.length>1){const sp=mk("div");sp.innerHTML=dSpark(t.spark);x.appendChild(sp)}w.appendChild(x)});return w}
// ---- AI assistant (local LLM): explain / chat about the current output, or let the model run read-only checks ----
let aiHist=[];
async function aiInit(){const r=await api("/api/llm/config",{});if(!r.ok)return;
 $("#ai_url").value=r.url;$("#ai_model").value=r.model||"";aiRoute(r);$("#ai_budget").value=r.budget;
 $("#ai_key").placeholder=r.has_key?"(set · type to replace)":"(none)";if(!r.model)$("#ai_cfg").open=true;aiStatus(r.model);aiWelcome()}
function aiRoute(r){if(r&&r.route)$("#ai_route").textContent="Data goes to: "+r.route+" · approved servers: "+(r.approved||[]).join(", ")+" or this PC"}
function aiStatus(m){$("#ai_sub").textContent=m?"online · "+m:"local LLM · no model set";$("#ai_by").textContent=m||"local LLM";$("#ai_av").classList.toggle("off",!m)}
function aiCfg(){const c=$("#ai_cfg");c.open=!c.open;if(c.open)$("#aicard .aibody").scrollTop=0}
function aiWelcome(){if($("#ai_log").children.length)return;
 aiAdd("bot","Welcome to the ITSec assistant 👋 How can I help?\n\nI can explain the output on screen, answer questions about it, or run **read-only** checks on all the connected devices (firewalls, F5, Cloudflare) to answer any question. Just type it and press Enter.",{welcome:true})}
// Enter / Send: run read-only checks on all connected devices whenever one is connected (the output on screen is still sent as context);
// without a device it can only talk about the output.
function aiSend(){aiAsk(devices.length?"agent":"chat")}
async function aiSave(loud){const r=await api("/api/llm/config",{set:true,url:g("ai_url"),model:g("ai_model"),key:g("ai_key"),
  budget:g("ai_budget")});const m=$("#ai_cfgmsg");
 if(r.ok){aiStatus(r.model);aiRoute(r);$("#ai_key").value="";$("#ai_key").placeholder=r.has_key?"(set · type to replace)":"(none)";if(loud){m.className="ok";m.textContent="saved · "+(r.model||"no model picked yet")}}
 else{m.className="bad";m.textContent="error: "+r.error;$("#ai_cfg").open=true}return r.ok}
async function aiModels(){if(!await aiSave(false))return;const m=$("#ai_cfgmsg");m.className="muted";m.textContent="asking the model server…";
 const r=await api("/api/llm/models",{});if(!r.ok){m.className="bad";m.textContent="error: "+r.error;return}
 if(r.url)$("#ai_url").value=r.url;const dl=$("#ai_models");dl.innerHTML="";r.models.forEach(x=>{const o=document.createElement("option");o.value=x;dl.appendChild(o)});
 m.className=r.models.length?"muted":"bad";m.textContent=r.models.length?"Models on the server (click one to use it):":"No models on the server. Pull one first, e.g. ollama pull qwen2.5:7b";
 if(!g("ai_model")&&r.models[0]){$("#ai_model").value=r.models[0];await aiSave(false)}aiModelList(r.models)}
function aiModelList(ms){const box=$("#ai_mlist");box.innerHTML="";
 ms.forEach(x=>{const b=mk("button",x===g("ai_model")?"cur":"",(x===g("ai_model")?"✓ ":"")+x);
  b.onclick=async()=>{$("#ai_model").value=x;if(await aiSave(false)){aiModelList(ms);const m=$("#ai_cfgmsg");m.className="ok";m.textContent="Using "+x+" (saved)"}};box.appendChild(b)})}
function aiMd(t){const out=[];let inCode=false,code=[],list=null;
 const inl=s=>esc(s).replace(/`([^`]+)`/g,"<code>$1</code>").replace(/\*\*([^*]+)\*\*/g,"<b>$1</b>");
 const endList=()=>{if(list){out.push("<ul>"+list.join("")+"</ul>");list=null}};
 String(t||"").split("\n").forEach(l=>{
  if(/^\s*```/.test(l)){if(inCode){out.push("<pre>"+esc(code.join("\n"))+"</pre>");code=[];inCode=false}else{endList();inCode=true}return}
  if(inCode){code.push(l);return}
  const m=l.match(/^\s*(?:[-*]|\d+[.)])\s+(.*)/);if(m){(list=list||[]).push("<li>"+inl(m[1])+"</li>");return}
  endList();const h=l.match(/^#{1,6}\s+(.*)/);if(h){out.push('<div class="aih">'+inl(h[1])+"</div>");return}
  if(l.trim())out.push("<p>"+inl(l)+"</p>")});
 if(inCode)out.push("<pre>"+esc(code.join("\n"))+"</pre>");endList();return out.join("")}
function aiRow(kind,d){const row=mk("div","airow "+(kind==="user"?"user":"bot"));if(kind!=="user")row.appendChild(mk("span","aiav","✦"));row.appendChild(d);return row}
function aiAdd(kind,text,r){const box=$("#ai_log"),d=mk("div","aimsg "+kind);
 if(kind==="bot"&&r&&r.welcome)d.innerHTML=aiMd(text);
 else if(kind==="bot"){d.innerHTML=aiMd(text);
  (r.steps||[]).forEach(s=>{const x=mk("div","aistep");x.appendChild(mk("span",s.ok?"ok":"bad",s.ok?"✓":"✕"));
   x.appendChild(mk("code",null,s.call));if(s.verdict||s.error)x.appendChild(mk("span","muted",s.verdict||s.error));
   if(s.result){const b=mk("button",null,"show");b.onclick=()=>{show(s.result,"AI ran "+s.call);$("#outcard").scrollIntoView({behavior:"smooth"})};x.appendChild(b)}
   d.insertBefore(x,d.firstChild)});
  d.appendChild(mk("div","aimeta",r.model+" · "+(r.ms/1000).toFixed(1)+" s"+(r.steps&&r.steps.length?" · "+r.steps.length+" check(s) run":"")+
   (r.trimmed?" · output was trimmed to fit the context budget":"")+(r.usage&&r.usage.total_tokens?" · "+r.usage.total_tokens+" tokens":"")+(r.usage&&r.usage.num_ctx?" · context window "+r.usage.num_ctx:"")));
  if(r.warning)d.insertBefore(mk("div","aiwarn","⚠ "+r.warning),d.firstChild);
  if(r.sent){const lk=mk("span","aimeta lnk"," data sent to the model ("+r.sent.length.toLocaleString()+" characters)");lk.style.cursor="pointer";lk.style.color="var(--mint)";
   const pre=mk("pre",null,r.sent);pre.style.display="none";pre.style.maxHeight="300px";pre.style.overflow="auto";
   lk.onclick=()=>{pre.style.display=pre.style.display?"":"none"};d.appendChild(lk);d.appendChild(pre)}
  if(r.raw){const lk=mk("div","aimeta lnk","model reply (raw)");lk.style.cursor="pointer";
   const pre=mk("pre",null,r.raw);pre.style.display="none";pre.style.maxHeight="300px";pre.style.overflow="auto";
   lk.onclick=()=>{pre.style.display=pre.style.display?"":"none"};d.appendChild(lk);d.appendChild(pre)}}
 else d.textContent=text;box.appendChild(aiRow(kind,d));aiScroll()}
function aiScroll(){const sc=$("#aicard .aibody");sc.scrollTop=sc.scrollHeight}
function aiToggle(force){const c=$("#aicard"),open=force==null?c.hidden:!!force;c.hidden=!open;$("#aifab").classList.toggle("on",open);
 try{localStorage.setItem("ai_open",open?"1":"")}catch(e){}if(open)setTimeout(()=>$("#ai_q").focus(),0)}
document.addEventListener("keydown",e=>{if(e.key==="Escape"&&!$("#aicard").hidden)aiToggle(false)});
function aiClear(){aiHist=[];$("#ai_log").innerHTML="";aiWelcome()}
async function aiAsk(mode,qx,sx){const q=qx||g("ai_q").trim();
 if(mode!=="explain"&&!q)return aiAdd("err","Type a question first.");
 if(mode!=="agent"&&!last)return aiAdd("err","Run a check first: there is no output to talk about yet.");
 if(mode==="agent"&&!devices.length)return aiAdd("err","Connect a device first: the checks run on the connected devices.");
 if(!await aiSave(false))return;
 if(mode==="explain"){aiHist=[];$("#ai_log").innerHTML=""}
 const shown=sx||q||"Explain the current output ("+(lastCtx.label||"output")+")";
 aiAdd("user",shown+(mode==="agent"?"  · may run read-only checks on the connected devices":mode==="chat"?"  · answers from the output on screen only":""));
 $("#ai_q").value="";
 // a visible "waiting" bubble with a timer; the buttons stay disabled so the same question is not sent twice
 const wait=mk("div","aimsg bot aiwait");wait.innerHTML='<span class="aidots"><i></i><i></i><i></i></span>';
 const t0=Date.now(),btns=[...document.querySelectorAll("#ai_chips button,#ai_send")],card=$("#aicard"),wrow=aiRow("bot",wait);
 const tick=()=>{wait.title=Math.round((Date.now()-t0)/1000)+" s"};
 tick();$("#ai_log").appendChild(wrow);card.classList.add("busy");aiScroll();const iv=setInterval(tick,1000);btns.forEach(b=>b.disabled=true);
 let r;try{r=await api("/api/llm/chat",{id:cur,mode,question:q,history:aiHist,context:last,label:lastCtx.label,device:lastCtx.device,time:lastCtx.time})}
 catch(e){r={ok:false,error:"no answer from the console: "+e.message+" (is netops_console.py still running?)"}}
 finally{clearInterval(iv);wrow.remove();card.classList.remove("busy");btns.forEach(b=>b.disabled=false)}
 if(!r.ok)return aiAdd("err",r.error||"error");
 aiAdd("bot",r.answer,r);aiHist.push({role:"user",content:shown},{role:"assistant",content:r.answer})}
// Packet capture: the file goes to the console (memory only), which sends back a summary; that summary becomes the
// current output, so Explain / Ask / Ask & run checks all work on it. The model never gets the packets themselves.
const PCAP_Q="Analyse this packet capture (a summary the console made from the capture file). Say: 1) what traffic it shows "+
 "(main conversations and protocols); 2) every problem with its evidence: failed or reset TCP connections and which side sent the reset, "+
 "retransmissions, slow handshakes, zero windows, DNS errors or unanswered queries, TLS alerts with the server name, ICMP unreachable / "+
 "fragmentation needed, ARP conflicts; 3) the most likely cause; 4) what to check next (which side or device, and which console check). "+
 "Quote IPs, ports, names and counts exactly as they appear in the data; if the capture looks healthy, say so.";
async function aiPcap(f){if(!f)return;aiToggle(true);
 const mb=(f.size/1048576).toFixed(1);
 if(f.size>64*1048576)return aiAdd("err",f.name+" is "+mb+" MB; the limit is 64 MB. Cut it down first (Wireshark: File > Export Specified Packets, or editcap).");
 aiAdd("user","📎 "+f.name+" ("+mb+" MB)");
 const wait=mk("div","aimsg bot aiwait");wait.innerHTML='<span class="aidots"><i></i><i></i><i></i></span> reading the capture…';const wrow=aiRow("bot",wait);
 $("#ai_log").appendChild(wrow);aiScroll();
 let r;try{const res=await fetch("/api/pcap",{method:"POST",headers:{"X-Token":T,"X-Filename":encodeURIComponent(f.name),"Content-Type":"application/octet-stream"},body:f});r=await res.json()}
 catch(e){r={ok:false,error:"upload failed: "+e.message}}
 finally{wrow.remove()}
 if(!r.ok)return aiAdd("err",r.error||"could not read the capture");
 show(r,"Packet capture "+f.name);lastCtx.device="";aiHist=[];
 const s=r.summary||[],d=mk("div","aimsg bot");
 d.innerHTML=aiMd("Capture **"+f.name+"** read: "+(s[0]||"")+".\n\n"+(s.length>1?"Found:\n"+s.slice(1,7).map(x=>"- "+x).join("\n")+(s.length>7?"\n- and "+(s.length-7)+" more in the Output panel":""):"No obvious problems found.")+
  "\n\nThe full summary is in the Output panel. Ask me anything about it, or:");
 const b=mk("button",null,"Analyse this capture");b.style.marginTop="8px";b.onclick=()=>aiAsk("chat",PCAP_Q,"Analyse the capture "+f.name);
 d.appendChild(b);$("#ai_log").appendChild(aiRow("bot",d));aiScroll()}
document.addEventListener("dragover",e=>{if(e.target.closest&&e.target.closest("#aicard"))e.preventDefault()});
document.addEventListener("drop",e=>{if(!(e.target.closest&&e.target.closest("#aicard")))return;e.preventDefault();
 const f=e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files[0];if(f)aiPcap(f)});
document.addEventListener("keydown",e=>{if(e.target&&e.target.id==="ai_q"&&e.key==="Enter"&&!e.shiftKey&&!e.isComposing){e.preventDefault();if(!$("#ai_send").disabled)aiSend()}});
document.addEventListener("input",e=>{if(e.target&&e.target.id==="ai_q"){e.target.style.height="auto";e.target.style.height=Math.min(e.target.scrollHeight+2,140)+"px";e.target.style.overflowY=e.target.scrollHeight>138?"auto":"hidden"}});
function barsNode(list){const grid=mk("div","dgrid tops");grid.style.marginBottom="16px";
 list.forEach(b=>{const card=mk("div","dcard");card.appendChild(mk("div","sec",b.title));
  if(!b.rows.length){card.appendChild(mk("div","nv","No data."));grid.appendChild(card);return}
  const f=b.fmt==="pct"?(v=>(+v||0).toFixed(1)+"%"):(DFMT[b.fmt]||dNum),m=b.fmt==="pct"?Math.max(100,...b.rows.map(r=>r[1])):Math.max(...b.rows.map(r=>r[1]),1),gr=mk("div","dtop");
  b.rows.forEach(([name,v])=>{const nm=mk("div","dn",name);nm.title=name;const bar=mk("div","db"),fill=mk("span");
   fill.style.width=(100*v/m).toFixed(1)+"%";
   if(/^idle$|^not resident/.test(name))fill.style.background=DOTHER;else if(b.fmt==="pct"&&v>=80)fill.style.background=v>=90?DC[1]:DC[3];
   bar.appendChild(fill);gr.appendChild(nm);gr.appendChild(bar);gr.appendChild(mk("div","dvv",f(v)))});
  card.appendChild(gr);grid.appendChild(card)});return grid}
function accFilt(){const f={};ACC_F.forEach(([k])=>{const v=g("acc_f_"+k).trim();if(v)f[k]=v});return f}
async function accRun(){const f=accFilt(),ks=Object.keys(f);
 setBusy("ACC (reads up to "+g("acc_scan")+" log entries per log type; can take a minute)");
 const r=await api("/api/acc",{id:cur,period:g("acc_period"),sort:g("acc_sort"),scan:g("acc_scan"),log_source:g("acc_src"),vdom:g("acc_vdom"),filters:f});
 show(r,"ACC · "+g("acc_period")+(ks.length?" · "+ks.map(k=>k+" "+f[k]).join(" · "):""))}
function accSet(k,v){const i=$("#acc_f_"+k);if(i)i.value=v}
function accClear(){ACC_F.forEach(([k])=>accSet(k,""));accRun()}
function accDrill(k,v){accSet(k,v);accRun()}
function accUnset(k){accSet(k,"");accRun()}
function accTop(tp,sort){const card=mk("div","dcard");card.appendChild(mk("div","sec",tp.title));
 if(!tp.rows.length){card.appendChild(mk("div","nv","None in the logs read."));return card}
 const byB=tp.metric==="traffic"&&sort==="bytes"&&tp.rows.some(r=>r[2]),pv=r=>byB?r[2]:r[1],m=Math.max(...tp.rows.map(pv),1),gr=mk("div","dtop");
 tp.rows.forEach(r=>{const ok=!!(tp.drill&&r[3]),nm=mk("div","dn"+(ok?" lnk":""),r[0]);
  nm.title=(ok?"Click: filter the ACC to "+r[0]:r[0])+"\n"+(tp.metric==="traffic"?dNum(r[1])+" sessions · "+dBytes(r[2]):dNum(r[1])+" log entries");
  if(ok)nm.onclick=()=>accDrill(tp.drill,r[3]);
  const bar=mk("div","db"),fill=mk("span");fill.style.width=(100*pv(r)/m).toFixed(1)+"%";bar.appendChild(fill);
  gr.appendChild(nm);gr.appendChild(bar);gr.appendChild(mk("div","dvv",byB?dBytes(r[2]):dNum(r[1])))});
 card.appendChild(gr);return card}
function accNode(d){const w=mk("div","dash");
 const tiles=mk("div","dtiles");d.tiles.forEach(t=>{const x=mk("div","dtile");x.appendChild(mk("div","dl",t.label));
  x.appendChild(mk("div","dv",t.value==null?"n/a":DFMT[t.fmt](t.value)));if(t.sub)x.appendChild(mk("div","dl",t.sub));
  if(t.spark){const sp=mk("div");sp.innerHTML=dSpark(t.spark);x.appendChild(sp)}tiles.appendChild(x)});
 w.appendChild(tiles);
 const ks=Object.keys(d.filters||{}),hint=mk("div","muted",(ks.length?"Filters:":"No filters")+"");
 ks.forEach(k=>{const c=mk("span","fchip",d.filters[k].label+": "+d.filters[k].value+" ✕");c.title="Remove this filter and run again";c.onclick=()=>accUnset(k);hint.appendChild(c)});
 hint.appendChild(document.createTextNode(" · buckets: "+d.bucket+" · times are the firewall's clock · hover a chart for values · click a highlighted entry to filter by it"));
 w.appendChild(hint);
 const bar=mk("div","dtabs"),panes=[];
 d.tabs.forEach((tab,i)=>{const b=mk("button",i===accTab?"on":"",tab.title+" ("+dNum(tab.count)+")");
  b.onclick=()=>{accTab=i;[...bar.children].forEach((x,j)=>x.classList.toggle("on",j===i));panes.forEach((p,j)=>p.style.display=j===i?"":"none")};bar.appendChild(b);
  const p=mk("div");p.style.display=i===accTab?"":"none";const cg=mk("div","dgrid");cg.style.marginBottom="12px";
  tab.charts.forEach(c=>cg.appendChild(dChart(c.title,d.t,c.series.map(([n,v],k)=>({name:n,color:ACC_C[String(n).toLowerCase()]||DC[k%DC.length],vals:v})),
   {stack:!!c.stack,fmt:DFMT[c.fmt]||dNum,noTotal:c.fmt!=="num"})));
  p.appendChild(cg);const tg=mk("div","dgrid tops");tab.tops.forEach(tp=>tg.appendChild(accTop(tp,d.sort)));p.appendChild(tg);
  panes.push(p)});
 w.appendChild(bar);panes.forEach(p=>w.appendChild(p));return w}
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
// ---- Device monitor: poll /api/monitor, pop up changes, Windows notification + sound ----
let monSeq=-1,monLast=null,monOpen=false;
const MON_TITLE={offline:"DOWN",pooldown:"F5 pool has NO available members",recovered:"Back up",
 admin:"Taken out of service",baseline:"Already down when monitoring started",ha:"HA state changed",error:"Monitor"};
function monTitle(e){return e.kind==="offline"||e.kind==="recovered"||e.kind==="admin"?(e.cat||"")+" "+MON_TITLE[e.kind]+" \u00b7 "+e.device:(MON_TITLE[e.kind]||"Monitor")+(e.device?" \u00b7 "+e.device:"")}
function monPref(k,d){try{const v=localStorage.getItem("mon_"+k);return v==null?d:v==="1"}catch(e){return d}}
function monSetPref(k,v){try{localStorage.setItem("mon_"+k,v?"1":"0")}catch(e){}}
function monBeep(bad){if(!monPref("sound",true))return;try{const c=new(window.AudioContext||window.webkitAudioContext)();
 (bad?[880,660,880]:[660,990]).forEach((f,i)=>{const o=c.createOscillator(),g=c.createGain(),t=c.currentTime+i*.18;o.frequency.value=f;o.connect(g);g.connect(c.destination);
  g.gain.setValueAtTime(.0001,t);g.gain.exponentialRampToValueAtTime(.2,t+.02);g.gain.exponentialRampToValueAtTime(.0001,t+.16);o.start(t);o.stop(t+.17)})}catch(e){}}
function monToast(e){const bad=e.kind==="offline"||e.kind==="pooldown"||e.kind==="baseline"||e.kind==="ha";
 const t=mk("div","mtoast "+e.kind),h=mk("div","mth");h.appendChild(mk("span",null,(bad?"\u26a0 ":e.kind==="recovered"?"\u2713 ":"\u2022 ")+monTitle(e)));
 h.appendChild(mk("small","muted",e.t));const x=mk("button",null,"\u2715");x.onclick=()=>t.remove();h.appendChild(x);t.appendChild(h);
 t.appendChild(mk("div",null,e.text));if(e.vips&&e.vips.length)t.appendChild(mk("div","mtv","VIP: "+e.vips.join(", ")));
 const box=$("#montoasts");box.appendChild(t);while(box.children.length>6)box.firstChild.remove();
 if(!bad)setTimeout(()=>t.remove(),e.kind==="recovered"?20000:60000);
 if(monPref("notify",true)&&window.Notification&&Notification.permission==="granted"){
  try{new Notification(monTitle(e),{body:e.text+(e.vips&&e.vips.length?"\nVIP: "+e.vips.join(", "):""),tag:"mon"+e.seq,requireInteraction:bad})}catch(err){}}
 if(e.kind!=="error")monBeep(bad)}
async function monPoll(){if(!devices.some(d=>["f5","paloalto","fortigate"].includes(d.vendor))){$("#monbtn").hidden=true;$("#monpanel").hidden=true;monOpen=false;return}
 $("#monbtn").hidden=false;let r;try{r=await api("/api/monitor"+(monSeq>=0?"?since="+monSeq:""))}catch(e){return}if(!r||!r.ok)return;
 if(monSeq>=0)r.events.forEach(monToast);monSeq=r.seq;
 if(!monLast)monLast={events:[]};monLast.on=r.on;monLast.interval=r.interval;monLast.status=r.status;
 monLast.events=monLast.events.concat(r.events).slice(-40);
 const off=r.status.reduce((n,s)=>n+(s.offline||0),0),b=$("#monbadge");
 b.hidden=!off;b.textContent=off;$("#monbtn").classList.toggle("alert",off>0);
 $("#monbtn").title="Device monitor: "+(r.on?"on, every "+r.interval+" s":"off")+(off?" \u00b7 "+off+" down":"");
 if(monOpen)monRender()}
function monRender(){const p=$("#monpanel"),m=monLast||{status:[],events:[]};p.innerHTML="";p.appendChild(mk("h3",null,"Device monitor"));
 const r1=mk("div","mrow"),lb=mk("label"),cb=mk("input");cb.type="checkbox";cb.checked=!!m.on;cb.onchange=()=>monSet({on:cb.checked});
 lb.appendChild(cb);lb.appendChild(document.createTextNode("Watch devices"));r1.appendChild(lb);
 const iv=mk("select");[15,30,60,120,300].forEach(v=>{const o=mk("option",null,"every "+(v<60?v+" s":v/60+" min"));o.value=v;if(v===m.interval)o.selected=true;iv.appendChild(o)});
 iv.onchange=()=>monSet({interval:+iv.value});r1.appendChild(iv);const now=mk("button",null,"Check now");now.onclick=()=>monSet({now:true});r1.appendChild(now);p.appendChild(r1);
 const r2=mk("div","mrow");[["sound","Sound"],["notify","Windows notification"]].forEach(([k,t])=>{const l=mk("label"),c=mk("input");c.type="checkbox";c.checked=monPref(k,true);
  c.onchange=()=>{monSetPref(k,c.checked);if(k==="notify"&&c.checked)monAskNotify()};l.appendChild(c);l.appendChild(document.createTextNode(t));r2.appendChild(l)});
 if(window.Notification&&Notification.permission!=="granted"){const a=mk("button",null,Notification.permission==="denied"?"Notifications blocked in the browser":"Allow Windows notifications");
  a.disabled=Notification.permission==="denied";a.onclick=monAskNotify;r2.appendChild(a)}
 p.appendChild(r2);
 p.appendChild(mk("div","msec","Devices"));(m.status||[]).forEach(s=>p.appendChild(mk("div","mline"+(s.error?" error":""),
  s.device+": "+(s.error?"cannot read ("+s.error+")":Object.entries(s.counts||{}).map(([k,v])=>v+" "+k.toLowerCase()+(v===1?"":"s")).join(", ")+
   (s.ha?" \u00b7 HA "+s.ha:"")+" \u00b7 "+(s.offline||0)+" down")+(s.time?" \u00b7 checked "+s.time:"")+
   ((s.warnings||[]).length?" \u00b7 not readable: "+s.warnings.join("; "):""))));
 if(!(m.status||[]).length)p.appendChild(mk("div","mline muted",m.on?"First check running\u2026":"Monitoring is off."));
 const down=[].concat(...(m.status||[]).map(s=>(s.down||[]).map(x=>Object.assign({device:s.device},x))));
 if(down.length){p.appendChild(mk("div","msec","Out of service now ("+down.length+")"));down.slice(0,60).forEach(x=>p.appendChild(mk("div","mline "+(x.cls==="bad"?"offline":"admin"),
  x.cat+" "+x.label+" \u00b7 "+x.state+" \u00b7 "+x.device+(x.vips&&x.vips.length?" \u00b7 VIP "+x.vips.join(", "):""))))}
 p.appendChild(mk("div","msec","Recent changes"));const ev=(m.events||[]).slice().reverse();
 if(!ev.length)p.appendChild(mk("div","mline muted","No changes yet."));ev.slice(0,25).forEach(e=>p.appendChild(mk("div","mline "+e.kind,e.t+" \u00b7 "+e.text)))}
function monPanel(){monOpen=$("#monpanel").hidden;$("#monpanel").hidden=!monOpen;if(monOpen){monRender();if(window.Notification&&Notification.permission==="default"&&monPref("notify",true))monAskNotify()}}
async function monSet(b){const r=await api("/api/monitor",b);if(!r.ok){alert(r.error);return}monPoll();setTimeout(monPoll,2500)}
function monAskNotify(){if(window.Notification&&Notification.permission==="default")Notification.requestPermission().then(()=>{if(monOpen)monRender()})}
document.addEventListener("click",e=>{if(monOpen&&!e.target.closest("#monpanel")&&!e.target.closest("#monbtn")){monOpen=false;$("#monpanel").hidden=true}});
setInterval(monPoll,5000);setTimeout(monPoll,1500);
// Live update: the server picks up edits to netops_console.py; tell the user, and offer a reload when the page itself changed
let hotV=null,hotT=0;
function hotBar(cls,html){let b=$("#hotbar");if(!b){b=mk("div");b.id="hotbar";document.body.appendChild(b)}b.className=cls;b.innerHTML=html;b.hidden=false;
 const x=mk("button",null,"✕");x.onclick=()=>{b.hidden=true};b.appendChild(x);return b}
async function hotCheck(){let v;try{v=await api("/api/version")}catch(e){return}if(!v||v.gen==null)return;
 if(!hotV){hotV=v;return}
 if(v.error&&v.error!==hotV.error)hotBar("bad","Update <b>not applied</b> ("+esc(v.time)+"), the console keeps running the previous code: "+esc(v.error));
 else if(v.gen!==hotV.gen){
  if(v.page!==hotV.page){const b=hotBar("new","Console updated at "+esc(v.time)+". The page changed: reload to see it (connected devices stay connected). ");
   const r=mk("button","primary","Reload page");r.onclick=()=>location.reload();b.insertBefore(r,b.lastChild)}
  else{hotBar("ok","Console updated at "+esc(v.time)+" (server side), already active.");clearTimeout(hotT);hotT=setTimeout(()=>{const b=$("#hotbar");if(b&&b.className==="ok")b.hidden=true},6000)}}
 hotV=Object.assign({},v,{page:v.page!==hotV.page&&v.gen!==hotV.gen?hotV.page:v.page})}
setInterval(hotCheck,4000);hotCheck();
// a reloaded page (e.g. after a live update) picks up the devices the console is still connected to
async function devicesRestore(){let l;try{l=await api("/api/devices")}catch(e){return}if(!Array.isArray(l)||!l.length)return;
 l.forEach(x=>{if(!devices.some(d=>d.id===x.id))devices.push(x)});
 let pick=null;try{pick=sessionStorage.getItem("cur")}catch(e){}
 if(!cur)cur=devices.some(d=>d.id===pick)?pick:devices[0].id;renderAll()}
api("/api/catalog").then(c=>{catalog=c;devicesRestore()});loadProfiles();vaultLoad();aiInit();try{if(localStorage.getItem("ai_open"))aiToggle(true)}catch(e){}
</script></body></html>
"""


# ---- Device monitor: the page pops up a message when something goes down (read-only polling) --------------------
# F5: pool members, virtual servers, nodes, failover state. Palo Alto / FortiGate: HA, interfaces, IPsec tunnels.
# The page asks /api/monitor every few seconds; when a check is due, one background pass reads the pool list of every
# connected F5 (one GET each: member monitor state is part of the pool configuration) and compares it with the previous
# pass. Changes become events that the page shows as pop-ups and Windows notifications.
MON = {"on": True, "interval": 30, "seq": 0, "events": collections.deque(maxlen=300), "state": {}, "vips": {},
       "status": {}, "busy": False, "next": 0.0, "lock": threading.Lock()}
MON_INTERVALS = (15, 30, 60, 120, 300)


def mon_member_state(m):
    st, ses = str(m.get("state") or ""), str(m.get("session") or "")
    if st == "user-down":
        return "forced offline"
    if st == "down":
        return "offline"
    if ses == "user-disabled":
        return "disabled"
    if st == "up":
        return "up"
    return "no monitor" if st == "unchecked" else (st or "unknown")


def mon_event(kind, sess, text, **kw):
    with MON["lock"]:
        MON["seq"] += 1
        e = dict(kw, seq=MON["seq"], kind=kind, t=time.strftime("%H:%M:%S"), ts=time.time(),
                 device=sess.get("name") or sess.get("host"), text=text)
        MON["events"].append(e)
    if kind in ("offline", "pooldown", "recovered", "admin", "ha"):
        audit(sess, "monitor: " + text[:200])


def mon_item(cat, label, state, cls, **extra):
    """One watched object. cls: 'good', 'bad' (down: alert), 'admin' (taken out of service on purpose), 'ha' (any change
    alerts), 'info' (shown, never alerts)."""
    return dict(extra, cat=cat, label=label, state=state, cls=cls)


# Kinds of object that are reported as already down when monitoring starts. Interfaces and tunnels are not: unused
# ports and idle on-demand tunnels are down all the time, so they only alert after they have been seen up once.
MON_BASELINE = ("Pool member", "Virtual server", "Node")


def mon_f5(sid, sess, prev):
    items, errs = {}, []
    ok, d = f5_get(sess, "/mgmt/tm/ltm/pool?expandSubcollections=true")
    if not ok:
        raise ValueError("pool list not readable: %s" % str(d)[:160])
    vip = MON["vips"].get(sid)
    if not vip or time.time() - vip[0] > 300:   # which virtual servers use each pool (refreshed every 5 minutes)
        okv, dv = f5_get(sess, "/mgmt/tm/ltm/virtual")
        m = {}
        for v in (dv.get("items", []) if okv else []):
            if v.get("pool"):
                dest = (v.get("destination") or "").rsplit("/", 1)[-1]
                m.setdefault(v["pool"], []).append("%s (%s:%s)" % (v.get("fullPath"), f5_dest_ip(v.get("destination")),
                                                                   f5_member_port(dest)))
        vip = MON["vips"][sid] = (time.time(), m)
    for p in d.get("items", []):
        pool = p.get("fullPath") or p.get("name") or ""
        for mb in (p.get("membersReference") or {}).get("items", []):
            st = mon_member_state(mb)
            ip = "%s:%s" % (strip_rd(mb.get("address")), f5_member_port(mb.get("name")))
            items["pm|%s|%s" % (pool, mb.get("name"))] = mon_item(
                "Pool member", "%s in %s" % (ip, pool), st,
                "bad" if st == "offline" else "admin" if st in ("forced offline", "disabled") else "good",
                pool=pool, vips=vip[1].get(pool, []))
    try:
        okv, dv = f5_get(sess, "/mgmt/tm/ltm/virtual/stats")
        if not okv:
            raise ValueError("HTTP error")
        for name, st in f5_stat_status(dv).items():
            items["vs|" + name] = mon_item("Virtual server", name, st,
                                           "bad" if st == "offline" else "admin" if "disabled" in st else "good")
    except Exception as e:  # noqa: BLE001 - one part failing must not stop the rest
        errs.append("virtual servers: %s" % getattr(e, "reason", e))
    try:
        okn, dn = f5_get(sess, "/mgmt/tm/ltm/node")
        if not okn:
            raise ValueError("HTTP error")
        for nd in dn.get("items", []):
            st = mon_member_state(nd)
            items["node|" + str(nd.get("fullPath"))] = mon_item(
                "Node", "%s (%s)" % (nd.get("fullPath"), strip_rd(nd.get("address"))), st,
                "bad" if st == "offline" else "admin" if st in ("forced offline", "disabled") else "good")
    except Exception as e:  # noqa: BLE001 - one part failing must not stop the rest
        errs.append("nodes: %s" % getattr(e, "reason", e))
    ha = f5_ha_state(sess)
    if ha:
        items["ha"] = mon_item("HA state", "failover state", ha, "ha")
    return items, errs


def mon_pan(sid, sess, prev):
    items, errs = {}, []

    def entries(x):
        if isinstance(x, dict):
            if x.get("entry") is not None:
                return [i for i in as_list(x["entry"]) if isinstance(i, dict)]
            for v in x.values():
                r = entries(v)
                if r:
                    return r
        return []
    try:
        st, ok, d = pan_op(sess, "<show><high-availability><state/></high-availability></show>")
        res = d.get("result") if ok and isinstance(d, dict) else None
        if isinstance(res, dict) and str(res.get("enabled", "")).lower() == "yes":
            grp = res.get("group") or {}
            loc, peer = grp.get("local-info") or {}, grp.get("peer-info") or {}
            if loc.get("state"):
                items["ha"] = mon_item("HA state", "this firewall", str(loc["state"]), "ha")
            if peer.get("conn-status"):
                cs = str(peer["conn-status"]).lower()
                items["hapeer"] = mon_item("HA peer", "link to %s" % (peer.get("mgmt-ip") or "the peer"), cs,
                                           "good" if cs == "up" else "bad")
            if peer.get("state"):
                items["hapeerst"] = mon_item("HA state", "peer", str(peer["state"]), "ha")
        elif not ok:
            errs.append("HA state not readable (HTTP %s)" % st)
    except Exception as e:  # noqa: BLE001 - one part failing must not stop the rest
        errs.append("HA: %s" % getattr(e, "reason", e))
    try:
        st, ok, d = pan_op(sess, "<show><interface>all</interface></show>")
        res = d.get("result") if ok and isinstance(d, dict) else None
        for e in entries((res or {}).get("hw")) if isinstance(res, dict) else []:
            s = str(e.get("state") or "").lower()
            if e.get("name") and s:
                items["if|" + e["name"]] = mon_item("Interface", e["name"], s, "good" if s == "up" else "bad")
        if not ok:
            errs.append("interfaces not readable (HTTP %s)" % st)
    except Exception as e:  # noqa: BLE001 - one part failing must not stop the rest
        errs.append("interfaces: %s" % getattr(e, "reason", e))
    try:
        st, ok, d = pan_op(sess, "<show><vpn><flow/></vpn></show>")
        res = d.get("result") if ok and isinstance(d, dict) else None
        for e in entries(res) if isinstance(res, dict) else []:
            name, s, mon = e.get("name"), str(e.get("state") or "").lower(), str(e.get("mon") or "").lower()
            if not name or not s:
                continue
            up = s == "active" and mon != "down"
            items["vpn|" + name] = mon_item("IPsec tunnel", name, s + (" / monitor " + mon if mon not in ("", "off") else ""),
                                            "good" if up else "bad")
    except Exception as e:  # noqa: BLE001 - one part failing must not stop the rest
        errs.append("IPsec tunnels: %s" % getattr(e, "reason", e))
    return items, errs


def mon_fg(sid, sess, prev):
    items, errs = {}, []

    def get(path):
        st, ok, d = rest_get(sess, path)
        if not ok or not isinstance(d, dict):
            raise ValueError("HTTP %s" % st)
        return d.get("results")
    try:
        peers = [p for p in as_list(get("/api/v2/monitor/system/ha-peer")) if isinstance(p, dict)]
        cluster = len(peers) > 1 or any(k.startswith("hapeer|") for k in (prev or {}))
        if cluster:   # a cluster: alert when a member leaves it, or the primary changes
            for p in peers:
                k = "hapeer|" + str(p.get("serial_no") or p.get("hostname"))
                items[k] = mon_item("HA member", "%s (%s)" % (p.get("hostname") or "?", p.get("serial_no") or "?"),
                                    "in cluster", "good")
                if any(p.get(f) is True for f in ("primary", "is_primary", "is_manage_master", "is_root_primary")):
                    items["ha"] = mon_item("HA state", "primary unit", str(p.get("hostname") or p.get("serial_no")), "ha")
        for k, it in (prev or {}).items():   # a member that was in the cluster and is gone now
            if k.startswith("hapeer|") and k not in items and cluster:
                items[k] = dict(it, state="missing from the cluster", cls="bad")
    except Exception as e:  # noqa: BLE001 - one part failing must not stop the rest
        errs.append("HA: %s" % getattr(e, "reason", e))
    try:
        res = get("/api/v2/monitor/system/interface")
        for i in (res.values() if isinstance(res, dict) else as_list(res)):
            if isinstance(i, dict) and i.get("name") and isinstance(i.get("link"), bool):
                items["if|" + i["name"]] = mon_item("Interface", i["name"], "up" if i["link"] else "down",
                                                    "good" if i["link"] else "bad")
    except Exception as e:  # noqa: BLE001 - one part failing must not stop the rest
        errs.append("interfaces: %s" % getattr(e, "reason", e))
    try:
        for t in as_list(get("/api/v2/monitor/vpn/ipsec")):
            if not isinstance(t, dict) or not t.get("name"):
                continue
            px = [p for p in as_list(t.get("proxyid")) if isinstance(p, dict)]
            if not px:   # dial-up template without clients: nothing to watch
                continue
            up = sum(1 for p in px if str(p.get("status")).lower() == "up")
            items["vpn|" + t["name"]] = mon_item("IPsec tunnel", t["name"], "up" if up else "down",
                                                 "good" if up else "bad",
                                                 detail="%d of %d phase-2 selector(s) up" % (up, len(px)))
    except Exception as e:  # noqa: BLE001 - one part failing must not stop the rest
        errs.append("IPsec tunnels: %s" % getattr(e, "reason", e))
    return items, errs


MON_WATCH = {"f5": mon_f5, "paloalto": mon_pan, "fortigate": mon_fg}


def mon_poll(sid, sess):
    name = sess.get("name") or sess.get("host")
    prev = MON["state"].get(sid)
    if prev is not None and not all(isinstance(v, dict) and "cls" in v for v in prev.values()):
        prev = None   # kept by a live update from an older version of the monitor: start again from this pass
        MON.setdefault("quiet", {}).pop(sid, None)
    cur, errs = MON_WATCH[sess["vendor"]](sid, sess, prev)
    quiet = MON.setdefault("quiet", {}).setdefault(sid, set())
    if prev is None:
        quiet.update(k for k, it in cur.items() if it["cls"] == "bad" and it["cat"] not in MON_BASELINE)
        base = [it for it in cur.values() if it["cls"] == "bad" and it["cat"] in MON_BASELINE]
        if base:
            mon_event("baseline", sess, "%d object(s) on %s are down now: %s" % (
                len(base), name, ", ".join("%s %s" % (it["cat"].lower(), it["label"]) for it in base[:6]) +
                (" …" if len(base) > 6 else "")), members=base[:50])
    else:
        for k, it in cur.items():
            was = prev.get(k)
            if k in quiet:
                if it["cls"] != "bad":
                    quiet.discard(k)   # seen up: from now on it alerts like everything else
                continue
            if not was or was["state"] == it["state"]:
                continue
            what = dict(it, was=was["state"], now=it["state"])
            if it["cls"] == "ha":
                mon_event("ha", sess, "%s on %s changed: %s -> %s" % (it["label"].capitalize(), name, was["state"],
                                                                     it["state"]), **what)
            elif it["cls"] == "bad" and was["cls"] != "bad":
                mon_event("offline", sess, "%s %s went %s on %s (was %s)" % (
                    it["cat"], it["label"], "OFFLINE" if it["cat"] in MON_BASELINE else
                    "DOWN" if it["state"] == "down" else "DOWN (%s)" % it["state"],
                    name, was["state"]), **what)
            elif it["cls"] == "admin":   # disabled / forced offline by an admin (also a change between the two)
                mon_event("admin", sess, "%s %s was set to %s on %s (was %s)" % (it["cat"], it["label"], it["state"],
                                                                                name, was["state"]), **what)
            elif was["cls"] in ("bad", "admin"):   # back from offline, or enabled again by an admin
                mon_event("recovered", sess, "%s %s is back in service (%s) on %s (was %s)" % (
                    it["cat"], it["label"], it["state"], name, was["state"]), **what)
        pools, prev_pools = {}, {}
        for src, dst in ((cur, pools), (prev, prev_pools)):
            for it in src.values():
                if it["cat"] == "Pool member":
                    dst.setdefault(it["pool"], []).append(it["state"])
        for pool, sts in pools.items():
            if "up" not in sts and "no monitor" not in sts and any(s in ("up", "no monitor") for s in prev_pools.get(pool, [])):
                vips = next((it.get("vips") for it in cur.values() if it.get("pool") == pool), [])
                mon_event("pooldown", sess, "Pool %s on %s has NO available members" % (pool, name), pool=pool, vips=vips)
            elif any(s in ("up", "no monitor") for s in sts) and prev_pools.get(pool) and                     not any(s in ("up", "no monitor") for s in prev_pools[pool]):
                vips = next((it.get("vips") for it in cur.values() if it.get("pool") == pool), [])
                mon_event("recovered", sess, "Pool %s on %s has available members again" % (pool, name), pool=pool,
                          vips=vips, cat="Pool")
    for k in list(quiet):
        if k not in cur:
            quiet.discard(k)
    MON["state"][sid] = cur
    counts = collections.Counter(it["cat"] for it in cur.values() if it["cls"] != "ha")
    down = [dict(it) for k, it in cur.items() if it["cls"] in ("bad", "admin") and k not in quiet]
    ha = "; ".join("%s: %s" % (it["label"], it["state"]) for it in cur.values() if it["cls"] == "ha")
    MON["status"][sid] = {"device": name, "vendor": sess["vendor"], "time": time.strftime("%H:%M:%S"), "error": "",
                          "warnings": errs, "counts": dict(counts), "ha": ha, "down": down[:150],
                          "offline": sum(1 for it in down if it["cls"] == "bad")}


def mon_cycle(items):
    try:
        for sid, sess in items:
            try:
                mon_poll(sid, sess)
            except Exception as e:  # noqa: BLE001 - one device's failure must not stop the others or print a traceback
                err = str(getattr(e, "reason", e))[:200]
                if not isinstance(e, (ValueError, urllib.error.URLError, OSError)):
                    err = "%s: %s" % (type(e).__name__, err)
                st = MON["status"].setdefault(sid, {"device": sess.get("name") or sess.get("host"), "down": []})
                if st.get("error") != err:
                    mon_event("error", sess, "Monitor cannot read %s: %s" % (st["device"], err))
                st.update(error=err, time=time.strftime("%H:%M:%S"))
    finally:
        MON["busy"] = False


def mon_tick():
    """Start a background pass when one is due (called by the page's polling, so no thread runs without a page)."""
    with LOCK:
        f5 = [(sid, s) for sid, s in SESSIONS.items() if s.get("vendor") in MON_WATCH]
    for gone in [k for k in MON["status"] if k not in dict(f5)]:
        MON["status"].pop(gone, None)
        MON["state"].pop(gone, None)
        MON["vips"].pop(gone, None)
        MON.setdefault("quiet", {}).pop(gone, None)
    with MON["lock"]:
        if not MON["on"] or not f5 or MON["busy"] or time.time() < MON["next"]:
            return
        MON["busy"], MON["next"] = True, time.time() + MON["interval"]
    threading.Thread(target=mon_cycle, args=(f5,), daemon=True).start()


def do_monitor_get(query):
    mon_tick()
    try:
        since = int(urllib.parse.parse_qs(query).get("since", ["-1"])[0])
    except ValueError:
        since = -1
    with MON["lock"]:
        ev = [e for e in MON["events"] if e["seq"] > since] if since >= 0 else list(MON["events"])[-30:]
        seq = MON["seq"]
    return {"ok": True, "on": MON["on"], "interval": MON["interval"], "seq": seq, "events": ev, "busy": MON["busy"],
            "status": list(MON["status"].values())}


def do_monitor_set(b):
    if "on" in b:
        MON["on"] = bool(b.get("on"))
    if "interval" in b:
        try:
            iv = int(b.get("interval"))
        except (TypeError, ValueError):
            iv = 0
        if iv not in MON_INTERVALS:
            return {"ok": False, "error": "interval must be one of %s seconds" % ", ".join(map(str, MON_INTERVALS))}
        MON["interval"] = iv
    if b.get("now") or "interval" in b or b.get("on"):
        MON["next"] = 0.0
    return {"ok": True, "on": MON["on"], "interval": MON["interval"]}


# ---- Packet capture analysis: a .pcap / .pcapng uploaded in the AI assistant is read here (standard library only) ----
# The capture is parsed in memory and never written to disk. What the model gets is the summary below (flows, TCP
# problems, DNS, TLS server names / alerts, HTTP request lines without query strings, ICMP, ARP), never packet payloads.
PCAP_MAX = 64 * 1024 * 1024
PCAP_MAX_PKTS = 500000
PCAP_LINKS = {0: "BSD loopback", 1: "Ethernet", 12: "raw IP", 14: "raw IP", 101: "raw IP", 108: "OpenBSD loopback",
              113: "Linux cooked (SLL)", 228: "raw IPv4", 229: "raw IPv6", 276: "Linux cooked v2 (SLL2)"}
PCAP_PROTO = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF",
              112: "VRRP", 132: "SCTP"}
TLS_ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 22: "record_overflow",
              40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
              45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
              49: "access_denied", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
              71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled",
              109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
              113: "bad_certificate_status_response", 116: "certificate_required", 120: "no_application_protocol"}
TLS_VER = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS",
             255: "ANY"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
ICMP4 = {(3, 0): "net unreachable", (3, 1): "host unreachable", (3, 2): "protocol unreachable", (3, 3): "port unreachable",
         (3, 4): "fragmentation needed", (3, 9): "net administratively prohibited",
         (3, 10): "host administratively prohibited", (3, 13): "communication administratively prohibited",
         (11, 0): "TTL exceeded in transit", (11, 1): "fragment reassembly time exceeded", (5, 0): "redirect (net)",
         (5, 1): "redirect (host)", (0, 0): "echo reply", (8, 0): "echo request"}
ICMP6 = {1: "destination unreachable", 2: "packet too big", 3: "time exceeded", 4: "parameter problem",
         128: "echo request", 129: "echo reply", 133: "router solicitation", 134: "router advertisement",
         135: "neighbor solicitation", 136: "neighbor advertisement"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def pcap_frames(data, info):
    """Yield (time, linktype, frame) from a classic pcap or a pcapng file. Sets info['format'] / info['truncated']."""
    magic = bytes(data[:4])
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = "<" if magic[0] in (0xd4, 0x4d) else ">"
        div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        if len(data) < 24:
            raise ValueError("the file is too short to be a capture")
        info["format"] = "pcap"
        link = struct.unpack(e + "I", data[20:24])[0] & 0x0FFFFFF
        off, n = 24, len(data)
        while off + 16 <= n:
            s, frac, cap, _orig = struct.unpack(e + "IIII", data[off:off + 16])
            off += 16
            if off + cap > n or cap > 0x40000:
                info["truncated"] = True
                return
            yield s + frac / div, link, data[off:off + cap]
            off += cap
        if off != n:
            info["truncated"] = True
        return
    if magic == b"\x0a\x0d\x0d\x0a":
        info["format"] = "pcapng"
        off, n, e, ifs, last_t = 0, len(data), "<", [], 0.0
        while off + 12 <= n:
            if bytes(data[off:off + 4]) == b"\x0a\x0d\x0d\x0a":   # section header: byte order, new interface list
                e = "<" if bytes(data[off + 8:off + 12]) == b"\x4d\x3c\x2b\x1a" else ">"
                ifs = []
            btype, blen = struct.unpack(e + "II", data[off:off + 8])
            if blen < 12 or off + blen > n:
                info["truncated"] = True
                return
            body = data[off + 8:off + blen - 4]
            if btype == 1 and len(body) >= 8:   # interface description: link type, time resolution option
                link, res, p = struct.unpack(e + "H", body[0:2])[0], 1e-6, 8
                while p + 4 <= len(body):
                    code, ln = struct.unpack(e + "HH", body[p:p + 4])
                    if code == 0:
                        break
                    if code == 9 and ln >= 1:
                        v = body[p + 4]
                        res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                    p += 4 + ((ln + 3) & ~3)
                ifs.append((link, res))
            elif btype == 6 and len(body) >= 20:   # enhanced packet
                iid, hi, lo, cap, _orig = struct.unpack(e + "IIIII", body[:20])
                if iid < len(ifs):
                    last_t = ((hi << 32) | lo) * ifs[iid][1]
                    yield last_t, ifs[iid][0], body[20:20 + cap]
            elif btype == 3 and len(body) >= 4 and ifs:   # simple packet (no time stamp)
                yield last_t, ifs[0][0], body[4:]
            elif btype == 2 and len(body) >= 20:   # obsolete packet block
                iid, _dr, hi, lo, cap, _orig = struct.unpack(e + "HHIIII", body[:20])
                if iid < len(ifs):
                    last_t = ((hi << 32) | lo) * ifs[iid][1]
                    yield last_t, ifs[iid][0], body[20:20 + cap]
            off += blen
        return
    raise ValueError("not a pcap or pcapng file (unknown file header); save the capture as .pcap or .pcapng")


def pcap_l3(link, f):
    """(ethertype, layer-3 bytes, source MAC) for the link types tcpdump / Wireshark / F5 / PAN / FortiGate write."""
    if link == 1:
        if len(f) < 14:
            return None, b"", ""
        et, p = (f[12] << 8) | f[13], 14
        while et in (0x8100, 0x88A8, 0x9100) and len(f) >= p + 4:
            et, p = (f[p + 2] << 8) | f[p + 3], p + 4
        return et, f[p:], ":".join("%02x" % b for b in f[6:12])
    if link in (12, 14, 101):
        v = f[0] >> 4 if f else 0
        return (0x0800 if v == 4 else 0x86DD if v == 6 else None), f, ""
    if link == 228:
        return 0x0800, f, ""
    if link == 229:
        return 0x86DD, f, ""
    if link == 113 and len(f) >= 16:
        return (f[14] << 8) | f[15], f[16:], ""
    if link == 276 and len(f) >= 20:
        return (f[0] << 8) | f[1], f[20:], ""
    if link in (0, 108) and len(f) >= 4:
        fam = f[0] or f[3]
        return (0x0800 if fam == 2 else 0x86DD if fam in (10, 24, 28, 30) else None), f[4:], ""
    return None, b"", ""


def pcap_ip(et, b):
    """(src, dst, proto, layer-4 bytes, first fragment?) or None."""
    if et == 0x0800 and len(b) >= 20 and b[0] >> 4 == 4:
        ihl, tot = (b[0] & 15) * 4, (b[2] << 8) | b[3]
        end = tot if ihl <= tot <= len(b) else len(b)
        first = ((b[6] & 0x1F) << 8 | b[7]) == 0
        return socket.inet_ntoa(bytes(b[12:16])), socket.inet_ntoa(bytes(b[16:20])), b[9], b[ihl:end], first
    if et == 0x86DD and len(b) >= 40 and b[0] >> 4 == 6:
        nh, p, first = b[6], 40, True
        end = min(len(b), 40 + ((b[4] << 8) | b[5])) if (b[4] or b[5]) else len(b)
        while nh in (0, 43, 44, 60) and p + 8 <= end:
            if nh == 44:
                first = ((b[p + 2] << 8 | b[p + 3]) >> 3) == 0
                nh, p = b[p], p + 8
            else:
                nh, p = b[p], p + (b[p + 1] + 1) * 8
        return (socket.inet_ntop(socket.AF_INET6, bytes(b[8:24])), socket.inet_ntop(socket.AF_INET6, bytes(b[24:40])),
                nh, b[p:end], first)
    return None


def dns_name(m, p, depth=0):
    labels, jumped, end = [], False, p
    while p < len(m) and depth < 20:
        ln = m[p]
        if ln == 0:
            p += 1
            break
        if ln & 0xC0 == 0xC0:
            if p + 1 >= len(m):
                break
            if not jumped:
                end = p + 2
            jumped, depth, p = True, depth + 1, ((ln & 0x3F) << 8) | m[p + 1]
            continue
        labels.append(bytes(m[p + 1:p + 1 + ln]).decode("ascii", "replace"))
        p += 1 + ln
    return ".".join(labels) or ".", (end if jumped else p)


def dns_parse(m):
    """(id, is response, rcode, name, qtype, answers) of a DNS message, or None."""
    if len(m) < 12:
        return None
    tid, fl, qd, an = struct.unpack(">HHHH", m[:8])
    if qd < 1:
        return None
    name, p = dns_name(m, 12)
    if p + 4 > len(m):
        return None
    qtype = (m[p] << 8) | m[p + 1]
    p += 4
    answers = []
    for _ in range(min(an, 20)):
        _n, p = dns_name(m, p)
        if p + 10 > len(m):
            break
        typ, _cl, _ttl, rdl = struct.unpack(">HHIH", m[p:p + 10])
        rd = m[p + 10:p + 10 + rdl]
        if typ == 1 and rdl == 4:
            answers.append(socket.inet_ntoa(bytes(rd)))
        elif typ == 28 and rdl == 16:
            answers.append(socket.inet_ntop(socket.AF_INET6, bytes(rd)))
        elif typ == 5:
            answers.append("CNAME " + dns_name(m, p + 10)[0])
        p += 10 + rdl
    return tid, bool(fl & 0x8000), fl & 15, name, DNS_TYPES.get(qtype, str(qtype)), answers


def tls_hello(p):
    """(kind, sni / selected version) from the first TLS handshake record of a TCP segment."""
    try:
        if len(p) < 9 or p[0] != 22 or p[1] != 3:
            return None
        ht, q = p[5], 9
        if ht not in (1, 2):
            return None
        ver = (p[q] << 8) | p[q + 1]
        q += 34
        q += 1 + p[q]                          # session id
        if ht == 1:
            q += 2 + ((p[q] << 8) | p[q + 1])  # cipher suites
            q += 1 + p[q]                      # compression methods
        else:
            q += 3                             # chosen cipher + compression
        ext_end = q + 2 + ((p[q] << 8) | p[q + 1]) if q + 2 <= len(p) else q
        q += 2
        sni, sel = "", None
        while q + 4 <= min(ext_end, len(p)):
            et, ln = (p[q] << 8) | p[q + 1], (p[q + 2] << 8) | p[q + 3]
            d = p[q + 4:q + 4 + ln]
            if et == 0 and ht == 1 and len(d) > 5:
                sni = bytes(d[5:5 + ((d[3] << 8) | d[4])]).decode("ascii", "replace")
            elif et == 43 and ht == 2 and len(d) >= 2:
                sel = (d[0] << 8) | d[1]
            q += 4 + ln
        return ("client_hello", sni) if ht == 1 else ("server_hello", TLS_VER.get(sel or ver, hex(sel or ver)))
    except IndexError:
        return None


def pcap_analyze(data, fname):
    t_start = time.time()
    info = {"format": "", "truncated": False}
    pk = by = l2 = frags = 0
    protos, talk = collections.Counter(), {}
    flows, dns_q, dns_rows, tls_rows, http_rows, http_codes = {}, {}, [], {}, collections.Counter(), collections.Counter()
    http_tx, first_t = [], []
    rel_t = lambda t: round(t - first_t[0], 3) if first_t else 0.0   # noqa: E731
    icmp, arp_map, arp_n, links = collections.Counter(), collections.defaultdict(set), collections.Counter(), collections.Counter()
    t0 = t1 = None
    for ts, link, f in pcap_frames(data, info):
        if pk >= PCAP_MAX_PKTS:
            info["cut"] = True
            break
        pk += 1
        by += len(f)
        links[link] += 1
        t0 = ts if t0 is None else min(t0, ts)
        if not first_t:
            first_t.append(ts)
        t1 = ts if t1 is None else max(t1, ts)
        et, b, mac = pcap_l3(link, f)
        if et == 0x0806 and len(b) >= 28:
            op, sip = (b[6] << 8) | b[7], socket.inet_ntoa(bytes(b[14:18]))
            arp_n["request" if op == 1 else "reply" if op == 2 else "other"] += 1
            if op == 2 or (op == 1 and bytes(b[14:18]) == bytes(b[24:28])):
                arp_map[sip].add(":".join("%02x" % x for x in b[8:14]))
            protos["ARP"] += 1
            continue
        ip = pcap_ip(et, b) if et else None
        if not ip:
            l2 += 1
            protos["other L2" if et is None else "802.3 / LLC (non-IP)" if et < 0x0600 else "ethertype 0x%04x" % et] += 1
            continue
        src, dst, proto, l4, first = ip
        pname = PCAP_PROTO.get(proto, "IP proto %d" % proto)
        protos[pname] += 1
        for h in (src, dst):
            t = talk.setdefault(h, [0, 0])
            t[0] += 1
            t[1] += len(f)
        if not first:
            frags += 1
            continue
        sp = dp = 0
        if proto in (6, 17) and len(l4) >= 8:
            sp, dp = (l4[0] << 8) | l4[1], (l4[2] << 8) | l4[3]
        elif proto in (1, 58) and len(l4) >= 4:
            typ, code = l4[0], l4[1]
            if proto == 1:
                what = ICMP4.get((typ, code), "type %d code %d" % (typ, code))
                if typ == 3 and code == 4 and len(l4) >= 8:
                    what += " (next-hop MTU %d)" % ((l4[6] << 8) | l4[7])
                inner = pcap_ip(0x0800, l4[8:]) if typ in (3, 11, 5) else None
            else:
                what = ICMP6.get(typ, "type %d" % typ)
                if typ == 2 and len(l4) >= 8:
                    what += " (MTU %d)" % struct.unpack(">I", bytes(l4[4:8]))[0]
                inner = pcap_ip(0x86DD, l4[8:]) if typ in (1, 2, 3) else None
            about = ""
            if inner:
                ip_ = inner[3]
                about = "%s -> %s%s %s" % (inner[0], inner[1], (":%d" % ((ip_[2] << 8) | ip_[3]))
                                            if inner[2] in (6, 17) and len(ip_) >= 4 else "", PCAP_PROTO.get(inner[2], ""))
            icmp[(("ICMPv6 " if proto == 58 else "") + what, src, dst, about.strip())] += 1
        key = (proto,) + ((src, sp, dst, dp) if (src, sp) <= (dst, dp) else (dst, dp, src, sp))
        fl = flows.get(key)
        if fl is None:
            # no handshake seen yet: assume the lower port is the server (a SYN below corrects it)
            cs = ((src, sp), (dst, dp)) if not (sp and dp) or sp >= dp else ((dst, dp), (src, sp))
            fl = flows[key] = {"proto": pname, "c": cs[0], "s": cs[1], "pk": 0, "by": 0, "t0": ts, "t1": ts,
                               "syn": 0, "synack": 0, "syn_t": None, "hs": None, "rst": set(), "fin": 0, "retx": 0,
                               "zwin": 0, "seen": {}, "data": 0}
        fl["pk"] += 1
        fl["by"] += len(f)
        fl["t1"] = max(fl["t1"], ts)
        if proto == 6 and len(l4) >= 20:
            flags, off = l4[13], (l4[12] >> 4) * 4
            seq, win, pay = struct.unpack(">I", bytes(l4[4:8]))[0], (l4[14] << 8) | l4[15], l4[off:]
            if flags & 0x02 and not flags & 0x10:   # SYN: the sender is the client
                fl["syn"] += 1
                fl["c"], fl["s"] = (src, sp), (dst, dp)
                fl["syn_t"] = fl["syn_t"] or ts
            elif flags & 0x12 == 0x12:
                fl["synack"] += 1
                fl["c"], fl["s"] = (dst, dp), (src, sp)
                if fl["syn_t"] is not None and fl["hs"] is None:
                    fl["hs"] = (ts - fl["syn_t"]) * 1000
            if flags & 0x04:
                fl["rst"].add(src)
            if flags & 0x01:
                fl["fin"] += 1
            if win == 0 and not flags & 0x04:
                fl["zwin"] += 1
            if pay:
                fl["data"] += 1
                seen = fl["seen"].setdefault(src, set())
                k = (seq, len(pay))
                rx = k in seen
                if rx:
                    fl["retx"] += 1
                elif len(seen) < 50000:
                    seen.add(k)
                if pay[:1] == b"\x16":
                    h = tls_hello(pay)
                    if h:
                        tk = (fl["c"], fl["s"])
                        row = tls_rows.setdefault(tk, {"client": fl["c"][0], "server": "%s:%d" % fl["s"], "sni": "",
                                                       "version": "", "alert": ""})
                        if h[0] == "client_hello":
                            row["sni"] = row["sni"] or h[1]
                            row.setdefault("_ch", ts)
                        else:
                            row["version"] = h[1]
                            if "_ch" in row and "server_hello_ms" not in row:
                                row["server_hello_ms"] = round((ts - row["_ch"]) * 1000, 1)
                elif pay[:1] == b"\x15" and len(pay) == 7 and pay[1] == 3:   # plain-text alert (not encrypted)
                    tk = (fl["c"], fl["s"])
                    row = tls_rows.setdefault(tk, {"client": fl["c"][0], "server": "%s:%d" % fl["s"], "sni": "",
                                                   "version": "", "alert": ""})
                    row["alert"] = "%s %s from %s" % ("fatal" if pay[5] == 2 else "warning",
                                                      TLS_ALERTS.get(pay[6], str(pay[6])), src)
                elif bytes(pay[:8]).startswith(HTTP_METHODS):
                    head = bytes(pay[:2048]).split(b"\r\n")
                    parts = head[0].decode("latin-1", "replace").split(" ")
                    host = next((x[5:].strip().decode("latin-1", "replace") for x in head[1:]
                                 if x[:5].lower() == b"host:"), "")
                    path = parts[1].split("?")[0] + ("?…" if len(parts) > 1 and "?" in parts[1] else "") if len(parts) > 1 else ""
                    http_rows[(src, "%s:%d" % (dst, dp), parts[0], host, path[:200])] += 1
                    if not rx:   # pair with the next response on this connection (HTTP/1.x answers in order)
                        fl.setdefault("http", []).append((ts, src, "%s:%d" % (dst, dp), host, parts[0], path[:200]))
                elif pay[:7] == b"HTTP/1." and len(pay) >= 12:
                    code = bytes(pay[9:12]).decode("latin-1", "replace")
                    http_codes[code] += 1
                    if not rx and not code.startswith("1") and fl.get("http"):
                        t_req, cli, srv_, host, meth, path = fl["http"].pop(0)
                        http_tx.append({"time_s": rel_t(t_req), "client": cli, "server": srv_, "host": host,
                                        "method": meth, "path": path, "status": code,
                                        "response_ms": round((ts - t_req) * 1000, 1)})
        elif proto == 17 and len(l4) >= 8 and 53 in (sp, dp):
            d = dns_parse(l4[8:])
            if d:
                tid, resp, rc, name, qt, ans = d
                if not resp:
                    dns_q[(src, sp, tid, name)] = (ts, dst, qt)
                else:
                    q = dns_q.pop((dst, dp, tid, name), None)
                    dns_rows.append({"client": dst, "server": src, "name": name, "type": qt,
                                     "result": DNS_RCODES.get(rc, "rcode %d" % rc),
                                     "answers": ", ".join(ans[:6]) + (" …" if len(ans) > 6 else ""),
                                     "ms": round((ts - q[0]) * 1000, 1) if q else None})
    if not pk:
        raise ValueError("the capture holds no packets" + (" (the file is cut short)" if info["truncated"] else ""))
    dur = max(0.0, (t1 or 0) - (t0 or 0))
    rel = lambda t: round(t - t0, 3)   # noqa: E731
    findings, kind = [], "ok"

    def bad(text, k="bad"):
        nonlocal kind
        findings.append(text)
        kind = "bad" if k == "bad" or kind == "bad" else "warn"

    tcp = [f for f in flows.values() if f["proto"] == "TCP"]
    noreply = collections.Counter("%s:%d" % f["s"] for f in tcp if f["syn"] and not f["synack"] and not f["rst"])
    refused = collections.Counter("%s:%d" % f["s"] for f in tcp if f["syn"] and not f["synack"] and f["rst"])
    if noreply:
        bad("%d TCP connection attempt(s) got no reply (SYN only): %s" % (sum(noreply.values()), ", ".join(
            "%s (%d)" % kv for kv in noreply.most_common(5))))
    if refused:
        bad("%d TCP connection attempt(s) were refused with a reset: %s" % (sum(refused.values()), ", ".join(
            "%s (%d)" % kv for kv in refused.most_common(5))))
    resets = [f for f in tcp if f["rst"] and f["synack"]]
    if resets:
        by_who = collections.Counter(h for f in resets for h in f["rst"])
        bad("%d established TCP connection(s) were reset, reset sent by: %s" % (len(resets), ", ".join(
            "%s (%d)" % kv for kv in by_who.most_common(5))))
    mid = [f for f in tcp if f["rst"] and not f["syn"] and not f["synack"]]
    if mid:
        by_who = collections.Counter(h for f in mid for h in f["rst"])
        bad("%d TCP reset(s) on connections whose start is not in the capture, sent by: %s" % (len(mid), ", ".join(
            "%s (%d)" % kv for kv in by_who.most_common(5))), "warn")
    data_segs, retx = sum(f["data"] for f in tcp), sum(f["retx"] for f in tcp)
    if retx:
        worst = max(tcp, key=lambda f: f["retx"])
        pct = 100.0 * retx / max(1, data_segs)
        bad("%d TCP retransmission(s) (%.1f%% of data segments); most on %s:%d -> %s:%d (%d)" % (
            retx, pct, worst["c"][0], worst["c"][1], worst["s"][0], worst["s"][1], worst["retx"]),
            "bad" if pct >= 3 else "warn")
    zw = [f for f in tcp if f["zwin"]]
    if zw:
        bad("Zero-window (receiver full) seen on %d connection(s)" % len(zw), "warn")
    slow = [f for f in tcp if f["hs"] is not None and f["hs"] > 200]
    if slow:
        f = max(slow, key=lambda x: x["hs"])
        bad("Slow TCP handshake on %d connection(s); slowest %.0f ms to %s:%d" % (len(slow), f["hs"], *f["s"]), "warn")
    dfail = [r for r in dns_rows if r["result"] != "NOERROR"]
    if dfail:
        c = collections.Counter("%s %s" % (r["result"], r["name"]) for r in dfail)
        bad("DNS errors: %s" % ", ".join("%s (%d)" % kv for kv in c.most_common(6)))
    if dns_q:
        bad("%d DNS quer(y/ies) got no answer in the capture: %s" % (len(dns_q), ", ".join(
            sorted({k[3] for k in dns_q})[:5])), "warn")
    alerts = [r for r in tls_rows.values() if r["alert"] and "close_notify" not in r["alert"]]
    if alerts:
        bad("TLS alerts: %s" % "; ".join("%s -> %s (%s)" % (r["client"], r["server"], r["alert"]) for r in alerts[:5]))
    for (what, s, d, about), n in icmp.most_common():
        if "echo" not in what and "neighbor" not in what and "router" not in what:
            bad("ICMP %s from %s to %s%s (%d)" % (what, s, d, (" about " + about) if about else "", n), "warn")
            if len(findings) > 25:
                break
    if http_tx:
        worst = max(http_tx, key=lambda x: x["response_ms"])
        if worst["response_ms"] >= 1000:
            bad("Slowest HTTP response %.0f ms: %s %s%s (%s, status %s)" % (worst["response_ms"], worst["method"],
                worst["host"] or worst["server"], worst["path"], worst["server"], worst["status"]), "warn")
        e5 = [x for x in http_tx if x["status"].startswith("5")]
        if e5:
            c = collections.Counter("%s %s" % (x["status"], x["host"] or x["server"]) for x in e5)
            bad("HTTP server errors: %s" % ", ".join("%s (%d)" % kv for kv in c.most_common(5)), "warn")
    http_open = [r for f in flows.values() for r in f.get("http") or []]
    if http_open:
        c = collections.Counter(r[3] or r[2] for r in http_open)
        bad("%d HTTP request(s) got no response in the capture: %s" % (len(http_open), ", ".join(
            "%s (%d)" % kv for kv in c.most_common(5))), "warn")
    for ipa, macs in arp_map.items():
        if len(macs) > 1:
            bad("ARP: %s is claimed by %d MAC addresses (%s): IP conflict or failover" % (ipa, len(macs), ", ".join(sorted(macs))))
    if info["truncated"]:
        bad("The capture file is cut short (last packet incomplete); results cover what could be read", "warn")
    if info.get("cut"):
        bad("Only the first %d packets were analysed" % PCAP_MAX_PKTS, "warn")

    def state(f):
        if f["proto"] != "TCP":
            return ""
        if f["syn"] and not f["synack"]:
            return "refused (RST)" if f["rst"] else "no reply to SYN"
        if f["rst"]:
            return "reset by " + ", ".join(sorted(f["rst"]))
        if f["fin"]:
            return "closed (FIN)"
        return "established" if f["synack"] else "mid-stream (handshake not in capture)"

    def frow(f):
        return {"proto": f["proto"], "client": f["c"][0] + (":%d" % f["c"][1] if f["c"][1] else ""),
                "server": f["s"][0] + (":%d" % f["s"][1] if f["s"][1] else ""), "packets": f["pk"], "bytes": f["by"],
                "start_s": rel(f["t0"]), "duration_s": round(f["t1"] - f["t0"], 3), "state": state(f),
                "handshake_ms": round(f["hs"], 1) if f["hs"] is not None else "", "retransmissions": f["retx"] or ""}

    problem = [f for f in flows.values() if f["proto"] == "TCP" and (f["rst"] or (f["syn"] and not f["synack"]) or f["retx"] or f["zwin"])]
    problem.sort(key=lambda f: (-(f["syn"] and not f["synack"]), -len(f["rst"]), -f["retx"]))
    top = sorted(flows.values(), key=lambda f: -f["by"])[:30]
    when = lambda t: datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if t else ""   # noqa: E731
    data_out = collections.OrderedDict()
    data_out["capture"] = collections.OrderedDict([
        ("file", fname), ("format", info["format"]), ("link_type", ", ".join(PCAP_LINKS.get(k, "type %d" % k) for k in links)),
        ("packets", pk), ("bytes", by), ("first_packet", when(t0)), ("last_packet", when(t1)),
        ("duration_s", round(dur, 3)), ("conversations", len(flows)), ("ip_fragments", frags),
        ("protocols", ", ".join("%s %d" % kv for kv in protos.most_common()))])
    if problem:
        data_out["problem_connections"] = [frow(f) for f in problem[:40]]
    data_out["top_conversations"] = [frow(f) for f in top]
    data_out["top_talkers"] = [{"ip": h, "packets": v[0], "bytes": v[1]} for h, v in
                               sorted(talk.items(), key=lambda kv: -kv[1][1])[:15]]
    if dns_rows or dns_q:
        dns_rows.sort(key=lambda r: (r["result"] == "NOERROR", -(r["ms"] or 0)))
        data_out["dns"] = dns_rows[:60] + [{"client": k[0], "server": v[1], "name": k[3], "type": v[2],
                                            "result": "no answer", "answers": "", "ms": None}
                                           for k, v in list(dns_q.items())[:20]]
    if tls_rows:
        for r in tls_rows.values():
            r.pop("_ch", None)
            r.setdefault("server_hello_ms", "")
        data_out["tls"] = sorted(tls_rows.values(), key=lambda r: (not r["alert"], r["server"]))[:50]
    if http_rows:
        data_out["http_requests"] = [{"client": k[0], "server": k[1], "method": k[2], "host": k[3], "path": k[4], "count": n}
                                     for k, n in http_rows.most_common(40)]
    if http_tx or http_open:
        hosts = collections.OrderedDict()
        for x in http_tx:
            hosts.setdefault(x["host"] or x["server"], []).append(x)
        for r in http_open:
            hosts.setdefault(r[3] or r[2], [])
        rows = []
        for h, xs in hosts.items():
            ms = [x["response_ms"] for x in xs]
            slow = max(xs, key=lambda x: x["response_ms"]) if xs else None
            rows.append({"host": h, "requests": len(xs) + sum(1 for r in http_open if (r[3] or r[2]) == h),
                         "answered": len(xs), "avg_ms": round(sum(ms) / len(ms), 1) if ms else "",
                         "max_ms": max(ms) if ms else "",
                         "slowest": "%s %s -> %s at +%ss" % (slow["method"], slow["path"], slow["status"], slow["time_s"])
                         if slow else "",
                         "errors_4xx_5xx": sum(1 for x in xs if x["status"][:1] in ("4", "5")) or ""})
        rows.sort(key=lambda r: -(r["max_ms"] or 0))
        data_out["http_response_times_by_host"] = rows[:50]
        if http_tx:
            data_out["http_slowest_responses"] = sorted(http_tx, key=lambda x: -x["response_ms"])[:25]
    if http_codes:
        data_out["http_status_codes"] = dict(http_codes.most_common())
    if icmp:
        data_out["icmp"] = [{"message": k[0], "from": k[1], "to": k[2], "about": k[3], "count": n}
                            for k, n in icmp.most_common(30)]
    if arp_n:
        data_out["arp"] = [{"ip": ipa, "mac": ", ".join(sorted(m)), "conflict": "yes" if len(m) > 1 else ""}
                           for ipa, m in sorted(arp_map.items(), key=lambda kv: -len(kv[1]))[:30]] or \
                          [{"requests": arp_n["request"], "replies": arp_n["reply"]}]
    summary = ["%d packets, %d conversations over %.1f s (%s)" % (pk, len(flows), dur, info["format"])] + findings
    return {"ok": True, "status": 200, "ms": int((time.time() - t_start) * 1000),
            "verdict": {"kind": kind, "label": "Capture: %s" % ("problems found" if kind == "bad" else
                                                                  "worth a look" if kind == "warn" else "no obvious problems")},
            "summary": summary, "request": "packet capture %s" % fname, "data": data_out}


def do_pcap_upload(raw, fname):
    fname = re.sub(r"[^\w.\- ()]", "_", urllib.parse.unquote(fname or "capture"))[:120] or "capture"
    try:
        return pcap_analyze(bytes(raw), fname)
    except (ValueError, struct.error) as e:
        return {"ok": False, "error": "could not read %s: %s" % (fname, e)}


# ---- Live update: edits to this file are picked up while the console runs (no restart, nothing to re-enter) ----
# The new code is first run in a fresh namespace; only if it loads cleanly does the server switch to it. The objects
# below are the console's live state and are handed over unchanged, so connected devices, SSH terminals, the unlocked
# saved logins, AI settings, caches and the URL token survive an update. A file with errors is not applied: the page
# shows the error and the old code keeps running. The watcher itself and main() only change on a real restart.
LIVE_STATE = ("TOKEN", "SESSIONS", "AUDIT", "LOCK", "TERMS", "TERM_LOCK", "VAULT", "VAULT_LOCK", "F5_HOST_CACHE",
              "PAN_VRS", "CAPTURE_BUSY", "CF_EDGE", "WHOIS_BOOT", "LLM_CFG", "HOT", "MON")
HOT = {"gen": 0, "page": "", "error": "", "time": ""}


def devices_public():
    with LOCK:
        items = list(SESSIONS.items())
    out = []
    for sid, s in items:
        d = {"ok": True, "id": sid, "name": s.get("name") or s.get("host"), "vendor": s.get("vendor"),
             "host": s.get("host"), "user": s.get("user", "")}
        if s.get("vendor") == "cloudflare":
            d.update(zones=[z.get("name") for z in s.get("zones") or []], accounts=len(s.get("accounts") or {}))
        out.append(d)
    return out


def hot_page_id(page):
    return hashlib.sha256(page.encode("utf-8")).hexdigest()[:12]


def hot_reload(srv, cur):
    """Load this file again and switch the running server to it. Returns the namespace now in use."""
    path = os.path.abspath(__file__)
    try:
        with open(path, encoding="utf-8") as f:
            src = f.read()
        code = compile(src, path, "exec")
        ns = {"__name__": "__main__", "__file__": path, "__builtins__": __builtins__, "_HOT_RELOADING": True}
        exec(code, ns)
        if not isinstance(ns.get("Handler"), type) or "PAGE" not in ns:
            raise RuntimeError("the new file has no Handler / PAGE")
    except Exception as e:   # noqa: BLE001 - any error in the edited file: keep the old code running
        line = getattr(e, "lineno", None)
        cur["HOT"]["error"] = "%s%s: %s" % (type(e).__name__, " (line %s)" % line if line else "", e)
        cur["HOT"]["time"] = time.strftime("%H:%M:%S")
        print("[live update] NOT applied, old code keeps running: " + cur["HOT"]["error"])
        return cur
    for k in LIVE_STATE:
        if k in cur:
            ns[k] = cur[k]
    ns.pop("_HOT_RELOADING", None)
    hot = ns["HOT"]
    hot.update(gen=hot["gen"] + 1, page=hot_page_id(ns["PAGE"]), error="", time=time.strftime("%H:%M:%S"))
    srv.RequestHandlerClass = ns["Handler"]
    print("[live update] applied update #%d at %s" % (hot["gen"], hot["time"]))
    return ns


def hot_watch(srv):
    path, cur = os.path.abspath(__file__), globals()
    last = os.path.getmtime(path)
    while True:
        time.sleep(1.5)
        try:
            m = os.path.getmtime(path)
            if m == last:
                continue
            time.sleep(0.8)   # let the editor finish writing
            if os.path.getmtime(path) != m:
                continue
            last = m
        except OSError:
            continue
        cur = hot_reload(srv, cur)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--no-live-update", action="store_true", help="do not pick up edits to this file while running")
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    HOT["page"] = hot_page_id(PAGE)
    if not a.no_live_update:
        threading.Thread(target=hot_watch, args=(srv,), daemon=True).start()
    srv.allowed_hosts = {"127.0.0.1:%d" % a.port, "localhost:%d" % a.port}
    url = "http://127.0.0.1:%d/?t=%s" % (a.port, TOKEN)
    print("ITSec Ops (read-only). Open:\n  " + url + "\nCtrl+C to stop; credentials are cleared on exit.")
    if not a.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__" and not globals().get("_HOT_RELOADING"):
    main()
