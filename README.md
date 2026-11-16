# ITSec Ops (netsecops)

A local, single-file web console for troubleshooting **F5 BIG-IP**, **Palo Alto PAN-OS** and **FortiGate**
devices, and **Cloudflare** accounts, from one place. Python 3.8+, standard library only, no dependencies, built with Claude Code.

## Features
- Health checks and curated read-only status queries per vendor
- "Where does this IP appear?" lookup (F5 pools, nodes, virtual servers, data groups, policies; PAN/Forti rules
  that reference the IP)
- PAN-OS / FortiGate policy lookup (one box): an IP or subnet shows the objects and rules that reference it; a name
  (or FortiGate policy ID) finds the rule with its position, action, objects resolved to their values, security
  profiles and hit count; "List all policies" lists every rule
- PAN-OS / FortiGate flow check: source and destination IP (optional port, protocol; zones on PAN-OS) show which rule
  allows or blocks the flow; on FortiGate the ingress interface is optional and taken from the route to the source
- Flow trace (one card, shown once a device is connected): one flow (client IP -> destination IP or hostname, port,
  protocol) traced through the connected devices it actually crosses. Nothing is tied to device names, vendors or
  a fixed order: the path is found from each device's own configuration, so it fits any mix of FortiGate, Palo Alto
  and F5 (and Cloudflare). Only the devices on the path are shown, each tested with the addresses it sees; a device
  that does not answer is left out. The steps, each only where it applies:
  1. Edge: Cloudflare, for a hostname in its zones or a Cloudflare address: DNS record (origin IP, proxied or not)
     and WAF events for the client IP. When proxied, the next devices are tested with a Cloudflare edge address
  2. Upstream 1:1 NAT (cloud public IPs, a provider router): public -> private IP from the optional NAT list
     (`nat_map.txt`) or the optional VIP list (`vip_map.txt`: name or hostname, firewall VIP, F5 VIP, pasted from a
     spreadsheet; both git-ignored), or inferred when exactly one FortiGate VIP maps to the F5 virtual server
  3. Edge firewall: whichever connected firewall translates the destination: a FortiGate VIP or a Palo Alto
     destination / bi-directional static NAT rule. Policy verdict for the address it receives, then the translation
  4. Load balancer: the F5 whose virtual server is the translated address (or that serves the hostname): enabled,
     pool members up / down, and the source address it uses (automap: the self IP in the member's subnet or towards
     the route's gateway; SNAT pool: its first member)
  5. Firewall between the F5 (or the edge NAT) and the servers, e.g. a DC firewall: policy verdict for the address
     pair it sees
  A flow without a destination NAT (two internal addresses) starts at the firewall the client's subnet is connected to.
  How a firewall is placed on the path, strongest evidence first: the next hops from the device before it (route
  gateway = an interface address of a connected device: FortiOS `router/lookup`, PAN-OS `test routing fib-lookup`,
  F5 self IPs and static routes; all read-only); the flow crosses it (different interfaces towards the source and the
  destination) and the destination's subnet (or, at the start, the source's) is directly connected to it; with "Also
  search logs", its traffic log shows the flow; only when none of these finds anything for an internal flow, the
  routes alone. Cloud subnet routers (OCI, AWS, Azure) are not connected devices, which is why the "directly
  connected" evidence matters. Not taken into account: policy-based routing, SD-WAN rules, asymmetric return paths.
  The result opens with a diagram of the path (client → the devices crossed, in order → server): each device
  green / red / amber, animated flow up to where it stops, and next to each device the source → destination it sees;
  then one row per device and check, and the first block found ("STOPS AT ..."). FortiOS policy lookup on a VIP's
  external address and the PAN-OS route lookup reply are not yet verified on real units
- F5 ASM/WAF request-log search (incl. by any HTTP header: value, IP, True-Client-IP, hostname, URL, time, support ID, POST body), top-10 hostnames by violations (with source IPs, True-Client-IPs, URLs), WAF and SSL posture checks
- FortiGate lookups: Virtual IPs (name / external / mapped IP filter), static routes (IP, gateway, interface filter)
- PAN-OS lookups: destination / static NAT rules (the Virtual IP equivalent), configured static routes, session list
  with source / destination filter (URL category lookup was already available)
- SSH to F5, FortiGate and Palo Alto from the "SSH" card of the selected device, with this PC's OpenSSH client
  (`ssh -p <port> -l <user> <device>`; user name prefilled from the login when known):
  - "Open SSH in this page": a terminal inside the console (Windows 10 1809+; several at once). Click it to type;
    copy with a selection + Ctrl+C, paste with Ctrl+V; Disconnect ends the session
  - "Open in a separate window": a normal Windows terminal window; other systems get the command to copy
  - Every connection allows the hmac-sha1 MAC (`-o MACs=+hmac-sha1`), which older devices still need and OpenSSH 10
    no longer offers by default; devices with SHA-2 MACs still use those
  - "Allow older algorithms" (tick-box) is for old devices that answer "Unable to negotiate ... no matching key
    exchange / host key type / cipher": it adds SHA-1 key exchange, ssh-rsa and AES-CBC to that one connection
    only (MD5, DH group 1, 3DES and DSA stay off)
- Source NAT for an IP (check "Source NAT for an IP" on each device; the AI can run it too): what the IP is translated
  to when it is the source
  - Palo Alto: NAT rules that cover it in evaluation order (shared pre, local, shared post), objects / groups resolved,
    translated address or interface; with a destination, the firewall's own answer (`test nat-policy-match`, zones
    optional)
  - FortiGate: policies with NAT (IP pool with its range, or the egress interface address), central SNAT map in
    central-NAT mode, VIPs with nat-source-vip; with a destination, the policy the firewall's policy lookup picks
  - F5: standalone SNAT objects whose origins include the IP (virtual-server SNAT is in the flow trace)
- Resource utilization for PAN-OS and FortiGate (Checks, or the button on the health card): tiles, charts and findings
  with warning / high thresholds. PAN-OS: management CPU and memory (cache excluded), load, top processes, dataplane
  CPU per data processor (average of active cores, the busiest core, the highest core maximum), session table,
  packet buffers / descriptors, CPS / throughput / PPS, disk partitions, a per-core heatmap (cores x time) and the
  top management-plane processes by CPU and memory. FortiGate: CPU (incl. per core), memory
  against the device's own conserve-mode thresholds, log disk, sessions, setup rate and log rates.
  Time range (e.g. `1h`, `6h`, `3d`, `2w`): PAN-OS dataplane history goes back up to 13 weeks (per minute for 1 hour, per
  hour for 24 hours, per day for 7 days, per week for 13 weeks); management CPU / memory, sessions and disk are always
  current values. FortiOS keeps resource history for 24 hours at most; longer ranges add the memory conserve-mode
  enter / leave events from the system event log (needs Log & Report read)
- Palo Alto application traffic volume over a period (Checks > Traffic): sessions, bytes, average per hour and Mbit/s
  per application from the firewall's summary database (dynamic report top-app-summary), so a 24-hour or 7-day
  question covers the whole period instead of a log sample
- F5 top virtual servers: ranked by current, total or max connections, traffic or packets (Checks > LTM)
- F5 performance dashboard (Checks, or the button on the health card), time range 30 minutes to 24 hours: tiles
  (average CPU, busiest core, memory, TMM memory, control-plane memory, swap, fullest disk), CPU and memory charts
  over time, CPU per core, top 10 processes by CPU and by memory, subsystem CPU and memory (tmm, waf, l7_dos,
  log_analytics, fw, ... grouped by process), disk use per partition, with findings. Read-only REST gives the current
  values and the performance averages; with the F5 active-tools tick-box (Administrator) it also reads the history
  from the BIG-IP's own RRD files plus `top` and `df` through fixed, read-only util/bash commands
- ACC (Application Command Center-style dashboard) for PAN-OS and FortiGate, built from the firewall's logs with
  read-only log queries: headline tiles (sessions, data, applications, sources, blocked sessions, threats,
  critical / high threats, blocked URLs), charts over time, and top-10 lists in four tabs:
  - Network activity: applications, source / destination IPs, users, rules / policies, zones / interfaces,
    destination ports, countries, categories (FortiGate also: services, high-risk applications)
  - Threat activity: threats, severity, threat types, attackers, victims, applications, rules, actions
  - Blocked activity: blocked applications, sources, destinations, ports, blocking rules, threats, URL categories, hosts
  - URL activity: URL categories, web hosts, users, sources

  Global filters (source / destination IP or subnet, application, user, rule / policy, zone / interface, port) are
  sent to the firewall's log query and applied again locally. Click any entry to add it as a filter, and click a
  filter chip to remove it. The time range goes up to 7 days. On a busy firewall the read limit (5,000 entries per log
  type by default, up to 50,000) can cover less than the whole range, and the output shows exactly which time span was
  covered. Only traffic logged by a rule is counted, as in the firewall's own ACC
- AI assistant with a local LLM (any OpenAI-compatible server: Ollama, LM Studio, llama.cpp server, vLLM), in a chat
  panel opened from the "✦ AI" button in the bottom-right corner of the page:
  - Explain current output: what it shows, what is wrong or unusual, the likely cause and the next checks to run
  - Ask about current output: follow-up questions on the same output, with the conversation kept
  - Ask & run checks: the model answers any question by choosing and running up to 8 of the console's read-only
    lookups on ALL connected devices, whichever one is selected (tools named per device type: pa_, fg_, f5_, cf_;
    catalog checks, IP / policy lookup, log search, ACC, F5 hostname / WAF log search, Cloudflare lookups; a device
    field picks one when several of a type are connected), and combines them across devices; plus a policy check
    (every connected Palo Alto / FortiGate: which rule allows or blocks IP A -> IP B:port) and the flow trace for
    internet clients and published hostnames. Each call is in the audit log of the device it read and its result can
    be opened in Output. Needs a model with tool calling (e.g. qwen2.5 / qwen3, llama3.1+, mistral-nemo)
  - Typing a question and pressing Enter uses "Ask & run checks" whenever a device is connected (the output on
    screen is still sent along); "Ask about current output" answers from the screen only
  - Every answer is checked: names and IPs it states that are not in the data the model was given are listed in a
    warning (small models can invent them)

  Quick start: `ollama pull qwen2.5:14b`, `ollama serve`, then in Model settings use `http://127.0.0.1:11434/v1`,
  List models, Save. For long outputs start Ollama with a bigger context window (e.g. `OLLAMA_CONTEXT_LENGTH=16384`)
- PAN-OS / FortiGate log search, admin-change audit; log searches take a time range (up to 1 day back) on F5,
  FortiGate and the F5/FortiGate admin audit (PAN-OS has its own time-range selector)
- Optional F5 active tools (log search, tcpdump ( with the ability to extract the pms by utilizing tshark with f5 filters and save the output in .pms,
  both pcap and pms will be downloaded to the project folder and a copy is kept on the BIG-IP in /var/tmp, readable by root only)
- F5 file download (same tick-box): list a BIG-IP folder, download any file (or a folder as .tar.gz) up to 500 MB
  over iControl REST, MD5-checked; files holding secrets (password hashes, keys, master key, bigip.conf, UCS) need
  a second tick-box
- PAN-OS packet capture is disabled (the console refuses it; F5 tcpdump capture is unchanged)
- Configuration backup (F5: explicit tick-box required, the UCS archive is also kept on the BIG-IP;
  PAN-OS / FortiGate: read-only export)
- Cloudflare (API token; every lookup runs over all zones the token sees, for the last 24 hours; the traffic
  dashboard can zoom into a shorter period):
  - Investigate an IP (security events, traffic, IP Access Rules incl. ranges / ASN / country, IP lists, rules and
    DNS records that involve it, whether it is a Cloudflare edge address), a hostname (DNS and proxy status,
    certificates, zone settings, rules, Workers routes, page rules, load balancers, 5xx / 52x origin errors) or a
    Ray ID (what Cloudflare did with that request)
  - Security event search (IP, host, path, Ray ID, action, source, rule, country, ASN, user agent, method) and
    top-N / timeline by action, source, rule, IP, host, path, country, ASN, user agent, colo
  - HTTP traffic summaries (status codes, origin status, cache, TLS / HTTP version, colo, ...) and sampled requests
  - URL response time: edge TTFB and origin response time (p50 / p95 / p99, average) for a URL (exact path, prefix
    or contains), a timeline, breakdowns by status, cache, colo, method and path, and the slowest requests with
    DNS / TCP / TLS / response-header timings to the origin
  - Ray ID trace across Cloudflare → F5 → origin: the Cloudflare request and security events and the F5 ASM entry
    found by the `CF-Ray` header (support ID, violations), with a verdict on where it stopped (a request blocked by
    the F5 is shown as not reaching the origin: the HTTP 200 Cloudflare saw is the F5 blocking page)
  - WHOIS for an IP (network, range, owner, country, abuse contact, ASN holder) and a domain (registrar, dates,
    status, name servers, DNSSEC), via RDAP with port-43 WHOIS as fallback; also part of the IP and hostname
    investigations, with findings for domain expiry, registry holds and a missing transfer lock
  - Traffic dashboard (optional button): headline tiles with change vs the previous period, requests, data
    transfer, status codes, cache status and edge TTFB p50 / p95 / p99 over time, and top paths, countries,
    client IPs, ASNs, hosts and referrers; drawn in the page (no external libraries), with the numbers as tables below.
    Click to drill in: an IP or host opens its investigation, a path / country / ASN filters the dashboard, a
    referrer runs WHOIS, a chart column zooms to that time (1-minute columns list the sampled requests)
  - Rule search (text, IP, `$list`, rule or ruleset ID, incl. managed rules a zone deploys), DNS search, security
    posture (SSL mode, minimum TLS, HTTPS redirect, security level, True-Client-IP header, certificates, DNS-only records),
    load balancer origin health and health checks, account audit log
  - The Ray ID trace uses the connected F5 (the first one if several are connected) to find the request in the ASM
    log by its `CF-Ray` header, so one lookup shows whether Cloudflare or the F5 blocked it
  - The raw box accepts `/client/v4/...` GET paths or GraphQL queries (mutations are refused)

## Run
```
python3 netops_console.py
```
Open the URL printed in the terminal.

## Security model
- Binds to `127.0.0.1` only; random per-launch token plus Host-header check (CSRF / DNS-rebinding protection).
- Credentials live in memory only, unless you tick "Remember this login on this PC" when connecting. Remembered
  logins are encrypted with Windows DPAPI for your Windows account and with a passphrase (PBKDF2, 300k rounds), in
  `saved_logins.dat` next to the console (git-ignored). After a restart, enter the passphrase in the Devices card to
  reconnect every saved device. Without the passphrase, or under another Windows account, the file cannot be read.
  "Forgot the passphrase?" deletes it.
- Saved profiles (`device_profiles.json`) hold only label, vendor, address, port and TLS setting.
- Checks are read-only (GET, or PAN-OS `<show>`/allow-listed `<test>`). Exceptions are documented in the script
  header and require an explicit tick-box:
  - F5 active tools and F5 backup run fixed shell commands through `util/bash` (Administrator role).
  - PAN-OS packet capture is disabled: the console refuses it, so no packet-diag state is ever changed.
- SSH: in the page, keystrokes (the password too) pass through the console process to `ssh` and are never stored,
  logged or shown to the AI; only opening and closing a session go to the audit log. The session is a normal CLI
  session (not read-only). The AI has no SSH tool.
- AI assistant: device data is sent only to an approved model server: this PC (127.0.0.1 / localhost) or a host in
  `llm_approved.txt` next to `netops_console.py` (one host name per line; kept out of git, none by default). Any other address is refused, checked before
  every request. The model server is always reached directly (never through the system or a cloud web proxy), and a
  redirect is refused instead of followed, so neither the prompt nor the API key can be sent elsewhere. Model
  settings show where the data goes. Before sending, passwords, keys, tokens, hashes and PEM blocks are masked and large
  output is trimmed to the context budget. The model can only call read-only lookups; active tools are never offered
  to it, and nothing it writes is run. Model settings and the optional API key live in memory only.
- Backups and captures are written to `./captures` (git-ignored). **Never commit them**: they contain
  device configuration and secrets.



## Required permissions
Start with a read-only account; the everyday checks work with it. Use a stronger account only
for the features that need one, and only when you need them.

### F5 BIG-IP
| Feature | Account needed |
|---|---|
| Checks, IP / hostname lookup, WAF and SSL posture, ASM request log | Read access to iControl REST (e.g. Auditor; on some TMOS versions non-Administrator roles need REST access granted) |
| Active tools (log search, tcpdump, .pms), admin audit, config sync review, configuration backup | **Administrator**. These run fixed commands through `/mgmt/tm/util/bash` |

### Palo Alto PAN-OS
Built-in read-only roles cover the checks. For backup, use a custom Admin Role
Profile with only these XML API permissions:

| XML API permission | Used for |
|---|---|
| Operational Requests | `<show>` / allow-listed `<test>` checks |
| Configuration | IP lookup, NAT rules, static routes (reads the running config) |
| Log | Log search, ACC, admin audit |
| Export | Configuration backup |

Leave Commit, Import and User-ID off.

### FortiGate
Use a REST API admin with an admin profile limited to what you need, and set **Trusted hosts** to
the machine running this tool.

| Feature | Admin profile access |
|---|---|
| Checks, IP lookup, VIPs, static routes, sessions | Read on System, Network, Firewall |
| Traffic log search, ACC, admin audit | Read on Log & Report |
| Configuration backup | **super_admin** profile (FortiOS requires it for the backup API) |


### Cloudflare
Create a **custom API token** with read permissions only (Read, never Edit), limited to the zones / accounts you
work on. Each permission only enables its part; anything missing is reported in the output, not as a failure.
Permission names below are as the Cloudflare dashboard shows them and may change slightly over time.

| Feature | Token permission (Read) |
|---|---|
| Everything (zone list) | Zone: Zone |
| Security events, traffic summaries, sampled requests, Ray ID | Zone: Analytics |
| DNS search, hostname / IP investigation | Zone: DNS |
| Security posture, hostname investigation | Zone: Zone Settings, Zone: SSL and Certificates, Zone: Transform Rules |
| Rule search, IP / hostname investigation | Zone: Zone WAF, Zone: Firewall Services, Account: Account Rulesets, Account: Account Firewall Access Rules, Account: Account Filter Lists |
| Hostname investigation (extras) | Zone: Workers Routes, Zone: Page Rules |
| Load balancers & health checks | Zone: Load Balancers, Zone: Health Checks, Account: Load Balancing: Monitors and Pools |
| Audit log | Account: Account Settings (audit logs) |

Which analytics datasets exist, and how far back and how wide one query can be, depends on the zone plan.
For an account-owned token, enter the Account ID when connecting.

## Disclaimer
Use only on devices you are authorised to administer. Provided as-is, without warranty; review the code
before pointing it at production. Use a least-privilege account (see *Required permissions*).

## License
MIT. See [LICENSE](LICENSE).
