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
  protocol) followed along the path Cloudflare -> FortiGate DMZ -> F5 DMZ -> Palo Alto, each device tested with the
  addresses it sees:
  1. Cloudflare: DNS record (origin IP, proxied or not) and WAF events for the client IP. When proxied, the next
     devices are tested with a Cloudflare edge address as source (from Cloudflare's published ranges)
  2. FortiGate: policy verdict for that source -> origin IP:port, then the VIP that maps it to the F5 virtual address
     (a policy with NAT enabled is flagged)
  3. F5: virtual server on the mapped address (or for the hostname), enabled, pool members up / down, and the SNAT
     address it uses (automap: the self IP in the member's subnet, floating preferred; SNAT pool: its first member)
  4. Palo Alto: policy verdict for F5 SNAT address -> pool member IP:port
  A hostname not in Cloudflare is resolved through the F5 virtual server and the FortiGate VIP. Optional log search
  (F5 WAF log by the client IP header when proxied; FortiGate and Palo Alto traffic logs). The result is one row per
  device and check, and the first block found ("STOPS AT ..."). Devices not connected are skipped; routing between
  the devices is not checked; FortiOS policy lookup on a VIP's external address is not yet verified on a real unit
- F5 ASM/WAF request-log search (incl. by any HTTP header: value, IP, True-Client-IP, hostname, URL, time, support ID, POST body), top-10 hostnames by violations (with source IPs, True-Client-IPs, URLs), WAF and SSL posture checks
- FortiGate lookups: Virtual IPs (name / external / mapped IP filter), static routes (IP, gateway, interface filter)
- PAN-OS lookups: destination / static NAT rules (the Virtual IP equivalent), configured static routes, session list
  with source / destination filter (URL category lookup was already available)
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
- Optional PAN-OS packet capture (packet-diag, explicit tick-box required), downloaded as .pcap
- Configuration backup (F5: explicit tick-box required, the UCS archive is also kept on the BIG-IP;
  PAN-OS / FortiGate: read-only export)
- Cloudflare (API token; every lookup runs over all zones the token sees, or one zone, for a time range):
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
  - Cross-check with a connected F5: a Ray ID is looked up in the ASM log by the `CF-Ray` header, an IP by
    True-Client-IP, so one lookup shows whether Cloudflare or the F5 blocked a request
  - The raw box accepts `/client/v4/...` GET paths or GraphQL queries (mutations are refused)

## Run
```
python3 netops_console.py
```
Open the URL printed in the terminal.

## Security model
- Binds to `127.0.0.1` only; random per-launch token plus Host-header check (CSRF / DNS-rebinding protection).
- Credentials live in memory only and are never written to disk.
- Saved profiles (`device_profiles.json`) hold only label, vendor, address, port and TLS setting.
- Checks are read-only (GET, or PAN-OS `<show>`/allow-listed `<test>`). Exceptions are documented in the script
  header and require an explicit tick-box:
  - F5 active tools and F5 backup run fixed shell commands through `util/bash` (Administrator role).
  - PAN-OS packet capture changes packet-diag state and clears all packet-diag settings before and after,
    which ends any capture another admin has running.
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
Built-in read-only roles cover the checks. For packet capture and backup, use a custom Admin Role
Profile with only these XML API permissions:

| XML API permission | Used for |
|---|---|
| Operational Requests | `<show>` / allow-listed `<test>` checks, packet capture (`debug dataplane packet-diag`) |
| Configuration | IP lookup, NAT rules, static routes (reads the running config) |
| Log | Log search, ACC, admin audit |
| Export | Packet capture download, configuration backup |

Leave Commit, Import and User-ID off. Packet capture changes packet-diag state, so read-only
roles are refused.

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
