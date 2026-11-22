# ITSec Ops (netsecops)

A local, single-file web console for troubleshooting **F5 BIG-IP**, **Palo Alto PAN-OS**, **FortiGate**,
**FortiWeb** and **FortiADC** devices, **Cloudflare** accounts and **SolarWinds Orion** monitoring, from one place. Python 3.8+, standard library only, no dependencies, built with Claude Code.

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
     the route's gateway; SNAT pool: its first member). With a client IP (not behind a proxy), the F5's live
     connections (`show sys connection cs-client-addr`) show the pool member the client is really on, and the next
     firewall is tested with that exact F5 source -> member pair
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
- F5 live connections by client IP (LTM > "Live connections by client IP"): client, virtual server, F5 source
  (self IP / SNAT) and pool member for each connection, read-only (`tmsh show sys connection` through the REST API)
- F5 ASM/WAF request-log search (incl. by any HTTP header: value, IP, True-Client-IP, hostname, URL, time, support ID, POST body), top-10 hostnames by violations (with source IPs, True-Client-IPs, URLs), WAF and SSL posture checks
  - Attack filter: 'Attack type / signature / violation contains' (e.g. Buffer Overflow, SQL-Injection, Illegal meta character), alone or with the other
    filters. Each blocked / alerted request's full record is read (up to 1,500 per search, 2 minutes) and its violations and signatures are resolved to
    the ASM attack type; passed requests are skipped. Every search result now shows attack_type and signatures next to the block reason, and the
    summary lists the attack types seen in the range and whether the scan reached the start of the range. The AI tool f5_waf_log_search takes 'attack' too
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
- F5 iRules (Checks > LTM): every iRule in every partition with the virtual servers it is assigned to and its
  position in each one's iRule list; iRules assigned to no virtual server are flagged UNUSED (optional name filter).
  Click an iRule name to see its code in a pop-up (read-only, with Copy)
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
  - The AI can read the operations dashboard: "✦ Ask AI" on the dashboard asks what needs attention, and follow-up
    questions keep using a fresh snapshot (health of every card, HA, resources, interfaces down, SolarWinds' view,
    the F5s / firewalls seen only in SolarWinds, Orion KPIs, alerts and 24-hour trends) until ✕ or a new output.
    In "Ask & run checks" the model also has a 'dashboard' tool for overall-health questions. If the dashboard
    never refreshed, the first question runs a refresh; each read is in the audit log
  - iRules: "✦ Explain with AI" in the iRule code pop-up sends the iRule (read again from the F5, numbered lines) and
    asks for its purpose, events, traffic flow, problems (bugs, security, performance) and improvements; follow-up
    questions stay on that iRule. In "Ask & run checks" the model can read any iRule itself (f5_irule_code). Values
    that look like secrets in the code (set api_key "...", auth / key headers inserted, Basic / Bearer values) are
    masked before sending
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

- **Device monitor (pop-up alerts)**
  - While devices are connected and the console page is open, they are checked every 30 s (15 s to 5 min, or off),
    read-only; the 🔔 in the header shows how many things are down
  - F5: pool members, a pool left with no available member (with the VIPs using it), virtual servers, nodes, failover
    state (Active / Standby). Palo Alto: HA state and peer link, interfaces, IPsec tunnels. FortiGate: HA primary and
    cluster members, interfaces, IPsec tunnels
  - Each change pops up a message (device, object, old and new state) with a sound and a Windows notification, and is
    written to the audit log. Interfaces and tunnels that are already down when monitoring starts (unused ports, idle
    tunnels) only alert after they have been up once
  - Configuration changes (checked every minute, can be switched off in the 🔔 panel): Palo Alto config log entries
    (admin, command, object path, new values) and uncommitted changes appearing; FortiGate configuration events from
    the system event log (admin, action, path, object, attribute); F5 objects added, modified or deleted (virtual
    servers, pools and members, nodes, iRules, policies, monitors, profiles, SNAT, data groups, self IPs, VLANs,
    routes, users, certificates), compared between checks, since the F5 REST API does not record who made a change

- **Operations dashboard**
  - ▦ in the header opens one full-screen page for every connected Palo Alto, FortiGate and F5: resource utilization,
    interface status and HA status, one card per device (firewalls first, then load balancers)
  - Refreshed every 20 minutes by default (5 to 60 min, or "Refresh now"), read-only, all devices in parallel, while
    the console page is open. Each card shows when it was read; a sparkline per resource shows the latest refreshes
  - Resources: the same readers as "Resource utilization" (CPU, memory, dataplane, sessions, packet buffers, disk),
    with warning / high thresholds. F5 uses read-only REST only (no util/bash)
  - Interfaces: up / DOWN / disabled; a port that has never been seen up is shown as "not connected", not as down
  - HA: mode, this unit's state, peer state and link, config sync (F5 sync status, PAN-OS running sync, FortiGate
    checksums); a change since the previous refresh is highlighted

- **Vendor advisories (headline under the header)**
  - One chip per vendor and software version of the connected Palo Alto, FortiGate, FortiWeb and F5 units: number of critical /
    high issues that affect that exact version, how many are known to be exploited, and the advised release
    (→ version). Click a chip for the list: severity and score, advisory link, fixed release on your train, exploited
    flag, publication date
  - Sources (public, downloaded whole every 12 hours while the console page is open, or "Refresh now"):
    Palo Alto's advisory feed (security.paloaltonetworks.com) for PAN-OS; for F5, FortiOS and FortiWeb, the NVD lists of
    every BIG-IP / FortiOS / FortiWeb CVE and each CVE's record from the vendor on CVE.org (affected ranges and fixed versions; NVD's
    ranges are used when the vendor record has none); the CISA Known Exploited Vulnerabilities catalog. They are kept
    in `advisory_cache.json` (git-ignored) so a restart does not download them again. The first download takes 2–3
    minutes (NVD allows few requests without an API key)
  - Matching is done in the console: the device versions are never sent anywhere. F5 issues that only concern a
    module that is not provisioned (e.g. APM) are left out; PAN-OS issues limited to Panorama, VM-Series or a hardware
    series are applied only to matching units; for FortiOS / FortiWeb only that product's entries in a CVE count
    (a CVE that also names FortiProxy does not turn FortiProxy's fixed versions into FortiOS advice)
  - Advised release = the lowest release, on the current train first, that none of the listed advisories affects. It
    is computed from the advisories, not a vendor recommendation: check the vendor's release guidance (linked in the
    panel) and the advisory details (some need a feature in use, such as GlobalProtect or an exposed management
    interface). A train no longer named in recent advisories is flagged "end of life?"
  - Shows high and above by default (switch to critical only, or medium and above); exploited issues are always shown
  - **Advisories vs configuration** (check "Vendor advisories vs this device's configuration" under Security, or the
    "Check … against its configuration (AI)" button in the panel): for each CVE of the unit's version, the advisory
    sentences that say when it applies, the configuration facts such conditions depend on (read-only), and a console
    hint from keyword rules (likely applies / likely not applicable). Facts read: Palo Alto GlobalProtect portals and
    gateways, management profiles on data interfaces, management permitted IPs, DNS proxy, IKE gateways,
    authentication portal; FortiGate SSL-VPN, admin access / FGFM / CAPWAP per interface, admin ports, FortiCloud SSO
    admin login, IPsec tunnels, BGP neighbors, HA mode, admins without trusted hosts; FortiWeb admin access per
    interface, admin ports, FortiCloud SSO admin login (when the firmware shows it), FortiWeb Manager access, admins
    without trusted hosts, HA mode, server policies and deployment modes (field names not yet confirmed on every
    firmware); F5 provisioned modules, self IP
    port lockdown (with the default list), Configuration utility / SSH allow lists, APM access profiles, profile types
    used by virtual servers (HTTP/2, SSL, SIP, WebSocket, …). The button then asks the AI assistant to judge every CVE
    as APPLIES / DOES NOT APPLY / CAN'T TELL with the deciding fact; exposure to the internet cannot be seen by the
    console, so those come back as CAN'T TELL with what to check

- **Packet capture analysis (AI assistant)**
  - 📎 in the assistant (or drag a file onto it): `.pcap` / `.pcapng` up to 64 MB, read by the console itself
    (standard library only, no Wireshark needed; Ethernet, VLAN, Linux cooked, raw IP, loopback; first 500,000 packets)
  - Summary in the Output panel: conversations, unanswered / refused / reset TCP connections and who sent the reset,
    retransmissions, slow handshakes, zero windows, DNS errors and unanswered queries, TLS server names and alerts,
    HTTP request lines and response times per hostname (request start to first response byte; slowest requests,
    4xx/5xx, unanswered), TLS ClientHello-to-ServerHello time, ICMP unreachable / fragmentation needed, ARP conflicts,
    top talkers
  - "Analyse this capture" asks the model about that summary; follow-up questions and "Ask & run read-only checks"
    work on it too. The model gets the summary only, never packet payloads; URL query strings and HTTP headers other
    than Host are not included. The file is kept in memory only.

- **SolarWinds Orion** (vendor "SolarWinds Orion" in Connect; SWIS API on port 17774, older Orion 17778, tried
  automatically)
  - Overview: nodes, interfaces and active alerts by status, and what needs attention
  - Active alerts, most severe first, with object, node, age, message and acknowledgement
  - Nodes needing attention (not up, CPU or memory >= 90%, packet loss), all nodes, one node in detail (health, every
    interface, its active alerts)
  - Interface issues (down, utilization at or above a threshold, errors / discards today) and the busiest interfaces
  - Raw box: one SWQL `SELECT` query
  - The AI assistant can run these checks too (tools `sw_...`), e.g. "is anything down?" or "is the DMZ uplink busy?"
  - Operations dashboard (▦): a SolarWinds panel at the top with network availability, nodes / interfaces by
    status, active and unacknowledged alerts, trends of average CPU, memory, response time and packet loss
    (Orion's own history, range picked on the panel: 24 hours, 7 days or 30 days per hour; 30 days, 90 days or 12
    months per day. Orion keeps hourly data about 30 days and daily data about a year by default; when it has less
    than the range asked for, the panel says from which date it has data. Changing the range re-reads only the history
    queries. If that history is not readable, the console's own refreshes are charted, 24 hours at most), what needs attention, the
    busiest interfaces, interfaces down, highest CPU and slowest nodes. Each firewall / F5 card also shows what
    SolarWinds reports for that unit (matched by management IP, else by name): status, response time, loss, CPU,
    active alerts, interfaces down, busiest interface. F5s and firewalls that Orion monitors but that are not
    connected in the console (recognised from Orion's vendor / machine type: F5, Palo Alto, Fortinet, Cisco ASA /
    Firepower, Check Point, Juniper SRX, SonicWall, Sophos, WatchGuard, Forcepoint, Barracuda) get their own dashed
    card beside the connected ones, built from Orion's data alone: status, CPU, memory, interfaces, alerts. A tick
    box hides them.

- **FortiWeb** (WAF) and **FortiADC** (ADC / load balancer), REST API, read-only
  - Connect with a read-only administrator (user / password) or an API token; optional VDOM / ADOM. FortiWeb gets
    its REST v2 token (base64 of user, password and VDOM, built in memory); FortiADC logs in for a session token and
    logs in again when it expires
  - REST paths differ between firmware releases: each check tries the known paths in order, the result names the one
    that answered, and when none does it lists what it tried. The raw box takes any GET under `/api/v2.0/`
    (FortiWeb) or `/api/` (FortiADC) to explore a firmware; paths that name an action (reboot, backup, restore,
    upgrade, delete, clear, execute, ...) are refused. Only GET is sent (plus the FortiADC login POST)
  - FortiWeb: system status, license, resources, HA, interfaces, certificates; server policies joined with their
    virtual server and VIP addresses, protected hostnames, server pool, protection profile and mode (flags policies
    without a protection profile, in monitor mode = log only, or disabled); virtual servers, VIPs, server pools and
    members, protected hostname groups, web protection profiles; attack log search (client IP, hostname, URL, action,
    any text such as a signature ID; counts by action and attack type)
  - FortiADC: system status, resources, HA, interfaces, certificates; virtual servers joined with pool, members
    (real server address:port and status), content routing, scripts, WAF profile; virtual / real server health,
    pools, pool members, real servers, content routing and rewriting, Lua scripts with their code, health checks,
    WAF profiles
  - FortiWeb analytics (the "🛡 FortiWeb analytics" card at the top of Checks & tools when a FortiWeb is selected;
    it shows the last result and opens the full view for 24 h, the last hour or 7 days): statistics of the attack log (FortiWeb 8.0: the GUI's
    `log/logreport.logaccess.filter?log_type=3`, paged with `filter_offset` until the range is covered, at most 10,000 entries) over 1 h, 6 h, 24 h, 3 days or 7 days, for all
    server policies or one: attacks, blocked share, logged-only, attacking clients, hosts, ML anomalies, API
    violations, bot events and high-threat entries; trend of attacks and of the blocked share; breakdowns by protection
    category, action, OWASP Top 10, attack type, signature, threat level, client, country, server policy, host, URL and
    HTTP method; sections for ML anomaly detection (by URL, type, parameter, plus the ML policies), API protection
    (violations by endpoint and type, plus the API learning / protection policies) and bots; server policies with mode
    and profile. Insights at the top, each with the numbers behind it: attack spike in the last hour, one client
    dominating, mostly logged-only, attacks on monitor-mode policies, policies without a protection profile, possible
    false positives (one signature on one URL from many clients that tripped nothing else), ML anomalies concentrated
    on one URL, API violations concentrated on one endpoint. "✦ Ask AI" asks for an assessment of the range. The same
    statistics are the "Security statistics and insights" check, so the AI agent can use them
  - ML based API protection (in the API protection section of the 🛡 view; read through the GUI's own read API,
    `/api/v2.0/machine_learning/api_learning_policy.*`, seen on FortiWeb 8.0): pick a learned domain / policy
    (from the learning policies, `.get_policy_rules`, also shown as "Policies"; learned URLs of a domain: `.geturls?rule_id=`, shown as an endpoint inventory: model status, method, authentication, data categories, zombie and excessive-data flags, a path tree like the GUI's Tree View, and AppSec findings mapped to the OWASP API Security Top 10 2023: sensitive data without authentication (API2; sign-in / registration endpoints excluded), PUT / PATCH / DELETE without authentication (API5), excessive data exposure (API3), zombie APIs (API9), sensitive endpoints still collecting samples), then its overview (`.overview`: endpoint and model-state counts with insights such as most endpoints
    still collecting samples or models discarded, top endpoints, response-code trends, most attacked endpoints), its learned schema (`.schemafile`, OpenAPI as YAML on FortiWeb 8.0, read with a small built-in YAML reader) as an
    API View like the GUI's: the YAML with colours and Export on the left, the endpoints Swagger-style on the right (method
    badges; parameters, request-body fields with types / required / oneOf, responses; the inventory flags joined by
    url_id: authentication, model status, zombie, excessive data, data categories), filter and expand / collapse or its event log (`.eventlog`). "✦ Ask AI" includes the picked domain's schema and events and asks
    for a review (sensitive endpoints, unexpected DELETE / PUT, endpoints without learned parameters). Also the
    "ML based API protection" check, for the AI agent
  - "From the FortiWeb GUI API": API discovery results and ML model status are not in the documented API; copy the
    request path from the GUI with the browser developer tools (F12, Network) and load it there (read-only GET). The
    rows are shown as a table with automatic charts (counts by each low-cardinality column, highest values)
  - Both: find an IP, hostname or name anywhere in the load-balancing / WAF configuration (objects and their
    sub-entries, with the matching fields)
  - Values whose field names look like secrets (passwords, keys, PSKs ...) are shown as "(hidden)"
  - The AI assistant can run these checks (tools `fwb_...`, `fad_...`), and "Explain the current output" explains a
    FortiADC Lua script; secrets written in scripts are masked before sending
  - Not yet: dashboard cards, monitor pop-ups and the flow trace for FortiWeb / FortiADC, vendor advisories for FortiADC

- **Look**
  - Light theme by default, dark theme one click away (◐ in the header; the choice is remembered in the browser)
  - Optional organisation logo in the header: put `brand_logo.svg` or `brand_logo.png` (max 1 MB) next to the script.
    Both names are git-ignored, so the logo is never published with the tool.

## Run
```
python3 netops_console.py
```
Open the URL printed in the terminal.

**Live update:** while the console runs it watches `netops_console.py`. When the file changes, the new code is loaded
and checked first, then the running server switches to it. Connected devices, open SSH terminals, unlocked saved
logins, AI settings and the URL stay as they are, so nothing has to be re-entered. If the page itself changed, a bar
offers "Reload page"; if the edited file has an error, the bar shows it and the previous code keeps running.
Changes to the update watcher or to startup options (`main()`) still need a restart. Turn it off with `--no-live-update`.

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
  output is trimmed to the context budget (default 60,000 characters, about 15-20k tokens: the model's context window
  should be 32k tokens or more; each check result the agent runs gets a quarter of it, all results together at most
  twice it). The model can only call read-only lookups; active tools are never offered
  to it, and nothing it writes is run. Model settings and the optional API key live in memory only.
- Vendor advisories: the console downloads public lists only (security.paloaltonetworks.com, services.nvd.nist.gov,
  cveawg.mitre.org, cisa.gov) directly over HTTPS, without a proxy. Requests ask for whole product lists and every
  CVE of a product at the chosen severity, never for a version, so nothing about the devices leaves the PC.
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

### SolarWinds Orion
A read-only Orion account is enough (an Orion individual account, or a Windows / AD account entered as
`DOMAIN\user`). The console only calls the SWIS `Query` endpoint, which cannot change anything; it never uses
Invoke, Create, Update or Delete. The PC must reach the Orion server on TCP 17774 (older releases: 17778), not only on
443. Orion normally uses its own self-signed certificate on that port, so "Skip TLS verification" is usually needed.
Account limitations set in Orion (which nodes the account may see) apply to the console too.

### FortiWeb / FortiADC
A read-only administrator is enough: an admin profile with read access to system, network, server policy / load
balancing, security (WAF) and log; no write access. Enable REST API access for that administrator if the firmware
asks for it, and add this PC to its trusted hosts. An API token can be pasted instead of user / password (FortiWeb:
sent as the Authorization header; FortiADC: as a Bearer token). The console only sends GET requests (FortiADC also
the login POST) and refuses GET paths that name an action. REST paths and fields change between firmware releases;
when a check finds no endpoint, use the raw box to find the right path.

## Disclaimer
Use only on devices you are authorised to administer. Provided as-is, without warranty; review the code
before pointing it at production. Use a least-privilege account (see *Required permissions*).

## License
MIT. See [LICENSE](LICENSE).
