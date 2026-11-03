# ITSec Ops (netsecops)

A local, single-file web console for troubleshooting **F5 BIG-IP**, **Palo Alto PAN-OS** and **FortiGate**
devices, and **Cloudflare** accounts, from one place. Python 3.8+, standard library only, no dependencies, built with Claude Code.

## Features
- Health checks and curated read-only status queries per vendor
- "Where does this IP appear?" lookup (F5 pools, nodes, virtuals, data groups, policies; PAN/Forti policy lookup)
- F5 ASM/WAF request-log search (incl. by any HTTP header: value, IP, True-Client-IP, hostname, URL, time, support ID, POST body), top-10 hostnames by violations (with source IPs, True-Client-IPs, URLs), WAF and SSL posture checks
- FortiGate lookups: Virtual IPs (name / external / mapped IP filter), static routes (IP, gateway, interface filter)
- PAN-OS lookups: destination / static NAT rules (the Virtual IP equivalent), configured static routes, session list
  with source / destination filter (URL category lookup was already available)
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
| Log | Log search, admin audit |
| Export | Packet capture download, configuration backup |

Leave Commit, Import and User-ID off. Packet capture changes packet-diag state, so read-only
roles are refused.

### FortiGate
Use a REST API admin with an admin profile limited to what you need, and set **Trusted hosts** to
the machine running this tool.

| Feature | Admin profile access |
|---|---|
| Checks, IP lookup, VIPs, static routes, sessions | Read on System, Network, Firewall |
| Traffic log search, admin audit | Read on Log & Report |
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
