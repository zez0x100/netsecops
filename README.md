# ITSec Ops (netsecops)

A local, single-file web console for troubleshooting **F5 BIG-IP**, **Palo Alto PAN-OS** and **FortiGate**
devices from one place. Python 3.8+, standard library only, no dependencies, built with Claude Code.

## Features
- Health checks and curated read-only status queries per vendor
- "Where does this IP appear?" lookup (F5 pools, nodes, virtuals, data groups, policies; PAN/Forti policy lookup)
- F5 ASM/WAF request-log search, top-10 hostnames by violations (with source IPs, True-Client-IPs, URLs), WAF and SSL posture checks
- FortiGate lookups: Virtual IPs (name / external / mapped IP filter), static routes (IP, gateway, interface filter)
- PAN-OS lookups: destination / static NAT rules (the Virtual IP equivalent), configured static routes, session list
  with source / destination filter (URL category lookup was already available)
- PAN-OS / FortiGate log search, admin-change audit; log searches take a time range (up to 1 day back) on F5,
  FortiGate and the F5/FortiGate admin audit (PAN-OS has its own time-range selector)
- Optional F5 active tools (log search, tcpdump ( with the ability to extract the pms by utilizing tshark with f5 filters and save the output in .pms,
  both pcap and pms will be downloaded to the project folder and a copy is kept on the BIG-IP in /var/tmp, readable by root only)
- Optional PAN-OS packet capture (packet-diag, explicit tick-box required), downloaded as .pcap
- Configuration backup (F5: explicit tick-box required, the UCS archive is also kept on the BIG-IP;
  PAN-OS / FortiGate: read-only export)

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


## Disclaimer
Use only on devices you are authorised to administer. Provided as-is, without warranty; review the code
before pointing it at production. Use a least-privilege account (see *Required permissions*).

## License
MIT. See [LICENSE](LICENSE).
