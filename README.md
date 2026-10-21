# ITSec Ops (netsecops)

A local, single-file web console for troubleshooting **F5 BIG-IP**, **Palo Alto PAN-OS** and **FortiGate**
devices from one place. Python 3.8+, standard library only, no dependencies.

## Features
- Health checks and curated read-only status queries per vendor
- "Where does this IP appear?" lookup (F5 pools, nodes, virtuals, data groups, policies; PAN/Forti policy lookup)
- F5 ASM/WAF request-log search, WAF and SSL posture checks
- PAN-OS / FortiGate log search, admin-change audit
- Optional F5 active tools (log search, tcpdump ( with the ability to extract the pms by utilizing tshark with f5 filters and save the output in .pms,
  both pcap and pms will be downloaded to the project folder)
- Configuration backup (explicit tick-box required)

## Run
```
python3 netops_console.py
```
Open the URL printed in the terminal.

## Security model
- Binds to `127.0.0.1` only; random per-launch token plus Host-header check (CSRF / DNS-rebinding protection).
- Credentials live in memory only and are never written to disk.
- Saved profiles (`device_profiles.json`) hold only label, vendor, address, port and TLS setting.
- Checks are read-only (GET, or PAN-OS `<show>`/allow-listed `<test>`). Exceptions (F5 active tools, backups)
  are documented in the script header and require an explicit opt-in.
- Backups and captures are written to `./captures` (git-ignored). **Never commit them**: they contain
  device configuration and secrets.

## Disclaimer
Use only on devices you are authorised to administer. Provided as-is, without warranty; review the code
before pointing it at production. Use a least-privilege account where possible.
