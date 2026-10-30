<p align="center">
  <img src="https://raw.githubusercontent.com/playwjj/wanhound/main/logo/logo-512.png" width="150" alt="WanHound logo">
</p>

# WanHound

**Audit your own home network's public exposure — from the outside.**

Give WanHound your home's public IPv4 or IPv6 address. It probes every port from an external vantage point, identifies what answers, explains the risk in plain language, and diffs the result against last time.

Your router's admin page, your NAS login, a database a container quietly published, a port some device opened for itself via UPnP — from inside the house, none of this is visible. WanHound stands outside and knocks on every door, then writes you a readable report instead of raw scan output.

WanHound is the outside companion to [LanHound](https://github.com/playwjj/lanhound), which watches devices *inside* the LAN. LanHound sees who is home; WanHound checks which doors face the street.

Source, issues and full documentation: **[github.com/playwjj/wanhound](https://github.com/playwjj/wanhound)**

## Quick start

Run the audit **from a machine outside your home network** (a VPS is ideal). The container needs no special capabilities — WanHound uses plain TCP connect probes, no raw sockets.

```bash
# Full-port audit of both stacks, saved under the label "home"
docker run --rm -v wanhound-data:/home/wanhound/.local/share/wanhound \
  passport888/wanhound scan --ipv4 <your-public-ip> --ipv6 <your-public-ipv6> --label home

# Fast re-check on the curated port set
docker run --rm -v wanhound-data:/home/wanhound/.local/share/wanhound \
  passport888/wanhound scan --ipv4 <your-public-ip> --label home --quick

# Web UI (always password-gated — see Safety)
docker run -d --name wanhound -p 127.0.0.1:8687:8687 \
  -e WANHOUND_PASSWORD='choose-a-strong-one' \
  -v wanhound-data:/home/wanhound/.local/share/wanhound \
  passport888/wanhound serve --addr 0.0.0.0:8687
```

> The named volume keeps snapshots on the host, so the next run can diff against the last one. Replace `<your-public-ip>` with the address your router shows on its WAN interface (or any address you own and are authorized to test).

Example output (abridged):

```
━━ 198.51.100.23 (IPv4) ━━
Scanned 65535 TCP ports in 1m42s (timeout 412ms, rtt 66ms): 3 open · 0 closed · 65532 filtered
Compared with 2026-10-23 09:00 (198.51.100.23):
  NEW open TCP ports: 8291

  PORT       SERVICE                    RISK    FINDING
  80/tcp     Router / modem admin page  HIGH    A router or modem admin page is reachable from the internet
  8291/tcp   MikroTik Winbox            HIGH    MikroTik Winbox management is exposed
  51413/tcp  unknown                    LOW     Port 51413 is open and not in the known-service list
```

Every finding carries its evidence (banner, certificate, page title), a confidence level, a plain-language explanation, one concrete piece of advice and a rule ID.

### Exit codes (for cron / alerting)

| Code | Meaning |
|---|---|
| 0 | No high-risk findings, nothing new |
| 1 | A high-risk port is open, **or** new ports opened since the last snapshot |
| 2 | The audit could not run (bad input, unauditable address, distorted vantage point) |

## What it does

- **Full-port TCP audit** of a single IPv4 and/or IPv6 address (all 65,535 ports by default; a curated `--quick` set for fast re-checks; `--ports` for your own list). UPnP mappings and device services love random high ports, so the default does not stop at the top 1000.
- **Adaptive, conservative pacing** — a short RTT calibration picks the per-connection timeout (a silent gateway does not stretch the audit), a pacer caps the connection rate, and scattered filtered ports get one slower retry pass. A full audit typically takes 1–3 minutes, and the expected worst case is printed before it starts.
- **Three-state results** — `open` / `closed` / `filtered` are reported separately; silence is never dressed up as "safe".
- **Service identification** — banner grab, TLS certificate (issuer, expiry, self-signed), HTTP status/server/title over plain HTTP *and* TLS (following one same-origin redirect), so a finding says *what* answered, with the evidence attached and a confidence level.
- **Plain-language risk findings** from a structured, versioned rule base (60+ entries): every rule is `match (port / banner / title / server / certificate / auth patterns) → risk, explanation, advice, rule ID`. Router and modem admin pages, cameras, NAS panels, hypervisor/container panels, databases, remote desktops, Telnet, TR-069, Winbox, SMB… `wanhound rules` lists them all.
- **Whole-home combination rules** — router management reachable from the internet, databases/remote desktops published directly, "ten ports open: a DMZ host?", IPv6 hits with no NAT in front, smart-home devices on the street.
- **Small UDP set** (DNS — including open-resolver detection —, NTP, IKE, OpenVPN, SSDP/UPnP, mDNS, WireGuard), clearly marked advisory.
- **Snapshot diff** — history is kept per *home label* (not per IP, because home addresses change), address changes are reported as events, and the next run calls out **newly opened ports** at the top. Diffs are coverage-aware: a `--quick` re-check never "closes" the high ports a full audit found.
- **Vantage-point self-checks before scanning** — private, loopback, CGNAT (`100.64.0.0/10`) and reserved addresses are refused with an explanation; if this machine's public egress *is* the target, or a transparent proxy / TUN-mode VPN is answering for every port, WanHound stops and tells you why instead of producing a distorted report.
- **English or Chinese reports** — terminal, HTML, Web UI and push digest (`--lang zh`, or automatically under a `zh_*` locale).
- **LanHound companion mode** — audit every device's public IPv6, one by one, from a LanHound device export.
- **CLI + Web UI, one binary** — `wanhound scan` for scripts and cron (exit-code contract, JSON, standalone HTML report, optional Telegram push), `wanhound serve` for a password-gated web interface with live progress, history timeline and side-by-side diff.

## How it differs

| | What it answers | How |
|---|---|---|
| IP lookup sites | "Whose address is this?" | Registry data. Never touches the target. |
| Shodan / Censys | "What did a crawler see, days ago?" | A third-party historical database; home IPs are often stale or missing, IPv6 coverage is thin. |
| nmap | "Which ports are open?" | Raw data for experts — an X-ray, not a diagnosis. |
| **WanHound** | "**What of mine is exposed right now, how bad is it, and what changed?**" | Live probing + a home-focused rule base + history diff. A checkup report. |

## Safety & scope — read this first

WanHound is a **defensive self-audit tool**, in the same family as nmap or Greenbone, and it is deliberately fenced:

- **One target at a time.** A single IPv4 and/or IPv6 literal. No CIDR ranges, no target lists — single-target audit vs. bulk scanning is the line this project does not cross.
- **Probe only, never exploit.** Plain TCP `connect()` plus read-only banner/TLS/HTTP identification. No vulnerability checks, no password guessing, no payloads, no stealth/evasion features, conservative default rates.
- **Audit only addresses you own or are authorized to test.** The intended use is: run it on an outside machine (a VPS, a friend's network) against *your own* home address.
- **The Web UI is always password-gated.** A reachable scanner page turns your server into someone else's jump host and the abuse lands on *your* IP — so `serve` refuses to run without a password, and binding it to a LAN/Tailscale address is recommended over public exposure.

## Notes on the report

- On an IPv4 target, an open port may be the router's own service **or** a forward/UPnP mapping to an inside device — from outside these cannot always be told apart, and the report says so rather than guessing. On IPv6 there is no NAT: a hit is the device itself.
- `filtered` means *this vantage point* got silence. Important results deserve a re-check from a second network.
- Address intel (ASN/ISP via a public lookup API) is optional and can be fully disabled with `--offline` — any online lookup necessarily shows the queried address to that service.

## Roadmap

- **P0 — done** — dual-stack single-target audit with address classification (CGNAT/private/reserved refusal), full/quick/custom port sets, adaptive timeouts, three-state engine, banner probing, structured rule base, terminal + JSON output, exit-code contract.
- **P1 — done** — TLS/HTTP deep identification, combination rules, per-label snapshot diff, vantage-point self-checks, UDP probe set, Web UI with progress, report, history timeline and side-by-side diff, plus the full access-control set.
- **P2 — done** — standalone HTML report export ✔, Telegram push ✔, auditing each device's IPv6 from a LanHound export ✔ (one by one — still no range scanning).
- **v0.3** — Simplified Chinese reports (terminal, HTML, Web UI, Telegram digest).
- **v0.5** — accepted risks (reason + expiry; quiet until they lapse); clearer egress status; SNI-only TLS ports recognized as HTTPS.
- **v0.4** — LanHound batch import in the Web UI; snapshot/label deletion and `audit.log` rotation; macOS and Windows binaries; ipinfo token.

## License

MIT — see the [LICENSE](https://github.com/playwjj/wanhound/blob/main/LICENSE) in the source repository.

Only audit networks you own or are authorized to test.
