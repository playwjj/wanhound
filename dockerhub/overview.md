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

Example output:

```
WanHound audit — label "home", target 198.51.100.23
Scanned 65535 ports in 1m48s: 3 open

NEW open ports since last run: 8291

[HIGH  ] 23/tcp  Telnet is exposed
         evidence: banner=BusyBox shell (login)
         Telnet sends everything, including passwords, in plaintext. Disable it ... (KH-001)
[MEDIUM] 8291/tcp  MikroTik Winbox management is exposed
         Winbox has a history of serious vulnerabilities. Restrict management to LAN/VPN ... (KH-021)
[LOW   ] 443/tcp  A web service is reachable over HTTPS
         evidence: tls cert CN="nas.home" SANs=[nas.home]
         Check the certificate and title in the report to identify it. ... (KH-018)
```

### Exit codes (for cron / alerting)

| Code | Meaning |
|---|---|
| 0 | No high-risk findings |
| 1 | A high-risk port is open, **or** new ports opened since the last snapshot |
| 2 | The audit could not run (bad input, unauditable address class) |

## What it does

- **Full-port TCP audit** of a single IPv4 and/or IPv6 address (all 65,535 ports by default; a curated `--quick` set for fast re-checks). UPnP mappings and device services love random high ports, so the default does not stop at the top 1000.
- **Three-state results** — `open` / `closed` / `filtered` are reported separately; silence is never dressed up as "safe".
- **Service identification** — banner grab, TLS certificate, HTTP title/headers, so a finding says *what* answered, with the evidence attached.
- **Plain-language risk findings** from a curated, versioned rule base (30+ home-relevant entries): Telnet, exposed databases, router management ports (including TR-069 on 7547), remote desktop, NAS panels, VPN endpoints… every finding carries a rule ID and one concrete piece of advice.
- **Snapshot diff** — history is kept per *home label* (not per IP, because home addresses change). The next run calls out **newly opened ports** at the top of the report.
- **Address sanity checks before scanning** — feed it a private or loopback address and it explains why that cannot be audited from outside; feed it a `100.64.0.0/10` address and it tells you you're behind carrier-grade NAT and there is no public IPv4 exposure to audit.

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

- **P0 (current)** — dual-stack single-target audit, full/quick port sets, three-state engine, banner probing, rule base v1, snapshots + diff, exit-code contract, gated Web UI skeleton.
- **P1** — adaptive timeouts and filtered-port retry, deeper TLS/HTTP identification, combination rules, UDP probe set, full Web UI (progress, history timeline, side-by-side diff).
- **P2** — standalone HTML report export, Telegram push of results, optional import of an address list exported from LanHound (audited one by one — still no range scanning).

## License

MIT — see the [LICENSE](https://github.com/playwjj/wanhound/blob/main/LICENSE) in the source repository.

Only audit networks you own or are authorized to test.
