<p align="center">
  <img src="logo/logo.svg" width="150" alt="WanHound logo">
</p>

<h1 align="center">WanHound</h1>

<p align="center"><strong>Audit your own home network's public exposure — from the outside.</strong></p>

<p align="center">
Give WanHound your home's public IPv4 or IPv6 address. It probes every port from an external vantage point, identifies what answers, explains the risk in plain language, and diffs the result against last time.
</p>

---

Your router's admin page, your NAS login, a database a container quietly published, a port some device opened for itself via UPnP — from inside the house, none of this is visible. WanHound stands outside and knocks on every door, then writes you a readable report instead of raw scan output.

WanHound is the outside companion to [LanHound](https://github.com/playwjj/lanhound), which watches devices *inside* the LAN. LanHound sees who is home; WanHound checks which doors face the street.

## What it does

- **Full-port TCP audit** of a single IPv4 and/or IPv6 address (all 65,535 ports by default; a curated `--quick` set for fast re-checks). UPnP mappings and device services love random high ports, so the default does not stop at the top 1000.
- **Three-state results** — `open` / `closed` / `filtered` are reported separately; silence is never dressed up as "safe".
- **Service identification** — banner grab, TLS certificate, HTTP title/headers, so a finding says *what* answered, with the evidence attached.
- **Plain-language risk findings** from a curated, versioned rule base (30+ home-relevant entries): Telnet, exposed databases, router management ports, remote desktop, NAS panels, VPN endpoints… every finding carries a rule ID and one concrete piece of advice.
- **Snapshot diff** — history is kept per *home label* (not per IP, because home addresses change). The next run calls out **newly opened ports** at the top of the report.
- **Address sanity checks before scanning** — feed it a private or loopback address and it explains why that cannot be audited from outside; feed it a `100.64.0.0/10` address and it tells you you're behind carrier-grade NAT and there is no public IPv4 exposure to audit.
- **CLI + Web UI, one binary** — `wanhound scan` for scripts and cron, `wanhound serve` for a password-gated web interface (see the safety section — the gate is not optional).

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
- **The Web UI is always password-gated.** A reachable scanner page turns your server into someone else's jump host and the abuse lands on *your* IP — so `serve` refuses to run without a password, and the docs recommend binding it to a LAN/Tailscale address.

## Quick start

Build from source (Go 1.23+, no other dependencies — pure standard library, one static binary):

```bash
git clone https://github.com/playwjj/wanhound.git
cd wanhound
make build
```

Or Docker:

```bash
docker build -t wanhound .
docker run --rm wanhound scan --ipv4 <your-public-ip> --label home
```

Run a scan **from outside your home network**:

```bash
# Full audit of both stacks, saved under the label "home"
./wanhound scan --ipv4 198.51.100.23 --ipv6 2001:db8:85a3::7 --label home

# Fast re-check on the curated port set
./wanhound scan --ipv4 198.51.100.23 --label home --quick

# Just a few ports
./wanhound scan --ipv4 198.51.100.23 --ports 22,80,443,8291
```

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

Notes on the report:

- On an IPv4 target, an open port may be the router's own service **or** a forward/UPnP mapping to an inside device — from outside these cannot always be told apart, and the report says so rather than guessing. On IPv6 there is no NAT: a hit is the device itself.
- `filtered` means *this vantage point* got silence. Important results deserve a re-check from a second network.

### Exit codes (for cron / alerting)

| Code | Meaning |
|---|---|
| 0 | No high-risk findings |
| 1 | A high-risk port is open, **or** new ports opened since the last snapshot |
| 2 | The audit could not run (bad input, unauditable address class) |

```bash
wanhound scan --ipv4 <ip> --label home || \
  curl -s "https://api.telegram.org/bot<token>/sendMessage" -d "chat_id=<id>&text=WanHound: check the home audit"
```

### Web UI

```bash
WANHOUND_PASSWORD='choose-a-strong-one' ./wanhound serve --addr 127.0.0.1:8687
# or bind your Tailscale address — avoid public exposure even with a password
```

The P0 build serves a gated placeholder; the scan form with live progress, report pages and side-by-side diff land in P1 (see roadmap). The password gate, audit logging and rate limits are already part of the design and are not optional extras.

## How it works

```
address ──▶ classify (public? CGNAT? private?) ──▶ connect-scan (3-state)
        ──▶ probe open ports (banner / TLS / HTTP) ──▶ rule base (findings)
        ──▶ snapshot under your home label ──▶ diff vs. last run ──▶ report
```

- Pure Go standard library: no cgo, no embedded nmap, no raw sockets (so no `NET_RAW`, no root).
- Address intel (ASN/ISP via a public lookup API) is optional and can be fully disabled with `--offline` — note that any online lookup necessarily shows the queried address to that service.
- Snapshots live in `~/.local/share/wanhound/` as plain JSON.

## Roadmap

- **P0 (this skeleton)** — dual-stack single-target audit, full/quick port sets, three-state engine, banner probing, rule base v1, snapshots + diff, exit-code contract, gated Web UI skeleton.
- **P1** — adaptive timeouts and filtered-port retry, deeper TLS/HTTP identification, combination rules, UDP probe set, full Web UI (progress, history timeline, side-by-side diff).
- **P2** — standalone HTML report export, Telegram push of results, optional import of an address list exported from LanHound (audited one by one — still no range scanning).

## Known limitations

- **The vantage point decides the result.** Different outside networks filter differently; `filtered` is not proof of safety.
- **Dynamic IPs.** History is keyed by label, but if your address changed, old and new runs may describe different lines — the report flags address changes.
- **UDP is fuzzy.** No response cannot distinguish open from filtered; UDP findings are advisory.
- **Identification is fingerprinting.** Banners and titles are evidence, not proof; findings show their evidence and confidence is yours to judge.
- **IPv6 scope = the addresses you give it.** IPv6 space cannot be enumerated; devices you don't list are not audited.

## Development

```bash
make build   # ./wanhound
make test    # unit tests (address classification, scanner fixture, port parser)
make vet
make fmt
```

Layout: `cmd/wanhound` (CLI) · `internal/intel` (address classification) · `internal/scan` (engine) · `internal/probe` (service ID) · `internal/knowledge` (rule base, `rules.json`) · `internal/store` (snapshots/diff) · `internal/report` · `internal/web` (serve mode).

## License

MIT — see [LICENSE](LICENSE).

Only audit networks you own or are authorized to test.
