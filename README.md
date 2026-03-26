# External Network Reconnaissance Framework

A modular, automated reconnaissance tool for authorized external network penetration testing engagements. Designed for pentesters and security consultants — runs all passive and active discovery phases, deduplicates results, and produces a client-ready Excel report.

> ⚠️ **Authorized use only.** Only run this tool against targets you have written permission to test.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Scan Modes](#scan-modes)
- [All Flags](#all-flags)
- [API Keys & Tokens](#api-keys--tokens)
- [Tools & Auto-Install](#tools--auto-install)
- [Phases Reference](#phases-reference)
- [Output Files](#output-files)
- [Excel Report Sheets](#excel-report-sheets)
- [Platform Support](#platform-support)
- [Timing Reference](#timing-reference)

---

## Quick Start

```bash
# Default scan — subdomains, DNS, CDN check, port scan, HTTP probe, enrichment
python3 recon.py -t example.com

# Scan from a target file
python3 recon.py -f targets.txt

# PM / pre-meeting mode — fast scope mapping, no port scan
python3 recon.py -t example.com --pm

# Full scan — everything including service fingerprint, web crawl, bruteforce
python3 recon.py -t example.com --run-all

# With API tokens
python3 recon.py -t example.com --pm \
  --github-token ghp_xxxxxxxxxxxx \
  --shodan-token xxxxxxxxxxxx \
  --pdcp-token pdcp_xxxxxxxxxxxx
```

**Target formats — mix and match freely:**
```bash
python3 recon.py -t example.com 192.168.1.1 10.0.0.0/24
```

---

## Scan Modes

| Mode | Command | Runtime | What it does |
|---|---|---|---|
| **Default** | `python3 recon.py -t example.com` | 3–5 min | Subdomains → DNS → CDN check → Port scan → HTTP probe → IP enrichment |
| **PM Mode** | `--pm` | 3–8 min | Subdomains → DNS → APEX → HTTP probe → IP enrichment. **No port scan, no nmap, no bruteforce** |
| **Full Scan** | `--run-all` | 5–10 min + bruteforce | Everything including nmap service detection, web crawl, and permutation bruteforce |

### What `--pm` is for

Pre-meeting / SOW preparation. Gives you the full passive picture — subdomains, live web hosts with titles and tech stack, APEX domains, ASN ranges, and IP enrichment — without running naabu or nmap. Fast enough to run before a client call.

### What `--run-all` adds

- `nmap -sV` service fingerprinting on open ports
- `hakrawler` web crawling for additional host discovery
- `alterx` + `dnsgen` permutation wordlist generation
- `shuffledns` resolution against three resolver tiers (extended → standard → trusted)

**Bruteforce timing** (run-all only):

| Target size | Known subs | Estimated time |
|---|---|---|
| Small | < 50 | 3–5 min |
| Medium | ~200 | 10–20 min |
| Large | 500+ | 30–60 min |

---

## All Flags

### Scan mode flags

| Flag | Description |
|---|---|
| *(no flags)* | Default scan |
| `--pm` | PM / pre-meeting mode |
| `--run-all` | Full scan, all phases |

### Input / output

| Flag | Description |
|---|---|
| `-t TARGET [TARGET ...]` | One or more targets (domains, IPs, CIDRs) |
| `-f FILE` | File with targets, one per line (`#` for comments) |
| `-o DIR` | Output directory (default: `recon_output`) |

### API tokens

| Flag | Description |
|---|---|
| `--github-token TOKEN` | GitHub PAT for `github-subdomains` |
| `--shodan-token TOKEN` | Shodan API key for `shosubgo` |
| `--pdcp-token TOKEN` | ProjectDiscovery Cloud Platform key for `asnmap` (also reads `PDCP_API_KEY` env var) |

### Individual phase flags

Run specific phases only. Phases execute in code order regardless of flag order.

| Flag | Phase | Auto-runs deps? |
|---|---|---|
| `--subdomains` | All subdomain tools in parallel | No |
| `--github-subdomains` | GitHub code search (requires `--github-token`) | No |
| `--dns` | DNS resolution | No |
| `--ct-logs` | Certificate Transparency log query | No |
| `--apex` | APEX / root domain discovery | Yes (runs subdomains + CT logs if no data) |
| `--ports` | Port scanning with naabu | No |
| `--cdn-check` | CDN/WAF detection | No |
| `--ip-enrichment` | WHOIS/RDAP ASN + org + country | Yes (runs DNS if no IPs) |
| `--services` | nmap service fingerprinting | Yes (runs ports first) |
| `--crawl` | hakrawler web crawl | Yes (runs ports first) |
| `--reverse-dns` | Reverse PTR lookup on IPs | No |
| `--bruteforce` | Permutation + shuffledns resolution | Yes (runs subdomains first) |

**Combine freely:**
```bash
python3 recon.py -t example.com --subdomains --dns --ports
python3 recon.py -t 192.168.1.0/24 --reverse-dns --cdn-check --ip-enrichment
```

---

## API Keys & Tokens

All tokens are optional — tools skip gracefully with a warning if not provided. Tokens are **redacted** in all Excel audit logs and output files.

| Token | Tool | Where to get it |
|---|---|---|
| `--github-token` | `github-subdomains` | [github.com/settings/tokens](https://github.com/settings/tokens) — `public_repo` read scope only |
| `--shodan-token` | `shosubgo` | [account.shodan.io](https://account.shodan.io) |
| `--pdcp-token` | `asnmap` | [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io) — required since March 2024 |

**asnmap note:** The PDCP key can also be set as an environment variable to avoid passing it on the command line:
```bash
export PDCP_API_KEY=pdcp_xxxxxxxxxxxx
python3 recon.py -t example.com --pm
```

---

## Tools & Auto-Install

All tools are auto-installed on first run. Go tools install to `~/go/bin/`, Python tools via pipx/pip, scripts fetched from their source.

### Subdomain Enumeration

| Tool | Install method | Notes |
|---|---|---|
| `subfinder` | `go install` | Primary passive source, broadest coverage |
| `amass` | `go install` | Additional passive sources, runs in parallel with subfinder |
| `assetfinder` | `go install` | Fast enumeration; also used in APEX mode without `--subs-only` |
| `gau` | `go install` | URL archive mining (Wayback, CommonCrawl) → hostname extraction |
| `sublist3r` | `pip install` | Search engine enumeration |
| `github-subdomains` | `go install` | GitHub code search — **requires `--github-token`** |
| `shosubgo` | `go install` | Shodan subdomain lookup — **requires `--shodan-token`** |

All tools run **in parallel** and results are merged into one deduplicated list.

### DNS & Resolution

| Tool | Role |
|---|---|
| `dnsx` | Batch DNS resolution, reverse PTR lookups |
| `dig` | Fallback resolver if dnsx unavailable |

### APEX & ASN Discovery

| Tool | Role |
|---|---|
| `assetfinder` (no `--subs-only`) | Finds related org domains beyond the target |
| `365doms.py` | O365 tenant discovery (fetched from gist on first run) |
| `whois` | Registrant email domain extraction |
| `asnmap` | Maps ASN → CIDR ranges — **for review only, never scanned** |

### HTTP Probing

| Tool | Role |
|---|---|
| `httpx` (ProjectDiscovery) | Probes ports 80, 443, 8080, 8443, 8888, 9443 — title, status, tech stack, CDN |

> **Note on naming conflict:** Python's `httpx` package also installs an `httpx` binary. The framework resolves this by preferring `~/go/bin/httpx` which is always the ProjectDiscovery version.

### Scanning (default + run-all only)

| Tool | Role |
|---|---|
| `naabu` | Two-pass port scan: top 1000 + critical extra ports |
| `cdncheck` | CDN/WAF detection — CDN IPs are excluded from port scanning |
| `nmap` | Service fingerprinting (`-sV`) on open ports — **run-all only** |

### Web & Crawling (run-all only)

| Tool | Role |
|---|---|
| `hakrawler` | Web crawl for additional host discovery |

### Bruteforce (run-all + `--bruteforce` only)

| Tool | Role |
|---|---|
| `alterx` | Permutation wordlist generation from known subdomains |
| `dnsgen` | Additional permutation generation |
| `shuffledns` | Resolves permutations against three resolver tiers |

Resolver lists are fetched automatically from [trickest/resolvers](https://github.com/trickest/resolvers):
- `resolvers-extended.txt` (broadest)
- `resolvers.txt` (standard)
- `resolvers-trusted.txt` (most reliable)

### IP Enrichment

| Tool | Role |
|---|---|
| `ipwhois` (Python) | RDAP/WHOIS lookup — ASN, org name, country, network range |

### System Tools (manual install required)

| Tool | Install |
|---|---|
| `nmap` | `brew install nmap` / `apt install nmap` |
| `dig` | `brew install bind` / `apt install dnsutils` |
| `whois` | `brew install whois` / `apt install whois` |

---

## Phases Reference

Phases in execution order for the **default scan**:

```
CIDR Expansion         → expand CIDRs to individual IPs
Reverse DNS            → discover domains from IPs (if IPs provided)
Subdomain Enumeration  → all tools in parallel
CT Logs                → crt.sh certificate transparency query
APEX Discovery         → tldextract + assetfinder + 365doms + whois + asnmap
DNS Resolution         → resolve all domains → IPs
CDN Check              → identify CDN/WAF-protected IPs (excluded from port scan)
Port Scan              → naabu two-pass (top 1000 + critical ports)
IP Enrichment          → WHOIS/RDAP for ASN, org, country
HTTP Probe             → httpx on web ports 80,443,8080,8443,8888,9443
Reporting              → deduplicate → text summary + Excel report
```

**PM mode** skips: CDN check, port scan, service fingerprint, web crawl, bruteforce.

**Run-all** adds after port scan: service fingerprint (nmap), web crawl (hakrawler), bruteforce (alterx + dnsgen + shuffledns).

### CDN Check behaviour

`cdncheck` identifies IPs behind Cloudflare, Akamai, Fastly, etc. Those IPs are **automatically excluded from naabu port scanning** — scanning CDN infrastructure would only return CDN ports (80/443 always open), waste time, and potentially trigger abuse complaints against the CDN rather than finding anything about the actual target.

### asnmap behaviour

ASN CIDR ranges from `asnmap` are **never port scanned**. They are output-only, intended for review and discussion with the client to confirm scope before any testing. They appear in the **ASN Ranges** Excel sheet with a prominent warning banner.

---

## Output Files

All files are written to the output directory (default: `recon_output/`).

| File | Contents |
|---|---|
| `recon_summary_TIMESTAMP.txt` | Text summary with counts for every phase |
| `recon_report_TIMESTAMP.xlsx` | Full Excel report (9 sheets) |
| `subdomains_TIMESTAMP.txt` | All discovered subdomains (validated hostnames only) |
| `github_subdomains_TIMESTAMP.txt` | GitHub-sourced subdomains |
| `gau_subdomains_TIMESTAMP.txt` | gau URL archive subdomains |
| `ct_logs_TIMESTAMP.txt` | CT log domains |
| `apex_domains_TIMESTAMP.txt` | Discovered APEX/root domains |
| `reverse_dns_domains_TIMESTAMP.txt` | Domains discovered from reverse PTR |
| `ip_addresses_TIMESTAMP.txt` | All resolved IPs |
| `open_ports_TIMESTAMP.txt` | Port scan results (JSON) |
| `cdn_results_TIMESTAMP.txt` | CDN/WAF detection results |
| `ip_enrichment_TIMESTAMP.txt` | WHOIS/RDAP data per IP |
| `httpx_domains_TIMESTAMP.txt` | Clean domain list passed to httpx |
| `httpx_probe_TIMESTAMP.json` | Raw httpx JSON output |
| `services_TIMESTAMP.txt` | nmap service fingerprinting output |
| `web_crawl_TIMESTAMP.txt` | Hosts discovered via web crawling |
| `github_subs_DOMAIN_TIMESTAMP.txt` | Per-domain github-subdomains output |
| `naabu_TIMESTAMP.json` | naabu top-1000 port scan results |
| `naabu_extra_TIMESTAMP.json` | naabu critical ports results |
| `bruteforce_subdomains_TIMESTAMP.txt` | New subs found via permutation |

---

## Excel Report Sheets

The Excel report (`recon_report_TIMESTAMP.xlsx`) contains 9 sheets:

| Sheet | Contents |
|---|---|
| **1. Summary** | High-level counts for every phase + full tool audit with exact commands run |
| **2. Domains** | Every discovered domain with IP, CDN status, open ports, and source tool |
| **3. IP Addresses** | Every resolved IP with ports, associated domains, org, country, ASN, network range |
| **4. Services** | nmap service fingerprinting results (run-all only) |
| **5. GitHub Subdomains** | Subdomains sourced specifically from GitHub code search |
| **6. APEX Domains** | Root/org domains with subdomain count, discovery source, IPs, CDN status |
| **7. Live Web Hosts** | httpx results — URL, status code (colour-coded), title, server, tech stack, CDN |
| **8. ASN Ranges** | CIDR ranges from asnmap — **review only, not scanned** — with red warning banner |
| **9. Scope Confirmation** | Copy-paste ready asset list formatted for client emails |

### Colour coding

| Colour | Meaning |
|---|---|
| 🟢 Green | Newly discovered asset (not in original target list) |
| 🟡 Gold | CDN/WAF protected |
| 🟣 Lilac/Purple | GitHub-sourced |
| 🔵 Blue header | Column headers |
| 🟢 Green (status) | HTTP 2xx |
| 🟡 Yellow (status) | HTTP 3xx |
| 🔴 Red (status) | HTTP 4xx |
| 🔴 Dark red (status) | HTTP 5xx |

### Tool Audit

Every scan generates a **Tool Audit** section in the Summary sheet showing the exact command run for each tool (or "Not Run" in grey italic if skipped). This lets PMs and peer reviewers verify that best-practice flags were used.

Sensitive values (`--github-token`, `--shodan-token`) are always shown as `<REDACTED>` in audit logs.

---

## Platform Support

| Platform | Status | Notes |
|---|---|---|
| **macOS** | ✅ Full support | Auto-install via Homebrew for Go; pipx/pip for Python tools |
| **Linux** | ✅ Full support | Auto-install via direct Go download + apt hints |
| **WSL2** | ✅ Full support | Recommended for Windows users |
| **Windows (native)** | ⚠️ Limited | Use WSL2 for full functionality |

---

## Timing Reference

| Mode | Runtime | Bottleneck |
|---|---|---|
| `--pm` | 3–8 min | Subdomain tools (parallel) |
| Default | 3–5 min | naabu port scan |
| `--run-all` (small target) | 5–15 min | nmap + shuffledns |
| `--run-all` (large target) | 30–90 min | shuffledns bruteforce on 500+ subs |
| `--bruteforce` alone | 3–60 min | Depends on known sub count |
| `--subdomains` only | 1–3 min | github-subdomains (sequential per domain) |
| `--ports` only | 2–3 min (/24) | naabu rate + CIDR size |

---

## Tips

1. **Start with `--pm`** for initial client scoping calls — fast, passive, client-friendly output
2. **Run default scan** once scope is confirmed — adds port data to the picture
3. **Use `--run-all` overnight** or in a `tmux` session — bruteforce can take a while
4. **Check the Tool Audit sheet** before sending reports — confirms correct flags were used
5. **ASN Ranges sheet** is for client discussion only — always confirm before testing those CIDRs
6. **CIDR notation** is supported as targets — IPs from CIDR expansion are reverse-DNS'd but not necessarily port scanned unless explicitly in scope
7. **Tokens are optional** — every tool with a token requirement skips gracefully if the token isn't provided; you won't get an error
