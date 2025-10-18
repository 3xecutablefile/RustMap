# RustMap

RustMap is a fast banner-grabbing port scanner that enriches findings with exploit-db lookups.
It launches highly parallel TCP connect probes, fingerprints common services using a curated set
of nmap-style payloads, and then ranks any matching exploits by an opinionated risk score.

## Features

- ⚡ **Fast TCP scanner** – scan the top 1k–30k ports or all 65,535 with a multithreaded engine.
- 🔍 **Lightweight service detection** – banner grabbing and protocol-specific probes inspired by nmap fingerprints.
- 💥 **Exploit enrichment** – automatic `searchsploit` queries for each detected product/version pair.
- 📊 **Risk scoring** – heuristic score based on exploit count, CVSS keywords, and service criticality.
- 🎨 **Rich terminal UX** – live progress bars, color-coded risk cards, and optional JSON output for automation.

## Requirements

- Rust 1.70 or newer
- `searchsploit` (from exploit-db) available on your `$PATH`

## Installation

```bash
git clone https://github.com/3xecutablefile/RustMap.git
cd RustMap
cargo install --path .
```

## Usage

```
rustmap <target> [-1k|-2k|...|-30k] [--json]
```

### Options

- `-Nk` – limit the scan to the first `N * 1000` TCP ports (e.g. `-5k` scans ports 1–5000). Without this flag, RustMap scans all 65,535 ports.
- `--json` – emit structured output instead of the interactive TUI.

### Examples

```bash
# Scan the default full port range
rustmap 192.168.1.10

# Scan the top 5000 ports only
rustmap example.com -5k

# Pipe JSON results into jq
rustmap target.local --json | jq
```

## How it works

1. **Target resolution** – resolve the hostname once and reuse every socket address.
2. **Parallel TCP scan** – fire short-lived TCP connect attempts across a rayon thread pool.
3. **Protocol fingerprinting** – run null reads and targeted probes to capture banners and detect services.
4. **Exploit lookup** – query `searchsploit` for each unique product/version signature.
5. **Risk aggregation** – score and sort results before presenting either JSON or rich terminal cards.

## License

MIT

## Author

Made by: 3xecutablefile
