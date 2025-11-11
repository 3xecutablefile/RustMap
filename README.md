# OxideScanner

A high-performance network security scanner that combines fast port scanning with intelligent exploit discovery.

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Lightning-fast port scanning** - Parallel TCP scanning with configurable thread pools
- **Service detection** - Automatic service fingerprinting via nmap
- **Exploit discovery** - Built-in searchsploit integration for finding exploits
- **Risk assessment** - CVSS-based scoring with service-specific multipliers
- **Multiple output formats** - Rich terminal UI and JSON export
- **Rate limiting** - Configurable to avoid detection

## Quick Start

```bash
# Scan top 1000 ports (default)
oxscan target.com

# Scan specific number of ports
oxscan target.com -1k  # First 1000 ports
oxscan target.com -5k  # First 5000 ports
oxscan target.com -10k # First 10000 ports

# JSON output for automation
oxscan target.com -5k --json

# Multi-threaded scanning
oxscan target.com -10k --threads 16
```

## Installation

### Automated Install
```bash
git clone https://github.com/NotSmartMan/OxideScanner.git
cd OxideScanner
chmod +x install.sh
./install.sh
```

### Manual Build
```bash
# Prerequisites: nmap, searchsploit, Ruby
sudo apt install nmap ruby git  # Ubuntu/Debian
brew install nmap ruby git      # macOS

# Clone and build
git clone https://github.com/NotSmartMan/OxideScanner.git
cd OxideScanner
cargo build --release
sudo cp target/release/oxscan /usr/local/bin/
```

## Usage

### Syntax
```bash
oxscan <target> [options]
```

### Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `-Nk` | Scan N*1000 ports | `-1k` = 1000, `-5k` = 5000 |
| `-N` | Scan N ports directly | `-1000` = exactly 1000 ports |
| `--ports N` | Scan specific port count | `--ports 1000` |
| `--json` | JSON output format | `--json` |
| `--threads N` | Worker threads | `--threads 8` |
| `--scan-timeout MS` | TCP timeout | `--scan-timeout 50` |

### Environment Variables

```bash
export OXIDE_THREADS=8                    # Worker threads
export OXIDE_SCAN_TIMEOUT=50              # Scan timeout (ms)
export OXIDE_LOG_LEVEL=info               # Log level
export OXIDE_ENABLE_RATE_LIMIT=true       # Enable rate limiting
```

## Examples

```bash
# Basic scanning
oxscan scanme.nmap.org
oxscan example.com -5k

# Enterprise scanning
oxscan target.com -30k --threads 32 --json

# Cloud reconnaissance
oxscan api.example.com -10k --scan-timeout 25

# Automated vulnerability assessment
oxscan target.com -20k --json > results.json
```

## Understanding Results

OxideScanner assigns risk scores based on:
- Number of available exploits
- CVSS severity scores
- Service-specific risk multipliers

| Risk Level | Score | Action Required |
|------------|-------|-----------------|
| **CRITICAL** | 50+ | Immediate attention |
| **HIGH** | 30-49 | Priority fix |
| **MEDIUM** | 15-29 | Schedule remediation |
| **LOW** | <15 | Monitor |

## Architecture

OxideScanner uses a modular design:

- **scanner** - High-performance parallel port scanning
- **exploit** - Exploit database integration and risk scoring
- **external** - nmap and searchsploit abstractions
- **utils** - Networking utilities and target resolution

## Security

**⚠️ Authorized use only** - Only scan systems you own or have explicit permission to test.

```bash
# Responsible scanning practices
oxscan target.com -10k --threads 4 --scan-timeout 100
```

## Contributing

1. Fork the repository
2. Create a feature branch  
3. Make changes with tests
4. Run `cargo test` and `cargo fmt`
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

Made by [3xecutablefile](https://github.com/NotSmartMan)