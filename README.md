# OxideScanner

A fast network port scanner with intelligent exploit discovery. Built for security professionals who need quick, accurate vulnerability assessment.

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)]()

## Features

- **Fast port scanning** - Parallel TCP scanning with configurable threads
- **Service detection** - Automatic service fingerprinting via nmap
- **Smart exploit discovery** - Searchsploit integration with intelligent filtering
- **Risk assessment** - CVSS-based scoring with service multipliers
- **Multiple formats** - Terminal interface and JSON output
- **Rate limiting** - Configurable to avoid detection



## Quick Start

### Installation
```bash
git clone https://github.com/NotSmartMan/OxideScanner.git
cd OxideScanner
./install.sh
```

### Basic Usage
```bash
# Quick scan (top 1000 ports)
oxscan target.com

# Scan specific ranges
oxscan target.com -1k     # First 1000 ports
oxscan target.com -5k     # First 5000 ports
oxscan target.com -10k    # First 10000 ports

# JSON output for scripts
oxscan target.com -5k --json > results.json

# Performance tuning
oxscan target.com -30k --threads 32 --scan-timeout 50
```

## Installation Options

### Automated
```bash
git clone https://github.com/NotSmartMan/OxideScanner.git
cd OxideScanner
chmod +x install.sh
./install.sh
```

### Manual Build
```bash
# Prerequisites
sudo apt install nmap ruby git        # Ubuntu/Debian
brew install nmap ruby git            # macOS

# Build from source
git clone https://github.com/NotSmartMan/OxideScanner.git
cd OxideScanner
cargo build --release
sudo cp target/release/oxscan /usr/local/bin/
```

## Usage Reference

### Command Syntax
```bash
oxscan <target> [options]
```

### Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `-Nk` | Scan N×1000 ports | `-1k` = 1000, `-5k` = 5000 |
| `-N` | Scan N ports | `-1000` = exactly 1000 ports |
| `--ports N` | Scan port count | `--ports 1000` |
| `--json` | JSON output | `--json` |
| `--threads N` | Worker threads | `--threads 8` |
| `--scan-timeout MS` | TCP timeout | `--scan-timeout 50` |

### Configuration
```bash
export OXIDE_THREADS=8                    # Parallel scanning
export OXIDE_SCAN_TIMEOUT=50              # Connection timeout
export OXIDE_LOG_LEVEL=info               # Logging level
export OXIDE_ENABLE_RATE_LIMIT=true       # Enable rate limiting
```

## Examples

### Basic Security Scan
```bash
# Quick vulnerability assessment
oxscan scanme.nmap.org

# Custom port range
oxscan example.com -10k
```

### Large-Scale Scanning
```bash
# Comprehensive scan with JSON output
oxscan target.com -30k --threads 32 --json

# Cloud service scanning
oxscan api.example.com -10k --scan-timeout 25
```

### Automation
```bash
# Filter critical findings
oxscan target.com -20k --json | jq '.results[] | select(.risk_level == "CRITICAL")'

# CI/CD integration
oxscan staging.example.com -5k --json > security-report.json
```

## Understanding Results

### How It Works

1. **Port Scanning**: Fast TCP connect scanning on target ports
2. **Service Detection**: Nmap identifies services and versions
3. **Smart Filtering**: Only searches exploits when specific service info is available
4. **Risk Analysis**: Calculates CVSS-based risk scores

### Risk Levels

| Level | Score | Action Required |
|-------|-------|-----------------|
| **CRITICAL** | 50+ | Immediate attention |
| **HIGH** | 30-49 | Priority fix |
| **MEDIUM** | 15-29 | Schedule remediation |
| **LOW** | <15 | Monitor |

### Sample Output
```
================================================================
Port 80 | http Apache httpd 2.4.7 | Risk: 136.5 | 17 exploits
----------------------------------------------------------------
   [9.8] Apache + PHP Remote Code Execution
    Path: php/remote/29290.c

   [8.1] Apache Memory Information Leak
    Path: linux/web-apps/42745.py
    ...
    15 more exploits available
================================================================

Summary:
  Total exploits: 17
  High-risk services: 1
  Services analyzed: 1
```

## Architecture

### System Design

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Port Scanner  │───▶│  Service Detector│───▶│ Exploit Finder  │
│                 │    │                  │    │                 │
│ • Parallel TCP  │    │ • Nmap integration│    │ • Searchsploit  │
│ • Thread pools  │    │ • Version detection│    │ • CVSS scoring  │
│ • Rate limiting │    │ • Product ID      │    │ • Risk analysis │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Formatter     │    │    Output        │    │   Reporting     │
│                 │    │                  │    │                 │
│ • Terminal UI   │    │ • Rich display   │    │ • JSON export   │
│ • Progress bars │    │ • Color coding   │    │ • Risk metrics  │
│ • Status updates│    │ • Summary stats  │    │ • Service info  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Core Components

- **scanner** - High-performance parallel port scanning
- **exploit** - Exploit database integration and risk scoring
- **external** - Nmap and searchsploit tool abstractions
- **utils** - Networking utilities and target resolution

## Security & Ethics

### Important
**Only scan systems you own or have explicit permission to test.**

### Responsible Scanning
```bash
# Conservative scanning to avoid detection
oxscan target.com -10k --threads 4 --scan-timeout 100

# Rate-limited scanning for production environments
oxscan target.com -5k --threads 2 --enable-rate-limit

# Authorized testing only
oxscan authorized-target.com --explicit-permission
```

### Legal Guidelines
- Get written authorization before scanning
- Respect system resources and rate limits
- Document all testing activities
- Report vulnerabilities responsibly

## Development

### Building from Source
```bash
git clone https://github.com/NotSmartMan/OxideScanner.git
cd OxideScanner
cargo build --release
```

### Running Tests
```bash
cargo test        # Run all tests
cargo test --release  # Performance tests
cargo fmt         # Code formatting
cargo clippy      # Linting
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run `cargo test && cargo fmt && cargo clippy`
5. Submit pull request

## Performance

### Scanning Speed
- **1,000 ports**: ~3 seconds
- **10,000 ports**: ~30 seconds
- **65,535 ports**: ~200 seconds

### Memory Usage
- **Idle**: ~10MB
- **Scanning**: ~50-100MB
- **Peak**: ~200MB (large port ranges)

### Exploit Search
- **Specific services**: 1-5 seconds
- **Generic services**: <1 second (skipped)
- **Large ranges**: Optimized caching

## Changelog

### v1.0.1 (2025-11-11)
- Fixed searchsploit JSON parsing with correct field mappings
- Added intelligent query filtering for targeted exploit search
- Improved performance by filtering generic service queries
- Enhanced documentation with comprehensive examples
- Cleaned codebase and removed unused dependencies

### v1.0.0
- Initial release with basic port scanning and exploit integration

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/NotSmartMan/OxideScanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/NotSmartMan/OxideScanner/discussions)
- **Documentation**: [docs.rs/oxidescanner](https://docs.rs/oxidescanner)

## Author

**3xecutablefile**  
*Security Tool Developer*

[![GitHub](https://img.shields.io/badge/GitHub-NotSmartMan-blue.svg)](https://github.com/NotSmartMan)

---

<div align="center">

**Fast Port Scanning with Smart Exploit Discovery**

[Star Repository](https://github.com/NotSmartMan/OxideScanner) • [Report Issues](https://github.com/NotSmartMan/OxideScanner/issues) • [Request Features](https://github.com/NotSmartMan/OxideScanner/discussions)

</div>