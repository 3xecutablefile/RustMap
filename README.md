# OxideScanner

A rust-based scanner with built in exploit searching.

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)]()

<<<<<<< Updated upstream
=======
## Features

- **Fast port scanning** - Parallel TCP scanning with configurable threads
- **Service detection** - Automatic service fingerprinting via nmap
- **Smart exploit discovery** - Searchsploit integration with intelligent filtering
- **Risk assessment** - CVSS-based scoring with service multipliers
- **Multiple formats** - Terminal interface and JSON output
- **Rate limiting** - Configurable to avoid detection
- **Auto-update** - Built-in update mechanism

>>>>>>> Stashed changes

### Important
**Only scan systems you own or have explicit permission to test.**

## Quick Start

### Installation
```bash
git clone https://github.com/NotSmartMan/OxideScanner.git
cd OxideScanner
./install.sh
```

### Basic Usage
<<<<<<< Updated upstream


Common options
=======
```bash
# Interactive mode - tool will ask you to enter port count
oxscan scanme.nmap.org

# Scan specific port ranges
oxscan target.com --ports:1000-30000 --threads:6

# Scan top N ports
oxscan target.com --ports 1000

# JSON output for scripts
oxscan target.com --ports 5000 --json > results.json

# Update to latest version
oxscan --update
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
oxscan <target> [port-options] [--json] [--scan-timeout MS] [--exploit-timeout MS] [--threads N|--threads:N] [--update]
```

### Port Specification Options

| Option | Description | Example |
|--------|-------------|---------|
| `--ports:START-END` | Scan specific port range | `--ports:1000-30000` |
| `--ports N` | Scan top N ports | `--ports 1000` |
| (no flag) | Interactive port selection | `oxscan target.com` |

### Other Options
>>>>>>> Stashed changes

| Option | Description | Example |
|--------|-------------|---------|
| `--threads N` | Worker threads | `--threads 8` |
| `--threads:N` | Worker threads (compact) | `--threads:6` |
| `--json` | JSON output | `--json` |
| `--scan-timeout MS` | TCP connection timeout | `--scan-timeout 50` |
| `--exploit-timeout MS` | Exploit search timeout | `--exploit-timeout 15000` |
| `--update` | Update to latest version | `--update` |

Command Syntax
```bash
oxscan <target> [options]
```

Configuration
```bash
export OXIDE_THREADS=8                    # Parallel scanning
export OXIDE_SCAN_TIMEOUT=50              # Connection timeout
export OXIDE_LOG_LEVEL=info               # Logging level
export OXIDE_ENABLE_RATE_LIMIT=true       # Enable rate limiting
```

## Installation Options

### Automated
```bash
git clone https://github.com/3xecutablefile/OxideScanner.git
cd OxideScanner
chmod +x install.sh
./install.sh
```

### Manual Build
```bash
# Prerequisites
sudo apt install nmap ruby git        
brew install nmap ruby git            

# Build from source
git clone https://github.com/3xecutablefile/OxideScanner.git
cd OxideScanner
cargo build --release
sudo cp target/release/oxscan /usr/local/bin/
```



## Example

```bash
<<<<<<< Updated upstream
oxscan scanme.nmap.org
```
### Output:
=======
# Interactive scanning - tool asks for port count
oxscan scanme.nmap.org

# Custom port range with performance tuning
oxscan example.com --ports:1000-30000 --threads:6

# Quick scan of top ports
oxscan example.com --ports 1000
```

### Large-Scale Scanning
```bash
# Comprehensive scan with JSON output
oxscan target.com --ports:1-65535 --threads 32 --json

# Cloud service scanning with custom timeouts
oxscan api.example.com --ports:1000-10000 --scan-timeout 25

# High-performance scanning
oxscan target.com --ports:1-30000 --threads:16 --exploit-timeout 5000
```

### Automation & Scripting
```bash
# Filter critical findings
oxscan target.com --ports:1-10000 --json | jq '.results[] | select(.risk_level == "CRITICAL")'

# CI/CD integration
oxscan staging.example.com --ports 5000 --json > security-report.json

# Batch scanning multiple targets
for target in $(cat targets.txt); do
    oxscan $target --ports:1000-5000 --json >> scan-results.json
done
```

### Update & Maintenance
```bash
# Update to latest version
oxscan --update

# Check current version
oxscan --help
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
>>>>>>> Stashed changes
```
FAST SCAN Fast scanning ports 1000-30000 on example.com...
[████████████████████████████████████████] 100% | 29000/29000 scanned | 45.2s
SUCCESS Found 3 open ports

SERVICE DETECTION Results:
  -> Port 22: ssh OpenSSH 8.2p1
  -> Port 80: http Apache httpd 2.4.41
  -> Port 443: ssl/http Apache httpd 2.4.41

================================================================
Port 80 | http Apache httpd 2.4.41 | Risk: 136.5 | 17 exploits
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
  Services analyzed: 3
```

## Architecture


### Core Components

- **scanner** - High-performance parallel port scanning
- **exploit** - Exploit database integration and risk scoring
- **external** - Nmap and searchsploit tool abstractions
- **utils** - Networking utilities and target resolution



<<<<<<< Updated upstream
=======
### Responsible Scanning
```bash
# Conservative scanning to avoid detection
oxscan target.com --ports:1000-10000 --threads 4 --scan-timeout 100

# Rate-limited scanning for production environments
oxscan target.com --ports 5000 --threads 2

# Authorized testing only
oxscan authorized-target.com --ports:1000-30000 --explicit-permission
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
1. Fork repository
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
>>>>>>> Stashed changes

## Changelog

### v1.0.1 (2025-11-11)
- **NEW**: Added `--ports:START-END` port range specification
- **NEW**: Added `--threads:N` compact thread format
- **NEW**: Added `--update` flag for automatic updates
- **IMPROVED**: Simplified command-line interface
- **REMOVED**: Deprecated `-Nk` and `-N` flag formats
- **FIXED**: Searchsploit JSON parsing with correct field mappings
- **ENHANCED**: Interactive port selection when no flags specified

### v1.0.0
- Initial release with basic port scanning and exploit integration

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/3xecutablefile/OxideScanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/3xecutablefile/OxideScanner/discussions)

## Author

**3xecutablefile**  
*random kid*

[![GitHub](https://img.shields.io/badge/GitHub-3xecutablefile-blue.svg)](https://github.com/3xecutablefile)

---

<div align="center">

**Fast Port Scanning with Smart Exploit Discovery**

[Star Repository](https://github.com/3xecutablefile/OxideScanner) • [Report Issues](https://github.com/3xecutablefile/OxideScanner/issues) • [Request Features](https://github.com/3xecutablefile/OxideScanner/discussions)

</div>