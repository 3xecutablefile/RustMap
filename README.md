# OxideScanner

A high-performance network security scanner that combines lightning-fast port scanning with intelligent exploit discovery. Built for enterprise security teams and penetration testers.

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)]()

## 🌟 Key Features

- **⚡ Lightning-fast port scanning** - Parallel TCP scanning with configurable thread pools
- **🎯 Service detection** - Automatic service fingerprinting via nmap
- **🧠 Intelligent exploit discovery** - Searchsploit integration with smart query filtering
- **📊 Risk assessment** - CVSS-based scoring with service-specific multipliers
- **📱 Multiple output formats** - Rich terminal UI and JSON export
- **🛡️ Rate limiting** - Configurable to avoid detection

## 🚀 What's New in v1.0.1

### Intelligent Query Filtering

**Problem Solved**: Previous versions returned thousands of irrelevant exploits for generic terms like "http" and "https".

**Solution**: Intelligent filtering that only searches when meaningful service information is available.

| Before (v1.0.0) | After (v1.0.1) |
|-----------------|----------------|
| ❌ `http` → 27,309 irrelevant exploits | ✅ `http Apache httpd 2.4.7` → 17 real exploits |
| ❌ `https` → 27,309 irrelevant exploits | ✅ `https` → 0 exploits (correctly skipped) |
| ❌ Overwhelming false positives | ✅ Focused, actionable results |

### Real-World Examples

```bash
# scanme.nmap.org - Specific service detected
$ oxscan scanme.nmap.org -1k
Port 80: http Apache httpd 2.4.7 → 17 real exploits found ✅

# google.com - Generic services
$ oxscan google.com -1k  
Port 80: http → SUCCESS No exploits found for detected services ✅
```

## ⚡ Quick Start

### One-Line Installation
```bash
git clone https://github.com/NotSmartMan/OxideScanner.git && cd OxideScanner && ./install.sh
```

### Basic Usage
```bash
# Quick scan (top 1000 ports)
oxscan target.com

# Custom port ranges
oxscan target.com -1k     # First 1000 ports
oxscan target.com -5k     # First 5000 ports  
oxscan target.com -10k    # First 10000 ports

# JSON output for automation
oxscan target.com -5k --json > results.json

# Performance tuning
oxscan target.com -30k --threads 32 --scan-timeout 50
```

## 📋 Installation Options

### 🖥️ Automated Installation
```bash
git clone https://github.com/NotSmartMan/OxideScanner.git
cd OxideScanner
chmod +x install.sh
./install.sh
```

### 🔧 Manual Build
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

### 📦 Package Installation
```bash
# System binary
which oxscan  # Verify installation
oxscan --help
```

## 🎛️ Usage Reference

### Command Syntax
```bash
oxscan <target> [options]
```

### Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `-Nk` | Scan N×1000 ports | `-1k` = 1000, `-5k` = 5000 |
| `-N` | Scan N ports directly | `-1000` = exactly 1000 ports |
| `--ports N` | Scan specific port count | `--ports 1000` |
| `--json` | JSON output format | `--json` |
| `--threads N` | Worker threads | `--threads 8` |
| `--scan-timeout MS` | TCP timeout (ms) | `--scan-timeout 50` |

### Environment Configuration
```bash
export OXIDE_THREADS=8                    # Parallel scanning threads
export OXIDE_SCAN_TIMEOUT=50              # TCP connection timeout
export OXIDE_LOG_LEVEL=info               # Logging verbosity  
export OXIDE_ENABLE_RATE_LIMIT=true       # Enable rate limiting
```

## 🎯 Real-World Examples

### Basic Security Assessment
```bash
# Quick vulnerability scan
oxscan scanme.nmap.org

# Custom port range scan
oxscan example.com -10k
```

### Enterprise Reconnaissance  
```bash
# Large-scale enterprise scan
oxscan target.com -30k --threads 32 --json

# Cloud service reconnaissance
oxscan api.example.com -10k --scan-timeout 25
```

### Automated Integration
```bash
# Continuous security monitoring
oxscan target.com -20k --json | jq '.results[] | select(.risk_level == "CRITICAL")'

# CI/CD pipeline integration  
oxscan staging.example.com -5k --json > security-report.json
```

## 📊 Understanding Results

### Intelligent Exploit Analysis

OxideScanner v1.0.1 uses smart query filtering to provide accurate vulnerability intelligence:

#### How It Works
1. **Service Detection**: Nmap identifies services and products
2. **Intelligent Filtering**: Only searches when specific product info is available
3. **Exploit Discovery**: Queries searchsploit with targeted terms
4. **Risk Assessment**: Calculates CVSS-based risk scores

#### Service Detection Examples

| Service Type | Detection Result | Exploit Search |
|--------------|------------------|----------------|
| **Specific** | `http Apache httpd 2.4.7` | ✅ 17 real exploits |
| **Generic** | `http` | ❌ No exploits found |
| **Specific** | `ssh OpenSSH 8.4` | ✅ Real OpenSSH exploits |
| **Generic** | `https` | ❌ No exploits found |

### Risk Assessment Matrix

| Risk Level | Score Range | Action Required | Timeline |
|------------|-------------|-----------------|----------|
| **🔴 CRITICAL** | 50+ | Immediate attention | 24-48 hours |
| **🟡 HIGH** | 30-49 | Priority fix | 1-2 weeks |
| **🟠 MEDIUM** | 15-29 | Schedule remediation | 1-3 months |
| **🟢 LOW** | <15 | Monitor | Ongoing |

### Sample Output
```
==============================================================
RISK: CRITICAL | Port 80 | http Apache httpd 2.4.7 | Risk: 136.5 | 17 exploits
--------------------------------------------------------------
   [9.8 1 Apache + PHP < 5.3.12 - Remote Code Execution
    Path: php/remote/29290.c

   [8.1 2 Apache < 2.2.34 - OPTIONS Memory Leak  
    Path: linux/webapps/42745.py
   ...
   MORE 15 more exploits available
==============================================================

SUMMARY Summary:
  -> Total exploits found: 17
  -> High-risk services: 1
  -> Services analyzed: 1
```

## 🏗️ Architecture

OxideScanner employs a modular, high-performance architecture:

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

- **`scanner`** - High-performance parallel port scanning engine
- **`exploit`** - Intelligent exploit database integration and CVSS risk scoring
- **`external`** - Nmap and searchsploit abstraction layers
- **`utils`** - Networking utilities and target resolution

## 🛡️ Security & Ethics

### ⚠️ Important Disclaimer
**Authorized testing only** - Only scan systems you own or have explicit permission to test.

### Responsible Scanning Practices
```bash
# Conservative scanning to avoid detection
oxscan target.com -10k --threads 4 --scan-timeout 100

# Rate-limited scanning for production environments  
oxscan target.com -5k --threads 2 --enable-rate-limit

# Explicit permission scanning
oxscan authorized-target.com --explicit-permission
```

### Legal Compliance
- ✅ Obtain written authorization before scanning
- ✅ Respect rate limits and system resources
- ✅ Document all testing activities
- ✅ Report vulnerabilities responsibly

## 👨‍💻 Development

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
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes with comprehensive tests
4. Run `cargo test && cargo fmt && cargo clippy`
5. Submit a pull request with detailed description

## 📈 Performance Benchmarks

### Scanning Speed
- **1,000 ports**: ~3 seconds
- **10,000 ports**: ~30 seconds  
- **65,535 ports**: ~200 seconds

### Memory Usage
- **Idle**: ~10MB
- **Scanning**: ~50-100MB
- **Peak**: ~200MB (large port ranges)

### Exploit Search Performance
- **Specific services**: 1-5 seconds
- **Generic services**: <1 second (skipped)
- **Large ranges**: Optimized caching

## 📝 Changelog

### v1.0.1 (2025-11-11)
- 🎯 **Fixed** searchsploit JSON parsing with correct field mappings
- 🧠 **Added** intelligent query filtering for targeted exploit search
- ⚡ **Improved** performance by filtering out generic service queries
- 📊 **Enhanced** README with comprehensive examples and documentation
- 🔧 **Cleaned** codebase and removed unused dependencies

### v1.0.0 (Previous)
- Initial release with basic port scanning and exploit integration

## 📄 License

MIT License - see [LICENSE](LICENSE) for complete terms and conditions.

## 🤝 Support

- **Issues**: [GitHub Issues](https://github.com/NotSmartMan/OxideScanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/NotSmartMan/OxideScanner/discussions)
- **Documentation**: [docs.rs/oxidescanner](https://docs.rs/oxidescanner)

## 👨‍💻 Author

**3xecutablefile**  
*Enterprise Security Tools Developer*

[![GitHub](https://img.shields.io/badge/GitHub-NotSmartMan-blue.svg)](https://github.com/NotSmartMan)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue.svg)]()

---

<div align="center">

**Built with ❤️ for the security community**

[⭐ Star this repo](https://github.com/NotSmartMan/OxideScanner) • [🐛 Report Issues](https://github.com/NotSmartMan/OxideScanner/issues) • [💡 Request Features](https://github.com/NotSmartMan/OxideScanner/discussions)

</div>
