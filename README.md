# RustMap
*Fast port scanner and exploit finder written in Rust*

[![Made for hackers](https://img.shields.io/badge/made-for%20hackers-brightgreen.svg)](https://github.com/NotSmartMan/RustMap)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Security](https://img.shields.io/badge/security-professional-brightred.svg)]()

**RustMap** is a high-performance network reconnaissance tool that combines lightning-fast port scanning with automatic exploit discovery. Built for security professionals who need speed, accuracy, and actionable intelligence.

## Quick Start

```bash
git clone https://github.com/NotSmartMan/RustMap.git
cd RustMap
./install.sh
# Repository auto-deletes after successful installation!
rustmap scanme.nmap.org -1k
```

## Why RustMap?

- **Lightning Fast**: Parallel TCP scanning with Rayon
- **Smart Exploits**: Automatic searchsploit integration
- **Risk Scoring**: CVSS-based vulnerability assessment  
- **Professional Grade**: Rate limiting, timeouts, error handling
- **Multiple Formats**: Terminal UI + JSON output
- **Zero Config**: Works out of the box

## 🛠️ Installation

### One-Command Install
```bash
git clone https://github.com/NotSmartMan/RustMap.git && cd RustMap && chmod +x install.sh && ./install.sh
```

The installer automatically:
- Installs Rust, nmap, searchsploit
- Builds optimized release binary
- Installs to system PATH
- Cleans up source repository
- Verifies everything works

### Manual Install
```bash
# Prerequisites
sudo apt install nmap ruby git build-essential  # Ubuntu/Debian
brew install nmap git  # macOS

# Install searchsploit
git clone https://github.com/offensive-security/exploitdb.git /opt/searchsploit
sudo ln -sf /opt/searchsploit/searchsploit /usr/local/bin/

# Build RustMap
git clone https://github.com/NotSmartMan/RustMap.git
cd RustMap
cargo build --release
sudo cp target/release/rustmap /usr/local/bin/
```

## Usage Examples

### Basic Reconnaissance
```bash
# Quick scan of top 1000 ports
rustmap target.com -1k

# Full port scan (all 65535 ports)  
rustmap target.com

# Fast scan with custom port range
rustmap 192.168.1.1 -5k
```

### Advanced Scanning
```bash
# High-performance scanning
rustmap target.com -10k --threads 8 --scan-timeout 20

# Conservative scanning (sensitive networks)
rustmap target.com -1k --scan-timeout 100

# Custom timeouts
rustmap target.com -5k --scan-timeout 50 --exploit-timeout 15000
```

### JSON Output for Automation
```bash
# JSON output for scripting
rustmap target.com -5k --json

# Filter high-risk results
rustmap target.com -5k --json | jq '.[] | select(.risk_score > 50)'

# Export for reports
rustmap target.com -10k --json > scan_results.json
```

### Real-World Examples
```bash
# Scan your local network
rustmap 192.168.1.0/24 -1k

# Test against nmap's official target
rustmap scanme.nmap.org -1k

# Batch scan multiple targets
for target in target1.com target2.com target3.com; do
    rustmap "$target" -5k --json > "${target}_scan.json"
done
```

## Key Features

### Parallel Port Scanning
- Uses **Rayon** for CPU-optimized parallelism
- Configurable thread count or auto-detection
- Real-time progress reporting
- Efficient connection pooling

### Smart Service Detection
- **Nmap integration** for fingerprinting
- Product/version extraction
- Protocol-specific probes
- Banner grabbing capabilities

### Exploit Database Integration
- **Searchsploit** automatic queries
- CVSS score extraction
- Deduplicated results
- Risk-based prioritization

### Risk Assessment Engine
```bash
# Risk Levels:
CRITICAL  (50+): Active exploits available
HIGH      (30-49): Multiple vulnerabilities
MEDIUM    (15-29): Some security concerns  
LOW       (0-14): Minimal risk
```

### Professional Features
- **Rate limiting** prevents network overwhelm
- **Graceful timeouts** handle unresponsive services
- **Retry mechanisms** with exponential backoff
- **Metrics export** for monitoring
- **Structured logging** (console + file)

## Output Examples

### Terminal Output
```bash
$ rustmap scanme.nmap.org -1k

Fast scanning top 1000 ports on scanme.nmap.org...
[████████████████████████████████████████] 100% | 1000/1000 scanned | 2.1s

Found 3 open ports

Open Ports:
  → Port 22
  → Port 80  
  → Port 443

Detecting services with nmap-style probes...

Service Detection Results:
  → Port 22: ssh OpenSSH 7.4
  → Port 80: http Apache httpd 2.4.7
  → Port 443: ssl Apache httpd 2.4.7

Searching exploits and calculating risk scores...

Exploit Analysis Results:
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CRITICAL Port 80 | http Apache httpd 2.4.7 | Risk: 65.4 ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ [9.8] 1 Apache HTTP Server 2.4.7 mod_rewrite Buffer Overflow ┃
┃     apache/2.4.7/mod_rewrite.c                              ┃
┃ [9.8] 2 Apache HTTP Server 2.4.7 mod_cgi Environment RCE    ┃
┃     linux/remote/39773.txt                                  ┃
┃ [8.1] 3 Apache HTTP Server 2.4.7 mod_ssl Heartbeat         ┃
┃     apache/2.4.7/mod_ssl/heartbeat.c                        ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Summary:
  → Total exploits found: 18
  → High-risk services: 1
  → Services analyzed: 3
```

### JSON Output
```bash
$ rustmap scanme.nmap.org -1k --json | jq '.[0]'
{
  "port": {
    "port": 80,
    "service": "http",
    "product": "Apache httpd", 
    "version": "2.4.7"
  },
  "exploits": [
    {
      "title": "Apache HTTP Server 2.4.7 RCE",
      "url": "https://www.exploit-db.com/39773",
      "cvss": 9.8,
      "path": "apache/2.4.7/rce.c"
    }
  ],
  "risk_score": 65.4
}
```

## Configuration

### Command Line Options
| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-Nk` | Port limit (1-30k) | Full scan | `-5k` (5000 ports) |
| `--json` | JSON output | False | `--json` |
| `--scan-timeout MS` | TCP timeout | 25ms | `--scan-timeout 50` |
| `--exploit-timeout MS` | Search timeout | 10s | `--exploit-timeout 15000` |
| `--threads N` | Worker threads | Auto | `--threads 8` |
| `--no-rate-limit` | Disable rate limiting | Enabled | `--no-rate-limit` |

### Environment Variables
```bash
# Performance tuning
export RUSTMAP_THREADS=8                    # CPU cores
export RUSTMAP_SCAN_TIMEOUT=50              # Faster networks
export RUSTMAP_EXPLOIT_TIMEOUT=15000        # Slower systems

# Rate limiting  
export RUSTMAP_SCANNER_RATE_LIMIT=100       # Aggressive scanning
export RUSTMAP_EXTERNAL_TOOLS_RATE_LIMIT=10 # Nmap/searchsploit

# Logging
export RUSTMAP_LOG_LEVEL=debug             # Verbose output
export RUSTMAP_LOG_FILE=/var/log/rustmap.log # File logging

# Metrics
export RUSTMAP_METRICS_ENABLED=true         # Prometheus metrics
export RUSTMAP_METRICS_PORT=9090            # Metrics endpoint
```

## Use Cases

### Penetration Testing
```bash
# Initial reconnaissance
rustmap target.com -10k --json > initial_scan.json

# Focus on web services
rustmap target.com -5k --json | jq '.[] | select(.port.service == "http" or .port.service == "https")'

# High-risk targets only
rustmap target.com -5k --json | jq '.[] | select(.risk_score > 30)'
```

### Network Monitoring
```bash
# Detect new services
rustmap 192.168.1.0/24 -1k --json | jq '.[] | select(.risk_score > 20)'

# Compliance checking
rustmap internal-server.com -5k --json > compliance_scan.json

# Automated reporting
rustmap subnet.example.com -1k --json | jq '[.[] | {port: .port.port, service: .port.service, risk: .risk_score}]'
```

### Bug Bounty Hunting
```bash
# Quick target assessment
rustmap target.com -30k --threads 16

# Export for further analysis
rustmap target.com -10k --json > target_analysis.json

# Focus on uncommon ports
rustmap target.com -5k --json | jq '.[] | select(.port.port > 49152 or .port.port < 1024)'
```

### Network Monitoring
```bash
# Detect new services
rustmap 192.168.1.0/24 -1k --json | jq '.[] | select(.risk_score > 20)'

# Compliance checking
rustmap internal-server.com -5k --json > compliance_scan.json

# Automated reporting
rustmap subnet.example.com -1k --json | jq '[.[] | {port: .port.port, service: .port.service, risk: .risk_score}]'
```

### Bug Bounty Hunting
```bash
# Quick target assessment
rustmap target.com -30k --threads 16

# Export for further analysis
rustmap target.com -10k --json > target_analysis.json

# Focus on uncommon ports
rustmap target.com -5k --json | jq '.[] | select(.port.port > 49152 or .port.port < 1024)'
```

## Security & Ethics

### Legal Usage
- Only scan systems you own
- Test with explicit permission  
- Follow responsible disclosure
- Respect rate limits

### Best Practices
```bash
# Respectful scanning
rustmap target.com -1k --scan-timeout 100

# Conservative approach
rustmap target.com -5k --threads 4 --scan-timeout 200

# Production-safe
rustmap target.com -1k --scan-timeout 300 --no-rate-limit
```

## Performance

### Speed Comparisons
- **1k ports**: 2-10 seconds
- **5k ports**: 10-30 seconds  
- **Full scan**: 1-10 minutes
- **Exploit search**: 5-30 seconds

### Optimization Tips
```bash
# Fast networks
export RUSTMAP_THREADS=$(nproc)
export RUSTMAP_SCAN_TIMEOUT=10
export RUSTMAP_SCANNER_RATE_LIMIT=200

# Slow networks  
export RUSTMAP_SCAN_TIMEOUT=100
export RUSTMAP_SCANNER_RATE_LIMIT=25

# Resource conservation
export RUSTMAP_THREADS=4
export RUSTMAP_SCAN_TIMEOUT=200
```

## Troubleshooting

### Common Issues

**"Command not found" after install:**
```bash
# Re-run installer or manually add to PATH
export PATH="/usr/local/bin:$PATH"
```

**No exploits found:**
```bash
# Update exploit database
searchsploit --update

# Test with known vulnerable target
rustmap scanme.nmap.org -1k
```

**Slow scanning:**
```bash
# Faster timeouts
rustmap target.com -1k --scan-timeout 10

# More threads
rustmap target.com -5k --threads 8
```

**Permission errors:**
```bash
# Use local build
cargo build --release
./target/release/rustmap target.com -1k
```

### Diagnostic Script
```bash
#!/bin/bash
echo "RustMap Diagnostic Check"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -n "Rust: "; rustc --version 2>/dev/null && echo "OK" || echo "FAIL Install Rust"
echo -n "Nmap: "; nmap --version 2>/dev/null | head -1 && echo "OK" || echo "FAIL Install nmap"  
echo -n "Searchsploit: "; searchsploit --help 2>/dev/null | head -1 && echo "OK" || echo "FAIL Install searchsploit"
echo -n "RustMap: "; rustmap --help 2>/dev/null | head -1 && echo "OK" || echo "FAIL Install rustmap"
echo ""
echo "Functional Test:"
if rustmap scanme.nmap.org -1k --json >/dev/null 2>&1; then
    echo "OK RustMap working correctly!"
else
    echo "FAIL Test failed - check dependencies"
fi
```

## Documentation

- **Full API docs**: [docs.rs/rustmap](https://docs.rs/rustmap)
- **Configuration guide**: See `./config.toml` examples
- **Docker support**: `docker build -t rustmap .`
- **Kubernetes**: Deployment manifests in `k8s/`

## Contributing

We welcome contributions! Areas where help is needed:
- Additional service detection modules
- New exploit database integrations  
- Performance optimizations
- Security testing and validation
- Documentation improvements

### Development Setup
```bash
git clone https://github.com/NotSmartMan/RustMap.git
cd RustMap

# Install development tools
cargo install cargo-watch cargo-audit cargo-tarpaulin

# Run tests
cargo test

# Live development
cargo watch -x run -- target.com -1k

# Code coverage
cargo tarpaulin --out html
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- **nmap** - Network exploration and security auditing
- **searchsploit** - Exploit database from Offensive Security
- **Rayon** - Data parallelism in Rust
- **Tokio** - Asynchronous runtime
- **Rust Community** - For the amazing ecosystem

## Project Status

<<<<<<< HEAD
- **Stable**: Production-ready for security testing
- **Fast**: Optimized for performance
- **Safe**: Input validation and error handling
- **Tested**: Comprehensive test suite
- **Documented**: Full API and user docs
=======
- **Documentation**: [Full documentation](https://docs.rs/rustmap)
- **Issues**: [GitHub Issues](https://github.com/3xecutablefile/RustMap/issues)

>>>>>>> e0e5dd6a020901bbd38cffa83b3741765f1b4437

---

## Start Hacking Now

<<<<<<< HEAD
```bash
# Clone and scan in 30 seconds
git clone https://github.com/NotSmartMan/RustMap.git && cd RustMap && ./install.sh && rustmap scanme.nmap.org -1k
```

**Made for hackers, by hackers.**

*Built by security professionals, for security professionals.*
=======
*Built for security professionals, by security professionals.*
>>>>>>> e0e5dd6a020901bbd38cffa83b3741765f1b4437
