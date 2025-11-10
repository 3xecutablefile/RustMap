# RustMap

**Fast port scanner and exploit finder written in Rust**

RustMap is a high-performance network security tool that quickly scans ports and finds known exploits. Perfect for security professionals, penetration testers, and network administrators.

[![GitHub stars](https://img.shields.io/github/stars/3xecutablefile/RustMap.svg)](https://github.com/3xecutablefile/RustMap/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/3xecutablefile/RustMap.svg)](https://github.com/3xecutablefile/RustMap/issues)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why RustMap?

- **Super Fast** - Parallel scanning with optimized performance
- **Accurate** - Professional-grade service detection
- **Comprehensive** - Automatic exploit database integration
- **Safe** - Built-in rate limiting and error handling
- **Professional** - Clean output and JSON export

## Table of Contents

1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [Common Examples](#common-examples)
4. [Advanced Features](#advanced-features)
5. [Troubleshooting](#troubleshooting)
6. [Full Documentation](#full-documentation)

## Installation

### Option 1: Automatic Installation (Recommended)

```bash
git clone https://github.com/3xecutablefile/RustMap.git
cd RustMap
chmod +x install.sh
./install.sh
```

The installer will:
- Install Rust (if needed)
- Install nmap and searchsploit
- Build RustMap
- Add to your system PATH
- Verify everything works

### Option 2: Manual Installation

**Prerequisites:**
- Rust (install at https://rustup.rs)
- nmap: `sudo apt install nmap` (Ubuntu) or `brew install nmap` (macOS)
- searchsploit: `git clone https://github.com/offensive-security/exploitdb.git /opt/searchsploit && sudo ln -sf /opt/searchsploit/searchsploit /usr/local/bin/searchsploit`

**Build and Install:**
```bash
git clone https://github.com/3xecutablefile/RustMap.git
cd RustMap
cargo build --release
sudo cp target/release/rustmap /usr/local/bin/
```

## Basic Usage

### Simple Port Scan
```bash
# Scan top 1000 ports on a target
rustmap target.com -1k
```

### Quick Exploit Search
```bash
# Find exploits for a target
rustmap scanme.nmap.org -1k
```

The tool will:
1. Scan open ports
2. Identify services
3. Find related exploits
4. Show risk assessment

## Common Examples

### Network Reconnaissance
```bash
# Quick scan of a target
rustmap 192.168.1.1 -1k

# Full port scan
rustmap target.com

# Scan specific IP range
rustmap 192.168.1.0/24 -5k
```

### Vulnerability Assessment
```bash
# Find high-risk services
rustmap target.com -10k --json | jq '.[] | select(.risk_score > 50)'

# Export results for reporting
rustmap target.com -5k --json > scan_results.json
```

### Automation & Scripts
```bash
# Batch scan multiple targets
for target in target1.com target2.com target3.com; do
    rustmap "$target" -1k --json > "${target}_scan.json"
done

# Monitor for new services
rustmap target.com -1k | grep "HIGH|CRITICAL"
```

## Advanced Features

### Performance Tuning
```bash
# Faster scanning (aggressive settings)
rustmap target.com -30k --threads 16 --scan-timeout 10

# Conservative scanning (for sensitive networks)
rustmap target.com -5k --scan-timeout 100
```

### Custom Configuration
```bash
# Use JSON output for automation
rustmap target.com --json

# Set custom timeouts
rustmap target.com --scan-timeout 50 --exploit-timeout 15000
```

### Environment Configuration
```bash
# Set optimal thread count
export RUSTMAP_THREADS=8

# Enable detailed logging
export RUSTMAP_LOG_LEVEL=debug

# Custom rate limiting
export RUSTMAP_SCANNER_RATE_LIMIT=100
```

## Output Examples

### Terminal Output
```bash
$ rustmap scanme.nmap.org -1k

Fast scanning top 1000 ports on scanme.nmap.org...
[████████████████████████████████████████] 100% | 1000/1000 scanned | 2.1s
Found 3 open ports

Open Ports:
  → Port 22 (ssh)
  → Port 80 (http)
  → Port 443 (https)

Exploit Analysis:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HIGH  Port 80 | http Apache | Risk: 45.2 | 8 exploits ━━━━━━━
  [9.8] 1 Apache HTTP Server 2.4.7 RCE
  [8.1] 2 Apache mod_ssl Heartbleed
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### JSON Output
```bash
$ rustmap scanme.nmap.org --json | jq '.[0]'
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

## Quick Installation

### Automatic Installation (Recommended)
```bash
# Clone and run the installation script
git clone https://github.com/3xecutablefile/RustMap.git
cd RustMap
chmod +x install.sh
./install.sh
```

The installation script automatically:
- Detects your operating system
- Installs all dependencies (Rust, nmap, searchsploit, git, ruby)
- Builds RustMap in optimized release mode
- Installs to system PATH (/usr/local/bin)
- Updates exploit database
- Verifies all components are working

### One-Liner Installation
```bash
curl -sSL https://raw.githubusercontent.com/3xecutablefile/RustMap/main/install.sh | bash
```

### Manual Installation (Alternative)
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install system dependencies
# Ubuntu/Debian:
sudo apt install nmap ruby git build-essential

# macOS:
brew install nmap git

# Install searchsploit
git clone https://github.com/offensive-security/exploitdb.git /opt/searchsploit
sudo ln -sf /opt/searchsploit/searchsploit /usr/local/bin/searchsploit
searchsploit --update

# Build RustMap
git clone https://github.com/3xecutablefile/RustMap.git
cd RustMap && cargo build --release
sudo cp target/release/rustmap /usr/local/bin/
```

## Usage Examples

### Basic Scanning
```bash
# Quick scan of top 1000 ports
rustmap scanme.nmap.org -1k

# Full port scan (all 65,535 ports)
rustmap scanme.nmap.org

# Scan specific target
rustmap 192.168.1.100 -5k
```

### Advanced Configuration
```bash
# Custom timeouts for slow networks
rustmap target.local --scan-timeout 100 --exploit-timeout 30000

# High-performance scanning with aggressive settings
rustmap target.local -30k --threads 16 --scan-timeout 10

# JSON output for automation
rustmap scanme.nmap.org -5k --json

# Custom thread count
rustmap target.local -10k --threads 8
```

### Filtering and Analysis
```bash
# Filter high-risk results with jq
rustmap target.local --json | jq '.[] | select(.risk_score > 50)'

# Extract specific fields
rustmap scanme.nmap.org --json | jq '.[] | {port: .port.port, service: .port.service, risk: .risk_score}'

# Save results for analysis
rustmap target.local -10k --json > scan_results.json

# Process results offline
cat scan_results.json | jq '.[] | select(.exploits | length > 0)'
```

### Environment-Based Configuration
```bash
# Set custom thread count
export RUSTMAP_THREADS=8
rustmap target.local

# Enable debug logging
export RUSTMAP_LOG_LEVEL=debug
rustmap target.local -1k

# Custom rate limiting
export RUSTMAP_SCANNER_RATE_LIMIT=100
export RUSTMAP_EXTERNAL_TOOLS_RATE_LIMIT=10
rustmap target.local

# Metrics collection
export RUSTMAP_METRICS_ENABLED=true
export RUSTMAP_METRICS_PORT=9090
rustmap target.local -5k
```

### Batch Processing
```bash
# Scan multiple targets from file
while read target; do
    echo "Scanning $target..."
    rustmap "$target" -5k --json > "${target//[^a-zA-Z0-9]/_}.json"
done < targets.txt

# Process scan results
find . -name "*.json" -exec jq -r '.[] | select(.risk_score > 30) | "\(.port.port) \(.port.service) \(.risk_score)"' {} \;
```

## Configuration Options

### Command Line Arguments
| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-Nk` | Port limit (1-30k ports) | All ports | `-5k` (5000 ports) |
| `--json` | JSON output format | False | `--json` |
| `--scan-timeout MS` | TCP connection timeout | 25ms | `--scan-timeout 50` |
| `--exploit-timeout MS` | Exploit search timeout | 10000ms | `--exploit-timeout 15000` |
| `--threads N` | Thread count (0=auto) | Auto-detect | `--threads 8` |
| `--no-rate-limit` | Disable rate limiting | Enabled | `--no-rate-limit` |

### Environment Variables
| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `RUSTMAP_THREADS` | Number of worker threads | Auto | `8` |
| `RUSTMAP_LOG_LEVEL` | Logging level | `info` | `debug` |
| `RUSTMAP_LOG_JSON` | JSON logging | `false` | `true` |
| `RUSTMAP_LOG_FILE` | Log file path | None | `/var/log/rustmap.log` |
| `RUSTMAP_SCANNER_RATE_LIMIT` | Scanner operations/sec | `50` | `100` |
| `RUSTMAP_EXTERNAL_TOOLS_RATE_LIMIT` | External tools/sec | `5` | `10` |
| `RUSTMAP_EXPLOIT_QUERIES_RATE_LIMIT` | Exploit queries/sec | `2` | `5` |
| `RUSTMAP_METRICS_ENABLED` | Enable metrics | `false` | `true` |
| `RUSTMAP_METRICS_PORT` | Prometheus port | `9090` | `8080` |
| `RUSTMAP_RETRY_MAX` | Max retry attempts | `3` | `5` |
| `RUSTMAP_SHUTDOWN_TIMEOUT` | Graceful shutdown | `30` | `60` |

### Configuration File Support
Create `/etc/rustmap/config.toml` or `~/.config/rustmap/config.toml`:

```toml
[general]
threads = 8
shutdown_timeout = 60

[rate_limiting]
enabled = true
scanner_rate_limit = 100
external_tools_rate_limit = 10
exploit_queries_rate_limit = 5

[logging]
level = "info"
console = true
json = false
file_path = "/var/log/rustmap/rustmap.log"

[metrics]
enabled = true
prometheus_port = 9090
export_interval = 30

[retry]
max_retries = 5
base_delay = 1000
max_delay = 30000
backoff_multiplier = 2.0
```

## How It Works

### 1. **Target Resolution**
- Resolves hostname to IP addresses once and reuses socket addresses
- Validates input according to RFC 1123 standards
- Supports both IPv4 and IPv6 addresses

### 2. **Parallel TCP Scanning**
- Uses Rayon thread pool for optimal CPU utilization
- Performs parallel TCP connect attempts with configurable timeouts
- Implements rate limiting to prevent network overwhelm
- Progress reporting with live indicators

### 3. **Service Detection**
- Integrates with nmap for advanced service fingerprinting
- Performs protocol-specific probes and banner grabbing
- Extracts product names, versions, and service signatures
- Handles complex service combinations (e.g., HTTPS on port 80)

### 4. **Exploit Database Integration**
- Queries searchsploit for each unique product/version combination
- Implements intelligent search strategies (exact, fuzzy, service-only)
- Extracts CVSS scores and vulnerability classifications
- Deduplicates results and sorts by relevance

### 5. **Risk Assessment & Scoring**
- Calculates risk scores based on:
  - Number of available exploits
  - CVSS vulnerability scores
  - Service criticality multipliers
- Categorizes results: Critical, High, Medium, Low
- Provides detailed risk analysis with actionable insights

## Example Output

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

Exploit Analysis Results:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HIGH  Port 80 | http Apache httpd 2.4.7 | Risk: 65.4 | 15 exploits━━━━━━━━
  [9.8] 1 Apache HTTP Server 2.4.7 mod_rewrite Buffer Overflow
    apache/2.4.7/mod_rewrite.c
  [9.8] 2 Apache HTTP Server 2.4.7 mod_cgi Environment Variable RCE
    linux/remote/39773.txt
  [8.1] 3 Apache HTTP Server 2.4.7 mod_ssl Heartbeat Info Disclosure
    apache/2.4.7/mod_ssl/heartbeat.c
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Summary:
  → Total exploits found: 18
  → High-risk services: 1
  → Services analyzed: 3
```

### JSON Output
```json
[
  {
    "port": {
      "port": 80,
      "service": "http",
      "product": "Apache httpd",
      "version": "2.4.7"
    },
    "exploits": [
      {
        "title": "Apache HTTP Server 2.4.7 mod_rewrite Buffer Overflow",
        "url": "https://www.exploit-db.com/39773",
        "cvss": 9.8,
        "path": "apache/2.4.7/mod_rewrite.c"
      }
    ],
    "risk_score": 65.4
  }
]
```

## Troubleshooting

### Getting "command not found" errors?

**First, verify your installation:**
```bash
# Check if RustMap is installed
which rustmap

# If not found, run the installer again
./install.sh

# Or manually add to PATH
export PATH="$HOME/.cargo/bin:$PATH"
```

### Scan taking too long or timing out?

**Try these faster settings:**
```bash
# For fast networks
rustmap target.com -1k --scan-timeout 10

# For slow networks  
rustmap target.com -1k --scan-timeout 100
```

### No exploits found?

**Update the exploit database:**
```bash
# Update searchsploit
searchsploit --update

# Test with known vulnerable target
rustmap scanme.nmap.org -1k
```

### Permission errors?

**For system-wide installation:**
```bash
# Build locally instead
cargo build --release
./target/release/rustmap target.com -1k

# Or use sudo for system install
sudo ./install.sh
```

### Still having issues?

**Run the diagnostic script:**
```bash
#!/bin/bash
echo "Checking your setup..."

# Check all required tools
echo -n "Rust: " && rustc --version 2>/dev/null && echo "OK" || echo "Install Rust first"
echo -n "nmap: " && nmap --version 2>/dev/null | head -1 && echo "OK" || echo "Install nmap"
echo -n "searchsploit: " && searchsploit --help 2>/dev/null | head -1 && echo "OK" || echo "Install searchsploit"
echo -n "rustmap: " && rustmap --help 2>/dev/null | head -1 && echo "OK" || echo "Install rustmap"

# Test basic functionality
echo ""
echo "Testing basic functionality..."
if rustmap scanme.nmap.org -1k --json >/dev/null 2>&1; then
    echo "RustMap is working correctly!"
else
    echo "RustMap test failed - check the errors above"
fi
```

## Learning Path

### Beginner (Start Here)
```bash
# 1. Test with the official nmap test target
rustmap scanme.nmap.org -1k

# 2. Try your local network
rustmap 127.0.0.1 -1k

# 3. Scan a specific target
rustmap your-target.com -1k
```

### Intermediate
```bash
# Scan more ports
rustmap target.com -5k

# Get JSON output for analysis
rustmap target.com -5k --json

# Use faster timeouts
rustmap target.com -5k --scan-timeout 20
```

### Advanced
```bash
# Full port scan
rustmap target.com

# Custom thread count
rustmap target.com -10k --threads 8

# Batch processing
while read target; do
    rustmap "$target" -5k --json > "${target}_report.json"
done < targets.txt
```

## Pro Tips

### Target Selection
- **Public testing targets**: `scanme.nmap.org`, `testphp.vulnweb.com`
- **Your own systems**: Always scan only systems you own or have permission to test
- **Internal networks**: Use your internal IP ranges (192.168.x.x, 10.x.x.x)

### Performance Tips
- **Fast scanning**: Use `-1k` or `-5k` flags to limit port range
- **Slow networks**: Increase `--scan-timeout` to 100-200ms
- **Resource conservation**: Limit threads with `--threads 4`

### Security Best Practices
- **Rate limiting**: Always use in shared networks
- **Permission**: Only scan systems you own
- **Updates**: Keep `searchsploit --update` regular
- **Legal**: Ensure you have authorization before testing

## Common Questions

**Q: How long does a scan take?**
A: 
- 1k ports: 2-10 seconds
- 5k ports: 10-30 seconds  
- Full scan: 1-10 minutes

**Q: What does the risk score mean?**
A: 
- 0-15: Low risk
- 15-30: Medium risk
- 30-50: High risk
- 50+: Critical risk

**Q: Can I scan multiple targets?**
A: Yes! See the batch processing examples above.

**Q: How do I save results?**
A: Use `--json` and redirect to a file:
```bash
rustmap target.com -5k --json > results.json
```

**Q: Is it safe to run on production systems?**
A: Use conservative settings and test on a small port range first:
```bash
rustmap target.com -1k --scan-timeout 100
```

## What Next?

### Start Scanning
1. **Test Target**: `rustmap scanme.nmap.org -1k`
2. **Your Network**: `rustmap 192.168.1.1 -1k` 
3. **Save Results**: `rustmap target.com -5k --json > report.json`

### Learn More
- **Advanced Usage**: Check `rustmap --help` for all options
- **Batch Scanning**: Create target lists and scan automatically
- **Integration**: Use JSON output with other security tools

### Join the Community
- **Issues**: [Report bugs](https://github.com/3xecutablefile/RustMap/issues)
- **Discussions**: [Ask questions](https://github.com/3xecutablefile/RustMap/discussions)
- **Contributions**: [Help improve RustMap](https://github.com/3xecutablefile/RustMap/pulls)

## Need Help?

### Quick Self-Help
```bash
# Get help
rustmap --help

# Test your setup
rustmap scanme.nmap.org -1k

# Update exploits
searchsploit --update
```

### Common Solutions
- **"Command not found"**: Run `./install.sh` again
- **"No exploits found"**: Run `searchsploit --update`
- **"Too slow"**: Use `-1k` flag and `--scan-timeout 10`
- **"Permission denied"**: Use `sudo` or build locally

### Get Support
- **Email**: Create an issue on GitHub
- **Chat**: GitHub Discussions
- **Bugs**: GitHub Issues
- **Docs**: This README and code comments

## Show Your Support

If RustMap helps you, please:
- **Star** the repository
- **Report** issues you find
- **Suggest** improvements
- **Contribute** code or documentation

## Final Notes

**RustMap is a security tool** - use it responsibly and only on systems you own or have permission to test.

**Happy scanning!**

---

*Made with by [3xecutablefile](https://github.com/3xecutablefile)*

## Performance Tuning

### System Optimization
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize network parameters
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.core.netdev_max_backlog=5000
```

### Application Tuning
```bash
# Optimal thread count (match CPU cores)
export RUSTMAP_THREADS=$(nproc)

# Aggressive scanning for high-performance networks
export RUSTMAP_SCANNER_RATE_LIMIT=200
export RUSTMAP_EXTERNAL_TOOLS_RATE_LIMIT=10
export RUSTMAP_EXPLOIT_QUERIES_RATE_LIMIT=5

# Low timeouts for fast networks
export RUSTMAP_SCAN_TIMEOUT=10
export RUSTMAP_EXPLOIT_TIMEOUT=5000
```

### Performance Profiling
```bash
# Profile with perf (Linux)
sudo perf record -g rustmap target.com -5k
sudo perf report

# Monitor resource usage
htop -p $(pgrep rustmap)
iostat -x 1
```

## Security Considerations

### Input Validation
- All targets are validated according to RFC 1123
- Port ranges are checked for valid bounds
- Command inputs are sanitized to prevent injection
- Search queries are filtered for safety

### Network Safety
- Rate limiting prevents network overwhelm
- Configurable timeouts prevent hanging
- Conservative defaults for unknown networks
- Graceful handling of network errors

### Data Protection
- No sensitive data is logged
- Temporary files are cleaned up
- Process isolation for external tools
- Secure error messages without information leakage

### Best Practices
1. **Network Etiquette**: Always use rate limiting in shared networks
2. **Permission**: Only scan networks you own or have permission to test
3. **Updates**: Keep exploit database updated with `searchsploit --update`
4. **Logging**: Monitor logs for unusual activity
5. **Resource Limits**: Set appropriate timeouts and thread limits

## API Reference

### Core Modules
- **`config`** - Configuration management and command-line parsing
- **`scanner`** - High-performance TCP port scanning and service detection  
- **`exploit`** - Exploit database integration and risk assessment
- **`external`** - External tool abstractions (nmap, searchsploit)
- **`utils`** - Networking utilities and progress reporting
- **`validation`** - Input validation and sanitization
- **`error`** - Comprehensive error handling
- **`logging`** - Structured logging with multiple output formats
- **`metrics`** - Performance metrics and Prometheus export
- **`rate_limit`** - Token bucket rate limiting with configurable policies
- **`retry`** - Exponential backoff retry mechanisms

### Key Functions

#### Port Scanning
```rust
// High-performance parallel TCP scanning
pub async fn fast_scan(target_addrs: &[SocketAddr], config: &Config) -> Result<Vec<Port>>

// Advanced service detection with nmap integration
pub async fn detect_services(target: &str, ports: &[Port], config: &Config) -> Result<Vec<Port>>
```

#### Exploit Analysis
```rust
// Search and analyze exploits for detected services
pub async fn search_exploits(ports: &[Port], config: &Config) -> Result<Vec<PortResult>>

// Calculate risk scores based on CVSS and service criticality
impl RiskCalculator {
    pub fn calculate(exploits: &[Exploit], service: &str) -> f32
}
```

#### Configuration Management
```rust
// Parse command-line arguments with validation
impl Config {
    pub fn from_args(args: &[String]) -> Result<Config>
}
```

### Data Structures
```rust
// Port information with service details
pub struct Port {
    pub port: u16,
    pub service: String,
    pub product: String,
    pub version: String,
}

// Exploit information with metadata
pub struct Exploit {
    pub title: String,
    pub url: String,
    pub cvss: Option<f32>,
    pub path: String,
}

// Complete risk assessment result
pub struct PortResult {
    pub port: Port,
    pub exploits: Vec<Exploit>,
    pub risk_score: f32,
}

pub enum RiskLevel {
    Critical,  // Risk score >= 50
    High,      // Risk score >= 30  
    Medium,    // Risk score >= 15
    Low,       // Risk score < 15
}
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

### Development Setup
```bash
# Clone repository
git clone https://github.com/3xecutablefile/RustMap.git
cd RustMap

# Install development dependencies
cargo install cargo-watch cargo-audit cargo-tarpaulin

# Run tests
cargo test

# Run with live reloading
cargo watch -x run -- target.com -1k

# Check code coverage
cargo tarpaulin --out html
```

### Coding Standards
- Follow Rust standard formatting with `rustfmt`
- Use `cargo clippy` for linting
- Write comprehensive tests for new features
- Document public APIs with doc comments
- Follow semantic versioning for releases

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**3xecutablefile**
- GitHub: [@3xecutablefile](https://github.com/3xecutablefile)
- Project: [RustMap](https://github.com/3xecutablefile/RustMap)

## Acknowledgments

- **nmap** - Network exploration and security auditing
- **searchsploit** - Exploit database from Offensive Security  
- **Rayon** - Data parallelism in Rust
- **Tokio** - Asynchronous runtime for Rust
- **Rust Community** - For the excellent ecosystem

## Support

- **Documentation**: [Full documentation](https://docs.rs/rustmap)
- **Issues**: [GitHub Issues](https://github.com/3xecutablefile/RustMap/issues)


---

**Fast • Accurate • Secure • Comprehensive**

*Built for security professionals, by security professionals.*
