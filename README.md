# OxideScanner - Fast Port Scanner & Exploit Finder

<div align="center">

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-tool-red.svg)](https://github.com/NotSmartMan/OxideScanner)
[![Performance](https://img.shields.io/badge/performance-high-green.svg)]()

**High-performance network reconnaissance tool written in Rust**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Examples](#examples) • [API](#api-documentation)

</div>

---

## Overview

OxideScanner is a cutting-edge network security tool that combines lightning-fast port scanning with intelligent exploit discovery. Built in Rust for maximum performance and reliability, it provides security researchers and penetration testers with a comprehensive reconnaissance solution.

### Key Capabilities

- **Ultra-Fast Scanning**: Parallel TCP port scanning with configurable thread pools
- **Service Detection**: Advanced service fingerprinting using nmap integration
- **Exploit Discovery**: Automatic exploit database queries via searchsploit
- **Risk Assessment**: CVSS-based vulnerability scoring with service-specific multipliers
- **Performance**: Optimized for scanning large networks efficiently
- **Multiple Output**: Rich terminal UI and JSON export for integration

---

## Features

### Core Functionality
- **High-Speed Port Scanning**: Parallel TCP connect scanning using Rayon
- **Service Detection**: Banner grabbing and protocol fingerprinting
- **Exploit Database Integration**: Automatic searchsploit queries
- **Risk Scoring**: Sophisticated algorithm based on CVSS and service criticality
- **Multiple Output Formats**: Interactive terminal UI and JSON export

### Advanced Features
- **Rate Limiting**: Configurable rate limiting to avoid detection
- **Progress Reporting**: Real-time scan progress with visual feedback
- **Environment Configuration**: Full support for environment variables
- **Comprehensive Logging**: Structured logging with multiple levels
- **Graceful Shutdown**: Proper cleanup and timeout handling
- **Error Recovery**: Robust error handling and retry mechanisms

### Security & Performance
- **Input Validation**: Comprehensive target and parameter validation
- **Resource Management**: Efficient memory usage and cleanup
- **Concurrent Processing**: Multi-threaded scanning for maximum performance
- **Timeout Management**: Configurable timeouts for all operations
- **Dependency Checking**: Automatic verification of external tools

---

## Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/NotSmartMan/OxideScanner.git
cd OxideScanner

# Run the automated installation script
chmod +x install.sh
./install.sh
```

The installation script will:
- Detect your operating system
- Install Rust toolchain (if not present)
- Install required system packages (nmap, searchsploit)
- Build OxideScanner with optimizations
- Install to system PATH
- Update exploit database
- Verify installation

### Manual Installation

#### Prerequisites

- **Rust** (1.70+)
- **nmap** (for service detection)
- **searchsploit** (for exploit database)
- **Ruby** (for searchsploit)

#### System-Specific Setup

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nmap ruby git
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install nmap ruby git
# or
sudo dnf install nmap ruby git
```

**macOS:**
```bash
brew install nmap ruby git
```

**Searchsploit Installation:**
```bash
# Clone and install searchsploit
git clone https://github.com/offensive-security/exploitdb.git /opt/searchsploit
sudo ln -sf /opt/searchsploit/searchsploit /usr/local/bin/searchsploit

# Update database
searchsploit --update
```

#### Build from Source

```bash
# Clone repository
git clone https://github.com/NotSmartMan/OxideScanner.git
cd OxideScanner

# Build release version
cargo build --release

# Install to system (optional)
sudo cp target/release/oxscan /usr/local/bin/
sudo chmod +x /usr/local/bin/oxscan
```

---

## Usage

### Basic Syntax

```bash
oxscan <target> [port-options] [other-options]
```

### Port Options

| Option | Description | Example |
|--------|-------------|---------|
| `-Nk` | Scan N*1000 ports | `-1k` = 1000 ports, `-5k` = 5000 ports |
| `-N` | Scan N ports directly | `-1000` = first 1000 ports |
| `--ports N` | Scan N specific ports | `--ports 1000` |
| *(no flag)* | Scan top 1000 ports (default) | `oxscan target.com` |

### Other Options

| Option | Description | Default |
|--------|-------------|---------|
| `--json` | Output in JSON format | false |
| `--scan-timeout MS` | TCP connection timeout (ms) | 25ms |
| `--exploit-timeout MS` | Exploit search timeout (ms) | 10000ms |
| `--threads N` | Number of worker threads | all cores |
| `--no-rate-limit` | Disable rate limiting | false |

### Environment Variables

Configure OxideScanner using environment variables:

```bash
export RUSTMAP_THREADS=8                    # Worker threads
export RUSTMAP_SCAN_TIMEOUT=50              # Scan timeout in ms
export RUSTMAP_SHUTDOWN_TIMEOUT=60          # Shutdown timeout in seconds
export RUSTMAP_ENABLE_RATE_LIMIT=true       # Enable rate limiting
export RUSTMAP_SCANNER_RATE_LIMIT=100       # Scanner requests per second
export RUSTMAP_EXPLOIT_QUERIES_RATE_LIMIT=5 # Exploit queries per second
export RUSTMAP_LOG_LEVEL=info               # Log level (trace, debug, info, warn, error)
export RUSTMAP_METRICS_PORT=8080            # Metrics server port
```

---

## Examples

### Basic Scanning

```bash
# Scan top 1000 ports (default)
oxscan scanme.nmap.org

# Scan specific number of ports
oxscan target.com -1k              # First 1000 ports
oxscan target.com -5k              # First 5000 ports
oxscan target.com -65535           # All 65535 ports
oxscan target.com --ports 1000     # Exactly 1000 ports
```

### Advanced Scanning

```bash
# JSON output for automation
oxscan target.com -5k --json

# Custom timeouts for slow networks
oxscan target.com -10k --scan-timeout 50 --exploit-timeout 15000

# Multi-threaded scanning
oxscan target.com -10k --threads 16

# Enterprise scanning with rate limiting
oxscan target.com -30k --threads 32
```

### Real-World Scenarios

```bash
# Web Application Assessment
oxscan example.com -10k --threads 8

# Internal Network Discovery
oxscan 192.168.1.0/24 -1k --json | jq

# Cloud Environment Reconnaissance
oxscan api.example.com -5k --scan-timeout 25 --exploit-timeout 5000

# Vulnerability Assessment
oxscan target.com -20k --threads 16 --json > scan_results.json
```

### Integration Examples

```bash
# Pipeline with other tools
oxscan target.com -10k --json | jq -r '.[] | select(.risk_score > 50) | .port'

# Automated reporting
oxscan target.com -20k --json | python3 process_results.py

# Import into security platforms
oxscan target.com -15k --json > results.json
```

---

## Understanding Results

### Risk Levels

| Level | Score Range | Color | Description |
|-------|-------------|-------|-------------|
| **CRITICAL** | 50+ | Red | Severe vulnerabilities with high exploitability |
| **HIGH** | 30-49 | Orange | Significant security risks requiring attention |
| **MEDIUM** | 15-29 | Yellow | Moderate risks that should be addressed |
| **LOW** | <15 | Green | Minor security concerns |

### Service Risk Multipliers

Different services have different risk multipliers applied:

- **SMB/NetBIOS**: 1.8x (File sharing, high attack surface)
- **Databases**: 1.6x (Data exposure risk)
- **Remote Access**: 1.5x (SSH, Telnet, FTP)
- **Web Services**: 1.3x (HTTP/HTTPS)
- **Others**: 1.0x (Default multiplier)

### CVSS Score Mapping

OxideScanner automatically assigns CVSS scores to exploits based on vulnerability types:

- **Remote Code Execution**: 9.8-10.0
- **Authentication Bypass**: 9.8
- **SQL Injection**: 8.1-8.9
- **Buffer Overflows**: 8.5-9.3
- **XSS**: 6.1-7.5
- **Information Disclosure**: 4.3-5.5
- **DoS**: 5.3

---

## API Documentation

### Library Usage

```rust
use oxscan::{Config, scanner, exploit, utils};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration
    let config = Config::from_args(&[
        "oxscan".to_string(),
        "target.com".to_string(),
        "-5k".to_string(),
    ])?;
    
    // Resolve target addresses
    let target_addrs = utils::resolve_target(&config.target)?;
    
    // Perform port scan
    let open_ports = scanner::fast_scan(&target_addrs, &config).await?;
    println!("Found {} open ports", open_ports.len());
    
    // Detect services
    let services = scanner::detect_services(&config.target, &open_ports, &config).await?;
    
    // Search for exploits
    let results = exploit::search_exploits(&services, &config).await?;
    
    // Process results
    for result in results {
        println!("Port {}: Risk Score {:.1}", result.port.port, result.risk_score);
    }
    
    Ok(())
}
```

### Configuration Options

```rust
pub struct Config {
    pub target: String,                    // Target hostname/IP
    pub json_mode: bool,                   // JSON output mode
    pub port_limit: u16,                   // Port scan limit
    pub scan_timeout: Duration,            // TCP timeout
    pub exploit_timeout: Duration,         // Exploit search timeout
    pub threads: usize,                    // Worker threads
    pub enable_rate_limiting: bool,        // Rate limiting
    pub scanner_rate_limit: RateLimitPolicy, // Rate limit config
    pub logging: LogConfig,                // Logging configuration
    pub metrics: MetricsConfig,            // Metrics configuration
    pub retry: RetryConfig,                // Retry configuration
}
```

### Data Structures

```rust
// Port information
pub struct Port {
    pub port: u16,
    pub service: String,      // Service name
    pub product: String,      // Product name
    pub version: String,      // Version string
}

// Exploit information
pub struct Exploit {
    pub title: String,        // Exploit title
    pub url: String,          // Exploit-DB URL
    pub cvss: Option<f32>,    // CVSS score
    pub path: String,         // Local path
}

// Results with risk assessment
pub struct PortResult {
    pub port: Port,                   // Port information
    pub exploits: Vec<Exploit>,       // Found exploits
    pub risk_score: f32,              // Calculated risk score
}
```

---

## Security Considerations

### Legal & Ethical Use

**IMPORTANT**: This tool is intended for authorized security testing only.

- **Authorized Testing**: Only use on systems you own or have explicit permission to test
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Professional Use**: Use responsibly in professional security assessments
- **Rate Limiting**: Respect target systems with appropriate rate limiting

### Best Practices

```bash
# Use rate limiting to avoid detection
oxscan target.com -10k --threads 4

# Respect timeouts for slow networks
oxscan target.com -5k --scan-timeout 100

# Use appropriate thread counts
oxscan target.com -20k --threads 8  # Don't overwhelm target
```

### Network Impact

- **Thread Management**: Use appropriate thread counts to avoid network saturation
- **Timeout Configuration**: Adjust timeouts based on network conditions
- **Rate Limiting**: Enable rate limiting for stealthy scanning
- **Resource Usage**: Monitor system resources during large scans

---

## Technical Details

### Architecture

OxideScanner follows a modular architecture:

- **scanner**: High-performance parallel port scanning
- **exploit**: Exploit database integration and risk assessment
- **config**: Configuration management and validation
- **utils**: Networking utilities and helper functions
- **external**: Abstractions for external tools (nmap, searchsploit)
- **validation**: Input validation and sanitization
- **error**: Comprehensive error handling

### Performance Optimizations

- **Parallel Scanning**: Uses Rayon for thread pool management
- **Async I/O**: Async/await for non-blocking operations
- **Memory Efficiency**: Minimizes memory allocation during scanning
- **Connection Pooling**: Efficient TCP connection management
- **Progress Tracking**: Non-intrusive progress reporting

### Risk Scoring Algorithm

The risk scoring algorithm considers:

1. **Exploit Count** (0-20 points): Number of available exploits
2. **CVSS Scores** (Variable): Severity of vulnerabilities
3. **Service Multiplier** (1.0-1.8): Service-specific risk factors
4. **Total Score**: Combined weighted score

```
risk_score = (exploit_count * 2 + sum(cvss_scores)) * service_multiplier
```

---

## Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/OxideScanner.git
cd OxideScanner

# Install development dependencies
cargo install cargo-watch  # For auto-rebuilding
cargo install cargo-audit  # For security auditing

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run scanme.nmap.org -1k
```

### Code Standards

- Follow Rust standard formatting (`cargo fmt`)
- Use meaningful commit messages
- Add documentation for new features
- Include tests for new functionality
- Run security audit (`cargo audit`)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **nmap** - Network exploration and security auditing
- **searchsploit** - Exploit database
- **Rayon** - Data parallelism in Rust
- **Tokio** - Asynchronous runtime
- **Rust Community** - For the excellent ecosystem

---

## Support

- **Issues**: [GitHub Issues](https://github.com/NotSmartMan/OxideScanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/NotSmartMan/OxideScanner/discussions)
- **Security**: Report security issues privately via email
- **Documentation**: [Full Documentation](https://docs.rs/oxscan)

---

## Changelog

### v1.0.0
- Initial release
- Parallel port scanning with Rayon
- Service detection via nmap integration
- Exploit database queries via searchsploit
- Risk assessment with CVSS scoring
- Multiple output formats (terminal/JSON)
- Comprehensive configuration options
- Rate limiting and performance optimization

---

<div align="center">

**Made by [3xecutablefile](https://github.com/NotSmartMan)**

[![Stars](https://img.shields.io/github/stars/NotSmartMan/OxideScanner?style=social)](https://github.com/NotSmartMan/OxideScanner)
[![Forks](https://img.shields.io/github/forks/NotSmartMan/OxideScanner?style=social)](https://github.com/NotSmartMan/OxideScanner)

**Happy Hacking!**

</div>