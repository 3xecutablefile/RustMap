# RustMap

RustMap is a fast banner-grabbing port scanner that enriches findings with exploit-db lookups.
It launches highly parallel TCP connect probes, fingerprints common services using a curated set
of nmap-style payloads, and then ranks any matching exploits by an opinionated risk score.

## Features

-  **Fast TCP scanner** – scan the top 1k–30k ports or all 65,535 with a multithreaded engine.
-  **Lightweight service detection** – banner grabbing and protocol-specific probes inspired by nmap fingerprints.
-  **Exploit enrichment** – automatic `searchsploit` queries for each detected product/version pair.
-  **Risk scoring** – heuristic score based on exploit count, CVSS keywords, and service criticality.
-  **Rich terminal UX** – live progress bars, color-coded risk cards, and optional JSON output for automation.

## Requirements

- Rust 1.70 or newer
- `nmap` - Network scanning and service detection
- `searchsploit` - Exploit database search tool (from exploit-db)

## Installation

### 1. Install Rust

```bash
# Install Rust using rustup (recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Or on macOS with Homebrew
brew install rust
```

### 2. Install External Dependencies

#### macOS (Homebrew)
```bash
brew install nmap
brew install exploitdb
```

#### Debian/Ubuntu
```bash
sudo apt update
sudo apt install nmap
# Install searchsploit from exploit-db
git clone https://github.com/offensive-security/exploitdb.git
sudo cp exploitdb/searchsploit /usr/local/bin/
sudo cp -r exploitdb/exploits /opt/
```

#### Arch Linux
```bash
sudo pacman -S nmap
# Install searchsploit from exploit-db
git clone https://github.com/offensive-security/exploitdb.git
sudo cp exploitdb/searchsploit /usr/local/bin/
sudo cp -r exploitdb/exploits /opt/
```

#### Fedora/CentOS/RHEL
```bash
sudo dnf install nmap
# Install searchsploit from exploit-db
git clone https://github.com/offensive-security/exploitdb.git
sudo cp exploitdb/searchsploit /usr/local/bin/
sudo cp -r exploitdb/exploits /opt/
```

### 3. Install RustMap

```bash
git clone https://github.com/NotSmartMan/RustMap.git
cd rustmap
cargo install --path .
```

### 4. Verify Installation

```bash
# Check if tools are available
which nmap searchsploit rustmap

# Test RustMap
rustmap --help
```

## Usage

### Basic Command Line

```bash
rustmap <target> [-1k|-2k|...|-30k] [--json] [--scan-timeout MS] [--exploit-timeout MS]
```

### Options

- `-Nk` – limit the scan to the first `N * 1000` TCP ports (e.g. `-5k` scans ports 1–5000). Without this flag, RustMap scans all 65,535 ports.
- `--json` – emit structured output instead of the interactive TUI.
- `--scan-timeout MS` – TCP connection timeout in milliseconds (default: 25).
- `--exploit-timeout MS` – Exploit search timeout in milliseconds (default: 10000).

### Examples

```bash
# Scan the default full port range
rustmap 192.168.1.10

# Scan the top 5000 ports only
rustmap example.com -5k

# Custom timeouts and JSON output
rustmap target.local -10k --scan-timeout 50 --exploit-timeout 15000 --json

# Pipe JSON results into jq
rustmap target.local --json | jq '.[] | select(.risk_score > 30)'

# Scan with custom port limit and output to file
rustmap 192.168.1.100 -3k --json > scan_results.json
```

## Library Usage

RustMap can also be used as a Rust library in your own projects:

### Add to Cargo.toml

```toml
[dependencies]
rustmap = { path = "/path/to/rustmap" }
tokio = { version = "1.0", features = ["full"] }
```

### Basic Example

```rust
use rustmap::config::Config;
use rustmap::scanner::{fast_scan, detect_services};
use rustmap::exploit::search_exploits;
use rustmap::utils::resolve_target;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration
    let config = Config::from_args(&[
        "rustmap".to_string(),
        "example.com".to_string(),
        "-5k".to_string(),
        "--json".to_string(),
    ])?;

    // Resolve target
    let addrs = resolve_target(&config.target)?;
    println!("Resolved {} addresses", addrs.len());

    // Scan for open ports
    let open_ports = fast_scan(&addrs, &config).await?;
    println!("Found {} open ports", open_ports.len());

    // Detect services
    let services = detect_services(&config.target, &open_ports, &config).await?;
    println!("Detected {} services", services.len());

    // Search for exploits
    let results = search_exploits(&services, &config).await?;
    println!("Found exploits for {} ports", results.len());

    // Print high-risk results
    for result in results {
        if result.is_high_risk() {
            println!("HIGH RISK: Port {} ({}) - Score: {:.1}", 
                     result.port.port, result.port.service, result.risk_score);
        }
    }

    Ok(())
}
```

### Advanced Example with Custom Configuration

```rust
use rustmap::config::Config;
use rustmap::scanner::{fast_scan, Port};
use rustmap::exploit::{PortResult, RiskCalculator};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create custom configuration
    let mut config = Config::from_args(&[
        "rustmap".to_string(),
        "127.0.0.1".to_string(),
        "-1k".to_string(),
    ])?;
    
    // Customize timeouts
    config.scan_timeout = Duration::from_millis(100);
    config.exploit_timeout = Duration::from_millis(20000);

    // Manual port scanning
    let addrs = resolve_target(&config.target)?;
    let open_ports = fast_scan(&addrs, &config).await?;

    // Manual service detection
    let services = detect_services(&config.target, &open_ports, &config).await?;

    // Manual risk calculation
    for port in &services {
        if !port.service.is_empty() {
            let risk_score = RiskCalculator::calculate(&[], &port.service);
            println!("Port {} ({}): Base risk score = {:.1}", 
                     port.port, port.service, risk_score);
        }
    }

    Ok(())
}
```

### JSON Output Processing

```rust
use rustmap::config::Config;
use rustmap::scanner::fast_scan;
use rustmap::exploit::search_exploits;
use rustmap::utils::resolve_target;
use serde_json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_args(&[
        "rustmap".to_string(),
        "example.com".to_string(),
        "-5k".to_string(),
        "--json".to_string(),
    ])?;

    let addrs = resolve_target(&config.target)?;
    let open_ports = fast_scan(&addrs, &config).await?;
    let services = detect_services(&config.target, &open_ports, &config).await?;
    let results = search_exploits(&services, &config).await?;

    // Output as JSON
    let json_output = serde_json::to_string_pretty(&results)?;
    println!("{}", json_output);

    Ok(())
}
```

## How it works

1. **Target resolution** – resolve the hostname once and reuse every socket address.
2. **Parallel TCP scan** – fire short-lived TCP connect attempts across a rayon thread pool.
3. **Protocol fingerprinting** – run null reads and targeted probes to capture banners and detect services.
4. **Exploit lookup** – query `searchsploit` for each unique product/version signature.
5. **Risk aggregation** – score and sort results before presenting either JSON or rich terminal cards.

## API Reference

### Core Modules

- **`config`** - Command-line parsing and configuration management
- **`scanner`** - High-performance TCP port scanning and service detection
- **`exploit`** - Exploit database integration and risk assessment
- **`external`** - External tool abstractions (nmap, searchsploit)
- **`utils`** - Utility functions for networking and progress reporting
- **`validation`** - Input validation and sanitization
- **`error`** - Comprehensive error handling

### Key Functions

#### Scanning
```rust
// Fast parallel TCP scanning
pub async fn fast_scan(target_addrs: &[SocketAddr], config: &Config) -> Result<Vec<Port>>

// Service detection with nmap
pub async fn detect_services(target: &str, ports: &[Port], config: &Config) -> Result<Vec<Port>>
```

#### Exploit Integration
```rust
// Search exploits for multiple ports
pub async fn search_exploits(ports: &[Port], config: &Config) -> Result<Vec<PortResult>>

// Calculate risk scores
impl RiskCalculator {
    pub fn calculate(exploits: &[Exploit], service: &str) -> f32
}
```

#### Configuration
```rust
// Parse command-line arguments
impl Config {
    pub fn from_args(args: &[String]) -> Result<Config>
}
```

### Data Structures

#### Port Information
```rust
pub struct Port {
    pub port: u16,
    pub service: String,
    pub product: String,
    pub version: String,
}
```

#### Exploit Information
```rust
pub struct Exploit {
    pub title: String,
    pub url: String,
    pub cvss: Option<f32>,
    pub path: String,
}
```

#### Risk Assessment
```rust
pub struct PortResult {
    pub port: Port,
    pub exploits: Vec<Exploit>,
    pub risk_score: f32,
}

pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}
```

## Performance Considerations

- **Parallel Scanning**: Uses Rayon thread pool for optimal CPU utilization
- **Timeout Management**: Configurable timeouts balance speed and accuracy
- **Memory Efficiency**: Streaming processing for large port ranges
- **Network Optimization**: Connection reuse and efficient socket handling

## Security Considerations

- **Input Validation**: All user inputs are validated and sanitized
- **Timeout Protection**: Prevents hanging on unresponsive services
- **Safe Command Execution**: External tool execution with proper escaping
- **Error Handling**: Comprehensive error handling prevents information leakage

## License

MIT

## Author

Made by: 3xecutablefile
