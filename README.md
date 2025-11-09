# RustMap

Fast port scanner and exploit finder written in Rust with professional-grade output.

## Features

- **Fast TCP scanner** – scan the top 1k–30k ports or all 65,535 with a multithreaded engine
- **Lightweight service detection** – banner grabbing and protocol-specific probes inspired by nmap fingerprints
- **Exploit enrichment** – automatic `searchsploit` queries for each detected product/version pair
- **Risk scoring** – heuristic score based on exploit count, CVSS keywords, and service criticality
- **Rich terminal UX** – live progress bars, color-coded risk cards, and optional JSON output for automation
- **Professional output** – clean, enterprise-grade interface without distracting emojis

## Quick Installation

### Automatic Installation
```bash
git clone https://github.com/3xecutablefile/RustMap.git
cd RustMap
./install.sh
```

The installation script will:
- Install all dependencies (Rust, nmap, searchsploit)
- Build RustMap in release mode
- Install to system PATH (if possible)
- Update exploit database
- Verify installation

### Manual Installation
1. Install Rust: https://rustup.rs
2. Install system dependencies:
   - **Ubuntu/Debian**: `sudo apt-get install nmap ruby git`
   - **macOS**: `brew install nmap` (requires Homebrew)
   - **Arch**: `sudo pacman -S nmap ruby git`
3. Install searchsploit:
   ```bash
   git clone https://github.com/offensive-security/exploitdb.git /opt/searchsploit
   sudo ln -sf /opt/searchsploit/searchsploit /usr/local/bin/searchsploit
   searchsploit --update
   ```
4. Build and install:
   ```bash
   cargo build --release
   sudo cp target/release/rustmap /usr/local/bin/
   ```

## Requirements

- Rust 1.70 or newer
- `nmap` - Network scanning and service detection
- `searchsploit` - Exploit database search tool (from exploit-db)
- Ruby (for searchsploit)

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
- `--update` – update searchsploit database and sync repository

### Examples

```bash
# Quick scan
rustmap scanme.nmap.org

# Scan top 1000 ports
rustmap scanme.nmap.org -1k

# Custom timeouts and JSON output
rustmap target.local -10k --scan-timeout 50 --exploit-timeout 15000 --json

# Pipe JSON results into jq
rustmap target.local --json | jq '.[] | select(.risk_score > 30)'

# Scan with custom port limit and output to file
rustmap 192.168.1.100 -3k --json > scan_results.json

# JSON output for automation
rustmap scanme.nmap.org -5k --json | jq

# Update exploit database
rustmap --update
```

## How it works

1. **Target resolution** – resolve the hostname once and reuse every socket address
2. **Parallel TCP scan** – fire short-lived TCP connect attempts across a rayon thread pool
3. **Protocol fingerprinting** – run null reads and targeted probes to capture banners and detect services
4. **Exploit lookup** – query `searchsploit` for each unique product/version signature
5. **Risk aggregation** – score and sort results before presenting either JSON or rich terminal cards

## Example Output

```
INFO Fast scanning top 1000 ports on scanme.nmap.org...
[████████████████████████████████████████] 100% | 1000/1000 scanned | 2.1s
SUCCESS Found 3 open ports in 2.15s

INFO Open Ports:
  -> Port 22
  -> Port 80  
  -> Port 443

INFO Service Detection Results:
  -> Port 22: ssh OpenSSH 7.4
  -> Port 80: http Apache httpd 2.4.7
  -> Port 443: ssl Apache httpd 2.4.7

INFO Exploit Analysis Results:
Port 80 | http Apache httpd 2.4.7 | 282 exploits
...
INFO Summary:
  -> Total exploits found: 342
  -> Services analyzed: 3
```

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
