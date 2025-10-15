# Rustmap

A fast port scanner and exploit finder written in Rust.

## Features

- **Fast port scanning** - Scans all 65535 ports with parallel processing
- **Service detection** - Uses nmap for accurate service identification  
- **Exploit searching** - Automatically searches for exploits using searchsploit
- **Risk scoring** - Calculates risk scores based on CVSS and exploit count
- **Beautiful output** - Colorized terminal output with progress bars
- **JSON support** - Export results in JSON format

## Installation

### From Source
```bash
git clone 
cd rustmap-project
cargo install --path .
```

### Requirements
- `nmap` - For service detection
- `searchsploit` - For exploit database searching
- Rust 1.70+

## Usage

```bash
rustmap <target> [options]
```

### Options
- `--nmap-only` - Use only nmap scanning (skip fast scan)
- `--json` - Output results in JSON format

### Examples

```bash
# Basic scan
rustmap 192.168.1.1

# Scan with nmap only
rustmap 192.168.1.1 --nmap-only

# Get JSON output
rustmap 192.168.1.1 --json

# Scan a domain
rustmap example.com
```

## How it works

1. **Fast Port Scan** - Quickly scans all 65535 ports using parallel TCP connections
2. **Service Detection** - Runs nmap on discovered open ports for service identification
3. **Exploit Search** - Searches exploit-db for known vulnerabilities
4. **Risk Assessment** - Calculates risk scores based on CVSS ratings and exploit count
5. **Results Display** - Shows findings with color-coded risk levels

## License

MIT

## Author

Made by: 3xecutable
# RustMap
