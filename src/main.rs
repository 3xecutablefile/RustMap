// oxscan - fast port scanner and exploit finder written in Rust
// made by: 3xecutablefile

mod config;
mod constants;
mod error;
mod exploit;
mod external;
mod logging;
mod metrics;
mod rate_limit;
mod retry;
mod scanner;
mod shutdown;
mod utils;
mod validation;

use colored::*;
use error::{OxideScannerError, Result};
use std::env;
use std::process;

/// Application entry point
#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        process::exit(0);
    }

    let config = match config::Config::from_args(&args) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{} {}", "ERROR".red().bold(), e);
            process::exit(1);
        }
    };

    if let Err(e) = run(config).await {
        eprintln!("{} {}", "✗".red().bold(), e);
        process::exit(1);
    }
}

/// Print usage information
fn print_usage() {
    eprintln!(
        "{}",
        "usage: oxscan <target> [port-options] [--json] [--scan-timeout MS] [--exploit-timeout MS] [--threads N]"
            .red()
            .bold()
    );
    eprintln!("Port Options:");
    eprintln!("  -Nk                 Scan N*1000 ports (e.g., -1k=1000, -5k=5000, -30k=30000)");
    eprintln!("  -N                  Scan N ports directly (e.g., -1000, -5000)");
    eprintln!("  --ports N           Scan N ports (e.g., --ports 1000)");
    eprintln!("  (no flag)           Scan top 1000 ports (most common)");
    eprintln!("Other Options:");
    eprintln!("  --json              Output in JSON format");
    eprintln!("  --scan-timeout MS   TCP connection timeout in milliseconds (default: 25)");
    eprintln!("  --exploit-timeout MS Exploit search timeout in milliseconds (default: 10000)");
    eprintln!("  --threads N         Number of threads to use (default: all cores)");
    eprintln!("Examples:");
    eprintln!("  oxscan 127.0.0.1                    # Scan top 1000 ports");
    eprintln!("  oxscan example.com -1k              # Scan top 1000 ports");
    eprintln!("  oxscan example.com -5k              # Scan top 5000 ports");
    eprintln!("  oxscan example.com -500             # Scan first 500 ports");
    eprintln!("  oxscan example.com --ports 1000     # Scan 1000 ports");
    eprintln!("  oxscan example.com -65535           # Scan all ports");
    eprintln!("  oxscan 192.168.1.1 --json          # Output in JSON format");
}

/// Main application logic
async fn run(config: config::Config) -> Result<()> {
    // Check dependencies
    crate::utils::check_dependencies()?;

    // Resolve target
    let target_addrs = utils::resolve_target(&config.target)?;

    if !config.json_mode {
        print_scan_start(&config);
    }

    // Scan ports
    let open_ports = scanner::fast_scan(&target_addrs, &config).await?;

    if open_ports.is_empty() {
        if !config.json_mode {
            println!("{} No open ports found", "WARNING".yellow());
        }
        return Ok(());
    }

    // Detect services
    let ports = scanner::detect_services(&config.target, &open_ports, &config).await?;

    if ports.is_empty() {
        if !config.json_mode {
            println!("{} No services detected", "WARNING".yellow());
        }
        return Ok(());
    }

    // Search exploits
    let results = exploit::search_exploits(&ports, &config).await?;

    // Output results
    output_results(&results, &ports, &config)?;

    Ok(())
}

/// Print scan start message
fn print_scan_start(config: &config::Config) {
    println!(
        "{} Fast scanning {} ports on {}...",
        "FAST SCAN".bright_yellow(),
        if config.port_limit == constants::ports::MAX {
            "all".to_string()
        } else {
            format!("top {}", config.port_limit)
        },
        config.target
    );
}

/// Output results in appropriate format
fn output_results(
    results: &[exploit::PortResult],
    ports: &[scanner::Port],
    config: &config::Config,
) -> Result<()> {
    if config.json_mode {
        let json_output = serde_json::to_string_pretty(results)
            .map_err(|e| OxideScannerError::parse(format!("Failed to serialize JSON: {}", e)))?;
        println!("{}", json_output);
    } else {
        exploit::print_results(results, ports);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_usage_doesnt_panic() {
        print_usage();
    }

    #[test]
    fn test_print_scan_start() {
        let config = config::Config::from_args(&[
            "oxscan".to_string(),
            "127.0.0.1".to_string(),
            "-5k".to_string(),
        ])
        .unwrap();

        print_scan_start(&config);
    }
}
