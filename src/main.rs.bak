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
use std::process::Command;

/// Update OxideScanner to the latest version
async fn update_oxscan() -> Result<()> {
    println!("{} Updating OxideScanner...", "UPDATE".bright_yellow());
    
    // Check if we're in a git repository
    let git_check = Command::new("git")
        .args(&["rev-parse", "--git-dir"])
        .output();
    
    match git_check {
        Ok(output) if output.status.success() => {
            // Verify that we're in the OxideScanner repository
            let remote_url_output = Command::new("git")
                .args(&["remote", "get-url", "origin"])
                .output()
                .map_err(|e| OxideScannerError::external_tool("git", format!("Failed to get remote URL: {}", e)))?;

            if !remote_url_output.status.success() {
                return Err(OxideScannerError::external_tool(
                    "git",
                    format!("Failed to get remote URL: {}", String::from_utf8_lossy(&remote_url_output.stderr))
                ));
            }

            let remote_url = String::from_utf8_lossy(&remote_url_output.stdout).trim().to_lowercase();
            let expected_urls = [
                "https://github.com/notsmartman/oxidescanner.git",
                "https://github.com/3xecutablefile/oxidescanner.git", 
                "git@github.com:notsmartman/oxidescanner.git",
                "git@github.com:3xecutablefile/oxidescanner.git"
            ];

            if !expected_urls.iter().any(|&url| remote_url.contains(&url.to_lowercase())) {
                return Err(OxideScannerError::external_tool(
                    "git",
                    format!("Current directory is not the OxideScanner repository. Remote URL: {}", remote_url)
                ));
            }

            println!("{} Git repository verified as OxideScanner, pulling latest changes...", "INFO".bright_cyan());

            // Pull latest changes
            let pull_output = Command::new("git")
                .args(&["pull", "origin", "main"])
                .output()
                .map_err(|e| OxideScannerError::external_tool("git", format!("Failed to run git pull: {}", e)))?;

            if !pull_output.status.success() {
                return Err(OxideScannerError::external_tool(
                    "git",
                    format!("Git pull failed: {}", String::from_utf8_lossy(&pull_output.stderr))
                ));
            }

            println!("{} Successfully pulled latest changes", "SUCCESS".bright_green());
        }
        _ => {
            println!("{} Not a git repository, cloning latest version...", "INFO".bright_cyan());
            
            // Clone the repository
            let clone_output = Command::new("git")
                .args(&[
                    "clone",
                    "https://github.com/NotSmartMan/OxideScanner.git",
                    "/tmp/OxideScanner-update"
                ])
                .output()
                .map_err(|e| OxideScannerError::external_tool("git", format!("Failed to clone repository: {}", e)))?;
            
            if !clone_output.status.success() {
                return Err(OxideScannerError::external_tool(
                    "git",
                    format!("Git clone failed: {}", String::from_utf8_lossy(&clone_output.stderr))
                ));
            }
            
            println!("{} Successfully cloned latest version to /tmp/OxideScanner-update", "SUCCESS".bright_green());
            println!("{} Please manually copy the updated files to your OxideScanner directory", "INFO".bright_cyan());
        }
    }
    
    // Update Rust dependencies
    println!("{} Updating Rust dependencies...", "INFO".bright_cyan());
    let cargo_update_output = Command::new("cargo")
        .arg("update")
        .output()
        .map_err(|e| OxideScannerError::external_tool("cargo", format!("Failed to run cargo update: {}", e)))?;
    
    if !cargo_update_output.status.success() {
        return Err(OxideScannerError::external_tool(
            "cargo",
            format!("Cargo update failed: {}", String::from_utf8_lossy(&cargo_update_output.stderr))
        ));
    }
    
    println!("{} Dependencies updated successfully", "SUCCESS".bright_green());
    
    // Rebuild the project
    println!("{} Rebuilding OxideScanner...", "INFO".bright_cyan());
    let cargo_build_output = Command::new("cargo")
        .args(&["build", "--release"])
        .output()
        .map_err(|e| OxideScannerError::external_tool("cargo", format!("Failed to build project: {}", e)))?;
    
    if !cargo_build_output.status.success() {
        return Err(OxideScannerError::external_tool(
            "cargo",
            format!("Build failed: {}", String::from_utf8_lossy(&cargo_build_output.stderr))
        ));
    }
    
    println!("{} OxideScanner updated and rebuilt successfully!", "SUCCESS".bright_green());
    println!("{} You can now use the updated version", "INFO".bright_cyan());
    
    Ok(())
}

/// Application entry point
#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        process::exit(0);
    }

    // Handle --update flag
    if args[1] == "--update" {
        if let Err(e) = update_oxscan().await {
            eprintln!("{} {}", "ERROR".red().bold(), e);
            process::exit(1);
        }
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
        "usage: oxscan <target> [port-options] [--json] [--scan-timeout MS] [--exploit-timeout MS] [--threads N|--threads:N] [--update]"
            .red()
            .bold()
    );
    eprintln!("Port Options:");
    eprintln!("  --ports:START-END  Scan port range (e.g., --ports:1000-30000)");
    eprintln!("  --ports N           Scan N ports from top (e.g., --ports 1000)");
    eprintln!("  (no flag)           Interactively choose port count");
    eprintln!("Other Options:");
    eprintln!("  --json              Output in JSON format");
    eprintln!("  --scan-timeout MS   TCP connection timeout in milliseconds (default: 25)");
    eprintln!("  --exploit-timeout MS Exploit search timeout in milliseconds (default: 10000)");
    eprintln!("  --threads N         Number of threads to use (default: all cores)");
    eprintln!("  --threads:N         Number of threads to use (default: all cores)");
    eprintln!("  --update            Update OxideScanner to latest version");
    eprintln!("Examples:");
    eprintln!("  oxscan scanme.nmap.org               # Interactively choose ports");
    eprintln!("  oxscan example.com --ports:1000-30000 --threads:6  # Scan range with 6 threads");
    eprintln!("  oxscan example.com --ports 1000     # Scan top 1000 ports");
    eprintln!("  oxscan 192.168.1.1 --json          # Output in JSON format");
    eprintln!("  oxscan --update                     # Update to latest version");
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
    let port_description = if let (Some(start), Some(end)) = (config.port_start, config.port_end) {
        format!("ports {}-{}", start, end)
    } else if config.port_limit == constants::ports::MAX {
        "all ports".to_string()
    } else {
        format!("top {} ports", config.port_limit)
    };

    println!(
        "{} Fast scanning {} on {}...",
        "FAST SCAN".bright_yellow(),
        port_description,
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
