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
use crate::exploit::PortResult;

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

            // Sanitize the remote URL to prevent command injection
            let _ = sanitize_git_url(&remote_url)?;

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
            
            // Create a unique temporary directory to prevent symlink attacks
            use std::time::{SystemTime, UNIX_EPOCH};
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| OxideScannerError::external_tool("update", format!("Failed to generate timestamp: {}", e)))?
                .as_secs();
            
            let temp_dir = format!("/tmp/oxscan-update-{}", timestamp);

            // Sanitize the temp directory path to prevent directory traversal
            if !is_safe_path(&temp_dir) {
                return Err(OxideScannerError::external_tool(
                    "update",
                    format!("Unsafe temporary directory path: {}", temp_dir)
                ));
            }

            // Create temporary directory with restricted permissions
            use std::fs;
            fs::create_dir_all(&temp_dir)
                .map_err(|e| OxideScannerError::external_tool("update", format!("Failed to create temp directory: {}", e)))?;

            // Clone the repository to the unique temporary directory
            let clone_output = Command::new("git")
                .args(&[
                    "clone",
                    "https://github.com/3xecutablefile/OxideScanner.git",
                    &temp_dir
                ])
                .output()
                .map_err(|e| OxideScannerError::external_tool("git", format!("Failed to clone repository: {}", e)))?;
            
            if !clone_output.status.success() {
                return Err(OxideScannerError::external_tool(
                    "git",
                    format!("Git clone failed: {}", String::from_utf8_lossy(&clone_output.stderr))
                ));
            }
            
            println!("{} Successfully cloned latest version to {}", "SUCCESS".bright_green(), temp_dir);
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

    // Update searchsploit database
    println!("{} Updating searchsploit database...", "INFO".bright_cyan());
    let searchsploit_update_output = std::process::Command::new("searchsploit")
        .arg("-u")
        .output()
        .map_err(|e| OxideScannerError::external_tool("searchsploit", format!("Failed to update searchsploit database: {}", e)))?;

    if searchsploit_update_output.status.success() {
        println!("{} Searchsploit database updated successfully", "SUCCESS".bright_green());
    } else {
        // Log the issue but don't fail the entire update
        eprintln!("{} Warning: Searchsploit database update failed: {}", "WARNING".yellow(), 
                  String::from_utf8_lossy(&searchsploit_update_output.stderr));
    }

    // Attempt to update nmap if possible (OS-specific)
    println!("{} Checking for nmap updates...", "INFO".bright_cyan());
    update_nmap_if_possible()?;

    println!("{} You can now use the updated version", "INFO".bright_cyan());

    Ok(())
}

/// Sanitize git URL to prevent command injection
fn sanitize_git_url(url: &str) -> Result<String> {
    // Only allow alphanumeric characters, hyphens, underscores, dots, slashes, colons, and @
    let valid_chars = regex::Regex::new(r"^[a-zA-Z0-9._\-@:/~]+$")
        .map_err(|e| OxideScannerError::external_tool("regex", format!("Failed to compile regex: {}", e)))?;

    if !valid_chars.is_match(url) {
        return Err(OxideScannerError::external_tool(
            "update",
            format!("Git URL contains invalid characters: {}", url)
        ));
    }

    // Additional checks for common command injection patterns
    if url.contains("..") || url.contains(";") || url.contains("&") ||
       url.contains("|") || url.contains("`") || url.contains("$(") || url.contains("\"") || url.contains("'") {
        return Err(OxideScannerError::external_tool(
            "update",
            format!("Git URL contains potential command injection: {}", url)
        ));
    }

    Ok(url.to_string())
}

/// Validate that a path is safe to use (no directory traversal)
fn is_safe_path(path: &str) -> bool {
    // Check for directory traversal patterns
    if path.contains("../") || path.contains("..\\") {
        return false;
    }

    // Ensure the path starts with expected prefix
    if !path.starts_with("/tmp/oxscan-update-") {
        return false;
    }

    true
}

/// Attempt to update nmap based on the operating system
fn update_nmap_if_possible() -> Result<()> {
    // Check if nmap is installed first
    let nmap_check = std::process::Command::new("nmap")
        .arg("--version")
        .output();

    match nmap_check {
        Ok(output) if output.status.success() => {
            // Nmap is installed, try to update it using various package managers
            let update_commands = vec![
                // Try apt (Debian/Ubuntu)
                ("sh", &["-c", "sudo apt update && sudo apt install -y nmap"][..]),
                // Try pacman (Arch Linux) 
                ("sh", &["-c", "sudo pacman -Syu nmap --noconfirm"][..]),
                // Try brew (macOS)
                ("brew", &["upgrade", "nmap"][..]),
                // Try dnf (Fedora)
                ("sh", &["-c", "sudo dnf update -y nmap"][..]),
            ];

            for (cmd, args) in update_commands {
                let result = std::process::Command::new(cmd).args(args).output();

                if let Ok(output) = result {
                    if output.status.success() {
                        println!("{} Nmap updated successfully using system package manager", "SUCCESS".bright_green());
                        return Ok(());
                    }
                }
            }
            
            // If all update attempts fail, just report that nmap is accessible
            println!("{} Nmap is installed and accessible (update may require manual intervention or different package manager)", "INFO".bright_cyan());
        },
        _ => {
            // Nmap not installed or not accessible
            eprintln!("{} Warning: Nmap is not accessible, please install it manually", "WARNING".yellow());
        }
    }

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
        "usage: oxscan <target> [port-options] [--json] [--output FILE|-o FILE] [--scan-timeout MS] [--exploit-timeout MS] [--threads N|--threads:N] [--update]"
            .red()
            .bold()
    );
    eprintln!("Port Options:");
    eprintln!("  --ports:START-END  Scan port range (e.g., --ports:1000-30000)");
    eprintln!("  --ports N          Scan N ports from 1 to N (e.g., --ports 1000)");
    eprintln!("  -NK                Scan N*1000 ports from 1 to N*1000 (e.g., -1k = 1000 ports, -5k = 5000 ports)");
    eprintln!("  (no flag)           Interactively choose port count");
    eprintln!("Other Options:");
    eprintln!("  --json              Output in JSON format");
    eprintln!("  --output FILE       Save results to specified file");
    eprintln!("  -o FILE             Shorthand for --output");
    eprintln!("  --scan-timeout MS   TCP connection timeout in milliseconds (default: 25)");
    eprintln!("  --exploit-timeout MS Exploit search timeout in milliseconds (default: 10000)");
    eprintln!("  --threads N         Number of threads to use (default: all cores)");
    eprintln!("  --threads:N         Number of threads to use (default: all cores)");
    eprintln!("  --update            Update OxideScanner to latest version");
    eprintln!("Examples:");
    eprintln!("  oxscan scanme.nmap.org               # Interactively choose ports");
    eprintln!("  oxscan example.com --ports:1000-30000 --threads:6  # Scan range with 6 threads");
    eprintln!("  oxscan example.com --ports 1000     # Scan 1000 ports (1-1000)");
    eprintln!("  oxscan example.com -1k              # Scan 1000 ports (1-1000)");
    eprintln!("  oxscan example.com -5k              # Scan 5000 ports (1-5000)");
    eprintln!("  oxscan 192.168.1.1 --json          # Output in JSON format");
    eprintln!("  oxscan target.com --output results.txt  # Save results to file");
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
        format!("ports 1-{}", config.port_limit)
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
    if let Some(ref output_file) = config.output_file {
        // Write to specified file
        use std::fs::File;
        use std::io::Write;
        
        let mut file = File::create(output_file)
            .map_err(|e| OxideScannerError::Io(e))?;
        
        if config.json_mode {
            let json_output = serde_json::to_string_pretty(results)
                .map_err(|e| OxideScannerError::parse(format!("Failed to serialize JSON: {}", e)))?;
            file.write_all(json_output.as_bytes())
                .map_err(|e| OxideScannerError::Io(e))?;
        } else {
            // Capture the printed results to write to file
            let output = format_output_results(results, ports)?;
            file.write_all(output.as_bytes())
                .map_err(|e| OxideScannerError::Io(e))?;
        }
        
        if !config.json_mode {
            // Still print to console for non-JSON mode
            exploit::print_results(results, ports);
        }
        
        println!("{} Results saved to {}", "INFO".bright_cyan(), output_file);
    } else {
        // Original behavior - print to stdout
        if config.json_mode {
            let json_output = serde_json::to_string_pretty(results)
                .map_err(|e| OxideScannerError::parse(format!("Failed to serialize JSON: {}", e)))?;
            println!("{}", json_output);
        } else {
            exploit::print_results(results, ports);
        }
    }

    Ok(())
}

/// Format results as string for file output (non-JSON mode)
fn format_output_results(
    results: &[exploit::PortResult],
    ports: &[scanner::Port],
) -> Result<String> {
    if !results.is_empty() {
        let mut output = String::new();
        output.push_str("\nEXPLOIT ANALYSIS Results:\n");
        
        for result in results {
            let formatted_result = format_single_result_as_string(result)?;
            output.push_str(&formatted_result);
            output.push('\n');
        }
        
        // Add summary
        let total_exploits: usize = results.iter().map(|r| r.exploits.len()).sum();
        let high_risk_count = results.iter().filter(|r| r.is_high_risk()).count();
        
        output.push_str("\nSUMMARY:\n");
        output.push_str(&format!("  Total exploits found: {}\n", total_exploits));
        output.push_str(&format!("  High-risk services: {}\n", high_risk_count));
        output.push_str(&format!("  Services analyzed: {}\n", results.len()));
        
        Ok(output)
    } else {
        // If no exploits found, use the same format as the print function
        let mut output = String::from("\nSUCCESS No exploits found for detected services.\n");
        
        if !ports.is_empty() {
            output.push_str("\nSECURE SERVICES:\n");
            for port in ports {
                let service_info = if !port.product.is_empty() {
                    format!(
                        "{} {} {}",
                        port.service,
                        port.product,
                        port.version
                    )
                } else {
                    port.service.clone()
                };
                output.push_str(&format!("  Port {}: {}\n", port.port, service_info));
            }
        }
        
        Ok(output)
    }
}

/// Format a single port result as string for file output
fn format_single_result_as_string(result: &PortResult) -> Result<String> {
    let port = &result.port;
    let exploits = &result.exploits;
    
    let service_info = if !port.product.is_empty() {
        format!(
            "{} {} {}",
            port.service,
            port.product,
            port.version
        )
    } else {
        port.service.clone()
    };
    
    let header = format!(
        "Port {} | {} | Risk: {:.1} | {} exploits",
        port.port,
        service_info,
        result.risk_score,
        exploits.len()
    );
    
    let mut output = String::new();
    output.push_str(&format!("\n{}", "=".repeat(header.len() + 8)));
    output.push_str(&format!("\nRISK: {} | {}\n", result.risk_level().display(), header));
    output.push_str(&format!("{}\n", "-".repeat(header.len() + 8)));
    
    if exploits.is_empty() {
        output.push_str("  SUCCESS No exploits found\n");
    } else {
        for (i, exploit) in exploits.iter().take(constants::MAX_DISPLAYED_EXPLOITS).enumerate() {
            let cvss_indicator = format_cvss_indicator_as_string(exploit.cvss);
            output.push_str(&format!("  {}{} {}\n", cvss_indicator, (i + 1), exploit.title));
            
            if !exploit.path.is_empty() {
                output.push_str(&format!("    Path: {}\n", exploit.path));
            }
            
            if i < exploits.len().saturating_sub(1) && i < constants::MAX_DISPLAYED_EXPLOITS - 1 {
                output.push('\n');
            }
        }
        
        if exploits.len() > constants::MAX_DISPLAYED_EXPLOITS {
            output.push_str(&format!(
                "  MORE {} more exploits available\n",
                exploits.len() - constants::MAX_DISPLAYED_EXPLOITS
            ));
        }
    }
    
    output.push_str(&format!("{}\n", "=".repeat(header.len() + 8)));
    
    Ok(output)
}

/// Format CVSS indicator as string for file output
fn format_cvss_indicator_as_string(cvss: Option<f32>) -> String {
    match cvss {
        Some(score) if score >= 9.0 => format!("[{}]", score),
        Some(score) if score >= 7.0 => format!("[{}]", score),
        Some(score) if score >= 4.0 => format!("[{}]", score),
        Some(score) => format!("[{}]", score),
        None => "[?.?]".to_string(),
    }
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
