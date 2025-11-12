//! # Utility Functions
//!
//! This module provides various utility functions for networking, progress reporting,
//! and system operations. It includes functions for target resolution, dependency
//! checking, and user interface utilities.
//!
//! ## Features
//!
//! - Target hostname and IP resolution
//! - External tool dependency checking
//! - Progress bar generation for terminal output
//! - Port list generation for scanning
//! - Binary path detection in system PATH
//!
//! ## Example
//!
//! ```rust
//! use oxidescanner::utils::{resolve_target, get_port_list, progress_bar};
//!
//! // Resolve a target
//! let addrs = resolve_target("example.com")?;
//! println!("Resolved {} addresses", addrs.len());
//!
//! // Generate port list
//! let ports = get_port_list(1000);
//! println!("Scanning {} ports", ports.len());
//!
//! // Create progress bar
//! let bar = progress_bar(50, 40);
//! println!("Progress: {}", bar);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::constants;
use crate::error::{OxideScannerError, Result};
use crate::validation;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::Command;

/// Check if required external tools are available
///
/// This function verifies that all required external tools (nmap, searchsploit)
/// are installed and available in system PATH. Returns an error if any
/// required tools are missing.
pub fn check_dependencies() -> Result<()> {
    let required_tools = vec![
        ("searchsploit", "Exploit database search tool"),
        ("nmap", "Network scanning and service detection"),
    ];

    let mut missing = Vec::new();

    for (tool, description) in required_tools {
        if !check_binary_in_path(tool) {
            missing.push(format!("{} ({})", tool, description));
        }
    }

    if !missing.is_empty() {
        return Err(OxideScannerError::external_tool(
            "dependency_check",
            format!(
                "Missing required tools:\n  {}\n\nInstall with:\n  sudo apt install nmap  # Debian/Ubuntu\n  sudo pacman -S nmap  # Arch\n  brew install nmap  # macOS\n\n  # Install searchsploit from exploit-db:\n  git clone https://github.com/offensive-security/exploitdb.git\n  sudo cp exploitdb/searchsploit /usr/local/bin/\n  sudo cp -r exploitdb/exploits /opt/",
                missing.join("\n  ")
            )
        ));
    }

    Ok(())
}

/// Check if a binary exists in the system PATH
pub fn check_binary_in_path(bin: &str) -> bool {
    match Command::new("which").arg(bin).output() {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// Resolve target hostname or IP to socket addresses
pub fn resolve_target(target: &str) -> Result<Vec<SocketAddr>> {
    // Validate target first with enhanced validation for external tools
    let validated_target = validation::validate_target_for_external_tools(target)?;

    let base = format!("{}:0", validated_target);
    match base.to_socket_addrs() {
        Ok(iter) => {
            let addrs: Vec<SocketAddr> = iter.collect();
            if addrs.is_empty() {
                Err(OxideScannerError::network_error("target resolution", format!("could not resolve target: {}", target)))
            } else {
                Ok(addrs)
            }
        }
        Err(e) => Err(OxideScannerError::network_error("target resolution", format!("resolve error: {}", e))),
    }
}



/// Generate a list of ports to scan based on configuration
pub fn get_port_list_from_config(config: &crate::config::Config) -> Vec<u16> {
    // If we have a port range, use it
    if let (Some(start), Some(end)) = (config.port_start, config.port_end) {
        return (start..=end).collect();
    }
    
    // Otherwise, use the legacy port_limit
    let validated_limit = validation::validate_port_limit(config.port_limit).unwrap_or(config.port_limit);

    if validated_limit == constants::ports::MAX {
        (constants::ports::MIN..=constants::ports::MAX).collect()
    } else {
        (constants::ports::MIN..=validated_limit).collect()
    }
}

/// Create a progress bar string
pub fn progress_bar(percent: usize, width: usize) -> String {
    let filled = (percent * width) / 100;
    let mut bar = String::with_capacity(width);

    for i in 0..width {
        if i < filled {
            bar.push('█');
        } else {
            bar.push('░');
        }
    }

    bar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_bar() {
        let bar = progress_bar(50, 40);
        let filled_count = bar.chars().filter(|&c| c == '█').count();
        let empty_count = bar.chars().filter(|&c| c == '░').count();
        assert_eq!(filled_count, 20);
        assert_eq!(empty_count, 20);
        assert_eq!(filled_count + empty_count, 40);
    }
}
