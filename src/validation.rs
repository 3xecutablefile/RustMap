//! # Input Validation and Sanitization
//!
//! This module provides comprehensive input validation and sanitization functions
//! to ensure security and reliability of user inputs. It validates targets,
//! port ranges, timeouts, and other configuration parameters.
//!
//! ## Features
//!
//! - Hostname and IP address validation
//! - Port range and limit validation
//! - Timeout value validation
//! - Command input sanitization
//! - Search query validation
//! - Regular expression-based validation patterns
//!
//! ## Example
//!
//! ```rust
//! use oxidescanner::validation::{validate_target, validate_port_limit, sanitize_command_input};
//!
//! // Validate targets
//! assert!(validate_target("example.com").is_ok());
//! assert!(validate_target("127.0.0.1").is_ok());
//! assert!(validate_target("invalid..hostname").is_err());
//!
//! // Validate port limits
//! assert!(validate_port_limit(1000).is_ok());
//! assert!(validate_port_limit(0).is_err());
//!
//! // Sanitize command input
//! let safe = sanitize_command_input("test;rm -rf")?;
//! assert_eq!(safe, "testrm -rf");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::constants;
use crate::error::{OxideScannerError, Result};
use regex::Regex;
use std::net::IpAddr;

lazy_static::lazy_static! {
    /// Regular expression for hostname validation according to RFC 1123
    static ref HOSTNAME_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    ).unwrap();

    /// Regular expression for safe command input validation
    static ref SAFE_COMMAND_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_\-\.]+$").unwrap();
}

/// Validates and sanitizes a target (hostname or IP address)
///
/// This function validates that a target string is either a valid IP address
/// or a valid hostname according to RFC 1123 standards. It returns the
/// original string if valid, or an error if invalid.
pub fn validate_target(target: &str) -> Result<String> {
    if target.is_empty() {
        return Err(OxideScannerError::validation("Target cannot be empty"));
    }

    if target.len() > constants::validation::MAX_TARGET_LENGTH {
        return Err(OxideScannerError::validation("Target too long"));
    }

    // Check if it's a valid IP address
    if target.parse::<IpAddr>().is_ok() {
        return Ok(target.to_string());
    }

    // Check if it's a valid hostname
    if !HOSTNAME_REGEX.is_match(target) {
        return Err(OxideScannerError::validation(
            "Invalid hostname or IP address",
        ));
    }

    Ok(target.to_string())
}

/// Validates port limit value
pub fn validate_port_limit(limit: u16) -> Result<u16> {
    if limit == 0 {
        return Err(OxideScannerError::validation(
            "Port limit must be greater than 0",
        ));
    }

    // Since MAX is the maximum value for u16, no upper bound check needed
    // This validation is kept for future type changes or different limits
    #[allow(clippy::absurd_extreme_comparisons)]
    if limit > constants::ports::MAX {
        return Err(OxideScannerError::validation(format!(
            "Port limit cannot exceed {}",
            constants::ports::MAX
        )));
    }

    Ok(limit)
}

/// Validates timeout values
pub fn validate_timeout_ms(timeout_ms: u64) -> Result<u64> {
    if timeout_ms == 0 {
        return Err(OxideScannerError::validation(
            "Timeout must be greater than 0",
        ));
    }

    if timeout_ms > 300_000 {
        return Err(OxideScannerError::validation(
            "Timeout cannot exceed 5 minutes",
        ));
    }

    Ok(timeout_ms)
}

/// Sanitizes input for safe command execution
pub fn sanitize_command_input(input: &str) -> Result<String> {
    if input.is_empty() {
        return Err(OxideScannerError::validation(
            "Command input cannot be empty",
        ));
    }

    // Remove potentially dangerous characters
    let sanitized = input
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.' || *c == ' ')
        .collect::<String>()
        .trim()
        .to_string();

    if sanitized.is_empty() {
        return Err(OxideScannerError::validation("Invalid command input"));
    }

    Ok(sanitized)
}

/// Validates port list format for nmap
pub fn validate_port_list(port_list: &str) -> Result<String> {
    if port_list.is_empty() {
        return Err(OxideScannerError::validation("Port list cannot be empty"));
    }

    // Check for valid port ranges and individual ports
    for part in port_list.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            // Port range
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(OxideScannerError::validation("Invalid port range format"));
            }

            let start: u16 = range_parts[0]
                .parse()
                .map_err(|_| OxideScannerError::validation("Invalid port number"))?;
            let end: u16 = range_parts[1]
                .parse()
                .map_err(|_| OxideScannerError::validation("Invalid port number"))?;

            if start > end {
                return Err(OxideScannerError::validation(
                    "Invalid port range: start > end",
                ));
            }
        } else {
            // Single port
            let _: u16 = part
                .parse()
                .map_err(|_| OxideScannerError::validation("Invalid port number"))?;
        }
    }

    Ok(port_list.to_string())
}

/// Validates search query for exploit database
pub fn validate_search_query(query: &str) -> Result<String> {
    if query.is_empty() {
        return Err(OxideScannerError::validation(
            "Search query cannot be empty",
        ));
    }

    if query.len() > 200 {
        return Err(OxideScannerError::validation("Search query too long"));
    }

    // Remove potentially dangerous characters for shell commands
    let sanitized = sanitize_command_input(query)?;

    Ok(sanitized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_target() {
        assert!(validate_target("127.0.0.1").is_ok());
        assert!(validate_target("example.com").is_ok());
        assert!(validate_target("").is_err());
        assert!(validate_target("invalid..hostname").is_err());
    }

    #[test]
    fn test_validate_port_limit() {
        assert!(validate_port_limit(1000).is_ok());
        assert!(validate_port_limit(65535).is_ok());
        assert!(validate_port_limit(0).is_err());
        assert!(validate_port_limit(u16::MAX).is_ok());
    }

    #[test]
    fn test_sanitize_command_input() {
        assert_eq!(sanitize_command_input("test123").unwrap(), "test123");
        assert_eq!(sanitize_command_input("test-123").unwrap(), "test-123");
        assert_eq!(sanitize_command_input("test;rm -rf").unwrap(), "testrm -rf");
        assert!(sanitize_command_input("").is_err());
    }
}
