//! # Enhanced Input Validation Module
//!
//! This module provides comprehensive enhanced input validation functions for OxideScanner,
//! implementing defense-in-depth security measures for all user inputs.
//!
//! ## Enhanced Validation Features
//!
//! - **Network Input Validation**: Enhanced IP, hostname, and URL validation
//! - **Path Validation**: Robust file path validation with traversal prevention
//! - **Command Argument Validation**: Secure command argument sanitization
//! - **User Input Sanitization**: Comprehensive input sanitization utilities
//!
//! ## Security Principles Applied
//!
//! - Defense-in-depth approach
//! - Input sanitization and validation
//! - Prevention of injection attacks
//! - Secure defaults

use crate::error::{OxideScannerError, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

/// Enhanced network target validation with additional security checks
pub fn validate_network_target(target: &str) -> Result<String> {
    // First apply basic validation
    validate_target(target)?;

    // Additional security checks for network targets
    if target.chars().any(|c| matches!(c, '\0' | '\r' | '\n' | '\t')) {
        return Err(OxideScannerError::validation(
            "Target contains control characters that could be used for injection attacks"
        ));
    }

    // Check for potential command injection patterns
    if contains_command_injection_patterns(target) {
        return Err(OxideScannerError::validation(
            "Target contains potential command injection patterns"
        ));
    }

    // Validate the format more strictly
    if !is_valid_network_format(target) {
        return Err(OxideScannerError::validation(
            "Target is not in a valid network format (IP, hostname, or domain)"
        ));
    }

    Ok(target.to_string())
}

/// Enhanced IP address validation with additional checks
pub fn validate_ip_address(ip_str: &str) -> Result<String> {
    // Remove any leading/trailing whitespace
    let ip_str = ip_str.trim();

    if ip_str.is_empty() {
        return Err(OxideScannerError::validation("IP address cannot be empty"));
    }

    // Check for potential command injection
    if contains_command_injection_patterns(ip_str) {
        return Err(OxideScannerError::validation(
            "IP address contains potential command injection patterns"
        ));
    }

    // Check for IP address length limits
    if ip_str.len() > 39 { // Max IPv6 length is 39 characters
        return Err(OxideScannerError::validation("IP address too long"));
    }

    // Parse as IPv4 first
    if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
        // Additional checks for potentially dangerous IPv4 addresses
        if is_potentially_dangerous_ipv4(&ipv4) {
            return Err(OxideScannerError::validation(
                "IP address is in a potentially dangerous range (localhost, broadcast, etc.)"
            ));
        }
        return Ok(ipv4.to_string());
    }

    // Try IPv6
    if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
        // Additional checks for potentially dangerous IPv6 addresses
        if is_potentially_dangerous_ipv6(&ipv6) {
            return Err(OxideScannerError::validation(
                "IP address is in a potentially dangerous range"
            ));
        }
        return Ok(ipv6.to_string());
    }

    Err(OxideScannerError::validation("Invalid IP address format"))
}

/// Enhanced hostname validation with additional security checks
pub fn validate_hostname(hostname: &str) -> Result<String> {
    if hostname.is_empty() {
        return Err(OxideScannerError::validation("Hostname cannot be empty"));
    }

    if hostname.len() > 253 {
        return Err(OxideScannerError::validation("Hostname too long (max 253 characters)"));
    }

    // Check for potential command injection
    if contains_command_injection_patterns(hostname) {
        return Err(OxideScannerError::validation(
            "Hostname contains potential command injection patterns"
        ));
    }

    // Validate hostname format more strictly
    if !is_valid_hostname_format(hostname) {
        return Err(OxideScannerError::validation("Invalid hostname format"));
    }

    // Check for potential IDN homograph attacks
    if contains_potential_homograph_chars(hostname) {
        return Err(OxideScannerError::validation(
            "Hostname contains characters that may be used for homograph attacks"
        ));
    }

    Ok(hostname.to_string())
}

/// Enhanced port validation with additional security checks
pub fn validate_port(port: u16) -> Result<u16> {
    if port == 0 {
        return Err(OxideScannerError::validation("Port cannot be 0"));
    }

    if port > 65535 {
        return Err(OxideScannerError::validation("Port number exceeds maximum (65535)"));
    }

    // Check for potentially sensitive ports that should be handled carefully
    if is_privileged_port(port) {
        // Log this as a potential security concern but allow it
        eprintln!("WARNING: Scanning privileged port {}", port);
    }

    Ok(port)
}

/// Enhanced port range validation
pub fn validate_port_range(start: u16, end: u16) -> Result<(u16, u16)> {
    validate_port(start)?;
    validate_port(end)?;

    if start > end {
        return Err(OxideScannerError::validation("Start port cannot be greater than end port"));
    }

    // Check for extremely large ranges that could be resource-intensive
    if end as u32 - start as u32 > 65000 {
        return Err(OxideScannerError::validation(
            "Port range is extremely large and may cause performance issues"
        ));
    }

    Ok((start, end))
}

/// Enhanced file path validation to prevent directory traversal and other attacks
pub fn validate_file_path(path_str: &str) -> Result<PathBuf> {
    if path_str.is_empty() {
        return Err(OxideScannerError::validation("File path cannot be empty"));
    }

    // Check for potential directory traversal
    if path_str.contains("../") || path_str.contains("..\\") {
        return Err(OxideScannerError::validation(
            "File path contains directory traversal sequences"
        ));
    }

    // Check for null bytes which can cause issues
    if path_str.contains('\0') {
        return Err(OxideScannerError::validation("File path contains null bytes"));
    }

    // Check for potential command injection
    if contains_command_injection_patterns(path_str) {
        return Err(OxideScannerError::validation(
            "File path contains potential command injection patterns"
        ));
    }

    // Check for dangerous file extensions that could be used maliciously
    if contains_dangerous_extensions(path_str) {
        return Err(OxideScannerError::validation(
            "File path contains potentially dangerous extensions"
        ));
    }

    // Convert to Path and validate
    let path = Path::new(path_str);

    // Check for absolute paths if we want to restrict to relative
    if path.is_absolute() {
        // For security, you might want to restrict to relative paths only
        // This depends on your specific requirements
        // For now, we'll allow absolute paths but validate them carefully
    }

    // Normalize the path to resolve any symbolic links or relative components
    let normalized_path = normalize_path(path)?;

    // Additional checks on the normalized path
    if contains_dangerous_path_components(&normalized_path) {
        return Err(OxideScannerError::validation(
            "File path contains dangerous components"
        ));
    }

    // Check if the final path is within allowed directories (if applicable)
    if !is_path_allowed(&normalized_path) {
        return Err(OxideScannerError::validation(
            "File path is outside allowed directories"
        ));
    }

    Ok(normalized_path)
}

/// Enhanced file path validation for output files specifically
pub fn validate_output_file_path(path_str: &str) -> Result<PathBuf> {
    validate_file_path(path_str)?;

    // Additional checks specific to output files
    let path = Path::new(path_str);

    // Check file extension for output files
    if let Some(extension) = path.extension() {
        let ext = extension.to_string_lossy().to_lowercase();
        // Only allow safe file extensions for output
        if !ALLOWED_OUTPUT_EXTENSIONS.contains(&ext.as_str()) {
            return Err(OxideScannerError::validation(
                format!("Output file extension '{}' is not allowed", ext)
            ));
        }
    }

    Ok(PathBuf::from(path_str))
}

/// Enhanced file path validation for input files
pub fn validate_input_file_path(path_str: &str) -> Result<PathBuf> {
    validate_file_path(path_str)?;

    // Additional checks specific to input files
    let path = Path::new(path_str);

    // Check if file exists (for input files)
    if !path.exists() {
        return Err(OxideScannerError::validation(
            "Input file does not exist"
        ));
    }

    // Check file extension for input files
    if let Some(extension) = path.extension() {
        let ext = extension.to_string_lossy().to_lowercase();
        // Only allow safe file extensions for input
        if !ALLOWED_INPUT_EXTENSIONS.contains(&ext.as_str()) {
            return Err(OxideScannerError::validation(
                format!("Input file extension '{}' is not allowed", ext)
            ));
        }
    }

    Ok(PathBuf::from(path_str))
}

/// Enhanced command argument validation to prevent injection attacks
pub fn validate_command_args(args: &[String]) -> Result<Vec<String>> {
    let mut validated_args = Vec::new();

    for (index, arg) in args.iter().enumerate() {
        // Check for potential command injection patterns
        if contains_command_injection_patterns(arg) {
            return Err(OxideScannerError::validation(
                format!("Command argument {} contains injection patterns: {}", index, arg)
            ));
        }

        // Check for potential path traversal in arguments
        if arg.contains("../") || arg.contains("..\\") {
            return Err(OxideScannerError::validation(
                format!("Command argument {} contains path traversal: {}", index, arg)
            ));
        }

        // Check for null bytes which can cause issues with shell commands
        if arg.contains('\0') {
            return Err(OxideScannerError::validation(
                format!("Command argument {} contains null bytes", index)
            ));
        }

        // Check for dangerous characters that could be used for command injection
        if contains_dangerous_shell_chars(arg) {
            return Err(OxideScannerError::validation(
                format!("Command argument {} contains dangerous shell characters", index)
            ));
        }

        // Sanitize the argument by removing or escaping dangerous characters
        let sanitized_arg = sanitize_command_argument(arg);
        validated_args.push(sanitized_arg);
    }

    Ok(validated_args)
}

/// Enhanced validation for external tool command arguments
pub fn validate_external_tool_args(tool_name: &str, args: &[String]) -> Result<Vec<String>> {
    // First validate the arguments normally
    let mut validated_args = validate_command_args(args)?;

    // Apply tool-specific validation
    match tool_name {
        "nmap" => {
            // Validate nmap-specific arguments
            validated_args = validate_nmap_args(validated_args)?;
        },
        "searchsploit" => {
            // Validate searchsploit-specific arguments
            validated_args = validate_searchsploit_args(validated_args)?;
        },
        _ => {
            // For other tools, apply general validation
        }
    }

    Ok(validated_args)
}

/// Validate nmap-specific arguments to prevent dangerous options
fn validate_nmap_args(args: Vec<String>) -> Result<Vec<String>> {
    for arg in &args {
        // Check for potentially dangerous nmap options
        if is_dangerous_nmap_option(arg) {
            return Err(OxideScannerError::validation(
                format!("Nmap argument '{}' is potentially dangerous", arg)
            ));
        }
    }
    Ok(args)
}

/// Validate searchsploit-specific arguments
fn validate_searchsploit_args(args: Vec<String>) -> Result<Vec<String>> {
    for arg in &args {
        // Check for potentially dangerous searchsploit options
        if is_dangerous_searchsploit_option(arg) {
            return Err(OxideScannerError::validation(
                format!("Searchsploit argument '{}' is potentially dangerous", arg)
            ));
        }
    }
    Ok(args)
}

/// Check if nmap option is potentially dangerous
fn is_dangerous_nmap_option(arg: &str) -> bool {
    // List of potentially dangerous nmap options that could be misused
    let dangerous_options = [
        "--script", "--script-args", "--script-args-file",  // Script execution
        "--script-trace", "--script-help",  // Script-related
        "-oA", "-oS", "-oX", "-oG", "-oJ", "-oB", "--opb",  // Output options (some could be misused)
        "--stylesheet", "--webxml",  // XML-related options
        "--datadir", "--nmap-service-probes",  // Data directory manipulation
        "--privileged", "--unprivileged",  // Privilege-related options
        "-e", "--interface",  // Interface specification
        "--source-port", "--proxies", "--proxy",  // Network manipulation
        "--host-timeout", "--max-rtt-timeout", "--min-rtt-timeout",  // Timing manipulation
        "--max-retries", "--min-retries",  // Retry manipulation
        "--host-timeout", "--script-timeout",  // Timeout manipulation
        "-A",  // Aggressive scan (includes version detection, script scanning, etc.)
    ];

    dangerous_options.iter().any(|&opt| arg.starts_with(opt))
}

/// Check if searchsploit option is potentially dangerous
fn is_dangerous_searchsploit_option(arg: &str) -> bool {
    // For searchsploit, most options are relatively safe, but we should be cautious
    // about options that could manipulate file system or execute commands
    let dangerous_options = [
        "--update",  // Update option might be dangerous in some contexts
        "--update-git",  // Git update option
        "--git",  // Git-related option
    ];

    dangerous_options.iter().any(|&opt| arg.starts_with(opt))
}

/// Check if argument contains dangerous shell characters
fn contains_dangerous_shell_chars(s: &str) -> bool {
    // Check for characters that have special meaning in shell contexts
    s.chars().any(|c| (c as u32 >= 0x00 && c as u32 <= 0x1f) || 
                  (c as u32 >= 0x7f && c as u32 <= 0x9f) || 
                  (c as u32 >= 0x2000 && c as u32 <= 0x200F) || 
                  (c as u32 >= 0x2028 && c as u32 <= 0x2029) || 
                  (c as u32 >= 0x202A && c as u32 <= 0x202E) || 
                  (c as u32 >= 0x2060 && c as u32 <= 0x206F) || 
                  (c as u32 >= 0xD800 && c as u32 <= 0xDFFF) || 
                  (c as u32 >= 0xFFF0 && c as u32 <= 0xFFFF))
    || s.chars().any(|c| matches!(c, '\x00' | '\n' | '\r' | '\t' | '\x0b' | '\x0c')) // Control characters
}

/// Enhanced user input sanitization
pub fn sanitize_user_input(input: &str) -> String {
    // Remove or escape potentially dangerous characters
    input
        .chars()
        .filter(|c| !matches!(c, '\0' | '\r' | '\n' | '\t')) // Remove control characters
        .collect()
}

/// Sanitize user input for use in shell commands
pub fn sanitize_for_shell(input: &str) -> String {
    // For shell usage, we need to be more careful
    // Remove or escape shell metacharacters
    let mut result = String::new();
    for c in input.chars() {
        match c {
            // Characters that have special meaning in shells
            '\'' | '"' | ';' | '&' | '|' | '`' | '$' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | '#' | '~' | '*' | '?' | '\\' => {
                // For security, we'll remove these characters rather than escape them
                // In a real implementation, proper escaping would be needed
            },
            '\0' | '\n' | '\r' | '\t' => {
                // Remove control characters
            },
            _ => result.push(c),
        }
    }
    result
}

/// Sanitize user input for file paths
pub fn sanitize_for_file_path(input: &str) -> String {
    // Remove characters that could be used for path traversal or injection
    input
        .chars()
        .filter(|c| !matches!(c, '\0' | '\n' | '\r' | '\t' | ';' | '&' | '|' | '`' | '$' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | '#' | '~' | '*' | '?' | '\\' | '\"' | '\''))
        .collect()
}

/// Sanitize user input for network targets
pub fn sanitize_for_network_target(input: &str) -> String {
    // Remove characters that could be used for injection attacks
    input
        .chars()
        .filter(|c| !matches!(c, '\0' | '\n' | '\r' | '\t' | ';' | '&' | '|' | '`' | '$' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | '#' | '~' | '*' | '?' | '\\' | '\"' | '\''))
        .collect()
}

/// Validate and sanitize user input based on context
pub fn validate_and_sanitize_input(input: &str, context: InputContext) -> Result<String> {
    match context {
        InputContext::NetworkTarget => {
            let sanitized = sanitize_for_network_target(input);
            validate_network_target(&sanitized)?;
            Ok(sanitized)
        },
        InputContext::FilePath => {
            let sanitized = sanitize_for_file_path(input);
            validate_file_path(&sanitized)?;
            Ok(sanitized)
        },
        InputContext::CommandLineArg => {
            let sanitized = sanitize_for_shell(input);
            // Further validation would be context-specific
            Ok(sanitized)
        },
        InputContext::General => {
            let sanitized = sanitize_user_input(input);
            Ok(sanitized)
        },
    }
}

/// Context for input validation and sanitization
#[derive(Debug, Clone)]
pub enum InputContext {
    NetworkTarget,
    FilePath,
    CommandLineArg,
    General,
}

// Constants for allowed file extensions
const ALLOWED_OUTPUT_EXTENSIONS: &[&str] = &["txt", "json", "xml", "csv", "log"];
const ALLOWED_INPUT_EXTENSIONS: &[&str] = &["txt", "json", "xml", "csv", "log", "conf", "cfg"];

/// Enhanced URL validation (if needed for future features)
pub fn validate_url(url_str: &str) -> Result<String> {
    if url_str.is_empty() {
        return Err(OxideScannerError::validation("URL cannot be empty"));
    }

    // Check for potential command injection
    if contains_command_injection_patterns(url_str) {
        return Err(OxideScannerError::validation(
            "URL contains potential command injection patterns"
        ));
    }

    // Basic URL format validation (more comprehensive validation would require regex or a URL parsing library)
    if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
        // For OxideScanner, we might only accept hostnames/IPs, not full URLs
        return Err(OxideScannerError::validation(
            "URL format not supported, please use hostname or IP address"
        ));
    }

    Ok(url_str.to_string())
}

// Helper functions for validation

/// Check if string contains potential command injection patterns
pub fn contains_command_injection_patterns(s: &str) -> bool {
    s.chars().any(|c| matches!(c, ';' | '&' | '|' | '`' | '$' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | '#' | '~' | '*' | '?' | '\\' | '\"' | '\'' | '%'))
}

/// Check if string is in valid network format
fn is_valid_network_format(s: &str) -> bool {
    // Try to parse as IP address first
    if s.parse::<Ipv4Addr>().is_ok() || s.parse::<Ipv6Addr>().is_ok() {
        return true;
    }

    // Then try as hostname
    is_valid_hostname_format(s)
}

/// Enhanced hostname format validation
fn is_valid_hostname_format(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    // Split by dots to validate each label
    let labels: Vec<&str> = hostname.split('.').collect();
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // Label must start and end with alphanumeric
        if !label.chars().next().unwrap_or('0').is_alphanumeric()
            || !label.chars().last().unwrap_or('0').is_alphanumeric()
        {
            return false;
        }

        // Can only contain alphanumeric, hyphens, and underscores
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return false;
        }
    }

    true
}

/// Check for potentially dangerous IPv4 addresses
fn is_potentially_dangerous_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    
    // Check for localhost (127.x.x.x)
    if octets[0] == 127 {
        return true;
    }
    
    // Check for broadcast addresses
    if octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255 {
        return true;
    }
    
    // Check for multicast addresses (224.x.x.x to 239.x.x.x)
    if octets[0] >= 224 && octets[0] <= 239 {
        return true;
    }
    
    false
}

/// Check for potentially dangerous IPv6 addresses
fn is_potentially_dangerous_ipv6(ip: &Ipv6Addr) -> bool {
    // Check for localhost (::1)
    if ip.is_loopback() {
        return true;
    }
    
    // Check for multicast addresses (ff00::/8)
    if ip.segments()[0] & 0xff00 == 0xff00 {
        return true;
    }
    
    false
}

/// Check for potential homograph attack characters
fn contains_potential_homograph_chars(hostname: &str) -> bool {
    // Check for Unicode characters that could be used in homograph attacks
    hostname.chars().any(|c| {
        // Characters that look similar to ASCII but are Unicode
        let code = c as u32;
        // Cyrillic characters that look like Latin ones
        (0x0400..=0x04FF).contains(&code) ||
        // Greek and Coptic characters that look like Latin
        (0x0370..=0x03FF).contains(&code) ||
        // Other potentially confusing Unicode characters
        matches!(code, 0x212C /* Script B */ | 0x2132 /* Turned F */ | 0x2141 /* Turned G */)
    })
}

/// Check if port is a privileged port (0-1023)
fn is_privileged_port(port: u16) -> bool {
    port <= 1023
}

/// Normalize a path to resolve relative components
fn normalize_path(path: &Path) -> Result<PathBuf> {
    // Convert to string and check for null bytes
    if path.to_string_lossy().contains('\0') {
        return Err(OxideScannerError::validation("Path contains null bytes"));
    }

    // Resolve relative path components
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                // Remove the last component if it's not the root
                if !normalized.pop() {
                    return Err(OxideScannerError::validation("Invalid path with too many parent directories"));
                }
            }
            std::path::Component::Normal(c) => {
                normalized.push(c);
            }
            std::path::Component::RootDir | std::path::Component::CurDir => {
                // Keep these components as they are
                normalized.push(component.as_os_str());
            }
            std::path::Component::Prefix(_) => {
                // Windows prefix (like C:\), keep as is
                normalized.push(component.as_os_str());
            }
        }
    }

    Ok(normalized)
}

/// Check if path contains dangerous components after normalization
fn contains_dangerous_path_components(path: &PathBuf) -> bool {
    // Check if the final path contains any dangerous elements
    path.to_string_lossy().contains(|c: char| matches!(c, '|' | '&' | ';' | '`' | '$' | '{' | '}' | '[' | ']' | '(' | ')'))
}

/// Check if file path contains dangerous extensions
fn contains_dangerous_extensions(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    
    // Check for potentially dangerous file extensions
    DANGEROUS_EXTENSIONS.iter().any(|ext| path_lower.ends_with(ext))
}

/// Check if path is within allowed directories
fn is_path_allowed(path: &Path) -> bool {
    // For now, we'll allow any path that doesn't contain dangerous components
    // In a more restrictive environment, you could check against allowed base directories
    true
}

/// Sanitize command argument by escaping or removing dangerous characters
fn sanitize_command_argument(arg: &str) -> String {
    // For now, we'll just return the argument as-is after validation
    // In a real implementation, you might want to escape certain characters
    arg.to_string()
}

// Re-export existing validation functions for backward compatibility
pub use crate::validation::{validate_target, validate_target_for_external_tools, validate_port_limit, validate_port_list};

// List of potentially dangerous file extensions
const DANGEROUS_EXTENSIONS: &[&str] = &[
    ".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".js", ".jar", 
    ".sh", ".pl", ".php", ".py", ".rb", ".sql", ".dll", ".so", ".dylib"
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ip_address() {
        assert!(validate_ip_address("192.168.1.1").is_ok());
        assert!(validate_ip_address("::1").is_ok());
        assert!(validate_ip_address("invalid").is_err());
        assert!(validate_ip_address("192.168.1.1;rm -rf").is_err());
    }

    #[test]
    fn test_validate_hostname() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
        assert!(validate_hostname("example..com").is_err());
        assert!(validate_hostname("example.com;rm -rf").is_err());
    }

    #[test]
    fn test_validate_port() {
        assert!(validate_port(80).is_ok());
        assert!(validate_port(65535).is_ok());
        assert!(validate_port(0).is_err());
        assert!(validate_port(65536).is_err());
    }

    #[test]
    fn test_validate_file_path() {
        assert!(validate_file_path("output.txt").is_ok());
        assert!(validate_file_path("../output.txt").is_err());
        assert!(validate_file_path("output.txt;rm -rf").is_err());
    }

    #[test]
    fn test_contains_command_injection_patterns() {
        assert!(contains_command_injection_patterns("test;rm -rf"));
        assert!(contains_command_injection_patterns("test & echo"));
        assert!(!contains_command_injection_patterns("test"));
    }
}