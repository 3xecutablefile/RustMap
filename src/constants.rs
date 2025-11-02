//! # Configuration Constants
//! 
//! This module contains all configuration constants used throughout RustMap,
//! including default timeouts, risk scoring parameters, and operational limits.
//! These constants are carefully tuned for optimal performance and security.
//! 
//! ## Categories
//! 
//! - **Timeouts**: Default timeouts for various operations
//! - **Risk Scoring**: CVSS mappings and risk thresholds
//! - **Service Multipliers**: Risk multipliers for different service types
//! - **Port Limits**: Port scanning limits and ranges
//! - **Validation**: Input validation limits and constraints
//! 
//! ## Example
//! 
//! ```rust
//! use rustmap::constants::*;
//! use std::time::Duration;
//! 
//! // Use default scan timeout
//! let timeout = Duration::from_millis(DEFAULT_SCAN_TIMEOUT_MS);
//! 
//! // Check risk thresholds
//! let score = 25.0;
//! let is_critical = score >= risk::CRITICAL;
//! let is_high_risk = score >= risk::HIGH;
//! 
//! // Apply service multipliers
//! let service_type = "http";
//! let multiplier = match service_type {
//!     "smb" => service_multipliers::SMB,
//!     "http" => service_multipliers::WEB,
//!     _ => service_multipliers::DEFAULT,
//! };
//! ```

/// Default timeout for TCP connections in milliseconds
/// 
/// This timeout is used for initial TCP connect attempts during port scanning.
/// A shorter timeout improves scanning speed but may miss slow-responding services.
pub const DEFAULT_SCAN_TIMEOUT_MS: u64 = 25;

/// Default timeout for exploit searches in seconds
pub const DEFAULT_EXPLOIT_TIMEOUT_SECS: u64 = 10;

/// Default timeout for nmap service detection in seconds
pub const NMAP_TIMEOUT_SECS: u64 = 30;

/// Default nmap version intensity level
pub const NMAP_VERSION_INTENSITY: u8 = 1;

/// Progress bar update interval in milliseconds
pub const PROGRESS_UPDATE_INTERVAL_MS: u64 = 100;

/// TCP read timeout for connection verification in milliseconds
pub const TCP_READ_TIMEOUT_MS: u64 = 100;

/// Maximum number of exploits to display per port
pub const MAX_DISPLAYED_EXPLOITS: usize = 10;

/// Risk score thresholds
pub mod risk {
    /// Critical risk threshold
    pub const CRITICAL: f32 = 50.0;
    /// High risk threshold
    pub const HIGH: f32 = 30.0;
    /// Medium risk threshold
    pub const MEDIUM: f32 = 15.0;
}

/// Service risk multipliers
pub mod service_multipliers {
    /// SMB and related services
    pub const SMB: f32 = 1.8;
    /// Database services
    pub const DATABASE: f32 = 1.6;
    /// Remote access services
    pub const REMOTE_ACCESS: f32 = 1.5;
    /// Web services
    pub const WEB: f32 = 1.3;
    /// Default multiplier
    pub const DEFAULT: f32 = 1.0;
}

/// CVSS score mappings for vulnerability types
pub mod cvss {
    /// Pre-authentication RCE
    pub const PRE_AUTH_RCE: f32 = 10.0;
    /// Remote code execution
    pub const RCE: f32 = 9.8;
    /// Authentication bypass (remote)
    pub const AUTH_BYPASS_REMOTE: f32 = 9.8;
    /// Blind SQL injection
    pub const BLIND_SQLI: f32 = 8.9;
    /// SQL injection
    pub const SQLI: f32 = 8.1;
    /// Remote buffer overflow
    pub const REMOTE_BUFFER_OVERFLOW: f32 = 9.3;
    /// Buffer overflow
    pub const BUFFER_OVERFLOW: f32 = 8.5;
    /// File upload with RCE
    pub const FILE_UPLOAD_RCE: f32 = 9.8;
    /// File upload
    pub const FILE_UPLOAD: f32 = 8.9;
    /// Root privilege escalation
    pub const ROOT_PRIV_ESC: f32 = 8.8;
    /// Privilege escalation
    pub const PRIV_ESC: f32 = 7.8;
    /// Remote command injection
    pub const REMOTE_CMD_INJECTION: f32 = 9.0;
    /// Command injection
    pub const CMD_INJECTION: f32 = 8.6;
    /// Remote deserialization
    pub const REMOTE_DESERIALIZATION: f32 = 8.5;
    /// Root directory traversal
    pub const ROOT_DIR_TRAVERSAL: f32 = 7.5;
    /// Directory traversal
    pub const DIR_TRAVERSAL: f32 = 6.8;
    /// Stored XSS
    pub const STORED_XSS: f32 = 7.5;
    /// Cross-site scripting
    pub const XSS: f32 = 6.1;
    /// Cross-site request forgery
    pub const CSRF: f32 = 6.5;
    /// Server-side request forgery
    pub const SSRF: f32 = 7.5;
    /// Denial of service
    pub const DOS: f32 = 5.3;
    /// Sensitive information disclosure
    pub const SENSITIVE_INFO_DISCLOSURE: f32 = 5.5;
    /// Information disclosure
    pub const INFO_DISCLOSURE: f32 = 4.3;
    /// Brute force
    pub const BRUTE_FORCE: f32 = 5.0;
    /// Clickjacking
    pub const CLICKJACKING: f32 = 4.3;
}

/// Port scanning limits
pub mod ports {
    /// Maximum port number
    pub const MAX: u16 = 65535;
    /// Minimum port number
    pub const MIN: u16 = 1;
    /// Default port limit when using -k flags
    pub const DEFAULT_LIMIT: u16 = 1000;
    /// Maximum k value for port limits (30k = 30000)
    pub const MAX_K_VALUE: u16 = 30;
}

/// Progress bar settings
pub mod progress {
    /// Default progress bar width
    pub const DEFAULT_WIDTH: usize = 40;
}

/// Input validation
pub mod validation {
    /// Maximum target string length
    pub const MAX_TARGET_LENGTH: usize = 253;

}