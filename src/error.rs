//! # Error Handling
//!
//! This module provides comprehensive error handling for OxideScanner operations
//! with custom error types that cover various failure scenarios. It uses the
//! `thiserror` crate for clean error definitions and improved error messages.
//!
//! ## Features
//!
//! - Custom error types for different operation categories
//! - Detailed error messages with context
//! - Error conversion from standard I/O errors
//! - Result type alias for convenience
//! - Structured error reporting
//!
//! ## Example
//!
//! ```rust
//! use oxidescanner::error::{OxideScannerError, Result};
//!
//! fn validate_port(port: u16) -> Result<()> {
//!     if port == 0 {
//!         return Err(OxideScannerError::validation("Port cannot be 0"));
//!     }
//!     if port > 65535 {
//!         return Err(OxideScannerError::validation("Port cannot exceed 65535"));
//!     }
//!     Ok(())
//! }
//!
//! match validate_port(0) {
//!     Ok(_) => println!("Port is valid"),
//!     Err(e) => println!("Error: {}", e),
//! }
//! ```

use std::io;

/// Custom error types for OxideScanner operations
///
/// This enum represents all possible error conditions that can occur during
/// OxideScanner operations, providing specific error types for different scenarios
/// like configuration errors, network issues, and external tool failures.
#[derive(Debug, thiserror::Error)]
pub enum OxideScannerError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("External tool error: {tool} failed with {message}")]
    ExternalTool { tool: String, message: String },

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Parsing error: {0}")]
    Parse(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Timeout error: operation timed out after {duration_ms}ms")]
    Timeout { duration_ms: u64 },

    #[error("Service detection failed: {0}")]
    ServiceDetection(String),



    #[error("Target resolution failed: {0}")]
    TargetResolution(String),
}

impl OxideScannerError {
    /// Create a new configuration error
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Create a new external tool error
    pub fn external_tool(tool: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ExternalTool {
            tool: tool.into(),
            message: message.into(),
        }
    }

    /// Create a new validation error
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    /// Create a new parsing error
    pub fn parse(msg: impl Into<String>) -> Self {
        Self::Parse(msg.into())
    }

    /// Create a new timeout error
    pub fn timeout(duration_ms: u64) -> Self {
        Self::Timeout { duration_ms }
    }

    /// Create a new service detection error
    pub fn service_detection(msg: impl Into<String>) -> Self {
        Self::ServiceDetection(msg.into())
    }



    /// Create a new target resolution error
    pub fn target_resolution(msg: impl Into<String>) -> Self {
        Self::TargetResolution(msg.into())
    }
}

/// Result type alias for OxideScanner operations
pub type Result<T> = std::result::Result<T, OxideScannerError>;
