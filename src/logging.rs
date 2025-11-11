//! # Logging Module
//!
//! This module provides structured logging capabilities for OxideScanner using the
//! tracing crate. It provides configuration management for log levels, output formats,
//! and file logging with rotation.
//!
//! ## Features
//!
//! - Structured logging with tracing
//! - Multiple output formats (console, file)
//! - Environment-based configuration
//! - Log rotation and management
//! - Performance-aware logging
//!
//! ## Example
//!
//! ```rust
//! use oxidescanner::logging::LogConfig;
//!
//! let config = LogConfig::default();
//! let config = LogConfig::from_env().unwrap();
//!
//! assert_eq!(config.level, "info");
//! assert!(config.console);
//! ```

use crate::error::{OxideScannerError, Result};
use serde::{Deserialize, Serialize};

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Enable console output
    pub console: bool,
    /// Enable JSON output format
    pub json: bool,
    /// Console log timestamps
    pub console_timestamps: bool,
    /// Log file path (if file logging is enabled)
    pub file_path: Option<std::path::PathBuf>,
    /// Maximum log file size in bytes
    pub max_file_size: u64,
    /// Maximum number of log files to keep
    pub max_files: u32,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            console: true,
            json: false,
            console_timestamps: true,
            file_path: None,
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_files: 5,
        }
    }
}

impl LogConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();

        if let Ok(level) = std::env::var("OXIDE_LOG_LEVEL") {
            config.level = level;
        }

        if let Ok(console) = std::env::var("OXIDE_LOG_CONSOLE") {
            config.console = console
                .parse::<bool>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_LOG_CONSOLE value"))?;
        }

        if let Ok(json) = std::env::var("OXIDE_LOG_JSON") {
            config.json = json
                .parse::<bool>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_LOG_JSON value"))?;
        }

        if let Ok(timestamps) = std::env::var("OXIDE_LOG_CONSOLE_TIMESTAMPS") {
            config.console_timestamps = timestamps.parse::<bool>().map_err(|_| {
                OxideScannerError::config("Invalid OXIDE_LOG_CONSOLE_TIMESTAMPS value")
            })?;
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert_eq!(config.level, "info");
        assert!(config.console);
        assert!(!config.json);
        assert!(config.file_path.is_none());
    }

    #[test]
    fn test_log_config_from_env() {
        // Set environment variables
        env::set_var("OXIDE_LOG_LEVEL", "debug");
        env::set_var("OXIDE_LOG_CONSOLE", "false");
        env::set_var("OXIDE_LOG_JSON", "true");

        let config = LogConfig::from_env().unwrap();
        assert_eq!(config.level, "debug");
        assert!(!config.console);
        assert!(config.json);

        // Clean up
        env::remove_var("OXIDE_LOG_LEVEL");
        env::remove_var("OXIDE_LOG_CONSOLE");
        env::remove_var("OXIDE_LOG_JSON");
    }
}
