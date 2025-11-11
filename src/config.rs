//! # Configuration Management
//!
//! This module handles command-line argument parsing and configuration management
//! for OxideScanner scanning operations. It provides a flexible configuration system
//! that supports various scanning options and output formats.
//!
//! ## Example
//!
//! ```rust
//! use oxidescanner::config::Config;
//!
//! let config = Config::from_args(&[
//!     "oxidescanner".to_string(),
//!     "example.com".to_string(),
//!     "-5k".to_string(),
//!     "--json".to_string(),
//! ])?;
//!
//! assert_eq!(config.target, "example.com");
//! assert_eq!(config.port_limit, 5000);
//! assert!(config.json_mode);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::constants;
use crate::error::{OxideScannerError, Result};
use crate::logging::LogConfig;
use crate::metrics::MetricsConfig;
use crate::rate_limit::RateLimitPolicy;
use crate::retry::RetryConfig;
use crate::validation;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

use std::time::Duration;
///
/// This struct contains all the parameters needed to configure a scan,
/// including target specification, port ranges, timeouts, and output formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Target hostname or IP address
    pub target: String,
    /// Output in JSON format
    pub json_mode: bool,
    /// Maximum port number to scan
    pub port_limit: u16,
    /// TCP connection timeout
    pub scan_timeout: Duration,
    /// Exploit search timeout
    pub exploit_timeout: Duration,
    /// Number of threads to use (0 = auto-detect)
    pub threads: usize,
    /// Graceful shutdown timeout
    pub shutdown_timeout: Duration,
    /// Enable rate limiting
    pub enable_rate_limiting: bool,
    /// Scanner rate limit policy
    pub scanner_rate_limit: RateLimitPolicy,
    /// External tools rate limit policy
    pub external_tools_rate_limit: RateLimitPolicy,
    /// Exploit queries rate limit policy
    pub exploit_queries_rate_limit: RateLimitPolicy,
    /// Logging configuration
    pub logging: LogConfig,
    /// Metrics configuration
    pub metrics: MetricsConfig,
    /// Retry configuration
    pub retry: RetryConfig,
}

impl Config {
    /// Create configuration from command line arguments
    pub fn from_args(args: &[String]) -> Result<Self> {
        if args.len() < 2 {
            return Err(OxideScannerError::config("Target argument required"));
        }

        // Parse and validate target
        let target = validation::validate_target(&args[1])?;

        // Parse boolean flags
        let json_mode = args.contains(&"--json".to_string());

        // Parse port limit
        let port_limit = if args
            .iter()
            .any(|arg| arg.starts_with('-') && arg.ends_with('k'))
        {
            Self::parse_port_limit_flag(args)?
        } else if let Some(limit) = Self::parse_numeric_port_flag(args)? {
            limit
        } else {
            // Always prompt for port count when no port specification is given
            // This provides better user experience
            Self::prompt_port_limit()?
        };

        // Parse optional timeout arguments
        let scan_timeout =
            Self::parse_timeout_arg(args, "--scan-timeout", constants::DEFAULT_SCAN_TIMEOUT_MS)?;
        let exploit_timeout = Self::parse_timeout_arg(
            args,
            "--exploit-timeout",
            constants::DEFAULT_EXPLOIT_TIMEOUT_SECS * 1000,
        )?;

        // Load environment-based configuration
        let env_config = Self::from_env()?;

        // Merge command line args with environment config
        let threads = Self::parse_thread_arg(args, env_config.threads)?;
        let shutdown_timeout = Self::parse_timeout_arg(
            args,
            "--shutdown-timeout",
            env_config.shutdown_timeout.as_millis() as u64,
        )?;
        let enable_rate_limiting =
            !args.contains(&"--no-rate-limit".to_string()) && env_config.enable_rate_limiting;

        let logging = LogConfig::from_env()?;
        let metrics = MetricsConfig::from_env()?;
        let retry = RetryConfig::from_env()?;

        Ok(Config {
            target,
            json_mode,
            port_limit,
            scan_timeout,
            exploit_timeout,
            threads,
            shutdown_timeout,
            enable_rate_limiting,
            scanner_rate_limit: env_config.scanner_rate_limit,
            external_tools_rate_limit: env_config.external_tools_rate_limit,
            exploit_queries_rate_limit: env_config.exploit_queries_rate_limit,
            logging,
            metrics,
            retry,
        })
    }

    /// Parse timeout argument from command line
    fn parse_timeout_arg(args: &[String], flag: &str, default_ms: u64) -> Result<Duration> {
        for (i, arg) in args.iter().enumerate() {
            if arg == flag {
                if i + 1 >= args.len() {
                    return Err(OxideScannerError::config(format!(
                        "Missing timeout value for {}",
                        flag
                    )));
                }

                let timeout_ms = args[i + 1].parse::<u64>().map_err(|_| {
                    OxideScannerError::config(format!(
                        "Invalid timeout value for {}: {}",
                        flag,
                        args[i + 1]
                    ))
                })?;

                let validated_ms = validation::validate_timeout_ms(timeout_ms)?;
                return Ok(Duration::from_millis(validated_ms));
            }
        }
        Ok(Duration::from_millis(default_ms))
    }

    /// Parse port limit from numeric flags (e.g., -1000 or --ports 1000)
    fn parse_numeric_port_flag(args: &[String]) -> Result<Option<u16>> {
        // Check for --ports flag
        for (i, arg) in args.iter().enumerate() {
            if arg == "--ports" {
                if i + 1 >= args.len() {
                    return Err(OxideScannerError::config(
                        "Missing port count value for --ports flag",
                    ));
                }

                let port_count = args[i + 1].parse::<u16>().map_err(|_| {
                    OxideScannerError::config(format!("Invalid port count: {}", args[i + 1]))
                })?;

                if port_count < 1 {
                    return Err(OxideScannerError::config(
                        "Port count must be at least 1",
                    ));
                }

                return Ok(Some(port_count));
            }
        }

        // Check for direct numeric flags like -1000
        for arg in args {
            if arg.starts_with('-') && arg.len() > 1 {
                // Check if it's a pure number after the dash
                let num_str = &arg[1..];
                if let Ok(num) = num_str.parse::<u16>() {
                    if num >= 1 {
                        return Ok(Some(num));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Parse port limit from -k flag (e.g., -5k for 5000 ports)
    fn parse_port_limit_flag(args: &[String]) -> Result<u16> {
        for arg in args {
            if arg.starts_with('-') && arg.ends_with('k') {
                let num_str = &arg[1..arg.len() - 1];
                if let Ok(num) = num_str.parse::<u16>() {
                    if (1..=constants::ports::MAX_K_VALUE).contains(&num) {
                        return Ok(num * constants::ports::DEFAULT_LIMIT);
                    } else {
                        return Err(OxideScannerError::config(format!(
                            "Port limit must be between 1k and {}k",
                            constants::ports::MAX_K_VALUE
                        )));
                    }
                } else {
                    return Err(OxideScannerError::config(format!(
                        "Invalid port limit format: {}",
                        arg
                    )));
                }
            }
        }
        Ok(constants::ports::MAX)
    }

    /// Prompt user for port limit interactively
    fn prompt_port_limit() -> Result<u16> {
        print!(
            "{} Enter number of ports to scan (1-65535, or 'all' for full scan): ",
            "→".bright_cyan()
        );

        if let Err(e) = io::stdout().flush() {
            return Err(OxideScannerError::Io(e));
        }

        let mut input = String::new();
        if let Err(e) = io::stdin().read_line(&mut input) {
            return Err(OxideScannerError::Io(e));
        }

        let input = input.trim().to_lowercase();

        if input == "all" {
            Ok(constants::ports::MAX)
        } else if let Ok(num) = input.parse::<u16>() {
            validation::validate_port_limit(num)
        } else {
            Err(OxideScannerError::config(format!(
                "Invalid port number: {}",
                input
            )))
        }
    }

    /// Parse thread count argument
    fn parse_thread_arg(args: &[String], default: usize) -> Result<usize> {
        for (i, arg) in args.iter().enumerate() {
            if arg == "--threads" {
                if i + 1 >= args.len() {
                    return Err(OxideScannerError::config("Missing thread count value"));
                }

                let threads = args[i + 1].parse::<usize>().map_err(|_| {
                    OxideScannerError::config(format!("Invalid thread count: {}", args[i + 1]))
                })?;

                if threads == 0 {
                    return Ok(num_cpus::get());
                }

                return Ok(threads);
            }
        }
        Ok(if default == 0 {
            num_cpus::get()
        } else {
            default
        })
    }

    /// Load configuration from environment variables
    fn from_env() -> Result<Self> {
        let threads = if let Ok(threads) = std::env::var("OXIDE_THREADS") {
            threads
                .parse::<usize>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_THREADS value"))?
        } else {
            0 // Auto-detect
        };

        let shutdown_timeout = if let Ok(timeout) = std::env::var("OXIDE_SHUTDOWN_TIMEOUT") {
            let secs = timeout
                .parse::<u64>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_SHUTDOWN_TIMEOUT value"))?;
            Duration::from_secs(secs)
        } else {
            Duration::from_secs(30)
        };

        let enable_rate_limiting = if let Ok(enabled) = std::env::var("OXIDE_ENABLE_RATE_LIMIT") {
            enabled
                .parse::<bool>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_ENABLE_RATE_LIMIT value"))?
        } else {
            true
        };

        let scanner_rate_limit = RateLimitPolicy::new(
            std::env::var("OXIDE_SCANNER_RATE_LIMIT")
                .unwrap_or_else(|_| "50".to_string())
                .parse::<u32>()
                .map_err(|_| OxideScannerError::config("Invalid OXIDE_SCANNER_RATE_LIMIT value"))?,
            Duration::from_secs(1),
        );

        let external_tools_rate_limit = RateLimitPolicy::new(
            std::env::var("OXIDE_EXTERNAL_TOOLS_RATE_LIMIT")
                .unwrap_or_else(|_| "5".to_string())
                .parse::<u32>()
                .map_err(|_| {
                    OxideScannerError::config("Invalid OXIDE_EXTERNAL_TOOLS_RATE_LIMIT value")
                })?,
            Duration::from_secs(1),
        );

        let exploit_queries_rate_limit = RateLimitPolicy::new(
            std::env::var("OXIDE_EXPLOIT_QUERIES_RATE_LIMIT")
                .unwrap_or_else(|_| "2".to_string())
                .parse::<u32>()
                .map_err(|_| {
                    OxideScannerError::config("Invalid OXIDE_EXPLOIT_QUERIES_RATE_LIMIT value")
                })?,
            Duration::from_secs(1),
        );

        let logging = LogConfig::from_env()?;
        let metrics = MetricsConfig::from_env()?;
        let retry = RetryConfig::from_env()?;

        Ok(Config {
            target: String::new(), // Will be set from command line
            json_mode: false,
            port_limit: 1000, // Default to top 1000 ports instead of all
            scan_timeout: Duration::from_millis(constants::DEFAULT_SCAN_TIMEOUT_MS),
            exploit_timeout: Duration::from_secs(constants::DEFAULT_EXPLOIT_TIMEOUT_SECS),
            threads,
            shutdown_timeout,
            enable_rate_limiting,
            scanner_rate_limit,
            external_tools_rate_limit,
            exploit_queries_rate_limit,
            logging,
            metrics,
            retry,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_args_basic() {
        let args = vec![
            "oxidescanner".to_string(),
            "127.0.0.1".to_string(),
            "-5k".to_string(),
            "--json".to_string(),
        ];

        let config = Config::from_args(&args).unwrap();
        assert_eq!(config.target, "127.0.0.1");
        assert!(config.json_mode);
        assert_eq!(config.port_limit, 5000);
    }

    #[test]
    fn test_config_from_args_with_timeouts() {
        let args = vec![
            "oxidescanner".to_string(),
            "example.com".to_string(),
            "-5k".to_string(),
            "--scan-timeout".to_string(),
            "50".to_string(),
            "--exploit-timeout".to_string(),
            "15000".to_string(),
        ];

        let config = Config::from_args(&args).unwrap();
        assert_eq!(config.target, "example.com");
        assert_eq!(config.scan_timeout.as_millis(), 50);
        assert_eq!(config.exploit_timeout.as_millis(), 15000);
    }

    #[test]
    fn test_config_invalid_target() {
        let args = vec!["oxidescanner".to_string(), "invalid..hostname".to_string()];

        let result = Config::from_args(&args);
        assert!(result.is_err());
    }
}
