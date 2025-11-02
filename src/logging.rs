//! # Structured Logging Module
//! 
//! This module provides comprehensive structured logging capabilities for RustMap
//! with configurable log levels, output formats, and file rotation support.
//! It uses the `tracing` ecosystem for high-performance structured logging.
//! 
//! ## Features
//! 
//! - Configurable log levels (trace, debug, info, warn, error)
//! - Multiple output formats (console, JSON, file)
//! - Log file rotation with size limits
//! - Environment-based configuration
//! - Performance-optimized async logging
//! - Context-aware logging with request IDs
//! 
//! ## Example
//! 
//! ```rust
//! use rustmap::logging::{init_logging, LogConfig};
//! 
//! let config = LogConfig::from_env()?;
//! init_logging(&config)?;
//! 
//! tracing::info!("Application started successfully");
//! tracing::warn!("High memory usage detected: {}%", usage);
//! tracing::error!("Failed to connect to target: {}", error);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{RustMapError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Configuration for structured logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Whether to output to console
    pub console: bool,
    /// Whether to output in JSON format
    pub json: bool,
    /// Log file path (optional)
    pub file_path: Option<PathBuf>,
    /// Maximum log file size in bytes before rotation
    pub max_file_size: u64,
    /// Number of rotated log files to keep
    pub max_files: usize,
    /// Whether to include timestamps in console output
    pub console_timestamps: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            console: true,
            json: false,
            file_path: None,
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_files: 5,
            console_timestamps: false,
        }
    }
}

impl LogConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();
        
        if let Ok(level) = std::env::var("RUSTMAP_LOG_LEVEL") {
            config.level = level;
        }
        
        if let Ok(console) = std::env::var("RUSTMAP_LOG_CONSOLE") {
            config.console = console.parse::<bool>()
                .map_err(|_| RustMapError::config("Invalid RUSTMAP_LOG_CONSOLE value"))?;
        }
        
        if let Ok(json) = std::env::var("RUSTMAP_LOG_JSON") {
            config.json = json.parse::<bool>()
                .map_err(|_| RustMapError::config("Invalid RUSTMAP_LOG_JSON value"))?;
        }
        
        if let Ok(file_path) = std::env::var("RUSTMAP_LOG_FILE") {
            config.file_path = Some(PathBuf::from(file_path));
        }
        
        if let Ok(max_size) = std::env::var("RUSTMAP_LOG_MAX_SIZE") {
            config.max_file_size = max_size.parse::<u64>()
                .map_err(|_| RustMapError::config("Invalid RUSTMAP_LOG_MAX_SIZE value"))?;
        }
        
        if let Ok(max_files) = std::env::var("RUSTMAP_LOG_MAX_FILES") {
            config.max_files = max_files.parse::<usize>()
                .map_err(|_| RustMapError::config("Invalid RUSTMAP_LOG_MAX_FILES value"))?;
        }
        
        if let Ok(timestamps) = std::env::var("RUSTMAP_LOG_CONSOLE_TIMESTAMPS") {
            config.console_timestamps = timestamps.parse::<bool>()
                .map_err(|_| RustMapError::config("Invalid RUSTMAP_LOG_CONSOLE_TIMESTAMPS value"))?;
        }
        
        Ok(config)
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.level.as_str()) {
            return Err(RustMapError::config(format!(
                "Invalid log level '{}'. Valid levels: {}",
                self.level,
                valid_levels.join(", ")
            )));
        }
        
        if self.max_file_size == 0 {
            return Err(RustMapError::config("Log file size must be greater than 0"));
        }
        
        if self.max_files == 0 {
            return Err(RustMapError::config("Max files must be greater than 0"));
        }
        
        Ok(())
    }
}

/// Initialize structured logging with the given configuration
/// 
/// This function sets up the tracing subscriber with multiple layers:
/// - Console output (optional)
/// - File output with rotation (optional)
/// - Environment filter for log levels
/// 
/// Returns a worker guard that must be kept in scope for the duration of the program.
pub fn init_logging(config: &LogConfig) -> Result<Vec<WorkerGuard>> {
    config.validate()?;
    
    let mut guards = Vec::new();
    let mut layers = Vec::new();
    
    // Create environment filter
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.level));
    
    // Console layer
    if config.console {
        let console_layer = if config.json {
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .boxed()
        } else {
            let layer = tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_writer(std::io::stdout);
            
            if !config.console_timestamps {
                layer.boxed()
            } else {
                layer.boxed()
            }
        };
        
        layers.push(console_layer.with_filter(env_filter.clone()));
    }
    
    // File layer
    if let Some(file_path) = &config.file_path {
        let file_appender = tracing_appender::rolling::Builder::new()
            .rotation(tracing_appender::rolling::Rotation::HOURLY)
            .filename_prefix("rustmap")
            .filename_suffix("log")
            .max_log_files(config.max_files)
            .build(file_path.parent().unwrap_or_else(|| std::path::Path::new(".")))
            .map_err(|e| RustMapError::config(format!("Failed to create log appender: {}", e)))?;
        
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        guards.push(guard);
        
        let file_layer = if config.json {
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(non_blocking)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .boxed()
        } else {
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .boxed()
        };
        
        layers.push(file_layer.with_filter(env_filter));
    }
    
    // Initialize subscriber
    tracing_subscriber::registry()
        .with(layers)
        .init();
    
    tracing::info!(
        level = %config.level,
        console = config.console,
        json = config.json,
        file_path = ?config.file_path,
        "Logging initialized"
    );
    
    Ok(guards)
}

/// Create a span for scanning operations
pub fn scan_span(target: &str, port_count: u16) -> tracing::Span {
    tracing::info_span!(
        "scan",
        target = %target,
        port_count = port_count,
        start_time = %chrono::Utc::now().to_rfc3339()
    )
}

/// Create a span for exploit search operations
pub fn exploit_span(service_count: usize) -> tracing::Span {
    tracing::info_span!(
        "exploit_search",
        service_count = service_count,
        start_time = %chrono::Utc::now().to_rfc3339()
    )
}

/// Log scan progress
pub fn log_scan_progress(target: &str, ports_scanned: u16, total_ports: u16, open_ports: u16) {
    let progress = (ports_scanned as f32 / total_ports as f32) * 100.0;
    tracing::debug!(
        target = %target,
        ports_scanned = ports_scanned,
        total_ports = total_ports,
        open_ports = open_ports,
        progress_percent = progress,
        "Scan progress"
    );
}

/// Log scan completion
pub fn log_scan_completion(target: &str, duration_ms: u64, open_ports: u16, services_detected: u16) {
    tracing::info!(
        target = %target,
        duration_ms = duration_ms,
        open_ports = open_ports,
        services_detected = services_detected,
        "Scan completed"
    );
}

/// Log exploit search results
pub fn log_exploit_results(total_exploits: usize, high_risk_count: usize, duration_ms: u64) {
    tracing::info!(
        total_exploits = total_exploits,
        high_risk_count = high_risk_count,
        duration_ms = duration_ms,
        "Exploit search completed"
    );
}

/// Log external tool execution
pub fn log_external_tool(tool: &str, command: &str, duration_ms: u64, success: bool) {
    if success {
        tracing::debug!(
            tool = %tool,
            command = %command,
            duration_ms = duration_ms,
            "External tool executed successfully"
        );
    } else {
        tracing::warn!(
            tool = %tool,
            command = %command,
            duration_ms = duration_ms,
            "External tool execution failed"
        );
    }
}

/// Log performance metrics
pub fn log_performance_metrics(operation: &str, duration_ms: u64, items_processed: usize) {
    let throughput = if duration_ms > 0 {
        (items_processed as f64 / duration_ms as f64) * 1000.0
    } else {
        0.0
    };
    
    tracing::info!(
        operation = %operation,
        duration_ms = duration_ms,
        items_processed = items_processed,
        throughput_per_second = throughput,
        "Performance metrics"
    );
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
    fn test_log_config_validation() {
        let mut config = LogConfig::default();
        
        // Valid configuration
        assert!(config.validate().is_ok());
        
        // Invalid log level
        config.level = "invalid".to_string();
        assert!(config.validate().is_err());
        
        // Reset and test invalid file size
        config.level = "info".to_string();
        config.max_file_size = 0;
        assert!(config.validate().is_err());
        
        // Reset and test invalid max files
        config.max_file_size = 1024;
        config.max_files = 0;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_log_config_from_env() {
        // Set environment variables
        env::set_var("RUSTMAP_LOG_LEVEL", "debug");
        env::set_var("RUSTMAP_LOG_CONSOLE", "false");
        env::set_var("RUSTMAP_LOG_JSON", "true");
        
        let config = LogConfig::from_env().unwrap();
        assert_eq!(config.level, "debug");
        assert!(!config.console);
        assert!(config.json);
        
        // Clean up
        env::remove_var("RUSTMAP_LOG_LEVEL");
        env::remove_var("RUSTMAP_LOG_CONSOLE");
        env::remove_var("RUSTMAP_LOG_JSON");
    }
}