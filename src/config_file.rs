use crate::error::{OxideScannerError, Result};
use crate::rate_limit::RateLimitPolicy;
use crate::retry::RetryConfig;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Configuration structure for serialization/deserialization in config files
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigFile {
    // Basic settings
    pub target: Option<String>,
    pub json_mode: Option<bool>,
    pub port_limit: Option<u16>,
    pub port_start: Option<u16>,
    pub port_end: Option<u16>,
    
    // Timeouts
    pub scan_timeout_ms: Option<u64>,
    pub exploit_timeout_ms: Option<u64>,
    pub shutdown_timeout_secs: Option<u64>,
    
    // Threading
    pub threads: Option<usize>,
    
    // Features
    pub enable_rate_limiting: Option<bool>,
    
    // Rate limiting policies
    pub scanner_rate_limit: Option<RateLimitPolicyFile>,
    pub external_tools_rate_limit: Option<RateLimitPolicyFile>,
    pub exploit_queries_rate_limit: Option<RateLimitPolicyFile>,
    
    // Retry configuration
    pub retry: Option<RetryConfigFile>,

    // Output settings
    pub output_file: Option<String>,
}

/// Rate limit policy for config file serialization
#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitPolicyFile {
    pub max_operations: u32,
    pub period_secs: u64,
    pub burst_capacity: Option<u32>,
}

/// Retry config for config file serialization
#[derive(Debug, Serialize, Deserialize)]
pub struct RetryConfigFile {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
    pub jitter_factor: f64,
}

impl From<RateLimitPolicyFile> for RateLimitPolicy {
    fn from(policy_file: RateLimitPolicyFile) -> Self {
        let period = std::time::Duration::from_secs(policy_file.period_secs);
        let mut policy = RateLimitPolicy::new(policy_file.max_operations, period);
        if let Some(burst) = policy_file.burst_capacity {
            policy = RateLimitPolicy::with_burst(policy_file.max_operations, period, burst);
        }
        policy
    }
}

impl From<RetryConfigFile> for RetryConfig {
    fn from(retry_file: RetryConfigFile) -> Self {
        RetryConfig::new(
            retry_file.max_retries,
            std::time::Duration::from_millis(retry_file.base_delay_ms),
            std::time::Duration::from_millis(retry_file.max_delay_ms),
        )
        .with_backoff_multiplier(retry_file.backoff_multiplier)
        .with_jitter_factor(retry_file.jitter_factor)
    }
}

impl From<RateLimitPolicy> for RateLimitPolicyFile {
    fn from(policy: RateLimitPolicy) -> Self {
        RateLimitPolicyFile {
            max_operations: policy.max_operations,
            period_secs: policy.period.as_secs(),
            burst_capacity: policy.burst_capacity,
        }
    }
}

impl From<RetryConfig> for RetryConfigFile {
    fn from(retry: RetryConfig) -> Self {
        RetryConfigFile {
            max_retries: retry.max_retries,
            base_delay_ms: retry.base_delay.as_millis() as u64,
            max_delay_ms: retry.max_delay.as_millis() as u64,
            backoff_multiplier: retry.backoff_multiplier,
            jitter_factor: retry.jitter_factor,
        }
    }
}

impl ConfigFile {
    /// Load configuration from a file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| OxideScannerError::Io(e))?;
            
        toml::from_str(&content)
            .map_err(|e| OxideScannerError::parse(format!("Failed to parse config file: {}", e)))
    }
    
    /// Save configuration to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| OxideScannerError::parse(format!("Failed to serialize config: {}", e)))?;
            
        fs::write(path, content)
            .map_err(|e| OxideScannerError::Io(e))?;
            
        Ok(())
    }
    
    /// Create a default configuration file structure
    pub fn default_config() -> Self {
        Self {
            target: None,
            json_mode: Some(false),
            port_limit: Some(1000),
            port_start: None,
            port_end: None,
            scan_timeout_ms: Some(25),
            exploit_timeout_ms: Some(10000),
            shutdown_timeout_secs: Some(30),
            threads: Some(0),
            enable_rate_limiting: Some(true),
            scanner_rate_limit: Some(RateLimitPolicyFile {
                max_operations: 50,
                period_secs: 1,
                burst_capacity: Some(50),
            }),
            external_tools_rate_limit: Some(RateLimitPolicyFile {
                max_operations: 5,
                period_secs: 1,
                burst_capacity: Some(5),
            }),
            exploit_queries_rate_limit: Some(RateLimitPolicyFile {
                max_operations: 2,
                period_secs: 1,
                burst_capacity: Some(2),
            }),
            retry: Some(RetryConfigFile {
                max_retries: 3,
                base_delay_ms: 100,
                max_delay_ms: 5000,
                backoff_multiplier: 2.0,
                jitter_factor: 0.1,
            }),
            output_file: None,
        }
    }
}