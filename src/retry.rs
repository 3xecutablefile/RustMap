//! # Retry Mechanism Module
//! 
//! This module provides configurable retry mechanisms for external tool calls
//! and network operations. It supports exponential backoff, jitter, and
//! different retry strategies for different operation types.
//! 
//! ## Features
//! 
//! - Exponential backoff with jitter
//! - Configurable retry policies
//! - Operation-specific retry strategies
//! - Retry condition evaluation
//! - Maximum retry limits
//! - Retry delay calculation
//! 
//! ## Example
//! 
//! ```rust
//! use rustmap::retry::{RetryConfig, RetryPolicy, RetryExecutor};
//! use std::time::Duration;
//! 
//! let config = RetryConfig::default();
//! let executor = RetryExecutor::new(config);
//! 
//! let result = executor.execute_with_retry(
//!     || async {
//!         // Your operation here
//!         Ok::<_, std::io::Error>("success")
//!     },
//!     RetryPolicy::default(),
//! ).await?;
//! ```

use crate::error::{RustMapError, Result};
use rand::Rng;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tracing::{debug, warn};

/// Retry configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Base delay between retries
    pub base_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
    /// Jitter factor (0.0 = no jitter, 1.0 = full jitter)
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(1000),
            max_delay: Duration::from_millis(30000),
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }
}

impl RetryConfig {
    /// Create retry configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let max_retries = if let Ok(retries) = std::env::var("RUSTMAP_RETRY_MAX") {
            retries.parse::<u32>()
                .map_err(|_| RustMapError::config("Invalid RUSTMAP_RETRY_MAX value"))?
        } else {
            3
        };
        
        let base_delay = if let Ok(delay) = std::env::var("RUSTMAP_RETRY_BASE_DELAY") {
            let ms = delay.parse::<u64>()
                .map_err(|_| RustMapError::config("Invalid RUSTMAP_RETRY_BASE_DELAY value"))?;
            Duration::from_millis(ms)
        } else {
            Duration::from_millis(1000)
        };
        
        let max_delay = if let Ok(delay) = std::env::var("RUSTMAP_RETRY_MAX_DELAY") {
            let ms = delay.parse::<u64>()
                .map_err(|_| RustMapError::config("Invalid RUSTMAP_RETRY_MAX_DELAY value"))?;
            Duration::from_millis(ms)
        } else {
            Duration::from_millis(30000)
        };
        
        let backoff_multiplier = if let Ok(multiplier) = std::env::var("RUSTMAP_RETRY_BACKOFF_MULTIPLIER") {
            multiplier.parse::<f64>()
                .map_err(|_| RustMapError::config("Invalid RUSTMAP_RETRY_BACKOFF_MULTIPLIER value"))?
        } else {
            2.0
        };
        
        Ok(Self {
            max_retries,
            base_delay,
            max_delay,
            backoff_multiplier,
            jitter_factor: 0.1,
        })
    }
    
    
}

impl RetryConfig {
    /// Create a new retry configuration
    pub fn new(max_retries: u32, base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_retries,
            base_delay,
            max_delay,
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }
    
    /// Set the backoff multiplier
    pub fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }
    
    /// Set the jitter factor
    pub fn with_jitter_factor(mut self, factor: f64) -> Self {
        self.jitter_factor = factor.clamp(0.0, 1.0);
        self
    }
    
    /// Calculate delay for a specific retry attempt
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        
        // Calculate exponential backoff
        let delay_ms = self.base_delay.as_millis() as f64 * self.backoff_multiplier.powi(attempt as i32 - 1);
        let delay_ms = delay_ms.min(self.max_delay.as_millis() as f64);
        
        // Add jitter
        let jitter_range = delay_ms * self.jitter_factor;
        let jitter = rand::thread_rng().gen_range(-jitter_range..=jitter_range);
        let final_delay_ms = (delay_ms + jitter).max(0.0) as u64;
        
        Duration::from_millis(final_delay_ms)
    }
}

/// Retry policy for different operation types
#[derive(Debug, Clone)]
pub enum RetryPolicy {
    /// No retries
    None,
    /// Conservative retry policy (few retries, longer delays)
    Conservative,
    /// Standard retry policy (balanced)
    Standard,
    /// Aggressive retry policy (more retries, shorter delays)
    Aggressive,
    /// Custom policy with specific configuration
    Custom(RetryConfig),
}

impl RetryPolicy {
    /// Get the retry configuration for this policy
    pub fn config(&self) -> RetryConfig {
        match self {
            RetryPolicy::None => RetryConfig {
                max_retries: 0,
                base_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
                backoff_multiplier: 1.0,
                jitter_factor: 0.0,
            },
            RetryPolicy::Conservative => RetryConfig {
                max_retries: 2,
                base_delay: Duration::from_secs(2),
                max_delay: Duration::from_secs(60),
                backoff_multiplier: 3.0,
                jitter_factor: 0.2,
            },
            RetryPolicy::Standard => RetryConfig::default(),
            RetryPolicy::Aggressive => RetryConfig {
                max_retries: 5,
                base_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(10),
                backoff_multiplier: 1.5,
                jitter_factor: 0.1,
            },
            RetryPolicy::Custom(config) => config.clone(),
        }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::Standard
    }
}

/// Retry condition evaluator
pub trait RetryCondition: Send + Sync {
    /// Determine if the operation should be retried based on the error
    fn should_retry(&self, error: &RustMapError, attempt: u32) -> bool;
}

/// Default retry condition that retries on most errors
#[derive(Debug, Clone)]
pub struct DefaultRetryCondition;

impl RetryCondition for DefaultRetryCondition {
    fn should_retry(&self, error: &RustMapError, attempt: u32) -> bool {
        match error {
            // Don't retry on configuration errors
            RustMapError::Config(_) => false,
            RustMapError::Validation(_) => false,
            RustMapError::Parse(_) => false,
            
            // Retry on network and timeout errors
            RustMapError::Io(_) => true,
            RustMapError::Timeout { .. } => true,
            RustMapError::ExternalTool { .. } => true,
            RustMapError::ServiceDetection(_) => true,
            RustMapError::ExploitSearch(_) => true,
            RustMapError::TargetResolution(_) => true,
        }
    }
}

/// Retry condition for external tool calls
#[derive(Debug, Clone)]
pub struct ExternalToolRetryCondition;

impl RetryCondition for ExternalToolRetryCondition {
    fn should_retry(&self, error: &RustMapError, attempt: u32) -> bool {
        match error {
            // Retry on external tool failures and timeouts
            RustMapError::ExternalTool { .. } => true,
            RustMapError::Timeout { .. } => true,
            RustMapError::Io(_) => true,
            
            // Don't retry on other errors
            _ => false,
        }
    }
}

/// Retry condition for network operations
#[derive(Debug, Clone)]
pub struct NetworkRetryCondition;

impl RetryCondition for NetworkRetryCondition {
    fn should_retry(&self, error: &RustMapError, attempt: u32) -> bool {
        match error {
            // Retry on network-related errors
            RustMapError::Io(_) => true,
            RustMapError::Timeout { .. } => true,
            RustMapError::TargetResolution(_) => true,
            
            // Don't retry on other errors
            _ => false,
        }
    }
}

/// Retry executor
#[derive(Debug)]
pub struct RetryExecutor {
    config: RetryConfig,
}

impl RetryExecutor {
    /// Create a new retry executor
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }
    
    /// Create a retry executor with a policy
    pub fn with_policy(policy: RetryPolicy) -> Self {
        Self::new(policy.config())
    }
    
    /// Execute an operation with retry logic
    pub async fn execute_with_retry<F, T, E>(
        &self,
        operation: F,
        policy: RetryPolicy,
    ) -> Result<T>
    where
        F: Fn() -> Pin<Box<dyn Future<Output = Result<T>> + Send>>,
        E: Into<RustMapError>,
    {
        let config = policy.config();
        let condition = DefaultRetryCondition;
        
        for attempt in 0..=config.max_retries {
            match operation().await {
                Ok(result) => {
                    if attempt > 0 {
                        debug!("Operation succeeded on attempt {}", attempt + 1);
                    }
                    return Ok(result);
                }
                Err(error) => {
                    if attempt >= config.max_retries || !condition.should_retry(&error, attempt) {
                        warn!("Operation failed after {} attempts: {}", attempt + 1, error);
                        return Err(error);
                    }
                    
                    let delay = config.calculate_delay(attempt + 1);
                    debug!("Operation failed on attempt {}, retrying in {:?}: {}", attempt + 1, delay, error);
                    tokio::time::sleep(delay).await;
                }
            }
        }
        
        unreachable!("Loop should have returned")
    }
    
    /// Execute an operation with custom retry condition
    pub async fn execute_with_condition<F, C, T>(
        &self,
        operation: F,
        condition: C,
    ) -> Result<T>
    where
        F: Fn() -> Pin<Box<dyn Future<Output = Result<T>> + Send>>,
        C: RetryCondition,
    {
        for attempt in 0..=self.config.max_retries {
            match operation().await {
                Ok(result) => {
                    if attempt > 0 {
                        debug!("Operation succeeded on attempt {}", attempt + 1);
                    }
                    return Ok(result);
                }
                Err(error) => {
                    if attempt >= self.config.max_retries || !condition.should_retry(&error, attempt) {
                        warn!("Operation failed after {} attempts: {}", attempt + 1, error);
                        return Err(error);
                    }
                    
                    let delay = self.config.calculate_delay(attempt + 1);
                    debug!("Operation failed on attempt {}, retrying in {:?}: {}", attempt + 1, delay, error);
                    tokio::time::sleep(delay).await;
                }
            }
        }
        
        unreachable!("Loop should have returned")
    }
}

/// Convenience functions for common retry scenarios
pub mod retry_policies {
    use super::*;
    
    /// Get retry policy for external tool calls
    pub fn external_tools() -> RetryPolicy {
        RetryPolicy::Conservative
    }
    
    /// Get retry policy for network operations
    pub fn network_operations() -> RetryPolicy {
        RetryPolicy::Standard
    }
    
    /// Get retry policy for exploit database queries
    pub fn exploit_queries() -> RetryPolicy {
        RetryPolicy::Aggressive
    }
    
    /// Get retry policy for service detection
    pub fn service_detection() -> RetryPolicy {
        RetryPolicy::Standard
    }
}

/// Macro for easy retry execution
#[macro_export]
macro_rules! retry_async {
    ($executor:expr, $policy:expr, $operation:expr) => {
        $executor.execute_with_retry(
            || Box::pin(async move { $operation }),
            $policy,
        ).await
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_retry_config_creation() {
        let config = RetryConfig::new(5, Duration::from_millis(500), Duration::from_secs(10));
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.base_delay, Duration::from_millis(500));
        assert_eq!(config.max_delay, Duration::from_secs(10));
    }
    
    #[test]
    fn test_retry_config_delay_calculation() {
        let config = RetryConfig::new(3, Duration::from_millis(100), Duration::from_secs(1));
        
        // First attempt should have no delay
        assert_eq!(config.calculate_delay(0), Duration::ZERO);
        
        // Subsequent attempts should have increasing delays
        let delay1 = config.calculate_delay(1);
        let delay2 = config.calculate_delay(2);
        let delay3 = config.calculate_delay(3);
        
        assert!(delay1 > Duration::ZERO);
        assert!(delay2 > delay1);
        assert!(delay3 > delay2);
        
        // Should not exceed max delay
        assert!(delay3 <= Duration::from_secs(1));
    }
    
    #[test]
    fn test_retry_policy_configs() {
        let none_config = RetryPolicy::None.config();
        assert_eq!(none_config.max_retries, 0);
        
        let conservative_config = RetryPolicy::Conservative.config();
        assert_eq!(conservative_config.max_retries, 2);
        assert!(conservative_config.base_delay >= Duration::from_secs(2));
        
        let standard_config = RetryPolicy::Standard.config();
        assert_eq!(standard_config.max_retries, 3);
        
        let aggressive_config = RetryPolicy::Aggressive.config();
        assert_eq!(aggressive_config.max_retries, 5);
    }
    
    #[test]
    fn test_default_retry_condition() {
        let condition = DefaultRetryCondition;
        
        // Should retry on IO errors
        let io_error = RustMapError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
        assert!(condition.should_retry(&io_error, 1));
        
        // Should not retry on config errors
        let config_error = RustMapError::config("invalid config");
        assert!(!condition.should_retry(&config_error, 1));
    }
    
    #[tokio::test]
    async fn test_retry_executor_success() {
        let config = RetryConfig::new(3, Duration::from_millis(10), Duration::from_millis(100));
        let executor = RetryExecutor::new(config);
        
        let call_count = std::sync::atomic::AtomicU32::new(0);
        let result = executor.execute_with_retry(
            || {
                Box::pin(async move {
                    call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let current = call_count.load(std::sync::atomic::Ordering::SeqCst);
                    if current < 3 {
                        Err(RustMapError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")))
                    } else {
                        Ok("success")
                    }
                })
            },
            RetryPolicy::Standard,
        ).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }
    
    #[tokio::test]
    async fn test_retry_executor_with_retries() {
        let config = RetryConfig::new(3, Duration::from_millis(10), Duration::from_millis(100));
        let executor = RetryExecutor::new(config);
        
        let call_count = std::sync::atomic::AtomicU32::new(0);
        let result = executor.execute_with_retry::<_, String, _>(
            || {
                Box::pin(async move {
                    call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let current = call_count.load(std::sync::atomic::Ordering::SeqCst);
                    if current < 3 {
                        Err(RustMapError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")))
                    } else {
                        Ok("success")
                    }
                })
            },
            RetryPolicy::Standard,
        ).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 3);
    }
    
    #[tokio::test]
    async fn test_retry_executor_exhausted() {
        let config = RetryConfig::new(2, Duration::from_millis(10), Duration::from_millis(100));
        let executor = RetryExecutor::new(config);
        
        let call_count = std::sync::atomic::AtomicU32::new(0);
        let result = executor.execute_with_retry::<_, String, _>(
            || {
                Box::pin(async move {
                    call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let current = call_count.load(std::sync::atomic::Ordering::SeqCst);
                    if current < 3 {
                        Err(RustMapError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")))
                    } else {
                        Ok("success".to_string())
                    }
                })
            },
            RetryPolicy::Standard,
        ).await;
        
        assert!(result.is_err());
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 3); // Initial + 2 retries
    }
}