//! # Rate Limiting Module
//! 
//! This module provides rate limiting capabilities to prevent overwhelming
//! target networks and external services. It uses the governor crate for
//! token bucket rate limiting with configurable policies.
//! 
//! ## Features
//! 
//! - Token bucket rate limiting
//! - Configurable policies per operation type
//! - Per-target rate limiting
//! - Burst capacity handling
//! - Dynamic rate limit adjustment
//! 
//! ## Example
//! 
//! ```rust
//! use rustmap::rate_limit::{RateLimiter, RateLimitPolicy};
//! use std::time::Duration;
//! 
//! // Create a rate limiter for scanning
//! let policy = RateLimitPolicy::new(100, Duration::from_secs(1)); // 100 ops/sec
//! let limiter = RateLimiter::new(policy);
//! 
//! // Check if operation is allowed
//! if limiter.check_rate_limit("target1").await {
//!     // Perform operation
//! } else {
//!     // Rate limited, wait or skip
//! }
//! ```

use crate::error::{RustMapError, Result};
use rand::Rng;
use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovernorRateLimiter,
};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

/// Rate limiting policy configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitPolicy {
    /// Maximum number of operations per time period
    pub max_operations: u32,
    /// Time period for the rate limit
    pub period: Duration,
    /// Burst capacity (optional, defaults to max_operations)
    pub burst_capacity: Option<u32>,
}

impl RateLimitPolicy {
    /// Create a new rate limit policy
    pub fn new(max_operations: u32, period: Duration) -> Self {
        Self {
            max_operations,
            period,
            burst_capacity: None,
        }
    }
    
    /// Create a policy with burst capacity
    pub fn with_burst(max_operations: u32, period: Duration, burst_capacity: u32) -> Self {
        Self {
            max_operations,
            period,
            burst_capacity: Some(burst_capacity),
        }
    }
    
    /// Convert to governor Quota
    fn to_quota(&self) -> Result<Quota> {
        let max_ops = NonZeroU32::new(self.max_operations)
            .ok_or_else(|| RustMapError::config("Rate limit max_operations must be greater than 0"))?;
        
        let quota = if let Some(burst) = self.burst_capacity {
            let burst_ops = NonZeroU32::new(burst)
                .ok_or_else(|| RustMapError::config("Rate limit burst_capacity must be greater than 0"))?;
            Quota::with_period(self.period)
                .unwrap()
                .allow_burst(max_ops)
        } else {
            Quota::with_period(self.period)
                .unwrap()
                .allow_burst(max_ops)
        };
        
        Ok(quota)
    }
}

/// Default rate limiting policies
pub mod policies {
    use super::*;
    
    /// Conservative policy for sensitive targets
    pub fn conservative() -> RateLimitPolicy {
        RateLimitPolicy::new(10, Duration::from_secs(1))
    }
    
    /// Standard policy for general scanning
    pub fn standard() -> RateLimitPolicy {
        RateLimitPolicy::new(50, Duration::from_secs(1))
    }
    
    /// Aggressive policy for high-performance scanning
    pub fn aggressive() -> RateLimitPolicy {
        RateLimitPolicy::new(200, Duration::from_secs(1))
    }
    
    /// Policy for external tool calls
    pub fn external_tools() -> RateLimitPolicy {
        RateLimitPolicy::new(5, Duration::from_secs(1))
    }
    
    /// Policy for exploit database queries
    pub fn exploit_queries() -> RateLimitPolicy {
        RateLimitPolicy::new(2, Duration::from_secs(1))
    }
}

/// Rate limiter implementation
#[derive(Debug)]
pub struct RateLimiter {
    /// Global rate limiter for all operations
    global_limiter: Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>>,
    /// Per-target rate limiters
    target_limiters: Arc<DashMap<String, Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>>>>,
    /// Rate limit policy
    policy: RateLimitPolicy,
}

impl RateLimiter {
    /// Create a new rate limiter with the given policy
    pub fn new(policy: RateLimitPolicy) -> Result<Self> {
        let quota = policy.to_quota()?;
        let global_limiter = Arc::new(GovernorRateLimiter::direct(quota));
        
        Ok(Self {
            global_limiter,
            target_limiters: Arc::new(DashMap::new()),
            policy,
        })
    }
    
    /// Create a rate limiter with a standard policy
    pub fn standard() -> Result<Self> {
        Self::new(policies::standard())
    }
    
    /// Create a rate limiter with a conservative policy
    pub fn conservative() -> Result<Self> {
        Self::new(policies::conservative())
    }
    
    /// Create a rate limiter with an aggressive policy
    pub fn aggressive() -> Result<Self> {
        Self::new(policies::aggressive())
    }
    
    /// Check if an operation is allowed for a specific target
    pub async fn check_rate_limit(&self, target: &str) -> bool {
        // Check global rate limit first
        if !self.global_limiter.check().is_ok() {
            debug!("Global rate limit exceeded");
            return false;
        }
        
        // Get or create per-target limiter
        let target_limiter = self.target_limiters
            .entry(target.to_string())
            .or_try_insert_with(|| {
                let quota = self.policy.to_quota()?;
                Ok(Arc::new(GovernorRateLimiter::direct(quota)))
            })
            .unwrap_or_else(|_| {
                // Fallback to global limiter if per-target creation fails
                drop(entry);
                return self.global_limiter.check();
            });
        
        // Check per-target rate limit
        if !target_limiter.check().is_ok() {
            debug!("Rate limit exceeded for target: {}", target);
            return false;
        }
        
        true
    }
    
    /// Wait until operation is allowed (with timeout)
    pub async fn wait_for_rate_limit(&self, target: &str, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        
        while start.elapsed() < timeout {
            if self.check_rate_limit(target).await {
                return Ok(());
            }
            
            // Add jitter to avoid thundering herd
            let jitter = rand::thread_rng().gen_range(0..=10);
            tokio::time::sleep(Duration::from_millis(jitter)).await;
        }
        
        warn!("Rate limit wait timeout for target: {}", target);
        Err(RustMapError::timeout(timeout.as_millis() as u64))
    }
    
    /// Get the current rate limit status
    pub fn get_status(&self) -> RateLimitStatus {
        RateLimitStatus {
            policy: self.policy.clone(),
            global_available: self.global_limiter.check().map_or(0, |_| 1),
            target_count: self.target_limiters.len(),
        }
    }
    
    /// Update the rate limit policy
    pub fn update_policy(&mut self, policy: RateLimitPolicy) -> Result<()> {
        self.policy = policy;
        let quota = self.policy.to_quota()?;
        self.global_limiter = Arc::new(GovernorRateLimiter::direct(quota));
        
        // Clear existing target limiters to force recreation with new policy
        self.target_limiters.clear();
        
        Ok(())
    }
}

/// Rate limit status information
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    /// Current rate limit policy
    pub policy: RateLimitPolicy,
    /// Number of available permits in global limiter
    pub global_available: u32,
    /// Number of per-target limiters
    pub target_count: usize,
}

/// Multi-policy rate limiter for different operation types
#[derive(Debug)]
pub struct MultiPolicyRateLimiter {
    /// Scanner rate limiter
    scanner: Arc<RateLimiter>,
    /// External tools rate limiter
    external_tools: Arc<RateLimiter>,
    /// Exploit queries rate limiter
    exploit_queries: Arc<RateLimiter>,
}

impl MultiPolicyRateLimiter {
    /// Create a new multi-policy rate limiter with default policies
    pub fn new() -> Result<Self> {
        Ok(Self {
            scanner: Arc::new(RateLimiter::standard()?),
            external_tools: Arc::new(RateLimiter::conservative()?),
            exploit_queries: Arc::new(RateLimiter::new(policies::exploit_queries())?),
        })
    }
    
    /// Create with custom policies
    pub fn with_policies(
        scanner_policy: RateLimitPolicy,
        external_tools_policy: RateLimitPolicy,
        exploit_queries_policy: RateLimitPolicy,
    ) -> Result<Self> {
        Ok(Self {
            scanner: Arc::new(RateLimiter::new(scanner_policy)?),
            external_tools: Arc::new(RateLimiter::new(external_tools_policy)?),
            exploit_queries: Arc::new(RateLimiter::new(exploit_queries_policy)?),
        })
    }
    
    /// Check scanner rate limit
    pub async fn check_scanner(&self, target: &str) -> bool {
        self.scanner.check_rate_limit(target).await
    }
    
    /// Check external tools rate limit
    pub async fn check_external_tools(&self, target: &str) -> bool {
        self.external_tools.check_rate_limit(target).await
    }
    
    /// Check exploit queries rate limit
    pub async fn check_exploit_queries(&self, target: &str) -> bool {
        self.exploit_queries.check_rate_limit(target).await
    }
    
    /// Wait for scanner rate limit
    pub async fn wait_for_scanner(&self, target: &str, timeout: Duration) -> Result<()> {
        self.scanner.wait_for_rate_limit(target, timeout).await
    }
    
    /// Wait for external tools rate limit
    pub async fn wait_for_external_tools(&self, target: &str, timeout: Duration) -> Result<()> {
        self.external_tools.wait_for_rate_limit(target, timeout).await
    }
    
    /// Wait for exploit queries rate limit
    pub async fn wait_for_exploit_queries(&self, target: &str, timeout: Duration) -> Result<()> {
        self.exploit_queries.wait_for_rate_limit(target, timeout).await
    }
    
    /// Get status for all limiters
    pub fn get_all_status(&self) -> MultiPolicyStatus {
        MultiPolicyStatus {
            scanner: self.scanner.get_status(),
            external_tools: self.external_tools.get_status(),
            exploit_queries: self.exploit_queries.get_status(),
        }
    }
}

/// Status for multi-policy rate limiter
#[derive(Debug, Clone)]
pub struct MultiPolicyStatus {
    pub scanner: RateLimitStatus,
    pub external_tools: RateLimitStatus,
    pub exploit_queries: RateLimitStatus,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rate_limit_policy_creation() {
        let policy = RateLimitPolicy::new(100, Duration::from_secs(1));
        assert_eq!(policy.max_operations, 100);
        assert_eq!(policy.period, Duration::from_secs(1));
        assert!(policy.burst_capacity.is_none());
    }
    
    #[test]
    fn test_rate_limit_policy_with_burst() {
        let policy = RateLimitPolicy::with_burst(100, Duration::from_secs(1), 200);
        assert_eq!(policy.max_operations, 100);
        assert_eq!(policy.burst_capacity, Some(200));
    }
    
    #[test]
    fn test_policies() {
        let conservative = policies::conservative();
        assert_eq!(conservative.max_operations, 10);
        
        let standard = policies::standard();
        assert_eq!(standard.max_operations, 50);
        
        let aggressive = policies::aggressive();
        assert_eq!(aggressive.max_operations, 200);
    }
    
    #[tokio::test]
    async fn test_rate_limiter_creation() {
        let policy = RateLimitPolicy::new(10, Duration::from_secs(1));
        let limiter = RateLimiter::new(policy);
        assert!(limiter.is_ok());
    }
    
    #[tokio::test]
    async fn test_rate_limiter_check() {
        let limiter = RateLimiter::standard().unwrap();
        assert!(limiter.check_rate_limit("test").await);
    }
    
    #[tokio::test]
    async fn test_multi_policy_rate_limiter() {
        let multi = MultiPolicyRateLimiter::new();
        assert!(multi.is_ok());
        
        let multi = multi.unwrap();
        assert!(multi.check_scanner("test").await);
        assert!(multi.check_external_tools("test").await);
        assert!(multi.check_exploit_queries("test").await);
    }
}