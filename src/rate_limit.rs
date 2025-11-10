//! # Rate Limiting Configuration Module
//! 
//! This module provides rate limiting policy configuration for OxideScanner.
//! The actual rate limiting functionality is not used in the current implementation.

use crate::error::{OxideScannerError, Result};
use std::time::Duration;

/// Rate limiting policy configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitPolicy {
    /// Maximum number of operations per time period
    pub max_operations: u32,
    /// Time period for rate limiting
    pub period: Duration,
    /// Optional burst capacity (allows short bursts above the rate limit)
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
    
    /// Create a new rate limit policy with burst capacity
    pub fn with_burst(max_operations: u32, period: Duration, burst_capacity: u32) -> Self {
        Self {
            max_operations,
            period,
            burst_capacity: Some(burst_capacity),
        }
    }
    
    /// Convert policy to governor Quota
    /// 
    /// Returns a Quota for use with the governor rate limiter crate.
    fn to_quota(&self) -> Result<governor::Quota> {
        use governor::Quota;
        use std::num::NonZeroU32;
        
        let max_ops = NonZeroU32::new(self.max_operations)
            .ok_or_else(|| OxideScannerError::config("Rate limit max_operations must be greater than 0"))?;
        
        let quota = if let Some(burst) = self.burst_capacity {
            let _burst_ops = NonZeroU32::new(burst)
                .ok_or_else(|| OxideScannerError::config("Rate limit burst_capacity must be greater than 0"))?;
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
