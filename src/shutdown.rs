//! # Shutdown Configuration Module
//! 
//! This module provides shutdown timeout configuration for OxideScanner.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Shutdown configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownConfig {
    /// Shutdown timeout duration
    pub timeout: Duration,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }
}

impl ShutdownConfig {
    /// Create a new shutdown configuration
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}
