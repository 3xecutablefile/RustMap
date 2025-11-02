//! # External Tool Integration
//! 
//! This module provides abstractions for executing external security tools
//! like nmap and searchsploit with proper timeout handling and error management.
//! It offers a unified interface for tool execution while maintaining flexibility
//! for tool-specific configurations.
//! 
//! ## Features
//! 
//! - Async tool execution with configurable timeouts
//! - Unified error handling for external processes
//! - Tool-specific implementations for nmap and searchsploit
//! - Safe command execution with input validation
//! - Structured output parsing and error reporting
//! 
//! ## Example
//! 
//! ```rust
//! use rustmap::external::{BaseTool, ExternalTool};
//! use std::time::Duration;
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let tool = BaseTool::new("echo")?;
//!     let output = tool.execute_command(&["hello"], Duration::from_secs(5)).await?;
//!     
//!     println!("Output: {}", String::from_utf8_lossy(&output.stdout));
//!     Ok(())
//! }
//! ```

pub mod nmap;
pub mod searchsploit;

use crate::error::{RustMapError, Result};
use async_trait::async_trait;
use std::process::Output;
use std::time::Duration;

/// Trait for external tool execution with timeout support
/// 
/// This trait defines a common interface for executing external security tools
/// with proper timeout handling and error management.
#[async_trait]
pub trait ExternalTool {
    /// Execute the tool with given arguments and timeout
    async fn execute_with_timeout(&self, args: &[&str], timeout: Duration) -> Result<Output>;
    

}

/// Base implementation for external tool execution
pub struct BaseTool {
    pub name: &'static str,
    pub binary_path: String,
}

impl BaseTool {
    pub fn new(name: &'static str) -> Result<Self> {
        let binary_path = Self::find_binary(name)?;
        Ok(Self { name, binary_path })
    }
    
    fn find_binary(name: &str) -> Result<String> {
        use std::process::Command;
        
        let output = Command::new("which").arg(name).output()
            .map_err(|e| RustMapError::external_tool("which", e.to_string()))?;
        
        if !output.status.success() {
            return Err(RustMapError::external_tool(
                name,
                "Tool not found in PATH".to_string()
            ));
        }
        
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if path.is_empty() {
            return Err(RustMapError::external_tool(
                name,
                "Tool path is empty".to_string()
            ));
        }
        
        Ok(path)
    }
    
    pub async fn execute_command(&self, args: &[&str], timeout_duration: Duration) -> Result<Output> {
        use tokio::process::Command;
        use tokio::time::timeout as tokio_timeout;
        
        let mut cmd = Command::new(&self.binary_path);
        cmd.args(args);
        
        let output = tokio_timeout(timeout_duration, cmd.output())
            .await
            .map_err(|_| RustMapError::timeout(timeout_duration.as_millis() as u64))?;
        
        let output = output
            .map_err(|e| RustMapError::external_tool(self.name, e.to_string()))?;
        
        Ok(output)
    }
}