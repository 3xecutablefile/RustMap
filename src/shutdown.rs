//! # Graceful Shutdown Module
//! 
//! This module provides graceful shutdown capabilities for RustMap, allowing
//! the application to clean up resources properly when receiving termination signals.
//! It handles SIGINT, SIGTERM, and supports timeout-based shutdown.
//! 
//! ## Features
//! 
//! - Signal handling for SIGINT and SIGTERM
//! - Configurable shutdown timeout
//! - Cleanup task registration
//! - Progress reporting during shutdown
//! - Force shutdown option for unresponsive operations
//! 
//! ## Example
//! 
//! ```rust
//! use rustmap::shutdown::{ShutdownManager, ShutdownSignal};
//! use tokio::time::{sleep, Duration};
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let shutdown = ShutdownManager::new(Duration::from_secs(30));
//!     
//!     // Register cleanup tasks
//!     shutdown.register_cleanup_task(async {
//!         println!("Cleaning up resources...");
//!         sleep(Duration::from_secs(2)).await;
//!         println!("Cleanup completed");
//!     });
//!     
//!     // Main application logic
//!     tokio::select! {
//!         _ = shutdown.wait_for_signal() => {
//!             println!("Received shutdown signal");
//!         }
//!         _ = async {
//!             // Your main application logic here
//!             sleep(Duration::from_secs(60)).await;
//!         } => {
//!             println!("Application completed normally");
//!         }
//!     }
//!     
//!     // Perform graceful shutdown
//!     shutdown.graceful_shutdown().await?;
//!     Ok(())
//! }
//! ```

use crate::error::{RustMapError, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Signal types that can trigger shutdown
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownSignal {
    /// SIGINT (Ctrl+C)
    SigInt,
    /// SIGTERM (termination signal)
    SigTerm,
    /// Internal shutdown request
    Internal,
}

impl std::fmt::Display for ShutdownSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownSignal::SigInt => write!(f, "SIGINT"),
            ShutdownSignal::SigTerm => write!(f, "SIGTERM"),
            ShutdownSignal::Internal => write!(f, "INTERNAL"),
        }
    }
}

/// Cleanup task that runs during shutdown
pub type CleanupTask = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'static>>;

/// Manages graceful shutdown operations
#[derive(Debug)]
pub struct ShutdownManager {
    /// Shutdown timeout duration
    timeout: Duration,
    /// Channel for receiving shutdown signals
    signal_rx: broadcast::Receiver<ShutdownSignal>,
    /// Channel for sending shutdown signals
    signal_tx: broadcast::Sender<ShutdownSignal>,
    /// Channel for cleanup tasks
    cleanup_tx: mpsc::Sender<CleanupTask>,
    /// Cleanup task receiver
    cleanup_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<CleanupTask>>>,
    /// Whether shutdown has been initiated
    shutdown_initiated: Arc<std::sync::atomic::AtomicBool>,
}

impl ShutdownManager {
    /// Create a new shutdown manager with the specified timeout
    pub fn new(timeout: Duration) -> Self {
        let (signal_tx, signal_rx) = broadcast::channel(10);
        let (cleanup_tx, cleanup_rx) = mpsc::channel(100);
        
        Self {
            timeout,
            signal_rx,
            signal_tx,
            cleanup_tx,
            cleanup_rx: Arc::new(tokio::sync::Mutex::new(cleanup_rx)),
            shutdown_initiated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
    
    /// Start listening for shutdown signals
    pub async fn start_signal_handler(&self) -> Result<()> {
        let signal_tx = self.signal_tx.clone();
        let shutdown_initiated = self.shutdown_initiated.clone();
        
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            
            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(sig) => sig,
                Err(e) => {
                    error!("Failed to setup SIGINT handler: {}", e);
                    return;
                }
            };
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(sig) => sig,
                Err(e) => {
                    error!("Failed to setup SIGTERM handler: {}", e);
                    return;
                }
            };
            
            loop {
                tokio::select! {
                    _ = sigint.recv() => {
                        if !shutdown_initiated.fetch_or(true, std::sync::atomic::Ordering::SeqCst) {
                            info!("Received SIGINT signal, initiating shutdown");
                            let _ = signal_tx.send(ShutdownSignal::SigInt);
                            break;
                        }
                    }
                    _ = sigterm.recv() => {
                        if !shutdown_initiated.fetch_or(true, std::sync::atomic::Ordering::SeqCst) {
                            info!("Received SIGTERM signal, initiating shutdown");
                            let _ = signal_tx.send(ShutdownSignal::SigTerm);
                            break;
                        }
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Wait for a shutdown signal
    pub async fn wait_for_signal(&mut self) -> ShutdownSignal {
        match self.signal_rx.recv().await {
            Ok(signal) => signal,
            Err(_) => ShutdownSignal::Internal, // Channel closed
        }
    }
    
    /// Register a cleanup task to run during shutdown
    pub async fn register_cleanup_task(&self, task: CleanupTask) -> Result<()> {
        self.cleanup_tx.send(task).await
            .map_err(|_| RustMapError::config("Failed to register cleanup task"))?;
        Ok(())
    }
    
    /// Initiate shutdown from within the application
    pub fn initiate_shutdown(&self) -> Result<()> {
        if !self.shutdown_initiated.fetch_or(true, std::sync::atomic::Ordering::SeqCst) {
            info!("Initiating internal shutdown");
            let _ = self.signal_tx.send(ShutdownSignal::Internal);
        }
        Ok(())
    }
    
    /// Check if shutdown has been initiated
    pub fn is_shutdown_initiated(&self) -> bool {
        self.shutdown_initiated.load(std::sync::atomic::Ordering::SeqCst)
    }
    
    /// Perform graceful shutdown with timeout
    pub async fn graceful_shutdown(&self) -> Result<()> {
        info!("Starting graceful shutdown (timeout: {:?})", self.timeout);
        
        let cleanup_rx = self.cleanup_rx.clone();
        let timeout_duration = self.timeout;
        
        match timeout(timeout_duration, async {
            let mut cleanup_rx = cleanup_rx.lock().await;
            let mut task_count = 0;
            
            while let Some(task) = cleanup_rx.recv().await {
                task_count += 1;
                debug!("Executing cleanup task {}/?", task_count);
                
                match task.await {
                    Ok(_) => debug!("Cleanup task {} completed successfully", task_count),
                    Err(e) => warn!("Cleanup task {} failed: {}", task_count, e),
                }
            }
            
            info!("All cleanup tasks completed");
            Ok::<(), RustMapError>(())
        }).await {
            Ok(result) => {
                result?;
                info!("Graceful shutdown completed successfully");
                Ok(())
            }
            Err(_) => {
                error!("Graceful shutdown timed out after {:?}", timeout_duration);
                Err(RustMapError::timeout(timeout_duration.as_millis() as u64))
            }
        }
    }
    
    /// Force immediate shutdown without waiting for cleanup tasks
    pub fn force_shutdown(&self) {
        warn!("Force shutdown initiated");
        std::process::exit(1);
    }
}

/// A handle to the shutdown manager for checking shutdown status
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    shutdown_initiated: Arc<std::sync::atomic::AtomicBool>,
}

impl ShutdownHandle {
    /// Create a new shutdown handle
    pub fn new(shutdown_initiated: Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self { shutdown_initiated }
    }
    
    /// Check if shutdown has been initiated
    pub fn is_shutdown_initiated(&self) -> bool {
        self.shutdown_initiated.load(std::sync::atomic::Ordering::SeqCst)
    }
    
    /// Create a future that resolves when shutdown is initiated
    pub async fn wait_for_shutdown(&self) {
        while !self.is_shutdown_initiated() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl ShutdownManager {
    /// Create a shutdown handle for checking status
    pub fn handle(&self) -> ShutdownHandle {
        ShutdownHandle::new(self.shutdown_initiated.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_shutdown_manager_creation() {
        let manager = ShutdownManager::new(Duration::from_secs(5));
        assert!(!manager.is_shutdown_initiated());
    }
    
    #[tokio::test]
    async fn test_shutdown_initiation() {
        let manager = ShutdownManager::new(Duration::from_secs(5));
        
        manager.initiate_shutdown().unwrap();
        assert!(manager.is_shutdown_initiated());
    }
    
    #[tokio::test]
    async fn test_cleanup_task_registration() {
        let manager = ShutdownManager::new(Duration::from_secs(5));
        
        let task: CleanupTask = Box::new(async {
            sleep(Duration::from_millis(100)).await;
            Ok(())
        });
        
        manager.register_cleanup_task(task).await.unwrap();
    }
    
    #[tokio::test]
    async fn test_graceful_shutdown() {
        let manager = ShutdownManager::new(Duration::from_secs(2));
        
        // Register a cleanup task
let task: CleanupTask = Box::new(async {
            sleep(Duration::from_millis(100)).await;
            Ok(())
        });
        
        manager.register_cleanup_task(task).await.unwrap();
        
        // Perform graceful shutdown
        let result = manager.graceful_shutdown().await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_shutdown_timeout() {
        let manager = ShutdownManager::new(Duration::from_millis(100));
        
        // Register a long-running cleanup task
let task: CleanupTask = Box::new(async {
            sleep(Duration::from_millis(100)).await;
            Ok(())
        });
        
        manager.register_cleanup_task(task).await.unwrap();
        
        // Perform graceful shutdown (should timeout)
        let result = manager.graceful_shutdown().await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_shutdown_handle() {
        let manager = ShutdownManager::new(Duration::from_secs(5));
        let handle = manager.handle();
        
        assert!(!handle.is_shutdown_initiated());
        
        manager.initiate_shutdown().unwrap();
        assert!(handle.is_shutdown_initiated());
    }
}