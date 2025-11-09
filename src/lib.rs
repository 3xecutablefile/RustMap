//! # RustMap - Fast Port Scanner and Exploit Finder
//! 
//! RustMap is a high-performance network security tool written in Rust that combines
//! fast TCP port scanning with automatic exploit database lookups. It provides
//! parallel scanning capabilities, service detection, and risk assessment.
//! 
//! ## Features
//! 
//! - **Fast TCP Scanning**: Parallel port scanning using Rayon
//! - **Service Detection**: Banner grabbing and protocol fingerprinting
//! - **Exploit Integration**: Automatic searchsploit queries for detected services
//! - **Risk Assessment**: Heuristic scoring based on CVSS and service criticality
//! - **Multiple Output Formats**: Interactive terminal UI and JSON export
//! 
//! ## Quick Start
//! 
//! ```rust
//! use rustmap::config::Config;
//! use rustmap::scanner::fast_scan;
//! use rustmap::utils::resolve_target;
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::from_args(&[
//!         "rustmap".to_string(),
//!         "127.0.0.1".to_string(),
//!         "-1k".to_string(),
//!     ])?;
//!     
//!     let addrs = resolve_target(&config.target)?;
//!     let open_ports = fast_scan(&addrs, &config).await?;
//!     
//!     println!("Found {} open ports", open_ports.len());
//!     Ok(())
//! }
//! ```
//! 
//! ## Architecture
//! 
//! The library is organized into several modules:
//! 
//! - [`config`]: Command-line argument parsing and configuration management
//! - [`scanner`]: High-performance TCP port scanning and service detection
//! - [`exploit`]: Exploit database integration and risk assessment
//! - [`external`]: Abstractions for external tools (nmap, searchsploit)
//! - [`utils`]: Utility functions for networking, progress reporting, etc.
//! - [`validation`]: Input validation and sanitization
//! - [`error`]: Comprehensive error handling with custom error types
//! - [`constants`]: Configuration constants and risk scoring parameters

pub mod config;
pub mod constants;
pub mod error;
pub mod exploit;
pub mod external;
pub mod logging;
pub mod metrics;
pub mod rate_limit;
pub mod retry;
pub mod scanner;
pub mod shutdown;
pub mod utils;
pub mod validation;