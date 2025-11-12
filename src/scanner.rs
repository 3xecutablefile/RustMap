//! # High-Performance Port Scanner
//!
//! This module provides fast TCP port scanning capabilities with service detection.
//! It uses parallel processing to scan multiple ports simultaneously and integrates
//! with external tools like nmap for advanced service fingerprinting.
//!
//! ## Features
//!
//! - Parallel TCP connect scanning using Rayon
//! - Configurable timeouts and port ranges
//! - Service detection with banner grabbing
//! - Progress reporting for long-running scans
//! - Integration with nmap for detailed service analysis
//!
//! ## Example
//!
//! ```rust
//! use oxidescanner::scanner::{fast_scan, Port};
//! use oxidescanner::config::Config;
//! use oxidescanner::utils::resolve_target;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::from_args(&[
//!         "oxidescanner".to_string(),
//!         "127.0.0.1".to_string(),
//!         "-1k".to_string(),
//!     ])?;
//!     
//!     let addrs = resolve_target(&config.target)?;
//!     let open_ports = fast_scan(&addrs, &config).await?;
//!     
//!     for port in open_ports {
//!         println!("Port {} is open", port.port);
//!     }
//!     
//!     Ok(())
//! }
//! ```

use crate::config::Config;
use crate::constants;
use crate::error::{OxideScannerError, Result};
use crate::external::nmap::NmapDetector;
use crate::utils;
use colored::*;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

/// Port information with service detection results
///
/// This struct represents a scanned port and contains information about
/// the service running on it, including product and version details when available.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Port {
    /// Port number
    pub port: u16,
    /// Service name (e.g., "http", "ssh")
    pub service: String,
    /// Product name (e.g., "Apache httpd")
    pub product: String,
    /// Version string (e.g., "2.4.41")
    pub version: String,
}

impl Port {
    /// Create a new port with basic information
    pub fn new(port: u16) -> Self {
        Self {
            port,
            service: String::new(),
            product: String::new(),
            version: String::new(),
        }
    }

    /// Create a port with service information
    pub fn with_service(port: u16, service: String, product: String, version: String) -> Self {
        Self {
            port,
            service,
            product,
            version,
        }
    }
}

/// Progress reporter for port scanning
struct ProgressReporter {
    scanned: Arc<AtomicUsize>,
    total: usize,
    start_time: Instant,
    json_mode: bool,
}

impl ProgressReporter {
    fn new(total: usize, json_mode: bool) -> Self {
        Self {
            scanned: Arc::new(AtomicUsize::new(0)),
            total,
            start_time: Instant::now(),
            json_mode,
        }
    }

    fn start_reporting(&self) -> Option<thread::JoinHandle<()>> {
        if self.json_mode {
            return None;
        }

        let scanned_clone = Arc::clone(&self.scanned);
        let total = self.total;
        let start_time = self.start_time;

        Some(thread::spawn(move || {
            loop {
                let scanned = scanned_clone.load(Ordering::Relaxed);
                let percent = if total > 0 {
                    (scanned * 100) / total
                } else {
                    100
                };
                let bar = utils::progress_bar(percent, constants::progress::DEFAULT_WIDTH);

                print!(
                    "\r[{}] {:3}% | {}/{} scanned | {:.1}s",
                    bar,
                    percent,
                    scanned,
                    total,
                    start_time.elapsed().as_secs_f32()
                );

                if let Err(e) = std::io::stdout().flush() {
                    eprintln!("Failed to flush stdout: {}", e);
                    break;
                }

                if scanned >= total {
                    break;
                }
                thread::sleep(Duration::from_millis(
                    constants::PROGRESS_UPDATE_INTERVAL_MS,
                ));
            }

            // Clear the progress line
            print!("\r");
            if let Err(e) = std::io::stdout().flush() {
                eprintln!("Failed to flush stdout: {}", e);
            }
        }))
    }

    fn increment(&self) {
        self.scanned.fetch_add(1, Ordering::Relaxed);
    }
}

/// Perform fast TCP port scanning on multiple addresses
///
/// This function implements high-performance parallel TCP port scanning using
/// Rayon for thread pool management. It attempts to connect to each port on all
/// target addresses and returns a list of open ports.
///
/// # Arguments
///
/// * `target_addrs` - List of socket addresses to scan
/// * `config` - Scanning configuration including timeouts and port limits
///
/// # Returns
///
/// A vector of `Port` structs representing open ports
///
/// # Example
///
/// ```rust
/// use oxidescanner::scanner::fast_scan;
/// use oxidescanner::config::Config;
/// use std::net::SocketAddr;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = Config::from_args(&[
///         "oxidescanner".to_string(),
///         "127.0.0.1".to_string(),
///         "-1k".to_string(),
///     ])?;
///     
///     let addrs = vec!["127.0.0.1:0".parse::<SocketAddr>()?];
///     let open_ports = fast_scan(&addrs, &config).await?;
///     
///     println!("Found {} open ports", open_ports.len());
///     Ok(())
/// }
/// ```
pub async fn fast_scan(target_addrs: &[SocketAddr], config: &Config) -> Result<Vec<Port>> {
    let ports: Vec<u16> = utils::get_port_list_from_config(config);
    let total = ports.len();

    if total == 0 {
        return Ok(Vec::new());
    }

    let progress_reporter = ProgressReporter::new(total, config.json_mode);
    let progress_handle = progress_reporter.start_reporting();

    let addrs_clone = target_addrs.to_vec();
    let scan_timeout = config.scan_timeout;

    // Use rayon for parallel scanning
    let found_ports: Vec<Port> = ports
        .par_iter()
        .map_init(
            || addrs_clone.clone(),
            |addrs_local, &port| {
                let is_open = tcp_connect_addrs(addrs_local, port, scan_timeout);
                progress_reporter.increment();

                if is_open {
                    Some(Port::new(port))
                } else {
                    None
                }
            },
        )
        .filter_map(|x| x)
        .collect();

    if let Some(handle) = progress_handle {
        if let Err(e) = handle.join() {
            eprintln!("Progress reporter thread panicked: {:?}", e);
        }
    }

    let mut result = found_ports;
    result.sort_by_key(|p| p.port);

    if !config.json_mode {
        print_scan_summary(&result);
    }

    Ok(result)
}

/// Detect services on open ports using nmap
///
/// This function uses nmap to perform detailed service detection on open ports.
/// It attempts to identify service names, products, and versions for each open port.
///
/// # Arguments
///
/// * `target` - Target hostname or IP address
/// * `ports` - List of open ports from previous scanning
/// * `config` - Scanning configuration
///
/// # Returns
///
/// A vector of `Port` structs with service information populated
///
/// # Example
///
/// ```rust
/// use oxidescanner::scanner::{detect_services, Port};
/// use oxidescanner::config::Config;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = Config::from_args(&[
///         "oxidescanner".to_string(),
///         "127.0.0.1".to_string(),
///         "-1k".to_string(),
///     ])?;
///     
///     let open_ports = vec![Port::new(80), Port::new(22)];
///     let services = detect_services("127.0.0.1", &open_ports, &config).await?;
///     
///     for port in services {
///         if !port.service.is_empty() {
///             println!("Port {}: {} {}", port.port, port.service, port.version);
///         }
///     }
///     
///     Ok(())
/// }
/// ```
pub async fn detect_services(target: &str, ports: &[Port], config: &Config) -> Result<Vec<Port>> {
    if ports.is_empty() {
        return Ok(Vec::new());
    }

    let nmap_detector = NmapDetector::new().map_err(|e| {
        OxideScannerError::service_detection(format!("Failed to initialize nmap: {}", e))
    })?;

    let port_numbers: Vec<u16> = ports.iter().map(|p| p.port).collect();
    let timeout = Some(Duration::from_secs(constants::NMAP_TIMEOUT_SECS));

    let nmap_services = nmap_detector
        .detect_services(target, &port_numbers, timeout)
        .await
        .map_err(|e| {
            OxideScannerError::service_detection(format!("Service detection failed: {}", e))
        })?;

    // Convert nmap services to our Port format
    let mut detected_ports: Vec<Port> = nmap_services
        .into_iter()
        .map(|ns| Port::with_service(ns.port, ns.service, ns.product, ns.version))
        .collect();

    detected_ports.sort_by_key(|p| p.port);

    if !config.json_mode {
        print_service_detection_results(&detected_ports);
    }

    Ok(detected_ports)
}

/// Print scan summary in non-JSON mode
fn print_scan_summary(ports: &[Port]) {
    println!(
        "\n{} Found {} open ports",
        "SUCCESS".bright_green(),
        ports.len()
    );

    if !ports.is_empty() {
        println!("\n{} Open Ports:", "OPEN PORTS".bright_cyan().bold());
        for port in ports {
            println!("  {} Port {}", "->".bright_blue(), port.port);
        }

        println!(
            "\n{} Detecting services with nmap-style probes...",
            "DETECTING".bright_cyan()
        );
    }
}

/// Print service detection results in non-JSON mode
fn print_service_detection_results(ports: &[Port]) {
    if ports.is_empty() {
        return;
    }

    println!(
        "\n{} Service Detection Results:",
        "SERVICE DETECTION".bright_green().bold()
    );
    for port in ports {
        let service_info = if !port.product.is_empty() {
            format!(
                "{} {} {}",
                port.service.bright_cyan(),
                port.product.bright_white(),
                port.version.bright_black()
            )
        } else {
            port.service.bright_cyan().to_string()
        };
        println!(
            "  {} Port {}: {}",
            "->".bright_blue(),
            port.port,
            service_info
        );
    }
}

/// Test TCP connectivity to multiple addresses for a specific port
fn tcp_connect_addrs(addrs: &[SocketAddr], port: u16, timeout: Duration) -> bool {
    for base in addrs {
        let mut socket_addr = *base;
        socket_addr.set_port(port);

        match TcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(stream) => {
                // Verify connection is actually usable by setting a read timeout
                match stream
                    .set_read_timeout(Some(Duration::from_millis(constants::TCP_READ_TIMEOUT_MS)))
                {
                    Ok(_) => return true,
                    Err(_) => continue, // Try next address
                }
            }
            Err(_) => continue, // Try next address
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_new() {
        let port = Port::new(80);
        assert_eq!(port.port, 80);
        assert!(port.service.is_empty());
        assert!(port.product.is_empty());
        assert!(port.version.is_empty());
    }

    #[test]
    fn test_port_with_service() {
        let port = Port::with_service(
            80,
            "http".to_string(),
            "Apache".to_string(),
            "2.4.41".to_string(),
        );
        assert_eq!(port.port, 80);
        assert_eq!(port.service, "http");
        assert_eq!(port.product, "Apache");
        assert_eq!(port.version, "2.4.41");
        assert!(!port.service.is_empty() || !port.product.is_empty());
    }

    #[test]
    fn test_progress_reporter() {
        let reporter = ProgressReporter::new(100, false);
        assert_eq!(reporter.total, 100);
        assert!(!reporter.json_mode);

        reporter.increment();
        assert_eq!(reporter.scanned.load(Ordering::Relaxed), 1);
    }
}
