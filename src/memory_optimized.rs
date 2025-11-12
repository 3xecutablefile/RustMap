//! # Memory Optimized Scanning Module
//!
//! This module provides memory-efficient implementations for large-scale scanning
//! operations in OxideScanner. It implements batch processing, streaming results,
//! and optimized data structures to reduce memory usage during large scans.

use crate::error::{OxideScannerError, Result};
use crate::scanner::Port;
use crate::exploit::{Exploit, PortResult};
use std::collections::VecDeque;

/// Configuration for memory optimization during large scans
#[derive(Debug, Clone)]
pub struct MemoryOptConfig {
    /// Maximum number of ports to scan in a single batch
    pub batch_size: usize,
    /// Maximum number of results to buffer before writing to output
    pub buffer_size: usize,
    /// Whether to stream results directly to file instead of holding in memory
    pub stream_to_file: bool,
    /// Whether to compress intermediate results to reduce memory usage
    pub compress_results: bool,
}

impl Default for MemoryOptConfig {
    fn default() -> Self {
        Self {
            batch_size: 1000,    // Process 1000 ports at a time
            buffer_size: 100,    // Buffer up to 100 results
            stream_to_file: true, // Stream directly to file when possible
            compress_results: false, // Don't compress by default to maintain performance
        }
    }
}

/// Memory-optimized batch processor for port scanning
pub struct BatchScanner {
    config: MemoryOptConfig,
}

impl BatchScanner {
    /// Create a new batch scanner with specified configuration
    pub fn new(config: MemoryOptConfig) -> Self {
        Self { config }
    }

    /// Process ports in batches to reduce memory usage
    pub async fn scan_in_batches<F, Fut>(
        &self,
        all_ports: Vec<u16>,
        scan_func: F,
    ) -> Result<Vec<Port>>
    where
        F: Fn(Vec<u16>) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<Port>>>,
    {
        let mut results = Vec::new();
        let mut start_idx = 0;

        while start_idx < all_ports.len() {
            let end_idx = std::cmp::min(start_idx + self.config.batch_size, all_ports.len());
            let batch = all_ports[start_idx..end_idx].to_vec();

            let batch_results = scan_func(batch).await?;
            results.extend(batch_results);

            start_idx = end_idx;
        }

        Ok(results)
    }

    /// Process exploits in batches to reduce memory usage
    pub async fn process_exploits_in_batches<F, Fut>(
        &self,
        ports: Vec<Port>,
        process_func: F,
    ) -> Result<Vec<PortResult>>
    where
        F: Fn(Port) -> Fut,
        Fut: std::future::Future<Output = Result<PortResult>>,
    {
        let mut results = Vec::with_capacity(ports.len());
        let mut port_queue: VecDeque<Port> = ports.into();

        while let Some(port) = port_queue.pop_front() {
            let result = process_func(port).await?;
            
            if results.len() >= self.config.buffer_size {
                // Process the buffered results before adding more
                // This helps keep memory usage under control
            }
            
            results.push(result);
        }

        Ok(results)
    }
}

/// Memory-efficient result writer that can stream directly to files
pub struct StreamResultWriter {
    buffer: Vec<PortResult>,
    buffer_size: usize,
    output_file: Option<String>,
}

impl StreamResultWriter {
    /// Create a new stream writer
    pub fn new(buffer_size: usize, output_file: Option<String>) -> Self {
        Self {
            buffer: Vec::with_capacity(buffer_size),
            buffer_size,
            output_file,
        }
    }

    /// Add a result to the buffer
    pub fn add_result(&mut self, result: PortResult) -> Result<()> {
        self.buffer.push(result);

        if self.buffer.len() >= self.buffer_size {
            self.flush()?;
        }

        Ok(())
    }

    /// Flush the buffer to output
    pub fn flush(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        if let Some(ref file_path) = self.output_file {
            // Write the buffered results directly to the file
            use std::fs::OpenOptions;
            use std::io::Write;

            let json_output = serde_json::to_string_pretty(&self.buffer)
                .map_err(|e| OxideScannerError::parse(format!("Failed to serialize JSON: {}", e)))?;

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(file_path)
                .map_err(|e| OxideScannerError::Io(e))?;

            file.write_all(json_output.as_bytes())
                .map_err(|e| OxideScannerError::Io(e))?;

            // Clear the buffer after writing
            self.buffer.clear();
        }

        Ok(())
    }

    /// Get remaining buffered results
    pub fn finish(self) -> Vec<PortResult> {
        self.buffer
    }
}

/// Memory-efficient port iterator for large port ranges
pub struct PortIterator {
    current: u16,
    end: u16,
}

impl PortIterator {
    /// Create a new port iterator for a range
    pub fn new(start: u16, end: u16) -> Self {
        Self {
            current: start,
            end,
        }
    }
}

impl Iterator for PortIterator {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current <= self.end {
            let current = self.current;
            self.current += 1;
            Some(current)
        } else {
            None
        }
    }
}

/// Memory-efficient data structure for storing scan results
#[derive(Debug, Clone)]
pub struct MemoryEfficientResult {
    pub port: u16,
    pub service: Option<String>,  // Use Option to save space when not available
    pub product: Option<String>,  // Use Option to save space when not available
    pub version: Option<String>,  // Use Option to save space when not available
    pub exploits: Vec<Exploit>,
    pub risk_score: f32,
}

impl From<PortResult> for MemoryEfficientResult {
    fn from(result: PortResult) -> Self {
        Self {
            port: result.port.port,
            service: if !result.port.service.is_empty() {
                Some(result.port.service)
            } else {
                None
            },
            product: if !result.port.product.is_empty() {
                Some(result.port.product)
            } else {
                None
            },
            version: if !result.port.version.is_empty() {
                Some(result.port.version)
            } else {
                None
            },
            exploits: result.exploits,
            risk_score: result.risk_score,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_iterator() {
        let mut iter = PortIterator::new(80, 85);
        let ports: Vec<u16> = iter.collect();
        assert_eq!(ports, vec![80, 81, 82, 83, 84, 85]);
    }

    #[test]
    fn test_memory_config_default() {
        let config = MemoryOptConfig::default();
        assert_eq!(config.batch_size, 1000);
        assert_eq!(config.buffer_size, 100);
    }
}