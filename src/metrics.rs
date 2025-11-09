//! # Metrics and Telemetry Module
//! 
//! This module provides comprehensive metrics collection and telemetry capabilities
//! for RustMap, including Prometheus export, performance tracking, and operational
//! monitoring. It uses the metrics crate for efficient metric collection.
//! 
//! ## Features
//! 
//! - Counter, gauge, and histogram metrics
//! - Prometheus metrics export
//! - Performance timing
//! - Operation success/failure tracking
//! - Resource usage monitoring
//! - Custom metric registration
//! 
//! ## Example
//! 
//! ```rust
//! use rustmap::metrics::{MetricsCollector, MetricsConfig};
//! use std::time::Duration;
//! 
//! let config = MetricsConfig::default();
//! let metrics = MetricsCollector::new(config);
//! 
//! // Record metrics
//! metrics.increment_counter("scans_started");
//! metrics.set_gauge("active_scans", 1.0);
//! metrics.record_histogram("scan_duration", Duration::from_secs(30));
//! 
//! // Export metrics
//! let prometheus_output = metrics.export_prometheus();
//! ```

use crate::error::{RustMapError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Metrics configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,
    /// Prometheus metrics port
    pub prometheus_port: u16,
    /// Metrics export interval
    pub export_interval: Duration,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            prometheus_port: 9090,
            export_interval: Duration::from_secs(30),
        }
    }
}

impl MetricsConfig {
    /// Create metrics configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let enabled = if let Ok(enabled) = std::env::var("RUSTMAP_METRICS_ENABLED") {
            enabled.parse::<bool>()
                .map_err(|_| RustMapError::config("Invalid RUSTMAP_METRICS_ENABLED value"))?
        } else {
            false
        };
        
        let prometheus_port = if let Ok(port) = std::env::var("RUSTMAP_METRICS_PORT") {
            port.parse::<u16>()
                .map_err(|_| RustMapError::config("Invalid RUSTMAP_METRICS_PORT value"))?
        } else {
            9090
        };
        
        let export_interval = if let Ok(interval) = std::env::var("RUSTMAP_METRICS_INTERVAL") {
            let secs = interval.parse::<u64>()
                .map_err(|_| RustMapError::config("Invalid RUSTMAP_METRICS_INTERVAL value"))?;
            Duration::from_secs(secs)
        } else {
            Duration::from_secs(30)
        };
        
        Ok(Self {
            enabled,
            prometheus_port,
            export_interval,
        })
    }
}

/// Metric types
#[derive(Debug, Clone)]
pub enum MetricType {
    /// Counter metric (monotonically increasing)
    Counter,
    /// Gauge metric (can go up and down)
    Gauge,
    /// Histogram metric (distribution of values)
    Histogram,
}

/// Metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    /// Counter value
    Counter(u64),
    /// Gauge value
    Gauge(f64),
    /// Histogram value with buckets
    Histogram {
        count: u64,
        sum: f64,
        buckets: HashMap<String, u64>,
    },
}

/// Collected metrics data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedMetrics {
    /// Timestamp when metrics were collected
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// All metrics with their values
    pub metrics: HashMap<String, MetricValue>,
    /// System resource usage
    pub system_metrics: SystemMetrics,
}

/// System resource metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// Memory usage percentage
    pub memory_usage_percent: f64,
    /// Number of threads
    pub thread_count: usize,
    /// Open file descriptors
    pub open_fds: u64,
}

/// Metrics collector implementation
#[derive(Debug)]
pub struct MetricsCollector {
    config: MetricsConfig,
    metrics: Arc<RwLock<HashMap<String, MetricValue>>>,
    start_time: Instant,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(config: MetricsConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(RwLock::new(HashMap::new())),
            start_time: Instant::now(),
        }
    }
    
    /// Initialize the metrics system
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        info!("Initializing metrics collection");
        
        // Register standard metrics
        self.register_metric("scans_started", MetricType::Counter).await?;
        self.register_metric("scans_completed", MetricType::Counter).await?;
        self.register_metric("scans_failed", MetricType::Counter).await?;
        self.register_metric("active_scans", MetricType::Gauge).await?;
        self.register_metric("total_ports_scanned", MetricType::Counter).await?;
        self.register_metric("total_open_ports_found", MetricType::Counter).await?;
        self.register_metric("total_services_detected", MetricType::Counter).await?;
        self.register_metric("total_exploits_found", MetricType::Counter).await?;
        self.register_metric("scan_duration_seconds", MetricType::Histogram).await?;
        self.register_metric("exploit_search_duration_seconds", MetricType::Histogram).await?;
        self.register_metric("external_tool_duration_seconds", MetricType::Histogram).await?;
        
        // Initialize counters to zero
        self.set_metric("scans_started", MetricValue::Counter(0)).await?;
        self.set_metric("scans_completed", MetricValue::Counter(0)).await?;
        self.set_metric("scans_failed", MetricValue::Counter(0)).await?;
        self.set_metric("active_scans", MetricValue::Gauge(0.0)).await?;
        self.set_metric("total_ports_scanned", MetricValue::Counter(0)).await?;
        self.set_metric("total_open_ports_found", MetricValue::Counter(0)).await?;
        self.set_metric("total_services_detected", MetricValue::Counter(0)).await?;
        self.set_metric("total_exploits_found", MetricValue::Counter(0)).await?;
        
        Ok(())
    }
    
    /// Register a new metric
    pub async fn register_metric(&self, name: &str, metric_type: MetricType) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let mut metrics = self.metrics.write().await;
        
        if metrics.contains_key(name) {
            return Err(RustMapError::config(format!("Metric '{}' already registered", name)));
        }
        
        let initial_value = match metric_type {
            MetricType::Counter => MetricValue::Counter(0),
            MetricType::Gauge => MetricValue::Gauge(0.0),
            MetricType::Histogram => MetricValue::Histogram {
                count: 0,
                sum: 0.0,
                buckets: HashMap::new(),
            },
        };
        
        metrics.insert(name.to_string(), initial_value);
        debug!("Registered metric: {} ({:?})", name, metric_type);
        
        Ok(())
    }
    
    /// Set a metric value
    async fn set_metric(&self, name: &str, value: MetricValue) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let mut metrics = self.metrics.write().await;
        metrics.insert(name.to_string(), value);
        Ok(())
    }
    
    /// Increment a counter metric
    pub async fn increment_counter(&self, name: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let mut metrics = self.metrics.write().await;
        if let Some(metric) = metrics.get_mut(name) {
            if let MetricValue::Counter(value) = metric {
                *value += 1;
            } else {
                return Err(RustMapError::config(format!("Metric '{}' is not a counter", name)));
            }
        } else {
            return Err(RustMapError::config(format!("Metric '{}' not found", name)));
        }
        
        Ok(())
    }
    
    /// Increment a counter by a specific amount
    pub async fn increment_counter_by(&self, name: &str, value: u64) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let mut metrics = self.metrics.write().await;
        if let Some(metric) = metrics.get_mut(name) {
            if let MetricValue::Counter(current) = metric {
                *current += value;
            } else {
                return Err(RustMapError::config(format!("Metric '{}' is not a counter", name)));
            }
        } else {
            return Err(RustMapError::config(format!("Metric '{}' not found", name)));
        }
        
        Ok(())
    }
    
    /// Set a gauge metric
    pub async fn set_gauge(&self, name: &str, value: f64) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let mut metrics = self.metrics.write().await;
        if let Some(metric) = metrics.get_mut(name) {
            if let MetricValue::Gauge(_) = metric {
                *metric = MetricValue::Gauge(value);
            } else {
                return Err(RustMapError::config(format!("Metric '{}' is not a gauge", name)));
            }
        } else {
            return Err(RustMapError::config(format!("Metric '{}' not found", name)));
        }
        
        Ok(())
    }
    
    /// Record a histogram observation
    pub async fn record_histogram(&self, name: &str, value: Duration) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let value_seconds = value.as_secs_f64();
        let mut metrics = self.metrics.write().await;
        
        if let Some(metric) = metrics.get_mut(name) {
            if let MetricValue::Histogram { count, sum, buckets } = metric {
                *count += 1;
                *sum += value_seconds;
                
                // Update buckets (standard Prometheus buckets)
                let bucket_bounds = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0];
                for bound in &bucket_bounds {
                    if value_seconds <= *bound {
                        let bucket_key = format!("le_{}", bound);
                        *buckets.entry(bucket_key).or_insert(0) += 1;
                    }
                }
                
                // Update +Inf bucket
                *buckets.entry("le_+Inf".to_string()).or_insert(0) += 1;
            } else {
                return Err(RustMapError::config(format!("Metric '{}' is not a histogram", name)));
            }
        } else {
            return Err(RustMapError::config(format!("Metric '{}' not found", name)));
        }
        
        Ok(())
    }
    
    /// Collect all current metrics
    pub async fn collect_metrics(&self) -> Result<CollectedMetrics> {
        let metrics = self.metrics.read().await;
        let system_metrics = self.collect_system_metrics().await?;
        
        Ok(CollectedMetrics {
            timestamp: chrono::Utc::now(),
            metrics: metrics.clone(),
            system_metrics,
        })
    }
    
    /// Export metrics in Prometheus format
    pub async fn export_prometheus(&self) -> Result<String> {
        let collected = self.collect_metrics().await?;
        let mut output = String::new();
        
        // Add metadata
        output.push_str("# Generated by RustMap\n");
        output.push_str(&format!("# Collection time: {}\n", collected.timestamp));
        output.push_str("\n");
        
        // Export metrics
        for (name, value) in collected.metrics {
            match value {
                MetricValue::Counter(count) => {
                    output.push_str(&format!("# TYPE {} counter\n", name));
                    output.push_str(&format!("{} {}\n", name, count));
                }
                MetricValue::Gauge(value) => {
                    output.push_str(&format!("# TYPE {} gauge\n", name));
                    output.push_str(&format!("{} {}\n", name, value));
                }
                MetricValue::Histogram { count, sum, buckets } => {
                    output.push_str(&format!("# TYPE {} histogram\n", name));
                    output.push_str(&format!("{}_count {}\n", name, count));
                    output.push_str(&format!("{}_sum {}\n", name, sum));
                    
                    for (bucket, bucket_count) in buckets {
                        output.push_str(&format!("{}_bucket{{le=\"{}\"}} {}\n", name, bucket, bucket_count));
                    }
                }
            }
            output.push_str("\n");
        }
        
        // Export system metrics
        output.push_str("# System metrics\n");
        output.push_str(&format!("# TYPE rustmap_cpu_usage gauge\n"));
        output.push_str(&format!("rustmap_cpu_usage {}\n", collected.system_metrics.cpu_usage));
        output.push_str(&format!("# TYPE rustmap_memory_bytes gauge\n"));
        output.push_str(&format!("rustmap_memory_bytes {}\n", collected.system_metrics.memory_usage));
        output.push_str(&format!("# TYPE rustmap_memory_percent gauge\n"));
        output.push_str(&format!("rustmap_memory_percent {}\n", collected.system_metrics.memory_usage_percent));
        output.push_str(&format!("# TYPE rustmap_threads gauge\n"));
        output.push_str(&format!("rustmap_threads {}\n", collected.system_metrics.thread_count));
        output.push_str(&format!("# TYPE rustmap_open_fds gauge\n"));
        output.push_str(&format!("rustmap_open_fds {}\n", collected.system_metrics.open_fds));
        
        Ok(output)
    }
    
    /// Collect system resource metrics
    async fn collect_system_metrics(&self) -> Result<SystemMetrics> {
        // This is a simplified implementation
        // In a production environment, you'd use proper system monitoring libraries
        
        let memory_usage = self.get_memory_usage().await?;
        let thread_count = self.get_thread_count().await?;
        let open_fds = self.get_open_fds().await?;
        
        Ok(SystemMetrics {
            cpu_usage: 0.0, // Would need proper CPU monitoring
            memory_usage,
            memory_usage_percent: 0.0, // Would need total memory
            thread_count,
            open_fds,
        })
    }
    
    /// Get current memory usage in bytes
    async fn get_memory_usage(&self) -> Result<u64> {
        // Simplified memory usage calculation
        // In production, use proper memory monitoring
        Ok(0)
    }
    
    /// Get current thread count
    async fn get_thread_count(&self) -> Result<usize> {
        // Simplified thread count
        // In production, use proper thread monitoring
        Ok(num_cpus::get())
    }
    
    /// Get current open file descriptor count
    async fn get_open_fds(&self) -> Result<u64> {
        // Simplified FD count
        // In production, use proper FD monitoring
        Ok(0)
    }
    
    /// Get uptime since metrics collector started
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Metrics timer for measuring operation duration
pub struct MetricsTimer {
    collector: Arc<MetricsCollector>,
    metric_name: String,
    start_time: Instant,
}

impl MetricsTimer {
    /// Create a new timer
    pub fn new(collector: Arc<MetricsCollector>, metric_name: String) -> Self {
        Self {
            collector,
            metric_name,
            start_time: Instant::now(),
        }
    }
    
    /// Finish timing and record the duration
    pub async fn finish(self) -> Result<()> {
        let duration = self.start_time.elapsed();
        self.collector.record_histogram(&self.metric_name, duration).await
    }
}

impl Drop for MetricsTimer {
    fn drop(&mut self) {
        let collector = self.collector.clone();
        let metric_name = self.metric_name.clone();
        let duration = self.start_time.elapsed();
        
        // Use tokio spawn to avoid blocking in drop
        tokio::spawn(async move {
            if let Err(e) = collector.record_histogram(&metric_name, duration).await {
                error!("Failed to record metric '{}': {}", metric_name, e);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_metrics_collector_creation() {
        let config = MetricsConfig::default();
        let collector = MetricsCollector::new(config);
        assert!(!collector.config.enabled);
    }
    
    #[tokio::test]
    async fn test_metrics_registration() {
        let config = MetricsConfig { enabled: true, ..Default::default() };
        let collector = MetricsCollector::new(config);
        
        collector.register_metric("test_counter", MetricType::Counter).await.unwrap();
        collector.register_metric("test_gauge", MetricType::Gauge).await.unwrap();
        collector.register_metric("test_histogram", MetricType::Histogram).await.unwrap();
    }
    
    #[tokio::test]
    async fn test_counter_operations() {
        let config = MetricsConfig { enabled: true, ..Default::default() };
        let collector = MetricsCollector::new(config);
        
        collector.register_metric("test_counter", MetricType::Counter).await.unwrap();
        collector.increment_counter("test_counter").await.unwrap();
        collector.increment_counter_by("test_counter", 5).await.unwrap();
        
        let metrics = collector.collect_metrics().await.unwrap();
        if let Some(MetricValue::Counter(value)) = metrics.metrics.get("test_counter") {
            assert_eq!(*value, 6);
        } else {
            panic!("Expected counter metric");
        }
    }
    
    #[tokio::test]
    async fn test_gauge_operations() {
        let config = MetricsConfig { enabled: true, ..Default::default() };
        let collector = MetricsCollector::new(config);
        
        collector.register_metric("test_gauge", MetricType::Gauge).await.unwrap();
        collector.set_gauge("test_gauge", 42.5).await.unwrap();
        
        let metrics = collector.collect_metrics().await.unwrap();
        if let Some(MetricValue::Gauge(value)) = metrics.metrics.get("test_gauge") {
            assert_eq!(*value, 42.5);
        } else {
            panic!("Expected gauge metric");
        }
    }
    
    #[tokio::test]
    async fn test_histogram_operations() {
        let config = MetricsConfig { enabled: true, ..Default::default() };
        let collector = MetricsCollector::new(config);
        
        collector.register_metric("test_histogram", MetricType::Histogram).await.unwrap();
        collector.record_histogram("test_histogram", Duration::from_millis(100)).await.unwrap();
        collector.record_histogram("test_histogram", Duration::from_millis(200)).await.unwrap();
        
        let metrics = collector.collect_metrics().await.unwrap();
        if let Some(MetricValue::Histogram { count, sum, .. }) = metrics.metrics.get("test_histogram") {
            assert_eq!(*count, 2);
            assert_eq!(*sum, 0.3);
        } else {
            panic!("Expected histogram metric");
        }
    }
    
    #[tokio::test]
    async fn test_prometheus_export() {
        let config = MetricsConfig { enabled: true, ..Default::default() };
        let collector = MetricsCollector::new(config);
        
        collector.register_metric("test_counter", MetricType::Counter).await.unwrap();
        collector.increment_counter("test_counter").await.unwrap();
        
        let prometheus_output = collector.export_prometheus().await.unwrap();
        assert!(prometheus_output.contains("test_counter 1"));
        assert!(prometheus_output.contains("# TYPE test_counter counter"));
    }
}