# RustMap Deployment Guide

This guide provides comprehensive instructions for deploying RustMap in production environments.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Environment Variables](#environment-variables)
5. [Docker Deployment](#docker-deployment)
6. [Kubernetes Deployment](#kubernetes-deployment)
7. [Monitoring and Observability](#monitoring-and-observability)
8. [Security Considerations](#security-considerations)
9. [Performance Tuning](#performance-tuning)
10. [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements
- **CPU**: 2 cores
- **Memory**: 4GB RAM
- **Storage**: 1GB free space
- **Network**: Stable internet connection
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+), macOS 10.15+, Windows 10+

### Recommended Requirements
- **CPU**: 4+ cores
- **Memory**: 8GB+ RAM
- **Storage**: 5GB+ free space
- **Network**: High-speed connection with low latency

### External Dependencies
- **nmap**: Version 7.80 or later
- **searchsploit**: Part of exploit-db package
- **git**: For cloning exploit-db repository

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/your-org/rustmap.git
cd rustmap

# Build in release mode
cargo build --release

# Install to system
sudo cp target/release/rustmap /usr/local/bin/
```

### From Package Manager

```bash
# Using cargo install
cargo install rustmap

# Using system package (if available)
sudo apt-get install rustmap  # Ubuntu/Debian
sudo yum install rustmap      # CentOS/RHEL
brew install rustmap          # macOS
```

### Docker Installation

```bash
# Pull the latest image
docker pull rustmap/rustmap:latest

# Or build from source
docker build -t rustmap:latest .
```

## Configuration

### Basic Configuration

RustMap can be configured through command-line arguments, environment variables, or configuration files.

### Command Line Arguments

```bash
# Basic scan
rustmap example.com -5k

# With custom timeouts
rustmap example.com -10k --scan-timeout 50 --exploit-timeout 15000

# JSON output
rustmap example.com --json

# Custom thread count
rustmap example.com --threads 8
```

### Configuration File

Create a configuration file at `/etc/rustmap/config.toml`:

```toml
[general]
default_threads = 0  # 0 = auto-detect
shutdown_timeout = 30  # seconds

[rate_limiting]
enabled = true
scanner_rate_limit = 50  # operations per second
external_tools_rate_limit = 5
exploit_queries_rate_limit = 2

[logging]
level = "info"
console = true
json = false
file_path = "/var/log/rustmap/rustmap.log"
max_file_size = 10485760  # 10MB
max_files = 5
console_timestamps = false

[metrics]
enabled = true
prometheus_port = 9090
export_interval = 30  # seconds

[retry]
max_retries = 3
base_delay = 1000  # milliseconds
max_delay = 30000
backoff_multiplier = 2.0
```

## Environment Variables

### General Configuration

```bash
# Thread configuration
export RUSTMAP_THREADS=8
export RUSTMAP_SHUTDOWN_TIMEOUT=30

# Rate limiting
export RUSTMAP_ENABLE_RATE_LIMIT=true
export RUSTMAP_SCANNER_RATE_LIMIT=50
export RUSTMAP_EXTERNAL_TOOLS_RATE_LIMIT=5
export RUSTMAP_EXPLOIT_QUERIES_RATE_LIMIT=2
```

### Logging Configuration

```bash
# Log level: trace, debug, info, warn, error
export RUSTMAP_LOG_LEVEL=info

# Output configuration
export RUSTMAP_LOG_CONSOLE=true
export RUSTMAP_LOG_JSON=false
export RUSTMAP_LOG_CONSOLE_TIMESTAMPS=false

# File logging
export RUSTMAP_LOG_FILE=/var/log/rustmap/rustmap.log
export RUSTMAP_LOG_MAX_SIZE=10485760
export RUSTMAP_LOG_MAX_FILES=5
```

### Metrics Configuration

```bash
export RUSTMAP_METRICS_ENABLED=true
export RUSTMAP_METRICS_PORT=9090
export RUSTMAP_METRICS_INTERVAL=30
```

### Retry Configuration

```bash
export RUSTMAP_RETRY_MAX=3
export RUSTMAP_RETRY_BASE_DELAY=1000
export RUSTMAP_RETRY_MAX_DELAY=30000
export RUSTMAP_RETRY_BACKOFF_MULTIPLIER=2.0
```

## Docker Deployment

### Dockerfile

```dockerfile
FROM rust:1.70 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install searchsploit
RUN git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb \
    && ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && chmod +x /usr/local/bin/searchsploit

# Copy binary
COPY --from=builder /app/target/release/rustmap /usr/local/bin/

# Create directories
RUN mkdir -p /var/log/rustmap /etc/rustmap

# Copy configuration
COPY config.toml /etc/rustmap/

EXPOSE 9090

CMD ["rustmap"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  rustmap:
    build: .
    container_name: rustmap
    environment:
      - RUSTMAP_LOG_LEVEL=info
      - RUSTMAP_METRICS_ENABLED=true
      - RUSTMAP_METRICS_PORT=9090
      - RUSTMAP_ENABLE_RATE_LIMIT=true
    volumes:
      - ./logs:/var/log/rustmap
      - ./config:/etc/rustmap
    ports:
      - "9090:9090"
    restart: unless-stopped
    
  prometheus:
    image: prom/prometheus:latest
    container_name: rustmap-prometheus
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    restart: unless-stopped
```

### Running with Docker

```bash
# Build and run
docker-compose up -d

# Execute a scan
docker-compose exec rustmap rustmap example.com -5k --json

# View logs
docker-compose logs -f rustmap

# View metrics
curl http://localhost:9090/metrics
```

## Kubernetes Deployment

### Deployment Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustmap
  labels:
    app: rustmap
spec:
  replicas: 1
  selector:
    matchLabels:
      app: rustmap
  template:
    metadata:
      labels:
        app: rustmap
    spec:
      containers:
      - name: rustmap
        image: rustmap/rustmap:latest
        env:
        - name: RUSTMAP_LOG_LEVEL
          value: "info"
        - name: RUSTMAP_METRICS_ENABLED
          value: "true"
        - name: RUSTMAP_METRICS_PORT
          value: "9090"
        - name: RUSTMAP_ENABLE_RATE_LIMIT
          value: "true"
        ports:
        - containerPort: 9090
          name: metrics
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        volumeMounts:
        - name: logs
          mountPath: /var/log/rustmap
        - name: config
          mountPath: /etc/rustmap
      volumes:
      - name: logs
        emptyDir: {}
      - name: config
        configMap:
          name: rustmap-config
---
apiVersion: v1
kind: Service
metadata:
  name: rustmap-metrics
spec:
  selector:
    app: rustmap
  ports:
  - port: 9090
    targetPort: 9090
    name: metrics
  type: ClusterIP
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: rustmap-config
data:
  config.toml: |
    [general]
    default_threads = 0
    shutdown_timeout = 30
    
    [rate_limiting]
    enabled = true
    scanner_rate_limit = 50
    external_tools_rate_limit = 5
    exploit_queries_rate_limit = 2
    
    [logging]
    level = "info"
    console = true
    json = false
    console_timestamps = false
    
    [metrics]
    enabled = true
    prometheus_port = 9090
    export_interval = 30
```

### Deploying to Kubernetes

```bash
# Apply the manifest
kubectl apply -f rustmap-deployment.yaml

# Check the deployment
kubectl get pods -l app=rustmap

# View logs
kubectl logs -l app=rustmap -f

# Port forward for metrics
kubectl port-forward service/rustmap-metrics 9090:9090
```

## Monitoring and Observability

### Prometheus Metrics

RustMap exposes the following metrics:

- `scans_started` - Total number of scans initiated
- `scans_completed` - Total number of scans completed
- `scans_failed` - Total number of scans failed
- `active_scans` - Currently active scans
- `total_ports_scanned` - Total ports scanned across all scans
- `total_open_ports_found` - Total open ports discovered
- `total_services_detected` - Total services detected
- `total_exploits_found` - Total exploits found
- `scan_duration_seconds` - Histogram of scan durations
- `exploit_search_duration_seconds` - Histogram of exploit search durations
- `external_tool_duration_seconds` - Histogram of external tool execution times

### Prometheus Configuration

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'rustmap'
    static_configs:
      - targets: ['rustmap:9090']
    scrape_interval: 30s
    metrics_path: /metrics
```

### Grafana Dashboard

A sample Grafana dashboard configuration is available in `grafana/dashboard.json`.

### Log Analysis

#### Structured Logging

When JSON logging is enabled, logs can be parsed and analyzed:

```bash
# View error logs
jq 'select(.level == "ERROR")' /var/log/rustmap/rustmap.log

# View scan performance
jq 'select(.target != null) | {timestamp, target, duration_ms, open_ports}' /var/log/rustmap/rustmap.log

# Analyze rate limiting
jq 'select(.message | contains("Rate limit"))' /var/log/rustmap/rustmap.log
```

#### Log Aggregation

For production deployments, consider using log aggregation tools:

- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Fluentd** + **Elasticsearch**
- **Loki** + **Grafana**
- **Splunk**

## Security Considerations

### Network Security

1. **Firewall Configuration**:
   ```bash
   # Allow only necessary ports
   ufw allow 22/tcp    # SSH
   ufw allow 9090/tcp  # Metrics
   ufw enable
   ```

2. **Network Segmentation**:
   - Deploy RustMap in a dedicated network segment
   - Use VPN or jump hosts for access

3. **Rate Limiting**:
   - Enable built-in rate limiting
   - Configure network-level rate limits

### Access Control

1. **User Permissions**:
   ```bash
   # Create dedicated user
   sudo useradd -r -s /bin/false rustmap
   sudo chown -R rustmap:rustmap /var/log/rustmap
   sudo chown -R rustmap:rustmap /etc/rustmap
   ```

2. **File Permissions**:
   ```bash
   # Secure configuration files
   chmod 600 /etc/rustmap/config.toml
   chmod 755 /var/log/rustmap
   chmod 644 /var/log/rustmap/*.log
   ```

### Container Security

1. **Non-root User**:
   ```dockerfile
   FROM rust:1.70 as builder
   # ... build steps ...
   
   FROM debian:bullseye-slim
   RUN groupadd -r rustmap && useradd -r -g rustmap rustmap
   USER rustmap
   ```

2. **Read-only Filesystem**:
   ```yaml
   securityContext:
     readOnlyRootFilesystem: true
     runAsNonRoot: true
     runAsUser: 1000
   ```

3. **Resource Limits**:
   ```yaml
   resources:
     limits:
       cpu: "1000m"
       memory: "2Gi"
     requests:
       cpu: "250m"
       memory: "512Mi"
   ```

### Data Protection

1. **Log Sanitization**:
   - Enable JSON logging for structured parsing
   - Avoid logging sensitive information
   - Implement log rotation

2. **Encryption**:
   - Use TLS for metrics endpoints
   - Encrypt log files at rest
   - Secure configuration files

## Performance Tuning

### System Optimization

1. **File Descriptor Limits**:
   ```bash
   # Increase file descriptor limits
   echo "* soft nofile 65536" >> /etc/security/limits.conf
   echo "* hard nofile 65536" >> /etc/security/limits.conf
   ```

2. **Network Parameters**:
   ```bash
   # Optimize network stack
   sysctl -w net.core.somaxconn=65535
   sysctl -w net.ipv4.tcp_max_syn_backlog=65535
   sysctl -w net.core.netdev_max_backlog=5000
   ```

3. **Memory Management**:
   ```bash
   # Optimize memory usage
   sysctl -w vm.swappiness=10
   sysctl -w vm.dirty_ratio=15
   sysctl -w vm.dirty_background_ratio=5
   ```

### Application Tuning

1. **Thread Configuration**:
   ```bash
   # Set optimal thread count
   export RUSTMAP_THREADS=$(nproc)
   ```

2. **Rate Limiting**:
   ```bash
   # Adjust rate limits based on network capacity
   export RUSTMAP_SCANNER_RATE_LIMIT=100
   export RUSTMAP_EXTERNAL_TOOLS_RATE_LIMIT=10
   ```

3. **Timeout Configuration**:
   ```bash
   # Optimize timeouts for your environment
   export RUSTMAP_SCAN_TIMEOUT=50
   export RUSTMAP_EXPLOIT_TIMEOUT=20000
   ```

### Monitoring Performance

1. **Key Metrics to Watch**:
   - Scan duration trends
   - Memory usage patterns
   - Network I/O rates
   - Error rates

2. **Performance Alerts**:
   ```yaml
   # Prometheus alert rules
   groups:
   - name: rustmap
     rules:
     - alert: HighScanDuration
       expr: histogram_quantile(0.95, rate(scan_duration_seconds_bucket[5m])) > 300
       for: 2m
       labels:
         severity: warning
       annotations:
         summary: "High scan duration detected"
         
     - alert: HighMemoryUsage
       expr: rustmap_memory_percent > 80
       for: 5m
       labels:
         severity: critical
       annotations:
         summary: "High memory usage detected"
   ```

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**:
   ```bash
   # Check file permissions
   ls -la /var/log/rustmap/
   ls -la /etc/rustmap/
   
   # Fix permissions
   sudo chown -R rustmap:rustmap /var/log/rustmap
   sudo chmod 755 /var/log/rustmap
   ```

2. **External Tool Not Found**:
   ```bash
   # Check tool availability
   which nmap
   which searchsploit
   
   # Install missing tools
   sudo apt-get install nmap
   git clone https://github.com/offensive-security/exploitdb.git
   sudo ln -s /path/to/exploitdb/searchsploit /usr/local/bin/
   ```

3. **High Memory Usage**:
   ```bash
   # Monitor memory usage
   top -p $(pgrep rustmap)
   ps aux | grep rustmap
   
   # Reduce thread count
   export RUSTMAP_THREADS=2
   ```

4. **Rate Limiting Issues**:
   ```bash
   # Check rate limit status
   curl http://localhost:9090/metrics | grep rustmap_rate_limit
   
   # Adjust rate limits
   export RUSTMAP_SCANNER_RATE_LIMIT=25
   ```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
export RUSTMAP_LOG_LEVEL=debug
export RUSTMAP_LOG_CONSOLE=true
export RUSTMAP_LOG_JSON=false

# Run with debug output
rustmap example.com -1k
```

### Health Checks

Implement health checks for monitoring:

```bash
#!/bin/bash
# health_check.sh

# Check if process is running
if ! pgrep -f rustmap > /dev/null; then
    echo "ERROR: RustMap process not running"
    exit 1
fi

# Check metrics endpoint
if ! curl -f http://localhost:9090/metrics > /dev/null 2>&1; then
    echo "ERROR: Metrics endpoint not responding"
    exit 1
fi

# Check log file
if [ ! -f /var/log/rustmap/rustmap.log ]; then
    echo "ERROR: Log file not found"
    exit 1
fi

echo "OK: All health checks passed"
exit 0
```

### Log Analysis Commands

```bash
# Find recent errors
tail -1000 /var/log/rustmap/rustmap.log | grep ERROR

# Analyze scan performance
grep "Scan completed" /var/log/rustmap/rustmap.log | tail -10

# Check rate limiting
grep "Rate limit" /var/log/rustmap/rustmap.log | wc -l

# Monitor real-time logs
tail -f /var/log/rustmap/rustmap.log | grep -E "(ERROR|WARN)"
```

## Support

For additional support:

1. **Documentation**: Check the [main README](README.md)
2. **Issues**: Report bugs on [GitHub Issues](https://github.com/your-org/rustmap/issues)
3. **Discussions**: Join our [GitHub Discussions](https://github.com/your-org/rustmap/discussions)
4. **Security**: Report security issues privately to security@yourorg.com

## Version History

- **v1.0.0**: Production release with all enterprise features
- **v0.2.0**: Added metrics and retry mechanisms
- **v0.1.0**: Initial release with basic scanning capabilities