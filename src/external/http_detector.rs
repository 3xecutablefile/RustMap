use crate::error::{OxideScannerError, Result};
use std::time::Duration;
use tokio::time::timeout;

/// HTTP service information
#[derive(Debug, Clone)]
pub struct HttpService {
    pub port: u16,
    pub server_header: String,
    pub powered_by_header: String,
    pub response_code: u16,
}

/// HTTP service detector
pub struct HttpDetector;

impl HttpDetector {
    pub fn new() -> Self {
        Self {}
    }

    /// Detect HTTP services on specified ports for a target
    pub async fn detect_services(&self, target: &str, ports: &[u16]) -> Result<Vec<HttpService>> {
        let mut services = Vec::new();
        
        for &port in ports {
            // Try both HTTP and HTTPS detection depending on the port
            if let Some(service) = self.detect_http_service(target, port).await {
                services.push(service);
            }
        }
        
        Ok(services)
    }

    /// Detect HTTP service on a specific port
    async fn detect_http_service(&self, target: &str, port: u16) -> Option<HttpService> {
        // Create a client with a reasonable timeout
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true) // For HTTPS with potentially self-signed certificates
            .build()
            .ok()?;

        let protocol = if port == 443 || port == 8443 {
            "https"
        } else {
            "http"
        };

        let url = format!("{}://{}:{}", protocol, target, port);

        // Try HEAD request first (similar to curl -I)
        let response = timeout(
            Duration::from_secs(10),
            client.head(&url).send()
        ).await;

        if let Ok(Ok(response)) = response {
            let server_header = response
                .headers()
                .get("server")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_default();

            let powered_by_header = response
                .headers()
                .get("x-powered-by")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_default();

            let status_code = response.status().as_u16();

            if !server_header.is_empty() || !powered_by_header.is_empty() {
                return Some(HttpService {
                    port,
                    server_header,
                    powered_by_header,
                    response_code: status_code,
                });
            }
        }

        // If HEAD fails, try GET request
        let response = timeout(
            Duration::from_secs(10),
            client.get(&url).send()
        ).await;

        if let Ok(Ok(response)) = response {
            let server_header = response
                .headers()
                .get("server")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_default();

            let powered_by_header = response
                .headers()
                .get("x-powered-by")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_default();

            let status_code = response.status().as_u16();

            if !server_header.is_empty() || !powered_by_header.is_empty() {
                return Some(HttpService {
                    port,
                    server_header,
                    powered_by_header,
                    response_code: status_code,
                });
            }
        }

        None
    }
}