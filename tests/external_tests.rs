#[cfg(test)]
mod tests {
    use rustmap::external::BaseTool;
    use rustmap::external::nmap::{NmapDetector, NmapService};
    use rustmap::external::searchsploit::{ExploitSearcher, Exploit, SearchStrategy};
    use std::time::Duration;

    #[tokio::test]
    async fn test_base_tool_creation() {
        // Test with a common command that should exist
        let result = BaseTool::new("echo");
        // This might fail if echo is not in PATH, but should not panic
        match result {
            Ok(tool) => {
                assert!(!tool.binary_path.is_empty());
            }
            Err(_) => {
                // Expected if echo is not found
            }
        }
    }

    #[tokio::test]
    async fn test_base_tool_invalid_command() {
        let result = BaseTool::new("definitely_not_a_real_command_12345");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_base_tool_execute_command() {
        if let Ok(tool) = BaseTool::new("echo") {
            let result = tool.execute_command(&["hello"], Duration::from_secs(5)).await;
            
            match result {
                Ok(output) => {
                    assert!(output.status.success());
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    assert!(output_str.contains("hello"));
                }
                Err(_) => {
                    // Command execution might fail
                }
            }
        }
    }

    #[tokio::test]
    async fn test_base_tool_timeout() {
        if let Ok(tool) = BaseTool::new("sleep") {
            // Test with a very short timeout
            let result = tool.execute_command(&["10"], Duration::from_millis(100)).await;
            assert!(result.is_err()); // Should timeout
        }
    }

    #[tokio::test]
    async fn test_nmap_detector_creation() {
        let result = NmapDetector::new();
        // This might fail if nmap is not installed
        match result {
            Ok(_detector) => {
                // Successfully created
            }
            Err(_) => {
                // Expected if nmap is not installed
            }
        }
    }

    #[tokio::test]
    async fn test_nmap_detect_services_empty_ports() {
        if let Ok(detector) = NmapDetector::new() {
            let empty_ports: Vec<u16> = vec![];
            let result = detector.detect_services("127.0.0.1", &empty_ports, Some(Duration::from_secs(5))).await;
            
            match result {
                Ok(services) => {
                    assert!(services.is_empty());
                }
                Err(_) => {
                    // Expected if nmap fails
                }
            }
        }
    }

    #[tokio::test]
    async fn test_nmap_detect_services_with_ports() {
        if let Ok(detector) = NmapDetector::new() {
            let ports = vec![22, 80, 443];
            let result = detector.detect_services("127.0.0.1", &ports, Some(Duration::from_secs(10))).await;
            
            match result {
                Ok(services) => {
                    // Should not panic, services might be empty if no services are detected
                    assert!(services.len() <= ports.len());
                    
                    for service in &services {
                        assert!(ports.contains(&service.port));
                        assert!(!service.service.is_empty());
                    }
                }
                Err(_) => {
                    // Expected if nmap fails or is not available
                }
            }
        }
    }

    #[test]
    fn test_nmap_service_creation() {
        let service = NmapService {
            port: 80,
            service: "http".to_string(),
            product: "Apache httpd".to_string(),
            version: "2.4.41".to_string(),
        };

        assert_eq!(service.port, 80);
        assert_eq!(service.service, "http");
        assert_eq!(service.product, "Apache httpd");
        assert_eq!(service.version, "2.4.41");
    }

    #[test]
    fn test_nmap_service_serialization() {
        let service = NmapService {
            port: 22,
            service: "ssh".to_string(),
            product: "OpenSSH".to_string(),
            version: "8.2p1".to_string(),
        };

        let json = serde_json::to_string(&service);
        assert!(json.is_ok());
    }

    #[tokio::test]
    async fn test_exploit_searcher_creation() {
        let result = ExploitSearcher::new();
        // This might fail if searchsploit is not installed
        match result {
            Ok(_searcher) => {
                // Successfully created
            }
            Err(_) => {
                // Expected if searchsploit is not installed
            }
        }
    }

    #[tokio::test]
    async fn test_exploit_searcher_search_exploits() {
        if let Ok(searcher) = ExploitSearcher::new() {
            let result = searcher.search_exploits("apache", Some(Duration::from_secs(10))).await;
            
            match result {
                Ok(exploits) => {
                    // Should not panic, exploits might be empty if nothing is found
                    for exploit in &exploits {
                        assert!(!exploit.title.is_empty());
                        assert!(!exploit.path.is_empty());
                    }
                }
                Err(_) => {
                    // Expected if searchsploit fails or is not available
                }
            }
        }
    }

    #[tokio::test]
    async fn test_exploit_searcher_search_with_strategies() {
        if let Ok(searcher) = ExploitSearcher::new() {
            let strategies = vec![
                SearchStrategy::Exact,
                SearchStrategy::Fuzzy,
                SearchStrategy::ServiceOnly,
            ];

            for strategy in strategies {
                let result = searcher.search_with_strategy("ssh", strategy, Duration::from_secs(5)).await;
                
                match result {
                    Ok(exploits) => {
                        // Should not panic
                        for exploit in &exploits {
                            assert!(!exploit.title.is_empty());
                        }
                    }
                    Err(_) => {
                        // Expected if searchsploit fails
                    }
                }
            }
        }
    }

    #[test]
    fn test_exploit_creation() {
        let exploit = Exploit {
            title: "Test Exploit".to_string(),
            url: "https://example.com/exploit".to_string(),
            cvss: Some(7.5),
            path: "/path/to/exploit".to_string(),
        };

        assert_eq!(exploit.title, "Test Exploit");
        assert_eq!(exploit.url, "https://example.com/exploit");
        assert_eq!(exploit.cvss, Some(7.5));
        assert_eq!(exploit.path, "/path/to/exploit");
    }

    #[test]
    fn test_exploit_serialization() {
        let exploit = Exploit {
            title: "Test Exploit".to_string(),
            url: "https://example.com/exploit".to_string(),
            cvss: Some(8.0),
            path: "/path/to/exploit".to_string(),
        };

        let json = serde_json::to_string(&exploit);
        assert!(json.is_ok());
    }

    #[test]
    fn test_search_strategy_display() {
        // Test that SearchStrategy can be cloned and compared
        let exact = SearchStrategy::Exact;
        let fuzzy = SearchStrategy::Fuzzy;
        let service_only = SearchStrategy::ServiceOnly;

        let exact_clone = exact.clone();
        assert_eq!(exact, exact_clone);
        assert_ne!(exact, fuzzy);
        assert_ne!(fuzzy, service_only);
    }

    #[tokio::test]
    async fn test_external_tool_timeout_handling() {
        if let Ok(tool) = BaseTool::new("sleep") {
            // Test timeout with a command that should definitely timeout
            let start = std::time::Instant::now();
            let result = tool.execute_command(&["30"], Duration::from_millis(500)).await;
            let elapsed = start.elapsed();

            // Should fail due to timeout
            assert!(result.is_err());
            // Should timeout quickly (within 2 seconds, allowing some overhead)
            assert!(elapsed < Duration::from_secs(2));
        }
    }

    #[tokio::test]
    async fn test_external_tool_invalid_arguments() {
        if let Ok(tool) = BaseTool::new("echo") {
            // Test with invalid arguments
            let result = tool.execute_command(&[], Duration::from_secs(5)).await;
            
            match result {
                Ok(_) => {
                    // Some commands might handle empty args
                }
                Err(_) => {
                    // Expected for many commands
                }
            }
        }
    }

    #[test]
    fn test_base_tool_binary_path() {
        if let Ok(tool) = BaseTool::new("echo") {
            assert!(!tool.binary_path.is_empty());
            assert!(tool.binary_path.contains("echo") || tool.binary_path.ends_with("echo"));
        }
    }
}