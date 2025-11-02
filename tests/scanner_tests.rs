#[cfg(test)]
mod tests {
    use rustmap::scanner::{Port, fast_scan, detect_services};
    use rustmap::config::Config;
    use rustmap::utils;
    use std::net::SocketAddr;
    use std::time::Duration;

    #[test]
    fn test_port_creation() {
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
            "Apache httpd".to_string(),
            "2.4.41".to_string(),
        );
        assert_eq!(port.port, 80);
        assert_eq!(port.service, "http");
        assert_eq!(port.product, "Apache httpd");
        assert_eq!(port.version, "2.4.41");
    }

    #[test]
    fn test_port_list_generation() {
        let ports = utils::get_port_list(100);
        assert_eq!(ports.len(), 100);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[99], 100);
    }

    #[test]
    fn test_port_list_full_range() {
        let ports = utils::get_port_list(65535);
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[65534], 65535);
    }

    #[test]
    fn test_config_scanning() {
        let config = Config::from_args(&[
            "rustmap".to_string(),
            "127.0.0.1".to_string(),
            "-5k".to_string(),
        ]).unwrap();
        
        assert_eq!(config.port_limit, 5000);
        assert_eq!(config.target, "127.0.0.1");
    }

    #[tokio::test]
    async fn test_fast_scan_no_targets() {
        let empty_addrs: Vec<SocketAddr> = vec![];
        let config = Config::from_args(&[
            "rustmap".to_string(),
            "127.0.0.1".to_string(),
            "-1k".to_string(),
        ]).unwrap();
        
        let result = fast_scan(&empty_addrs, &config).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_fast_scan_localhost() {
        // This test requires localhost to be accessible
        let addrs = vec![
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        ];
        let config = Config::from_args(&[
            "rustmap".to_string(),
            "127.0.0.1".to_string(),
            "-1k".to_string(), // Only scan first 1000 ports (minimum with k format)
        ]).unwrap();
        
        let result = fast_scan(&addrs, &config).await;
        assert!(result.is_ok());
        
        // We can't guarantee which ports are open, but the result should be valid
        let ports = result.unwrap();
        for port in ports {
            // Ports should be within the scanned range (1-1000)
            assert!(port.port <= 1000);
        }
    }

    #[tokio::test]
    async fn test_detect_services_empty_ports() {
        let empty_ports: Vec<Port> = vec![];
        let config = Config::from_args(&[
            "rustmap".to_string(),
            "127.0.0.1".to_string(),
            "-1k".to_string(),
        ]).unwrap();
        
        let result = detect_services("127.0.0.1", &empty_ports, &config).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_progress_bar_calculation() {
        let bar = utils::progress_bar(50, 40);
        let filled_count = bar.chars().filter(|&c| c == '█').count();
        let empty_count = bar.chars().filter(|&c| c == '░').count();
        assert_eq!(filled_count, 20);
        assert_eq!(empty_count, 20);
        assert_eq!(filled_count + empty_count, 40);
    }

    #[test]
    fn test_progress_bar_zero_percent() {
        let bar = utils::progress_bar(0, 40);
        assert_eq!(bar.chars().filter(|&c| c == '█').count(), 0);
        assert_eq!(bar.chars().filter(|&c| c == '░').count(), 40);
    }

    #[test]
    fn test_progress_bar_hundred_percent() {
        let bar = utils::progress_bar(100, 40);
        assert_eq!(bar.chars().filter(|&c| c == '█').count(), 40);
        assert_eq!(bar.chars().filter(|&c| c == '░').count(), 0);
    }

    #[test]
    fn test_timeout_configuration() {
        let config = Config::from_args(&[
            "rustmap".to_string(),
            "127.0.0.1".to_string(),
            "-1k".to_string(),
            "--scan-timeout".to_string(),
            "100".to_string(),
        ]).unwrap();
        
        assert_eq!(config.scan_timeout, Duration::from_millis(100));
    }

    #[test]
    fn test_json_mode_configuration() {
        let config = Config::from_args(&[
            "rustmap".to_string(),
            "127.0.0.1".to_string(),
            "-1k".to_string(),
            "--json".to_string(),
        ]).unwrap();
        
        assert!(config.json_mode);
    }

    #[test]
    fn test_port_limit_validation() {
        // Test valid port limits
        let config = Config::from_args(&[
            "rustmap".to_string(),
            "127.0.0.1".to_string(),
            "-1k".to_string(),
        ]).unwrap();
        assert_eq!(config.port_limit, 1000);

        let config = Config::from_args(&[
            "rustmap".to_string(),
            "127.0.0.1".to_string(),
            "-30k".to_string(),
        ]).unwrap();
        assert_eq!(config.port_limit, 30000);
    }

    #[test]
    fn test_exploit_timeout_configuration() {
        let config = Config::from_args(&[
            "rustmap".to_string(),
            "127.0.0.1".to_string(),
            "-1k".to_string(),
            "--exploit-timeout".to_string(),
            "20000".to_string(),
        ]).unwrap();
        
        assert_eq!(config.exploit_timeout, Duration::from_millis(20000));
    }
}