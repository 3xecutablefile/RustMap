#[cfg(test)]
mod tests {
    use rustmap::config::Config;
    use rustmap::utils;

    #[test]
    fn test_config_parsing() {
        let args = vec![
            "rustmap".to_string(),
            "127.0.0.1".to_string(),
            "-5k".to_string(),
            "--json".to_string(),
            "--scan-timeout".to_string(),
            "50".to_string(),
        ];
        
        let config = Config::from_args(&args).unwrap();
        assert_eq!(config.target, "127.0.0.1");
        assert!(config.json_mode);
        assert_eq!(config.scan_timeout.as_millis(), 50);
        assert_eq!(config.port_limit, 5000);
    }

    #[test]
    fn test_port_limit_parsing() {
        let args = vec![
            "rustmap".to_string(),
            "example.com".to_string(),
            "-5k".to_string(),
        ];
        
        let config = Config::from_args(&args).unwrap();
        assert_eq!(config.port_limit, 5000);
    }

    #[test]
    fn test_dependency_check() {
        // This test will fail if required tools aren't installed
        // In a real CI environment, you'd mock this or install the tools
        let result = utils::check_dependencies();
        // We don't assert success here since tools might not be installed
        // but we verify the function runs without panicking
        match result {
            Ok(_) => println!("All dependencies available"),
            Err(e) => println!("Missing dependencies: {}", e),
        }
    }

    #[test]
    fn test_port_list_generation() {
        let ports = utils::get_port_list(100);
        assert_eq!(ports.len(), 100);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[99], 100);
    }

    #[test]
    fn test_progress_bar() {
        let bar = utils::progress_bar(50, 40);
        let filled_count = bar.chars().filter(|&c| c == '█').count();
        let empty_count = bar.chars().filter(|&c| c == '░').count();
        assert_eq!(filled_count, 20);
        assert_eq!(empty_count, 20);
        assert_eq!(filled_count + empty_count, 40);
    }
}