use crate::constants;
use crate::error::{OxideScannerError, Result};
use crate::external::{BaseTool, ExternalTool};
use crate::validation;
use serde::Serialize;
use std::collections::HashSet;
use std::process::Output;
use std::time::Duration;

/// Exploit information from searchsploit
#[derive(Debug, Clone, Serialize)]
pub struct Exploit {
    pub title: String,
    pub url: String,
    pub cvss: Option<f32>,
    pub path: String,
}

/// Exploit database searcher
pub struct ExploitSearcher {
    base_tool: BaseTool,
}

impl ExploitSearcher {
    /// Create a new exploit searcher
    pub fn new() -> Result<Self> {
        let base_tool = BaseTool::new("searchsploit")?;
        Ok(Self { base_tool })
    }

    /// Search for exploits with multiple strategies
    pub async fn search_exploits(
        &self,
        query: &str,
        timeout: Option<Duration>,
    ) -> Result<Vec<Exploit>> {
        let timeout =
            timeout.unwrap_or(Duration::from_secs(constants::DEFAULT_EXPLOIT_TIMEOUT_SECS));

        // Validate query
        let validated_query = validation::validate_search_query(query)?;

        let mut all_exploits = Vec::new();
        let mut seen_titles = HashSet::new();

        // Generate multiple query variations to increase success rate
        let queries = self.generate_search_queries(&validated_query);

        for query_variant in queries {
            if let Ok(exploits) = self.search_with_strategy(&query_variant, timeout).await {
                for exploit in exploits {
                    if seen_titles.insert(exploit.title.clone()) {
                        all_exploits.push(exploit);
                    }
                }
            }
        }

        // Sort by CVSS score and relevance
        self.sort_exploits(&mut all_exploits);

        Ok(all_exploits)
    }

    /// Generate multiple query variations for more comprehensive search
    fn generate_search_queries(&self, original: &str) -> Vec<String> {
        let mut queries = Vec::new();
        let original_trimmed = original.trim();

        // 1. Original query
        queries.push(original_trimmed.to_string());

        // 2. Remove "httpd" if present (common issue)
        if original_trimmed.to_lowercase().contains("httpd") {
            let without_httpd = original_trimmed
                .to_lowercase()
                .replace("httpd", "")
                .trim()
                .to_string();
            if !without_httpd.is_empty() {
                queries.push(without_httpd);
            }
        }

        // 3. Try just the product name
        let parts: Vec<&str> = original_trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            queries.push(format!("{} {}", parts[0], parts[1]));
        }

        // 4. Try just the first part (product name only)
        if !parts.is_empty() {
            queries.push(parts[0].to_string());
        }

        // 5. Try with different service keywords
        if original_trimmed.contains("Apache") {
            queries.push("Apache".to_string());
            queries.push("Apache webserver".to_string());
            queries.push("Apache http server".to_string());
        }

        // 6. Try common web server terms
        if original_trimmed.contains("http") {
            queries.push("http server".to_string());
            queries.push("web server".to_string());
        }

        // Remove duplicates while preserving order
        queries.dedup();

        // Limit to reasonable number of queries
        queries.truncate(6);

        queries
    }

    /// Search with specific strategy
    pub async fn search_with_strategy(
        &self,
        query: &str,
        timeout: Duration,
    ) -> Result<Vec<Exploit>> {
        let args = vec![query];
        let output = self.execute_with_timeout(&args, timeout).await?;
        self.parse_searchsploit_output(&output)
    }

    /// Parse searchsploit output
    fn parse_searchsploit_output(&self, output: &Output) -> Result<Vec<Exploit>> {
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OxideScannerError::external_tool(
                "searchsploit",
                format!("Command failed: {}", stderr),
            ));
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let mut exploits = Vec::new();

        for line in text.lines() {
            if self.should_skip_line(line) {
                continue;
            }

            if let Some(exploit) = self.parse_exploit_line(line)? {
                exploits.push(exploit);
            }
        }

        Ok(exploits)
    }

    /// Check if line should be skipped during parsing
    fn should_skip_line(&self, line: &str) -> bool {
        line.contains("----")
            || line.contains("Exploit Title")
            || line.contains("Title")
            || line.contains("Path")
            || line.trim().is_empty()
            || line.starts_with("  #")
    }

    /// Parse individual exploit line
    fn parse_exploit_line(&self, line: &str) -> Result<Option<Exploit>> {
        let parts: Vec<_> = line.splitn(3, " | ").collect();
        if parts.len() < 2 {
            return Ok(None);
        }

        let title = parts[0].trim().to_string();

        // Skip if title looks like an ID number
        if title.parse::<u32>().is_ok() {
            return Ok(None);
        }

        let path = if parts.len() == 3 {
            format!("{} | {}", parts[1].trim(), parts[2].trim())
        } else {
            parts[1].trim().to_string()
        };

        let cvss_score = self.extract_cvss(&title);
        let url = self.build_exploit_url(&path);

        Ok(Some(Exploit {
            title,
            url,
            cvss: cvss_score,
            path,
        }))
    }

    /// Extract CVSS score from exploit title
    fn extract_cvss(&self, text: &str) -> Option<f32> {
        let text_lower = text.to_lowercase();

        // Use constants for CVSS scoring
        if text_lower.contains("pre-authentication rce")
            || text_lower.contains("unauthenticated rce")
        {
            Some(constants::cvss::PRE_AUTH_RCE)
        } else if text_lower.contains("remote code execution") || text_lower.contains("rce") {
            Some(constants::cvss::RCE)
        } else if text_lower.contains("authentication bypass")
            && (text_lower.contains("remote") || text_lower.contains("network"))
        {
            Some(constants::cvss::AUTH_BYPASS_REMOTE)
        } else if text_lower.contains("sql injection")
            && (text_lower.contains("blind") || text_lower.contains("time-based"))
        {
            Some(constants::cvss::BLIND_SQLI)
        } else if text_lower.contains("sql injection") || text_lower.contains("sqli") {
            Some(constants::cvss::SQLI)
        } else if text_lower.contains("buffer overflow") && text_lower.contains("remote") {
            Some(constants::cvss::REMOTE_BUFFER_OVERFLOW)
        } else if text_lower.contains("buffer overflow") {
            Some(constants::cvss::BUFFER_OVERFLOW)
        } else if text_lower.contains("file upload") && text_lower.contains("remote code execution")
        {
            Some(constants::cvss::FILE_UPLOAD_RCE)
        } else if text_lower.contains("file upload") {
            Some(constants::cvss::FILE_UPLOAD)
        } else if text_lower.contains("privilege escalation") && text_lower.contains("root") {
            Some(constants::cvss::ROOT_PRIV_ESC)
        } else if text_lower.contains("privilege escalation") {
            Some(constants::cvss::PRIV_ESC)
        } else if text_lower.contains("remote command injection") {
            Some(constants::cvss::REMOTE_CMD_INJECTION)
        } else if text_lower.contains("command injection") {
            Some(constants::cvss::CMD_INJECTION)
        } else if text_lower.contains("deserialization") && text_lower.contains("remote") {
            Some(constants::cvss::REMOTE_DESERIALIZATION)
        } else if text_lower.contains("directory traversal") && text_lower.contains("root") {
            Some(constants::cvss::ROOT_DIR_TRAVERSAL)
        } else if text_lower.contains("directory traversal")
            || text_lower.contains("path traversal")
        {
            Some(constants::cvss::DIR_TRAVERSAL)
        } else if text_lower.contains("cross-site scripting") && text_lower.contains("stored") {
            Some(constants::cvss::STORED_XSS)
        } else if text_lower.contains("xss")
            || text_lower.contains("cross site")
            || text_lower.contains("cross-site scripting")
        {
            Some(constants::cvss::XSS)
        } else if text_lower.contains("csrf") || text_lower.contains("cross-site request forgery") {
            Some(constants::cvss::CSRF)
        } else if text_lower.contains("ssrf") {
            Some(constants::cvss::SSRF)
        } else if text_lower.contains("denial of service") || text_lower.contains("dos") {
            Some(constants::cvss::DOS)
        } else if text_lower.contains("information disclosure") && text_lower.contains("sensitive")
        {
            Some(constants::cvss::SENSITIVE_INFO_DISCLOSURE)
        } else if text_lower.contains("information disclosure") {
            Some(constants::cvss::INFO_DISCLOSURE)
        } else if text_lower.contains("brute force") {
            Some(constants::cvss::BRUTE_FORCE)
        } else if text_lower.contains("clickjacking") {
            Some(constants::cvss::CLICKJACKING)
        } else {
            None
        }
    }

    /// Build exploit URL from path
    fn build_exploit_url(&self, path: &str) -> String {
        let exploit_id = path
            .split('/')
            .next_back()
            .unwrap_or(path)
            .replace(".txt", "")
            .replace(".rb", "");

        format!("https://www.exploit-db.com/{}", exploit_id)
    }

    /// Sort exploits by CVSS score and relevance
    fn sort_exploits(&self, exploits: &mut [Exploit]) {
        exploits.sort_by(|a, b| match (a.cvss, b.cvss) {
            (Some(a_score), Some(b_score)) => b_score
                .partial_cmp(&a_score)
                .unwrap_or(std::cmp::Ordering::Equal),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.title.cmp(&b.title),
        });
    }
}

impl ExternalTool for ExploitSearcher {
    async fn execute_with_timeout(&self, args: &[&str], timeout: Duration) -> Result<Output> {
        self.base_tool.execute_command(args, timeout).await
    }

    fn name(&self) -> &str {
        "searchsploit"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cvss() {
        let searcher = ExploitSearcher::new().unwrap();

        assert_eq!(searcher.extract_cvss("Remote Code Execution"), Some(9.8));
        assert_eq!(searcher.extract_cvss("SQL Injection"), Some(8.1));
        assert_eq!(searcher.extract_cvss("Some random exploit"), None);
    }

    #[test]
    fn test_should_skip_line() {
        let searcher = ExploitSearcher::new().unwrap();

        assert!(searcher.should_skip_line("----"));
        assert!(searcher.should_skip_line("Exploit Title | Path"));
        assert!(searcher.should_skip_line(""));
        assert!(searcher.should_skip_line("  # Comment"));
        assert!(!searcher.should_skip_line("Some exploit title | /path/to/exploit"));
    }

    #[test]
    fn test_parse_exploit_line() {
        let searcher = ExploitSearcher::new().unwrap();

        let line = "Test Exploit | /path/to/exploit.txt | Description";
        let result = searcher.parse_exploit_line(line).unwrap().unwrap();

        assert_eq!(result.title, "Test Exploit");
        assert_eq!(result.path, "/path/to/exploit.txt | Description");
        assert_eq!(
            result.url,
            "https://www.exploit-db.com/exploit | Description"
        );
    }
}
