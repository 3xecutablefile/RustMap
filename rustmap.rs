// rustmap - fast port scanner and exploit finder written in Rust
// made by: 3xecutablefile

use colored::*;

use rayon::prelude::*;
use std::sync::Once;

use roxmltree::Document;
use serde::Serialize;
use std::collections::HashSet;
use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};



#[derive(Clone, Debug, Serialize)]
struct Port {
    port: u16,
    service: String,
    product: String,
    version: String,
}

#[derive(Clone, Debug, Serialize)]
struct Exploit {
    title: String,
    url: String,
    cvss: Option<f32>,
    path: String,
}

#[derive(Clone, Debug, Serialize)]
struct PortResult {
    port: Port,
    exploits: Vec<Exploit>,
    risk_score: f32,
}



static INIT: Once = Once::new();

fn print_usage() {
    println!("{} RustMap - Fast Port Scanner & Exploit Finder", "INFO".bright_cyan().bold());
    println!();
    println!("{} Usage:", "INFO".bright_blue().bold());
    println!("  rustmap <target> [-Nk] [--json]");
    println!("  rustmap --update");
    println!();
    println!("{} Arguments:", "INFO".bright_blue().bold());
    println!("  <target>          IP address or hostname to scan (required)");
    println!();
    println!("{} Options:", "INFO".bright_blue().bold());
    println!("  -1k, -2k, -30k   Scan top N*1000 ports (e.g. -5k = 5000 ports)");
    println!("  --json           Output results in JSON format");
    println!("  --update         Update searchsploit database and repository");
    println!();
    println!("{} Examples:", "INFO".bright_blue().bold());
    println!("  rustmap scanme.nmap.org");
    println!("  rustmap scanme.nmap.org -1k");
    println!("  rustmap scanme.nmap.org -5k --json");
    println!("  rustmap --update");
    println!();
    println!("{} Quick Start:", "INFO".bright_green().bold());
    println!("  # Scan top 1000 ports (fast)");
    println!("  rustmap example.com -1k");
    println!();
    println!("  # Interactive mode (prompts for port count)");
    println!("  rustmap example.com");
    println!();
    println!("{} For more info: https://github.com/3xecutablefile/RustMap", "INFO".bright_black());
}

fn main() {
    INIT.call_once(|| {
        rayon::ThreadPoolBuilder::new().build_global().unwrap();
    });
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    // Handle update command
    if args[1] == "--update" {
        update_searchsploit();
        return;
    }

    let target = &args[1];
    let json_mode = args.contains(&"--json".to_string());
    let port_limit = if args.iter().any(|arg| arg.starts_with('-') && arg.ends_with('k')) {
        parse_port_limit(&args)
    } else {
        print!("{} Enter number of ports to scan (1-65535, or 'all' for full scan): ", "->".bright_cyan());
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let input = input.trim().to_lowercase();
        
        if input == "all" {
            65535
        } else if let Ok(num) = input.parse::<u16>() {
            if num == 0 {
                eprintln!("{} Port number must be greater than 0", "ERROR".red().bold());
                std::process::exit(1);
            }
            num
        } else {
            eprintln!("{} Invalid port number: {}", "ERROR".red().bold(), input);
            std::process::exit(1);
        }
    };

    // check if required binaries exist
    if !check_binary_in_path("searchsploit") {
        eprintln!("{} searchsploit not found in PATH", "ERROR".red().bold());
        std::process::exit(1);
    }
    if !check_binary_in_path("nmap") {
        eprintln!("{} nmap not found in PATH", "ERROR".red().bold());
        std::process::exit(1);
    }

    // resolve target once
    let target_addrs = match resolve_target_addrs(target) {
        Ok(addrs) => addrs,
        Err(e) => {
            eprintln!("{} {}", "ERROR".red().bold(), e);
            std::process::exit(1);
        }
    };

    if !json_mode {
        println!(
            "{} Fast scanning {} ports on {}...",
            "INFO".bright_yellow(),
            if port_limit == 65535 {
                "all".to_string()
            } else {
                format!("top {}", port_limit)
            },
            target
        );
    }

    let start = Instant::now();
    let open_ports = fast_scan_all(&target_addrs, json_mode, port_limit);

    if open_ports.is_empty() {
        if !json_mode {
            println!("{} No open ports found", "WARNING".yellow());
        }
        std::process::exit(0);
    }

    if !json_mode {
        println!(
            "\n{} Found {} open ports in {:.2?}",
            "SUCCESS".bright_green(),
            open_ports.len(),
            start.elapsed()
        );
        
        // Display open ports immediately
        println!("\n{} Open Ports:", "INFO".bright_cyan().bold());
        for port in &open_ports {
            println!("  {} Port {}", "->".bright_blue(), port.port);
        }
        
        println!(
            "\n{} Detecting services with nmap-style probes...",
            "INFO".bright_cyan()
        );
    }

    let ports = detect_services(target, &open_ports, json_mode);

    if ports.is_empty() {
        if !json_mode {
            println!("{} No services detected", "WARNING".yellow());
        }
        std::process::exit(0);
    }

    if !json_mode {
        println!("\n{} Service Detection Results:", "INFO".bright_green().bold());
        for port in &ports {
            let service_info = if !port.product.is_empty() {
                format!("{} {} {}", port.service.bright_cyan(), port.product.bright_white(), port.version.bright_black())
            } else {
                port.service.bright_cyan().to_string()
            };
            println!("  {} Port {}: {}", "->".bright_blue(), port.port, service_info);
        }
    }

    if !json_mode {
        println!(
            "\n{} Searching exploits and calculating risk scores...\n",
            "INFO".bright_magenta()
        );
    }

    // collect unique queries sequentially (no parallel exploit lookups)
    let mut queries = Vec::new();
    let mut seen_q = HashSet::new();
    for port in &ports {
        let q = build_query(&port.product, &port.version, &port.service);
        if !q.is_empty() && seen_q.insert(q.clone()) {
            queries.push((q, port.clone()));
        }
    }

    let results = Arc::new(Mutex::new(Vec::new()));

    // run searchsploit sequentially
    for (q, example_port) in queries {
        match search_exploits_default(&q) {
            Ok(exploits) => {
                if !exploits.is_empty() {
                    let risk_score = calculate_risk(&exploits, &example_port.service);
                    results.lock().unwrap().push(PortResult {
                        port: example_port.clone(),
                        exploits,
                        risk_score,
                    });
                }
            }
            Err(e) => {
                if !json_mode {
                    eprintln!("{} searchsploit error for {}: {}", "WARNING".yellow(), q, e);
                }
            }
        }
    }

    let mut final_results = results.lock().unwrap().clone();
    final_results.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if json_mode {
        println!("{}", serde_json::to_string_pretty(&final_results).unwrap());
        return;
    }

    if !final_results.is_empty() {
        println!("\n{} Exploit Analysis Results:", "INFO".bright_magenta().bold());
        for result in &final_results {
            print_results(result);
        }
        
        // Summary
        let total_exploits: usize = final_results.iter().map(|r| r.exploits.len()).sum();
        
        println!("\n{} Summary:", "INFO".bright_cyan().bold());
        println!(
            "  {} Total exploits found: {}",
            "->".bright_blue(),
            total_exploits.to_string().bright_yellow()
        );
        println!(
            "  {} Services analyzed: {}",
            "->".bright_blue(),
            final_results.len().to_string().bright_green()
        );
        
    } else {
        println!(
            "\n{} No exploits found for detected services.",
            "SUCCESS".bright_green()
        );
        println!("\n{} Secure Services:", "INFO".bright_green().bold());
        for port in &ports {
            let service_info = if !port.product.is_empty() {
                format!("{} {} {}", port.service.bright_cyan(), port.product.bright_white(), port.version.bright_black())
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
        
        println!("\n{} This is good! However, keep in mind:", "INFO".bright_yellow().bold());
        println!("  {} No public exploits != No vulnerabilities", "->".bright_yellow());
        println!("  {} Always verify services are up-to-date", "->".bright_yellow());
        println!("  {} Consider running additional security scans", "->".bright_yellow());
    }
}

fn update_searchsploit() {
    println!("{} Updating searchsploit database...", "INFO".bright_cyan());
    
    // Update searchsploit
    let output = Command::new("searchsploit")
        .args(["--update"])
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                println!("{} Searchsploit database updated successfully", "SUCCESS".bright_green());
                println!("{}", String::from_utf8_lossy(&result.stdout));
            } else {
                eprintln!("{} Failed to update searchsploit: {}", "ERROR".red().bold(), 
                         String::from_utf8_lossy(&result.stderr));
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{} Failed to execute searchsploit: {}", "ERROR".red().bold(), e);
            std::process::exit(1);
        }
    }
    
    // Update rustmap from git repo
    println!("{} Updating RustMap from repository...", "INFO".bright_cyan());
    
    // Check if we're in a git repo
    let git_check = Command::new("git")
        .args(["status"])
        .output();
    
    match git_check {
        Ok(result) => {
            if result.status.success() {
                // Pull latest changes
                let pull_output = Command::new("git")
                    .args(["pull", "origin", "main"])
                    .output();
                
                match pull_output {
                    Ok(pull_result) => {
                        if pull_result.status.success() {
                            println!("{} RustMap repository updated successfully", "SUCCESS".bright_green());
                            println!("{}", String::from_utf8_lossy(&pull_result.stdout));
                        } else {
                            eprintln!("{} Failed to pull latest changes: {}", "WARNING".yellow(),
                                     String::from_utf8_lossy(&pull_result.stderr));
                        }
                    }
                    Err(e) => {
                        eprintln!("{} Failed to execute git pull: {}", "WARNING".yellow(), e);
                    }
                }
            } else {
                println!("{} Not a git repository, skipping repository update", "WARNING".yellow());
            }
        }
        Err(e) => {
            eprintln!("{} Git not available or not in git repository: {}", "WARNING".yellow(), e);
        }
    }
    
    println!("{} Update completed", "SUCCESS".bright_green());
}

fn parse_port_limit(args: &[String]) -> u16 {
    for arg in args {
        if arg.starts_with('-') && arg.ends_with('k') {
            let num_str = &arg[1..arg.len() - 1];
            if let Ok(num) = num_str.parse::<u16>() {
                if (1..=30).contains(&num) {
                    return num * 1000;
                }
            }
        }
    }
    65535
}

fn resolve_target_addrs(target: &str) -> Result<Vec<SocketAddr>, String> {
    let base = format!("{}:0", target);
    match base.to_socket_addrs() {
        Ok(iter) => {
            let addrs: Vec<SocketAddr> = iter.collect();
            if addrs.is_empty() {
                Err(format!("could not resolve target: {}", target))
            } else {
                Ok(addrs)
            }
        }
        Err(e) => Err(format!("resolve error: {}", e)),
    }
}

fn tcp_connect_addrs(addrs: &[SocketAddr], port: u16, timeout: Duration) -> bool {
    for base in addrs {
        let mut sa = *base;
        sa.set_port(port);
        match TcpStream::connect_timeout(&sa, timeout) {
            Ok(_) => return true,
            Err(_) => continue,
        }
    }
    false
}

fn check_binary_in_path(bin: &str) -> bool {
    match Command::new("which").arg(bin).output() {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

fn fast_scan_all(target_addrs: &[SocketAddr], quiet: bool, port_limit: u16) -> Vec<Port> {
    let timeout = Duration::from_millis(25);
    let scanned = Arc::new(AtomicUsize::new(0));

    let ports: Vec<u16> = get_port_list(port_limit);
    let total = ports.len();
    let ports_arc = Arc::new(ports);

    let progress_handle = if !quiet {
        let scanned_clone = Arc::clone(&scanned);
        Some(thread::spawn(move || {
            let start = Instant::now();
            loop {
                let sc = scanned_clone.load(Ordering::Relaxed);
                let percent = if total > 0 { (sc * 100) / total } else { 100 };
                let bar = progress_bar(percent, 40);

                print!(
                    "\r[{}] {:3}% | {}/{} scanned | {:.1}s",
                    bar,
                    percent,
                    sc,
                    total,
                    start.elapsed().as_secs_f32()
                );
                std::io::stdout().flush().unwrap();

                if sc >= total {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            print!("\r");
            std::io::stdout().flush().unwrap();
        }))
    } else {
        None
    };

    // lock-free collection
    let addrs_clone = target_addrs.to_vec();
    let found: Vec<Port> = ports_arc
        .par_iter()
        .map_init(
            || addrs_clone.clone(),
            |addrs_local, &port| {
                let ok = tcp_connect_addrs(addrs_local, port, timeout);
                scanned.fetch_add(1, Ordering::Relaxed);
                if ok {
                    Some(Port {
                        port,
                        service: "".to_string(),
                        product: "".to_string(),
                        version: "".to_string(),
                    })
                } else {
                    None
                }
            },
        )
        .filter_map(|x| x)
        .collect();

    if let Some(h) = progress_handle {
        h.join().unwrap();
    }

    let mut result = found;
    result.sort_by_key(|p| p.port);
    result
}

fn get_port_list(limit: u16) -> Vec<u16> {
    if limit == u16::MAX {
        return (1..=u16::MAX).collect();
    }
    (1..=limit).collect()
}

fn progress_bar(percent: usize, width: usize) -> String {
    let filled = (percent * width) / 100;
    let mut bar = String::new();
    for i in 0..width {
        if i < filled {
            bar.push('█');
        } else {
            bar.push('░');
        }
    }
    bar
}

fn detect_services(target: &str, ports: &[Port], quiet: bool) -> Vec<Port> {
    if ports.is_empty() {
        return Vec::new();
    }

    if !quiet {
        println!("{} Running nmap service detection...", "INFO".bright_cyan());
    }

    let port_list: Vec<String> = ports.iter().map(|p| p.port.to_string()).collect();
    let ports_str = port_list.join(",");

    let output = Command::new("nmap")
        .args([
            "-sV",
            "--version-intensity",
            "1",
            "-p",
            &ports_str,
            "-oX",
            "-",
            "--open",
            "--disable-arp-ping",
            "-Pn",
            target,
        ])
        .output()
        .map_err(|e| format!("nmap execution failed: {}", e));

    match output {
        Ok(result) => {
            if !result.status.success() {
                if !quiet {
                    eprintln!("{} nmap failed: {}", "WARNING".yellow(), 
                             String::from_utf8_lossy(&result.stderr));
                }
                return Vec::new();
            }

            let xml_content = String::from_utf8_lossy(&result.stdout);
            // Remove DTD declaration if present
            let xml_clean = xml_content.lines()
                .filter(|line| !line.trim().starts_with("<!DOCTYPE"))
                .collect::<Vec<_>>()
                .join("\n");
            parse_nmap_xml(&xml_clean, &[])
        }
        Err(e) => {
            if !quiet {
                eprintln!("{} {}", "ERROR".red().bold(), e);
            }
            Vec::new()
        }
    }
}



fn parse_nmap_xml(xml_content: &str, _original_ports: &[Port]) -> Vec<Port> {
    let mut detected_ports = Vec::new();

    let doc = match Document::parse(xml_content) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{} Failed to parse nmap XML: {}", "WARNING".yellow(), e);
            return detected_ports;
        }
    };

    let root = doc.root_element();
    if root.tag_name().name() != "nmaprun" {
        eprintln!("{} Invalid nmap XML format", "WARNING".yellow());
        return detected_ports;
    }

    for host in root.children() {
        if host.tag_name().name() != "host" {
            continue;
        }

        for ports_elem in host.children() {
            if ports_elem.tag_name().name() != "ports" {
                continue;
            }

            for port_elem in ports_elem.children() {
                if port_elem.tag_name().name() != "port" {
                    continue;
                }

                let port_id = match port_elem.attribute("portid") {
                    Some(p) => p.parse::<u16>().unwrap_or(0),
                    None => continue,
                };

                if port_id == 0 {
                    continue;
                }

                let mut service_name = "unknown".to_string();
                let mut product = "".to_string();
                let mut version = "".to_string();

                for service_elem in port_elem.children() {
                    if service_elem.tag_name().name() != "service" {
                        continue;
                    }

                    service_name = service_elem
                        .attribute("name")
                        .unwrap_or("unknown")
                        .to_string();

                    product = service_elem.attribute("product").unwrap_or("").to_string();

                    version = service_elem.attribute("version").unwrap_or("").to_string();

                    break;
                }

                detected_ports.push(Port {
                    port: port_id,
                    service: service_name,
                    product,
                    version,
                });
            }
        }
    }

    detected_ports.sort_by_key(|p| p.port);
    detected_ports
}



fn build_query(product: &str, version: &str, service: &str) -> String {
    // Build multiple search queries for better results
    let product_version = format!("{} {}", product, version).trim().to_string();
    
    // Prefer product+version if available
    if !product_version.is_empty() && product_version != " " {
        return product_version;
    }
    
    // Fall back to product only
    if !product.is_empty() {
        return product.to_string();
    }
    
    // Finally use service name
    service.to_string()
}

fn search_exploits_default(query: &str) -> Result<Vec<Exploit>, String> {
    // Try multiple search strategies for better results
    let mut all_exploits = Vec::new();
    
    // Strategy 1: Exact match search
    if let Ok(exploits) = search_exploits_with_options(query, &["-e"]) {
        all_exploits.extend(exploits);
    }
    
    // Strategy 2: Fuzzy search if no exact results
    if all_exploits.is_empty() {
        if let Ok(exploits) = search_exploits_with_options(query, &[]) {
            all_exploits.extend(exploits);
        }
    }
    
    // Strategy 3: Try searching for just the service name if query is complex
    if all_exploits.is_empty() && query.contains(' ') {
        let simple_query = query.split_whitespace().next().unwrap_or(query);
        if let Ok(exploits) = search_exploits_with_options(simple_query, &[]) {
            all_exploits.extend(exploits);
        }
    }
    
    // Remove duplicates and sort by relevance
    all_exploits.sort_by(|a, b| {
        // Prioritize exploits with CVSS scores
        match (a.cvss, b.cvss) {
            (Some(a_score), Some(b_score)) => b_score.partial_cmp(&a_score).unwrap_or(std::cmp::Ordering::Equal),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.title.cmp(&b.title),
        }
    });
    
    all_exploits.dedup_by(|a, b| a.title == b.title && a.path == b.path);
    
    Ok(all_exploits)
}

fn search_exploits_with_options(query: &str, options: &[&str]) -> Result<Vec<Exploit>, String> {
    let mut cmd = Command::new("timeout");
    cmd.args(["10", "searchsploit"]);
    
    // Add options if provided
    for opt in options {
        cmd.arg(opt);
    }
    
    cmd.arg(query);
    
    let out = cmd.output()
        .map_err(|e| format!("searchsploit execution failed: {}", e))?;

    if !out.status.success() {
        return Err(format!(
            "searchsploit failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut exploits = Vec::new();

    for line in text.lines() {
        // Skip header lines and separators
        if line.contains("----") || 
           line.contains("Exploit Title") || 
           line.contains("Title") || 
           line.contains("Path") || 
           line.trim().is_empty() ||
           line.starts_with("  #") {
            continue;
        }
        
        // Parse the exploit line format: "Title | Path"
        let parts: Vec<_> = line.splitn(3, " | ").collect();
        if parts.len() >= 2 {
            let title = parts[0].trim().to_string();
            let path = if parts.len() == 3 {
                format!("{} | {}", parts[1].trim(), parts[2].trim())
            } else {
                parts[1].trim().to_string()
            };
            
            // Skip if title is just a number and space (malformed line)
            if title.trim().parse::<u32>().is_ok() && title.trim().len() < 5 {
                continue;
            }
            
            let cvss_score = extract_cvss(&title);
            let url = format!("https://www.exploit-db.com/{}", 
                path.split('/').next_back().unwrap_or(&path).replace(".txt", "").replace(".rb", ""));
            
            exploits.push(Exploit {
                title,
                url,
                cvss: cvss_score,
                path,
            });
        }
    }
    
    Ok(exploits)
}

fn extract_cvss(text: &str) -> Option<f32> {
    let t = text.to_lowercase();

    // Critical vulnerabilities (9.0-10.0)
    if t.contains("remote code execution") || t.contains("rce") {
        Some(9.8)
    } else if t.contains("pre-authentication rce") || t.contains("unauthenticated rce") {
        Some(10.0)
    } else if t.contains("authentication bypass") && (t.contains("remote") || t.contains("network")) {
        Some(9.8)
    } else if t.contains("authentication bypass") {
        Some(9.1)
    } else if t.contains("sql injection") && (t.contains("blind") || t.contains("time-based")) {
        Some(8.9)
    } else if t.contains("sql injection") || t.contains("sqli") {
        Some(8.1)
    } else if t.contains("buffer overflow") && t.contains("remote") {
        Some(9.3)
    } else if t.contains("buffer overflow") {
        Some(8.5)
    } else if t.contains("file upload") && t.contains("remote code execution") {
        Some(9.8)
    } else if t.contains("file upload") {
        Some(8.9)
    } 
    // High vulnerabilities (7.0-8.9)
    else if t.contains("privilege escalation") && t.contains("root") {
        Some(8.8)
    } else if t.contains("privilege escalation") {
        Some(7.8)
    } else if t.contains("remote command injection") {
        Some(9.0)
    } else if t.contains("command injection") {
        Some(8.6)
    } else if t.contains("deserialization") && t.contains("remote") {
        Some(8.5)
    } 
    // Medium vulnerabilities (4.0-6.9)
    else if t.contains("directory traversal") && t.contains("root") {
        Some(7.5)
    } else if t.contains("directory traversal") || t.contains("path traversal") {
        Some(6.8)
    } else if t.contains("cross-site scripting") && t.contains("stored") {
        Some(7.5)
    } else if t.contains("xss") || t.contains("cross site") || t.contains("cross-site scripting") {
        Some(6.1)
    } else if t.contains("csrf") || t.contains("cross-site request forgery") {
        Some(6.5)
    } else if t.contains("denial of service") || t.contains("dos") {
        Some(5.3)
    } else if t.contains("information disclosure") && t.contains("sensitive") {
        Some(5.5)
    } else if t.contains("information disclosure") {
        Some(4.3)
    } 
    // Low vulnerabilities (0.1-3.9)
    else if t.contains("brute force") {
        Some(5.0)
    } else if t.contains("clickjacking") {
        Some(4.3)
    } else if t.contains("ssrf") {
        Some(7.5)
    } else {
        None
    }
}

fn calculate_risk(exploits: &[Exploit], service: &str) -> f32 {
    let mut score = 0.0;

    score += (exploits.len() as f32).min(10.0) * 2.0;

    for exploit in exploits {
        if let Some(cvss) = exploit.cvss {
            score += cvss;
        } else {
            score += 5.0;
        }
    }

    let multiplier = match service {
        "smb" | "netbios-ssn" | "microsoft-ds" => 1.8,
        "mysql" | "postgresql" | "mssql" => 1.6,
        "ssh" | "telnet" | "ftp" => 1.5,
        "http" | "https" | "ssl" => 1.3,
        _ => 1.0,
    };

    score * multiplier
}

fn print_results(result: &PortResult) {
    let port = &result.port;
    let exploits = &result.exploits;

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

    let header = format!(
        "Port {} | {} | {} exploits",
        port.port,
        service_info,
        exploits.len()
    );

    println!("\n{}╭{}╮", "┃".bright_black(), "━".repeat(header.len() + 4));
    println!(
        "{}│ {} {}│",
        "┃".bright_black(),
        header,
        "┃".bright_black()
    );
    println!("{}├{}┤", "┃".bright_black(), "─".repeat(header.len() + 4));

    if exploits.is_empty() {
        println!(
            "{}│  {} No exploits found {}│",
            "┃".bright_black(),
            "✓".bright_green(),
            "┃".bright_black()
        );
    } else {
        for (i, exploit) in exploits.iter().take(10).enumerate() {
            let cvss_indicator = if let Some(cvss) = exploit.cvss {
                if cvss >= 9.0 {
                    format!(" {}{} ", "[".red(), format!("{:.1}", cvss).red().bold())
                } else if cvss >= 7.0 {
                    format!(" {}{} ", "[".bright_red(), format!("{:.1}", cvss).bright_red().bold())
                } else if cvss >= 4.0 {
                    format!(" {}{} ", "[".yellow(), format!("{:.1}", cvss).yellow().bold())
                } else {
                    format!(" {}{} ", "[".green(), format!("{:.1}", cvss).green())
                }
            } else {
                " [?.?] ".bright_black().to_string()
            };

            println!(
                "{}│{} {} {} {}│",
                "┃".bright_black(),
                cvss_indicator,
                (i + 1).to_string().bright_blue(),
                exploit.title,
                "┃".bright_black()
            );
            
            if !exploit.path.is_empty() {
                println!(
                    "{}│    {} {}│",
                    "┃".bright_black(),
                    exploit.path.bright_black(),
                    "┃".bright_black()
                );
            }
            
            if i < exploits.len().saturating_sub(1) && i < 9 {
                println!("{}│{}│", "┃".bright_black(), " ".repeat(header.len() + 2));
            }
        }

        if exploits.len() > 10 {
            println!(
                "{}│  {} {} more exploits available {}│",
                "┃".bright_black(),
                "...".bright_black(),
                (exploits.len() - 10).to_string().bright_yellow(),
                "┃".bright_black()
            );
        }
    }

    println!("{}╰{}╯", "┃".bright_black(), "━".repeat(header.len() + 4));
}