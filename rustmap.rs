// rustmap - fast port scanner and exploit finder written in Rust
// made by: 3xecutablefile

use colored::*;
use once_cell::sync::Lazy;
use rayon::prelude::*;
use std::sync::Once;
use regex::Regex;
use roxmltree::Document;
use serde::Serialize;
use std::collections::HashSet;
use std::io::{Write, Read};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

// static compiled regexes
static ANSI_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\x1b\[[0-9;]*[mK]").expect("ansi regex"));

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

fn main() {
    INIT.call_once(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(0) // Use all available threads
            .build_global()
            .unwrap();
    });
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!(
            "{}",
            "usage: rustmap <target> [--json]"
                .red()
                .bold()
        );
        std::process::exit(1);
    }

    let target = &args[1];
    let json_mode = args.contains(&"--json".to_string());
    let port_limit = if args.iter().any(|arg| arg.starts_with('-') && arg.ends_with('k')) {
        parse_port_limit(&args)
    } else {
        print!("{} Enter number of ports to scan (1-65535, or 'all' for full scan): ", "→".bright_cyan());
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let input = input.trim().to_lowercase();
        
        if input == "all" {
            65535
        } else if let Ok(num) = input.parse::<u16>() {
            if num == 0 {
                eprintln!("{} Port number must be greater than 0", "✗".red().bold());
                std::process::exit(1);
            }
            num
        } else {
            eprintln!("{} Invalid port number: {}", "✗".red().bold(), input);
            std::process::exit(1);
        }
    };

    // check if required binaries exist
    if !check_binary_in_path("searchsploit") {
        eprintln!("{} searchsploit not found in PATH", "✗".red().bold());
        std::process::exit(1);
    }
    if !check_binary_in_path("nmap") {
        eprintln!("{} nmap not found in PATH", "✗".red().bold());
        std::process::exit(1);
    }

    // resolve target once
    let target_addrs = match resolve_target_addrs(target) {
        Ok(addrs) => addrs,
        Err(e) => {
            eprintln!("{} {}", "✗".red().bold(), e);
            std::process::exit(1);
        }
    };

    if !json_mode {
        println!(
            "{} Fast scanning {} ports on {}...",
            "⚡".bright_yellow(),
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
            println!("{} No open ports found", "⚠".yellow());
        }
        std::process::exit(0);
    }

    if !json_mode {
        println!(
            "{} Found {} open ports in {:.2?}",
            "✓".bright_green(),
            open_ports.len(),
            start.elapsed()
        );
        println!(
            "{} Detecting services with nmap-style probes...",
            "🔍".bright_cyan()
        );
    }

    let ports = detect_services(target, &open_ports, json_mode);

    if ports.is_empty() {
        if !json_mode {
            println!("{} No services detected", "⚠".yellow());
        }
        std::process::exit(0);
    }

    if !json_mode {
        println!(
            "{} Searching exploits and calculating risk scores...\n",
            "💥".bright_magenta()
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
                    eprintln!("{} searchsploit error for {}: {}", "⚠".yellow(), q, e);
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
        for result in &final_results {
            print_results(result);
        }
    } else {
        println!(
            "\n{} No exploits found for detected services.",
            "✓".bright_green()
        );
        for port in &ports {
            println!(
                "  {}Port {}: {} {} {}",
                "→".bright_blue(),
                port.port,
                port.service.bright_cyan(),
                port.product.bright_white(),
                port.version.bright_black()
            );
        }
    }
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
            println!();
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
                let ok = tcp_connect_addrs(&addrs_local, port, timeout);
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
        println!("{} Running nmap service detection...", "🔍".bright_cyan());
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
                    eprintln!("{} nmap failed: {}", "⚠".yellow(), 
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
                eprintln!("{} {}", "✗".red().bold(), e);
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
            eprintln!("{} Failed to parse nmap XML: {}", "⚠".yellow(), e);
            return detected_ports;
        }
    };

    let root = doc.root_element();
    if root.tag_name().name() != "nmaprun" {
        eprintln!("{} Invalid nmap XML format", "⚠".yellow());
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

                    product = service_elem
                        .attribute("product")
                        .unwrap_or("")
                        .to_string();

                    version = service_elem
                        .attribute("version")
                        .unwrap_or("")
                        .to_string();

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
    let pv = format!("{} {}", product, version).trim().to_string();
    if !pv.is_empty() {
        return pv;
    }
    service.to_string()
}

fn search_exploits_default(query: &str) -> Result<Vec<Exploit>, String> {
    let out = Command::new("timeout")
        .args(["5", "searchsploit", query])
        .output()
        .map_err(|e| format!("searchsploit: {}", e))?;

    if !out.status.success() {
        return Err(format!(
            "searchsploit failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut exploits = Vec::new();

    for line in text.lines() {
        if line.contains("----") || line.contains("Exploit Title") || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<_> = line.splitn(2, " | ").collect();
        if parts.len() == 2 {
            let title = parts[0].trim().to_string();
            let path = parts[1].trim().to_string();
            let cvss_score = extract_cvss(&title);
            exploits.push(Exploit {
                title,
                url: String::new(),
                cvss: cvss_score,
                path,
            });
        }
    }
    Ok(exploits)
}

fn extract_cvss(text: &str) -> Option<f32> {
    let t = text.to_lowercase();

    if t.contains("remote code execution") || t.contains("rce") {
        Some(9.8)
    } else if t.contains("authentication bypass") {
        Some(9.1)
    } else if t.contains("sql injection") || t.contains("sqli") {
        Some(8.1)
    } else if t.contains("buffer overflow") {
        Some(8.5)
    } else if t.contains("file upload") {
        Some(8.9)
    } else if t.contains("privilege escalation") {
        Some(7.8)
    } else if t.contains("directory traversal") {
        Some(6.8)
    } else if t.contains("xss") || t.contains("cross site") {
        Some(6.1)
    } else if t.contains("denial of service") || t.contains("dos") {
        Some(5.3)
    } else if t.contains("information disclosure") {
        Some(4.3)
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

    let risk_color = if result.risk_score >= 50.0 {
        "🔴 CRITICAL".red().bold()
    } else if result.risk_score >= 30.0 {
        "🟠 HIGH".bright_red().bold()
    } else if result.risk_score >= 15.0 {
        "🟡 MEDIUM".yellow().bold()
    } else {
        "🟢 LOW".green()
    };

    let mut max_width = 50;
    for exploit in exploits {
        let len = strip_ansi(&format!("{}  {}", exploit.title, exploit.path)).len();
        max_width = max_width.max(len);
    }

    let header = format!(
        "Port {} | {} {} | Risk: {:.1}",
        port.port, port.product, port.version, result.risk_score
    );
    let header_vis = strip_ansi(&header);
    max_width = max_width.max(header_vis.len());
    max_width += 4;

    let bar = "━".repeat(max_width);

    println!("\n{}╭{}╮{}", "".bright_black(), bar, "".clear());
    println!(
        "{}│{} {} {:<width$} {}│{}",
        "".bright_black(),
        "".clear(),
        risk_color,
        header,
        "".bright_black(),
        "".clear(),
        width = max_width.saturating_sub(20)
    );
    println!("{}├{}┤{}", "".bright_black(), bar, "".clear());

    for exploit in exploits.iter().take(10) {
        let line = format!("{}  {}", exploit.title, exploit.path.bright_black());
        println!(
            "{}│{}  {:<width$}  {}│{}",
            "".bright_black(),
            "".clear(),
            line,
            "".bright_black(),
            "".clear(),
            width = max_width - 2
        );
    }

    if exploits.len() > 10 {
        println!(
            "{}│{}  {} more exploits... {}│{}",
            "".bright_black(),
            "".clear(),
            exploits.len() - 10,
            "".bright_black(),
            "".clear()
        );
    }

    println!("{}╰{}╯{}", "".bright_black(), bar, "".clear());
}

fn strip_ansi(s: &str) -> String {
    ANSI_RE.replace_all(s, "").to_string()
}
