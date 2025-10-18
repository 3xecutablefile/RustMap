// rustmap - fast port scanner and exploit finder written in Rust
// made by: 3xecutablefile

use colored::*;
use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::io::{Read, Write};
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
static SSH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"OpenSSH[_-]([0-9.]+p?[0-9]*)").expect("ssh regex"));
static HTTP_SERVER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([^/\s]+)/([0-9.]+)").expect("http server regex"));
static FTP_VSFTPD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"vsFTPd ([0-9.]+)").expect("vsftpd regex"));
static FTP_PROFTPD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"ProFTPD ([0-9.]+)").expect("proftpd regex"));
static FTP_FILEZILLA_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"FileZilla Server ([0-9.]+)").expect("filezilla regex"));
static MYSQL_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([0-9]+\.[0-9]+\.[0-9]+)").expect("mysql version regex"));
static REDIS_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"redis_version:([0-9.]+)").expect("redis version regex"));
static EXIM_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"Exim ([0-9.]+)").expect("exim regex"));

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

struct Probe {
    name: &'static str,
    payload: Vec<u8>,
    ports: Vec<u16>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!(
            "{}",
            "usage: rustmap <target> [-1k|-2k|-3k...|-30k] [--json]"
                .red()
                .bold()
        );
        std::process::exit(1);
    }

    let target = &args[1];
    let json_mode = args.contains(&"--json".to_string());
    let port_limit = parse_port_limit(&args);

    // check if searchsploit exists
    if !check_binary_in_path("searchsploit") {
        eprintln!("{} searchsploit not found in PATH", "✗".red().bold());
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
                if num >= 1 && num <= 30 {
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
        for _ in 0..2 {
            match TcpStream::connect_timeout(&sa, timeout) {
                Ok(_) => return true,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => continue,
                _ => break,
            }
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
    let timeout = Duration::from_millis(80);
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
    if limit >= 65535 {
        return (1..=65535).collect();
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
    let detected = Arc::new(Mutex::new(Vec::new()));
    let scanned = Arc::new(AtomicUsize::new(0));
    let total = ports.len();

    let progress_handle = if !quiet {
        let scanned_clone = Arc::clone(&scanned);
        Some(thread::spawn(move || {
            loop {
                let sc = scanned_clone.load(Ordering::Relaxed);
                let percent = if total > 0 { (sc * 100) / total } else { 100 };
                let bar = progress_bar(percent, 30);
                print!("\r[{}] {:3}% service detection", bar, percent);
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

    ports.par_iter().for_each(|port| {
        let info = probe_service_intensive(target, port.port);
        detected.lock().unwrap().push(info);
        scanned.fetch_add(1, Ordering::Relaxed);
    });

    if let Some(h) = progress_handle {
        h.join().unwrap();
    }

    detected.lock().unwrap().clone()
}

fn probe_service_intensive(host: &str, port: u16) -> Port {
    let probes = get_nmap_probes();

    if let Some(result) = try_null_probe(host, port) {
        return result;
    }

    let relevant_probes: Vec<_> = probes
        .iter()
        .filter(|p| p.ports.is_empty() || p.ports.contains(&port))
        .collect();

    for probe in relevant_probes {
        if let Some(result) = try_probe(host, port, probe) {
            return result;
        }
    }

    let service = get_service_by_port(port);
    Port {
        port,
        service: service.to_string(),
        product: "".to_string(),
        version: "".to_string(),
    }
}

fn try_null_probe(host: &str, port: u16) -> Option<Port> {
    let addr = format!("{}:{}", host, port);
    let mut stream =
        TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_secs(3)).ok()?;

    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let mut buffer = vec![0u8; 4096];

    if let Ok(n) = stream.read(&mut buffer) {
        if n > 0 {
            let response = String::from_utf8_lossy(&buffer[..n]).to_string();
            return parse_response(&response, port);
        }
    }
    None
}

fn try_probe(host: &str, port: u16, probe: &Probe) -> Option<Port> {
    let addr = format!("{}:{}", host, port);
    let mut stream =
        TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_secs(2)).ok()?;

    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;

    if stream.write_all(&probe.payload).is_err() {
        return None;
    }

    let mut buffer = vec![0u8; 8192];
    if let Ok(n) = stream.read(&mut buffer) {
        if n > 0 {
            let response = String::from_utf8_lossy(&buffer[..n]).to_string();
            return parse_response(&response, port);
        }
    }

    None
}

fn get_nmap_probes() -> Vec<Probe> {
    vec![
        Probe {
            name: "GetRequest",
            payload: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
            ports: vec![80, 443, 8080, 8443, 8000, 8888],
        },
        Probe {
            name: "HTTPOptions",
            payload: b"OPTIONS / HTTP/1.0\r\n\r\n".to_vec(),
            ports: vec![80, 443, 8080],
        },
        Probe {
            name: "Help",
            payload: b"HELP\r\n".to_vec(),
            ports: vec![21],
        },
        Probe {
            name: "EHLO",
            payload: b"EHLO nmap.org\r\n".to_vec(),
            ports: vec![25, 587],
        },
        Probe {
            name: "POP3",
            payload: b"CAPA\r\n".to_vec(),
            ports: vec![110, 995],
        },
        Probe {
            name: "IMAP",
            payload: b"A001 CAPABILITY\r\n".to_vec(),
            ports: vec![143, 993],
        },
        Probe {
            name: "MySQL",
            payload: vec![
                0x4a, 0x00, 0x00, 0x01, 0x85, 0xa6, 0xff, 0x01, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00,
                0x00, 0x00,
            ],
            ports: vec![3306],
        },
        Probe {
            name: "SMBProgNeg",
            payload: vec![
                0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18,
                0x53, 0xc8,
            ],
            ports: vec![445, 139],
        },
        Probe {
            name: "SSLSessionReq",
            payload: vec![
                0x16, 0x03, 0x00, 0x00, 0x5a, 0x01, 0x00, 0x00, 0x56, 0x03, 0x00,
            ],
            ports: vec![443, 8443, 465, 993, 995],
        },
        Probe {
            name: "SIPOptions",
            payload: b"OPTIONS sip:nm SIP/2.0\r\n\r\n".to_vec(),
            ports: vec![5060, 5061],
        },
        Probe {
            name: "RTSPRequest",
            payload: b"OPTIONS / RTSP/1.0\r\n\r\n".to_vec(),
            ports: vec![554],
        },
        Probe {
            name: "redis-server",
            payload: b"INFO\r\n".to_vec(),
            ports: vec![6379],
        },
        Probe {
            name: "mongodb",
            payload: vec![0x3a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            ports: vec![27017],
        },
        Probe {
            name: "PostgreSQL",
            payload: vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f],
            ports: vec![5432],
        },
        Probe {
            name: "LDAPBindReq",
            payload: vec![0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02],
            ports: vec![389, 636],
        },
    ]
}

fn parse_response(response: &str, port: u16) -> Option<Port> {
    let lower = response.to_lowercase();

    if response.starts_with("SSH-") {
        let parts: Vec<_> = response.trim().split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        let banner_parts: Vec<_> = parts[0].split('-').collect();
        let version = if banner_parts.len() >= 2 {
            banner_parts[1]
        } else {
            "2.0"
        };
        let product_info = if banner_parts.len() >= 3 {
            banner_parts[2]
        } else {
            ""
        };

        let (product, prod_version) = parse_ssh_banner(product_info);

        return Some(Port {
            port,
            service: "ssh".to_string(),
            product,
            version: format!("{} {}", version, prod_version).trim().to_string(),
        });
    }

    if response.starts_with("HTTP/") {
        let (product, version) = extract_http_info(response);
        return Some(Port {
            port,
            service: if port == 443 { "https" } else { "http" }.to_string(),
            product,
            version,
        });
    }

    if response.starts_with("220") && (lower.contains("ftp") || port == 21) {
        let (product, version) = extract_ftp_info(response);
        return Some(Port {
            port,
            service: "ftp".to_string(),
            product,
            version,
        });
    }

    if response.starts_with("220") && lower.contains("smtp") {
        let (product, version) = extract_smtp_info(response);
        return Some(Port {
            port,
            service: "smtp".to_string(),
            product,
            version,
        });
    }

    if response.starts_with("+OK") {
        return Some(Port {
            port,
            service: "pop3".to_string(),
            product: "".to_string(),
            version: "".to_string(),
        });
    }

    if response.starts_with("* OK") && lower.contains("imap") {
        return Some(Port {
            port,
            service: "imap".to_string(),
            product: "".to_string(),
            version: "".to_string(),
        });
    }

    if response.len() > 10 && (lower.contains("mysql") || lower.contains("mariadb")) {
        let (product, version) = extract_mysql_info(response);
        return Some(Port {
            port,
            service: "mysql".to_string(),
            product,
            version,
        });
    }

    if lower.contains("redis_version") {
        let version = extract_redis_version(response);
        return Some(Port {
            port,
            service: "redis".to_string(),
            product: "Redis".to_string(),
            version,
        });
    }

    if lower.contains("mongodb") || lower.contains("ismaster") {
        return Some(Port {
            port,
            service: "mongodb".to_string(),
            product: "MongoDB".to_string(),
            version: "".to_string(),
        });
    }

    if lower.contains("postgresql") {
        return Some(Port {
            port,
            service: "postgresql".to_string(),
            product: "PostgreSQL".to_string(),
            version: "".to_string(),
        });
    }

    if lower.contains("smb") || lower.contains("samba") {
        return Some(Port {
            port,
            service: "microsoft-ds".to_string(),
            product: "Samba smbd".to_string(),
            version: "".to_string(),
        });
    }

    None
}

fn parse_ssh_banner(banner: &str) -> (String, String) {
    if let Some(cap) = SSH_RE.captures(banner) {
        return ("OpenSSH".to_string(), cap[1].to_string());
    }

    if banner.contains("Cisco") {
        return ("Cisco SSH".to_string(), "".to_string());
    }

    if banner.to_lowercase().contains("dropbear") {
        return ("Dropbear".to_string(), "".to_string());
    }

    ("".to_string(), "".to_string())
}

fn extract_http_info(response: &str) -> (String, String) {
    for line in response.lines() {
        if line.to_lowercase().starts_with("server:") {
            let server = line.split(':').nth(1).unwrap_or("").trim();

            if let Some(cap) = HTTP_SERVER_RE.captures(server) {
                return (cap[1].to_string(), cap[2].to_string());
            }

            return (server.to_string(), "".to_string());
        }
    }
    ("".to_string(), "".to_string())
}

fn extract_ftp_info(banner: &str) -> (String, String) {
    if let Some(cap) = FTP_VSFTPD_RE.captures(banner) {
        return ("vsftpd".to_string(), cap[1].to_string());
    }
    if let Some(cap) = FTP_PROFTPD_RE.captures(banner) {
        return ("ProFTPD".to_string(), cap[1].to_string());
    }
    if let Some(cap) = FTP_FILEZILLA_RE.captures(banner) {
        return ("FileZilla".to_string(), cap[1].to_string());
    }
    if banner.to_lowercase().contains("pure-ftpd") {
        return ("Pure-FTPd".to_string(), "".to_string());
    }

    ("".to_string(), "".to_string())
}

fn extract_smtp_info(banner: &str) -> (String, String) {
    let lower = banner.to_lowercase();
    if lower.contains("postfix") {
        return ("Postfix".to_string(), "".to_string());
    }
    if lower.contains("exim") {
        if let Some(cap) = EXIM_RE.captures(banner) {
            return ("Exim".to_string(), cap[1].to_string());
        }
        return ("Exim".to_string(), "".to_string());
    }
    if lower.contains("sendmail") {
        return ("Sendmail".to_string(), "".to_string());
    }
    ("".to_string(), "".to_string())
}

fn extract_mysql_info(response: &str) -> (String, String) {
    let lower = response.to_lowercase();

    if lower.contains("mariadb") {
        if let Some(cap) = MYSQL_VERSION_RE.find(response) {
            return ("MariaDB".to_string(), cap.as_str().to_string());
        }
        return ("MariaDB".to_string(), "".to_string());
    }

    if let Some(cap) = MYSQL_VERSION_RE.find(response) {
        return ("MySQL".to_string(), cap.as_str().to_string());
    }

    ("MySQL".to_string(), "".to_string())
}

fn extract_redis_version(response: &str) -> String {
    if let Some(cap) = REDIS_VERSION_RE.captures(response) {
        return cap[1].to_string();
    }
    "".to_string()
}

fn get_service_by_port(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        587 => "submission",
        993 => "imaps",
        995 => "pop3s",
        1433 => "ms-sql-s",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        27017 => "mongodb",
        _ => "unknown",
    }
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
        .args(&["5", "searchsploit", query])
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
