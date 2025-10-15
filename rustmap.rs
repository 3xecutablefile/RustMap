// rustmap - fast port scanner and exploit finder written in Rust
// made by: 3xecutablefile

use std::collections::HashSet;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};
use std::time::{Duration, Instant};
use std::io::Write;
use std::thread;
use rayon::prelude::*;
use colored::*;
use serde::Serialize;

// stuff we found on the target
#[derive(Clone, Debug, Serialize)]
struct Port {
port: u16,
service: String,
product: String,
version: String,
}

// exploits n stuff
#[derive(Clone, Debug, Serialize)]
struct Exploit {
title: String,
url: String,
cvss: Option<f32>,
path: String,          // local file inside /usr/share/exploitdb
}

// puts it all together 
#[derive(Clone, Debug, Serialize)]
struct PortResult {
port: Port,
exploits: Vec<Exploit>,
risk_score: f32,
}

fn main() {
let args: Vec<String> = std::env::args().collect();

if args.len() < 2 {
          eprintln!("{}", "usage: rustmap <target> [--nmap-only] [--json]".red().bold());
std::process::exit(1);
}

let target = &args[1];
let nmap_only = args.contains(&"--nmap-only".to_string());
let json_mode = args.contains(&"--json".to_string());

// check if we got the tools we need
for dep in &["nmap", "searchsploit"] {
if Command::new("which").arg(dep).output().is_err() {
eprintln!("{} {} not found", "✗".red().bold(), dep);
std::process::exit(1);
}
}

// do the scan thingy yk
let ports = if nmap_only {
if !json_mode {
println!("{} Running full nmap scan...", "⚡".bright_yellow());
}
nmap_scan_full(target)
} else {
if !json_mode {
println!("{} Fast scanning all 65535 ports on {}...", 
"⚡".bright_yellow(), target);
}

let start = Instant::now();
let open_ports = fast_scan_all(target, json_mode);

if open_ports.is_empty() {
if !json_mode {
println!("{} No open ports found", "⚠".yellow());
}
std::process::exit(0);
}

if !json_mode {
println!("{} Found {} open ports in {:.2?}", 
"✓".bright_green(), open_ports.len(), start.elapsed());
println!("{} Detecting services with nmap...", "🔍".bright_cyan());
}

nmap_scan_ports(target, &open_ports)
};

if ports.is_empty() {
if !json_mode {
println!("{} No services detected", "⚠".yellow());
}
std::process::exit(0);
}

if !json_mode {
println!("{} Searching exploits and calculating risk scores...\n", 
"💥".bright_magenta());
}

// make sure we dont search same thing twice
let seen = Arc::new(Mutex::new(HashSet::new()));
let results = Arc::new(Mutex::new(Vec::new()));

// this runs in at the same time which is why its fast
ports.par_iter().for_each(|port| {
let key = format!("{}|{}", port.service, port.version);

{
let mut seen_lock = seen.lock().unwrap();
if seen_lock.contains(&key) {
return;
}
seen_lock.insert(key);
}

let query = build_query(&port.product, &port.version, &port.service);
if query.is_empty() {
return;
}

if let Ok(exploits) = search_exploits_default(&query) {
if !exploits.is_empty() {
let risk_score = calculate_risk(&exploits, &port.service);
results.lock().unwrap().push(PortResult {
port: port.clone(),
exploits,
risk_score,
});
}
}
});

let mut final_results = results.lock().unwrap().clone();
final_results.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());

if json_mode {
println!("{}", serde_json::to_string_pretty(&final_results).unwrap());
return;
}

// print the cool boxes
for result in &final_results {
print_results(result);
}
}

// scans all TCP ports super fast with threads
fn fast_scan_all(target: &str, quiet: bool) -> Vec<Port> {
let timeout = Duration::from_millis(80);
let open: Arc<Mutex<Vec<Port>>> = Arc::new(Mutex::new(Vec::new()));
let scanned = Arc::new(AtomicUsize::new(0));
let total = 65535;

let ports: Vec<u16> = (1..=65535).collect();
let ports_arc = Arc::new(ports);

// progress bar so u know its working
let progress_handle = if !quiet {
let scanned_clone = Arc::clone(&scanned);
let open_clone = Arc::clone(&open);
Some(thread::spawn(move || {
let start = Instant::now();
loop {
let sc = scanned_clone.load(Ordering::Relaxed);
let op = open_clone.lock().unwrap().len();
let percent = (sc * 100) / total;
let bar = progress_bar(percent, 40);

print!("\r[{}] {:3}% | {}/{} scanned | {} open | {:.1}s",
bar, percent, sc, total, op, start.elapsed().as_secs_f32());
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

// actually do the scanning
ports_arc.par_iter().for_each(|&port| {
if tcp_connect(target, port, timeout) {
open.lock().unwrap().push(Port {
port,
service: "".to_string(),
product: "".to_string(),
version: "".to_string(),
});
}
scanned.fetch_add(1, Ordering::Relaxed);
});

if let Some(h) = progress_handle {
h.join().unwrap();
}

let mut result = open.lock().unwrap().clone();
result.sort_by_key(|p| p.port);
result
}

// makes the cool loading bar
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

// checks if port is open (with one retry on refused)
fn tcp_connect(host: &str, port: u16, timeout: Duration) -> bool {
let addr = format!("{}:{}", host, port);
        if let Ok(addrs) = addr.to_socket_addrs() {
for sa in addrs {
for _ in 0..2 {
match TcpStream::connect_timeout(&sa, timeout) {
Ok(_) => return true,
Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => continue,
_ => break,
}
}
}
}
false
}

// run nmap on specific ports we found to be accurate. its pretty fast still
fn nmap_scan_ports(target: &str, ports: &[Port]) -> Vec<Port> {
let port_list = ports.iter()
.map(|p| p.port.to_string())
.collect::<Vec<_>>()
.join(",");

let output = Command::new("nmap")
.args(&["-sV", "-Pn", "-n", "--version-intensity", "7", 
"-oX", "-", "-p", &port_list, target])
.stdout(Stdio::piped())
.stderr(Stdio::null())
.output();

match output {
Ok(out) => parse_nmap_xml(&String::from_utf8_lossy(&out.stdout)),
Err(_) => Vec::new(),
}
}

// run nmap normally if u want, rly no point, js there if u want it
fn nmap_scan_full(target: &str) -> Vec<Port> {
let output = Command::new("nmap")
.args(&["-sV", "-Pn", "-n", "-p-", "-oX", "-", target])
.stdout(Stdio::piped())
.stderr(Stdio::null())
.output();

match output {
Ok(out) => parse_nmap_xml(&String::from_utf8_lossy(&out.stdout)),
Err(_) => Vec::new(),
}
}

// reads nmap xml cuz its annoying
fn parse_nmap_xml(xml: &str) -> Vec<Port> {
use roxmltree::Document;

let doc = match Document::parse(xml) {
Ok(d) => d,
Err(_) => return Vec::new(),
};

let mut ports = Vec::new();

for port_node in doc.descendants().filter(|n| n.has_tag_name("port")) {
let state = port_node.descendants()
.find(|n| n.has_tag_name("state"))
.and_then(|n| n.attribute("state"));

if state != Some("open") {
continue;
}

let service = port_node.descendants()
.find(|n| n.has_tag_name("service"));

let port_num = port_node.attribute("portid")
.and_then(|p| p.parse().ok())
.unwrap_or(0);

let svc_name = service.and_then(|s| s.attribute("name"))
.unwrap_or("unknown")
.to_string();

let product = service.and_then(|s| s.attribute("product"))
.unwrap_or("")
.to_string();

let version = service.and_then(|s| s.attribute("version"))
.unwrap_or("")
.to_string();

ports.push(Port {
port: port_num,
service: svc_name,
product,
version,
});
}

ports
}

// figures out what to search for
fn build_query(product: &str, version: &str, service: &str) -> String {
let pv = format!("{} {}", product, version).trim().to_string();
if !pv.is_empty() {
return pv;
}
service.to_string()
}

// searchsploit stuff with timeout so it doesnt hang  (TEXT  mode)
fn search_exploits_default(query: &str) -> Result<Vec<Exploit>, String> {
let out = Command::new("timeout")
.args(&["5", "searchsploit", query])   // NO -j -w
.output()
.map_err(|e| format!("searchsploit: {}", e))?;

let text = String::from_utf8_lossy(&out.stdout);
let mut exploits = Vec::new();

for line in text.lines() {
if line.contains("----") || line.contains("Exploit Title") || line.trim().is_empty() {
continue;
}
let parts: Vec<_> = line.splitn(2, " | ").collect();
if parts.len() == 2 {
let title = parts[0].trim().to_string();
let path  = parts[1].trim().to_string();
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

// guesses how bad the exploit is based on keywords. also no point, feeling like a skid rn
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

// calculates overall risk score
fn calculate_risk(exploits: &[Exploit], service: &str) -> f32 {
let mut score = 0.0;

// more exploits = better for us, worse for them
score += (exploits.len() as f32).min(10.0) * 2.0;

// add up all the cvss scores
for exploit in exploits {
if let Some(cvss) = exploit.cvss {
score += cvss;
} else {
score += 5.0;  // default if we dunno
}
}

// some services are worse than others
let multiplier = match service {
"smb" | "netbios-ssn" | "microsoft-ds" => 1.8,  // windows smb is always sus
"mysql" | "postgresql" | "mssql" => 1.6,
"ssh" | "telnet" | "ftp" => 1.5,
"http" | "https" | "ssl" => 1.3,
_ => 1.0,
};

score * multiplier
}

// prints the fancy boxes  (DEFAULT  shows  title + path)
fn print_results(result: &PortResult) {
let port = &result.port;
let exploits = &result.exploits;

// pick color based on how bad it is
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

let header = format!("Port {} | {} {} | Risk: {:.1}", 
port.port, port.product, port.version, result.risk_score);
let header_vis = strip_ansi(&header);
max_width = max_width.max(header_vis.len());
max_width += 4;

let bar = "━".repeat(max_width);

// draw the box
println!("\n{}╭{}╮{}", "".bright_black(), bar, "".clear());
println!("{}│{} {} {:<width$} {}│{}",
"".bright_black(),
"".clear(),
risk_color,
header,
"".bright_black(),
"".clear(),
width = max_width.saturating_sub(20)
);
println!("{}├{}┤{}", "".bright_black(), bar, "".clear());

// show first 10 exploits  (title + path)
for exploit in exploits.iter().take(10) {
let line = format!("{}  {}", exploit.title, exploit.path.bright_black());
println!("{}│{}  {:<width$}  {}│{}",
"".bright_black(),
"".clear(),
line,
"".bright_black(),
"".clear(),
width = max_width - 2
);
}

if exploits.len() > 10 {
println!("{}│{}  {} more exploits... {}│{}",
"".bright_black(),
"".clear(),
exploits.len() - 10,
"".bright_black(),
"".clear()
);
}

println!("{}╰{}╯{}", "".bright_black(), bar, "".clear());
}

// removes color codes so we can measure text properly
fn strip_ansi(s: &str) -> String {
let re = regex::Regex::new(r"\x1b\[[0-9;]*[mK]").unwrap();
re.replace_all(s, "").to_string()
}
// now that i think abt it this was stupid