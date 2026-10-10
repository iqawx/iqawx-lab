
use ipnet::IpNet;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::{sleep_until, timeout, Instant as TokioInstant};

const MAX_JOBS: usize = 1_000_000;
const MAX_SERVICE_JOBS: usize = 4096;
const MAX_TARGET_LABELS: usize = 131_072;
const MAX_BANNER: usize = 4096;
const MAX_SERVICES_FILE: usize = 16 * 1024 * 1024;
const MAX_SERVICE_NAME_BYTES: usize = 128;
const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 8080,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Open,
    Closed,
    Filtered,
    #[serde(rename = "open|filtered")]
    OpenFiltered,
    Error,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
            Self::OpenFiltered => "open|filtered",
            Self::Error => "error",
        })
    }
}

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub retries: u8,
    /// Limits connection/probe starts; the operating system controls TCP retransmissions.
    pub rate: Option<u32>,
    pub service_detection: bool,
    pub protocol: Protocol,
    pub max_hosts: usize,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub protocol: Protocol,
    pub scan_type: String,
    pub timeout_ms: u64,
    pub retries: u8,
    pub elapsed_ms: u64,
    pub hosts: Vec<HostReport>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HostReport {
    pub address: String,
    pub targets: Vec<String>,
    pub ports: Vec<PortResult>,
}

#[derive(Debug, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub state: State,
    pub protocol: Protocol,
    pub reason: String,
    pub attempts: u8,
    pub elapsed_ms: u64,
    pub service: Option<ServiceInfo>,
    pub banner: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServiceInfo {
    pub name: String,
    
    pub method: String,
    pub evidence: Option<String>,
}

#[derive(Debug)]
struct ServiceEntry {
    name: String,
    frequency: f64,
}

#[derive(Debug, Default)]
pub struct ServiceDatabase {
    entries: BTreeMap<(Protocol, u16), ServiceEntry>,
}

impl ServiceDatabase {
    /// Read a UTF-8 services file, with a strict 16 MiB input bound.
    pub fn load(path: &Path) -> Result<Self, String> {
        let file = File::open(path)
            .map_err(|error| format!("Cannot open services file {}: {error}", path.display()))?;
        let mut bytes = Vec::new();
        file.take((MAX_SERVICES_FILE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("Cannot read services file {}: {error}", path.display()))?;
        if bytes.len() > MAX_SERVICES_FILE {
            return Err("Services file exceeds the 16 MiB size limit".into());
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "Services file must contain valid UTF-8 text".to_owned())?;
        Self::parse(text)
    }

  
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.len() > MAX_SERVICES_FILE {
            return Err("Services file exceeds the 16 MiB size limit".into());
        }
        let mut database = Self::default();
        for (index, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let error = |message: &str| format!("Services file line {}: {message}", index + 1);
            let mut columns = line.split_whitespace();
            let name = columns.next().expect("nonempty line has first column");
            if name.len() > MAX_SERVICE_NAME_BYTES {
                return Err(error("service name exceeds the 128-byte limit"));
            }
            if name.chars().any(char::is_control) {
                return Err(error("service name must not contain control characters"));
            }
            let endpoint = columns
                .next()
                .ok_or_else(|| error("expected service-name and port/protocol"))?;
            let (port, protocol) = endpoint
                .split_once('/')
                .ok_or_else(|| error("expected port/protocol in the second column"))?;
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(error("port must be an integer between 0 and 65535"));
            }
            let port = port
                .parse::<u16>()
                .map_err(|_| error("port must be an integer between 0 and 65535"))?;
            if protocol.is_empty()
                || !protocol
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(error("protocol must be a nonempty protocol name"));
            }
            let frequency = columns
                .next()
                .and_then(|value| value.parse::<f64>().ok())
                .unwrap_or(0.0);
            if !frequency.is_finite() || !(0.0..=1.0).contains(&frequency) {
                return Err(error(
                    "numeric frequency must be finite and between 0 and 1",
                ));
            }
            // Treat negative zero exactly like omitted/positive zero during tie sorting.
            let frequency = if frequency == 0.0 { 0.0 } else { frequency };
            let protocol = match protocol {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => continue,
            };
            if port == 0 {
                continue;
            }
            database
                .entries
                .entry((protocol, port))
                .or_insert_with(|| ServiceEntry {
                    name: name.to_owned(),
                    frequency,
                });
        }
        Ok(database)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Rank separately by protocol, descending frequency and ascending port for ties.
    /// Zero-frequency entries remain eligible after entries with higher frequency.
    pub fn top_ports(&self, protocol: Protocol, count: usize) -> Result<Vec<u16>, String> {
        if !(1..=usize::from(u16::MAX)).contains(&count) {
            return Err("top-ports count must be between 1 and 65535".into());
        }
        let mut ports: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(&(entry_protocol, port), entry)| {
                (entry_protocol == protocol).then_some((port, entry.frequency))
            })
            .collect();
        if count > ports.len() {
            return Err(format!(
                "Requested {count} top {protocol} ports, but services file contains only {} eligible {protocol} entries",
                ports.len()
            ));
        }
        ports.sort_by(
            |(left_port, left_frequency), (right_port, right_frequency)| {
                right_frequency
                    .total_cmp(left_frequency)
                    .then_with(|| left_port.cmp(right_port))
            },
        );
        Ok(ports
            .into_iter()
            .take(count)
            .map(|(port, _)| port)
            .collect())
    }

    /// Apply imported hints only when no observed identity or other evidence exists.
    pub fn apply_hints(&self, report: &mut ScanReport) {
        for result in report.hosts.iter_mut().flat_map(|host| &mut host.ports) {
            if result
                .service
                .as_ref()
                .is_some_and(|service| service.method == "observed" || service.evidence.is_some())
            {
                continue;
            }
            if let Some(entry) = self.entries.get(&(result.protocol, result.port)) {
                result.service = Some(ServiceInfo {
                    name: entry.name.clone(),
                    method: "service-db-hint".into(),
                    evidence: None,
                });
            }
        }
    }
}

/// Parse individual ports and inclusive ranges. Empty means sixteen common TCP ports.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(DEFAULT_PORTS.to_vec());
    }
    if spec == "-" {
        return Ok((1..=u16::MAX).collect());
    }
    let mut ports = BTreeSet::new();
    for item in spec.split(',') {
        let item = item.trim();
        if item.is_empty() {
            return Err("Port list contains an empty item".into());
        }
        if let Some((start, end)) = item.split_once('-') {
            let start = parse_port(start)?;
            let end = parse_port(end)?;
            if start > end {
                return Err(format!("Reversed port range: {item}"));
            }
            ports.extend(start..=end);
        } else {
            ports.insert(parse_port(item)?);
        }
    }
    Ok(ports.into_iter().collect())
}

fn parse_port(value: &str) -> Result<u16, String> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("Invalid port: {value:?}"));
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| format!("Port must be between 1 and 65535: {value}"))
}

fn validate(options: &ScanOptions) -> Result<(), String> {
    if !(1..=60_000).contains(&options.timeout_ms) {
        return Err("timeout_ms must be between 1 and 60000".into());
    }
    if !(1..=1024).contains(&options.concurrency) {
        return Err("concurrency must be between 1 and 1024".into());
    }
    if options.retries > 5 {
        return Err("retries must be between 0 and 5".into());
    }
    if !(1..=65_536).contains(&options.max_hosts) {
        return Err("max_hosts must be between 1 and 65536".into());
    }
    if options.rate == Some(0) {
        return Err("rate must be greater than zero".into());
    }
    Ok(())
}

async fn resolve_targets(
    targets: &[String],
    options: &ScanOptions,
) -> Result<BTreeMap<IpAddr, BTreeSet<String>>, String> {
    if targets.is_empty() {
        return Err("At least one target is required".into());
    }
    let mut hosts = BTreeMap::<IpAddr, BTreeSet<String>>::new();
    let mut seen_targets = BTreeSet::new();
    let mut seen_cidrs = BTreeSet::new();
    let mut target_labels = 0_usize;
    for original in targets {
        let target = original.trim();
        if target.is_empty() {
            return Err("Target cannot be empty".into());
        }
        if !seen_targets.insert(target.to_owned()) {
            continue;
        }
        let mut add = |ip: IpAddr| -> Result<(), String> {
            if !hosts.contains_key(&ip) && hosts.len() >= options.max_hosts {
                return Err(format!(
                    "Targets exceed max_hosts={} (unique IP addresses)",
                    options.max_hosts
                ));
            }
            let labels = hosts.entry(ip).or_default();
            if !labels.contains(target) {
                if target_labels >= MAX_TARGET_LABELS {
                    return Err(format!(
                        "Targets exceed {MAX_TARGET_LABELS} host/target labels; reduce overlapping target ranges"
                    ));
                }
                labels.insert(target.to_owned());
                target_labels += 1;
            }
            Ok(())
        };
        if target.contains('/') {
            let net: IpNet = target
                .parse()
                .map_err(|_| format!("Invalid CIDR target: {target}"))?;
            // Different host bits can spell the same network. Keep the first
            // supplied label and avoid expanding equivalent CIDRs repeatedly.
            if !seen_cidrs.insert(net.trunc().to_string()) {
                continue;
            }
            let host_bits = match net {
                IpNet::V4(n) => 32 - n.prefix_len(),
                IpNet::V6(n) => 128 - n.prefix_len(),
            };
            // Check cardinality before any expansion, including /0 and large IPv6 networks.
            let count = 1_u128
                .checked_shl(u32::from(host_bits))
                .filter(|count| *count <= options.max_hosts as u128)
                .ok_or_else(|| format!("CIDR {target} exceeds max_hosts={}", options.max_hosts))?;
            match net {
                IpNet::V4(net) => {
                    let start = u32::from(net.network());
                    for offset in 0..count {
                        add(IpAddr::V4(Ipv4Addr::from(start + offset as u32)))?;
                    }
                }
                IpNet::V6(net) => {
                    let start = u128::from(net.network());
                    for offset in 0..count {
                        add(IpAddr::V6(Ipv6Addr::from(start + offset)))?;
                    }
                }
            }
        } else if let Ok(ip) = target.parse::<IpAddr>() {
            add(ip)?;
        } else {
            if target.contains(':') || target.chars().any(char::is_whitespace) {
                return Err(format!(
                    "Invalid target {target:?}; use a bare hostname, IP address, or CIDR"
                ));
            }
            let resolved = timeout(
                Duration::from_millis(options.timeout_ms.clamp(1000, 10_000)),
                lookup_host((target, 0)),
            )
            .await
            .map_err(|_| format!("DNS resolution timed out for {target}"))?
            .map_err(|error| format!("Cannot resolve {target}: {error}"))?;
            let mut any = false;
            for addr in resolved {
                add(addr.ip())?;
                any = true;
            }
            if !any {
                return Err(format!("No IP addresses found for {target}"));
            }
        }
    }
    Ok(hosts)
}

struct RateLimiter {
    interval: Option<Duration>,
    next: Mutex<TokioInstant>,
}

impl RateLimiter {
    fn new(rate: Option<u32>) -> Self {
        Self {
            interval: rate.map(|r| Duration::from_nanos(1_000_000_000_u64.div_ceil(u64::from(r)))),
            next: Mutex::new(TokioInstant::now()),
        }
    }
    async fn acquire(&self) {
        if let Some(interval) = self.interval {
            let mut next = self.next.lock().await;
            sleep_until(*next).await;
            *next = TokioInstant::now() + interval;
        }
    }
}

pub async fn scan(
    targets: &[String],
    ports: &[u16],
    options: ScanOptions,
) -> Result<ScanReport, String> {
    let started = Instant::now();
    validate(&options)?;
    if ports.is_empty() || ports.contains(&0) {
        return Err("Provide at least one port; port zero is not supported".into());
    }
    let ports: Vec<u16> = ports
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let addresses = resolve_targets(targets, &options).await?;
    if addresses
        .len()
        .checked_mul(ports.len())
        .is_none_or(|count| count > MAX_JOBS)
    {
        return Err(format!(
            "Scan exceeds {MAX_JOBS} host/port jobs; reduce targets or ports"
        ));
    }
    if options.service_detection && addresses.len() * ports.len() > MAX_SERVICE_JOBS {
        return Err(format!(
            "Service detection exceeds {MAX_SERVICE_JOBS} host/port jobs; disable service detection or reduce targets or ports"
        ));
    }
    let mut hosts: Vec<HostReport> = addresses
        .iter()
        .map(|(ip, names)| HostReport {
            address: ip.to_string(),
            targets: names.iter().cloned().collect(),
            ports: Vec::with_capacity(ports.len()),
        })
        .collect();
    let ip_addresses: Vec<IpAddr> = addresses.keys().copied().collect();
    let mut jobs = ip_addresses
        .iter()
        .enumerate()
        .flat_map(|(index, ip)| ports.iter().map(move |port| (index, *ip, *port)));
    let options = Arc::new(options);
    let limiter = Arc::new(RateLimiter::new(options.rate));
    let mut active = JoinSet::new();
    // The iterator is lazy: neither a giant task list nor a task per port is allocated.
    loop {
        while active.len() < options.concurrency {
            if let Some((index, ip, port)) = jobs.next() {
                let options = options.clone();
                let limiter = limiter.clone();
                active.spawn(async move { (index, inspect(ip, port, &options, &limiter).await) });
            } else {
                break;
            }
        }
        match active.join_next().await {
            Some(Ok((index, result))) => hosts[index].ports.push(result),
            Some(Err(error)) => return Err(format!("Scan worker failed: {error}")),
            None => break,
        }
    }
    for host in &mut hosts {
        host.ports.sort_by_key(|result| result.port);
    }
    let mut warnings = vec!["Port-based service hints are not proof of the running service. No OS fingerprinting is performed.".into()];
    if options.protocol == Protocol::Udp {
        warnings.push("UDP silence is reported as open|filtered; it cannot establish that a port is open. ICMP errors and their timing depend on the OS and network.".into());
    }
    if options.rate.is_some() {
        warnings.push("The rate limit controls probe/connection starts. The operating system controls TCP retransmissions.".into());
    }
    Ok(ScanReport {
        protocol: options.protocol,
        scan_type: match options.protocol {
            Protocol::Tcp => "tcp-connect",
            Protocol::Udp => "udp",
        }
        .into(),
        timeout_ms: options.timeout_ms,
        retries: options.retries,
        elapsed_ms: elapsed_ms(started),
        hosts,
        warnings,
    })
}

struct Outcome {
    state: State,
    reason: String,
    banner: Option<String>,
    observed: Option<ServiceInfo>,
    retryable: bool,
}

impl Outcome {
    fn new(state: State, reason: impl Into<String>, retryable: bool) -> Self {
        Self {
            state,
            reason: reason.into(),
            banner: None,
            observed: None,
            retryable,
        }
    }
}

async fn inspect(
    ip: IpAddr,
    port: u16,
    options: &ScanOptions,
    limiter: &RateLimiter,
) -> PortResult {
    let started = Instant::now();
    let mut attempts = 0;
    let outcome = loop {
        attempts += 1;
        limiter.acquire().await;
        let outcome = match options.protocol {
            Protocol::Tcp => inspect_tcp(SocketAddr::new(ip, port), options, limiter).await,
            Protocol::Udp => inspect_udp(SocketAddr::new(ip, port), options).await,
        };
        if !outcome.retryable || attempts > options.retries {
            break outcome;
        }
    };
    PortResult {
        port,
        state: outcome.state,
        protocol: options.protocol,
        reason: outcome.reason,
        attempts,
        elapsed_ms: elapsed_ms(started),
        service: outcome
            .observed
            .or_else(|| port_hint(port, options.protocol)),
        banner: outcome.banner,
    }
}

async fn inspect_tcp(addr: SocketAddr, options: &ScanOptions, limiter: &RateLimiter) -> Outcome {
    match timeout(
        Duration::from_millis(options.timeout_ms),
        TcpStream::connect(addr),
    )
    .await
    {
        Err(_) => Outcome::new(
            State::Filtered,
            "TCP connection timed out; filtering or packet loss is possible",
            true,
        ),
        Ok(Err(error)) if error.kind() == io::ErrorKind::TimedOut => Outcome::new(
            State::Filtered,
            format!("TCP connection timed out: {error}"),
            true,
        ),
        Ok(Err(error)) => io_outcome(error, "TCP connection"),
        Ok(Ok(mut stream)) => {
            let mut outcome = Outcome::new(State::Open, "TCP connection accepted", false);
            if options.service_detection {
                if let Some(bytes) =
                    read_banner(&mut stream, addr, options.timeout_ms, limiter).await
                {
                    outcome.observed = recognize_banner(&bytes);
                    outcome.banner = Some(String::from_utf8_lossy(&bytes).into_owned());
                }
            }
            outcome
        }
    }
}

async fn read_banner(
    stream: &mut TcpStream,
    addr: SocketAddr,
    timeout_ms: u64,
    limiter: &RateLimiter,
) -> Option<Vec<u8>> {
    let mut data = Vec::with_capacity(512);
    let mut buffer = [0_u8; MAX_BANNER];
    let passive = Duration::from_millis(timeout_ms.min(250));
    let first = timeout(passive, stream.read(&mut buffer)).await;
    match first {
        Ok(Ok(0)) | Ok(Err(_)) => return None,
        Ok(Ok(n)) => data.extend_from_slice(&buffer[..n]),
        Err(_) if matches!(addr.port(), 80 | 8000 | 8080 | 8081 | 8888) => {
            limiter.acquire().await;
            let host = match addr.ip() {
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(ip) => format!("[{ip}]"),
            };
            let request = format!("HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: iqawx-lab/4\r\n\r\n");
            if !matches!(
                timeout(
                    Duration::from_millis(timeout_ms.min(2000)),
                    stream.write_all(request.as_bytes())
                )
                .await,
                Ok(Ok(()))
            ) {
                return None;
            }
        }
        Err(_) => return None,
    }
    let deadline = TokioInstant::now() + Duration::from_millis(timeout_ms.min(2000));
    while data.len() < MAX_BANNER {
        let remaining = deadline.saturating_duration_since(TokioInstant::now());
        if remaining.is_zero() {
            break;
        }
        let wait = if data.is_empty() {
            remaining
        } else {
            remaining.min(Duration::from_millis(100))
        };
        let room = MAX_BANNER - data.len();
        match timeout(wait, stream.read(&mut buffer[..room])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => data.extend_from_slice(&buffer[..n]),
        }
    }
    (!data.is_empty()).then_some(data)
}

async fn inspect_udp(addr: SocketAddr, options: &ScanOptions) -> Outcome {
    let bind = match addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) => return io_outcome(error, "UDP bind"),
    };
    if let Err(error) = socket.connect(addr).await {
        return io_outcome(error, "UDP connect");
    }
    // Root NS query (no recursion), rather than an invalid empty packet, for DNS.
    const DNS_QUERY: &[u8] = &[0x49, 0x51, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
    let payload = if addr.port() == 53 { DNS_QUERY } else { &[] };
    let budget = Duration::from_millis(options.timeout_ms);
    match timeout(budget, socket.send(payload)).await {
        Err(_) => return Outcome::new(State::Error, "UDP send timed out", true),
        Ok(Err(error)) => return io_outcome(error, "UDP send"),
        Ok(Ok(_)) => (),
    }
    let mut buffer = [0_u8; MAX_BANNER];
    match timeout(budget, socket.recv(&mut buffer)).await {
        Err(_) => Outcome::new(
            State::OpenFiltered,
            "No UDP response before timeout; open and filtered cannot be distinguished",
            true,
        ),
        Ok(Err(error)) if error.kind() == io::ErrorKind::TimedOut => Outcome::new(
            State::OpenFiltered,
            format!("UDP response timed out: {error}"),
            true,
        ),
        Ok(Err(error)) => io_outcome(error, "UDP receive"),
        Ok(Ok(n)) => {
            let mut outcome = Outcome::new(
                State::Open,
                format!("Received a UDP datagram ({n} bytes) from the target"),
                false,
            );
            if options.service_detection && n > 0 {
                outcome.banner = Some(String::from_utf8_lossy(&buffer[..n]).into_owned());
                if addr.port() == 53
                    && n >= 12
                    && buffer[..2] == DNS_QUERY[..2]
                    && buffer[2] & 0x80 != 0
                {
                    outcome.observed = Some(ServiceInfo {
                        name: "domain".into(),
                        method: "observed".into(),
                        evidence: Some(
                            "DNS response with matching transaction ID and response flag".into(),
                        ),
                    });
                } else {
                    outcome.observed = recognize_banner(&buffer[..n]);
                }
            }
            outcome
        }
    }
}

fn io_outcome(error: io::Error, operation: &str) -> Outcome {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => Outcome::new(
            State::Closed,
            format!("{operation} refused by the target or network: {error}"),
            false,
        ),
        _ => {
            let retryable = !matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied
                    | io::ErrorKind::InvalidInput
                    | io::ErrorKind::AddrNotAvailable
                    | io::ErrorKind::Unsupported
            );
            Outcome::new(
                State::Error,
                format!("{operation} failed: {error}"),
                retryable,
            )
        }
    }
}

fn recognize_banner(bytes: &[u8]) -> Option<ServiceInfo> {
    let text = String::from_utf8_lossy(bytes);
    let lower = text.to_ascii_lowercase();
    let (name, evidence) = if text.starts_with("SSH-") {
        ("ssh", "SSH protocol identification line")
    } else if text.starts_with("HTTP/") {
        ("http", "HTTP response status line")
    } else if (text.starts_with("220 ") || text.starts_with("220-")) && lower.contains("smtp") {
        ("smtp", "SMTP greeting signature")
    } else if (text.starts_with("220 ") || text.starts_with("220-")) && lower.contains("ftp") {
        ("ftp", "FTP greeting signature")
    } else if lower.starts_with("+ok") && lower.contains("pop") {
        ("pop3", "POP3 greeting signature")
    } else if lower.starts_with("* ok") && lower.contains("imap") {
        ("imap", "IMAP greeting signature")
    } else {
        return None;
    };
    Some(ServiceInfo {
        name: name.into(),
        method: "observed".into(),
        evidence: Some(evidence.into()),
    })
}

fn port_hint(port: u16, protocol: Protocol) -> Option<ServiceInfo> {
    let name = match (protocol, port) {
        (Protocol::Tcp, 21) => "ftp",
        (Protocol::Tcp, 22) => "ssh",
        (Protocol::Tcp, 23) => "telnet",
        (Protocol::Tcp, 25 | 465 | 587) => "smtp",
        (_, 53) => "domain",
        (Protocol::Udp, 67 | 68) => "dhcp",
        (Protocol::Udp, 69) => "tftp",
        (Protocol::Udp, 123) => "ntp",
        (Protocol::Udp, 161 | 162) => "snmp",
        (Protocol::Tcp, 80 | 8000 | 8080 | 8081 | 8888) => "http",
        (Protocol::Tcp, 110 | 995) => "pop3",
        (Protocol::Tcp, 139) => "netbios-ssn",
        (Protocol::Tcp, 143 | 993) => "imap",
        (Protocol::Tcp, 443 | 8443) => "https",
        (Protocol::Tcp, 445) => "microsoft-ds",
        (Protocol::Tcp, 3306) => "mysql",
        (Protocol::Tcp, 3389) => "ms-wbt-server",
        (Protocol::Tcp, 5432) => "postgresql",
        (Protocol::Tcp, 6379) => "redis",
        (Protocol::Tcp, 27017) => "mongodb",
        _ => return None,
    };
    Some(ServiceInfo {
        name: name.into(),
        method: "port-hint".into(),
        evidence: None,
    })
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn options(protocol: Protocol) -> ScanOptions {
        ScanOptions {
            timeout_ms: 150,
            concurrency: 4,
            retries: 0,
            rate: None,
            service_detection: true,
            protocol,
            max_hosts: 256,
        }
    }
    async fn one(port: u16, protocol: Protocol) -> PortResult {
        scan(&["127.0.0.1".into()], &[port], options(protocol))
            .await
            .unwrap()
            .hosts
            .remove(0)
            .ports
            .remove(0)
    }

    #[test]
    fn ports_are_validated_sorted_and_unique() {
        assert_eq!(parse_ports("80,22,20-22,80").unwrap(), vec![20, 21, 22, 80]);
        assert_eq!(parse_ports("").unwrap().len(), 16);
        assert_eq!(parse_ports("-").unwrap().len(), 65535);
        for invalid in ["0", "65536", "90-80", "80,", "-1", "1-2-3", "hello", "+80"] {
            assert!(parse_ports(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn service_database_parses_comments_aliases_and_independent_protocols() {
        let database = ServiceDatabase::parse(
            "# locally supplied examples\n\n\
             web 8080/tcp 0.8 # inline comment\n\
             shell 2222/tcp 0.8 ignored-column\n\
             low 9090/tcp 0.01\n\
             alias-service 1234/tcp alias-name another-alias\n\
             no-frequency 4321/tcp\n\
             negative-zero 5432/tcp -0.0\n\
             resolver 5353/udp 0.9\n\
             datagram-web 8080/udp 0.01\n\
             unsupported 9090/sctp 0.7\n\
             zero 0/tcp 1.0\n",
        )
        .unwrap();
        assert_eq!(database.len(), 8);
        assert_eq!(
            database.top_ports(Protocol::Tcp, 3).unwrap(),
            vec![2222, 8080, 9090]
        );
        assert_eq!(
            database.top_ports(Protocol::Udp, 2).unwrap(),
            vec![5353, 8080]
        );
        assert_eq!(
            database.top_ports(Protocol::Tcp, 6).unwrap(),
            vec![2222, 8080, 9090, 1234, 4321, 5432]
        );
    }

    #[test]
    fn service_database_first_duplicate_wins_and_ports_stay_unique() {
        let database = ServiceDatabase::parse(
            "first 8022/tcp 0.1\nsecond 8022/tcp 0.9\nother 8023/tcp 0.2\ndatagram 8022/udp 0.3",
        )
        .unwrap();
        assert_eq!(database.len(), 3);
        assert_eq!(
            database.top_ports(Protocol::Tcp, 2).unwrap(),
            vec![8023, 8022]
        );
        assert_eq!(database.entries[&(Protocol::Tcp, 8022)].name, "first");
        assert_eq!(database.entries[&(Protocol::Udp, 8022)].name, "datagram");
    }

    #[test]
    fn malformed_services_rows_report_their_line() {
        for row in [
            "service",
            "service 80",
            "service 80/",
            "service /tcp",
            "service -1/tcp",
            "service 65536/tcp",
            "service 80/tcp/udp",
            "service 80/tcp NaN",
            "service 80/tcp inf",
            "service 80/tcp 1e309",
            "service 80/tcp -0.01",
            "service 80/tcp 1.01",
            "service\0 80/tcp 0.5",
        ] {
            let error = ServiceDatabase::parse(&format!("# comment\n{row}")).unwrap_err();
            assert!(error.contains("line 2:"), "{row}: {error}");
        }
    }

    #[test]
    fn service_names_have_a_byte_limit_before_hints_are_cloned() {
        let accepted = format!("{} 8022/tcp 0.5", "x".repeat(128));
        assert_eq!(ServiceDatabase::parse(&accepted).unwrap().len(), 1);
        for name in ["x".repeat(129), "é".repeat(65)] {
            let text = format!("# comment\n{name} 8022/tcp 0.5");
            let error = ServiceDatabase::parse(&text).unwrap_err();
            assert!(error.contains("line 2:"), "{error}");
            assert!(error.contains("128-byte limit"), "{error}");
        }
        assert!(ServiceDatabase::parse("# no entries").unwrap().is_empty());
        assert!(!ServiceDatabase::parse(&accepted).unwrap().is_empty());
    }

    #[test]
    fn top_ports_requires_a_valid_count_and_enough_protocol_entries() {
        let database = ServiceDatabase::parse("web 8080/tcp 0.5").unwrap();
        for count in [0, 2, 65536, usize::MAX] {
            assert!(database.top_ports(Protocol::Tcp, count).is_err());
        }
        assert!(database.top_ports(Protocol::Udp, 1).is_err());
        assert!(ServiceDatabase::parse("")
            .unwrap()
            .top_ports(Protocol::Tcp, 1)
            .is_err());
    }

    #[test]
    fn loading_services_enforces_utf8_and_the_size_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("services");
        std::fs::write(&path, "example 8022/tcp 0.1\n").unwrap();
        assert_eq!(ServiceDatabase::load(&path).unwrap().len(), 1);
        std::fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(ServiceDatabase::load(&path).unwrap_err().contains("UTF-8"));
        File::create(&path)
            .unwrap()
            .set_len((MAX_SERVICES_FILE + 1) as u64)
            .unwrap();
        assert!(ServiceDatabase::load(&path).unwrap_err().contains("16 MiB"));
        assert!(ServiceDatabase::load(&directory.path().join("missing")).is_err());
    }

    #[test]
    fn imported_hints_replace_defaults_but_never_observed_evidence() {
        let database = ServiceDatabase::parse(
            "custom-shell 22/tcp 0.1\ncustom-udp 22/udp 0.2\ncustom-service 12345/tcp 0.3\ncustom-web 80/tcp 0.4",
        ).unwrap();
        let port = |number, protocol, service| PortResult {
            port: number,
            state: State::Open,
            protocol,
            reason: "test fixture".into(),
            attempts: 1,
            elapsed_ms: 0,
            service,
            banner: None,
        };
        let observed = || ServiceInfo {
            name: "ssh".into(),
            method: "observed".into(),
            evidence: Some("SSH protocol identification line".into()),
        };
        let mut report = ScanReport {
            protocol: Protocol::Tcp,
            scan_type: "test".into(),
            timeout_ms: 100,
            retries: 0,
            elapsed_ms: 0,
            warnings: vec![],
            hosts: vec![HostReport {
                address: "127.0.0.1".into(),
                targets: vec![],
                ports: vec![
                    port(22, Protocol::Tcp, port_hint(22, Protocol::Tcp)),
                    port(22, Protocol::Udp, None),
                    port(12345, Protocol::Tcp, None),
                    port(80, Protocol::Tcp, Some(observed())),
                    port(
                        80,
                        Protocol::Tcp,
                        Some(ServiceInfo {
                            name: "another".into(),
                            method: "future-observation".into(),
                            evidence: Some("response bytes".into()),
                        }),
                    ),
                    port(
                        80,
                        Protocol::Tcp,
                        Some(ServiceInfo {
                            name: "observed-without-detail".into(),
                            method: "observed".into(),
                            evidence: None,
                        }),
                    ),
                ],
            }],
        };
        database.apply_hints(&mut report);
        let services: Vec<_> = report.hosts[0]
            .ports
            .iter()
            .map(|port| port.service.as_ref().unwrap())
            .collect();
        assert_eq!(
            services
                .iter()
                .map(|service| service.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "custom-shell",
                "custom-udp",
                "custom-service",
                "ssh",
                "another",
                "observed-without-detail"
            ]
        );
        for service in &services[..3] {
            assert_eq!(service.method, "service-db-hint");
            assert!(service.evidence.is_none());
        }
        assert_eq!(services[3].evidence, observed().evidence);
    }

    #[tokio::test]
    async fn cidrs_expand_both_ip_families_and_deduplicate() {
        let targets = vec![
            "127.0.0.0/30".into(),
            "127.0.0.1".into(),
            "::1/128".into(),
            "::1".into(),
        ];
        let hosts = resolve_targets(&targets, &options(Protocol::Tcp))
            .await
            .unwrap();
        assert_eq!(hosts.len(), 5);
        assert_eq!(hosts[&"127.0.0.1".parse::<IpAddr>().unwrap()].len(), 2);
        assert_eq!(hosts[&"::1".parse::<IpAddr>().unwrap()].len(), 2);
        for target in [
            "::/0",
            "::/64",
            "10.0.0.0/8",
            "not-a-cidr/24",
            "",
            "127.0.0.1:80",
        ] {
            assert!(
                resolve_targets(&[target.into()], &options(Protocol::Tcp))
                    .await
                    .is_err(),
                "{target}"
            );
        }
    }

    #[tokio::test]
    async fn tcp_open_banner_is_observed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"SSH-2.0-LocalTest\r\n").await.unwrap();
        });
        let result = one(port, Protocol::Tcp).await;
        server.await.unwrap();
        assert_eq!(result.state, State::Open);
        assert_eq!(result.attempts, 1);
        assert!(result.banner.unwrap().contains("SSH-2.0-LocalTest"));
        let service = result.service.unwrap();
        assert_eq!(service.name, "ssh");
        assert_eq!(service.method, "observed");
    }

    #[tokio::test]
    async fn tcp_banner_silence_stays_open() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let result = one(port, Protocol::Tcp).await;
        assert_eq!(result.state, State::Open);
        assert!(result.banner.is_none());
        drop(listener);
    }

    #[tokio::test]
    async fn http_probe_accumulates_chunks_with_a_hard_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let n = timeout(Duration::from_secs(2), stream.read(&mut request))
                .await
                .unwrap()
                .unwrap();
            assert!(request[..n].starts_with(b"HEAD / HTTP/1.0\r\n"));
            stream.write_all(b"HTTP/1.0 200 OK\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            // Permit a reset if the client has already read its maximum.
            let _ = stream.write_all(&vec![b'x'; 6000]).await;
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        // The connected socket is an ephemeral loopback port; use HTTP's port only
        // to exercise the banner routine's protocol-specific probe selection.
        let bytes = read_banner(
            &mut stream,
            SocketAddr::new(addr.ip(), 80),
            300,
            &RateLimiter::new(None),
        )
        .await
        .unwrap();
        assert_eq!(bytes.len(), MAX_BANNER);
        assert_eq!(recognize_banner(&bytes).unwrap().name, "http");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_refused_is_closed_without_retries() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut opts = options(Protocol::Tcp);
        opts.retries = 2;
        let report = scan(&["127.0.0.1".into()], &[port], opts).await.unwrap();
        assert_eq!(report.hosts[0].ports[0].state, State::Closed);
        assert_eq!(report.hosts[0].ports[0].attempts, 1);
    }

    #[tokio::test]
    async fn udp_response_is_open() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut bytes = [0_u8; 128];
            let (_, peer) = socket.recv_from(&mut bytes).await.unwrap();
            socket.send_to(b"test response", peer).await.unwrap();
        });
        let result = one(port, Protocol::Udp).await;
        server.await.unwrap();
        assert_eq!(result.state, State::Open);
        assert_eq!(result.banner.as_deref(), Some("test response"));
    }

    #[tokio::test]
    async fn udp_silence_is_ambiguous_and_retried() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let mut opts = options(Protocol::Udp);
        opts.retries = 1;
        opts.timeout_ms = 30;
        let report = scan(&["127.0.0.1".into()], &[port], opts).await.unwrap();
        let result = &report.hosts[0].ports[0];
        assert_eq!(result.state, State::OpenFiltered);
        assert_eq!(result.attempts, 2);
        assert_eq!(
            serde_json::to_string(&result.state).unwrap(),
            "\"open|filtered\""
        );
        drop(socket);
    }

    #[tokio::test]
    async fn invalid_scan_options_fail_before_network_access() {
        let mut opts = options(Protocol::Tcp);
        opts.concurrency = 0;
        assert!(scan(&["127.0.0.1".into()], &[80], opts).await.is_err());
        let mut opts = options(Protocol::Tcp);
        opts.rate = Some(0);
        assert!(scan(&["127.0.0.1".into()], &[80], opts).await.is_err());
        assert!(scan(&[], &[80], options(Protocol::Tcp)).await.is_err());
        assert!(scan(&["127.0.0.1".into()], &[0], options(Protocol::Tcp))
            .await
            .is_err());
        let mut opts = options(Protocol::Tcp);
        opts.max_hosts = 65536;
        assert!(
            scan(&["10.0.0.0/16".into()], &(1..=16).collect::<Vec<_>>(), opts)
                .await
                .unwrap_err()
                .contains("1000000")
        );
    }

    #[tokio::test]
    async fn equivalent_cidrs_are_expanded_only_once() {
        let hosts = resolve_targets(
            &[
                "10.0.0.1/30".into(),
                "10.0.0.2/30".into(),
                "10.0.0.0/30".into(),
            ],
            &options(Protocol::Tcp),
        )
        .await
        .unwrap();
        assert_eq!(hosts.len(), 4);
        for labels in hosts.values() {
            assert_eq!(labels.len(), 1);
            assert!(labels.contains("10.0.0.1/30"));
        }
    }

    #[tokio::test]
    async fn overlapping_ranges_cannot_allocate_unbounded_labels() {
        let mut opts = options(Protocol::Tcp);
        opts.max_hosts = 65536;
        let error = resolve_targets(
            &[
                "10.0.0.0/16".into(),
                "10.0.0.0/17".into(),
                "10.0.128.0/17".into(),
                "10.0.0.0/18".into(),
            ],
            &opts,
        )
        .await
        .unwrap_err();
        assert!(error.contains("host/target labels"), "{error}");
    }

    #[tokio::test]
    async fn service_detection_has_a_separate_memory_bound() {
        let error = scan(
            &["10.0.0.0/24".into()],
            &(1..=17).collect::<Vec<_>>(),
            options(Protocol::Tcp),
        )
        .await
        .unwrap_err();
        assert!(error.contains("Service detection exceeds 4096"), "{error}");
    }

    #[test]
    fn permission_errors_are_never_classified_as_closed() {
        let result = io_outcome(io::Error::from(io::ErrorKind::PermissionDenied), "connect");
        assert_eq!(result.state, State::Error);
        assert!(!result.retryable);
        let hint = port_hint(22, Protocol::Tcp).unwrap();
        assert_eq!(hint.method, "port-hint");
        assert!(hint.evidence.is_none());
    }
}
