use crate::ReportFormat;
use iqawx_lab::scanner::{ScanReport, State};
use std::fmt::Write;

pub fn terminal_safe(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

fn xml_escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&apos;".into(),
            c if (c < '\u{20}' && !matches!(c, '\n' | '\r' | '\t'))
                || matches!(c, '\u{fffe}' | '\u{ffff}') =>
            {
                "\u{fffd}".into()
            }
            c => c.to_string(),
        })
        .collect()
}

pub fn render(
    report: &ScanReport,
    format: ReportFormat,
    only_open: bool,
) -> Result<String, String> {
    if matches!(format, ReportFormat::Csv) {
        return Ok(csv_report(report, only_open));
    }
    if matches!(format, ReportFormat::Html) {
        return Ok(html_report(report, only_open));
    }
    if matches!(format, ReportFormat::Json) {
        let mut value = serde_json::to_value(report).map_err(|e| e.to_string())?;
        if only_open {
            if let Some(hosts) = value.get_mut("hosts").and_then(|v| v.as_array_mut()) {
                for host in hosts {
                    if let Some(ports) = host.get_mut("ports").and_then(|v| v.as_array_mut()) {
                        ports.retain(|p| p["state"] == "open");
                    }
                }
            }
        }
        value["summary"] = serde_json::json!(state_counts(report));
        value["display_filter"] = serde_json::json!(if only_open { "open-only" } else { "all" });
        return serde_json::to_string_pretty(&value)
            .map(|s| s + "\n")
            .map_err(|e| e.to_string());
    }
    let mut out = String::new();
    match format {
        ReportFormat::Xml => {
            writeln!(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>").unwrap();
            writeln!(out, "<iqawx-scan version=\"{}\" protocol=\"{}\" type=\"{}\" elapsed-ms=\"{}\" display-filter=\"{}\">", env!("CARGO_PKG_VERSION"), report.protocol, xml_escape(&report.scan_type), report.elapsed_ms, if only_open {"open-only"} else {"all"}).unwrap();
            writeln!(
                out,
                "  <completion complete=\"{}\" total=\"{}\" completed=\"{}\" />",
                report.complete, report.total_jobs, report.completed_jobs
            )
            .unwrap();
            for warning in &report.warnings {
                writeln!(out, "  <warning>{}</warning>", xml_escape(warning)).unwrap();
            }
        }
        ReportFormat::Text | ReportFormat::Grep => {
            writeln!(
                out,
                "# IQAWX native {} / {} — {} ms",
                report.scan_type, report.protocol, report.elapsed_ms
            )
            .unwrap();
            writeln!(
                out,
                "# {}: {}/{} completed | {:?}",
                if report.complete {
                    "Complete"
                } else {
                    "PARTIAL"
                },
                report.completed_jobs,
                report.total_jobs,
                state_counts(report)
            )
            .unwrap();
            if only_open {
                writeln!(out, "# Display filter: open ports only").unwrap();
            }
            for warning in &report.warnings {
                writeln!(out, "# {}", terminal_safe(warning)).unwrap();
            }
        }
        _ => unreachable!(),
    }
    for host in &report.hosts {
        match format {
            ReportFormat::Text => writeln!(out, "\nHost: {} ({})\nPORT       STATE           SERVICE          METHOD       REASON / BANNER", terminal_safe(&host.address), terminal_safe(&host.targets.join(", "))).unwrap(),
            ReportFormat::Xml => {
                writeln!(out, "  <host address=\"{}\">", xml_escape(&host.address)).unwrap();
                for target in &host.targets { writeln!(out, "    <target>{}</target>", xml_escape(target)).unwrap(); }
            }
            ReportFormat::Grep => writeln!(out, "Host: {}\tTargets: {}", terminal_safe(&host.address), terminal_safe(&host.targets.join(","))).unwrap(),
            _ => unreachable!(),
        }
        for port in host
            .ports
            .iter()
            .filter(|p| !only_open || matches!(p.state, State::Open))
        {
            let service = port
                .service
                .as_ref()
                .map(|s| s.name.as_str())
                .unwrap_or("unknown");
            let method = port
                .service
                .as_ref()
                .map(|s| s.method.as_str())
                .unwrap_or("none");
            match format {
                ReportFormat::Text => writeln!(out, "{:<10} {:<15} {:<16} {:<12} {}{}", format!("{}/{}", port.port, port.protocol), port.state.to_string(), terminal_safe(service), method, terminal_safe(&port.reason), port.banner.as_ref().map(|b| format!(" / {}", terminal_safe(b))).unwrap_or_default()).unwrap(),
                ReportFormat::Grep => writeln!(out, "Host: {}\tPort: {}/{}\tState: {}\tService: {}\tMethod: {}\tReason: {}\tBanner: {}", host.address, port.port, port.protocol, port.state, terminal_safe(service), method, terminal_safe(&port.reason), terminal_safe(port.banner.as_deref().unwrap_or(""))).unwrap(),
                ReportFormat::Xml => {
                    writeln!(out, "    <port number=\"{}\" protocol=\"{}\" state=\"{}\" attempts=\"{}\" elapsed-ms=\"{}\">", port.port, port.protocol, port.state, port.attempts, port.elapsed_ms).unwrap();
                    writeln!(out, "      <reason>{}</reason>", xml_escape(&port.reason)).unwrap();
                    writeln!(out, "      <service name=\"{}\" method=\"{}\" />", xml_escape(service), xml_escape(method)).unwrap();
                    if let Some(banner) = &port.banner { writeln!(out, "      <banner>{}</banner>", xml_escape(banner)).unwrap(); }
                    writeln!(out, "    </port>").unwrap();
                }
                _ => unreachable!(),
            }
        }
        if matches!(format, ReportFormat::Xml) {
            writeln!(out, "  </host>").unwrap();
        }
    }
    if matches!(format, ReportFormat::Xml) {
        writeln!(out, "</iqawx-scan>").unwrap();
    }
    Ok(out)
}

fn state_counts(report: &ScanReport) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::from_iter(
        ["open", "closed", "filtered", "open|filtered", "error"].map(|s| (s.to_owned(), 0)),
    );
    for p in report.hosts.iter().flat_map(|h| &h.ports) {
        *counts.entry(p.state.to_string()).or_default() += 1;
    }
    counts
}

fn csv_field(value: &str) -> String {
    // Prevent spreadsheet formula execution while retaining original evidence in JSON.
    let safe = terminal_safe(value);
    let prefix = if safe.trim_start().starts_with(['=', '+', '-', '@']) {
        "'"
    } else {
        ""
    };
    format!("\"{}{}\"", prefix, safe.replace('"', "\"\""))
}

fn csv_report(report: &ScanReport, only_open: bool) -> String {
    let mut out = String::from("record,complete,total_jobs,completed_jobs,address,port,protocol,state,service,method,reason,banner\r\n");
    writeln!(
        out,
        "scan,{},{},{},,,,,,,,\r",
        report.complete, report.total_jobs, report.completed_jobs
    )
    .unwrap();
    for host in &report.hosts {
        for p in host
            .ports
            .iter()
            .filter(|p| !only_open || p.state == State::Open)
        {
            let fields = [
                "port".to_owned(),
                report.complete.to_string(),
                report.total_jobs.to_string(),
                report.completed_jobs.to_string(),
                host.address.clone(),
                p.port.to_string(),
                p.protocol.to_string(),
                p.state.to_string(),
                p.service
                    .as_ref()
                    .map(|s| s.name.clone())
                    .unwrap_or_default(),
                p.service
                    .as_ref()
                    .map(|s| s.method.clone())
                    .unwrap_or_default(),
                p.reason.clone(),
                p.banner.clone().unwrap_or_default(),
            ];
            out.push_str(
                &fields
                    .iter()
                    .map(|v| csv_field(v))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            out.push_str("\r\n");
        }
    }
    out
}

fn html_report(report: &ScanReport, only_open: bool) -> String {
    let mut out = String::from("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>IQAWX scan report</title><style>body{font:16px system-ui;background:#0e1421;color:#e2e8f0;margin:0;padding:32px}main{max-width:1200px;margin:auto}h1{color:#67e8f9}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:12px;border-bottom:1px solid #334155;vertical-align:top;overflow-wrap:anywhere}th{color:#67e8f9}.scroll{overflow:auto}li{margin:8px 0}p{color:#cbd5e1}.status{padding:16px;background:#1e293b;border-radius:12px}</style></head><body><main><h1>IQAWX · Network report</h1>");
    writeln!(out, "<p class=\"status\"><strong>{}</strong> · {} / {} completed · {} ms · {}</p><p>States across completed jobs: {}</p><p>Display filter: {}</p><ul>", if report.complete {"Complete"} else {"PARTIAL — unfinished ports are unknown"}, report.completed_jobs, report.total_jobs, report.elapsed_ms, report.protocol, xml_escape(&format!("{:?}", state_counts(report))), if only_open {"open only"} else {"all"}).unwrap();
    for warning in &report.warnings {
        writeln!(out, "<li>{}</li>", xml_escape(warning)).unwrap();
    }
    out.push_str("</ul><div class=\"scroll\"><table><thead><tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Evidence method</th><th>Reason / banner</th></tr></thead><tbody>");
    for h in &report.hosts {
        for p in h
            .ports
            .iter()
            .filter(|p| !only_open || p.state == State::Open)
        {
            writeln!(out, "<tr><td>{}</td><td>{}/{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}<br>{}</td></tr>", xml_escape(&h.address), p.port, p.protocol, p.state, xml_escape(p.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown")), xml_escape(p.service.as_ref().map(|s| s.method.as_str()).unwrap_or("none")), xml_escape(&p.reason), xml_escape(p.banner.as_deref().unwrap_or(""))).unwrap();
        }
    }
    out.push_str("</tbody></table></div></main></body></html>\n");
    out
}

fn preview(text: &str, limit: usize) -> String {
    let clipped: String = text.chars().take(limit).collect();
    format!(
        "{}{}",
        terminal_safe(&clipped),
        if text.chars().count() > limit {
            "…"
        } else {
            ""
        }
    )
}

pub fn analysis_text(r: &iqawx_lab::analysis::AnalysisReport) -> String {
    let mut out = format!("IQAWX · Data analysis\nSize: {} bytes\nType hint: {}\nSHA-256: {}\nCRC32: {}\nEntropy: {:.3} bits/byte\nValid UTF-8: {}\nCandidate sample: {} bytes{}\n\n{}\n", r.size_bytes, terminal_safe(&r.file_type_hint), r.sha256, r.crc32_hex, r.entropy_bits_per_byte, r.unicode.valid_utf8, r.candidate_sample_bytes, if r.candidates_sampled {" (sampled)"} else {""}, r.candidate_score_caveat);
    writeln!(
        out,
        "\nPreview: {}",
        preview(
            r.input_preview_utf8
                .as_deref()
                .unwrap_or(&r.input_preview_hex),
            240
        )
    )
    .unwrap();
    for (i, c) in r.candidates.iter().enumerate() {
        writeln!(
            out,
            "\n{}. {} | key: {} | score: {:.3}\n{}",
            i + 1,
            terminal_safe(&c.method),
            terminal_safe(c.key.as_deref().unwrap_or("none")),
            c.heuristic_score,
            preview(c.text.as_deref().unwrap_or(&c.output_hex), 240)
        )
        .unwrap();
    }
    writeln!(out, "\nASCII strings (up to 20 shown):").unwrap();
    for s in r.ascii_strings.iter().take(20) {
        writeln!(out, "  @{}: {}", s.offset, preview(&s.text, 120)).unwrap();
    }
    out
}

pub fn layers_text(layers: &[iqawx_lab::analysis::LayerCandidate]) -> String {
    let mut out = String::from("IQAWX · Possible encoding layers\nCandidates are possible decodings, not confirmed format detection. Previews are limited to 240 characters; JSON contains full bytes.\n");
    if layers.is_empty() {
        out.push_str("No candidate layers found.\n");
    }
    for (i, c) in layers.iter().enumerate() {
        writeln!(
            out,
            "\n{}. {}\n{}",
            i + 1,
            c.chain.join(" → "),
            preview(c.text.as_deref().unwrap_or(&c.output_hex), 240)
        )
        .unwrap();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn csv_fields_block_formulas_and_escape_quotes() {
        assert_eq!(
            csv_field("=HYPERLINK(\"bad\")"),
            "\"'=HYPERLINK(\"\"bad\"\")\""
        );
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert!(!csv_field("\t=1+1").contains('\t'));
    }
    #[test]
    fn escape_untrusted_output() {
        assert_eq!(xml_escape("<&\"\u{1b}"), "&lt;&amp;&quot;�");
        assert_eq!(terminal_safe("hello\u{1b}[31m\n"), "hello\\u{1b}[31m\\n");
    }
}
