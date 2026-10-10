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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escape_untrusted_output() {
        assert_eq!(xml_escape("<&\"\u{1b}"), "&lt;&amp;&quot;�");
        assert_eq!(terminal_safe("hello\u{1b}[31m\n"), "hello\\u{1b}[31m\\n");
    }
}
