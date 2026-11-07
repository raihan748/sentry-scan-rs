use colored::Colorize;
use crate::classification::RiskLevel;
use crate::scanner::ScanReport;

pub fn render_table(report: &ScanReport) -> String {
    let mut out = String::new();

    out.push_str("\n");
    out.push_str(&format!(
        "{:<18} {:<7} {:<16} {:<8} {:<10} {:<10} {}\n",
        "TARGET HOST".bold(),
        "PORT".bold(),
        "SERVICE".bold(),
        "STATE".bold(),
        "RTT".bold(),
        "RISK".bold(),
        "BANNER / VULNERABILITY SUMMARY".bold()
    ));
    out.push_str(&format!("{}\n", "─".repeat(105).dimmed()));

    if report.results.is_empty() {
        out.push_str(&format!("{}\n", "  No open ports discovered in target range.".yellow()));
    } else {
        for res in &report.results {
            let risk_str = match res.risk.level {
                RiskLevel::Critical => res.risk.level.as_str().red().bold(),
                RiskLevel::High => res.risk.level.as_str().bright_red(),
                RiskLevel::Medium => res.risk.level.as_str().yellow(),
                RiskLevel::Low => res.risk.level.as_str().cyan(),
                RiskLevel::Info => res.risk.level.as_str().green(),
            };

            let banner_preview = if let Some(ref b) = res.banner {
                if let Some(ref srv) = b.server_header {
                    format!("{}: Server: {}", b.protocol, srv)
                } else if !b.raw_banner.is_empty() {
                    let first = b.raw_banner.lines().next().unwrap_or("").trim();
                    if first.len() > 45 {
                        format!("{}...", &first[..42])
                    } else {
                        first.to_string()
                    }
                } else {
                    res.risk.summary.clone()
                }
            } else {
                res.risk.summary.clone()
            };

            out.push_str(&format!(
                "{:<18} {:<7} {:<16} {:<8} {:<10} {:<10} {}\n",
                res.host.to_string().bright_white(),
                res.port.to_string().cyan(),
                res.service.name.bright_blue(),
                "OPEN".green().bold(),
                format!("{:.2}ms", res.rtt_ms).dimmed(),
                risk_str,
                banner_preview
            ));
        }
    }

    out.push_str(&format!("{}\n", "─".repeat(105).dimmed()));

    // Metrics & risk summary
    let mut crit = 0;
    let mut high = 0;
    let mut med = 0;
    let mut low = 0;
    let mut info = 0;

    for r in &report.results {
        match r.risk.level {
            RiskLevel::Critical => crit += 1,
            RiskLevel::High => high += 1,
            RiskLevel::Medium => med += 1,
            RiskLevel::Low => low += 1,
            RiskLevel::Info => info += 1,
        }
    }

    out.push_str(&format!(
        "Scan Complete: {} targets probed in {:.2}s ({:.1} ports/sec) | Open: {} | Filtered/Closed: {}\n",
        report.scanned_count.to_string().bold(),
        report.duration_secs,
        report.scan_rate,
        report.open_count.to_string().green().bold(),
        report.closed_count.to_string().dimmed()
    ));

    out.push_str(&format!(
        "Risk Breakdown: Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}\n\n",
        crit.to_string().red().bold(),
        high.to_string().bright_red(),
        med.to_string().yellow(),
        low.to_string().cyan(),
        info.to_string().green()
    ));

    out
}
