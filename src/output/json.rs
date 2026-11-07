use serde_json::json;
use crate::classification::RiskLevel;
use crate::error::SentryScanError;
use crate::scanner::ScanReport;

pub fn render_json(report: &ScanReport) -> Result<String, SentryScanError> {
    serde_json::to_string_pretty(report).map_err(SentryScanError::from)
}

/// Generate OASIS SARIF 2.1.0 security report for GitHub Security / CI/CD scanning
pub fn render_sarif(report: &ScanReport) -> Result<String, SentryScanError> {
    let mut sarif_rules = Vec::new();
    let mut sarif_results = Vec::new();

    for res in &report.results {
        let rule_id = format!("SENTRY-TCP-{}", res.port);
        let sarif_level = match res.risk.level {
            RiskLevel::Critical | RiskLevel::High => "error",
            RiskLevel::Medium => "warning",
            RiskLevel::Low | RiskLevel::Info => "note",
        };

        sarif_rules.push(json!({
            "id": rule_id,
            "name": format!("ExposedPort{}", res.port),
            "shortDescription": {
                "text": format!("Exposed {} service on port {}", res.service.name, res.port)
            },
            "fullDescription": {
                "text": res.risk.summary
            },
            "help": {
                "text": res.risk.recommendation
            },
            "properties": {
                "tags": res.risk.tags,
                "precision": "very-high"
            }
        }));

        sarif_results.push(json!({
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": format!(
                    "Discovered open port {} ({}) on target host {} (RTT: {:.2}ms). Risk: {}. Recommendation: {}",
                    res.port,
                    res.service.name,
                    res.host,
                    res.rtt_ms,
                    res.risk.level.as_str(),
                    res.risk.recommendation
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": format!("network://{}:{}", res.host, res.port)
                        }
                    }
                }
            ]
        }));
    }

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SentryScan",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/developer/sentry-scan-rs",
                        "rules": sarif_rules
                    }
                },
                "results": sarif_results
            }
        ]
    });

    serde_json::to_string_pretty(&sarif).map_err(SentryScanError::from)
}
