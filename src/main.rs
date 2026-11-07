use std::fs::File;
use std::io::Write;
use std::process::exit;
use std::time::Duration;
use clap::Parser;
use colored::Colorize;

use sentry_scan::cidr::{parse_ports, parse_targets};
use sentry_scan::cli::CliArgs;
use sentry_scan::output::{render_json, render_sarif, render_table};
use sentry_scan::scanner::{run_scan, ScanConfig};

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();

    // Default to top100 preset if no ports or preset specified
    let (ports_spec, preset_spec) = if args.ports.is_none() && args.preset.is_none() {
        (None, Some("top100".to_string()))
    } else {
        (args.ports.as_deref(), args.preset)
    };

    let usable_only = !args.all_hosts;
    let targets = match parse_targets(&args.target, usable_only) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{} {}", "[Target Error]".red().bold(), err);
            exit(1);
        }
    };

    let ports = match parse_ports(ports_spec, preset_spec.as_deref()) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("{} {}", "[Port Error]".red().bold(), err);
            exit(1);
        }
    };

    if !args.json && !args.sarif {
        println!(
            "{}",
            "=== SentryScan High-Concurrency TCP Recon CLI ===".cyan().bold()
        );
        println!(
            "Probing {} hosts across {} ports (Total {} target sockets, Concurrency: {}, Timeout: {}ms, Banner: {})...",
            targets.len().to_string().bold(),
            ports.len().to_string().bold(),
            (targets.len() * ports.len()).to_string().bold(),
            args.concurrency,
            args.timeout_ms,
            if args.banner { "ENABLED".green() } else { "DISABLED".yellow() }
        );
    }

    let config = ScanConfig {
        concurrency: args.concurrency,
        timeout: Duration::from_millis(args.timeout_ms),
        grab_banner: args.banner,
    };

    let report = run_scan(&targets, &ports, config).await;

    let output_content = if args.sarif {
        match render_sarif(&report) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{} Failed to generate SARIF: {}", "[Error]".red(), e);
                exit(1);
            }
        }
    } else if args.json {
        match render_json(&report) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("{} Failed to generate JSON: {}", "[Error]".red(), e);
                exit(1);
            }
        }
    } else {
        render_table(&report)
    };

    if let Some(file_path) = args.output_file {
        match File::create(&file_path).and_then(|mut f| f.write_all(output_content.as_bytes())) {
            Ok(_) => {
                println!(
                    "{} Report successfully written to '{}'",
                    "[Success]".green().bold(),
                    file_path
                );
            }
            Err(err) => {
                eprintln!(
                    "{} Failed to write output file '{}': {}",
                    "[Error]".red().bold(),
                    file_path,
                    err
                );
                exit(1);
            }
        }
    } else {
        println!("{}", output_content);
    }
}
