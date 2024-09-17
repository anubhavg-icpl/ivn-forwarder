use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod config;
mod log_parser;
mod metrics;

use config::{LogConfig, CHECK_INTERVAL};
use log_parser::parse_logs;
use metrics::setup_metrics;

fn main() -> std::io::Result<()> {
    let addr: SocketAddr = "127.0.0.1:9184".parse().unwrap();
    let exporter = prometheus_exporter::start(addr).expect("Failed to start exporter");

    let log_count = setup_metrics();
    let log_configs = config::get_log_configs();

    let mut file_positions = HashMap::new();
    let mut last_check = Instant::now();

    loop {
        let wait_time = CHECK_INTERVAL.checked_sub(last_check.elapsed()).unwrap_or(Duration::from_secs(0));
        let guard = exporter.wait_duration(wait_time);
        
        for config in &log_configs {
            if let Err(e) = parse_logs(config, &mut file_positions, &log_count) {
                eprintln!("Error parsing logs for {}: {}", config.name, e);
            }
        }

        drop(guard);
        last_check = Instant::now();
    }
}