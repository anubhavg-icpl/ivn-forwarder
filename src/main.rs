use prometheus_exporter::{self, prometheus::{register_int_counter_vec, IntCounterVec}};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use regex::Regex;
use chrono::NaiveDateTime;
use glob::glob;

const LOG_DIR: &str = r"C:\ProgramData\Infopercept\logs";
const CHECK_INTERVAL: Duration = Duration::from_millis(100); // Check every 100ms

struct LogConfig {
    name: String,
    file_pattern: String,
    regex: Regex,
    time_format: String,
}

fn main() -> io::Result<()> {
    let addr: SocketAddr = "127.0.0.1:9184".parse().unwrap();
    let exporter = prometheus_exporter::start(addr).expect("Failed to start exporter");

    let log_count = register_int_counter_vec!(
        "infopercept_log_count", 
        "Number of log entries",
        &["log_type", "severity"]
    ).unwrap();

    let log_configs = vec![
        LogConfig {
            name: "ArStatusUpdate".to_string(),
            file_pattern: format!(r"{}\ArStatusUpdate*.log", LOG_DIR),
            regex: Regex::new(r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} [+-]\d{2}:\d{2}) \[(?P<severity>\w+)\] (?P<message>.*)").unwrap(),
            time_format: "%Y-%m-%d %H:%M:%S.%f %z".to_string(),
        },
        LogConfig {
            name: "IvsAgent".to_string(),
            file_pattern: format!(r"{}\IvsAgent*.log", LOG_DIR),
            regex: Regex::new(r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} [+-]\d{2}:\d{2}) \[(?P<severity>\w+)\] (?P<message>.*)").unwrap(),
            time_format: "%Y-%m-%d %H:%M:%S.%f %z".to_string(),
        },
        LogConfig {
            name: "IvsSync".to_string(),
            file_pattern: format!(r"{}\IvsSync*.log", LOG_DIR),
            regex: Regex::new(r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} [+-]\d{2}:\d{2}) \[(?P<severity>\w+)\] (?P<message>.*)").unwrap(),
            time_format: "%Y-%m-%d %H:%M:%S.%f %z".to_string(),
        },
        LogConfig {
            name: "IvsTray".to_string(),
            file_pattern: format!(r"{}\IvsTray*.log", LOG_DIR),
            regex: Regex::new(r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} [+-]\d{2}:\d{2}) \[(?P<severity>\w+)\] (?P<message>.*)").unwrap(),
            time_format: "%Y-%m-%d %H:%M:%S.%f %z".to_string(),
        },
        LogConfig {
            name: "osquery-install".to_string(),
            file_pattern: format!(r"{}\osquery-install.log", LOG_DIR),
            regex: Regex::new(r"=== (?P<message>.*) (?P<time>\d{2}/\d{2}/\d{4}  \d{2}:\d{2}:\d{2})  (?P<extra>.*)===$").unwrap(),
            time_format: "%d/%m/%Y  %H:%M:%S".to_string(),
        },
        LogConfig {
            name: "wazuh-install".to_string(),
            file_pattern: format!(r"{}\wazuh-install.log", LOG_DIR),
            regex: Regex::new(r"=== (?P<message>.*) (?P<time>\d{2}/\d{2}/\d{4}  \d{2}:\d{2}:\d{2})  (?P<extra>.*)===$").unwrap(),
            time_format: "%d/%m/%Y  %H:%M:%S".to_string(),
        },
    ];

    let mut file_positions = HashMap::new();
    let mut last_check = Instant::now();

    loop {
        let wait_time = CHECK_INTERVAL.checked_sub(last_check.elapsed()).unwrap_or(Duration::from_secs(0));
        let guard = exporter.wait_duration(wait_time);
        
        // Update metrics
        if let Err(e) = update_metrics(&log_configs, &mut file_positions, &log_count) {
            eprintln!("Error updating metrics: {}", e);
        }

        // If a scrape occurred, the metrics have just been sent
        drop(guard);
        
        last_check = Instant::now();
    }
}

fn update_metrics(
    log_configs: &[LogConfig],
    file_positions: &mut HashMap<String, u64>,
    log_count: &IntCounterVec,
) -> io::Result<()> {
    for config in log_configs {
        if let Err(e) = parse_logs(&config, file_positions, log_count) {
            eprintln!("Error parsing logs for {}: {}", config.name, e);
        }
    }
    Ok(())
}

fn parse_logs(
    config: &LogConfig,
    file_positions: &mut HashMap<String, u64>,
    log_count: &IntCounterVec,
) -> io::Result<()> {
    for entry in glob(&config.file_pattern).map_err(|e| io::Error::new(io::ErrorKind::Other, e))? {
        let path = entry.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let path_str = path.to_str().unwrap().to_string();
        let file = File::open(&path)?;
        
        let position = file_positions.entry(path_str.clone()).or_insert(0);
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(*position))?;

        let mut line = String::new();
        while reader.read_line(&mut line)? > 0 {
            if let Some(captures) = config.regex.captures(&line) {
                if let (Some(time), Some(severity)) = (captures.name("time"), captures.name("severity")) {
                    if NaiveDateTime::parse_from_str(time.as_str(), &config.time_format).is_ok() {
                        log_count.with_label_values(&[&config.name, severity.as_str()]).inc();
                    }
                } else if config.name == "osquery-install" || config.name == "wazuh-install" {
                    if let Some(time) = captures.name("time") {
                        if NaiveDateTime::parse_from_str(time.as_str(), &config.time_format).is_ok() {
                            log_count.with_label_values(&[&config.name, "info"]).inc();
                        }
                    }
                }
            }
            line.clear(); // Clear the line for the next iteration
        }
        *position = reader.stream_position()?;
    }
    Ok(())
}