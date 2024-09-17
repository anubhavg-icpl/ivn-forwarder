use prometheus_exporter::{self, prometheus::{register_int_counter_vec, IntCounterVec}};
use std::fs::File;
use std::io::{self, Read, BufReader, Seek, SeekFrom};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use regex::Regex;
use chrono::NaiveDateTime;
use glob::glob;
use encoding_rs_io::DecodeReaderBytes;

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
            regex: Regex::new(r"=== (?P<message>.*) (?P<time>\d{2}-\d{2}-\d{4}  \d{2}:\d{2}:\d{2})  .*===").unwrap(),
            time_format: "%d-%m-%Y  %H:%M:%S".to_string(),
        },
        LogConfig {
            name: "wazuh-install".to_string(),
            file_pattern: format!(r"{}\wazuh-install.log", LOG_DIR),
            regex: Regex::new(r"=== (?P<message>.*) (?P<time>\d{2}-\d{2}-\d{4}  \d{2}:\d{2}:\d{2})  .*===").unwrap(),
            time_format: "%d-%m-%Y  %H:%M:%S".to_string(),
        },
    ];

    let mut file_positions = HashMap::new();
    let mut last_check = Instant::now();

    loop {
        let wait_time = CHECK_INTERVAL.checked_sub(last_check.elapsed()).unwrap_or(Duration::from_secs(0));
        let guard = exporter.wait_duration(wait_time);
        
        // Update metrics
        for config in &log_configs {
            match parse_logs(config, &mut file_positions, &log_count) {
                Ok(_) => println!("Successfully parsed logs for {}", config.name),
                Err(e) => {
                    eprintln!("Error parsing logs for {}: {}", config.name, e);
                    // Print the first few bytes of the file for debugging
                    if let Ok(mut file) = File::open(&config.file_pattern) {
                        let mut buffer = [0; 100];
                        if let Ok(bytes_read) = file.read(&mut buffer) {
                            eprintln!("First {} bytes of file: {:?}", bytes_read, &buffer[..bytes_read]);
                        }
                    }
                }
            }
        }

        // If a scrape occurred, the metrics have just been sent
        drop(guard);
        
        last_check = Instant::now();
    }
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

        let mut decoder = DecodeReaderBytes::new(reader);
        let mut buffer = String::new();
        let mut bytes_read = 0;

        while let Ok(n) = decoder.read_to_string(&mut buffer) {
            if n == 0 {
                break;
            }
            bytes_read += n;

            for line in buffer.lines() {
                if let Some(captures) = config.regex.captures(line) {
                    if config.name == "osquery-install" || config.name == "wazuh-install" {
                        if let Some(time) = captures.name("time") {
                            if NaiveDateTime::parse_from_str(time.as_str(), &config.time_format).is_ok() {
                                log_count.with_label_values(&[&config.name, "info"]).inc();
                            } else {
                                eprintln!("Failed to parse time: {} for log: {}", time.as_str(), config.name);
                            }
                        }
                    } else if let (Some(time), Some(severity)) = (captures.name("time"), captures.name("severity")) {
                        if NaiveDateTime::parse_from_str(time.as_str(), &config.time_format).is_ok() {
                            log_count.with_label_values(&[&config.name, severity.as_str()]).inc();
                        } else {
                            eprintln!("Failed to parse time: {} for log: {}", time.as_str(), config.name);
                        }
                    }
                } else {
                    eprintln!("Failed to match regex for log: {} with line: {}", config.name, line);
                }
            }
            buffer.clear();
        }
        
        *position += bytes_read as u64;
    }
    Ok(())
}