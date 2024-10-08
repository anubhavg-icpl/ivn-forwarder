use std::time::Duration;
use regex::Regex;

pub const LOG_DIR: &str = r"C:\ProgramData\Infopercept\logs";
pub const CHECK_INTERVAL: Duration = Duration::from_millis(100);

pub struct LogConfig {
    pub name: String,
    pub file_pattern: String,
    pub regex: Regex,
    pub time_format: String,
}

pub fn get_log_configs() -> Vec<LogConfig> {
    vec![
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
    ]
}