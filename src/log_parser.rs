use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use chrono::NaiveDateTime;
use encoding_rs_io::DecodeReaderBytes;
use glob::glob;
use prometheus::IntCounterVec;
use regex::Regex;

use crate::config::LogConfig;

pub fn parse_logs(
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

        let stack_trace_regex = Regex::new(r"^\s+at ").unwrap();
        let exception_regex = Regex::new(r"^[A-Za-z.]+Exception:").unwrap();
        let mut in_stack_trace = false;
        let mut current_severity = String::new();

        while let Ok(n) = decoder.read_to_string(&mut buffer) {
            if n == 0 {
                break;
            }
            bytes_read += n;

            for line in buffer.lines() {
                if let Some(captures) = config.regex.captures(line) {
                    if let (Some(time), Some(severity)) = (captures.name("time"), captures.name("severity")) {
                        if NaiveDateTime::parse_from_str(time.as_str(), &config.time_format).is_ok() {
                            log_count.with_label_values(&[&config.name, severity.as_str()]).inc();
                            current_severity = severity.as_str().to_string();
                            in_stack_trace = false;
                        }
                    }
                } else if stack_trace_regex.is_match(line) || exception_regex.is_match(line) {
                    if !in_stack_trace {
                        log_count.with_label_values(&[&config.name, &current_severity]).inc();
                        in_stack_trace = true;
                    }
                } else if !line.trim().is_empty() {
                    // If it's not a recognized log format and not empty, count it as an unknown entry
                    log_count.with_label_values(&[&config.name, "UNKNOWN"]).inc();
                    in_stack_trace = false;
                }
            }
            buffer.clear();
        }
        
        *position += bytes_read as u64;
    }
    Ok(())
}