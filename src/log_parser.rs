use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use chrono::NaiveDateTime;
use encoding_rs_io::DecodeReaderBytes;
use glob::glob;
use prometheus::IntCounterVec;

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

        while let Ok(n) = decoder.read_to_string(&mut buffer) {
            if n == 0 {
                break;
            }
            bytes_read += n;

            for line in buffer.lines() {
                if let Some(captures) = config.regex.captures(line) {
                    if let Some(time) = captures.name("time") {
                        if NaiveDateTime::parse_from_str(time.as_str(), &config.time_format).is_ok() {
                            let severity = captures.name("severity").map_or("info", |m| m.as_str());
                            log_count.with_label_values(&[&config.name, severity]).inc();
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