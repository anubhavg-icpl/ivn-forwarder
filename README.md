<h1 align="center">
<br>
<img src=assets\mmm-yummy-drinking.gif>
<br>

</h1>


The IVN Forwarder is a log parsing and metrics collection system designed to monitor and analyze log files from various Infopercept services, particularly focusing on IVS (Infopercept Visibility Suite) components.

## Key Components
1. **Log Parser**: Processes log files from IvsAgent, IvsSync, and IvsTray.
2. **Metrics Exporter**: Exposes collected metrics in Prometheus format.
3. **Configuration System**: Manages log file patterns and parsing rules.

## Main Features
- Parses log files and categorizes entries by log type and severity.
- Handles various log formats, including standard log entries, stack traces, and exceptions.
- Generates metrics counting the occurrences of different log severities for each log type.
- Exposes metrics via a Prometheus exporter for easy integration with monitoring systems.
- Implements a robust error handling mechanism to deal with unexpected log formats.

## Recent Improvements
- Enhanced parsing logic to properly handle multi-line entries like stack traces.
- Introduced an "UNKNOWN" severity category for unrecognized log entries.
- Reduced noise in error output by minimizing messages for unmatched lines.
- Improved overall accuracy of metrics by maintaining context across related log lines.

## Technical Stack
- **Language**: Rust
- **Key Libraries**: 
  - `prometheus_exporter` for metrics exposure
  - `regex` for log parsing
  - `chrono` for timestamp handling
  - `encoding_rs_io` for dealing with different file encodings

## Current Focus
The project currently focuses on processing logs from IvsAgent, IvsSync, and IvsTray, with the flexibility to expand to other log types in the future.

## Future Potential
- Expansion to handle additional log types and formats.
- Implementation of more advanced metrics and analysis features.
- Integration with alerting systems based on log patterns or metric thresholds.