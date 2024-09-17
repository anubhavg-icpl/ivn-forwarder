use prometheus::{register_int_counter_vec, IntCounterVec};

pub fn setup_metrics() -> IntCounterVec {
    register_int_counter_vec!(
        "infopercept_log_count", 
        "Number of log entries",
        &["log_type", "severity"]
    ).unwrap()
}