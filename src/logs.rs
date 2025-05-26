use std::str::FromStr;

use tracing::debug;
use tracing_subscriber::EnvFilter;

pub(crate) fn init_logging() {
    let filter = EnvFilter::from_str("debug").unwrap();
    let format = tracing_subscriber::fmt::format()
        .with_ansi(true)
        .with_level(true)
        .with_target(true)
        .with_file(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .compact();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .event_format(format)
        .init();
    debug!("Logging initialized");
}
