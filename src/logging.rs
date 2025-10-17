use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub fn initialize_tracing(verbose: bool) {
    let filter = if let Ok(filter) = std::env::var("RUST_LOG") {
        EnvFilter::new(filter)
    } else if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    if let Ok(config) = std::env::var("TRACING_LOG") {
        let mut log_level = "info";
        let mut log_file = String::new();
        let mut append = false;
        let mut rotation = "never";
        let mut max_size: Option<u64> = None;
        let mut max_files: Option<usize> = None;

        for part in config.split(',') {
            let kv: Vec<&str> = part.trim().splitn(2, '=').collect();
            if kv.len() == 2 {
                match kv[0] {
                    "level" => log_level = kv[1],
                    "file" => log_file = kv[1].to_string(),
                    "append" => append = kv[1] == "true",
                    "rotation" => rotation = kv[1],
                    "max_size" => {
                        let size_str = kv[1].to_uppercase();
                        if let Some(num) = size_str.strip_suffix("M") {
                            max_size = num.parse::<u64>().ok().map(|n| n * 1024 * 1024);
                        } else if let Some(num) = size_str.strip_suffix("K") {
                            max_size = num.parse::<u64>().ok().map(|n| n * 1024);
                        } else if let Some(num) = size_str.strip_suffix("G") {
                            max_size = num.parse::<u64>().ok().map(|n| n * 1024 * 1024 * 1024);
                        } else {
                            max_size = kv[1].parse::<u64>().ok();
                        }
                    }
                    "max_files" => max_files = kv[1].parse::<usize>().ok(),
                    _ => {}
                }
            }
        }

        if !log_file.is_empty() {
            if let (Some(size), Some(count)) = (max_size, max_files) {
                let file = tracing_rolling_file::RollingFileAppenderBase::builder()
                    .filename(log_file.clone())
                    .max_filecount(count)
                    .condition_max_file_size(size)
                    .build()
                    .expect("Failed to create rolling file appender");

                let (non_blocking, _guard) = tracing_appender::non_blocking(file);

                tracing_subscriber::registry()
                    .with(EnvFilter::new(log_level))
                    .with(tracing_subscriber::fmt::layer().with_writer(non_blocking))
                    .init();

                std::mem::forget(_guard);
                return;
            }

            let path = std::path::Path::new(&log_file);
            let (directory, filename) = if let Some(parent) = path.parent() {
                let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("app.log");
                (parent.to_str().unwrap_or("."), fname)
            } else {
                (".", log_file.as_str())
            };

            if !append && rotation == "never" {
                let _ = std::fs::remove_file(path);
            }

            let file_appender = match rotation {
                "hourly" => tracing_appender::rolling::hourly(directory, filename),
                "daily" => tracing_appender::rolling::daily(directory, filename),
                "minutely" => tracing_appender::rolling::minutely(directory, filename),
                _ => tracing_appender::rolling::never(directory, filename),
            };

            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

            tracing_subscriber::registry()
                .with(EnvFilter::new(log_level))
                .with(tracing_subscriber::fmt::layer().with_writer(non_blocking))
                .init();

            std::mem::forget(_guard);
            return;
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
}