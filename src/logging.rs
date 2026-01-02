use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

#[derive(Clone, Copy, PartialEq)]
enum LogFormat {
    Pretty,
    Compact,
    Json,
}

pub fn initialize_tracing(verbose: bool) {
    let filter = env_filter(verbose);
    let mut format = env_log_format();
    let mut log_level_override: Option<String> = None;
    let mut log_file = String::new();
    let mut append = false;
    let mut rotation = String::from("never");
    let mut max_size: Option<u64> = None;
    let mut max_files: Option<usize> = None;

    if let Ok(config) = std::env::var("TRACING_LOG") {
        for part in config.split(',') {
            let kv: Vec<&str> = part.trim().splitn(2, '=').collect();
            if kv.len() != 2 {
                continue;
            }
            match kv[0] {
                "level" => log_level_override = Some(kv[1].to_string()),
                "file" => log_file = kv[1].to_string(),
                "append" => append = parse_bool(kv[1]),
                "rotation" => rotation = kv[1].to_string(),
                "format" => format = parse_format(kv[1]),
                "max_size" => max_size = parse_bytes(kv[1]),
                "max_files" => max_files = kv[1].parse::<usize>().ok(),
                _ => {}
            }
        }
    }

    if !log_file.is_empty() {
        let file_filter = log_level_override
            .as_deref()
            .map(EnvFilter::new)
            .unwrap_or_else(|| filter.clone());

        if let (Some(size), Some(count)) = (max_size, max_files) {
            let file = tracing_rolling_file::RollingFileAppenderBase::builder()
                .filename(log_file.clone())
                .max_filecount(count)
                .condition_max_file_size(size)
                .build()
                .expect("Failed to create rolling file appender");

            let (non_blocking, _guard) = tracing_appender::non_blocking(file);

            tracing_subscriber::registry()
                .with(file_filter)
                .with(build_fmt_layer(format, non_blocking, false))
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

        let file_appender = match rotation.as_str() {
            "hourly" => tracing_appender::rolling::hourly(directory, filename),
            "daily" => tracing_appender::rolling::daily(directory, filename),
            "minutely" => tracing_appender::rolling::minutely(directory, filename),
            _ => tracing_appender::rolling::never(directory, filename),
        };

        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::registry()
            .with(file_filter)
            .with(build_fmt_layer(format, non_blocking, false))
            .init();

        std::mem::forget(_guard);
        return;
    }

    tracing_subscriber::registry()
        .with(filter)
        .with(build_fmt_layer(format, std::io::stdout, format != LogFormat::Json))
        .init();

}

fn env_filter(verbose: bool) -> EnvFilter {
    if let Ok(filter) = std::env::var("RUST_LOG") {
        EnvFilter::new(filter)
    } else if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    }
}

fn env_log_format() -> LogFormat {
    std::env::var("EXPOSEME_LOG_FORMAT")
        .ok()
        .map(|v| parse_format(&v))
        .unwrap_or(LogFormat::Pretty)
}

fn build_fmt_layer<S, W>(
    format: LogFormat,
    writer: W,
    ansi: bool,
) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + Send + Sync + 'static,
{
    let base = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(ansi);

    match format {
        LogFormat::Json => Box::new(base.json()),
        LogFormat::Compact => Box::new(base.compact()),
        LogFormat::Pretty => Box::new(base.pretty()),
    }
}

fn parse_format(value: &str) -> LogFormat {
    match value.trim().to_ascii_lowercase().as_str() {
        "json" => LogFormat::Json,
        "compact" => LogFormat::Compact,
        _ => LogFormat::Pretty,
    }
}

fn parse_bool(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on")
}

fn parse_bytes(value: &str) -> Option<u64> {
    let size_str = value.trim().to_ascii_uppercase();
    if let Some(num) = size_str.strip_suffix('M') {
        num.parse::<u64>().ok().map(|n| n * 1024 * 1024)
    } else if let Some(num) = size_str.strip_suffix('K') {
        num.parse::<u64>().ok().map(|n| n * 1024)
    } else if let Some(num) = size_str.strip_suffix('G') {
        num.parse::<u64>().ok().map(|n| n * 1024 * 1024 * 1024)
    } else {
        value.trim().parse::<u64>().ok()
    }
}
