#[cfg(not(windows))]
use super::super::capturer::{capture_file, capture_interface, capture_packets, capture_stream};
#[cfg(not(windows))]
use super::super::Opts;
#[cfg(not(windows))]
use super::super::Source;
#[cfg(not(windows))]
use eyre::Report;
#[cfg(not(windows))]
use std::collections::HashMap;
#[cfg(not(windows))]
use std::sync::{Arc, Mutex};

#[cfg(not(windows))]
pub async fn run_on_unix(opts: Opts) -> Result<(), Report> {
    let source = opts.source.clone();

    return match source {
        Source::Interface(interface) => capture_interface(interface, opts),
        Source::Port(port) => {
            let map = Arc::new(Mutex::new(HashMap::new()));
            let stream = capture_stream(opts, map.clone(), port)?;
            capture_packets(stream).await;

            Ok(())
        }
        Source::Filename(filename) => capture_file(&filename, opts),
    };
}
