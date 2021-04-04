use super::super::capturer::{capture_device, capture_file};
use super::super::Opts;
use super::Source;
use eyre::Report;

#[cfg(windows)]
pub fn run_on_windows(opts: Opts) -> Result<(), Report> {
    let source = opts.source.clone();

    return match source {
        Source::Device(device) => capture_device(device, opts),
        Source::Filename(filename) => capture_file(&filename, opts),
        Source::Port(_) => Err(Report::msg("On windows, use `device` or `file` instead.")),
    };
}
