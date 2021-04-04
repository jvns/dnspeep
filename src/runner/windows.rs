use super::super::capturer::{capture_file, capture_interface};
use super::super::Opts;
use super::Source;
use eyre::Report;

#[cfg(windows)]
pub fn run_on_windows(opts: Opts) -> Result<(), Report> {
    let source = opts.source.clone();

    return match source {
        Source::Interface(interface) => capture_interface(interface, opts),
        Source::Filename(filename) => capture_file(&filename, opts),
        Source::Port(_) => Err(Report::msg(
            "On windows, use `interface` or `file` instead.",
        )),
    };
}
