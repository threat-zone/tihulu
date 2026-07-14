#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(windows)]
mod call_scanner;
#[cfg(windows)]
mod debug_tracker;
#[cfg(windows)]
mod memory_reader;
#[cfg(windows)]
mod proxy;
mod tls_decrypt;
mod tls_parser;
mod tls_types;

use clap::Parser;

// ---------------------------------------------------------------------------
// Colorized logging
//
// All tool status output goes to stderr through `logln!`, which colors just
// the leading status indicator and prints the message itself in white:
// `[+]` green (success), `[!]` yellow (warning), `[*]` bold (progress),
// `[-]` red (error/teardown). Lines without one of those markers (e.g. verbose
// `[dbg]` traces) are left uncolored. Colors are emitted only when stderr is a
// terminal and `NO_COLOR` is unset, so redirected logs stay plain. Key material
// is written to files/stdout separately and is never touched by this.
// ---------------------------------------------------------------------------

/// Format like `eprintln!` but route through the colorizer. `()` prints a
/// blank line, matching `eprintln!()`.
#[macro_export]
macro_rules! logln {
    () => { $crate::emit_log(format_args!("")) };
    ($($arg:tt)*) => { $crate::emit_log(format_args!($($arg)*)) };
}

/// True when ANSI colors should be emitted on stderr. Decided once.
fn color_enabled() -> bool {
    use std::io::IsTerminal;
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED
        .get_or_init(|| std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal())
}

/// Wrap `msg` in the ANSI color for its leading marker, honoring the runtime
/// color decision. See [`colorize_with`] for the pure mapping.
fn colorize(msg: &str) -> std::borrow::Cow<'_, str> {
    colorize_with(msg, color_enabled())
}

/// Pure colorizer: when `enabled`, color just the 3-char status indicator and
/// render the rest of the message in white. `[+]` green, `[!]` yellow, `[*]`
/// bold, `[-]` red; a line without one of those markers is returned unchanged.
fn colorize_with(msg: &str, enabled: bool) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    if !enabled {
        return Cow::Borrowed(msg);
    }
    // Marker style: 32 = green, 33 = yellow, 1 = bold, 31 = red.
    let code = if msg.starts_with("[+]") {
        "32"
    } else if msg.starts_with("[!]") {
        "33"
    } else if msg.starts_with("[*]") {
        "1"
    } else if msg.starts_with("[-]") {
        "31"
    } else {
        return Cow::Borrowed(msg);
    };
    // Color only the 3-char indicator (`[X]`); print the message itself in
    // white (37). The reset after the marker keeps bold `[*]` from bleeding
    // into the message text.
    let (marker, rest) = msg.split_at(3);
    Cow::Owned(format!("\x1b[{}m{}\x1b[0m\x1b[37m{}\x1b[0m", code, marker, rest))
}

#[cfg(test)]
mod color_tests {
    use super::colorize_with;

    #[test]
    fn colors_only_the_marker() {
        assert_eq!(
            colorize_with("[+] ok", true),
            "\x1b[32m[+]\x1b[0m\x1b[37m ok\x1b[0m"
        );
        assert_eq!(
            colorize_with("[!] warn", true),
            "\x1b[33m[!]\x1b[0m\x1b[37m warn\x1b[0m"
        );
        assert_eq!(
            colorize_with("[*] work", true),
            "\x1b[1m[*]\x1b[0m\x1b[37m work\x1b[0m"
        );
        assert_eq!(
            colorize_with("[-] bye", true),
            "\x1b[31m[-]\x1b[0m\x1b[37m bye\x1b[0m"
        );
    }

    #[test]
    fn leaves_other_lines_untouched() {
        assert_eq!(colorize_with("[dbg] trace", true), "[dbg] trace");
        assert_eq!(colorize_with("plain", true), "plain");
    }

    #[test]
    fn disabled_never_colors() {
        assert_eq!(colorize_with("[+] ok", false), "[+] ok");
    }
}

/// Write one colorized log line to stderr. Backs the `logln!` macro.
pub(crate) fn emit_log(args: std::fmt::Arguments) {
    use std::io::Write;
    let s = args.to_string();
    let line = colorize(&s);
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{}", line);
}

#[derive(Parser, Debug, Clone)]
#[command(name = "tlsdump", about = "Windows TLS 1.2/1.3 key extractor")]
struct Args {
    /// Directory in which to write per-process key files
    /// (`<PID>_<PROCESS_NAME>_tls.key`). Defaults to stdout when unset.
    #[arg(short = 'w', long = "write")]
    output_dir: Option<String>,

    /// Enable verbose debug logging.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Process ID to attach to.
    #[arg(long)]
    pid: Option<u32>,

    /// Number of threads to use for memory scanning (default: number of CPUs).
    #[arg(short = 't', long = "threads")]
    threads: Option<usize>,

    /// Fall back to brute-force memory scan if CALL-probe yields no working
    /// candidate. Off by default — the call-probe scanner is the primary path.
    #[arg(long = "fallback-scan")]
    fallback_scan: bool,

    /// Disable the CALL-probe scanner entirely (use brute-force only).
    #[arg(long = "no-call-probe")]
    no_call_probe: bool,

    /// Keep intercepting connections and extracting keys after the first TLS
    /// session's keys are recovered. Without this flag Tihulu stops
    /// intercepting new connections once the first key search finishes (the
    /// connect hooks are not re-armed) and simply stays attached until the
    /// target exits.
    #[arg(short = 'c', long = "continue")]
    continuous: bool,

    /// Maximum number of CALL-instruction breakpoints to install per arming
    /// of the scanner. Lower values reduce per-event overhead; higher values
    /// improve coverage on large processes.
    #[arg(long = "max-call-bps", default_value_t = 500_000)]
    max_call_bps: usize,

    /// Also trace any child processes spawned by the target. When set,
    /// CreateProcess{A,W,AsUserW} / NtCreateUserProcess are hooked and each
    /// spawned PID is attached to in the same Tihulu instance.
    #[arg(long = "trace-children")]
    trace_children: bool,

    /// Command to execute and trace (all remaining arguments).
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

fn main() {
    let args = Args::parse();

    if args.pid.is_none() && args.command.is_empty() {
        crate::logln!("Usage:");
        crate::logln!("  tlsdump [options] [--] command [args...]");
        crate::logln!("  tlsdump [options] --pid <PID>");
        crate::logln!();
        crate::logln!("Options:");
        crate::logln!("  -w <dir>      Write per-process key files into <dir>");
        crate::logln!("                (file name: <PID>_<PROCESS_NAME>_tls.key)");
        crate::logln!("  --pid <PID>   Attach to a running process by PID");
        crate::logln!("  -t <N>        Number of memory-scan threads (default: num CPUs)");
        std::process::exit(1);
    }

    #[cfg(windows)]
    {
        run_windows(args);
    }

    #[cfg(not(windows))]
    {
        crate::logln!("This tool only runs on Windows.");
        crate::logln!("using the Windows Debug API.");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run_windows(args: Args) {
    use debug_tracker::{DebugTracker, MultiTracker, TrackerConfig};

    // Ensure the output directory exists *before* launching the target so
    // that any SSLKEYLOGFILE path we hand to the child resolves to a real
    // directory the moment the loader picks the variable up.
    if let Some(ref dir) = args.output_dir {
        if let Err(e) = std::fs::create_dir_all(dir) {
            crate::logln!("Failed to create output directory {}: {}", dir, e);
            std::process::exit(1);
        }
        crate::logln!("Writing per-process key files into {}", dir);
    }

    let pid = if let Some(pid) = args.pid {
        if let Err(e) = DebugTracker::attach(pid) {
            crate::logln!("Failed to attach to PID {}: {}", pid, e);
            std::process::exit(1);
        }
        pid
    } else if !args.command.is_empty() {
        let cmd = &args.command[0];
        let cmd_args: Vec<&str> = args.command[1..].iter().map(|s| s.as_str()).collect();
        match DebugTracker::launch_process(cmd, &cmd_args, args.output_dir.as_deref()) {
            Ok(pid) => pid,
            Err(e) => {
                crate::logln!("Failed to launch process: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        crate::logln!("No target specified");
        std::process::exit(1);
    };

    // Set `SSLKEYLOGFILE` in *our* environment to the canonical per-PID
    // path. This is purely so any process Tihulu itself spawns later
    // (e.g. a child Tihulu instance under `--trace-children`) inherits the
    // variable — the launched target had its env block patched directly in
    // `launch_process`, and an attach-mode target's env block is already
    // frozen and cannot be retroactively modified.
    if let Some(ref dir) = args.output_dir {
        let abs_dir = std::path::absolute(std::path::Path::new(dir))
            .unwrap_or_else(|_| std::path::PathBuf::from(dir));
        let key_path = abs_dir.join(format!("{}_SSLKEYLOGFILE.key", pid));
        std::env::set_var("SSLKEYLOGFILE", &key_path);
    }

    let cfg = TrackerConfig {
        output_dir: args.output_dir,
        verbose: args.verbose,
        search_threads: args.threads,
        call_probe_enabled: !args.no_call_probe,
        max_call_bps: args.max_call_bps,
        fallback_scan: args.fallback_scan,
        trace_children: args.trace_children,
        continuous: args.continuous,
    };
    let initial = DebugTracker::new(
        pid,
        cfg.output_dir.clone(),
        cfg.verbose,
        cfg.search_threads,
        cfg.call_probe_enabled,
        cfg.max_call_bps,
        cfg.fallback_scan,
        cfg.trace_children,
        cfg.continuous,
        /*resume_on_attach=*/ false,
    );
    let mut multi = MultiTracker::new(cfg);
    multi.add_initial(initial);
    if let Err(e) = multi.run() {
        crate::logln!("Debug loop error: {}", e);
        std::process::exit(1);
    }
}
