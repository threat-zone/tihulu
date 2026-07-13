#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(windows)]
mod debug_tracker;
#[cfg(windows)]
mod call_scanner;
#[cfg(windows)]
mod memory_reader;
#[cfg(windows)]
mod proxy;
mod tls_decrypt;
mod tls_parser;
mod tls_types;

use clap::Parser;

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
        eprintln!("Usage:");
        eprintln!("  tlsdump [options] [--] command [args...]");
        eprintln!("  tlsdump [options] --pid <PID>");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  -w <dir>      Write per-process key files into <dir>");
        eprintln!("                (file name: <PID>_<PROCESS_NAME>_tls.key)");
        eprintln!("  --pid <PID>   Attach to a running process by PID");
        eprintln!("  -t <N>        Number of memory-scan threads (default: num CPUs)");
        std::process::exit(1);
    }

    #[cfg(windows)]
    {
        run_windows(args);
    }

    #[cfg(not(windows))]
    {
        eprintln!("This tool only runs on Windows.");
        eprintln!("using the Windows Debug API.");
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
            eprintln!("Failed to create output directory {}: {}", dir, e);
            std::process::exit(1);
        }
        eprintln!("Writing per-process key files into {}", dir);
    }

    let pid = if let Some(pid) = args.pid {
        if let Err(e) = DebugTracker::attach(pid) {
            eprintln!("Failed to attach to PID {}: {}", pid, e);
            std::process::exit(1);
        }
        pid
    } else if !args.command.is_empty() {
        let cmd = &args.command[0];
        let cmd_args: Vec<&str> = args.command[1..].iter().map(|s| s.as_str()).collect();
        match DebugTracker::launch_process(cmd, &cmd_args, args.output_dir.as_deref()) {
            Ok(pid) => pid,
            Err(e) => {
                eprintln!("Failed to launch process: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("No target specified");
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
        /*resume_on_attach=*/ false,
    );
    let mut multi = MultiTracker::new(cfg);
    multi.add_initial(initial);
    if let Err(e) = multi.run() {
        eprintln!("Debug loop error: {}", e);
        std::process::exit(1);
    }
}
