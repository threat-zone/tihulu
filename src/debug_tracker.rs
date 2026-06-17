//! Windows Debug API based connection tracker.
//!
//! Uses software breakpoints on Winsock functions to intercept network I/O,
//! then feeds captured data to the TLS parser for key extraction.
//!
//! Key design points:
//! - Function breakpoints (INT3) on connect/send/recv/closesocket/WSASend/WSARecv
//! - Return-address breakpoints for recv/WSARecv to capture incoming data
//! - Breakpoints are retried on each LOAD_DLL event until ws2_32 is mapped
//! - DEBUG_ONLY_THIS_PROCESS avoids child-process handle confusion

#![cfg(windows)]

use std::collections::HashMap;
use std::mem;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use windows::Win32::Foundation::*;
use windows::Win32::Networking::WinSock::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;

use crate::memory_reader::MemoryReader;
use crate::tls_decrypt;
use crate::tls_parser::{hex_string, TlsParser, TLS13_CHTS, TLS13_CTS0, TLS13_SHTS, TLS13_STS0, TLS13_ALL};
use crate::tls_types::*;
use crate::call_scanner::{self, ArgReg, CallScanner, Phase as ScanPhase};

macro_rules! dbg_log {
    ($self:expr, $($arg:tt)*) => {
        if $self.verbose {
            eprintln!($($arg)*);
        }
    };
}

// ============================================================================
// Raw FFI for x86_64-specific APIs
// ============================================================================

#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
pub struct Amd64Context {
    _home: [u64; 6],
    pub context_flags: u32,
    _mx_csr: u32,
    _seg: [u16; 6],
    pub eflags: u32,
    _debug_regs: [u64; 6],
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    _rest: [u8; 976],
}

#[cfg(target_arch = "x86_64")]
const CTX_AMD64: u32 = 0x0010_0000;
#[cfg(target_arch = "x86_64")]
const CTX_CONTROL: u32 = CTX_AMD64 | 0x01;
#[cfg(target_arch = "x86_64")]
const CTX_INTEGER: u32 = CTX_AMD64 | 0x02;
#[cfg(target_arch = "x86_64")]
const CTX_FLOATING: u32 = CTX_AMD64 | 0x08;
#[cfg(target_arch = "x86_64")]
const CTX_FULL: u32 = CTX_CONTROL | CTX_INTEGER | CTX_FLOATING;

extern "system" {
    fn GetThreadContext(h: HANDLE, ctx: *mut Amd64Context) -> BOOL;
    fn SetThreadContext(h: HANDLE, ctx: *const Amd64Context) -> BOOL;
    fn ReadProcessMemory(
        h: HANDLE,
        base: *const std::ffi::c_void,
        buf: *mut std::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> BOOL;
    fn WriteProcessMemory(
        h: HANDLE,
        base: *const std::ffi::c_void,
        buf: *const std::ffi::c_void,
        size: usize,
        written: *mut usize,
    ) -> BOOL;
    fn FlushInstructionCache(h: HANDLE, base: *const std::ffi::c_void, size: usize) -> BOOL;
    fn SuspendThread(h: HANDLE) -> u32;
    fn ResumeThread(h: HANDLE) -> u32;
}

// ============================================================================
// Internal types
// ============================================================================

struct HookAddresses {
    connect: u64,
    wsaconnect: u64,
    send: u64,
    recv: u64,
    recvfrom: u64,
    sendto: u64,
    closesocket: u64,
    wsasend: u64,
    wsarecv: u64,
    wsarecvfrom: u64,
    wsasendto: u64,
    gqcs: u64,
    gqcs_ex: u64,
    wsa_get_overlapped_result: u64,
    // Process-creation APIs — we hook these so we can also trace any child
    // process spawned by the target. Optional: zero means "not resolved".
    create_process_w: u64,
    create_process_a: u64,
    create_process_as_user_w: u64,
    // ntdll syscall stubs that all higher-level CreateProcess variants
    // ultimately call. Hooking them lets us also catch alternate process
    // launch paths (e.g. RtlCreateUserProcess, posix subsystem, etc.).
    nt_create_user_process: u64,
    zw_create_user_process: u64,
}

enum BreakpointKind {
    /// Permanent breakpoint at an API function entry point.
    Function,
    /// One-shot breakpoint at a return address to capture post-call state.
    /// Multiple concurrent calls (from different threads) may share the same
    /// return address — all pending calls are stored and dispatched by thread.
    Return { calls: Vec<(u32, PendingCall)> },
    /// CALL-probe breakpoint placed on a CALL instruction inside an
    /// allow-listed module. Inspected at hit time for TLS secret candidates.
    CallProbe,
}

/// Resolved buffer pointer + capacity from a WSABUF struct.
#[derive(Clone)]
struct ResolvedBuf {
    ptr: u64,
    len: usize,
}

/// Tracks a pending overlapped recv so IOCP completions can find the buffers.
/// Buffer pointers are resolved eagerly at call time so they remain valid even
/// if the original WSABUF array was stack-allocated and has since been freed.
#[derive(Clone)]
struct PendingOverlapped {
    socket: u64,
    bufs: Vec<ResolvedBuf>,
}

#[derive(Clone)]
enum PendingCall {
    Recv {
        socket: u64,
        buf_ptr: u64,
        max_len: usize,
    },
    RecvFrom {
        socket: u64,
        buf_ptr: u64,
        max_len: usize,
    },
    WsaRecv {
        socket: u64,
        bufs: Vec<ResolvedBuf>,
        bytes_received_ptr: u64,
        overlapped_ptr: u64,
    },
    WsaRecvFrom {
        socket: u64,
        bufs: Vec<ResolvedBuf>,
        bytes_received_ptr: u64,
        overlapped_ptr: u64,
    },
    Gqcs {
        bytes_transferred_ptr: u64,
        completion_key_ptr: u64,
        overlapped_ptr_ptr: u64,
    },
    GqcsEx {
        entries_ptr: u64,
        num_removed_ptr: u64,
    },
    WsaGetOverlappedResult {
        socket: u64,
        overlapped_ptr: u64,
        transfer_ptr: u64,
    },
    /// CreateProcess{A,W,AsUserW}. The 10th argument (lpProcessInformation)
    /// is filled in by the time the call returns; we read dwProcessId from
    /// it and spawn a child Tihulu instance to monitor the new process.
    CreateProcess {
        process_info_ptr: u64,
    },
    /// NtCreateUserProcess / ZwCreateUserProcess. The first argument is a
    /// PHANDLE that receives the new process handle (in the *target's*
    /// handle table); we resolve it to a PID at return time by duplicating
    /// the handle into our own process.
    NtCreateUserProcess {
        process_handle_ptr: u64,
    },
}

struct Breakpoint {
    original_byte: u8,
    kind: BreakpointKind,
}

struct ConnectionState {
    parser: TlsParser,
    process_handle: HANDLE,
}

struct ThreadState {
    /// Address of function breakpoint to re-set after single-step.
    restore_bp: Option<u64>,
}

// ============================================================================
// DebugTracker
// ============================================================================

/// Result of processing a single `DEBUG_EVENT` from `WaitForDebugEvent`.
pub(crate) struct EventOutcome {
    pub status: NTSTATUS,
    /// True when `EXIT_PROCESS_DEBUG_EVENT` was just observed for this PID.
    /// The orchestrator must remove the tracker from its active set.
    pub finished: bool,
}

pub struct DebugTracker {
    process_handle: HANDLE,
    pid: u32,
    hook_addrs: Option<HookAddresses>,
    breakpoints: HashMap<u64, Breakpoint>,
    /// True once all function breakpoints are installed in the target.
    breakpoints_active: bool,
    connections: HashMap<(u32, u64), ConnectionState>,
    /// Pending overlapped recv operations, keyed by OVERLAPPED pointer address.
    pending_overlapped: HashMap<u64, PendingOverlapped>,
    /// Recently consumed return-breakpoint addresses → original byte.
    /// Used to handle "ghost" breakpoints from other threads that hit the
    /// INT3 between write and consume on a different thread.
    consumed_return_addrs: HashMap<u64, u8>,
    threads: HashMap<u32, ThreadState>,
    thread_handles: HashMap<u32, HANDLE>,
    /// User-specified output directory. Each tracked process writes its keys
    /// into `<output_dir>/<PID>_<PROCESS_NAME>_tls.key`. None ⇒ stdout.
    output_dir: Option<String>,
    /// Resolved per-process output file path. Computed lazily on the first
    /// key extraction once the process image name is known.
    output_path: Option<std::path::PathBuf>,
    /// Image name of the target process (without path, without extension).
    /// Populated from CREATE_PROCESS_DEBUG_EVENT.
    process_name: String,
    /// Child PIDs that the multi-tracker orchestrator should attach to
    /// after this tracker finishes processing the current debug event.
    /// Populated when a CreateProcess/NtCreateUserProcess hook fires.
    pending_child_attaches: Vec<u32>,
    /// When true, CreateProcess{A,W,AsUserW} are hooked and any child
    /// processes spawned by the target are also attached to in the same
    /// Tihulu instance. Off by default.
    trace_children: bool,
    /// When true, the target process was launched in a suspended state by
    /// a parent Tihulu instance. Once all breakpoints have been installed
    /// the main thread is resumed exactly once.
    resume_on_attach: bool,
    /// Thread ID of the target's main thread, captured from
    /// `CREATE_PROCESS_DEBUG_EVENT`. Used by the `--resume-on-attach` path.
    main_thread_tid: Option<u32>,
    /// Whether we have already performed the post-attach `ResumeThread` for
    /// `--resume-on-attach`. ResumeThread is not idempotent so this flag
    /// prevents accidental double-resume.
    resumed_on_attach: bool,
    /// Set to true once we have successfully extracted and recorded at least
    /// one TLS secret. The event loop unhooks and detaches on the next tick.
    should_detach: bool,
    /// Set once we have called `DebugActiveProcessStop` so `Drop` knows it
    /// must not touch the target process's memory anymore.
    detached: bool,
    verbose: bool,
    /// Number of threads to use when scanning process memory for secrets.
    search_threads: usize,
    /// Set to true whenever a TLS ClientHello is observed on any connection.
    /// Persists even after the connection is closed/removed.
    any_tls_seen: bool,
    /// Loaded modules (DLL base address → (name, optional end)). Populated
    /// from LOAD_DLL events and completed on demand via EnumProcessModulesEx.
    loaded_modules: HashMap<u64, LoadedModule>,
    /// Base address of the main image (from CREATE_PROCESS_DEBUG_EVENT).
    main_image_base: u64,
    /// CALL-probe scanner. Inert (phase == WaitingHandshake) until ServerHello.
    scanner: CallScanner,
    /// Whether CALL-probe scanning is enabled.
    call_probe_enabled: bool,
    /// Maximum number of CALL breakpoints to install in a single arming.
    max_call_bps: usize,
    /// Whether the brute-force scan fallback is allowed when no candidate decrypts.
    fallback_scan: bool,
    _stop: Arc<AtomicBool>,
}

struct LoadedModule {
    name: String,
    base: u64,
}

impl DebugTracker {
    pub fn new(
        pid: u32,
        output_dir: Option<String>,
        verbose: bool,
        search_threads: Option<usize>,
        call_probe_enabled: bool,
        max_call_bps: usize,
        fallback_scan: bool,
        trace_children: bool,
        resume_on_attach: bool,
    ) -> Self {
        let search_threads = search_threads
            .filter(|&n| n > 0)
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
        eprintln!("[*] Memory-scan threads: {}", search_threads);
        eprintln!(
            "[*] CALL-probe scanner: {}, brute-force fallback: {}",
            if call_probe_enabled { "enabled" } else { "disabled" },
            if fallback_scan { "enabled" } else { "disabled" },
        );
        eprintln!(
            "[*] Child-process tracing: {}",
            if trace_children { "enabled" } else { "disabled" },
        );
        if resume_on_attach {
            eprintln!("[*] Target was started suspended — will resume after hook install");
        }
        Self {
            process_handle: HANDLE::default(),
            pid,
            hook_addrs: None,
            breakpoints: HashMap::new(),
            breakpoints_active: false,
            connections: HashMap::new(),
            pending_overlapped: HashMap::new(),
            consumed_return_addrs: HashMap::new(),
            threads: HashMap::new(),
            thread_handles: HashMap::new(),
            output_dir,
            output_path: None,
            process_name: String::new(),
            pending_child_attaches: Vec::new(),
            should_detach: false,
            detached: false,
            verbose,
            search_threads,
            any_tls_seen: false,
            loaded_modules: HashMap::new(),
            main_image_base: 0,
            scanner: CallScanner::new(0, verbose),
            call_probe_enabled,
            max_call_bps,
            fallback_scan,
            trace_children,
            resume_on_attach,
            main_thread_tid: None,
            resumed_on_attach: false,
            _stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn launch_process(
        cmd: &str,
        args: &[&str],
        output_dir: Option<&str>,
    ) -> std::io::Result<u32> {
        use std::os::windows::ffi::OsStrExt;
        let mut cmdline = format!("\"{}\"", cmd);
        for a in args {
            cmdline.push(' ');
            cmdline.push_str(a);
        }
        let mut wide: Vec<u16> = std::ffi::OsStr::new(&cmdline)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // When an output directory is configured, inject `SSLKEYLOGFILE` into
        // the child's environment so any TLS library that honours the NSS key
        // log convention (BoringSSL, NSS, OpenSSL ≥ 1.1.1, GnuTLS, rustls via
        // `KeyLogFile::new`, .NET 9+) writes its own keys alongside Tihulu's.
        //
        // The child is launched `CREATE_SUSPENDED` so the loader has not yet
        // read any environment variable. We set `SSLKEYLOGFILE` in *our own*
        // env to a path containing a fixed-width 10-digit placeholder, which
        // the child inherits verbatim. Once `CreateProcessW` returns the real
        // PID, we patch the placeholder digits inside the child's already
        // copied environment block (via PEB → ProcessParameters → Environment)
        // and only then resume the main thread.
        const PID_PLACEHOLDER: &str = "0000000000"; // exactly 10 chars (u32::MAX = 4294967295)
        // Resolve `output_dir` to a fully-qualified absolute path: the child
        // process may inherit a different working directory than ours, so a
        // relative `SSLKEYLOGFILE` would land in an unpredictable location
        // (or fail to open at all). `std::path::absolute` performs purely
        // lexical resolution against the current process's CWD without
        // requiring the path to exist yet and — crucially on Windows —
        // without prepending the `\\?\` extended-length prefix that
        // `fs::canonicalize` adds (some runtimes refuse such paths).
        let key_path_template = output_dir.and_then(|dir| {
            let dir_path = std::path::Path::new(dir);
            let abs_dir = match std::path::absolute(dir_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "[!] Could not resolve absolute path for output dir '{}': {} \
                         — SSLKEYLOGFILE will not be injected",
                        dir, e
                    );
                    return None;
                }
            };
            let file = abs_dir.join(format!("{}_SSLKEYLOGFILE.key", PID_PLACEHOLDER));
            Some(file.to_string_lossy().into_owned())
        });
        // Set `SSLKEYLOGFILE` in our own environment so the freshly-created
        // child (and any further direct children Tihulu may spawn during
        // this run) inherit it. We deliberately do *not* restore the prior
        // value after `CreateProcessW`: keeping the variable set is the
        // whole point — any process inheriting from Tihulu should see it.
        if let Some(ref p) = key_path_template {
            std::env::set_var("SSLKEYLOGFILE", p);
        }

        let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
        si.cb = mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

        unsafe {
            CreateProcessW(
                None,
                windows::core::PWSTR(wide.as_mut_ptr()),
                None,
                None,
                false,
                DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
                None,
                None,
                &si,
                &mut pi,
            )?;
        }

        if let Some(ref template) = key_path_template {
            let pid_str = format!("{:0>10}", pi.dwProcessId);
            match patch_child_env_placeholder(
                pi.hProcess,
                "SSLKEYLOGFILE=",
                PID_PLACEHOLDER,
                &pid_str,
            ) {
                Ok(()) => {
                    let final_path = template.replacen(PID_PLACEHOLDER, &pid_str, 1);
                    // Update our own env to the patched (real-PID) path so
                    // subsequent process spawns from Tihulu inherit the
                    // canonical filename rather than the placeholder.
                    std::env::set_var("SSLKEYLOGFILE", &final_path);
                    eprintln!("[*] SSLKEYLOGFILE injected: {}", final_path);
                }
                Err(e) => {
                    eprintln!(
                        "[!] Failed to patch SSLKEYLOGFILE in child env: {} \
                         (child will use placeholder PID filename)",
                        e
                    );
                }
            }
        }

        unsafe {
            // Release the main thread now that the env block has been patched.
            // The kernel will queue the CREATE_PROCESS_DEBUG_EVENT for our
            // debug loop in the normal way.
            ResumeThread(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        }
        Ok(pi.dwProcessId)
    }

    pub fn attach(pid: u32) -> std::io::Result<()> {
        // `DebugActiveProcess` on a freshly-created suspended child races
        // against the kernel finishing user-mode initialisation of the new
        // process and returns ERROR_INVALID_PARAMETER (0x57) until the
        // debug port is wired. Rather than blindly retrying, poll
        // `NtQueryInformationProcess(ProcessDebugObjectHandle)`: once it
        // returns STATUS_PORT_NOT_SET the process is ready to accept a
        // debugger. Falls back to a short retry loop if the query path is
        // unavailable for any reason.
        wait_until_debuggable(pid);
        const RETRIES: u32 = 5;
        let mut last_err: Option<std::io::Error> = None;
        for attempt in 0..RETRIES {
            match unsafe { DebugActiveProcess(pid) } {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let raw = e.code().0 as u32;
                    // 0x80070057 == HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER)
                    let transient = raw == 0x8007_0057;
                    last_err = Some(std::io::Error::from(e));
                    if !transient || attempt + 1 == RETRIES {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "DebugActiveProcess failed")
        }))
    }

    // ------------------------------------------------------------------
    // Event loop
    // ------------------------------------------------------------------

    /// Process a single DEBUG_EVENT delivered by `WaitForDebugEvent`. The
    /// caller (the multi-target orchestrator) is responsible for calling
    /// `ContinueDebugEvent` afterwards with the returned status. Returns
    /// `finished=true` when this process has exited and the tracker should
    /// be removed from the active set.
    pub(crate) fn process_one_event(&mut self, event: &DEBUG_EVENT) -> EventOutcome {
        let status: NTSTATUS = match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { &event.u.CreateProcessInfo };
                self.process_handle = info.hProcess;
                self.thread_handles.insert(event.dwThreadId, info.hThread);
                self.threads
                    .insert(event.dwThreadId, ThreadState { restore_bp: None });
                if self.main_thread_tid.is_none() {
                    self.main_thread_tid = Some(event.dwThreadId);
                }
                if !info.hFile.is_invalid() {
                    unsafe {
                        let _ = CloseHandle(info.hFile);
                    }
                }
                self.main_image_base = info.lpBaseOfImage as u64;
                if self.process_name.is_empty() {
                    self.process_name = query_process_image_name(self.process_handle)
                        .unwrap_or_else(|| format!("pid{}", self.pid));
                    eprintln!("[*] Target process image: {} (PID {})", self.process_name, self.pid);
                }
                dbg_log!(self, "[dbg] CREATE_PROCESS tid={} handle={:?} main_image=0x{:X}",
                    event.dwThreadId, self.process_handle, self.main_image_base);
                self.resolve_hook_addresses();
                DBG_CONTINUE
            }
            CREATE_THREAD_DEBUG_EVENT => {
                let info = unsafe { &event.u.CreateThread };
                self.thread_handles.insert(event.dwThreadId, info.hThread);
                self.threads
                    .insert(event.dwThreadId, ThreadState { restore_bp: None });
                DBG_CONTINUE
            }
            EXIT_THREAD_DEBUG_EVENT => {
                eprintln!("[-] Thread exited: tid={} (PID {})", event.dwThreadId, self.pid);
                self.threads.remove(&event.dwThreadId);
                self.thread_handles.remove(&event.dwThreadId);
                DBG_CONTINUE
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                eprintln!("[-] Target process exited (PID {})", self.pid);
                return EventOutcome { status: DBG_CONTINUE, finished: true };
            }
            EXCEPTION_DEBUG_EVENT => {
                let info = unsafe { &event.u.Exception };
                self.handle_exception(event.dwProcessId, event.dwThreadId, info)
            }
            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { &event.u.LoadDll };
                let base = info.lpBaseOfDll as u64;
                let name = read_dll_name(self.process_handle, info);
                if !info.hFile.is_invalid() {
                    unsafe {
                        let _ = CloseHandle(info.hFile);
                    }
                }
                dbg_log!(self, "[dbg] LOAD_DLL base=0x{:X} name={}", base, name);
                if base != 0 {
                    self.loaded_modules.insert(base, LoadedModule { name, base });
                }
                if !self.breakpoints_active {
                    if self.hook_addrs.is_none() {
                        self.resolve_hook_addresses();
                    }
                    let result = self.try_set_all_breakpoints();
                    dbg_log!(self, "[dbg] try_set_all_breakpoints => {}", result);
                    if result {
                        self.breakpoints_active = true;
                        eprintln!("[+] All breakpoints installed (PID {})", self.pid);
                        self.maybe_resume_on_attach();
                    }
                }
                DBG_CONTINUE
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { &event.u.UnloadDll };
                let base = info.lpBaseOfDll as u64;
                self.loaded_modules.remove(&base);
                DBG_CONTINUE
            }
            _ => DBG_CONTINUE,
        };
        EventOutcome { status, finished: false }
    }

    /// Emit the end-of-session diagnostic for this tracker.
    pub(crate) fn finalize_summary(&mut self) {
        if !self.any_tls_seen {
            eprintln!("[!] No TLS ClientHello was observed for PID {} during this session.",
                self.pid);
        }
        self.connections.clear();
    }

    // ------------------------------------------------------------------
    // Exception handling
    // ------------------------------------------------------------------

    fn handle_exception(
        &mut self,
        pid: u32,
        tid: u32,
        info: &EXCEPTION_DEBUG_INFO,
    ) -> NTSTATUS {
        let code = info.ExceptionRecord.ExceptionCode;
        let addr = info.ExceptionRecord.ExceptionAddress as u64;

        if code == EXCEPTION_BREAKPOINT {
            dbg_log!(self, "[dbg] BREAKPOINT at 0x{:X} first_chance={}", addr, info.dwFirstChance);
            // Determine breakpoint type without holding a borrow on self.
            let bp_info = self.breakpoints.get(&addr).map(|bp| {
                let tag: u8 = match bp.kind {
                    BreakpointKind::Function => 0,
                    BreakpointKind::Return { .. } => 1,
                    BreakpointKind::CallProbe => 2,
                };
                (bp.original_byte, tag)
            });
            if bp_info.is_none() {
                dbg_log!(self, "[dbg]   not one of our breakpoints");
            }

            if let Some((orig, tag)) = bp_info {
                // Restore original byte so the instruction can execute.
                write_mem(self.process_handle, addr, &[orig]);

                if tag == 0 {
                    // --- Function breakpoint ---
                    dbg_log!(self, "[dbg]   => function BP at 0x{:X}, dispatching", addr);
                    self.dispatch_function_bp(pid, tid, addr);

                    // Rewind RIP and single-step past the original instruction.
                    if let Some(&th) = self.thread_handles.get(&tid) {
                        set_rip(th, addr);
                        enable_trap_flag(th);
                    }
                    if let Some(ts) = self.threads.get_mut(&tid) {
                        ts.restore_bp = Some(addr);
                    }
                } else if tag == 2 {
                    // --- CALL-probe breakpoint ---
                    let cull = self.on_call_probe_hit(tid, addr);
                    if cull {
                        // Permanently disarm this site. Byte is already restored.
                        self.breakpoints.remove(&addr);
                        self.scanner.bps.remove(&addr);
                        flush_icache(self.process_handle, addr);
                        if let Some(&th) = self.thread_handles.get(&tid) {
                            set_rip(th, addr);
                        }
                    } else {
                        if let Some(&th) = self.thread_handles.get(&tid) {
                            set_rip(th, addr);
                            enable_trap_flag(th);
                        }
                        if let Some(ts) = self.threads.get_mut(&tid) {
                            ts.restore_bp = Some(addr);
                        }
                    }
                } else {
                    // --- Return breakpoint ---
                    dbg_log!(self, "[dbg]   => return BP at 0x{:X}, dispatching for tid={}", addr, tid);
                    let mut bp = self.breakpoints.remove(&addr).unwrap();
                    // Extract the call for this thread from the calls list.
                    let dispatched_call = if let BreakpointKind::Return { ref mut calls } = bp.kind {
                        if let Some(pos) = calls.iter().position(|(t, _)| *t == tid) {
                            Some(calls.remove(pos))
                        } else {
                            // No call for this thread — may be a ghost hit.
                            None
                        }
                    } else {
                        None
                    };
                    // If there are remaining calls from other threads, re-insert the BP.
                    let has_remaining = if let BreakpointKind::Return { ref calls } = bp.kind {
                        !calls.is_empty()
                    } else {
                        false
                    };
                    if has_remaining {
                        // Don't re-write INT3 yet — the current thread must
                        // single-step past the original instruction first.
                        // The SINGLE_STEP handler will re-arm it via restore_bp.
                        self.breakpoints.insert(addr, bp);
                    } else {
                        // Last call consumed — track as consumed for ghost BP handling.
                        self.consumed_return_addrs.insert(addr, bp.original_byte);
                        flush_icache(self.process_handle, addr);
                    }
                    if let Some((_tid, call)) = dispatched_call {
                        self.dispatch_return_bp(pid, tid, &call);
                    }
                    // Rewind RIP but do NOT single-step (don't re-set 0xCC).
                    if let Some(&th) = self.thread_handles.get(&tid) {
                        set_rip(th, addr);
                        if has_remaining {
                            // Single-step past the restored byte, then re-set 0xCC.
                            enable_trap_flag(th);
                            if let Some(ts) = self.threads.get_mut(&tid) {
                                ts.restore_bp = Some(addr);
                            }
                        }
                    }
                }
                return DBG_CONTINUE;
            }

            // Ghost breakpoint: another thread hit an INT3 that was written
            // for a return breakpoint on a different thread. The byte was
            // already restored; we just need to rewind RIP.
            if let Some(&orig) = self.consumed_return_addrs.get(&addr) {
                dbg_log!(self, "[dbg]   ghost return BP at 0x{:X}, rewinding RIP", addr);
                // Ensure byte is still restored (belt-and-suspenders).
                write_mem(self.process_handle, addr, &[orig]);
                flush_icache(self.process_handle, addr);
                if let Some(&th) = self.thread_handles.get(&tid) {
                    set_rip(th, addr);
                }
                return DBG_CONTINUE;
            }

            // System/initial breakpoint — pass through.
            return if info.dwFirstChance != 0 {
                DBG_CONTINUE
            } else {
                DBG_EXCEPTION_NOT_HANDLED
            };
        }

        if code == EXCEPTION_SINGLE_STEP {
            dbg_log!(self, "[dbg] SINGLE_STEP tid={}", tid);
            // Re-set the function breakpoint after single-stepping past it.
            if let Some(ts) = self.threads.get_mut(&tid) {
                if let Some(bp_addr) = ts.restore_bp.take() {
                    write_mem(self.process_handle, bp_addr, &[0xCC]);
                    flush_icache(self.process_handle, bp_addr);
                }
            }
            return DBG_CONTINUE;
        }

        DBG_EXCEPTION_NOT_HANDLED
    }

    // ------------------------------------------------------------------
    // Function breakpoint dispatch
    // ------------------------------------------------------------------

    fn dispatch_function_bp(&mut self, pid: u32, tid: u32, addr: u64) {
        let addrs = match &self.hook_addrs {
            Some(a) => a,
            None => return,
        };
        let th = match self.thread_handles.get(&tid) {
            Some(&h) => h,
            None => return,
        };
        let ctx = match get_ctx(th) {
            Some(c) => c,
            None => return,
        };

        if addr == addrs.connect || addr == addrs.wsaconnect {
            dbg_log!(self, "[dbg] => connect/WSAConnect()");
            self.on_connect(pid, &ctx);
        } else if addr == addrs.send {
            dbg_log!(self, "[dbg] => send() socket=0x{:X} len={}", ctx.rcx, ctx.r8);
            self.on_send(pid, &ctx, Direction::Out);
        } else if addr == addrs.sendto {
            dbg_log!(self, "[dbg] => sendto() socket=0x{:X} len={}", ctx.rcx, ctx.r8);
            self.on_send(pid, &ctx, Direction::Out);
        } else if addr == addrs.recv {
            dbg_log!(self, "[dbg] => recv() socket=0x{:X} maxlen={}", ctx.rcx, ctx.r8);
            self.on_recv_entry(pid, tid, &ctx);
        } else if addr == addrs.recvfrom {
            dbg_log!(self, "[dbg] => recvfrom() socket=0x{:X} maxlen={}", ctx.rcx, ctx.r8);
            self.on_recvfrom_entry(pid, tid, &ctx);
        } else if addr == addrs.closesocket {
            dbg_log!(self, "[dbg] => closesocket() socket=0x{:X}", ctx.rcx);
            self.on_close(pid, &ctx);
        } else if addr == addrs.wsasend {
            dbg_log!(self, "[dbg] => WSASend() socket=0x{:X} bufcount={}", ctx.rcx, ctx.r8);
            self.on_wsasend(pid, &ctx);
        } else if addr == addrs.wsarecv {
            dbg_log!(self, "[dbg] => WSARecv() socket=0x{:X} bufcount={}", ctx.rcx, ctx.r8);
            self.on_wsarecv_entry(pid, tid, &ctx);
        } else if addr == addrs.wsarecvfrom {
            dbg_log!(self, "[dbg] => WSARecvFrom() socket=0x{:X} bufcount={}", ctx.rcx, ctx.r8);
            self.on_wsarecvfrom_entry(pid, tid, &ctx);
        } else if addr == addrs.wsasendto {
            dbg_log!(self, "[dbg] => WSASendTo() socket=0x{:X} bufcount={}", ctx.rcx, ctx.r8);
            self.on_wsasendto(pid, &ctx);
        } else if addr == addrs.gqcs {
            dbg_log!(self, "[dbg] => GetQueuedCompletionStatus()");
            self.on_gqcs_entry(tid, &ctx);
        } else if addr == addrs.gqcs_ex {
            dbg_log!(self, "[dbg] => GetQueuedCompletionStatusEx()");
            self.on_gqcs_ex_entry(tid, &ctx);
        } else if addr == addrs.wsa_get_overlapped_result {
            dbg_log!(self, "[dbg] => WSAGetOverlappedResult() socket=0x{:X}", ctx.rcx);
            self.on_wsa_get_overlapped_result_entry(tid, &ctx);
        } else if addrs.create_process_w != 0 && addr == addrs.create_process_w {
            dbg_log!(self, "[dbg] => CreateProcessW()");
            self.on_create_process_entry(tid, &ctx);
        } else if addrs.create_process_a != 0 && addr == addrs.create_process_a {
            dbg_log!(self, "[dbg] => CreateProcessA()");
            self.on_create_process_entry(tid, &ctx);
        } else if addrs.create_process_as_user_w != 0 && addr == addrs.create_process_as_user_w {
            dbg_log!(self, "[dbg] => CreateProcessAsUserW()");
            self.on_create_process_as_user_entry(tid, &ctx);
        } else if addrs.nt_create_user_process != 0 && addr == addrs.nt_create_user_process {
            dbg_log!(self, "[dbg] => NtCreateUserProcess()");
            self.on_nt_create_user_process_entry(tid, &ctx);
        } else if addrs.zw_create_user_process != 0 && addr == addrs.zw_create_user_process {
            dbg_log!(self, "[dbg] => ZwCreateUserProcess()");
            self.on_nt_create_user_process_entry(tid, &ctx);
        } else {
            dbg_log!(self, "[dbg] => unknown function BP at 0x{:X} (not matching any hook)", addr);
        }
    }

    // ------------------------------------------------------------------
    // Return breakpoint dispatch
    // ------------------------------------------------------------------

    fn dispatch_return_bp(&mut self, pid: u32, tid: u32, call: &PendingCall) {
        let th = match self.thread_handles.get(&tid) {
            Some(&h) => h,
            None => return,
        };
        let ctx = match get_ctx(th) {
            Some(c) => c,
            None => return,
        };

        match call {
            PendingCall::Recv {
                socket,
                buf_ptr,
                max_len,
            } | PendingCall::RecvFrom {
                socket,
                buf_ptr,
                max_len,
            } => {
                // recv/recvfrom returns int: >0 = bytes, 0 = closed, <0 = error
                let result = ctx.rax as i64;
                dbg_log!(self, "[dbg] recv/recvfrom returned {} for socket 0x{:X}", result, socket);
                if result <= 0 {
                    return;
                }
                let to_read = (result as usize).min(*max_len);
                let mut buf = vec![0u8; to_read];
                if read_mem(self.process_handle, *buf_ptr, &mut buf) {
                    self.process_data(pid, *socket, &buf, Direction::In);
                }
            }
            PendingCall::WsaRecv {
                socket,
                bufs,
                bytes_received_ptr,
                overlapped_ptr,
            } | PendingCall::WsaRecvFrom {
                socket,
                bufs,
                bytes_received_ptr,
                overlapped_ptr,
            } => {
                dbg_log!(self, "[dbg] WSARecv/WSARecvFrom returned 0x{:X} for socket 0x{:X}", ctx.rax, socket);
                if ctx.rax == 0 {
                    // Synchronous success — read the actual byte count from
                    // lpNumberOfBytesRecvd (arg5) which was saved at call time.
                    self.pending_overlapped.remove(overlapped_ptr);
                    let bytes_received = if *bytes_received_ptr != 0 {
                        let mut br = [0u8; 4];
                        if read_mem(self.process_handle, *bytes_received_ptr, &mut br) {
                            u32::from_le_bytes(br) as usize
                        } else {
                            0
                        }
                    } else {
                        0
                    };
                    dbg_log!(self, "[dbg]   sync completion, {} bytes received", bytes_received);
                    if bytes_received > 0 {
                        self.read_resolved_bufs_and_process(pid, *socket, bufs, bytes_received);
                    }
                } else {
                    // SOCKET_ERROR (-1) — likely WSA_IO_PENDING.
                    // Data will arrive via IOCP; pending_overlapped is already stored.
                    dbg_log!(self, "[dbg]   async pending, overlapped=0x{:X}", overlapped_ptr);
                }
            }
            PendingCall::Gqcs {
                bytes_transferred_ptr,
                completion_key_ptr,
                overlapped_ptr_ptr,
            } => {
                // GetQueuedCompletionStatus returns BOOL (non-zero = success)
                if ctx.rax == 0 {
                    dbg_log!(self, "[dbg] GQCS returned FALSE");
                    return;
                }
                let mut ov_bytes = [0u8; 8];
                if !read_mem(self.process_handle, *overlapped_ptr_ptr, &mut ov_bytes) {
                    return;
                }
                let overlapped_addr = u64::from_le_bytes(ov_bytes);
                let mut bt_bytes = [0u8; 4];
                if !read_mem(self.process_handle, *bytes_transferred_ptr, &mut bt_bytes) {
                    return;
                }
                let bytes_transferred = u32::from_le_bytes(bt_bytes) as usize;
                // Read completion key (often the socket handle).
                let completion_key = read_stack_u64(self.process_handle, *completion_key_ptr);
                dbg_log!(self, "[dbg] GQCS: overlapped=0x{:X} bytes={} key=0x{:X}",
                    overlapped_addr, bytes_transferred, completion_key);
                if let Some(pending) = self.pending_overlapped.remove(&overlapped_addr) {
                    if bytes_transferred > 0 {
                        self.read_resolved_bufs_and_process(
                            pid, pending.socket, &pending.bufs, bytes_transferred,
                        );
                    }
                } else if bytes_transferred > 0 {
                    // Overlapped not tracked — WSARecv likely happened before
                    // breakpoints were installed. Use the completion key as the
                    // socket handle and attempt to read from the OVERLAPPED's
                    // internal buffers.
                    dbg_log!(self, "[dbg] GQCS: untracked overlapped 0x{:X}, key(socket?)=0x{:X}, {} bytes lost",
                        overlapped_addr, completion_key, bytes_transferred);
                    dbg_log!(self, "[!] IOCP completion for untracked overlapped (socket?=0x{:X}, {} bytes) \
                        — WSARecv was likely issued before breakpoints were installed",
                        completion_key, bytes_transferred);
                    // Auto-track the socket for future operations.
                    self.ensure_tracked(pid, completion_key);
                }
            }
            PendingCall::GqcsEx {
                entries_ptr,
                num_removed_ptr,
            } => {
                if ctx.rax == 0 {
                    dbg_log!(self, "[dbg] GQCSEx returned FALSE");
                    return;
                }
                let mut nr_bytes = [0u8; 4];
                if !read_mem(self.process_handle, *num_removed_ptr, &mut nr_bytes) {
                    return;
                }
                let num_entries = u32::from_le_bytes(nr_bytes) as usize;
                dbg_log!(self, "[dbg] GQCSEx: {} entries completed", num_entries);
                // OVERLAPPED_ENTRY is 32 bytes on x64:
                //   { ULONG_PTR CompletionKey(8), LPOVERLAPPED(8),
                //     ULONG_PTR Internal(8), DWORD dwBytes(4)+pad(4) }
                for i in 0..num_entries {
                    let mut entry = [0u8; 32];
                    if !read_mem(self.process_handle, *entries_ptr + (i * 32) as u64, &mut entry) {
                        continue;
                    }
                    let completion_key = u64::from_le_bytes(entry[0..8].try_into().unwrap());
                    let overlapped_addr = u64::from_le_bytes(entry[8..16].try_into().unwrap());
                    let bytes_transferred = u32::from_le_bytes(
                        [entry[24], entry[25], entry[26], entry[27]],
                    ) as usize;
                    dbg_log!(self, "[dbg]   entry {}: overlapped=0x{:X} bytes={} key=0x{:X}",
                        i, overlapped_addr, bytes_transferred, completion_key);
                    if let Some(pending) = self.pending_overlapped.remove(&overlapped_addr) {
                        if bytes_transferred > 0 {
                            self.read_resolved_bufs_and_process(
                                pid, pending.socket, &pending.bufs, bytes_transferred,
                            );
                        }
                    } else if bytes_transferred > 0 {
                        dbg_log!(self, "[dbg]   untracked overlapped 0x{:X}, key(socket?)=0x{:X}, {} bytes lost",
                            overlapped_addr, completion_key, bytes_transferred);
                        eprintln!("[!] IOCP completion for untracked overlapped (socket?=0x{:X}, {} bytes) \
                            — WSARecv was likely issued before breakpoints were installed",
                            completion_key, bytes_transferred);
                        self.ensure_tracked(pid, completion_key);
                    }
                }
            }
            PendingCall::WsaGetOverlappedResult {
                socket,
                overlapped_ptr,
                transfer_ptr,
            } => {
                // WSAGetOverlappedResult returns BOOL (non-zero = success)
                if ctx.rax == 0 {
                    dbg_log!(self, "[dbg] WSAGetOverlappedResult returned FALSE for socket 0x{:X}", socket);
                    return;
                }
                let mut bt = [0u8; 4];
                if !read_mem(self.process_handle, *transfer_ptr, &mut bt) {
                    return;
                }
                let bytes_transferred = u32::from_le_bytes(bt) as usize;
                dbg_log!(self, "[dbg] WSAGetOverlappedResult: socket=0x{:X} overlapped=0x{:X} bytes={}",
                    socket, overlapped_ptr, bytes_transferred);
                if let Some(pending) = self.pending_overlapped.remove(overlapped_ptr) {
                    if bytes_transferred > 0 {
                        self.read_resolved_bufs_and_process(
                            pid, pending.socket, &pending.bufs, bytes_transferred,
                        );
                    }
                } else if bytes_transferred > 0 {
                    dbg_log!(self, "[dbg] WSAGetOverlappedResult: untracked overlapped 0x{:X}", overlapped_ptr);
                }
            }
            PendingCall::CreateProcess { process_info_ptr } => {
                // CreateProcess* returns BOOL: 0 = failure.
                if ctx.rax == 0 {
                    dbg_log!(self, "[dbg] CreateProcess returned FALSE");
                    return;
                }
                // PROCESS_INFORMATION { HANDLE hProcess(8), HANDLE hThread(8),
                //                       DWORD dwProcessId(4), DWORD dwThreadId(4) }
                let mut pi = [0u8; 24];
                if !read_mem(self.process_handle, *process_info_ptr, &mut pi) {
                    dbg_log!(self, "[dbg] CreateProcess: failed to read PROCESS_INFORMATION");
                    return;
                }
                let child_pid = u32::from_le_bytes([pi[16], pi[17], pi[18], pi[19]]);
                if child_pid == 0 {
                    return;
                }
                eprintln!("[+] Target spawned child process PID {}", child_pid);
                if !nudge_then_freeze_child(child_pid) {
                    eprintln!(
                        "[!] Could not dispatch+freeze child PID {} before attach — \
                        DebugActiveProcess may fail",
                        child_pid
                    );
                }
                self.spawn_child_tracker(child_pid);
            }
            PendingCall::NtCreateUserProcess { process_handle_ptr } => {
                // NtCreateUserProcess returns NTSTATUS — negative values are
                // failures, anything >= 0 is success.
                let status = ctx.rax as i32;
                if status < 0 {
                    dbg_log!(self, "[dbg] NtCreateUserProcess returned 0x{:08X}", status as u32);
                    return;
                }
                // Read the new HANDLE (8 bytes) from the out-pointer.
                let mut hbuf = [0u8; 8];
                if !read_mem(self.process_handle, *process_handle_ptr, &mut hbuf) {
                    dbg_log!(self, "[dbg] NtCreateUserProcess: failed to read out-handle");
                    return;
                }
                let target_handle = u64::from_le_bytes(hbuf);
                if target_handle == 0 {
                    return;
                }
                // The handle is valid in the target's handle table; duplicate
                // it into our own process so we can resolve it to a PID.
                let child_pid = duplicate_and_get_pid(self.process_handle, target_handle);
                match child_pid {
                    Some(pid) => {
                        eprintln!("[+] Target spawned child process PID {} (via NtCreateUserProcess)", pid);
                        if !nudge_then_freeze_child(pid) {
                            eprintln!(
                                "[!] Could not dispatch+freeze child PID {} before attach — \
                                DebugActiveProcess may fail",
                                pid
                            );
                        }
                        self.spawn_child_tracker(pid);
                    }
                    None => {
                        dbg_log!(self, "[dbg] NtCreateUserProcess: could not resolve target handle 0x{:X} to PID",
                            target_handle);
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Winsock handlers
    // ------------------------------------------------------------------

    fn on_connect(&mut self, pid: u32, ctx: &Amd64Context) {
        let socket = ctx.rcx;
        let sa_ptr = ctx.rdx;

        let mut fam = [0u8; 2];
        if !read_mem(self.process_handle, sa_ptr, &mut fam) {
            return;
        }
        let family = u16::from_ne_bytes(fam);
        if family != AF_INET.0 && family != AF_INET6.0 {
            return;
        }
        eprintln!("connect() socket=0x{:X} AF={}", socket, family);
        self.connections.insert(
            (pid, socket),
            ConnectionState {
                parser: TlsParser::new(),
                process_handle: self.process_handle,
            },
        );
    }

    /// Ensure a socket is tracked. Auto-creates a connection if needed.
    fn ensure_tracked(&mut self, pid: u32, socket: u64) {
        let key = (pid, socket);
        if !self.connections.contains_key(&key) {
            dbg_log!(self, "[dbg] auto-tracking socket 0x{:X} (no connect seen)", socket);
            self.connections.insert(
                key,
                ConnectionState {
                    parser: TlsParser::new(),
                    process_handle: self.process_handle,
                },
            );
        }
    }

    fn on_send(&mut self, pid: u32, ctx: &Amd64Context, dir: Direction) {
        let socket = ctx.rcx;
        let ptr = ctx.rdx;
        let len = ctx.r8 as usize;
        if len == 0 {
            return;
        }
        self.ensure_tracked(pid, socket);
        let mut buf = vec![0u8; len];
        if !read_mem(self.process_handle, ptr, &mut buf) {
            return;
        }
        self.process_data(pid, socket, &buf, dir);
    }

    fn on_recv_entry(&mut self, _pid: u32, tid: u32, ctx: &Amd64Context) {
        let socket = ctx.rcx;
        let buf_ptr = ctx.rdx;
        let max_len = ctx.r8 as usize;
        self.ensure_tracked(self.pid, socket);
        // Read return address from [rsp] (x64 calling convention).
        let mut ret_bytes = [0u8; 8];
        if !read_mem(self.process_handle, ctx.rsp, &mut ret_bytes) {
            dbg_log!(self, "[dbg] recv: failed to read return address from rsp=0x{:X}", ctx.rsp);
            return;
        }
        let ret_addr = u64::from_le_bytes(ret_bytes);
        dbg_log!(self, "[dbg] recv: setting return BP at 0x{:X}", ret_addr);
        self.set_return_breakpoint(
            ret_addr,
            tid,
            PendingCall::Recv {
                socket,
                buf_ptr,
                max_len,
            },
        );
    }

    fn on_recvfrom_entry(&mut self, _pid: u32, tid: u32, ctx: &Amd64Context) {
        // recvfrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)
        //   RCX=socket, RDX=buf, R8=len, R9=flags
        let socket = ctx.rcx;
        let buf_ptr = ctx.rdx;
        let max_len = ctx.r8 as usize;
        self.ensure_tracked(self.pid, socket);
        let mut ret_bytes = [0u8; 8];
        if !read_mem(self.process_handle, ctx.rsp, &mut ret_bytes) {
            dbg_log!(self, "[dbg] recvfrom: failed to read return address from rsp=0x{:X}", ctx.rsp);
            return;
        }
        let ret_addr = u64::from_le_bytes(ret_bytes);
        dbg_log!(self, "[dbg] recvfrom: setting return BP at 0x{:X}", ret_addr);
        self.set_return_breakpoint(
            ret_addr,
            tid,
            PendingCall::RecvFrom {
                socket,
                buf_ptr,
                max_len,
            },
        );
    }

    fn on_close(&mut self, pid: u32, ctx: &Amd64Context) {
        self.connections.remove(&(pid, ctx.rcx));
    }

    fn on_wsasend(&mut self, pid: u32, ctx: &Amd64Context) {
        let socket = ctx.rcx;
        let lp = ctx.rdx;
        let count = ctx.r8 as usize;
        self.ensure_tracked(pid, socket);
        // WSABUF on x64: { ULONG len(4), pad(4), CHAR* buf(8) } = 16 bytes
        for i in 0..count {
            let mut raw = [0u8; 16];
            if !read_mem(self.process_handle, lp + (i * 16) as u64, &mut raw) {
                continue;
            }
            let blen = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
            let bptr = u64::from_le_bytes(raw[8..16].try_into().unwrap());
            if blen == 0 {
                continue;
            }
            let mut buf = vec![0u8; blen];
            if read_mem(self.process_handle, bptr, &mut buf) {
                self.process_data(pid, socket, &buf, Direction::Out);
            }
        }
    }

    fn on_wsarecv_entry(&mut self, _pid: u32, tid: u32, ctx: &Amd64Context) {
        let socket = ctx.rcx;
        let bufs_ptr = ctx.rdx;
        let buf_count = ctx.r8 as u32;
        self.ensure_tracked(self.pid, socket);
        // Resolve WSABUF pointers eagerly so they remain valid after the
        // stack frame is gone (important for IOCP async completions).
        let bufs = self.resolve_wsabufs(bufs_ptr, buf_count);
        // WSARecv arg4 (lpNumberOfBytesRecvd) is in R9 (register, not stack).
        // [RSP+0x28] is arg5 (lpFlags) — reading that gave us a bogus byte
        // count on synchronous completion, causing us to miss data for any
        // recv that didn't go async (common for Go binaries, whose TLS
        // reader often hits kernel-buffered data after the first completion).
        let bytes_received_ptr = ctx.r9;
        // WSARecv arg6 (lpOverlapped) is at [RSP+0x30]
        let overlapped_ptr = read_stack_u64(self.process_handle, ctx.rsp + 0x30);
        dbg_log!(self, "[dbg] WSARecv: overlapped=0x{:X} bytesRecvdPtr=0x{:X}", overlapped_ptr, bytes_received_ptr);
        // Pre-register overlapped so IOCP can find it if the call is async.
        if overlapped_ptr != 0 {
            self.pending_overlapped.insert(overlapped_ptr, PendingOverlapped {
                socket, bufs: bufs.clone(),
            });
        }
        let mut ret_bytes = [0u8; 8];
        if !read_mem(self.process_handle, ctx.rsp, &mut ret_bytes) {
            dbg_log!(self, "[dbg] WSARecv: failed to read return address from rsp=0x{:X}", ctx.rsp);
            return;
        }
        let ret_addr = u64::from_le_bytes(ret_bytes);
        dbg_log!(self, "[dbg] WSARecv: setting return BP at 0x{:X}", ret_addr);
        self.set_return_breakpoint(
            ret_addr,
            tid,
            PendingCall::WsaRecv {
                socket,
                bufs,
                bytes_received_ptr,
                overlapped_ptr,
            },
        );
    }

    // ------------------------------------------------------------------
    // Additional Winsock / IOCP handlers
    // ------------------------------------------------------------------

    fn on_wsasendto(&mut self, pid: u32, ctx: &Amd64Context) {
        // WSASendTo args: RCX=socket, RDX=lpBuffers, R8=dwBufferCount
        let socket = ctx.rcx;
        let lp = ctx.rdx;
        let count = ctx.r8 as usize;
        self.ensure_tracked(pid, socket);
        for i in 0..count {
            let mut raw = [0u8; 16];
            if !read_mem(self.process_handle, lp + (i * 16) as u64, &mut raw) {
                continue;
            }
            let blen = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
            let bptr = u64::from_le_bytes(raw[8..16].try_into().unwrap());
            if blen == 0 {
                continue;
            }
            let mut buf = vec![0u8; blen];
            if read_mem(self.process_handle, bptr, &mut buf) {
                self.process_data(pid, socket, &buf, Direction::Out);
            }
        }
    }

    fn on_wsarecvfrom_entry(&mut self, _pid: u32, tid: u32, ctx: &Amd64Context) {
        let socket = ctx.rcx;
        let bufs_ptr = ctx.rdx;
        let buf_count = ctx.r8 as u32;
        self.ensure_tracked(self.pid, socket);
        let bufs = self.resolve_wsabufs(bufs_ptr, buf_count);
        // WSARecvFrom arg4 (lpNumberOfBytesRecvd) is in R9 (register, not stack).
        let bytes_received_ptr = ctx.r9;
        // WSARecvFrom arg8 (lpOverlapped) is at [RSP+0x40]
        let overlapped_ptr = read_stack_u64(self.process_handle, ctx.rsp + 0x40);
        dbg_log!(self, "[dbg] WSARecvFrom: overlapped=0x{:X} bytesRecvdPtr=0x{:X}", overlapped_ptr, bytes_received_ptr);
        if overlapped_ptr != 0 {
            self.pending_overlapped.insert(overlapped_ptr, PendingOverlapped {
                socket, bufs: bufs.clone(),
            });
        }
        let mut ret_bytes = [0u8; 8];
        if !read_mem(self.process_handle, ctx.rsp, &mut ret_bytes) {
            dbg_log!(self, "[dbg] WSARecvFrom: failed to read return address from rsp=0x{:X}", ctx.rsp);
            return;
        }
        let ret_addr = u64::from_le_bytes(ret_bytes);
        dbg_log!(self, "[dbg] WSARecvFrom: setting return BP at 0x{:X}", ret_addr);
        self.set_return_breakpoint(
            ret_addr,
            tid,
            PendingCall::WsaRecvFrom {
                socket,
                bufs,
                bytes_received_ptr,
                overlapped_ptr,
            },
        );
    }

    fn on_gqcs_entry(&mut self, tid: u32, ctx: &Amd64Context) {
        // GetQueuedCompletionStatus(hPort, lpBytesTransferred, lpKey, lpOverlapped, ms)
        //   RCX = hCompletionPort
        //   RDX = lpNumberOfBytesTransferred (LPDWORD, output)
        //   R8  = lpCompletionKey (PULONG_PTR, output)
        //   R9  = lpOverlapped (LPOVERLAPPED*, output ptr-to-ptr)
        let bytes_transferred_ptr = ctx.rdx;
        let completion_key_ptr = ctx.r8;
        let overlapped_ptr_ptr = ctx.r9;
        let mut ret_bytes = [0u8; 8];
        if !read_mem(self.process_handle, ctx.rsp, &mut ret_bytes) {
            return;
        }
        let ret_addr = u64::from_le_bytes(ret_bytes);
        dbg_log!(self, "[dbg] GQCS: setting return BP at 0x{:X}", ret_addr);
        self.set_return_breakpoint(
            ret_addr,
            tid,
            PendingCall::Gqcs {
                bytes_transferred_ptr,
                completion_key_ptr,
                overlapped_ptr_ptr,
            },
        );
    }

    fn on_gqcs_ex_entry(&mut self, tid: u32, ctx: &Amd64Context) {
        // GetQueuedCompletionStatusEx(hPort, lpEntries, ulCount, ulNumRemoved, ms, fAlertable)
        //   RCX = hCompletionPort
        //   RDX = lpCompletionPortEntries (OVERLAPPED_ENTRY array, output)
        //   R8  = ulCount (max entries)
        //   R9  = ulNumEntriesRemoved (PULONG, output)
        let entries_ptr = ctx.rdx;
        let num_removed_ptr = ctx.r9;
        let mut ret_bytes = [0u8; 8];
        if !read_mem(self.process_handle, ctx.rsp, &mut ret_bytes) {
            return;
        }
        let ret_addr = u64::from_le_bytes(ret_bytes);
        dbg_log!(self, "[dbg] GQCSEx: setting return BP at 0x{:X}", ret_addr);
        self.set_return_breakpoint(
            ret_addr,
            tid,
            PendingCall::GqcsEx {
                entries_ptr,
                num_removed_ptr,
            },
        );
    }

    fn on_wsa_get_overlapped_result_entry(&mut self, tid: u32, ctx: &Amd64Context) {
        // WSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED lpOverlapped,
        //   LPDWORD lpcbTransfer, BOOL fWait, LPDWORD lpdwFlags)
        //   RCX = socket, RDX = lpOverlapped, R8 = lpcbTransfer, R9 = fWait
        let socket = ctx.rcx;
        let overlapped_ptr = ctx.rdx;
        let transfer_ptr = ctx.r8;
        self.ensure_tracked(self.pid, socket);
        let mut ret_bytes = [0u8; 8];
        if !read_mem(self.process_handle, ctx.rsp, &mut ret_bytes) {
            return;
        }
        let ret_addr = u64::from_le_bytes(ret_bytes);
        dbg_log!(self, "[dbg] WSAGetOverlappedResult: setting return BP at 0x{:X}", ret_addr);
        self.set_return_breakpoint(
            ret_addr,
            tid,
            PendingCall::WsaGetOverlappedResult {
                socket,
                overlapped_ptr,
                transfer_ptr,
            },
        );
    }

    /// CreateProcess{A,W} entry. 10 arguments on x64 — the first 4 go in
    /// RCX/RDX/R8/R9 and the rest are on the stack starting at [RSP+0x28]:
    ///   arg5 (bInheritHandles)      → [RSP+0x28]
    ///   arg6 (dwCreationFlags)      → [RSP+0x30]
    ///   arg7 (lpEnvironment)        → [RSP+0x38]
    ///   arg8 (lpCurrentDirectory)   → [RSP+0x40]
    ///   arg9 (lpStartupInfo)        → [RSP+0x48]
    ///   arg10 (lpProcessInformation)→ [RSP+0x50]
    /// We force `CREATE_SUSPENDED` (0x4) into `dwCreationFlags` so the new
    /// process's main thread starts frozen — the freshly-spawned child
    /// Tihulu instance is responsible for resuming it once its breakpoints
    /// are armed (see `--resume-on-attach`).
    fn on_create_process_entry(&mut self, tid: u32, ctx: &Amd64Context) {
        force_suspended_creation_flag(self.process_handle, ctx.rsp + 0x30, CREATE_SUSPENDED_FLAG);
        let process_info_ptr = read_stack_u64(self.process_handle, ctx.rsp + 0x50);
        let mut ret_bytes = [0u8; 8];
        if !read_mem(self.process_handle, ctx.rsp, &mut ret_bytes) {
            return;
        }
        let ret_addr = u64::from_le_bytes(ret_bytes);
        dbg_log!(self, "[dbg] CreateProcess: lpProcessInformation=0x{:X}, return BP at 0x{:X}",
            process_info_ptr, ret_addr);
        if process_info_ptr == 0 {
            return;
        }
        self.set_return_breakpoint(
            ret_addr,
            tid,
            PendingCall::CreateProcess { process_info_ptr },
        );
    }

    /// CreateProcessAsUserW takes one extra leading argument (hToken) so
    /// every argument is shifted by one slot:
    ///   arg7 (dwCreationFlags)      → [RSP+0x38]
    ///   arg11 (lpProcessInformation)→ [RSP+0x58]
    fn on_create_process_as_user_entry(&mut self, tid: u32, ctx: &Amd64Context) {
        force_suspended_creation_flag(self.process_handle, ctx.rsp + 0x38, CREATE_SUSPENDED_FLAG);
        let process_info_ptr = read_stack_u64(self.process_handle, ctx.rsp + 0x58);
        let mut ret_bytes = [0u8; 8];
        if !read_mem(self.process_handle, ctx.rsp, &mut ret_bytes) {
            return;
        }
        let ret_addr = u64::from_le_bytes(ret_bytes);
        dbg_log!(self, "[dbg] CreateProcessAsUserW: lpProcessInformation=0x{:X}, return BP at 0x{:X}",
            process_info_ptr, ret_addr);
        if process_info_ptr == 0 {
            return;
        }
        self.set_return_breakpoint(
            ret_addr,
            tid,
            PendingCall::CreateProcess { process_info_ptr },
        );
    }

    /// NtCreateUserProcess / ZwCreateUserProcess entry. Signature (11 args):
    ///   NTSTATUS NtCreateUserProcess(
    ///     PHANDLE ProcessHandle,            // [out] arg 1 (RCX)
    ///     PHANDLE ThreadHandle,             //       arg 2 (RDX)
    ///     ACCESS_MASK ProcessDesiredAccess, //       arg 3 (R8)
    ///     ACCESS_MASK ThreadDesiredAccess,  //       arg 4 (R9)
    ///     ...
    ///     ULONG ThreadFlags,                //       arg 8 ([RSP+0x40])
    ///     ...
    ///   );
    /// We OR `THREAD_CREATE_FLAGS_CREATE_SUSPENDED` (0x1) into ThreadFlags so
    /// the new process's initial thread is created suspended; the spawned
    /// child Tihulu will resume it once its breakpoints are installed.
    /// We capture the ProcessHandle out-pointer here; the handle value it
    /// receives is meaningful in the *target's* handle table, so we resolve
    /// it to a PID at return time via DuplicateHandle into our process.
    fn on_nt_create_user_process_entry(&mut self, tid: u32, ctx: &Amd64Context) {
        force_suspended_creation_flag(
            self.process_handle,
            ctx.rsp + 0x40,
            NT_THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        );
        let process_handle_ptr = ctx.rcx;
        let mut ret_bytes = [0u8; 8];
        if !read_mem(self.process_handle, ctx.rsp, &mut ret_bytes) {
            return;
        }
        let ret_addr = u64::from_le_bytes(ret_bytes);
        dbg_log!(self, "[dbg] NtCreateUserProcess: PHANDLE=0x{:X}, return BP at 0x{:X}",
            process_handle_ptr, ret_addr);
        if process_handle_ptr == 0 {
            return;
        }
        self.set_return_breakpoint(
            ret_addr,
            tid,
            PendingCall::NtCreateUserProcess { process_handle_ptr },
        );
    }

    /// Launch a fresh Tihulu instance to monitor a freshly created child.
    /// All of the user's CLI options (output directory, verbose, threads, ...)
    /// are propagated; only `--pid` and the trailing command are replaced.
    /// The child is told via `--resume-on-attach` that it must resume the
    /// target's main thread once its breakpoints are installed (we force
    /// `CREATE_SUSPENDED` in every process-creation hook so the new process
    /// is frozen until the child Tihulu is ready).
    /// Queue a child PID for the multi-tracker orchestrator to attach to.
    /// The actual `DebugActiveProcess` call happens on the orchestrator's
    /// event loop thread right after this debug event is acknowledged via
    /// `ContinueDebugEvent`. That ordering matters: the child is still
    /// suspended, so we can attach without racing user-mode init.
    fn spawn_child_tracker(&mut self, child_pid: u32) {
        self.pending_child_attaches.push(child_pid);
    }

    /// Drain queued child PIDs for the orchestrator.
    pub(crate) fn take_pending_child_attaches(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.pending_child_attaches)
    }

    pub(crate) fn pid(&self) -> u32 { self.pid }
    pub(crate) fn is_done(&self) -> bool { self.should_detach && !self.detached }

    /// If the target process was process-suspended by the parent's child-
    /// creation hook (and we attached after-the-fact), release the whole
    /// process now via `NtResumeProcess`. This unwinds the process-wide
    /// suspend count applied by `nudge_then_freeze_child`, allowing every
    /// thread the loader created during its brief dispatch window to run
    /// once our breakpoints are in place. Idempotent.
    fn maybe_resume_on_attach(&mut self) {
        if !self.resume_on_attach || self.resumed_on_attach {
            return;
        }
        if self.process_handle.is_invalid() {
            return;
        }
        let st = unsafe { NtResumeProcess(self.process_handle) };
        if st < 0 {
            eprintln!(
                "[!] NtResumeProcess(PID {}) failed: 0x{:08X}",
                self.pid, st as u32
            );
        } else {
            eprintln!("[+] Released suspended child process (PID {})", self.pid);
        }
        self.resumed_on_attach = true;
    }

    /// Resolve WSABUF structs from the target process into local ResolvedBuf entries.
    /// Called eagerly at WSARecv/WSARecvFrom entry so the pointers are captured
    /// before the stack frame is freed.
    fn resolve_wsabufs(&self, bufs_ptr: u64, buf_count: u32) -> Vec<ResolvedBuf> {
        let mut result = Vec::with_capacity(buf_count as usize);
        // WSABUF on x64: { ULONG len(4), pad(4), CHAR* buf(8) } = 16 bytes
        for i in 0..buf_count as usize {
            let mut raw = [0u8; 16];
            if !read_mem(self.process_handle, bufs_ptr + (i * 16) as u64, &mut raw) {
                continue;
            }
            let blen = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
            let bptr = u64::from_le_bytes(raw[8..16].try_into().unwrap());
            result.push(ResolvedBuf { ptr: bptr, len: blen });
        }
        result
    }

    /// Read data from previously-resolved buffer pointers and feed it to the TLS parser.
    /// `max_bytes` limits total bytes read (from IOCP/sync byte count).
    fn read_resolved_bufs_and_process(
        &mut self,
        pid: u32,
        socket: u64,
        bufs: &[ResolvedBuf],
        max_bytes: usize,
    ) {
        let mut remaining = max_bytes;
        for rb in bufs {
            if remaining == 0 {
                break;
            }
            let to_read = rb.len.min(remaining);
            if to_read == 0 {
                continue;
            }
            let mut buf = vec![0u8; to_read];
            if read_mem(self.process_handle, rb.ptr, &mut buf) {
                self.process_data(pid, socket, &buf, Direction::In);
                remaining = remaining.saturating_sub(to_read);
            }
        }
    }

    // ------------------------------------------------------------------
    // TLS processing & key search
    // ------------------------------------------------------------------

    fn process_data(&mut self, pid: u32, socket: u64, data: &[u8], dir: Direction) {
        let key = (pid, socket);
        let conn = match self.connections.get_mut(&key) {
            Some(c) => c,
            None => return,
        };
        if conn.parser.finished {
            return;
        }

        let records = conn.parser.handle_data(data, dir);
        dbg_log!(self, "[dbg] process_data: {} bytes {:?}, got {} records", data.len(), dir, records.len());
        for (r, d) in &records {
            dbg_log!(self, "[dbg]   record type=0x{:02X} ver=0x{:04X} len={}", r.content_type, r.version, r.data.len());
            conn.parser.process_record(r, *d);
        }

        // Track at the DebugTracker level so it persists past closesocket.
        if conn.parser.client_hello_seen {
            self.any_tls_seen = true;
        }

        // Arm the CALL-probe scanner as soon as the ServerHello has been
        // parsed and a cipher suite is known. For TLS 1.3 the traffic-secret
        // length is slen(32|48); for TLS 1.2 we use the master-secret length.
        let arm_slen = if conn.parser.cipher_suite_set && !self.scanner.is_armed() {
            conn.parser.cipher_suite.map(|cs| {
                if cs.is_tls13() {
                    cs.secret_len()
                } else {
                    SSL_MASTER_SECRET_LENGTH
                }
            })
        } else {
            None
        };

        dbg_log!(self, "[dbg]   parser state: finished={} is_tls13={} has_cr={} has_sr={} cipher={:?}",
            conn.parser.finished,
            conn.parser.is_tls13,
            conn.parser.client_random != [0u8; 32],
            conn.parser.server_random != [0u8; 32],
            conn.parser.cipher_suite.map(|cs| cs.number),
        );
        dbg_log!(self, "[dbg]   may_decrypt_tls12={} may_decrypt_tls13={}",
            conn.parser.may_decrypt_tls12(),
            conn.parser.may_decrypt_tls13(),
        );

        if let Some(slen) = arm_slen {
            self.arm_call_scanner(slen);
        }

        if !self.connections.get(&key).map(|c| c.parser.finished).unwrap_or(true) {
            let is_tls13 = self.connections.get(&key).map(|c| c.parser.is_tls13).unwrap_or(false);
            let may13 = self.connections.get(&key).map(|c| c.parser.may_decrypt_tls13()).unwrap_or(false);
            let found13 = self.connections.get(&key).map(|c| c.parser.tls13_found_secrets).unwrap_or(0);
            let may12 = self.connections.get(&key).map(|c| c.parser.may_decrypt_tls12()).unwrap_or(false);
            if is_tls13 {
                if may13 && found13 != TLS13_ALL {
                    eprintln!("[*] All TLS 1.3 records captured — triggering secret search");
                    self.find_tls13_secrets(pid, socket);
                }
            } else if may12 {
                eprintln!("[*] triggering TLS 1.2 master secret search");
                self.find_master_secret(pid, socket);
            }
        }
    }

    fn find_master_secret(&mut self, pid: u32, socket: u64) {
        let key = (pid, socket);
        let conn = match self.connections.get(&key) {
            Some(c) => c,
            None => return,
        };
        let cs = match conn.parser.cipher_suite {
            Some(c) => c,
            None => return,
        };
        let record = match &conn.parser.data_record {
            Some(r) => r.clone(),
            None => return,
        };
        let cr = conn.parser.client_random;
        let sr = conn.parser.server_random;
        let handle = conn.process_handle;

        // ---- Phase 1: try CALL-probe candidates first ----
        if self.call_probe_enabled && !self.scanner.candidates.is_empty() {
            eprintln!(
                "[*] TLS 1.2: trying {} CALL-probe candidate secret(s) ...",
                self.scanner.candidates.len()
            );
            self.suspend_target();
            self.disarm_call_scanner_inner_no_suspend();
            let hit = self.trial_tls12_candidates(cs, &cr, &sr, &record);
            self.resume_target();
            if let Some(secret) = hit {
                self.output_keylog(&format!(
                    "CLIENT_RANDOM {} {}\n",
                    hex_string(&cr),
                    hex_string(&secret),
                ));
                if let Some(c) = self.connections.get_mut(&key) {
                    c.parser.finished = true;
                }
                eprintln!("[+] Master secret found via CALL-probe!");
                return;
            }
            eprintln!("[-] No CALL-probe candidate decrypted TLS 1.2 record");
        }

        if !self.fallback_scan {
            eprintln!(
                "[-] Master secret not recovered; brute-force fallback disabled \
                 (pass --fallback-scan to enable)"
            );
            if let Some(c) = self.connections.get_mut(&key) {
                c.parser.finished = true;
            }
            return;
        }

        eprintln!("[*] Falling back to brute-force memory scan for master secret ...");
        self.suspend_target();
        let reader = MemoryReader::new(handle, pid);
        let regions = reader.get_memory_regions();
        dbg_log!(self, "[dbg] scanning {} memory regions across {} threads", regions.len(), self.search_threads);

        // Parallelize across regions: each worker thread claims a region,
        // reads it, and scans it for a candidate master secret. `find_map_any`
        // stops as soon as one worker finds a match.
        use rayon::prelude::*;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.search_threads)
            .build()
            .expect("failed to build search thread pool");
        let reader_ref = &reader;
        let cr_ref = &cr;
        let sr_ref = &sr;
        let record_ref = &record;
        let hit: Option<Vec<u8>> = pool.install(|| {
            regions.par_iter().find_map_any(|region| {
                if region.size < SSL_MASTER_SECRET_LENGTH {
                    return None;
                }
                let mem = reader_ref.read_region(region)?;
                if mem.len() < SSL_MASTER_SECRET_LENGTH {
                    return None;
                }
                dbg_log!(self, "[dbg] searching region 0x{:X}-0x{:X} (size={}) for master secret",
                    region.base, region.base + region.size as u64, mem.len());
                let range = mem.len() + 1 - SSL_MASTER_SECRET_LENGTH;
                for i in 0..range {
                    if tls_decrypt::try_decrypt_tls12(
                        cs,
                        &mem[i..i + SSL_MASTER_SECRET_LENGTH],
                        cr_ref,
                        sr_ref,
                        record_ref,
                    ) {
                        return Some(mem[i..i + SSL_MASTER_SECRET_LENGTH].to_vec());
                    }
                }
                None
            })
        });

        let found = if let Some(secret) = hit {
            self.output_keylog(&format!(
                "CLIENT_RANDOM {} {}\n",
                hex_string(&cr),
                hex_string(&secret),
            ));
            true
        } else {
            false
        };

        if let Some(c) = self.connections.get_mut(&key) {
            c.parser.finished = true;
        }
        self.resume_target();
        if found {
            eprintln!("[+] Master secret found!");
        } else { 
            eprintln!("[-] Warning: master secret not found");
        }
    }

    fn find_tls13_secrets(&mut self, pid: u32, socket: u64) {
        let key = (pid, socket);
        let conn = match self.connections.get(&key) {
            Some(c) => c,
            None => return,
        };
        let cs = match conn.parser.cipher_suite {
            Some(c) => c,
            None => return,
        };
        let cr = conn.parser.client_random;
        let handle = conn.process_handle;
        let slen = cs.secret_len();
        let already_found = conn.parser.tls13_found_secrets;

        // Build targets list dynamically — only include records that exist
        // and whose corresponding secret hasn't been found yet.
        let mut targets: Vec<(&'static str, TlsRecord, u64, u8)> = Vec::new();
        if already_found & TLS13_CHTS == 0 {
            if let Some(ref rec) = conn.parser.tls13_client_finished {
                targets.push(("CLIENT_HANDSHAKE_TRAFFIC_SECRET", rec.clone(), 0, TLS13_CHTS));
            }
        }
        if already_found & TLS13_CTS0 == 0 {
            if let Some(ref rec) = conn.parser.tls13_client_app_data {
                targets.push(("CLIENT_TRAFFIC_SECRET_0", rec.clone(), 0, TLS13_CTS0));
            }
        }
        if already_found & TLS13_SHTS == 0 {
            if let Some(ref rec) = conn.parser.tls13_server_encrypted {
                targets.push(("SERVER_HANDSHAKE_TRAFFIC_SECRET", rec.clone(), 0, TLS13_SHTS));
            }
        }
        if already_found & TLS13_STS0 == 0 {
            if let Some(ref rec) = conn.parser.tls13_server_app_data {
                targets.push(("SERVER_TRAFFIC_SECRET_0", rec.clone(), 0, TLS13_STS0));
            }
        }
        if targets.is_empty() {
            return;
        }

        // ---- Phase 1: try CALL-probe candidates first ----
        if self.call_probe_enabled && !self.scanner.candidates.is_empty() {
            eprintln!(
                "[*] TLS 1.3: trying {} CALL-probe candidate secret(s) across {} target record(s) ...",
                self.scanner.candidates.len(),
                targets.len(),
            );
            self.suspend_target();
            self.disarm_call_scanner_inner_no_suspend();

            let mut newly_found: u8 = 0;
            let mut findings: Vec<(&'static str, Vec<u8>)> = Vec::new();
            let mut remaining: Vec<(&'static str, TlsRecord, u64, u8)> = Vec::new();
            for (label, record, seq, mask) in targets {
                match self.trial_tls13_candidates(cs, &record, seq) {
                    Some(secret) => {
                        eprintln!("[+] [{}] found via CALL-probe", label);
                        newly_found |= mask;
                        findings.push((label, secret));
                    }
                    None => {
                        eprintln!("[-] [{}] no CALL-probe candidate decrypted", label);
                        remaining.push((label, record, seq, mask));
                    }
                }
            }

            for (label, secret) in &findings {
                self.output_keylog(&format!(
                    "{} {} {}\n",
                    label,
                    hex_string(&cr),
                    hex_string(secret),
                ));
            }
            if let Some(c) = self.connections.get_mut(&key) {
                c.parser.tls13_found_secrets |= newly_found;
                if c.parser.tls13_found_secrets == TLS13_ALL {
                    c.parser.finished = true;
                    eprintln!("[+] All TLS 1.3 secrets found via CALL-probe!");
                }
            }
            self.resume_target();

            if remaining.is_empty() {
                return;
            }
            if !self.fallback_scan {
                eprintln!(
                    "[-] {} TLS 1.3 secret(s) not recovered via CALL-probe; brute-force \
                     fallback disabled (pass --fallback-scan to enable)",
                    remaining.len()
                );
                if let Some(c) = self.connections.get_mut(&key) {
                    // Mark finished to avoid retrying on every subsequent record.
                    c.parser.finished = true;
                }
                return;
            }
            eprintln!(
                "[*] Falling back to brute-force scan for {} remaining target(s) ...",
                remaining.len()
            );
            // Fall through into brute-force path with only the unresolved targets.
            let targets = remaining;
            self.find_tls13_secrets_bruteforce(pid, socket, cs, cr, handle, slen, targets);
            return;
        }

        if !self.fallback_scan {
            eprintln!(
                "[-] No CALL-probe candidates collected; brute-force fallback disabled \
                 (pass --fallback-scan to enable)"
            );
            if let Some(c) = self.connections.get_mut(&key) {
                c.parser.finished = true;
            }
            return;
        }

        self.find_tls13_secrets_bruteforce(pid, socket, cs, cr, handle, slen, targets);
    }

    fn find_tls13_secrets_bruteforce(
        &mut self,
        pid: u32,
        socket: u64,
        cs: &'static CipherSuite,
        cr: [u8; 32],
        handle: HANDLE,
        slen: usize,
        targets: Vec<(&'static str, TlsRecord, u64, u8)>,
    ) {
        let key = (pid, socket);
        let already_found = self
            .connections
            .get(&key)
            .map(|c| c.parser.tls13_found_secrets)
            .unwrap_or(0);

        eprintln!(
            "[*] Brute-force TLS 1.3 scan: {} targets, {}/4 found so far, {} worker threads ...",
            targets.len(),
            already_found.count_ones(),
            self.search_threads,
        );
        self.suspend_target();
        let reader = MemoryReader::new(handle, pid);
        let all_regions = reader.get_memory_regions();
        // Read all candidate sections once while the target is suspended.
        let sections: Vec<Vec<u8>> = all_regions
            .iter()
            .filter(|r| r.size >= slen)
            .filter_map(|r| reader.read_region(r))
            .collect();
        dbg_log!(
            self,
            "[dbg] {} memory sections (size >= {}), using {} worker threads",
            sections.len(), slen, self.search_threads
        );

        // --- Shared state between the 4 main scan threads ---
        //
        // Each target gets its own control block. When any thread finds its
        // secret in section `si`, it broadcasts `si` to the other targets by
        // pushing it into their hint queues and setting their cancel flags.
        // The other targets, on noticing the cancel flag, abandon whatever
        // section they are currently scanning and pick up the hint first.
        //
        // A single shared rayon::ThreadPool (sized by the user's --threads
        // argument) is used for the per-section offset scanning. The 4 main
        // threads submit `par_iter` work to it concurrently; rayon's work
        // stealing interleaves them across the pool's workers.
        struct TargetCtrl {
            hints: std::sync::Mutex<std::collections::VecDeque<usize>>,
            cancel: std::sync::atomic::AtomicBool,
        }
        let sections = Arc::new(sections);
        let pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(self.search_threads)
                .build()
                .expect("failed to build search thread pool"),
        );
        let ctrls: Vec<Arc<TargetCtrl>> = (0..targets.len())
            .map(|_| {
                Arc::new(TargetCtrl {
                    hints: std::sync::Mutex::new(std::collections::VecDeque::new()),
                    cancel: std::sync::atomic::AtomicBool::new(false),
                })
            })
            .collect();

        let verbose = self.verbose;
        let mut handles: Vec<
            std::thread::JoinHandle<Option<(u8, &'static str, Vec<u8>, usize, usize)>>,
        > = Vec::new();

        for (idx, (label, record, seq, mask)) in targets.into_iter().enumerate() {
            let sections = Arc::clone(&sections);
            let pool = Arc::clone(&pool);
            let my_ctrl = Arc::clone(&ctrls[idx]);
            let other_ctrls: Vec<Arc<TargetCtrl>> = ctrls
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != idx)
                .map(|(_, c)| Arc::clone(c))
                .collect();

            handles.push(std::thread::spawn(move || {
                use rayon::prelude::*;
                use std::sync::atomic::Ordering;

                enum ScanOut {
                    Found(usize),
                    Cancelled,
                }

                let n = sections.len();
                let mut scanned = vec![false; n];
                let mut cursor: usize = 0;

                eprintln!("[*] [{}] search started", label);

                loop {
                    // Pick the next section to scan. Hinted sections (from
                    // other targets that have already found their secret)
                    // take priority over the sequential scan order.
                    let pick_hint = || -> Option<usize> {
                        let mut h = my_ctrl.hints.lock().unwrap();
                        while let Some(r) = h.pop_front() {
                            if r < n && !scanned[r] {
                                return Some(r);
                            }
                        }
                        None
                    };
                    let si = match pick_hint().or_else(|| {
                        while cursor < n {
                            let i = cursor;
                            cursor += 1;
                            if !scanned[i] {
                                return Some(i);
                            }
                        }
                        None
                    }) {
                        Some(s) => s,
                        None => break,
                    };
                    scanned[si] = true;

                    let sec: &Vec<u8> = &sections[si];
                    if sec.len() < slen {
                        continue;
                    }
                    let range = sec.len() + 1 - slen;

                    // Clear any stale cancel signal before starting this section.
                    my_ctrl.cancel.store(false, Ordering::Relaxed);
                    if verbose {
                        eprintln!(
                            "[dbg] [{}] scanning section {} (size=0x{:X})",
                            label, si, sec.len()
                        );
                    }

                    let ctrl_ref = &my_ctrl;
                    let record_ref = &record;
                    let out: Option<ScanOut> = pool.install(|| {
                        (0..range).into_par_iter().find_map_any(|k| {
                            // Check for cancellation every 16384 iterations to
                            // amortize the atomic load. On cancel, bail out of
                            // the whole par_iter by returning Some(Cancelled).
                            if (k & 0x3FFF) == 0
                                && ctrl_ref.cancel.load(Ordering::Relaxed)
                            {
                                return Some(ScanOut::Cancelled);
                            }
                            if tls_decrypt::try_decrypt_tls13(
                                cs,
                                &sec[k..k + slen],
                                record_ref,
                                seq,
                            ) {
                                Some(ScanOut::Found(k))
                            } else {
                                None
                            }
                        })
                    });

                    match out {
                        Some(ScanOut::Found(off)) => {
                            eprintln!(
                                "[+] [{}] found at section {} offset 0x{:X}",
                                label, si, off
                            );
                            // Broadcast the winning section index to every
                            // other target so they try this section next.
                            for other in &other_ctrls {
                                other.hints.lock().unwrap().push_front(si);
                                other.cancel.store(true, Ordering::Relaxed);
                            }
                            let secret = sec[off..off + slen].to_vec();
                            return Some((mask, label, secret, si, off));
                        }
                        Some(ScanOut::Cancelled) => {
                            // Another target found a secret in some section
                            // and broadcast a hint. Abandon this section for
                            // now, re-queue it at the back of our own hint
                            // queue so we return to it after consuming any
                            // pending hints, and loop.
                            if verbose {
                                eprintln!(
                                    "[dbg] [{}] scan of section {} cancelled by hint, \
                                     will retry later",
                                    label, si
                                );
                            }
                            scanned[si] = false;
                            my_ctrl.hints.lock().unwrap().push_back(si);
                        }
                        None => {
                            // Section exhausted, secret not in this one.
                        }
                    }
                }

                eprintln!("[-] [{}] not found", label);
                None
            }));
        }

        let mut newly_found: u8 = 0;
        let mut findings: Vec<(&'static str, Vec<u8>)> = Vec::new();
        for h in handles {
            if let Ok(Some((mask, label, secret, _si, _off))) = h.join() {
                newly_found |= mask;
                findings.push((label, secret));
            }
        }

        for (label, secret) in &findings {
            self.output_keylog(&format!(
                "{} {} {}\n",
                label,
                hex_string(&cr),
                hex_string(secret),
            ));
        }

        // Update found bitmask.
        if let Some(c) = self.connections.get_mut(&key) {
            c.parser.tls13_found_secrets |= newly_found;
            // Mark finished only when all 4 secrets have been found.
            if c.parser.tls13_found_secrets == TLS13_ALL {
                c.parser.finished = true;
                eprintln!("[+] All TLS 1.3 secrets found!");
            }
        }
        dbg_log!(
            self,
            "[dbg] TLS 1.3 secret search complete: {}/4 secrets found",
            (already_found | newly_found).count_ones()
        );
        eprintln!("[*] Resuming target process");
        self.resume_target();
    }

    fn output_keylog(&mut self, line: &str) {
        let mut wrote_to_file = false;
        if let Some(ref dir) = self.output_dir.clone() {
            if self.output_path.is_none() {
                let name = if self.process_name.is_empty() {
                    "process".to_string()
                } else {
                    sanitize_filename(&self.process_name)
                };
                let filename = format!("{}_{}_tls.key", self.pid, name);
                let path = std::path::Path::new(dir).join(filename);
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                eprintln!("[*] Writing keys to {}", path.display());
                self.output_path = Some(path);
            }
            if let Some(ref path) = self.output_path {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    let _ = f.write_all(line.as_bytes());
                    wrote_to_file = true;
                }
            }
        } else {
            print!("{}", line);
            wrote_to_file = true;
        }

        if wrote_to_file {
            // First successful extraction triggers an orderly detach so the
            // target process keeps running without our breakpoints.
            self.should_detach = true;
        }
    }

    // ------------------------------------------------------------------
    // CALL-probe scanner: arm / disarm / hit handler / trial decrypt
    // ------------------------------------------------------------------

    /// Arm the CALL-probe scanner once ServerHello has been parsed and the
    /// cipher's secret length is known. No-op if already armed or disabled.
    fn arm_call_scanner(&mut self, slen: usize) {
        if !self.call_probe_enabled {
            return;
        }
        if self.scanner.is_armed() {
            return;
        }
        eprintln!("[*] Arming CALL-probe scanner (secret_len={})", slen);
        self.scanner = CallScanner::new(slen, self.verbose);
        self.scanner.phase = ScanPhase::Harvesting;

        self.suspend_target();
        let reader = MemoryReader::new(self.process_handle, self.pid);
        self.scanner.refresh_ranges(&reader);
        let exec_regions = reader.get_executable_regions();
        dbg_log!(self, "[dbg] scanner: {} executable regions", exec_regions.len());

        // Probe every executable region in the process — no module allow-list.
        let mut sites: Vec<u64> = Vec::new();
        for region in &exec_regions {
            let bytes = match reader.read_region(region) {
                Some(b) => b,
                None => continue,
            };
            CallScanner::collect_call_sites(&bytes, region.base, &mut sites);
            if sites.len() >= self.max_call_bps * 2 {
                break;
            }
        }
        if sites.len() > self.max_call_bps {
            eprintln!(
                "[!] scanner: truncating {} CALL sites to cap of {}",
                sites.len(),
                self.max_call_bps,
            );
            sites.truncate(self.max_call_bps);
        }
        eprintln!("[*] scanner: arming {} CALL breakpoints", sites.len());

        let mut installed = 0usize;
        for ip in sites {
            // Skip if this address already has a breakpoint (e.g. Winsock hook).
            if self.breakpoints.contains_key(&ip) {
                continue;
            }
            let mut orig = [0u8; 1];
            if !read_mem(self.process_handle, ip, &mut orig) {
                continue;
            }
            // Sanity: a CALL must start with 0xE8 (rel32), 0xFF (indirect),
            // or 0x9A (far — shouldn't appear in x64 user mode). Guard against
            // writing INT3 over self-modified code.
            if orig[0] != 0xE8 && orig[0] != 0xFF && orig[0] != 0x9A {
                continue;
            }
            if !write_mem(self.process_handle, ip, &[0xCC]) {
                continue;
            }
            self.scanner.bps.insert(ip, orig[0]);
            self.breakpoints.insert(
                ip,
                Breakpoint {
                    original_byte: orig[0],
                    kind: BreakpointKind::CallProbe,
                },
            );
            installed += 1;
        }
        // Flush i-cache once across the whole process after bulk writes.
        flush_icache(self.process_handle, 0);
        eprintln!("[+] scanner: {} CALL breakpoints installed", installed);
        self.resume_target();
    }

    /// Remove every CALL-probe breakpoint and transition the scanner to Done.
    #[allow(dead_code)]
    fn disarm_call_scanner(&mut self) {
        if self.scanner.bps.is_empty() {
            self.scanner.phase = ScanPhase::Done;
            return;
        }
        let sites: Vec<u64> = self.scanner.bps.keys().copied().collect();
        self.suspend_target();
        for addr in &sites {
            if let Some(bp) = self.breakpoints.remove(addr) {
                write_mem(self.process_handle, *addr, &[bp.original_byte]);
            }
        }
        flush_icache(self.process_handle, 0);
        self.resume_target();
        let n = self.scanner.bps.len();
        self.scanner.bps.clear();
        self.scanner.phase = ScanPhase::Done;
        eprintln!("[*] scanner: disarmed {} CALL breakpoints", n);
    }

    /// Variant used by the trial-decrypt path: the caller has already
    /// suspended the target (and will resume it). Avoids redundant suspends.
    fn disarm_call_scanner_inner_no_suspend(&mut self) {
        if self.scanner.bps.is_empty() {
            self.scanner.phase = ScanPhase::Done;
            return;
        }
        let sites: Vec<u64> = self.scanner.bps.keys().copied().collect();
        let n = sites.len();
        for addr in &sites {
            if let Some(bp) = self.breakpoints.remove(addr) {
                write_mem(self.process_handle, *addr, &[bp.original_byte]);
            }
        }
        flush_icache(self.process_handle, 0);
        self.scanner.bps.clear();
        self.scanner.phase = ScanPhase::Done;
        eprintln!("[*] scanner: disarmed {} CALL breakpoints", n);
    }

    /// Called on each CALL-probe breakpoint hit. Returns true if the site
    /// should be permanently culled (no more matches expected).
    fn on_call_probe_hit(&mut self, tid: u32, addr: u64) -> bool {
        let th = match self.thread_handles.get(&tid) {
            Some(&h) => h,
            None => return false,
        };
        let ctx = match get_ctx(th) {
            Some(c) => c,
            None => return false,
        };
        let slen = self.scanner.secret_len as u64;
        let regs = [
            (ArgReg::Rcx, ctx.rcx),
            (ArgReg::Rdx, ctx.rdx),
            (ArgReg::R8, ctx.r8),
            (ArgReg::R9, ctx.r9),
        ];

        // Find a register holding exactly the secret length.
        let len_holder = regs.iter().find(|(_, v)| *v == slen).copied();
        if let Some((rl, _)) = len_holder {
            for &(rp, v) in regs.iter() {
                if rp == rl {
                    continue;
                }
                // Alignment + range heuristic; quickly reject obvious non-pointers.
                if v < 0x10000 || (v & 0x7) != 0 {
                    continue;
                }
                let cls = match self.scanner.classify(v) {
                    Some(c) => c,
                    None => continue,
                };
                let in_private = matches!(cls, crate::memory_reader::PtrClass::Private);
                let mut buf = vec![0u8; self.scanner.secret_len];
                if !read_mem(self.process_handle, v, &mut buf) {
                    continue;
                }
                if self.scanner.record_candidate(buf, v, addr, rp, rl, in_private) {
                    dbg_log!(
                        self,
                        "[dbg] candidate @ call=0x{:X} ptr={:?}=0x{:X} ({}) len_reg={:?}",
                        addr, rp, v, if in_private { "priv" } else { "shared" }, rl
                    );
                }
            }
        }

        self.scanner.note_hit_and_should_cull(addr)
    }

    /// Walk loaded_modules and return (base, end) ranges for the main image
    /// plus every DLL whose name matches the default TLS module allow-list.
    /// End is estimated via VirtualQueryEx.
    #[allow(dead_code)]
    fn allowlisted_module_ranges(&self) -> Vec<(u64, u64)> {
        let mut out: Vec<(u64, u64)> = Vec::new();
        let mut push = |base: u64| {
            if base == 0 {
                return;
            }
            let size = module_image_size(self.process_handle, base);
            if size > 0 {
                out.push((base, base + size));
            }
        };
        if self.main_image_base != 0 {
            push(self.main_image_base);
        }
        for m in self.loaded_modules.values() {
            let short = m.name.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(&m.name);
            if call_scanner::module_is_allowlisted(
                short,
                call_scanner::DEFAULT_TLS_MODULES,
                false,
            ) {
                push(m.base);
            }
        }
        out
    }

    /// Try every candidate against a TLS 1.3 record. Returns the first
    /// secret that decrypts.
    fn trial_tls13_candidates(
        &self,
        cs: &CipherSuite,
        record: &TlsRecord,
        seq: u64,
    ) -> Option<Vec<u8>> {
        let slen = self.scanner.secret_len;
        for cand in self.scanner.ranked_candidates() {
            if cand.bytes.len() != slen {
                continue;
            }
            if tls_decrypt::try_decrypt_tls13(cs, &cand.bytes, record, seq) {
                return Some(cand.bytes.clone());
            }
        }
        None
    }

    /// TLS 1.2 trial for a master-secret-sized candidate.
    fn trial_tls12_candidates(
        &self,
        cs: &CipherSuite,
        cr: &[u8; 32],
        sr: &[u8; 32],
        record: &TlsRecord,
    ) -> Option<Vec<u8>> {
        for cand in self.scanner.ranked_candidates() {
            if cand.bytes.len() != SSL_MASTER_SECRET_LENGTH {
                continue;
            }
            if tls_decrypt::try_decrypt_tls12(cs, &cand.bytes, cr, sr, record) {
                return Some(cand.bytes.clone());
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Hook resolution & breakpoints
    // ------------------------------------------------------------------

    fn resolve_hook_addresses(&mut self) {
        if self.hook_addrs.is_some() {
            return;
        }
        unsafe {
            let ws2 = match LoadLibraryA(windows::core::s!("ws2_32.dll")) {
                Ok(m) => m,
                Err(_) => return,
            };
            let k32 = match LoadLibraryA(windows::core::s!("kernel32.dll")) {
                Ok(m) => m,
                Err(_) => return,
            };
            // advapi32 hosts CreateProcessAsUserW; failure to load is OK
            // (we'll simply not hook that variant).
            let adv32 = LoadLibraryA(windows::core::s!("advapi32.dll")).ok();
            // ntdll is always present, but loading it explicitly keeps the
            // resolution path uniform with the other modules.
            let ntdll = LoadLibraryA(windows::core::s!("ntdll.dll")).ok();
            let c = GetProcAddress(ws2, windows::core::s!("connect"));
            let wc = GetProcAddress(ws2, windows::core::s!("WSAConnect"));
            let s = GetProcAddress(ws2, windows::core::s!("send"));
            let r = GetProcAddress(ws2, windows::core::s!("recv"));
            let rf = GetProcAddress(ws2, windows::core::s!("recvfrom"));
            let st = GetProcAddress(ws2, windows::core::s!("sendto"));
            let x = GetProcAddress(ws2, windows::core::s!("closesocket"));
            let ws = GetProcAddress(ws2, windows::core::s!("WSASend"));
            let wr = GetProcAddress(ws2, windows::core::s!("WSARecv"));
            let wrf = GetProcAddress(ws2, windows::core::s!("WSARecvFrom"));
            let wst = GetProcAddress(ws2, windows::core::s!("WSASendTo"));
            let wgor = GetProcAddress(ws2, windows::core::s!("WSAGetOverlappedResult"));
            let gq = GetProcAddress(k32, windows::core::s!("GetQueuedCompletionStatus"));
            let gqe = GetProcAddress(k32, windows::core::s!("GetQueuedCompletionStatusEx"));
            let cpw = GetProcAddress(k32, windows::core::s!("CreateProcessW"));
            let cpa = GetProcAddress(k32, windows::core::s!("CreateProcessA"));
            let cpau = adv32.and_then(|h| GetProcAddress(h, windows::core::s!("CreateProcessAsUserW")));
            let ntcup = ntdll.and_then(|h| GetProcAddress(h, windows::core::s!("NtCreateUserProcess")));
            let zwcup = ntdll.and_then(|h| GetProcAddress(h, windows::core::s!("ZwCreateUserProcess")));
            if let (Some(c), Some(wc), Some(s), Some(r), Some(rf), Some(st), Some(x), Some(ws), Some(wr), Some(wrf), Some(wst), Some(wgor), Some(gq), Some(gqe)) =
                (c, wc, s, r, rf, st, x, ws, wr, wrf, wst, wgor, gq, gqe)
            {
                eprintln!("Resolved hooks:");
                eprintln!("  connect    = 0x{:X}", c as u64);
                eprintln!("  WSAConnect = 0x{:X}", wc as u64);
                eprintln!("  send       = 0x{:X}", s as u64);
                eprintln!("  recv       = 0x{:X}", r as u64);
                eprintln!("  recvfrom   = 0x{:X}", rf as u64);
                eprintln!("  sendto     = 0x{:X}", st as u64);
                eprintln!("  closeskt   = 0x{:X}", x as u64);
                eprintln!("  WSASend    = 0x{:X}", ws as u64);
                eprintln!("  WSARecv    = 0x{:X}", wr as u64);
                eprintln!("  WSARecvFrom= 0x{:X}", wrf as u64);
                eprintln!("  WSASendTo  = 0x{:X}", wst as u64);
                eprintln!("  WSAGetOvrl = 0x{:X}", wgor as u64);
                eprintln!("  GQCS       = 0x{:X}", gq as u64);
                eprintln!("  GQCSEx     = 0x{:X}", gqe as u64);
                let create_process_w = cpw.map(|f| f as u64).unwrap_or(0);
                let create_process_a = cpa.map(|f| f as u64).unwrap_or(0);
                let create_process_as_user_w = cpau.map(|f| f as u64).unwrap_or(0);
                let nt_create_user_process = ntcup.map(|f| f as u64).unwrap_or(0);
                let zw_create_user_process = zwcup.map(|f| f as u64).unwrap_or(0);
                if create_process_w != 0 {
                    eprintln!("  CreateProcessW = 0x{:X}", create_process_w);
                }
                if create_process_a != 0 {
                    eprintln!("  CreateProcessA = 0x{:X}", create_process_a);
                }
                if create_process_as_user_w != 0 {
                    eprintln!("  CreateProcessAsUserW = 0x{:X}", create_process_as_user_w);
                }
                if nt_create_user_process != 0 {
                    eprintln!("  NtCreateUserProcess = 0x{:X}", nt_create_user_process);
                }
                // Hide ZwCreateUserProcess if it aliases NtCreateUserProcess
                // (the common case on modern Windows).
                if zw_create_user_process != 0 && zw_create_user_process != nt_create_user_process {
                    eprintln!("  ZwCreateUserProcess = 0x{:X}", zw_create_user_process);
                }
                self.hook_addrs = Some(HookAddresses {
                    connect: c as u64,
                    wsaconnect: wc as u64,
                    send: s as u64,
                    recv: r as u64,
                    recvfrom: rf as u64,
                    sendto: st as u64,
                    closesocket: x as u64,
                    wsasend: ws as u64,
                    wsarecv: wr as u64,
                    wsarecvfrom: wrf as u64,
                    wsasendto: wst as u64,
                    wsa_get_overlapped_result: wgor as u64,
                    gqcs: gq as u64,
                    gqcs_ex: gqe as u64,
                    create_process_w,
                    create_process_a,
                    create_process_as_user_w,
                    nt_create_user_process,
                    zw_create_user_process,
                });
            }
        }
    }

    /// Try to install all function breakpoints. Returns true only if ALL
    /// were successfully written to the target process memory.
    fn try_set_all_breakpoints(&mut self) -> bool {
        let addrs: Vec<u64> = match &self.hook_addrs {
            Some(a) => {
                let mut v = vec![
                    a.connect,
                    a.wsaconnect,
                    a.send,
                    a.recv,
                    a.recvfrom,
                    a.sendto,
                    a.closesocket,
                    a.wsasend,
                    a.wsarecv,
                    a.wsarecvfrom,
                    a.wsasendto,
                    a.wsa_get_overlapped_result,
                    a.gqcs,
                    a.gqcs_ex,
                ];
                // Process-creation hooks are optional — only attempt to set
                // them if their address was successfully resolved AND the
                // user opted in to child-process tracing.
                if self.trace_children {
                    for opt in [
                        a.create_process_w,
                        a.create_process_a,
                        a.create_process_as_user_w,
                        a.nt_create_user_process,
                        a.zw_create_user_process,
                    ] {
                        if opt != 0 {
                            v.push(opt);
                        }
                    }
                }
                v
            }
            None => return false,
        };
        let mut all_ok = true;
        for &addr in &addrs {
            if !self.set_function_breakpoint(addr) {
                all_ok = false;
            }
        }
        all_ok
    }

    fn set_function_breakpoint(&mut self, address: u64) -> bool {
        if self.breakpoints.contains_key(&address) {
            return true;
        }
        let mut orig = [0u8; 1];
        if !read_mem(self.process_handle, address, &mut orig) {
            dbg_log!(self, "[dbg] set_bp 0x{:X}: read failed", address);
            return false;
        }
        if !write_mem(self.process_handle, address, &[0xCC]) {
            dbg_log!(self, "[dbg] set_bp 0x{:X}: write failed", address);
            return false;
        }
        dbg_log!(self, "[dbg] set_bp 0x{:X}: OK (orig=0x{:02X})", address, orig[0]);
        flush_icache(self.process_handle, address);
        self.breakpoints.insert(
            address,
            Breakpoint {
                original_byte: orig[0],
                kind: BreakpointKind::Function,
            },
        );
        true
    }

    fn set_return_breakpoint(&mut self, address: u64, tid: u32, call: PendingCall) {
        // If a return BP already exists at this address (e.g. shared call site
        // used by multiple threads/goroutines), append the new call to it.
        if let Some(bp) = self.breakpoints.get_mut(&address) {
            if let BreakpointKind::Return { ref mut calls } = bp.kind {
                dbg_log!(self, "[dbg] return BP 0x{:X}: appending call for tid={} (now {} calls)",
                    address, tid, calls.len() + 1);
                calls.push((tid, call));
                return;
            }
            // Address is a function breakpoint — skip.
            return;
        }
        // Also check consumed_return_addrs — the address may have been
        // recently consumed but the INT3 byte restored. Re-arm it.
        let orig_byte = if let Some(&orig) = self.consumed_return_addrs.get(&address) {
            orig
        } else {
            let mut orig = [0u8; 1];
            if !read_mem(self.process_handle, address, &mut orig) {
                return;
            }
            orig[0]
        };
        if !write_mem(self.process_handle, address, &[0xCC]) {
            return;
        }
        flush_icache(self.process_handle, address);
        self.consumed_return_addrs.remove(&address);
        self.breakpoints.insert(
            address,
            Breakpoint {
                original_byte: orig_byte,
                kind: BreakpointKind::Return {
                    calls: vec![(tid, call)],
                },
            },
        );
    }

    fn remove_breakpoint(&mut self, address: u64) {
        if let Some(bp) = self.breakpoints.remove(&address) {
            write_mem(self.process_handle, address, &[bp.original_byte]);
            flush_icache(self.process_handle, address);
        }
    }

    /// Suspend all threads in the target process so memory is stable during scanning.
    fn suspend_target(&self) {
        for (&tid, &handle) in &self.thread_handles {
            let prev = unsafe { SuspendThread(handle) };
            if prev == u32::MAX {
                dbg_log!(self, "[dbg] SuspendThread({}) failed", tid);
            }
        }
    }

    /// Resume all threads previously suspended by suspend_target.
    fn resume_target(&self) {
        for (&tid, &handle) in &self.thread_handles {
            let prev = unsafe { ResumeThread(handle) };
            if prev == u32::MAX {
                dbg_log!(self, "[dbg] ResumeThread({}) failed", tid);
            }
        }
    }

    /// Remove every breakpoint we installed, then detach from the target
    /// without killing it. After this returns the target process is
    /// running normally with all of its original code restored.
    fn detach_target(&mut self) {
        if self.detached {
            return;
        }
        // Freeze the target so we can safely rewrite code under it.
        self.suspend_target();
        let addrs: Vec<u64> = self.breakpoints.keys().copied().collect();
        for addr in &addrs {
            if let Some(bp) = self.breakpoints.remove(addr) {
                write_mem(self.process_handle, *addr, &[bp.original_byte]);
            }
        }
        // Also restore any return-BP addresses we'd already consumed (their
        // original byte is preserved in `consumed_return_addrs`). The bytes
        // are already restored, but writing them again is harmless and keeps
        // the post-conditions explicit.
        for (addr, &orig) in &self.consumed_return_addrs {
            write_mem(self.process_handle, *addr, &[orig]);
        }
        flush_icache(self.process_handle, 0);
        self.consumed_return_addrs.clear();
        self.scanner.bps.clear();
        self.resume_target();

        unsafe {
            // Make sure detaching does NOT kill the process. This is a
            // per-debug-object setting and must be requested explicitly.
            let _ = DebugSetProcessKillOnExit(false);
            if let Err(e) = DebugActiveProcessStop(self.pid) {
                eprintln!("[!] DebugActiveProcessStop({}) failed: {:?}", self.pid, e);
            } else {
                eprintln!("[+] Detached from PID {} (target continues running)", self.pid);
            }
        }
        self.detached = true;
    }
}

impl Drop for DebugTracker {
    fn drop(&mut self) {
        if self.detached {
            // detach_target already restored every breakpoint and stopped
            // the debug session; the process handle is no longer ours.
            return;
        }
        let addrs: Vec<u64> = self.breakpoints.keys().copied().collect();
        for a in addrs {
            self.remove_breakpoint(a);
        }
    }
}

// ============================================================================
// Low-level helpers
// ============================================================================

fn read_stack_u64(handle: HANDLE, addr: u64) -> u64 {
    let mut bytes = [0u8; 8];
    if read_mem(handle, addr, &mut bytes) {
        u64::from_le_bytes(bytes)
    } else {
        0
    }
}

pub fn read_mem(handle: HANDLE, addr: u64, buf: &mut [u8]) -> bool {
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(
            handle,
            addr as *const _,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            &mut n,
        )
        .as_bool()
    }
}

fn write_mem(handle: HANDLE, addr: u64, data: &[u8]) -> bool {
    unsafe {
        let mut old = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(
            handle,
            addr as *const _,
            data.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old,
        );
        let mut n = 0usize;
        let ok = WriteProcessMemory(
            handle,
            addr as *const _,
            data.as_ptr() as *const _,
            data.len(),
            &mut n,
        )
        .as_bool();
        let _ = VirtualProtectEx(handle, addr as *const _, data.len(), old, &mut old);
        ok
    }
}

fn flush_icache(handle: HANDLE, addr: u64) {
    unsafe {
        let _ = FlushInstructionCache(handle, addr as *const _, 1);
    }
}

#[cfg(target_arch = "x86_64")]
fn get_ctx(thread: HANDLE) -> Option<Amd64Context> {
    unsafe {
        let mut ctx: Amd64Context = mem::zeroed();
        ctx.context_flags = CTX_FULL;
        if GetThreadContext(thread, &mut ctx).as_bool() {
            Some(ctx)
        } else {
            None
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn set_rip(thread: HANDLE, addr: u64) {
    unsafe {
        let mut ctx: Amd64Context = mem::zeroed();
        ctx.context_flags = CTX_CONTROL;
        if GetThreadContext(thread, &mut ctx).as_bool() {
            ctx.rip = addr;
            let _ = SetThreadContext(thread, &ctx);
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn enable_trap_flag(thread: HANDLE) {
    unsafe {
        let mut ctx: Amd64Context = mem::zeroed();
        ctx.context_flags = CTX_CONTROL;
        if GetThreadContext(thread, &mut ctx).as_bool() {
            ctx.eflags |= 0x100; // TF
            let _ = SetThreadContext(thread, &ctx);
        }
    }
}

// ----------------------------------------------------------------------------
// Module / range helpers for the CALL-probe scanner
// ----------------------------------------------------------------------------

/// Read the DLL name from a LOAD_DLL_DEBUG_INFO. Tries `lpImageName` first,
/// then falls back to querying the mapped file name via VirtualQueryEx +
/// GetMappedFileNameW.
fn read_dll_name(handle: HANDLE, info: &LOAD_DLL_DEBUG_INFO) -> String {
    // lpImageName is optional and points into the target process.
    if !info.lpImageName.is_null() {
        let mut ptr_bytes = [0u8; 8];
        if read_mem(handle, info.lpImageName as u64, &mut ptr_bytes) {
            let name_ptr = u64::from_le_bytes(ptr_bytes);
            if name_ptr != 0 {
                let mut buf = [0u8; 1024];
                if read_mem(handle, name_ptr, &mut buf) {
                    if info.fUnicode != 0 {
                        // UTF-16; read as u16 pairs until NUL.
                        let mut wide: Vec<u16> = Vec::new();
                        for chunk in buf.chunks_exact(2) {
                            let w = u16::from_le_bytes([chunk[0], chunk[1]]);
                            if w == 0 {
                                break;
                            }
                            wide.push(w);
                        }
                        if !wide.is_empty() {
                            return String::from_utf16_lossy(&wide);
                        }
                    } else {
                        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                        if end > 0 {
                            return String::from_utf8_lossy(&buf[..end]).into_owned();
                        }
                    }
                }
            }
        }
    }
    // Fallback: GetMappedFileNameW on the DLL base.
    get_mapped_file_name(handle, info.lpBaseOfDll as u64).unwrap_or_default()
}

/// Query size of a module loaded at `base`. Walks VirtualQueryEx regions
/// until it leaves the MEM_IMAGE allocation identified by AllocationBase.
fn module_image_size(handle: HANDLE, base: u64) -> u64 {
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION,
    };
    let mut addr = base;
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let sz = mem::size_of::<MEMORY_BASIC_INFORMATION>();
    let mut total: u64 = 0;
    unsafe {
        loop {
            if VirtualQueryEx(handle, Some(addr as *const _), &mut mbi, sz) == 0 {
                break;
            }
            if mbi.AllocationBase as u64 != base {
                break;
            }
            let region_size = mbi.RegionSize as u64;
            total += region_size;
            let next = mbi.BaseAddress as u64 + region_size;
            if next <= addr {
                break;
            }
            addr = next;
        }
    }
    total
}

fn get_mapped_file_name(handle: HANDLE, addr: u64) -> Option<String> {
    extern "system" {
        fn K32GetMappedFileNameW(
            h_process: HANDLE,
            lpv: *const std::ffi::c_void,
            lp_filename: *mut u16,
            n_size: u32,
        ) -> u32;
    }
    let mut buf = [0u16; 1024];
    let n = unsafe {
        K32GetMappedFileNameW(handle, addr as *const _, buf.as_mut_ptr(), buf.len() as u32)
    };
    if n == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..n as usize]))
}

#[allow(dead_code)]
fn any_range_overlaps(ranges: &[(u64, u64)], base: u64, end: u64) -> bool {
    ranges.iter().any(|&(b, e)| base < e && b < end)
}

/// Resolve the basename of the target process's image (without path or
/// extension) given a process handle. Returns None if the OS API fails.
fn query_process_image_name(handle: HANDLE) -> Option<String> {
    extern "system" {
        fn K32GetProcessImageFileNameW(
            h_process: HANDLE,
            lp_image_file_name: *mut u16,
            n_size: u32,
        ) -> u32;
    }
    let mut buf = [0u16; 1024];
    let n = unsafe { K32GetProcessImageFileNameW(handle, buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        return None;
    }
    let full = String::from_utf16_lossy(&buf[..n as usize]);
    // Path is in NT-device form (e.g. "\\Device\\HarddiskVolume3\\...\\foo.exe").
    // We only care about the file name component.
    let base = full
        .rsplit(|c: char| c == '\\' || c == '/')
        .next()
        .unwrap_or(&full);
    // Strip the trailing extension if any.
    let stem = match base.rfind('.') {
        Some(dot) if dot > 0 => &base[..dot],
        _ => base,
    };
    if stem.is_empty() {
        None
    } else {
        Some(stem.to_string())
    }
}

/// Replace anything that isn't a safe filename character with `_` so the
/// process image name can be embedded into the per-process key file name.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `CREATE_SUSPENDED` bit for the `dwCreationFlags` argument of the
/// `CreateProcess*` family.
const CREATE_SUSPENDED_FLAG: u32 = 0x0000_0004;/// `THREAD_CREATE_FLAGS_CREATE_SUSPENDED` bit for the `ThreadFlags` argument
/// of `NtCreateUserProcess` / `ZwCreateUserProcess`.
const NT_THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;

/// OR the bits `flag` into the 32-bit value currently on the target's stack
/// at `slot_addr`. Used to force `CREATE_SUSPENDED` (or the NT equivalent)
/// into a process-creation function's arguments before the function runs.
fn force_suspended_creation_flag(handle: HANDLE, slot_addr: u64, flag: u32) {
    let mut raw = [0u8; 4];
    if !read_mem(handle, slot_addr, &mut raw) {
        return;
    }
    let cur = u32::from_le_bytes(raw);
    if cur & flag == flag {
        return;
    }
    let new = cur | flag;
    write_mem(handle, slot_addr, &new.to_le_bytes());
}

/// Best-effort resume of a process's main thread when we created it
/// suspended but for some reason can't launch a child Tihulu against it.
/// Used as a safety net so we don't leave orphaned, frozen processes behind.
fn resume_pid_main_thread(pid: u32) {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Threading::{OpenThread, THREAD_SUSPEND_RESUME};
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            Ok(h) => h,
            Err(_) => return,
        };
        let mut te: THREADENTRY32 = mem::zeroed();
        te.dwSize = mem::size_of::<THREADENTRY32>() as u32;
        if Thread32First(snap, &mut te).is_err() {
            let _ = CloseHandle(snap);
            return;
        }
        loop {
            if te.th32OwnerProcessID == pid {
                if let Ok(h) = OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID) {
                    let _ = ResumeThread(h);
                    let _ = CloseHandle(h);
                }
                // Only the *initial* thread is suspended by CREATE_SUSPENDED,
                // and the first thread enumerated for the PID is overwhelmingly
                // that main thread. Stop after the first resume attempt.
                break;
            }
            if Thread32Next(snap, &mut te).is_err() {
                break;
            }
        }
        let _ = CloseHandle(snap);
    }
}

/// Duplicate a HANDLE that lives in `source_process`'s handle table into our/// own process, query its PID, then close the duplicate. Returns None on any
/// failure. Used to resolve the ProcessHandle output of NtCreateUserProcess
/// (which is meaningful only inside the target) to a numeric PID we can pass
/// to a child Tihulu instance via `--pid`.
fn duplicate_and_get_pid(source_process: HANDLE, source_handle_value: u64) -> Option<u32> {
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS};
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessId};

    let src_handle = HANDLE(source_handle_value as *mut std::ffi::c_void);
    let mut dup = HANDLE::default();
    unsafe {
        DuplicateHandle(
            source_process,
            src_handle,
            GetCurrentProcess(),
            &mut dup,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .ok()?;
        let pid = GetProcessId(dup);
        let _ = CloseHandle(dup);
        if pid == 0 {
            None
        } else {
            Some(pid)
        }
    }
}

/// Patch a fixed-width placeholder embedded inside a `KEY=value` entry of
/// the child process's already-instantiated environment block. Used to
/// stamp the freshly-allocated PID into an env var whose value was prepared
/// in the parent before `CreateProcessW` (when the PID was not yet known).
///
/// The child must be in a state where the kernel has populated its PEB and
/// `RTL_USER_PROCESS_PARAMETERS` but the loader has not yet read the
/// targeted variable — i.e. immediately after a `CREATE_SUSPENDED` create
/// and before `ResumeThread`. `placeholder` and `replacement` must have the
/// same byte length so the surrounding env block stays well-formed.
fn patch_child_env_placeholder(
    hproc: HANDLE,
    var_prefix: &str,
    placeholder: &str,
    replacement: &str,
) -> Result<(), String> {
    if placeholder.len() != replacement.len() {
        return Err("placeholder/replacement length mismatch".into());
    }

    // PROCESS_BASIC_INFORMATION (x64 layout).
    #[repr(C)]
    #[derive(Default)]
    struct ProcessBasicInformation {
        exit_status: i32,
        _pad: u32,
        peb_base_address: usize,
        affinity_mask: usize,
        base_priority: i32,
        _pad2: u32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    type NtQueryInformationProcessFn = unsafe extern "system" fn(
        process: HANDLE,
        info_class: u32,
        info: *mut std::ffi::c_void,
        info_len: u32,
        ret_len: *mut u32,
    ) -> i32;

    let nt_query: NtQueryInformationProcessFn = unsafe {
        let ntdll = GetModuleHandleA(windows::core::s!("ntdll.dll"))
            .map_err(|e| format!("GetModuleHandle ntdll: {}", e))?;
        let proc = GetProcAddress(ntdll, windows::core::s!("NtQueryInformationProcess"))
            .ok_or_else(|| "NtQueryInformationProcess not found".to_string())?;
        std::mem::transmute(proc)
    };

    let mut pbi: ProcessBasicInformation = ProcessBasicInformation::default();
    let mut ret_len: u32 = 0;
    let status = unsafe {
        nt_query(
            hproc,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as *mut _,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        )
    };
    if status != 0 {
        return Err(format!("NtQueryInformationProcess status=0x{:X}", status as u32));
    }
    if pbi.peb_base_address == 0 {
        return Err("PEB base address is null".into());
    }
    let peb = pbi.peb_base_address as u64;

    // PEB.ProcessParameters lives at offset 0x20 on x64.
    let mut pp_bytes = [0u8; 8];
    if !read_mem(hproc, peb + 0x20, &mut pp_bytes) {
        return Err("read PEB.ProcessParameters failed".into());
    }
    let pp = u64::from_le_bytes(pp_bytes);
    if pp == 0 {
        return Err("ProcessParameters pointer is null".into());
    }

    // RTL_USER_PROCESS_PARAMETERS.Environment at offset 0x80 (x64),
    // EnvironmentSize at offset 0x3F0 (Windows 10+). EnvironmentSize is
    // optional — fall back to a generous cap if it looks bogus.
    let mut env_ptr_bytes = [0u8; 8];
    if !read_mem(hproc, pp + 0x80, &mut env_ptr_bytes) {
        return Err("read ProcessParameters.Environment failed".into());
    }
    let env_ptr = u64::from_le_bytes(env_ptr_bytes);
    if env_ptr == 0 {
        return Err("Environment pointer is null".into());
    }
    let mut env_size_bytes = [0u8; 8];
    let _ = read_mem(hproc, pp + 0x3F0, &mut env_size_bytes);
    let mut env_size = u64::from_le_bytes(env_size_bytes) as usize;
    if env_size == 0 || env_size > 4 * 1024 * 1024 {
        env_size = 64 * 1024;
    }

    let mut env_buf: Vec<u8> = vec![0u8; env_size];
    if !read_mem(hproc, env_ptr, &mut env_buf) {
        // Try a smaller buffer in case the requested size straddles an
        // unreadable boundary.
        env_size = 32 * 1024;
        env_buf.resize(env_size, 0);
        if !read_mem(hproc, env_ptr, &mut env_buf) {
            return Err("ReadProcessMemory env block failed".into());
        }
    }

    // The env block is a contiguous sequence of UTF-16 NUL-terminated
    // strings, terminated by an extra UTF-16 NUL.
    let usable = env_buf.len() & !1; // round down to u16 pair
    let env_u16: &[u16] = unsafe {
        std::slice::from_raw_parts(env_buf.as_ptr() as *const u16, usable / 2)
    };

    let prefix_w: Vec<u16> = var_prefix.encode_utf16().collect();
    let placeholder_w: Vec<u16> = placeholder.encode_utf16().collect();
    let replacement_w: Vec<u16> = replacement.encode_utf16().collect();

    let prefix_idx = env_u16
        .windows(prefix_w.len())
        .position(|w| w == prefix_w.as_slice())
        .ok_or_else(|| format!("'{}' not found in child env block", var_prefix))?;

    // Search for the placeholder *within the value* of this entry (i.e.
    // before the next NUL).
    let val_start = prefix_idx + prefix_w.len();
    let mut placeholder_idx: Option<usize> = None;
    let mut p = val_start;
    while p + placeholder_w.len() <= env_u16.len() {
        if env_u16[p] == 0 {
            break;
        }
        if &env_u16[p..p + placeholder_w.len()] == placeholder_w.as_slice() {
            placeholder_idx = Some(p);
            break;
        }
        p += 1;
    }
    let placeholder_idx = placeholder_idx
        .ok_or_else(|| format!("placeholder '{}' not found in env value", placeholder))?;

    // WriteProcessMemory at the absolute address.
    let write_addr = env_ptr + (placeholder_idx as u64) * 2;
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            replacement_w.as_ptr() as *const u8,
            replacement_w.len() * 2,
        )
    };
    let mut written: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            hproc,
            write_addr as *const _,
            bytes.as_ptr() as *const _,
            bytes.len(),
            &mut written,
        )
        .as_bool()
    };
    if !ok || written != bytes.len() {
        return Err("WriteProcessMemory failed".into());
    }
    Ok(())
}

/// Block (briefly) until the kernel has finished wiring up the user-mode
/// state of `pid` and the process is ready to accept `DebugActiveProcess`.
///
/// We probe via `NtQueryInformationProcess(ProcessDebugObjectHandle)`:
///   * `STATUS_PORT_NOT_SET` (0xC0000353) -> ready to be debugged (no debug
///     port attached yet). This is the signal we want.
///   * `STATUS_SUCCESS` -> already being debugged, attach will fail with
///     ERROR_NOT_SUPPORTED but there is no point waiting longer.
///   * `STATUS_INFO_LENGTH_MISMATCH` / `STATUS_INVALID_INFO_CLASS` -> kernel
///     hasn't materialised the process info yet; keep polling.
///   * Anything else -> give up and let the caller's retry loop handle it.
///
/// Best-effort: silently returns on any setup failure (OpenProcess, missing
/// ntdll export, etc.). The caller still has a fallback retry path.
fn wait_until_debuggable(pid: u32) {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 30;
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_PORT_NOT_SET: i32 = 0xC000_0353_u32 as i32;

    type NtQueryInformationProcessFn = unsafe extern "system" fn(
        process: HANDLE,
        info_class: u32,
        info: *mut std::ffi::c_void,
        info_len: u32,
        ret_len: *mut u32,
    ) -> i32;

    let nt_query: NtQueryInformationProcessFn = unsafe {
        let ntdll = match GetModuleHandleA(windows::core::s!("ntdll.dll")) {
            Ok(h) if !h.is_invalid() => h,
            _ => return,
        };
        let proc = match GetProcAddress(ntdll, windows::core::s!("NtQueryInformationProcess")) {
            Some(p) => p,
            None => return,
        };
        std::mem::transmute(proc)
    };

    let handle = unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return,
        }
    };

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2000);
    let mut delay_us: u64 = 250;
    loop {
        let mut dbg_obj: usize = 0;
        let mut ret_len: u32 = 0;
        let status = unsafe {
            nt_query(
                handle,
                PROCESS_DEBUG_OBJECT_HANDLE,
                &mut dbg_obj as *mut _ as *mut _,
                std::mem::size_of::<usize>() as u32,
                &mut ret_len,
            )
        };
        match status {
            STATUS_PORT_NOT_SET => break,
            STATUS_SUCCESS => break, // already debugged; let caller fail fast
            // 0xC0000004 STATUS_INFO_LENGTH_MISMATCH, 0xC0000003 STATUS_INVALID_INFO_CLASS,
            // 0xC0000008 STATUS_INVALID_HANDLE -> race during teardown/setup; keep polling.
            s if (s as u32) & 0xF000_0000 == 0xC000_0000 => {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_micros(delay_us));
                delay_us = (delay_us * 2).min(10_000);
            }
            _ => break,
        }
    }
    unsafe { let _ = CloseHandle(handle); }
}

// ============================================================================
// MultiTracker — debugs many processes from a single Tihulu instance.
// ============================================================================

/// Static configuration shared across every `DebugTracker` managed by a
/// `MultiTracker`. Cloned for each new child attach.
#[derive(Clone)]
pub struct TrackerConfig {
    pub output_dir: Option<String>,
    pub verbose: bool,
    pub search_threads: Option<usize>,
    pub call_probe_enabled: bool,
    pub max_call_bps: usize,
    pub fallback_scan: bool,
    pub trace_children: bool,
}

/// Orchestrator that drives a single `WaitForDebugEvent` loop and routes
/// every event to the per-process `DebugTracker` keyed by `dwProcessId`.
///
/// Each tracked child appears as an additional entry in `trackers`. When a
/// tracked process triggers a CreateProcess-family hook the responsible
/// tracker enqueues the child's PID; after `ContinueDebugEvent` for the
/// current event we call `DebugActiveProcess` on every queued child (still
/// suspended at that point) and add a fresh `DebugTracker` to the map.
pub struct MultiTracker {
    cfg: TrackerConfig,
    trackers: HashMap<u32, DebugTracker>,
}

impl MultiTracker {
    pub fn new(cfg: TrackerConfig) -> Self {
        Self { cfg, trackers: HashMap::new() }
    }

    /// Build a fresh `DebugTracker` from this orchestrator's configuration.
    /// `resume_on_attach=true` is used for children that the parent target
    /// created suspended — the tracker will `ResumeThread` the main thread
    /// once breakpoints are installed.
    fn make_tracker(&self, pid: u32, resume_on_attach: bool) -> DebugTracker {
        DebugTracker::new(
            pid,
            self.cfg.output_dir.clone(),
            self.cfg.verbose,
            self.cfg.search_threads,
            self.cfg.call_probe_enabled,
            self.cfg.max_call_bps,
            self.cfg.fallback_scan,
            self.cfg.trace_children,
            resume_on_attach,
        )
    }

    /// Insert an already-attached tracker (the caller is responsible for
    /// having called `DebugActiveProcess` or `CreateProcess` with the
    /// `DEBUG_*` flag). Used for the initial CLI-supplied target.
    pub fn add_initial(&mut self, tracker: DebugTracker) {
        eprintln!("[*] Tracing PID {}", tracker.pid());
        self.trackers.insert(tracker.pid(), tracker);
    }

    /// Attach to `pid` via `DebugActiveProcess` and add a tracker for it.
    /// Used for children spawned by a tracked process (which are suspended
    /// at the point this is called, eliminating the user-mode-init race).
    pub fn attach_child(&mut self, pid: u32) -> std::io::Result<()> {
        DebugTracker::attach(pid)?;
        let tracker = self.make_tracker(pid, /*resume_on_attach=*/ true);
        eprintln!("[*] Tracing PID {} (child)", pid);
        self.trackers.insert(pid, tracker);
        Ok(())
    }

    /// Run the debug event loop until every tracked process has either
    /// exited or been cleanly detached after capturing keys.
    pub fn run(&mut self) -> std::io::Result<()> {
        let mut event: DEBUG_EVENT = unsafe { mem::zeroed() };

        while !self.trackers.is_empty() {
            if unsafe { WaitForDebugEvent(&mut event, 100) }.is_err() {
                continue;
            }

            let pid = event.dwProcessId;
            let tid = event.dwThreadId;

            // Route the event to the matching tracker. Unknown PIDs (e.g.
            // a stale event after detach) get a default continuation.
            let outcome = match self.trackers.get_mut(&pid) {
                Some(t) => t.process_one_event(&event),
                None => EventOutcome { status: DBG_CONTINUE, finished: false },
            };

            unsafe {
                ContinueDebugEvent(pid, tid, outcome.status)?;
            }

            // Drain any child-attach requests this event produced. The
            // child is currently suspended, so `DebugActiveProcess` is
            // race-free here.
            let pending: Vec<u32> = self
                .trackers
                .get_mut(&pid)
                .map(|t| t.take_pending_child_attaches())
                .unwrap_or_default();
            for child_pid in pending {
                if let Err(e) = self.attach_child(child_pid) {
                    eprintln!(
                        "[!] Failed to attach to child PID {}: {} — releasing it",
                        child_pid, e
                    );
                    resume_pid_main_thread(child_pid);
                }
            }

            // Per-tracker termination: process exited or keys captured.
            let mut remove = outcome.finished;
            if !remove {
                if let Some(t) = self.trackers.get_mut(&pid) {
                    if t.is_done() {
                        eprintln!(
                            "[*] Keys captured — unhooking and detaching from PID {}",
                            pid
                        );
                        t.detach_target();
                        remove = true;
                    }
                }
            }
            if remove {
                if let Some(mut t) = self.trackers.remove(&pid) {
                    t.finalize_summary();
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Child dispatch helpers — defeat the DebugActiveProcess race on suspended
// children by briefly running their primary thread (loader init) and then
// freezing the entire process before user code reaches the entry point.
// ============================================================================

#[link(name = "ntdll")]
extern "system" {
    fn NtSuspendProcess(process: HANDLE) -> i32;
    fn NtResumeProcess(process: HANDLE) -> i32;
}

/// Locate the lowest-TID thread belonging to `pid` via a Toolhelp32 snapshot.
/// For a freshly-created `CREATE_SUSPENDED` process this is the primary
/// thread (only thread). Returns 0 if the lookup fails.
fn first_thread_of_pid(pid: u32) -> u32 {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            Ok(h) => h,
            Err(_) => return 0,
        };
        let mut te: THREADENTRY32 = mem::zeroed();
        te.dwSize = mem::size_of::<THREADENTRY32>() as u32;
        let mut found: u32 = 0;
        if Thread32First(snap, &mut te).is_ok() {
            loop {
                if te.th32OwnerProcessID == pid {
                    if found == 0 || te.th32ThreadID < found {
                        found = te.th32ThreadID;
                    }
                }
                if Thread32Next(snap, &mut te).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
        found
    }
}

/// Dispatch a `CREATE_SUSPENDED` child's primary thread for an instant, then
/// freeze the whole process before the entry point runs. After this returns,
/// `DebugActiveProcess(pid)` will succeed (the thread is no longer in the
/// "never dispatched" state that the kernel rejects), while the child is
/// still parked in `LdrInitializeThunk` / `LdrpInitializeProcess` and has
/// not executed any application code.
///
/// Returns `false` if any step fails (caller should treat as best-effort).
fn nudge_then_freeze_child(child_pid: u32) -> bool {
    use windows::Win32::System::Threading::{
        GetCurrentThread, GetThreadPriority, OpenProcess, OpenThread, SetThreadPriority,
        PROCESS_SUSPEND_RESUME, THREAD_PRIORITY, THREAD_PRIORITY_TIME_CRITICAL,
        THREAD_SUSPEND_RESUME,
    };

    let proc_handle = unsafe {
        match OpenProcess(PROCESS_SUSPEND_RESUME, false, child_pid) {
            Ok(h) => h,
            Err(e) => {
                eprintln!(
                    "[!] nudge: OpenProcess(PID {}) failed: {:?}",
                    child_pid, e
                );
                return false;
            }
        }
    };

    let tid = first_thread_of_pid(child_pid);
    if tid == 0 {
        unsafe {
            let _ = CloseHandle(proc_handle);
        }
        eprintln!("[!] nudge: could not enumerate threads of PID {}", child_pid);
        return false;
    }

    let thread_handle = unsafe {
        match OpenThread(THREAD_SUSPEND_RESUME, false, tid) {
            Ok(h) => h,
            Err(e) => {
                let _ = CloseHandle(proc_handle);
                eprintln!(
                    "[!] nudge: OpenThread(tid {}) of PID {} failed: {:?}",
                    tid, child_pid, e
                );
                return false;
            }
        }
    };

    // Boost our priority so the window between ResumeThread and
    // NtSuspendProcess stays microseconds-short.
    let prev_prio = unsafe { GetThreadPriority(GetCurrentThread()) };
    let _ = unsafe {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL)
    };

    // Release the suspended primary thread — it begins running ntdll's
    // LdrpInitializeProcess.
    let prev = unsafe { ResumeThread(thread_handle) };

    // Immediately freeze the whole process. NtSuspendProcess bumps every
    // thread's suspend count by 1, blocking the loader before it hands off
    // to the executable's entry point.
    let st = unsafe { NtSuspendProcess(proc_handle) };

    // Restore our priority.
    let _ = unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY(prev_prio)) };

    unsafe {
        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(proc_handle);
    }

    if prev == u32::MAX {
        eprintln!(
            "[!] nudge: ResumeThread(tid {}) of PID {} failed",
            tid, child_pid
        );
        return false;
    }
    if st < 0 {
        eprintln!(
            "[!] nudge: NtSuspendProcess(PID {}) failed: 0x{:08X}",
            child_pid, st as u32
        );
        return false;
    }
    true
}
