# Tihulu

![tihulu](.github/banner.png)

A Windows TLS 1.2/1.3 key extractor that uses the Windows Debug API to intercept Winsock calls and recover TLS session secrets at runtime — without patching the target binary or requiring source access. Recovered secrets are written in [NSS Key Log](https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html) format, making captured traffic directly decryptable in Wireshark.


## How does it work?

Tihulu attaches to a target process as a debugger (or launches it as a child) and sets software breakpoints (INT3) on the Winsock connection-establishment entry points. When the target initiates a connection it is briefly frozen while Tihulu rewrites the destination to point at a loopback listener it owns, recording the original `IP:PORT` and the randomly chosen proxy port. The target then transparently connects to this local relay, which pumps the raw TCP stream to and from the real server while teeing a copy of every byte to an in-process TLS parser. Because the relay never terminates TLS, the genuine session secrets are still derived inside the target's own memory — exactly where the scanners below look for them.

The following entry points are hooked so high-level HTTP stacks are covered as well as raw sockets:

* **`connect` / `WSAConnect`** (`ws2_32.dll`) — plain synchronous connects. The destination `sockaddr` (RDX) is rewritten to the loopback listener.
* **`ConnectEx`** (`mswsock.dll`) — the overlapped connect used by **WinHTTP** and other stacks that never reach `connect`. It takes the same `sockaddr` in RDX, so the identical rewrite applies. Its address (exported only as a Winsock extension) is resolved via `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` and armed once `mswsock.dll` maps into the target.
* **`WSAConnectByNameW` / `WSAConnectByNameA`** (`ws2_32.dll`) — resolve-and-connect helpers that never surface a `sockaddr`. Tihulu resolves the real destination itself, then repoints the `nodename` argument at `127.0.0.1` and the `servicename` argument at the relay port. The original hostname is untouched for the upper layer, so TLS **SNI**/`Host` are preserved.

The teed byte stream is fed to a TLS parser that tracks the handshake, extracts the **ClientRandom**, **ServerRandom**, and negotiated **cipher suite**, and identifies when application-data records are available for trial decryption. Connections whose first outbound bytes are not a TLS handshake are relayed verbatim and otherwise ignored.

Once the handshake is complete, Tihulu attempts to recover the session secret using one of two strategies:

### 0. `SSLKEYLOGFILE` injection (free side-channel)

Whenever Tihulu **launches** the target itself and an output directory is configured with `-w`, it sets the `SSLKEYLOGFILE` environment variable in the child to `<dir>\<PID>_SSLKEYLOGFILE.key` before the loader runs. Any TLS library that honours the NSS key-log convention (BoringSSL, NSS, OpenSSL ≥ 1.1.1 built with `enable-ssl-trace`, GnuTLS, rustls via `KeyLogFile::new`, .NET 9+, recent Node.js/Electron builds) will write its own keys to that file in parallel with Tihulu's debugger-based extraction.

Implementation detail: the child is spawned `CREATE_SUSPENDED`, the placeholder PID in the inherited env block is patched in place via `PEB → ProcessParameters → Environment`, then the main thread is resumed. This path is launch-only — when attaching to an already-running process (`--pid`), the env block is already frozen and Tihulu falls back to the debugger-based strategies below.

If the target actually honours the variable, the injected `<dir>\<PID>_SSLKEYLOGFILE.key` file appears. The debugger-based strategies below still run in full regardless — but at end of session Tihulu checks for that file and, if present, prints an extra success message pointing at it. Nothing else ever creates this exact filename (Tihulu's own keys go to a separate `_tls.key` file), so its presence is an unambiguous signal that the target produced a complete, ready-to-use key log of its own alongside Tihulu's extraction.

### 1. CALL-probe scanner (primary)

Tihulu disassembles every executable region of the target process using [iced-x86](https://github.com/icedland/iced) and installs INT3 breakpoints on every `CALL` instruction (up to 200 000 sites). At each hit, it inspects the x86-64 System V / Microsoft ABI argument registers (RCX, RDX, R8, R9):

- If one register holds a value matching the expected secret length (32 bytes for SHA-256 suites, 48 for SHA-384), and
- another register holds a pointer to a readable, high-entropy memory region (preferring private heap/stack over mapped images),

the bytes at that pointer are captured as a **candidate secret**. Candidates are deduplicated by content. Each candidate is then trial-decrypted against a captured TLS application-data record; the one that produces valid plaintext is the master secret (TLS 1.2) or traffic secret (TLS 1.3).

Call-probe breakpoints are dynamically culled: sites that are hit repeatedly without ever producing a viable candidate are removed after 8 non-matching hits, keeping the overhead low.

### 2. Brute-force memory scan (fallback)

When `--fallback-scan` is passed, Tihulu walks every committed, readable, private memory region of the target process (`VirtualQueryEx` + `ReadProcessMemory`) and tests each 48/32-byte window via trial decryption. Scanning is parallelised across all available CPUs using [Rayon](https://github.com/rayon-rs/rayon).

### Output format

Secrets are written in NSS Key Log format:

```
# TLS 1.2
CLIENT_RANDOM <client_random_hex> <master_secret_hex>

# TLS 1.3
CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random_hex> <secret_hex>
SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random_hex> <secret_hex>
CLIENT_TRAFFIC_SECRET_0         <client_random_hex> <secret_hex>
SERVER_TRAFFIC_SECRET_0         <client_random_hex> <secret_hex>
```

Load the resulting file in Wireshark via **Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename** to decrypt captured traffic.

## Installation

Requires a Rust toolchain targeting Windows (nightly or stable ≥ 1.77) and must be compiled and run on Windows x86-64.

```powershell
git clone https://github.com/yourname/tihulu
cd tihulu
cargo build --release
```

The resulting binary is at `target\release\tlsdump.exe`.

## Usage

```
tlsdump [OPTIONS] [-- COMMAND [ARGS...]]
tlsdump [OPTIONS] --pid <PID>
```

### Options

| Flag | Description |
|------|-------------|
| `--pid <PID>` | Attach to a running process by PID |
| `-w <dir>` | Write per-process NSS key logs into `<dir>` (file name: `<PID>_<PROCESS_NAME>_tls.key`) |
| `-v`, `--verbose` | Enable verbose debug logging |
| `-t <N>`, `--threads <N>` | Threads for memory scan (default: number of CPUs) |
| `--fallback-scan` | Enable brute-force memory scan if CALL-probe finds nothing |
| `--no-call-probe` | Skip CALL-probe entirely; use only brute-force scan |
| `--trace-children` | Hook CreateProcess and trace any subprocesses spawned by the target (off by default) |

### Examples

Trace a new process (and any subprocesses it spawns) and write per-process key files into a directory:
```powershell
tlsdump -w keys\ -- curl.exe https://example.com
```
Each traced process produces its own file at `keys\<PID>_<PROCESS_NAME>_tls.key`. When the target spawns a child process, Tihulu re-launches itself against the new PID and propagates the original CLI options.

Attach to a running process and print keys to stdout:
```powershell
tlsdump --pid 1234
```

Attach with verbose output and brute-force fallback enabled:
```powershell
tlsdump --pid 1234 --verbose --fallback-scan -w keys\
```

Once TLS keys have been recovered, Tihulu unhooks every breakpoint and detaches without terminating the target — the process keeps running normally.

## Supported cipher suites

Tihulu covers the full Wireshark TLS cipher suite table and can trial-decrypt records encrypted with:

- **AES-128-GCM**, **AES-256-GCM**
- **ChaCha20-Poly1305**
- AES-CBC (HMAC-SHA256 / HMAC-SHA384) for TLS 1.2

TLS 1.3 per-epoch traffic secrets (handshake + application) are extracted independently as each epoch becomes observable.

## Limitations

* **Memory obfuscation** — A target can trivially evade secret extraction by XOR-masking keys while they are in memory, only unmasking them inside the crypto primitive. A single XOR pass would defeat both scanning strategies.
* **Windows x86-64 only** — The CALL-probe scanner and context capture rely on the Microsoft x64 ABI and Windows Debug API; 32-bit processes are not supported.
* **No kernel-mode TLS** — Traffic handled entirely in kernel mode (e.g., HTTP.sys with kernel TLS offload) is not intercepted.
* **Connection-oriented sockets only** — Interception keys off the TCP connect entry points (`connect`/`WSAConnect`/`ConnectEx`/`WSAConnectByName{W,A}`), so the relay covers connected sockets. Connectionless datagram flows (`sendto`/`recvfrom` without a prior `connect`) are not proxied.

