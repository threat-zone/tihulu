//! CALL-instruction breakpoint scanner.
//!
//! Instead of brute-force scanning the entire heap for TLS secrets, this
//! module places INT3 on every CALL instruction inside allow-listed modules
//! and inspects x64 register arguments (RCX, RDX, R8, R9) at each hit.
//!
//! A CALL is considered a secret-carrying candidate when:
//!   1. one argument register holds exactly one of the plausible TLS secret
//!      lengths ([`SECRET_LENS`]: 32 for SHA-256 ciphers, 48 for SHA-384 /
//!      the TLS 1.2 master secret), AND
//!   2. another argument register holds a pointer to a readable memory
//!      region (MEM_PRIVATE heap/stack is preferred over MEM_IMAGE).
//!
//! Because the scanner is armed as soon as a ClientHello is seen — before the
//! negotiated cipher (and thus the true secret length) is known — it harvests
//! candidates for *every* length in [`SECRET_LENS`]. The matching length's
//! worth of bytes at that pointer are captured as a candidate secret.
//! Candidates are deduplicated by content. When a TLS record is available for
//! trial decryption, every candidate of the cipher's actual length is tested.

#![cfg(windows)]

use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, Mnemonic};

use crate::memory_reader::{self, MemoryReader, PtrClass};


/// Plausible TLS secret lengths to harvest. 32 covers SHA-256 TLS 1.3
/// traffic secrets; 48 covers SHA-384 TLS 1.3 traffic secrets and the TLS 1.2
/// master secret. The scanner arms before the cipher is negotiated, so it
/// captures candidates of every length here and lets trial decryption pick.
pub const SECRET_LENS: [usize; 2] = [32, 48];

/// Number of non-matching hits after which a CALL BP is culled.
pub const CULL_THRESHOLD: u32 = 8;

/// Minimum distinct byte values required in a candidate buffer. Anything
/// below this (e.g. zero pages, ASCII text) is rejected as low-entropy.
pub const MIN_DISTINCT_BYTES: usize = 16;

/// Modules we allow CALL probing inside by default. Currently unused (the
/// scanner probes every executable region), but kept for potential future
/// use as a faster, narrower probe mode.
#[allow(dead_code)]
pub const DEFAULT_TLS_MODULES: &[&str] = &[
    "schannel.dll",
    "ncrypt.dll",
    "ncryptsslp.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "cryptsp.dll",
    "lsasrv.dll",
    // .NET
    "clr.dll",
    "coreclr.dll",
    "system.security.cryptography.native.dll",
    // OpenSSL / curl commonly bundled
    "libssl-3.dll",
    "libssl-3-x64.dll",
    "libcrypto-3.dll",
    "libcrypto-3-x64.dll",
    "ssleay32.dll",
    "libeay32.dll",
    // Go/Rust static TLS — main image is always allowed separately
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Phase {
    WaitingHandshake,
    Harvesting,
    Decrypting,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgReg {
    Rcx,
    Rdx,
    R8,
    R9,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Candidate {
    pub bytes: Vec<u8>,
    pub src_ptr: u64,
    pub call_site: u64,
    pub reg_ptr: ArgReg,
    pub reg_len: ArgReg,
    pub in_private: bool,
    pub hits: u32,
}

#[allow(dead_code)]
pub struct CallScanner {
    /// Original instruction byte per armed CALL site (address → byte).
    pub bps: HashMap<u64, u8>,
    /// Per-site hit counter for dynamic culling.
    pub hit_count: HashMap<u64, u32>,
    /// Per-site "ever matched" flag.
    pub ever_matched: HashMap<u64, bool>,
    /// Candidates keyed by a small hash of the bytes (first 8 bytes XOR last 8).
    pub candidates: HashMap<u64, Candidate>,
    /// Readable ranges snapshot, private (heap/stack) and shared (image).
    pub private_ranges: Vec<(u64, u64)>,
    pub shared_ranges: Vec<(u64, u64)>,
    pub phase: Phase,
    /// Hits counted toward the "keep harvesting after app-data" grace window.
    pub bps_hit_since_appdata: u32,
    pub verbose: bool,
}

impl CallScanner {
    pub fn new(verbose: bool) -> Self {
        Self {
            bps: HashMap::new(),
            hit_count: HashMap::new(),
            ever_matched: HashMap::new(),
            candidates: HashMap::new(),
            private_ranges: Vec::new(),
            shared_ranges: Vec::new(),
            phase: Phase::WaitingHandshake,
            bps_hit_since_appdata: 0,
            verbose,
        }
    }

    pub fn is_armed(&self) -> bool {
        matches!(self.phase, Phase::Harvesting | Phase::Decrypting)
    }

    pub fn classify(&self, ptr: u64) -> Option<PtrClass> {
        memory_reader::classify_ptr(&self.private_ranges, &self.shared_ranges, ptr)
    }

    /// Refresh the readable-range snapshot. Must be called while the target
    /// is suspended so the enumeration is consistent.
    pub fn refresh_ranges(&mut self, reader: &MemoryReader) {
        let (priv_r, shared_r) = reader.snapshot_readable_ranges();
        self.private_ranges = priv_r;
        self.shared_ranges = shared_r;
    }

    /// Decode an executable region and return all CALL instruction IPs.
    pub fn collect_call_sites(bytes: &[u8], base: u64, out: &mut Vec<u64>) {
        let mut dec = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
        let mut insn = iced_x86::Instruction::default();
        while dec.can_decode() {
            dec.decode_out(&mut insn);
            if insn.is_invalid() {
                continue;
            }
            if insn.mnemonic() == Mnemonic::Call {
                out.push(insn.ip());
            }
        }
    }

    /// Record a possible candidate observed at a CALL breakpoint hit.
    /// `bytes` must be one of the [`SECRET_LENS`] and already sampled from the
    /// target process at `src_ptr`. Returns true if newly recorded.
    pub fn record_candidate(
        &mut self,
        bytes: Vec<u8>,
        src_ptr: u64,
        call_site: u64,
        reg_ptr: ArgReg,
        reg_len: ArgReg,
        in_private: bool,
    ) -> bool {
        if !SECRET_LENS.contains(&bytes.len()) {
            return false;
        }
        if !has_entropy(&bytes, MIN_DISTINCT_BYTES) {
            return false;
        }
        let key = candidate_key(&bytes);
        if let Some(existing) = self.candidates.get_mut(&key) {
            existing.hits += 1;
            return false;
        }
        self.candidates.insert(
            key,
            Candidate {
                bytes,
                src_ptr,
                call_site,
                reg_ptr,
                reg_len,
                in_private,
                hits: 1,
            },
        );
        self.ever_matched.insert(call_site, true);
        true
    }

    /// Register a hit on a CALL site (matched or not). Returns true if this
    /// site should be culled (unarmed) because it has produced no matches
    /// after CULL_THRESHOLD hits.
    pub fn note_hit_and_should_cull(&mut self, call_site: u64) -> bool {
        let c = self.hit_count.entry(call_site).or_insert(0);
        *c += 1;
        let matched = self.ever_matched.get(&call_site).copied().unwrap_or(false);
        !matched && *c >= CULL_THRESHOLD
    }

    /// Iterate candidates sorted with highest-priority (private-heap,
    /// multi-hit) first.
    pub fn ranked_candidates(&self) -> Vec<&Candidate> {
        let mut v: Vec<&Candidate> = self.candidates.values().collect();
        v.sort_by(|a, b| {
            b.in_private
                .cmp(&a.in_private)
                .then_with(|| b.hits.cmp(&a.hits))
        });
        v
    }
}

/// Count distinct byte values; rough entropy check.
fn has_entropy(data: &[u8], min_distinct: usize) -> bool {
    let mut seen = [false; 256];
    let mut count = 0;
    for &b in data {
        if !seen[b as usize] {
            seen[b as usize] = true;
            count += 1;
            if count >= min_distinct {
                return true;
            }
        }
    }
    false
}

fn candidate_key(data: &[u8]) -> u64 {
    // FNV-1a for dedup keying. Collisions don't affect correctness (the
    // trial decrypt will reject wrong secrets anyway) but this keeps the
    // candidate map small and O(1) for insert.
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Returns true if `name` (case-insensitive) matches any entry in `list` or
/// is the main image (base_is_main == true).
#[allow(dead_code)]
pub fn module_is_allowlisted(name: &str, list: &[&str], is_main_image: bool) -> bool {
    if is_main_image {
        return true;
    }
    let lname = name.to_ascii_lowercase();
    for &m in list {
        if lname == m || lname.ends_with(&format!("\\{}", m)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_call_instructions() {
        // Near CALL rel32: E8 ?? ?? ?? ??
        // Indirect CALL: FF 15 ?? ?? ?? ?? (call [rip+disp32])
        let bytes = &[
            0x90, // nop
            0xE8, 0x05, 0x00, 0x00, 0x00, // call +5
            0x90, // nop
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // call [rip+0]
            0xC3, // ret
        ];
        let mut sites = Vec::new();
        CallScanner::collect_call_sites(bytes, 0x1000, &mut sites);
        assert_eq!(sites, vec![0x1001, 0x1007]);
    }

    #[test]
    fn entropy_filter_rejects_zeros() {
        let zeros = vec![0u8; 32];
        assert!(!has_entropy(&zeros, MIN_DISTINCT_BYTES));
    }

    #[test]
    fn entropy_filter_accepts_random() {
        let mut data = Vec::with_capacity(32);
        for i in 0..32u8 {
            data.push(i.wrapping_mul(37).wrapping_add(11));
        }
        assert!(has_entropy(&data, MIN_DISTINCT_BYTES));
    }
}
