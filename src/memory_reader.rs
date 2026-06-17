//! Process memory reader for Windows.
//!
//! Uses VirtualQueryEx to enumerate committed memory regions and raw FFI
//! ReadProcessMemory to read them. Equivalent to Linux /proc/<pid>/maps +
//! process_vm_readv.

#![cfg(windows)]

use windows::Win32::Foundation::*;
use windows::Win32::System::Memory::*;

use std::mem;

// Raw FFI for ReadProcessMemory (avoids feature-flag issues)
extern "system" {
    fn ReadProcessMemory(
        h: HANDLE,
        base: *const std::ffi::c_void,
        buf: *mut std::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> BOOL;
}

/// A contiguous committed memory region.
pub struct MemoryRegion {
    pub base: u64,
    pub size: usize,
    /// True for MEM_PRIVATE regions (heap/stack), false for MEM_IMAGE/MEM_MAPPED.
    pub is_private: bool,
}

/// Classification of a pointer's target region for the call-probe scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtrClass {
    /// Pointer into a MEM_PRIVATE readable region (heap/stack).
    Private,
    /// Pointer into a readable MEM_IMAGE/MEM_MAPPED region.
    Shared,
}

pub struct MemoryReader {
    handle: HANDLE,
    _pid: u32,
}

// ReadProcessMemory is thread-safe against the same target handle, and the
// handle itself is a kernel handle that can be shared by multiple threads.
unsafe impl Send for MemoryReader {}
unsafe impl Sync for MemoryReader {}

impl MemoryReader {
    pub fn new(handle: HANDLE, pid: u32) -> Self {
        Self { handle, _pid: pid }
    }

    /// Enumerate all committed, readable regions.
    pub fn get_memory_regions(&self) -> Vec<MemoryRegion> {
        let mut regions = Vec::new();
        let mut addr: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        let mbi_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

        loop {
            let ret = unsafe {
                VirtualQueryEx(self.handle, Some(addr as *const _), &mut mbi, mbi_size)
            };
            if ret == 0 {
                break;
            }

            // Only consider committed, non-guard, non-noaccess read+write regions
            if mbi.State == MEM_COMMIT
                && (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == PAGE_PROTECTION_FLAGS(0)
                && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != PAGE_PROTECTION_FLAGS(0)
            {
                regions.push(MemoryRegion {
                    base: mbi.BaseAddress as u64,
                    size: mbi.RegionSize,
                    is_private: mbi.Type.0 == 0x20000, // MEM_PRIVATE
                });
            }

            addr = mbi.BaseAddress as usize + mbi.RegionSize;
            if addr == 0 {
                break;
            }
        }
        // Sort heap-candidate (MEM_PRIVATE) regions first for faster secret search.
        regions.sort_by_key(|r| if r.is_private { 0u8 } else { 1 });
        regions
    }

    /// Read a memory region into a Vec.
    pub fn read_region(&self, region: &MemoryRegion) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; region.size];
        let mut bytes_read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                region.base as *const _,
                buffer.as_mut_ptr() as *mut _,
                region.size,
                &mut bytes_read,
            )
            .as_bool()
        };
        if ok {
            buffer.truncate(bytes_read);
            Some(buffer)
        } else {
            None
        }
    }

    /// Enumerate all committed, executable regions. Used by the call-probe
    /// scanner to disassemble code and place INT3 on CALL instructions.
    pub fn get_executable_regions(&self) -> Vec<MemoryRegion> {
        let mut regions = Vec::new();
        let mut addr: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        let mbi_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

        loop {
            let ret = unsafe {
                VirtualQueryEx(self.handle, Some(addr as *const _), &mut mbi, mbi_size)
            };
            if ret == 0 {
                break;
            }

            let exec_mask =
                PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
            if mbi.State == MEM_COMMIT
                && (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == PAGE_PROTECTION_FLAGS(0)
                && (mbi.Protect & exec_mask) != PAGE_PROTECTION_FLAGS(0)
            {
                regions.push(MemoryRegion {
                    base: mbi.BaseAddress as u64,
                    size: mbi.RegionSize,
                    is_private: mbi.Type.0 == 0x20000,
                });
            }

            addr = mbi.BaseAddress as usize + mbi.RegionSize;
            if addr == 0 {
                break;
            }
        }
        regions
    }

    /// Snapshot readable regions for pointer-classification. Returns two
    /// sorted (base, end) range lists: private (heap/stack-like) and shared
    /// (image/mapped), both readable.
    pub fn snapshot_readable_ranges(&self) -> (Vec<(u64, u64)>, Vec<(u64, u64)>) {
        let mut private = Vec::new();
        let mut shared = Vec::new();
        let mut addr: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        let mbi_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

        let readable = PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY;

        loop {
            let ret = unsafe {
                VirtualQueryEx(self.handle, Some(addr as *const _), &mut mbi, mbi_size)
            };
            if ret == 0 {
                break;
            }
            if mbi.State == MEM_COMMIT
                && (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == PAGE_PROTECTION_FLAGS(0)
                && (mbi.Protect & readable) != PAGE_PROTECTION_FLAGS(0)
            {
                let base = mbi.BaseAddress as u64;
                let end = base + mbi.RegionSize as u64;
                if mbi.Type.0 == 0x20000 {
                    private.push((base, end));
                } else {
                    shared.push((base, end));
                }
            }
            addr = mbi.BaseAddress as usize + mbi.RegionSize;
            if addr == 0 {
                break;
            }
        }
        private.sort_unstable();
        shared.sort_unstable();
        (private, shared)
    }
}

/// Classify a pointer as pointing into a private or shared readable region,
/// or neither. Ranges must be sorted ascending by base.
pub fn classify_ptr(
    private: &[(u64, u64)],
    shared: &[(u64, u64)],
    ptr: u64,
) -> Option<PtrClass> {
    if in_ranges(private, ptr) {
        Some(PtrClass::Private)
    } else if in_ranges(shared, ptr) {
        Some(PtrClass::Shared)
    } else {
        None
    }
}

fn in_ranges(ranges: &[(u64, u64)], ptr: u64) -> bool {
    // Binary search for the greatest base <= ptr.
    let idx = match ranges.binary_search_by_key(&ptr, |&(b, _)| b) {
        Ok(i) => i,
        Err(0) => return false,
        Err(i) => i - 1,
    };
    let (base, end) = ranges[idx];
    ptr >= base && ptr < end
}
