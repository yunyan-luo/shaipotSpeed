//! C++ CPU Hamiltonian path searcher FFI bindings

use std::ffi::CString;
use std::os::raw::c_char;

// C API declarations
#[repr(C)]
pub struct HamiltonianSearcherCPU {
    _private: [u8; 0],
}

pub const HC_GRAPH_SIZE: usize = 2008;

extern "C" {
    // Hugepage memory pool management
    fn hc_cpu_init_hugepages(pool_size_mb: usize) -> i32;

    fn hc_cpu_create() -> *mut HamiltonianSearcherCPU;
    fn hc_cpu_destroy(searcher: *mut HamiltonianSearcherCPU);

    // Full search: run HC1 + HC2 sequentially
    fn hc_cpu_search_full(
        searcher: *mut HamiltonianSearcherCPU,
        first_hash_hex: *const c_char,
        worker_percentage_x10: u16,
        queen_percentage_x10: u16,
        max_worker_paths: u16,
        data_hex: *const c_char,
        target_hex: *const c_char,
        out_path: *mut u16,
        out_path_len: *mut usize,
        out_solution_hex: *mut c_char,
        out_hash_count: *mut u64,
        job_version: *const u64,
        expected_version: u64,
    ) -> i32;
}

/// C++ CPU searcher wrapper
pub struct CppSearcher {
    inner: *mut HamiltonianSearcherCPU,
}

unsafe impl Send for CppSearcher {}

/// Initialize the hugepage memory pool.
/// pool_size_mb: pool size (MB)
/// Returns: true if hugepages are used, false if it falls back to regular pages.
pub fn init_hugepages(pool_size_mb: usize) -> bool {
    let result = unsafe { hc_cpu_init_hugepages(pool_size_mb) };
    result == 1
}

impl CppSearcher {
    pub fn new() -> Option<Self> {
        let inner = unsafe { hc_cpu_create() };
        if inner.is_null() {
            None
        } else {
            Some(CppSearcher { inner })
        }
    }

    /// Full search: run HC1 + HC2 sequentially.
    /// Returns: (status, path, solution_hex, hash_count)
    /// status: 0=HC1 failed, 1=valid solution found, 2=exhausted without solution, 3=canceled due to job change
    pub fn search_full(
        &self,
        first_hash_hex: &str,
        worker_percentage_x10: u16,
        queen_percentage_x10: u16,
        max_worker_paths: u16,
        data_hex: &str,
        target_hex: &str,
        job_version: Option<&std::sync::atomic::AtomicU64>,
        expected_version: u64,
    ) -> (i32, Vec<u16>, String, u64) {
        if self.inner.is_null() {
            return (0, Vec::new(), String::new(), 0);
        }

        let c_first_hash = CString::new(first_hash_hex).unwrap();
        let c_data = CString::new(data_hex).unwrap();
        let c_target = CString::new(target_hex).unwrap();

        let mut out_path = vec![0u16; HC_GRAPH_SIZE];
        let mut out_path_len: usize = 0;
        let mut out_solution_hex = vec![0u8; HC_GRAPH_SIZE * 4 + 1];
        let mut out_hash_count: u64 = 0;

        let job_version_ptr = match job_version {
            Some(atomic) => atomic.as_ptr(),
            None => std::ptr::null(),
        };

        let status = unsafe {
            hc_cpu_search_full(
                self.inner,
                c_first_hash.as_ptr(),
                worker_percentage_x10,
                queen_percentage_x10,
                max_worker_paths,
                c_data.as_ptr(),
                c_target.as_ptr(),
                out_path.as_mut_ptr(),
                &mut out_path_len,
                out_solution_hex.as_mut_ptr() as *mut c_char,
                &mut out_hash_count,
                job_version_ptr,
                expected_version,
            )
        };

        out_path.truncate(out_path_len);

        let solution_hex = {
            let len = out_solution_hex
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(out_solution_hex.len());
            String::from_utf8_lossy(&out_solution_hex[..len]).to_string()
        };

        (status, out_path, solution_hex, out_hash_count)
    }
}

impl Drop for CppSearcher {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            unsafe { hc_cpu_destroy(self.inner) };
        }
    }
}
