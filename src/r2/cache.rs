use std::cell::RefCell;
use std::collections::HashMap;
use uuid::Uuid;

use crate::r2::analysis::{self, FunctionDisassembly, FunctionInfo, RelocatableRegion};
use crate::r2::ffi::RCore;
use crate::r2::guid::compute_function_guid;

#[derive(Debug, Clone)]
pub struct XrefInfo {
    pub from: u64,
    pub to: u64,
    pub ref_type: String,
    pub name: Option<String>,
}

pub struct AnalysisCache {
    functions: HashMap<u64, FunctionInfo>,
    /// Map from function address to its xrefs (calls FROM this function)
    func_xrefs: HashMap<u64, Vec<XrefInfo>>,
    guids: RefCell<HashMap<u64, Uuid>>,
    /// Cached disassembly per function (addr -> disassembly with all blocks)
    disassembly_cache: RefCell<HashMap<u64, FunctionDisassembly>>,
    all_funcs_sorted: Vec<u64>,
    regions: Vec<RelocatableRegion>,
    initialized: bool,
}

impl AnalysisCache {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            func_xrefs: HashMap::new(),
            guids: RefCell::new(HashMap::new()),
            disassembly_cache: RefCell::new(HashMap::new()),
            all_funcs_sorted: Vec::new(),
            regions: Vec::new(),
            initialized: false,
        }
    }

    /// Initialize cache with all function info and xrefs
    pub unsafe fn initialize(&mut self, core: *mut RCore) {
        if self.initialized {
            return;
        }

        // Get relocatable regions once
        self.regions = analysis::get_relocatable_regions(core);

        // Get all functions
        let func_addrs = analysis::get_all_functions(core);
        let total = func_addrs.len();

        // Batch fetch function info using aflj
        self.cache_all_functions(core);

        // Sort addresses for adjacency lookups
        self.all_funcs_sorted = func_addrs;
        self.all_funcs_sorted.sort();

        // Batch fetch xrefs and map to containing functions
        self.cache_all_xrefs(core);

        self.initialized = true;

        // Log completion
        let cmd =
            std::ffi::CString::new(format!("echo Cache initialized: {} functions", total)).unwrap();
        crate::r2::ffi::r_core_cmd(core, cmd.as_ptr());
    }

    /// Cache all function info from single aflj call
    unsafe fn cache_all_functions(&mut self, core: *mut RCore) {
        let cmd = std::ffi::CString::new("aflj").unwrap();
        let result = crate::r2::ffi::r_core_cmd_str(core, cmd.as_ptr());

        if result.is_null() {
            return;
        }

        let json_str = std::ffi::CStr::from_ptr(result)
            .to_string_lossy()
            .into_owned();

        crate::r2::ffi::free(result as *mut _);

        if let Ok(funcs) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
            for func in funcs {
                // Try both "offset" and "addr"
                let addr = func
                    .get("offset")
                    .or_else(|| func.get("addr"))
                    .and_then(|v| v.as_u64());

                if let Some(addr) = addr {
                    let name = func
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let size = func.get("size").and_then(|v| v.as_u64()).unwrap_or(0);

                    self.functions
                        .insert(addr, FunctionInfo { addr, size, name });
                }
            }
        }
    }

    /// Find which function contains an address
    fn find_function_containing(&self, addr: u64) -> Option<u64> {
        // Binary search for the function that contains this address
        let idx = self
            .all_funcs_sorted
            .binary_search(&addr)
            .unwrap_or_else(|idx| idx.saturating_sub(1));

        if idx < self.all_funcs_sorted.len() {
            let func_addr = self.all_funcs_sorted[idx];
            if let Some(func) = self.functions.get(&func_addr) {
                // Check if addr is within this function
                if addr >= func.addr && addr < func.addr + func.size {
                    return Some(func_addr);
                }
            }
        }
        None
    }

    /// Cache xrefs for all functions - map xrefs to their containing function
    unsafe fn cache_all_xrefs(&mut self, core: *mut RCore) {
        // Get all xrefs
        let cmd = std::ffi::CString::new("axfj").unwrap();
        let result = crate::r2::ffi::r_core_cmd_str(core, cmd.as_ptr());

        if result.is_null() {
            return;
        }

        let json_str = std::ffi::CStr::from_ptr(result)
            .to_string_lossy()
            .into_owned();

        crate::r2::ffi::free(result as *mut _);

        if let Ok(xrefs) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
            for xref in xrefs {
                let from = xref.get("from").and_then(|v| v.as_u64()).unwrap_or(0);
                let to = xref.get("to").and_then(|v| v.as_u64()).unwrap_or(0);
                let ref_type = xref
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = xref
                    .get("name")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());

                if from != 0 && ref_type == "CALL" {
                    // Find which function contains this call site
                    if let Some(func_addr) = self.find_function_containing(from) {
                        self.func_xrefs
                            .entry(func_addr)
                            .or_default()
                            .push(XrefInfo {
                                from,
                                to,
                                ref_type,
                                name,
                            });
                    }
                }
            }
        }
    }

    /// Get function info from cache
    pub fn get_function(&self, addr: u64) -> Option<&FunctionInfo> {
        self.functions.get(&addr)
    }

    /// Get or compute function GUID
    pub unsafe fn get_or_compute_guid(&self, core: *mut RCore, addr: u64) -> Option<Uuid> {
        // Check if already cached
        if let Some(&guid) = self.guids.borrow().get(&addr) {
            return Some(guid);
        }

        // Get or cache disassembly (efficient - single pdrj call per function)
        let disasm = self.get_or_cache_disassembly(core, addr)?;

        // Compute and cache GUID using pre-cached disassembly
        let guid = compute_function_guid(core, addr, &self.regions, Some(&disasm)).ok()?;
        self.guids.borrow_mut().insert(addr, guid.guid);
        Some(guid.guid)
    }

    /// Get or cache function disassembly (all blocks with instruction bytes)
    pub unsafe fn get_or_cache_disassembly(
        &self,
        core: *mut RCore,
        addr: u64,
    ) -> Option<FunctionDisassembly> {
        // Check cache first
        if let Some(disasm) = self.disassembly_cache.borrow().get(&addr) {
            return Some(disasm.clone());
        }

        // Fetch and cache
        let disasm = analysis::cache_function_disassembly(core, addr)?;
        self.disassembly_cache
            .borrow_mut()
            .insert(addr, disasm.clone());
        Some(disasm)
    }

    /// Get xrefs FROM a function (calls made by this function)
    pub fn get_xrefs_from_function(&self, func_addr: u64) -> &[XrefInfo] {
        self.func_xrefs
            .get(&func_addr)
            .map(|v| v.as_slice())
            .unwrap_or_default()
    }

    /// Get adjacency functions (up to 2 before and after)
    pub fn get_adjacent_functions(&self, addr: u64) -> Vec<u64> {
        let mut adjacent = Vec::new();

        if let Ok(pos) = self.all_funcs_sorted.binary_search(&addr) {
            // Up to 2 before
            let start = pos.saturating_sub(2);
            for i in start..pos {
                adjacent.push(self.all_funcs_sorted[i]);
            }

            // Up to 2 after
            let end = (pos + 3).min(self.all_funcs_sorted.len());
            for i in (pos + 1)..end {
                adjacent.push(self.all_funcs_sorted[i]);
            }
        }

        adjacent
    }

    /// Get all function addresses (sorted)
    pub fn get_all_functions(&self) -> &[u64] {
        &self.all_funcs_sorted
    }

    /// Check if address is an internal function
    pub fn is_internal_function(&self, addr: u64) -> bool {
        self.functions.contains_key(&addr)
    }

    /// Get relocatable regions
    pub fn get_regions(&self) -> &[RelocatableRegion] {
        &self.regions
    }

    /// Clear cache
    pub fn clear(&mut self) {
        self.functions.clear();
        self.func_xrefs.clear();
        self.guids.borrow_mut().clear();
        self.disassembly_cache.borrow_mut().clear();
        self.all_funcs_sorted.clear();
        self.regions.clear();
        self.initialized = false;
    }

    /// Get cache stats
    pub fn stats(&self) -> (usize, usize, usize, usize) {
        (
            self.functions.len(),
            self.guids.borrow().len(),
            self.func_xrefs.len(),
            self.disassembly_cache.borrow().len(),
        )
    }
}

impl Default for AnalysisCache {
    fn default() -> Self {
        Self::new()
    }
}
