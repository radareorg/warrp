use std::collections::HashSet;

use crate::r2::ffi::RCore;
use crate::r2::analysis;
use crate::warp::signature::{Constraint, FunctionGUID, Symbol, SymbolClass};

pub struct ConstraintBuilder;

impl ConstraintBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Collect call site constraints for a function.
    /// 
    /// For each call instruction in the function, we create a constraint
    /// based on the called function (if internal) or symbol (if external/import).
    pub unsafe fn call_site_constraints(
        &self,
        core: *mut RCore,
        func_addr: u64,
        regions: &[analysis::RelocatableRegion],
    ) -> HashSet<Constraint> {
        let mut constraints = HashSet::new();
        
        // Get function info to calculate offsets relative to function start
        let func_info = match analysis::get_function_at(core, func_addr) {
            Some(info) => info,
            None => return constraints,
        };
        
        let func_start = func_info.addr;
        
        // Get xrefs from this function using axffj (xrefs from function JSON)
        let cmd = std::ffi::CString::new(format!("axffj @ 0x{:x}", func_addr)).unwrap();
        let result = crate::r2::ffi::r_core_cmd_str(core, cmd.as_ptr());
        
        if result.is_null() {
            return constraints;
        }
        
        let json_str = std::ffi::CStr::from_ptr(result)
            .to_string_lossy()
            .into_owned();
        
        crate::r2::ffi::free(result as *mut _);
        
        // Handle empty response
        if json_str.trim().is_empty() {
            return constraints;
        }
        
        // Parse xrefs JSON
        let xrefs: Vec<serde_json::Value> = match serde_json::from_str(&json_str) {
            Ok(arr) => arr,
            Err(_) => return constraints,
        };
        
        for xref in xrefs {
            let ref_type = xref.get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            
            // Only process CALL references
            if ref_type != "CALL" {
                continue;
            }
            
            let call_site = xref.get("at")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            
            let call_target = xref.get("ref")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            
            if call_target == 0 {
                continue;
            }
            
            // Calculate offset relative to function start
            let call_site_offset: i64 = call_site as i64 - func_start as i64;
            
            // Check if target is an internal function
            if let Some(target_func) = analysis::get_function_at(core, call_target) {
                // Internal function - create GUID constraint
                if target_func.addr != func_start {
                    if let Ok(guid) = crate::r2::guid::compute_function_guid(core, call_target, regions) {
                        let constraint = Constraint::from_function(
                            &FunctionGUID::from_uuid(guid.guid),
                            Some(call_site_offset),
                        );
                        constraints.insert(constraint);
                    }
                }
            } else {
                // External/import - create symbol constraint
                // Try to get the name from the xref itself
                if let Some(name) = xref.get("name").and_then(|n| n.as_str()) {
                    let cleaned_name = clean_symbol_name(name);
                    let symbol = Symbol::new(cleaned_name, SymbolClass::Function);
                    let constraint = Constraint::from_symbol(&symbol, Some(call_site_offset));
                    constraints.insert(constraint);
                }
            }
        }
        
        constraints
    }

    /// Collect adjacency constraints for a function.
    /// 
    /// We look at functions immediately before and after this function
    /// and create constraints based on their GUIDs and symbols.
    pub unsafe fn adjacency_constraints(
        &self,
        core: *mut RCore,
        func_addr: u64,
        regions: &[analysis::RelocatableRegion],
    ) -> HashSet<Constraint> {
        let mut constraints = HashSet::new();
        
        // Get all functions sorted by address
        let all_funcs = analysis::get_all_functions(core);
        let mut sorted_funcs: Vec<u64> = all_funcs.into_iter().collect();
        sorted_funcs.sort();
        
        // Find position of current function
        let pos = match sorted_funcs.binary_search(&func_addr) {
            Ok(p) => p,
            Err(_) => return constraints,
        };
        
        // Look at up to 2 functions before
        let start = pos.saturating_sub(2);
        for i in start..pos {
            let adj_addr = sorted_funcs[i];
            if adj_addr != func_addr {
                self.add_adjacency_constraint(core, adj_addr, func_addr, regions, &mut constraints);
            }
        }
        
        // Look at up to 2 functions after
        let end = (pos + 3).min(sorted_funcs.len());
        for i in (pos + 1)..end {
            let adj_addr = sorted_funcs[i];
            if adj_addr != func_addr {
                self.add_adjacency_constraint(core, adj_addr, func_addr, regions, &mut constraints);
            }
        }
        
        constraints
    }

    unsafe fn add_adjacency_constraint(
        &self,
        core: *mut RCore,
        adj_addr: u64,
        func_addr: u64,
        regions: &[analysis::RelocatableRegion],
        constraints: &mut HashSet<Constraint>,
    ) {
        let offset = adj_addr as i64 - func_addr as i64;
        
        // Add GUID constraint
        if let Ok(guid) = crate::r2::guid::compute_function_guid(core, adj_addr, regions) {
            let constraint = Constraint::from_function(
                &FunctionGUID::from_uuid(guid.guid),
                Some(offset),
            );
            constraints.insert(constraint);
        }
        
        // Add symbol constraint
        if let Some(adj_info) = analysis::get_function_at(core, adj_addr) {
            if let Some(name) = adj_info.name {
                let cleaned_name = clean_symbol_name(&name);
                let symbol = Symbol::new(cleaned_name, SymbolClass::Function);
                let constraint = Constraint::from_symbol(&symbol, Some(offset));
                constraints.insert(constraint);
            }
        }
    }

    /// Get symbol name at an address
    unsafe fn get_symbol_at(&self, core: *mut RCore, addr: u64) -> Option<String> {
        let cmd = std::ffi::CString::new(format!("is.j @ 0x{:x}", addr)).unwrap();
        let result = crate::r2::ffi::r_core_cmd_str(core, cmd.as_ptr());
        
        if result.is_null() {
            return None;
        }
        
        let json_str = std::ffi::CStr::from_ptr(result)
            .to_string_lossy()
            .into_owned();
        
        crate::r2::ffi::free(result as *mut _);
        
        // Parse symbol JSON
        let symbols: Vec<serde_json::Value> = match serde_json::from_str(&json_str) {
            Ok(arr) => arr,
            Err(_) => return None,
        };
        
        symbols.first()
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string())
    }
}

impl Default for ConstraintBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Clean symbol name by removing common prefixes and suffixes.
///
/// Examples:
/// - "__imp__RemoveDirectoryW@4" -> "RemoveDirectoryW"
/// - "__free_base" -> "free_base"
/// - "j___free_base" -> "free_base"
/// - "sym.func_name" -> "func_name"
pub fn clean_symbol_name(symbol_name: &str) -> String {
    let mut result = symbol_name;
    
    // Strip radare2 prefixes (sym., imp., etc.)
    for prefix in &["sym.", "imp.", "fcn."] {
        if result.starts_with(prefix) {
            result = &result[prefix.len()..];
            break;
        }
    }
    
    // Handle MSVC-style imported symbols
    if result.starts_with("__imp__") {
        result = &result[7..];
    }
    
    // Handle jump thunk prefix
    if result.starts_with("j_") {
        result = &result[2..];
    }
    
    // Strip leading underscores (but keep at least one if the name would be empty)
    while result.starts_with('_') && result.len() > 1 {
        result = &result[1..];
    }
    
    // Remove stdcall decoration (@N suffix)
    match result.find('@') {
        Some(pos) => result[..pos].to_string(),
        None => result.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_symbol_name() {
        assert_eq!(clean_symbol_name("sym.free"), "free");
        assert_eq!(clean_symbol_name("imp.free"), "free");
        assert_eq!(clean_symbol_name("__imp__RemoveDirectoryW@4"), "RemoveDirectoryW");
        assert_eq!(clean_symbol_name("j___free_base"), "free_base");
        assert_eq!(clean_symbol_name("fcn.0x1234"), "0x1234");
    }
}