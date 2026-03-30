use std::ffi::CString;

use crate::r2::ffi::{RCore, r_core_cmd, r_core_cmd_str, free};

pub struct RelocatableRegion {
    pub start: u64,
    pub end: u64,
}

pub struct FunctionInfo {
    pub addr: u64,
    pub size: u64,
    pub name: Option<String>,
}

pub struct BasicBlockInfo {
    pub addr: u64,
    pub size: u64,
}

/// Get all functions in the current binary
pub unsafe fn get_all_functions(core: *mut RCore) -> Vec<u64> {
    let mut functions = Vec::new();
    
    // Use r_core_cmd to get function list as JSON
    let cmd = CString::new("aflj").unwrap();
    let result = r_core_cmd_str(core, cmd.as_ptr());
    
    if result.is_null() {
        return functions;
    }
    
    let json_str = std::ffi::CStr::from_ptr(result)
        .to_string_lossy()
        .into_owned();
    
    free(result as *mut _);
    
    // Parse JSON array of functions
    if let Ok(funcs) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
        for func in funcs {
            // Try both "offset" and "addr" fields (r2 uses different field names)
            let addr = func.get("offset")
                .or_else(|| func.get("addr"))
                .and_then(|v| v.as_u64());
            
            if let Some(addr) = addr {
                functions.push(addr);
            }
        }
    }
    
    functions
}

/// Get function at address
pub unsafe fn get_function_at(core: *mut RCore, addr: u64) -> Option<FunctionInfo> {
    let cmd = CString::new(format!("afij @ 0x{:x}", addr)).unwrap();
    let result = r_core_cmd_str(core, cmd.as_ptr());
    
    if result.is_null() {
        return None;
    }
    
    let json_str = std::ffi::CStr::from_ptr(result)
        .to_string_lossy()
        .into_owned();
    
    free(result as *mut _);
    
    // Parse JSON (may be null or array)
    let funcs = serde_json::from_str::<Vec<serde_json::Value>>(&json_str).ok()?;
    
    if funcs.is_empty() {
        return None;
    }
    
    let func = &funcs[0];
    Some(FunctionInfo {
        addr: func.get("offset")?.as_u64()?,
        size: func.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
        name: func.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()),
    })
}

/// Get basic blocks for a function
pub unsafe fn get_function_blocks(core: *mut RCore, addr: u64) -> Vec<BasicBlockInfo> {
    let mut blocks = Vec::new();
    
    let cmd = CString::new(format!("afbj @ 0x{:x}", addr)).unwrap();
    let result = r_core_cmd_str(core, cmd.as_ptr());
    
    if result.is_null() {
        return blocks;
    }
    
    let json_str = std::ffi::CStr::from_ptr(result)
        .to_string_lossy()
        .into_owned();
    
    free(result as *mut _);
    
    // Parse JSON array of blocks
    if let Ok(block_arr) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
        for block in block_arr {
            if let (Some(addr), Some(size)) = (
                block.get("addr").and_then(|v| v.as_u64()),
                block.get("size").and_then(|v| v.as_u64()),
            ) {
                blocks.push(BasicBlockInfo { addr, size });
            }
        }
    }
    
    blocks
}

/// Disassemble instructions at address and return raw bytes
pub unsafe fn disassemble_at(core: *mut RCore, addr: u64, _size: u64) -> Vec<Vec<u8>> {
    let mut instructions = Vec::new();
    
    // Use pDrj to get disassembly with bytes (capital D includes bytes field)
    let cmd = CString::new(format!("pDrj @ 0x{:x}", addr)).unwrap();
    let result = r_core_cmd_str(core, cmd.as_ptr());
    
    if result.is_null() {
        return instructions;
    }
    
    let json_str = std::ffi::CStr::from_ptr(result)
        .to_string_lossy()
        .into_owned();
    
    free(result as *mut _);
    
    // The output is a JSON object with "ops" array or "bbs" array
    // Try to parse as object with ops
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&json_str) {
        // Try "ops" array first (flat format)
        if let Some(ops) = obj.get("ops").and_then(|v| v.as_array()) {
            for op in ops {
                if let Some(bytes_hex) = op.get("bytes").and_then(|v| v.as_str()) {
                    if !bytes_hex.is_empty() {
                        if let Ok(bytes) = hex::decode(bytes_hex) {
                            instructions.push(bytes);
                        }
                    }
                }
            }
        }
        // Try "bbs" array (block format)
        else if let Some(bbs) = obj.get("bbs").and_then(|v| v.as_array()) {
            for bb in bbs {
                if let Some(ops) = bb.get("ops").and_then(|v| v.as_array()) {
                    for op in ops {
                        if let Some(bytes_hex) = op.get("bytes").and_then(|v| v.as_str()) {
                            if !bytes_hex.is_empty() {
                                if let Ok(bytes) = hex::decode(bytes_hex) {
                                    instructions.push(bytes);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    instructions
}

/// Get relocatable regions from sections/segments
pub unsafe fn get_relocatable_regions(core: *mut RCore) -> Vec<RelocatableRegion> {
    let mut regions = Vec::new();
    
    // Get sections (executable and writable)
    let cmd = CString::new("iSj").unwrap();
    let result = r_core_cmd_str(core, cmd.as_ptr());
    
    if result.is_null() {
        return regions;
    }
    
    let json_str = std::ffi::CStr::from_ptr(result)
        .to_string_lossy()
        .into_owned();
    
    free(result as *mut _);
    
    if let Ok(sections) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
        for section in sections {
            if let (Some(vaddr), Some(size)) = (
                section.get("vaddr").and_then(|v| v.as_u64()),
                section.get("vsize").and_then(|v| v.as_u64()),
            ) {
                // Include all sections as potential relocatable regions
                // In practice, you'd filter to executable and/or writable sections
                regions.push(RelocatableRegion {
                    start: vaddr,
                    end: vaddr + size,
                });
            }
        }
    }
    
    regions
}

/// Get current architecture info
pub unsafe fn get_arch_info(core: *mut RCore) -> (String, String) {
    let cmd = CString::new("ij").unwrap();
    let result = r_core_cmd_str(core, cmd.as_ptr());
    
    let mut arch = "unknown".to_string();
    let mut platform = "unknown".to_string();
    
    if !result.is_null() {
        let json_str = std::ffi::CStr::from_ptr(result)
            .to_string_lossy()
            .into_owned();
        
        free(result as *mut _);
        
        if let Ok(info) = serde_json::from_str::<serde_json::Value>(&json_str) {
            if let Some(bin) = info.get("bin") {
                arch = bin.get("arch")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                let os = bin.get("os")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                
                let bits = bin.get("bits")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(64);
                
                platform = format!("{}-{}", os, bits);
            }
        }
    }
    
    (arch, platform)
}

/// Check if interactive mode is enabled
pub unsafe fn is_interactive(core: *mut RCore) -> bool {
    let cmd = CString::new("e scr.interactive").unwrap();
    let result = r_core_cmd_str(core, cmd.as_ptr());
    
    if result.is_null() {
        return false;
    }
    
    let value = std::ffi::CStr::from_ptr(result)
        .to_string_lossy()
        .into_owned();
    
    free(result as *mut _);
    
    value.trim() == "true"
}

/// Apply function metadata from WARP
pub unsafe fn apply_function_metadata(
    core: *mut RCore,
    addr: u64,
    warp_func: &crate::warp::signature::Function,
) -> bool {
    // Apply name
    let name = &warp_func.symbol.name;
    if !name.is_empty() {
        let cmd = CString::new(format!("afn {} @ 0x{:x}", name, addr)).unwrap();
        r_core_cmd(core, cmd.as_ptr());
    }
    
    // Apply comments
    for comment in &warp_func.comments {
        let offset = comment.offset as u64;
        let text = &comment.text;
        let cmd = CString::new(format!("CC {} @ 0x{:x}", text, addr + offset)).unwrap();
        r_core_cmd(core, cmd.as_ptr());
    }
    
    // TODO: Apply type information (requires type parsing)
    
    true
}

/// Simple hex decoder module
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
        if s.len() % 2 != 0 {
            return Err("Invalid hex string length");
        }
        
        let mut bytes = Vec::with_capacity(s.len() / 2);
        let mut chars = s.chars();
        
        while let (Some(h), Some(l)) = (chars.next(), chars.next()) {
            let high = h.to_digit(16).ok_or("Invalid hex digit")? as u8;
            let low = l.to_digit(16).ok_or("Invalid hex digit")? as u8;
            bytes.push((high << 4) | low);
        }
        
        Ok(bytes)
    }
}