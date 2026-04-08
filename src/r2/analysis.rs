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

/// Cached disassembly for a function's blocks (instruction bytes)
#[derive(Debug, Clone)]
pub struct FunctionDisassembly {
    pub blocks: Vec<BlockDisassembly>,
}

#[derive(Debug, Clone)]
pub struct BlockDisassembly {
    pub addr: u64,
    pub instructions: Vec<Vec<u8>>,
}

pub unsafe fn run_minimal_analysis(core: *mut RCore) {
    let cmd = CString::new("aa").unwrap();
    r_core_cmd(core, cmd.as_ptr());
}

pub unsafe fn ensure_functions_exist(core: *mut RCore) -> bool {
    let functions = get_all_functions(core);
    if functions.is_empty() {
        print_status(core, "No functions found. Running 'aa' to analyze binary...");
        run_minimal_analysis(core);

        // Small delay for analysis to complete
        let cons = crate::r2::ffi::r_core_get_cons(core);
        crate::r2::ffi::r_cons_flush(cons);

        let functions_after = get_all_functions(core);
        if functions_after.is_empty() {
            print_status(core, "Still no functions. Trying 'aaa' for deeper analysis...");
            let cmd = CString::new("aaa").unwrap();
            r_core_cmd(core, cmd.as_ptr());
            crate::r2::ffi::r_cons_flush(cons);

            let functions_final = get_all_functions(core);
            !functions_final.is_empty()
        } else {
            true
        }
    } else {
        true
    }
}

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

    // Try both "offset" and "addr" fields (r2 uses different field names)
    let func_addr = func.get("offset")
        .or_else(|| func.get("addr"))
        .and_then(|v| v.as_u64())?;

    Some(FunctionInfo {
        addr: func_addr,
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

/// Cache function disassembly - fetches ALL blocks with instruction bytes in ONE call
/// This is much more efficient than calling disassemble_at() per block
pub unsafe fn cache_function_disassembly(core: *mut RCore, fcn_addr: u64) -> Option<FunctionDisassembly> {
    let cmd = CString::new(format!("pdrj @ 0x{:x}", fcn_addr)).unwrap();
    let result = r_core_cmd_str(core, cmd.as_ptr());

    if result.is_null() {
        return None;
    }

    let json_str = std::ffi::CStr::from_ptr(result)
        .to_string_lossy()
        .into_owned();

    free(result as *mut _);

    let obj = serde_json::from_str::<serde_json::Value>(&json_str).ok()?;
    let bbs = obj.get("bbs")?.as_array()?;

    let mut blocks = Vec::new();
    let empty_ops: Vec<serde_json::Value> = Vec::new();

    for bb in bbs {
        let bb_addr = bb.get("addr")?.as_u64()?;
        let ops = bb.get("ops").and_then(|v| v.as_array()).unwrap_or(&empty_ops);

        let mut instructions = Vec::new();
        for op in ops {
            if let Some(bytes_hex) = op.get("bytes").and_then(|v| v.as_str()) {
                if !bytes_hex.is_empty() {
                    if let Ok(bytes) = hex::decode(bytes_hex) {
                        instructions.push(bytes);
                    }
                }
            }
        }

        // Only include blocks that have instructions
        if !instructions.is_empty() {
            blocks.push(BlockDisassembly {
                addr: bb_addr,
                instructions,
            });
        }
    }

    if blocks.is_empty() {
        None
    } else {
        Some(FunctionDisassembly { blocks })
    }
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

/// Get current architecture info in Binary Ninja compatible format
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
                let r2_arch = bin.get("arch")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let os = bin.get("os")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let bits = bin.get("bits")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(64);

                // Convert r2 arch/bits to Binary Ninja compatible naming
                // r2: "arm", bits=64 -> BN: arch="aarch64", platform="linux-aarch64"
                // r2: "arm", bits=32 -> BN: arch="arm", platform="linux-arm"
                // r2: "x86", bits=64 -> BN: arch="x86_64", platform="linux-x86_64"
                // r2: "x86", bits=32 -> BN: arch="x86", platform="linux-x86"
                let (bn_arch, suffix): (&str, &str) = match (r2_arch, bits) {
                    ("arm", 64) => ("aarch64", "aarch64"),
                    ("arm", 32) => ("arm", "arm"),
                    ("x86", 64) => ("x86_64", "x86_64"),
                    ("x86", 32) => ("x86", "x86"),
                    (other_arch, other_bits) => {
                        // Fallback: use arch name with bits suffix
                        if other_bits == 64 {
                            (other_arch, other_arch)
                        } else {
                            (other_arch, other_arch)
                        }
                    }
                };

                arch = bn_arch.to_string();
                platform = format!("{}-{}", os, suffix);
            }
        }
    }

    (arch, platform)
}

pub unsafe fn print_status(core: *mut RCore, msg: &str) {
    let c_str = CString::new(format!("{}\n", msg)).unwrap();
    let cons = crate::r2::ffi::r_core_get_cons(core);
    crate::r2::ffi::r_cons_print(cons, c_str.as_ptr());
}

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
