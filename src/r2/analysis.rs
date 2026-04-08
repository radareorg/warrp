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

pub const ADDRESS_RELOCATION_THRESHOLD: u64 = 0x10000;

#[derive(Debug, Clone)]
pub struct FunctionDisassembly {
    pub blocks: Vec<BlockDisassembly>,
}

#[derive(Debug, Clone)]
pub struct BlockDisassembly {
    pub addr: u64,
    pub instructions: Vec<InstructionInfo>,
}

#[derive(Debug, Clone)]
pub struct InstructionInfo {
    pub bytes: Vec<u8>,
    pub ptr: Option<u64>,
    pub refptr: bool,
    pub jump: Option<u64>,
    pub op_type: u32,
    pub is_nop: bool,
    pub is_self_move: bool,
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

    let arch_bits = get_arch_bits(core);

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
                        let ptr = op.get("ptr").and_then(|v| v.as_u64());
                        let refptr = op.get("refptr").and_then(|v| v.as_bool()).unwrap_or(false);
                        let jump = op.get("jump").and_then(|v| v.as_u64());
                        let op_type = op.get("type_num")
                            .or_else(|| op.get("type"))
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32;

                        let is_nop = is_nop_from_analysis(op, &bytes);
                        let is_self_move = is_self_move_from_analysis(op, &bytes, arch_bits);

                        instructions.push(InstructionInfo {
                            bytes,
                            ptr,
                            refptr,
                            jump,
                            op_type,
                            is_nop,
                            is_self_move,
                        });
                    }
                }
            }
        }

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
    let mut use_sections = true;

    let seg_cmd = CString::new("iSSj").unwrap();
    let seg_result = r_core_cmd_str(core, seg_cmd.as_ptr());

    if !seg_result.is_null() {
        let seg_json_str = std::ffi::CStr::from_ptr(seg_result)
            .to_string_lossy()
            .into_owned();
        free(seg_result as *mut _);

        if let Ok(segments) = serde_json::from_str::<Vec<serde_json::Value>>(&seg_json_str) {
            let valid_segments: Vec<_> = segments.iter().filter(|seg| {
                let vaddr = seg.get("vaddr").and_then(|v| v.as_u64()).unwrap_or(0);
                let perm = seg.get("perm").and_then(|v| v.as_str()).unwrap_or("");
                vaddr != 0 && !perm.is_empty()
            }).collect();

            if !valid_segments.is_empty() {
                use_sections = false;
                for seg in valid_segments {
                    if let (Some(vaddr), Some(size)) = (
                        seg.get("vaddr").and_then(|v| v.as_u64()),
                        seg.get("vsize").and_then(|v| v.as_u64()).or_else(|| seg.get("size").and_then(|v| v.as_u64())),
                    ) {
                        regions.push(RelocatableRegion {
                            start: vaddr,
                            end: vaddr + size,
                        });
                    }
                }
            }
        }
    }

    if use_sections {
        let cmd = CString::new("iSj").unwrap();
        let result = r_core_cmd_str(core, cmd.as_ptr());

        if !result.is_null() {
            let json_str = std::ffi::CStr::from_ptr(result)
                .to_string_lossy()
                .into_owned();
            free(result as *mut _);

            if let Ok(sections) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
                for section in sections {
                    if let (Some(vaddr), Some(size)) = (
                        section.get("vaddr").and_then(|v| v.as_u64()),
                        section.get("vsize").and_then(|v| v.as_u64()).or_else(|| section.get("size").and_then(|v| v.as_u64())),
                    ) {
                        regions.push(RelocatableRegion {
                            start: vaddr,
                            end: vaddr + size,
                        });
                    }
                }
            }
        }
    }

    regions
}

pub fn is_address_relocatable(regions: &[RelocatableRegion], address: u64) -> bool {
    regions.iter().any(|range| {
        (address >= range.start && address < range.end)
            || (address > range.end && address > ADDRESS_RELOCATION_THRESHOLD && address <= range.end + ADDRESS_RELOCATION_THRESHOLD)
            || (address < range.start && address > ADDRESS_RELOCATION_THRESHOLD && address >= range.start.saturating_sub(ADDRESS_RELOCATION_THRESHOLD))
    })
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

unsafe fn get_arch_bits(core: *mut RCore) -> u32 {
    let cmd = CString::new("ij").unwrap();
    let result = r_core_cmd_str(core, cmd.as_ptr());

    if result.is_null() {
        return 64;
    }

    let json_str = std::ffi::CStr::from_ptr(result)
        .to_string_lossy()
        .into_owned();
    free(result as *mut _);

    serde_json::from_str::<serde_json::Value>(&json_str)
        .ok()
        .and_then(|info| info.get("bin")?.get("bits")?.as_u64())
        .unwrap_or(64) as u32
}

fn is_nop_from_analysis(op: &serde_json::Value, bytes: &[u8]) -> bool {
    if bytes.len() == 1 && bytes[0] == 0x90 {
        return true;
    }
    if bytes.len() == 2 && (bytes == &[0x66, 0x90] || bytes == &[0x87, 0xc0]) {
        return true;
    }
    if bytes.len() == 4 && (bytes == &[0x1f, 0x20, 0x03, 0xd5]
        || bytes == &[0x00, 0xf0, 0x01, 0xf0]
        || bytes == &[0xbf, 0x00, 0xbf, 0x00])
    {
        return true;
    }
    if op.get("type").and_then(|v| v.as_str()) == Some("nop") {
        return true;
    }
    false
}

fn is_self_move_from_analysis(op: &serde_json::Value, bytes: &[u8], arch_bits: u32) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    let disasm = op.get("disasm").and_then(|v| v.as_str()).unwrap_or("");

    if !is_self_move_mnemonic(disasm) {
        return false;
    }

    if arch_bits == 64 {
        if let Some(operands) = disasm.strip_prefix("mov ").or_else(|| disasm.strip_prefix("mov.w ")) {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                let dst = parts[0];
                let src = parts[1];
                if dst == src {
                    if is_32bit_register(dst) {
                        return false;
                    }
                    return true;
                }
            }
        }
        return false;
    }

    if let Some(operands) = disasm.strip_prefix("mov ").or_else(|| disasm.strip_prefix("mov.w ")) {
        let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
        if parts.len() == 2 && parts[0] == parts[1] {
            return true;
        }
    }

    if bytes.len() >= 3 {
        let has_rex_w = bytes[0] == 0x48 || bytes[0] == 0x4c
            || bytes[0] == 0x49 || bytes[0] == 0x4d;
        if has_rex_w && (bytes[1] == 0x89 || bytes[1] == 0x8b) {
            let modrm = bytes[2];
            let src = modrm & 0x7;
            let dst = (modrm >> 3) & 0x7;
            if src == dst {
                return true;
            }
        }
    }

    false
}

fn is_self_move_mnemonic(disasm: &str) -> bool {
    disasm.starts_with("mov ") || disasm.starts_with("mov.w ")
}

fn is_32bit_register(reg: &str) -> bool {
    matches!(reg,
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp"
        | "r8d" | "r9d" | "r10d" | "r11d" | "r12d" | "r13d" | "r14d" | "r15d"
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_relocatable_inside_region() {
        let regions = vec![RelocatableRegion { start: 0x1000, end: 0x2000 }];
        assert!(is_address_relocatable(&regions, 0x1500));
    }

    #[test]
    fn test_address_relocatable_proximity_after() {
        let regions = vec![RelocatableRegion { start: 0x10000, end: 0x20000 }];
        assert!(is_address_relocatable(&regions, 0x20001));
        assert!(is_address_relocatable(&regions, 0x2FFFF));
        assert!(!is_address_relocatable(&regions, 0x100000));
    }

    #[test]
    fn test_address_relocatable_proximity_before() {
        let regions = vec![RelocatableRegion { start: 0x20000, end: 0x30000 }];
        assert!(is_address_relocatable(&regions, 0x10001));
        assert!(is_address_relocatable(&regions, 0x1FFFF));
    }

    #[test]
    fn test_address_not_relocatable() {
        let regions = vec![RelocatableRegion { start: 0x10000, end: 0x20000 }];
        assert!(!is_address_relocatable(&regions, 0x100));
    }

    #[test]
    fn test_nop_detection_single_byte() {
        let op = serde_json::json!({});
        assert!(is_nop_from_analysis(&op, &[0x90]));
        assert!(!is_nop_from_analysis(&op, &[0x55]));
    }

    #[test]
    fn test_nop_detection_two_byte() {
        let op = serde_json::json!({});
        assert!(is_nop_from_analysis(&op, &[0x66, 0x90]));
        assert!(is_nop_from_analysis(&op, &[0x87, 0xc0]));
    }

    #[test]
    fn test_nop_detection_arm64() {
        let op = serde_json::json!({});
        assert!(is_nop_from_analysis(&op, &[0x1f, 0x20, 0x03, 0xd5]));
    }

    #[test]
    fn test_nop_from_type_field() {
        let op = serde_json::json!({"type": "nop"});
        assert!(is_nop_from_analysis(&op, &[0x55]));
    }

    #[test]
    fn test_self_move_64bit_edi_not_blacklisted() {
        let op = serde_json::json!({"disasm": "mov edi, edi"});
        let bytes = vec![0x89, 0xff];
        assert!(!is_self_move_from_analysis(&op, &bytes, 64));
    }

    #[test]
    fn test_self_move_32bit_edi_blacklisted() {
        let op = serde_json::json!({"disasm": "mov edi, edi"});
        let bytes = vec![0x89, 0xff];
        assert!(is_self_move_from_analysis(&op, &bytes, 32));
    }

    #[test]
    fn test_self_move_64bit_rdi_blacklisted() {
        let op = serde_json::json!({"disasm": "mov rdi, rdi"});
        let bytes = vec![0x48, 0x89, 0xff];
        assert!(is_self_move_from_analysis(&op, &bytes, 64));
    }

    #[test]
    fn test_self_move_not_a_move() {
        let op = serde_json::json!({"disasm": "push rbp"});
        let bytes = vec![0x55];
        assert!(!is_self_move_from_analysis(&op, &bytes, 64));
    }

    #[test]
    fn test_32bit_register_detection() {
        assert!(is_32bit_register("eax"));
        assert!(is_32bit_register("edi"));
        assert!(is_32bit_register("r8d"));
        assert!(!is_32bit_register("rax"));
        assert!(!is_32bit_register("rdi"));
        assert!(!is_32bit_register("r8"));
    }
}
