use std::ffi::CString;

use crate::r2::ffi::{free, r_core_cmd, r_core_cmd_str, RCore};

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

unsafe fn cmd_json(core: *mut RCore, cmd: &str) -> Option<serde_json::Value> {
    let c_cmd = CString::new(cmd).unwrap();
    let result = r_core_cmd_str(core, c_cmd.as_ptr());
    if result.is_null() {
        return None;
    }
    let json_str = std::ffi::CStr::from_ptr(result)
        .to_string_lossy()
        .into_owned();
    free(result as *mut _);
    serde_json::from_str(&json_str).ok()
}

pub unsafe fn run_minimal_analysis(core: *mut RCore) {
    let cmd = CString::new("aa").unwrap();
    r_core_cmd(core, cmd.as_ptr());
}

pub unsafe fn ensure_functions_exist(core: *mut RCore) -> bool {
    if !get_all_functions(core).is_empty() {
        return true;
    }
    print_status(
        core,
        "No functions found. Running 'aa' to analyze binary...",
    );
    run_minimal_analysis(core);
    let cons = crate::r2::ffi::r_core_get_cons(core);
    crate::r2::ffi::r_cons_flush(cons);

    if !get_all_functions(core).is_empty() {
        return true;
    }
    print_status(
        core,
        "Still no functions. Trying 'aaa' for deeper analysis...",
    );
    let cmd = CString::new("aaa").unwrap();
    r_core_cmd(core, cmd.as_ptr());
    crate::r2::ffi::r_cons_flush(cons);
    !get_all_functions(core).is_empty()
}

pub unsafe fn get_all_functions(core: *mut RCore) -> Vec<u64> {
    let mut functions = Vec::new();
    let Some(json) = cmd_json(core, "aflj") else {
        return functions;
    };
    for func in json.as_array().unwrap_or(&Vec::new()) {
        if let Some(addr) = func
            .get("offset")
            .or_else(|| func.get("addr"))
            .and_then(|v| v.as_u64())
        {
            functions.push(addr);
        }
    }
    functions
}

pub unsafe fn get_function_at(core: *mut RCore, addr: u64) -> Option<FunctionInfo> {
    let funcs = cmd_json(core, &format!("afij @ 0x{:x}", addr))?
        .as_array()?
        .to_vec();
    let func = funcs.first()?;
    let func_addr = func
        .get("offset")
        .or_else(|| func.get("addr"))
        .and_then(|v| v.as_u64())?;
    Some(FunctionInfo {
        addr: func_addr,
        size: func.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
        name: func
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

pub unsafe fn get_function_blocks(core: *mut RCore, addr: u64) -> Vec<BasicBlockInfo> {
    let mut blocks = Vec::new();
    let Some(json) = cmd_json(core, &format!("afbj @ 0x{:x}", addr)) else {
        return blocks;
    };
    for block in json.as_array().unwrap_or(&Vec::new()) {
        if let (Some(addr), Some(size)) = (
            block.get("addr").and_then(|v| v.as_u64()),
            block.get("size").and_then(|v| v.as_u64()),
        ) {
            blocks.push(BasicBlockInfo { addr, size });
        }
    }
    blocks
}

pub unsafe fn cache_function_disassembly(
    core: *mut RCore,
    fcn_addr: u64,
) -> Option<FunctionDisassembly> {
    let obj = cmd_json(core, &format!("pdrj @ 0x{:x}", fcn_addr))?;
    let bbs = obj.get("bbs")?.as_array()?;
    let arch_bits = get_arch_bits(core);
    let empty_ops = Vec::new();

    let mut blocks = Vec::new();
    for bb in bbs {
        let bb_addr = bb.get("addr")?.as_u64()?;
        let ops = bb
            .get("ops")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_ops);

        let mut instructions = Vec::new();
        for op in ops {
            let Some(bytes_hex) = op.get("bytes").and_then(|v| v.as_str()) else {
                continue;
            };
            if bytes_hex.is_empty() {
                continue;
            }
            let Ok(bytes) = hex::decode(bytes_hex) else {
                continue;
            };

            instructions.push(InstructionInfo {
                ptr: op.get("ptr").and_then(|v| v.as_u64()),
                refptr: op.get("refptr").and_then(|v| v.as_bool()).unwrap_or(false),
                jump: op.get("jump").and_then(|v| v.as_u64()),
                op_type: op
                    .get("type_num")
                    .or_else(|| op.get("type"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                is_nop: is_nop_from_analysis(op, &bytes),
                is_self_move: is_self_move_from_analysis(op, &bytes, arch_bits),
                bytes,
            });
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

unsafe fn parse_regions_from_json(json: &serde_json::Value) -> Vec<RelocatableRegion> {
    let mut regions = Vec::new();
    for entry in json.as_array().unwrap_or(&Vec::new()) {
        if let (Some(vaddr), Some(size)) = (
            entry.get("vaddr").and_then(|v| v.as_u64()),
            entry
                .get("vsize")
                .and_then(|v| v.as_u64())
                .or_else(|| entry.get("size").and_then(|v| v.as_u64())),
        ) {
            regions.push(RelocatableRegion {
                start: vaddr,
                end: vaddr + size,
            });
        }
    }
    regions
}

pub unsafe fn get_relocatable_regions(core: *mut RCore) -> Vec<RelocatableRegion> {
    let empty = Vec::new();
    if let Some(json) = cmd_json(core, "iSSj") {
        let arr = json.as_array().unwrap_or(&empty);
        let valid: Vec<_> = arr
            .iter()
            .filter(|seg| {
                let vaddr = seg.get("vaddr").and_then(|v| v.as_u64()).unwrap_or(0);
                let perm = seg.get("perm").and_then(|v| v.as_str()).unwrap_or("");
                vaddr != 0 && !perm.is_empty()
            })
            .collect();
        if !valid.is_empty() {
            let regions_json = serde_json::Value::Array(valid.into_iter().cloned().collect());
            return parse_regions_from_json(&regions_json);
        }
    }
    cmd_json(core, "iSj")
        .map(|j| parse_regions_from_json(&j))
        .unwrap_or_default()
}

pub fn is_address_relocatable(regions: &[RelocatableRegion], address: u64) -> bool {
    regions.iter().any(|range| {
        (address >= range.start && address < range.end)
            || (address > range.end
                && address > ADDRESS_RELOCATION_THRESHOLD
                && address <= range.end + ADDRESS_RELOCATION_THRESHOLD)
            || (address < range.start
                && address > ADDRESS_RELOCATION_THRESHOLD
                && address >= range.start.saturating_sub(ADDRESS_RELOCATION_THRESHOLD))
    })
}

pub unsafe fn get_arch_info(core: *mut RCore) -> (String, String) {
    let json = match cmd_json(core, "ij") {
        Some(j) => j,
        None => return ("unknown".to_string(), "unknown".to_string()),
    };
    let Some(bin) = json.get("bin") else {
        return ("unknown".to_string(), "unknown".to_string());
    };
    let r2_arch = bin
        .get("arch")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let os = bin.get("os").and_then(|v| v.as_str()).unwrap_or("unknown");
    let bits = bin.get("bits").and_then(|v| v.as_u64()).unwrap_or(64);
    let suffix = match (r2_arch, bits) {
        ("arm", 64) => "aarch64",
        ("arm", 32) => "arm",
        ("x86", 64) => "x86_64",
        ("x86", 32) => "x86",
        _ => r2_arch,
    };
    let bn_arch = match (r2_arch, bits) {
        ("arm", 64) => "aarch64",
        ("arm", 32) => "arm",
        ("x86", 64) => "x86_64",
        ("x86", 32) => "x86",
        _ => r2_arch,
    };
    (bn_arch.to_string(), format!("{}-{}", os, suffix))
}

pub unsafe fn print_status(core: *mut RCore, msg: &str) {
    let c_str = CString::new(format!("{}\n", msg)).unwrap();
    let cons = crate::r2::ffi::r_core_get_cons(core);
    crate::r2::ffi::r_cons_print(cons, c_str.as_ptr());
}

pub unsafe fn is_interactive(core: *mut RCore) -> bool {
    cmd_json(core, "e scr.interactive").is_some() || {
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
}

pub unsafe fn apply_function_metadata(
    core: *mut RCore,
    addr: u64,
    warp_func: &crate::warp::signature::Function,
) -> bool {
    let name = &warp_func.symbol.name;
    if !name.is_empty() {
        let cmd = CString::new(format!("afn {} @ 0x{:x}", name, addr)).unwrap();
        r_core_cmd(core, cmd.as_ptr());
    }
    for comment in &warp_func.comments {
        let text = &comment.text;
        let cmd = CString::new(format!(
            "CC {} @ 0x{:x}",
            text,
            addr + comment.offset as u64
        ))
        .unwrap();
        r_core_cmd(core, cmd.as_ptr());
    }
    true
}

unsafe fn get_arch_bits(core: *mut RCore) -> u32 {
    cmd_json(core, "ij")
        .and_then(|info| info.get("bin")?.get("bits")?.as_u64())
        .unwrap_or(64) as u32
}

fn is_nop_from_analysis(op: &serde_json::Value, bytes: &[u8]) -> bool {
    matches!(bytes, [0x90] | [0x66, 0x90] | [0x87, 0xc0])
        || bytes.len() == 4
            && matches!(
                bytes,
                [0x1f, 0x20, 0x03, 0xd5] | [0x00, 0xf0, 0x01, 0xf0] | [0xbf, 0x00, 0xbf, 0x00]
            )
        || op.get("type").and_then(|v| v.as_str()) == Some("nop")
}

fn parse_self_move_operands(disasm: &str) -> Option<(&str, &str)> {
    let operands = disasm
        .strip_prefix("mov ")
        .or_else(|| disasm.strip_prefix("mov.w "))?;
    let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
    (parts.len() == 2).then(|| (parts[0], parts[1]))
}

fn is_self_move_from_analysis(op: &serde_json::Value, bytes: &[u8], arch_bits: u32) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    let disasm = op.get("disasm").and_then(|v| v.as_str()).unwrap_or("");
    if !is_self_move_mnemonic(disasm) {
        return false;
    }

    if let Some((dst, src)) = parse_self_move_operands(disasm) {
        if dst == src {
            return !(arch_bits == 64 && is_32bit_register(dst));
        }
    }

    bytes.len() >= 3
        && matches!(bytes[0], 0x48 | 0x4c | 0x49 | 0x4d)
        && matches!(bytes[1], 0x89 | 0x8b)
        && (bytes[2] & 0x7) == ((bytes[2] >> 3) & 0x7)
}

fn is_self_move_mnemonic(disasm: &str) -> bool {
    disasm.starts_with("mov ") || disasm.starts_with("mov.w ")
}

fn is_32bit_register(reg: &str) -> bool {
    matches!(
        reg,
        "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "r8d"
            | "r9d"
            | "r10d"
            | "r11d"
            | "r12d"
            | "r13d"
            | "r14d"
            | "r15d"
    )
}

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
        let regions = vec![RelocatableRegion {
            start: 0x1000,
            end: 0x2000,
        }];
        assert!(is_address_relocatable(&regions, 0x1500));
    }

    #[test]
    fn test_address_relocatable_proximity_after() {
        let regions = vec![RelocatableRegion {
            start: 0x10000,
            end: 0x20000,
        }];
        assert!(is_address_relocatable(&regions, 0x20001));
        assert!(is_address_relocatable(&regions, 0x2FFFF));
        assert!(!is_address_relocatable(&regions, 0x100000));
    }

    #[test]
    fn test_address_relocatable_proximity_before() {
        let regions = vec![RelocatableRegion {
            start: 0x20000,
            end: 0x30000,
        }];
        assert!(is_address_relocatable(&regions, 0x10001));
        assert!(is_address_relocatable(&regions, 0x1FFFF));
    }

    #[test]
    fn test_address_not_relocatable() {
        let regions = vec![RelocatableRegion {
            start: 0x10000,
            end: 0x20000,
        }];
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
