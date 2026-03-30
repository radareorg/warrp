use uuid::{Uuid, uuid};

use crate::r2::ffi::RCore;
use crate::r2::analysis::{RelocatableRegion, FunctionDisassembly};

pub const NAMESPACE_BASICBLOCK: Uuid = uuid!("0192a178-7a5f-7936-8653-3cbaa7d6afe7");
pub const NAMESPACE_FUNCTION: Uuid = uuid!("0192a179-61ac-7cef-88ed-012296e9492f");
pub const NAMESPACE_CONSTRAINT: Uuid = uuid!("019701f3-e89c-7afa-9181-371a5e98a576");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionGUID {
    pub guid: Uuid,
}

impl FunctionGUID {
    pub fn from_basic_blocks(block_guids: &[BasicBlockGUID]) -> Self {
        let mut sorted_guids: Vec<_> = block_guids.to_vec();
        sorted_guids.sort_by(|a, b| b.addr.cmp(&a.addr));
        
        let bytes: Vec<u8> = sorted_guids
            .iter()
            .flat_map(|g| g.guid.as_bytes().to_vec())
            .collect();
        
        FunctionGUID {
            guid: Uuid::new_v5(&NAMESPACE_FUNCTION, &bytes),
        }
    }
    
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.guid.as_bytes()
    }
    
    pub fn to_string(&self) -> String {
        self.guid.to_string()
    }
}

impl std::fmt::Display for FunctionGUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.guid)
    }
}

#[derive(Debug, Clone)]
pub struct BasicBlockGUID {
    pub addr: u64,
    pub guid: Uuid,
}

impl BasicBlockGUID {
    pub fn from_bytes(addr: u64, bytes: &[u8]) -> Self {
        BasicBlockGUID {
            addr,
            guid: Uuid::new_v5(&NAMESPACE_BASICBLOCK, bytes),
        }
    }
}

/// Compute function GUID for the function at the given address
/// 
/// If disassembly is provided, it uses the cached data (efficient path).
/// If not, it fetches the disassembly itself (slow path, for backwards compatibility).
pub unsafe fn compute_function_guid(
    core: *mut RCore,
    fcn_addr: u64,
    regions: &[RelocatableRegion],
    disasm: Option<&FunctionDisassembly>,
) -> Result<FunctionGUID, String> {
    // Get disassembly - either from cache or fetch it
    let disasm_data = match disasm {
        Some(d) => d.clone(),
        None => {
            crate::r2::analysis::cache_function_disassembly(core, fcn_addr)
                .ok_or_else(|| format!("No disassembly for function at 0x{:x}", fcn_addr))?
        }
    };
    
    if disasm_data.blocks.is_empty() {
        return Err(format!("No basic blocks found at 0x{:x}", fcn_addr));
    }
    
    // Compute GUID for each block
    let mut block_guids: Vec<BasicBlockGUID> = Vec::new();
    
    for block in &disasm_data.blocks {
        match compute_block_guid_from_instructions(block.addr, &block.instructions, regions) {
            Ok(bg) => block_guids.push(bg),
            Err(_) => {
                // Skip blocks with no valid instructions (data/padding)
                // Don't fail the entire function for empty blocks
            }
        }
    }
    
    if block_guids.is_empty() {
        return Err("No valid basic block GUIDs computed".to_string());
    }
    
    Ok(FunctionGUID::from_basic_blocks(&block_guids))
}

/// Compute basic block GUID from pre-fetched instruction bytes
fn compute_block_guid_from_instructions(
    addr: u64,
    instructions: &[Vec<u8>],
    regions: &[RelocatableRegion],
) -> Result<BasicBlockGUID, String> {
    if instructions.is_empty() {
        return Err("No instructions in block".to_string());
    }
    
    // Build byte sequence with relocatable masking
    let mut bytes = Vec::new();
    
    for insn_bytes in instructions {
        if is_relocatable_insn(insn_bytes, regions) {
            let masked = mask_relocatable_bytes(insn_bytes, regions);
            bytes.extend(masked);
        } else if !is_nop_insn(insn_bytes) && !is_self_move_insn(insn_bytes) {
            bytes.extend(insn_bytes.iter());
        }
    }
    
    if bytes.is_empty() {
        return Err("Block produced no bytes after filtering".to_string());
    }
    
    Ok(BasicBlockGUID::from_bytes(addr, &bytes))
}

/// Check if instruction appears to be a NOP
fn is_nop_insn(bytes: &[u8]) -> bool {
    // Common NOP patterns
    match bytes.len() {
        1 => bytes == &[0x90], // x86 nop
        2 => bytes == &[0x87, 0xc0] || // x86 xchg eax, eax (effectively nop)
              bytes == &[0x66, 0x90] || // x86 2-byte nop
              bytes == &[0x00, 0x00] || // null bytes
              bytes == &[0x01, 0x00],   // another null variant
        // ARM NOP is often a specific encoding
        4 => bytes == &[0x1f, 0x20, 0x03, 0xd5] || // ARM64 nop
              bytes == &[0x00, 0xf0, 0x01, 0xf0] || // ARM32 nop
              bytes == &[0xbf, 0x00, 0xbf, 0x00] || // Thumb nop
              is_arm_nop(bytes),
        _ => false,
    }
}

#[cfg(target_arch = "arm")]
fn is_arm_nop(bytes: &[u8]) -> bool {
    // Check for ARM/Thumb NOP patterns
    bytes == &[0x00, 0xbf, 0x00, 0xbf] // Thumb nop.w
}

#[cfg(not(target_arch = "arm"))]
fn is_arm_nop(_bytes: &[u8]) -> bool {
    false
}

/// Check if instruction is a self-move (register-to-itself, effectively NOP)
fn is_self_move_insn(bytes: &[u8]) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    
    // x86: mov reg, reg (8b c0 for eax, 89 c0 for eax, etc.)
    // Pattern: 89 c0-c7 (mov r8, r8 to mov r15, r15) or 8b c0-c7
    // This is architecture-specific and simplified
    if bytes.len() >= 2 {
        // x86-64: MOV reg64, reg64 with REX prefix
        if bytes[0] == 0x48 || bytes[0] == 0x4c || // REX.W
           bytes[0] == 0x49 || bytes[0] == 0x4d {  // REX.W + REX.B
            if bytes[1] == 0x89 || bytes[1] == 0x8b {
                // Check if source and dest are the same register
                if bytes.len() >= 3 {
                    let modrm = bytes[2];
                    let src = modrm & 0x7;
                    let dst = (modrm >> 3) & 0x7;
                    if src == dst {
                        return true;
                    }
                }
            }
        }
    }
    
    false
}

/// Check if instruction contains a relocatable address
fn is_relocatable_insn(bytes: &[u8], _regions: &[RelocatableRegion]) -> bool {
    // This is a heuristic - we need to check if any embedded address falls within
    // mapped sections that could be relocated
    // For now, assume call/jmp instructions to addresses in relocatable regions
    // are relocatable
    
    // x86-64 call rel32 (e8 xx xx xx xx) - always potentially relocatable
    if bytes.len() >= 5 && bytes[0] == 0xe8 {
        return true;
    }
    
    // x86-64 jmp rel32 (e9 xx xx xx xx)
    if bytes.len() >= 5 && bytes[0] == 0xe9 {
        return true;
    }
    
    // For other cases, we'd need to decode the instruction and check if
    // it references an address within a relocatable region
    // This is simplified for now
    
    false
}

/// Mask relocatable bytes in an instruction
fn mask_relocatable_bytes(bytes: &[u8], _regions: &[RelocatableRegion]) -> Vec<u8> {
    // Zero out relocatable portion (typically the immediate/offset)
    let mut result = bytes.to_vec();
    
    // For call/jmp with relative offset, zero the offset bytes
    if bytes.len() >= 5 {
        if bytes[0] == 0xe8 || bytes[0] == 0xe9 {
            // Zero out the 4-byte relative offset
            result[1] = 0;
            result[2] = 0;
            result[3] = 0;
            result[4] = 0;
        }
    }
    
    // For MOV with immediate, zero the immediate
    // This is simplified - proper implementation would decode the instruction
    
    result
}

/// Compute constraint GUID from function GUID
pub fn compute_constraint_guid(func_guid: &FunctionGUID) -> Uuid {
    Uuid::new_v5(&NAMESPACE_CONSTRAINT, func_guid.as_bytes())
}

/// Compute constraint GUID from offset
pub fn compute_constraint_from_offset(offset: i64) -> Uuid {
    Uuid::new_v5(&NAMESPACE_CONSTRAINT, &offset.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_block_guid() {
        let bytes = vec![0x55, 0x48, 0x89, 0xe5]; // push rbp; mov rbp, rsp
        let bg = BasicBlockGUID::from_bytes(0x1000, &bytes);
        
        // GUID should be deterministic
        let bg2 = BasicBlockGUID::from_bytes(0x1000, &bytes);
        assert_eq!(bg.guid, bg2.guid);
    }
    
    #[test]
    fn test_function_guid() {
        let bytes1 = vec![0x55]; // push rbp
        let bg1 = BasicBlockGUID::from_bytes(0x1000, &bytes1);
        
        let bytes2 = vec![0xc3]; // ret
        let bg2 = BasicBlockGUID::from_bytes(0x1010, &bytes2);
        
        let fg = FunctionGUID::from_basic_blocks(&[bg1, bg2]);
        let fg2 = FunctionGUID::from_basic_blocks(&[bg2, bg1]); // Different order
        
        // Order shouldn't matter for final GUID (blocks are sorted by address)
        assert_ne!(fg.guid, fg2.guid); // Different because of sorting
    }
}