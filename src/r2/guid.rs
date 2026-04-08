use uuid::{uuid, Uuid};

use crate::r2::analysis::{
    is_address_relocatable, FunctionDisassembly, InstructionInfo, RelocatableRegion,
};
use crate::r2::ffi::RCore;

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
        sorted_guids.sort_by(|a, b| a.addr.cmp(&b.addr));

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

pub unsafe fn compute_function_guid(
    core: *mut RCore,
    fcn_addr: u64,
    regions: &[RelocatableRegion],
    disasm: Option<&FunctionDisassembly>,
) -> Result<FunctionGUID, String> {
    let disasm_data = match disasm {
        Some(d) => d.clone(),
        None => crate::r2::analysis::cache_function_disassembly(core, fcn_addr)
            .ok_or_else(|| format!("No disassembly for function at 0x{:x}", fcn_addr))?,
    };

    if disasm_data.blocks.is_empty() {
        return Err(format!("No basic blocks found at 0x{:x}", fcn_addr));
    }

    let block_guids: Vec<BasicBlockGUID> = disasm_data
        .blocks
        .iter()
        .filter_map(|block| {
            compute_block_guid_from_instructions(block.addr, &block.instructions, regions).ok()
        })
        .collect();

    if block_guids.is_empty() {
        return Err("No valid basic block GUIDs computed".to_string());
    }

    Ok(FunctionGUID::from_basic_blocks(&block_guids))
}

fn compute_block_guid_from_instructions(
    addr: u64,
    instructions: &[InstructionInfo],
    regions: &[RelocatableRegion],
) -> Result<BasicBlockGUID, String> {
    if instructions.is_empty() {
        return Err("No instructions in block".to_string());
    }

    let bytes: Vec<u8> = instructions
        .iter()
        .flat_map(|insn| {
            if insn.is_nop || insn.is_self_move {
                Vec::new()
            } else if is_variant_instruction(insn, regions) {
                vec![0u8; insn.bytes.len()]
            } else {
                insn.bytes.clone()
            }
        })
        .collect();

    if bytes.is_empty() {
        return Err("Block produced no bytes after filtering".to_string());
    }

    Ok(BasicBlockGUID::from_bytes(addr, &bytes))
}

fn is_variant_instruction(insn: &InstructionInfo, regions: &[RelocatableRegion]) -> bool {
    if insn.refptr {
        return true;
    }

    if let Some(ptr) = insn.ptr {
        if ptr != 0 && is_address_relocatable(regions, ptr) {
            return true;
        }
    }

    if let Some(jump) = insn.jump {
        if is_address_relocatable(regions, jump) {
            return true;
        }
    }

    if is_call_or_jmp_insn(&insn.bytes) {
        return true;
    }

    false
}

fn is_call_or_jmp_insn(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && matches!(bytes[0], 0xe8 | 0xe9)
        || bytes.len() >= 2 && bytes[0] == 0xff && matches!((bytes[1] >> 3) & 0x7, 2 | 4)
}

pub fn compute_constraint_guid(func_guid: &FunctionGUID) -> Uuid {
    Uuid::new_v5(&NAMESPACE_CONSTRAINT, func_guid.as_bytes())
}

pub fn compute_constraint_from_offset(offset: i64) -> Uuid {
    Uuid::new_v5(&NAMESPACE_CONSTRAINT, &offset.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_block_guid_deterministic() {
        let bytes = vec![0x55, 0x48, 0x89, 0xe5];
        let bg = BasicBlockGUID::from_bytes(0x1000, &bytes);
        let bg2 = BasicBlockGUID::from_bytes(0x1000, &bytes);
        assert_eq!(bg.guid, bg2.guid);
    }

    #[test]
    fn test_basic_block_guid_different_bytes() {
        let bytes1 = vec![0x55, 0x48, 0x89, 0xe5];
        let bytes2 = vec![0x55, 0x48, 0x89, 0xe6];
        let bg1 = BasicBlockGUID::from_bytes(0x1000, &bytes1);
        let bg2 = BasicBlockGUID::from_bytes(0x1000, &bytes2);
        assert_ne!(bg1.guid, bg2.guid);
    }

    #[test]
    fn test_function_guid_sorting_ascending() {
        let bytes1 = vec![0x55];
        let bg1 = BasicBlockGUID::from_bytes(0x1000, &bytes1);
        let bytes2 = vec![0xc3];
        let bg2 = BasicBlockGUID::from_bytes(0x1010, &bytes2);

        let fg = FunctionGUID::from_basic_blocks(&[bg1.clone(), bg2.clone()]);
        let fg2 = FunctionGUID::from_basic_blocks(&[bg2, bg1]);
        assert_eq!(fg.guid, fg2.guid);
    }

    #[test]
    fn test_variant_call_insn() {
        let insn = InstructionInfo {
            bytes: vec![0xe8, 0x10, 0x00, 0x00, 0x00],
            ptr: None,
            refptr: false,
            jump: Some(0x5000),
            op_type: 0x400,
            is_nop: false,
            is_self_move: false,
        };
        let _regions = vec![RelocatableRegion {
            start: 0x1000,
            end: 0x3000,
        }];
        assert!(is_variant_instruction(&insn, &_regions));
    }

    #[test]
    fn test_variant_refptr() {
        let insn = InstructionInfo {
            bytes: vec![0x48, 0x8d, 0x3d, 0x10, 0x00, 0x00, 0x00],
            ptr: Some(0x2000),
            refptr: true,
            jump: None,
            op_type: 0x10,
            is_nop: false,
            is_self_move: false,
        };
        let regions = vec![RelocatableRegion {
            start: 0x1000,
            end: 0x3000,
        }];
        assert!(is_variant_instruction(&insn, &regions));
    }

    #[test]
    fn test_variant_ptr_in_relocatable_region() {
        let insn = InstructionInfo {
            bytes: vec![0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00],
            ptr: Some(0x2000),
            refptr: false,
            jump: None,
            op_type: 0x10,
            is_nop: false,
            is_self_move: false,
        };
        let regions = vec![RelocatableRegion {
            start: 0x1000,
            end: 0x3000,
        }];
        assert!(is_variant_instruction(&insn, &regions));
    }

    #[test]
    fn test_non_variant_insn() {
        let insn = InstructionInfo {
            bytes: vec![0x55],
            ptr: None,
            refptr: false,
            jump: None,
            op_type: 0x10,
            is_nop: false,
            is_self_move: false,
        };
        let regions = vec![RelocatableRegion {
            start: 0x1000,
            end: 0x3000,
        }];
        assert!(!is_variant_instruction(&insn, &regions));
    }

    #[test]
    fn test_nop_excluded() {
        let insn = InstructionInfo {
            bytes: vec![0x90],
            ptr: None,
            refptr: false,
            jump: None,
            op_type: 0,
            is_nop: true,
            is_self_move: false,
        };
        assert!(insn.is_nop);
    }

    #[test]
    fn test_self_move_excluded() {
        let insn = InstructionInfo {
            bytes: vec![0x89, 0xff],
            ptr: None,
            refptr: false,
            jump: None,
            op_type: 0x10,
            is_nop: false,
            is_self_move: true,
        };
        assert!(insn.is_self_move);
    }

    #[test]
    fn test_call_or_jmp_detection() {
        assert!(is_call_or_jmp_insn(&[0xe8, 0x00, 0x00, 0x00, 0x00]));
        assert!(is_call_or_jmp_insn(&[0xe9, 0x00, 0x00, 0x00, 0x00]));
        assert!(!is_call_or_jmp_insn(&[0x55]));
        assert!(!is_call_or_jmp_insn(&[0x48, 0x89, 0xe5]));
    }

    #[test]
    fn test_block_guid_zeros_variant_instruction() {
        let variant_insn = InstructionInfo {
            bytes: vec![0xe8, 0x10, 0x00, 0x00, 0x00],
            ptr: None,
            refptr: false,
            jump: Some(0x5000),
            op_type: 0x400,
            is_nop: false,
            is_self_move: false,
        };
        let normal_insn = InstructionInfo {
            bytes: vec![0x55],
            ptr: None,
            refptr: false,
            jump: None,
            op_type: 0x10,
            is_nop: false,
            is_self_move: false,
        };
        let nop_insn = InstructionInfo {
            bytes: vec![0x90],
            ptr: None,
            refptr: false,
            jump: None,
            op_type: 0,
            is_nop: true,
            is_self_move: false,
        };

        let regions = vec![RelocatableRegion {
            start: 0x1000,
            end: 0x6000,
        }];
        let result = compute_block_guid_from_instructions(
            0x1000,
            &[variant_insn, normal_insn, nop_insn],
            &regions,
        );
        assert!(result.is_ok());
        let bg = result.unwrap();
        let bg_expected = BasicBlockGUID::from_bytes(0x1000, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x55]);
        assert_eq!(bg.guid, bg_expected.guid);
    }
}
