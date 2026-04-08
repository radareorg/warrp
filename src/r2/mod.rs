pub mod analysis;
pub mod cache;
pub mod ffi;
pub mod guid;

pub use analysis::{
    apply_function_metadata, cache_function_disassembly, get_all_functions, get_arch_info,
    get_function_at, get_function_blocks, get_relocatable_regions, is_address_relocatable,
    BasicBlockInfo, BlockDisassembly, FunctionDisassembly, FunctionInfo, InstructionInfo,
    RelocatableRegion,
};
pub use cache::{AnalysisCache, XrefInfo};
pub use ffi::{free, r_cons_print, r_cons_printf, r_core_cmd, r_core_cmd_str, RCons, RCore};
pub use guid::{
    compute_function_guid, BasicBlockGUID, FunctionGUID, NAMESPACE_BASICBLOCK,
    NAMESPACE_CONSTRAINT, NAMESPACE_FUNCTION,
};
