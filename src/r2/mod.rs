pub mod ffi;
pub mod analysis;
pub mod guid;
pub mod cache;

pub use ffi::{RCore, RCons, r_core_cmd, r_core_cmd_str, r_cons_printf, r_cons_print, free};
pub use analysis::{RelocatableRegion, FunctionInfo, BasicBlockInfo, BlockDisassembly, FunctionDisassembly, get_all_functions, get_function_at, get_function_blocks, cache_function_disassembly, get_relocatable_regions, get_arch_info, apply_function_metadata};
pub use guid::{compute_function_guid, FunctionGUID, BasicBlockGUID, NAMESPACE_BASICBLOCK, NAMESPACE_FUNCTION, NAMESPACE_CONSTRAINT};
pub use cache::{AnalysisCache, XrefInfo};