// radare2 core types
use std::os::raw::{c_char, c_int, c_void};

// Opaque types for structs we only access via pointers
pub type RCons = c_void;
pub type RAnal = c_void;
pub type RAnalFunction = c_void;
pub type RAnalBlock = c_void;
pub type RAnalOp = c_void;
pub type RAnalVar = c_void;
pub type RIO = c_void;
pub type RList = c_void;
pub type RListIter = c_void;
pub type RFlagItem = c_void;
pub type RFlag = c_void;
pub type RBin = c_void;
pub type Sdb = c_void;
pub type PJ = c_void;

// RCore is the main structure - we need to access cons field
// From r_core.h: RCons *cons; is at a certain offset
// We'll access it through a helper function instead
#[repr(C)]
pub struct RCore {
    _pad: [u8; 0],
}

pub const R_ANAL_OP_TYPE_NOP: u32 = 0x00001000;
pub const R_ANAL_OP_TYPE_MOV: u32 = 0x00000010;
pub const R_ANAL_OP_TYPE_CALL: u32 = 0x00000400;
pub const R_ANAL_OP_TYPE_JMP: u32 = 0x00000100;
pub const R_ANAL_OP_TYPE_CJMP: u32 = 0x00000200;
pub const R_ANAL_OP_TYPE_UCALL: u32 = 0x00000800;
pub const R_ANAL_OP_TYPE_RET: u32 = 0x00000008;

pub const R_ANAL_REF_TYPE_NULL: i32 = 0;
pub const R_ANAL_REF_TYPE_CODE: i32 = 0x10;
pub const R_ANAL_REF_TYPE_CALL: i32 = 0x20;
pub const R_ANAL_REF_TYPE_DATA: i32 = 1;

#[repr(C)]
pub struct RVecAnalRef {
    pub v: *mut c_void,
    pub len: usize,
    pub cap: usize,
}

#[repr(C)]
pub struct RAnalRef {
    pub addr: u64,
    pub at: u64,
    pub type_: i32,
}

#[repr(C)]
pub struct RAnalHint {
    pub addr: u64,
    pub ptr: u64,
    pub jump: u64,
    pub fail: u64,
    pub val: u64,
    pub immbase: i32,
    pub size: i32,
    pub nword: i32,
    pub opcode: *mut c_char,
    pub esil: *mut c_char,
    pub offset: *mut c_char,
    pub offset_delta: i64,
    pub syntax: *mut c_char,
    pub type_: i32,
    pub typesize: i32,
    pub reg: *mut c_char,
}

extern "C" {
    // Core
    pub fn r_core_cmd(core: *mut RCore, cmd: *const c_char) -> c_int;
    pub fn r_core_cmd_str(core: *mut RCore, cmd: *const c_char) -> *mut c_char;
    pub fn r_core_get_cons(core: *mut RCore) -> *mut RCons;

    // Analysis
    pub fn r_anal_get_fcn_in(anal: *mut RAnal, addr: u64, filter: c_int) -> *mut RAnalFunction;
    pub fn r_anal_get_function_at(anal: *mut RAnal, addr: u64) -> *mut RAnalFunction;
    pub fn r_anal_get_function_byname(anal: *mut RAnal, name: *const c_char) -> *mut RAnalFunction;
    pub fn r_anal_functions(anal: *mut RAnal) -> *mut RList;

    // Function access
    pub fn r_anal_function_addr(fcn: *const RAnalFunction) -> u64;
    pub fn r_anal_function_size(fcn: *const RAnalFunction) -> u64;
    pub fn r_anal_function_name(fcn: *const RAnalFunction) -> *const c_char;
    pub fn r_anal_function_rename(fcn: *mut RAnalFunction, name: *const c_char) -> bool;
    pub fn r_anal_function_blocks(fcn: *const RAnalFunction) -> *mut RList;
    pub fn r_anal_function_xrefs(fcn: *const RAnalFunction) -> *mut RVecAnalRef;
    pub fn r_anal_function_get_refs(fcn: *const RAnalFunction) -> *mut RVecAnalRef;
    pub fn r_anal_function_vars(fcn: *const RAnalFunction) -> *mut RList;

    // Basic block access
    pub fn r_anal_block_addr(block: *const RAnalBlock) -> u64;
    pub fn r_anal_block_size(block: *const RAnalBlock) -> u64;
    pub fn r_anal_block_successors(block: *const RAnalBlock) -> *mut RList;
    pub fn r_anal_block_op_addr(block: *const RAnalBlock, i: usize) -> *mut c_void;

    // Disassembly
    pub fn r_anal_op(
        anal: *mut RAnal,
        op: *mut RAnalOp,
        addr: u64,
        buf: *const u8,
        len: c_int,
        mask: c_int,
    ) -> c_int;
    pub fn r_anal_op_get_bytes(op: *const RAnalOp) -> *const u8;
    pub fn r_anal_op_get_size(op: *const RAnalOp) -> c_int;

    // IO/Memory
    pub fn r_io_read_at(io: *mut RIO, addr: u64, buf: *mut u8, len: c_int);
    pub fn r_io_map_get(io: *mut RIO, addr: u64) -> *mut c_void;
    pub fn r_io_section_get(io: *mut RIO, addr: u64) -> *mut c_void;

    // List iteration
    pub fn r_list_iter(list: *mut RList) -> *mut RListIter;
    pub fn r_list_iter_get(iter: *mut RListIter) -> *mut c_void;
    pub fn r_list_iter_next(iter: *mut RListIter) -> bool;
    pub fn r_list_first(list: *const RList) -> *mut c_void;
    pub fn r_list_length(list: *const RList) -> c_int;
    pub fn r_list_free(list: *mut RList);

    // Console output
    pub fn r_cons_printf(cons: *mut RCons, fmt: *const c_char, ...) -> c_int;
    pub fn r_cons_print(cons: *mut RCons, msg: *const c_char);
    pub fn r_cons_newline(cons: *mut RCons);
    pub fn r_cons_flush(cons: *mut RCons);

    // Memory management
    pub fn free(ptr: *mut c_void);
    pub fn r_mem_free(ptr: *mut c_void);
}

// Type definitions for plugin structures
#[repr(C)]
pub struct RPluginMeta {
    pub name: *mut c_char,
    pub desc: *mut c_char,
    pub author: *mut c_char,
    pub version: *mut c_char,
    pub license: *mut c_char,
    pub contact: *mut c_char,
    pub copyright: *mut c_char,
    pub status: c_int,
}

#[repr(C)]
pub struct RCorePlugin {
    pub meta: RPluginMeta,
    pub init: Option<unsafe extern "C" fn(*mut RCorePluginSession) -> bool>,
    pub fini: Option<unsafe extern "C" fn(*mut RCorePluginSession) -> bool>,
    pub call: Option<unsafe extern "C" fn(*mut RCorePluginSession, *const c_char) -> bool>,
}

#[repr(C)]
pub struct RCorePluginSession {
    pub core: *mut RCore,
    pub plugin: *mut RCorePlugin,
    pub data: *mut c_void,
}

#[repr(C)]
pub struct RLibStruct {
    pub type_: c_int,
    pub data: *mut c_void,
    pub version: *const c_char,
    pub free: Option<unsafe extern "C" fn(*mut c_void)>,
    pub pkgname: *const c_char,
    pub abiversion: u32,
}

pub const R_LIB_TYPE_CORE: c_int = 12;
pub const R_PLUGIN_STATUS_OK: c_int = 3;
