use std::ffi::{c_void, c_char, c_int, CStr};

use crate::cmd::handle_zw_command;
use crate::r2::ffi::{RCorePluginSession, R_LIB_TYPE_CORE, R_PLUGIN_STATUS_OK, r_core_cmd_str, free};
use crate::warp::container::WarpContainer;

const R2_VERSION: &str = "6.1.3\0";
const R2_ABIVERSION: u32 = 82;

static mut G_CONTAINER: Option<WarpContainer> = None;
static mut IN_ZHELP: bool = false;

#[repr(C)]
pub struct RCorePluginStatic {
    pub meta: RPluginMetaStatic,
    pub init: Option<unsafe extern "C" fn(*mut RCorePluginSession) -> bool>,
    pub fini: Option<unsafe extern "C" fn(*mut RCorePluginSession) -> bool>,
    pub call: Option<unsafe extern "C" fn(*mut RCorePluginSession, *const c_char) -> bool>,
}

#[repr(C)]
pub struct RPluginMetaStatic {
    pub name: *const c_char,
    pub desc: *const c_char,
    pub author: *const c_char,
    pub version: *const c_char,
    pub license: *const c_char,
    pub contact: *const c_char,
    pub copyright: *const c_char,
    pub status: c_int,
}

#[repr(C)]
pub struct RLibStructStatic {
    pub type_: std::os::raw::c_int,
    pub data: *const c_void,
    pub version: *const c_char,
    pub free: Option<unsafe extern "C" fn(*mut c_void)>,
    pub pkgname: *const c_char,
    pub abiversion: u32,
}

unsafe impl Sync for RLibStructStatic {}
unsafe impl Sync for RCorePluginStatic {}

static WARP_CORE_PLUGIN: RCorePluginStatic = RCorePluginStatic {
    meta: RPluginMetaStatic {
        name: b"warp\0".as_ptr() as *const c_char,
        desc: b"WARP signature format support\0".as_ptr() as *const c_char,
        author: b"WARP Contributors\0".as_ptr() as *const c_char,
        version: b"0.1.0\0".as_ptr() as *const c_char,
        license: b"LGPL-3.0\0".as_ptr() as *const c_char,
        contact: std::ptr::null(),
        copyright: std::ptr::null(),
        status: R_PLUGIN_STATUS_OK,
    },
    init: Some(warp_init),
    fini: Some(warp_fini),
    call: Some(warp_call),
};

#[no_mangle]
pub static radare_plugin: RLibStructStatic = RLibStructStatic {
    type_: R_LIB_TYPE_CORE,
    data: std::ptr::addr_of!(WARP_CORE_PLUGIN) as *const c_void,
    version: R2_VERSION.as_ptr() as *const c_char,
    free: None,
    pkgname: b"warp\0".as_ptr() as *const c_char,
    abiversion: R2_ABIVERSION,
};

unsafe extern "C" fn warp_init(_session: *mut RCorePluginSession) -> bool {
    G_CONTAINER = Some(WarpContainer::new());
    true
}

unsafe extern "C" fn warp_fini(_session: *mut RCorePluginSession) -> bool {
    G_CONTAINER = None;
    true
}

unsafe extern "C" fn warp_call(session: *mut RCorePluginSession, input: *const c_char) -> bool {
    if input.is_null() {
        return false;
    }
    
    let input_str: &str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    
    let core = (*session).core;
    
    if input_str == "z?" || input_str == "z??" {
        if IN_ZHELP {
            return false;
        }
        IN_ZHELP = true;
        let help_cmd = std::ffi::CString::new("z?").unwrap();
        let native_help = r_core_cmd_str(core, help_cmd.as_ptr());
        if !native_help.is_null() {
            let s = std::ffi::CStr::from_ptr(native_help).to_string_lossy();
            crate::cmd::print_str(core, &s);
            free(native_help as *mut _);
        }
        IN_ZHELP = false;
        crate::cmd::print_str(core, "| zw[?]        manage WARP signatures\n");
        return true;
    }
    
    if !input_str.starts_with("zw") {
        return false;
    }
    
    std::panic::catch_unwind(|| {
        if let Some(ref mut container) = G_CONTAINER {
            handle_zw_command(core, container, input_str)
        } else {
            false
        }
    }).unwrap_or(false)
}
