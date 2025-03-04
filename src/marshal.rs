use std::ffi::CStr;
use crate::util;

const PTR_TO_STRING_ANSI: &str = "48 85 C9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? CC CC CC 48 83 EC ?? 48 85 C9 74 ?? 48 83 C4 ??";
type MarshalPtrToStringAnsi = unsafe extern "fastcall" fn(*const u8) -> *const u8;
static mut PTR_TO_STRING_ANSI_ADDR: Option<usize> = None;

pub unsafe fn ptr_to_string_ansi(content: &CStr) -> *const u8 {
    if PTR_TO_STRING_ANSI_ADDR.is_none() {
        find();
    }

    let func = std::mem::transmute::<usize, MarshalPtrToStringAnsi>(PTR_TO_STRING_ANSI_ADDR.unwrap());
    func(content.to_bytes_with_nul().as_ptr())
}

pub unsafe fn find() {
    let ptr_to_string_ansi = util::pattern_scan_code("GameAssembly.dll", PTR_TO_STRING_ANSI);
    if let Some(addr) = ptr_to_string_ansi {
        let addr_offset = addr as usize;
        PTR_TO_STRING_ANSI_ADDR = Some(addr_offset);
        println!("ptr_to_string_ansi: {:x}", addr_offset);
    } else {
        println!("Failed to find ptr_to_string_ansi");
    }
}