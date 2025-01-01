use core::iter::once;
use std::ffi::{c_void, OsStr};

use patternscan::{scan_first_match};
use std::io::Cursor;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect};
use windows::core::{s, PCSTR, PCWSTR};
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS,IMAGE_SECTION_HEADER};
use std::slice;

#[inline]
pub unsafe fn read_csharp_string(s: usize) -> String {
    let str_length = *(s.wrapping_add(16) as *const u32);
    let str_ptr = s.wrapping_add(20) as *const u8;

    String::from_utf16le_lossy(std::slice::from_raw_parts(
        str_ptr,
        (str_length * 2) as usize,
    ))
}

pub fn wide_str(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(once(0)).collect()
}

// VMProtect hooks NtProtectVirtualMemory to prevent changing protection of executable segments
// We use this trick to remove hook
pub unsafe fn disable_memprotect_guard() {
    let ntdll = wide_str("ntdll.dll");
    let ntdll = GetModuleHandleW(PCWSTR::from_raw(ntdll.as_ptr())).unwrap();
    let proc_addr = GetProcAddress(
        ntdll,
        PCSTR::from_raw(c"NtProtectVirtualMemory".to_bytes_with_nul().as_ptr()),
    )
    .unwrap();

    let routine = if is_wine() {
        GetProcAddress(ntdll, s!("NtPulseEvent")).unwrap()
    } else {
        GetProcAddress(ntdll, s!("NtQuerySection")).unwrap()
    } as *mut u32;

    let mut old_prot = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(
        proc_addr as *const usize as *mut c_void,
        1,
        PAGE_EXECUTE_READWRITE,
        &mut old_prot,
    )
    .unwrap();

    let routine_val = *(routine as *const usize);

    let lower_bits_mask = !(0xFFu64 << 32);
    let lower_bits = routine_val & lower_bits_mask as usize;

    let offset_val = *((routine as usize + 4) as *const u32);
    let upper_bits = ((offset_val as usize).wrapping_sub(1) as usize) << 32;

    let result = lower_bits | upper_bits;

    *(proc_addr as *mut usize) = result;

    VirtualProtect(
        proc_addr as *const usize as *mut c_void,
        1,
        old_prot,
        &mut old_prot,
    )
    .unwrap();
}

unsafe fn is_wine() -> bool {
    let module = GetModuleHandleA(s!("ntdll.dll")).unwrap();
    GetProcAddress(module, s!("wine_get_version")).is_some()
}

pub unsafe fn pattern_scan_code(module: &str, pattern: &str) -> Option<*mut u8> {
    let w_module_name = wide_str(module);
    
    let module_handle = match GetModuleHandleW(PCWSTR::from_raw(w_module_name.as_ptr())) {
        Ok(module) => Some(module.0 as usize),
        Err(_) => panic!("Failed to get module handle"),
    };
    
    let module_handle_addr = module_handle.unwrap();
    let mod_base = module_handle_addr as *const u8;
    let dos_header = unsafe { &*(mod_base as *const IMAGE_DOS_HEADER) };
    let nt_headers = unsafe { &*((mod_base.offset(dos_header.e_lfanew as isize)) as *const IMAGE_NT_HEADERS) };
    let text_section = nt_headers.OptionalHeader.BaseOfCode as usize;
    let size_of_text = nt_headers.OptionalHeader.SizeOfCode as usize;
    let text_section_offset = mod_base.offset(text_section as isize);
    let text_slice: &[u8] = unsafe { slice::from_raw_parts(text_section_offset, size_of_text) };
    let mut cursor = Cursor::new(text_slice);
     
    let loc = scan_first_match(&mut cursor, pattern.replace("??", "?").as_str()).unwrap();
    match loc {
        None => None,
        Some(loc) => Some((text_section_offset.wrapping_add(loc)) as *mut u8),
    }
}

pub unsafe fn pattern_scan_il2cpp(module: &str, pattern: &str) -> Option<*mut u8> {
    let w_module_name = wide_str(module);
    
    let module_handle = match GetModuleHandleW(PCWSTR::from_raw(w_module_name.as_ptr())) {
        Ok(module) => Some(module.0 as usize),
        Err(_) => panic!("Failed to get module handle"),
    };
    
    let module_handle_addr = module_handle.unwrap();
    let mod_base = module_handle_addr as *const u8;
    let dos_header = unsafe { &*(mod_base as *const IMAGE_DOS_HEADER) };
    let nt_headers = unsafe { &*((mod_base.offset(dos_header.e_lfanew as isize)) as *const IMAGE_NT_HEADERS) };
    
    let section_headers = unsafe {
        std::slice::from_raw_parts(
            (mod_base.offset(dos_header.e_lfanew as isize) as *const u8).offset(std::mem::size_of::<IMAGE_NT_HEADERS>() as isize) as *const IMAGE_SECTION_HEADER,
            nt_headers.FileHeader.NumberOfSections as usize,
        )
    };
    let il2cpp_section = section_headers.iter().find(|section| {
    let name = std::ffi::CStr::from_ptr(section.Name.as_ptr() as *const i8).to_str().unwrap_or("");
        name == "il2cpp"
    });
    
    if il2cpp_section.is_none() {
        println!("Failed to find il2cpp section");
        return None;
    }
    
    let il2cpp_base = mod_base.offset(il2cpp_section.unwrap().VirtualAddress as isize);
    let il2cpp_size = il2cpp_section.unwrap().SizeOfRawData as usize;
    let il2cpp_slice: &[u8] = unsafe { slice::from_raw_parts(il2cpp_base, il2cpp_size) };
    let mut cursor = Cursor::new(il2cpp_slice);
     
    let loc = scan_first_match(&mut cursor, pattern.replace("??", "?").as_str()).unwrap();
    match loc {
        None => None,
        Some(loc) => Some((il2cpp_base.wrapping_add(loc)) as *mut u8),
    }
}