#![feature(str_from_utf16_endian)]

use std::{sync::RwLock};

use lazy_static::lazy_static;
use windows::Win32::System::Console;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::{Foundation::HINSTANCE, System::LibraryLoader::GetModuleFileNameA};
use std::ffi::CStr;
use std::path::Path;
use std::time::Duration;
use std::thread;

mod interceptor;
mod marshal;
mod modules;
mod util;

use crate::modules::{Http, MhyContext, ModuleManager};

unsafe fn thread_func() {
    let mut module_manager = MODULE_MANAGER.write().unwrap();

    util::disable_memprotect_guard();
    Console::AllocConsole().unwrap();

    println!("sr network redirector");

    let mut buffer = [0u8; 260];
    GetModuleFileNameA(None, &mut buffer);
    let exe_path = CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap();
    let exe_name = Path::new(exe_path).file_name().unwrap().to_str().unwrap();
    println!("Current executable name: {}", exe_name);

    if exe_name != "StarRail.exe" {
        println!("Executable is not sr. Skipping initialization.");
        return;
    }

    println!("Initializing modules...");

    thread::sleep(Duration::from_secs(3));

    marshal::find();
    module_manager.enable(MhyContext::<Http>::new("GameAssembly.dll"));

    println!("Successfully initialized!");
}

lazy_static! {
    static ref MODULE_MANAGER: RwLock<ModuleManager> = RwLock::new(ModuleManager::default());
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        std::thread::spawn(|| thread_func());
    }

    true
}
