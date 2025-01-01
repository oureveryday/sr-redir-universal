use std::ffi::CString;

use super::{MhyContext, MhyModule, ModuleType};
use crate::marshal;
use crate::util;
use anyhow::Result;
use ilhook::x64::Registers;

const WEB_REQUEST_UTILS_MAKE_INITIAL_URL: &str = "48 89 4C 24 ?? 53 56 57 41 56 41 57 48 83 EC ?? 48 C7 44 24 ?? ?? ?? ?? ?? 48 8B FA 48 8B D9 80 3D ?? ?? ?? ?? ?? 75 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? 48 8B CB";

pub struct Http;

impl MhyModule for MhyContext<Http> {
    unsafe fn init(&mut self) -> Result<()> {
        let web_request_utils_make_initial_url =
            util::pattern_scan_il2cpp(self.assembly_name, WEB_REQUEST_UTILS_MAKE_INITIAL_URL);
        if let Some(addr) = web_request_utils_make_initial_url {
            println!("web_request_utils_make_initial_url: {:x}", addr as usize);
            self.interceptor
                .attach(addr as usize, on_make_initial_url)?;
        } else {
            println!("Failed to find web_request_utils_make_initial_url");
        }

        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Http
    }
}

const URL: &str = "http://127.0.0.1:21000";

unsafe extern "win64" fn on_make_initial_url(reg: *mut Registers, _: usize) {
    let url = util::read_csharp_string((*reg).rcx as usize);

    let mut new_url = match url.as_str() {
        s if ((s.contains("mihoyo.com")
            || s.contains("hoyoverse.com")
            || s.contains("starrails.com")
            || s.contains(".bhsr.com"))
            && !(s.contains("autopatchcn") || s.contains("autopatchos"))) =>
        {
            URL.to_string()
        }
        s => {
            println!("Leaving request as-is: {s}");
            return;
        }
    };

    url.split('/').skip(3).for_each(|s| {
        new_url.push_str("/");
        new_url.push_str(s);
    });

    println!("UnityWebRequest: \"{url}\", replacing with \"{new_url}\"");
    (*reg).rcx =
        marshal::ptr_to_string_ansi(CString::new(new_url.as_str()).unwrap().as_c_str()) as u64;
}
