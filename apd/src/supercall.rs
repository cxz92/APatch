use libc::{c_long, syscall};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read};

use crate::package::read_ap_package_config;

const MAJOR: c_long = 0;
const MINOR: c_long = 11;
const PATCH: c_long = 0;

const __NR_SUPERCALL: c_long = 45;
const SUPERCALL_HELLO: c_long = 0x1000;
const SUPERCALL_KLOG: c_long = 0x1004;

const SUPERCALL_KERNELPATCH_VER: c_long = 0x1008;
const SUPERCALL_KERNEL_VER: c_long = 0x1009;

const SUPERCALL_SKEY_GET: c_long = 0x100a;
const SUPERCALL_SKEY_SET: c_long = 0x100b;
const SUPERCALL_SKEY_ROOT_ENABLE: c_long = 0x100c;

const SUPERCALL_SU: c_long = 0x1010;
const SUPERCALL_SU_TASK: c_long = 0x1011;

const SUPERCALL_MEM_PHYS: c_long = 0x1041;
const SUPERCALL_MEM_KERNEL_PHYS: c_long = 0x1042;
const SUPERCALL_MEM_MAP_KERNEL: c_long = 0x1048;
const SUPERCALL_MEM_MAP_USER: c_long = 0x1049;
const SUPERCALL_MEM_PROT: c_long = 0x1049;
const SUPERCALL_MEM_CACHE_FLUSH: c_long = 0x1049;
const SUPERCALL_SU_RESET_PATH: c_long = 0x1111;
const SUPERCALL_SCONTEXT_LEN: usize = 0x60;

#[repr(C)]
struct SuProfile {
    uid: i32,
    to_uid: i32,
    sctx: String,
}

fn hash_key(key: &CStr) -> c_long {
    let mut hash: c_long = 1000000007;
    for &byte in key.to_bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as c_long);
    }
    hash
}

fn hash_key_cmd(key: &CStr, cmd: c_long) -> c_long {
    let hash = hash_key(key);
    (hash & 0xFFFF0000) | cmd
}

fn ver_and_cmd(key: &CStr, cmd: c_long) -> c_long {
    let version_code: u32 = ((MAJOR << 16) + (MINOR << 8) + PATCH).try_into().unwrap();
    ((version_code as c_long) << 32) | (0x1158 << 16) | (cmd & 0xFFFF)
}

fn compact_cmd(key: &CStr, cmd: c_long) -> c_long {
    let ver: c_long = unsafe {
        syscall(
            __NR_SUPERCALL,
            key.as_ptr(),
            ver_and_cmd(key, SUPERCALL_KERNELPATCH_VER),
        )
    };
    if ver >= 0x0a05 {
        return ver_and_cmd(key, cmd);
    }
    hash_key_cmd(key, cmd)
}

fn sc_su_grant_uid(key: &CStr, profile: &SuProfile) -> c_long {
    if key.to_bytes().is_empty() {
        return (-libc::EINVAL).into();
    }
    unsafe {
        syscall(
            __NR_SUPERCALL,
            key.as_ptr(),
            compact_cmd(key, SUPERCALL_SU),
            profile,
        )
    }
}

fn sc_su_reset_path(key: &CStr, path: &CStr) -> c_long {
    if key.to_bytes().is_empty() || path.to_bytes().is_empty() {
        return (-libc::EINVAL).into();
    }
    unsafe {
        syscall(
            __NR_SUPERCALL,
            key.as_ptr(),
            compact_cmd(key, SUPERCALL_SU_RESET_PATH),
            path.as_ptr(),
        )
    }
}

fn read_file_to_string(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

pub fn init_notify_su_uid(superkey: &Option<String>) {
    let package_configs = read_ap_package_config();

    for config in package_configs {
        if config.allow == 1 && config.exclude == 0 {
            if let Some(ref key_str) = superkey {
                match CString::new(key_str.clone()) {
                    Ok(key) => {
                        let profile = SuProfile {
                            uid: config.uid,
                            to_uid: config.to_uid,
                            sctx: config.sctx.clone(),
                        };
                        let result = sc_su_grant_uid(&key, &profile);
                        println!("Processed {}: result = {}", config.pkg, result);
                    }
                    Err(e) => {
                        eprintln!("Failed to convert key to CString: {}", e);
                    }
                }
            } else {
                eprintln!("Superkey is None, skipping config: {}", config.pkg);
            }
        }
    }
}

pub fn init_notify_su_path(superkey: &Option<String>) {
    let su_path_file = "/data/adb/ap/su_path";

    match read_file_to_string(su_path_file) {
        Ok(su_path) => {
            if let Some(ref superkey_str) = superkey {
                match CString::new(superkey_str.clone()) {
                    Ok(superkey_cstr) => match CString::new(su_path.trim()) {
                        Ok(su_path_cstr) => {
                            let result = sc_su_reset_path(&superkey_cstr, &su_path_cstr);
                            if result == 0 {
                                println!("Path reset successfully");
                            } else {
                                eprintln!("Failed to reset path, error code: {}", result);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to convert su_path to CString: {}", e);
                        }
                    },
                    Err(e) => {
                        eprintln!("Failed to convert superkey to CString: {}", e);
                    }
                }
            } else {
                eprintln!("Superkey is None, skipping...");
            }
        }
        Err(e) => {
            eprintln!("Failed to read su_path file: {}", e);
        }
    }
}
