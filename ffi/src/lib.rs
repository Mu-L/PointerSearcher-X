#![allow(clippy::missing_safety_doc)]

#[cfg(not(target_endian = "little"))]
compile_error!("not supported.");

mod ffi_types;

use std::{
    ffi::{c_char, c_int, CStr, CString},
    fs::{File, OpenOptions},
    path::Path,
    ptr::{self, slice_from_raw_parts},
    str::{self, Utf8Error},
};

pub use ffi_types::*;
use ptrsx::PtrsxScanner;
use vmmap::Pid;

macro_rules! try_result {
    ($p:expr, $m:expr) => {
        match $m {
            Ok(val) => val,
            Err(err) => {
                $p.set_last_error(err);
                return -1;
            }
        }
    };
}

#[derive(Default)]
pub struct PointerSearcherX {
    inner: PtrsxScanner,
    last_error: Option<CString>,
}

const PARAMS_ERROR: &str = "params error";

impl PointerSearcherX {
    fn set_last_error(&mut self, err: impl ToString) {
        self.last_error = Some(unsafe { CString::from_vec_unchecked(err.to_string().into()) })
    }
}

#[no_mangle]
pub unsafe extern "C" fn get_last_error(ptr: *mut PointerSearcherX) -> *const c_char {
    let ptrsx = &(*ptr);
    match &ptrsx.last_error {
        Some(err) => err.as_ptr(),
        None => ptr::null(),
    }
}

#[no_mangle]
pub extern "C" fn ptrsx_init() -> *mut PointerSearcherX {
    Box::into_raw(Box::default())
}

#[no_mangle]
pub unsafe extern "C" fn ptrsx_free(ptr: *mut PointerSearcherX) {
    if ptr.is_null() {
        return;
    }
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn create_pointer_map_file(
    ptr: *mut PointerSearcherX,
    pid: Pid,
    align: bool,
    info_file_path: *const c_char,
    bin_file_path: *const c_char,
) -> c_int {
    let ptrsx = &mut (*ptr);
    let string = try_result!(ptrsx, str::from_utf8(CStr::from_ptr(info_file_path).to_bytes()));
    let info_file_name = Path::new(string);
    let string = try_result!(ptrsx, str::from_utf8(CStr::from_ptr(bin_file_path).to_bytes()));
    let bin_file_name = Path::new(string);
    let scanner = &ptrsx.inner;
    let info_file = try_result!(
        ptrsx,
        OpenOptions::new()
            .write(true)
            .read(true)
            .append(true)
            .create_new(true)
            .open(info_file_name)
    );
    let bin_file = try_result!(
        ptrsx,
        OpenOptions::new()
            .write(true)
            .read(true)
            .append(true)
            .create_new(true)
            .open(bin_file_name)
    );

    try_result!(ptrsx, scanner.create_pointer_map(pid, align, info_file, bin_file));

    0
}

#[no_mangle]
pub unsafe extern "C" fn load_pointer_map_file(ptr: *mut PointerSearcherX, file_path: *const c_char) -> c_int {
    let ptrsx = &mut (*ptr);
    let string = try_result!(ptrsx, str::from_utf8(CStr::from_ptr(file_path).to_bytes()));
    let file = try_result!(ptrsx, File::open(string));
    let scanner = &mut ptrsx.inner;
    try_result!(ptrsx, scanner.load_pointer_map(file));
    0
}

#[no_mangle]
pub unsafe extern "C" fn scanner_pointer_chain(
    ptr: *mut PointerSearcherX,
    modules: ModuleList,
    params: Params,
    file_path: *const c_char,
) -> c_int {
    let ptrsx = &mut (*ptr);
    let scanner = &mut ptrsx.inner;
    let Params { target, depth, node, rangel, ranger } = params;
    if node >= depth || depth > 32 {
        ptrsx.set_last_error(PARAMS_ERROR);
        return -1;
    }
    let string = try_result!(ptrsx, str::from_utf8(CStr::from_ptr(file_path).to_bytes()));
    let file_name = Path::new(string);
    let file = try_result!(
        ptrsx,
        OpenOptions::new()
            .write(true)
            .read(true)
            .append(true)
            .create_new(true)
            .open(file_name)
    );

    let param = ptrsx::Param { depth, target, node, offset: (rangel, ranger) };
    let binding = &*slice_from_raw_parts(modules.data, modules.len);
    let modules = binding
        .iter()
        .map(|&Module { start, end, name }| {
            Ok((start..end, str::from_utf8(CStr::from_ptr(name).to_bytes())?.to_string()))
        })
        .collect::<Result<Vec<_>, Utf8Error>>();

    let modules = try_result!(ptrsx, modules);
    scanner.set_modules(modules);

    try_result!(ptrsx, scanner.pointer_chain_scanner(param, file));

    0
}
