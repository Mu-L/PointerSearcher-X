#![allow(clippy::missing_safety_doc)]

#[cfg(not(target_endian = "little"))]
compile_error!("not supported.");

use std::{
    cell::RefCell,
    collections::HashSet,
    ffi::{c_char, c_int, CStr, CString},
    fs,
    io::{BufWriter, Write},
    ptr,
};

use ptrsx::PtrsxScanner;
use vmmap::{Pid, Process};

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_last_error(err: impl ToString) {
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(unsafe { CString::from_vec_unchecked(err.to_string().into_bytes()) });
    });
}

macro_rules! error {
    ($m:expr) => {
        match $m {
            Ok(val) => val,
            Err(err) => {
                set_last_error(err);
                return -2;
            }
        }
    };
}

#[repr(C)]
pub struct Param {
    pub addr: usize,
    pub depth: usize,
    pub node: usize,
    pub left: usize,
    pub right: usize,
}

#[derive(Default)]
pub struct PointerScan {
    inner: PtrsxScanner,
}

#[no_mangle]
pub extern "C" fn ptrs_init() -> *mut PointerScan {
    Box::into_raw(Box::default())
}

#[no_mangle]
pub unsafe extern "C" fn ptrs_free(ptr: *mut PointerScan) {
    if ptr.is_null() {
        return;
    }
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn get_last_error() -> *const c_char {
    LAST_ERROR.with(|prev| match prev.borrow().as_ref() {
        Some(err) => err.as_ptr(),
        None => ptr::null_mut(),
    })
}

#[no_mangle]
pub unsafe extern "C" fn ptrs_create_pointer_map(
    ptr: *mut PointerScan,
    pid: Pid,
    align: bool,
    info_path: *const c_char,
    bin_path: *const c_char,
) -> c_int {
    let info_file_path = error!(CStr::from_ptr(info_path).to_str());
    let bin_file_path = error!(CStr::from_ptr(bin_path).to_str());
    let this = &mut (*ptr).inner;
    let info_file = error!(
        fs::OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(info_file_path)
    );
    let bin_file = error!(fs::OpenOptions::new().append(true).create_new(true).open(bin_file_path));
    error!(this.create_pointer_map(pid, align, info_file, bin_file));

    0
}

#[no_mangle]
pub unsafe extern "C" fn ptrs_load_pointer_map(
    ptr: *mut PointerScan,
    info_path: *const c_char,
    bin_path: *const c_char,
) -> c_int {
    let this = &mut (*ptr).inner;
    let info_path = error!(CStr::from_ptr(info_path).to_str());
    let file = error!(fs::File::open(info_path));
    error!(this.load_modules_info(file));
    let bin_path = error!(CStr::from_ptr(bin_path).to_str());
    let file = error!(fs::File::open(bin_path));
    error!(this.load_pointer_map(file));
    0
}

#[no_mangle]
pub unsafe extern "C" fn ptrs_scan_pointer_chain(
    ptr: *mut PointerScan,
    params: Param,
    file_path: *const c_char,
) -> c_int {
    let this = &mut (*ptr).inner;
    let Param { addr, depth, node, left, right } = params;
    let file_name = error!(CStr::from_ptr(file_path).to_str());
    let file = error!(fs::OpenOptions::new().append(true).create_new(true).open(file_name));
    let param = ptrsx::Param { depth, addr, node, range: (left, right) };
    error!(this.pointer_chain_scanner(param, file));

    0
}

#[no_mangle]
pub unsafe extern "C" fn compare_two_file(file1: *const c_char, file2: *const c_char, outfile: *const c_char) -> c_int {
    let file1 = error!(CStr::from_ptr(file1).to_str());
    let file2 = error!(CStr::from_ptr(file2).to_str());
    let outfile = error!(CStr::from_ptr(outfile).to_str());

    let b1 = error!(fs::read_to_string(file1));
    let b2 = error!(fs::read_to_string(file2));
    let s1 = b1.lines().collect::<HashSet<_>>();
    let s2 = b2.lines().collect::<HashSet<_>>();

    let f = error!(fs::OpenOptions::new().append(true).create(true).open(outfile));
    let mut w = BufWriter::new(f);
    error!(s1.intersection(&s2).try_for_each(|s| writeln!(w, "{s}")));

    0
}

#[derive(Default)]
pub struct PointerVerify {
    proc: Option<Process>,
}

#[no_mangle]
pub extern "C" fn ptrv_init() -> *mut PointerVerify {
    Box::into_raw(Box::default())
}

#[no_mangle]
pub unsafe extern "C" fn ptrv_free(ptr: *mut PointerVerify) {
    if ptr.is_null() {
        return;
    }
    let _ = Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn ptrv_set_proc(ptr: *mut PointerVerify, pid: Pid) -> c_int {
    let proc = error!(Process::open(pid));
    let this = &mut (*ptr);
    this.proc = Some(proc);
    0
}

#[no_mangle]
pub unsafe extern "C" fn ptrv_invalid_filter(ptr: *mut PointerVerify, _file: *const c_char) -> c_int {
    let _proc = match &(*ptr).proc {
        Some(p) => p,
        None => return -2,
    };

    // TODO

    0
}

#[no_mangle]
pub unsafe extern "C" fn ptrv_value_filter(
    ptr: *mut PointerVerify,
    _file: *const c_char,
    _data: *const u8,
    _size: usize,
) -> c_int {
    let _proc = match &(*ptr).proc {
        Some(p) => p,
        None => return -2,
    };

    // TODO

    0
}
