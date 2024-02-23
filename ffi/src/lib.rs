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

const PTR_NULL: &str = "ptr is null";
const NO_OPEN_PROCESS: &str = "no process is opened";

macro_rules! null_ptr {
    ($m:expr) => {
        match $m {
            Some(val) => val,
            None => {
                set_last_error(PTR_NULL);
                return -1;
            }
        }
    };
}

macro_rules! ref_proc {
    ($m:expr) => {
        match $m {
            Some(val) => val,
            None => {
                set_last_error(NO_OPEN_PROCESS);
                return -2;
            }
        }
    };
}

macro_rules! error {
    ($m:expr) => {
        match $m {
            Ok(val) => val,
            Err(err) => {
                set_last_error(err);
                return -3;
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
pub struct PointerScanTool {
    scan: PtrsxScanner,
    proc: Option<Process>,
}

#[no_mangle]
pub extern "C" fn ptrs_init() -> *mut PointerScanTool {
    Box::into_raw(Box::default())
}

#[no_mangle]
pub unsafe extern "C" fn ptrs_free(ptr: *mut PointerScanTool) {
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
pub unsafe extern "C" fn ptrs_set_proc(ptr: *mut PointerScanTool, pid: Pid) -> c_int {
    let proc = error!(Process::open(pid));
    let this = null_ptr!(ptr.as_mut());
    this.proc = Some(proc);
    0
}

#[no_mangle]
pub unsafe extern "C" fn ptrs_create_pointer_map(
    ptr: *mut PointerScanTool,
    info_path: *const c_char,
    bin_path: *const c_char,
) -> c_int {
    let info_file = error!(CStr::from_ptr(null_ptr!(info_path.as_ref())).to_str());
    let bin_file = error!(CStr::from_ptr(null_ptr!(bin_path.as_ref())).to_str());

    dbg!(info_file, bin_file);

    let w1 = error!(fs::OpenOptions::new().append(true).create_new(true).open(info_file));
    let w2 = error!(fs::OpenOptions::new().append(true).create_new(true).open(bin_file));
    let this = null_ptr!(ptr.as_ref());
    let proc = ref_proc!(this.proc.as_ref());
    error!(this.scan.create_pointer_map(proc, true, w1, w2));

    0
}

#[no_mangle]
pub unsafe extern "C" fn ptrs_load_pointer_map(
    ptr: *mut PointerScanTool,
    info_path: *const c_char,
    bin_path: *const c_char,
) -> c_int {
    let scan = &mut null_ptr!(ptr.as_mut()).scan;
    let info_path = error!(CStr::from_ptr(null_ptr!(info_path.as_ref())).to_str());

    dbg!(info_path);

    let file = error!(fs::File::open(info_path));
    error!(scan.load_modules_info(file));
    let bin_path = error!(CStr::from_ptr(null_ptr!(bin_path.as_ref())).to_str());

    dbg!(bin_path);

    let file = error!(fs::File::open(bin_path));
    error!(scan.load_pointer_map(file));
    0
}

#[no_mangle]
pub unsafe extern "C" fn ptrs_scan_pointer_chain(
    ptr: *mut PointerScanTool,
    params: Param,
    file_path: *const c_char,
) -> c_int {
    let scan = &null_ptr!(ptr.as_ref()).scan;
    let Param { addr, depth, node, left, right } = params;
    let file_name = error!(CStr::from_ptr(null_ptr!(file_path.as_ref())).to_str());

    dbg!(addr, depth, node, left, right, file_name);

    let file = error!(fs::OpenOptions::new().append(true).create_new(true).open(file_name));
    let param = ptrsx::Param { depth, addr, node, range: (left, right) };
    error!(scan.pointer_chain_scanner(param, file));

    0
}

#[no_mangle]
pub unsafe extern "C" fn compare_two_file(file1: *const c_char, file2: *const c_char, outfile: *const c_char) -> c_int {
    let file1 = error!(CStr::from_ptr(null_ptr!(file1.as_ref())).to_str());
    let file2 = error!(CStr::from_ptr(null_ptr!(file2.as_ref())).to_str());
    let outfile = error!(CStr::from_ptr(null_ptr!(outfile.as_ref())).to_str());

    dbg!(file1, file2, outfile);

    let b1 = error!(fs::read_to_string(file1));
    let b2 = error!(fs::read_to_string(file2));
    let s1 = b1.lines().collect::<HashSet<_>>();
    let s2 = b2.lines().collect::<HashSet<_>>();

    let f = error!(fs::OpenOptions::new().append(true).create(true).open(outfile));
    let mut w = BufWriter::new(f);
    error!(s1.intersection(&s2).try_for_each(|s| writeln!(w, "{s}")));

    0
}

#[no_mangle]
pub unsafe extern "C" fn ptrs_get_chain_addr(
    ptr: *mut PointerScanTool,
    chain: *const c_char,
    addr: *mut usize,
) -> c_int {
    let _proc = ref_proc!(null_ptr!(ptr.as_ref()).proc.as_ref());
    let chain = error!(CStr::from_ptr(null_ptr!(chain.as_ref())).to_str());
    dbg!(chain);
    // TODO

    addr.write(12345678912345123451);

    0
}

#[no_mangle]
pub unsafe extern "C" fn ptrs_filter_invalid(
    ptr: *mut PointerScanTool,
    infile: *const c_char,
    outfile: *const c_char,
) -> c_int {
    let _proc = ref_proc!(null_ptr!(ptr.as_ref()).proc.as_ref());
    let infile = error!(CStr::from_ptr(null_ptr!(infile.as_ref())).to_str());
    let outfile = error!(CStr::from_ptr(null_ptr!(outfile.as_ref())).to_str());

    dbg!(infile, outfile);

    // TODO

    0
}

#[no_mangle]
pub unsafe extern "C" fn ptrs_filter_value(
    ptr: *mut PointerScanTool,
    infile: *const c_char,
    outfile: *const c_char,
    data: *const u8,
    size: usize,
) -> c_int {
    let _proc = ref_proc!(null_ptr!(ptr.as_ref()).proc.as_ref());
    let value = null_ptr!(ptr::slice_from_raw_parts(data, size).as_ref());
    let infile = error!(CStr::from_ptr(null_ptr!(infile.as_ref())).to_str());
    let outfile = error!(CStr::from_ptr(null_ptr!(outfile.as_ref())).to_str());

    dbg!(infile, outfile, value);

    // TODO

    0
}

#[no_mangle]
pub unsafe extern "C" fn ptrs_filter_addr(
    ptr: *mut PointerScanTool,
    infile: *const c_char,
    outfile: *const c_char,
    addr: usize,
) -> c_int {
    let _proc = ref_proc!(null_ptr!(ptr.as_ref()).proc.as_ref());
    let infile = error!(CStr::from_ptr(null_ptr!(infile.as_ref())).to_str());
    let outfile = error!(CStr::from_ptr(null_ptr!(outfile.as_ref())).to_str());

    dbg!(infile, outfile, addr);

    // TODO

    0
}
