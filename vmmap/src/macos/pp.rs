#[allow(non_camel_case_types)]
pub mod ffi {
    pub type __uint32_t = ::core::ffi::c_uint;
    pub type __int64_t = ::core::ffi::c_longlong;
    pub type __darwin_natural_t = ::core::ffi::c_uint;
    pub type natural_t = __darwin_natural_t;
    pub type __darwin_uid_t = __uint32_t;
    pub type uid_t = __darwin_uid_t;
    pub type gid_t = __darwin_gid_t;
    pub type __darwin_gid_t = __uint32_t;
    pub type off_t = __darwin_off_t;
    pub type __darwin_off_t = __int64_t;
    pub type kern_return_t = ::core::ffi::c_int;
    pub type mach_port_name_t = natural_t;
    pub type mach_port_t = ::core::ffi::c_uint;
    pub type vm_map_t = mach_port_t;
    pub type mach_vm_address_t = u64;
    pub type vm_offset_t = usize;
    pub type vm_prot_t = ::core::ffi::c_int;
    pub type mach_msg_type_number_t = natural_t;
    pub type vm_task_entry_t = mach_port_t;
    pub type mach_vm_size_t = u64;
    pub const MACH_PORT_NULL: mach_port_t = 0;
    pub const VM_PROT_WRITE: vm_prot_t = 1 << 1;
    pub const KERN_SUCCESS: kern_return_t = 0;
    pub const ESRCH: ::core::ffi::c_int = 3;
    pub const EINVAL: ::core::ffi::c_int = 22;

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct fsid {
        pub val: [i32; 2usize],
    }
    pub type fsid_t = fsid;

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct proc_regioninfo {
        pub pri_protection: u32,
        pub pri_max_protection: u32,
        pub pri_inheritance: u32,
        pub pri_flags: u32,
        pub pri_offset: u64,
        pub pri_behavior: u32,
        pub pri_user_wired_count: u32,
        pub pri_user_tag: u32,
        pub pri_pages_resident: u32,
        pub pri_pages_shared_now_private: u32,
        pub pri_pages_swapped_out: u32,
        pub pri_pages_dirtied: u32,
        pub pri_ref_count: u32,
        pub pri_shadow_depth: u32,
        pub pri_share_mode: u32,
        pub pri_private_pages_resident: u32,
        pub pri_shared_pages_resident: u32,
        pub pri_obj_id: u32,
        pub pri_depth: u32,
        pub pri_address: u64,
        pub pri_size: u64,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct vinfo_stat {
        pub vst_dev: u32,
        pub vst_mode: u16,
        pub vst_nlink: u16,
        pub vst_ino: u64,
        pub vst_uid: uid_t,
        pub vst_gid: gid_t,
        pub vst_atime: i64,
        pub vst_atimensec: i64,
        pub vst_mtime: i64,
        pub vst_mtimensec: i64,
        pub vst_ctime: i64,
        pub vst_ctimensec: i64,
        pub vst_birthtime: i64,
        pub vst_birthtimensec: i64,
        pub vst_size: off_t,
        pub vst_blocks: i64,
        pub vst_blksize: i32,
        pub vst_flags: u32,
        pub vst_gen: u32,
        pub vst_rdev: u32,
        pub vst_qspare: [i64; 2usize],
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct vnode_info {
        pub vi_stat: vinfo_stat,
        pub vi_type: ::core::ffi::c_int,
        pub vi_pad: ::core::ffi::c_int,
        pub vi_fsid: fsid_t,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct vnode_info_path {
        pub vip_vi: vnode_info,
        pub vip_path: [::core::ffi::c_char; 1024usize],
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct proc_regionwithpathinfo {
        pub prp_prinfo: proc_regioninfo,
        pub prp_vip: vnode_info_path,
    }

    pub const PROC_PIDREGIONPATHINFO: core::ffi::c_int = 8;
    pub const PROC_PIDREGIONPATHINFO_SIZE: core::ffi::c_int =
        core::mem::size_of::<proc_regionwithpathinfo>() as core::ffi::c_int;

    extern "C" {
        pub fn proc_pidinfo(
            pid: ::core::ffi::c_int,
            flavor: ::core::ffi::c_int,
            arg: u64,
            buffer: *mut ::core::ffi::c_void,
            buffersize: ::core::ffi::c_int,
        ) -> ::core::ffi::c_int;
        static mach_task_self_: mach_port_t;
        pub fn task_for_pid(
            target_tport: mach_port_name_t,
            pid: ::core::ffi::c_int,
            t: *mut mach_port_name_t,
        ) -> kern_return_t;
        pub fn mach_vm_write(
            target_task: vm_map_t,
            address: mach_vm_address_t,
            data: vm_offset_t,
            dataCnt: mach_msg_type_number_t,
        ) -> kern_return_t;
        pub fn mach_vm_read_overwrite(
            target_task: vm_task_entry_t,
            address: mach_vm_address_t,
            size: mach_vm_size_t,
            data: mach_vm_address_t,
            outsize: *mut mach_vm_size_t,
        ) -> kern_return_t;
    }

    pub unsafe fn mach_task_self() -> mach_port_t {
        mach_task_self_
    }
}

use std::{ffi::CStr, io::ErrorKind, mem::MaybeUninit};

use ffi::*;
use machx::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ};

use crate::{Process, VirtualQuery};

pub fn mappings_for_pid(pid: i32) -> Result<Vec<proc_regionwithpathinfo>, std::io::Error> {
    let mut r = vec![];
    let mut addr: u64 = 0;
    loop {
        let mut reg: MaybeUninit<proc_regionwithpathinfo> = MaybeUninit::zeroed();
        let written = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDREGIONPATHINFO,
                addr,
                reg.as_mut_ptr() as *mut core::ffi::c_void,
                PROC_PIDREGIONPATHINFO_SIZE,
            )
        };
        if written <= 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(ESRCH) || err.raw_os_error() == Some(EINVAL) {
                break;
            }
            return Err(err);
        }
        if written < PROC_PIDREGIONPATHINFO_SIZE {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                format!("only recieved {}/{} bytes of struct", written, PROC_PIDREGIONPATHINFO_SIZE),
            ));
        }
        let reg = unsafe { reg.assume_init() };
        addr = reg.prp_prinfo.pri_address + reg.prp_prinfo.pri_size;
        r.push(reg);
    }
    Ok(r)
}

pub type Mapping = ffi::proc_regionwithpathinfo;

pub trait ProcessInfoProcFixed {
    fn pid(&self) -> i32;
    fn app_path(&self) -> &std::path::Path;
    fn get_maps(&self) -> impl Iterator<Item = crate::Result<Mapping>>;
}

impl ProcessInfoProcFixed for Process {
    fn pid(&self) -> i32 {
        self.pid
    }

    fn app_path(&self) -> &std::path::Path {
        &self.pathname
    }

    fn get_maps(&self) -> impl Iterator<Item = crate::Result<Mapping>> {
        let mp = mappings_for_pid(self.pid).unwrap();
        mp.into_iter().map(Ok)
    }
}

impl VirtualQuery for Mapping {
    fn start(&self) -> usize {
        self.prp_prinfo.pri_address as usize
    }

    fn end(&self) -> usize {
        (self.prp_prinfo.pri_address + self.prp_prinfo.pri_size) as usize
    }

    fn size(&self) -> usize {
        self.prp_prinfo.pri_size as usize
    }

    fn is_read(&self) -> bool {
        self.prp_prinfo.pri_protection as i32 & VM_PROT_READ != 0
    }

    fn is_write(&self) -> bool {
        self.prp_prinfo.pri_protection as i32 & VM_PROT_WRITE != 0
    }

    fn is_exec(&self) -> bool {
        self.prp_prinfo.pri_protection as i32 & VM_PROT_EXECUTE != 0
    }

    fn name(&self) -> Option<&str> {
        unsafe {
            let path = CStr::from_ptr(self.prp_vip.vip_path.as_ptr());
            if path.is_empty() {
                None
            } else {
                Some(path.to_str().unwrap())
            }
        }
    }
}
