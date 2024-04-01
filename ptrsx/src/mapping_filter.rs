#[cfg(target_os = "macos")]
#[inline]
pub fn mapping_filter<Q: vmmap::VirtualQuery>(page: &Q) -> bool {
    let Some(name) = page.name() else {
        return true;
    };

    if name.starts_with("/System/Library/")
        || name.starts_with("/usr/lib")
        || name.starts_with("/System/iOSSupport")
        || name.starts_with("/private")
        || !name.starts_with('/')
    {
        return false;
    }

    true
}

#[cfg(target_os = "linux")]
#[inline]
pub fn mapping_filter<Q: vmmap::VirtualQuery>(page: &Q) -> bool {
    use std::{fs::File, io::Read, path::Path};

    let Some(name) = page.name() else {
        return true;
    };
    if name.eq("[stack]") || name.eq("[heap]") {
        return true;
    }
    if name.get(0..7).is_some_and(|s| s.eq("/memfd:")) {
        return false;
    }
    let path = Path::new(name);
    if !path.has_root() || path.starts_with("/dev") {
        return false;
    }
    let mut buf = [0; 8];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok_and(|_| [0x7f, b'E', b'L', b'F'].eq(&buf[0..4]))
}

#[cfg(target_os = "android")]
#[inline]
pub fn mapping_filter<Q: vmmap::VirtualQuery>(page: &Q) -> bool {
    use std::{fs::File, io::Read, path::Path};

    // anonmyous return true
    let Some(name) = page.name() else {
        return true;
    };

    if name.eq("[anon:.bss]") || name.eq("[anon:libc_malloc]") || name.eq("[stack]") || name.eq("[heap]") {
        return true;
    }

    if name.get(0..7).is_some_and(|s| s.eq("/memfd:")) {
        return false;
    }

    let path = Path::new(name);

    if !path.has_root()
        || path.starts_with("/dev")
        || path.starts_with("/system")
        || path.starts_with("/system_ext")
        || path.starts_with("/apex")
        || path.starts_with("/product")
        || path.starts_with("/vendor")
        || path.extension().is_some_and(|x| x.eq("dex") || x.eq("odex"))
    {
        return false;
    }

    let mut buf = [0; 64];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok_and(|_| [0x7f, b'E', b'L', b'F'].eq(&buf[0..4]))
}

#[cfg(target_os = "windows")]
#[inline]
pub fn mapping_filter<Q: vmmap::VirtualQuery + vmmap::windows::VirtualQueryExt>(page: &Q) -> bool {
    use std::{fs::File, io::Read, path::Path};

    if page.is_guard() || page.is_free() {
        return false;
    }

    let Some(name) = page.name() else {
        return true;
    };
    if name[..40].contains("\\Windows\\") {
        return false;
    }
    let name = name.replacen(r#"\Device"#, r#"\\?"#, 1);
    let path = Path::new(&name);
    if !path.has_root() {
        return false;
    }
    let mut buf = [0; 8];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok_and(|_| [0x4d, 0x5a].eq(&buf[0..2]))
}
