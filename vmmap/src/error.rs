#[cfg(target_os = "macos")]
pub enum Error {
    OpenProcess(machx::kern_return::kern_return_t),
    ReadMemory(machx::kern_return::kern_return_t),
    WriteMemory(machx::kern_return::kern_return_t),
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub enum Error {
    OpenProcess(std::io::Error),
    ReadMemory(std::io::Error),
    WriteMemory(std::io::Error),
}

#[cfg(target_os = "windows")]
pub enum Error {
    OpenProcess(windows_sys::Win32::Foundation::WIN32_ERROR),
    ReadMemory(windows_sys::Win32::Foundation::WIN32_ERROR),
    WriteMemory(windows_sys::Win32::Foundation::WIN32_ERROR),
}

#[cfg(target_os = "macos")]
macro_rules! mach_error {
    ($arg:expr) => {{
        let ptr = machx::error::mach_error_string($arg);
        core::str::from_utf8_unchecked(std::ffi::CStr::from_ptr(ptr).to_bytes())
    }};
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(target_os = "macos")]
        unsafe {
            match self {
                Error::OpenProcess(err) => write!(f, "OpenProcess, {}. code: {err}", mach_error!(*err)),
                Error::ReadMemory(err) => write!(f, "ReadMemory, {}. code: {err}", mach_error!(*err)),
                Error::WriteMemory(err) => write!(f, "WriteMemory, {}. code: {err}", mach_error!(*err)),
            }
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        match self {
            Error::OpenProcess(err) => write!(f, "OpenProcess, {err}"),
            Error::ReadMemory(err) => write!(f, "ReadMemory, {err}"),
            Error::WriteMemory(err) => write!(f, "WriteMemory, {err}"),
        }
        #[cfg(target_os = "windows")]
        match self {
            Error::OpenProcess(err) => write!(f, "OpenProcess, code: {err}"),
            Error::ReadMemory(err) => write!(f, "ReadMemory, code: {err}"),
            Error::WriteMemory(err) => write!(f, "WriteMemory, code: {err}"),
        }
    }
}
