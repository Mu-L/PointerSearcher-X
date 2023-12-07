#![feature(slice_split_at_unchecked)]

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    fmt::Display,
    fs::File,
    io::{BufReader, BufWriter, Cursor, Read, Write},
    mem,
    ops::{Bound::Included, Range},
    path::Path,
    str::Lines,
};

use rangemap::RangeMap;
use vmmap::{Pid, Process, ProcessInfo, VirtualMemoryRead, VirtualQuery};

const PTRSIZE: usize = mem::size_of::<usize>();

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const DEFAULT_BUF_SIZE: usize = 0x4000;

#[cfg(any(target_os = "linux", target_os = "android"))]
const DEFAULT_BUF_SIZE: usize = 0x40000;

#[cfg(any(target_os = "windows", all(target_os = "macos", target_arch = "x86_64"),))]
const DEFAULT_BUF_SIZE: usize = 0x1000;

#[derive(Debug)]
pub enum Error {
    Vmmap(vmmap::Error),
    Io(std::io::Error),
}

impl From<vmmap::Error> for Error {
    fn from(value: vmmap::Error) -> Self {
        Self::Vmmap(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Vmmap(err) => write!(f, "{err}"),
            Error::Io(err) => write!(f, "{err}"),
        }
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[cfg(target_os = "macos")]
#[inline]
pub fn check_region<Q: VirtualQuery + vmmap::macos::VirtualQueryExt>(page: &Q) -> bool {
    if !page.is_read() || page.is_reserve() {
        return false;
    }

    let Some(name) = page.name() else {
        return matches!(page.tag(), |1..=9| 11 | 30 | 33 | 60 | 61);
    };
    let path = Path::new(name);
    if path.starts_with("/usr") {
        return false;
    }
    let mut buf = [0; 8];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok_and(|_| match buf[0..4] {
            [width, 0xfa, 0xed, 0xfe] if width == 0xcf || width == 0xce => true,
            [0xfe, 0xed, 0xfa, width] if width == 0xcf || width == 0xce => true,
            [0xca, 0xfe, 0xba, 0xbe] => u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) < 45,
            _ => false,
        })
}

#[cfg(target_os = "linux")]
#[inline]
pub fn check_region<Q: VirtualQuery>(page: &Q) -> bool {
    if !page.is_read() {
        return false;
    }

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
pub fn check_region<Q: VirtualQuery>(page: &Q) -> bool {
    if !page.is_read() {
        return false;
    }

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
pub fn check_region<Q: VirtualQuery>(page: &Q) -> bool {
    if !page.is_read() {
        return false;
    }

    let Some(name) = page.name() else {
        return true;
    };
    if name.contains("\\Windows\\System32\\") {
        return false;
    }
    let name = name.replacen(r#"\Device"#, r#"\\?"#, 1);
    let path = Path::new(&name);
    if !path.has_root() {
        return false;
    }
    let mut buf = [0; 8];
    File::open(path)
        .and_then(|mut f| f.read(&mut buf))
        .is_ok_and(|_| [0x4d, 0x5a].eq(&buf[0..2]))
}

#[derive(Default)]
pub struct PtrsxScanner {
    index: RangeMap<usize, String>,
    forward: BTreeMap<usize, usize>,
    reverse: BTreeMap<usize, Vec<usize>>,
}

pub struct Param {
    pub depth: usize,
    pub target: usize,
    pub node: usize,
    pub range: (usize, usize),
}

struct Region<'a> {
    start: usize,
    end: usize,
    name: &'a str,
}

struct RegionIter<'a>(Lines<'a>);

impl<'a> RegionIter<'a> {
    fn new(contents: &'a str) -> Self {
        Self(contents.lines())
    }
}

impl<'a> Iterator for RegionIter<'a> {
    type Item = Region<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let line = self.0.next()?;
        let mut split = line.splitn(2, ' ');
        let mut range_split = split.next()?.split('-');
        let start = usize::from_str_radix(range_split.next()?, 16).ok()?;
        let end = usize::from_str_radix(range_split.next()?, 16).ok()?;
        let name = split.next()?.trim();
        Some(Region { start, end, name })
    }
}

fn create_pointer_map<P, W>(proc: &P, region: &[(usize, usize)], is_align: bool, w: &mut W) -> Result<(), Error>
where
    P: VirtualMemoryRead,
    W: Write,
{
    let mut buf = [0; DEFAULT_BUF_SIZE];

    if is_align {
        for &(start, size) in region {
            for off in (0..size).step_by(DEFAULT_BUF_SIZE) {
                let size = proc.read_at(buf.as_mut_slice(), start + off)?;
                for (k, value) in buf[..size]
                    .windows(PTRSIZE)
                    .enumerate()
                    .step_by(PTRSIZE)
                    .map(|(k, buf)| (k, usize::from_le_bytes(unsafe { *(buf.as_ptr().cast()) })))
                {
                    if region
                        .binary_search_by(|&(start, size)| {
                            if (start..start + size).contains(&value) {
                                Ordering::Equal
                            } else {
                                start.cmp(&value)
                            }
                        })
                        .is_ok()
                    {
                        let key = start + off + k;
                        w.write_all(&key.to_le_bytes())?;
                        w.write_all(&value.to_le_bytes())?;
                    }
                }
            }
        }
    } else {
        for &(start, size) in region {
            for off in (0..size).step_by(DEFAULT_BUF_SIZE) {
                let size = proc.read_at(buf.as_mut_slice(), start + off)?;
                for (k, value) in buf[..size]
                    .windows(PTRSIZE)
                    .enumerate()
                    .map(|(k, buf)| (k, usize::from_le_bytes(unsafe { *(buf.as_ptr().cast()) })))
                {
                    if region
                        .binary_search_by(|&(start, size)| {
                            if (start..start + size).contains(&value) {
                                Ordering::Equal
                            } else {
                                start.cmp(&value)
                            }
                        })
                        .is_ok()
                    {
                        let key = start + off + k;
                        w.write_all(&key.to_le_bytes())?;
                        w.write_all(&value.to_le_bytes())?;
                    }
                }
            }
        }
    }

    Ok(())
}

impl PtrsxScanner {
    #[cfg(target_family = "unix")]
    const PREFIX: char = '/';
    #[cfg(target_os = "windows")]
    const PREFIX: char = '\\';

    pub fn create_pointer_map<W: Write>(&self, pid: Pid, align: bool, info_w: W, bin_w: W) -> Result<(), Error> {
        let proc = Process::open(pid)?;
        let pages = proc.get_maps().filter(check_region).collect::<Vec<_>>();
        let region = pages.iter().map(|m| (m.start(), m.size())).collect::<Vec<_>>();
        let mut counts = HashMap::new();
        let mut info_w = BufWriter::new(info_w);
        pages
            .iter()
            .flat_map(|m| {
                use core::fmt::Write;
                let mut name = m.name()?.rsplit_once(Self::PREFIX)?.1.to_string();
                let count = counts.entry(name.clone()).or_insert(1);
                let _ = write!(name, "[{}]", count);
                *count += 1;
                Some((m.start(), m.end(), name))
            })
            .try_for_each(|(start, end, name)| writeln!(info_w, "{start:x}-{end:x} {name}"))?;
        create_pointer_map(&proc, &region, align, &mut BufWriter::new(bin_w))
    }

    pub fn load_pointer_map<R: Read>(&mut self, reader: R) -> Result<()> {
        let mut buf = vec![0; PTRSIZE * 0x10000];
        let mut cursor = Cursor::new(reader);
        loop {
            let size = cursor.get_mut().read(&mut buf)?;
            if size == 0 {
                break;
            }
            for chuks in buf[..size].chunks_exact(PTRSIZE * 2) {
                let (key, value) = unsafe {
                    let (key, value) = chuks.split_at_unchecked(PTRSIZE);
                    (usize::from_le_bytes(*(key.as_ptr().cast())), usize::from_le_bytes(*(value.as_ptr().cast())))
                };
                self.forward.insert(key, value);
            }
        }
        self.forward.iter().for_each(|(&k, &v)| {
            self.reverse.entry(v).or_default().push(k);
        });
        Ok(())
    }

    pub fn set_modules(&mut self, modules: Vec<(Range<usize>, String)>) {
        self.index.extend(modules)
    }

    pub fn load_modules_info<R: Read>(&mut self, r: R) -> Result<()> {
        let contents = &mut String::with_capacity(0x80000);
        let mut reader = BufReader::new(r);
        let _ = reader.read_to_string(contents)?;
        self.index = RegionIter::new(contents)
            .map(|Region { start, end, name }| (start..end, name.to_string()))
            .collect();
        Ok(())
    }

    pub fn pointer_chain_scanner<W: Write>(&mut self, param: Param, w: W) -> Result<()> {
        let points = &self
            .index
            .iter()
            .flat_map(|(Range { start, end }, _)| self.forward.range((Included(start), Included(end))))
            .map(|(&k, _)| k)
            .collect::<Vec<_>>();
        self.scanner(param, points, 1, &mut Vec::with_capacity(0x100), &mut BufWriter::new(w))
    }

    fn scanner<W>(&self, param: Param, points: &[usize], lv: usize, chain: &mut Vec<isize>, w: &mut W) -> Result<()>
    where
        W: Write,
    {
        let Param { depth, target, node, range } = param;

        let min = target.saturating_sub(range.1);
        let max = target.saturating_add(range.0);

        let idx = points.binary_search(&min).unwrap_or_else(|x| x);

        if points
            .iter()
            .skip(idx)
            .copied()
            .take_while(|x| max.ge(x))
            .min_by_key(|x| (x.wrapping_sub(target) as isize).abs())
            .is_some_and(|_| chain.len() >= node)
        {
            if let Some((Range { start, end: _ }, name)) = self.index.get_key_value(&target) {
                write!(w, "{name}+{}", target - start)?;
                chain.iter().rev().try_for_each(|o| write!(w, "@{o}"))?;
                writeln!(w)?;
            }
        }

        if lv <= depth {
            for (&k, vec) in self.reverse.range((Included(min), Included(max))) {
                chain.push(target.wrapping_sub(k) as isize);
                vec.iter().try_for_each(|&target| {
                    self.scanner(Param { depth, target, node, range }, points, lv + 1, chain, w)
                })?;
                chain.pop();
            }
        }

        Ok(())
    }
}
