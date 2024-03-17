use std::{fmt::Write, mem, path::Path};

#[cfg(target_os = "macos")]
use vmmap::macos::cmd::ProcessInfoCmdFixed as ProcessInfo;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "android"))]
use vmmap::ProcessInfo;
use vmmap::{Process, VirtualMemoryRead, VirtualMemoryWrite, VirtualQuery};

use super::{Error, TestChainCommand};

impl TestChainCommand {
    pub fn init(self) -> Result<(), Error> {
        let TestChainCommand { pid, chain, write, read } = self;
        let proc = Process::open(pid)?;
        let address = get_pointer_chain_address(&proc, chain).ok_or("Invalid pointer chain")?;
        println!("target = {address:x}");

        if let Some(size) = read {
            let mut buf = vec![0; size];
            proc.read_exact_at(&mut buf, address)?;
            println!("{}", hex_encode(&buf));
        }

        if let Some(bytes) = write {
            proc.write_at(&bytes.0, address)?;
        }

        Ok(())
    }
}

#[inline]
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(256), |mut output, b| {
        let _ = write!(output, "{b:02X}");
        output
    })
}

#[inline]
pub fn get_pointer_chain_address<P, S>(proc: &P, chain: S) -> Option<usize>
where
    P: VirtualMemoryRead + ProcessInfo,
    S: AsRef<str>,
{
    let (a, cs) = chain.as_ref().rsplit_once(']')?;
    let (name, idx) = a.rsplit_once('[')?;
    let idx = idx.parse::<usize>().ok()?;
    let mut iter = cs.split('.');
    let base = iter.next()?.parse().ok()?;
    let items = iter.map(|s| s.parse());

    let mut address = find_base_address(proc, name, idx)?.checked_add(base)?;

    println!("{name}[{idx}] + {base} = {address:x}");
    let mut buf = [0; mem::size_of::<usize>()];
    for item in items {
        proc.read_exact_at(&mut buf, address).ok()?;
        let item = item.ok()?;
        address = usize::from_le_bytes(buf).checked_add_signed(item)?;
        println!("+ {item} = {address:x}");
    }

    Some(address)
}

struct Module<'a> {
    start: usize,
    end: usize,
    name: &'a str,
}

#[inline]
fn find_base_address<P: ProcessInfo>(proc: &P, name: &str, index: usize) -> Option<usize> {
    let vqs = proc.get_maps().flatten().collect::<Vec<_>>();
    vqs.iter()
        .filter(|x| x.is_write() && x.is_read())
        .flat_map(|x| Some(Module { start: x.start(), end: x.end(), name: x.name()? }))
        .fold(Vec::<Module>::with_capacity(vqs.len()), |mut acc, cur| {
            match acc.last_mut() {
                Some(last) if last.name == cur.name => last.end = cur.end,
                _ => acc.push(cur),
            }
            acc
        })
        .into_iter()
        .map(|Module { start, end, name }| {
            let name = Path::new(name).file_name().and_then(|s| s.to_str()).unwrap_or(name);
            Module { start, end, name }
        })
        .filter(|x| x.name.eq(name))
        .nth(index)
        .map(|x| x.start)
}
