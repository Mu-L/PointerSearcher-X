use std::{fmt::Write, mem, path::Path};

use vmmap::{Process, ProcessInfo, VirtualMemoryRead, VirtualQuery};

use super::{ChainCommand, Error};

fn find_base_address<P: ProcessInfo>(proc: &P, name: &str, index: usize) -> Result<usize, &'static str> {
    proc.get_maps()
        .filter(|m| m.is_read())
        .filter(|m| {
            m.name()
                .is_some_and(|s| Path::new(s).file_name().is_some_and(|n| n.eq(name)))
        })
        .collect::<Vec<_>>()
        .get(index - 1)
        .map(|x| x.start())
        .ok_or("find modules error")
}

impl ChainCommand {
    pub fn init(self) -> Result<(), Error> {
        let ChainCommand { pid, chain, num } = self;
        let proc = Process::open(pid)?;
        let Chain { name, index, chain, offset } = parse_chain(&chain).ok_or("parse pointer chain error")?;
        let mut address = find_base_address(&proc, name, index)?;

        let mut buf = [0; mem::size_of::<usize>()];

        for off in chain {
            proc.read_at(&mut buf, address.checked_add_signed(off).ok_or("pointer overflow")?)?;
            address = usize::from_le_bytes(buf);
        }

        let address = address.checked_add_signed(offset).ok_or("pointer overflow")?;
        println!("{address:#x}");

        if let Some(num) = num {
            let mut buf = vec![0; num];
            proc.read_at(&mut buf, address)?;
            println!("{}", hex_encode(&buf));
        }

        Ok(())
    }
}

pub struct Chain<'a> {
    pub name: &'a str,
    pub index: usize,
    pub chain: Vec<isize>,
    pub offset: isize,
}

#[inline(always)]
fn parse_chain(chain: &str) -> Option<Chain> {
    let (curr, last) = chain.split_once('+')?;
    let (last, offset) = last.rsplit_once('@')?;
    let offset = offset.parse().ok()?;
    let chain = last
        .split('@')
        .map(|x| x.parse())
        .collect::<Result<Vec<isize>, _>>()
        .ok()?;
    let (name, index) = curr.rsplit_once('[')?;
    let index = index.trim_matches(']').parse().ok()?;
    Some(Chain { name, index, chain, offset })
}

#[inline(always)]
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(256), |mut output, b| {
        let _ = write!(output, "{b:02X}");
        output
    })
}
