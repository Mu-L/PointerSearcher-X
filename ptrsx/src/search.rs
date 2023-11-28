#[cfg(target_family = "unix")]
use std::os::unix::prelude::FileExt;
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fs::File,
    io, mem,
    ops::{Bound::Included, Range},
    path::Path,
};

use arrayvec::ArrayVec;

#[cfg(target_os = "windows")]
use super::WindowsFileExt;
use super::{decode_modules, Error, PtrsxScanner, PTRSIZE};

struct WalkParams<'a, W> {
    base: usize,
    depth: usize,
    target: usize,
    node: usize,
    offset: (usize, usize),
    points: &'a [usize],
    writer: &'a mut W,
}

// [usize] no dups optimized binary_search
#[inline(always)]
unsafe fn binary_search_by<'a, T, F>(slice: &'a [T], mut f: F) -> Result<usize, usize>
where
    F: FnMut(&'a T) -> Ordering,
{
    let mut size = slice.len();
    if size == 0 {
        return Err(0);
    }
    let mut base = 0usize;
    while size > 1 {
        let half = size / 2;
        let mid = base + half;
        let cmp = f(slice.get_unchecked(mid));
        base = if cmp == Ordering::Greater { base } else { mid };
        size -= half;
    }
    let cmp: Ordering = f(slice.get_unchecked(base));
    if cmp == Ordering::Equal {
        Ok(base)
    } else {
        Err(base + (cmp == Ordering::Less) as usize)
    }
}

type Tmp<'a> = (&'a mut ArrayVec<isize, 32>, &'a mut itoa::Buffer);

fn pointer_chain_scanner<W>(map: &BTreeMap<usize, Vec<usize>>, params: WalkParams<W>) -> io::Result<()>
where
    W: io::Write,
{
    unsafe { scanner(map, params, 1, (&mut ArrayVec::new_const(), &mut itoa::Buffer::new())) }
}

#[inline(always)]
unsafe fn scanner<W>(map: &BTreeMap<usize, Vec<usize>>, params: WalkParams<W>, lv: usize, tmp: Tmp) -> io::Result<()>
where
    W: io::Write,
{
    let WalkParams { base, depth, target, node, offset: (lr, ur), points, writer } = params;
    let (avec, itoa) = tmp;

    let min = target.saturating_sub(ur);
    let max = target.saturating_add(lr);

    let idx = binary_search_by(points, |p| p.cmp(&min)).unwrap_or_else(|x| x);

    if points
        .iter()
        .skip(idx)
        .copied()
        .take_while(|x| max.ge(x))
        .min_by_key(|x| (x.wrapping_sub(target) as isize).abs())
        .is_some_and(|_| avec.len() >= node)
    {
        writer.write_all(itoa.format(target - base).as_bytes())?;
        for &off in avec.iter().rev() {
            writer.write_all(&[0x40])?;
            writer.write_all(itoa.format(off).as_bytes())?;
        }
        writer.write_all(&[0xA])?;
    }

    if lv <= depth {
        for (&k, vec) in map.range((Included(min), Included(max))) {
            avec.push_unchecked(target.wrapping_sub(k) as isize);
            for &target in vec {
                scanner(
                    map,
                    WalkParams { base, depth, target, node, offset: (lr, ur), points, writer },
                    lv + 1,
                    (avec, itoa),
                )?;
            }
            avec.pop();
        }
    }

    Ok(())
}

pub struct Params<'a, W> {
    pub depth: usize,
    pub target: usize,
    pub node: usize,
    pub offset: (usize, usize),
    pub writer: &'a mut W,
}

impl PtrsxScanner {
    pub fn load_pointer_map_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Error> {
        let file = File::open(&path)?;
        const SIZE: usize = 8 + mem::size_of::<usize>();
        let mut headers = [0; SIZE];
        let mut seek = 0_u64;
        file.read_exact_at(&mut headers, seek)?;
        seek += headers.len() as u64;

        let (_, len) = headers.split_at(8);
        let len = usize::from_le_bytes(unsafe { *(len.as_ptr().cast()) });

        let mut buf = vec![0; len];
        file.read_exact_at(&mut buf, seek)?;
        self.modules = decode_modules(&buf);
        seek += len as u64;

        let mut buf = vec![0; PTRSIZE * 0x10000];
        loop {
            let size = file.read_at(&mut buf, seek)?;
            if size == 0 {
                break;
            }
            for chuks in buf[..size].chunks_exact(PTRSIZE * 2) {
                let (key, value) = chuks.split_at(PTRSIZE);
                unsafe {
                    self.forward.insert(
                        usize::from_le_bytes(*(key.as_ptr().cast())),
                        usize::from_le_bytes(*(value.as_ptr().cast())),
                    )
                };
            }
            seek += size as u64;
        }

        self.forward.iter().for_each(|(&k, &v)| {
            self.reverse.entry(v).or_default().push(k);
        });

        Ok(())
    }

    pub fn scanner_with_range<W: io::Write>(&self, range: Range<usize>, params: Params<W>) -> io::Result<()> {
        let points = &self
            .forward
            .range((Included(range.start), Included(range.end)))
            .map(|(&k, _)| k)
            .collect::<Vec<_>>();

        let Params { depth, target, node, offset, writer } = params;
        let params = WalkParams { base: range.start, depth, target, node, offset, points, writer };
        pointer_chain_scanner(&self.reverse, params)
    }

    pub fn scanner_with_address<W: io::Write>(&self, points: &[usize], params: Params<W>) -> io::Result<()> {
        let Params { depth, target, node, offset, writer } = params;
        let params = WalkParams { base: 0, depth, target, node, offset, points, writer };
        pointer_chain_scanner(&self.reverse, params)
    }
}

#[test]
fn test_pointer_chain_scanner_s1() {
    let forward = BTreeMap::from([
        (0x104B28008, 0x125F040A0),
        (0x104B28028, 0x125F04090),
        (0x104B281B0, 0x125F040E0),
        (0x125F04090, 0x125F04080),
    ]);

    let points = &forward
        .range((Included(0x104B18000), Included(0x104B38000)))
        .map(|(k, _)| k)
        .copied()
        .collect::<Vec<_>>();

    let mut reverse: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (k, v) in forward {
        reverse.entry(v).or_default().push(k);
    }

    let writer = &mut Vec::with_capacity(128);
    let params =
        WalkParams {
            base: 0x104B18000,
            depth: 4,
            target: 0x125F04080,
            node: 3,
            offset: (0, 16),
            points,
            writer,
        };

    pointer_chain_scanner(&reverse, params).unwrap();

    assert_eq!(writer, b"65576@0@16@16@0\n65576@0@16@0\n");
}

#[test]
fn test_pointer_chain_scanner_s2() {
    let forward = BTreeMap::from([
        (0x104B28008, 0x125F040A0),
        (0x104B28028, 0x125F04090),
        (0x104B281B0, 0x125F040E0),
        (0x125F04090, 0x125F04080),
    ]);

    let mut reverse: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (k, v) in forward {
        reverse.entry(v).or_default().push(k);
    }

    let writer = &mut Vec::with_capacity(128);

    let params = WalkParams {
        base: 0,
        depth: 4,
        target: 0x125F04080,
        node: 3,
        offset: (0, 16),
        points: &[0x125F04090],
        writer,
    };

    pointer_chain_scanner(&reverse, params).unwrap();

    assert_eq!(writer, b"4931469456@16@16@0\n4931469456@16@16@16@0\n");
}
