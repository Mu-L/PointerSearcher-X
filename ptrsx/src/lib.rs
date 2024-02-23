use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    io::{BufReader, BufWriter, Cursor, Read, Write},
    mem,
    ops::{Bound, ControlFlow, Range},
    path::Path,
};

mod error;
mod mapping_filter;
mod pointer_map;
mod pointer_scan;
mod rangemap;
mod try_trait;

pub use error::{Error, Result};
use mapping_filter::mapping_filter;
use pointer_map::try_create_pointer_map;
use pointer_scan::{try_pointer_chain_scan, Param};
use rangemap::RangeMap;
use vmmap::{ProcessInfo, VirtualMemoryRead, VirtualQuery};

// 基址模块信息
struct Module<'a> {
    start: usize,
    end: usize,
    name: &'a str,
}

struct ModuleIter<'a>(core::str::Lines<'a>);

impl<'a> ModuleIter<'a> {
    fn new(contents: &'a str) -> Self {
        Self(contents.lines())
    }
}

impl<'a> Iterator for ModuleIter<'a> {
    type Item = Module<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let line = self.0.next()?;
        let mut split = line.splitn(2, ' ');
        let mut range_split = split.next()?.split('-');
        let start = usize::from_str_radix(range_split.next()?, 16).ok()?;
        let end = usize::from_str_radix(range_split.next()?, 16).ok()?;
        let name = split.next()?.trim();
        Some(Module { start, end, name })
    }
}

#[derive(Default)]
pub struct PtrsxScanner {
    index: RangeMap<usize, String>,
    forward: BTreeSet<usize>,
    reverse: BTreeMap<usize, Vec<usize>>,
}

pub struct UserParam {
    pub depth: usize,
    pub addr: usize,
    pub range: (usize, usize),
    // 使用模块名+offset作为基址
    pub use_module: bool,
    // 只保留长度大于node的指针链
    pub node: Option<usize>,
    // 限制最大指针链结果数量
    pub max: Option<usize>,
    // 必须以指定偏移结束
    pub last: Option<isize>,
}

impl PtrsxScanner {
    pub fn create_pointer_map<P1, P2, P3>(&self, proc: &P1, path1: P2, path2: P3) -> Result<()>
    where
        P1: ProcessInfo + VirtualMemoryRead,
        P2: AsRef<Path>,
        P3: AsRef<Path>,
    {
        // 获取全部内存区域
        let iter = proc.get_maps().collect::<Result<Vec<_>, vmmap::Error>>()?.into_iter();
        let vqs = iter
            .filter(|x| x.is_read() && x.is_write())
            .filter(mapping_filter)
            .collect::<Vec<_>>();

        let file = fs::OpenOptions::new().append(true).create_new(true).open(path1)?;
        let mut writer = BufWriter::new(file);

        // 处理所有可用于基址的模块，合并处于同一模块的区域，截断模块路径只保留模块名，
        // 检查如果有多个模块名相同但是路径不同的区域就在模块名后面加一个数字，
        // 将处理过的内存映射信息写入文件
        let mut counts = HashMap::new();
        vqs.iter()
            .flat_map(|x| Some(Module { start: x.start(), end: x.end(), name: x.name()? }))
            .fold(Vec::<Module>::with_capacity(vqs.len()), |mut acc, cur| {
                match acc.last_mut() {
                    Some(last) if last.name == cur.name => last.end = cur.end,
                    _ => acc.push(cur),
                }
                acc
            })
            .into_iter()
            .try_for_each(|Module { start, end, name }| {
                let name = Path::new(name).file_name().and_then(|s| s.to_str()).unwrap_or(name);
                let count = counts.entry(name).or_insert(0);
                let name = format!("{name}[{count}]");
                *count += 1;
                writeln!(writer, "{start:x}-{end:x} {name}")
            })?;

        let file = fs::OpenOptions::new().append(true).create_new(true).open(path2)?;
        let mut writer = BufWriter::new(file);

        // 将 [k=地址:v=k中所储存的指针] 数据写入文件
        let mut f = |k: usize, v: usize| {
            writer
                .write_all(&k.to_ne_bytes())
                .and(writer.write_all(&v.to_ne_bytes()))
        };
        try_create_pointer_map(proc, &vqs, true, &mut f)?;

        Ok(())
    }

    pub fn load_pointer_map<R: Read>(&mut self, reader: R) -> Result<()> {
        const BUF_SIZE: usize = mem::size_of::<usize>() * 0x20000;
        const CHUNK_SIZE: usize = mem::size_of::<usize>() * 2;
        let mut buf = vec![0; BUF_SIZE];
        let mut cursor = Cursor::new(reader);
        loop {
            let size = cursor.get_mut().read(&mut buf)?;
            if size == 0 {
                break;
            }
            for chuks in buf[..size].chunks_exact(CHUNK_SIZE) {
                let (key, value) = chuks.split_at(mem::size_of::<usize>());
                let (key, value) =
                    (usize::from_ne_bytes(key.try_into().unwrap()), usize::from_ne_bytes(value.try_into().unwrap()));
                if self.forward.insert(key) {
                    self.reverse.entry(value).or_default().push(key);
                }
            }
        }
        Ok(())
    }

    pub fn load_modules_info<R: Read>(&mut self, r: R) -> Result<()> {
        let contents = &mut String::with_capacity(0x80000);
        let mut reader = BufReader::new(r);
        let _ = reader.read_to_string(contents)?;
        self.index
            .extend(ModuleIter::new(contents).map(|Module { start, end, name }| (start..end, name.to_string())));
        Ok(())
    }

    pub fn pointer_chain_scanner(&self, param: UserParam, path: impl AsRef<Path>) -> Result<()> {
        let file = fs::OpenOptions::new().append(true).create_new(true).open(path)?;
        let mut writer = BufWriter::new(file);

        let points = &self
            .index
            .iter()
            .flat_map(|(Range { start, end }, _)| self.forward.range((Bound::Included(start), Bound::Included(end))))
            .copied()
            .collect::<Vec<_>>();

        let UserParam { depth, addr, range, use_module, node, max, last } = param;
        let param = Param { depth, addr, range };

        match use_module {
            true => match (node, max, last) {
                (None, None, None) => {
                    let mut f = |base: usize, chain: &[isize]| {
                        let Some((Range { start, end: _ }, name)) = self.index.get_key_value(base) else {
                            return ControlFlow::Continue(());
                        };
                        match write!(writer, "{name}+{}", base - start)
                            .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                            .and(writeln!(writer))
                        {
                            Ok(_) => ControlFlow::Continue(()),
                            Err(err) => ControlFlow::Break(Err(err)),
                        }
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (None, None, Some(last)) => {
                    let mut f = |base: usize, chain: &[isize]| {
                        if chain.first().is_some_and(|o| last.eq(o)) {
                            let Some((Range { start, end: _ }, name)) = self.index.get_key_value(base) else {
                                return ControlFlow::Continue(());
                            };
                            return match write!(writer, "{name}+{}", base - start)
                                .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                                .and(writeln!(writer))
                            {
                                Ok(_) => ControlFlow::Continue(()),
                                Err(err) => ControlFlow::Break(Err(err)),
                            };
                        }
                        ControlFlow::Continue(())
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (None, Some(max), None) => {
                    let mut n = 0;
                    let mut f = |base: usize, chain: &[isize]| {
                        if n >= max {
                            return ControlFlow::Break(Ok(()));
                        }
                        let Some((Range { start, end: _ }, name)) = self.index.get_key_value(base) else {
                            return ControlFlow::Continue(());
                        };
                        match write!(writer, "{name}+{}", base - start)
                            .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                            .and(writeln!(writer))
                        {
                            Ok(_) => {
                                n += 1;
                                ControlFlow::Continue(())
                            }
                            Err(err) => ControlFlow::Break(Err(err)),
                        }
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (None, Some(max), Some(last)) => {
                    let mut n = 0;
                    let mut f = |base: usize, chain: &[isize]| {
                        if n >= max {
                            return ControlFlow::Break(Ok(()));
                        }
                        if chain.first().is_some_and(|o| last.eq(o)) {
                            let Some((Range { start, end: _ }, name)) = self.index.get_key_value(base) else {
                                return ControlFlow::Continue(());
                            };
                            return match write!(writer, "{name}+{}", base - start)
                                .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                                .and(writeln!(writer))
                            {
                                Ok(_) => {
                                    n += 1;
                                    ControlFlow::Continue(())
                                }
                                Err(err) => ControlFlow::Break(Err(err)),
                            };
                        }
                        ControlFlow::Continue(())
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (Some(node), None, None) => {
                    let mut f = |base: usize, chain: &[isize]| {
                        if chain.len() >= node {
                            let Some((Range { start, end: _ }, name)) = self.index.get_key_value(base) else {
                                return ControlFlow::Continue(());
                            };
                            return match write!(writer, "{name}+{}", base - start)
                                .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                                .and(writeln!(writer))
                            {
                                Ok(_) => ControlFlow::Continue(()),
                                Err(err) => ControlFlow::Break(Err(err)),
                            };
                        }
                        ControlFlow::Continue(())
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (Some(node), None, Some(last)) => {
                    let mut f = |base: usize, chain: &[isize]| {
                        if chain.len() >= node && chain.first().is_some_and(|o| last.eq(o)) {
                            let Some((Range { start, end: _ }, name)) = self.index.get_key_value(base) else {
                                return ControlFlow::Continue(());
                            };
                            return match write!(writer, "{name}+{}", base - start)
                                .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                                .and(writeln!(writer))
                            {
                                Ok(_) => ControlFlow::Continue(()),
                                Err(err) => ControlFlow::Break(Err(err)),
                            };
                        }
                        ControlFlow::Continue(())
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (Some(node), Some(max), None) => {
                    let mut n = 0;
                    let mut f = |base: usize, chain: &[isize]| {
                        if n >= max {
                            return ControlFlow::Break(Ok(()));
                        }

                        if chain.len() >= node {
                            let Some((Range { start, end: _ }, name)) = self.index.get_key_value(base) else {
                                return ControlFlow::Continue(());
                            };
                            return match write!(writer, "{name}+{}", base - start)
                                .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                                .and(writeln!(writer))
                            {
                                Ok(_) => {
                                    n += 1;
                                    ControlFlow::Continue(())
                                }
                                Err(err) => ControlFlow::Break(Err(err)),
                            };
                        }
                        ControlFlow::Continue(())
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (Some(node), Some(max), Some(last)) => {
                    let mut n = 0;
                    let mut f = |base: usize, chain: &[isize]| {
                        if n >= max {
                            return ControlFlow::Break(Ok(()));
                        }
                        if chain.len() >= node && chain.first().is_some_and(|o| last.eq(o)) {
                            let Some((Range { start, end: _ }, name)) = self.index.get_key_value(base) else {
                                return ControlFlow::Continue(());
                            };
                            return match write!(writer, "{name}+{}", base - start)
                                .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                                .and(writeln!(writer))
                            {
                                Ok(_) => {
                                    n += 1;
                                    ControlFlow::Continue(())
                                }
                                Err(err) => ControlFlow::Break(Err(err)),
                            };
                        }
                        ControlFlow::Continue(())
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
            }?,
            false => match (node, max, last) {
                (None, None, None) => {
                    let mut f = |base: usize, chain: &[isize]| {
                        write!(writer, "{base}")
                            .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                            .and(writeln!(writer))
                    };
                    return Ok(try_pointer_chain_scan(param, &mut f, points, &self.reverse)?);
                }
                (None, None, Some(last)) => {
                    let mut f = |base: usize, chain: &[isize]| {
                        if chain.first().is_some_and(|o| last.eq(o)) {
                            if let Err(err) = write!(writer, "{base}")
                                .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                                .and(writeln!(writer))
                            {
                                return ControlFlow::Break(Err(err));
                            }
                        }
                        ControlFlow::Continue(())
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (None, Some(max), None) => {
                    let mut n = 0;
                    let mut f = |base: usize, chain: &[isize]| {
                        if n >= max {
                            return ControlFlow::Break(Ok(()));
                        }
                        match write!(writer, "{base}")
                            .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                            .and(writeln!(writer))
                        {
                            Ok(_) => {
                                n += 1;
                                ControlFlow::Continue(())
                            }
                            Err(err) => ControlFlow::Break(Err(err)),
                        }
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (None, Some(max), Some(last)) => {
                    let mut n = 0;
                    let mut f = |base: usize, chain: &[isize]| {
                        if n >= max {
                            return ControlFlow::Break(Ok(()));
                        }
                        if chain.first().is_some_and(|o| last.eq(o)) {
                            match write!(writer, "{base}")
                                .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                                .and(writeln!(writer))
                            {
                                Ok(_) => {
                                    n += 1;
                                    return ControlFlow::Continue(());
                                }
                                Err(err) => return ControlFlow::Break(Err(err)),
                            }
                        }
                        ControlFlow::Continue(())
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (Some(node), None, None) => {
                    let mut f = |base: usize, chain: &[isize]| {
                        if chain.len() >= node {
                            match write!(writer, "{base}")
                                .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                                .and(writeln!(writer))
                            {
                                Ok(_) => {
                                    return ControlFlow::Continue(());
                                }
                                Err(err) => return ControlFlow::Break(Err(err)),
                            }
                        }
                        ControlFlow::Continue(())
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (Some(node), None, Some(last)) => {
                    let mut f = |base: usize, chain: &[isize]| {
                        if chain.len() >= node && chain.first().is_some_and(|o| last.eq(o)) {
                            match write!(writer, "{base}")
                                .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                                .and(writeln!(writer))
                            {
                                Ok(_) => {
                                    return ControlFlow::Continue(());
                                }
                                Err(err) => return ControlFlow::Break(Err(err)),
                            }
                        }
                        ControlFlow::Continue(())
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (Some(node), Some(max), None) => {
                    let mut n = 0;
                    let mut f = |base: usize, chain: &[isize]| {
                        if n >= max {
                            return ControlFlow::Break(Ok(()));
                        }

                        if chain.len() >= node {
                            match write!(writer, "{base}")
                                .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                                .and(writeln!(writer))
                            {
                                Ok(_) => {
                                    n += 1;
                                    return ControlFlow::Continue(());
                                }
                                Err(err) => return ControlFlow::Break(Err(err)),
                            }
                        }
                        ControlFlow::Continue(())
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
                (Some(node), Some(max), Some(last)) => {
                    let mut n = 0;
                    let mut f = |base: usize, chain: &[isize]| {
                        if n >= max {
                            return ControlFlow::Break(Ok(()));
                        }
                        if chain.len() >= node && chain.first().is_some_and(|o| last.eq(o)) {
                            match write!(writer, "{base}")
                                .and(chain.iter().rev().try_for_each(|o| write!(writer, "@{o}")))
                                .and(writeln!(writer))
                            {
                                Ok(_) => {
                                    n += 1;
                                    return ControlFlow::Continue(());
                                }
                                Err(err) => return ControlFlow::Break(Err(err)),
                            }
                        }
                        ControlFlow::Continue(())
                    };
                    match try_pointer_chain_scan(param, &mut f, points, &self.reverse) {
                        ControlFlow::Continue(_) => Ok(()),
                        ControlFlow::Break(b) => b,
                    }
                }
            }?,
        }

        Ok(())
    }

    pub fn reset(&mut self) {
        self.index.clear();
        self.forward.clear();
        self.reverse.clear();
    }
}
