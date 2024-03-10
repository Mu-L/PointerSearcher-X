use core::ops::{Bound, ControlFlow};
use std::{collections::BTreeMap, isize};

use super::try_trait::{FromResidual, Try};

pub struct Param {
    pub depth: usize,
    pub addr: usize,
    pub range: (usize, usize),
}

// large amounts data
fn _try_chain_scan_1<F, R>(param: Param, f: &mut F, points: &[usize], map: &BTreeMap<usize, Vec<usize>>) -> R
where
    F: FnMut(usize, &[isize]) -> R,
    R: Try<Output = ()>,
{
    let mut chain = Vec::with_capacity(param.depth);
    __try_chain_scan_1(param, f, &mut chain, points, map, 0)
}

fn __try_chain_scan_1<F, R>(
    param: Param,
    f: &mut F,
    chain: &mut Vec<isize>,
    points: &[usize],
    map: &BTreeMap<usize, Vec<usize>>,
    curr: usize,
) -> R
where
    F: FnMut(usize, &[isize]) -> R,
    R: Try<Output = ()>,
{
    let Param { depth, addr, range } = param;
    let min = addr.saturating_sub(range.1);
    let max = addr.saturating_add(range.0);

    let idx = points.binary_search(&min).unwrap_or_else(|x| x);

    if points
        .iter()
        .skip(idx)
        .take_while(|x| max.ge(x))
        .min_by_key(|x| (x.wrapping_sub(addr) as isize).abs())
        .is_some()
    {
        let branch = f(addr, chain);
        match Try::branch(branch) {
            ControlFlow::Continue(c) => c,
            ControlFlow::Break(b) => return FromResidual::from_residual(b),
        }
    }

    if curr < depth {
        for (&k, v) in map.range((Bound::Included(min), Bound::Included(max))) {
            chain.push(addr.wrapping_sub(k) as isize);
            for &addr in v {
                let branch = __try_chain_scan_1(Param { depth, addr, range }, f, chain, points, map, curr + 1);
                match Try::branch(branch) {
                    ControlFlow::Continue(c) => c,
                    ControlFlow::Break(b) => return FromResidual::from_residual(b),
                }
            }
            chain.pop();
        }
    };

    Try::from_output(())
}

// small amount data
fn _try_chain_scan_2<F, R>(param: Param, f: &mut F, points: &[usize], map: &BTreeMap<usize, Vec<usize>>) -> R
where
    F: FnMut(usize, &[isize]) -> R,
    R: Try<Output = ()>,
{
    let mut chain = Vec::with_capacity(param.depth);
    __try_chain_scan_2(param, f, &mut chain, points, map, 0)
}

fn __try_chain_scan_2<F, R>(
    param: Param,
    f: &mut F,
    chain: &mut Vec<isize>,
    points: &[usize],
    map: &BTreeMap<usize, Vec<usize>>,
    curr: usize,
) -> R
where
    F: FnMut(usize, &[isize]) -> R,
    R: Try<Output = ()>,
{
    let Param { depth, addr, range } = param;
    let min = addr.saturating_sub(range.1);
    let max = addr.saturating_add(range.0);

    let idx = points.iter().position(|x| min.le(x)).unwrap_or(points.len());

    if points
        .iter()
        .skip(idx)
        .take_while(|x| max.ge(x))
        .min_by_key(|x| (x.wrapping_sub(addr) as isize).abs())
        .is_some()
    {
        let branch = f(addr, chain);
        match Try::branch(branch) {
            ControlFlow::Continue(c) => c,
            ControlFlow::Break(b) => return FromResidual::from_residual(b),
        }
    }

    if curr < depth {
        for (&k, v) in map.range((Bound::Included(min), Bound::Included(max))) {
            chain.push(addr.wrapping_sub(k) as isize);
            for &addr in v {
                let branch = __try_chain_scan_2(Param { depth, addr, range }, f, chain, points, map, curr + 1);
                match Try::branch(branch) {
                    ControlFlow::Continue(c) => c,
                    ControlFlow::Break(b) => return FromResidual::from_residual(b),
                }
            }
            chain.pop();
        }
    };
    Try::from_output(())
}

// large amounts data
fn _chain_scan_1<F>(param: Param, f: &mut F, points: &[usize], map: &BTreeMap<usize, Vec<usize>>)
where
    F: FnMut(usize, &[isize]),
{
    let mut chain = Vec::with_capacity(param.depth);
    __chain_scan_1(param, f, &mut chain, points, map, 0)
}

fn __chain_scan_1<F>(
    param: Param,
    f: &mut F,
    chain: &mut Vec<isize>,
    points: &[usize],
    map: &BTreeMap<usize, Vec<usize>>,
    curr: usize,
) where
    F: FnMut(usize, &[isize]),
{
    let Param { depth, addr, range } = param;
    let min = addr.saturating_sub(range.1);
    let max = addr.saturating_add(range.0);

    let idx = points.binary_search(&min).unwrap_or_else(|x| x);

    if points
        .iter()
        .skip(idx)
        .take_while(|x| max.ge(x))
        .min_by_key(|x| (x.wrapping_sub(addr) as isize).abs())
        .is_some()
    {
        f(addr, chain)
    }

    if curr < depth {
        for (&k, v) in map.range((Bound::Included(min), Bound::Included(max))) {
            chain.push(addr.wrapping_sub(k) as isize);
            for &addr in v {
                __chain_scan_1(Param { depth, addr, range }, f, chain, points, map, curr + 1)
            }
            chain.pop();
        }
    };
}

// small amount data
fn _chain_scan_2<F>(param: Param, f: &mut F, points: &[usize], map: &BTreeMap<usize, Vec<usize>>)
where
    F: FnMut(usize, &[isize]),
{
    let mut chain = Vec::with_capacity(param.depth);
    __chain_scan_2(param, f, &mut chain, points, map, 0)
}

fn __chain_scan_2<F>(
    param: Param,
    f: &mut F,
    chain: &mut Vec<isize>,
    points: &[usize],
    map: &BTreeMap<usize, Vec<usize>>,
    curr: usize,
) where
    F: FnMut(usize, &[isize]),
{
    let Param { depth, addr, range } = param;
    let min = addr.saturating_sub(range.1);
    let max = addr.saturating_add(range.0);

    let idx = points.iter().position(|x| min.le(x)).unwrap_or(points.len());

    if points
        .iter()
        .skip(idx)
        .take_while(|x| max.ge(x))
        .min_by_key(|x| (x.wrapping_sub(addr) as isize).abs())
        .is_some()
    {
        f(addr, chain)
    }

    if curr < depth {
        for (&k, v) in map.range((Bound::Included(min), Bound::Included(max))) {
            chain.push(addr.wrapping_sub(k) as isize);
            for &addr in v {
                __chain_scan_2(Param { depth, addr, range }, f, chain, points, map, curr + 1)
            }
            chain.pop();
        }
    };
}

// TODO: maybe make public
#[allow(dead_code)]
fn pointer_chain_scan<F>(param: Param, f: &mut F, points: &[usize], map: &BTreeMap<usize, Vec<usize>>)
where
    F: FnMut(usize, &[isize]),
{
    let count = map.values().filter(|v| v.len() < 64).count();
    match (map.len() - count).checked_mul(256) {
        Some(n) if n < count => _chain_scan_2(param, f, points, map),
        _ => _chain_scan_1(param, f, points, map),
    }
}

pub fn try_pointer_chain_scan<F, R>(param: Param, f: &mut F, points: &[usize], map: &BTreeMap<usize, Vec<usize>>) -> R
where
    F: FnMut(usize, &[isize]) -> R,
    R: Try<Output = ()>,
{
    let count = map.values().filter(|v| v.len() < 64).count();
    match (map.len() - count).checked_mul(256) {
        Some(n) if n < count => _try_chain_scan_2(param, f, points, map),
        _ => _try_chain_scan_1(param, f, points, map),
    }
}

// use core::{
//     iter::{Chain, Map, Once, Skip},
//     slice::Iter,
// };

// pub type ChainIter<'a> =
//     Map<Chain<Once<&'a (usize, isize)>, Skip<Iter<'a, (usize, isize)>>>, for<'b> fn(&'b (usize, isize)) -> &'b isize>;

pub fn __try_chain_scan_1_ref_cycle<F, R>(
    param: Param,
    f: &mut F,
    chain: &mut Vec<(usize, isize)>,
    points: &[usize],
    map: &BTreeMap<usize, Vec<usize>>,
    curr: usize,
) -> R
where
    F: FnMut(usize, &dyn Iterator<Item = isize>) -> R,
    R: Try<Output = ()>,
{
    let Param { depth, addr, range } = param;
    let min = addr.saturating_sub(range.1);
    let max = addr.saturating_add(range.0);

    let idx = points.binary_search(&min).unwrap_or_else(|x| x);

    if points
        .iter()
        .skip(idx)
        .take_while(|x| max.ge(x))
        .min_by_key(|x| (x.wrapping_sub(addr) as isize).abs())
        .is_some()
    {
        // let iter = if let Some(first)= chain.first() {
        //     if let Some(n) = chain.iter().position(|(a, _)| a.eq(&first.0)){
        //         core::iter::once(first).chain(chain.iter().skip(n)).map(|(_, b)| b)
        //     }else {
        //         chain.iter()
        //     }
        // }else {
        //     chain.iter()
        // };

        let first = chain.first().unwrap();
        let n = chain.iter().position(|(a, _)| a.eq(&first.0)).unwrap();
        let iter = core::iter::once(first)
            .chain(chain.iter().skip(n))
            .map(|(_, b)| b)
            .copied();

        let branch = f(addr, &iter);
        match Try::branch(branch) {
            ControlFlow::Continue(c) => c,
            ControlFlow::Break(b) => return FromResidual::from_residual(b),
        }
    }

    if curr < depth {
        for (&k, v) in map.range((Bound::Included(min), Bound::Included(max))) {
            chain.push((k, addr.wrapping_sub(k) as isize));
            for &addr in v {
                let branch =
                    __try_chain_scan_1_ref_cycle(Param { depth, addr, range }, f, chain, points, map, curr + 1);
                match Try::branch(branch) {
                    ControlFlow::Continue(c) => c,
                    ControlFlow::Break(b) => return FromResidual::from_residual(b),
                }
            }
            chain.pop();
        }
    };

    Try::from_output(())
}
