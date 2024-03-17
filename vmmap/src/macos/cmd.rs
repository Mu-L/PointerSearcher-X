use std::process::Command;

use crate::{Pid, Process, VirtualQuery};

pub trait ProcessInfoCmdFixed {
    fn pid(&self) -> Pid;
    fn app_path(&self) -> &std::path::Path;
    fn get_maps(&self) -> impl Iterator<Item = crate::Result<Mapping>>;
}

pub struct Mapping {
    pub start: usize,
    pub end: usize,
    pub perm: String,
    pub share_mode: String,
    pub purge: String,
    pub name: String,
    pub tag: String,
}

pub fn get_maps(pid: i32) -> Vec<Mapping> {
    let pid = pid.to_string();
    let title = format!("==== Writable regions for process {pid}");
    let output = Command::new("/usr/bin/vmmap").arg(&pid).output().unwrap();

    let mut m = vec![];

    if output.status.success() {
        let text = String::from_utf8(output.stdout).unwrap();
        let iter = text.lines().skip_while(|s| !s.starts_with(&title)).skip(2);
        for line in iter {
            if line.is_empty() {
                break;
            }
            let (a, b) = line.split_once('[').unwrap();
            let (_, b) = b.split_once(']').unwrap();
            let (tag, range) = a.split_once("   ").unwrap();
            let (start, end) = range.trim().split_once('-').unwrap();
            let (perm, b) = b.trim_start().split_once(' ').unwrap();
            let (share_mode, b) = b.split_once(' ').map(|(a, b)| (a, b.trim_start())).unwrap();

            let (purge, name) = match b.get(0..6).is_some_and(|s| s.contains("PURGE=")) {
                true => b.split_once(' ').map(|(a, b)| (a, b.trim())).unwrap(),
                false => ("", b.trim()),
            };

            m.push(Mapping {
                start: usize::from_str_radix(start, 16).unwrap(),
                end: usize::from_str_radix(end, 16).unwrap(),
                perm: perm.to_string(),
                share_mode: share_mode.to_string(),
                purge: purge.to_string(),
                name: name.to_string(),
                tag: tag.to_string(),
            });
        }
    } else {
        eprintln!("{}", String::from_utf8(output.stderr).unwrap())
    }

    m
}

impl VirtualQuery for Mapping {
    fn start(&self) -> usize {
        self.start
    }

    fn end(&self) -> usize {
        self.end
    }

    fn size(&self) -> usize {
        self.end - self.start
    }

    fn is_read(&self) -> bool {
        true
    }

    fn is_write(&self) -> bool {
        true
    }

    fn is_exec(&self) -> bool {
        &self.perm[6..7] == "x"
    }

    fn name(&self) -> Option<&str> {
        if self.name.is_empty() { None } else { Some(&self.name) }
    }
}

impl ProcessInfoCmdFixed for Process {
    fn pid(&self) -> crate::Pid {
        self.pid
    }

    fn app_path(&self) -> &std::path::Path {
        &self.pathname
    }

    fn get_maps(&self) -> impl Iterator<Item = crate::Result<Mapping>> {
        get_maps(self.pid).into_iter().map(Ok)
    }
}
