use std::path::PathBuf;

use argh::{FromArgValue, FromArgs};
use vmmap::Pid;

#[derive(FromArgs)]
#[argh(description = "Commands.")]
pub struct Commands {
    #[argh(subcommand)]
    pub cmds: CommandEnum,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum CommandEnum {
    DumpProcess(DumpCommand),
    PointerChain(ChainCommand),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "disk", description = "dump process pointer to disk")]
pub struct DumpCommand {
    #[argh(option, short = 'p', description = "process id")]
    pub pid: Pid,

    #[argh(option, short = 'f', description = "out filename")]
    pub file: Option<PathBuf>,

    #[argh(option, default = "true", description = "pointer align, default true")]
    pub align: bool,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "test", description = "test pointer chain")]
pub struct ChainCommand {
    #[argh(option, short = 'p', description = "process id")]
    pub pid: Pid,

    #[argh(option, description = "pointer chain")]
    pub chain: String,

    #[argh(option, short = 'w', description = "write bytes")]
    pub write: Option<WVecU8>,

    #[argh(option, short = 'r', description = "show bytes")]
    pub read: Option<usize>,
}

pub struct WVecU8(pub Vec<u8>);

impl FromArgValue for WVecU8 {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        let content = get_content_between_parentheses(value.trim()).ok_or(format!("parse command error: {value}"))?;
        let bytes = content
            .split(',')
            .map(|s| u8::from_str_radix(s.trim().trim_start_matches("0x"), 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        Ok(Self(bytes))
    }
}

fn get_content_between_parentheses(value: &str) -> Option<&str> {
    let start_index = value.find('[')?;
    let end_index = value[start_index + 1..].find(']').map(|i| start_index + 1 + i)?;
    Some(&value[start_index + 1..end_index])
}
