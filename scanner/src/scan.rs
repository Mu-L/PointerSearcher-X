use std::{
    fs::{File, OpenOptions},
    path::PathBuf,
};

use ptrsx::{Param, PtrsxScanner};

use super::{select_base_module, Address, Error, Offset, Spinner, SubCommandScan};

impl SubCommandScan {
    pub fn init(self) -> Result<(), Error> {
        let Self {
            bin,
            info,
            target: Address(target),
            depth,
            offset: Offset(offset),
            node,
            dir,
        } = self;

        if depth <= node {
            return Err(format!("Error: depth must be greater than node. current depth({depth}), node({node}).").into());
        }

        let mut spinner = Spinner::start("Start loading cache...");
        let mut ptrsx = PtrsxScanner::default();
        let info = File::open(info)?;
        ptrsx.load_modules_info_file(info)?;
        let bin = File::open(bin)?;
        ptrsx.load_pointer_map_file(bin)?;
        spinner.stop("cache loaded.");

        let modules = ptrsx.get_modules_info().cloned().collect::<Vec<_>>();
        let modules = select_base_module(&modules)?;

        let mut spinner = Spinner::start("Start scanning pointer chain...");

        let file = dir.unwrap_or_else(|| PathBuf::from(target.to_string()).with_extension("scandata"));
        let file = OpenOptions::new()
            .write(true)
            .append(true)
            .create_new(true)
            .open(file)?;
        let param = Param { depth, target, node, offset };
        ptrsx.pointer_chain_scanner(modules, param, file)?;

        spinner.stop("Pointer chain is scanned.");

        Ok(())
    }
}
