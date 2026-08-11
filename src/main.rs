use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use nix_archive::nar::{encode_path, restore_path};

/// Pack and unpack Nix Archive (NAR) files without linking to Nix.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serialize a filesystem tree into a NAR file.
    Pack {
        /// NAR file to create, or - for standard output.
        #[arg(value_name = "NARFILE")]
        narfile: PathBuf,
        /// Filesystem tree to serialize.
        #[arg(value_name = "DIRECTORY")]
        directory: PathBuf,
    },
    /// Restore a NAR file into a new filesystem tree.
    Unpack {
        /// NAR file to read, or - for standard input.
        #[arg(value_name = "NARFILE")]
        narfile: PathBuf,
        /// Destination, which must not already exist.
        #[arg(value_name = "DIRECTORY")]
        directory: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Pack { narfile, directory } => finish(pack(&narfile, &directory)),
        Command::Unpack { narfile, directory } => finish(unpack(&narfile, &directory)),
    }
}

fn finish(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nix-archive: {error}");
            ExitCode::FAILURE
        }
    }
}

fn pack(narfile: &Path, directory: &Path) -> Result<(), String> {
    if narfile == Path::new("-") {
        let stdout = io::stdout();
        let mut writer = stdout.lock();
        encode_path(&mut writer, directory).map_err(|error| {
            format!(
                "cannot pack {} to standard output: {error}",
                directory.display()
            )
        })?;
        writer
            .flush()
            .map_err(|error| format!("cannot flush standard output: {error}"))?;
        return Ok(());
    }

    let archive = File::create(narfile)
        .map_err(|error| format!("cannot create {}: {error}", narfile.display()))?;
    let mut writer = BufWriter::new(archive);
    encode_path(&mut writer, directory).map_err(|error| {
        format!(
            "cannot pack {} into {}: {error}",
            directory.display(),
            narfile.display()
        )
    })?;
    writer
        .flush()
        .map_err(|error| format!("cannot finish {}: {error}", narfile.display()))
}

fn unpack(narfile: &Path, directory: &Path) -> Result<(), String> {
    let nar = if narfile == Path::new("-") {
        let mut nar = Vec::new();
        io::stdin()
            .lock()
            .read_to_end(&mut nar)
            .map_err(|error| format!("cannot read standard input: {error}"))?;
        nar
    } else {
        fs::read(narfile).map_err(|error| format!("cannot read {}: {error}", narfile.display()))?
    };

    restore_path(&nar, directory).map_err(|error| {
        format!(
            "cannot unpack {} into {}: {error}",
            archive_name(narfile),
            directory.display()
        )
    })
}

fn archive_name(path: &Path) -> String {
    if path == Path::new("-") {
        "standard input".into()
    } else {
        path.display().to_string()
    }
}
