use std::fs::File;
#[cfg(unix)]
use std::io::BufReader;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
#[cfg(unix)]
use nix_archive::nar::restore_reader;
use nix_archive::nar::{encode_path, CaseHack};

/// Pack and unpack Nix Archive (NAR) files without linking to Nix.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Nix's case-collision hack, which rewrites names carrying the
    /// `~nix~case~hack~N` suffix and changes the resulting NAR hash.
    ///
    /// `native` follows Nix's own default: on for macOS, off elsewhere. Set it
    /// explicitly to match an installation whose `use-case-hack` differs, such
    /// as a macOS host on a case-sensitive volume.
    #[arg(long, value_enum, default_value_t = CaseHackArg::Native, global = true)]
    case_hack: CaseHackArg,
}

#[derive(Clone, Copy, ValueEnum)]
enum CaseHackArg {
    /// Nix's default for this platform.
    Native,
    Enabled,
    Disabled,
}

impl From<CaseHackArg> for CaseHack {
    fn from(value: CaseHackArg) -> Self {
        match value {
            CaseHackArg::Native => CaseHack::native(),
            CaseHackArg::Enabled => CaseHack::Enabled,
            CaseHackArg::Disabled => CaseHack::Disabled,
        }
    }
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
    let cli = Cli::parse();
    let case_hack = cli.case_hack.into();
    match cli.command {
        Command::Pack { narfile, directory } => finish(pack(&narfile, &directory, case_hack)),
        Command::Unpack { narfile, directory } => finish(unpack(&narfile, &directory, case_hack)),
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

fn pack(narfile: &Path, directory: &Path, case_hack: CaseHack) -> Result<(), String> {
    if narfile == Path::new("-") {
        let stdout = io::stdout();
        let mut writer = stdout.lock();
        encode_path(&mut writer, directory, case_hack).map_err(|error| {
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
    encode_path(&mut writer, directory, case_hack).map_err(|error| {
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

fn unpack(narfile: &Path, directory: &Path, case_hack: CaseHack) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (narfile, directory, case_hack);
        Err("unpacking NAR files is currently supported only on Unix".into())
    }

    #[cfg(unix)]
    {
        // Each branch calls `restore_reader` on its own concrete reader rather than
        // through one `&mut dyn Read`: the erased form costs a userspace round trip
        // per chunk, where the concrete one lets the payload copy stay in the
        // kernel.
        let restored = if narfile == Path::new("-") {
            restore_reader(&mut io::stdin().lock(), directory, case_hack)
        } else {
            let archive = File::open(narfile)
                .map_err(|error| format!("cannot open {}: {error}", narfile.display()))?;
            restore_reader(&mut BufReader::new(archive), directory, case_hack)
        };

        restored.map_err(|error| {
            format!(
                "cannot unpack {} into {}: {error}",
                archive_name(narfile),
                directory.display()
            )
        })
    }
}

#[cfg(unix)]
fn archive_name(path: &Path) -> String {
    if path == Path::new("-") {
        "standard input".into()
    } else {
        path.display().to_string()
    }
}
