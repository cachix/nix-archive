//! Minimal synchronous Nix worker-protocol client used only by the benchmark.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

const WORKER_MAGIC_1: u64 = 0x6e69_7863;
const WORKER_MAGIC_2: u64 = 0x6478_696f;
const CLIENT_PROTOCOL: u64 = (1 << 8) | 35;
const NAR_FROM_PATH: u64 = 38;

const STDERR_NEXT: u64 = 0x6f6c_6d67;
const STDERR_LAST: u64 = 0x616c_7473;
const STDERR_ERROR: u64 = 0x6378_7470;
const STDERR_START_ACTIVITY: u64 = 0x5354_5254;
const STDERR_STOP_ACTIVITY: u64 = 0x5354_4f50;
const STDERR_RESULT: u64 = 0x5253_4c54;

const MAX_CONTROL_STRING: usize = 16 * 1024 * 1024;

pub struct NixDaemon {
    stream: UnixStream,
    protocol: u64,
    version: String,
}

impl NixDaemon {
    pub fn connect(socket: &Path) -> io::Result<Self> {
        let mut stream = UnixStream::connect(socket)?;

        write_u64(&mut stream, WORKER_MAGIC_1)?;
        write_u64(&mut stream, CLIENT_PROTOCOL)?;
        stream.flush()?;

        let magic = read_u64(&mut stream)?;
        if magic != WORKER_MAGIC_2 {
            return Err(invalid_data(format!(
                "unexpected Nix daemon magic {magic:#x}"
            )));
        }

        let server_protocol = read_u64(&mut stream)?;
        if server_protocol >> 8 != 1 {
            return Err(invalid_data(format!(
                "unsupported Nix daemon protocol {server_protocol:#x}"
            )));
        }
        let protocol = server_protocol.min(CLIENT_PROTOCOL);

        if protocol_at_least(protocol, 14) {
            write_u64(&mut stream, 0)?;
        }
        if protocol_at_least(protocol, 11) {
            write_u64(&mut stream, 0)?;
        }
        stream.flush()?;

        let version = if protocol_at_least(protocol, 33) {
            read_string(&mut stream)?
        } else {
            "unknown".to_owned()
        };
        if protocol_at_least(protocol, 35) {
            // Optional trust flag: 0 = none, 1 = trusted, 2 = not trusted.
            read_u64(&mut stream)?;
        }

        let mut daemon = Self {
            stream,
            protocol,
            version,
        };
        daemon.read_stderr()?;
        Ok(daemon)
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn nar_from_path(&mut self, path: &str, output: &mut [u8]) -> io::Result<()> {
        write_u64(&mut self.stream, NAR_FROM_PATH)?;
        write_string(&mut self.stream, path)?;
        self.stream.flush()?;

        self.read_stderr()?;
        self.stream.read_exact(output)
    }

    fn read_stderr(&mut self) -> io::Result<()> {
        loop {
            match read_u64(&mut self.stream)? {
                STDERR_LAST => return Ok(()),
                STDERR_NEXT => {
                    read_string(&mut self.stream)?;
                }
                STDERR_ERROR => return Err(self.read_error()?),
                STDERR_START_ACTIVITY => {
                    read_u64(&mut self.stream)?;
                    read_u64(&mut self.stream)?;
                    read_u64(&mut self.stream)?;
                    read_string(&mut self.stream)?;
                    discard_fields(&mut self.stream)?;
                    read_u64(&mut self.stream)?;
                }
                STDERR_STOP_ACTIVITY => {
                    read_u64(&mut self.stream)?;
                }
                STDERR_RESULT => {
                    read_u64(&mut self.stream)?;
                    read_u64(&mut self.stream)?;
                    discard_fields(&mut self.stream)?;
                }
                message => {
                    return Err(invalid_data(format!(
                        "unknown Nix daemon stderr message {message:#x}"
                    )));
                }
            }
        }
    }

    fn read_error(&mut self) -> io::Result<io::Error> {
        if protocol_at_least(self.protocol, 26) {
            let first_type = read_string(&mut self.stream)?;
            read_u64(&mut self.stream)?;
            let second_type = read_string(&mut self.stream)?;
            let message = read_string(&mut self.stream)?;
            read_u64(&mut self.stream)?;

            let trace_count = read_u64(&mut self.stream)?;
            for _ in 0..trace_count {
                read_u64(&mut self.stream)?;
                read_string(&mut self.stream)?;
            }

            if first_type != "Error" || second_type != "Error" {
                return Err(invalid_data("malformed Nix daemon error"));
            }
            Ok(io::Error::other(message))
        } else {
            let message = read_string(&mut self.stream)?;
            read_u64(&mut self.stream)?;
            Ok(io::Error::other(message))
        }
    }
}

fn protocol_at_least(protocol: u64, minor: u64) -> bool {
    protocol >> 8 == 1 && protocol & 0xff >= minor
}

fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_u64(writer: &mut impl Write, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn read_string(reader: &mut impl Read) -> io::Result<String> {
    let length = usize::try_from(read_u64(reader)?)
        .map_err(|_| invalid_data("Nix daemon string length does not fit usize"))?;
    if length > MAX_CONTROL_STRING {
        return Err(invalid_data(format!(
            "Nix daemon control string is too large: {length} bytes"
        )));
    }

    let padded_length = length
        .checked_add((8 - length % 8) % 8)
        .ok_or_else(|| invalid_data("Nix daemon string length overflow"))?;
    let mut bytes = vec![0; padded_length];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes[..length].to_vec())
        .map_err(|error| invalid_data(format!("Nix daemon returned non-UTF-8 text: {error}")))
}

fn write_string(writer: &mut impl Write, value: &str) -> io::Result<()> {
    write_u64(writer, value.len() as u64)?;
    writer.write_all(value.as_bytes())?;

    let padding = (8 - value.len() % 8) % 8;
    writer.write_all(&[0; 7][..padding])
}

fn discard_fields(reader: &mut impl Read) -> io::Result<()> {
    let count = read_u64(reader)?;
    for _ in 0..count {
        match read_u64(reader)? {
            0 => {
                read_u64(reader)?;
            }
            1 => {
                read_string(reader)?;
            }
            field_type => {
                return Err(invalid_data(format!(
                    "unknown Nix daemon activity field type {field_type}"
                )));
            }
        }
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
