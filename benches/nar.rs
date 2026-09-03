#[cfg(unix)]
include!("support/nar_unix.rs");

#[cfg(not(unix))]
fn main() {}
