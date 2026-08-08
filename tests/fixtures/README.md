# Offline NAR goldens

These hexadecimal files are byte-for-byte `nix-store --dump` outputs for the
small regular, executable, symlink, and directory samples in
`tests/dump_parity.rs`. They mirror the long-lived Nix-oracle fixtures in
`hnix-store-nar` and keep the fundamental compatibility checks active when Nix
is not installed.

The live differential tests still compare broader filesystem fixtures directly
with the pinned `nix-store` available in the development environment.
