{ pkgs, ... }:

{
  languages.rust.enable = true;

  # Used as the live differential oracle by the compatibility tests.
  packages = [ pkgs.nix ];
}
