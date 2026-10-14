# nix-build packaging/nix
{
  pkgs ? import <nixpkgs> { },
}:
pkgs.callPackage ./package.nix { }
