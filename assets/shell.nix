{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell rec {

  buildInputs = [
    pkgs.python3
    pkgs.uv
    pkgs.zlib
    pkgs.ruff
    pkgs.pkg-config
    pkgs.libxml2
    pkgs.xmlsec
    pkgs.libtool
  ];

  shellHook = ''
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath buildInputs}:$LD_LIBRARY_PATH"
    export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib.outPath}/lib:$LD_LIBRARY_PATH"
  '';
}
