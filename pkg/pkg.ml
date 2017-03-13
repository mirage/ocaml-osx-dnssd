#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "osx-dnssd" @@ fun c ->
  Ok [
    Pkg.mllib "lib/osx-dnssd.mllib";
    Pkg.clib "lib/libosx-dnssd_stubs.clib";
    Pkg.test  "lib_test/test" ~args:(Cmd.v "-q");
  ]
