(*
 * Copyright (C) 2017 Docker Inc <dave.scott@docker.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

type kDNSServiceType =
  | A
  | NS
  | MD
  | MF
  | CNAME
  | SOA
  | MB
  | MG
  | MR
  | NULL
  | WKS
  | PTR
  | HINFO
  | MINFO
  | MX
  | TXT
  | RP
  | AFSDB
  | X25
  | ISDN
  | RT
  | NSAP
  | NSAP_PTR
  | SIG
  | KEY
  | PX
  | GPOS
  | AAAA
  | LOC
  | NXT
  | EID
  | NIMLOC
  | SRV
  | ATMA
  | NAPTR
  | KX
  | CERT
  | A6
  | DNAME
  | SINK
  | OPT
  | APL
  | DS
  | SSHFP
  | IPSECKEY
  | RRSIG
  | NSEC
  | DNSKEY
  | DHCID
  | NSEC3
  | NSEC3PARAM
  | HIP
  | SPF
  | UINFO
  | UID
  | GID
  | UNSPEC
  | TKEY
  | TSIG
  | IXFR
  | AXFR
  | MAILB
  | MAILA
  | ANY

external int_of_DNSServiceType: kDNSServiceType -> int = "stub_int_of_DNSServiceType"

(* Low-level, unsafe APIs *)

type query (* wraps a DNSServiceRef *)

let next_token =
  let i = ref 0 in
  fun () ->
    let this = !i in
    incr i;
    this

type in_progress_call = {
  mutable results: Bytes.t list;
}

let in_progress_calls = Hashtbl.create 7

type token = int

external query_record: string -> int -> token -> query = "stub_query_record"

external query_process: query -> unit = "stub_query_process"

external query_deallocate: query -> unit = "stub_query_deallocate"

let common_callback token =
  Printf.fprintf stderr "common_callback token = %d\n%!" token;
  Hashtbl.replace in_progress_calls token { results = [] }

let query name ty =
  let ty' = int_of_DNSServiceType ty in
  if ty' < 0 then failwith "Unrecognised query type";
  let token = next_token () in
  let q = query_record name ty' token in
  query_process q;
  let results = (Hashtbl.find in_progress_calls token).results in
  Hashtbl.remove in_progress_calls token;
  query_deallocate q;
  results

let () =
  Callback.register "ocaml-osx-dnssd" common_callback
