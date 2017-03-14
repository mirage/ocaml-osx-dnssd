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

(* The callback fires once per result *)
type rr = {
  rrclass: int;
  rrtype: int;
  rrdata: Bytes.t;
  ttl: int;
}

let string_of_rr rr =
  Printf.sprintf "{ rrclass = %d; rrtype = %d; rrdata(%d) = %s; ttl = %d }"
    rr.rrclass rr.rrtype (Bytes.length rr.rrdata) rr.rrdata rr.ttl

(* Accumulate the results here *)
let in_progress_calls = Hashtbl.create 7

type token = int

external query_record: string -> int -> token -> query = "stub_query_record"

external query_process: query -> unit = "stub_query_process"

external query_deallocate: query -> unit = "stub_query_deallocate"

let common_callback token =
  function
  | None ->
    Printf.fprintf stderr "Some error happened\n%!"
  | Some this ->
    let existing =
      if Hashtbl.mem in_progress_calls token
      then Hashtbl.find in_progress_calls token
      else [] in
    Hashtbl.replace in_progress_calls token (this :: existing)

let query name ty =
  let ty' = int_of_DNSServiceType ty in
  if ty' < 0 then failwith "Unrecognised query type";
  let token = next_token () in
  let q = query_record name ty' token in
  query_process q;
  let all = Hashtbl.find in_progress_calls token in
  Hashtbl.remove in_progress_calls token;
  query_deallocate q;
  all

let () =
  Callback.register "ocaml-osx-dnssd" common_callback
