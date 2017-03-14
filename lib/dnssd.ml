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

type error =
  | Unknown
  | NoSuchName
  | NoMemory
  | BadParam
  | BadReference
  | BadState
  | BadFlags
  | Unsupported
  | NotInitialized
  | AlreadyRegistered
  | NameConflict
  | Invalid
  | Firewall
  | Incompatible
  | BadInterfaceIndex
  | Refused
  | NoSuchRecord
  | NoAuth
  | NoSuchKey
  | NATTraversal
  | DoubleNAT
  | BadTime
  | BadSig
  | BadKey
  | Transient
  | ServiceNotRunning
  | NATPortMappingUnsupported
  | NATPortMappingDisabled
  | NoRouter
  | PollingMode
  | Timeout

let string_of_error = function
  | Unknown -> "Unknown"
  | NoSuchName -> "NoSuchName"
  | NoMemory -> "NoMemory"
  | BadParam -> "BadParam"
  | BadReference -> "BadReference"
  | BadState -> "BadState"
  | BadFlags -> "BadFlags"
  | Unsupported -> "Unsupported"
  | NotInitialized -> "NotInitialized"
  | AlreadyRegistered -> "AlreadyRegistered"
  | NameConflict -> "NameConflict"
  | Invalid -> "Invalid"
  | Firewall -> "Firewall"
  | Incompatible -> "Incompatible"
  | BadInterfaceIndex -> "BadInterfaceIndex"
  | Refused -> "Refused"
  | NoSuchRecord -> "NoSuchRecord"
  | NoAuth -> "NoAuth"
  | NoSuchKey -> "NoSuchKey"
  | NATTraversal -> "NATTraversal"
  | DoubleNAT -> "DoubleNAT"
  | BadTime -> "BadTime"
  | BadSig -> "BadSig"
  | BadKey -> "BadKey"
  | Transient -> "Transient"
  | ServiceNotRunning -> "ServiceNotRunning"
  | NATPortMappingUnsupported -> "NATPortMappingUnsupported"
  | NATPortMappingDisabled -> "NATPortMappingDisabled"
  | NoRouter -> "NoRouter"
  | PollingMode -> "PollingMode"
  | Timeout -> "Timeout"

(* Low-level, unsafe APIs *)

type query (* wraps a DNSServiceRef *)

let next_token =
  let i = ref 0 in
  fun () ->
    let this = !i in
    incr i;
    this

(* The callback fires once per result *)
type cb_result = {
  cb_fullname: string;
  cb_rrtype: int;
  cb_rrclass: int;
  cb_rrdata: Bytes.t;
  cb_ttl: int;
}

type rr = {
  name: Dns.Name.t;
  cls: Dns.Packet.rr_class;
  ttl: int32;
  rdata: Dns.Packet.rdata;
}
(** A DNS resource record *)

type response = {
  rr: rr option;
}

let string_of_response = function
  | { rr = None } -> "None"
  | { rr = Some { name; cls; ttl; rdata } } ->
    Printf.sprintf "Some { name = %s; cls = %s; ttl = %ld; rdata = %s }"
    (Dns.Name.to_string name)
    (Dns.Packet.rr_class_to_string cls)
    ttl
    (Dns.Packet.rdata_to_string rdata)

(* Accumulate the results here *)
let in_progress_calls = Hashtbl.create 7

type token = int

external query_record: string -> int -> token -> query = "stub_query_record"

external query_process: query -> unit = "stub_query_process"

external query_deallocate: query -> unit = "stub_query_deallocate"

let common_callback token result = match result with
  | Error err ->
    Hashtbl.replace in_progress_calls token (Error err)
  | Ok this ->
    let rr = match Dns.Packet.int_to_rr_type this.cb_rrtype with
      | None -> None
      | Some rrtype ->
        let buf = Cstruct.create (Bytes.length this.cb_rrdata) in
        Cstruct.blit_from_bytes this.cb_rrdata 0 buf 0 (Bytes.length this.cb_rrdata);
        begin
          try
            let rdata = Dns.Packet.parse_rdata (Hashtbl.create 1) 0 rrtype this.cb_rrclass (Int32.of_int this.cb_ttl) buf in
            if this.cb_rrclass = 1
            then Some { name = Dns.Name.of_string this.cb_fullname; cls = Dns.Packet.RR_IN; ttl = Int32.of_int this.cb_ttl; rdata }
            else None
          with Dns.Packet.Not_implemented ->
            None
        end in
    let response = { rr } in
    if Hashtbl.mem in_progress_calls token then begin
      match Hashtbl.find in_progress_calls token with
      | Error _ -> () (* keep the error *)
      | Ok existing -> Hashtbl.replace in_progress_calls token (Ok (response :: existing))
    end else Hashtbl.replace in_progress_calls token (Ok [ response ])

let query name ty =
  let ty' = int_of_DNSServiceType ty in
  if ty' < 0 then failwith "Unrecognised query type";
  let token = next_token () in
  let q = query_record name ty' token in
  query_process q;
  let result = Hashtbl.find in_progress_calls token in
  Hashtbl.remove in_progress_calls token;
  query_deallocate q;
  result

let () =
  Callback.register "ocaml-osx-dnssd" common_callback
