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

(* Convert from DNS `q_type` to the `type` enum values *)

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
