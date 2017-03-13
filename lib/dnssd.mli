(**
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

(** Bindings to the macOS DNS SD API

    These functions allow DNS queries to be made via the macOS resolver.

    @see <https://opensource.apple.com/source/mDNSResponder/mDNSResponder-320.5/mDNSShared/dns_sd.h>dns_sd.h

*)

type kDNSServiceType =
  | A          (** Host address. *)
  | NS         (** Authoritative server. *)
  | MD         (** Mail destination. *)
  | MF         (** Mail forwarder. *)
  | CNAME      (** Canonical name. *)
  | SOA        (** Start of authority zone. *)
  | MB         (** Mailbox domain name. *)
  | MG         (** Mail group member. *)
  | MR         (** Mail rename name. *)
  | NULL       (** Null resource record. *)
  | WKS        (** Well known service. *)
  | PTR        (** Domain name pointer. *)
  | HINFO      (** Host information. *)
  | MINFO      (** Mailbox information. *)
  | MX         (** Mail routing information. *)
  | TXT        (** One or more text strings (NOT "zero or more..."). *)
  | RP         (** Responsible person. *)
  | AFSDB      (** AFS cell database. *)
  | X25        (** X_25 calling address. *)
  | ISDN       (** ISDN calling address. *)
  | RT         (** Router. *)
  | NSAP       (** NSAP address. *)
  | NSAP_PTR   (** Reverse NSAP lookup (deprecated). *)
  | SIG        (** Security signature. *)
  | KEY        (** Security key. *)
  | PX         (** X.400 mail mapping. *)
  | GPOS       (** Geographical position (withdrawn). *)
  | AAAA       (** IPv6 Address. *)
  | LOC        (** Location Information. *)
  | NXT        (** Next domain (security). *)
  | EID        (** Endpoint identifier. *)
  | NIMLOC     (** Nimrod Locator. *)
  | SRV        (** Server Selection. *)
  | ATMA       (** ATM Address *)
  | NAPTR      (** Naming Authority PoinTeR *)
  | KX         (** Key Exchange *)
  | CERT       (** Certification record *)
  | A6         (** IPv6 Address (deprecated) *)
  | DNAME      (** Non-terminal DNAME (for IPv6) *)
  | SINK       (** Kitchen sink (experimental) *)
  | OPT        (** EDNS0 option (meta-RR) *)
  | APL        (** Address Prefix List *)
  | DS         (** Delegation Signer *)
  | SSHFP      (** SSH Key Fingerprint *)
  | IPSECKEY   (** IPSECKEY *)
  | RRSIG      (** RRSIG *)
  | NSEC       (** Denial of Existence *)
  | DNSKEY     (** DNSKEY *)
  | DHCID      (** DHCP Client Identifier *)
  | NSEC3      (** Hashed Authenticated Denial of Existence *)
  | NSEC3PARAM (** Hashed Authenticated Denial of Existence *)
  | HIP        (** Host Identity Protocol *)

  | SPF        (** Sender Policy Framework for E-Mail *)
  | UINFO      (** IANA-Reserved *)
  | UID        (** IANA-Reserved *)
  | GID        (** IANA-Reserved *)
  | UNSPEC     (** IANA-Reserved *)

  | TKEY       (** Transaction key *)
  | TSIG       (** Transaction signature. *)
  | IXFR       (** Incremental zone transfer. *)
  | AXFR       (** Transfer zone of authority. *)
  | MAILB      (** Transfer mailbox records. *)
  | MAILA      (** Transfer mail agent records. *)
  | ANY        (** Wildcard match. *)
(** DNS record type *)
