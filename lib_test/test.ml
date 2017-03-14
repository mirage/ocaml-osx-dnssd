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

let src =
  let src = Logs.Src.create "dnssd" ~doc:"DNS-SD interface" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let test_mx () =
  match Dnssd.(query "google.com" Dns.Packet.Q_MX) with
  | Error err -> failwith (Printf.sprintf "Error looking up MX records for google.com: %s" (Dnssd.string_of_error err))
  | Ok [] -> failwith "No MX records found for google.com";
  | Ok results ->
    List.iter
      (fun rr ->
        Log.info (fun f -> f "google.com MX: %s" (Dns.Packet.rr_to_string rr))
      ) results

let test_nomx () =
  match Dnssd.(query "dave.recoil.org" Dns.Packet.Q_MX) with
  | Error err -> failwith (Printf.sprintf "Error looking up records for dave.recoil.org: %s" (Dnssd.string_of_error err))
  | Ok results ->
    List.iter
      (fun rr ->
        Log.info (fun f -> f "dave.recoil.org MX: %s" (Dns.Packet.rr_to_string rr))
      ) results
    (* FIXME: check the type of the records *)

let test_types = [
  "MX", `Quick, test_mx;
  "No MX", `Quick, test_nomx;
]

let test_notfound () =
  match Dnssd.(query "doesnotexist.dave.recoil.org" Dns.Packet.Q_MX) with
  | Error Dnssd.NoSuchRecord -> ()
  | Error err -> failwith (Printf.sprintf "Error looking up records for doesnotexist.dave.recoil.org: %s" (Dnssd.string_of_error err))
  | Ok results ->
    List.iter
      (fun rr ->
        Log.info (fun f -> f "doesnotexist.dave.recoil.org MX: %s" (Dns.Packet.rr_to_string rr))
      ) results;
    failwith "expected NXDomain for doesnotexist.dave.recoil.org"

let test_errors = [
  "NXDomain", `Quick, test_notfound;
]

let test_select () =
  let open Dnssd.LowLevel in
  let q = query "dave.recoil.org" Dns.Packet.Q_A in
  let fd = socket q in
  let r, _, _ = Unix.select [ fd ] [] [] 5. in
  if r = [] then failwith "No events on socket according to select";
  match response q with
  | Error err -> failwith (Printf.sprintf "Error looking up records for dave.recoil.org: %s" (Dnssd.string_of_error err))
  | Ok results ->
    List.iter
      (fun rr ->
        Log.info (fun f -> f "dave.recoil.org A: %s" (Dns.Packet.rr_to_string rr))
      ) results

let test_cancel () =
  let open Dnssd.LowLevel in
  let q = query "dave.recoil.org" Dns.Packet.Q_A in
  cancel q;
  try
    let _ = response q in
    failwith "test_cancel expected an exception"
  with Cancelled ->
    ()
  | e -> raise e

let test_lowlevel = [
  "select", `Quick, test_select;
  "cancel", `Quick, test_cancel;
]

let test_1000 () =
  for _ = 0 to 1000 do
    match Dnssd.(query "google.com" Dns.Packet.Q_MX) with
    | Error err -> failwith (Printf.sprintf "Error looking up MX records for google.com: %s" (Dnssd.string_of_error err))
    | Ok [] -> failwith "No MX records found for google.com";
    | Ok _ -> ()
  done

let test_perf = [
  "1000", `Quick, test_1000;
]

let () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Lwt.async_exception_hook := (fun exn ->
    Logs.err (fun f -> f "Lwt.async failure %s: %s"
      (Printexc.to_string exn)
      (Printexc.get_backtrace ())
    )
  );
  Alcotest.run "dnssd" [
    "types", test_types;
    "errors", test_errors;
    "lowlevel", test_lowlevel;
    "performance", test_perf;
  ]
