#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/custom.h>

#include <dns_sd.h>
#include <string.h>

int table_DNSServiceType[] = {
    kDNSServiceType_A,
    kDNSServiceType_NS,
    kDNSServiceType_MD,
    kDNSServiceType_MF,
    kDNSServiceType_CNAME,
    kDNSServiceType_SOA,
    kDNSServiceType_MB,
    kDNSServiceType_MG,
    kDNSServiceType_MR,
    kDNSServiceType_NULL,
    kDNSServiceType_WKS,
    kDNSServiceType_PTR,
    kDNSServiceType_HINFO,
    kDNSServiceType_MINFO,
    kDNSServiceType_MX,
    kDNSServiceType_TXT,
    kDNSServiceType_RP,
    kDNSServiceType_AFSDB,
    kDNSServiceType_X25,
    kDNSServiceType_ISDN,
    kDNSServiceType_RT,
    kDNSServiceType_NSAP,
    kDNSServiceType_NSAP_PTR,
    kDNSServiceType_SIG,
    kDNSServiceType_KEY,
    kDNSServiceType_PX,
    kDNSServiceType_GPOS,
    kDNSServiceType_AAAA,
    kDNSServiceType_LOC,
    kDNSServiceType_NXT,
    kDNSServiceType_EID,
    kDNSServiceType_NIMLOC,
    kDNSServiceType_SRV,
    kDNSServiceType_ATMA,
    kDNSServiceType_NAPTR,
    kDNSServiceType_KX,
    kDNSServiceType_CERT,
    kDNSServiceType_A6,
    kDNSServiceType_DNAME,
    kDNSServiceType_SINK,
    kDNSServiceType_OPT,
    kDNSServiceType_APL,
    kDNSServiceType_DS,
    kDNSServiceType_SSHFP,
    kDNSServiceType_IPSECKEY,
    kDNSServiceType_RRSIG,
    kDNSServiceType_NSEC,
    kDNSServiceType_DNSKEY,
    kDNSServiceType_DHCID,
    kDNSServiceType_NSEC3,
    kDNSServiceType_NSEC3PARAM,

    kDNSServiceType_HIP,

    kDNSServiceType_SPF,
    kDNSServiceType_UINFO,
    kDNSServiceType_UID,
    kDNSServiceType_GID,
    kDNSServiceType_UNSPEC,

    kDNSServiceType_TKEY,
    kDNSServiceType_TSIG,
    kDNSServiceType_IXFR,
    kDNSServiceType_AXFR,
    kDNSServiceType_MAILB,
    kDNSServiceType_MAILA,
    kDNSServiceType_ANY
};

CAMLprim value stub_int_of_DNSServiceType(value ty) {
  CAMLparam1(ty);
  CAMLlocal1(ret);
  int c_ty = Int_val(ty);
  if (c_ty >= sizeof(table_DNSServiceType)) {
    ret = Val_int(-1);
  } else {
    ret = Val_int(table_DNSServiceType[c_ty]);
  }
  CAMLreturn(ret);
}

typedef struct _query {
  DNSServiceRef serviceRef;
  bool finalized;
  /* callback */
} query;

#define Query_val(x) ((query*)Data_custom_val(x))

static void finalize_query(value v) {
  query *q = Query_val(v);
  if (!q->finalized) DNSServiceRefDeallocate(q->serviceRef);
  q->finalized = true;
}

static struct custom_operations query_custom_ops = {
    .identifier   = "DNSServiceRef query handling",
    .finalize     = finalize_query,
    .compare      = custom_compare_default,
    .hash         = custom_hash_default,
    .serialize    = custom_serialize_default,
    .deserialize  = custom_deserialize_default
};

CAMLprim value stub_query_record(value name, value ty, value callback) {
  CAMLparam3(name, ty, callback);
  CAMLlocal1(v);
  v = caml_alloc_custom(&query_custom_ops, sizeof(query), 0, 1);
  query *q = Query_val(v);
  q->finalized = false;
  /* TODO: set the serviceRef */
  CAMLreturn(v);
}

CAMLprim value stub_query_process(value v) {
  CAMLparam1(v);
  query *q = Query_val(v);
  DNSServiceProcessResult(q->serviceRef);
  CAMLreturn(Val_unit);
}

CAMLprim value stub_query_deallocate(value v) {
  CAMLparam1(v);
  query *q = Query_val(v);
  if (!q->finalized) DNSServiceRefDeallocate(q->serviceRef);
  q->finalized = true;
  CAMLreturn(Val_unit);
}
