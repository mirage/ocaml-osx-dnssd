#include <caml/mlvalues.h>
#include <caml/memory.h>

#include <dns_sd.h>

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
