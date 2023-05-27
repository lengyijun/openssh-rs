use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type sshbuf;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    fn getaddrinfo(
        __name: *const libc::c_char,
        __service: *const libc::c_char,
        __req: *const addrinfo,
        __pai: *mut *mut addrinfo,
    ) -> libc::c_int;
    fn freeaddrinfo(__ai: *mut addrinfo);
    fn fprintf(_: *mut libc::FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn getrrsetbyname(
        _: *const libc::c_char,
        _: libc::c_uint,
        _: libc::c_uint,
        _: libc::c_uint,
        _: *mut *mut rrsetinfo,
    ) -> libc::c_int;
    fn freerrset(_: *mut rrsetinfo);
    fn timingsafe_bcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn xmalloc(_: size_t) -> *mut libc::c_void;
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn sshkey_fingerprint_raw(
        k: *const sshkey,
        _: libc::c_int,
        retp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;

    fn sshfatal(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: LogLevel,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: ...
    ) -> !;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int8_t = __uint8_t;
pub type u_int64_t = __uint64_t;
pub type socklen_t = __socklen_t;
pub type __socket_type = libc::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type uint8_t = __uint8_t;

pub type _IO_lock_t = ();

#[derive(Copy, Clone)]
#[repr(C)]
pub struct addrinfo {
    pub ai_flags: libc::c_int,
    pub ai_family: libc::c_int,
    pub ai_socktype: libc::c_int,
    pub ai_protocol: libc::c_int,
    pub ai_addrlen: socklen_t,
    pub ai_addr: *mut sockaddr,
    pub ai_canonname: *mut libc::c_char,
    pub ai_next: *mut addrinfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rdatainfo {
    pub rdi_length: libc::c_uint,
    pub rdi_data: *mut libc::c_uchar,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rrsetinfo {
    pub rri_flags: libc::c_uint,
    pub rri_rdclass: libc::c_uint,
    pub rri_rdtype: libc::c_uint,
    pub rri_ttl: libc::c_uint,
    pub rri_nrdatas: libc::c_uint,
    pub rri_nsigs: libc::c_uint,
    pub rri_name: *mut libc::c_char,
    pub rri_rdatas: *mut rdatainfo,
    pub rri_sigs: *mut rdatainfo,
}
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type EC_KEY = ec_key_st;
pub type sshkey_types = libc::c_uint;
pub const KEY_UNSPEC: sshkey_types = 14;
pub const KEY_ED25519_SK_CERT: sshkey_types = 13;
pub const KEY_ED25519_SK: sshkey_types = 12;
pub const KEY_ECDSA_SK_CERT: sshkey_types = 11;
pub const KEY_ECDSA_SK: sshkey_types = 10;
pub const KEY_XMSS_CERT: sshkey_types = 9;
pub const KEY_XMSS: sshkey_types = 8;
pub const KEY_ED25519_CERT: sshkey_types = 7;
pub const KEY_ECDSA_CERT: sshkey_types = 6;
pub const KEY_DSA_CERT: sshkey_types = 5;
pub const KEY_RSA_CERT: sshkey_types = 4;
pub const KEY_ED25519: sshkey_types = 3;
pub const KEY_ECDSA: sshkey_types = 2;
pub const KEY_DSA: sshkey_types = 1;
pub const KEY_RSA: sshkey_types = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_cert {
    pub certblob: *mut sshbuf,
    pub type_0: u_int,
    pub serial: u_int64_t,
    pub key_id: *mut libc::c_char,
    pub nprincipals: u_int,
    pub principals: *mut *mut libc::c_char,
    pub valid_after: u_int64_t,
    pub valid_before: u_int64_t,
    pub critical: *mut sshbuf,
    pub extensions: *mut sshbuf,
    pub signature_key: *mut sshkey,
    pub signature_type: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey {
    pub type_0: libc::c_int,
    pub flags: libc::c_int,
    pub rsa: *mut RSA,
    pub dsa: *mut DSA,
    pub ecdsa_nid: libc::c_int,
    pub ecdsa: *mut EC_KEY,
    pub ed25519_sk: *mut u_char,
    pub ed25519_pk: *mut u_char,
    pub xmss_name: *mut libc::c_char,
    pub xmss_filename: *mut libc::c_char,
    pub xmss_state: *mut libc::c_void,
    pub xmss_sk: *mut u_char,
    pub xmss_pk: *mut u_char,
    pub sk_application: *mut libc::c_char,
    pub sk_flags: uint8_t,
    pub sk_key_handle: *mut sshbuf,
    pub sk_reserved: *mut sshbuf,
    pub cert: *mut sshkey_cert,
    pub shielded_private: *mut u_char,
    pub shielded_len: size_t,
    pub shield_prekey: *mut u_char,
    pub shield_prekey_len: size_t,
}
pub type sshfp_types = libc::c_uint;
pub const SSHFP_KEY_XMSS: sshfp_types = 5;
pub const SSHFP_KEY_ED25519: sshfp_types = 4;
pub const SSHFP_KEY_ECDSA: sshfp_types = 3;
pub const SSHFP_KEY_DSA: sshfp_types = 2;
pub const SSHFP_KEY_RSA: sshfp_types = 1;
pub const SSHFP_KEY_RESERVED: sshfp_types = 0;
pub type sshfp_hashes = libc::c_uint;
pub const SSHFP_HASH_MAX: sshfp_hashes = 3;
pub const SSHFP_HASH_SHA256: sshfp_hashes = 2;
pub const SSHFP_HASH_SHA1: sshfp_hashes = 1;
pub const SSHFP_HASH_RESERVED: sshfp_hashes = 0;
pub type LogLevel = libc::c_int;
pub const SYSLOG_LEVEL_NOT_SET: LogLevel = -1;
pub const SYSLOG_LEVEL_DEBUG3: LogLevel = 7;
pub const SYSLOG_LEVEL_DEBUG2: LogLevel = 6;
pub const SYSLOG_LEVEL_DEBUG1: LogLevel = 5;
pub const SYSLOG_LEVEL_VERBOSE: LogLevel = 4;
pub const SYSLOG_LEVEL_INFO: LogLevel = 3;
pub const SYSLOG_LEVEL_ERROR: LogLevel = 2;
pub const SYSLOG_LEVEL_FATAL: LogLevel = 1;
pub const SYSLOG_LEVEL_QUIET: LogLevel = 0;
static mut errset_text: [*const libc::c_char; 6] = [
    b"success\0" as *const u8 as *const libc::c_char,
    b"out of memory\0" as *const u8 as *const libc::c_char,
    b"general failure\0" as *const u8 as *const libc::c_char,
    b"invalid parameter\0" as *const u8 as *const libc::c_char,
    b"name does not exist\0" as *const u8 as *const libc::c_char,
    b"data does not exist\0" as *const u8 as *const libc::c_char,
];
unsafe extern "C" fn dns_result_totext(mut res: libc::c_uint) -> *const libc::c_char {
    match res {
        0 => return errset_text[0 as libc::c_int as usize],
        1 => return errset_text[1 as libc::c_int as usize],
        2 => return errset_text[2 as libc::c_int as usize],
        3 => return errset_text[3 as libc::c_int as usize],
        4 => return errset_text[4 as libc::c_int as usize],
        5 => return errset_text[5 as libc::c_int as usize],
        _ => return b"unknown error\0" as *const u8 as *const libc::c_char,
    };
}
unsafe extern "C" fn dns_read_key(
    mut algorithm: *mut u_int8_t,
    mut digest_type: *mut u_int8_t,
    mut digest: *mut *mut u_char,
    mut digest_len: *mut size_t,
    mut key: *mut sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut fp_alg: libc::c_int = -(1 as libc::c_int);
    match (*key).type_0 {
        0 => {
            *algorithm = SSHFP_KEY_RSA as libc::c_int as u_int8_t;
        }
        1 => {
            *algorithm = SSHFP_KEY_DSA as libc::c_int as u_int8_t;
        }
        2 => {
            *algorithm = SSHFP_KEY_ECDSA as libc::c_int as u_int8_t;
        }
        3 => {
            *algorithm = SSHFP_KEY_ED25519 as libc::c_int as u_int8_t;
        }
        8 => {
            *algorithm = SSHFP_KEY_XMSS as libc::c_int as u_int8_t;
        }
        _ => {
            *algorithm = SSHFP_KEY_RESERVED as libc::c_int as u_int8_t;
        }
    }
    match *digest_type as libc::c_int {
        1 => {
            fp_alg = 1 as libc::c_int;
        }
        2 => {
            fp_alg = 2 as libc::c_int;
        }
        _ => {
            *digest_type = SSHFP_HASH_RESERVED as libc::c_int as u_int8_t;
        }
    }
    if *algorithm as libc::c_int != 0 && *digest_type as libc::c_int != 0 {
        r = sshkey_fingerprint_raw(key, fp_alg, digest, digest_len);
        if r != 0 as libc::c_int {
            sshfatal(
                b"dns.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"dns_read_key\0"))
                    .as_ptr(),
                121 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"sshkey_fingerprint_raw\0" as *const u8 as *const libc::c_char,
            );
        }
        success = 1 as libc::c_int;
    } else {
        *digest = 0 as *mut u_char;
        *digest_len = 0 as libc::c_int as size_t;
    }
    return success;
}
unsafe extern "C" fn dns_read_rdata(
    mut algorithm: *mut u_int8_t,
    mut digest_type: *mut u_int8_t,
    mut digest: *mut *mut u_char,
    mut digest_len: *mut size_t,
    mut rdata: *mut u_char,
    mut rdata_len: libc::c_int,
) -> libc::c_int {
    let mut success: libc::c_int = 0 as libc::c_int;
    *algorithm = SSHFP_KEY_RESERVED as libc::c_int as u_int8_t;
    *digest_type = SSHFP_HASH_RESERVED as libc::c_int as u_int8_t;
    if rdata_len >= 2 as libc::c_int {
        *algorithm = *rdata.offset(0 as libc::c_int as isize);
        *digest_type = *rdata.offset(1 as libc::c_int as isize);
        *digest_len = (rdata_len - 2 as libc::c_int) as size_t;
        if *digest_len > 0 as libc::c_int as libc::c_ulong {
            *digest = xmalloc(*digest_len) as *mut u_char;
            memcpy(
                *digest as *mut libc::c_void,
                rdata.offset(2 as libc::c_int as isize) as *const libc::c_void,
                *digest_len,
            );
        } else {
            *digest = xstrdup(b"\0" as *const u8 as *const libc::c_char) as *mut u_char;
        }
        success = 1 as libc::c_int;
    }
    return success;
}
unsafe extern "C" fn is_numeric_hostname(mut hostname: *const libc::c_char) -> libc::c_int {
    let mut hints: addrinfo = addrinfo {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: 0 as *mut sockaddr,
        ai_canonname: 0 as *mut libc::c_char,
        ai_next: 0 as *mut addrinfo,
    };
    let mut ai: *mut addrinfo = 0 as *mut addrinfo;
    if hostname.is_null() {
        crate::log::sshlog(
            b"dns.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"is_numeric_hostname\0"))
                .as_ptr(),
            175 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"is_numeric_hostname called with NULL hostname\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_socktype = SOCK_DGRAM as libc::c_int;
    hints.ai_flags = 0x4 as libc::c_int;
    if getaddrinfo(hostname, 0 as *const libc::c_char, &mut hints, &mut ai) == 0 as libc::c_int {
        freeaddrinfo(ai);
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn verify_host_key_dns(
    mut hostname: *const libc::c_char,
    mut _address: *mut sockaddr,
    mut hostkey: *mut sshkey,
    mut flags: *mut libc::c_int,
) -> libc::c_int {
    let mut counter: u_int = 0;
    let mut result: libc::c_int = 0;
    let mut fingerprints: *mut rrsetinfo = 0 as *mut rrsetinfo;
    let mut hostkey_algorithm: u_int8_t = 0;
    let mut hostkey_digest: *mut u_char = 0 as *mut u_char;
    let mut hostkey_digest_len: size_t = 0;
    let mut dnskey_algorithm: u_int8_t = 0;
    let mut dnskey_digest_type: u_int8_t = 0;
    let mut dnskey_digest: *mut u_char = 0 as *mut u_char;
    let mut dnskey_digest_len: size_t = 0;
    *flags = 0 as libc::c_int;
    crate::log::sshlog(
        b"dns.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"verify_host_key_dns\0"))
            .as_ptr(),
        214 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"verify_host_key_dns\0" as *const u8 as *const libc::c_char,
    );
    if hostkey.is_null() {
        sshfatal(
            b"dns.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"verify_host_key_dns\0"))
                .as_ptr(),
            216 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"No key to look up!\0" as *const u8 as *const libc::c_char,
        );
    }
    if is_numeric_hostname(hostname) != 0 {
        crate::log::sshlog(
            b"dns.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"verify_host_key_dns\0"))
                .as_ptr(),
            219 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"skipped DNS lookup for numerical hostname\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    result = getrrsetbyname(
        hostname,
        1 as libc::c_int as libc::c_uint,
        44 as libc::c_int as libc::c_uint,
        0 as libc::c_int as libc::c_uint,
        &mut fingerprints,
    );
    if result != 0 {
        crate::log::sshlog(
            b"dns.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"verify_host_key_dns\0"))
                .as_ptr(),
            226 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"DNS lookup error: %s\0" as *const u8 as *const libc::c_char,
            dns_result_totext(result as libc::c_uint),
        );
        return -(1 as libc::c_int);
    }
    if (*fingerprints).rri_flags & 1 as libc::c_int as libc::c_uint != 0 {
        *flags |= 0x4 as libc::c_int;
        crate::log::sshlog(
            b"dns.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"verify_host_key_dns\0"))
                .as_ptr(),
            233 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"found %d secure fingerprints in DNS\0" as *const u8 as *const libc::c_char,
            (*fingerprints).rri_nrdatas,
        );
    } else {
        crate::log::sshlog(
            b"dns.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"verify_host_key_dns\0"))
                .as_ptr(),
            236 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"found %d insecure fingerprints in DNS\0" as *const u8 as *const libc::c_char,
            (*fingerprints).rri_nrdatas,
        );
    }
    if (*fingerprints).rri_nrdatas != 0 {
        *flags |= 0x1 as libc::c_int;
    }
    counter = 0 as libc::c_int as u_int;
    while counter < (*fingerprints).rri_nrdatas {
        if dns_read_rdata(
            &mut dnskey_algorithm,
            &mut dnskey_digest_type,
            &mut dnskey_digest,
            &mut dnskey_digest_len,
            (*((*fingerprints).rri_rdatas).offset(counter as isize)).rdi_data,
            (*((*fingerprints).rri_rdatas).offset(counter as isize)).rdi_length as libc::c_int,
        ) == 0
        {
            crate::log::sshlog(
                b"dns.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"verify_host_key_dns\0",
                ))
                .as_ptr(),
                251 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_VERBOSE,
                0 as *const libc::c_char,
                b"Error parsing fingerprint from DNS.\0" as *const u8 as *const libc::c_char,
            );
        } else {
            crate::log::sshlog(
                b"dns.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"verify_host_key_dns\0",
                ))
                .as_ptr(),
                255 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"checking SSHFP type %d fptype %d\0" as *const u8 as *const libc::c_char,
                dnskey_algorithm as libc::c_int,
                dnskey_digest_type as libc::c_int,
            );
            if dns_read_key(
                &mut hostkey_algorithm,
                &mut dnskey_digest_type,
                &mut hostkey_digest,
                &mut hostkey_digest_len,
                hostkey,
            ) == 0
            {
                crate::log::sshlog(
                    b"dns.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"verify_host_key_dns\0",
                    ))
                    .as_ptr(),
                    260 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Error calculating key fingerprint.\0" as *const u8 as *const libc::c_char,
                );
                free(dnskey_digest as *mut libc::c_void);
                freerrset(fingerprints);
                return -(1 as libc::c_int);
            }
            if hostkey_algorithm as libc::c_int == dnskey_algorithm as libc::c_int
                && hostkey_digest_len == dnskey_digest_len
            {
                if timingsafe_bcmp(
                    hostkey_digest as *const libc::c_void,
                    dnskey_digest as *const libc::c_void,
                    hostkey_digest_len,
                ) == 0 as libc::c_int
                {
                    crate::log::sshlog(
                        b"dns.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"verify_host_key_dns\0",
                        ))
                        .as_ptr(),
                        272 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"matched SSHFP type %d fptype %d\0" as *const u8 as *const libc::c_char,
                        dnskey_algorithm as libc::c_int,
                        dnskey_digest_type as libc::c_int,
                    );
                    *flags |= 0x2 as libc::c_int;
                } else {
                    crate::log::sshlog(
                        b"dns.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"verify_host_key_dns\0",
                        ))
                        .as_ptr(),
                        276 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"failed SSHFP type %d fptype %d\0" as *const u8 as *const libc::c_char,
                        dnskey_algorithm as libc::c_int,
                        dnskey_digest_type as libc::c_int,
                    );
                    *flags |= 0x8 as libc::c_int;
                }
            }
            free(dnskey_digest as *mut libc::c_void);
            free(hostkey_digest as *mut libc::c_void);
        }
        counter = counter.wrapping_add(1);
        counter;
    }
    freerrset(fingerprints);
    if *flags & 0x8 as libc::c_int != 0 {
        *flags &= !(0x2 as libc::c_int);
    }
    if *flags & 0x1 as libc::c_int != 0 {
        if *flags & 0x2 as libc::c_int != 0 {
            crate::log::sshlog(
                b"dns.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"verify_host_key_dns\0",
                ))
                .as_ptr(),
                292 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"matching host key fingerprint found in DNS\0" as *const u8 as *const libc::c_char,
            );
        } else {
            crate::log::sshlog(
                b"dns.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"verify_host_key_dns\0",
                ))
                .as_ptr(),
                294 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"mismatching host key fingerprint found in DNS\0" as *const u8
                    as *const libc::c_char,
            );
        }
    } else {
        crate::log::sshlog(
            b"dns.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"verify_host_key_dns\0"))
                .as_ptr(),
            296 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"no host key fingerprint found in DNS\0" as *const u8 as *const libc::c_char,
        );
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn export_dns_rr(
    mut hostname: *const libc::c_char,
    mut key: *mut sshkey,
    mut f: *mut libc::FILE,
    mut generic: libc::c_int,
    mut alg: libc::c_int,
) -> libc::c_int {
    let mut rdata_pubkey_algorithm: u_int8_t = 0 as libc::c_int as u_int8_t;
    let mut rdata_digest_type: u_int8_t = SSHFP_HASH_RESERVED as libc::c_int as u_int8_t;
    let mut dtype: u_int8_t = 0;
    let mut rdata_digest: *mut u_char = 0 as *mut u_char;
    let mut i: size_t = 0;
    let mut rdata_digest_len: size_t = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    dtype = SSHFP_HASH_SHA1 as libc::c_int as u_int8_t;
    while (dtype as libc::c_int) < SSHFP_HASH_MAX as libc::c_int {
        if !(alg != -(1 as libc::c_int) && dtype as libc::c_int != alg) {
            rdata_digest_type = dtype;
            if dns_read_key(
                &mut rdata_pubkey_algorithm,
                &mut rdata_digest_type,
                &mut rdata_digest,
                &mut rdata_digest_len,
                key,
            ) != 0
            {
                if generic != 0 {
                    fprintf(
                        f,
                        b"%s IN TYPE%d \\# %zu %02x %02x \0" as *const u8 as *const libc::c_char,
                        hostname,
                        44 as libc::c_int,
                        (2 as libc::c_int as libc::c_ulong).wrapping_add(rdata_digest_len),
                        rdata_pubkey_algorithm as libc::c_int,
                        rdata_digest_type as libc::c_int,
                    );
                } else {
                    fprintf(
                        f,
                        b"%s IN SSHFP %d %d \0" as *const u8 as *const libc::c_char,
                        hostname,
                        rdata_pubkey_algorithm as libc::c_int,
                        rdata_digest_type as libc::c_int,
                    );
                }
                i = 0 as libc::c_int as size_t;
                while i < rdata_digest_len {
                    fprintf(
                        f,
                        b"%02x\0" as *const u8 as *const libc::c_char,
                        *rdata_digest.offset(i as isize) as libc::c_int,
                    );
                    i = i.wrapping_add(1);
                    i;
                }
                fprintf(f, b"\n\0" as *const u8 as *const libc::c_char);
                free(rdata_digest as *mut libc::c_void);
                success = 1 as libc::c_int;
            }
        }
        dtype = dtype.wrapping_add(1);
        dtype;
    }
    if success == 0 as libc::c_int {
        crate::log::sshlog(
            b"dns.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"export_dns_rr\0"))
                .as_ptr(),
            340 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"unsupported algorithm and/or digest_type\0" as *const u8 as *const libc::c_char,
        );
    }
    return success;
}
