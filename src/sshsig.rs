use crate::digest_openssl::ssh_digest_ctx;
use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::FILE;
    fn __getdelim(
        __lineptr: *mut *mut libc::c_char,
        __n: *mut size_t,
        __delimiter: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> __ssize_t;
    fn ferror(__stream: *mut libc::FILE) -> libc::c_int;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;

    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;
    fn sshkey_advance_past_options(cpp: *mut *mut libc::c_char) -> libc::c_int;
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;

    fn skip_space(_: *mut *mut libc::c_char);
    fn strdelimw(_: *mut *mut libc::c_char) -> *mut libc::c_char;
    fn tohex(_: *const libc::c_void, _: size_t) -> *mut libc::c_char;
    fn parse_absolute_time(_: *const libc::c_char, _: *mut uint64_t) -> libc::c_int;
    fn format_absolute_time(_: uint64_t, _: *mut libc::c_char, _: size_t);
    fn opt_flag(
        opt: *const libc::c_char,
        allow_negate: libc::c_int,
        optsp: *mut *const libc::c_char,
    ) -> libc::c_int;
    fn opt_dequote(
        sp: *mut *const libc::c_char,
        errstrp: *mut *const libc::c_char,
    ) -> *mut libc::c_char;
    fn opt_match(opts: *mut *const libc::c_char, term: *const libc::c_char) -> libc::c_int;

    fn sshbuf_find(
        b: *const crate::sshbuf::sshbuf,
        start_offset: size_t,
        s: *const libc::c_void,
        len: size_t,
        offsetp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_cmp(
        b: *const crate::sshbuf::sshbuf,
        offset: size_t,
        s: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_b64tod(buf: *mut crate::sshbuf::sshbuf, b64: *const libc::c_char) -> libc::c_int;
    fn sshbuf_dtob64(
        d: *const crate::sshbuf::sshbuf,
        b64: *mut crate::sshbuf::sshbuf,
        wrap: libc::c_int,
    ) -> libc::c_int;
    fn sshbuf_get_string_direct(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;

    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_consume_end(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_consume(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;

    fn sshbuf_fromb(buf: *mut crate::sshbuf::sshbuf) -> *mut crate::sshbuf::sshbuf;

    fn sshkey_puts(_: *const crate::sshkey::sshkey, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshkey_sign(
        _: *mut crate::sshkey::sshkey,
        _: *mut *mut u_char,
        _: *mut size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: u_int,
    ) -> libc::c_int;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;

    fn sshkey_verify(
        _: *const crate::sshkey::sshkey,
        _: *const u_char,
        _: size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: u_int,
        _: *mut *mut sshkey_sig_details,
    ) -> libc::c_int;
    fn sshkey_get_sigtype(_: *const u_char, _: size_t, _: *mut *mut libc::c_char) -> libc::c_int;
    fn sshkey_froms(
        _: *mut crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_cert_check_authority(
        _: *const crate::sshkey::sshkey,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: uint64_t,
        _: *const libc::c_char,
        _: *mut *const libc::c_char,
    ) -> libc::c_int;

    fn sshkey_is_cert(_: *const crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_equal(
        _: *const crate::sshkey::sshkey,
        _: *const crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_read(_: *mut crate::sshkey::sshkey, _: *mut *mut libc::c_char) -> libc::c_int;
    fn sshkey_new(_: libc::c_int) -> *mut crate::sshkey::sshkey;
    fn match_pattern(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn match_pattern_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn ssh_digest_alg_by_name(name: *const libc::c_char) -> libc::c_int;
    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_digest_buffer(
        alg: libc::c_int,
        b: *const crate::sshbuf::sshbuf,
        d: *mut u_char,
        dlen: size_t,
    ) -> libc::c_int;
    fn ssh_digest_start(alg: libc::c_int) -> *mut ssh_digest_ctx;
    fn ssh_digest_update(
        ctx: *mut ssh_digest_ctx,
        m: *const libc::c_void,
        mlen: size_t,
    ) -> libc::c_int;
    fn ssh_digest_final(ctx: *mut ssh_digest_ctx, d: *mut u_char, dlen: size_t) -> libc::c_int;
    fn ssh_digest_free(ctx: *mut ssh_digest_ctx);
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;

pub type _IO_lock_t = ();

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshsigopt {
    pub ca: libc::c_int,
    pub namespaces: *mut libc::c_char,
    pub valid_after: uint64_t,
    pub valid_before: uint64_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_sig_details {
    pub sk_counter: uint32_t,
    pub sk_flags: uint8_t,
}
pub type sshsig_signer = unsafe extern "C" fn(
    *mut crate::sshkey::sshkey,
    *mut *mut u_char,
    *mut size_t,
    *const u_char,
    size_t,
    *const libc::c_char,
    *const libc::c_char,
    *const libc::c_char,
    u_int,
    *mut libc::c_void,
) -> libc::c_int;
pub const KEY_RSA: sshkey_types = 0;
pub const KEY_UNSPEC: sshkey_types = 14;
pub type sshkey_types = libc::c_uint;
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
#[inline]
unsafe extern "C" fn getline(
    mut __lineptr: *mut *mut libc::c_char,
    mut __n: *mut size_t,
    mut __stream: *mut libc::FILE,
) -> __ssize_t {
    return __getdelim(__lineptr, __n, '\n' as i32, __stream);
}
pub unsafe extern "C" fn sshsig_armor(
    mut blob: *const crate::sshbuf::sshbuf,
    mut out: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = -(1 as libc::c_int);
    *out = 0 as *mut crate::sshbuf::sshbuf;
    buf = crate::sshbuf::sshbuf_new();
    if buf.is_null() {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sshsig_armor\0")).as_ptr(),
            57 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
        r = -(2 as libc::c_int);
    } else {
        r = sshbuf_put(
            buf,
            b"-----BEGIN SSH SIGNATURE-----\n\0" as *const u8 as *const libc::c_char
                as *const libc::c_void,
            (::core::mem::size_of::<[libc::c_char; 31]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sshsig_armor\0"))
                    .as_ptr(),
                64 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"crate::sshbuf_getput_basic::sshbuf_putf\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = sshbuf_dtob64(blob, buf, 1 as libc::c_int);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"sshsig.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sshsig_armor\0"))
                        .as_ptr(),
                    69 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"base64 encode signature\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = sshbuf_put(
                    buf,
                    b"-----END SSH SIGNATURE-----\0" as *const u8 as *const libc::c_char
                        as *const libc::c_void,
                    (::core::mem::size_of::<[libc::c_char; 28]>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                );
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, '\n' as i32 as u_char);
                    r != 0 as libc::c_int
                } {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"sshsig_armor\0",
                        ))
                        .as_ptr(),
                        76 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"sshbuf_put\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    *out = buf;
                    buf = 0 as *mut crate::sshbuf::sshbuf;
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    crate::sshbuf::sshbuf_free(buf);
    return r;
}
pub unsafe extern "C" fn sshsig_dearmor(
    mut sig: *mut crate::sshbuf::sshbuf,
    mut out: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut eoffset: size_t = 0 as libc::c_int as size_t;
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut b64: *mut libc::c_char = 0 as *mut libc::c_char;
    sbuf = sshbuf_fromb(sig);
    if sbuf.is_null() {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sshsig_dearmor\0"))
                .as_ptr(),
            98 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"sshbuf_fromb failed\0" as *const u8 as *const libc::c_char,
        );
        return -(2 as libc::c_int);
    }
    r = sshbuf_cmp(
        sbuf,
        0 as libc::c_int as size_t,
        b"-----BEGIN SSH SIGNATURE-----\n\0" as *const u8 as *const libc::c_char
            as *const libc::c_void,
        (::core::mem::size_of::<[libc::c_char; 31]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    );
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sshsig_dearmor\0"))
                .as_ptr(),
            104 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Couldn't parse signature: missing header\0" as *const u8 as *const libc::c_char,
        );
    } else {
        r = sshbuf_consume(
            sbuf,
            (::core::mem::size_of::<[libc::c_char; 31]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sshsig_dearmor\0"))
                    .as_ptr(),
                109 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"consume\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = sshbuf_find(
                sbuf,
                0 as libc::c_int as size_t,
                b"\n-----END SSH SIGNATURE-----\0" as *const u8 as *const libc::c_char
                    as *const libc::c_void,
                (::core::mem::size_of::<[libc::c_char; 29]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                &mut eoffset,
            );
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"sshsig.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"sshsig_dearmor\0",
                    ))
                    .as_ptr(),
                    115 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Couldn't parse signature: missing footer\0" as *const u8
                        as *const libc::c_char,
                );
            } else {
                r = sshbuf_consume_end(
                    sbuf,
                    (crate::sshbuf::sshbuf_len(sbuf)).wrapping_sub(eoffset),
                );
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"sshsig_dearmor\0",
                        ))
                        .as_ptr(),
                        120 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"consume\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    b64 = crate::sshbuf_misc::sshbuf_dup_string(sbuf);
                    if b64.is_null() {
                        crate::log::sshlog(
                            b"sshsig.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"sshsig_dearmor\0",
                            ))
                            .as_ptr(),
                            125 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"crate::sshbuf_misc::sshbuf_dup_string failed\0" as *const u8
                                as *const libc::c_char,
                        );
                        r = -(2 as libc::c_int);
                    } else {
                        buf = crate::sshbuf::sshbuf_new();
                        if buf.is_null() {
                            crate::log::sshlog(
                                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                    b"sshsig_dearmor\0",
                                ))
                                .as_ptr(),
                                131 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"crate::sshbuf::sshbuf_new() failed\0" as *const u8
                                    as *const libc::c_char,
                            );
                            r = -(2 as libc::c_int);
                        } else {
                            r = sshbuf_b64tod(buf, b64);
                            if r != 0 as libc::c_int {
                                crate::log::sshlog(
                                    b"sshsig.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                        b"sshsig_dearmor\0",
                                    ))
                                    .as_ptr(),
                                    137 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    ssh_err(r),
                                    b"decode base64\0" as *const u8 as *const libc::c_char,
                                );
                            } else {
                                *out = buf;
                                r = 0 as libc::c_int;
                                buf = 0 as *mut crate::sshbuf::sshbuf;
                            }
                        }
                    }
                }
            }
        }
    }
    crate::sshbuf::sshbuf_free(buf);
    crate::sshbuf::sshbuf_free(sbuf);
    libc::free(b64 as *mut libc::c_void);
    return r;
}
unsafe extern "C" fn sshsig_wrap_sign(
    mut key: *mut crate::sshkey::sshkey,
    mut hashalg: *const libc::c_char,
    mut sk_provider: *const libc::c_char,
    mut sk_pin: *const libc::c_char,
    mut h_message: *const crate::sshbuf::sshbuf,
    mut sig_namespace: *const libc::c_char,
    mut out: *mut *mut crate::sshbuf::sshbuf,
    mut signer: Option<sshsig_signer>,
    mut signer_ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = 0;
    let mut slen: size_t = 0 as libc::c_int as size_t;
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut tosign: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sign_alg: *const libc::c_char = 0 as *const libc::c_char;
    tosign = crate::sshbuf::sshbuf_new();
    if tosign.is_null() || {
        blob = crate::sshbuf::sshbuf_new();
        blob.is_null()
    } {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"sshsig_wrap_sign\0"))
                .as_ptr(),
            167 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
        r = -(2 as libc::c_int);
    } else {
        r = sshbuf_put(
            tosign,
            b"SSHSIG\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            (::core::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
        if r != 0 as libc::c_int
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(tosign, sig_namespace);
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_string(
                    tosign,
                    0 as *const libc::c_void,
                    0 as libc::c_int as size_t,
                );
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(tosign, hashalg);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_stringb(tosign, h_message);
                r != 0 as libc::c_int
            }
        {
            crate::log::sshlog(
                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"sshsig_wrap_sign\0"))
                    .as_ptr(),
                177 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"assemble message to sign\0" as *const u8 as *const libc::c_char,
            );
        } else {
            if sshkey_type_plain((*key).type_0) == KEY_RSA as libc::c_int {
                sign_alg = b"rsa-sha2-512\0" as *const u8 as *const libc::c_char;
            }
            if signer.is_some() {
                r = signer.expect("non-null function pointer")(
                    key,
                    &mut sig,
                    &mut slen,
                    crate::sshbuf::sshbuf_ptr(tosign),
                    crate::sshbuf::sshbuf_len(tosign),
                    sign_alg,
                    sk_provider,
                    sk_pin,
                    0 as libc::c_int as u_int,
                    signer_ctx,
                );
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                            b"sshsig_wrap_sign\0",
                        ))
                        .as_ptr(),
                        189 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"Couldn't sign message (signer)\0" as *const u8 as *const libc::c_char,
                    );
                    current_block = 12108230819160066442;
                } else {
                    current_block = 10048703153582371463;
                }
            } else {
                r = sshkey_sign(
                    key,
                    &mut sig,
                    &mut slen,
                    crate::sshbuf::sshbuf_ptr(tosign),
                    crate::sshbuf::sshbuf_len(tosign),
                    sign_alg,
                    sk_provider,
                    sk_pin,
                    0 as libc::c_int as u_int,
                );
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                            b"sshsig_wrap_sign\0",
                        ))
                        .as_ptr(),
                        196 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"Couldn't sign message\0" as *const u8 as *const libc::c_char,
                    );
                    current_block = 12108230819160066442;
                } else {
                    current_block = 10048703153582371463;
                }
            }
            match current_block {
                12108230819160066442 => {}
                _ => {
                    r = sshbuf_put(
                        blob,
                        b"SSHSIG\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                        (::core::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    );
                    if r != 0 as libc::c_int
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                                blob,
                                0x1 as libc::c_int as u_int32_t,
                            );
                            r != 0 as libc::c_int
                        }
                        || {
                            r = sshkey_puts(key, blob);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_cstring(blob, sig_namespace);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_string(
                                blob,
                                0 as *const libc::c_void,
                                0 as libc::c_int as size_t,
                            );
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_cstring(blob, hashalg);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_string(
                                blob,
                                sig as *const libc::c_void,
                                slen,
                            );
                            r != 0 as libc::c_int
                        }
                    {
                        crate::log::sshlog(
                            b"sshsig.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                                b"sshsig_wrap_sign\0",
                            ))
                            .as_ptr(),
                            208 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"assemble signature object\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        if !out.is_null() {
                            *out = blob;
                            blob = 0 as *mut crate::sshbuf::sshbuf;
                        }
                        r = 0 as libc::c_int;
                    }
                }
            }
        }
    }
    libc::free(sig as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(blob);
    crate::sshbuf::sshbuf_free(tosign);
    return r;
}
unsafe extern "C" fn sshsig_parse_preamble(mut buf: *mut crate::sshbuf::sshbuf) -> libc::c_int {
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut sversion: uint32_t = 0;
    r = sshbuf_cmp(
        buf,
        0 as libc::c_int as size_t,
        b"SSHSIG\0" as *const u8 as *const libc::c_char as *const libc::c_void,
        (::core::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    );
    if r != 0 as libc::c_int
        || {
            r = sshbuf_consume(
                buf,
                (::core::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut sversion);
            r != 0 as libc::c_int
        }
    {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"sshsig_parse_preamble\0"))
                .as_ptr(),
            234 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Couldn't verify signature: invalid format\0" as *const u8 as *const libc::c_char,
        );
        return r;
    }
    if sversion > 0x1 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"sshsig_parse_preamble\0"))
                .as_ptr(),
            240 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Signature version %lu is larger than supported version %u\0" as *const u8
                as *const libc::c_char,
            sversion as libc::c_ulong,
            0x1 as libc::c_int,
        );
        return -(4 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn sshsig_check_hashalg(mut hashalg: *const libc::c_char) -> libc::c_int {
    if hashalg.is_null()
        || match_pattern_list(
            hashalg,
            b"sha256,sha512\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        ) == 1 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"sshsig.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"sshsig_check_hashalg\0"))
            .as_ptr(),
        252 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"unsupported hash algorithm \"%.100s\"\0" as *const u8 as *const libc::c_char,
        hashalg,
    );
    return -(58 as libc::c_int);
}
unsafe extern "C" fn sshsig_peek_hashalg(
    mut signature: *mut crate::sshbuf::sshbuf,
    mut hashalgp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut hashalg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = -(1 as libc::c_int);
    if !hashalgp.is_null() {
        *hashalgp = 0 as *mut libc::c_char;
    }
    buf = sshbuf_fromb(signature);
    if buf.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshsig_parse_preamble(buf);
    if !(r != 0 as libc::c_int) {
        r = sshbuf_get_string_direct(buf, 0 as *mut *const u_char, 0 as *mut size_t);
        if r != 0 as libc::c_int
            || {
                r = sshbuf_get_string_direct(buf, 0 as *mut *const u_char, 0 as *mut size_t);
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_get_string(
                    buf,
                    0 as *mut *mut u_char,
                    0 as *mut size_t,
                );
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_get_cstring(
                    buf,
                    &mut hashalg,
                    0 as *mut size_t,
                );
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_get_string_direct(buf, 0 as *mut *const u_char, 0 as *mut size_t);
                r != 0 as libc::c_int
            }
        {
            crate::log::sshlog(
                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"sshsig_peek_hashalg\0",
                ))
                .as_ptr(),
                274 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"parse signature object\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = 0 as libc::c_int;
            *hashalgp = hashalg;
            hashalg = 0 as *mut libc::c_char;
        }
    }
    libc::free(hashalg as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(buf);
    return r;
}
unsafe extern "C" fn sshsig_wrap_verify(
    mut signature: *mut crate::sshbuf::sshbuf,
    mut hashalg: *const libc::c_char,
    mut h_message: *const crate::sshbuf::sshbuf,
    mut expect_namespace: *const libc::c_char,
    mut sign_keyp: *mut *mut crate::sshkey::sshkey,
    mut sig_details: *mut *mut sshkey_sig_details,
) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut toverify: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut sig: *const u_char = 0 as *const u_char;
    let mut got_namespace: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sigtype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sig_hashalg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut siglen: size_t = 0;
    crate::log::sshlog(
        b"sshsig.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"sshsig_wrap_verify\0"))
            .as_ptr(),
        300 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"verify message length %zu\0" as *const u8 as *const libc::c_char,
        crate::sshbuf::sshbuf_len(h_message),
    );
    if !sig_details.is_null() {
        *sig_details = 0 as *mut sshkey_sig_details;
    }
    if !sign_keyp.is_null() {
        *sign_keyp = 0 as *mut crate::sshkey::sshkey;
    }
    toverify = crate::sshbuf::sshbuf_new();
    if toverify.is_null() {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"sshsig_wrap_verify\0"))
                .as_ptr(),
            307 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
        r = -(2 as libc::c_int);
    } else {
        r = sshbuf_put(
            toverify,
            b"SSHSIG\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            (::core::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
        if r != 0 as libc::c_int
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(toverify, expect_namespace);
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_string(
                    toverify,
                    0 as *const libc::c_void,
                    0 as libc::c_int as size_t,
                );
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(toverify, hashalg);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_stringb(toverify, h_message);
                r != 0 as libc::c_int
            }
        {
            crate::log::sshlog(
                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"sshsig_wrap_verify\0",
                ))
                .as_ptr(),
                317 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"assemble message to verify\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = sshsig_parse_preamble(signature);
            if !(r != 0 as libc::c_int) {
                r = sshkey_froms(signature, &mut key);
                if r != 0 as libc::c_int
                    || {
                        r = crate::sshbuf_getput_basic::sshbuf_get_cstring(
                            signature,
                            &mut got_namespace,
                            0 as *mut size_t,
                        );
                        r != 0 as libc::c_int
                    }
                    || {
                        r = crate::sshbuf_getput_basic::sshbuf_get_string(
                            signature,
                            0 as *mut *mut u_char,
                            0 as *mut size_t,
                        );
                        r != 0 as libc::c_int
                    }
                    || {
                        r = crate::sshbuf_getput_basic::sshbuf_get_cstring(
                            signature,
                            &mut sig_hashalg,
                            0 as *mut size_t,
                        );
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_get_string_direct(signature, &mut sig, &mut siglen);
                        r != 0 as libc::c_int
                    }
                {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"sshsig_wrap_verify\0",
                        ))
                        .as_ptr(),
                        329 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"parse signature object\0" as *const u8 as *const libc::c_char,
                    );
                } else if crate::sshbuf::sshbuf_len(signature) != 0 as libc::c_int as libc::c_ulong
                {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"sshsig_wrap_verify\0",
                        ))
                        .as_ptr(),
                        334 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Signature contains trailing data\0" as *const u8 as *const libc::c_char,
                    );
                    r = -(4 as libc::c_int);
                } else if libc::strcmp(expect_namespace, got_namespace) != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"sshsig_wrap_verify\0",
                        ))
                        .as_ptr(),
                        340 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Couldn't verify signature: namespace does not match\0" as *const u8
                            as *const libc::c_char,
                    );
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"sshsig_wrap_verify\0",
                        ))
                        .as_ptr(),
                        342 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"expected namespace \"%s\" received \"%s\"\0" as *const u8
                            as *const libc::c_char,
                        expect_namespace,
                        got_namespace,
                    );
                    r = -(21 as libc::c_int);
                } else if libc::strcmp(hashalg, sig_hashalg) != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"sshsig_wrap_verify\0",
                        ))
                        .as_ptr(),
                        347 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Couldn't verify signature: hash algorithm mismatch\0" as *const u8
                            as *const libc::c_char,
                    );
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"sshsig_wrap_verify\0",
                        ))
                        .as_ptr(),
                        349 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"expected algorithm \"%s\" received \"%s\"\0" as *const u8
                            as *const libc::c_char,
                        hashalg,
                        sig_hashalg,
                    );
                    r = -(21 as libc::c_int);
                } else {
                    if sshkey_type_plain((*key).type_0) == KEY_RSA as libc::c_int {
                        r = sshkey_get_sigtype(sig, siglen, &mut sigtype);
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                    b"sshsig_wrap_verify\0",
                                ))
                                .as_ptr(),
                                357 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"Couldn't verify signature: unable to get signature type\0"
                                    as *const u8
                                    as *const libc::c_char,
                            );
                            current_block = 12070049392499819894;
                        } else if match_pattern_list(
                            sigtype,
                            b"rsa-sha2-512,rsa-sha2-256\0" as *const u8 as *const libc::c_char,
                            0 as libc::c_int,
                        ) != 1 as libc::c_int
                        {
                            crate::log::sshlog(
                                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<
                                    &[u8; 19],
                                    &[libc::c_char; 19],
                                >(b"sshsig_wrap_verify\0"))
                                    .as_ptr(),
                                362 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"Couldn't verify signature: unsupported crate::sshkey::RSA signature algorithm %s\0"
                                    as *const u8 as *const libc::c_char,
                                sigtype,
                            );
                            r = -(58 as libc::c_int);
                            current_block = 12070049392499819894;
                        } else {
                            current_block = 1608152415753874203;
                        }
                    } else {
                        current_block = 1608152415753874203;
                    }
                    match current_block {
                        12070049392499819894 => {}
                        _ => {
                            r = sshkey_verify(
                                key,
                                sig,
                                siglen,
                                crate::sshbuf::sshbuf_ptr(toverify),
                                crate::sshbuf::sshbuf_len(toverify),
                                0 as *const libc::c_char,
                                0 as libc::c_int as u_int,
                                sig_details,
                            );
                            if r != 0 as libc::c_int {
                                crate::log::sshlog(
                                    b"sshsig.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                        b"sshsig_wrap_verify\0",
                                    ))
                                    .as_ptr(),
                                    369 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    ssh_err(r),
                                    b"Signature verification failed\0" as *const u8
                                        as *const libc::c_char,
                                );
                            } else {
                                r = 0 as libc::c_int;
                                if !sign_keyp.is_null() {
                                    *sign_keyp = key;
                                    key = 0 as *mut crate::sshkey::sshkey;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    libc::free(got_namespace as *mut libc::c_void);
    libc::free(sigtype as *mut libc::c_void);
    libc::free(sig_hashalg as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(buf);
    crate::sshbuf::sshbuf_free(toverify);
    crate::sshkey::sshkey_free(key);
    return r;
}
unsafe extern "C" fn hash_buffer(
    mut m: *const crate::sshbuf::sshbuf,
    mut hashalg: *const libc::c_char,
    mut bp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut hex: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hash: [libc::c_char; 64] = [0; 64];
    let mut alg: libc::c_int = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    *bp = 0 as *mut crate::sshbuf::sshbuf;
    memset(
        hash.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
    );
    r = sshsig_check_hashalg(hashalg);
    if r != 0 as libc::c_int {
        return r;
    }
    alg = ssh_digest_alg_by_name(hashalg);
    if alg == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"hash_buffer\0")).as_ptr(),
            402 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"can't look up hash algorithm %s\0" as *const u8 as *const libc::c_char,
            hashalg,
        );
        return -(1 as libc::c_int);
    }
    r = ssh_digest_buffer(
        alg,
        m,
        hash.as_mut_ptr() as *mut u_char,
        ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
    );
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"hash_buffer\0")).as_ptr(),
            406 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"ssh_digest_buffer\0" as *const u8 as *const libc::c_char,
        );
        return r;
    }
    hex = tohex(
        hash.as_mut_ptr() as *const libc::c_void,
        ssh_digest_bytes(alg),
    );
    if !hex.is_null() {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"hash_buffer\0")).as_ptr(),
            410 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"final hash: %s\0" as *const u8 as *const libc::c_char,
            hex,
        );
        freezero(hex as *mut libc::c_void, strlen(hex));
    }
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        r = -(2 as libc::c_int);
    } else {
        r = sshbuf_put(
            b,
            hash.as_mut_ptr() as *const libc::c_void,
            ssh_digest_bytes(alg),
        );
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"hash_buffer\0"))
                    .as_ptr(),
                418 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"sshbuf_put\0" as *const u8 as *const libc::c_char,
            );
        } else {
            *bp = b;
            b = 0 as *mut crate::sshbuf::sshbuf;
            r = 0 as libc::c_int;
        }
    }
    crate::sshbuf::sshbuf_free(b);
    explicit_bzero(
        hash.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
    );
    return r;
}
pub unsafe extern "C" fn sshsig_signb(
    mut key: *mut crate::sshkey::sshkey,
    mut hashalg: *const libc::c_char,
    mut sk_provider: *const libc::c_char,
    mut sk_pin: *const libc::c_char,
    mut message: *const crate::sshbuf::sshbuf,
    mut sig_namespace: *const libc::c_char,
    mut out: *mut *mut crate::sshbuf::sshbuf,
    mut signer: Option<sshsig_signer>,
    mut signer_ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = -(1 as libc::c_int);
    if hashalg.is_null() {
        hashalg = b"sha512\0" as *const u8 as *const libc::c_char;
    }
    if !out.is_null() {
        *out = 0 as *mut crate::sshbuf::sshbuf;
    }
    r = hash_buffer(message, hashalg, &mut b);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sshsig_signb\0")).as_ptr(),
            445 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"hash buffer\0" as *const u8 as *const libc::c_char,
        );
    } else {
        r = sshsig_wrap_sign(
            key,
            hashalg,
            sk_provider,
            sk_pin,
            b,
            sig_namespace,
            out,
            signer,
            signer_ctx,
        );
        if !(r != 0 as libc::c_int) {
            r = 0 as libc::c_int;
        }
    }
    crate::sshbuf::sshbuf_free(b);
    return r;
}
pub unsafe extern "C" fn sshsig_verifyb(
    mut signature: *mut crate::sshbuf::sshbuf,
    mut message: *const crate::sshbuf::sshbuf,
    mut expect_namespace: *const libc::c_char,
    mut sign_keyp: *mut *mut crate::sshkey::sshkey,
    mut sig_details: *mut *mut sshkey_sig_details,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut hashalg: *mut libc::c_char = 0 as *mut libc::c_char;
    if !sig_details.is_null() {
        *sig_details = 0 as *mut sshkey_sig_details;
    }
    if !sign_keyp.is_null() {
        *sign_keyp = 0 as *mut crate::sshkey::sshkey;
    }
    r = sshsig_peek_hashalg(signature, &mut hashalg);
    if r != 0 as libc::c_int {
        return r;
    }
    crate::log::sshlog(
        b"sshsig.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sshsig_verifyb\0")).as_ptr(),
        473 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"signature made with hash \"%s\"\0" as *const u8 as *const libc::c_char,
        hashalg,
    );
    r = hash_buffer(message, hashalg, &mut b);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sshsig_verifyb\0"))
                .as_ptr(),
            475 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"hash buffer\0" as *const u8 as *const libc::c_char,
        );
    } else {
        r = sshsig_wrap_verify(
            signature,
            hashalg,
            b,
            expect_namespace,
            sign_keyp,
            sig_details,
        );
        if !(r != 0 as libc::c_int) {
            r = 0 as libc::c_int;
        }
    }
    crate::sshbuf::sshbuf_free(b);
    libc::free(hashalg as *mut libc::c_void);
    return r;
}
unsafe extern "C" fn hash_file(
    mut fd: libc::c_int,
    mut hashalg: *const libc::c_char,
    mut bp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut hex: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut rbuf: [libc::c_char; 8192] = [0; 8192];
    let mut hash: [libc::c_char; 64] = [0; 64];
    let mut n: ssize_t = 0;
    let mut total: ssize_t = 0 as libc::c_int as ssize_t;
    let mut ctx: *mut ssh_digest_ctx = 0 as *mut ssh_digest_ctx;
    let mut alg: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    *bp = 0 as *mut crate::sshbuf::sshbuf;
    memset(
        hash.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
    );
    r = sshsig_check_hashalg(hashalg);
    if r != 0 as libc::c_int {
        return r;
    }
    alg = ssh_digest_alg_by_name(hashalg);
    if alg == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"hash_file\0")).as_ptr(),
            504 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"can't look up hash algorithm %s\0" as *const u8 as *const libc::c_char,
            hashalg,
        );
        return -(1 as libc::c_int);
    }
    ctx = ssh_digest_start(alg);
    if ctx.is_null() {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"hash_file\0")).as_ptr(),
            508 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"ssh_digest_start failed\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    loop {
        n = read(
            fd,
            rbuf.as_mut_ptr() as *mut libc::c_void,
            ::core::mem::size_of::<[libc::c_char; 8192]>() as libc::c_ulong,
        );
        if n == -(1 as libc::c_int) as libc::c_long {
            if *libc::__errno_location() == 4 as libc::c_int
                || *libc::__errno_location() == 11 as libc::c_int
            {
                continue;
            }
            oerrno = *libc::__errno_location();
            crate::log::sshlog(
                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"hash_file\0"))
                    .as_ptr(),
                516 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"read: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
            *libc::__errno_location() = oerrno;
            r = -(24 as libc::c_int);
            current_block = 6182669104404250719;
            break;
        } else if n == 0 as libc::c_int as libc::c_long {
            crate::log::sshlog(
                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"hash_file\0"))
                    .as_ptr(),
                521 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"hashed %zu bytes\0" as *const u8 as *const libc::c_char,
                total,
            );
            current_block = 5601891728916014340;
            break;
        } else {
            total = (total as libc::c_ulong).wrapping_add(n as size_t) as ssize_t as ssize_t;
            r = ssh_digest_update(ctx, rbuf.as_mut_ptr() as *const libc::c_void, n as size_t);
            if !(r != 0 as libc::c_int) {
                continue;
            }
            crate::log::sshlog(
                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"hash_file\0"))
                    .as_ptr(),
                526 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"ssh_digest_update\0" as *const u8 as *const libc::c_char,
            );
            current_block = 6182669104404250719;
            break;
        }
    }
    match current_block {
        5601891728916014340 => {
            r = ssh_digest_final(
                ctx,
                hash.as_mut_ptr() as *mut u_char,
                ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
            );
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"sshsig.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"hash_file\0"))
                        .as_ptr(),
                    531 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"ssh_digest_final\0" as *const u8 as *const libc::c_char,
                );
            } else {
                hex = tohex(
                    hash.as_mut_ptr() as *const libc::c_void,
                    ssh_digest_bytes(alg),
                );
                if !hex.is_null() {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"hash_file\0"))
                            .as_ptr(),
                        535 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"final hash: %s\0" as *const u8 as *const libc::c_char,
                        hex,
                    );
                    freezero(hex as *mut libc::c_void, strlen(hex));
                }
                b = crate::sshbuf::sshbuf_new();
                if b.is_null() {
                    r = -(2 as libc::c_int);
                } else {
                    r = sshbuf_put(
                        b,
                        hash.as_mut_ptr() as *const libc::c_void,
                        ssh_digest_bytes(alg),
                    );
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"sshsig.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(
                                b"hash_file\0",
                            ))
                            .as_ptr(),
                            543 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"sshbuf_put\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        *bp = b;
                        b = 0 as *mut crate::sshbuf::sshbuf;
                        r = 0 as libc::c_int;
                    }
                }
            }
        }
        _ => {}
    }
    oerrno = *libc::__errno_location();
    crate::sshbuf::sshbuf_free(b);
    ssh_digest_free(ctx);
    explicit_bzero(
        hash.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
    );
    *libc::__errno_location() = oerrno;
    return r;
}
pub unsafe extern "C" fn sshsig_sign_fd(
    mut key: *mut crate::sshkey::sshkey,
    mut hashalg: *const libc::c_char,
    mut sk_provider: *const libc::c_char,
    mut sk_pin: *const libc::c_char,
    mut fd: libc::c_int,
    mut sig_namespace: *const libc::c_char,
    mut out: *mut *mut crate::sshbuf::sshbuf,
    mut signer: Option<sshsig_signer>,
    mut signer_ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = -(1 as libc::c_int);
    if hashalg.is_null() {
        hashalg = b"sha512\0" as *const u8 as *const libc::c_char;
    }
    if !out.is_null() {
        *out = 0 as *mut crate::sshbuf::sshbuf;
    }
    r = hash_file(fd, hashalg, &mut b);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sshsig_sign_fd\0"))
                .as_ptr(),
            573 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"hash_file\0" as *const u8 as *const libc::c_char,
        );
        return r;
    }
    r = sshsig_wrap_sign(
        key,
        hashalg,
        sk_provider,
        sk_pin,
        b,
        sig_namespace,
        out,
        signer,
        signer_ctx,
    );
    if !(r != 0 as libc::c_int) {
        r = 0 as libc::c_int;
    }
    crate::sshbuf::sshbuf_free(b);
    return r;
}
pub unsafe extern "C" fn sshsig_verify_fd(
    mut signature: *mut crate::sshbuf::sshbuf,
    mut fd: libc::c_int,
    mut expect_namespace: *const libc::c_char,
    mut sign_keyp: *mut *mut crate::sshkey::sshkey,
    mut sig_details: *mut *mut sshkey_sig_details,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut hashalg: *mut libc::c_char = 0 as *mut libc::c_char;
    if !sig_details.is_null() {
        *sig_details = 0 as *mut sshkey_sig_details;
    }
    if !sign_keyp.is_null() {
        *sign_keyp = 0 as *mut crate::sshkey::sshkey;
    }
    r = sshsig_peek_hashalg(signature, &mut hashalg);
    if r != 0 as libc::c_int {
        return r;
    }
    crate::log::sshlog(
        b"sshsig.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"sshsig_verify_fd\0")).as_ptr(),
        601 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"signature made with hash \"%s\"\0" as *const u8 as *const libc::c_char,
        hashalg,
    );
    r = hash_file(fd, hashalg, &mut b);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"sshsig_verify_fd\0"))
                .as_ptr(),
            603 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"hash_file\0" as *const u8 as *const libc::c_char,
        );
    } else {
        r = sshsig_wrap_verify(
            signature,
            hashalg,
            b,
            expect_namespace,
            sign_keyp,
            sig_details,
        );
        if !(r != 0 as libc::c_int) {
            r = 0 as libc::c_int;
        }
    }
    crate::sshbuf::sshbuf_free(b);
    libc::free(hashalg as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn sshsigopt_parse(
    mut opts: *const libc::c_char,
    mut _path: *const libc::c_char,
    mut _linenum: u_long,
    mut errstrp: *mut *const libc::c_char,
) -> *mut sshsigopt {
    let mut current_block: u64;
    let mut ret: *mut sshsigopt = 0 as *mut sshsigopt;
    let mut r: libc::c_int = 0;
    let mut opt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
    ret = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<sshsigopt>() as libc::c_ulong,
    ) as *mut sshsigopt;
    if ret.is_null() {
        return 0 as *mut sshsigopt;
    }
    if opts.is_null() || *opts as libc::c_int == '\0' as i32 {
        return ret;
    }
    loop {
        if !(*opts as libc::c_int != 0
            && *opts as libc::c_int != ' ' as i32
            && *opts as libc::c_int != '\t' as i32)
        {
            current_block = 9853141518545631134;
            break;
        }
        r = opt_flag(
            b"cert-authority\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
            &mut opts,
        );
        if r != -(1 as libc::c_int) {
            (*ret).ca = 1 as libc::c_int;
        } else if opt_match(
            &mut opts,
            b"namespaces\0" as *const u8 as *const libc::c_char,
        ) != 0
        {
            if !((*ret).namespaces).is_null() {
                errstr = b"multiple \"namespaces\" clauses\0" as *const u8 as *const libc::c_char;
                current_block = 10058102262011668777;
                break;
            } else {
                (*ret).namespaces = opt_dequote(&mut opts, &mut errstr);
                if ((*ret).namespaces).is_null() {
                    current_block = 10058102262011668777;
                    break;
                }
            }
        } else if opt_match(
            &mut opts,
            b"valid-after\0" as *const u8 as *const libc::c_char,
        ) != 0
        {
            if (*ret).valid_after != 0 as libc::c_int as libc::c_ulong {
                errstr = b"multiple \"valid-after\" clauses\0" as *const u8 as *const libc::c_char;
                current_block = 10058102262011668777;
                break;
            } else {
                opt = opt_dequote(&mut opts, &mut errstr);
                if opt.is_null() {
                    current_block = 10058102262011668777;
                    break;
                }
                if parse_absolute_time(opt, &mut (*ret).valid_after) != 0 as libc::c_int
                    || (*ret).valid_after == 0 as libc::c_int as libc::c_ulong
                {
                    libc::free(opt as *mut libc::c_void);
                    errstr = b"invalid \"valid-after\" time\0" as *const u8 as *const libc::c_char;
                    current_block = 10058102262011668777;
                    break;
                } else {
                    libc::free(opt as *mut libc::c_void);
                }
            }
        } else if opt_match(
            &mut opts,
            b"valid-before\0" as *const u8 as *const libc::c_char,
        ) != 0
        {
            if (*ret).valid_before != 0 as libc::c_int as libc::c_ulong {
                errstr = b"multiple \"valid-before\" clauses\0" as *const u8 as *const libc::c_char;
                current_block = 10058102262011668777;
                break;
            } else {
                opt = opt_dequote(&mut opts, &mut errstr);
                if opt.is_null() {
                    current_block = 10058102262011668777;
                    break;
                }
                if parse_absolute_time(opt, &mut (*ret).valid_before) != 0 as libc::c_int
                    || (*ret).valid_before == 0 as libc::c_int as libc::c_ulong
                {
                    libc::free(opt as *mut libc::c_void);
                    errstr = b"invalid \"valid-before\" time\0" as *const u8 as *const libc::c_char;
                    current_block = 10058102262011668777;
                    break;
                } else {
                    libc::free(opt as *mut libc::c_void);
                }
            }
        }
        if *opts as libc::c_int == '\0' as i32
            || *opts as libc::c_int == ' ' as i32
            || *opts as libc::c_int == '\t' as i32
        {
            current_block = 9853141518545631134;
            break;
        }
        if *opts as libc::c_int != ',' as i32 {
            errstr = b"unknown key option\0" as *const u8 as *const libc::c_char;
            current_block = 10058102262011668777;
            break;
        } else {
            opts = opts.offset(1);
            opts;
            if !(*opts as libc::c_int == '\0' as i32) {
                continue;
            }
            errstr = b"unexpected end-of-options\0" as *const u8 as *const libc::c_char;
            current_block = 10058102262011668777;
            break;
        }
    }
    match current_block {
        9853141518545631134 => {
            if (*ret).valid_after != 0 as libc::c_int as libc::c_ulong
                && (*ret).valid_before != 0 as libc::c_int as libc::c_ulong
                && (*ret).valid_before <= (*ret).valid_after
            {
                errstr = b"\"valid-before\" time is before \"valid-after\"\0" as *const u8
                    as *const libc::c_char;
            } else {
                return ret;
            }
        }
        _ => {}
    }
    if !errstrp.is_null() {
        *errstrp = errstr;
    }
    sshsigopt_free(ret);
    return 0 as *mut sshsigopt;
}
pub unsafe extern "C" fn sshsigopt_free(mut opts: *mut sshsigopt) {
    if opts.is_null() {
        return;
    }
    libc::free((*opts).namespaces as *mut libc::c_void);
    libc::free(opts as *mut libc::c_void);
}
unsafe extern "C" fn parse_principals_key_and_options(
    mut path: *const libc::c_char,
    mut linenum: u_long,
    mut line: *mut libc::c_char,
    mut required_principal: *const libc::c_char,
    mut principalsp: *mut *mut libc::c_char,
    mut keyp: *mut *mut crate::sshkey::sshkey,
    mut sigoptsp: *mut *mut sshsigopt,
) -> libc::c_int {
    let mut current_block: u64;
    let mut opts: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut principals: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut reason: *const libc::c_char = 0 as *const libc::c_char;
    let mut sigopts: *mut sshsigopt = 0 as *mut sshsigopt;
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut r: libc::c_int = -(1 as libc::c_int);
    if !principalsp.is_null() {
        *principalsp = 0 as *mut libc::c_char;
    }
    if !sigoptsp.is_null() {
        *sigoptsp = 0 as *mut sshsigopt;
    }
    if !keyp.is_null() {
        *keyp = 0 as *mut crate::sshkey::sshkey;
    }
    cp = line;
    cp = cp.offset(strspn(cp, b" \t\0" as *const u8 as *const libc::c_char) as isize);
    if *cp as libc::c_int == '#' as i32 || *cp as libc::c_int == '\0' as i32 {
        return -(46 as libc::c_int);
    }
    tmp = strdelimw(&mut cp);
    if tmp.is_null() || cp.is_null() {
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                b"parse_principals_key_and_options\0",
            ))
            .as_ptr(),
            744 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s:%lu: invalid line\0" as *const u8 as *const libc::c_char,
            path,
            linenum,
        );
        r = -(4 as libc::c_int);
    } else {
        principals = libc::strdup(tmp);
        if principals.is_null() {
            crate::log::sshlog(
                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                    b"parse_principals_key_and_options\0",
                ))
                .as_ptr(),
                749 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"libc::strdup failed\0" as *const u8 as *const libc::c_char,
            );
            r = -(2 as libc::c_int);
        } else {
            if !required_principal.is_null() {
                if match_pattern_list(required_principal, principals, 0 as libc::c_int)
                    != 1 as libc::c_int
                {
                    r = -(46 as libc::c_int);
                    current_block = 14021242045470572277;
                } else {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                            b"parse_principals_key_and_options\0",
                        ))
                        .as_ptr(),
                        765 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"%s:%lu: matched principal \"%s\"\0" as *const u8 as *const libc::c_char,
                        path,
                        linenum,
                        required_principal,
                    );
                    current_block = 5948590327928692120;
                }
            } else {
                current_block = 5948590327928692120;
            }
            match current_block {
                14021242045470572277 => {}
                _ => {
                    key = sshkey_new(KEY_UNSPEC as libc::c_int);
                    if key.is_null() {
                        crate::log::sshlog(
                            b"sshsig.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                                b"parse_principals_key_and_options\0",
                            ))
                            .as_ptr(),
                            769 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
                        );
                        r = -(2 as libc::c_int);
                    } else {
                        if sshkey_read(key, &mut cp) != 0 as libc::c_int {
                            opts = cp;
                            if sshkey_advance_past_options(&mut cp) != 0 as libc::c_int {
                                crate::log::sshlog(
                                    b"sshsig.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                                        b"parse_principals_key_and_options\0",
                                    ))
                                    .as_ptr(),
                                    777 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"%s:%lu: invalid options\0" as *const u8
                                        as *const libc::c_char,
                                    path,
                                    linenum,
                                );
                                r = -(4 as libc::c_int);
                                current_block = 14021242045470572277;
                            } else if cp.is_null() || *cp as libc::c_int == '\0' as i32 {
                                crate::log::sshlog(
                                    b"sshsig.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                                        b"parse_principals_key_and_options\0",
                                    ))
                                    .as_ptr(),
                                    782 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"%s:%lu: missing key\0" as *const u8 as *const libc::c_char,
                                    path,
                                    linenum,
                                );
                                r = -(4 as libc::c_int);
                                current_block = 14021242045470572277;
                            } else {
                                let fresh0 = cp;
                                cp = cp.offset(1);
                                *fresh0 = '\0' as i32 as libc::c_char;
                                skip_space(&mut cp);
                                if sshkey_read(key, &mut cp) != 0 as libc::c_int {
                                    crate::log::sshlog(
                                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                                            b"parse_principals_key_and_options\0",
                                        ))
                                        .as_ptr(),
                                        789 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"%s:%lu: invalid key\0" as *const u8
                                            as *const libc::c_char,
                                        path,
                                        linenum,
                                    );
                                    r = -(4 as libc::c_int);
                                    current_block = 14021242045470572277;
                                } else {
                                    current_block = 2891135413264362348;
                                }
                            }
                        } else {
                            current_block = 2891135413264362348;
                        }
                        match current_block {
                            14021242045470572277 => {}
                            _ => {
                                crate::log::sshlog(
                                    b"sshsig.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                                        b"parse_principals_key_and_options\0",
                                    ))
                                    .as_ptr(),
                                    794 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG3,
                                    0 as *const libc::c_char,
                                    b"%s:%lu: options %s\0" as *const u8 as *const libc::c_char,
                                    path,
                                    linenum,
                                    if opts.is_null() {
                                        b"\0" as *const u8 as *const libc::c_char
                                    } else {
                                        opts as *const libc::c_char
                                    },
                                );
                                sigopts = sshsigopt_parse(opts, path, linenum, &mut reason);
                                if sigopts.is_null() {
                                    crate::log::sshlog(
                                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                                            b"parse_principals_key_and_options\0",
                                        ))
                                        .as_ptr(),
                                        796 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"%s:%lu: bad options: %s\0" as *const u8
                                            as *const libc::c_char,
                                        path,
                                        linenum,
                                        reason,
                                    );
                                    r = -(4 as libc::c_int);
                                } else {
                                    if !principalsp.is_null() {
                                        *principalsp = principals;
                                        principals = 0 as *mut libc::c_char;
                                    }
                                    if !sigoptsp.is_null() {
                                        *sigoptsp = sigopts;
                                        sigopts = 0 as *mut sshsigopt;
                                    }
                                    if !keyp.is_null() {
                                        *keyp = key;
                                        key = 0 as *mut crate::sshkey::sshkey;
                                    }
                                    r = 0 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    libc::free(principals as *mut libc::c_void);
    sshsigopt_free(sigopts);
    crate::sshkey::sshkey_free(key);
    return r;
}
unsafe extern "C" fn cert_filter_principals(
    mut path: *const libc::c_char,
    mut linenum: u_long,
    mut principalsp: *mut *mut libc::c_char,
    mut cert: *const crate::sshkey::sshkey,
    mut verify_time: uint64_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut oprincipals: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut principals: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut reason: *const libc::c_char = 0 as *const libc::c_char;
    let mut nprincipals: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut i: u_int = 0;
    principals = *principalsp;
    oprincipals = principals;
    *principalsp = 0 as *mut libc::c_char;
    nprincipals = crate::sshbuf::sshbuf_new();
    if nprincipals.is_null() {
        r = -(2 as libc::c_int);
    } else {
        's_27: loop {
            cp = strsep(&mut principals, b",\0" as *const u8 as *const libc::c_char);
            if !(!cp.is_null() && *cp as libc::c_int != '\0' as i32) {
                current_block = 10048703153582371463;
                break;
            }
            r = sshkey_cert_check_authority(
                cert,
                0 as libc::c_int,
                1 as libc::c_int,
                0 as libc::c_int,
                verify_time,
                0 as *const libc::c_char,
                &mut reason,
            );
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"sshsig.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"cert_filter_principals\0",
                    ))
                    .as_ptr(),
                    844 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"%s:%lu: principal \"%s\" not authorized: %s\0" as *const u8
                        as *const libc::c_char,
                    path,
                    linenum,
                    cp,
                    reason,
                );
            } else {
                i = 0 as libc::c_int as u_int;
                while i < (*(*cert).cert).nprincipals {
                    if match_pattern(*((*(*cert).cert).principals).offset(i as isize), cp) != 0 {
                        r = crate::sshbuf_getput_basic::sshbuf_putf(
                            nprincipals,
                            b"%s%s\0" as *const u8 as *const libc::c_char,
                            if crate::sshbuf::sshbuf_len(nprincipals)
                                != 0 as libc::c_int as libc::c_ulong
                            {
                                b",\0" as *const u8 as *const libc::c_char
                            } else {
                                b"\0" as *const u8 as *const libc::c_char
                            },
                            *((*(*cert).cert).principals).offset(i as isize),
                        );
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                    b"cert_filter_principals\0",
                                ))
                                .as_ptr(),
                                853 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"buffer error\0" as *const u8 as *const libc::c_char,
                            );
                            current_block = 14441937283647387424;
                            break 's_27;
                        }
                    }
                    i = i.wrapping_add(1);
                    i;
                }
            }
        }
        match current_block {
            14441937283647387424 => {}
            _ => {
                if crate::sshbuf::sshbuf_len(nprincipals) == 0 as libc::c_int as libc::c_ulong {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                            b"cert_filter_principals\0",
                        ))
                        .as_ptr(),
                        860 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s:%lu: no valid principals found\0" as *const u8 as *const libc::c_char,
                        path,
                        linenum,
                    );
                    r = -(25 as libc::c_int);
                } else {
                    principals = crate::sshbuf_misc::sshbuf_dup_string(nprincipals);
                    if principals.is_null() {
                        crate::log::sshlog(
                            b"sshsig.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                b"cert_filter_principals\0",
                            ))
                            .as_ptr(),
                            865 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"buffer error\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        success = 1 as libc::c_int;
                        *principalsp = principals;
                    }
                }
            }
        }
    }
    crate::sshbuf::sshbuf_free(nprincipals);
    libc::free(oprincipals as *mut libc::c_void);
    return if success != 0 { 0 as libc::c_int } else { r };
}
unsafe extern "C" fn check_allowed_keys_line(
    mut path: *const libc::c_char,
    mut linenum: u_long,
    mut line: *mut libc::c_char,
    mut sign_key: *const crate::sshkey::sshkey,
    mut principal: *const libc::c_char,
    mut sig_namespace: *const libc::c_char,
    mut verify_time: uint64_t,
    mut principalsp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut found_key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut principals: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut reason: *const libc::c_char = 0 as *const libc::c_char;
    let mut sigopts: *mut sshsigopt = 0 as *mut sshsigopt;
    let mut tvalid: [libc::c_char; 64] = [0; 64];
    let mut tverify: [libc::c_char; 64] = [0; 64];
    if !principalsp.is_null() {
        *principalsp = 0 as *mut libc::c_char;
    }
    r = parse_principals_key_and_options(
        path,
        linenum,
        line,
        principal,
        &mut principals,
        &mut found_key,
        &mut sigopts,
    );
    if !(r != 0 as libc::c_int) {
        if (*sigopts).ca == 0 && sshkey_equal(found_key, sign_key) != 0 {
            crate::log::sshlog(
                b"sshsig.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"check_allowed_keys_line\0",
                ))
                .as_ptr(),
                901 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"%s:%lu: matched key\0" as *const u8 as *const libc::c_char,
                path,
                linenum,
            );
            current_block = 4956146061682418353;
        } else if (*sigopts).ca != 0
            && sshkey_is_cert(sign_key) != 0
            && crate::sshkey::sshkey_equal_public((*(*sign_key).cert).signature_key, found_key) != 0
        {
            if !principal.is_null() {
                r = sshkey_cert_check_authority(
                    sign_key,
                    0 as libc::c_int,
                    1 as libc::c_int,
                    0 as libc::c_int,
                    verify_time,
                    principal,
                    &mut reason,
                );
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                            b"check_allowed_keys_line\0",
                        ))
                        .as_ptr(),
                        909 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s:%lu: certificate not authorized: %s\0" as *const u8
                            as *const libc::c_char,
                        path,
                        linenum,
                        reason,
                    );
                    current_block = 10583858686454308878;
                } else {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                            b"check_allowed_keys_line\0",
                        ))
                        .as_ptr(),
                        913 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"%s:%lu: matched certificate CA key\0" as *const u8 as *const libc::c_char,
                        path,
                        linenum,
                    );
                    current_block = 4956146061682418353;
                }
            } else {
                r = cert_filter_principals(path, linenum, &mut principals, sign_key, verify_time);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                            b"check_allowed_keys_line\0",
                        ))
                        .as_ptr(),
                        920 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        ssh_err(r),
                        b"%s:%lu: cert_filter_principals\0" as *const u8 as *const libc::c_char,
                        path,
                        linenum,
                    );
                    current_block = 10583858686454308878;
                } else {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                            b"check_allowed_keys_line\0",
                        ))
                        .as_ptr(),
                        924 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"%s:%lu: matched certificate CA key\0" as *const u8 as *const libc::c_char,
                        path,
                        linenum,
                    );
                    current_block = 4956146061682418353;
                }
            }
        } else {
            current_block = 10583858686454308878;
        }
        match current_block {
            10583858686454308878 => {}
            _ => {
                if !((*sigopts).namespaces).is_null()
                    && !sig_namespace.is_null()
                    && match_pattern_list(sig_namespace, (*sigopts).namespaces, 0 as libc::c_int)
                        != 1 as libc::c_int
                {
                    crate::log::sshlog(
                        b"sshsig.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                            b"check_allowed_keys_line\0",
                        ))
                        .as_ptr(),
                        935 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s:%lu: key is not permitted for use in signature namespace \"%s\"\0"
                            as *const u8 as *const libc::c_char,
                        path,
                        linenum,
                        sig_namespace,
                    );
                } else {
                    format_absolute_time(
                        verify_time,
                        tverify.as_mut_ptr(),
                        ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
                    );
                    if (*sigopts).valid_after != 0 as libc::c_int as libc::c_ulong
                        && verify_time < (*sigopts).valid_after
                    {
                        format_absolute_time(
                            (*sigopts).valid_after,
                            tvalid.as_mut_ptr(),
                            ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
                        );
                        crate::log::sshlog(
                            b"sshsig.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                b"check_allowed_keys_line\0",
                            ))
                            .as_ptr(),
                            947 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s:%lu: key is not yet valid: verify time %s < valid-after %s\0"
                                as *const u8 as *const libc::c_char,
                            path,
                            linenum,
                            tverify.as_mut_ptr(),
                            tvalid.as_mut_ptr(),
                        );
                    } else if (*sigopts).valid_before != 0 as libc::c_int as libc::c_ulong
                        && verify_time > (*sigopts).valid_before
                    {
                        format_absolute_time(
                            (*sigopts).valid_before,
                            tvalid.as_mut_ptr(),
                            ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
                        );
                        crate::log::sshlog(
                            b"sshsig.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                b"check_allowed_keys_line\0",
                            ))
                            .as_ptr(),
                            956 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s:%lu: key has expired: verify time %s > valid-before %s\0"
                                as *const u8 as *const libc::c_char,
                            path,
                            linenum,
                            tverify.as_mut_ptr(),
                            tvalid.as_mut_ptr(),
                        );
                    } else {
                        success = 1 as libc::c_int;
                    }
                }
            }
        }
    }
    if success != 0 && !principalsp.is_null() {
        *principalsp = principals;
        principals = 0 as *mut libc::c_char;
    }
    libc::free(principals as *mut libc::c_void);
    crate::sshkey::sshkey_free(found_key);
    sshsigopt_free(sigopts);
    return if success != 0 {
        0 as libc::c_int
    } else {
        -(46 as libc::c_int)
    };
}
pub unsafe extern "C" fn sshsig_check_allowed_keys(
    mut path: *const libc::c_char,
    mut sign_key: *const crate::sshkey::sshkey,
    mut principal: *const libc::c_char,
    mut sig_namespace: *const libc::c_char,
    mut verify_time: uint64_t,
) -> libc::c_int {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut linenum: u_long = 0 as libc::c_int as u_long;
    let mut r: libc::c_int = -(46 as libc::c_int);
    let mut oerrno: libc::c_int = 0;
    f = fopen(path, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        oerrno = *libc::__errno_location();
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"sshsig_check_allowed_keys\0",
            ))
            .as_ptr(),
            986 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Unable to open allowed keys file \"%s\": %s\0" as *const u8 as *const libc::c_char,
            path,
            libc::strerror(*libc::__errno_location()),
        );
        *libc::__errno_location() = oerrno;
        return -(24 as libc::c_int);
    }
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        linenum = linenum.wrapping_add(1);
        linenum;
        r = check_allowed_keys_line(
            path,
            linenum,
            line,
            sign_key,
            principal,
            sig_namespace,
            verify_time,
            0 as *mut *mut libc::c_char,
        );
        libc::free(line as *mut libc::c_void);
        line = 0 as *mut libc::c_char;
        linesize = 0 as libc::c_int as size_t;
        if r == -(46 as libc::c_int) {
            continue;
        }
        if !(r == 0 as libc::c_int) {
            break;
        }
        fclose(f);
        return 0 as libc::c_int;
    }
    fclose(f);
    libc::free(line as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn sshsig_find_principals(
    mut path: *const libc::c_char,
    mut sign_key: *const crate::sshkey::sshkey,
    mut verify_time: uint64_t,
    mut principals: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut linenum: u_long = 0 as libc::c_int as u_long;
    let mut r: libc::c_int = -(46 as libc::c_int);
    let mut oerrno: libc::c_int = 0;
    f = fopen(path, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        oerrno = *libc::__errno_location();
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"sshsig_find_principals\0",
            ))
            .as_ptr(),
            1026 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Unable to open allowed keys file \"%s\": %s\0" as *const u8 as *const libc::c_char,
            path,
            libc::strerror(*libc::__errno_location()),
        );
        *libc::__errno_location() = oerrno;
        return -(24 as libc::c_int);
    }
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        linenum = linenum.wrapping_add(1);
        linenum;
        r = check_allowed_keys_line(
            path,
            linenum,
            line,
            sign_key,
            0 as *const libc::c_char,
            0 as *const libc::c_char,
            verify_time,
            principals,
        );
        libc::free(line as *mut libc::c_void);
        line = 0 as *mut libc::c_char;
        linesize = 0 as libc::c_int as size_t;
        if r == -(46 as libc::c_int) {
            continue;
        }
        if !(r == 0 as libc::c_int) {
            break;
        }
        fclose(f);
        return 0 as libc::c_int;
    }
    libc::free(line as *mut libc::c_void);
    if ferror(f) != 0 as libc::c_int {
        oerrno = *libc::__errno_location();
        fclose(f);
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"sshsig_find_principals\0",
            ))
            .as_ptr(),
            1053 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Unable to read allowed keys file \"%s\": %s\0" as *const u8 as *const libc::c_char,
            path,
            libc::strerror(*libc::__errno_location()),
        );
        *libc::__errno_location() = oerrno;
        return -(24 as libc::c_int);
    }
    fclose(f);
    return r;
}
pub unsafe extern "C" fn sshsig_match_principals(
    mut path: *const libc::c_char,
    mut principal: *const libc::c_char,
    mut principalsp: *mut *mut *mut libc::c_char,
    mut nprincipalsp: *mut size_t,
) -> libc::c_int {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut found: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut principals: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut tmp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut i: size_t = 0;
    let mut nprincipals: size_t = 0 as libc::c_int as size_t;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut linenum: u_long = 0 as libc::c_int as u_long;
    let mut oerrno: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if !principalsp.is_null() {
        *principalsp = 0 as *mut *mut libc::c_char;
    }
    if !nprincipalsp.is_null() {
        *nprincipalsp = 0 as libc::c_int as size_t;
    }
    f = fopen(path, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        oerrno = *libc::__errno_location();
        crate::log::sshlog(
            b"sshsig.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"sshsig_match_principals\0",
            ))
            .as_ptr(),
            1080 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Unable to open allowed keys file \"%s\": %s\0" as *const u8 as *const libc::c_char,
            path,
            libc::strerror(*libc::__errno_location()),
        );
        *libc::__errno_location() = oerrno;
        return -(24 as libc::c_int);
    }
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        linenum = linenum.wrapping_add(1);
        linenum;
        r = parse_principals_key_and_options(
            path,
            linenum,
            line,
            principal,
            &mut found,
            0 as *mut *mut crate::sshkey::sshkey,
            0 as *mut *mut sshsigopt,
        );
        if r != 0 as libc::c_int {
            if r == -(46 as libc::c_int) {
                continue;
            }
            ret = r;
            oerrno = *libc::__errno_location();
            break;
        } else {
            tmp = recallocarray(
                principals as *mut libc::c_void,
                nprincipals,
                nprincipals.wrapping_add(1 as libc::c_int as libc::c_ulong),
                ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
            ) as *mut *mut libc::c_char;
            if tmp.is_null() {
                ret = -(2 as libc::c_int);
                libc::free(found as *mut libc::c_void);
                break;
            } else {
                principals = tmp;
                let fresh1 = nprincipals;
                nprincipals = nprincipals.wrapping_add(1);
                let ref mut fresh2 = *principals.offset(fresh1 as isize);
                *fresh2 = found;
                libc::free(line as *mut libc::c_void);
                line = 0 as *mut libc::c_char;
                linesize = 0 as libc::c_int as size_t;
            }
        }
    }
    fclose(f);
    if ret == 0 as libc::c_int {
        if nprincipals == 0 as libc::c_int as libc::c_ulong {
            ret = -(46 as libc::c_int);
        }
        if !principalsp.is_null() {
            *principalsp = principals;
            principals = 0 as *mut *mut libc::c_char;
        }
        if !nprincipalsp.is_null() {
            *nprincipalsp = nprincipals;
            nprincipals = 0 as libc::c_int as size_t;
        }
    }
    i = 0 as libc::c_int as size_t;
    while i < nprincipals {
        libc::free(*principals.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(principals as *mut libc::c_void);
    *libc::__errno_location() = oerrno;
    return ret;
}
pub unsafe extern "C" fn sshsig_get_pubkey(
    mut signature: *mut crate::sshbuf::sshbuf,
    mut pubkey: *mut *mut crate::sshkey::sshkey,
) -> libc::c_int {
    let mut pk: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut r: libc::c_int = -(21 as libc::c_int);
    if pubkey.is_null() {
        return -(1 as libc::c_int);
    }
    r = sshsig_parse_preamble(signature);
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshkey_froms(signature, &mut pk);
    if r != 0 as libc::c_int {
        return r;
    }
    *pubkey = pk;
    pk = 0 as *mut crate::sshkey::sshkey;
    return 0 as libc::c_int;
}
