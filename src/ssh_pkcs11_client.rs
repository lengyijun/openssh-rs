use crate::atomicio::atomicio;
use ::libc;
use libc::close;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type sshbuf;
    pub type bignum_st;
    pub type bignum_ctx;
    pub type dsa_st;
    pub type rsa_st;
    pub type rsa_meth_st;
    pub type ec_key_st;
    pub type ec_key_method_st;
    pub type ECDSA_SIG_st;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;

    fn execlp(__file: *const libc::c_char, __arg: *const libc::c_char, _: ...) -> libc::c_int;

    fn fork() -> __pid_t;
    static mut stderr: *mut libc::FILE;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn EC_KEY_METHOD_get_sign(
        meth: *const EC_KEY_METHOD,
        psign: *mut Option<
            unsafe extern "C" fn(
                libc::c_int,
                *const libc::c_uchar,
                libc::c_int,
                *mut libc::c_uchar,
                *mut libc::c_uint,
                *const BIGNUM,
                *const BIGNUM,
                *mut EC_KEY,
            ) -> libc::c_int,
        >,
        psign_setup: *mut Option<
            unsafe extern "C" fn(
                *mut EC_KEY,
                *mut BN_CTX,
                *mut *mut BIGNUM,
                *mut *mut BIGNUM,
            ) -> libc::c_int,
        >,
        psign_sig: *mut Option<
            unsafe extern "C" fn(
                *const libc::c_uchar,
                libc::c_int,
                *const BIGNUM,
                *const BIGNUM,
                *mut EC_KEY,
            ) -> *mut ECDSA_SIG,
        >,
    );
    fn EC_KEY_METHOD_set_sign(
        meth: *mut EC_KEY_METHOD,
        sign: Option<
            unsafe extern "C" fn(
                libc::c_int,
                *const libc::c_uchar,
                libc::c_int,
                *mut libc::c_uchar,
                *mut libc::c_uint,
                *const BIGNUM,
                *const BIGNUM,
                *mut EC_KEY,
            ) -> libc::c_int,
        >,
        sign_setup: Option<
            unsafe extern "C" fn(
                *mut EC_KEY,
                *mut BN_CTX,
                *mut *mut BIGNUM,
                *mut *mut BIGNUM,
            ) -> libc::c_int,
        >,
        sign_sig: Option<
            unsafe extern "C" fn(
                *const libc::c_uchar,
                libc::c_int,
                *const BIGNUM,
                *const BIGNUM,
                *mut EC_KEY,
            ) -> *mut ECDSA_SIG,
        >,
    );
    fn EC_KEY_METHOD_new(meth: *const EC_KEY_METHOD) -> *mut EC_KEY_METHOD;
    fn d2i_ECDSA_SIG(
        a: *mut *mut ECDSA_SIG,
        in_0: *mut *const libc::c_uchar,
        len: libc::c_long,
    ) -> *mut ECDSA_SIG;
    fn EC_KEY_set_method(key: *mut EC_KEY, meth: *const EC_KEY_METHOD) -> libc::c_int;
    fn EC_KEY_OpenSSL() -> *const EC_KEY_METHOD;
    fn EC_KEY_up_ref(key: *mut EC_KEY) -> libc::c_int;
    fn RSA_size(rsa: *const RSA) -> libc::c_int;
    fn RSA_up_ref(r: *mut RSA) -> libc::c_int;
    fn RSA_get_default_method() -> *const RSA_METHOD;
    fn RSA_set_method(rsa: *mut RSA, meth: *const RSA_METHOD) -> libc::c_int;
    fn RSA_meth_dup(meth: *const RSA_METHOD) -> *mut RSA_METHOD;
    fn RSA_meth_set1_name(meth: *mut RSA_METHOD, name: *const libc::c_char) -> libc::c_int;
    fn RSA_meth_set_priv_enc(
        rsa: *mut RSA_METHOD,
        priv_enc: Option<
            unsafe extern "C" fn(
                libc::c_int,
                *const libc::c_uchar,
                *mut libc::c_uchar,
                *mut RSA,
                libc::c_int,
            ) -> libc::c_int,
        >,
    ) -> libc::c_int;
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn sshbuf_new() -> *mut sshbuf;
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_reset(buf: *mut sshbuf);
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_mutable_ptr(buf: *const sshbuf) -> *mut u_char;
    fn sshbuf_consume(buf: *mut sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_put(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_put_u8(buf: *mut sshbuf, val: u_char) -> libc::c_int;
    fn sshbuf_get_string(
        buf: *mut sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_string(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn log_level_get() -> LogLevel;

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
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn sshkey_new(_: libc::c_int) -> *mut sshkey;
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_ecdsa_key_to_nid(_: *mut EC_KEY) -> libc::c_int;
    fn sshkey_from_blob(_: *const u_char, _: size_t, _: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_to_blob(_: *const sshkey, _: *mut *mut u_char, _: *mut size_t) -> libc::c_int;

}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __ssize_t = libc::c_long;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
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
pub type uint8_t = __uint8_t;

pub type _IO_lock_t = ();

pub type BIGNUM = bignum_st;
pub type BN_CTX = bignum_ctx;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type RSA_METHOD = rsa_meth_st;
pub type EC_KEY = ec_key_st;
pub type EC_KEY_METHOD = ec_key_method_st;
pub type ECDSA_SIG = ECDSA_SIG_st;
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
static mut fd: libc::c_int = -(1 as libc::c_int);
static mut pid: pid_t = -(1 as libc::c_int);
unsafe extern "C" fn send_msg(mut m: *mut sshbuf) {
    let mut buf: [u_char; 4] = [0; 4];
    let mut mlen: size_t = sshbuf_len(m);
    let mut r: libc::c_int = 0;
    let __v: u_int32_t = mlen as u_int32_t;
    *buf.as_mut_ptr().offset(0 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *buf.as_mut_ptr().offset(1 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *buf.as_mut_ptr().offset(2 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *buf.as_mut_ptr().offset(3 as libc::c_int as isize) =
        (__v & 0xff as libc::c_int as libc::c_uint) as u_char;
    if atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        fd,
        buf.as_mut_ptr() as *mut libc::c_void,
        4 as libc::c_int as size_t,
    ) != 4 as libc::c_int as libc::c_ulong
        || atomicio(
            ::core::mem::transmute::<
                Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
                Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
            >(Some(
                write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
            )),
            fd,
            sshbuf_mutable_ptr(m) as *mut libc::c_void,
            sshbuf_len(m),
        ) != sshbuf_len(m)
    {
        crate::log::sshlog(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"send_msg\0")).as_ptr(),
            66 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"write to helper failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_consume(m, mlen);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"send_msg\0")).as_ptr(),
            68 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"consume\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn recv_msg(mut m: *mut sshbuf) -> libc::c_int {
    let mut l: u_int = 0;
    let mut len: u_int = 0;
    let mut c: u_char = 0;
    let mut buf: [u_char; 1024] = [0; 1024];
    let mut r: libc::c_int = 0;
    len = atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        fd,
        buf.as_mut_ptr() as *mut libc::c_void,
        4 as libc::c_int as size_t,
    ) as u_int;
    if len != 4 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"recv_msg\0")).as_ptr(),
            79 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"read from helper failed: %u\0" as *const u8 as *const libc::c_char,
            len,
        );
        return 0 as libc::c_int;
    }
    len = (*(buf.as_mut_ptr() as *const u_char).offset(0 as libc::c_int as isize) as u_int32_t)
        << 24 as libc::c_int
        | (*(buf.as_mut_ptr() as *const u_char).offset(1 as libc::c_int as isize) as u_int32_t)
            << 16 as libc::c_int
        | (*(buf.as_mut_ptr() as *const u_char).offset(2 as libc::c_int as isize) as u_int32_t)
            << 8 as libc::c_int
        | *(buf.as_mut_ptr() as *const u_char).offset(3 as libc::c_int as isize) as u_int32_t;
    if len > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_uint {
        sshfatal(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"recv_msg\0")).as_ptr(),
            84 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"response too long: %u\0" as *const u8 as *const libc::c_char,
            len,
        );
    }
    sshbuf_reset(m);
    while len > 0 as libc::c_int as libc::c_uint {
        l = len;
        if l as libc::c_ulong > ::core::mem::size_of::<[u_char; 1024]>() as libc::c_ulong {
            l = ::core::mem::size_of::<[u_char; 1024]>() as libc::c_ulong as u_int;
        }
        if atomicio(
            Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            l as size_t,
        ) != l as libc::c_ulong
        {
            crate::log::sshlog(
                b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"recv_msg\0")).as_ptr(),
                92 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"response from helper failed.\0" as *const u8 as *const libc::c_char,
            );
            return 0 as libc::c_int;
        }
        r = sshbuf_put(m, buf.as_mut_ptr() as *const libc::c_void, l as size_t);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"recv_msg\0")).as_ptr(),
                96 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"sshbuf_put\0" as *const u8 as *const libc::c_char,
            );
        }
        len = (len as libc::c_uint).wrapping_sub(l) as u_int as u_int;
    }
    r = sshbuf_get_u8(m, &mut c);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"recv_msg\0")).as_ptr(),
            100 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse type\0" as *const u8 as *const libc::c_char,
        );
    }
    return c as libc::c_int;
}
pub unsafe extern "C" fn pkcs11_init(mut _interactive: libc::c_int) -> libc::c_int {
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn pkcs11_terminate() {
    if fd >= 0 as libc::c_int {
        close(fd);
    }
}
unsafe extern "C" fn rsa_encrypt(
    mut flen: libc::c_int,
    mut from: *const u_char,
    mut to: *mut u_char,
    mut rsa: *mut RSA,
    mut padding: libc::c_int,
) -> libc::c_int {
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut blob: *mut u_char = 0 as *mut u_char;
    let mut signature: *mut u_char = 0 as *mut u_char;
    let mut blen: size_t = 0;
    let mut slen: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if !(padding != 1 as libc::c_int) {
        key = sshkey_new(KEY_UNSPEC as libc::c_int);
        if key.is_null() {
            crate::log::sshlog(
                b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"rsa_encrypt\0"))
                    .as_ptr(),
                130 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            (*key).type_0 = KEY_RSA as libc::c_int;
            RSA_up_ref(rsa);
            (*key).rsa = rsa;
            r = sshkey_to_blob(key, &mut blob, &mut blen);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"rsa_encrypt\0"))
                        .as_ptr(),
                    137 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"encode key\0" as *const u8 as *const libc::c_char,
                );
            } else {
                msg = sshbuf_new();
                if msg.is_null() {
                    sshfatal(
                        b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                            b"rsa_encrypt\0",
                        ))
                        .as_ptr(),
                        141 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
                    );
                }
                r = sshbuf_put_u8(msg, 13 as libc::c_int as u_char);
                if r != 0 as libc::c_int
                    || {
                        r = sshbuf_put_string(msg, blob as *const libc::c_void, blen);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_string(msg, from as *const libc::c_void, flen as size_t);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_u32(msg, 0 as libc::c_int as u_int32_t);
                        r != 0 as libc::c_int
                    }
                {
                    sshfatal(
                        b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                            b"rsa_encrypt\0",
                        ))
                        .as_ptr(),
                        146 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose\0" as *const u8 as *const libc::c_char,
                    );
                }
                send_msg(msg);
                sshbuf_reset(msg);
                if recv_msg(msg) == 14 as libc::c_int {
                    r = sshbuf_get_string(msg, &mut signature, &mut slen);
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"rsa_encrypt\0",
                            ))
                            .as_ptr(),
                            152 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"parse\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    if slen <= RSA_size(rsa) as size_t {
                        memcpy(
                            to as *mut libc::c_void,
                            signature as *const libc::c_void,
                            slen,
                        );
                        ret = slen as libc::c_int;
                    }
                    libc::free(signature as *mut libc::c_void);
                }
            }
        }
    }
    libc::free(blob as *mut libc::c_void);
    sshkey_free(key);
    sshbuf_free(msg);
    return ret;
}
unsafe extern "C" fn ecdsa_do_sign(
    mut dgst: *const libc::c_uchar,
    mut dgst_len: libc::c_int,
    mut _inv: *const BIGNUM,
    mut _rp: *const BIGNUM,
    mut ec: *mut EC_KEY,
) -> *mut ECDSA_SIG {
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut ret: *mut ECDSA_SIG = 0 as *mut ECDSA_SIG;
    let mut cp: *const u_char = 0 as *const u_char;
    let mut blob: *mut u_char = 0 as *mut u_char;
    let mut signature: *mut u_char = 0 as *mut u_char;
    let mut blen: size_t = 0;
    let mut slen: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    let mut nid: libc::c_int = 0;
    nid = sshkey_ecdsa_key_to_nid(ec);
    if nid < 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ecdsa_do_sign\0"))
                .as_ptr(),
            181 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"couldn't get curve nid\0" as *const u8 as *const libc::c_char,
        );
    } else {
        key = sshkey_new(KEY_UNSPEC as libc::c_int);
        if key.is_null() {
            crate::log::sshlog(
                b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ecdsa_do_sign\0"))
                    .as_ptr(),
                187 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            (*key).ecdsa = ec;
            (*key).ecdsa_nid = nid;
            (*key).type_0 = KEY_ECDSA as libc::c_int;
            EC_KEY_up_ref(ec);
            r = sshkey_to_blob(key, &mut blob, &mut blen);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ecdsa_do_sign\0"))
                        .as_ptr(),
                    196 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"encode key\0" as *const u8 as *const libc::c_char,
                );
            } else {
                msg = sshbuf_new();
                if msg.is_null() {
                    sshfatal(
                        b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(
                            b"ecdsa_do_sign\0",
                        ))
                        .as_ptr(),
                        200 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
                    );
                }
                r = sshbuf_put_u8(msg, 13 as libc::c_int as u_char);
                if r != 0 as libc::c_int
                    || {
                        r = sshbuf_put_string(msg, blob as *const libc::c_void, blen);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_string(msg, dgst as *const libc::c_void, dgst_len as size_t);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_u32(msg, 0 as libc::c_int as u_int32_t);
                        r != 0 as libc::c_int
                    }
                {
                    sshfatal(
                        b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(
                            b"ecdsa_do_sign\0",
                        ))
                        .as_ptr(),
                        205 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose\0" as *const u8 as *const libc::c_char,
                    );
                }
                send_msg(msg);
                sshbuf_reset(msg);
                if recv_msg(msg) == 14 as libc::c_int {
                    r = sshbuf_get_string(msg, &mut signature, &mut slen);
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(
                                b"ecdsa_do_sign\0",
                            ))
                            .as_ptr(),
                            211 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"parse\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    cp = signature;
                    ret = d2i_ECDSA_SIG(0 as *mut *mut ECDSA_SIG, &mut cp, slen as libc::c_long);
                    libc::free(signature as *mut libc::c_void);
                }
            }
        }
    }
    libc::free(blob as *mut libc::c_void);
    sshkey_free(key);
    sshbuf_free(msg);
    return ret;
}
static mut helper_rsa: *mut RSA_METHOD = 0 as *const RSA_METHOD as *mut RSA_METHOD;
static mut helper_ecdsa: *mut EC_KEY_METHOD = 0 as *const EC_KEY_METHOD as *mut EC_KEY_METHOD;
unsafe extern "C" fn wrap_key(mut k: *mut sshkey) {
    if (*k).type_0 == KEY_RSA as libc::c_int {
        RSA_set_method((*k).rsa, helper_rsa);
    } else if (*k).type_0 == KEY_ECDSA as libc::c_int {
        EC_KEY_set_method((*k).ecdsa, helper_ecdsa);
    } else {
        sshfatal(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"wrap_key\0")).as_ptr(),
            241 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"unknown key type\0" as *const u8 as *const libc::c_char,
        );
    };
}
unsafe extern "C" fn pkcs11_start_helper_methods() -> libc::c_int {
    if !helper_rsa.is_null() {
        return 0 as libc::c_int;
    }
    let mut orig_sign: Option<
        unsafe extern "C" fn(
            libc::c_int,
            *const libc::c_uchar,
            libc::c_int,
            *mut libc::c_uchar,
            *mut libc::c_uint,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> libc::c_int,
    > = None;
    if !helper_ecdsa.is_null() {
        return 0 as libc::c_int;
    }
    helper_ecdsa = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    if helper_ecdsa.is_null() {
        return -(1 as libc::c_int);
    }
    EC_KEY_METHOD_get_sign(
        helper_ecdsa,
        &mut orig_sign,
        0 as *mut Option<
            unsafe extern "C" fn(
                *mut EC_KEY,
                *mut BN_CTX,
                *mut *mut BIGNUM,
                *mut *mut BIGNUM,
            ) -> libc::c_int,
        >,
        0 as *mut Option<
            unsafe extern "C" fn(
                *const libc::c_uchar,
                libc::c_int,
                *const BIGNUM,
                *const BIGNUM,
                *mut EC_KEY,
            ) -> *mut ECDSA_SIG,
        >,
    );
    EC_KEY_METHOD_set_sign(
        helper_ecdsa,
        orig_sign,
        None,
        Some(
            ecdsa_do_sign
                as unsafe extern "C" fn(
                    *const libc::c_uchar,
                    libc::c_int,
                    *const BIGNUM,
                    *const BIGNUM,
                    *mut EC_KEY,
                ) -> *mut ECDSA_SIG,
        ),
    );
    helper_rsa = RSA_meth_dup(RSA_get_default_method());
    if helper_rsa.is_null() {
        sshfatal(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"pkcs11_start_helper_methods\0",
            ))
            .as_ptr(),
            263 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"RSA_meth_dup failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if RSA_meth_set1_name(
        helper_rsa,
        b"ssh-pkcs11-helper\0" as *const u8 as *const libc::c_char,
    ) == 0
        || RSA_meth_set_priv_enc(
            helper_rsa,
            Some(
                rsa_encrypt
                    as unsafe extern "C" fn(
                        libc::c_int,
                        *const u_char,
                        *mut u_char,
                        *mut RSA,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
        ) == 0
    {
        sshfatal(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"pkcs11_start_helper_methods\0",
            ))
            .as_ptr(),
            266 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"failed to prepare method\0" as *const u8 as *const libc::c_char,
        );
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs11_start_helper() -> libc::c_int {
    let mut pair: [libc::c_int; 2] = [0; 2];
    let mut helper: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut verbosity: *mut libc::c_char = 0 as *mut libc::c_char;
    if log_level_get() as libc::c_int >= SYSLOG_LEVEL_DEBUG1 as libc::c_int {
        verbosity = b"-vvv\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if pkcs11_start_helper_methods() == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"pkcs11_start_helper\0"))
                .as_ptr(),
            281 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"pkcs11_start_helper_methods failed\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if libc::socketpair(
        1 as libc::c_int,
        SOCK_STREAM as libc::c_int,
        0 as libc::c_int,
        pair.as_mut_ptr(),
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"pkcs11_start_helper\0"))
                .as_ptr(),
            286 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libc::socketpair: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    pid = fork();
    if pid == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"pkcs11_start_helper\0"))
                .as_ptr(),
            290 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"fork: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    } else if pid == 0 as libc::c_int {
        if libc::dup2(pair[1 as libc::c_int as usize], 0 as libc::c_int) == -(1 as libc::c_int)
            || libc::dup2(pair[1 as libc::c_int as usize], 1 as libc::c_int) == -(1 as libc::c_int)
        {
            libc::fprintf(
                stderr,
                b"libc::dup2: %s\n\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
            libc::_exit(1 as libc::c_int);
        }
        close(pair[0 as libc::c_int as usize]);
        close(pair[1 as libc::c_int as usize]);
        helper = getenv(b"SSH_PKCS11_HELPER\0" as *const u8 as *const libc::c_char);
        if helper.is_null() || strlen(helper) == 0 as libc::c_int as libc::c_ulong {
            helper = b"/usr/local/libexec/ssh-pkcs11-helper\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        }
        crate::log::sshlog(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"pkcs11_start_helper\0"))
                .as_ptr(),
            304 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"starting %s %s\0" as *const u8 as *const libc::c_char,
            helper,
            if verbosity.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                verbosity as *const libc::c_char
            },
        );
        execlp(
            helper,
            helper,
            verbosity,
            0 as *mut libc::c_void as *mut libc::c_char,
        );
        libc::fprintf(
            stderr,
            b"exec: %s: %s\n\0" as *const u8 as *const libc::c_char,
            helper,
            strerror(*libc::__errno_location()),
        );
        libc::_exit(1 as libc::c_int);
    }
    close(pair[1 as libc::c_int as usize]);
    fd = pair[0 as libc::c_int as usize];
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn pkcs11_add_provider(
    mut name: *mut libc::c_char,
    mut pin: *mut libc::c_char,
    mut keysp: *mut *mut *mut sshkey,
    mut labelsp: *mut *mut *mut libc::c_char,
) -> libc::c_int {
    let mut k: *mut sshkey = 0 as *mut sshkey;
    let mut r: libc::c_int = 0;
    let mut type_0: libc::c_int = 0;
    let mut blob: *mut u_char = 0 as *mut u_char;
    let mut label: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut blen: size_t = 0;
    let mut nkeys: u_int = 0;
    let mut i: u_int = 0;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    if fd < 0 as libc::c_int && pkcs11_start_helper() < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"pkcs11_add_provider\0"))
                .as_ptr(),
            330 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u8(msg, 20 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_cstring(msg, name);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, pin);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"pkcs11_add_provider\0"))
                .as_ptr(),
            334 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(msg);
    sshbuf_reset(msg);
    type_0 = recv_msg(msg);
    if type_0 == 12 as libc::c_int {
        r = sshbuf_get_u32(msg, &mut nkeys);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"pkcs11_add_provider\0",
                ))
                .as_ptr(),
                341 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse nkeys\0" as *const u8 as *const libc::c_char,
            );
        }
        *keysp = xcalloc(
            nkeys as size_t,
            ::core::mem::size_of::<*mut sshkey>() as libc::c_ulong,
        ) as *mut *mut sshkey;
        if !labelsp.is_null() {
            *labelsp = xcalloc(
                nkeys as size_t,
                ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
            ) as *mut *mut libc::c_char;
        }
        i = 0 as libc::c_int as u_int;
        while i < nkeys {
            r = sshbuf_get_string(msg, &mut blob, &mut blen);
            if r != 0 as libc::c_int || {
                r = sshbuf_get_cstring(msg, &mut label, 0 as *mut size_t);
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"pkcs11_add_provider\0",
                    ))
                    .as_ptr(),
                    349 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse key\0" as *const u8 as *const libc::c_char,
                );
            }
            r = sshkey_from_blob(blob, blen, &mut k);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"pkcs11_add_provider\0",
                    ))
                    .as_ptr(),
                    351 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"decode key\0" as *const u8 as *const libc::c_char,
                );
            }
            wrap_key(k);
            let ref mut fresh0 = *(*keysp).offset(i as isize);
            *fresh0 = k;
            if !labelsp.is_null() {
                let ref mut fresh1 = *(*labelsp).offset(i as isize);
                *fresh1 = label;
            } else {
                libc::free(label as *mut libc::c_void);
            }
            libc::free(blob as *mut libc::c_void);
            i = i.wrapping_add(1);
            i;
        }
    } else if type_0 == 30 as libc::c_int {
        r = sshbuf_get_u32(msg, &mut nkeys);
        if r != 0 as libc::c_int {
            nkeys = -(1 as libc::c_int) as u_int;
        }
    } else {
        nkeys = -(1 as libc::c_int) as u_int;
    }
    sshbuf_free(msg);
    return nkeys as libc::c_int;
}
pub unsafe extern "C" fn pkcs11_del_provider(mut name: *mut libc::c_char) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"pkcs11_del_provider\0"))
                .as_ptr(),
            377 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u8(msg, 21 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_cstring(msg, name);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, b"\0" as *const u8 as *const libc::c_char);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"ssh-pkcs11-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"pkcs11_del_provider\0"))
                .as_ptr(),
            381 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(msg);
    sshbuf_reset(msg);
    if recv_msg(msg) == 6 as libc::c_int {
        ret = 0 as libc::c_int;
    }
    sshbuf_free(msg);
    return ret;
}
