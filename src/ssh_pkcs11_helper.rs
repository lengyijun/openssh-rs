use crate::log::log_init;
use ::libc;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type sshbuf;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;

    static mut stderr: *mut libc::FILE;

    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: libc::c_int) -> libc::c_int;
    fn seed_rng();

    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn xmalloc(_: size_t) -> *mut libc::c_void;
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn sshbuf_put_stringb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_string(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_string(
        buf: *mut sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_u8(buf: *mut sshbuf, val: u_char) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_put(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_consume(buf: *mut sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_check_reserve(buf: *const sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_ptr(buf: *const sshbuf) -> *const u_char;
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_new() -> *mut sshbuf;
    fn ECDSA_size(eckey: *const EC_KEY) -> libc::c_int;
    fn ECDSA_sign(
        type_0: libc::c_int,
        dgst: *const libc::c_uchar,
        dgstlen: libc::c_int,
        sig: *mut libc::c_uchar,
        siglen: *mut libc::c_uint,
        eckey: *mut EC_KEY,
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
    fn get_u32(_: *const libc::c_void) -> u_int32_t;
    fn RSA_size(rsa: *const RSA) -> libc::c_int;
    fn RSA_private_encrypt(
        flen: libc::c_int,
        from: *const libc::c_uchar,
        to: *mut libc::c_uchar,
        rsa: *mut RSA,
        padding: libc::c_int,
    ) -> libc::c_int;
    fn sshkey_to_blob(_: *const sshkey, _: *mut *mut u_char, _: *mut size_t) -> libc::c_int;
    fn sshkey_from_blob(_: *const u_char, _: size_t, _: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_equal(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn pkcs11_init(_: libc::c_int) -> libc::c_int;
    fn pkcs11_add_provider(
        _: *mut libc::c_char,
        _: *mut libc::c_char,
        _: *mut *mut *mut sshkey,
        _: *mut *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn pkcs11_del_provider(_: *mut libc::c_char) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type uint8_t = __uint8_t;

pub type _IO_lock_t = ();

pub type nfds_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: libc::c_int,
    pub events: libc::c_short,
    pub revents: libc::c_short,
}
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type EC_KEY = ec_key_st;
pub type SyslogFacility = libc::c_int;
pub const SYSLOG_FACILITY_NOT_SET: SyslogFacility = -1;
pub const SYSLOG_FACILITY_LOCAL7: SyslogFacility = 10;
pub const SYSLOG_FACILITY_LOCAL6: SyslogFacility = 9;
pub const SYSLOG_FACILITY_LOCAL5: SyslogFacility = 8;
pub const SYSLOG_FACILITY_LOCAL4: SyslogFacility = 7;
pub const SYSLOG_FACILITY_LOCAL3: SyslogFacility = 6;
pub const SYSLOG_FACILITY_LOCAL2: SyslogFacility = 5;
pub const SYSLOG_FACILITY_LOCAL1: SyslogFacility = 4;
pub const SYSLOG_FACILITY_LOCAL0: SyslogFacility = 3;
pub const SYSLOG_FACILITY_AUTH: SyslogFacility = 2;
pub const SYSLOG_FACILITY_USER: SyslogFacility = 1;
pub const SYSLOG_FACILITY_DAEMON: SyslogFacility = 0;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs11_keyinfo {
    pub key: *mut sshkey,
    pub providername: *mut libc::c_char,
    pub label: *mut libc::c_char,
    pub next: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub tqe_next: *mut pkcs11_keyinfo,
    pub tqe_prev: *mut *mut pkcs11_keyinfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub tqh_first: *mut pkcs11_keyinfo,
    pub tqh_last: *mut *mut pkcs11_keyinfo,
}
pub static mut pkcs11_keylist: C2RustUnnamed_0 = C2RustUnnamed_0 {
    tqh_first: 0 as *const pkcs11_keyinfo as *mut pkcs11_keyinfo,
    tqh_last: 0 as *const *mut pkcs11_keyinfo as *mut *mut pkcs11_keyinfo,
};
pub static mut iqueue: *mut sshbuf = 0 as *const sshbuf as *mut sshbuf;
pub static mut oqueue: *mut sshbuf = 0 as *const sshbuf as *mut sshbuf;
unsafe extern "C" fn add_key(
    mut k: *mut sshkey,
    mut name: *mut libc::c_char,
    mut label: *mut libc::c_char,
) {
    let mut ki: *mut pkcs11_keyinfo = 0 as *mut pkcs11_keyinfo;
    ki = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<pkcs11_keyinfo>() as libc::c_ulong,
    ) as *mut pkcs11_keyinfo;
    (*ki).providername = xstrdup(name);
    (*ki).key = k;
    (*ki).label = xstrdup(label);
    (*ki).next.tqe_next = 0 as *mut pkcs11_keyinfo;
    (*ki).next.tqe_prev = pkcs11_keylist.tqh_last;
    *pkcs11_keylist.tqh_last = ki;
    pkcs11_keylist.tqh_last = &mut (*ki).next.tqe_next;
}
unsafe extern "C" fn del_keys_by_name(mut name: *mut libc::c_char) {
    let mut ki: *mut pkcs11_keyinfo = 0 as *mut pkcs11_keyinfo;
    let mut nxt: *mut pkcs11_keyinfo = 0 as *mut pkcs11_keyinfo;
    ki = pkcs11_keylist.tqh_first;
    while !ki.is_null() {
        nxt = (*ki).next.tqe_next;
        if strcmp((*ki).providername, name) == 0 {
            if !((*ki).next.tqe_next).is_null() {
                (*(*ki).next.tqe_next).next.tqe_prev = (*ki).next.tqe_prev;
            } else {
                pkcs11_keylist.tqh_last = (*ki).next.tqe_prev;
            }
            *(*ki).next.tqe_prev = (*ki).next.tqe_next;
            libc::free((*ki).providername as *mut libc::c_void);
            libc::free((*ki).label as *mut libc::c_void);
            sshkey_free((*ki).key);
            libc::free(ki as *mut libc::c_void);
        }
        ki = nxt;
    }
}
unsafe extern "C" fn lookup_key(mut k: *mut sshkey) -> *mut sshkey {
    let mut ki: *mut pkcs11_keyinfo = 0 as *mut pkcs11_keyinfo;
    ki = pkcs11_keylist.tqh_first;
    while !ki.is_null() {
        crate::log::sshlog(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"lookup_key\0")).as_ptr(),
            102 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"check %s %s %s\0" as *const u8 as *const libc::c_char,
            sshkey_type((*ki).key),
            (*ki).providername,
            (*ki).label,
        );
        if sshkey_equal(k, (*ki).key) != 0 {
            return (*ki).key;
        }
        ki = (*ki).next.tqe_next;
    }
    return 0 as *mut sshkey;
}
unsafe extern "C" fn send_msg(mut m: *mut sshbuf) {
    let mut r: libc::c_int = 0;
    r = sshbuf_put_stringb(oqueue, m);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"send_msg\0")).as_ptr(),
            115 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"enqueue\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn process_add() {
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut keys: *mut *mut sshkey = 0 as *mut *mut sshkey;
    let mut r: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut nkeys: libc::c_int = 0;
    let mut blob: *mut u_char = 0 as *mut u_char;
    let mut blen: size_t = 0;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut labels: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_add\0")).as_ptr(),
            130 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_get_cstring(iqueue, &mut name, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_cstring(iqueue, &mut pin, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_add\0")).as_ptr(),
            133 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    nkeys = pkcs11_add_provider(name, pin, &mut keys, &mut labels);
    if nkeys > 0 as libc::c_int {
        r = sshbuf_put_u8(msg, 12 as libc::c_int as u_char);
        if r != 0 as libc::c_int || {
            r = sshbuf_put_u32(msg, nkeys as u_int32_t);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_add\0"))
                    .as_ptr(),
                138 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose\0" as *const u8 as *const libc::c_char,
            );
        }
        i = 0 as libc::c_int;
        while i < nkeys {
            r = sshkey_to_blob(*keys.offset(i as isize), &mut blob, &mut blen);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_add\0"))
                        .as_ptr(),
                    141 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    ssh_err(r),
                    b"encode key\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = sshbuf_put_string(msg, blob as *const libc::c_void, blen);
                if r != 0 as libc::c_int || {
                    r = sshbuf_put_cstring(msg, *labels.offset(i as isize));
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                            b"process_add\0",
                        ))
                        .as_ptr(),
                        146 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose key\0" as *const u8 as *const libc::c_char,
                    );
                }
                libc::free(blob as *mut libc::c_void);
                add_key(*keys.offset(i as isize), name, *labels.offset(i as isize));
                libc::free(*labels.offset(i as isize) as *mut libc::c_void);
            }
            i += 1;
            i;
        }
    } else {
        r = sshbuf_put_u8(msg, 5 as libc::c_int as u_char);
        if r != 0 as libc::c_int || {
            r = sshbuf_put_u32(msg, -nkeys as u_int32_t);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_add\0"))
                    .as_ptr(),
                153 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    libc::free(labels as *mut libc::c_void);
    libc::free(keys as *mut libc::c_void);
    libc::free(pin as *mut libc::c_void);
    libc::free(name as *mut libc::c_void);
    send_msg(msg);
    sshbuf_free(msg);
}
unsafe extern "C" fn process_del() {
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_del\0")).as_ptr(),
            170 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_get_cstring(iqueue, &mut name, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_cstring(iqueue, &mut pin, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_del\0")).as_ptr(),
            173 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    del_keys_by_name(name);
    r = sshbuf_put_u8(
        msg,
        (if pkcs11_del_provider(name) == 0 as libc::c_int {
            6 as libc::c_int
        } else {
            5 as libc::c_int
        }) as u_char,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_del\0")).as_ptr(),
            177 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    libc::free(pin as *mut libc::c_void);
    libc::free(name as *mut libc::c_void);
    send_msg(msg);
    sshbuf_free(msg);
}
unsafe extern "C" fn process_sign() {
    let mut blob: *mut u_char = 0 as *mut u_char;
    let mut data: *mut u_char = 0 as *mut u_char;
    let mut signature: *mut u_char = 0 as *mut u_char;
    let mut blen: size_t = 0;
    let mut dlen: size_t = 0;
    let mut slen: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    let mut ok: libc::c_int = -(1 as libc::c_int);
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut found: *mut sshkey = 0 as *mut sshkey;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    r = sshbuf_get_string(iqueue, &mut blob, &mut blen);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_string(iqueue, &mut data, &mut dlen);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(iqueue, 0 as *mut u_int32_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0")).as_ptr(),
            197 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshkey_from_blob(blob, blen, &mut key);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0")).as_ptr(),
            200 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"decode key\0" as *const u8 as *const libc::c_char,
        );
    } else {
        found = lookup_key(key);
        if !found.is_null() {
            let mut ret: libc::c_int = 0;
            if (*key).type_0 == KEY_RSA as libc::c_int {
                slen = RSA_size((*key).rsa) as size_t;
                signature = xmalloc(slen) as *mut u_char;
                ret = RSA_private_encrypt(
                    dlen as libc::c_int,
                    data,
                    signature,
                    (*found).rsa,
                    1 as libc::c_int,
                );
                if ret != -(1 as libc::c_int) {
                    slen = ret as size_t;
                    ok = 0 as libc::c_int;
                }
            } else if (*key).type_0 == KEY_ECDSA as libc::c_int {
                let mut xslen: u_int = ECDSA_size((*key).ecdsa) as u_int;
                signature = xmalloc(xslen as size_t) as *mut u_char;
                ret = ECDSA_sign(
                    -(1 as libc::c_int),
                    data,
                    dlen as libc::c_int,
                    signature,
                    &mut xslen,
                    (*found).ecdsa,
                );
                if ret != 0 as libc::c_int {
                    ok = 0 as libc::c_int;
                } else {
                    crate::log::sshlog(
                        b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"process_sign\0",
                        ))
                        .as_ptr(),
                        226 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"ECDSA_sign returned %d\0" as *const u8 as *const libc::c_char,
                        ret,
                    );
                }
                slen = xslen as size_t;
            } else {
                crate::log::sshlog(
                    b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0"))
                        .as_ptr(),
                    231 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"don't know how to sign with key type %d\0" as *const u8
                        as *const libc::c_char,
                    (*key).type_0,
                );
            }
        }
        sshkey_free(key);
    }
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0")).as_ptr(),
            237 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if ok == 0 as libc::c_int {
        r = sshbuf_put_u8(msg, 14 as libc::c_int as u_char);
        if r != 0 as libc::c_int || {
            r = sshbuf_put_string(msg, signature as *const libc::c_void, slen);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0"))
                    .as_ptr(),
                241 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose response\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        r = sshbuf_put_u8(msg, 30 as libc::c_int as u_char);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0"))
                    .as_ptr(),
                244 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose failure response\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    libc::free(data as *mut libc::c_void);
    libc::free(blob as *mut libc::c_void);
    libc::free(signature as *mut libc::c_void);
    send_msg(msg);
    sshbuf_free(msg);
}
unsafe extern "C" fn process() {
    let mut msg_len: u_int = 0;
    let mut buf_len: u_int = 0;
    let mut consumed: u_int = 0;
    let mut type_0: u_char = 0;
    let mut cp: *const u_char = 0 as *const u_char;
    let mut r: libc::c_int = 0;
    buf_len = sshbuf_len(iqueue) as u_int;
    if buf_len < 5 as libc::c_int as libc::c_uint {
        return;
    }
    cp = sshbuf_ptr(iqueue);
    msg_len = get_u32(cp as *const libc::c_void);
    if msg_len > 10240 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
            269 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"bad message len %d\0" as *const u8 as *const libc::c_char,
            msg_len,
        );
        cleanup_exit(11 as libc::c_int);
    }
    if buf_len < msg_len.wrapping_add(4 as libc::c_int as libc::c_uint) {
        return;
    }
    r = sshbuf_consume(iqueue, 4 as libc::c_int as size_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u8(iqueue, &mut type_0);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
            276 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse type/len\0" as *const u8 as *const libc::c_char,
        );
    }
    buf_len =
        (buf_len as libc::c_uint).wrapping_sub(4 as libc::c_int as libc::c_uint) as u_int as u_int;
    match type_0 as libc::c_int {
        20 => {
            crate::log::sshlog(
                b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
                280 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"process_add\0" as *const u8 as *const libc::c_char,
            );
            process_add();
        }
        21 => {
            crate::log::sshlog(
                b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
                284 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"process_del\0" as *const u8 as *const libc::c_char,
            );
            process_del();
        }
        13 => {
            crate::log::sshlog(
                b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
                288 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"process_sign\0" as *const u8 as *const libc::c_char,
            );
            process_sign();
        }
        _ => {
            crate::log::sshlog(
                b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
                292 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Unknown message %d\0" as *const u8 as *const libc::c_char,
                type_0 as libc::c_int,
            );
        }
    }
    if (buf_len as libc::c_ulong) < sshbuf_len(iqueue) {
        crate::log::sshlog(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
            297 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"iqueue grew unexpectedly\0" as *const u8 as *const libc::c_char,
        );
        cleanup_exit(255 as libc::c_int);
    }
    consumed = (buf_len as libc::c_ulong).wrapping_sub(sshbuf_len(iqueue)) as u_int;
    if msg_len < consumed {
        crate::log::sshlog(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
            302 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"msg_len %d < consumed %d\0" as *const u8 as *const libc::c_char,
            msg_len,
            consumed,
        );
        cleanup_exit(255 as libc::c_int);
    }
    if msg_len > consumed {
        r = sshbuf_consume(iqueue, msg_len.wrapping_sub(consumed) as size_t);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
                307 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"consume\0" as *const u8 as *const libc::c_char,
            );
        }
    }
}
pub unsafe extern "C" fn cleanup_exit(mut i: libc::c_int) -> ! {
    libc::_exit(i);
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut ch: libc::c_int = 0;
    let mut in_0: libc::c_int = 0;
    let mut out: libc::c_int = 0;
    let mut log_stderr: libc::c_int = 0 as libc::c_int;
    let mut len: ssize_t = 0;
    let mut log_facility: SyslogFacility = SYSLOG_FACILITY_AUTH;
    let mut log_level: LogLevel = SYSLOG_LEVEL_ERROR;
    let mut buf: [libc::c_char; 16384] = [0; 16384];
    extern "C" {
        static mut __progname: *mut libc::c_char;
    }
    let mut pfd: [pollfd; 2] = [pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    }; 2];
    __progname =
        crate::openbsd_compat::bsd_misc::ssh_get_progname(*argv.offset(0 as libc::c_int as isize));
    seed_rng();
    pkcs11_keylist.tqh_first = 0 as *mut pkcs11_keyinfo;
    pkcs11_keylist.tqh_last = &mut pkcs11_keylist.tqh_first;
    log_init(__progname, log_level, log_facility, log_stderr);
    loop {
        ch = crate::openbsd_compat::getopt_long::BSDgetopt(
            argc,
            argv,
            b"v\0" as *const u8 as *const libc::c_char,
        );
        if !(ch != -(1 as libc::c_int)) {
            break;
        }
        match ch {
            118 => {
                log_stderr = 1 as libc::c_int;
                if log_level as libc::c_int == SYSLOG_LEVEL_ERROR as libc::c_int {
                    log_level = SYSLOG_LEVEL_DEBUG1;
                } else if (log_level as libc::c_int) < SYSLOG_LEVEL_DEBUG3 as libc::c_int {
                    log_level += 1;
                    log_level;
                }
            }
            _ => {
                libc::fprintf(
                    stderr,
                    b"usage: %s [-v]\n\0" as *const u8 as *const libc::c_char,
                    __progname,
                );
                libc::exit(1 as libc::c_int);
            }
        }
    }
    log_init(__progname, log_level, log_facility, log_stderr);
    pkcs11_init(0 as libc::c_int);
    in_0 = 0 as libc::c_int;
    out = 1 as libc::c_int;
    iqueue = sshbuf_new();
    if iqueue.is_null() {
        sshfatal(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            358 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    oqueue = sshbuf_new();
    if oqueue.is_null() {
        sshfatal(
            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            360 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    loop {
        memset(
            pfd.as_mut_ptr() as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<[pollfd; 2]>() as libc::c_ulong,
        );
        pfd[0 as libc::c_int as usize].fd = in_0;
        pfd[1 as libc::c_int as usize].fd = out;
        r = sshbuf_check_reserve(
            iqueue,
            ::core::mem::size_of::<[libc::c_char; 16384]>() as libc::c_ulong,
        );
        if r == 0 as libc::c_int && {
            r = sshbuf_check_reserve(oqueue, 10240 as libc::c_int as size_t);
            r == 0 as libc::c_int
        } {
            pfd[0 as libc::c_int as usize].events = 0x1 as libc::c_int as libc::c_short;
        } else if r != -(9 as libc::c_int) {
            sshfatal(
                b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                376 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"reserve\0" as *const u8 as *const libc::c_char,
            );
        }
        if sshbuf_len(oqueue) > 0 as libc::c_int as libc::c_ulong {
            pfd[1 as libc::c_int as usize].events = 0x4 as libc::c_int as libc::c_short;
        }
        r = poll(
            pfd.as_mut_ptr(),
            2 as libc::c_int as nfds_t,
            -(1 as libc::c_int),
        );
        if r <= 0 as libc::c_int {
            if r == 0 as libc::c_int || *libc::__errno_location() == 4 as libc::c_int {
                continue;
            }
            sshfatal(
                b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                384 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"poll: %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        } else {
            if pfd[0 as libc::c_int as usize].revents as libc::c_int
                & (0x1 as libc::c_int | 0x10 as libc::c_int | 0x8 as libc::c_int)
                != 0 as libc::c_int
            {
                len = read(
                    in_0,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    ::core::mem::size_of::<[libc::c_char; 16384]>() as libc::c_ulong,
                );
                if len == 0 as libc::c_int as libc::c_long {
                    crate::log::sshlog(
                        b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        391 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"read eof\0" as *const u8 as *const libc::c_char,
                    );
                    cleanup_exit(0 as libc::c_int);
                } else if len < 0 as libc::c_int as libc::c_long {
                    crate::log::sshlog(
                        b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        394 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"read: %s\0" as *const u8 as *const libc::c_char,
                        strerror(*libc::__errno_location()),
                    );
                    cleanup_exit(1 as libc::c_int);
                } else {
                    r = sshbuf_put(
                        iqueue,
                        buf.as_mut_ptr() as *const libc::c_void,
                        len as size_t,
                    );
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            397 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"sshbuf_put\0" as *const u8 as *const libc::c_char,
                        );
                    }
                }
            }
            if pfd[1 as libc::c_int as usize].revents as libc::c_int
                & (0x4 as libc::c_int | 0x10 as libc::c_int)
                != 0 as libc::c_int
            {
                len = write(
                    out,
                    sshbuf_ptr(oqueue) as *const libc::c_void,
                    sshbuf_len(oqueue),
                );
                if len < 0 as libc::c_int as libc::c_long {
                    crate::log::sshlog(
                        b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        404 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"write: %s\0" as *const u8 as *const libc::c_char,
                        strerror(*libc::__errno_location()),
                    );
                    cleanup_exit(1 as libc::c_int);
                } else {
                    r = sshbuf_consume(oqueue, len as size_t);
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            407 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"consume\0" as *const u8 as *const libc::c_char,
                        );
                    }
                }
            }
            r = sshbuf_check_reserve(oqueue, 10240 as libc::c_int as size_t);
            if r == 0 as libc::c_int {
                process();
            } else if r != -(9 as libc::c_int) {
                sshfatal(
                    b"ssh-pkcs11-helper.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    418 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"reserve\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
}
pub fn main() {
    let mut args: Vec<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::core::ptr::null_mut());
    unsafe {
        ::std::process::exit(main_0(
            (args.len() - 1) as libc::c_int,
            args.as_mut_ptr() as *mut *mut libc::c_char,
        ) as i32)
    }
}
