use ::libc;
extern "C" {

    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    fn freezero(_: *mut libc::c_void, _: size_t);

    fn crypto_sign_ed25519(
        _: *mut libc::c_uchar,
        _: *mut libc::c_ulonglong,
        _: *const libc::c_uchar,
        _: libc::c_ulonglong,
        _: *const libc::c_uchar,
    ) -> libc::c_int;
    fn crypto_sign_ed25519_open(
        _: *mut libc::c_uchar,
        _: *mut libc::c_ulonglong,
        _: *const libc::c_uchar,
        _: libc::c_ulonglong,
        _: *const libc::c_uchar,
    ) -> libc::c_int;
    fn crypto_sign_ed25519_keypair(_: *mut libc::c_uchar, _: *mut libc::c_uchar) -> libc::c_int;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;

    fn sshbuf_get_string_direct(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;

    fn sshbuf_from(blob: *const libc::c_void, len: size_t) -> *mut crate::sshbuf::sshbuf;

    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int64_t = __uint64_t;
pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;
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
pub type sshkey_serialize_rep = libc::c_uint;
pub const SSHKEY_SERIALIZE_INFO: sshkey_serialize_rep = 254;
pub const SSHKEY_SERIALIZE_SHIELD: sshkey_serialize_rep = 3;
pub const SSHKEY_SERIALIZE_FULL: sshkey_serialize_rep = 2;
pub const SSHKEY_SERIALIZE_STATE: sshkey_serialize_rep = 1;
pub const SSHKEY_SERIALIZE_DEFAULT: sshkey_serialize_rep = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_cert {
    pub certblob: *mut crate::sshbuf::sshbuf,
    pub type_0: u_int,
    pub serial: u_int64_t,
    pub key_id: *mut libc::c_char,
    pub nprincipals: u_int,
    pub principals: *mut *mut libc::c_char,
    pub valid_after: u_int64_t,
    pub valid_before: u_int64_t,
    pub critical: *mut crate::sshbuf::sshbuf,
    pub extensions: *mut crate::sshbuf::sshbuf,
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
    pub sk_key_handle: *mut crate::sshbuf::sshbuf,
    pub sk_reserved: *mut crate::sshbuf::sshbuf,
    pub cert: *mut sshkey_cert,
    pub shielded_private: *mut u_char,
    pub shielded_len: size_t,
    pub shield_prekey: *mut u_char,
    pub shield_prekey_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_sig_details {
    pub sk_counter: uint32_t,
    pub sk_flags: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_impl_funcs {
    pub size: Option<unsafe extern "C" fn(*const sshkey) -> u_int>,
    pub alloc: Option<unsafe extern "C" fn(*mut sshkey) -> libc::c_int>,
    pub cleanup: Option<unsafe extern "C" fn(*mut sshkey) -> ()>,
    pub equal: Option<unsafe extern "C" fn(*const sshkey, *const sshkey) -> libc::c_int>,
    pub serialize_public: Option<
        unsafe extern "C" fn(
            *const sshkey,
            *mut crate::sshbuf::sshbuf,
            sshkey_serialize_rep,
        ) -> libc::c_int,
    >,
    pub deserialize_public: Option<
        unsafe extern "C" fn(
            *const libc::c_char,
            *mut crate::sshbuf::sshbuf,
            *mut sshkey,
        ) -> libc::c_int,
    >,
    pub serialize_private: Option<
        unsafe extern "C" fn(
            *const sshkey,
            *mut crate::sshbuf::sshbuf,
            sshkey_serialize_rep,
        ) -> libc::c_int,
    >,
    pub deserialize_private: Option<
        unsafe extern "C" fn(
            *const libc::c_char,
            *mut crate::sshbuf::sshbuf,
            *mut sshkey,
        ) -> libc::c_int,
    >,
    pub generate: Option<unsafe extern "C" fn(*mut sshkey, libc::c_int) -> libc::c_int>,
    pub copy_public: Option<unsafe extern "C" fn(*const sshkey, *mut sshkey) -> libc::c_int>,
    pub sign: Option<
        unsafe extern "C" fn(
            *mut sshkey,
            *mut *mut u_char,
            *mut size_t,
            *const u_char,
            size_t,
            *const libc::c_char,
            *const libc::c_char,
            *const libc::c_char,
            u_int,
        ) -> libc::c_int,
    >,
    pub verify: Option<
        unsafe extern "C" fn(
            *const sshkey,
            *const u_char,
            size_t,
            *const u_char,
            size_t,
            *const libc::c_char,
            u_int,
            *mut *mut sshkey_sig_details,
        ) -> libc::c_int,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_impl {
    pub name: *const libc::c_char,
    pub shortname: *const libc::c_char,
    pub sigalg: *const libc::c_char,
    pub type_0: libc::c_int,
    pub nid: libc::c_int,
    pub cert: libc::c_int,
    pub sigonly: libc::c_int,
    pub keybits: libc::c_int,
    pub funcs: *const sshkey_impl_funcs,
}
unsafe extern "C" fn ssh_ed25519_cleanup(mut k: *mut sshkey) {
    freezero(
        (*k).ed25519_pk as *mut libc::c_void,
        32 as libc::c_uint as size_t,
    );
    freezero(
        (*k).ed25519_sk as *mut libc::c_void,
        64 as libc::c_uint as size_t,
    );
    (*k).ed25519_pk = 0 as *mut u_char;
    (*k).ed25519_sk = 0 as *mut u_char;
}
unsafe extern "C" fn ssh_ed25519_equal(mut a: *const sshkey, mut b: *const sshkey) -> libc::c_int {
    if ((*a).ed25519_pk).is_null() || ((*b).ed25519_pk).is_null() {
        return 0 as libc::c_int;
    }
    if memcmp(
        (*a).ed25519_pk as *const libc::c_void,
        (*b).ed25519_pk as *const libc::c_void,
        32 as libc::c_uint as libc::c_ulong,
    ) != 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ssh_ed25519_serialize_public(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut _opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    if ((*key).ed25519_pk).is_null() {
        return -(10 as libc::c_int);
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_string(
        b,
        (*key).ed25519_pk as *const libc::c_void,
        32 as libc::c_uint as size_t,
    );
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ed25519_serialize_private(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut _opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = crate::sshbuf_getput_basic::sshbuf_put_string(
        b,
        (*key).ed25519_pk as *const libc::c_void,
        32 as libc::c_uint as size_t,
    );
    if r != 0 as libc::c_int || {
        r = crate::sshbuf_getput_basic::sshbuf_put_string(
            b,
            (*key).ed25519_sk as *const libc::c_void,
            64 as libc::c_uint as size_t,
        );
        r != 0 as libc::c_int
    } {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ed25519_generate(
    mut k: *mut sshkey,
    mut _bits: libc::c_int,
) -> libc::c_int {
    (*k).ed25519_pk = libc::malloc(32 as usize) as *mut u_char;
    if ((*k).ed25519_pk).is_null() || {
        (*k).ed25519_sk = libc::malloc(64 as usize) as *mut u_char;
        ((*k).ed25519_sk).is_null()
    } {
        return -(2 as libc::c_int);
    }
    crypto_sign_ed25519_keypair((*k).ed25519_pk, (*k).ed25519_sk);
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ed25519_copy_public(
    mut from: *const sshkey,
    mut to: *mut sshkey,
) -> libc::c_int {
    if ((*from).ed25519_pk).is_null() {
        return 0 as libc::c_int;
    }
    (*to).ed25519_pk = libc::malloc(32 as usize) as *mut u_char;
    if ((*to).ed25519_pk).is_null() {
        return -(2 as libc::c_int);
    }
    memcpy(
        (*to).ed25519_pk as *mut libc::c_void,
        (*from).ed25519_pk as *const libc::c_void,
        32 as libc::c_uint as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ed25519_deserialize_public(
    mut _ktype: *const libc::c_char,
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut sshkey,
) -> libc::c_int {
    let mut pk: *mut u_char = 0 as *mut u_char;
    let mut len: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    r = crate::sshbuf_getput_basic::sshbuf_get_string(b, &mut pk, &mut len);
    if r != 0 as libc::c_int {
        return r;
    }
    if len != 32 as libc::c_uint as libc::c_ulong {
        freezero(pk as *mut libc::c_void, len);
        return -(4 as libc::c_int);
    }
    (*key).ed25519_pk = pk;
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ed25519_deserialize_private(
    mut _ktype: *const libc::c_char,
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut sklen: size_t = 0 as libc::c_int as size_t;
    let mut ed25519_sk: *mut u_char = 0 as *mut u_char;
    r = ssh_ed25519_deserialize_public(0 as *const libc::c_char, b, key);
    if !(r != 0 as libc::c_int) {
        r = crate::sshbuf_getput_basic::sshbuf_get_string(b, &mut ed25519_sk, &mut sklen);
        if !(r != 0 as libc::c_int) {
            if sklen != 64 as libc::c_uint as libc::c_ulong {
                r = -(4 as libc::c_int);
            } else {
                (*key).ed25519_sk = ed25519_sk;
                ed25519_sk = 0 as *mut u_char;
                r = 0 as libc::c_int;
            }
        }
    }
    freezero(ed25519_sk as *mut libc::c_void, sklen);
    return r;
}
unsafe extern "C" fn ssh_ed25519_sign(
    mut key: *mut sshkey,
    mut sigp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut data: *const u_char,
    mut datalen: size_t,
    mut _alg: *const libc::c_char,
    mut _sk_provider: *const libc::c_char,
    mut _sk_pin: *const libc::c_char,
    mut _compat: u_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut slen: size_t = 0 as libc::c_int as size_t;
    let mut len: size_t = 0;
    let mut smlen: libc::c_ulonglong = 0;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    if !lenp.is_null() {
        *lenp = 0 as libc::c_int as size_t;
    }
    if !sigp.is_null() {
        *sigp = 0 as *mut u_char;
    }
    if key.is_null()
        || sshkey_type_plain((*key).type_0) != KEY_ED25519 as libc::c_int
        || ((*key).ed25519_sk).is_null()
        || datalen
            >= (2147483647 as libc::c_int as libc::c_uint).wrapping_sub(64 as libc::c_uint)
                as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    slen = datalen.wrapping_add(64 as libc::c_uint as libc::c_ulong);
    smlen = slen as libc::c_ulonglong;
    sig = libc::malloc(slen as usize) as *mut u_char;
    if sig.is_null() {
        return -(2 as libc::c_int);
    }
    ret = crypto_sign_ed25519(
        sig,
        &mut smlen,
        data,
        datalen as libc::c_ulonglong,
        (*key).ed25519_sk,
    );
    if ret != 0 as libc::c_int || smlen <= datalen as libc::c_ulonglong {
        r = -(10 as libc::c_int);
    } else {
        b = crate::sshbuf::sshbuf_new();
        if b.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
                b,
                b"ssh-ed25519\0" as *const u8 as *const libc::c_char,
            );
            if !(r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_string(
                    b,
                    sig as *const libc::c_void,
                    smlen.wrapping_sub(datalen as libc::c_ulonglong) as size_t,
                );
                r != 0 as libc::c_int
            }) {
                len = crate::sshbuf::sshbuf_len(b);
                if !sigp.is_null() {
                    *sigp = libc::malloc(len as usize) as *mut u_char;
                    if (*sigp).is_null() {
                        r = -(2 as libc::c_int);
                        current_block = 7497926444865556885;
                    } else {
                        memcpy(
                            *sigp as *mut libc::c_void,
                            crate::sshbuf::sshbuf_ptr(b) as *const libc::c_void,
                            len,
                        );
                        current_block = 6009453772311597924;
                    }
                } else {
                    current_block = 6009453772311597924;
                }
                match current_block {
                    7497926444865556885 => {}
                    _ => {
                        if !lenp.is_null() {
                            *lenp = len;
                        }
                        r = 0 as libc::c_int;
                    }
                }
            }
        }
    }
    crate::sshbuf::sshbuf_free(b);
    if !sig.is_null() {
        freezero(sig as *mut libc::c_void, slen);
    }
    return r;
}
unsafe extern "C" fn ssh_ed25519_verify(
    mut key: *const sshkey,
    mut sig: *const u_char,
    mut siglen: size_t,
    mut data: *const u_char,
    mut dlen: size_t,
    mut _alg: *const libc::c_char,
    mut _compat: u_int,
    mut _detailsp: *mut *mut sshkey_sig_details,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut ktype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sigblob: *const u_char = 0 as *const u_char;
    let mut sm: *mut u_char = 0 as *mut u_char;
    let mut m: *mut u_char = 0 as *mut u_char;
    let mut len: size_t = 0;
    let mut smlen: libc::c_ulonglong = 0 as libc::c_int as libc::c_ulonglong;
    let mut mlen: libc::c_ulonglong = 0 as libc::c_int as libc::c_ulonglong;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    if key.is_null()
        || sshkey_type_plain((*key).type_0) != KEY_ED25519 as libc::c_int
        || ((*key).ed25519_pk).is_null()
        || dlen
            >= (2147483647 as libc::c_int as libc::c_uint).wrapping_sub(64 as libc::c_uint)
                as libc::c_ulong
        || sig.is_null()
        || siglen == 0 as libc::c_int as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    b = sshbuf_from(sig as *const libc::c_void, siglen);
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut ktype, 0 as *mut size_t);
    if !(r != 0 as libc::c_int || {
        r = sshbuf_get_string_direct(b, &mut sigblob, &mut len);
        r != 0 as libc::c_int
    }) {
        if libc::strcmp(b"ssh-ed25519\0" as *const u8 as *const libc::c_char, ktype)
            != 0 as libc::c_int
        {
            r = -(13 as libc::c_int);
        } else if crate::sshbuf::sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong {
            r = -(23 as libc::c_int);
        } else if len > 64 as libc::c_uint as libc::c_ulong {
            r = -(4 as libc::c_int);
        } else if dlen >= (18446744073709551615 as libc::c_ulong).wrapping_sub(len) {
            r = -(10 as libc::c_int);
        } else {
            smlen = len.wrapping_add(dlen) as libc::c_ulonglong;
            mlen = smlen;
            sm = libc::malloc(smlen as usize) as *mut u_char;
            if sm.is_null() || {
                m = libc::malloc(mlen as usize) as *mut u_char;
                m.is_null()
            } {
                r = -(2 as libc::c_int);
            } else {
                memcpy(sm as *mut libc::c_void, sigblob as *const libc::c_void, len);
                memcpy(
                    sm.offset(len as isize) as *mut libc::c_void,
                    data as *const libc::c_void,
                    dlen,
                );
                ret = crypto_sign_ed25519_open(m, &mut mlen, sm, smlen, (*key).ed25519_pk);
                if ret != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"ssh-ed25519.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_ed25519_verify\0",
                        ))
                        .as_ptr(),
                        256 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"crypto_sign_ed25519_open failed: %d\0" as *const u8
                            as *const libc::c_char,
                        ret,
                    );
                }
                if ret != 0 as libc::c_int || mlen != dlen as libc::c_ulonglong {
                    r = -(21 as libc::c_int);
                } else {
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    if !sm.is_null() {
        freezero(sm as *mut libc::c_void, smlen as size_t);
    }
    if !m.is_null() {
        freezero(m as *mut libc::c_void, smlen as size_t);
    }
    crate::sshbuf::sshbuf_free(b);
    libc::free(ktype as *mut libc::c_void);
    return r;
}
pub static mut sshkey_ed25519_funcs: sshkey_impl_funcs = unsafe {
    {
        let mut init = sshkey_impl_funcs {
            size: None,
            alloc: None,
            cleanup: Some(ssh_ed25519_cleanup as unsafe extern "C" fn(*mut sshkey) -> ()),
            equal: Some(
                ssh_ed25519_equal
                    as unsafe extern "C" fn(*const sshkey, *const sshkey) -> libc::c_int,
            ),
            serialize_public: Some(
                ssh_ed25519_serialize_public
                    as unsafe extern "C" fn(
                        *const sshkey,
                        *mut crate::sshbuf::sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_public: Some(
                ssh_ed25519_deserialize_public
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut crate::sshbuf::sshbuf,
                        *mut sshkey,
                    ) -> libc::c_int,
            ),
            serialize_private: Some(
                ssh_ed25519_serialize_private
                    as unsafe extern "C" fn(
                        *const sshkey,
                        *mut crate::sshbuf::sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_private: Some(
                ssh_ed25519_deserialize_private
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut crate::sshbuf::sshbuf,
                        *mut sshkey,
                    ) -> libc::c_int,
            ),
            generate: Some(
                ssh_ed25519_generate
                    as unsafe extern "C" fn(*mut sshkey, libc::c_int) -> libc::c_int,
            ),
            copy_public: Some(
                ssh_ed25519_copy_public
                    as unsafe extern "C" fn(*const sshkey, *mut sshkey) -> libc::c_int,
            ),
            sign: Some(
                ssh_ed25519_sign
                    as unsafe extern "C" fn(
                        *mut sshkey,
                        *mut *mut u_char,
                        *mut size_t,
                        *const u_char,
                        size_t,
                        *const libc::c_char,
                        *const libc::c_char,
                        *const libc::c_char,
                        u_int,
                    ) -> libc::c_int,
            ),
            verify: Some(
                ssh_ed25519_verify
                    as unsafe extern "C" fn(
                        *const sshkey,
                        *const u_char,
                        size_t,
                        *const u_char,
                        size_t,
                        *const libc::c_char,
                        u_int,
                        *mut *mut sshkey_sig_details,
                    ) -> libc::c_int,
            ),
        };
        init
    }
};
pub static mut sshkey_ed25519_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"ssh-ed25519\0" as *const u8 as *const libc::c_char,
            shortname: b"ED25519\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ED25519 as libc::c_int,
            nid: 0 as libc::c_int,
            cert: 0 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 256 as libc::c_int,
            funcs: &sshkey_ed25519_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_ed25519_cert_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"ssh-ed25519-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
            shortname: b"ED25519-CERT\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ED25519_CERT as libc::c_int,
            nid: 0 as libc::c_int,
            cert: 1 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 256 as libc::c_int,
            funcs: &sshkey_ed25519_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
