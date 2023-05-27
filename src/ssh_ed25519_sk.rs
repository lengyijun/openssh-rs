use ::libc;
extern "C" {
    pub type sshbuf;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    fn freezero(_: *mut libc::c_void, _: size_t);

    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn crypto_sign_ed25519_open(
        _: *mut libc::c_uchar,
        _: *mut libc::c_ulonglong,
        _: *const libc::c_uchar,
        _: libc::c_ulonglong,
        _: *const libc::c_uchar,
    ) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn sshbuf_get_string_direct(
        buf: *mut sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_u8(buf: *mut sshbuf, val: u_char) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_put(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_ptr(buf: *const sshbuf) -> *const u_char;
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_from(blob: *const libc::c_void, len: size_t) -> *mut sshbuf;
    fn sshbuf_new() -> *mut sshbuf;
    fn sshkey_private_deserialize_sk(buf: *mut sshbuf, k: *mut sshkey) -> libc::c_int;
    fn sshkey_serialize_private_sk(key: *const sshkey, buf: *mut sshbuf) -> libc::c_int;
    fn sshkey_deserialize_sk(b: *mut sshbuf, key: *mut sshkey) -> libc::c_int;
    fn sshkey_copy_public_sk(from: *const sshkey, to: *mut sshkey) -> libc::c_int;
    fn sshkey_serialize_sk(key: *const sshkey, b: *mut sshbuf) -> libc::c_int;
    fn sshkey_sk_cleanup(k: *mut sshkey);
    fn sshkey_sk_fields_equal(a: *const sshkey, b: *const sshkey) -> libc::c_int;
    fn sshkey_sig_details_free(_: *mut sshkey_sig_details);
    fn sshkey_ssh_name_plain(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn ssh_digest_memory(
        alg: libc::c_int,
        m: *const libc::c_void,
        mlen: size_t,
        d: *mut u_char,
        dlen: size_t,
    ) -> libc::c_int;
    static mut sshkey_ed25519_funcs: sshkey_impl_funcs;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
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
        unsafe extern "C" fn(*const sshkey, *mut sshbuf, sshkey_serialize_rep) -> libc::c_int,
    >,
    pub deserialize_public:
        Option<unsafe extern "C" fn(*const libc::c_char, *mut sshbuf, *mut sshkey) -> libc::c_int>,
    pub serialize_private: Option<
        unsafe extern "C" fn(*const sshkey, *mut sshbuf, sshkey_serialize_rep) -> libc::c_int,
    >,
    pub deserialize_private:
        Option<unsafe extern "C" fn(*const libc::c_char, *mut sshbuf, *mut sshkey) -> libc::c_int>,
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
unsafe extern "C" fn ssh_ed25519_sk_cleanup(mut k: *mut sshkey) {
    sshkey_sk_cleanup(k);
    (sshkey_ed25519_funcs.cleanup).expect("non-null function pointer")(k);
}
unsafe extern "C" fn ssh_ed25519_sk_equal(
    mut a: *const sshkey,
    mut b: *const sshkey,
) -> libc::c_int {
    if sshkey_sk_fields_equal(a, b) == 0 {
        return 0 as libc::c_int;
    }
    if (sshkey_ed25519_funcs.equal).expect("non-null function pointer")(a, b) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ssh_ed25519_sk_serialize_public(
    mut key: *const sshkey,
    mut b: *mut sshbuf,
    mut opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = (sshkey_ed25519_funcs.serialize_public).expect("non-null function pointer")(key, b, opts);
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshkey_serialize_sk(key, b);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ed25519_sk_serialize_private(
    mut key: *const sshkey,
    mut b: *mut sshbuf,
    mut opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = (sshkey_ed25519_funcs.serialize_public).expect("non-null function pointer")(key, b, opts);
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshkey_serialize_private_sk(key, b);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ed25519_sk_copy_public(
    mut from: *const sshkey,
    mut to: *mut sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = (sshkey_ed25519_funcs.copy_public).expect("non-null function pointer")(from, to);
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshkey_copy_public_sk(from, to);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ed25519_sk_deserialize_public(
    mut ktype: *const libc::c_char,
    mut b: *mut sshbuf,
    mut key: *mut sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = (sshkey_ed25519_funcs.deserialize_public).expect("non-null function pointer")(
        ktype, b, key,
    );
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshkey_deserialize_sk(b, key);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ed25519_sk_deserialize_private(
    mut ktype: *const libc::c_char,
    mut b: *mut sshbuf,
    mut key: *mut sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = (sshkey_ed25519_funcs.deserialize_public).expect("non-null function pointer")(
        ktype, b, key,
    );
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshkey_private_deserialize_sk(b, key);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ed25519_sk_verify(
    mut key: *const sshkey,
    mut sig: *const u_char,
    mut siglen: size_t,
    mut data: *const u_char,
    mut dlen: size_t,
    mut _alg: *const libc::c_char,
    mut _compat: u_int,
    mut detailsp: *mut *mut sshkey_sig_details,
) -> libc::c_int {
    let mut b: *mut sshbuf = 0 as *mut sshbuf;
    let mut encoded: *mut sshbuf = 0 as *mut sshbuf;
    let mut ktype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sigblob: *const u_char = 0 as *const u_char;
    let mut sm: *const u_char = 0 as *const u_char;
    let mut m: *mut u_char = 0 as *mut u_char;
    let mut apphash: [u_char; 32] = [0; 32];
    let mut msghash: [u_char; 32] = [0; 32];
    let mut sig_flags: u_char = 0;
    let mut sig_counter: u_int = 0;
    let mut len: size_t = 0;
    let mut smlen: libc::c_ulonglong = 0 as libc::c_int as libc::c_ulonglong;
    let mut mlen: libc::c_ulonglong = 0 as libc::c_int as libc::c_ulonglong;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut ret: libc::c_int = 0;
    let mut details: *mut sshkey_sig_details = 0 as *mut sshkey_sig_details;
    if !detailsp.is_null() {
        *detailsp = 0 as *mut sshkey_sig_details;
    }
    if key.is_null()
        || sshkey_type_plain((*key).type_0) != KEY_ED25519_SK as libc::c_int
        || ((*key).ed25519_pk).is_null()
        || sig.is_null()
        || siglen == 0 as libc::c_int as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    b = sshbuf_from(sig as *const libc::c_void, siglen);
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    if sshbuf_get_cstring(b, &mut ktype, 0 as *mut size_t) != 0 as libc::c_int
        || sshbuf_get_string_direct(b, &mut sigblob, &mut len) != 0 as libc::c_int
        || sshbuf_get_u8(b, &mut sig_flags) != 0 as libc::c_int
        || sshbuf_get_u32(b, &mut sig_counter) != 0 as libc::c_int
    {
        r = -(4 as libc::c_int);
    } else if strcmp(sshkey_ssh_name_plain(key), ktype) != 0 as libc::c_int {
        r = -(13 as libc::c_int);
    } else if sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong {
        r = -(23 as libc::c_int);
    } else if len > 64 as libc::c_uint as libc::c_ulong {
        r = -(4 as libc::c_int);
    } else if ssh_digest_memory(
        2 as libc::c_int,
        (*key).sk_application as *const libc::c_void,
        strlen((*key).sk_application),
        apphash.as_mut_ptr(),
        ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
    ) != 0 as libc::c_int
        || ssh_digest_memory(
            2 as libc::c_int,
            data as *const libc::c_void,
            dlen,
            msghash.as_mut_ptr(),
            ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
        ) != 0 as libc::c_int
    {
        r = -(10 as libc::c_int);
    } else {
        details = calloc(
            1 as libc::c_int as libc::c_ulong,
            ::core::mem::size_of::<sshkey_sig_details>() as libc::c_ulong,
        ) as *mut sshkey_sig_details;
        if details.is_null() {
            r = -(2 as libc::c_int);
        } else {
            (*details).sk_counter = sig_counter;
            (*details).sk_flags = sig_flags;
            encoded = sshbuf_new();
            if encoded.is_null() {
                r = -(2 as libc::c_int);
            } else if sshbuf_put(encoded, sigblob as *const libc::c_void, len) != 0 as libc::c_int
                || sshbuf_put(
                    encoded,
                    apphash.as_mut_ptr() as *const libc::c_void,
                    ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
                ) != 0 as libc::c_int
                || sshbuf_put_u8(encoded, sig_flags) != 0 as libc::c_int
                || sshbuf_put_u32(encoded, sig_counter) != 0 as libc::c_int
                || sshbuf_put(
                    encoded,
                    msghash.as_mut_ptr() as *const libc::c_void,
                    ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
                ) != 0 as libc::c_int
            {
                r = -(2 as libc::c_int);
            } else {
                sm = sshbuf_ptr(encoded);
                smlen = sshbuf_len(encoded) as libc::c_ulonglong;
                mlen = smlen;
                m = libc::malloc(smlen as usize) as *mut u_char;
                if m.is_null() {
                    r = -(2 as libc::c_int);
                } else {
                    ret = crypto_sign_ed25519_open(m, &mut mlen, sm, smlen, (*key).ed25519_pk);
                    if ret != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"ssh-ed25519-sk.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                b"ssh_ed25519_sk_verify\0",
                            ))
                            .as_ptr(),
                            228 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"crypto_sign_ed25519_open failed: %d\0" as *const u8
                                as *const libc::c_char,
                            ret,
                        );
                    }
                    if ret != 0 as libc::c_int
                        || mlen != smlen.wrapping_sub(len as libc::c_ulonglong)
                    {
                        r = -(21 as libc::c_int);
                    } else {
                        r = 0 as libc::c_int;
                        if !detailsp.is_null() {
                            *detailsp = details;
                            details = 0 as *mut sshkey_sig_details;
                        }
                    }
                }
            }
        }
    }
    if !m.is_null() {
        freezero(m as *mut libc::c_void, smlen as size_t);
    }
    sshkey_sig_details_free(details);
    sshbuf_free(b);
    sshbuf_free(encoded);
    libc::free(ktype as *mut libc::c_void);
    return r;
}
static mut sshkey_ed25519_sk_funcs: sshkey_impl_funcs = unsafe {
    {
        let mut init = sshkey_impl_funcs {
            size: None,
            alloc: None,
            cleanup: Some(ssh_ed25519_sk_cleanup as unsafe extern "C" fn(*mut sshkey) -> ()),
            equal: Some(
                ssh_ed25519_sk_equal
                    as unsafe extern "C" fn(*const sshkey, *const sshkey) -> libc::c_int,
            ),
            serialize_public: Some(
                ssh_ed25519_sk_serialize_public
                    as unsafe extern "C" fn(
                        *const sshkey,
                        *mut sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_public: Some(
                ssh_ed25519_sk_deserialize_public
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut sshbuf,
                        *mut sshkey,
                    ) -> libc::c_int,
            ),
            serialize_private: Some(
                ssh_ed25519_sk_serialize_private
                    as unsafe extern "C" fn(
                        *const sshkey,
                        *mut sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_private: Some(
                ssh_ed25519_sk_deserialize_private
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut sshbuf,
                        *mut sshkey,
                    ) -> libc::c_int,
            ),
            generate: None,
            copy_public: Some(
                ssh_ed25519_sk_copy_public
                    as unsafe extern "C" fn(*const sshkey, *mut sshkey) -> libc::c_int,
            ),
            sign: None,
            verify: Some(
                ssh_ed25519_sk_verify
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
pub static mut sshkey_ed25519_sk_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"sk-ssh-ed25519@openssh.com\0" as *const u8 as *const libc::c_char,
            shortname: b"ED25519-SK\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ED25519_SK as libc::c_int,
            nid: 0 as libc::c_int,
            cert: 0 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 256 as libc::c_int,
            funcs: &sshkey_ed25519_sk_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_ed25519_sk_cert_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"sk-ssh-ed25519-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
            shortname: b"ED25519-SK-CERT\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ED25519_SK_CERT as libc::c_int,
            nid: 0 as libc::c_int,
            cert: 1 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 256 as libc::c_int,
            funcs: &sshkey_ed25519_sk_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
