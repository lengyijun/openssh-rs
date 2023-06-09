use crate::sshkey::sshkey_sig_details;
use ::libc;
extern "C" {

    fn freezero(_: *mut libc::c_void, _: size_t);

    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn crypto_sign_ed25519_open(
        _: *mut libc::c_uchar,
        _: *mut libc::c_ulonglong,
        _: *const libc::c_uchar,
        _: libc::c_ulonglong,
        _: *const libc::c_uchar,
    ) -> libc::c_int;

    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn sshbuf_get_string_direct(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;

    fn sshkey_private_deserialize_sk(
        buf: *mut crate::sshbuf::sshbuf,
        k: *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_serialize_private_sk(
        key: *const crate::sshkey::sshkey,
        buf: *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshkey_deserialize_sk(
        b: *mut crate::sshbuf::sshbuf,
        key: *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_copy_public_sk(
        from: *const crate::sshkey::sshkey,
        to: *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_serialize_sk(
        key: *const crate::sshkey::sshkey,
        b: *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshkey_sk_cleanup(k: *mut crate::sshkey::sshkey);
    fn sshkey_sk_fields_equal(
        a: *const crate::sshkey::sshkey,
        b: *const crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_sig_details_free(_: *mut sshkey_sig_details);
    fn sshkey_ssh_name_plain(_: *const crate::sshkey::sshkey) -> *const libc::c_char;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;

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
pub struct sshkey_impl_funcs {
    pub size: Option<unsafe extern "C" fn(*const crate::sshkey::sshkey) -> u_int>,
    pub alloc: Option<unsafe extern "C" fn(*mut crate::sshkey::sshkey) -> libc::c_int>,
    pub cleanup: Option<unsafe extern "C" fn(*mut crate::sshkey::sshkey) -> ()>,
    pub equal: Option<
        unsafe extern "C" fn(
            *const crate::sshkey::sshkey,
            *const crate::sshkey::sshkey,
        ) -> libc::c_int,
    >,
    pub serialize_public: Option<
        unsafe extern "C" fn(
            *const crate::sshkey::sshkey,
            *mut crate::sshbuf::sshbuf,
            sshkey_serialize_rep,
        ) -> libc::c_int,
    >,
    pub deserialize_public: Option<
        unsafe extern "C" fn(
            *const libc::c_char,
            *mut crate::sshbuf::sshbuf,
            *mut crate::sshkey::sshkey,
        ) -> libc::c_int,
    >,
    pub serialize_private: Option<
        unsafe extern "C" fn(
            *const crate::sshkey::sshkey,
            *mut crate::sshbuf::sshbuf,
            sshkey_serialize_rep,
        ) -> libc::c_int,
    >,
    pub deserialize_private: Option<
        unsafe extern "C" fn(
            *const libc::c_char,
            *mut crate::sshbuf::sshbuf,
            *mut crate::sshkey::sshkey,
        ) -> libc::c_int,
    >,
    pub generate:
        Option<unsafe extern "C" fn(*mut crate::sshkey::sshkey, libc::c_int) -> libc::c_int>,
    pub copy_public: Option<
        unsafe extern "C" fn(
            *const crate::sshkey::sshkey,
            *mut crate::sshkey::sshkey,
        ) -> libc::c_int,
    >,
    pub sign: Option<
        unsafe extern "C" fn(
            *mut crate::sshkey::sshkey,
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
            *const crate::sshkey::sshkey,
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
unsafe extern "C" fn ssh_ed25519_sk_cleanup(mut k: *mut crate::sshkey::sshkey) {
    sshkey_sk_cleanup(k);
    (sshkey_ed25519_funcs.cleanup).expect("non-null function pointer")(k);
}
unsafe extern "C" fn ssh_ed25519_sk_equal(
    mut a: *const crate::sshkey::sshkey,
    mut b: *const crate::sshkey::sshkey,
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
    mut key: *const crate::sshkey::sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
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
    mut key: *const crate::sshkey::sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
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
    mut from: *const crate::sshkey::sshkey,
    mut to: *mut crate::sshkey::sshkey,
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
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut crate::sshkey::sshkey,
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
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut crate::sshkey::sshkey,
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
    mut key: *const crate::sshkey::sshkey,
    mut sig: *const u_char,
    mut siglen: size_t,
    mut data: *const u_char,
    mut dlen: size_t,
    mut _alg: *const libc::c_char,
    mut _compat: u_int,
    mut detailsp: *mut *mut sshkey_sig_details,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut encoded: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
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
    b = crate::sshbuf::sshbuf_from(sig as *const libc::c_void, siglen);
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    if crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut ktype, 0 as *mut size_t)
        != 0 as libc::c_int
        || sshbuf_get_string_direct(b, &mut sigblob, &mut len) != 0 as libc::c_int
        || crate::sshbuf_getput_basic::sshbuf_get_u8(b, &mut sig_flags) != 0 as libc::c_int
        || crate::sshbuf_getput_basic::sshbuf_get_u32(b, &mut sig_counter) != 0 as libc::c_int
    {
        r = -(4 as libc::c_int);
    } else if libc::strcmp(sshkey_ssh_name_plain(key), ktype) != 0 as libc::c_int {
        r = -(13 as libc::c_int);
    } else if crate::sshbuf::sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong {
        r = -(23 as libc::c_int);
    } else if len > 64 as libc::c_uint as libc::c_ulong {
        r = -(4 as libc::c_int);
    } else if crate::digest_openssl::ssh_digest_memory(
        2 as libc::c_int,
        (*key).sk_application as *const libc::c_void,
        strlen((*key).sk_application),
        apphash.as_mut_ptr(),
        ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
    ) != 0 as libc::c_int
        || crate::digest_openssl::ssh_digest_memory(
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
            encoded = crate::sshbuf::sshbuf_new();
            if encoded.is_null() {
                r = -(2 as libc::c_int);
            } else if crate::sshbuf_getput_basic::sshbuf_put(
                encoded,
                sigblob as *const libc::c_void,
                len,
            ) != 0 as libc::c_int
                || crate::sshbuf_getput_basic::sshbuf_put(
                    encoded,
                    apphash.as_mut_ptr() as *const libc::c_void,
                    ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
                ) != 0 as libc::c_int
                || crate::sshbuf_getput_basic::sshbuf_put_u8(encoded, sig_flags) != 0 as libc::c_int
                || crate::sshbuf_getput_basic::sshbuf_put_u32(encoded, sig_counter)
                    != 0 as libc::c_int
                || crate::sshbuf_getput_basic::sshbuf_put(
                    encoded,
                    msghash.as_mut_ptr() as *const libc::c_void,
                    ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
                ) != 0 as libc::c_int
            {
                r = -(2 as libc::c_int);
            } else {
                sm = crate::sshbuf::sshbuf_ptr(encoded);
                smlen = crate::sshbuf::sshbuf_len(encoded) as libc::c_ulonglong;
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
    crate::sshbuf::sshbuf_free(b);
    crate::sshbuf::sshbuf_free(encoded);
    libc::free(ktype as *mut libc::c_void);
    return r;
}
static mut sshkey_ed25519_sk_funcs: sshkey_impl_funcs = unsafe {
    {
        let mut init = sshkey_impl_funcs {
            size: None,
            alloc: None,
            cleanup: Some(
                ssh_ed25519_sk_cleanup as unsafe extern "C" fn(*mut crate::sshkey::sshkey) -> (),
            ),
            equal: Some(
                ssh_ed25519_sk_equal
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
                        *const crate::sshkey::sshkey,
                    ) -> libc::c_int,
            ),
            serialize_public: Some(
                ssh_ed25519_sk_serialize_public
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
                        *mut crate::sshbuf::sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_public: Some(
                ssh_ed25519_sk_deserialize_public
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut crate::sshbuf::sshbuf,
                        *mut crate::sshkey::sshkey,
                    ) -> libc::c_int,
            ),
            serialize_private: Some(
                ssh_ed25519_sk_serialize_private
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
                        *mut crate::sshbuf::sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_private: Some(
                ssh_ed25519_sk_deserialize_private
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut crate::sshbuf::sshbuf,
                        *mut crate::sshkey::sshkey,
                    ) -> libc::c_int,
            ),
            generate: None,
            copy_public: Some(
                ssh_ed25519_sk_copy_public
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
                        *mut crate::sshkey::sshkey,
                    ) -> libc::c_int,
            ),
            sign: None,
            verify: Some(
                ssh_ed25519_sk_verify
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
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
