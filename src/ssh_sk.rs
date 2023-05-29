use ::libc;
extern "C" {

    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    pub type ec_group_st;
    pub type ec_point_st;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn dlopen(__file: *const libc::c_char, __mode: libc::c_int) -> *mut libc::c_void;
    fn dlclose(__handle: *mut libc::c_void) -> libc::c_int;
    fn dlsym(__handle: *mut libc::c_void, __name: *const libc::c_char) -> *mut libc::c_void;
    fn dlerror() -> *mut libc::c_char;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;

    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_free(point: *mut EC_POINT);
    fn EC_KEY_new_by_curve_name(nid: libc::c_int) -> *mut EC_KEY;
    fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;
    fn EC_KEY_set_public_key(key: *mut EC_KEY, pub_0: *const EC_POINT) -> libc::c_int;

    fn ssh_err(n: libc::c_int) -> *const libc::c_char;

    fn sshbuf_reset(buf: *mut crate::sshbuf::sshbuf);
    fn sshbuf_len(buf: *const crate::sshbuf::sshbuf) -> size_t;
    fn sshbuf_ptr(buf: *const crate::sshbuf::sshbuf) -> *const u_char;
    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut crate::sshbuf::sshbuf, val: u_int32_t) -> libc::c_int;

    fn sshbuf_put_string(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut crate::sshbuf::sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_put_bignum2_bytes(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_get_ec(
        buf: *mut crate::sshbuf::sshbuf,
        v: *mut EC_POINT,
        g: *const EC_GROUP,
    ) -> libc::c_int;
    fn sshkey_new(_: libc::c_int) -> *mut sshkey;
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn sshkey_ec_validate_public(_: *const EC_GROUP, _: *const EC_POINT) -> libc::c_int;
    fn sshkey_ssh_name_plain(_: *const sshkey) -> *const libc::c_char;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type EC_KEY = ec_key_st;
pub type EC_GROUP = ec_group_st;
pub type EC_POINT = ec_point_st;
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
pub struct sk_option {
    pub name: *mut libc::c_char,
    pub value: *mut libc::c_char,
    pub required: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshsk_resident_key {
    pub key: *mut sshkey,
    pub user_id: *mut uint8_t,
    pub user_id_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sk_enroll_response {
    pub flags: uint8_t,
    pub public_key: *mut uint8_t,
    pub public_key_len: size_t,
    pub key_handle: *mut uint8_t,
    pub key_handle_len: size_t,
    pub signature: *mut uint8_t,
    pub signature_len: size_t,
    pub attestation_cert: *mut uint8_t,
    pub attestation_cert_len: size_t,
    pub authdata: *mut uint8_t,
    pub authdata_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshsk_provider {
    pub path: *mut libc::c_char,
    pub dlhandle: *mut libc::c_void,
    pub sk_api_version: Option<unsafe extern "C" fn() -> uint32_t>,
    pub sk_enroll: Option<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            size_t,
            *const libc::c_char,
            uint8_t,
            *const libc::c_char,
            *mut *mut sk_option,
            *mut *mut sk_enroll_response,
        ) -> libc::c_int,
    >,
    pub sk_sign: Option<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            size_t,
            *const libc::c_char,
            *const uint8_t,
            size_t,
            uint8_t,
            *const libc::c_char,
            *mut *mut sk_option,
            *mut *mut sk_sign_response,
        ) -> libc::c_int,
    >,
    pub sk_load_resident_keys: Option<
        unsafe extern "C" fn(
            *const libc::c_char,
            *mut *mut sk_option,
            *mut *mut *mut sk_resident_key,
            *mut size_t,
        ) -> libc::c_int,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sk_resident_key {
    pub alg: uint32_t,
    pub slot: size_t,
    pub application: *mut libc::c_char,
    pub key: sk_enroll_response,
    pub flags: uint8_t,
    pub user_id: *mut uint8_t,
    pub user_id_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sk_sign_response {
    pub flags: uint8_t,
    pub counter: uint32_t,
    pub sig_r: *mut uint8_t,
    pub sig_r_len: size_t,
    pub sig_s: *mut uint8_t,
    pub sig_s_len: size_t,
}
unsafe extern "C" fn sshsk_free(mut p: *mut sshsk_provider) {
    if p.is_null() {
        return;
    }
    libc::free((*p).path as *mut libc::c_void);
    if !((*p).dlhandle).is_null() {
        dlclose((*p).dlhandle);
    }
    libc::free(p as *mut libc::c_void);
}
unsafe extern "C" fn sshsk_open(mut path: *const libc::c_char) -> *mut sshsk_provider {
    let mut ret: *mut sshsk_provider = 0 as *mut sshsk_provider;
    let mut version: uint32_t = 0;
    if path.is_null() || *path as libc::c_int == '\0' as i32 {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sshsk_open\0")).as_ptr(),
            113 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"No FIDO SecurityKeyProvider specified\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut sshsk_provider;
    }
    ret = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<sshsk_provider>() as libc::c_ulong,
    ) as *mut sshsk_provider;
    if ret.is_null() {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sshsk_open\0")).as_ptr(),
            117 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"calloc failed\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut sshsk_provider;
    }
    (*ret).path = libc::strdup(path);
    if ((*ret).path).is_null() {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sshsk_open\0")).as_ptr(),
            121 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libc::strdup failed\0" as *const u8 as *const libc::c_char,
        );
    } else if strcasecmp(
        (*ret).path,
        b"internal\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sshsk_open\0")).as_ptr(),
            132 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"internal security key support not enabled\0" as *const u8 as *const libc::c_char,
        );
    } else {
        (*ret).dlhandle = dlopen(path, 0x2 as libc::c_int);
        if ((*ret).dlhandle).is_null() {
            crate::log::sshlog(
                b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sshsk_open\0"))
                    .as_ptr(),
                137 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Provider \"%s\" dlopen failed: %s\0" as *const u8 as *const libc::c_char,
                path,
                dlerror(),
            );
        } else {
            (*ret).sk_api_version = ::core::mem::transmute::<
                *mut libc::c_void,
                Option<unsafe extern "C" fn() -> uint32_t>,
            >(dlsym(
                (*ret).dlhandle,
                b"sk_api_version\0" as *const u8 as *const libc::c_char,
            ));
            if ((*ret).sk_api_version).is_none() {
                crate::log::sshlog(
                    b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sshsk_open\0"))
                        .as_ptr(),
                    143 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Provider \"%s\" dlsym(sk_api_version) failed: %s\0" as *const u8
                        as *const libc::c_char,
                    path,
                    dlerror(),
                );
            } else {
                version = ((*ret).sk_api_version).expect("non-null function pointer")();
                crate::log::sshlog(
                    b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sshsk_open\0"))
                        .as_ptr(),
                    148 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"provider %s implements version 0x%08lx\0" as *const u8 as *const libc::c_char,
                    (*ret).path,
                    version as u_long,
                );
                if version & 0xffff0000 as libc::c_uint != 0xa0000 as libc::c_int as libc::c_uint {
                    crate::log::sshlog(
                        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<
                            &[u8; 11],
                            &[libc::c_char; 11],
                        >(b"sshsk_open\0"))
                            .as_ptr(),
                        152 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Provider \"%s\" implements unsupported version 0x%08lx (supported: 0x%08lx)\0"
                            as *const u8 as *const libc::c_char,
                        path,
                        version as u_long,
                        0xa0000 as libc::c_int as u_long,
                    );
                } else {
                    (*ret).sk_enroll = ::core::mem::transmute::<
                        *mut libc::c_void,
                        Option<
                            unsafe extern "C" fn(
                                libc::c_int,
                                *const uint8_t,
                                size_t,
                                *const libc::c_char,
                                uint8_t,
                                *const libc::c_char,
                                *mut *mut sk_option,
                                *mut *mut sk_enroll_response,
                            ) -> libc::c_int,
                        >,
                    >(dlsym(
                        (*ret).dlhandle,
                        b"sk_enroll\0" as *const u8 as *const libc::c_char,
                    ));
                    if ((*ret).sk_enroll).is_none() {
                        crate::log::sshlog(
                            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                b"sshsk_open\0",
                            ))
                            .as_ptr(),
                            157 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"Provider %s dlsym(sk_enroll) failed: %s\0" as *const u8
                                as *const libc::c_char,
                            path,
                            dlerror(),
                        );
                    } else {
                        (*ret).sk_sign = ::core::mem::transmute::<
                            *mut libc::c_void,
                            Option<
                                unsafe extern "C" fn(
                                    libc::c_int,
                                    *const uint8_t,
                                    size_t,
                                    *const libc::c_char,
                                    *const uint8_t,
                                    size_t,
                                    uint8_t,
                                    *const libc::c_char,
                                    *mut *mut sk_option,
                                    *mut *mut sk_sign_response,
                                )
                                    -> libc::c_int,
                            >,
                        >(dlsym(
                            (*ret).dlhandle,
                            b"sk_sign\0" as *const u8 as *const libc::c_char,
                        ));
                        if ((*ret).sk_sign).is_none() {
                            crate::log::sshlog(
                                b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                    b"sshsk_open\0",
                                ))
                                .as_ptr(),
                                162 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"Provider \"%s\" dlsym(sk_sign) failed: %s\0" as *const u8
                                    as *const libc::c_char,
                                path,
                                dlerror(),
                            );
                        } else {
                            (*ret).sk_load_resident_keys = ::core::mem::transmute::<
                                *mut libc::c_void,
                                Option<
                                    unsafe extern "C" fn(
                                        *const libc::c_char,
                                        *mut *mut sk_option,
                                        *mut *mut *mut sk_resident_key,
                                        *mut size_t,
                                    )
                                        -> libc::c_int,
                                >,
                            >(dlsym(
                                (*ret).dlhandle,
                                b"sk_load_resident_keys\0" as *const u8 as *const libc::c_char,
                            ));
                            if ((*ret).sk_load_resident_keys).is_none() {
                                crate::log::sshlog(
                                    b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                        b"sshsk_open\0",
                                    ))
                                    .as_ptr(),
                                    168 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"Provider \"%s\" dlsym(sk_load_resident_keys) failed: %s\0"
                                        as *const u8
                                        as *const libc::c_char,
                                    path,
                                    dlerror(),
                                );
                            } else {
                                return ret;
                            }
                        }
                    }
                }
            }
        }
    }
    sshsk_free(ret);
    return 0 as *mut sshsk_provider;
}
unsafe extern "C" fn sshsk_free_enroll_response(mut r: *mut sk_enroll_response) {
    if r.is_null() {
        return;
    }
    freezero((*r).key_handle as *mut libc::c_void, (*r).key_handle_len);
    freezero((*r).public_key as *mut libc::c_void, (*r).public_key_len);
    freezero((*r).signature as *mut libc::c_void, (*r).signature_len);
    freezero(
        (*r).attestation_cert as *mut libc::c_void,
        (*r).attestation_cert_len,
    );
    freezero((*r).authdata as *mut libc::c_void, (*r).authdata_len);
    freezero(
        r as *mut libc::c_void,
        ::core::mem::size_of::<sk_enroll_response>() as libc::c_ulong,
    );
}
unsafe extern "C" fn sshsk_free_sign_response(mut r: *mut sk_sign_response) {
    if r.is_null() {
        return;
    }
    freezero((*r).sig_r as *mut libc::c_void, (*r).sig_r_len);
    freezero((*r).sig_s as *mut libc::c_void, (*r).sig_s_len);
    freezero(
        r as *mut libc::c_void,
        ::core::mem::size_of::<sk_sign_response>() as libc::c_ulong,
    );
}
unsafe extern "C" fn sshsk_ecdsa_assemble(
    mut resp: *mut sk_enroll_response,
    mut keyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut q: *mut EC_POINT = 0 as *mut EC_POINT;
    let mut r: libc::c_int = 0;
    *keyp = 0 as *mut sshkey;
    key = sshkey_new(KEY_ECDSA_SK as libc::c_int);
    if key.is_null() {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"sshsk_ecdsa_assemble\0"))
                .as_ptr(),
            213 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
        );
        r = -(2 as libc::c_int);
    } else {
        (*key).ecdsa_nid = 415 as libc::c_int;
        (*key).ecdsa = EC_KEY_new_by_curve_name((*key).ecdsa_nid);
        if ((*key).ecdsa).is_null()
            || {
                q = EC_POINT_new(EC_KEY_get0_group((*key).ecdsa));
                q.is_null()
            }
            || {
                b = crate::sshbuf::sshbuf_new();
                b.is_null()
            }
        {
            crate::log::sshlog(
                b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"sshsk_ecdsa_assemble\0",
                ))
                .as_ptr(),
                221 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"allocation failed\0" as *const u8 as *const libc::c_char,
            );
            r = -(2 as libc::c_int);
        } else {
            r = sshbuf_put_string(
                b,
                (*resp).public_key as *const libc::c_void,
                (*resp).public_key_len,
            );
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"sshsk_ecdsa_assemble\0",
                    ))
                    .as_ptr(),
                    227 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"sshbuf_put_string\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = sshbuf_get_ec(b, q, EC_KEY_get0_group((*key).ecdsa));
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"sshsk_ecdsa_assemble\0",
                        ))
                        .as_ptr(),
                        231 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"parse\0" as *const u8 as *const libc::c_char,
                    );
                    r = -(4 as libc::c_int);
                } else if sshkey_ec_validate_public(EC_KEY_get0_group((*key).ecdsa), q)
                    != 0 as libc::c_int
                {
                    crate::log::sshlog(
                        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"sshsk_ecdsa_assemble\0",
                        ))
                        .as_ptr(),
                        236 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Authenticator returned invalid ECDSA key\0" as *const u8
                            as *const libc::c_char,
                    );
                    r = -(20 as libc::c_int);
                } else if EC_KEY_set_public_key((*key).ecdsa, q) != 1 as libc::c_int {
                    crate::log::sshlog(
                        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"sshsk_ecdsa_assemble\0",
                        ))
                        .as_ptr(),
                        242 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"allocation failed\0" as *const u8 as *const libc::c_char,
                    );
                    r = -(2 as libc::c_int);
                } else {
                    *keyp = key;
                    key = 0 as *mut sshkey;
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    EC_POINT_free(q);
    sshkey_free(key);
    crate::sshbuf::sshbuf_free(b);
    return r;
}
unsafe extern "C" fn sshsk_ed25519_assemble(
    mut resp: *mut sk_enroll_response,
    mut keyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut r: libc::c_int = 0;
    *keyp = 0 as *mut sshkey;
    if (*resp).public_key_len != 32 as libc::c_uint as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"sshsk_ed25519_assemble\0",
            ))
            .as_ptr(),
            266 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"invalid size: %zu\0" as *const u8 as *const libc::c_char,
            (*resp).public_key_len,
        );
        r = -(4 as libc::c_int);
    } else {
        key = sshkey_new(KEY_ED25519_SK as libc::c_int);
        if key.is_null() {
            crate::log::sshlog(
                b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"sshsk_ed25519_assemble\0",
                ))
                .as_ptr(),
                271 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
            );
            r = -(2 as libc::c_int);
        } else {
            (*key).ed25519_pk = libc::malloc(32 as usize) as *mut u_char;
            if ((*key).ed25519_pk).is_null() {
                crate::log::sshlog(
                    b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"sshsk_ed25519_assemble\0",
                    ))
                    .as_ptr(),
                    276 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"libc::malloc failed\0" as *const u8 as *const libc::c_char,
                );
                r = -(2 as libc::c_int);
            } else {
                memcpy(
                    (*key).ed25519_pk as *mut libc::c_void,
                    (*resp).public_key as *const libc::c_void,
                    32 as libc::c_uint as libc::c_ulong,
                );
                *keyp = key;
                key = 0 as *mut sshkey;
                r = 0 as libc::c_int;
            }
        }
    }
    sshkey_free(key);
    return r;
}
unsafe extern "C" fn sshsk_key_from_response(
    mut alg: libc::c_int,
    mut application: *const libc::c_char,
    mut flags: uint8_t,
    mut resp: *mut sk_enroll_response,
    mut keyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut current_block: u64;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut r: libc::c_int = -(1 as libc::c_int);
    *keyp = 0 as *mut sshkey;
    if ((*resp).public_key).is_null() || ((*resp).key_handle).is_null() {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"sshsk_key_from_response\0",
            ))
            .as_ptr(),
            301 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"sk_enroll response invalid\0" as *const u8 as *const libc::c_char,
        );
        r = -(4 as libc::c_int);
    } else {
        match alg {
            0 => {
                r = sshsk_ecdsa_assemble(resp, &mut key);
                if r != 0 as libc::c_int {
                    current_block = 11373327429110953420;
                } else {
                    current_block = 13109137661213826276;
                }
            }
            1 => {
                r = sshsk_ed25519_assemble(resp, &mut key);
                if r != 0 as libc::c_int {
                    current_block = 11373327429110953420;
                } else {
                    current_block = 13109137661213826276;
                }
            }
            _ => {
                crate::log::sshlog(
                    b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"sshsk_key_from_response\0",
                    ))
                    .as_ptr(),
                    317 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"unsupported algorithm %d\0" as *const u8 as *const libc::c_char,
                    alg,
                );
                r = -(10 as libc::c_int);
                current_block = 11373327429110953420;
            }
        }
        match current_block {
            11373327429110953420 => {}
            _ => {
                (*key).sk_flags = flags;
                (*key).sk_key_handle = crate::sshbuf::sshbuf_new();
                if ((*key).sk_key_handle).is_null() || {
                    (*key).sk_reserved = crate::sshbuf::sshbuf_new();
                    ((*key).sk_reserved).is_null()
                } {
                    crate::log::sshlog(
                        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                            b"sshsk_key_from_response\0",
                        ))
                        .as_ptr(),
                        324 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"allocation failed\0" as *const u8 as *const libc::c_char,
                    );
                    r = -(2 as libc::c_int);
                } else {
                    (*key).sk_application = libc::strdup(application);
                    if ((*key).sk_application).is_null() {
                        crate::log::sshlog(
                            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                b"sshsk_key_from_response\0",
                            ))
                            .as_ptr(),
                            329 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"libc::strdup application failed\0" as *const u8
                                as *const libc::c_char,
                        );
                        r = -(2 as libc::c_int);
                    } else {
                        r = sshbuf_put(
                            (*key).sk_key_handle,
                            (*resp).key_handle as *const libc::c_void,
                            (*resp).key_handle_len,
                        );
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                    b"sshsk_key_from_response\0",
                                ))
                                .as_ptr(),
                                335 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"put key handle\0" as *const u8 as *const libc::c_char,
                            );
                        } else {
                            r = 0 as libc::c_int;
                            *keyp = key;
                            key = 0 as *mut sshkey;
                        }
                    }
                }
            }
        }
    }
    sshkey_free(key);
    return r;
}
unsafe extern "C" fn skerr_to_ssherr(mut skerr: libc::c_int) -> libc::c_int {
    match skerr {
        -2 => return -(59 as libc::c_int),
        -3 => return -(43 as libc::c_int),
        -4 => return -(60 as libc::c_int),
        -5 => return -(44 as libc::c_int),
        -1 | _ => return -(4 as libc::c_int),
    };
}
unsafe extern "C" fn sshsk_free_options(mut opts: *mut *mut sk_option) {
    let mut i: size_t = 0;
    if opts.is_null() {
        return;
    }
    i = 0 as libc::c_int as size_t;
    while !(*opts.offset(i as isize)).is_null() {
        libc::free((**opts.offset(i as isize)).name as *mut libc::c_void);
        libc::free((**opts.offset(i as isize)).value as *mut libc::c_void);
        libc::free(*opts.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(opts as *mut libc::c_void);
}
unsafe extern "C" fn sshsk_add_option(
    mut optsp: *mut *mut *mut sk_option,
    mut noptsp: *mut size_t,
    mut name: *const libc::c_char,
    mut value: *const libc::c_char,
    mut required: uint8_t,
) -> libc::c_int {
    let mut opts: *mut *mut sk_option = *optsp;
    let mut nopts: size_t = *noptsp;
    opts = recallocarray(
        opts as *mut libc::c_void,
        nopts,
        nopts.wrapping_add(2 as libc::c_int as libc::c_ulong),
        ::core::mem::size_of::<*mut sk_option>() as libc::c_ulong,
    ) as *mut *mut sk_option;
    if opts.is_null() {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"sshsk_add_option\0"))
                .as_ptr(),
            389 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"array alloc failed\0" as *const u8 as *const libc::c_char,
        );
        return -(2 as libc::c_int);
    }
    *optsp = opts;
    *noptsp = nopts.wrapping_add(1 as libc::c_int as libc::c_ulong);
    let ref mut fresh0 = *opts.offset(nopts as isize);
    *fresh0 = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<sk_option>() as libc::c_ulong,
    ) as *mut sk_option;
    if (*fresh0).is_null() {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"sshsk_add_option\0"))
                .as_ptr(),
            395 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"alloc failed\0" as *const u8 as *const libc::c_char,
        );
        return -(2 as libc::c_int);
    }
    let ref mut fresh1 = (**opts.offset(nopts as isize)).name;
    *fresh1 = libc::strdup(name);
    if (*fresh1).is_null() || {
        let ref mut fresh2 = (**opts.offset(nopts as isize)).value;
        *fresh2 = libc::strdup(value);
        (*fresh2).is_null()
    } {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"sshsk_add_option\0"))
                .as_ptr(),
            400 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"alloc failed\0" as *const u8 as *const libc::c_char,
        );
        return -(2 as libc::c_int);
    }
    (**opts.offset(nopts as isize)).required = required;
    return 0 as libc::c_int;
}
unsafe extern "C" fn make_options(
    mut device: *const libc::c_char,
    mut user_id: *const libc::c_char,
    mut optsp: *mut *mut *mut sk_option,
) -> libc::c_int {
    let mut opts: *mut *mut sk_option = 0 as *mut *mut sk_option;
    let mut nopts: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if !device.is_null() && {
        r = sshsk_add_option(
            &mut opts,
            &mut nopts,
            b"device\0" as *const u8 as *const libc::c_char,
            device,
            0 as libc::c_int as uint8_t,
        );
        r != 0 as libc::c_int
    } {
        ret = r;
    } else if !user_id.is_null() && {
        r = sshsk_add_option(
            &mut opts,
            &mut nopts,
            b"user\0" as *const u8 as *const libc::c_char,
            user_id,
            0 as libc::c_int as uint8_t,
        );
        r != 0 as libc::c_int
    } {
        ret = r;
    } else {
        *optsp = opts;
        opts = 0 as *mut *mut sk_option;
        nopts = 0 as libc::c_int as size_t;
        ret = 0 as libc::c_int;
    }
    sshsk_free_options(opts);
    return ret;
}
unsafe extern "C" fn fill_attestation_blob(
    mut resp: *const sk_enroll_response,
    mut attest: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    if attest.is_null() {
        return 0 as libc::c_int;
    }
    r = sshbuf_put_cstring(
        attest,
        b"ssh-sk-attest-v01\0" as *const u8 as *const libc::c_char,
    );
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_string(
                attest,
                (*resp).attestation_cert as *const libc::c_void,
                (*resp).attestation_cert_len,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(
                attest,
                (*resp).signature as *const libc::c_void,
                (*resp).signature_len,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(
                attest,
                (*resp).authdata as *const libc::c_void,
                (*resp).authdata_len,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(attest, 0 as libc::c_int as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(attest, 0 as *const libc::c_void, 0 as libc::c_int as size_t);
            r != 0 as libc::c_int
        }
    {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"fill_attestation_blob\0"))
                .as_ptr(),
            453 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshsk_enroll(
    mut type_0: libc::c_int,
    mut provider_path: *const libc::c_char,
    mut device: *const libc::c_char,
    mut application: *const libc::c_char,
    mut userid: *const libc::c_char,
    mut flags: uint8_t,
    mut pin: *const libc::c_char,
    mut challenge_buf: *mut crate::sshbuf::sshbuf,
    mut keyp: *mut *mut sshkey,
    mut attest: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut skp: *mut sshsk_provider = 0 as *mut sshsk_provider;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut randchall: [u_char; 32] = [0; 32];
    let mut challenge: *const u_char = 0 as *const u_char;
    let mut challenge_len: size_t = 0;
    let mut resp: *mut sk_enroll_response = 0 as *mut sk_enroll_response;
    let mut opts: *mut *mut sk_option = 0 as *mut *mut sk_option;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut alg: libc::c_int = 0;
    crate::log::sshlog(
        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sshsk_enroll\0"))
            .as_ptr(),
        480 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"provider \"%s\", device \"%s\", application \"%s\", userid \"%s\", flags 0x%02x, challenge len %zu%s\0"
            as *const u8 as *const libc::c_char,
        provider_path,
        device,
        application,
        userid,
        flags as libc::c_int,
        if challenge_buf.is_null() {
            0 as libc::c_int as libc::c_ulong
        } else {
            sshbuf_len(challenge_buf)
        },
        if !pin.is_null() && *pin as libc::c_int != '\0' as i32 {
            b" with-pin\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    *keyp = 0 as *mut sshkey;
    if !attest.is_null() {
        sshbuf_reset(attest);
    }
    r = make_options(device, userid, &mut opts);
    if !(r != 0 as libc::c_int) {
        match type_0 {
            10 => {
                alg = 0 as libc::c_int;
                current_block = 11050875288958768710;
            }
            12 => {
                alg = 0x1 as libc::c_int;
                current_block = 11050875288958768710;
            }
            _ => {
                crate::log::sshlog(
                    b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sshsk_enroll\0"))
                        .as_ptr(),
                    499 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"unsupported key type\0" as *const u8 as *const libc::c_char,
                );
                r = -(10 as libc::c_int);
                current_block = 7177629584601204510;
            }
        }
        match current_block {
            7177629584601204510 => {}
            _ => {
                if provider_path.is_null() {
                    crate::log::sshlog(
                        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"sshsk_enroll\0",
                        ))
                        .as_ptr(),
                        504 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"missing provider\0" as *const u8 as *const libc::c_char,
                    );
                    r = -(10 as libc::c_int);
                } else if application.is_null() || *application as libc::c_int == '\0' as i32 {
                    crate::log::sshlog(
                        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"sshsk_enroll\0",
                        ))
                        .as_ptr(),
                        509 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"missing application\0" as *const u8 as *const libc::c_char,
                    );
                    r = -(10 as libc::c_int);
                } else {
                    if challenge_buf.is_null() {
                        crate::log::sshlog(
                            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"sshsk_enroll\0",
                            ))
                            .as_ptr(),
                            514 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"using random challenge\0" as *const u8 as *const libc::c_char,
                        );
                        arc4random_buf(
                            randchall.as_mut_ptr() as *mut libc::c_void,
                            ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
                        );
                        challenge = randchall.as_mut_ptr();
                        challenge_len = ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong;
                        current_block = 13550086250199790493;
                    } else if sshbuf_len(challenge_buf) == 0 as libc::c_int as libc::c_ulong {
                        crate::log::sshlog(
                            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"sshsk_enroll\0",
                            ))
                            .as_ptr(),
                            519 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"Missing enrollment challenge\0" as *const u8 as *const libc::c_char,
                        );
                        r = -(10 as libc::c_int);
                        current_block = 7177629584601204510;
                    } else {
                        challenge = sshbuf_ptr(challenge_buf);
                        challenge_len = sshbuf_len(challenge_buf);
                        crate::log::sshlog(
                            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"sshsk_enroll\0",
                            ))
                            .as_ptr(),
                            525 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG3,
                            0 as *const libc::c_char,
                            b"using explicit challenge len=%zd\0" as *const u8
                                as *const libc::c_char,
                            challenge_len,
                        );
                        current_block = 13550086250199790493;
                    }
                    match current_block {
                        7177629584601204510 => {}
                        _ => {
                            skp = sshsk_open(provider_path);
                            if skp.is_null() {
                                r = -(4 as libc::c_int);
                            } else {
                                r = ((*skp).sk_enroll).expect("non-null function pointer")(
                                    alg,
                                    challenge,
                                    challenge_len,
                                    application,
                                    flags,
                                    pin,
                                    opts,
                                    &mut resp,
                                );
                                if r != 0 as libc::c_int {
                                    crate::log::sshlog(
                                        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                            b"sshsk_enroll\0",
                                        ))
                                        .as_ptr(),
                                        535 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG1,
                                        0 as *const libc::c_char,
                                        b"provider \"%s\" failure %d\0" as *const u8
                                            as *const libc::c_char,
                                        provider_path,
                                        r,
                                    );
                                    r = skerr_to_ssherr(r);
                                } else {
                                    r = sshsk_key_from_response(
                                        alg,
                                        application,
                                        (*resp).flags,
                                        resp,
                                        &mut key,
                                    );
                                    if !(r != 0 as libc::c_int) {
                                        r = fill_attestation_blob(resp, attest);
                                        if !(r != 0 as libc::c_int) {
                                            *keyp = key;
                                            key = 0 as *mut sshkey;
                                            r = 0 as libc::c_int;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    sshsk_free_options(opts);
    sshsk_free(skp);
    sshkey_free(key);
    sshsk_free_enroll_response(resp);
    explicit_bzero(
        randchall.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
    );
    return r;
}
unsafe extern "C" fn sshsk_ecdsa_sig(
    mut resp: *mut sk_sign_response,
    mut sig: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut inner_sig: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = -(1 as libc::c_int);
    if ((*resp).sig_r).is_null() || ((*resp).sig_s).is_null() {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"sshsk_ecdsa_sig\0"))
                .as_ptr(),
            570 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"sk_sign response invalid\0" as *const u8 as *const libc::c_char,
        );
        r = -(4 as libc::c_int);
    } else {
        inner_sig = crate::sshbuf::sshbuf_new();
        if inner_sig.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = sshbuf_put_bignum2_bytes(
                inner_sig,
                (*resp).sig_r as *const libc::c_void,
                (*resp).sig_r_len,
            );
            if r != 0 as libc::c_int || {
                r = sshbuf_put_bignum2_bytes(
                    inner_sig,
                    (*resp).sig_s as *const libc::c_void,
                    (*resp).sig_s_len,
                );
                r != 0 as libc::c_int
            } {
                crate::log::sshlog(
                    b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"sshsk_ecdsa_sig\0",
                    ))
                    .as_ptr(),
                    583 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"compose inner\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = sshbuf_put_stringb(sig, inner_sig);
                if r != 0 as libc::c_int
                    || {
                        r = crate::sshbuf_getput_basic::sshbuf_put_u8(sig, (*resp).flags);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_u32(sig, (*resp).counter);
                        r != 0 as libc::c_int
                    }
                {
                    crate::log::sshlog(
                        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"sshsk_ecdsa_sig\0",
                        ))
                        .as_ptr(),
                        589 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"compose\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    crate::sshbuf::sshbuf_free(inner_sig);
    return r;
}
unsafe extern "C" fn sshsk_ed25519_sig(
    mut resp: *mut sk_sign_response,
    mut sig: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = -(1 as libc::c_int);
    if ((*resp).sig_r).is_null() {
        crate::log::sshlog(
            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"sshsk_ed25519_sig\0"))
                .as_ptr(),
            614 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"sk_sign response invalid\0" as *const u8 as *const libc::c_char,
        );
        r = -(4 as libc::c_int);
    } else {
        r = sshbuf_put_string(sig, (*resp).sig_r as *const libc::c_void, (*resp).sig_r_len);
        if r != 0 as libc::c_int
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(sig, (*resp).flags);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_u32(sig, (*resp).counter);
                r != 0 as libc::c_int
            }
        {
            crate::log::sshlog(
                b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"sshsk_ed25519_sig\0"))
                    .as_ptr(),
                622 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"compose\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = 0 as libc::c_int;
        }
    }
    return r;
}
pub unsafe extern "C" fn sshsk_sign(
    mut provider_path: *const libc::c_char,
    mut key: *mut sshkey,
    mut sigp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut data: *const u_char,
    mut datalen: size_t,
    mut _compat: u_int,
    mut pin: *const libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut skp: *mut sshsk_provider = 0 as *mut sshsk_provider;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut type_0: libc::c_int = 0;
    let mut alg: libc::c_int = 0;
    let mut resp: *mut sk_sign_response = 0 as *mut sk_sign_response;
    let mut inner_sig: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sig: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut opts: *mut *mut sk_option = 0 as *mut *mut sk_option;
    crate::log::sshlog(
        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sshsk_sign\0")).as_ptr(),
        648 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"provider \"%s\", key %s, flags 0x%02x%s\0" as *const u8 as *const libc::c_char,
        provider_path,
        sshkey_type(key),
        (*key).sk_flags as libc::c_int,
        if !pin.is_null() && *pin as libc::c_int != '\0' as i32 {
            b" with-pin\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    if !sigp.is_null() {
        *sigp = 0 as *mut u_char;
    }
    if !lenp.is_null() {
        *lenp = 0 as libc::c_int as size_t;
    }
    type_0 = sshkey_type_plain((*key).type_0);
    match type_0 {
        10 => {
            alg = 0 as libc::c_int;
        }
        12 => {
            alg = 0x1 as libc::c_int;
        }
        _ => return -(10 as libc::c_int),
    }
    if provider_path.is_null()
        || ((*key).sk_key_handle).is_null()
        || ((*key).sk_application).is_null()
        || *(*key).sk_application as libc::c_int == '\0' as i32
    {
        r = -(10 as libc::c_int);
    } else {
        skp = sshsk_open(provider_path);
        if skp.is_null() {
            r = -(4 as libc::c_int);
        } else {
            r = ((*skp).sk_sign).expect("non-null function pointer")(
                alg,
                data,
                datalen,
                (*key).sk_application,
                sshbuf_ptr((*key).sk_key_handle),
                sshbuf_len((*key).sk_key_handle),
                (*key).sk_flags,
                pin,
                opts,
                &mut resp,
            );
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sshsk_sign\0"))
                        .as_ptr(),
                    686 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"sk_sign failed with code %d\0" as *const u8 as *const libc::c_char,
                    r,
                );
                r = skerr_to_ssherr(r);
            } else {
                sig = crate::sshbuf::sshbuf_new();
                if sig.is_null() {
                    r = -(2 as libc::c_int);
                } else {
                    r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(key));
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                b"sshsk_sign\0",
                            ))
                            .as_ptr(),
                            696 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"compose outer\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        match type_0 {
                            10 => {
                                r = sshsk_ecdsa_sig(resp, sig);
                                if r != 0 as libc::c_int {
                                    current_block = 7648509926025298111;
                                } else {
                                    current_block = 7056779235015430508;
                                }
                            }
                            12 => {
                                r = sshsk_ed25519_sig(resp, sig);
                                if r != 0 as libc::c_int {
                                    current_block = 7648509926025298111;
                                } else {
                                    current_block = 7056779235015430508;
                                }
                            }
                            _ => {
                                current_block = 7056779235015430508;
                            }
                        }
                        match current_block {
                            7648509926025298111 => {}
                            _ => {
                                if !sigp.is_null() {
                                    *sigp = libc::malloc(sshbuf_len(sig) as usize) as *mut u_char;
                                    if (*sigp).is_null() {
                                        r = -(2 as libc::c_int);
                                        current_block = 7648509926025298111;
                                    } else {
                                        memcpy(
                                            *sigp as *mut libc::c_void,
                                            sshbuf_ptr(sig) as *const libc::c_void,
                                            sshbuf_len(sig),
                                        );
                                        current_block = 8693738493027456495;
                                    }
                                } else {
                                    current_block = 8693738493027456495;
                                }
                                match current_block {
                                    7648509926025298111 => {}
                                    _ => {
                                        if !lenp.is_null() {
                                            *lenp = sshbuf_len(sig);
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
    }
    sshsk_free_options(opts);
    sshsk_free(skp);
    sshsk_free_sign_response(resp);
    crate::sshbuf::sshbuf_free(sig);
    crate::sshbuf::sshbuf_free(inner_sig);
    return r;
}
unsafe extern "C" fn sshsk_free_sk_resident_keys(
    mut rks: *mut *mut sk_resident_key,
    mut nrks: size_t,
) {
    let mut i: size_t = 0;
    if nrks == 0 as libc::c_int as libc::c_ulong || rks.is_null() {
        return;
    }
    i = 0 as libc::c_int as size_t;
    while i < nrks {
        libc::free((**rks.offset(i as isize)).application as *mut libc::c_void);
        freezero(
            (**rks.offset(i as isize)).user_id as *mut libc::c_void,
            (**rks.offset(i as isize)).user_id_len,
        );
        freezero(
            (**rks.offset(i as isize)).key.key_handle as *mut libc::c_void,
            (**rks.offset(i as isize)).key.key_handle_len,
        );
        freezero(
            (**rks.offset(i as isize)).key.public_key as *mut libc::c_void,
            (**rks.offset(i as isize)).key.public_key_len,
        );
        freezero(
            (**rks.offset(i as isize)).key.signature as *mut libc::c_void,
            (**rks.offset(i as isize)).key.signature_len,
        );
        freezero(
            (**rks.offset(i as isize)).key.attestation_cert as *mut libc::c_void,
            (**rks.offset(i as isize)).key.attestation_cert_len,
        );
        freezero(
            *rks.offset(i as isize) as *mut libc::c_void,
            ::core::mem::size_of::<sk_resident_key>() as libc::c_ulong,
        );
        i = i.wrapping_add(1);
        i;
    }
    libc::free(rks as *mut libc::c_void);
}
unsafe extern "C" fn sshsk_free_resident_key(mut srk: *mut sshsk_resident_key) {
    if srk.is_null() {
        return;
    }
    sshkey_free((*srk).key);
    freezero((*srk).user_id as *mut libc::c_void, (*srk).user_id_len);
    libc::free(srk as *mut libc::c_void);
}
pub unsafe extern "C" fn sshsk_free_resident_keys(
    mut srks: *mut *mut sshsk_resident_key,
    mut nsrks: size_t,
) {
    let mut i: size_t = 0;
    if srks.is_null() || nsrks == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    i = 0 as libc::c_int as size_t;
    while i < nsrks {
        sshsk_free_resident_key(*srks.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    libc::free(srks as *mut libc::c_void);
}
pub unsafe extern "C" fn sshsk_load_resident(
    mut provider_path: *const libc::c_char,
    mut device: *const libc::c_char,
    mut pin: *const libc::c_char,
    mut _flags: u_int,
    mut srksp: *mut *mut *mut sshsk_resident_key,
    mut nsrksp: *mut size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut skp: *mut sshsk_provider = 0 as *mut sshsk_provider;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut rks: *mut *mut sk_resident_key = 0 as *mut *mut sk_resident_key;
    let mut i: size_t = 0;
    let mut nrks: size_t = 0 as libc::c_int as size_t;
    let mut nsrks: size_t = 0 as libc::c_int as size_t;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut srk: *mut sshsk_resident_key = 0 as *mut sshsk_resident_key;
    let mut srks: *mut *mut sshsk_resident_key = 0 as *mut *mut sshsk_resident_key;
    let mut tmp: *mut *mut sshsk_resident_key = 0 as *mut *mut sshsk_resident_key;
    let mut sk_flags: uint8_t = 0;
    let mut opts: *mut *mut sk_option = 0 as *mut *mut sk_option;
    crate::log::sshlog(
        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"sshsk_load_resident\0"))
            .as_ptr(),
        798 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"provider \"%s\"%s\0" as *const u8 as *const libc::c_char,
        provider_path,
        if !pin.is_null() && *pin as libc::c_int != '\0' as i32 {
            b", have-pin\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    if srksp.is_null() || nsrksp.is_null() {
        return -(10 as libc::c_int);
    }
    *srksp = 0 as *mut *mut sshsk_resident_key;
    *nsrksp = 0 as libc::c_int as size_t;
    r = make_options(device, 0 as *const libc::c_char, &mut opts);
    if !(r != 0 as libc::c_int) {
        skp = sshsk_open(provider_path);
        if skp.is_null() {
            r = -(4 as libc::c_int);
        } else {
            r = ((*skp).sk_load_resident_keys).expect("non-null function pointer")(
                pin, opts, &mut rks, &mut nrks,
            );
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"sshsk_load_resident\0",
                    ))
                    .as_ptr(),
                    812 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Provider \"%s\" returned failure %d\0" as *const u8 as *const libc::c_char,
                    provider_path,
                    r,
                );
                r = skerr_to_ssherr(r);
            } else {
                i = 0 as libc::c_int as size_t;
                loop {
                    if !(i < nrks) {
                        current_block = 14136749492126903395;
                        break;
                    }
                    crate::log::sshlog(
                        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"sshsk_load_resident\0",
                        ))
                        .as_ptr(),
                        819 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu\0" as *const u8
                            as *const libc::c_char,
                        i,
                        (**rks.offset(i as isize)).slot,
                        (**rks.offset(i as isize)).alg,
                        (**rks.offset(i as isize)).application,
                        (**rks.offset(i as isize)).user_id_len,
                    );
                    if !(strncmp(
                        (**rks.offset(i as isize)).application,
                        b"ssh:\0" as *const u8 as *const libc::c_char,
                        4 as libc::c_int as libc::c_ulong,
                    ) != 0 as libc::c_int)
                    {
                        match (**rks.offset(i as isize)).alg {
                            0 | 1 => {
                                sk_flags = (0x1 as libc::c_int | 0x20 as libc::c_int) as uint8_t;
                                if (**rks.offset(i as isize)).flags as libc::c_int
                                    & 0x4 as libc::c_int
                                    != 0
                                {
                                    sk_flags =
                                        (sk_flags as libc::c_int | 0x4 as libc::c_int) as uint8_t;
                                }
                                r = sshsk_key_from_response(
                                    (**rks.offset(i as isize)).alg as libc::c_int,
                                    (**rks.offset(i as isize)).application,
                                    sk_flags,
                                    &mut (**rks.offset(i as isize)).key,
                                    &mut key,
                                );
                                if r != 0 as libc::c_int {
                                    current_block = 11059859196351308165;
                                    break;
                                }
                                srk = calloc(
                                    1 as libc::c_int as libc::c_ulong,
                                    ::core::mem::size_of::<sshsk_resident_key>() as libc::c_ulong,
                                ) as *mut sshsk_resident_key;
                                if srk.is_null() {
                                    crate::log::sshlog(
                                        b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                            b"sshsk_load_resident\0",
                                        ))
                                        .as_ptr(),
                                        837 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"calloc failed\0" as *const u8 as *const libc::c_char,
                                    );
                                    r = -(2 as libc::c_int);
                                    current_block = 11059859196351308165;
                                    break;
                                } else {
                                    (*srk).key = key;
                                    key = 0 as *mut sshkey;
                                    (*srk).user_id = calloc(
                                        1 as libc::c_int as libc::c_ulong,
                                        (**rks.offset(i as isize)).user_id_len,
                                    )
                                        as *mut uint8_t;
                                    if ((*srk).user_id).is_null() {
                                        crate::log::sshlog(
                                            b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 20],
                                                &[libc::c_char; 20],
                                            >(
                                                b"sshsk_load_resident\0"
                                            ))
                                            .as_ptr(),
                                            844 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"calloc failed\0" as *const u8 as *const libc::c_char,
                                        );
                                        r = -(2 as libc::c_int);
                                        current_block = 11059859196351308165;
                                        break;
                                    } else {
                                        memcpy(
                                            (*srk).user_id as *mut libc::c_void,
                                            (**rks.offset(i as isize)).user_id
                                                as *const libc::c_void,
                                            (**rks.offset(i as isize)).user_id_len,
                                        );
                                        (*srk).user_id_len = (**rks.offset(i as isize)).user_id_len;
                                        tmp = recallocarray(
                                            srks as *mut libc::c_void,
                                            nsrks,
                                            nsrks.wrapping_add(1 as libc::c_int as libc::c_ulong),
                                            ::core::mem::size_of::<*mut sshsk_resident_key>()
                                                as libc::c_ulong,
                                        )
                                            as *mut *mut sshsk_resident_key;
                                        if tmp.is_null() {
                                            crate::log::sshlog(
                                                b"ssh-sk.c\0" as *const u8 as *const libc::c_char,
                                                (*::core::mem::transmute::<
                                                    &[u8; 20],
                                                    &[libc::c_char; 20],
                                                >(
                                                    b"sshsk_load_resident\0"
                                                ))
                                                .as_ptr(),
                                                852 as libc::c_int,
                                                1 as libc::c_int,
                                                SYSLOG_LEVEL_ERROR,
                                                0 as *const libc::c_char,
                                                b"recallocarray failed\0" as *const u8
                                                    as *const libc::c_char,
                                            );
                                            r = -(2 as libc::c_int);
                                            current_block = 11059859196351308165;
                                            break;
                                        } else {
                                            srks = tmp;
                                            let fresh3 = nsrks;
                                            nsrks = nsrks.wrapping_add(1);
                                            let ref mut fresh4 = *srks.offset(fresh3 as isize);
                                            *fresh4 = srk;
                                            srk = 0 as *mut sshsk_resident_key;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    i = i.wrapping_add(1);
                    i;
                }
                match current_block {
                    11059859196351308165 => {}
                    _ => {
                        *srksp = srks;
                        *nsrksp = nsrks;
                        srks = 0 as *mut *mut sshsk_resident_key;
                        nsrks = 0 as libc::c_int as size_t;
                        r = 0 as libc::c_int;
                    }
                }
            }
        }
    }
    sshsk_free_options(opts);
    sshsk_free(skp);
    sshsk_free_sk_resident_keys(rks, nrks);
    sshkey_free(key);
    sshsk_free_resident_key(srk);
    sshsk_free_resident_keys(srks, nsrks);
    return r;
}
