use ::libc;
extern "C" {

    pub type bignum_st;

    pub type ECDSA_SIG_st;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn BN_clear_free(a: *mut BIGNUM);
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn ECDSA_do_verify(
        dgst: *const libc::c_uchar,
        dgst_len: libc::c_int,
        sig: *const ECDSA_SIG,
        eckey: *mut crate::sshkey::EC_KEY,
    ) -> libc::c_int;
    fn ECDSA_SIG_set0(sig: *mut ECDSA_SIG, r: *mut BIGNUM, s: *mut BIGNUM) -> libc::c_int;
    fn ECDSA_SIG_free(sig: *mut ECDSA_SIG);
    fn ECDSA_SIG_new() -> *mut ECDSA_SIG;

    fn sshbuf_froms(
        buf: *mut crate::sshbuf::sshbuf,
        bufp: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;

    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_putb(buf: *mut crate::sshbuf::sshbuf, v: *const crate::sshbuf::sshbuf)
        -> libc::c_int;

    fn sshbuf_get_bignum2(buf: *mut crate::sshbuf::sshbuf, valp: *mut *mut BIGNUM) -> libc::c_int;
    fn sshbuf_dtourlb64(
        d: *const crate::sshbuf::sshbuf,
        b64: *mut crate::sshbuf::sshbuf,
        wrap: libc::c_int,
    ) -> libc::c_int;
    fn sshbuf_cmp(
        b: *const crate::sshbuf::sshbuf,
        offset: size_t,
        s: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn ssh_digest_memory(
        alg: libc::c_int,
        m: *const libc::c_void,
        mlen: size_t,
        d: *mut u_char,
        dlen: size_t,
    ) -> libc::c_int;
    fn ssh_digest_buffer(
        alg: libc::c_int,
        b: *const crate::sshbuf::sshbuf,
        d: *mut u_char,
        dlen: size_t,
    ) -> libc::c_int;
    fn sshkey_is_cert(_: *const crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn sshkey_sig_details_free(_: *mut sshkey_sig_details);
    fn sshkey_sk_fields_equal(
        a: *const crate::sshkey::sshkey,
        b: *const crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_sk_cleanup(k: *mut crate::sshkey::sshkey);
    fn sshkey_serialize_sk(
        key: *const crate::sshkey::sshkey,
        b: *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshkey_copy_public_sk(
        from: *const crate::sshkey::sshkey,
        to: *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_deserialize_sk(
        b: *mut crate::sshbuf::sshbuf,
        key: *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_serialize_private_sk(
        key: *const crate::sshkey::sshkey,
        buf: *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshkey_private_deserialize_sk(
        buf: *mut crate::sshbuf::sshbuf,
        k: *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    static mut sshkey_ecdsa_funcs: sshkey_impl_funcs;
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
pub type BIGNUM = bignum_st;

pub type ECDSA_SIG = ECDSA_SIG_st;
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
pub struct sshkey_sig_details {
    pub sk_counter: uint32_t,
    pub sk_flags: uint8_t,
}
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
unsafe extern "C" fn ssh_ecdsa_sk_cleanup(mut k: *mut crate::sshkey::sshkey) {
    sshkey_sk_cleanup(k);
    (sshkey_ecdsa_funcs.cleanup).expect("non-null function pointer")(k);
}
unsafe extern "C" fn ssh_ecdsa_sk_equal(
    mut a: *const crate::sshkey::sshkey,
    mut b: *const crate::sshkey::sshkey,
) -> libc::c_int {
    if sshkey_sk_fields_equal(a, b) == 0 {
        return 0 as libc::c_int;
    }
    if (sshkey_ecdsa_funcs.equal).expect("non-null function pointer")(a, b) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ssh_ecdsa_sk_serialize_public(
    mut key: *const crate::sshkey::sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = (sshkey_ecdsa_funcs.serialize_public).expect("non-null function pointer")(key, b, opts);
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshkey_serialize_sk(key, b);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ecdsa_sk_serialize_private(
    mut key: *const crate::sshkey::sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    if sshkey_is_cert(key) == 0 {
        r = (sshkey_ecdsa_funcs.serialize_public).expect("non-null function pointer")(key, b, opts);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    r = sshkey_serialize_private_sk(key, b);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ecdsa_sk_copy_public(
    mut from: *const crate::sshkey::sshkey,
    mut to: *mut crate::sshkey::sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = (sshkey_ecdsa_funcs.copy_public).expect("non-null function pointer")(from, to);
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshkey_copy_public_sk(from, to);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ecdsa_sk_deserialize_public(
    mut ktype: *const libc::c_char,
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut crate::sshkey::sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = (sshkey_ecdsa_funcs.deserialize_public).expect("non-null function pointer")(ktype, b, key);
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshkey_deserialize_sk(b, key);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ecdsa_sk_deserialize_private(
    mut ktype: *const libc::c_char,
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut crate::sshkey::sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    if sshkey_is_cert(key) == 0 {
        r = (sshkey_ecdsa_funcs.deserialize_public).expect("non-null function pointer")(
            ktype, b, key,
        );
        if r != 0 as libc::c_int {
            return r;
        }
    }
    r = sshkey_private_deserialize_sk(b, key);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn webauthn_check_prepare_hash(
    mut data: *const u_char,
    mut datalen: size_t,
    mut origin: *const libc::c_char,
    mut wrapper: *const crate::sshbuf::sshbuf,
    mut flags: uint8_t,
    mut extensions: *const crate::sshbuf::sshbuf,
    mut msghash: *mut u_char,
    mut msghashlen: size_t,
) -> libc::c_int {
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut chall: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() || {
        chall = crate::sshbuf::sshbuf_from(data as *const libc::c_void, datalen);
        chall.is_null()
    } {
        r = -(2 as libc::c_int);
    } else if !(libc::strchr(origin, '"' as i32)).is_null()
        || flags as libc::c_int & 0x40 as libc::c_int != 0 as libc::c_int
        || (flags as libc::c_int & 0x80 as libc::c_int == 0 as libc::c_int) as libc::c_int
            != (crate::sshbuf::sshbuf_len(extensions) == 0 as libc::c_int as libc::c_ulong)
                as libc::c_int
    {
        r = -(4 as libc::c_int);
    } else {
        r = sshbuf_put(
            m,
            b"{\"type\":\"webauthn.get\",\"challenge\":\"\0" as *const u8 as *const libc::c_char
                as *const libc::c_void,
            (::core::mem::size_of::<[libc::c_char; 37]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
        if !(r != 0 as libc::c_int
            || {
                r = sshbuf_dtourlb64(chall, m, 0 as libc::c_int);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put(
                    m,
                    b"\",\"origin\":\"\0" as *const u8 as *const libc::c_char
                        as *const libc::c_void,
                    (::core::mem::size_of::<[libc::c_char; 13]>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                );
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put(m, origin as *const libc::c_void, strlen(origin));
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put(
                    m,
                    b"\"\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                    (::core::mem::size_of::<[libc::c_char; 2]>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                );
                r != 0 as libc::c_int
            })
        {
            r = sshbuf_cmp(
                wrapper,
                0 as libc::c_int as size_t,
                crate::sshbuf::sshbuf_ptr(m) as *const libc::c_void,
                crate::sshbuf::sshbuf_len(m),
            );
            if !(r != 0 as libc::c_int) {
                r = ssh_digest_buffer(2 as libc::c_int, wrapper, msghash, msghashlen);
                if !(r != 0 as libc::c_int) {
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    crate::sshbuf::sshbuf_free(chall);
    crate::sshbuf::sshbuf_free(m);
    return r;
}
unsafe extern "C" fn ssh_ecdsa_sk_verify(
    mut key: *const crate::sshkey::sshkey,
    mut sig: *const u_char,
    mut siglen: size_t,
    mut data: *const u_char,
    mut dlen: size_t,
    mut _alg: *const libc::c_char,
    mut _compat: u_int,
    mut detailsp: *mut *mut sshkey_sig_details,
) -> libc::c_int {
    let mut current_block: u64;
    let mut esig: *mut ECDSA_SIG = 0 as *mut ECDSA_SIG;
    let mut sig_r: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut sig_s: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut sig_flags: u_char = 0;
    let mut msghash: [u_char; 32] = [0; 32];
    let mut apphash: [u_char; 32] = [0; 32];
    let mut sighash: [u_char; 32] = [0; 32];
    let mut sig_counter: u_int = 0;
    let mut is_webauthn: libc::c_int = 0 as libc::c_int;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sigbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut original_signed: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut webauthn_wrapper: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut webauthn_exts: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut ktype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut webauthn_origin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut details: *mut sshkey_sig_details = 0 as *mut sshkey_sig_details;
    if !detailsp.is_null() {
        *detailsp = 0 as *mut sshkey_sig_details;
    }
    if key.is_null()
        || ((*key).ecdsa).is_null()
        || sshkey_type_plain((*key).type_0) != KEY_ECDSA_SK as libc::c_int
        || sig.is_null()
        || siglen == 0 as libc::c_int as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    if (*key).ecdsa_nid != 415 as libc::c_int {
        return -(1 as libc::c_int);
    }
    b = crate::sshbuf::sshbuf_from(sig as *const libc::c_void, siglen);
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    details = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<sshkey_sig_details>() as libc::c_ulong,
    ) as *mut sshkey_sig_details;
    if details.is_null() {
        ret = -(2 as libc::c_int);
    } else if crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut ktype, 0 as *mut size_t)
        != 0 as libc::c_int
    {
        ret = -(4 as libc::c_int);
    } else {
        if libc::strcmp(
            ktype,
            b"webauthn-sk-ecdsa-sha2-nistp256@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            is_webauthn = 1 as libc::c_int;
            current_block = 4956146061682418353;
        } else if libc::strcmp(
            ktype,
            b"sk-ecdsa-sha2-nistp256@openssh.com\0" as *const u8 as *const libc::c_char,
        ) != 0 as libc::c_int
        {
            ret = -(4 as libc::c_int);
            current_block = 3245404841433849185;
        } else {
            current_block = 4956146061682418353;
        }
        match current_block {
            3245404841433849185 => {}
            _ => {
                if sshbuf_froms(b, &mut sigbuf) != 0 as libc::c_int
                    || crate::sshbuf_getput_basic::sshbuf_get_u8(b, &mut sig_flags)
                        != 0 as libc::c_int
                    || crate::sshbuf_getput_basic::sshbuf_get_u32(b, &mut sig_counter)
                        != 0 as libc::c_int
                {
                    ret = -(4 as libc::c_int);
                } else {
                    if is_webauthn != 0 {
                        if crate::sshbuf_getput_basic::sshbuf_get_cstring(
                            b,
                            &mut webauthn_origin,
                            0 as *mut size_t,
                        ) != 0 as libc::c_int
                            || sshbuf_froms(b, &mut webauthn_wrapper) != 0 as libc::c_int
                            || sshbuf_froms(b, &mut webauthn_exts) != 0 as libc::c_int
                        {
                            ret = -(4 as libc::c_int);
                            current_block = 3245404841433849185;
                        } else {
                            current_block = 14576567515993809846;
                        }
                    } else {
                        current_block = 14576567515993809846;
                    }
                    match current_block {
                        3245404841433849185 => {}
                        _ => {
                            if crate::sshbuf::sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong {
                                ret = -(23 as libc::c_int);
                            } else if sshbuf_get_bignum2(sigbuf, &mut sig_r) != 0 as libc::c_int
                                || sshbuf_get_bignum2(sigbuf, &mut sig_s) != 0 as libc::c_int
                            {
                                ret = -(4 as libc::c_int);
                            } else if crate::sshbuf::sshbuf_len(sigbuf)
                                != 0 as libc::c_int as libc::c_ulong
                            {
                                ret = -(23 as libc::c_int);
                            } else {
                                esig = ECDSA_SIG_new();
                                if esig.is_null() {
                                    ret = -(2 as libc::c_int);
                                } else if ECDSA_SIG_set0(esig, sig_r, sig_s) == 0 {
                                    ret = -(22 as libc::c_int);
                                } else {
                                    sig_s = 0 as *mut BIGNUM;
                                    sig_r = sig_s;
                                    original_signed = crate::sshbuf::sshbuf_new();
                                    if original_signed.is_null() {
                                        ret = -(2 as libc::c_int);
                                    } else {
                                        if is_webauthn != 0 {
                                            ret = webauthn_check_prepare_hash(
                                                data,
                                                dlen,
                                                webauthn_origin,
                                                webauthn_wrapper,
                                                sig_flags,
                                                webauthn_exts,
                                                msghash.as_mut_ptr(),
                                                ::core::mem::size_of::<[u_char; 32]>()
                                                    as libc::c_ulong,
                                            );
                                            if ret != 0 as libc::c_int {
                                                current_block = 3245404841433849185;
                                            } else {
                                                current_block = 7746103178988627676;
                                            }
                                        } else {
                                            ret = ssh_digest_memory(
                                                2 as libc::c_int,
                                                data as *const libc::c_void,
                                                dlen,
                                                msghash.as_mut_ptr(),
                                                ::core::mem::size_of::<[u_char; 32]>()
                                                    as libc::c_ulong,
                                            );
                                            if ret != 0 as libc::c_int {
                                                current_block = 3245404841433849185;
                                            } else {
                                                current_block = 7746103178988627676;
                                            }
                                        }
                                        match current_block {
                                            3245404841433849185 => {}
                                            _ => {
                                                ret = ssh_digest_memory(
                                                    2 as libc::c_int,
                                                    (*key).sk_application as *const libc::c_void,
                                                    strlen((*key).sk_application),
                                                    apphash.as_mut_ptr(),
                                                    ::core::mem::size_of::<[u_char; 32]>()
                                                        as libc::c_ulong,
                                                );
                                                if !(ret != 0 as libc::c_int) {
                                                    ret = sshbuf_put(
                                                        original_signed,
                                                        apphash.as_mut_ptr() as *const libc::c_void,
                                                        ::core::mem::size_of::<[u_char; 32]>()
                                                            as libc::c_ulong,
                                                    );
                                                    if !(ret != 0 as libc::c_int
                                                        || {
                                                            ret = crate::sshbuf_getput_basic::sshbuf_put_u8(
                                                                original_signed,
                                                                sig_flags,
                                                            );
                                                            ret != 0 as libc::c_int
                                                        }
                                                        || {
                                                            ret = crate::sshbuf_getput_basic::sshbuf_put_u32(
                                                                original_signed,
                                                                sig_counter,
                                                            );
                                                            ret != 0 as libc::c_int
                                                        }
                                                        || {
                                                            ret = sshbuf_putb(
                                                                original_signed,
                                                                webauthn_exts,
                                                            );
                                                            ret != 0 as libc::c_int
                                                        }
                                                        || {
                                                            ret = sshbuf_put(
                                                                original_signed,
                                                                msghash.as_mut_ptr()
                                                                    as *const libc::c_void,
                                                                ::core::mem::size_of::<[u_char; 32]>(
                                                                )
                                                                    as libc::c_ulong,
                                                            );
                                                            ret != 0 as libc::c_int
                                                        })
                                                    {
                                                        ret = ssh_digest_buffer(
                                                            2 as libc::c_int,
                                                            original_signed,
                                                            sighash.as_mut_ptr(),
                                                            ::core::mem::size_of::<[u_char; 32]>()
                                                                as libc::c_ulong,
                                                        );
                                                        if !(ret != 0 as libc::c_int) {
                                                            (*details).sk_counter = sig_counter;
                                                            (*details).sk_flags = sig_flags;
                                                            match ECDSA_do_verify(
                                                                sighash.as_mut_ptr(),
                                                                ::core::mem::size_of::<[u_char; 32]>(
                                                                )
                                                                    as libc::c_ulong
                                                                    as libc::c_int,
                                                                esig,
                                                                (*key).ecdsa,
                                                            ) {
                                                                1 => {
                                                                    ret = 0 as libc::c_int;
                                                                    if !detailsp.is_null() {
                                                                        *detailsp = details;
                                                                        details = 0 as *mut sshkey_sig_details;
                                                                    }
                                                                }
                                                                0 => {
                                                                    ret = -(21 as libc::c_int);
                                                                }
                                                                _ => {
                                                                    ret = -(22 as libc::c_int);
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
                        }
                    }
                }
            }
        }
    }
    explicit_bzero(
        &mut sig_flags as *mut u_char as *mut libc::c_void,
        ::core::mem::size_of::<u_char>() as libc::c_ulong,
    );
    explicit_bzero(
        &mut sig_counter as *mut u_int as *mut libc::c_void,
        ::core::mem::size_of::<u_int>() as libc::c_ulong,
    );
    explicit_bzero(
        msghash.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
    );
    explicit_bzero(
        sighash.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
    );
    explicit_bzero(
        apphash.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
    );
    sshkey_sig_details_free(details);
    crate::sshbuf::sshbuf_free(webauthn_wrapper);
    crate::sshbuf::sshbuf_free(webauthn_exts);
    libc::free(webauthn_origin as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(original_signed);
    crate::sshbuf::sshbuf_free(sigbuf);
    crate::sshbuf::sshbuf_free(b);
    ECDSA_SIG_free(esig);
    BN_clear_free(sig_r);
    BN_clear_free(sig_s);
    libc::free(ktype as *mut libc::c_void);
    return ret;
}
static mut sshkey_ecdsa_sk_funcs: sshkey_impl_funcs = unsafe {
    {
        let mut init = sshkey_impl_funcs {
            size: None,
            alloc: None,
            cleanup: Some(
                ssh_ecdsa_sk_cleanup as unsafe extern "C" fn(*mut crate::sshkey::sshkey) -> (),
            ),
            equal: Some(
                ssh_ecdsa_sk_equal
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
                        *const crate::sshkey::sshkey,
                    ) -> libc::c_int,
            ),
            serialize_public: Some(
                ssh_ecdsa_sk_serialize_public
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
                        *mut crate::sshbuf::sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_public: Some(
                ssh_ecdsa_sk_deserialize_public
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut crate::sshbuf::sshbuf,
                        *mut crate::sshkey::sshkey,
                    ) -> libc::c_int,
            ),
            serialize_private: Some(
                ssh_ecdsa_sk_serialize_private
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
                        *mut crate::sshbuf::sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_private: Some(
                ssh_ecdsa_sk_deserialize_private
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut crate::sshbuf::sshbuf,
                        *mut crate::sshkey::sshkey,
                    ) -> libc::c_int,
            ),
            generate: None,
            copy_public: Some(
                ssh_ecdsa_sk_copy_public
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
                        *mut crate::sshkey::sshkey,
                    ) -> libc::c_int,
            ),
            sign: None,
            verify: Some(
                ssh_ecdsa_sk_verify
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
pub static mut sshkey_ecdsa_sk_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"sk-ecdsa-sha2-nistp256@openssh.com\0" as *const u8 as *const libc::c_char,
            shortname: b"ECDSA-SK\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ECDSA_SK as libc::c_int,
            nid: 415 as libc::c_int,
            cert: 0 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 256 as libc::c_int,
            funcs: &sshkey_ecdsa_sk_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_ecdsa_sk_cert_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com\0" as *const u8
                as *const libc::c_char,
            shortname: b"ECDSA-SK-CERT\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ECDSA_SK_CERT as libc::c_int,
            nid: 415 as libc::c_int,
            cert: 1 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 256 as libc::c_int,
            funcs: &sshkey_ecdsa_sk_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_ecdsa_sk_webauthn_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"webauthn-sk-ecdsa-sha2-nistp256@openssh.com\0" as *const u8
                as *const libc::c_char,
            shortname: b"ECDSA-SK\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ECDSA_SK as libc::c_int,
            nid: 415 as libc::c_int,
            cert: 0 as libc::c_int,
            sigonly: 1 as libc::c_int,
            keybits: 256 as libc::c_int,
            funcs: &sshkey_ecdsa_sk_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
