use ::libc;
extern "C" {

    pub type bignum_st;
    pub type bignum_ctx;
    pub type bn_gencb_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    fn timingsafe_bcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;
    fn freezero(_: *mut libc::c_void, _: size_t);

    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;

    fn BN_set_flags(b: *mut BIGNUM, n: libc::c_int);
    fn BN_value_one() -> *const BIGNUM;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(c: *mut BN_CTX);
    fn BN_num_bits(a: *const BIGNUM) -> libc::c_int;
    fn BN_new() -> *mut BIGNUM;
    fn BN_clear_free(a: *mut BIGNUM);
    fn BN_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_div(
        dv: *mut BIGNUM,
        rem: *mut BIGNUM,
        m: *const BIGNUM,
        d: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_set_word(a: *mut BIGNUM, w: libc::c_ulong) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_free(a: *mut BIGNUM);
    fn BN_dup(a: *const BIGNUM) -> *mut BIGNUM;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
        -> *mut libc::c_void;

    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn sshbuf_from(blob: *const libc::c_void, len: size_t) -> *mut crate::sshbuf::sshbuf;

    fn sshbuf_put_bignum2(buf: *mut crate::sshbuf::sshbuf, v: *const BIGNUM) -> libc::c_int;
    fn sshbuf_get_bignum2(buf: *mut crate::sshbuf::sshbuf, valp: *mut *mut BIGNUM) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut crate::sshbuf::sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_string(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_string(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn RSA_new() -> *mut RSA;
    fn RSA_size(rsa: *const RSA) -> libc::c_int;
    fn RSA_set0_key(r: *mut RSA, n: *mut BIGNUM, e: *mut BIGNUM, d: *mut BIGNUM) -> libc::c_int;
    fn RSA_set0_factors(r: *mut RSA, p: *mut BIGNUM, q: *mut BIGNUM) -> libc::c_int;
    fn RSA_set0_crt_params(
        r: *mut RSA,
        dmp1: *mut BIGNUM,
        dmq1: *mut BIGNUM,
        iqmp: *mut BIGNUM,
    ) -> libc::c_int;
    fn RSA_get0_key(
        r: *const RSA,
        n: *mut *const BIGNUM,
        e: *mut *const BIGNUM,
        d: *mut *const BIGNUM,
    );
    fn RSA_get0_factors(r: *const RSA, p: *mut *const BIGNUM, q: *mut *const BIGNUM);
    fn RSA_get0_crt_params(
        r: *const RSA,
        dmp1: *mut *const BIGNUM,
        dmq1: *mut *const BIGNUM,
        iqmp: *mut *const BIGNUM,
    );
    fn RSA_generate_key_ex(
        rsa: *mut RSA,
        bits: libc::c_int,
        e: *mut BIGNUM,
        cb: *mut BN_GENCB,
    ) -> libc::c_int;
    fn RSA_public_decrypt(
        flen: libc::c_int,
        from: *const libc::c_uchar,
        to: *mut libc::c_uchar,
        rsa: *mut RSA,
        padding: libc::c_int,
    ) -> libc::c_int;
    fn RSA_free(r: *mut RSA);
    fn RSA_sign(
        type_0: libc::c_int,
        m: *const libc::c_uchar,
        m_length: libc::c_uint,
        sigret: *mut libc::c_uchar,
        siglen: *mut libc::c_uint,
        rsa: *mut RSA,
    ) -> libc::c_int;
    fn RSA_blinding_on(rsa: *mut RSA, ctx: *mut BN_CTX) -> libc::c_int;
    fn sshkey_is_cert(_: *const sshkey) -> libc::c_int;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn sshkey_check_rsa_length(_: *const sshkey, _: libc::c_int) -> libc::c_int;
    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_digest_memory(
        alg: libc::c_int,
        m: *const libc::c_void,
        mlen: size_t,
        d: *mut u_char,
        dlen: size_t,
    ) -> libc::c_int;
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
pub type BIGNUM = bignum_st;
pub type BN_CTX = bignum_ctx;
pub type BN_GENCB = bn_gencb_st;
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
unsafe extern "C" fn ssh_rsa_size(mut key: *const sshkey) -> u_int {
    let mut rsa_n: *const BIGNUM = 0 as *const BIGNUM;
    if ((*key).rsa).is_null() {
        return 0 as libc::c_int as u_int;
    }
    RSA_get0_key(
        (*key).rsa,
        &mut rsa_n,
        0 as *mut *const BIGNUM,
        0 as *mut *const BIGNUM,
    );
    return BN_num_bits(rsa_n) as u_int;
}
unsafe extern "C" fn ssh_rsa_alloc(mut k: *mut sshkey) -> libc::c_int {
    (*k).rsa = RSA_new();
    if ((*k).rsa).is_null() {
        return -(2 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_rsa_cleanup(mut k: *mut sshkey) {
    RSA_free((*k).rsa);
    (*k).rsa = 0 as *mut RSA;
}
unsafe extern "C" fn ssh_rsa_equal(mut a: *const sshkey, mut b: *const sshkey) -> libc::c_int {
    let mut rsa_e_a: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_n_a: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_e_b: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_n_b: *const BIGNUM = 0 as *const BIGNUM;
    if ((*a).rsa).is_null() || ((*b).rsa).is_null() {
        return 0 as libc::c_int;
    }
    RSA_get0_key(
        (*a).rsa,
        &mut rsa_n_a,
        &mut rsa_e_a,
        0 as *mut *const BIGNUM,
    );
    RSA_get0_key(
        (*b).rsa,
        &mut rsa_n_b,
        &mut rsa_e_b,
        0 as *mut *const BIGNUM,
    );
    if rsa_e_a.is_null() || rsa_e_b.is_null() {
        return 0 as libc::c_int;
    }
    if rsa_n_a.is_null() || rsa_n_b.is_null() {
        return 0 as libc::c_int;
    }
    if BN_cmp(rsa_e_a, rsa_e_b) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if BN_cmp(rsa_n_a, rsa_n_b) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ssh_rsa_serialize_public(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut _opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut rsa_n: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_e: *const BIGNUM = 0 as *const BIGNUM;
    if ((*key).rsa).is_null() {
        return -(10 as libc::c_int);
    }
    RSA_get0_key((*key).rsa, &mut rsa_n, &mut rsa_e, 0 as *mut *const BIGNUM);
    r = sshbuf_put_bignum2(b, rsa_e);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_bignum2(b, rsa_n);
        r != 0 as libc::c_int
    } {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_rsa_serialize_private(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut _opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut rsa_n: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_e: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_d: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_iqmp: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_p: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_q: *const BIGNUM = 0 as *const BIGNUM;
    RSA_get0_key((*key).rsa, &mut rsa_n, &mut rsa_e, &mut rsa_d);
    RSA_get0_factors((*key).rsa, &mut rsa_p, &mut rsa_q);
    RSA_get0_crt_params(
        (*key).rsa,
        0 as *mut *const BIGNUM,
        0 as *mut *const BIGNUM,
        &mut rsa_iqmp,
    );
    if sshkey_is_cert(key) == 0 {
        r = sshbuf_put_bignum2(b, rsa_n);
        if r != 0 as libc::c_int || {
            r = sshbuf_put_bignum2(b, rsa_e);
            r != 0 as libc::c_int
        } {
            return r;
        }
    }
    r = sshbuf_put_bignum2(b, rsa_d);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_bignum2(b, rsa_iqmp);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_bignum2(b, rsa_p);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_bignum2(b, rsa_q);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_rsa_generate(mut k: *mut sshkey, mut bits: libc::c_int) -> libc::c_int {
    let mut private: *mut RSA = 0 as *mut RSA;
    let mut f4: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if bits < 1024 as libc::c_int
        || bits > 16384 as libc::c_int / 8 as libc::c_int * 8 as libc::c_int
    {
        return -(56 as libc::c_int);
    }
    private = RSA_new();
    if private.is_null() || {
        f4 = BN_new();
        f4.is_null()
    } {
        ret = -(2 as libc::c_int);
    } else if BN_set_word(f4, 0x10001 as libc::c_long as libc::c_ulong) == 0
        || RSA_generate_key_ex(private, bits, f4, 0 as *mut BN_GENCB) == 0
    {
        ret = -(22 as libc::c_int);
    } else {
        (*k).rsa = private;
        private = 0 as *mut RSA;
        ret = 0 as libc::c_int;
    }
    RSA_free(private);
    BN_free(f4);
    return ret;
}
unsafe extern "C" fn ssh_rsa_copy_public(
    mut from: *const sshkey,
    mut to: *mut sshkey,
) -> libc::c_int {
    let mut rsa_n: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_e: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_n_dup: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_e_dup: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut r: libc::c_int = -(1 as libc::c_int);
    RSA_get0_key((*from).rsa, &mut rsa_n, &mut rsa_e, 0 as *mut *const BIGNUM);
    rsa_n_dup = BN_dup(rsa_n);
    if rsa_n_dup.is_null() || {
        rsa_e_dup = BN_dup(rsa_e);
        rsa_e_dup.is_null()
    } {
        r = -(2 as libc::c_int);
    } else if RSA_set0_key((*to).rsa, rsa_n_dup, rsa_e_dup, 0 as *mut BIGNUM) == 0 {
        r = -(22 as libc::c_int);
    } else {
        rsa_e_dup = 0 as *mut BIGNUM;
        rsa_n_dup = rsa_e_dup;
        r = 0 as libc::c_int;
    }
    BN_clear_free(rsa_n_dup);
    BN_clear_free(rsa_e_dup);
    return r;
}
unsafe extern "C" fn ssh_rsa_deserialize_public(
    mut _ktype: *const libc::c_char,
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut sshkey,
) -> libc::c_int {
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut rsa_n: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_e: *mut BIGNUM = 0 as *mut BIGNUM;
    if sshbuf_get_bignum2(b, &mut rsa_e) != 0 as libc::c_int
        || sshbuf_get_bignum2(b, &mut rsa_n) != 0 as libc::c_int
    {
        ret = -(4 as libc::c_int);
    } else if RSA_set0_key((*key).rsa, rsa_n, rsa_e, 0 as *mut BIGNUM) == 0 {
        ret = -(22 as libc::c_int);
    } else {
        rsa_e = 0 as *mut BIGNUM;
        rsa_n = rsa_e;
        ret = sshkey_check_rsa_length(key, 0 as libc::c_int);
        if !(ret != 0 as libc::c_int) {
            ret = 0 as libc::c_int;
        }
    }
    BN_clear_free(rsa_n);
    BN_clear_free(rsa_e);
    return ret;
}
unsafe extern "C" fn ssh_rsa_deserialize_private(
    mut _ktype: *const libc::c_char,
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut sshkey,
) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = 0;
    let mut rsa_n: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_e: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_d: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_iqmp: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_p: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_q: *mut BIGNUM = 0 as *mut BIGNUM;
    if sshkey_is_cert(key) == 0 {
        r = sshbuf_get_bignum2(b, &mut rsa_n);
        if r != 0 as libc::c_int || {
            r = sshbuf_get_bignum2(b, &mut rsa_e);
            r != 0 as libc::c_int
        } {
            current_block = 13231491915535713422;
        } else if RSA_set0_key((*key).rsa, rsa_n, rsa_e, 0 as *mut BIGNUM) == 0 {
            r = -(22 as libc::c_int);
            current_block = 13231491915535713422;
        } else {
            rsa_e = 0 as *mut BIGNUM;
            rsa_n = rsa_e;
            current_block = 11875828834189669668;
        }
    } else {
        current_block = 11875828834189669668;
    }
    match current_block {
        11875828834189669668 => {
            r = sshbuf_get_bignum2(b, &mut rsa_d);
            if !(r != 0 as libc::c_int
                || {
                    r = sshbuf_get_bignum2(b, &mut rsa_iqmp);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_get_bignum2(b, &mut rsa_p);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_get_bignum2(b, &mut rsa_q);
                    r != 0 as libc::c_int
                })
            {
                if RSA_set0_key((*key).rsa, 0 as *mut BIGNUM, 0 as *mut BIGNUM, rsa_d) == 0 {
                    r = -(22 as libc::c_int);
                } else {
                    rsa_d = 0 as *mut BIGNUM;
                    if RSA_set0_factors((*key).rsa, rsa_p, rsa_q) == 0 {
                        r = -(22 as libc::c_int);
                    } else {
                        rsa_q = 0 as *mut BIGNUM;
                        rsa_p = rsa_q;
                        r = sshkey_check_rsa_length(key, 0 as libc::c_int);
                        if !(r != 0 as libc::c_int) {
                            r = ssh_rsa_complete_crt_parameters(key, rsa_iqmp);
                            if !(r != 0 as libc::c_int) {
                                if RSA_blinding_on((*key).rsa, 0 as *mut BN_CTX) != 1 as libc::c_int
                                {
                                    r = -(22 as libc::c_int);
                                } else {
                                    r = 0 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    BN_clear_free(rsa_n);
    BN_clear_free(rsa_e);
    BN_clear_free(rsa_d);
    BN_clear_free(rsa_p);
    BN_clear_free(rsa_q);
    BN_clear_free(rsa_iqmp);
    return r;
}
unsafe extern "C" fn rsa_hash_alg_ident(mut hash_alg: libc::c_int) -> *const libc::c_char {
    match hash_alg {
        1 => return b"ssh-rsa\0" as *const u8 as *const libc::c_char,
        2 => return b"rsa-sha2-256\0" as *const u8 as *const libc::c_char,
        4 => return b"rsa-sha2-512\0" as *const u8 as *const libc::c_char,
        _ => {}
    }
    return 0 as *const libc::c_char;
}
unsafe extern "C" fn rsa_hash_id_from_ident(mut ident: *const libc::c_char) -> libc::c_int {
    if libc::strcmp(ident, b"ssh-rsa\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    if libc::strcmp(ident, b"rsa-sha2-256\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        return 2 as libc::c_int;
    }
    if libc::strcmp(ident, b"rsa-sha2-512\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        return 4 as libc::c_int;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn rsa_hash_id_from_keyname(mut alg: *const libc::c_char) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = rsa_hash_id_from_ident(alg);
    if r != -(1 as libc::c_int) {
        return r;
    }
    if libc::strcmp(
        alg,
        b"ssh-rsa-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        return 1 as libc::c_int;
    }
    if libc::strcmp(
        alg,
        b"rsa-sha2-256-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        return 2 as libc::c_int;
    }
    if libc::strcmp(
        alg,
        b"rsa-sha2-512-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        return 4 as libc::c_int;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn rsa_hash_alg_nid(mut type_0: libc::c_int) -> libc::c_int {
    match type_0 {
        1 => return 64 as libc::c_int,
        2 => return 672 as libc::c_int,
        4 => return 674 as libc::c_int,
        _ => return -(1 as libc::c_int),
    };
}
pub unsafe extern "C" fn ssh_rsa_complete_crt_parameters(
    mut key: *mut sshkey,
    mut iqmp: *const BIGNUM,
) -> libc::c_int {
    let mut rsa_p: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_q: *const BIGNUM = 0 as *const BIGNUM;
    let mut rsa_d: *const BIGNUM = 0 as *const BIGNUM;
    let mut aux: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut d_consttime: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_dmq1: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_dmp1: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_iqmp: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    let mut r: libc::c_int = 0;
    if key.is_null()
        || ((*key).rsa).is_null()
        || sshkey_type_plain((*key).type_0) != KEY_RSA as libc::c_int
    {
        return -(10 as libc::c_int);
    }
    RSA_get0_key(
        (*key).rsa,
        0 as *mut *const BIGNUM,
        0 as *mut *const BIGNUM,
        &mut rsa_d,
    );
    RSA_get0_factors((*key).rsa, &mut rsa_p, &mut rsa_q);
    ctx = BN_CTX_new();
    if ctx.is_null() {
        return -(2 as libc::c_int);
    }
    aux = BN_new();
    if aux.is_null()
        || {
            rsa_dmq1 = BN_new();
            rsa_dmq1.is_null()
        }
        || {
            rsa_dmp1 = BN_new();
            rsa_dmp1.is_null()
        }
    {
        return -(2 as libc::c_int);
    }
    d_consttime = BN_dup(rsa_d);
    if d_consttime.is_null() || {
        rsa_iqmp = BN_dup(iqmp);
        rsa_iqmp.is_null()
    } {
        r = -(2 as libc::c_int);
    } else {
        BN_set_flags(aux, 0x4 as libc::c_int);
        BN_set_flags(d_consttime, 0x4 as libc::c_int);
        if BN_sub(aux, rsa_q, BN_value_one()) == 0 as libc::c_int
            || BN_div(0 as *mut BIGNUM, rsa_dmq1, d_consttime, aux, ctx) == 0 as libc::c_int
            || BN_sub(aux, rsa_p, BN_value_one()) == 0 as libc::c_int
            || BN_div(0 as *mut BIGNUM, rsa_dmp1, d_consttime, aux, ctx) == 0 as libc::c_int
        {
            r = -(22 as libc::c_int);
        } else if RSA_set0_crt_params((*key).rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp) == 0 {
            r = -(22 as libc::c_int);
        } else {
            rsa_iqmp = 0 as *mut BIGNUM;
            rsa_dmq1 = rsa_iqmp;
            rsa_dmp1 = rsa_dmq1;
            r = 0 as libc::c_int;
        }
    }
    BN_clear_free(aux);
    BN_clear_free(d_consttime);
    BN_clear_free(rsa_dmp1);
    BN_clear_free(rsa_dmq1);
    BN_clear_free(rsa_iqmp);
    BN_CTX_free(ctx);
    return r;
}
unsafe extern "C" fn ssh_rsa_sign(
    mut key: *mut sshkey,
    mut sigp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut data: *const u_char,
    mut datalen: size_t,
    mut alg: *const libc::c_char,
    mut _sk_provider: *const libc::c_char,
    mut _sk_pin: *const libc::c_char,
    mut _compat: u_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut rsa_n: *const BIGNUM = 0 as *const BIGNUM;
    let mut digest: [u_char; 64] = [0; 64];
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut slen: size_t = 0 as libc::c_int as size_t;
    let mut hlen: u_int = 0;
    let mut len: u_int = 0;
    let mut nid: libc::c_int = 0;
    let mut hash_alg: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    if !lenp.is_null() {
        *lenp = 0 as libc::c_int as size_t;
    }
    if !sigp.is_null() {
        *sigp = 0 as *mut u_char;
    }
    if alg.is_null() || strlen(alg) == 0 as libc::c_int as libc::c_ulong {
        hash_alg = 1 as libc::c_int;
    } else {
        hash_alg = rsa_hash_id_from_keyname(alg);
    }
    if key.is_null()
        || ((*key).rsa).is_null()
        || hash_alg == -(1 as libc::c_int)
        || sshkey_type_plain((*key).type_0) != KEY_RSA as libc::c_int
    {
        return -(10 as libc::c_int);
    }
    RSA_get0_key(
        (*key).rsa,
        &mut rsa_n,
        0 as *mut *const BIGNUM,
        0 as *mut *const BIGNUM,
    );
    if BN_num_bits(rsa_n) < 1024 as libc::c_int {
        return -(56 as libc::c_int);
    }
    slen = RSA_size((*key).rsa) as size_t;
    if slen <= 0 as libc::c_int as libc::c_ulong
        || slen > (16384 as libc::c_int / 8 as libc::c_int) as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    nid = rsa_hash_alg_nid(hash_alg);
    hlen = ssh_digest_bytes(hash_alg) as u_int;
    if hlen == 0 as libc::c_int as libc::c_uint {
        return -(1 as libc::c_int);
    }
    ret = ssh_digest_memory(
        hash_alg,
        data as *const libc::c_void,
        datalen,
        digest.as_mut_ptr(),
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    if !(ret != 0 as libc::c_int) {
        sig = libc::malloc(slen as usize) as *mut u_char;
        if sig.is_null() {
            ret = -(2 as libc::c_int);
        } else if RSA_sign(nid, digest.as_mut_ptr(), hlen, sig, &mut len, (*key).rsa)
            != 1 as libc::c_int
        {
            ret = -(22 as libc::c_int);
        } else {
            if (len as libc::c_ulong) < slen {
                let mut diff: size_t = slen.wrapping_sub(len as libc::c_ulong);
                memmove(
                    sig.offset(diff as isize) as *mut libc::c_void,
                    sig as *const libc::c_void,
                    len as libc::c_ulong,
                );
                explicit_bzero(sig as *mut libc::c_void, diff);
                current_block = 7172762164747879670;
            } else if len as libc::c_ulong > slen {
                ret = -(1 as libc::c_int);
                current_block = 14398652845524645006;
            } else {
                current_block = 7172762164747879670;
            }
            match current_block {
                14398652845524645006 => {}
                _ => {
                    b = crate::sshbuf::sshbuf_new();
                    if b.is_null() {
                        ret = -(2 as libc::c_int);
                    } else {
                        ret = sshbuf_put_cstring(b, rsa_hash_alg_ident(hash_alg));
                        if !(ret != 0 as libc::c_int || {
                            ret = sshbuf_put_string(b, sig as *const libc::c_void, slen);
                            ret != 0 as libc::c_int
                        }) {
                            len = crate::sshbuf::sshbuf_len(b) as u_int;
                            if !sigp.is_null() {
                                *sigp = libc::malloc(len as usize) as *mut u_char;
                                if (*sigp).is_null() {
                                    ret = -(2 as libc::c_int);
                                    current_block = 14398652845524645006;
                                } else {
                                    memcpy(
                                        *sigp as *mut libc::c_void,
                                        crate::sshbuf::sshbuf_ptr(b) as *const libc::c_void,
                                        len as libc::c_ulong,
                                    );
                                    current_block = 17500079516916021833;
                                }
                            } else {
                                current_block = 17500079516916021833;
                            }
                            match current_block {
                                14398652845524645006 => {}
                                _ => {
                                    if !lenp.is_null() {
                                        *lenp = len as size_t;
                                    }
                                    ret = 0 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    explicit_bzero(
        digest.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    freezero(sig as *mut libc::c_void, slen);
    crate::sshbuf::sshbuf_free(b);
    return ret;
}
unsafe extern "C" fn ssh_rsa_verify(
    mut key: *const sshkey,
    mut sig: *const u_char,
    mut siglen: size_t,
    mut data: *const u_char,
    mut dlen: size_t,
    mut alg: *const libc::c_char,
    mut _compat: u_int,
    mut _detailsp: *mut *mut sshkey_sig_details,
) -> libc::c_int {
    let mut current_block: u64;
    let mut rsa_n: *const BIGNUM = 0 as *const BIGNUM;
    let mut sigtype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hash_alg: libc::c_int = 0;
    let mut want_alg: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut len: size_t = 0 as libc::c_int as size_t;
    let mut diff: size_t = 0;
    let mut modlen: size_t = 0;
    let mut hlen: size_t = 0;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut digest: [u_char; 64] = [0; 64];
    let mut osigblob: *mut u_char = 0 as *mut u_char;
    let mut sigblob: *mut u_char = 0 as *mut u_char;
    if key.is_null()
        || ((*key).rsa).is_null()
        || sshkey_type_plain((*key).type_0) != KEY_RSA as libc::c_int
        || sig.is_null()
        || siglen == 0 as libc::c_int as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    RSA_get0_key(
        (*key).rsa,
        &mut rsa_n,
        0 as *mut *const BIGNUM,
        0 as *mut *const BIGNUM,
    );
    if BN_num_bits(rsa_n) < 1024 as libc::c_int {
        return -(56 as libc::c_int);
    }
    b = sshbuf_from(sig as *const libc::c_void, siglen);
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    if sshbuf_get_cstring(b, &mut sigtype, 0 as *mut size_t) != 0 as libc::c_int {
        ret = -(4 as libc::c_int);
    } else {
        hash_alg = rsa_hash_id_from_ident(sigtype);
        if hash_alg == -(1 as libc::c_int) {
            ret = -(13 as libc::c_int);
        } else {
            if !alg.is_null()
                && libc::strcmp(
                    alg,
                    b"ssh-rsa-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
                ) != 0 as libc::c_int
            {
                want_alg = rsa_hash_id_from_keyname(alg);
                if want_alg == -(1 as libc::c_int) {
                    ret = -(10 as libc::c_int);
                    current_block = 17539625483582710546;
                } else if hash_alg != want_alg {
                    ret = -(21 as libc::c_int);
                    current_block = 17539625483582710546;
                } else {
                    current_block = 12039483399334584727;
                }
            } else {
                current_block = 12039483399334584727;
            }
            match current_block {
                17539625483582710546 => {}
                _ => {
                    if sshbuf_get_string(b, &mut sigblob, &mut len) != 0 as libc::c_int {
                        ret = -(4 as libc::c_int);
                    } else if crate::sshbuf::sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong {
                        ret = -(23 as libc::c_int);
                    } else {
                        modlen = RSA_size((*key).rsa) as size_t;
                        if len > modlen {
                            ret = -(11 as libc::c_int);
                        } else {
                            if len < modlen {
                                diff = modlen.wrapping_sub(len);
                                osigblob = sigblob;
                                sigblob =
                                    realloc(sigblob as *mut libc::c_void, modlen) as *mut u_char;
                                if sigblob.is_null() {
                                    sigblob = osigblob;
                                    ret = -(2 as libc::c_int);
                                    current_block = 17539625483582710546;
                                } else {
                                    memmove(
                                        sigblob.offset(diff as isize) as *mut libc::c_void,
                                        sigblob as *const libc::c_void,
                                        len,
                                    );
                                    explicit_bzero(sigblob as *mut libc::c_void, diff);
                                    len = modlen;
                                    current_block = 11932355480408055363;
                                }
                            } else {
                                current_block = 11932355480408055363;
                            }
                            match current_block {
                                17539625483582710546 => {}
                                _ => {
                                    hlen = ssh_digest_bytes(hash_alg);
                                    if hlen == 0 as libc::c_int as libc::c_ulong {
                                        ret = -(1 as libc::c_int);
                                    } else {
                                        ret = ssh_digest_memory(
                                            hash_alg,
                                            data as *const libc::c_void,
                                            dlen,
                                            digest.as_mut_ptr(),
                                            ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
                                        );
                                        if !(ret != 0 as libc::c_int) {
                                            ret = openssh_RSA_verify(
                                                hash_alg,
                                                digest.as_mut_ptr(),
                                                hlen,
                                                sigblob,
                                                len,
                                                (*key).rsa,
                                            );
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
    freezero(sigblob as *mut libc::c_void, len);
    libc::free(sigtype as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(b);
    explicit_bzero(
        digest.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    return ret;
}
static mut id_sha1: [u_char; 15] = [
    0x30 as libc::c_int as u_char,
    0x21 as libc::c_int as u_char,
    0x30 as libc::c_int as u_char,
    0x9 as libc::c_int as u_char,
    0x6 as libc::c_int as u_char,
    0x5 as libc::c_int as u_char,
    0x2b as libc::c_int as u_char,
    0xe as libc::c_int as u_char,
    0x3 as libc::c_int as u_char,
    0x2 as libc::c_int as u_char,
    0x1a as libc::c_int as u_char,
    0x5 as libc::c_int as u_char,
    0 as libc::c_int as u_char,
    0x4 as libc::c_int as u_char,
    0x14 as libc::c_int as u_char,
];
static mut id_sha256: [u_char; 19] = [
    0x30 as libc::c_int as u_char,
    0x31 as libc::c_int as u_char,
    0x30 as libc::c_int as u_char,
    0xd as libc::c_int as u_char,
    0x6 as libc::c_int as u_char,
    0x9 as libc::c_int as u_char,
    0x60 as libc::c_int as u_char,
    0x86 as libc::c_int as u_char,
    0x48 as libc::c_int as u_char,
    0x1 as libc::c_int as u_char,
    0x65 as libc::c_int as u_char,
    0x3 as libc::c_int as u_char,
    0x4 as libc::c_int as u_char,
    0x2 as libc::c_int as u_char,
    0x1 as libc::c_int as u_char,
    0x5 as libc::c_int as u_char,
    0 as libc::c_int as u_char,
    0x4 as libc::c_int as u_char,
    0x20 as libc::c_int as u_char,
];
static mut id_sha512: [u_char; 19] = [
    0x30 as libc::c_int as u_char,
    0x51 as libc::c_int as u_char,
    0x30 as libc::c_int as u_char,
    0xd as libc::c_int as u_char,
    0x6 as libc::c_int as u_char,
    0x9 as libc::c_int as u_char,
    0x60 as libc::c_int as u_char,
    0x86 as libc::c_int as u_char,
    0x48 as libc::c_int as u_char,
    0x1 as libc::c_int as u_char,
    0x65 as libc::c_int as u_char,
    0x3 as libc::c_int as u_char,
    0x4 as libc::c_int as u_char,
    0x2 as libc::c_int as u_char,
    0x3 as libc::c_int as u_char,
    0x5 as libc::c_int as u_char,
    0 as libc::c_int as u_char,
    0x4 as libc::c_int as u_char,
    0x40 as libc::c_int as u_char,
];
unsafe extern "C" fn rsa_hash_alg_oid(
    mut hash_alg: libc::c_int,
    mut oidp: *mut *const u_char,
    mut oidlenp: *mut size_t,
) -> libc::c_int {
    match hash_alg {
        1 => {
            *oidp = id_sha1.as_ptr();
            *oidlenp = ::core::mem::size_of::<[u_char; 15]>() as libc::c_ulong;
        }
        2 => {
            *oidp = id_sha256.as_ptr();
            *oidlenp = ::core::mem::size_of::<[u_char; 19]>() as libc::c_ulong;
        }
        4 => {
            *oidp = id_sha512.as_ptr();
            *oidlenp = ::core::mem::size_of::<[u_char; 19]>() as libc::c_ulong;
        }
        _ => return -(10 as libc::c_int),
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn openssh_RSA_verify(
    mut hash_alg: libc::c_int,
    mut hash: *mut u_char,
    mut hashlen: size_t,
    mut sigbuf: *mut u_char,
    mut siglen: size_t,
    mut rsa: *mut RSA,
) -> libc::c_int {
    let mut rsasize: size_t = 0 as libc::c_int as size_t;
    let mut oidlen: size_t = 0 as libc::c_int as size_t;
    let mut hlen: size_t = 0 as libc::c_int as size_t;
    let mut ret: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut oidmatch: libc::c_int = 0;
    let mut hashmatch: libc::c_int = 0;
    let mut oid: *const u_char = 0 as *const u_char;
    let mut decrypted: *mut u_char = 0 as *mut u_char;
    ret = rsa_hash_alg_oid(hash_alg, &mut oid, &mut oidlen);
    if ret != 0 as libc::c_int {
        return ret;
    }
    ret = -(1 as libc::c_int);
    hlen = ssh_digest_bytes(hash_alg);
    if hashlen != hlen {
        ret = -(10 as libc::c_int);
    } else {
        rsasize = RSA_size(rsa) as size_t;
        if rsasize <= 0 as libc::c_int as libc::c_ulong
            || rsasize > (16384 as libc::c_int / 8 as libc::c_int) as libc::c_ulong
            || siglen == 0 as libc::c_int as libc::c_ulong
            || siglen > rsasize
        {
            ret = -(10 as libc::c_int);
        } else {
            decrypted = libc::malloc(rsasize as usize) as *mut u_char;
            if decrypted.is_null() {
                ret = -(2 as libc::c_int);
            } else {
                len = RSA_public_decrypt(
                    siglen as libc::c_int,
                    sigbuf,
                    decrypted,
                    rsa,
                    1 as libc::c_int,
                );
                if len < 0 as libc::c_int {
                    ret = -(22 as libc::c_int);
                } else if len < 0 as libc::c_int || len as size_t != hlen.wrapping_add(oidlen) {
                    ret = -(4 as libc::c_int);
                } else {
                    oidmatch = (timingsafe_bcmp(
                        decrypted as *const libc::c_void,
                        oid as *const libc::c_void,
                        oidlen,
                    ) == 0 as libc::c_int) as libc::c_int;
                    hashmatch = (timingsafe_bcmp(
                        decrypted.offset(oidlen as isize) as *const libc::c_void,
                        hash as *const libc::c_void,
                        hlen,
                    ) == 0 as libc::c_int) as libc::c_int;
                    if oidmatch == 0 || hashmatch == 0 {
                        ret = -(21 as libc::c_int);
                    } else {
                        ret = 0 as libc::c_int;
                    }
                }
            }
        }
    }
    freezero(decrypted as *mut libc::c_void, rsasize);
    return ret;
}
static mut sshkey_rsa_funcs: sshkey_impl_funcs = unsafe {
    {
        let mut init = sshkey_impl_funcs {
            size: Some(ssh_rsa_size as unsafe extern "C" fn(*const sshkey) -> u_int),
            alloc: Some(ssh_rsa_alloc as unsafe extern "C" fn(*mut sshkey) -> libc::c_int),
            cleanup: Some(ssh_rsa_cleanup as unsafe extern "C" fn(*mut sshkey) -> ()),
            equal: Some(
                ssh_rsa_equal as unsafe extern "C" fn(*const sshkey, *const sshkey) -> libc::c_int,
            ),
            serialize_public: Some(
                ssh_rsa_serialize_public
                    as unsafe extern "C" fn(
                        *const sshkey,
                        *mut crate::sshbuf::sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_public: Some(
                ssh_rsa_deserialize_public
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut crate::sshbuf::sshbuf,
                        *mut sshkey,
                    ) -> libc::c_int,
            ),
            serialize_private: Some(
                ssh_rsa_serialize_private
                    as unsafe extern "C" fn(
                        *const sshkey,
                        *mut crate::sshbuf::sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_private: Some(
                ssh_rsa_deserialize_private
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut crate::sshbuf::sshbuf,
                        *mut sshkey,
                    ) -> libc::c_int,
            ),
            generate: Some(
                ssh_rsa_generate as unsafe extern "C" fn(*mut sshkey, libc::c_int) -> libc::c_int,
            ),
            copy_public: Some(
                ssh_rsa_copy_public
                    as unsafe extern "C" fn(*const sshkey, *mut sshkey) -> libc::c_int,
            ),
            sign: Some(
                ssh_rsa_sign
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
                ssh_rsa_verify
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
pub static mut sshkey_rsa_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"ssh-rsa\0" as *const u8 as *const libc::c_char,
            shortname: b"RSA\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_RSA as libc::c_int,
            nid: 0 as libc::c_int,
            cert: 0 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_rsa_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_rsa_cert_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"ssh-rsa-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
            shortname: b"RSA-CERT\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_RSA_CERT as libc::c_int,
            nid: 0 as libc::c_int,
            cert: 1 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_rsa_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_rsa_sha256_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"rsa-sha2-256\0" as *const u8 as *const libc::c_char,
            shortname: b"RSA\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_RSA as libc::c_int,
            nid: 0 as libc::c_int,
            cert: 0 as libc::c_int,
            sigonly: 1 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_rsa_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_rsa_sha512_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"rsa-sha2-512\0" as *const u8 as *const libc::c_char,
            shortname: b"RSA\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_RSA as libc::c_int,
            nid: 0 as libc::c_int,
            cert: 0 as libc::c_int,
            sigonly: 1 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_rsa_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_rsa_sha256_cert_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"rsa-sha2-256-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
            shortname: b"RSA-CERT\0" as *const u8 as *const libc::c_char,
            sigalg: b"rsa-sha2-256\0" as *const u8 as *const libc::c_char,
            type_0: KEY_RSA_CERT as libc::c_int,
            nid: 0 as libc::c_int,
            cert: 1 as libc::c_int,
            sigonly: 1 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_rsa_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_rsa_sha512_cert_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"rsa-sha2-512-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
            shortname: b"RSA-CERT\0" as *const u8 as *const libc::c_char,
            sigalg: b"rsa-sha2-512\0" as *const u8 as *const libc::c_char,
            type_0: KEY_RSA_CERT as libc::c_int,
            nid: 0 as libc::c_int,
            cert: 1 as libc::c_int,
            sigonly: 1 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_rsa_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
