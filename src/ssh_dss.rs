use ::libc;
extern "C" {

    pub type bignum_st;
    pub type bn_gencb_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    pub type DSA_SIG_st;
    fn freezero(_: *mut libc::c_void, _: size_t);

    fn BN_num_bits(a: *const BIGNUM) -> libc::c_int;
    fn BN_new() -> *mut BIGNUM;
    fn BN_clear_free(a: *mut BIGNUM);
    fn BN_bin2bn(s: *const libc::c_uchar, len: libc::c_int, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_bn2bin(a: *const BIGNUM, to: *mut libc::c_uchar) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_dup(a: *const BIGNUM) -> *mut BIGNUM;
    fn DSA_set0_key(d: *mut DSA, pub_key: *mut BIGNUM, priv_key: *mut BIGNUM) -> libc::c_int;
    fn DSA_get0_key(d: *const DSA, pub_key: *mut *const BIGNUM, priv_key: *mut *const BIGNUM);
    fn DSA_set0_pqg(d: *mut DSA, p: *mut BIGNUM, q: *mut BIGNUM, g: *mut BIGNUM) -> libc::c_int;
    fn DSA_get0_pqg(
        d: *const DSA,
        p: *mut *const BIGNUM,
        q: *mut *const BIGNUM,
        g: *mut *const BIGNUM,
    );
    fn DSA_generate_key(a: *mut DSA) -> libc::c_int;
    fn DSA_generate_parameters_ex(
        dsa: *mut DSA,
        bits: libc::c_int,
        seed: *const libc::c_uchar,
        seed_len: libc::c_int,
        counter_ret: *mut libc::c_int,
        h_ret: *mut libc::c_ulong,
        cb: *mut BN_GENCB,
    ) -> libc::c_int;
    fn DSA_free(r: *mut DSA);
    fn DSA_new() -> *mut DSA;
    fn DSA_do_verify(
        dgst: *const libc::c_uchar,
        dgst_len: libc::c_int,
        sig: *mut DSA_SIG,
        dsa: *mut DSA,
    ) -> libc::c_int;
    fn DSA_do_sign(dgst: *const libc::c_uchar, dlen: libc::c_int, dsa: *mut DSA) -> *mut DSA_SIG;
    fn DSA_SIG_set0(sig: *mut DSA_SIG, r: *mut BIGNUM, s: *mut BIGNUM) -> libc::c_int;
    fn DSA_SIG_get0(sig: *const DSA_SIG, pr: *mut *const BIGNUM, ps: *mut *const BIGNUM);
    fn DSA_SIG_free(a: *mut DSA_SIG);
    fn DSA_SIG_new() -> *mut DSA_SIG;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;

    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn sshbuf_from(blob: *const libc::c_void, len: size_t) -> *mut crate::sshbuf::sshbuf;

    fn sshbuf_get_string(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_string(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut crate::sshbuf::sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_bignum2(buf: *mut crate::sshbuf::sshbuf, v: *const BIGNUM) -> libc::c_int;
    fn sshbuf_get_bignum2(buf: *mut crate::sshbuf::sshbuf, valp: *mut *mut BIGNUM) -> libc::c_int;
    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_digest_memory(
        alg: libc::c_int,
        m: *const libc::c_void,
        mlen: size_t,
        d: *mut u_char,
        dlen: size_t,
    ) -> libc::c_int;
    fn sshkey_is_cert(_: *const sshkey) -> libc::c_int;
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
pub type BIGNUM = bignum_st;
pub type BN_GENCB = bn_gencb_st;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type EC_KEY = ec_key_st;
pub type DSA_SIG = DSA_SIG_st;
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
unsafe extern "C" fn ssh_dss_size(mut key: *const sshkey) -> u_int {
    let mut dsa_p: *const BIGNUM = 0 as *const BIGNUM;
    if ((*key).dsa).is_null() {
        return 0 as libc::c_int as u_int;
    }
    DSA_get0_pqg(
        (*key).dsa,
        &mut dsa_p,
        0 as *mut *const BIGNUM,
        0 as *mut *const BIGNUM,
    );
    return BN_num_bits(dsa_p) as u_int;
}
unsafe extern "C" fn ssh_dss_alloc(mut k: *mut sshkey) -> libc::c_int {
    (*k).dsa = DSA_new();
    if ((*k).dsa).is_null() {
        return -(2 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_dss_cleanup(mut k: *mut sshkey) {
    DSA_free((*k).dsa);
    (*k).dsa = 0 as *mut DSA;
}
unsafe extern "C" fn ssh_dss_equal(mut a: *const sshkey, mut b: *const sshkey) -> libc::c_int {
    let mut dsa_p_a: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_q_a: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_g_a: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_pub_key_a: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_p_b: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_q_b: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_g_b: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_pub_key_b: *const BIGNUM = 0 as *const BIGNUM;
    if ((*a).dsa).is_null() || ((*b).dsa).is_null() {
        return 0 as libc::c_int;
    }
    DSA_get0_pqg((*a).dsa, &mut dsa_p_a, &mut dsa_q_a, &mut dsa_g_a);
    DSA_get0_pqg((*b).dsa, &mut dsa_p_b, &mut dsa_q_b, &mut dsa_g_b);
    DSA_get0_key((*a).dsa, &mut dsa_pub_key_a, 0 as *mut *const BIGNUM);
    DSA_get0_key((*b).dsa, &mut dsa_pub_key_b, 0 as *mut *const BIGNUM);
    if dsa_p_a.is_null()
        || dsa_p_b.is_null()
        || dsa_q_a.is_null()
        || dsa_q_b.is_null()
        || dsa_g_a.is_null()
        || dsa_g_b.is_null()
        || dsa_pub_key_a.is_null()
        || dsa_pub_key_b.is_null()
    {
        return 0 as libc::c_int;
    }
    if BN_cmp(dsa_p_a, dsa_p_b) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if BN_cmp(dsa_q_a, dsa_q_b) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if BN_cmp(dsa_g_a, dsa_g_b) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if BN_cmp(dsa_pub_key_a, dsa_pub_key_b) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ssh_dss_serialize_public(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut _opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut dsa_p: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_q: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_g: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_pub_key: *const BIGNUM = 0 as *const BIGNUM;
    if ((*key).dsa).is_null() {
        return -(10 as libc::c_int);
    }
    DSA_get0_pqg((*key).dsa, &mut dsa_p, &mut dsa_q, &mut dsa_g);
    DSA_get0_key((*key).dsa, &mut dsa_pub_key, 0 as *mut *const BIGNUM);
    if dsa_p.is_null() || dsa_q.is_null() || dsa_g.is_null() || dsa_pub_key.is_null() {
        return -(1 as libc::c_int);
    }
    r = sshbuf_put_bignum2(b, dsa_p);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_bignum2(b, dsa_q);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_bignum2(b, dsa_g);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_bignum2(b, dsa_pub_key);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_dss_serialize_private(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut dsa_priv_key: *const BIGNUM = 0 as *const BIGNUM;
    DSA_get0_key((*key).dsa, 0 as *mut *const BIGNUM, &mut dsa_priv_key);
    if sshkey_is_cert(key) == 0 {
        r = ssh_dss_serialize_public(key, b, opts);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    r = sshbuf_put_bignum2(b, dsa_priv_key);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_dss_generate(mut k: *mut sshkey, mut bits: libc::c_int) -> libc::c_int {
    let mut private: *mut DSA = 0 as *mut DSA;
    if bits != 1024 as libc::c_int {
        return -(56 as libc::c_int);
    }
    private = DSA_new();
    if private.is_null() {
        return -(2 as libc::c_int);
    }
    if DSA_generate_parameters_ex(
        private,
        bits,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        0 as *mut libc::c_int,
        0 as *mut libc::c_ulong,
        0 as *mut BN_GENCB,
    ) == 0
        || DSA_generate_key(private) == 0
    {
        DSA_free(private);
        return -(22 as libc::c_int);
    }
    (*k).dsa = private;
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_dss_copy_public(
    mut from: *const sshkey,
    mut to: *mut sshkey,
) -> libc::c_int {
    let mut dsa_p: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_q: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_g: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_pub_key: *const BIGNUM = 0 as *const BIGNUM;
    let mut dsa_p_dup: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dsa_q_dup: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dsa_g_dup: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dsa_pub_key_dup: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut r: libc::c_int = -(1 as libc::c_int);
    DSA_get0_pqg((*from).dsa, &mut dsa_p, &mut dsa_q, &mut dsa_g);
    DSA_get0_key((*from).dsa, &mut dsa_pub_key, 0 as *mut *const BIGNUM);
    dsa_p_dup = BN_dup(dsa_p);
    if dsa_p_dup.is_null()
        || {
            dsa_q_dup = BN_dup(dsa_q);
            dsa_q_dup.is_null()
        }
        || {
            dsa_g_dup = BN_dup(dsa_g);
            dsa_g_dup.is_null()
        }
        || {
            dsa_pub_key_dup = BN_dup(dsa_pub_key);
            dsa_pub_key_dup.is_null()
        }
    {
        r = -(2 as libc::c_int);
    } else if DSA_set0_pqg((*to).dsa, dsa_p_dup, dsa_q_dup, dsa_g_dup) == 0 {
        r = -(22 as libc::c_int);
    } else {
        dsa_g_dup = 0 as *mut BIGNUM;
        dsa_q_dup = dsa_g_dup;
        dsa_p_dup = dsa_q_dup;
        if DSA_set0_key((*to).dsa, dsa_pub_key_dup, 0 as *mut BIGNUM) == 0 {
            r = -(22 as libc::c_int);
        } else {
            dsa_pub_key_dup = 0 as *mut BIGNUM;
            r = 0 as libc::c_int;
        }
    }
    BN_clear_free(dsa_p_dup);
    BN_clear_free(dsa_q_dup);
    BN_clear_free(dsa_g_dup);
    BN_clear_free(dsa_pub_key_dup);
    return r;
}
unsafe extern "C" fn ssh_dss_deserialize_public(
    mut _ktype: *const libc::c_char,
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut sshkey,
) -> libc::c_int {
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut dsa_p: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dsa_q: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dsa_g: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dsa_pub_key: *mut BIGNUM = 0 as *mut BIGNUM;
    if sshbuf_get_bignum2(b, &mut dsa_p) != 0 as libc::c_int
        || sshbuf_get_bignum2(b, &mut dsa_q) != 0 as libc::c_int
        || sshbuf_get_bignum2(b, &mut dsa_g) != 0 as libc::c_int
        || sshbuf_get_bignum2(b, &mut dsa_pub_key) != 0 as libc::c_int
    {
        ret = -(4 as libc::c_int);
    } else if DSA_set0_pqg((*key).dsa, dsa_p, dsa_q, dsa_g) == 0 {
        ret = -(22 as libc::c_int);
    } else {
        dsa_g = 0 as *mut BIGNUM;
        dsa_q = dsa_g;
        dsa_p = dsa_q;
        if DSA_set0_key((*key).dsa, dsa_pub_key, 0 as *mut BIGNUM) == 0 {
            ret = -(22 as libc::c_int);
        } else {
            dsa_pub_key = 0 as *mut BIGNUM;
            ret = 0 as libc::c_int;
        }
    }
    BN_clear_free(dsa_p);
    BN_clear_free(dsa_q);
    BN_clear_free(dsa_g);
    BN_clear_free(dsa_pub_key);
    return ret;
}
unsafe extern "C" fn ssh_dss_deserialize_private(
    mut ktype: *const libc::c_char,
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut dsa_priv_key: *mut BIGNUM = 0 as *mut BIGNUM;
    if sshkey_is_cert(key) == 0 {
        r = ssh_dss_deserialize_public(ktype, b, key);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    r = sshbuf_get_bignum2(b, &mut dsa_priv_key);
    if r != 0 as libc::c_int {
        return r;
    }
    if DSA_set0_key((*key).dsa, 0 as *mut BIGNUM, dsa_priv_key) == 0 {
        BN_clear_free(dsa_priv_key);
        return -(22 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_dss_sign(
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
    let mut sig: *mut DSA_SIG = 0 as *mut DSA_SIG;
    let mut sig_r: *const BIGNUM = 0 as *const BIGNUM;
    let mut sig_s: *const BIGNUM = 0 as *const BIGNUM;
    let mut digest: [u_char; 64] = [0; 64];
    let mut sigblob: [u_char; 40] = [0; 40];
    let mut rlen: size_t = 0;
    let mut slen: size_t = 0;
    let mut len: size_t = 0;
    let mut dlen: size_t = ssh_digest_bytes(1 as libc::c_int);
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut ret: libc::c_int = -(10 as libc::c_int);
    if !lenp.is_null() {
        *lenp = 0 as libc::c_int as size_t;
    }
    if !sigp.is_null() {
        *sigp = 0 as *mut u_char;
    }
    if key.is_null()
        || ((*key).dsa).is_null()
        || sshkey_type_plain((*key).type_0) != KEY_DSA as libc::c_int
    {
        return -(10 as libc::c_int);
    }
    if dlen == 0 as libc::c_int as libc::c_ulong {
        return -(1 as libc::c_int);
    }
    ret = ssh_digest_memory(
        1 as libc::c_int,
        data as *const libc::c_void,
        datalen,
        digest.as_mut_ptr(),
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    if !(ret != 0 as libc::c_int) {
        sig = DSA_do_sign(digest.as_mut_ptr(), dlen as libc::c_int, (*key).dsa);
        if sig.is_null() {
            ret = -(22 as libc::c_int);
        } else {
            DSA_SIG_get0(sig, &mut sig_r, &mut sig_s);
            rlen = ((BN_num_bits(sig_r) + 7 as libc::c_int) / 8 as libc::c_int) as size_t;
            slen = ((BN_num_bits(sig_s) + 7 as libc::c_int) / 8 as libc::c_int) as size_t;
            if rlen > 20 as libc::c_int as libc::c_ulong
                || slen > 20 as libc::c_int as libc::c_ulong
            {
                ret = -(1 as libc::c_int);
            } else {
                explicit_bzero(
                    sigblob.as_mut_ptr() as *mut libc::c_void,
                    (2 as libc::c_int * 20 as libc::c_int) as size_t,
                );
                BN_bn2bin(
                    sig_r,
                    sigblob
                        .as_mut_ptr()
                        .offset((2 as libc::c_int * 20 as libc::c_int) as isize)
                        .offset(-(20 as libc::c_int as isize))
                        .offset(-(rlen as isize)),
                );
                BN_bn2bin(
                    sig_s,
                    sigblob
                        .as_mut_ptr()
                        .offset((2 as libc::c_int * 20 as libc::c_int) as isize)
                        .offset(-(slen as isize)),
                );
                b = crate::sshbuf::sshbuf_new();
                if b.is_null() {
                    ret = -(2 as libc::c_int);
                } else {
                    ret = sshbuf_put_cstring(b, b"ssh-dss\0" as *const u8 as *const libc::c_char);
                    if !(ret != 0 as libc::c_int || {
                        ret = sshbuf_put_string(
                            b,
                            sigblob.as_mut_ptr() as *const libc::c_void,
                            (2 as libc::c_int * 20 as libc::c_int) as size_t,
                        );
                        ret != 0 as libc::c_int
                    }) {
                        len = crate::sshbuf::sshbuf_len(b);
                        if !sigp.is_null() {
                            *sigp = libc::malloc(len as usize) as *mut u_char;
                            if (*sigp).is_null() {
                                ret = -(2 as libc::c_int);
                                current_block = 17014927154208801450;
                            } else {
                                memcpy(
                                    *sigp as *mut libc::c_void,
                                    crate::sshbuf::sshbuf_ptr(b) as *const libc::c_void,
                                    len,
                                );
                                current_block = 13472856163611868459;
                            }
                        } else {
                            current_block = 13472856163611868459;
                        }
                        match current_block {
                            17014927154208801450 => {}
                            _ => {
                                if !lenp.is_null() {
                                    *lenp = len;
                                }
                                ret = 0 as libc::c_int;
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
    DSA_SIG_free(sig);
    crate::sshbuf::sshbuf_free(b);
    return ret;
}
unsafe extern "C" fn ssh_dss_verify(
    mut key: *const sshkey,
    mut sig: *const u_char,
    mut siglen: size_t,
    mut data: *const u_char,
    mut dlen: size_t,
    mut _alg: *const libc::c_char,
    mut _compat: u_int,
    mut _detailsp: *mut *mut sshkey_sig_details,
) -> libc::c_int {
    let mut dsig: *mut DSA_SIG = 0 as *mut DSA_SIG;
    let mut sig_r: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut sig_s: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut digest: [u_char; 64] = [0; 64];
    let mut sigblob: *mut u_char = 0 as *mut u_char;
    let mut len: size_t = 0;
    let mut hlen: size_t = ssh_digest_bytes(1 as libc::c_int);
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut ktype: *mut libc::c_char = 0 as *mut libc::c_char;
    if key.is_null()
        || ((*key).dsa).is_null()
        || sshkey_type_plain((*key).type_0) != KEY_DSA as libc::c_int
        || sig.is_null()
        || siglen == 0 as libc::c_int as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    if hlen == 0 as libc::c_int as libc::c_ulong {
        return -(1 as libc::c_int);
    }
    b = sshbuf_from(sig as *const libc::c_void, siglen);
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    if sshbuf_get_cstring(b, &mut ktype, 0 as *mut size_t) != 0 as libc::c_int
        || sshbuf_get_string(b, &mut sigblob, &mut len) != 0 as libc::c_int
    {
        ret = -(4 as libc::c_int);
    } else if libc::strcmp(b"ssh-dss\0" as *const u8 as *const libc::c_char, ktype)
        != 0 as libc::c_int
    {
        ret = -(13 as libc::c_int);
    } else if crate::sshbuf::sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong {
        ret = -(23 as libc::c_int);
    } else if len != (2 as libc::c_int * 20 as libc::c_int) as libc::c_ulong {
        ret = -(4 as libc::c_int);
    } else {
        dsig = DSA_SIG_new();
        if dsig.is_null()
            || {
                sig_r = BN_new();
                sig_r.is_null()
            }
            || {
                sig_s = BN_new();
                sig_s.is_null()
            }
        {
            ret = -(2 as libc::c_int);
        } else if (BN_bin2bn(sigblob, 20 as libc::c_int, sig_r)).is_null()
            || (BN_bin2bn(
                sigblob.offset(20 as libc::c_int as isize),
                20 as libc::c_int,
                sig_s,
            ))
            .is_null()
        {
            ret = -(22 as libc::c_int);
        } else if DSA_SIG_set0(dsig, sig_r, sig_s) == 0 {
            ret = -(22 as libc::c_int);
        } else {
            sig_s = 0 as *mut BIGNUM;
            sig_r = sig_s;
            ret = ssh_digest_memory(
                1 as libc::c_int,
                data as *const libc::c_void,
                dlen,
                digest.as_mut_ptr(),
                ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
            );
            if !(ret != 0 as libc::c_int) {
                match DSA_do_verify(digest.as_mut_ptr(), hlen as libc::c_int, dsig, (*key).dsa) {
                    1 => {
                        ret = 0 as libc::c_int;
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
    explicit_bzero(
        digest.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    DSA_SIG_free(dsig);
    BN_clear_free(sig_r);
    BN_clear_free(sig_s);
    crate::sshbuf::sshbuf_free(b);
    libc::free(ktype as *mut libc::c_void);
    if !sigblob.is_null() {
        freezero(sigblob as *mut libc::c_void, len);
    }
    return ret;
}
static mut sshkey_dss_funcs: sshkey_impl_funcs = unsafe {
    {
        let mut init = sshkey_impl_funcs {
            size: Some(ssh_dss_size as unsafe extern "C" fn(*const sshkey) -> u_int),
            alloc: Some(ssh_dss_alloc as unsafe extern "C" fn(*mut sshkey) -> libc::c_int),
            cleanup: Some(ssh_dss_cleanup as unsafe extern "C" fn(*mut sshkey) -> ()),
            equal: Some(
                ssh_dss_equal as unsafe extern "C" fn(*const sshkey, *const sshkey) -> libc::c_int,
            ),
            serialize_public: Some(
                ssh_dss_serialize_public
                    as unsafe extern "C" fn(
                        *const sshkey,
                        *mut crate::sshbuf::sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_public: Some(
                ssh_dss_deserialize_public
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut crate::sshbuf::sshbuf,
                        *mut sshkey,
                    ) -> libc::c_int,
            ),
            serialize_private: Some(
                ssh_dss_serialize_private
                    as unsafe extern "C" fn(
                        *const sshkey,
                        *mut crate::sshbuf::sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_private: Some(
                ssh_dss_deserialize_private
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut crate::sshbuf::sshbuf,
                        *mut sshkey,
                    ) -> libc::c_int,
            ),
            generate: Some(
                ssh_dss_generate as unsafe extern "C" fn(*mut sshkey, libc::c_int) -> libc::c_int,
            ),
            copy_public: Some(
                ssh_dss_copy_public
                    as unsafe extern "C" fn(*const sshkey, *mut sshkey) -> libc::c_int,
            ),
            sign: Some(
                ssh_dss_sign
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
                ssh_dss_verify
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
pub static mut sshkey_dss_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"ssh-dss\0" as *const u8 as *const libc::c_char,
            shortname: b"DSA\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_DSA as libc::c_int,
            nid: 0 as libc::c_int,
            cert: 0 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_dss_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_dsa_cert_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"ssh-dss-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
            shortname: b"DSA-CERT\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_DSA_CERT as libc::c_int,
            nid: 0 as libc::c_int,
            cert: 1 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_dss_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
