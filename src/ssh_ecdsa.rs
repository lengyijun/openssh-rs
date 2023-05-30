use crate::sshkey::sshkey_sig_details;
use crate::sshkey::EC_GROUP;
use ::libc;
extern "C" {

    pub type bignum_st;
    pub type bignum_ctx;

    pub type ec_group_st;
    pub type ec_point_st;
    pub type ECDSA_SIG_st;

    fn BN_clear_free(a: *mut BIGNUM);
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;

    fn ECDSA_do_verify(
        dgst: *const libc::c_uchar,
        dgst_len: libc::c_int,
        sig: *const ECDSA_SIG,
        eckey: *mut crate::sshkey::EC_KEY,
    ) -> libc::c_int;
    fn ECDSA_do_sign(
        dgst: *const libc::c_uchar,
        dgst_len: libc::c_int,
        eckey: *mut crate::sshkey::EC_KEY,
    ) -> *mut ECDSA_SIG;
    fn ECDSA_SIG_set0(sig: *mut ECDSA_SIG, r: *mut BIGNUM, s: *mut BIGNUM) -> libc::c_int;
    fn ECDSA_SIG_get0(sig: *const ECDSA_SIG, pr: *mut *const BIGNUM, ps: *mut *const BIGNUM);
    fn ECDSA_SIG_free(sig: *mut ECDSA_SIG);
    fn ECDSA_SIG_new() -> *mut ECDSA_SIG;
    fn EC_KEY_generate_key(key: *mut crate::sshkey::EC_KEY) -> libc::c_int;
    fn EC_KEY_set_asn1_flag(eckey: *mut crate::sshkey::EC_KEY, asn1_flag: libc::c_int);
    fn EC_KEY_set_public_key(
        key: *mut crate::sshkey::EC_KEY,
        pub_0: *const EC_POINT,
    ) -> libc::c_int;
    fn EC_KEY_get0_public_key(key: *const crate::sshkey::EC_KEY) -> *const EC_POINT;
    fn EC_KEY_set_private_key(key: *mut crate::sshkey::EC_KEY, prv: *const BIGNUM) -> libc::c_int;
    fn EC_KEY_get0_private_key(key: *const crate::sshkey::EC_KEY) -> *const BIGNUM;
    fn EC_KEY_get0_group(key: *const crate::sshkey::EC_KEY) -> *const EC_GROUP;
    fn EC_KEY_free(key: *mut crate::sshkey::EC_KEY);
    fn EC_KEY_new_by_curve_name(nid: libc::c_int) -> *mut crate::sshkey::EC_KEY;
    fn EC_POINT_cmp(
        group: *const EC_GROUP,
        a: *const EC_POINT,
        b: *const EC_POINT,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_GROUP_cmp(a: *const EC_GROUP, b: *const EC_GROUP, ctx: *mut BN_CTX) -> libc::c_int;

    fn sshbuf_froms(
        buf: *mut crate::sshbuf::sshbuf,
        bufp: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;

    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_get_bignum2(buf: *mut crate::sshbuf::sshbuf, valp: *mut *mut BIGNUM) -> libc::c_int;
    fn sshbuf_put_bignum2(buf: *mut crate::sshbuf::sshbuf, v: *const BIGNUM) -> libc::c_int;
    fn sshbuf_get_eckey(
        buf: *mut crate::sshbuf::sshbuf,
        v: *mut crate::sshkey::EC_KEY,
    ) -> libc::c_int;
    fn sshbuf_put_eckey(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshkey::EC_KEY,
    ) -> libc::c_int;

    fn sshkey_ssh_name_plain(_: *const crate::sshkey::sshkey) -> *const libc::c_char;
    fn sshkey_ec_validate_private(_: *const crate::sshkey::EC_KEY) -> libc::c_int;
    fn sshkey_ec_validate_public(_: *const EC_GROUP, _: *const EC_POINT) -> libc::c_int;
    fn sshkey_ec_nid_to_hash_alg(nid: libc::c_int) -> libc::c_int;
    fn sshkey_ecdsa_bits_to_nid(_: libc::c_int) -> libc::c_int;
    fn sshkey_curve_nid_to_name(_: libc::c_int) -> *const libc::c_char;
    fn sshkey_curve_name_to_nid(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_ecdsa_nid_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn sshkey_is_cert(_: *const crate::sshkey::sshkey) -> libc::c_int;
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

pub type EC_POINT = ec_point_st;
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
unsafe extern "C" fn ssh_ecdsa_size(mut key: *const crate::sshkey::sshkey) -> u_int {
    match (*key).ecdsa_nid {
        415 => return 256 as libc::c_int as u_int,
        715 => return 384 as libc::c_int as u_int,
        716 => return 521 as libc::c_int as u_int,
        _ => return 0 as libc::c_int as u_int,
    };
}
unsafe extern "C" fn ssh_ecdsa_cleanup(mut k: *mut crate::sshkey::sshkey) {
    EC_KEY_free((*k).ecdsa);
    (*k).ecdsa = 0 as *mut crate::sshkey::EC_KEY;
}
unsafe extern "C" fn ssh_ecdsa_equal(
    mut a: *const crate::sshkey::sshkey,
    mut b: *const crate::sshkey::sshkey,
) -> libc::c_int {
    let mut grp_a: *const EC_GROUP = 0 as *const EC_GROUP;
    let mut grp_b: *const EC_GROUP = 0 as *const EC_GROUP;
    let mut pub_a: *const EC_POINT = 0 as *const EC_POINT;
    let mut pub_b: *const EC_POINT = 0 as *const EC_POINT;
    if ((*a).ecdsa).is_null() || ((*b).ecdsa).is_null() {
        return 0 as libc::c_int;
    }
    grp_a = EC_KEY_get0_group((*a).ecdsa);
    if grp_a.is_null() || {
        grp_b = EC_KEY_get0_group((*b).ecdsa);
        grp_b.is_null()
    } {
        return 0 as libc::c_int;
    }
    pub_a = EC_KEY_get0_public_key((*a).ecdsa);
    if pub_a.is_null() || {
        pub_b = EC_KEY_get0_public_key((*b).ecdsa);
        pub_b.is_null()
    } {
        return 0 as libc::c_int;
    }
    if EC_GROUP_cmp(grp_a, grp_b, 0 as *mut BN_CTX) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if EC_POINT_cmp(grp_a, pub_a, pub_b, 0 as *mut BN_CTX) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ssh_ecdsa_serialize_public(
    mut key: *const crate::sshkey::sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut _opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    if ((*key).ecdsa).is_null() {
        return -(10 as libc::c_int);
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
        b,
        sshkey_curve_nid_to_name((*key).ecdsa_nid),
    );
    if r != 0 as libc::c_int || {
        r = sshbuf_put_eckey(b, (*key).ecdsa);
        r != 0 as libc::c_int
    } {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ecdsa_serialize_private(
    mut key: *const crate::sshkey::sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    if sshkey_is_cert(key) == 0 {
        r = ssh_ecdsa_serialize_public(key, b, opts);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    r = sshbuf_put_bignum2(b, EC_KEY_get0_private_key((*key).ecdsa));
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ecdsa_generate(
    mut k: *mut crate::sshkey::sshkey,
    mut bits: libc::c_int,
) -> libc::c_int {
    let mut private: *mut crate::sshkey::EC_KEY = 0 as *mut crate::sshkey::EC_KEY;
    (*k).ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits);
    if (*k).ecdsa_nid == -(1 as libc::c_int) {
        return -(56 as libc::c_int);
    }
    private = EC_KEY_new_by_curve_name((*k).ecdsa_nid);
    if private.is_null() {
        return -(2 as libc::c_int);
    }
    if EC_KEY_generate_key(private) != 1 as libc::c_int {
        EC_KEY_free(private);
        return -(22 as libc::c_int);
    }
    EC_KEY_set_asn1_flag(private, 0x1 as libc::c_int);
    (*k).ecdsa = private;
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ecdsa_copy_public(
    mut from: *const crate::sshkey::sshkey,
    mut to: *mut crate::sshkey::sshkey,
) -> libc::c_int {
    (*to).ecdsa_nid = (*from).ecdsa_nid;
    (*to).ecdsa = EC_KEY_new_by_curve_name((*from).ecdsa_nid);
    if ((*to).ecdsa).is_null() {
        return -(2 as libc::c_int);
    }
    if EC_KEY_set_public_key((*to).ecdsa, EC_KEY_get0_public_key((*from).ecdsa)) != 1 as libc::c_int
    {
        return -(22 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_ecdsa_deserialize_public(
    mut ktype: *const libc::c_char,
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut crate::sshkey::sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut curve: *mut libc::c_char = 0 as *mut libc::c_char;
    (*key).ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype);
    if (*key).ecdsa_nid == -(1 as libc::c_int) {
        return -(10 as libc::c_int);
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut curve, 0 as *mut size_t);
    if !(r != 0 as libc::c_int) {
        if (*key).ecdsa_nid != sshkey_curve_name_to_nid(curve) {
            r = -(15 as libc::c_int);
        } else {
            EC_KEY_free((*key).ecdsa);
            (*key).ecdsa = 0 as *mut crate::sshkey::EC_KEY;
            (*key).ecdsa = EC_KEY_new_by_curve_name((*key).ecdsa_nid);
            if ((*key).ecdsa).is_null() {
                r = -(22 as libc::c_int);
            } else {
                r = sshbuf_get_eckey(b, (*key).ecdsa);
                if !(r != 0 as libc::c_int) {
                    if sshkey_ec_validate_public(
                        EC_KEY_get0_group((*key).ecdsa),
                        EC_KEY_get0_public_key((*key).ecdsa),
                    ) != 0 as libc::c_int
                    {
                        r = -(20 as libc::c_int);
                    } else {
                        r = 0 as libc::c_int;
                    }
                }
            }
        }
    }
    libc::free(curve as *mut libc::c_void);
    if r != 0 as libc::c_int {
        EC_KEY_free((*key).ecdsa);
        (*key).ecdsa = 0 as *mut crate::sshkey::EC_KEY;
    }
    return r;
}
unsafe extern "C" fn ssh_ecdsa_deserialize_private(
    mut ktype: *const libc::c_char,
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut crate::sshkey::sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut exponent: *mut BIGNUM = 0 as *mut BIGNUM;
    if sshkey_is_cert(key) == 0 {
        r = ssh_ecdsa_deserialize_public(ktype, b, key);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    r = sshbuf_get_bignum2(b, &mut exponent);
    if !(r != 0 as libc::c_int) {
        if EC_KEY_set_private_key((*key).ecdsa, exponent) != 1 as libc::c_int {
            r = -(22 as libc::c_int);
        } else {
            r = sshkey_ec_validate_private((*key).ecdsa);
            if !(r != 0 as libc::c_int) {
                r = 0 as libc::c_int;
            }
        }
    }
    BN_clear_free(exponent);
    return r;
}
unsafe extern "C" fn ssh_ecdsa_sign(
    mut key: *mut crate::sshkey::sshkey,
    mut sigp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut data: *const u_char,
    mut dlen: size_t,
    mut _alg: *const libc::c_char,
    mut _sk_provider: *const libc::c_char,
    mut _sk_pin: *const libc::c_char,
    mut _compat: u_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut esig: *mut ECDSA_SIG = 0 as *mut ECDSA_SIG;
    let mut sig_r: *const BIGNUM = 0 as *const BIGNUM;
    let mut sig_s: *const BIGNUM = 0 as *const BIGNUM;
    let mut hash_alg: libc::c_int = 0;
    let mut digest: [u_char; 64] = [0; 64];
    let mut len: size_t = 0;
    let mut hlen: size_t = 0;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut bb: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if !lenp.is_null() {
        *lenp = 0 as libc::c_int as size_t;
    }
    if !sigp.is_null() {
        *sigp = 0 as *mut u_char;
    }
    if key.is_null()
        || ((*key).ecdsa).is_null()
        || sshkey_type_plain((*key).type_0) != KEY_ECDSA as libc::c_int
    {
        return -(10 as libc::c_int);
    }
    hash_alg = sshkey_ec_nid_to_hash_alg((*key).ecdsa_nid);
    if hash_alg == -(1 as libc::c_int) || {
        hlen = crate::digest_openssl::ssh_digest_bytes(hash_alg);
        hlen == 0 as libc::c_int as libc::c_ulong
    } {
        return -(1 as libc::c_int);
    }
    ret = crate::digest_openssl::ssh_digest_memory(
        hash_alg,
        data as *const libc::c_void,
        dlen,
        digest.as_mut_ptr(),
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    if !(ret != 0 as libc::c_int) {
        esig = ECDSA_do_sign(digest.as_mut_ptr(), hlen as libc::c_int, (*key).ecdsa);
        if esig.is_null() {
            ret = -(22 as libc::c_int);
        } else {
            bb = crate::sshbuf::sshbuf_new();
            if bb.is_null() || {
                b = crate::sshbuf::sshbuf_new();
                b.is_null()
            } {
                ret = -(2 as libc::c_int);
            } else {
                ECDSA_SIG_get0(esig, &mut sig_r, &mut sig_s);
                ret = sshbuf_put_bignum2(bb, sig_r);
                if !(ret != 0 as libc::c_int || {
                    ret = sshbuf_put_bignum2(bb, sig_s);
                    ret != 0 as libc::c_int
                }) {
                    ret = crate::sshbuf_getput_basic::sshbuf_put_cstring(
                        b,
                        sshkey_ssh_name_plain(key),
                    );
                    if !(ret != 0 as libc::c_int || {
                        ret = sshbuf_put_stringb(b, bb);
                        ret != 0 as libc::c_int
                    }) {
                        len = crate::sshbuf::sshbuf_len(b);
                        if !sigp.is_null() {
                            *sigp = libc::malloc(len as usize) as *mut u_char;
                            if (*sigp).is_null() {
                                ret = -(2 as libc::c_int);
                                current_block = 12351472656133197307;
                            } else {
                                memcpy(
                                    *sigp as *mut libc::c_void,
                                    crate::sshbuf::sshbuf_ptr(b) as *const libc::c_void,
                                    len,
                                );
                                current_block = 12147880666119273379;
                            }
                        } else {
                            current_block = 12147880666119273379;
                        }
                        match current_block {
                            12351472656133197307 => {}
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
    crate::sshbuf::sshbuf_free(b);
    crate::sshbuf::sshbuf_free(bb);
    ECDSA_SIG_free(esig);
    return ret;
}
unsafe extern "C" fn ssh_ecdsa_verify(
    mut key: *const crate::sshkey::sshkey,
    mut sig: *const u_char,
    mut siglen: size_t,
    mut data: *const u_char,
    mut dlen: size_t,
    mut _alg: *const libc::c_char,
    mut _compat: u_int,
    mut _detailsp: *mut *mut sshkey_sig_details,
) -> libc::c_int {
    let mut esig: *mut ECDSA_SIG = 0 as *mut ECDSA_SIG;
    let mut sig_r: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut sig_s: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut hash_alg: libc::c_int = 0;
    let mut digest: [u_char; 64] = [0; 64];
    let mut hlen: size_t = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sigbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut ktype: *mut libc::c_char = 0 as *mut libc::c_char;
    if key.is_null()
        || ((*key).ecdsa).is_null()
        || sshkey_type_plain((*key).type_0) != KEY_ECDSA as libc::c_int
        || sig.is_null()
        || siglen == 0 as libc::c_int as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    hash_alg = sshkey_ec_nid_to_hash_alg((*key).ecdsa_nid);
    if hash_alg == -(1 as libc::c_int) || {
        hlen = crate::digest_openssl::ssh_digest_bytes(hash_alg);
        hlen == 0 as libc::c_int as libc::c_ulong
    } {
        return -(1 as libc::c_int);
    }
    b = crate::sshbuf::sshbuf_from(sig as *const libc::c_void, siglen);
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    if crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut ktype, 0 as *mut size_t)
        != 0 as libc::c_int
        || sshbuf_froms(b, &mut sigbuf) != 0 as libc::c_int
    {
        ret = -(4 as libc::c_int);
    } else if libc::strcmp(sshkey_ssh_name_plain(key), ktype) != 0 as libc::c_int {
        ret = -(13 as libc::c_int);
    } else if crate::sshbuf::sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong {
        ret = -(23 as libc::c_int);
    } else if sshbuf_get_bignum2(sigbuf, &mut sig_r) != 0 as libc::c_int
        || sshbuf_get_bignum2(sigbuf, &mut sig_s) != 0 as libc::c_int
    {
        ret = -(4 as libc::c_int);
    } else {
        esig = ECDSA_SIG_new();
        if esig.is_null() {
            ret = -(2 as libc::c_int);
        } else if ECDSA_SIG_set0(esig, sig_r, sig_s) == 0 {
            ret = -(22 as libc::c_int);
        } else {
            sig_s = 0 as *mut BIGNUM;
            sig_r = sig_s;
            if crate::sshbuf::sshbuf_len(sigbuf) != 0 as libc::c_int as libc::c_ulong {
                ret = -(23 as libc::c_int);
            } else {
                ret = crate::digest_openssl::ssh_digest_memory(
                    hash_alg,
                    data as *const libc::c_void,
                    dlen,
                    digest.as_mut_ptr(),
                    ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
                );
                if !(ret != 0 as libc::c_int) {
                    match ECDSA_do_verify(
                        digest.as_mut_ptr(),
                        hlen as libc::c_int,
                        esig,
                        (*key).ecdsa,
                    ) {
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
    }
    explicit_bzero(
        digest.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    crate::sshbuf::sshbuf_free(sigbuf);
    crate::sshbuf::sshbuf_free(b);
    ECDSA_SIG_free(esig);
    BN_clear_free(sig_r);
    BN_clear_free(sig_s);
    libc::free(ktype as *mut libc::c_void);
    return ret;
}
pub static mut sshkey_ecdsa_funcs: sshkey_impl_funcs = unsafe {
    {
        let mut init = sshkey_impl_funcs {
            size: Some(
                ssh_ecdsa_size as unsafe extern "C" fn(*const crate::sshkey::sshkey) -> u_int,
            ),
            alloc: None,
            cleanup: Some(
                ssh_ecdsa_cleanup as unsafe extern "C" fn(*mut crate::sshkey::sshkey) -> (),
            ),
            equal: Some(
                ssh_ecdsa_equal
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
                        *const crate::sshkey::sshkey,
                    ) -> libc::c_int,
            ),
            serialize_public: Some(
                ssh_ecdsa_serialize_public
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
                        *mut crate::sshbuf::sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_public: Some(
                ssh_ecdsa_deserialize_public
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut crate::sshbuf::sshbuf,
                        *mut crate::sshkey::sshkey,
                    ) -> libc::c_int,
            ),
            serialize_private: Some(
                ssh_ecdsa_serialize_private
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
                        *mut crate::sshbuf::sshbuf,
                        sshkey_serialize_rep,
                    ) -> libc::c_int,
            ),
            deserialize_private: Some(
                ssh_ecdsa_deserialize_private
                    as unsafe extern "C" fn(
                        *const libc::c_char,
                        *mut crate::sshbuf::sshbuf,
                        *mut crate::sshkey::sshkey,
                    ) -> libc::c_int,
            ),
            generate: Some(
                ssh_ecdsa_generate
                    as unsafe extern "C" fn(*mut crate::sshkey::sshkey, libc::c_int) -> libc::c_int,
            ),
            copy_public: Some(
                ssh_ecdsa_copy_public
                    as unsafe extern "C" fn(
                        *const crate::sshkey::sshkey,
                        *mut crate::sshkey::sshkey,
                    ) -> libc::c_int,
            ),
            sign: Some(
                ssh_ecdsa_sign
                    as unsafe extern "C" fn(
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
            ),
            verify: Some(
                ssh_ecdsa_verify
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
pub static mut sshkey_ecdsa_nistp256_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"ecdsa-sha2-nistp256\0" as *const u8 as *const libc::c_char,
            shortname: b"ECDSA\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ECDSA as libc::c_int,
            nid: 415 as libc::c_int,
            cert: 0 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_ecdsa_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_ecdsa_nistp256_cert_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"ecdsa-sha2-nistp256-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
            shortname: b"ECDSA-CERT\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ECDSA_CERT as libc::c_int,
            nid: 415 as libc::c_int,
            cert: 1 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_ecdsa_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_ecdsa_nistp384_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"ecdsa-sha2-nistp384\0" as *const u8 as *const libc::c_char,
            shortname: b"ECDSA\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ECDSA as libc::c_int,
            nid: 715 as libc::c_int,
            cert: 0 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_ecdsa_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_ecdsa_nistp384_cert_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"ecdsa-sha2-nistp384-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
            shortname: b"ECDSA-CERT\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ECDSA_CERT as libc::c_int,
            nid: 715 as libc::c_int,
            cert: 1 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_ecdsa_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_ecdsa_nistp521_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"ecdsa-sha2-nistp521\0" as *const u8 as *const libc::c_char,
            shortname: b"ECDSA\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ECDSA as libc::c_int,
            nid: 716 as libc::c_int,
            cert: 0 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_ecdsa_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
pub static mut sshkey_ecdsa_nistp521_cert_impl: sshkey_impl = unsafe {
    {
        let mut init = sshkey_impl {
            name: b"ecdsa-sha2-nistp521-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
            shortname: b"ECDSA-CERT\0" as *const u8 as *const libc::c_char,
            sigalg: 0 as *const libc::c_char,
            type_0: KEY_ECDSA_CERT as libc::c_int,
            nid: 716 as libc::c_int,
            cert: 1 as libc::c_int,
            sigonly: 0 as libc::c_int,
            keybits: 0 as libc::c_int,
            funcs: &sshkey_ecdsa_funcs as *const sshkey_impl_funcs,
        };
        init
    }
};
