use crate::kex::dh_st;
use crate::sshbuf_getput_crypto::BIGNUM;

use crate::kex::kex;

use ::libc;
extern "C" {

    pub type bignum_st;

    pub type ec_group_st;

    fn freezero(_: *mut libc::c_void, _: size_t);

    fn BN_new() -> *mut BIGNUM;
    fn BN_clear_free(a: *mut BIGNUM);
    fn BN_bin2bn(s: *const libc::c_uchar, len: libc::c_int, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_free(a: *mut BIGNUM);
    fn DH_free(dh: *mut DH);
    fn DH_size(dh: *const DH) -> libc::c_int;
    fn DH_compute_key(key: *mut libc::c_uchar, pub_key: *const BIGNUM, dh: *mut DH) -> libc::c_int;
    fn DH_get0_key(dh: *const DH, pub_key: *mut *const BIGNUM, priv_key: *mut *const BIGNUM);

    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_get_bignum2(buf: *mut crate::sshbuf::sshbuf, valp: *mut *mut BIGNUM) -> libc::c_int;
    fn sshbuf_put_bignum2(buf: *mut crate::sshbuf::sshbuf, v: *const BIGNUM) -> libc::c_int;
    fn dh_new_group1() -> *mut DH;
    fn dh_new_group14() -> *mut DH;
    fn dh_new_group16() -> *mut DH;
    fn dh_new_group18() -> *mut DH;
    fn dh_gen_key(_: *mut DH, _: libc::c_int) -> libc::c_int;
    fn dh_pub_is_valid(_: *const DH, _: *const BIGNUM) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type uint8_t = __uint8_t;
pub type sig_atomic_t = __sig_atomic_t;

pub type DH = dh_st;

pub type kex_exchange = libc::c_uint;
pub const KEX_MAX: kex_exchange = 10;
pub const KEX_KEM_SNTRUP761X25519_SHA512: kex_exchange = 9;
pub const KEX_C25519_SHA256: kex_exchange = 8;
pub const KEX_ECDH_SHA2: kex_exchange = 7;
pub const KEX_DH_GEX_SHA256: kex_exchange = 6;
pub const KEX_DH_GEX_SHA1: kex_exchange = 5;
pub const KEX_DH_GRP18_SHA512: kex_exchange = 4;
pub const KEX_DH_GRP16_SHA512: kex_exchange = 3;
pub const KEX_DH_GRP14_SHA256: kex_exchange = 2;
pub const KEX_DH_GRP14_SHA1: kex_exchange = 1;
pub const KEX_DH_GRP1_SHA1: kex_exchange = 0;

pub unsafe extern "C" fn kex_dh_keygen(mut kex: *mut kex) -> libc::c_int {
    match (*kex).kex_type {
        0 => {
            (*kex).dh = dh_new_group1();
        }
        1 | 2 => {
            (*kex).dh = dh_new_group14();
        }
        3 => {
            (*kex).dh = dh_new_group16();
        }
        4 => {
            (*kex).dh = dh_new_group18();
        }
        _ => return -(10 as libc::c_int),
    }
    if ((*kex).dh).is_null() {
        return -(2 as libc::c_int);
    }
    return dh_gen_key(
        (*kex).dh,
        ((*kex).we_need).wrapping_mul(8 as libc::c_int as libc::c_uint) as libc::c_int,
    );
}
pub unsafe extern "C" fn kex_dh_compute_key(
    mut kex: *mut kex,
    mut dh_pub: *mut BIGNUM,
    mut out: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut shared_secret: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut kbuf: *mut u_char = 0 as *mut u_char;
    let mut klen: size_t = 0 as libc::c_int as size_t;
    let mut kout: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    if dh_pub_is_valid((*kex).dh, dh_pub) == 0 {
        r = -(3 as libc::c_int);
    } else {
        klen = DH_size((*kex).dh) as size_t;
        kbuf = libc::malloc(klen as usize) as *mut u_char;
        if kbuf.is_null() || {
            shared_secret = BN_new();
            shared_secret.is_null()
        } {
            r = -(2 as libc::c_int);
        } else {
            kout = DH_compute_key(kbuf, dh_pub, (*kex).dh);
            if kout < 0 as libc::c_int || (BN_bin2bn(kbuf, kout, shared_secret)).is_null() {
                r = -(22 as libc::c_int);
            } else {
                r = sshbuf_put_bignum2(out, shared_secret);
            }
        }
    }
    freezero(kbuf as *mut libc::c_void, klen);
    BN_clear_free(shared_secret);
    return r;
}
pub unsafe extern "C" fn kex_dh_keypair(mut kex: *mut kex) -> libc::c_int {
    let mut pub_key: *const BIGNUM = 0 as *const BIGNUM;
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    r = kex_dh_keygen(kex);
    if r != 0 as libc::c_int {
        return r;
    }
    DH_get0_key((*kex).dh, &mut pub_key, 0 as *mut *const BIGNUM);
    buf = crate::sshbuf::sshbuf_new();
    if buf.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put_bignum2(buf, pub_key);
    if !(r != 0 as libc::c_int || {
        r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, 0 as *mut u_int32_t);
        r != 0 as libc::c_int
    }) {
        (*kex).client_pub = buf;
        buf = 0 as *mut crate::sshbuf::sshbuf;
    }
    crate::sshbuf::sshbuf_free(buf);
    return r;
}
pub unsafe extern "C" fn kex_dh_enc(
    mut kex: *mut kex,
    mut client_blob: *const crate::sshbuf::sshbuf,
    mut server_blobp: *mut *mut crate::sshbuf::sshbuf,
    mut shared_secretp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut pub_key: *const BIGNUM = 0 as *const BIGNUM;
    let mut server_blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    *server_blobp = 0 as *mut crate::sshbuf::sshbuf;
    *shared_secretp = 0 as *mut crate::sshbuf::sshbuf;
    r = kex_dh_keygen(kex);
    if !(r != 0 as libc::c_int) {
        DH_get0_key((*kex).dh, &mut pub_key, 0 as *mut *const BIGNUM);
        server_blob = crate::sshbuf::sshbuf_new();
        if server_blob.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = sshbuf_put_bignum2(server_blob, pub_key);
            if !(r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(server_blob, 0 as *mut u_int32_t);
                r != 0 as libc::c_int
            }) {
                r = kex_dh_dec(kex, client_blob, shared_secretp);
                if !(r != 0 as libc::c_int) {
                    *server_blobp = server_blob;
                    server_blob = 0 as *mut crate::sshbuf::sshbuf;
                }
            }
        }
    }
    DH_free((*kex).dh);
    (*kex).dh = 0 as *mut DH;
    crate::sshbuf::sshbuf_free(server_blob);
    return r;
}
pub unsafe extern "C" fn kex_dh_dec(
    mut kex: *mut kex,
    mut dh_blob: *const crate::sshbuf::sshbuf,
    mut shared_secretp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut dh_pub: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut r: libc::c_int = 0;
    *shared_secretp = 0 as *mut crate::sshbuf::sshbuf;
    buf = crate::sshbuf::sshbuf_new();
    if buf.is_null() {
        r = -(2 as libc::c_int);
    } else {
        r = sshbuf_put_stringb(buf, dh_blob);
        if !(r != 0 as libc::c_int || {
            r = sshbuf_get_bignum2(buf, &mut dh_pub);
            r != 0 as libc::c_int
        }) {
            crate::sshbuf::sshbuf_reset(buf);
            r = kex_dh_compute_key(kex, dh_pub, buf);
            if !(r != 0 as libc::c_int) {
                *shared_secretp = buf;
                buf = 0 as *mut crate::sshbuf::sshbuf;
            }
        }
    }
    BN_free(dh_pub);
    DH_free((*kex).dh);
    (*kex).dh = 0 as *mut DH;
    crate::sshbuf::sshbuf_free(buf);
    return r;
}
