use ::libc;
extern "C" {
    pub type ssh;
    pub type sshbuf;
    pub type bignum_st;
    pub type dh_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    pub type ec_group_st;
    pub type umac_ctx;
    pub type ssh_hmac_ctx;
    pub type sshcipher;
    fn freezero(_: *mut libc::c_void, _: size_t);

    fn BN_new() -> *mut BIGNUM;
    fn BN_clear_free(a: *mut BIGNUM);
    fn BN_bin2bn(s: *const libc::c_uchar, len: libc::c_int, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_free(a: *mut BIGNUM);
    fn DH_free(dh: *mut DH);
    fn DH_size(dh: *const DH) -> libc::c_int;
    fn DH_compute_key(key: *mut libc::c_uchar, pub_key: *const BIGNUM, dh: *mut DH) -> libc::c_int;
    fn DH_get0_key(dh: *const DH, pub_key: *mut *const BIGNUM, priv_key: *mut *const BIGNUM);
    fn sshbuf_new() -> *mut sshbuf;
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_reset(buf: *mut sshbuf);
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_put_stringb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_get_bignum2(buf: *mut sshbuf, valp: *mut *mut BIGNUM) -> libc::c_int;
    fn sshbuf_put_bignum2(buf: *mut sshbuf, v: *const BIGNUM) -> libc::c_int;
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
pub type BIGNUM = bignum_st;
pub type DH = dh_st;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type EC_KEY = ec_key_st;
pub type EC_GROUP = ec_group_st;
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
pub struct sshmac {
    pub name: *mut libc::c_char,
    pub enabled: libc::c_int,
    pub mac_len: u_int,
    pub key: *mut u_char,
    pub key_len: u_int,
    pub type_0: libc::c_int,
    pub etm: libc::c_int,
    pub hmac_ctx: *mut ssh_hmac_ctx,
    pub umac_ctx: *mut umac_ctx,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshenc {
    pub name: *mut libc::c_char,
    pub cipher: *const sshcipher,
    pub enabled: libc::c_int,
    pub key_len: u_int,
    pub iv_len: u_int,
    pub block_size: u_int,
    pub key: *mut u_char,
    pub iv: *mut u_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshcomp {
    pub type_0: u_int,
    pub enabled: libc::c_int,
    pub name: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct newkeys {
    pub enc: sshenc,
    pub mac: sshmac,
    pub comp: sshcomp,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct kex {
    pub newkeys: [*mut newkeys; 2],
    pub we_need: u_int,
    pub dh_need: u_int,
    pub server: libc::c_int,
    pub name: *mut libc::c_char,
    pub hostkey_alg: *mut libc::c_char,
    pub hostkey_type: libc::c_int,
    pub hostkey_nid: libc::c_int,
    pub kex_type: u_int,
    pub server_sig_algs: *mut libc::c_char,
    pub ext_info_c: libc::c_int,
    pub my: *mut sshbuf,
    pub peer: *mut sshbuf,
    pub client_version: *mut sshbuf,
    pub server_version: *mut sshbuf,
    pub session_id: *mut sshbuf,
    pub initial_sig: *mut sshbuf,
    pub initial_hostkey: *mut sshkey,
    pub done: sig_atomic_t,
    pub flags: u_int,
    pub hash_alg: libc::c_int,
    pub ec_nid: libc::c_int,
    pub failed_choice: *mut libc::c_char,
    pub verify_host_key: Option<unsafe extern "C" fn(*mut sshkey, *mut ssh) -> libc::c_int>,
    pub load_host_public_key:
        Option<unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut sshkey>,
    pub load_host_private_key:
        Option<unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut sshkey>,
    pub host_key_index:
        Option<unsafe extern "C" fn(*mut sshkey, libc::c_int, *mut ssh) -> libc::c_int>,
    pub sign: Option<
        unsafe extern "C" fn(
            *mut ssh,
            *mut sshkey,
            *mut sshkey,
            *mut *mut u_char,
            *mut size_t,
            *const u_char,
            size_t,
            *const libc::c_char,
        ) -> libc::c_int,
    >,
    pub kex: [Option<unsafe extern "C" fn(*mut ssh) -> libc::c_int>; 10],
    pub dh: *mut DH,
    pub min: u_int,
    pub max: u_int,
    pub nbits: u_int,
    pub ec_client_key: *mut EC_KEY,
    pub ec_group: *const EC_GROUP,
    pub c25519_client_key: [u_char; 32],
    pub c25519_client_pubkey: [u_char; 32],
    pub sntrup761_client_key: [u_char; 1763],
    pub client_pub: *mut sshbuf,
}
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
    mut out: *mut sshbuf,
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
    let mut buf: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    r = kex_dh_keygen(kex);
    if r != 0 as libc::c_int {
        return r;
    }
    DH_get0_key((*kex).dh, &mut pub_key, 0 as *mut *const BIGNUM);
    buf = sshbuf_new();
    if buf.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put_bignum2(buf, pub_key);
    if !(r != 0 as libc::c_int || {
        r = sshbuf_get_u32(buf, 0 as *mut u_int32_t);
        r != 0 as libc::c_int
    }) {
        (*kex).client_pub = buf;
        buf = 0 as *mut sshbuf;
    }
    sshbuf_free(buf);
    return r;
}
pub unsafe extern "C" fn kex_dh_enc(
    mut kex: *mut kex,
    mut client_blob: *const sshbuf,
    mut server_blobp: *mut *mut sshbuf,
    mut shared_secretp: *mut *mut sshbuf,
) -> libc::c_int {
    let mut pub_key: *const BIGNUM = 0 as *const BIGNUM;
    let mut server_blob: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    *server_blobp = 0 as *mut sshbuf;
    *shared_secretp = 0 as *mut sshbuf;
    r = kex_dh_keygen(kex);
    if !(r != 0 as libc::c_int) {
        DH_get0_key((*kex).dh, &mut pub_key, 0 as *mut *const BIGNUM);
        server_blob = sshbuf_new();
        if server_blob.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = sshbuf_put_bignum2(server_blob, pub_key);
            if !(r != 0 as libc::c_int || {
                r = sshbuf_get_u32(server_blob, 0 as *mut u_int32_t);
                r != 0 as libc::c_int
            }) {
                r = kex_dh_dec(kex, client_blob, shared_secretp);
                if !(r != 0 as libc::c_int) {
                    *server_blobp = server_blob;
                    server_blob = 0 as *mut sshbuf;
                }
            }
        }
    }
    DH_free((*kex).dh);
    (*kex).dh = 0 as *mut DH;
    sshbuf_free(server_blob);
    return r;
}
pub unsafe extern "C" fn kex_dh_dec(
    mut kex: *mut kex,
    mut dh_blob: *const sshbuf,
    mut shared_secretp: *mut *mut sshbuf,
) -> libc::c_int {
    let mut buf: *mut sshbuf = 0 as *mut sshbuf;
    let mut dh_pub: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut r: libc::c_int = 0;
    *shared_secretp = 0 as *mut sshbuf;
    buf = sshbuf_new();
    if buf.is_null() {
        r = -(2 as libc::c_int);
    } else {
        r = sshbuf_put_stringb(buf, dh_blob);
        if !(r != 0 as libc::c_int || {
            r = sshbuf_get_bignum2(buf, &mut dh_pub);
            r != 0 as libc::c_int
        }) {
            sshbuf_reset(buf);
            r = kex_dh_compute_key(kex, dh_pub, buf);
            if !(r != 0 as libc::c_int) {
                *shared_secretp = buf;
                buf = 0 as *mut sshbuf;
            }
        }
    }
    BN_free(dh_pub);
    DH_free((*kex).dh);
    (*kex).dh = 0 as *mut DH;
    sshbuf_free(buf);
    return r;
}
