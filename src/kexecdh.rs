use crate::cipher::sshcipher;
use ::libc;
extern "C" {
    pub type ssh;

    pub type bignum_st;
    pub type dh_st;

    pub type ec_group_st;
    pub type ec_point_st;
    pub type umac_ctx;
    pub type ssh_hmac_ctx;

    fn freezero(_: *mut libc::c_void, _: size_t);

    fn BN_new() -> *mut BIGNUM;
    fn BN_clear_free(a: *mut BIGNUM);
    fn BN_bin2bn(s: *const libc::c_uchar, len: libc::c_int, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn EC_GROUP_get_degree(group: *const EC_GROUP) -> libc::c_int;
    fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_clear_free(point: *mut EC_POINT);
    fn EC_KEY_new_by_curve_name(nid: libc::c_int) -> *mut crate::sshkey::EC_KEY;
    fn EC_KEY_free(key: *mut crate::sshkey::EC_KEY);
    fn EC_KEY_get0_group(key: *const crate::sshkey::EC_KEY) -> *const EC_GROUP;
    fn EC_KEY_get0_public_key(key: *const crate::sshkey::EC_KEY) -> *const EC_POINT;
    fn EC_KEY_generate_key(key: *mut crate::sshkey::EC_KEY) -> libc::c_int;
    fn ECDH_compute_key(
        out: *mut libc::c_void,
        outlen: size_t,
        pub_key: *const EC_POINT,
        ecdh: *const crate::sshkey::EC_KEY,
        KDF: Option<
            unsafe extern "C" fn(
                *const libc::c_void,
                size_t,
                *mut libc::c_void,
                *mut size_t,
            ) -> *mut libc::c_void,
        >,
    ) -> libc::c_int;
    fn sshkey_ec_validate_public(_: *const EC_GROUP, _: *const EC_POINT) -> libc::c_int;

    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_put_bignum2(buf: *mut crate::sshbuf::sshbuf, v: *const BIGNUM) -> libc::c_int;
    fn sshbuf_get_ec(
        buf: *mut crate::sshbuf::sshbuf,
        v: *mut EC_POINT,
        g: *const EC_GROUP,
    ) -> libc::c_int;
    fn sshbuf_put_ec(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const EC_POINT,
        g: *const EC_GROUP,
    ) -> libc::c_int;
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

pub type EC_GROUP = ec_group_st;
pub type EC_POINT = ec_point_st;

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
    pub my: *mut crate::sshbuf::sshbuf,
    pub peer: *mut crate::sshbuf::sshbuf,
    pub client_version: *mut crate::sshbuf::sshbuf,
    pub server_version: *mut crate::sshbuf::sshbuf,
    pub session_id: *mut crate::sshbuf::sshbuf,
    pub initial_sig: *mut crate::sshbuf::sshbuf,
    pub initial_hostkey: *mut crate::sshkey::sshkey,
    pub done: sig_atomic_t,
    pub flags: u_int,
    pub hash_alg: libc::c_int,
    pub ec_nid: libc::c_int,
    pub failed_choice: *mut libc::c_char,
    pub verify_host_key:
        Option<unsafe extern "C" fn(*mut crate::sshkey::sshkey, *mut ssh) -> libc::c_int>,
    pub load_host_public_key: Option<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut crate::sshkey::sshkey,
    >,
    pub load_host_private_key: Option<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut crate::sshkey::sshkey,
    >,
    pub host_key_index: Option<
        unsafe extern "C" fn(*mut crate::sshkey::sshkey, libc::c_int, *mut ssh) -> libc::c_int,
    >,
    pub sign: Option<
        unsafe extern "C" fn(
            *mut ssh,
            *mut crate::sshkey::sshkey,
            *mut crate::sshkey::sshkey,
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
    pub ec_client_key: *mut crate::sshkey::EC_KEY,
    pub ec_group: *const EC_GROUP,
    pub c25519_client_key: [u_char; 32],
    pub c25519_client_pubkey: [u_char; 32],
    pub sntrup761_client_key: [u_char; 1763],
    pub client_pub: *mut crate::sshbuf::sshbuf,
}
pub unsafe extern "C" fn kex_ecdh_keypair(mut kex: *mut kex) -> libc::c_int {
    let mut client_key: *mut crate::sshkey::EC_KEY = 0 as *mut crate::sshkey::EC_KEY;
    let mut group: *const EC_GROUP = 0 as *const EC_GROUP;
    let mut public_key: *const EC_POINT = 0 as *const EC_POINT;
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    client_key = EC_KEY_new_by_curve_name((*kex).ec_nid);
    if client_key.is_null() {
        r = -(2 as libc::c_int);
    } else if EC_KEY_generate_key(client_key) != 1 as libc::c_int {
        r = -(22 as libc::c_int);
    } else {
        group = EC_KEY_get0_group(client_key);
        public_key = EC_KEY_get0_public_key(client_key);
        buf = crate::sshbuf::sshbuf_new();
        if buf.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = sshbuf_put_ec(buf, public_key, group);
            if !(r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, 0 as *mut u_int32_t);
                r != 0 as libc::c_int
            }) {
                (*kex).ec_client_key = client_key;
                (*kex).ec_group = group;
                client_key = 0 as *mut crate::sshkey::EC_KEY;
                (*kex).client_pub = buf;
                buf = 0 as *mut crate::sshbuf::sshbuf;
            }
        }
    }
    EC_KEY_free(client_key);
    crate::sshbuf::sshbuf_free(buf);
    return r;
}
pub unsafe extern "C" fn kex_ecdh_enc(
    mut kex: *mut kex,
    mut client_blob: *const crate::sshbuf::sshbuf,
    mut server_blobp: *mut *mut crate::sshbuf::sshbuf,
    mut shared_secretp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut group: *const EC_GROUP = 0 as *const EC_GROUP;
    let mut pub_key: *const EC_POINT = 0 as *const EC_POINT;
    let mut server_key: *mut crate::sshkey::EC_KEY = 0 as *mut crate::sshkey::EC_KEY;
    let mut server_blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    *server_blobp = 0 as *mut crate::sshbuf::sshbuf;
    *shared_secretp = 0 as *mut crate::sshbuf::sshbuf;
    server_key = EC_KEY_new_by_curve_name((*kex).ec_nid);
    if server_key.is_null() {
        r = -(2 as libc::c_int);
    } else if EC_KEY_generate_key(server_key) != 1 as libc::c_int {
        r = -(22 as libc::c_int);
    } else {
        group = EC_KEY_get0_group(server_key);
        pub_key = EC_KEY_get0_public_key(server_key);
        server_blob = crate::sshbuf::sshbuf_new();
        if server_blob.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = sshbuf_put_ec(server_blob, pub_key, group);
            if !(r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(server_blob, 0 as *mut u_int32_t);
                r != 0 as libc::c_int
            }) {
                r = kex_ecdh_dec_key_group(kex, client_blob, server_key, group, shared_secretp);
                if !(r != 0 as libc::c_int) {
                    *server_blobp = server_blob;
                    server_blob = 0 as *mut crate::sshbuf::sshbuf;
                }
            }
        }
    }
    EC_KEY_free(server_key);
    crate::sshbuf::sshbuf_free(server_blob);
    return r;
}
unsafe extern "C" fn kex_ecdh_dec_key_group(
    mut _kex: *mut kex,
    mut ec_blob: *const crate::sshbuf::sshbuf,
    mut key: *mut crate::sshkey::EC_KEY,
    mut group: *const EC_GROUP,
    mut shared_secretp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut shared_secret: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dh_pub: *mut EC_POINT = 0 as *mut EC_POINT;
    let mut kbuf: *mut u_char = 0 as *mut u_char;
    let mut klen: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    *shared_secretp = 0 as *mut crate::sshbuf::sshbuf;
    buf = crate::sshbuf::sshbuf_new();
    if buf.is_null() {
        r = -(2 as libc::c_int);
    } else {
        r = sshbuf_put_stringb(buf, ec_blob);
        if !(r != 0 as libc::c_int) {
            dh_pub = EC_POINT_new(group);
            if dh_pub.is_null() {
                r = -(2 as libc::c_int);
            } else {
                r = sshbuf_get_ec(buf, dh_pub, group);
                if !(r != 0 as libc::c_int) {
                    crate::sshbuf::sshbuf_reset(buf);
                    if sshkey_ec_validate_public(group, dh_pub) != 0 as libc::c_int {
                        r = -(3 as libc::c_int);
                    } else {
                        klen = ((EC_GROUP_get_degree(group) + 7 as libc::c_int) / 8 as libc::c_int)
                            as size_t;
                        kbuf = libc::malloc(klen as usize) as *mut u_char;
                        if kbuf.is_null() || {
                            shared_secret = BN_new();
                            shared_secret.is_null()
                        } {
                            r = -(2 as libc::c_int);
                        } else if ECDH_compute_key(
                            kbuf as *mut libc::c_void,
                            klen,
                            dh_pub,
                            key,
                            None,
                        ) != klen as libc::c_int
                            || (BN_bin2bn(kbuf, klen as libc::c_int, shared_secret)).is_null()
                        {
                            r = -(22 as libc::c_int);
                        } else {
                            r = sshbuf_put_bignum2(buf, shared_secret);
                            if !(r != 0 as libc::c_int) {
                                *shared_secretp = buf;
                                buf = 0 as *mut crate::sshbuf::sshbuf;
                            }
                        }
                    }
                }
            }
        }
    }
    EC_POINT_clear_free(dh_pub);
    BN_clear_free(shared_secret);
    freezero(kbuf as *mut libc::c_void, klen);
    crate::sshbuf::sshbuf_free(buf);
    return r;
}
pub unsafe extern "C" fn kex_ecdh_dec(
    mut kex: *mut kex,
    mut server_blob: *const crate::sshbuf::sshbuf,
    mut shared_secretp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = kex_ecdh_dec_key_group(
        kex,
        server_blob,
        (*kex).ec_client_key,
        (*kex).ec_group,
        shared_secretp,
    );
    EC_KEY_free((*kex).ec_client_key);
    (*kex).ec_client_key = 0 as *mut crate::sshkey::EC_KEY;
    return r;
}
