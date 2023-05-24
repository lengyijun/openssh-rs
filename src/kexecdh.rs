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
    pub type ec_point_st;
    pub type umac_ctx;
    pub type ssh_hmac_ctx;
    pub type sshcipher;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn BN_new() -> *mut BIGNUM;
    fn BN_clear_free(a: *mut BIGNUM);
    fn BN_bin2bn(s: *const libc::c_uchar, len: libc::c_int, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn EC_GROUP_get_degree(group: *const EC_GROUP) -> libc::c_int;
    fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_clear_free(point: *mut EC_POINT);
    fn EC_KEY_new_by_curve_name(nid: libc::c_int) -> *mut EC_KEY;
    fn EC_KEY_free(key: *mut EC_KEY);
    fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;
    fn EC_KEY_get0_public_key(key: *const EC_KEY) -> *const EC_POINT;
    fn EC_KEY_generate_key(key: *mut EC_KEY) -> libc::c_int;
    fn ECDH_compute_key(
        out: *mut libc::c_void,
        outlen: size_t,
        pub_key: *const EC_POINT,
        ecdh: *const EC_KEY,
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
    fn sshbuf_new() -> *mut sshbuf;
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_reset(buf: *mut sshbuf);
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_put_stringb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_put_bignum2(buf: *mut sshbuf, v: *const BIGNUM) -> libc::c_int;
    fn sshbuf_get_ec(buf: *mut sshbuf, v: *mut EC_POINT, g: *const EC_GROUP) -> libc::c_int;
    fn sshbuf_put_ec(buf: *mut sshbuf, v: *const EC_POINT, g: *const EC_GROUP) -> libc::c_int;
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
pub type EC_POINT = ec_point_st;
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
pub unsafe extern "C" fn kex_ecdh_keypair(mut kex: *mut kex) -> libc::c_int {
    let mut client_key: *mut EC_KEY = 0 as *mut EC_KEY;
    let mut group: *const EC_GROUP = 0 as *const EC_GROUP;
    let mut public_key: *const EC_POINT = 0 as *const EC_POINT;
    let mut buf: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    client_key = EC_KEY_new_by_curve_name((*kex).ec_nid);
    if client_key.is_null() {
        r = -(2 as libc::c_int);
    } else if EC_KEY_generate_key(client_key) != 1 as libc::c_int {
        r = -(22 as libc::c_int);
    } else {
        group = EC_KEY_get0_group(client_key);
        public_key = EC_KEY_get0_public_key(client_key);
        buf = sshbuf_new();
        if buf.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = sshbuf_put_ec(buf, public_key, group);
            if !(r != 0 as libc::c_int || {
                r = sshbuf_get_u32(buf, 0 as *mut u_int32_t);
                r != 0 as libc::c_int
            }) {
                (*kex).ec_client_key = client_key;
                (*kex).ec_group = group;
                client_key = 0 as *mut EC_KEY;
                (*kex).client_pub = buf;
                buf = 0 as *mut sshbuf;
            }
        }
    }
    EC_KEY_free(client_key);
    sshbuf_free(buf);
    return r;
}
pub unsafe extern "C" fn kex_ecdh_enc(
    mut kex: *mut kex,
    mut client_blob: *const sshbuf,
    mut server_blobp: *mut *mut sshbuf,
    mut shared_secretp: *mut *mut sshbuf,
) -> libc::c_int {
    let mut group: *const EC_GROUP = 0 as *const EC_GROUP;
    let mut pub_key: *const EC_POINT = 0 as *const EC_POINT;
    let mut server_key: *mut EC_KEY = 0 as *mut EC_KEY;
    let mut server_blob: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    *server_blobp = 0 as *mut sshbuf;
    *shared_secretp = 0 as *mut sshbuf;
    server_key = EC_KEY_new_by_curve_name((*kex).ec_nid);
    if server_key.is_null() {
        r = -(2 as libc::c_int);
    } else if EC_KEY_generate_key(server_key) != 1 as libc::c_int {
        r = -(22 as libc::c_int);
    } else {
        group = EC_KEY_get0_group(server_key);
        pub_key = EC_KEY_get0_public_key(server_key);
        server_blob = sshbuf_new();
        if server_blob.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = sshbuf_put_ec(server_blob, pub_key, group);
            if !(r != 0 as libc::c_int || {
                r = sshbuf_get_u32(server_blob, 0 as *mut u_int32_t);
                r != 0 as libc::c_int
            }) {
                r = kex_ecdh_dec_key_group(kex, client_blob, server_key, group, shared_secretp);
                if !(r != 0 as libc::c_int) {
                    *server_blobp = server_blob;
                    server_blob = 0 as *mut sshbuf;
                }
            }
        }
    }
    EC_KEY_free(server_key);
    sshbuf_free(server_blob);
    return r;
}
unsafe extern "C" fn kex_ecdh_dec_key_group(
    mut _kex: *mut kex,
    mut ec_blob: *const sshbuf,
    mut key: *mut EC_KEY,
    mut group: *const EC_GROUP,
    mut shared_secretp: *mut *mut sshbuf,
) -> libc::c_int {
    let mut buf: *mut sshbuf = 0 as *mut sshbuf;
    let mut shared_secret: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dh_pub: *mut EC_POINT = 0 as *mut EC_POINT;
    let mut kbuf: *mut u_char = 0 as *mut u_char;
    let mut klen: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    *shared_secretp = 0 as *mut sshbuf;
    buf = sshbuf_new();
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
                    sshbuf_reset(buf);
                    if sshkey_ec_validate_public(group, dh_pub) != 0 as libc::c_int {
                        r = -(3 as libc::c_int);
                    } else {
                        klen = ((EC_GROUP_get_degree(group) + 7 as libc::c_int) / 8 as libc::c_int)
                            as size_t;
                        kbuf = malloc(klen) as *mut u_char;
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
                                buf = 0 as *mut sshbuf;
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
    sshbuf_free(buf);
    return r;
}
pub unsafe extern "C" fn kex_ecdh_dec(
    mut kex: *mut kex,
    mut server_blob: *const sshbuf,
    mut shared_secretp: *mut *mut sshbuf,
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
    (*kex).ec_client_key = 0 as *mut EC_KEY;
    return r;
}
