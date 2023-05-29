use crate::mac::sshmac;
use crate::sshkey::EC_GROUP;

use crate::kex::sshenc;

use ::libc;
extern "C" {
    pub type ssh;

    pub type dh_st;

    pub type ec_group_st;

    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn crypto_kem_sntrup761_enc(
        cstr: *mut libc::c_uchar,
        k: *mut libc::c_uchar,
        pk: *const libc::c_uchar,
    ) -> libc::c_int;
    fn crypto_kem_sntrup761_dec(
        k: *mut libc::c_uchar,
        cstr: *const libc::c_uchar,
        sk: *const libc::c_uchar,
    ) -> libc::c_int;
    fn crypto_kem_sntrup761_keypair(pk: *mut libc::c_uchar, sk: *mut libc::c_uchar) -> libc::c_int;
    fn kexc25519_keygen(key: *mut u_char, pub_0: *mut u_char);
    fn kexc25519_shared_key_ext(
        key: *const u_char,
        pub_0: *const u_char,
        out: *mut crate::sshbuf::sshbuf,
        _: libc::c_int,
    ) -> libc::c_int;

    fn sshbuf_reserve(
        buf: *mut crate::sshbuf::sshbuf,
        len: size_t,
        dpp: *mut *mut u_char,
    ) -> libc::c_int;

    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_digest_buffer(
        alg: libc::c_int,
        b: *const crate::sshbuf::sshbuf,
        d: *mut u_char,
        dlen: size_t,
    ) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int64_t = __uint64_t;
pub type uint8_t = __uint8_t;
pub type sig_atomic_t = __sig_atomic_t;
pub type DH = dh_st;

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
pub unsafe extern "C" fn kex_kem_sntrup761x25519_keypair(mut kex: *mut kex) -> libc::c_int {
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut cp: *mut u_char = 0 as *mut u_char;
    let mut need: size_t = 0;
    let mut r: libc::c_int = 0;
    buf = crate::sshbuf::sshbuf_new();
    if buf.is_null() {
        return -(2 as libc::c_int);
    }
    need = (1158 as libc::c_int + 32 as libc::c_int) as size_t;
    r = sshbuf_reserve(buf, need, &mut cp);
    if !(r != 0 as libc::c_int) {
        crypto_kem_sntrup761_keypair(cp, ((*kex).sntrup761_client_key).as_mut_ptr());
        cp = cp.offset(1158 as libc::c_int as isize);
        kexc25519_keygen(((*kex).c25519_client_key).as_mut_ptr(), cp);
        (*kex).client_pub = buf;
        buf = 0 as *mut crate::sshbuf::sshbuf;
    }
    crate::sshbuf::sshbuf_free(buf);
    return r;
}
pub unsafe extern "C" fn kex_kem_sntrup761x25519_enc(
    mut kex: *mut kex,
    mut client_blob: *const crate::sshbuf::sshbuf,
    mut server_blobp: *mut *mut crate::sshbuf::sshbuf,
    mut shared_secretp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut server_blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut client_pub: *const u_char = 0 as *const u_char;
    let mut kem_key: *mut u_char = 0 as *mut u_char;
    let mut ciphertext: *mut u_char = 0 as *mut u_char;
    let mut server_pub: *mut u_char = 0 as *mut u_char;
    let mut server_key: [u_char; 32] = [0; 32];
    let mut hash: [u_char; 64] = [0; 64];
    let mut need: size_t = 0;
    let mut r: libc::c_int = 0;
    *server_blobp = 0 as *mut crate::sshbuf::sshbuf;
    *shared_secretp = 0 as *mut crate::sshbuf::sshbuf;
    need = (1158 as libc::c_int + 32 as libc::c_int) as size_t;
    if crate::sshbuf::sshbuf_len(client_blob) != need {
        r = -(21 as libc::c_int);
    } else {
        client_pub = crate::sshbuf::sshbuf_ptr(client_blob);
        buf = crate::sshbuf::sshbuf_new();
        if buf.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = sshbuf_reserve(buf, 32 as libc::c_int as size_t, &mut kem_key);
            if !(r != 0 as libc::c_int) {
                server_blob = crate::sshbuf::sshbuf_new();
                if server_blob.is_null() {
                    r = -(2 as libc::c_int);
                } else {
                    need = (1039 as libc::c_int + 32 as libc::c_int) as size_t;
                    r = sshbuf_reserve(server_blob, need, &mut ciphertext);
                    if !(r != 0 as libc::c_int) {
                        crypto_kem_sntrup761_enc(ciphertext, kem_key, client_pub);
                        server_pub = ciphertext.offset(1039 as libc::c_int as isize);
                        kexc25519_keygen(server_key.as_mut_ptr(), server_pub);
                        client_pub = client_pub.offset(1158 as libc::c_int as isize);
                        r = kexc25519_shared_key_ext(
                            server_key.as_mut_ptr() as *const u_char,
                            client_pub,
                            buf,
                            1 as libc::c_int,
                        );
                        if !(r < 0 as libc::c_int) {
                            r = ssh_digest_buffer(
                                (*kex).hash_alg,
                                buf,
                                hash.as_mut_ptr(),
                                ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
                            );
                            if !(r != 0 as libc::c_int) {
                                crate::sshbuf::sshbuf_reset(buf);
                                r = crate::sshbuf_getput_basic::sshbuf_put_string(
                                    buf,
                                    hash.as_mut_ptr() as *const libc::c_void,
                                    ssh_digest_bytes((*kex).hash_alg),
                                );
                                if !(r != 0 as libc::c_int) {
                                    *server_blobp = server_blob;
                                    *shared_secretp = buf;
                                    server_blob = 0 as *mut crate::sshbuf::sshbuf;
                                    buf = 0 as *mut crate::sshbuf::sshbuf;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    explicit_bzero(
        hash.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    explicit_bzero(
        server_key.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
    );
    crate::sshbuf::sshbuf_free(server_blob);
    crate::sshbuf::sshbuf_free(buf);
    return r;
}
pub unsafe extern "C" fn kex_kem_sntrup761x25519_dec(
    mut kex: *mut kex,
    mut server_blob: *const crate::sshbuf::sshbuf,
    mut shared_secretp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut kem_key: *mut u_char = 0 as *mut u_char;
    let mut ciphertext: *const u_char = 0 as *const u_char;
    let mut server_pub: *const u_char = 0 as *const u_char;
    let mut hash: [u_char; 64] = [0; 64];
    let mut need: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut decoded: libc::c_int = 0;
    *shared_secretp = 0 as *mut crate::sshbuf::sshbuf;
    need = (1039 as libc::c_int + 32 as libc::c_int) as size_t;
    if crate::sshbuf::sshbuf_len(server_blob) != need {
        r = -(21 as libc::c_int);
    } else {
        ciphertext = crate::sshbuf::sshbuf_ptr(server_blob);
        server_pub = ciphertext.offset(1039 as libc::c_int as isize);
        buf = crate::sshbuf::sshbuf_new();
        if buf.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = sshbuf_reserve(buf, 32 as libc::c_int as size_t, &mut kem_key);
            if !(r != 0 as libc::c_int) {
                decoded = crypto_kem_sntrup761_dec(
                    kem_key,
                    ciphertext,
                    ((*kex).sntrup761_client_key).as_mut_ptr(),
                );
                r = kexc25519_shared_key_ext(
                    ((*kex).c25519_client_key).as_mut_ptr() as *const u_char,
                    server_pub,
                    buf,
                    1 as libc::c_int,
                );
                if !(r < 0 as libc::c_int) {
                    r = ssh_digest_buffer(
                        (*kex).hash_alg,
                        buf,
                        hash.as_mut_ptr(),
                        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
                    );
                    if !(r != 0 as libc::c_int) {
                        crate::sshbuf::sshbuf_reset(buf);
                        r = crate::sshbuf_getput_basic::sshbuf_put_string(
                            buf,
                            hash.as_mut_ptr() as *const libc::c_void,
                            ssh_digest_bytes((*kex).hash_alg),
                        );
                        if !(r != 0 as libc::c_int) {
                            if decoded != 0 as libc::c_int {
                                r = -(21 as libc::c_int);
                            } else {
                                *shared_secretp = buf;
                                buf = 0 as *mut crate::sshbuf::sshbuf;
                            }
                        }
                    }
                }
            }
        }
    }
    explicit_bzero(
        hash.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    crate::sshbuf::sshbuf_free(buf);
    return r;
}
