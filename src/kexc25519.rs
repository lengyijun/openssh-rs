use crate::kex::dh_st;

use crate::kex::kex;

use ::libc;
extern "C" {

    pub type ec_group_st;

    fn timingsafe_bcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn sshbuf_reserve(
        buf: *mut crate::sshbuf::sshbuf,
        len: size_t,
        dpp: *mut *mut u_char,
    ) -> libc::c_int;
    fn sshbuf_put_bignum2_bytes(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn crypto_scalarmult_curve25519(
        a: *mut u_char,
        b: *const u_char,
        c: *const u_char,
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

pub unsafe extern "C" fn kexc25519_keygen(mut key: *mut u_char, mut pub_0: *mut u_char) {
    static mut basepoint: [u_char; 32] = [
        9 as libc::c_int as u_char,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    arc4random_buf(key as *mut libc::c_void, 32 as libc::c_int as size_t);
    crypto_scalarmult_curve25519(pub_0, key as *const u_char, basepoint.as_ptr());
}
pub unsafe extern "C" fn kexc25519_shared_key_ext(
    mut key: *const u_char,
    mut pub_0: *const u_char,
    mut out: *mut crate::sshbuf::sshbuf,
    mut raw: libc::c_int,
) -> libc::c_int {
    let mut shared_key: [u_char; 32] = [0; 32];
    let mut zero: [u_char; 32] = [0; 32];
    let mut r: libc::c_int = 0;
    crypto_scalarmult_curve25519(shared_key.as_mut_ptr(), key, pub_0);
    explicit_bzero(
        zero.as_mut_ptr() as *mut libc::c_void,
        32 as libc::c_int as size_t,
    );
    if timingsafe_bcmp(
        zero.as_mut_ptr() as *const libc::c_void,
        shared_key.as_mut_ptr() as *const libc::c_void,
        32 as libc::c_int as size_t,
    ) == 0 as libc::c_int
    {
        return -(20 as libc::c_int);
    }
    if raw != 0 {
        r = crate::sshbuf_getput_basic::sshbuf_put(
            out,
            shared_key.as_mut_ptr() as *const libc::c_void,
            32 as libc::c_int as size_t,
        );
    } else {
        r = sshbuf_put_bignum2_bytes(
            out,
            shared_key.as_mut_ptr() as *const libc::c_void,
            32 as libc::c_int as size_t,
        );
    }
    explicit_bzero(
        shared_key.as_mut_ptr() as *mut libc::c_void,
        32 as libc::c_int as size_t,
    );
    return r;
}
pub unsafe extern "C" fn kexc25519_shared_key(
    mut key: *const u_char,
    mut pub_0: *const u_char,
    mut out: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    return kexc25519_shared_key_ext(key, pub_0, out, 0 as libc::c_int);
}
pub unsafe extern "C" fn kex_c25519_keypair(mut kex: *mut kex) -> libc::c_int {
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut cp: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    buf = crate::sshbuf::sshbuf_new();
    if buf.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_reserve(buf, 32 as libc::c_int as size_t, &mut cp);
    if !(r != 0 as libc::c_int) {
        kexc25519_keygen(((*kex).c25519_client_key).as_mut_ptr(), cp);
        (*kex).client_pub = buf;
        buf = 0 as *mut crate::sshbuf::sshbuf;
    }
    crate::sshbuf::sshbuf_free(buf);
    return r;
}
pub unsafe extern "C" fn kex_c25519_enc(
    mut _kex: *mut kex,
    mut client_blob: *const crate::sshbuf::sshbuf,
    mut server_blobp: *mut *mut crate::sshbuf::sshbuf,
    mut shared_secretp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut server_blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut client_pub: *const u_char = 0 as *const u_char;
    let mut server_pub: *mut u_char = 0 as *mut u_char;
    let mut server_key: [u_char; 32] = [0; 32];
    let mut r: libc::c_int = 0;
    *server_blobp = 0 as *mut crate::sshbuf::sshbuf;
    *shared_secretp = 0 as *mut crate::sshbuf::sshbuf;
    if crate::sshbuf::sshbuf_len(client_blob) != 32 as libc::c_int as libc::c_ulong {
        r = -(21 as libc::c_int);
    } else {
        client_pub = crate::sshbuf::sshbuf_ptr(client_blob);
        server_blob = crate::sshbuf::sshbuf_new();
        if server_blob.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = sshbuf_reserve(server_blob, 32 as libc::c_int as size_t, &mut server_pub);
            if !(r != 0 as libc::c_int) {
                kexc25519_keygen(server_key.as_mut_ptr(), server_pub);
                buf = crate::sshbuf::sshbuf_new();
                if buf.is_null() {
                    r = -(2 as libc::c_int);
                } else {
                    r = kexc25519_shared_key_ext(
                        server_key.as_mut_ptr() as *const u_char,
                        client_pub,
                        buf,
                        0 as libc::c_int,
                    );
                    if !(r < 0 as libc::c_int) {
                        *server_blobp = server_blob;
                        *shared_secretp = buf;
                        server_blob = 0 as *mut crate::sshbuf::sshbuf;
                        buf = 0 as *mut crate::sshbuf::sshbuf;
                    }
                }
            }
        }
    }
    explicit_bzero(
        server_key.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
    );
    crate::sshbuf::sshbuf_free(server_blob);
    crate::sshbuf::sshbuf_free(buf);
    return r;
}
pub unsafe extern "C" fn kex_c25519_dec(
    mut kex: *mut kex,
    mut server_blob: *const crate::sshbuf::sshbuf,
    mut shared_secretp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut server_pub: *const u_char = 0 as *const u_char;
    let mut r: libc::c_int = 0;
    *shared_secretp = 0 as *mut crate::sshbuf::sshbuf;
    if crate::sshbuf::sshbuf_len(server_blob) != 32 as libc::c_int as libc::c_ulong {
        r = -(21 as libc::c_int);
    } else {
        server_pub = crate::sshbuf::sshbuf_ptr(server_blob);
        buf = crate::sshbuf::sshbuf_new();
        if buf.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = kexc25519_shared_key_ext(
                ((*kex).c25519_client_key).as_mut_ptr() as *const u_char,
                server_pub,
                buf,
                0 as libc::c_int,
            );
            if !(r < 0 as libc::c_int) {
                *shared_secretp = buf;
                buf = 0 as *mut crate::sshbuf::sshbuf;
            }
        }
    }
    crate::sshbuf::sshbuf_free(buf);
    return r;
}
