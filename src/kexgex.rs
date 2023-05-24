use ::libc;
extern "C" {
    pub type sshbuf;
    pub type bignum_st;
    fn sshbuf_new() -> *mut sshbuf;
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_put(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_putb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_put_u8(buf: *mut sshbuf, val: u_char) -> libc::c_int;
    fn sshbuf_put_stringb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_put_bignum2(buf: *mut sshbuf, v: *const BIGNUM) -> libc::c_int;
    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_digest_buffer(
        alg: libc::c_int,
        b: *const sshbuf,
        d: *mut u_char,
        dlen: size_t,
    ) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type u_char = __u_char;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type BIGNUM = bignum_st;
pub unsafe extern "C" fn kexgex_hash(
    mut hash_alg: libc::c_int,
    mut client_version: *const sshbuf,
    mut server_version: *const sshbuf,
    mut client_kexinit: *const sshbuf,
    mut server_kexinit: *const sshbuf,
    mut server_host_key_blob: *const sshbuf,
    mut min: libc::c_int,
    mut wantbits: libc::c_int,
    mut max: libc::c_int,
    mut prime: *const BIGNUM,
    mut gen: *const BIGNUM,
    mut client_dh_pub: *const BIGNUM,
    mut server_dh_pub: *const BIGNUM,
    mut shared_secret: *const u_char,
    mut secretlen: size_t,
    mut hash: *mut u_char,
    mut hashlen: *mut size_t,
) -> libc::c_int {
    let mut b: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    if *hashlen < ssh_digest_bytes(1 as libc::c_int) {
        return -(10 as libc::c_int);
    }
    b = sshbuf_new();
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put_stringb(b, client_version);
    if r < 0 as libc::c_int
        || {
            r = sshbuf_put_stringb(b, server_version);
            r < 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(
                b,
                (sshbuf_len(client_kexinit)).wrapping_add(1 as libc::c_int as libc::c_ulong)
                    as u_int32_t,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u8(b, 20 as libc::c_int as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_putb(b, client_kexinit);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(
                b,
                (sshbuf_len(server_kexinit)).wrapping_add(1 as libc::c_int as libc::c_ulong)
                    as u_int32_t,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u8(b, 20 as libc::c_int as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_putb(b, server_kexinit);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(b, server_host_key_blob);
            r != 0 as libc::c_int
        }
        || min != -(1 as libc::c_int) && {
            r = sshbuf_put_u32(b, min as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(b, wantbits as u_int32_t);
            r != 0 as libc::c_int
        }
        || max != -(1 as libc::c_int) && {
            r = sshbuf_put_u32(b, max as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_bignum2(b, prime);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_bignum2(b, gen);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_bignum2(b, client_dh_pub);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_bignum2(b, server_dh_pub);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put(b, shared_secret as *const libc::c_void, secretlen);
            r != 0 as libc::c_int
        }
    {
        sshbuf_free(b);
        return r;
    }
    if ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0 as libc::c_int {
        sshbuf_free(b);
        return -(22 as libc::c_int);
    }
    sshbuf_free(b);
    *hashlen = ssh_digest_bytes(hash_alg);
    return 0 as libc::c_int;
}
