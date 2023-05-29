use crate::digest_openssl::ssh_digest_ctx;
use ::libc;
extern "C" {

    fn freezero(_: *mut libc::c_void, _: size_t);
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_digest_blocksize(ctx: *mut ssh_digest_ctx) -> size_t;
    fn ssh_digest_copy_state(from: *mut ssh_digest_ctx, to: *mut ssh_digest_ctx) -> libc::c_int;
    fn ssh_digest_memory(
        alg: libc::c_int,
        m: *const libc::c_void,
        mlen: size_t,
        d: *mut u_char,
        dlen: size_t,
    ) -> libc::c_int;
    fn ssh_digest_start(alg: libc::c_int) -> *mut ssh_digest_ctx;
    fn ssh_digest_update(
        ctx: *mut ssh_digest_ctx,
        m: *const libc::c_void,
        mlen: size_t,
    ) -> libc::c_int;
    fn ssh_digest_update_buffer(
        ctx: *mut ssh_digest_ctx,
        b: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn ssh_digest_final(ctx: *mut ssh_digest_ctx, d: *mut u_char, dlen: size_t) -> libc::c_int;
    fn ssh_digest_free(ctx: *mut ssh_digest_ctx);
}
pub type __u_char = libc::c_uchar;
pub type u_char = __u_char;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh_hmac_ctx {
    pub alg: libc::c_int,
    pub ictx: *mut ssh_digest_ctx,
    pub octx: *mut ssh_digest_ctx,
    pub digest: *mut ssh_digest_ctx,
    pub buf: *mut u_char,
    pub buf_len: size_t,
}
pub unsafe extern "C" fn ssh_hmac_bytes(mut alg: libc::c_int) -> size_t {
    return ssh_digest_bytes(alg);
}
pub unsafe extern "C" fn ssh_hmac_start(mut alg: libc::c_int) -> *mut ssh_hmac_ctx {
    let mut ret: *mut ssh_hmac_ctx = 0 as *mut ssh_hmac_ctx;
    ret = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<ssh_hmac_ctx>() as libc::c_ulong,
    ) as *mut ssh_hmac_ctx;
    if ret.is_null() {
        return 0 as *mut ssh_hmac_ctx;
    }
    (*ret).alg = alg;
    (*ret).ictx = ssh_digest_start(alg);
    if !(((*ret).ictx).is_null()
        || {
            (*ret).octx = ssh_digest_start(alg);
            ((*ret).octx).is_null()
        }
        || {
            (*ret).digest = ssh_digest_start(alg);
            ((*ret).digest).is_null()
        })
    {
        (*ret).buf_len = ssh_digest_blocksize((*ret).ictx);
        (*ret).buf = calloc(1 as libc::c_int as libc::c_ulong, (*ret).buf_len) as *mut u_char;
        if !((*ret).buf).is_null() {
            return ret;
        }
    }
    ssh_hmac_free(ret);
    return 0 as *mut ssh_hmac_ctx;
}
pub unsafe extern "C" fn ssh_hmac_init(
    mut ctx: *mut ssh_hmac_ctx,
    mut key: *const libc::c_void,
    mut klen: size_t,
) -> libc::c_int {
    let mut i: size_t = 0;
    if !key.is_null() {
        if klen <= (*ctx).buf_len {
            memcpy((*ctx).buf as *mut libc::c_void, key, klen);
        } else if ssh_digest_memory((*ctx).alg, key, klen, (*ctx).buf, (*ctx).buf_len)
            < 0 as libc::c_int
        {
            return -(1 as libc::c_int);
        }
        i = 0 as libc::c_int as size_t;
        while i < (*ctx).buf_len {
            let ref mut fresh0 = *((*ctx).buf).offset(i as isize);
            *fresh0 = (*fresh0 as libc::c_int ^ 0x36 as libc::c_int) as u_char;
            i = i.wrapping_add(1);
            i;
        }
        if ssh_digest_update(
            (*ctx).ictx,
            (*ctx).buf as *const libc::c_void,
            (*ctx).buf_len,
        ) < 0 as libc::c_int
        {
            return -(1 as libc::c_int);
        }
        i = 0 as libc::c_int as size_t;
        while i < (*ctx).buf_len {
            let ref mut fresh1 = *((*ctx).buf).offset(i as isize);
            *fresh1 =
                (*fresh1 as libc::c_int ^ (0x36 as libc::c_int ^ 0x5c as libc::c_int)) as u_char;
            i = i.wrapping_add(1);
            i;
        }
        if ssh_digest_update(
            (*ctx).octx,
            (*ctx).buf as *const libc::c_void,
            (*ctx).buf_len,
        ) < 0 as libc::c_int
        {
            return -(1 as libc::c_int);
        }
        explicit_bzero((*ctx).buf as *mut libc::c_void, (*ctx).buf_len);
    }
    if ssh_digest_copy_state((*ctx).ictx, (*ctx).digest) < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_hmac_update(
    mut ctx: *mut ssh_hmac_ctx,
    mut m: *const libc::c_void,
    mut mlen: size_t,
) -> libc::c_int {
    return ssh_digest_update((*ctx).digest, m, mlen);
}
pub unsafe extern "C" fn ssh_hmac_update_buffer(
    mut ctx: *mut ssh_hmac_ctx,
    mut b: *const crate::sshbuf::sshbuf,
) -> libc::c_int {
    return ssh_digest_update_buffer((*ctx).digest, b);
}
pub unsafe extern "C" fn ssh_hmac_final(
    mut ctx: *mut ssh_hmac_ctx,
    mut d: *mut u_char,
    mut dlen: size_t,
) -> libc::c_int {
    let mut len: size_t = 0;
    len = ssh_digest_bytes((*ctx).alg);
    if dlen < len || ssh_digest_final((*ctx).digest, (*ctx).buf, len) != 0 {
        return -(1 as libc::c_int);
    }
    if ssh_digest_copy_state((*ctx).octx, (*ctx).digest) < 0 as libc::c_int
        || ssh_digest_update((*ctx).digest, (*ctx).buf as *const libc::c_void, len)
            < 0 as libc::c_int
        || ssh_digest_final((*ctx).digest, d, dlen) < 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_hmac_free(mut ctx: *mut ssh_hmac_ctx) {
    if !ctx.is_null() {
        ssh_digest_free((*ctx).ictx);
        ssh_digest_free((*ctx).octx);
        ssh_digest_free((*ctx).digest);
        if !((*ctx).buf).is_null() {
            explicit_bzero((*ctx).buf as *mut libc::c_void, (*ctx).buf_len);
            libc::free((*ctx).buf as *mut libc::c_void);
        }
        freezero(
            ctx as *mut libc::c_void,
            ::core::mem::size_of::<ssh_hmac_ctx>() as libc::c_ulong,
        );
    }
}
