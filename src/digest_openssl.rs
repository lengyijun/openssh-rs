use ::libc;
extern "C" {

    pub type evp_md_st;
    pub type evp_md_ctx_st;
    pub type engine_st;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn EVP_MD_get_block_size(md: *const EVP_MD) -> libc::c_int;
    fn EVP_MD_CTX_get0_md(ctx: *const EVP_MD_CTX) -> *const EVP_MD;
    fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
    fn EVP_MD_CTX_copy_ex(out: *mut EVP_MD_CTX, in_0: *const EVP_MD_CTX) -> libc::c_int;
    fn EVP_DigestInit_ex(
        ctx: *mut EVP_MD_CTX,
        type_0: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, d: *const libc::c_void, cnt: size_t) -> libc::c_int;
    fn EVP_DigestFinal_ex(
        ctx: *mut EVP_MD_CTX,
        md: *mut libc::c_uchar,
        s: *mut libc::c_uint,
    ) -> libc::c_int;
    fn EVP_Digest(
        data: *const libc::c_void,
        count: size_t,
        md: *mut libc::c_uchar,
        size: *mut libc::c_uint,
        type_0: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_md5() -> *const EVP_MD;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_sha384() -> *const EVP_MD;
    fn EVP_sha512() -> *const EVP_MD;

    fn sshbuf_ptr(buf: *const crate::sshbuf::sshbuf) -> *const u_char;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type EVP_MD = evp_md_st;
pub type EVP_MD_CTX = evp_md_ctx_st;
pub type ENGINE = engine_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh_digest_ctx {
    pub alg: libc::c_int,
    pub mdctx: *mut EVP_MD_CTX,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh_digest {
    pub id: libc::c_int,
    pub name: *const libc::c_char,
    pub digest_len: size_t,
    pub mdfunc: Option<unsafe extern "C" fn() -> *const EVP_MD>,
}
pub static mut digests: [ssh_digest; 6] = unsafe {
    [
        {
            let mut init = ssh_digest {
                id: 0 as libc::c_int,
                name: b"MD5\0" as *const u8 as *const libc::c_char,
                digest_len: 16 as libc::c_int as size_t,
                mdfunc: Some(EVP_md5 as unsafe extern "C" fn() -> *const EVP_MD),
            };
            init
        },
        {
            let mut init = ssh_digest {
                id: 1 as libc::c_int,
                name: b"SHA1\0" as *const u8 as *const libc::c_char,
                digest_len: 20 as libc::c_int as size_t,
                mdfunc: Some(EVP_sha1 as unsafe extern "C" fn() -> *const EVP_MD),
            };
            init
        },
        {
            let mut init = ssh_digest {
                id: 2 as libc::c_int,
                name: b"SHA256\0" as *const u8 as *const libc::c_char,
                digest_len: 32 as libc::c_int as size_t,
                mdfunc: Some(EVP_sha256 as unsafe extern "C" fn() -> *const EVP_MD),
            };
            init
        },
        {
            let mut init = ssh_digest {
                id: 3 as libc::c_int,
                name: b"SHA384\0" as *const u8 as *const libc::c_char,
                digest_len: 48 as libc::c_int as size_t,
                mdfunc: Some(EVP_sha384 as unsafe extern "C" fn() -> *const EVP_MD),
            };
            init
        },
        {
            let mut init = ssh_digest {
                id: 4 as libc::c_int,
                name: b"SHA512\0" as *const u8 as *const libc::c_char,
                digest_len: 64 as libc::c_int as size_t,
                mdfunc: Some(EVP_sha512 as unsafe extern "C" fn() -> *const EVP_MD),
            };
            init
        },
        {
            let mut init = ssh_digest {
                id: -(1 as libc::c_int),
                name: 0 as *const libc::c_char,
                digest_len: 0 as libc::c_int as size_t,
                mdfunc: None,
            };
            init
        },
    ]
};
unsafe extern "C" fn ssh_digest_by_alg(mut alg: libc::c_int) -> *const ssh_digest {
    if alg < 0 as libc::c_int || alg >= 5 as libc::c_int {
        return 0 as *const ssh_digest;
    }
    if digests[alg as usize].id != alg {
        return 0 as *const ssh_digest;
    }
    if (digests[alg as usize].mdfunc).is_none() {
        return 0 as *const ssh_digest;
    }
    return &*digests.as_ptr().offset(alg as isize) as *const ssh_digest;
}
pub unsafe extern "C" fn ssh_digest_alg_by_name(mut name: *const libc::c_char) -> libc::c_int {
    let mut alg: libc::c_int = 0;
    alg = 0 as libc::c_int;
    while digests[alg as usize].id != -(1 as libc::c_int) {
        if strcasecmp(name, digests[alg as usize].name) == 0 as libc::c_int {
            return digests[alg as usize].id;
        }
        alg += 1;
        alg;
    }
    return -(1 as libc::c_int);
}
pub unsafe extern "C" fn ssh_digest_alg_name(mut alg: libc::c_int) -> *const libc::c_char {
    let mut digest: *const ssh_digest = ssh_digest_by_alg(alg);
    return if digest.is_null() {
        0 as *const libc::c_char
    } else {
        (*digest).name
    };
}
pub unsafe extern "C" fn ssh_digest_bytes(mut alg: libc::c_int) -> size_t {
    let mut digest: *const ssh_digest = ssh_digest_by_alg(alg);
    return if digest.is_null() {
        0 as libc::c_int as libc::c_ulong
    } else {
        (*digest).digest_len
    };
}
pub unsafe extern "C" fn ssh_digest_blocksize(mut ctx: *mut ssh_digest_ctx) -> size_t {
    return EVP_MD_get_block_size(EVP_MD_CTX_get0_md((*ctx).mdctx)) as size_t;
}
pub unsafe extern "C" fn ssh_digest_start(mut alg: libc::c_int) -> *mut ssh_digest_ctx {
    let mut digest: *const ssh_digest = ssh_digest_by_alg(alg);
    let mut ret: *mut ssh_digest_ctx = 0 as *mut ssh_digest_ctx;
    if digest.is_null() || {
        ret = calloc(
            1 as libc::c_int as libc::c_ulong,
            ::core::mem::size_of::<ssh_digest_ctx>() as libc::c_ulong,
        ) as *mut ssh_digest_ctx;
        ret.is_null()
    } {
        return 0 as *mut ssh_digest_ctx;
    }
    (*ret).alg = alg;
    (*ret).mdctx = EVP_MD_CTX_new();
    if ((*ret).mdctx).is_null() {
        libc::free(ret as *mut libc::c_void);
        return 0 as *mut ssh_digest_ctx;
    }
    if EVP_DigestInit_ex(
        (*ret).mdctx,
        ((*digest).mdfunc).expect("non-null function pointer")(),
        0 as *mut ENGINE,
    ) != 1 as libc::c_int
    {
        ssh_digest_free(ret);
        return 0 as *mut ssh_digest_ctx;
    }
    return ret;
}
pub unsafe extern "C" fn ssh_digest_copy_state(
    mut from: *mut ssh_digest_ctx,
    mut to: *mut ssh_digest_ctx,
) -> libc::c_int {
    if (*from).alg != (*to).alg {
        return -(10 as libc::c_int);
    }
    if EVP_MD_CTX_copy_ex((*to).mdctx, (*from).mdctx) == 0 {
        return -(22 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_digest_update(
    mut ctx: *mut ssh_digest_ctx,
    mut m: *const libc::c_void,
    mut mlen: size_t,
) -> libc::c_int {
    if EVP_DigestUpdate((*ctx).mdctx, m, mlen) != 1 as libc::c_int {
        return -(22 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_digest_update_buffer(
    mut ctx: *mut ssh_digest_ctx,
    mut b: *const crate::sshbuf::sshbuf,
) -> libc::c_int {
    return ssh_digest_update(
        ctx,
        sshbuf_ptr(b) as *const libc::c_void,
        crate::sshbuf::sshbuf_len(b),
    );
}
pub unsafe extern "C" fn ssh_digest_final(
    mut ctx: *mut ssh_digest_ctx,
    mut d: *mut u_char,
    mut dlen: size_t,
) -> libc::c_int {
    let mut digest: *const ssh_digest = ssh_digest_by_alg((*ctx).alg);
    let mut l: u_int = dlen as u_int;
    if digest.is_null()
        || dlen
            > (2147483647 as libc::c_int as libc::c_uint)
                .wrapping_mul(2 as libc::c_uint)
                .wrapping_add(1 as libc::c_uint) as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    if dlen < (*digest).digest_len {
        return -(10 as libc::c_int);
    }
    if EVP_DigestFinal_ex((*ctx).mdctx, d, &mut l) != 1 as libc::c_int {
        return -(22 as libc::c_int);
    }
    if l as libc::c_ulong != (*digest).digest_len {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_digest_free(mut ctx: *mut ssh_digest_ctx) {
    if ctx.is_null() {
        return;
    }
    EVP_MD_CTX_free((*ctx).mdctx);
    freezero(
        ctx as *mut libc::c_void,
        ::core::mem::size_of::<ssh_digest_ctx>() as libc::c_ulong,
    );
}
pub unsafe extern "C" fn ssh_digest_memory(
    mut alg: libc::c_int,
    mut m: *const libc::c_void,
    mut mlen: size_t,
    mut d: *mut u_char,
    mut dlen: size_t,
) -> libc::c_int {
    let mut digest: *const ssh_digest = ssh_digest_by_alg(alg);
    let mut mdlen: u_int = 0;
    if digest.is_null() {
        return -(10 as libc::c_int);
    }
    if dlen
        > (2147483647 as libc::c_int as libc::c_uint)
            .wrapping_mul(2 as libc::c_uint)
            .wrapping_add(1 as libc::c_uint) as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    if dlen < (*digest).digest_len {
        return -(10 as libc::c_int);
    }
    mdlen = dlen as u_int;
    if EVP_Digest(
        m,
        mlen,
        d,
        &mut mdlen,
        ((*digest).mdfunc).expect("non-null function pointer")(),
        0 as *mut ENGINE,
    ) == 0
    {
        return -(22 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_digest_buffer(
    mut alg: libc::c_int,
    mut b: *const crate::sshbuf::sshbuf,
    mut d: *mut u_char,
    mut dlen: size_t,
) -> libc::c_int {
    return ssh_digest_memory(
        alg,
        sshbuf_ptr(b) as *const libc::c_void,
        crate::sshbuf::sshbuf_len(b),
        d,
        dlen,
    );
}
