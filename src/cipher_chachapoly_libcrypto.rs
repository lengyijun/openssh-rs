use ::libc;
extern "C" {
    pub type evp_cipher_st;
    pub type evp_cipher_ctx_st;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn timingsafe_bcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn EVP_CIPHER_CTX_get_iv_length(ctx: *const EVP_CIPHER_CTX) -> libc::c_int;
    fn EVP_Cipher(
        c: *mut EVP_CIPHER_CTX,
        out: *mut libc::c_uchar,
        in_0: *const libc::c_uchar,
        inl: libc::c_uint,
    ) -> libc::c_int;
    fn EVP_CipherInit(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        key: *const libc::c_uchar,
        iv: *const libc::c_uchar,
        enc: libc::c_int,
    ) -> libc::c_int;
    fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_free(c: *mut EVP_CIPHER_CTX);
    fn EVP_chacha20() -> *const EVP_CIPHER;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn poly1305_auth(out: *mut u_char, m: *const u_char, inlen: size_t, key: *const u_char);
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type EVP_CIPHER = evp_cipher_st;
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct chachapoly_ctx {
    pub main_evp: *mut EVP_CIPHER_CTX,
    pub header_evp: *mut EVP_CIPHER_CTX,
}
pub unsafe extern "C" fn chachapoly_new(
    mut key: *const u_char,
    mut keylen: u_int,
) -> *mut chachapoly_ctx {
    let mut ctx: *mut chachapoly_ctx = 0 as *mut chachapoly_ctx;
    if keylen != (32 as libc::c_int + 32 as libc::c_int) as libc::c_uint {
        return 0 as *mut chachapoly_ctx;
    }
    ctx = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<chachapoly_ctx>() as libc::c_ulong,
    ) as *mut chachapoly_ctx;
    if ctx.is_null() {
        return 0 as *mut chachapoly_ctx;
    }
    (*ctx).main_evp = EVP_CIPHER_CTX_new();
    if !(((*ctx).main_evp).is_null() || {
        (*ctx).header_evp = EVP_CIPHER_CTX_new();
        ((*ctx).header_evp).is_null()
    }) {
        if !(EVP_CipherInit(
            (*ctx).main_evp,
            EVP_chacha20(),
            key,
            0 as *const libc::c_uchar,
            1 as libc::c_int,
        ) == 0)
        {
            if !(EVP_CipherInit(
                (*ctx).header_evp,
                EVP_chacha20(),
                key.offset(32 as libc::c_int as isize),
                0 as *const libc::c_uchar,
                1 as libc::c_int,
            ) == 0)
            {
                if !(EVP_CIPHER_CTX_get_iv_length((*ctx).header_evp) != 16 as libc::c_int) {
                    return ctx;
                }
            }
        }
    }
    chachapoly_free(ctx);
    return 0 as *mut chachapoly_ctx;
}
pub unsafe extern "C" fn chachapoly_free(mut cpctx: *mut chachapoly_ctx) {
    if cpctx.is_null() {
        return;
    }
    EVP_CIPHER_CTX_free((*cpctx).main_evp);
    EVP_CIPHER_CTX_free((*cpctx).header_evp);
    freezero(
        cpctx as *mut libc::c_void,
        ::core::mem::size_of::<chachapoly_ctx>() as libc::c_ulong,
    );
}
pub unsafe extern "C" fn chachapoly_crypt(
    mut ctx: *mut chachapoly_ctx,
    mut seqnr: u_int,
    mut dest: *mut u_char,
    mut src: *const u_char,
    mut len: u_int,
    mut aadlen: u_int,
    mut _authlen: u_int,
    mut do_encrypt: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut seqbuf: [u_char; 16] = [0; 16];
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut expected_tag: [u_char; 16] = [0; 16];
    let mut poly_key: [u_char; 32] = [0; 32];
    memset(
        seqbuf.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[u_char; 16]>() as libc::c_ulong,
    );
    let __v: u_int64_t = seqnr as u_int64_t;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) =
        (__v >> 56 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(1 as libc::c_int as isize) =
        (__v >> 48 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(2 as libc::c_int as isize) =
        (__v >> 40 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(3 as libc::c_int as isize) =
        (__v >> 32 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(4 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(5 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(6 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(7 as libc::c_int as isize) = (__v & 0xff as libc::c_int as libc::c_ulong) as u_char;
    memset(
        poly_key.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
    );
    if EVP_CipherInit(
        (*ctx).main_evp,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        seqbuf.as_mut_ptr(),
        1 as libc::c_int,
    ) == 0
        || EVP_Cipher(
            (*ctx).main_evp,
            poly_key.as_mut_ptr(),
            poly_key.as_mut_ptr(),
            ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong as libc::c_uint,
        ) < 0 as libc::c_int
    {
        r = -(22 as libc::c_int);
    } else {
        if do_encrypt == 0 {
            let mut tag: *const u_char = src.offset(aadlen as isize).offset(len as isize);
            poly1305_auth(
                expected_tag.as_mut_ptr(),
                src,
                aadlen.wrapping_add(len) as size_t,
                poly_key.as_mut_ptr() as *const u_char,
            );
            if timingsafe_bcmp(
                expected_tag.as_mut_ptr() as *const libc::c_void,
                tag as *const libc::c_void,
                16 as libc::c_int as size_t,
            ) != 0 as libc::c_int
            {
                r = -(30 as libc::c_int);
                current_block = 9447491583919733504;
            } else {
                current_block = 13056961889198038528;
            }
        } else {
            current_block = 13056961889198038528;
        }
        match current_block {
            9447491583919733504 => {}
            _ => {
                if aadlen != 0 {
                    if EVP_CipherInit(
                        (*ctx).header_evp,
                        0 as *const EVP_CIPHER,
                        0 as *const libc::c_uchar,
                        seqbuf.as_mut_ptr(),
                        1 as libc::c_int,
                    ) == 0
                        || EVP_Cipher((*ctx).header_evp, dest, src, aadlen) < 0 as libc::c_int
                    {
                        r = -(22 as libc::c_int);
                        current_block = 9447491583919733504;
                    } else {
                        current_block = 13242334135786603907;
                    }
                } else {
                    current_block = 13242334135786603907;
                }
                match current_block {
                    9447491583919733504 => {}
                    _ => {
                        seqbuf[0 as libc::c_int as usize] = 1 as libc::c_int as u_char;
                        if EVP_CipherInit(
                            (*ctx).main_evp,
                            0 as *const EVP_CIPHER,
                            0 as *const libc::c_uchar,
                            seqbuf.as_mut_ptr(),
                            1 as libc::c_int,
                        ) == 0
                            || EVP_Cipher(
                                (*ctx).main_evp,
                                dest.offset(aadlen as isize),
                                src.offset(aadlen as isize),
                                len,
                            ) < 0 as libc::c_int
                        {
                            r = -(22 as libc::c_int);
                        } else {
                            if do_encrypt != 0 {
                                poly1305_auth(
                                    dest.offset(aadlen as isize).offset(len as isize),
                                    dest,
                                    aadlen.wrapping_add(len) as size_t,
                                    poly_key.as_mut_ptr() as *const u_char,
                                );
                            }
                            r = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    explicit_bzero(
        expected_tag.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 16]>() as libc::c_ulong,
    );
    explicit_bzero(
        seqbuf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 16]>() as libc::c_ulong,
    );
    explicit_bzero(
        poly_key.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
    );
    return r;
}
pub unsafe extern "C" fn chachapoly_get_length(
    mut ctx: *mut chachapoly_ctx,
    mut plenp: *mut u_int,
    mut seqnr: u_int,
    mut cp: *const u_char,
    mut len: u_int,
) -> libc::c_int {
    let mut buf: [u_char; 4] = [0; 4];
    let mut seqbuf: [u_char; 16] = [0; 16];
    if len < 4 as libc::c_int as libc::c_uint {
        return -(3 as libc::c_int);
    }
    memset(
        seqbuf.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[u_char; 16]>() as libc::c_ulong,
    );
    let __v: u_int64_t = seqnr as u_int64_t;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) =
        (__v >> 56 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(1 as libc::c_int as isize) =
        (__v >> 48 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(2 as libc::c_int as isize) =
        (__v >> 40 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(3 as libc::c_int as isize) =
        (__v >> 32 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(4 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(5 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(6 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *seqbuf
        .as_mut_ptr()
        .offset(8 as libc::c_int as isize)
        .offset(7 as libc::c_int as isize) = (__v & 0xff as libc::c_int as libc::c_ulong) as u_char;
    if EVP_CipherInit(
        (*ctx).header_evp,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        seqbuf.as_mut_ptr(),
        0 as libc::c_int,
    ) == 0
    {
        return -(22 as libc::c_int);
    }
    if EVP_Cipher(
        (*ctx).header_evp,
        buf.as_mut_ptr(),
        cp as *mut u_char,
        ::core::mem::size_of::<[u_char; 4]>() as libc::c_ulong as libc::c_uint,
    ) < 0 as libc::c_int
    {
        return -(22 as libc::c_int);
    }
    *plenp = (*(buf.as_mut_ptr() as *const u_char).offset(0 as libc::c_int as isize) as u_int32_t)
        << 24 as libc::c_int
        | (*(buf.as_mut_ptr() as *const u_char).offset(1 as libc::c_int as isize) as u_int32_t)
            << 16 as libc::c_int
        | (*(buf.as_mut_ptr() as *const u_char).offset(2 as libc::c_int as isize) as u_int32_t)
            << 8 as libc::c_int
        | *(buf.as_mut_ptr() as *const u_char).offset(3 as libc::c_int as isize) as u_int32_t;
    return 0 as libc::c_int;
}
