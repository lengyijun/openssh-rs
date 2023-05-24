use ::libc;
extern "C" {
    pub type evp_cipher_ctx_st;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn EVP_CIPHER_CTX_get_iv_length(ctx: *const EVP_CIPHER_CTX) -> libc::c_int;
    fn EVP_CIPHER_CTX_iv(ctx: *const EVP_CIPHER_CTX) -> *const libc::c_uchar;
    fn EVP_CIPHER_CTX_iv_noconst(ctx: *mut EVP_CIPHER_CTX) -> *mut libc::c_uchar;
}
pub type size_t = libc::c_ulong;
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_iv(
    mut ctx: *const EVP_CIPHER_CTX,
    mut iv: *mut libc::c_uchar,
    mut len: size_t,
) -> libc::c_int {
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    if EVP_CIPHER_CTX_get_iv_length(ctx) < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if len != EVP_CIPHER_CTX_get_iv_length(ctx) as size_t {
        return 0 as libc::c_int;
    }
    if len > 16 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    if len != 0 as libc::c_int as libc::c_ulong {
        if iv.is_null() {
            return 0 as libc::c_int;
        }
        memcpy(
            iv as *mut libc::c_void,
            EVP_CIPHER_CTX_iv(ctx) as *const libc::c_void,
            len,
        );
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_iv(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut iv: *const libc::c_uchar,
    mut len: size_t,
) -> libc::c_int {
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    if EVP_CIPHER_CTX_get_iv_length(ctx) < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if len != EVP_CIPHER_CTX_get_iv_length(ctx) as size_t {
        return 0 as libc::c_int;
    }
    if len > 16 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    if len != 0 as libc::c_int as libc::c_ulong {
        if iv.is_null() {
            return 0 as libc::c_int;
        }
        memcpy(
            EVP_CIPHER_CTX_iv_noconst(ctx) as *mut libc::c_void,
            iv as *const libc::c_void,
            len,
        );
    }
    return 1 as libc::c_int;
}
