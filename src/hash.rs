use ::libc;
extern "C" {
    pub type engine_st;
    pub type evp_md_st;
    fn EVP_Digest(
        data: *const libc::c_void,
        count: size_t,
        md: *mut libc::c_uchar,
        size: *mut libc::c_uint,
        type_0: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_sha512() -> *const EVP_MD;
}
pub type size_t = libc::c_ulong;
pub type ENGINE = engine_st;
pub type EVP_MD = evp_md_st;
pub unsafe extern "C" fn crypto_hash_sha512(
    mut out: *mut libc::c_uchar,
    mut in_0: *const libc::c_uchar,
    mut inlen: libc::c_ulonglong,
) -> libc::c_int {
    if EVP_Digest(
        in_0 as *const libc::c_void,
        inlen as size_t,
        out,
        0 as *mut libc::c_uint,
        EVP_sha512(),
        0 as *mut ENGINE,
    ) == 0
    {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
