use ::libc;
extern "C" {
    pub type evp_cipher_st;
    pub type evp_cipher_ctx_st;
    pub type chachapoly_ctx;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;

    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;

    fn chachapoly_get_length(
        cpctx: *mut chachapoly_ctx,
        plenp: *mut u_int,
        seqnr: u_int,
        cp: *const u_char,
        len: u_int,
    ) -> libc::c_int;
    fn chachapoly_crypt(
        cpctx: *mut chachapoly_ctx,
        seqnr: u_int,
        dest: *mut u_char,
        src: *const u_char,
        len: u_int,
        aadlen: u_int,
        authlen: u_int,
        do_encrypt: libc::c_int,
    ) -> libc::c_int;
    fn chachapoly_free(cpctx: *mut chachapoly_ctx);
    fn chachapoly_new(key: *const u_char, keylen: u_int) -> *mut chachapoly_ctx;
    fn EVP_CIPHER_CTX_get_key_length(ctx: *const EVP_CIPHER_CTX) -> libc::c_int;
    fn EVP_CIPHER_CTX_get_iv_length(ctx: *const EVP_CIPHER_CTX) -> libc::c_int;
    fn EVP_CIPHER_CTX_get_updated_iv(
        ctx: *mut EVP_CIPHER_CTX,
        buf: *mut libc::c_void,
        len: size_t,
    ) -> libc::c_int;
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
    fn EVP_CIPHER_CTX_set_key_length(x: *mut EVP_CIPHER_CTX, keylen: libc::c_int) -> libc::c_int;
    fn EVP_CIPHER_CTX_ctrl(
        ctx: *mut EVP_CIPHER_CTX,
        type_0: libc::c_int,
        arg: libc::c_int,
        ptr: *mut libc::c_void,
    ) -> libc::c_int;
    fn EVP_des_ede3_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_128_ctr() -> *const EVP_CIPHER;
    fn EVP_aes_128_gcm() -> *const EVP_CIPHER;
    fn EVP_aes_192_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_192_ctr() -> *const EVP_CIPHER;
    fn EVP_aes_256_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_256_ctr() -> *const EVP_CIPHER;
    fn EVP_aes_256_gcm() -> *const EVP_CIPHER;
    fn EVP_CIPHER_CTX_set_iv(
        ctx: *mut EVP_CIPHER_CTX,
        iv: *const libc::c_uchar,
        len: size_t,
    ) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint32_t = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type EVP_CIPHER = evp_cipher_st;
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
pub type u8_0 = libc::c_uchar;
pub type u32_0 = libc::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aesctr_ctx {
    pub rounds: libc::c_int,
    pub ek: [u32_0; 60],
    pub ctr: [u8_0; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshcipher {
    pub name: *mut libc::c_char,
    pub block_size: u_int,
    pub key_len: u_int,
    pub iv_len: u_int,
    pub auth_len: u_int,
    pub flags: u_int,
    pub evptype: Option<unsafe extern "C" fn() -> *const EVP_CIPHER>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshcipher_ctx {
    pub plaintext: libc::c_int,
    pub encrypt: libc::c_int,
    pub evp: *mut EVP_CIPHER_CTX,
    pub cp_ctx: *mut chachapoly_ctx,
    pub ac_ctx: aesctr_ctx,
    pub cipher: *const sshcipher,
}
static mut ciphers: [sshcipher; 12] = unsafe {
    [
        {
            let mut init = sshcipher {
                name: b"3des-cbc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                block_size: 8 as libc::c_int as u_int,
                key_len: 24 as libc::c_int as u_int,
                iv_len: 0 as libc::c_int as u_int,
                auth_len: 0 as libc::c_int as u_int,
                flags: ((1 as libc::c_int) << 0 as libc::c_int) as u_int,
                evptype: Some(EVP_des_ede3_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = sshcipher {
                name: b"aes128-cbc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                block_size: 16 as libc::c_int as u_int,
                key_len: 16 as libc::c_int as u_int,
                iv_len: 0 as libc::c_int as u_int,
                auth_len: 0 as libc::c_int as u_int,
                flags: ((1 as libc::c_int) << 0 as libc::c_int) as u_int,
                evptype: Some(EVP_aes_128_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = sshcipher {
                name: b"aes192-cbc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                block_size: 16 as libc::c_int as u_int,
                key_len: 24 as libc::c_int as u_int,
                iv_len: 0 as libc::c_int as u_int,
                auth_len: 0 as libc::c_int as u_int,
                flags: ((1 as libc::c_int) << 0 as libc::c_int) as u_int,
                evptype: Some(EVP_aes_192_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = sshcipher {
                name: b"aes256-cbc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                block_size: 16 as libc::c_int as u_int,
                key_len: 32 as libc::c_int as u_int,
                iv_len: 0 as libc::c_int as u_int,
                auth_len: 0 as libc::c_int as u_int,
                flags: ((1 as libc::c_int) << 0 as libc::c_int) as u_int,
                evptype: Some(EVP_aes_256_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = sshcipher {
                name: b"aes128-ctr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                block_size: 16 as libc::c_int as u_int,
                key_len: 16 as libc::c_int as u_int,
                iv_len: 0 as libc::c_int as u_int,
                auth_len: 0 as libc::c_int as u_int,
                flags: 0 as libc::c_int as u_int,
                evptype: Some(EVP_aes_128_ctr as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = sshcipher {
                name: b"aes192-ctr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                block_size: 16 as libc::c_int as u_int,
                key_len: 24 as libc::c_int as u_int,
                iv_len: 0 as libc::c_int as u_int,
                auth_len: 0 as libc::c_int as u_int,
                flags: 0 as libc::c_int as u_int,
                evptype: Some(EVP_aes_192_ctr as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = sshcipher {
                name: b"aes256-ctr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                block_size: 16 as libc::c_int as u_int,
                key_len: 32 as libc::c_int as u_int,
                iv_len: 0 as libc::c_int as u_int,
                auth_len: 0 as libc::c_int as u_int,
                flags: 0 as libc::c_int as u_int,
                evptype: Some(EVP_aes_256_ctr as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = sshcipher {
                name: b"aes128-gcm@openssh.com\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                block_size: 16 as libc::c_int as u_int,
                key_len: 16 as libc::c_int as u_int,
                iv_len: 12 as libc::c_int as u_int,
                auth_len: 16 as libc::c_int as u_int,
                flags: 0 as libc::c_int as u_int,
                evptype: Some(EVP_aes_128_gcm as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = sshcipher {
                name: b"aes256-gcm@openssh.com\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                block_size: 16 as libc::c_int as u_int,
                key_len: 32 as libc::c_int as u_int,
                iv_len: 12 as libc::c_int as u_int,
                auth_len: 16 as libc::c_int as u_int,
                flags: 0 as libc::c_int as u_int,
                evptype: Some(EVP_aes_256_gcm as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = sshcipher {
                name: b"chacha20-poly1305@openssh.com\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                block_size: 8 as libc::c_int as u_int,
                key_len: 64 as libc::c_int as u_int,
                iv_len: 0 as libc::c_int as u_int,
                auth_len: 16 as libc::c_int as u_int,
                flags: ((1 as libc::c_int) << 1 as libc::c_int) as u_int,
                evptype: None,
            };
            init
        },
        {
            let mut init = sshcipher {
                name: b"none\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                block_size: 8 as libc::c_int as u_int,
                key_len: 0 as libc::c_int as u_int,
                iv_len: 0 as libc::c_int as u_int,
                auth_len: 0 as libc::c_int as u_int,
                flags: ((1 as libc::c_int) << 3 as libc::c_int) as u_int,
                evptype: None,
            };
            init
        },
        {
            let mut init = sshcipher {
                name: 0 as *const libc::c_char as *mut libc::c_char,
                block_size: 0 as libc::c_int as u_int,
                key_len: 0 as libc::c_int as u_int,
                iv_len: 0 as libc::c_int as u_int,
                auth_len: 0 as libc::c_int as u_int,
                flags: 0 as libc::c_int as u_int,
                evptype: None,
            };
            init
        },
    ]
};
pub unsafe extern "C" fn cipher_alg_list(
    mut sep: libc::c_char,
    mut auth_only: libc::c_int,
) -> *mut libc::c_char {
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut nlen: size_t = 0;
    let mut rlen: size_t = 0 as libc::c_int as size_t;
    let mut c: *const sshcipher = 0 as *const sshcipher;
    c = ciphers.as_ptr();
    while !((*c).name).is_null() {
        if !((*c).flags & ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint
            != 0 as libc::c_int as libc::c_uint)
        {
            if !(auth_only != 0 && (*c).auth_len == 0 as libc::c_int as libc::c_uint) {
                if !ret.is_null() {
                    let fresh0 = rlen;
                    rlen = rlen.wrapping_add(1);
                    *ret.offset(fresh0 as isize) = sep;
                }
                nlen = strlen((*c).name);
                tmp = realloc(
                    ret as *mut libc::c_void,
                    rlen.wrapping_add(nlen)
                        .wrapping_add(2 as libc::c_int as libc::c_ulong),
                ) as *mut libc::c_char;
                if tmp.is_null() {
                    libc::free(ret as *mut libc::c_void);
                    return 0 as *mut libc::c_char;
                }
                ret = tmp;
                memcpy(
                    ret.offset(rlen as isize) as *mut libc::c_void,
                    (*c).name as *const libc::c_void,
                    nlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
                );
                rlen = (rlen as libc::c_ulong).wrapping_add(nlen) as size_t as size_t;
            }
        }
        c = c.offset(1);
        c;
    }
    return ret;
}
pub unsafe extern "C" fn compression_alg_list(mut compression: libc::c_int) -> *const libc::c_char {
    return if compression != 0 {
        b"zlib@openssh.com,zlib,none\0" as *const u8 as *const libc::c_char
    } else {
        b"none,zlib@openssh.com,zlib\0" as *const u8 as *const libc::c_char
    };
}
pub unsafe extern "C" fn cipher_blocksize(mut c: *const sshcipher) -> u_int {
    return (*c).block_size;
}
pub unsafe extern "C" fn cipher_keylen(mut c: *const sshcipher) -> u_int {
    return (*c).key_len;
}
pub unsafe extern "C" fn cipher_seclen(mut c: *const sshcipher) -> u_int {
    if libc::strcmp(b"3des-cbc\0" as *const u8 as *const libc::c_char, (*c).name)
        == 0 as libc::c_int
    {
        return 14 as libc::c_int as u_int;
    }
    return cipher_keylen(c);
}
pub unsafe extern "C" fn cipher_authlen(mut c: *const sshcipher) -> u_int {
    return (*c).auth_len;
}
pub unsafe extern "C" fn cipher_ivlen(mut c: *const sshcipher) -> u_int {
    return if (*c).iv_len != 0 as libc::c_int as libc::c_uint
        || (*c).flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
            != 0 as libc::c_int as libc::c_uint
    {
        (*c).iv_len
    } else {
        (*c).block_size
    };
}
pub unsafe extern "C" fn cipher_is_cbc(mut c: *const sshcipher) -> u_int {
    return ((*c).flags & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint) as libc::c_int as u_int;
}
pub unsafe extern "C" fn cipher_ctx_is_plaintext(mut cc: *mut sshcipher_ctx) -> u_int {
    return (*cc).plaintext as u_int;
}
pub unsafe extern "C" fn cipher_by_name(mut name: *const libc::c_char) -> *const sshcipher {
    let mut c: *const sshcipher = 0 as *const sshcipher;
    c = ciphers.as_ptr();
    while !((*c).name).is_null() {
        if libc::strcmp((*c).name, name) == 0 as libc::c_int {
            return c;
        }
        c = c.offset(1);
        c;
    }
    return 0 as *const sshcipher;
}
pub unsafe extern "C" fn ciphers_valid(mut names: *const libc::c_char) -> libc::c_int {
    let mut c: *const sshcipher = 0 as *const sshcipher;
    let mut cipher_list: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    if names.is_null()
        || libc::strcmp(names, b"\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    cp = strdup(names);
    cipher_list = cp;
    if cipher_list.is_null() {
        return 0 as libc::c_int;
    }
    p = strsep(&mut cp, b",\0" as *const u8 as *const libc::c_char);
    while !p.is_null() && *p as libc::c_int != '\0' as i32 {
        c = cipher_by_name(p);
        if c.is_null()
            || (*c).flags & ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint
                != 0 as libc::c_int as libc::c_uint
        {
            libc::free(cipher_list as *mut libc::c_void);
            return 0 as libc::c_int;
        }
        p = strsep(&mut cp, b",\0" as *const u8 as *const libc::c_char);
    }
    libc::free(cipher_list as *mut libc::c_void);
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn cipher_warning_message(
    mut cc: *const sshcipher_ctx,
) -> *const libc::c_char {
    if cc.is_null() || ((*cc).cipher).is_null() {
        return 0 as *const libc::c_char;
    }
    return 0 as *const libc::c_char;
}
pub unsafe extern "C" fn cipher_init(
    mut ccp: *mut *mut sshcipher_ctx,
    mut cipher: *const sshcipher,
    mut key: *const u_char,
    mut keylen: u_int,
    mut iv: *const u_char,
    mut ivlen: u_int,
    mut do_encrypt: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut cc: *mut sshcipher_ctx = 0 as *mut sshcipher_ctx;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut type_0: *const EVP_CIPHER = 0 as *const EVP_CIPHER;
    let mut klen: libc::c_int = 0;
    *ccp = 0 as *mut sshcipher_ctx;
    cc = calloc(
        ::core::mem::size_of::<sshcipher_ctx>() as libc::c_ulong,
        1 as libc::c_int as libc::c_ulong,
    ) as *mut sshcipher_ctx;
    if cc.is_null() {
        return -(2 as libc::c_int);
    }
    (*cc).plaintext = ((*cipher).flags & ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint) as libc::c_int;
    (*cc).encrypt = do_encrypt;
    if keylen < (*cipher).key_len || !iv.is_null() && ivlen < cipher_ivlen(cipher) {
        ret = -(10 as libc::c_int);
    } else {
        (*cc).cipher = cipher;
        if (*(*cc).cipher).flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
            != 0 as libc::c_int as libc::c_uint
        {
            (*cc).cp_ctx = chachapoly_new(key, keylen);
            ret = if !((*cc).cp_ctx).is_null() {
                0 as libc::c_int
            } else {
                -(10 as libc::c_int)
            };
        } else if (*(*cc).cipher).flags & ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint
            != 0 as libc::c_int as libc::c_uint
        {
            ret = 0 as libc::c_int;
        } else {
            type_0 = (Some(((*cipher).evptype).expect("non-null function pointer")))
                .expect("non-null function pointer")();
            (*cc).evp = EVP_CIPHER_CTX_new();
            if ((*cc).evp).is_null() {
                ret = -(2 as libc::c_int);
            } else if EVP_CipherInit(
                (*cc).evp,
                type_0,
                0 as *const libc::c_uchar,
                iv as *mut u_char,
                (do_encrypt == 1 as libc::c_int) as libc::c_int,
            ) == 0 as libc::c_int
            {
                ret = -(22 as libc::c_int);
            } else if cipher_authlen(cipher) != 0
                && EVP_CIPHER_CTX_ctrl(
                    (*cc).evp,
                    0x12 as libc::c_int,
                    -(1 as libc::c_int),
                    iv as *mut u_char as *mut libc::c_void,
                ) == 0
            {
                ret = -(22 as libc::c_int);
            } else {
                klen = EVP_CIPHER_CTX_get_key_length((*cc).evp);
                if klen > 0 as libc::c_int && keylen != klen as u_int {
                    if EVP_CIPHER_CTX_set_key_length((*cc).evp, keylen as libc::c_int)
                        == 0 as libc::c_int
                    {
                        ret = -(22 as libc::c_int);
                        current_block = 11057989956906543695;
                    } else {
                        current_block = 18317007320854588510;
                    }
                } else {
                    current_block = 18317007320854588510;
                }
                match current_block {
                    11057989956906543695 => {}
                    _ => {
                        if EVP_CipherInit(
                            (*cc).evp,
                            0 as *const EVP_CIPHER,
                            key as *mut u_char,
                            0 as *const libc::c_uchar,
                            -(1 as libc::c_int),
                        ) == 0 as libc::c_int
                        {
                            ret = -(22 as libc::c_int);
                        } else {
                            ret = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    if ret == 0 as libc::c_int {
        *ccp = cc;
    } else if !cc.is_null() {
        EVP_CIPHER_CTX_free((*cc).evp);
        freezero(
            cc as *mut libc::c_void,
            ::core::mem::size_of::<sshcipher_ctx>() as libc::c_ulong,
        );
    }
    return ret;
}
pub unsafe extern "C" fn cipher_crypt(
    mut cc: *mut sshcipher_ctx,
    mut seqnr: u_int,
    mut dest: *mut u_char,
    mut src: *const u_char,
    mut len: u_int,
    mut aadlen: u_int,
    mut authlen: u_int,
) -> libc::c_int {
    if (*(*cc).cipher).flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        return chachapoly_crypt(
            (*cc).cp_ctx,
            seqnr,
            dest,
            src,
            len,
            aadlen,
            authlen,
            (*cc).encrypt,
        );
    }
    if (*(*cc).cipher).flags & ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        memcpy(
            dest as *mut libc::c_void,
            src as *const libc::c_void,
            aadlen.wrapping_add(len) as libc::c_ulong,
        );
        return 0 as libc::c_int;
    }
    if authlen != 0 {
        let mut lastiv: [u_char; 1] = [0; 1];
        if authlen != cipher_authlen((*cc).cipher) {
            return -(10 as libc::c_int);
        }
        if EVP_CIPHER_CTX_ctrl(
            (*cc).evp,
            0x13 as libc::c_int,
            1 as libc::c_int,
            lastiv.as_mut_ptr() as *mut libc::c_void,
        ) == 0
        {
            return -(22 as libc::c_int);
        }
        if (*cc).encrypt == 0
            && EVP_CIPHER_CTX_ctrl(
                (*cc).evp,
                0x11 as libc::c_int,
                authlen as libc::c_int,
                (src as *mut u_char)
                    .offset(aadlen as isize)
                    .offset(len as isize) as *mut libc::c_void,
            ) == 0
        {
            return -(22 as libc::c_int);
        }
    }
    if aadlen != 0 {
        if authlen != 0
            && EVP_Cipher(
                (*cc).evp,
                0 as *mut libc::c_uchar,
                src as *mut u_char,
                aadlen,
            ) < 0 as libc::c_int
        {
            return -(22 as libc::c_int);
        }
        memcpy(
            dest as *mut libc::c_void,
            src as *const libc::c_void,
            aadlen as libc::c_ulong,
        );
    }
    if len.wrapping_rem((*(*cc).cipher).block_size) != 0 {
        return -(10 as libc::c_int);
    }
    if EVP_Cipher(
        (*cc).evp,
        dest.offset(aadlen as isize),
        (src as *mut u_char).offset(aadlen as isize),
        len,
    ) < 0 as libc::c_int
    {
        return -(22 as libc::c_int);
    }
    if authlen != 0 {
        if EVP_Cipher(
            (*cc).evp,
            0 as *mut libc::c_uchar,
            0 as *const libc::c_uchar,
            0 as libc::c_int as libc::c_uint,
        ) < 0 as libc::c_int
        {
            return if (*cc).encrypt != 0 {
                -(22 as libc::c_int)
            } else {
                -(30 as libc::c_int)
            };
        }
        if (*cc).encrypt != 0
            && EVP_CIPHER_CTX_ctrl(
                (*cc).evp,
                0x10 as libc::c_int,
                authlen as libc::c_int,
                dest.offset(aadlen as isize).offset(len as isize) as *mut libc::c_void,
            ) == 0
        {
            return -(22 as libc::c_int);
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn cipher_get_length(
    mut cc: *mut sshcipher_ctx,
    mut plenp: *mut u_int,
    mut seqnr: u_int,
    mut cp: *const u_char,
    mut len: u_int,
) -> libc::c_int {
    if (*(*cc).cipher).flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        return chachapoly_get_length((*cc).cp_ctx, plenp, seqnr, cp, len);
    }
    if len < 4 as libc::c_int as libc::c_uint {
        return -(3 as libc::c_int);
    }
    *plenp = (*cp.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int
        | (*cp.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
        | (*cp.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
        | *cp.offset(3 as libc::c_int as isize) as u_int32_t;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn cipher_free(mut cc: *mut sshcipher_ctx) {
    if cc.is_null() {
        return;
    }
    if (*(*cc).cipher).flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        chachapoly_free((*cc).cp_ctx);
        (*cc).cp_ctx = 0 as *mut chachapoly_ctx;
    } else if (*(*cc).cipher).flags & ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        explicit_bzero(
            &mut (*cc).ac_ctx as *mut aesctr_ctx as *mut libc::c_void,
            ::core::mem::size_of::<aesctr_ctx>() as libc::c_ulong,
        );
    }
    EVP_CIPHER_CTX_free((*cc).evp);
    (*cc).evp = 0 as *mut EVP_CIPHER_CTX;
    freezero(
        cc as *mut libc::c_void,
        ::core::mem::size_of::<sshcipher_ctx>() as libc::c_ulong,
    );
}
pub unsafe extern "C" fn cipher_get_keyiv_len(mut cc: *const sshcipher_ctx) -> libc::c_int {
    let mut c: *const sshcipher = (*cc).cipher;
    if (*c).flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    } else if (*c).flags & ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        return ::core::mem::size_of::<[u8_0; 16]>() as libc::c_ulong as libc::c_int;
    }
    return EVP_CIPHER_CTX_get_iv_length((*cc).evp);
}
pub unsafe extern "C" fn cipher_get_keyiv(
    mut cc: *mut sshcipher_ctx,
    mut iv: *mut u_char,
    mut len: size_t,
) -> libc::c_int {
    let mut c: *const sshcipher = (*cc).cipher;
    let mut evplen: libc::c_int = 0;
    if (*(*cc).cipher).flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        if len != 0 as libc::c_int as libc::c_ulong {
            return -(10 as libc::c_int);
        }
        return 0 as libc::c_int;
    }
    if (*(*cc).cipher).flags & ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        if len != ::core::mem::size_of::<[u8_0; 16]>() as libc::c_ulong {
            return -(10 as libc::c_int);
        }
        memcpy(
            iv as *mut libc::c_void,
            ((*cc).ac_ctx.ctr).as_mut_ptr() as *const libc::c_void,
            len,
        );
        return 0 as libc::c_int;
    }
    if (*(*cc).cipher).flags & ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    evplen = EVP_CIPHER_CTX_get_iv_length((*cc).evp);
    if evplen == 0 as libc::c_int {
        return 0 as libc::c_int;
    } else if evplen < 0 as libc::c_int {
        return -(22 as libc::c_int);
    }
    if evplen as size_t != len {
        return -(10 as libc::c_int);
    }
    if cipher_authlen(c) != 0 {
        if EVP_CIPHER_CTX_ctrl(
            (*cc).evp,
            0x13 as libc::c_int,
            len as libc::c_int,
            iv as *mut libc::c_void,
        ) == 0
        {
            return -(22 as libc::c_int);
        }
    } else if EVP_CIPHER_CTX_get_updated_iv((*cc).evp, iv as *mut libc::c_void, len) == 0 {
        return -(22 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn cipher_set_keyiv(
    mut cc: *mut sshcipher_ctx,
    mut iv: *const u_char,
    mut len: size_t,
) -> libc::c_int {
    let mut c: *const sshcipher = (*cc).cipher;
    let mut evplen: libc::c_int = 0 as libc::c_int;
    if (*(*cc).cipher).flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    if (*(*cc).cipher).flags & ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    evplen = EVP_CIPHER_CTX_get_iv_length((*cc).evp);
    if evplen <= 0 as libc::c_int {
        return -(22 as libc::c_int);
    }
    if evplen as size_t != len {
        return -(10 as libc::c_int);
    }
    if cipher_authlen(c) != 0 {
        if EVP_CIPHER_CTX_ctrl(
            (*cc).evp,
            0x12 as libc::c_int,
            -(1 as libc::c_int),
            iv as *mut libc::c_void,
        ) == 0
        {
            return -(22 as libc::c_int);
        }
    } else if EVP_CIPHER_CTX_set_iv((*cc).evp, iv, evplen as size_t) == 0 {
        return -(22 as libc::c_int);
    }
    return 0 as libc::c_int;
}
