use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    pub type bio_st;
    pub type bignum_st;
    pub type bignum_ctx;
    pub type evp_cipher_st;
    pub type evp_pkey_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    pub type bio_method_st;
    pub type ec_method_st;
    pub type ec_group_st;
    pub type ec_point_st;
    pub type sshcipher;
    pub type sshcipher_ctx;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    static mut stderr: *mut libc::FILE;

    fn fputs(__s: *const libc::c_char, __stream: *mut libc::FILE) -> libc::c_int;
    fn fwrite(
        _: *const libc::c_void,
        _: libc::c_ulong,
        _: libc::c_ulong,
        _: *mut libc::FILE,
    ) -> libc::c_ulong;
    fn feof(__stream: *mut libc::FILE) -> libc::c_int;
    fn __b64_ntop(
        _: *const libc::c_uchar,
        _: size_t,
        _: *mut libc::c_char,
        _: size_t,
    ) -> libc::c_int;
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn arc4random() -> uint32_t;
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);
    fn timingsafe_bcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;
    fn bcrypt_pbkdf(
        _: *const libc::c_char,
        _: size_t,
        _: *const uint8_t,
        _: size_t,
        _: *mut uint8_t,
        _: size_t,
        _: libc::c_uint,
    ) -> libc::c_int;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    fn EVP_PKEY_get_base_id(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_set1_RSA(pkey: *mut EVP_PKEY, key: *mut rsa_st) -> libc::c_int;
    fn EVP_PKEY_get1_RSA(pkey: *mut EVP_PKEY) -> *mut rsa_st;
    fn EVP_PKEY_set1_DSA(pkey: *mut EVP_PKEY, key: *mut dsa_st) -> libc::c_int;
    fn EVP_PKEY_get1_DSA(pkey: *mut EVP_PKEY) -> *mut dsa_st;
    fn EVP_PKEY_set1_EC_KEY(pkey: *mut EVP_PKEY, key: *mut ec_key_st) -> libc::c_int;
    fn EVP_PKEY_get1_EC_KEY(pkey: *mut EVP_PKEY) -> *mut ec_key_st;
    fn EVP_PKEY_new() -> *mut EVP_PKEY;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);

    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;

    fn time(__timer: *mut time_t) -> time_t;
    fn BIO_new(type_0: *const BIO_METHOD) -> *mut BIO;
    fn BIO_free(a: *mut BIO) -> libc::c_int;
    fn BIO_write(b: *mut BIO, data: *const libc::c_void, dlen: libc::c_int) -> libc::c_int;
    fn BIO_ctrl(
        bp: *mut BIO,
        cmd: libc::c_int,
        larg: libc::c_long,
        parg: *mut libc::c_void,
    ) -> libc::c_long;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BN_value_one() -> *const BIGNUM;
    fn BN_num_bits(a: *const BIGNUM) -> libc::c_int;
    fn BN_new() -> *mut BIGNUM;
    fn BN_clear_free(a: *mut BIGNUM);
    fn BN_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_print_fp(fp: *mut libc::FILE, a: *const BIGNUM) -> libc::c_int;
    fn ERR_get_error() -> libc::c_ulong;
    fn ERR_peek_error() -> libc::c_ulong;
    fn ERR_peek_last_error() -> libc::c_ulong;
    fn RSA_get0_key(
        r: *const RSA,
        n: *mut *const BIGNUM,
        e: *mut *const BIGNUM,
        d: *mut *const BIGNUM,
    );
    fn RSA_blinding_on(rsa: *mut RSA, ctx: *mut BN_CTX) -> libc::c_int;
    fn EC_GROUP_cmp(a: *const EC_GROUP, b: *const EC_GROUP, ctx: *mut BN_CTX) -> libc::c_int;
    fn EC_GROUP_new_by_curve_name(nid: libc::c_int) -> *mut EC_GROUP;
    fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_free(point: *mut EC_POINT);
    fn EC_POINT_get_affine_coordinates_GFp(
        group: *const EC_GROUP,
        p: *const EC_POINT,
        x: *mut BIGNUM,
        y: *mut BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_POINT_is_at_infinity(group: *const EC_GROUP, p: *const EC_POINT) -> libc::c_int;
    fn EC_POINT_mul(
        group: *const EC_GROUP,
        r: *mut EC_POINT,
        n: *const BIGNUM,
        q: *const EC_POINT,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;
    fn EC_KEY_set_group(key: *mut EC_KEY, group: *const EC_GROUP) -> libc::c_int;
    fn EC_KEY_get0_private_key(key: *const EC_KEY) -> *const BIGNUM;
    fn EC_KEY_get0_public_key(key: *const EC_KEY) -> *const EC_POINT;
    fn EC_GROUP_set_asn1_flag(group: *mut EC_GROUP, flag: libc::c_int);
    fn EC_GROUP_get_curve_name(group: *const EC_GROUP) -> libc::c_int;
    fn EC_GROUP_get_order(
        group: *const EC_GROUP,
        order: *mut BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_GROUP_free(group: *mut EC_GROUP);
    fn EC_METHOD_get_field_type(meth: *const EC_METHOD) -> libc::c_int;
    fn EC_GROUP_method_of(group: *const EC_GROUP) -> *const EC_METHOD;
    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strndup(_: *const libc::c_char, _: libc::c_ulong) -> *mut libc::c_char;

    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn PEM_write_bio_PrivateKey(
        out: *mut BIO,
        x: *const EVP_PKEY,
        enc: *const EVP_CIPHER,
        kstr: *const libc::c_uchar,
        klen: libc::c_int,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn PEM_read_bio_PrivateKey(
        out: *mut BIO,
        x: *mut *mut EVP_PKEY,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut EVP_PKEY;
    fn PEM_write_bio_ECPrivateKey(
        out: *mut BIO,
        x: *const EC_KEY,
        enc: *const EVP_CIPHER,
        kstr: *const libc::c_uchar,
        klen: libc::c_int,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn PEM_write_bio_DSAPrivateKey(
        out: *mut BIO,
        x: *const DSA,
        enc: *const EVP_CIPHER,
        kstr: *const libc::c_uchar,
        klen: libc::c_int,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn PEM_write_bio_RSAPrivateKey(
        out: *mut BIO,
        x: *const RSA,
        enc: *const EVP_CIPHER,
        kstr: *const libc::c_uchar,
        klen: libc::c_int,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn format_absolute_time(_: uint64_t, _: *mut libc::c_char, _: size_t);

    fn sshbuf_from(blob: *const libc::c_void, len: size_t) -> *mut crate::sshbuf::sshbuf;
    fn sshbuf_fromb(buf: *mut crate::sshbuf::sshbuf) -> *mut crate::sshbuf::sshbuf;
    fn sshbuf_froms(
        buf: *mut crate::sshbuf::sshbuf,
        bufp: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;

    fn sshbuf_reset(buf: *mut crate::sshbuf::sshbuf);

    fn sshbuf_ptr(buf: *const crate::sshbuf::sshbuf) -> *const u_char;
    fn sshbuf_reserve(
        buf: *mut crate::sshbuf::sshbuf,
        len: size_t,
        dpp: *mut *mut u_char,
    ) -> libc::c_int;
    fn sshbuf_consume(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_putb(buf: *mut crate::sshbuf::sshbuf, v: *const crate::sshbuf::sshbuf)
        -> libc::c_int;

    fn sshbuf_get_u64(buf: *mut crate::sshbuf::sshbuf, valp: *mut u_int64_t) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut crate::sshbuf::sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut crate::sshbuf::sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_put_u64(buf: *mut crate::sshbuf::sshbuf, val: u_int64_t) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut crate::sshbuf::sshbuf, val: u_int32_t) -> libc::c_int;

    fn sshbuf_get_string(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_put_string(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut crate::sshbuf::sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_get_string_direct(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_dtob64_string(
        buf: *const crate::sshbuf::sshbuf,
        wrap: libc::c_int,
    ) -> *mut libc::c_char;
    fn sshbuf_dtob64(
        d: *const crate::sshbuf::sshbuf,
        b64: *mut crate::sshbuf::sshbuf,
        wrap: libc::c_int,
    ) -> libc::c_int;
    fn sshbuf_b64tod(buf: *mut crate::sshbuf::sshbuf, b64: *const libc::c_char) -> libc::c_int;
    fn cipher_free(_: *mut sshcipher_ctx);
    fn cipher_crypt(
        _: *mut sshcipher_ctx,
        _: u_int,
        _: *mut u_char,
        _: *const u_char,
        _: u_int,
        _: u_int,
        _: u_int,
    ) -> libc::c_int;
    fn cipher_init(
        _: *mut *mut sshcipher_ctx,
        _: *const sshcipher,
        _: *const u_char,
        _: u_int,
        _: *const u_char,
        _: u_int,
        _: libc::c_int,
    ) -> libc::c_int;
    fn cipher_by_name(_: *const libc::c_char) -> *const sshcipher;
    fn cipher_blocksize(_: *const sshcipher) -> u_int;
    fn cipher_keylen(_: *const sshcipher) -> u_int;
    fn cipher_authlen(_: *const sshcipher) -> u_int;
    fn cipher_ivlen(_: *const sshcipher) -> u_int;
    fn ssh_digest_alg_name(alg: libc::c_int) -> *const libc::c_char;
    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_digest_memory(
        alg: libc::c_int,
        m: *const libc::c_void,
        mlen: size_t,
        d: *mut u_char,
        dlen: size_t,
    ) -> libc::c_int;
    fn match_pattern(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn match_pattern_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn sshsk_sign(
        provider_path: *const libc::c_char,
        key: *mut sshkey,
        sigp: *mut *mut u_char,
        lenp: *mut size_t,
        data: *const u_char,
        datalen: size_t,
        compat: u_int,
        pin: *const libc::c_char,
    ) -> libc::c_int;
    static sshkey_ed25519_impl: sshkey_impl;
    static sshkey_ed25519_cert_impl: sshkey_impl;
    static sshkey_ed25519_sk_impl: sshkey_impl;
    static sshkey_ed25519_sk_cert_impl: sshkey_impl;
    static sshkey_ecdsa_sk_impl: sshkey_impl;
    static sshkey_ecdsa_sk_cert_impl: sshkey_impl;
    static sshkey_ecdsa_sk_webauthn_impl: sshkey_impl;
    static sshkey_ecdsa_nistp256_impl: sshkey_impl;
    static sshkey_ecdsa_nistp256_cert_impl: sshkey_impl;
    static sshkey_ecdsa_nistp384_impl: sshkey_impl;
    static sshkey_ecdsa_nistp384_cert_impl: sshkey_impl;
    static sshkey_ecdsa_nistp521_impl: sshkey_impl;
    static sshkey_ecdsa_nistp521_cert_impl: sshkey_impl;
    static sshkey_rsa_impl: sshkey_impl;
    static sshkey_rsa_cert_impl: sshkey_impl;
    static sshkey_rsa_sha256_impl: sshkey_impl;
    static sshkey_rsa_sha256_cert_impl: sshkey_impl;
    static sshkey_rsa_sha512_impl: sshkey_impl;
    static sshkey_rsa_sha512_cert_impl: sshkey_impl;
    static sshkey_dss_impl: sshkey_impl;
    static sshkey_dsa_cert_impl: sshkey_impl;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;

pub type _IO_lock_t = ();

pub type BIO = bio_st;
pub type BIGNUM = bignum_st;
pub type BN_CTX = bignum_ctx;
pub type EVP_CIPHER = evp_cipher_st;
pub type EVP_PKEY = evp_pkey_st;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type EC_KEY = ec_key_st;
pub type pem_password_cb = unsafe extern "C" fn(
    *mut libc::c_char,
    libc::c_int,
    libc::c_int,
    *mut libc::c_void,
) -> libc::c_int;
pub type BIO_METHOD = bio_method_st;
pub type EC_METHOD = ec_method_st;
pub type EC_GROUP = ec_group_st;
pub type EC_POINT = ec_point_st;
pub type sshkey_types = libc::c_uint;
pub const KEY_UNSPEC: sshkey_types = 14;
pub const KEY_ED25519_SK_CERT: sshkey_types = 13;
pub const KEY_ED25519_SK: sshkey_types = 12;
pub const KEY_ECDSA_SK_CERT: sshkey_types = 11;
pub const KEY_ECDSA_SK: sshkey_types = 10;
pub const KEY_XMSS_CERT: sshkey_types = 9;
pub const KEY_XMSS: sshkey_types = 8;
pub const KEY_ED25519_CERT: sshkey_types = 7;
pub const KEY_ECDSA_CERT: sshkey_types = 6;
pub const KEY_DSA_CERT: sshkey_types = 5;
pub const KEY_RSA_CERT: sshkey_types = 4;
pub const KEY_ED25519: sshkey_types = 3;
pub const KEY_ECDSA: sshkey_types = 2;
pub const KEY_DSA: sshkey_types = 1;
pub const KEY_RSA: sshkey_types = 0;
pub type sshkey_fp_rep = libc::c_uint;
pub const SSH_FP_RANDOMART: sshkey_fp_rep = 4;
pub const SSH_FP_BUBBLEBABBLE: sshkey_fp_rep = 3;
pub const SSH_FP_BASE64: sshkey_fp_rep = 2;
pub const SSH_FP_HEX: sshkey_fp_rep = 1;
pub const SSH_FP_DEFAULT: sshkey_fp_rep = 0;
pub type sshkey_serialize_rep = libc::c_uint;
pub const SSHKEY_SERIALIZE_INFO: sshkey_serialize_rep = 254;
pub const SSHKEY_SERIALIZE_SHIELD: sshkey_serialize_rep = 3;
pub const SSHKEY_SERIALIZE_FULL: sshkey_serialize_rep = 2;
pub const SSHKEY_SERIALIZE_STATE: sshkey_serialize_rep = 1;
pub const SSHKEY_SERIALIZE_DEFAULT: sshkey_serialize_rep = 0;
pub type sshkey_private_format = libc::c_uint;
pub const SSHKEY_PRIVATE_PKCS8: sshkey_private_format = 2;
pub const SSHKEY_PRIVATE_PEM: sshkey_private_format = 1;
pub const SSHKEY_PRIVATE_OPENSSH: sshkey_private_format = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_cert {
    pub certblob: *mut crate::sshbuf::sshbuf,
    pub type_0: u_int,
    pub serial: u_int64_t,
    pub key_id: *mut libc::c_char,
    pub nprincipals: u_int,
    pub principals: *mut *mut libc::c_char,
    pub valid_after: u_int64_t,
    pub valid_before: u_int64_t,
    pub critical: *mut crate::sshbuf::sshbuf,
    pub extensions: *mut crate::sshbuf::sshbuf,
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
    pub sk_key_handle: *mut crate::sshbuf::sshbuf,
    pub sk_reserved: *mut crate::sshbuf::sshbuf,
    pub cert: *mut sshkey_cert,
    pub shielded_private: *mut u_char,
    pub shielded_len: size_t,
    pub shield_prekey: *mut u_char,
    pub shield_prekey_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_sig_details {
    pub sk_counter: uint32_t,
    pub sk_flags: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_impl_funcs {
    pub size: Option<unsafe extern "C" fn(*const sshkey) -> u_int>,
    pub alloc: Option<unsafe extern "C" fn(*mut sshkey) -> libc::c_int>,
    pub cleanup: Option<unsafe extern "C" fn(*mut sshkey) -> ()>,
    pub equal: Option<unsafe extern "C" fn(*const sshkey, *const sshkey) -> libc::c_int>,
    pub serialize_public: Option<
        unsafe extern "C" fn(
            *const sshkey,
            *mut crate::sshbuf::sshbuf,
            sshkey_serialize_rep,
        ) -> libc::c_int,
    >,
    pub deserialize_public: Option<
        unsafe extern "C" fn(
            *const libc::c_char,
            *mut crate::sshbuf::sshbuf,
            *mut sshkey,
        ) -> libc::c_int,
    >,
    pub serialize_private: Option<
        unsafe extern "C" fn(
            *const sshkey,
            *mut crate::sshbuf::sshbuf,
            sshkey_serialize_rep,
        ) -> libc::c_int,
    >,
    pub deserialize_private: Option<
        unsafe extern "C" fn(
            *const libc::c_char,
            *mut crate::sshbuf::sshbuf,
            *mut sshkey,
        ) -> libc::c_int,
    >,
    pub generate: Option<unsafe extern "C" fn(*mut sshkey, libc::c_int) -> libc::c_int>,
    pub copy_public: Option<unsafe extern "C" fn(*const sshkey, *mut sshkey) -> libc::c_int>,
    pub sign: Option<
        unsafe extern "C" fn(
            *mut sshkey,
            *mut *mut u_char,
            *mut size_t,
            *const u_char,
            size_t,
            *const libc::c_char,
            *const libc::c_char,
            *const libc::c_char,
            u_int,
        ) -> libc::c_int,
    >,
    pub verify: Option<
        unsafe extern "C" fn(
            *const sshkey,
            *const u_char,
            size_t,
            *const u_char,
            size_t,
            *const libc::c_char,
            u_int,
            *mut *mut sshkey_sig_details,
        ) -> libc::c_int,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_impl {
    pub name: *const libc::c_char,
    pub shortname: *const libc::c_char,
    pub sigalg: *const libc::c_char,
    pub type_0: libc::c_int,
    pub nid: libc::c_int,
    pub cert: libc::c_int,
    pub sigonly: libc::c_int,
    pub keybits: libc::c_int,
    pub funcs: *const sshkey_impl_funcs,
}
pub type sshkey_certify_signer = unsafe extern "C" fn(
    *mut sshkey,
    *mut *mut u_char,
    *mut size_t,
    *const u_char,
    size_t,
    *const libc::c_char,
    *const libc::c_char,
    *const libc::c_char,
    u_int,
    *mut libc::c_void,
) -> libc::c_int;
#[inline]
unsafe extern "C" fn ERR_GET_LIB(mut errcode: libc::c_ulong) -> libc::c_int {
    if errcode
        & (2147483647 as libc::c_int as libc::c_uint).wrapping_add(1 as libc::c_int as libc::c_uint)
            as libc::c_ulong
        != 0 as libc::c_int as libc::c_ulong
    {
        return 2 as libc::c_int;
    }
    return (errcode >> 23 as libc::c_long & 0xff as libc::c_int as libc::c_ulong) as libc::c_int;
}
#[inline]
unsafe extern "C" fn ERR_GET_REASON(mut errcode: libc::c_ulong) -> libc::c_int {
    if errcode
        & (2147483647 as libc::c_int as libc::c_uint).wrapping_add(1 as libc::c_int as libc::c_uint)
            as libc::c_ulong
        != 0 as libc::c_int as libc::c_ulong
    {
        return (errcode & 2147483647 as libc::c_int as libc::c_uint as libc::c_ulong)
            as libc::c_int;
    }
    return (errcode & 0x7fffff as libc::c_int as libc::c_ulong) as libc::c_int;
}
pub static mut keyimpls: [*const sshkey_impl; 22] = unsafe {
    [
        &sshkey_ed25519_impl as *const sshkey_impl,
        &sshkey_ed25519_cert_impl as *const sshkey_impl,
        &sshkey_ed25519_sk_impl as *const sshkey_impl,
        &sshkey_ed25519_sk_cert_impl as *const sshkey_impl,
        &sshkey_ecdsa_nistp256_impl as *const sshkey_impl,
        &sshkey_ecdsa_nistp256_cert_impl as *const sshkey_impl,
        &sshkey_ecdsa_nistp384_impl as *const sshkey_impl,
        &sshkey_ecdsa_nistp384_cert_impl as *const sshkey_impl,
        &sshkey_ecdsa_nistp521_impl as *const sshkey_impl,
        &sshkey_ecdsa_nistp521_cert_impl as *const sshkey_impl,
        &sshkey_ecdsa_sk_impl as *const sshkey_impl,
        &sshkey_ecdsa_sk_cert_impl as *const sshkey_impl,
        &sshkey_ecdsa_sk_webauthn_impl as *const sshkey_impl,
        &sshkey_dss_impl as *const sshkey_impl,
        &sshkey_dsa_cert_impl as *const sshkey_impl,
        &sshkey_rsa_impl as *const sshkey_impl,
        &sshkey_rsa_cert_impl as *const sshkey_impl,
        &sshkey_rsa_sha256_impl as *const sshkey_impl,
        &sshkey_rsa_sha256_cert_impl as *const sshkey_impl,
        &sshkey_rsa_sha512_impl as *const sshkey_impl,
        &sshkey_rsa_sha512_cert_impl as *const sshkey_impl,
        0 as *const sshkey_impl,
    ]
};
unsafe extern "C" fn sshkey_impl_from_type(mut type_0: libc::c_int) -> *const sshkey_impl {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while !(keyimpls[i as usize]).is_null() {
        if (*keyimpls[i as usize]).type_0 == type_0 {
            return keyimpls[i as usize];
        }
        i += 1;
        i;
    }
    return 0 as *const sshkey_impl;
}
unsafe extern "C" fn sshkey_impl_from_type_nid(
    mut type_0: libc::c_int,
    mut nid: libc::c_int,
) -> *const sshkey_impl {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while !(keyimpls[i as usize]).is_null() {
        if (*keyimpls[i as usize]).type_0 == type_0
            && ((*keyimpls[i as usize]).nid == 0 as libc::c_int
                || (*keyimpls[i as usize]).nid == nid)
        {
            return keyimpls[i as usize];
        }
        i += 1;
        i;
    }
    return 0 as *const sshkey_impl;
}
unsafe extern "C" fn sshkey_impl_from_key(mut k: *const sshkey) -> *const sshkey_impl {
    if k.is_null() {
        return 0 as *const sshkey_impl;
    }
    return sshkey_impl_from_type_nid((*k).type_0, (*k).ecdsa_nid);
}
pub unsafe extern "C" fn sshkey_type(mut k: *const sshkey) -> *const libc::c_char {
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    impl_0 = sshkey_impl_from_key(k);
    if impl_0.is_null() {
        return b"unknown\0" as *const u8 as *const libc::c_char;
    }
    return (*impl_0).shortname;
}
unsafe extern "C" fn sshkey_ssh_name_from_type_nid(
    mut type_0: libc::c_int,
    mut nid: libc::c_int,
) -> *const libc::c_char {
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    impl_0 = sshkey_impl_from_type_nid(type_0, nid);
    if impl_0.is_null() {
        return b"ssh-unknown\0" as *const u8 as *const libc::c_char;
    }
    return (*impl_0).name;
}
pub unsafe extern "C" fn sshkey_type_is_cert(mut type_0: libc::c_int) -> libc::c_int {
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    impl_0 = sshkey_impl_from_type(type_0);
    if impl_0.is_null() {
        return 0 as libc::c_int;
    }
    return (*impl_0).cert;
}
pub unsafe extern "C" fn sshkey_ssh_name(mut k: *const sshkey) -> *const libc::c_char {
    return sshkey_ssh_name_from_type_nid((*k).type_0, (*k).ecdsa_nid);
}
pub unsafe extern "C" fn sshkey_ssh_name_plain(mut k: *const sshkey) -> *const libc::c_char {
    return sshkey_ssh_name_from_type_nid(sshkey_type_plain((*k).type_0), (*k).ecdsa_nid);
}
pub unsafe extern "C" fn sshkey_type_from_name(mut name: *const libc::c_char) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    i = 0 as libc::c_int;
    while !(keyimpls[i as usize]).is_null() {
        impl_0 = keyimpls[i as usize];
        if !((*impl_0).name).is_null() && libc::strcmp(name, (*impl_0).name) == 0 as libc::c_int
            || (*impl_0).cert == 0 && strcasecmp((*impl_0).shortname, name) == 0 as libc::c_int
        {
            return (*impl_0).type_0;
        }
        i += 1;
        i;
    }
    return KEY_UNSPEC as libc::c_int;
}
unsafe extern "C" fn key_type_is_ecdsa_variant(mut type_0: libc::c_int) -> libc::c_int {
    match type_0 {
        2 | 6 | 10 | 11 => return 1 as libc::c_int,
        _ => {}
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_ecdsa_nid_from_name(mut name: *const libc::c_char) -> libc::c_int {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while !(keyimpls[i as usize]).is_null() {
        if !(key_type_is_ecdsa_variant((*keyimpls[i as usize]).type_0) == 0) {
            if !((*keyimpls[i as usize]).name).is_null()
                && libc::strcmp(name, (*keyimpls[i as usize]).name) == 0 as libc::c_int
            {
                return (*keyimpls[i as usize]).nid;
            }
        }
        i += 1;
        i;
    }
    return -(1 as libc::c_int);
}
pub unsafe extern "C" fn sshkey_match_keyname_to_sigalgs(
    mut keyname: *const libc::c_char,
    mut sigalgs: *const libc::c_char,
) -> libc::c_int {
    let mut ktype: libc::c_int = 0;
    if sigalgs.is_null() || *sigalgs as libc::c_int == '\0' as i32 || {
        ktype = sshkey_type_from_name(keyname);
        ktype == KEY_UNSPEC as libc::c_int
    } {
        return 0 as libc::c_int;
    } else if ktype == KEY_RSA as libc::c_int {
        return (match_pattern_list(
            b"ssh-rsa\0" as *const u8 as *const libc::c_char,
            sigalgs,
            0 as libc::c_int,
        ) == 1 as libc::c_int
            || match_pattern_list(
                b"rsa-sha2-256\0" as *const u8 as *const libc::c_char,
                sigalgs,
                0 as libc::c_int,
            ) == 1 as libc::c_int
            || match_pattern_list(
                b"rsa-sha2-512\0" as *const u8 as *const libc::c_char,
                sigalgs,
                0 as libc::c_int,
            ) == 1 as libc::c_int) as libc::c_int;
    } else if ktype == KEY_RSA_CERT as libc::c_int {
        return (match_pattern_list(
            b"ssh-rsa-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
            sigalgs,
            0 as libc::c_int,
        ) == 1 as libc::c_int
            || match_pattern_list(
                b"rsa-sha2-256-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
                sigalgs,
                0 as libc::c_int,
            ) == 1 as libc::c_int
            || match_pattern_list(
                b"rsa-sha2-512-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
                sigalgs,
                0 as libc::c_int,
            ) == 1 as libc::c_int) as libc::c_int;
    } else {
        return (match_pattern_list(keyname, sigalgs, 0 as libc::c_int) == 1 as libc::c_int)
            as libc::c_int;
    };
}
pub unsafe extern "C" fn sshkey_alg_list(
    mut certs_only: libc::c_int,
    mut plain_only: libc::c_int,
    mut include_sigonly: libc::c_int,
    mut sep: libc::c_char,
) -> *mut libc::c_char {
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: size_t = 0;
    let mut nlen: size_t = 0;
    let mut rlen: size_t = 0 as libc::c_int as size_t;
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    i = 0 as libc::c_int as size_t;
    while !(keyimpls[i as usize]).is_null() {
        impl_0 = keyimpls[i as usize];
        if !((*impl_0).name).is_null() {
            if !(include_sigonly == 0 && (*impl_0).sigonly != 0) {
                if !(certs_only != 0 && (*impl_0).cert == 0
                    || plain_only != 0 && (*impl_0).cert != 0)
                {
                    if !ret.is_null() {
                        let fresh0 = rlen;
                        rlen = rlen.wrapping_add(1);
                        *ret.offset(fresh0 as isize) = sep;
                    }
                    nlen = strlen((*impl_0).name);
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
                        (*impl_0).name as *const libc::c_void,
                        nlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
                    );
                    rlen = (rlen as libc::c_ulong).wrapping_add(nlen) as size_t as size_t;
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return ret;
}
pub unsafe extern "C" fn sshkey_names_valid2(
    mut names: *const libc::c_char,
    mut allow_wildcard: libc::c_int,
) -> libc::c_int {
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    let mut i: libc::c_int = 0;
    let mut type_0: libc::c_int = 0;
    if names.is_null()
        || libc::strcmp(names, b"\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    cp = libc::strdup(names);
    s = cp;
    if s.is_null() {
        return 0 as libc::c_int;
    }
    let mut current_block_11: u64;
    p = strsep(&mut cp, b",\0" as *const u8 as *const libc::c_char);
    while !p.is_null() && *p as libc::c_int != '\0' as i32 {
        type_0 = sshkey_type_from_name(p);
        if type_0 == KEY_UNSPEC as libc::c_int {
            if allow_wildcard != 0 {
                impl_0 = 0 as *const sshkey_impl;
                i = 0 as libc::c_int;
                while !(keyimpls[i as usize]).is_null() {
                    if match_pattern_list((*keyimpls[i as usize]).name, p, 0 as libc::c_int)
                        != 0 as libc::c_int
                    {
                        impl_0 = keyimpls[i as usize];
                        break;
                    } else {
                        i += 1;
                        i;
                    }
                }
                if !impl_0.is_null() {
                    current_block_11 = 735147466149431745;
                } else {
                    current_block_11 = 10048703153582371463;
                }
            } else {
                current_block_11 = 10048703153582371463;
            }
            match current_block_11 {
                735147466149431745 => {}
                _ => {
                    libc::free(s as *mut libc::c_void);
                    return 0 as libc::c_int;
                }
            }
        }
        p = strsep(&mut cp, b",\0" as *const u8 as *const libc::c_char);
    }
    libc::free(s as *mut libc::c_void);
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_size(mut k: *const sshkey) -> u_int {
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    impl_0 = sshkey_impl_from_key(k);
    if impl_0.is_null() {
        return 0 as libc::c_int as u_int;
    }
    if ((*(*impl_0).funcs).size).is_some() {
        return ((*(*impl_0).funcs).size).expect("non-null function pointer")(k);
    }
    return (*impl_0).keybits as u_int;
}
unsafe extern "C" fn sshkey_type_is_valid_ca(mut type_0: libc::c_int) -> libc::c_int {
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    impl_0 = sshkey_impl_from_type(type_0);
    if impl_0.is_null() {
        return 0 as libc::c_int;
    }
    return ((*impl_0).cert == 0) as libc::c_int;
}
pub unsafe extern "C" fn sshkey_is_cert(mut k: *const sshkey) -> libc::c_int {
    if k.is_null() {
        return 0 as libc::c_int;
    }
    return sshkey_type_is_cert((*k).type_0);
}
pub unsafe extern "C" fn sshkey_is_sk(mut k: *const sshkey) -> libc::c_int {
    if k.is_null() {
        return 0 as libc::c_int;
    }
    match sshkey_type_plain((*k).type_0) {
        10 | 12 => return 1 as libc::c_int,
        _ => return 0 as libc::c_int,
    };
}
pub unsafe extern "C" fn sshkey_type_plain(mut type_0: libc::c_int) -> libc::c_int {
    match type_0 {
        4 => return KEY_RSA as libc::c_int,
        5 => return KEY_DSA as libc::c_int,
        6 => return KEY_ECDSA as libc::c_int,
        11 => return KEY_ECDSA_SK as libc::c_int,
        7 => return KEY_ED25519 as libc::c_int,
        13 => return KEY_ED25519_SK as libc::c_int,
        9 => return KEY_XMSS as libc::c_int,
        _ => return type_0,
    };
}
unsafe extern "C" fn sshkey_type_certified(mut type_0: libc::c_int) -> libc::c_int {
    match type_0 {
        0 => return KEY_RSA_CERT as libc::c_int,
        1 => return KEY_DSA_CERT as libc::c_int,
        2 => return KEY_ECDSA_CERT as libc::c_int,
        10 => return KEY_ECDSA_SK_CERT as libc::c_int,
        3 => return KEY_ED25519_CERT as libc::c_int,
        12 => return KEY_ED25519_SK_CERT as libc::c_int,
        8 => return KEY_XMSS_CERT as libc::c_int,
        _ => return -(1 as libc::c_int),
    };
}
pub unsafe extern "C" fn sshkey_curve_name_to_nid(mut name: *const libc::c_char) -> libc::c_int {
    if libc::strcmp(name, b"nistp256\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 415 as libc::c_int;
    } else if libc::strcmp(name, b"nistp384\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        return 715 as libc::c_int;
    } else if libc::strcmp(name, b"nistp521\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        return 716 as libc::c_int;
    } else {
        return -(1 as libc::c_int);
    };
}
pub unsafe extern "C" fn sshkey_curve_nid_to_bits(mut nid: libc::c_int) -> u_int {
    match nid {
        415 => return 256 as libc::c_int as u_int,
        715 => return 384 as libc::c_int as u_int,
        716 => return 521 as libc::c_int as u_int,
        _ => return 0 as libc::c_int as u_int,
    };
}
pub unsafe extern "C" fn sshkey_ecdsa_bits_to_nid(mut bits: libc::c_int) -> libc::c_int {
    match bits {
        256 => return 415 as libc::c_int,
        384 => return 715 as libc::c_int,
        521 => return 716 as libc::c_int,
        _ => return -(1 as libc::c_int),
    };
}
pub unsafe extern "C" fn sshkey_curve_nid_to_name(mut nid: libc::c_int) -> *const libc::c_char {
    match nid {
        415 => return b"nistp256\0" as *const u8 as *const libc::c_char,
        715 => return b"nistp384\0" as *const u8 as *const libc::c_char,
        716 => return b"nistp521\0" as *const u8 as *const libc::c_char,
        _ => return 0 as *const libc::c_char,
    };
}
pub unsafe extern "C" fn sshkey_ec_nid_to_hash_alg(mut nid: libc::c_int) -> libc::c_int {
    let mut kbits: libc::c_int = sshkey_curve_nid_to_bits(nid) as libc::c_int;
    if kbits <= 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if kbits <= 256 as libc::c_int {
        return 2 as libc::c_int;
    } else if kbits <= 384 as libc::c_int {
        return 3 as libc::c_int;
    } else {
        return 4 as libc::c_int;
    };
}
unsafe extern "C" fn cert_free(mut cert: *mut sshkey_cert) {
    let mut i: u_int = 0;
    if cert.is_null() {
        return;
    }
    crate::sshbuf::sshbuf_free((*cert).certblob);
    crate::sshbuf::sshbuf_free((*cert).critical);
    crate::sshbuf::sshbuf_free((*cert).extensions);
    libc::free((*cert).key_id as *mut libc::c_void);
    i = 0 as libc::c_int as u_int;
    while i < (*cert).nprincipals {
        libc::free(*((*cert).principals).offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free((*cert).principals as *mut libc::c_void);
    sshkey_free((*cert).signature_key);
    libc::free((*cert).signature_type as *mut libc::c_void);
    freezero(
        cert as *mut libc::c_void,
        ::core::mem::size_of::<sshkey_cert>() as libc::c_ulong,
    );
}
unsafe extern "C" fn cert_new() -> *mut sshkey_cert {
    let mut cert: *mut sshkey_cert = 0 as *mut sshkey_cert;
    cert = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<sshkey_cert>() as libc::c_ulong,
    ) as *mut sshkey_cert;
    if cert.is_null() {
        return 0 as *mut sshkey_cert;
    }
    (*cert).certblob = crate::sshbuf::sshbuf_new();
    if ((*cert).certblob).is_null()
        || {
            (*cert).critical = crate::sshbuf::sshbuf_new();
            ((*cert).critical).is_null()
        }
        || {
            (*cert).extensions = crate::sshbuf::sshbuf_new();
            ((*cert).extensions).is_null()
        }
    {
        cert_free(cert);
        return 0 as *mut sshkey_cert;
    }
    (*cert).key_id = 0 as *mut libc::c_char;
    (*cert).principals = 0 as *mut *mut libc::c_char;
    (*cert).signature_key = 0 as *mut sshkey;
    (*cert).signature_type = 0 as *mut libc::c_char;
    return cert;
}
pub unsafe extern "C" fn sshkey_new(mut type_0: libc::c_int) -> *mut sshkey {
    let mut k: *mut sshkey = 0 as *mut sshkey;
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    if type_0 != KEY_UNSPEC as libc::c_int && {
        impl_0 = sshkey_impl_from_type(type_0);
        impl_0.is_null()
    } {
        return 0 as *mut sshkey;
    }
    k = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<sshkey>() as libc::c_ulong,
    ) as *mut sshkey;
    if k.is_null() {
        return 0 as *mut sshkey;
    }
    (*k).type_0 = type_0;
    (*k).ecdsa_nid = -(1 as libc::c_int);
    if !impl_0.is_null() && ((*(*impl_0).funcs).alloc).is_some() {
        if ((*(*impl_0).funcs).alloc).expect("non-null function pointer")(k) != 0 as libc::c_int {
            libc::free(k as *mut libc::c_void);
            return 0 as *mut sshkey;
        }
    }
    if sshkey_is_cert(k) != 0 {
        (*k).cert = cert_new();
        if ((*k).cert).is_null() {
            sshkey_free(k);
            return 0 as *mut sshkey;
        }
    }
    return k;
}
pub unsafe extern "C" fn sshkey_sk_cleanup(mut k: *mut sshkey) {
    libc::free((*k).sk_application as *mut libc::c_void);
    crate::sshbuf::sshbuf_free((*k).sk_key_handle);
    crate::sshbuf::sshbuf_free((*k).sk_reserved);
    (*k).sk_application = 0 as *mut libc::c_char;
    (*k).sk_reserved = 0 as *mut crate::sshbuf::sshbuf;
    (*k).sk_key_handle = (*k).sk_reserved;
}
unsafe extern "C" fn sshkey_free_contents(mut k: *mut sshkey) {
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    if k.is_null() {
        return;
    }
    impl_0 = sshkey_impl_from_type((*k).type_0);
    if !impl_0.is_null() && ((*(*impl_0).funcs).cleanup).is_some() {
        ((*(*impl_0).funcs).cleanup).expect("non-null function pointer")(k);
    }
    if sshkey_is_cert(k) != 0 {
        cert_free((*k).cert);
    }
    freezero(
        (*k).shielded_private as *mut libc::c_void,
        (*k).shielded_len,
    );
    freezero(
        (*k).shield_prekey as *mut libc::c_void,
        (*k).shield_prekey_len,
    );
}
pub unsafe extern "C" fn sshkey_free(mut k: *mut sshkey) {
    sshkey_free_contents(k);
    freezero(
        k as *mut libc::c_void,
        ::core::mem::size_of::<sshkey>() as libc::c_ulong,
    );
}
unsafe extern "C" fn cert_compare(mut a: *mut sshkey_cert, mut b: *mut sshkey_cert) -> libc::c_int {
    if a.is_null() && b.is_null() {
        return 1 as libc::c_int;
    }
    if a.is_null() || b.is_null() {
        return 0 as libc::c_int;
    }
    if crate::sshbuf::sshbuf_len((*a).certblob) != crate::sshbuf::sshbuf_len((*b).certblob) {
        return 0 as libc::c_int;
    }
    if timingsafe_bcmp(
        sshbuf_ptr((*a).certblob) as *const libc::c_void,
        sshbuf_ptr((*b).certblob) as *const libc::c_void,
        crate::sshbuf::sshbuf_len((*a).certblob),
    ) != 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_sk_fields_equal(
    mut a: *const sshkey,
    mut b: *const sshkey,
) -> libc::c_int {
    if ((*a).sk_application).is_null() || ((*b).sk_application).is_null() {
        return 0 as libc::c_int;
    }
    if libc::strcmp((*a).sk_application, (*b).sk_application) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_equal_public(
    mut a: *const sshkey,
    mut b: *const sshkey,
) -> libc::c_int {
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    if a.is_null()
        || b.is_null()
        || sshkey_type_plain((*a).type_0) != sshkey_type_plain((*b).type_0)
    {
        return 0 as libc::c_int;
    }
    impl_0 = sshkey_impl_from_type((*a).type_0);
    if impl_0.is_null() {
        return 0 as libc::c_int;
    }
    return ((*(*impl_0).funcs).equal).expect("non-null function pointer")(a, b);
}
pub unsafe extern "C" fn sshkey_equal(mut a: *const sshkey, mut b: *const sshkey) -> libc::c_int {
    if a.is_null() || b.is_null() || (*a).type_0 != (*b).type_0 {
        return 0 as libc::c_int;
    }
    if sshkey_is_cert(a) != 0 {
        if cert_compare((*a).cert, (*b).cert) == 0 {
            return 0 as libc::c_int;
        }
    }
    return sshkey_equal_public(a, b);
}
pub unsafe extern "C" fn sshkey_serialize_sk(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = sshbuf_put_cstring(b, (*key).sk_application);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn to_blob_buf(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut force_plain: libc::c_int,
    mut opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut type_0: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut typename: *const libc::c_char = 0 as *const libc::c_char;
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    if key.is_null() {
        return -(10 as libc::c_int);
    }
    type_0 = if force_plain != 0 {
        sshkey_type_plain((*key).type_0)
    } else {
        (*key).type_0
    };
    if sshkey_type_is_cert(type_0) != 0 {
        if ((*key).cert).is_null() {
            return -(16 as libc::c_int);
        }
        if crate::sshbuf::sshbuf_len((*(*key).cert).certblob) == 0 as libc::c_int as libc::c_ulong {
            return -(17 as libc::c_int);
        }
        ret = sshbuf_putb(b, (*(*key).cert).certblob);
        if ret != 0 as libc::c_int {
            return ret;
        }
        return 0 as libc::c_int;
    }
    impl_0 = sshkey_impl_from_type(type_0);
    if impl_0.is_null() {
        return -(14 as libc::c_int);
    }
    typename = sshkey_ssh_name_from_type_nid(type_0, (*key).ecdsa_nid);
    ret = sshbuf_put_cstring(b, typename);
    if ret != 0 as libc::c_int {
        return ret;
    }
    return ((*(*impl_0).funcs).serialize_public).expect("non-null function pointer")(key, b, opts);
}
pub unsafe extern "C" fn sshkey_putb(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    return to_blob_buf(key, b, 0 as libc::c_int, SSHKEY_SERIALIZE_DEFAULT);
}
pub unsafe extern "C" fn sshkey_puts_opts(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut tmp: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    tmp = crate::sshbuf::sshbuf_new();
    if tmp.is_null() {
        return -(2 as libc::c_int);
    }
    r = to_blob_buf(key, tmp, 0 as libc::c_int, opts);
    if r == 0 as libc::c_int {
        r = sshbuf_put_stringb(b, tmp);
    }
    crate::sshbuf::sshbuf_free(tmp);
    return r;
}
pub unsafe extern "C" fn sshkey_puts(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    return sshkey_puts_opts(key, b, SSHKEY_SERIALIZE_DEFAULT);
}
pub unsafe extern "C" fn sshkey_putb_plain(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    return to_blob_buf(key, b, 1 as libc::c_int, SSHKEY_SERIALIZE_DEFAULT);
}
unsafe extern "C" fn to_blob(
    mut key: *const sshkey,
    mut blobp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut force_plain: libc::c_int,
    mut opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut len: size_t = 0;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    if !lenp.is_null() {
        *lenp = 0 as libc::c_int as size_t;
    }
    if !blobp.is_null() {
        *blobp = 0 as *mut u_char;
    }
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    ret = to_blob_buf(key, b, force_plain, opts);
    if !(ret != 0 as libc::c_int) {
        len = crate::sshbuf::sshbuf_len(b);
        if !lenp.is_null() {
            *lenp = len;
        }
        if !blobp.is_null() {
            *blobp = libc::malloc(len as usize) as *mut u_char;
            if (*blobp).is_null() {
                ret = -(2 as libc::c_int);
                current_block = 7890910541524280225;
            } else {
                memcpy(
                    *blobp as *mut libc::c_void,
                    sshbuf_ptr(b) as *const libc::c_void,
                    len,
                );
                current_block = 2979737022853876585;
            }
        } else {
            current_block = 2979737022853876585;
        }
        match current_block {
            7890910541524280225 => {}
            _ => {
                ret = 0 as libc::c_int;
            }
        }
    }
    crate::sshbuf::sshbuf_free(b);
    return ret;
}
pub unsafe extern "C" fn sshkey_to_blob(
    mut key: *const sshkey,
    mut blobp: *mut *mut u_char,
    mut lenp: *mut size_t,
) -> libc::c_int {
    return to_blob(key, blobp, lenp, 0 as libc::c_int, SSHKEY_SERIALIZE_DEFAULT);
}
pub unsafe extern "C" fn sshkey_plain_to_blob(
    mut key: *const sshkey,
    mut blobp: *mut *mut u_char,
    mut lenp: *mut size_t,
) -> libc::c_int {
    return to_blob(key, blobp, lenp, 1 as libc::c_int, SSHKEY_SERIALIZE_DEFAULT);
}
pub unsafe extern "C" fn sshkey_fingerprint_raw(
    mut k: *const sshkey,
    mut dgst_alg: libc::c_int,
    mut retp: *mut *mut u_char,
    mut lenp: *mut size_t,
) -> libc::c_int {
    let mut blob: *mut u_char = 0 as *mut u_char;
    let mut ret: *mut u_char = 0 as *mut u_char;
    let mut blob_len: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = -(1 as libc::c_int);
    if !retp.is_null() {
        *retp = 0 as *mut u_char;
    }
    if !lenp.is_null() {
        *lenp = 0 as libc::c_int as size_t;
    }
    if ssh_digest_bytes(dgst_alg) == 0 as libc::c_int as libc::c_ulong {
        r = -(10 as libc::c_int);
    } else {
        r = to_blob(
            k,
            &mut blob,
            &mut blob_len,
            1 as libc::c_int,
            SSHKEY_SERIALIZE_DEFAULT,
        );
        if !(r != 0 as libc::c_int) {
            ret = calloc(
                1 as libc::c_int as libc::c_ulong,
                64 as libc::c_int as libc::c_ulong,
            ) as *mut u_char;
            if ret.is_null() {
                r = -(2 as libc::c_int);
            } else {
                r = ssh_digest_memory(
                    dgst_alg,
                    blob as *const libc::c_void,
                    blob_len,
                    ret,
                    64 as libc::c_int as size_t,
                );
                if !(r != 0 as libc::c_int) {
                    if !retp.is_null() {
                        *retp = ret;
                        ret = 0 as *mut u_char;
                    }
                    if !lenp.is_null() {
                        *lenp = ssh_digest_bytes(dgst_alg);
                    }
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    libc::free(ret as *mut libc::c_void);
    if !blob.is_null() {
        freezero(blob as *mut libc::c_void, blob_len);
    }
    return r;
}
unsafe extern "C" fn fingerprint_b64(
    mut alg: *const libc::c_char,
    mut dgst_raw: *mut u_char,
    mut dgst_raw_len: size_t,
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut plen: size_t = (strlen(alg)).wrapping_add(1 as libc::c_int as libc::c_ulong);
    let mut rlen: size_t = dgst_raw_len
        .wrapping_add(2 as libc::c_int as libc::c_ulong)
        .wrapping_div(3 as libc::c_int as libc::c_ulong)
        .wrapping_mul(4 as libc::c_int as libc::c_ulong)
        .wrapping_add(plen)
        .wrapping_add(1 as libc::c_int as libc::c_ulong);
    if dgst_raw_len > 65536 as libc::c_int as libc::c_ulong || {
        ret = calloc(1 as libc::c_int as libc::c_ulong, rlen) as *mut libc::c_char;
        ret.is_null()
    } {
        return 0 as *mut libc::c_char;
    }
    strlcpy(ret, alg, rlen);
    strlcat(ret, b":\0" as *const u8 as *const libc::c_char, rlen);
    if dgst_raw_len == 0 as libc::c_int as libc::c_ulong {
        return ret;
    }
    if __b64_ntop(
        dgst_raw,
        dgst_raw_len,
        ret.offset(plen as isize),
        rlen.wrapping_sub(plen),
    ) == -(1 as libc::c_int)
    {
        freezero(ret as *mut libc::c_void, rlen);
        return 0 as *mut libc::c_char;
    }
    *ret.offset(strcspn(ret, b"=\0" as *const u8 as *const libc::c_char) as isize) =
        '\0' as i32 as libc::c_char;
    return ret;
}
unsafe extern "C" fn fingerprint_hex(
    mut alg: *const libc::c_char,
    mut dgst_raw: *mut u_char,
    mut dgst_raw_len: size_t,
) -> *mut libc::c_char {
    let mut retval: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hex: [libc::c_char; 5] = [0; 5];
    let mut i: size_t = 0;
    let mut rlen: size_t = dgst_raw_len
        .wrapping_mul(3 as libc::c_int as libc::c_ulong)
        .wrapping_add(strlen(alg))
        .wrapping_add(2 as libc::c_int as libc::c_ulong);
    if dgst_raw_len > 65536 as libc::c_int as libc::c_ulong || {
        retval = calloc(1 as libc::c_int as libc::c_ulong, rlen) as *mut libc::c_char;
        retval.is_null()
    } {
        return 0 as *mut libc::c_char;
    }
    strlcpy(retval, alg, rlen);
    strlcat(retval, b":\0" as *const u8 as *const libc::c_char, rlen);
    i = 0 as libc::c_int as size_t;
    while i < dgst_raw_len {
        libc::snprintf(
            hex.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 5]>() as usize,
            b"%s%02x\0" as *const u8 as *const libc::c_char,
            if i > 0 as libc::c_int as libc::c_ulong {
                b":\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            *dgst_raw.offset(i as isize) as libc::c_int,
        );
        strlcat(retval, hex.as_mut_ptr(), rlen);
        i = i.wrapping_add(1);
        i;
    }
    return retval;
}
unsafe extern "C" fn fingerprint_bubblebabble(
    mut dgst_raw: *mut u_char,
    mut dgst_raw_len: size_t,
) -> *mut libc::c_char {
    let mut vowels: [libc::c_char; 6] = [
        'a' as i32 as libc::c_char,
        'e' as i32 as libc::c_char,
        'i' as i32 as libc::c_char,
        'o' as i32 as libc::c_char,
        'u' as i32 as libc::c_char,
        'y' as i32 as libc::c_char,
    ];
    let mut consonants: [libc::c_char; 17] = [
        'b' as i32 as libc::c_char,
        'c' as i32 as libc::c_char,
        'd' as i32 as libc::c_char,
        'f' as i32 as libc::c_char,
        'g' as i32 as libc::c_char,
        'h' as i32 as libc::c_char,
        'k' as i32 as libc::c_char,
        'l' as i32 as libc::c_char,
        'm' as i32 as libc::c_char,
        'n' as i32 as libc::c_char,
        'p' as i32 as libc::c_char,
        'r' as i32 as libc::c_char,
        's' as i32 as libc::c_char,
        't' as i32 as libc::c_char,
        'v' as i32 as libc::c_char,
        'z' as i32 as libc::c_char,
        'x' as i32 as libc::c_char,
    ];
    let mut i: u_int = 0;
    let mut j: u_int = 0 as libc::c_int as u_int;
    let mut rounds: u_int = 0;
    let mut seed: u_int = 1 as libc::c_int as u_int;
    let mut retval: *mut libc::c_char = 0 as *mut libc::c_char;
    rounds = dgst_raw_len
        .wrapping_div(2 as libc::c_int as libc::c_ulong)
        .wrapping_add(1 as libc::c_int as libc::c_ulong) as u_int;
    retval =
        calloc(rounds as libc::c_ulong, 6 as libc::c_int as libc::c_ulong) as *mut libc::c_char;
    if retval.is_null() {
        return 0 as *mut libc::c_char;
    }
    let fresh1 = j;
    j = j.wrapping_add(1);
    *retval.offset(fresh1 as isize) = 'x' as i32 as libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < rounds {
        let mut idx0: u_int = 0;
        let mut idx1: u_int = 0;
        let mut idx2: u_int = 0;
        let mut idx3: u_int = 0;
        let mut idx4: u_int = 0;
        if i.wrapping_add(1 as libc::c_int as libc::c_uint) < rounds
            || dgst_raw_len.wrapping_rem(2 as libc::c_int as libc::c_ulong)
                != 0 as libc::c_int as libc::c_ulong
        {
            idx0 = (*dgst_raw.offset((2 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize)
                as u_int
                >> 6 as libc::c_int
                & 3 as libc::c_int as libc::c_uint)
                .wrapping_add(seed)
                .wrapping_rem(6 as libc::c_int as libc::c_uint);
            idx1 = *dgst_raw.offset((2 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize)
                as u_int
                >> 2 as libc::c_int
                & 15 as libc::c_int as libc::c_uint;
            idx2 = (*dgst_raw.offset((2 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize)
                as u_int
                & 3 as libc::c_int as libc::c_uint)
                .wrapping_add(seed.wrapping_div(6 as libc::c_int as libc::c_uint))
                .wrapping_rem(6 as libc::c_int as libc::c_uint);
            let fresh2 = j;
            j = j.wrapping_add(1);
            *retval.offset(fresh2 as isize) = vowels[idx0 as usize];
            let fresh3 = j;
            j = j.wrapping_add(1);
            *retval.offset(fresh3 as isize) = consonants[idx1 as usize];
            let fresh4 = j;
            j = j.wrapping_add(1);
            *retval.offset(fresh4 as isize) = vowels[idx2 as usize];
            if i.wrapping_add(1 as libc::c_int as libc::c_uint) < rounds {
                idx3 = *dgst_raw.offset(
                    (2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint)
                        as isize,
                ) as u_int
                    >> 4 as libc::c_int
                    & 15 as libc::c_int as libc::c_uint;
                idx4 = *dgst_raw.offset(
                    (2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint)
                        as isize,
                ) as u_int
                    & 15 as libc::c_int as libc::c_uint;
                let fresh5 = j;
                j = j.wrapping_add(1);
                *retval.offset(fresh5 as isize) = consonants[idx3 as usize];
                let fresh6 = j;
                j = j.wrapping_add(1);
                *retval.offset(fresh6 as isize) = '-' as i32 as libc::c_char;
                let fresh7 = j;
                j = j.wrapping_add(1);
                *retval.offset(fresh7 as isize) = consonants[idx4 as usize];
                seed = seed
                    .wrapping_mul(5 as libc::c_int as libc::c_uint)
                    .wrapping_add(
                        (*dgst_raw
                            .offset((2 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize)
                            as u_int)
                            .wrapping_mul(7 as libc::c_int as libc::c_uint)
                            .wrapping_add(
                                *dgst_raw.offset(
                                    (2 as libc::c_int as libc::c_uint)
                                        .wrapping_mul(i)
                                        .wrapping_add(1 as libc::c_int as libc::c_uint)
                                        as isize,
                                ) as u_int,
                            ),
                    )
                    .wrapping_rem(36 as libc::c_int as libc::c_uint);
            }
        } else {
            idx0 = seed.wrapping_rem(6 as libc::c_int as libc::c_uint);
            idx1 = 16 as libc::c_int as u_int;
            idx2 = seed.wrapping_div(6 as libc::c_int as libc::c_uint);
            let fresh8 = j;
            j = j.wrapping_add(1);
            *retval.offset(fresh8 as isize) = vowels[idx0 as usize];
            let fresh9 = j;
            j = j.wrapping_add(1);
            *retval.offset(fresh9 as isize) = consonants[idx1 as usize];
            let fresh10 = j;
            j = j.wrapping_add(1);
            *retval.offset(fresh10 as isize) = vowels[idx2 as usize];
        }
        i = i.wrapping_add(1);
        i;
    }
    let fresh11 = j;
    j = j.wrapping_add(1);
    *retval.offset(fresh11 as isize) = 'x' as i32 as libc::c_char;
    let fresh12 = j;
    j = j.wrapping_add(1);
    *retval.offset(fresh12 as isize) = '\0' as i32 as libc::c_char;
    return retval;
}
unsafe extern "C" fn fingerprint_randomart(
    mut alg: *const libc::c_char,
    mut dgst_raw: *mut u_char,
    mut dgst_raw_len: size_t,
    mut k: *const sshkey,
) -> *mut libc::c_char {
    let mut augmentation_string: *mut libc::c_char =
        b" .o+=*BOX@%&#/^SE\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    let mut retval: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut title: [libc::c_char; 17] = [0; 17];
    let mut hash: [libc::c_char; 17] = [0; 17];
    let mut field: [[u_char; 9]; 17] = [[0; 9]; 17];
    let mut i: size_t = 0;
    let mut tlen: size_t = 0;
    let mut hlen: size_t = 0;
    let mut b: u_int = 0;
    let mut x: libc::c_int = 0;
    let mut y: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut len: size_t =
        (strlen(augmentation_string)).wrapping_sub(1 as libc::c_int as libc::c_ulong);
    retval = calloc(
        (8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int + 3 as libc::c_int)
            as libc::c_ulong,
        (8 as libc::c_int + 1 as libc::c_int + 2 as libc::c_int) as libc::c_ulong,
    ) as *mut libc::c_char;
    if retval.is_null() {
        return 0 as *mut libc::c_char;
    }
    memset(
        field.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        (((8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int)
            * (8 as libc::c_int + 1 as libc::c_int)) as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<libc::c_char>() as libc::c_ulong),
    );
    x = (8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) / 2 as libc::c_int;
    y = (8 as libc::c_int + 1 as libc::c_int) / 2 as libc::c_int;
    i = 0 as libc::c_int as size_t;
    while i < dgst_raw_len {
        let mut input: libc::c_int = 0;
        input = *dgst_raw.offset(i as isize) as libc::c_int;
        b = 0 as libc::c_int as u_int;
        while b < 4 as libc::c_int as libc::c_uint {
            x += if input & 0x1 as libc::c_int != 0 {
                1 as libc::c_int
            } else {
                -(1 as libc::c_int)
            };
            y += if input & 0x2 as libc::c_int != 0 {
                1 as libc::c_int
            } else {
                -(1 as libc::c_int)
            };
            x = if x > 0 as libc::c_int {
                x
            } else {
                0 as libc::c_int
            };
            y = if y > 0 as libc::c_int {
                y
            } else {
                0 as libc::c_int
            };
            x = if x < 8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int - 1 as libc::c_int {
                x
            } else {
                8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int - 1 as libc::c_int
            };
            y = if y < 8 as libc::c_int + 1 as libc::c_int - 1 as libc::c_int {
                y
            } else {
                8 as libc::c_int + 1 as libc::c_int - 1 as libc::c_int
            };
            if (field[x as usize][y as usize] as libc::c_ulong)
                < len.wrapping_sub(2 as libc::c_int as libc::c_ulong)
            {
                field[x as usize][y as usize] = (field[x as usize][y as usize]).wrapping_add(1);
                field[x as usize][y as usize];
            }
            input = input >> 2 as libc::c_int;
            b = b.wrapping_add(1);
            b;
        }
        i = i.wrapping_add(1);
        i;
    }
    field[((8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) / 2 as libc::c_int) as usize]
        [((8 as libc::c_int + 1 as libc::c_int) / 2 as libc::c_int) as usize] =
        len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as u_char;
    field[x as usize][y as usize] = len as u_char;
    r = libc::snprintf(
        title.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 17]>() as usize,
        b"[%s %u]\0" as *const u8 as *const libc::c_char,
        sshkey_type(k),
        sshkey_size(k),
    );
    if r < 0 as libc::c_int
        || r > ::core::mem::size_of::<[libc::c_char; 17]>() as libc::c_ulong as libc::c_int
    {
        r = libc::snprintf(
            title.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 17]>() as usize,
            b"[%s]\0" as *const u8 as *const libc::c_char,
            sshkey_type(k),
        );
    }
    tlen = if r <= 0 as libc::c_int {
        0 as libc::c_int as libc::c_ulong
    } else {
        strlen(title.as_mut_ptr())
    };
    r = libc::snprintf(
        hash.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 17]>() as usize,
        b"[%s]\0" as *const u8 as *const libc::c_char,
        alg,
    );
    hlen = if r <= 0 as libc::c_int {
        0 as libc::c_int as libc::c_ulong
    } else {
        strlen(hash.as_mut_ptr())
    };
    p = retval;
    let fresh13 = p;
    p = p.offset(1);
    *fresh13 = '+' as i32 as libc::c_char;
    i = 0 as libc::c_int as size_t;
    while i
        < ((8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as libc::c_ulong)
            .wrapping_sub(tlen)
            .wrapping_div(2 as libc::c_int as libc::c_ulong)
    {
        let fresh14 = p;
        p = p.offset(1);
        *fresh14 = '-' as i32 as libc::c_char;
        i = i.wrapping_add(1);
        i;
    }
    memcpy(
        p as *mut libc::c_void,
        title.as_mut_ptr() as *const libc::c_void,
        tlen,
    );
    p = p.offset(tlen as isize);
    i = (i as libc::c_ulong).wrapping_add(tlen) as size_t as size_t;
    while i < (8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as libc::c_ulong {
        let fresh15 = p;
        p = p.offset(1);
        *fresh15 = '-' as i32 as libc::c_char;
        i = i.wrapping_add(1);
        i;
    }
    let fresh16 = p;
    p = p.offset(1);
    *fresh16 = '+' as i32 as libc::c_char;
    let fresh17 = p;
    p = p.offset(1);
    *fresh17 = '\n' as i32 as libc::c_char;
    y = 0 as libc::c_int;
    while y < 8 as libc::c_int + 1 as libc::c_int {
        let fresh18 = p;
        p = p.offset(1);
        *fresh18 = '|' as i32 as libc::c_char;
        x = 0 as libc::c_int;
        while x < 8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int {
            let fresh19 = p;
            p = p.offset(1);
            *fresh19 = *augmentation_string.offset(
                (if (field[x as usize][y as usize] as libc::c_ulong) < len {
                    field[x as usize][y as usize] as libc::c_ulong
                } else {
                    len
                }) as isize,
            );
            x += 1;
            x;
        }
        let fresh20 = p;
        p = p.offset(1);
        *fresh20 = '|' as i32 as libc::c_char;
        let fresh21 = p;
        p = p.offset(1);
        *fresh21 = '\n' as i32 as libc::c_char;
        y += 1;
        y;
    }
    let fresh22 = p;
    p = p.offset(1);
    *fresh22 = '+' as i32 as libc::c_char;
    i = 0 as libc::c_int as size_t;
    while i
        < ((8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as libc::c_ulong)
            .wrapping_sub(hlen)
            .wrapping_div(2 as libc::c_int as libc::c_ulong)
    {
        let fresh23 = p;
        p = p.offset(1);
        *fresh23 = '-' as i32 as libc::c_char;
        i = i.wrapping_add(1);
        i;
    }
    memcpy(
        p as *mut libc::c_void,
        hash.as_mut_ptr() as *const libc::c_void,
        hlen,
    );
    p = p.offset(hlen as isize);
    i = (i as libc::c_ulong).wrapping_add(hlen) as size_t as size_t;
    while i < (8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as libc::c_ulong {
        let fresh24 = p;
        p = p.offset(1);
        *fresh24 = '-' as i32 as libc::c_char;
        i = i.wrapping_add(1);
        i;
    }
    let fresh25 = p;
    p = p.offset(1);
    *fresh25 = '+' as i32 as libc::c_char;
    return retval;
}
pub unsafe extern "C" fn sshkey_fingerprint(
    mut k: *const sshkey,
    mut dgst_alg: libc::c_int,
    mut dgst_rep: sshkey_fp_rep,
) -> *mut libc::c_char {
    let mut retval: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut dgst_raw: *mut u_char = 0 as *mut u_char;
    let mut dgst_raw_len: size_t = 0;
    if sshkey_fingerprint_raw(k, dgst_alg, &mut dgst_raw, &mut dgst_raw_len) != 0 as libc::c_int {
        return 0 as *mut libc::c_char;
    }
    match dgst_rep as libc::c_uint {
        0 => {
            if dgst_alg == 0 as libc::c_int {
                retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg), dgst_raw, dgst_raw_len);
            } else {
                retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg), dgst_raw, dgst_raw_len);
            }
        }
        1 => {
            retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg), dgst_raw, dgst_raw_len);
        }
        2 => {
            retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg), dgst_raw, dgst_raw_len);
        }
        3 => {
            retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
        }
        4 => {
            retval =
                fingerprint_randomart(ssh_digest_alg_name(dgst_alg), dgst_raw, dgst_raw_len, k);
        }
        _ => {
            freezero(dgst_raw as *mut libc::c_void, dgst_raw_len);
            return 0 as *mut libc::c_char;
        }
    }
    freezero(dgst_raw as *mut libc::c_void, dgst_raw_len);
    return retval;
}
unsafe extern "C" fn peek_type_nid(
    mut s: *const libc::c_char,
    mut l: size_t,
    mut nid: *mut libc::c_int,
) -> libc::c_int {
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while !(keyimpls[i as usize]).is_null() {
        impl_0 = keyimpls[i as usize];
        if !(((*impl_0).name).is_null() || strlen((*impl_0).name) != l) {
            if memcmp(
                s as *const libc::c_void,
                (*impl_0).name as *const libc::c_void,
                l,
            ) == 0 as libc::c_int
            {
                *nid = -(1 as libc::c_int);
                if key_type_is_ecdsa_variant((*impl_0).type_0) != 0 {
                    *nid = (*impl_0).nid;
                }
                return (*impl_0).type_0;
            }
        }
        i += 1;
        i;
    }
    return KEY_UNSPEC as libc::c_int;
}
pub unsafe extern "C" fn sshkey_read(
    mut ret: *mut sshkey,
    mut cpp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut k: *mut sshkey = 0 as *mut sshkey;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut blobcopy: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut space: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut type_0: libc::c_int = 0;
    let mut curve_nid: libc::c_int = -(1 as libc::c_int);
    let mut blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    if ret.is_null() {
        return -(10 as libc::c_int);
    }
    if (*ret).type_0 != KEY_UNSPEC as libc::c_int
        && (sshkey_impl_from_type((*ret).type_0)).is_null()
    {
        return -(10 as libc::c_int);
    }
    cp = *cpp;
    space = strcspn(cp, b" \t\0" as *const u8 as *const libc::c_char);
    if space == strlen(cp) {
        return -(4 as libc::c_int);
    }
    type_0 = peek_type_nid(cp, space, &mut curve_nid);
    if type_0 == KEY_UNSPEC as libc::c_int {
        return -(4 as libc::c_int);
    }
    cp = cp.offset(space as isize);
    while *cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32 {
        cp = cp.offset(1);
        cp;
    }
    if *cp as libc::c_int == '\0' as i32 {
        return -(4 as libc::c_int);
    }
    if (*ret).type_0 != KEY_UNSPEC as libc::c_int && (*ret).type_0 != type_0 {
        return -(13 as libc::c_int);
    }
    blob = crate::sshbuf::sshbuf_new();
    if blob.is_null() {
        return -(2 as libc::c_int);
    }
    space = strcspn(cp, b" \t\0" as *const u8 as *const libc::c_char);
    blobcopy = strndup(cp, space);
    if blobcopy.is_null() {
        crate::sshbuf::sshbuf_free(blob);
        return -(2 as libc::c_int);
    }
    r = sshbuf_b64tod(blob, blobcopy);
    if r != 0 as libc::c_int {
        libc::free(blobcopy as *mut libc::c_void);
        crate::sshbuf::sshbuf_free(blob);
        return r;
    }
    libc::free(blobcopy as *mut libc::c_void);
    r = sshkey_fromb(blob, &mut k);
    if r != 0 as libc::c_int {
        crate::sshbuf::sshbuf_free(blob);
        return r;
    }
    crate::sshbuf::sshbuf_free(blob);
    cp = cp.offset(space as isize);
    while *cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32 {
        cp = cp.offset(1);
        cp;
    }
    if (*k).type_0 != type_0 {
        sshkey_free(k);
        return -(13 as libc::c_int);
    }
    if key_type_is_ecdsa_variant(type_0) != 0 && curve_nid != (*k).ecdsa_nid {
        sshkey_free(k);
        return -(15 as libc::c_int);
    }
    sshkey_free_contents(ret);
    *ret = *k;
    freezero(
        k as *mut libc::c_void,
        ::core::mem::size_of::<sshkey>() as libc::c_ulong,
    );
    *cpp = cp;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_to_base64(
    mut key: *const sshkey,
    mut b64p: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut uu: *mut libc::c_char = 0 as *mut libc::c_char;
    if !b64p.is_null() {
        *b64p = 0 as *mut libc::c_char;
    }
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshkey_putb(key, b);
    if !(r != 0 as libc::c_int) {
        uu = sshbuf_dtob64_string(b, 0 as libc::c_int);
        if uu.is_null() {
            r = -(2 as libc::c_int);
        } else {
            if !b64p.is_null() {
                *b64p = uu;
                uu = 0 as *mut libc::c_char;
            }
            r = 0 as libc::c_int;
        }
    }
    crate::sshbuf::sshbuf_free(b);
    libc::free(uu as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn sshkey_format_text(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut uu: *mut libc::c_char = 0 as *mut libc::c_char;
    r = sshkey_to_base64(key, &mut uu);
    if !(r != 0 as libc::c_int) {
        r = crate::sshbuf_getput_basic::sshbuf_putf(
            b,
            b"%s %s\0" as *const u8 as *const libc::c_char,
            sshkey_ssh_name(key),
            uu,
        );
        if !(r != 0 as libc::c_int) {
            r = 0 as libc::c_int;
        }
    }
    libc::free(uu as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn sshkey_write(
    mut key: *const sshkey,
    mut f: *mut libc::FILE,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = -(1 as libc::c_int);
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshkey_format_text(key, b);
    if !(r != 0 as libc::c_int) {
        if fwrite(
            sshbuf_ptr(b) as *const libc::c_void,
            crate::sshbuf::sshbuf_len(b),
            1 as libc::c_int as libc::c_ulong,
            f,
        ) != 1 as libc::c_int as libc::c_ulong
        {
            if feof(f) != 0 {
                *libc::__errno_location() = 32 as libc::c_int;
            }
            r = -(24 as libc::c_int);
        } else {
            r = 0 as libc::c_int;
        }
    }
    crate::sshbuf::sshbuf_free(b);
    return r;
}
pub unsafe extern "C" fn sshkey_cert_type(mut k: *const sshkey) -> *const libc::c_char {
    match (*(*k).cert).type_0 {
        1 => return b"user\0" as *const u8 as *const libc::c_char,
        2 => return b"host\0" as *const u8 as *const libc::c_char,
        _ => return b"unknown\0" as *const u8 as *const libc::c_char,
    };
}
pub unsafe extern "C" fn sshkey_check_rsa_length(
    mut k: *const sshkey,
    mut min_size: libc::c_int,
) -> libc::c_int {
    let mut rsa_n: *const BIGNUM = 0 as *const BIGNUM;
    let mut nbits: libc::c_int = 0;
    if k.is_null()
        || ((*k).rsa).is_null()
        || (*k).type_0 != KEY_RSA as libc::c_int && (*k).type_0 != KEY_RSA_CERT as libc::c_int
    {
        return 0 as libc::c_int;
    }
    RSA_get0_key(
        (*k).rsa,
        &mut rsa_n,
        0 as *mut *const BIGNUM,
        0 as *mut *const BIGNUM,
    );
    nbits = BN_num_bits(rsa_n);
    if nbits < 1024 as libc::c_int || min_size > 0 as libc::c_int && nbits < min_size {
        return -(56 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_ecdsa_key_to_nid(mut k: *mut EC_KEY) -> libc::c_int {
    let mut eg: *mut EC_GROUP = 0 as *mut EC_GROUP;
    let mut nids: [libc::c_int; 4] = [
        415 as libc::c_int,
        715 as libc::c_int,
        716 as libc::c_int,
        -(1 as libc::c_int),
    ];
    let mut nid: libc::c_int = 0;
    let mut i: u_int = 0;
    let mut g: *const EC_GROUP = EC_KEY_get0_group(k);
    nid = EC_GROUP_get_curve_name(g);
    if nid > 0 as libc::c_int {
        return nid;
    }
    i = 0 as libc::c_int as u_int;
    while nids[i as usize] != -(1 as libc::c_int) {
        eg = EC_GROUP_new_by_curve_name(nids[i as usize]);
        if eg.is_null() {
            return -(1 as libc::c_int);
        }
        if EC_GROUP_cmp(g, eg, 0 as *mut BN_CTX) == 0 as libc::c_int {
            break;
        }
        EC_GROUP_free(eg);
        i = i.wrapping_add(1);
        i;
    }
    if nids[i as usize] != -(1 as libc::c_int) {
        EC_GROUP_set_asn1_flag(eg, 0x1 as libc::c_int);
        if EC_KEY_set_group(k, eg) != 1 as libc::c_int {
            EC_GROUP_free(eg);
            return -(1 as libc::c_int);
        }
    }
    return nids[i as usize];
}
pub unsafe extern "C" fn sshkey_generate(
    mut type_0: libc::c_int,
    mut bits: u_int,
    mut keyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut k: *mut sshkey = 0 as *mut sshkey;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    if keyp.is_null() || sshkey_type_is_cert(type_0) != 0 {
        return -(10 as libc::c_int);
    }
    *keyp = 0 as *mut sshkey;
    impl_0 = sshkey_impl_from_type(type_0);
    if impl_0.is_null() {
        return -(14 as libc::c_int);
    }
    if ((*(*impl_0).funcs).generate).is_none() {
        return -(59 as libc::c_int);
    }
    k = sshkey_new(KEY_UNSPEC as libc::c_int);
    if k.is_null() {
        return -(2 as libc::c_int);
    }
    (*k).type_0 = type_0;
    ret = ((*(*impl_0).funcs).generate).expect("non-null function pointer")(k, bits as libc::c_int);
    if ret != 0 as libc::c_int {
        sshkey_free(k);
        return ret;
    }
    *keyp = k;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_cert_copy(
    mut from_key: *const sshkey,
    mut to_key: *mut sshkey,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: u_int = 0;
    let mut from: *const sshkey_cert = 0 as *const sshkey_cert;
    let mut to: *mut sshkey_cert = 0 as *mut sshkey_cert;
    let mut r: libc::c_int = -(1 as libc::c_int);
    if to_key.is_null() || {
        from = (*from_key).cert;
        from.is_null()
    } {
        return -(10 as libc::c_int);
    }
    to = cert_new();
    if to.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_putb((*to).certblob, (*from).certblob);
    if !(r != 0 as libc::c_int
        || {
            r = sshbuf_putb((*to).critical, (*from).critical);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_putb((*to).extensions, (*from).extensions);
            r != 0 as libc::c_int
        })
    {
        (*to).serial = (*from).serial;
        (*to).type_0 = (*from).type_0;
        if ((*from).key_id).is_null() {
            (*to).key_id = 0 as *mut libc::c_char;
            current_block = 11812396948646013369;
        } else {
            (*to).key_id = libc::strdup((*from).key_id);
            if ((*to).key_id).is_null() {
                r = -(2 as libc::c_int);
                current_block = 4002001025471763709;
            } else {
                current_block = 11812396948646013369;
            }
        }
        match current_block {
            4002001025471763709 => {}
            _ => {
                (*to).valid_after = (*from).valid_after;
                (*to).valid_before = (*from).valid_before;
                if ((*from).signature_key).is_null() {
                    (*to).signature_key = 0 as *mut sshkey;
                    current_block = 4166486009154926805;
                } else {
                    r = sshkey_from_private((*from).signature_key, &mut (*to).signature_key);
                    if r != 0 as libc::c_int {
                        current_block = 4002001025471763709;
                    } else {
                        current_block = 4166486009154926805;
                    }
                }
                match current_block {
                    4002001025471763709 => {}
                    _ => {
                        if !((*from).signature_type).is_null() && {
                            (*to).signature_type = libc::strdup((*from).signature_type);
                            ((*to).signature_type).is_null()
                        } {
                            r = -(2 as libc::c_int);
                        } else if (*from).nprincipals > 256 as libc::c_int as libc::c_uint {
                            r = -(10 as libc::c_int);
                        } else {
                            if (*from).nprincipals > 0 as libc::c_int as libc::c_uint {
                                (*to).principals = calloc(
                                    (*from).nprincipals as libc::c_ulong,
                                    ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                                )
                                    as *mut *mut libc::c_char;
                                if ((*to).principals).is_null() {
                                    r = -(2 as libc::c_int);
                                    current_block = 4002001025471763709;
                                } else {
                                    i = 0 as libc::c_int as u_int;
                                    loop {
                                        if !(i < (*from).nprincipals) {
                                            current_block = 15125582407903384992;
                                            break;
                                        }
                                        let ref mut fresh26 =
                                            *((*to).principals).offset(i as isize);
                                        *fresh26 =
                                            libc::strdup(*((*from).principals).offset(i as isize));
                                        if (*((*to).principals).offset(i as isize)).is_null() {
                                            (*to).nprincipals = i;
                                            r = -(2 as libc::c_int);
                                            current_block = 4002001025471763709;
                                            break;
                                        } else {
                                            i = i.wrapping_add(1);
                                            i;
                                        }
                                    }
                                }
                            } else {
                                current_block = 15125582407903384992;
                            }
                            match current_block {
                                4002001025471763709 => {}
                                _ => {
                                    (*to).nprincipals = (*from).nprincipals;
                                    cert_free((*to_key).cert);
                                    (*to_key).cert = to;
                                    to = 0 as *mut sshkey_cert;
                                    r = 0 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    cert_free(to);
    return r;
}
pub unsafe extern "C" fn sshkey_copy_public_sk(
    mut from: *const sshkey,
    mut to: *mut sshkey,
) -> libc::c_int {
    (*to).sk_application = libc::strdup((*from).sk_application);
    if ((*to).sk_application).is_null() {
        return -(2 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_from_private(
    mut k: *const sshkey,
    mut pkp: *mut *mut sshkey,
) -> libc::c_int {
    let mut n: *mut sshkey = 0 as *mut sshkey;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    *pkp = 0 as *mut sshkey;
    impl_0 = sshkey_impl_from_key(k);
    if impl_0.is_null() {
        return -(14 as libc::c_int);
    }
    n = sshkey_new((*k).type_0);
    if n.is_null() {
        r = -(2 as libc::c_int);
    } else {
        r = ((*(*impl_0).funcs).copy_public).expect("non-null function pointer")(k, n);
        if !(r != 0 as libc::c_int) {
            if !(sshkey_is_cert(k) != 0 && {
                r = sshkey_cert_copy(k, n);
                r != 0 as libc::c_int
            }) {
                *pkp = n;
                n = 0 as *mut sshkey;
                r = 0 as libc::c_int;
            }
        }
    }
    sshkey_free(n);
    return r;
}
pub unsafe extern "C" fn sshkey_is_shielded(mut k: *mut sshkey) -> libc::c_int {
    return (!k.is_null() && !((*k).shielded_private).is_null()) as libc::c_int;
}
pub unsafe extern "C" fn sshkey_shield_private(mut k: *mut sshkey) -> libc::c_int {
    let mut current_block: u64;
    let mut prvbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut prekey: *mut u_char = 0 as *mut u_char;
    let mut enc: *mut u_char = 0 as *mut u_char;
    let mut keyiv: [u_char; 64] = [0; 64];
    let mut cctx: *mut sshcipher_ctx = 0 as *mut sshcipher_ctx;
    let mut cipher: *const sshcipher = 0 as *const sshcipher;
    let mut i: size_t = 0;
    let mut enclen: size_t = 0 as libc::c_int as size_t;
    let mut kswap: *mut sshkey = 0 as *mut sshkey;
    let mut tmp: sshkey = sshkey {
        type_0: 0,
        flags: 0,
        rsa: 0 as *mut RSA,
        dsa: 0 as *mut DSA,
        ecdsa_nid: 0,
        ecdsa: 0 as *mut EC_KEY,
        ed25519_sk: 0 as *mut u_char,
        ed25519_pk: 0 as *mut u_char,
        xmss_name: 0 as *mut libc::c_char,
        xmss_filename: 0 as *mut libc::c_char,
        xmss_state: 0 as *mut libc::c_void,
        xmss_sk: 0 as *mut u_char,
        xmss_pk: 0 as *mut u_char,
        sk_application: 0 as *mut libc::c_char,
        sk_flags: 0,
        sk_key_handle: 0 as *mut crate::sshbuf::sshbuf,
        sk_reserved: 0 as *mut crate::sshbuf::sshbuf,
        cert: 0 as *mut sshkey_cert,
        shielded_private: 0 as *mut u_char,
        shielded_len: 0,
        shield_prekey: 0 as *mut u_char,
        shield_prekey_len: 0,
    };
    let mut r: libc::c_int = -(1 as libc::c_int);
    cipher = cipher_by_name(b"aes256-ctr\0" as *const u8 as *const libc::c_char);
    if cipher.is_null() {
        r = -(10 as libc::c_int);
    } else if (cipher_keylen(cipher)).wrapping_add(cipher_ivlen(cipher)) as libc::c_ulong
        > ssh_digest_bytes(4 as libc::c_int)
    {
        r = -(1 as libc::c_int);
    } else {
        prekey = libc::malloc(16 as usize) as *mut u_char;
        if prekey.is_null() {
            r = -(2 as libc::c_int);
        } else {
            arc4random_buf(
                prekey as *mut libc::c_void,
                (16 as libc::c_int * 1024 as libc::c_int) as size_t,
            );
            r = ssh_digest_memory(
                4 as libc::c_int,
                prekey as *const libc::c_void,
                (16 as libc::c_int * 1024 as libc::c_int) as size_t,
                keyiv.as_mut_ptr(),
                64 as libc::c_int as size_t,
            );
            if !(r != 0 as libc::c_int) {
                r = cipher_init(
                    &mut cctx,
                    cipher,
                    keyiv.as_mut_ptr(),
                    cipher_keylen(cipher),
                    keyiv.as_mut_ptr().offset(cipher_keylen(cipher) as isize),
                    cipher_ivlen(cipher),
                    1 as libc::c_int,
                );
                if !(r != 0 as libc::c_int) {
                    prvbuf = crate::sshbuf::sshbuf_new();
                    if prvbuf.is_null() {
                        r = -(2 as libc::c_int);
                    } else if !(sshkey_is_shielded(k) != 0 && {
                        r = sshkey_unshield_private(k);
                        r != 0 as libc::c_int
                    }) {
                        r = sshkey_private_serialize_opt(k, prvbuf, SSHKEY_SERIALIZE_SHIELD);
                        if !(r != 0 as libc::c_int) {
                            i = 0 as libc::c_int as size_t;
                            loop {
                                if !((crate::sshbuf::sshbuf_len(prvbuf))
                                    .wrapping_rem(cipher_blocksize(cipher) as libc::c_ulong)
                                    != 0)
                                {
                                    current_block = 5948590327928692120;
                                    break;
                                }
                                i = i.wrapping_add(1);
                                r = crate::sshbuf_getput_basic::sshbuf_put_u8(
                                    prvbuf,
                                    (i & 0xff as libc::c_int as libc::c_ulong) as u_char,
                                );
                                if r != 0 as libc::c_int {
                                    current_block = 8858214262807371918;
                                    break;
                                }
                            }
                            match current_block {
                                8858214262807371918 => {}
                                _ => {
                                    enclen = crate::sshbuf::sshbuf_len(prvbuf);
                                    enc = libc::malloc(enclen as usize) as *mut u_char;
                                    if enc.is_null() {
                                        r = -(2 as libc::c_int);
                                    } else {
                                        r = cipher_crypt(
                                            cctx,
                                            0 as libc::c_int as u_int,
                                            enc,
                                            sshbuf_ptr(prvbuf),
                                            crate::sshbuf::sshbuf_len(prvbuf) as u_int,
                                            0 as libc::c_int as u_int,
                                            0 as libc::c_int as u_int,
                                        );
                                        if !(r != 0 as libc::c_int) {
                                            r = sshkey_from_private(k, &mut kswap);
                                            if !(r != 0 as libc::c_int) {
                                                tmp = *kswap;
                                                *kswap = *k;
                                                *k = tmp;
                                                (*k).shielded_private = enc;
                                                (*k).shielded_len = enclen;
                                                (*k).shield_prekey = prekey;
                                                (*k).shield_prekey_len = (16 as libc::c_int
                                                    * 1024 as libc::c_int)
                                                    as size_t;
                                                prekey = 0 as *mut u_char;
                                                enc = prekey;
                                                enclen = 0 as libc::c_int as size_t;
                                                (*k).sk_flags = (*kswap).sk_flags;
                                                r = 0 as libc::c_int;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    cipher_free(cctx);
    explicit_bzero(
        keyiv.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    explicit_bzero(
        &mut tmp as *mut sshkey as *mut libc::c_void,
        ::core::mem::size_of::<sshkey>() as libc::c_ulong,
    );
    freezero(enc as *mut libc::c_void, enclen);
    freezero(
        prekey as *mut libc::c_void,
        (16 as libc::c_int * 1024 as libc::c_int) as size_t,
    );
    sshkey_free(kswap);
    crate::sshbuf::sshbuf_free(prvbuf);
    return r;
}
unsafe extern "C" fn private2_check_padding(
    mut decrypted: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut pad: u_char = 0;
    let mut i: size_t = 0;
    let mut r: libc::c_int = 0;
    i = 0 as libc::c_int as size_t;
    loop {
        if !(crate::sshbuf::sshbuf_len(decrypted) != 0) {
            current_block = 15619007995458559411;
            break;
        }
        r = sshbuf_get_u8(decrypted, &mut pad);
        if r != 0 as libc::c_int {
            current_block = 12374224028070376414;
            break;
        }
        i = i.wrapping_add(1);
        if !(pad as libc::c_ulong != i & 0xff as libc::c_int as libc::c_ulong) {
            continue;
        }
        r = -(4 as libc::c_int);
        current_block = 12374224028070376414;
        break;
    }
    match current_block {
        15619007995458559411 => {
            r = 0 as libc::c_int;
        }
        _ => {}
    }
    explicit_bzero(
        &mut pad as *mut u_char as *mut libc::c_void,
        ::core::mem::size_of::<u_char>() as libc::c_ulong,
    );
    explicit_bzero(
        &mut i as *mut size_t as *mut libc::c_void,
        ::core::mem::size_of::<size_t>() as libc::c_ulong,
    );
    return r;
}
pub unsafe extern "C" fn sshkey_unshield_private(mut k: *mut sshkey) -> libc::c_int {
    let mut prvbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut cp: *mut u_char = 0 as *mut u_char;
    let mut keyiv: [u_char; 64] = [0; 64];
    let mut cctx: *mut sshcipher_ctx = 0 as *mut sshcipher_ctx;
    let mut cipher: *const sshcipher = 0 as *const sshcipher;
    let mut kswap: *mut sshkey = 0 as *mut sshkey;
    let mut tmp: sshkey = sshkey {
        type_0: 0,
        flags: 0,
        rsa: 0 as *mut RSA,
        dsa: 0 as *mut DSA,
        ecdsa_nid: 0,
        ecdsa: 0 as *mut EC_KEY,
        ed25519_sk: 0 as *mut u_char,
        ed25519_pk: 0 as *mut u_char,
        xmss_name: 0 as *mut libc::c_char,
        xmss_filename: 0 as *mut libc::c_char,
        xmss_state: 0 as *mut libc::c_void,
        xmss_sk: 0 as *mut u_char,
        xmss_pk: 0 as *mut u_char,
        sk_application: 0 as *mut libc::c_char,
        sk_flags: 0,
        sk_key_handle: 0 as *mut crate::sshbuf::sshbuf,
        sk_reserved: 0 as *mut crate::sshbuf::sshbuf,
        cert: 0 as *mut sshkey_cert,
        shielded_private: 0 as *mut u_char,
        shielded_len: 0,
        shield_prekey: 0 as *mut u_char,
        shield_prekey_len: 0,
    };
    let mut r: libc::c_int = -(1 as libc::c_int);
    if sshkey_is_shielded(k) == 0 {
        return 0 as libc::c_int;
    }
    cipher = cipher_by_name(b"aes256-ctr\0" as *const u8 as *const libc::c_char);
    if cipher.is_null() {
        r = -(10 as libc::c_int);
    } else if (cipher_keylen(cipher)).wrapping_add(cipher_ivlen(cipher)) as libc::c_ulong
        > ssh_digest_bytes(4 as libc::c_int)
    {
        r = -(1 as libc::c_int);
    } else if (*k).shielded_len < cipher_blocksize(cipher) as libc::c_ulong
        || ((*k).shielded_len).wrapping_rem(cipher_blocksize(cipher) as libc::c_ulong)
            != 0 as libc::c_int as libc::c_ulong
    {
        r = -(4 as libc::c_int);
    } else {
        r = ssh_digest_memory(
            4 as libc::c_int,
            (*k).shield_prekey as *const libc::c_void,
            (*k).shield_prekey_len,
            keyiv.as_mut_ptr(),
            64 as libc::c_int as size_t,
        );
        if !(r != 0 as libc::c_int) {
            r = cipher_init(
                &mut cctx,
                cipher,
                keyiv.as_mut_ptr(),
                cipher_keylen(cipher),
                keyiv.as_mut_ptr().offset(cipher_keylen(cipher) as isize),
                cipher_ivlen(cipher),
                0 as libc::c_int,
            );
            if !(r != 0 as libc::c_int) {
                prvbuf = crate::sshbuf::sshbuf_new();
                if prvbuf.is_null() {
                    r = -(2 as libc::c_int);
                } else {
                    r = sshbuf_reserve(prvbuf, (*k).shielded_len, &mut cp);
                    if !(r != 0 as libc::c_int) {
                        r = cipher_crypt(
                            cctx,
                            0 as libc::c_int as u_int,
                            cp,
                            (*k).shielded_private,
                            (*k).shielded_len as u_int,
                            0 as libc::c_int as u_int,
                            0 as libc::c_int as u_int,
                        );
                        if !(r != 0 as libc::c_int) {
                            r = sshkey_private_deserialize(prvbuf, &mut kswap);
                            if !(r != 0 as libc::c_int) {
                                r = private2_check_padding(prvbuf);
                                if !(r != 0 as libc::c_int) {
                                    tmp = *kswap;
                                    *kswap = *k;
                                    *k = tmp;
                                    r = 0 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    cipher_free(cctx);
    explicit_bzero(
        keyiv.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    explicit_bzero(
        &mut tmp as *mut sshkey as *mut libc::c_void,
        ::core::mem::size_of::<sshkey>() as libc::c_ulong,
    );
    sshkey_free(kswap);
    crate::sshbuf::sshbuf_free(prvbuf);
    return r;
}
unsafe extern "C" fn cert_parse(
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut sshkey,
    mut certbuf: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut principals: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut crit: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut exts: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut ca: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut signed_len: size_t = 0 as libc::c_int as size_t;
    let mut slen: size_t = 0 as libc::c_int as size_t;
    let mut kidlen: size_t = 0 as libc::c_int as size_t;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    ret = sshbuf_putb((*(*key).cert).certblob, certbuf);
    if ret != 0 as libc::c_int {
        return ret;
    }
    ret = sshbuf_get_u64(b, &mut (*(*key).cert).serial);
    if ret != 0 as libc::c_int
        || {
            ret = sshbuf_get_u32(b, &mut (*(*key).cert).type_0);
            ret != 0 as libc::c_int
        }
        || {
            ret = sshbuf_get_cstring(b, &mut (*(*key).cert).key_id, &mut kidlen);
            ret != 0 as libc::c_int
        }
        || {
            ret = sshbuf_froms(b, &mut principals);
            ret != 0 as libc::c_int
        }
        || {
            ret = sshbuf_get_u64(b, &mut (*(*key).cert).valid_after);
            ret != 0 as libc::c_int
        }
        || {
            ret = sshbuf_get_u64(b, &mut (*(*key).cert).valid_before);
            ret != 0 as libc::c_int
        }
        || {
            ret = sshbuf_froms(b, &mut crit);
            ret != 0 as libc::c_int
        }
        || {
            ret = sshbuf_froms(b, &mut exts);
            ret != 0 as libc::c_int
        }
        || {
            ret = sshbuf_get_string_direct(b, 0 as *mut *const u_char, 0 as *mut size_t);
            ret != 0 as libc::c_int
        }
        || {
            ret = sshbuf_froms(b, &mut ca);
            ret != 0 as libc::c_int
        }
    {
        ret = -(4 as libc::c_int);
    } else {
        signed_len = (crate::sshbuf::sshbuf_len((*(*key).cert).certblob))
            .wrapping_sub(crate::sshbuf::sshbuf_len(b));
        ret = sshbuf_get_string(b, &mut sig, &mut slen);
        if ret != 0 as libc::c_int {
            ret = -(4 as libc::c_int);
        } else if (*(*key).cert).type_0 != 1 as libc::c_int as libc::c_uint
            && (*(*key).cert).type_0 != 2 as libc::c_int as libc::c_uint
        {
            ret = -(18 as libc::c_int);
        } else {
            loop {
                if !(crate::sshbuf::sshbuf_len(principals) > 0 as libc::c_int as libc::c_ulong) {
                    current_block = 5601891728916014340;
                    break;
                }
                let mut principal: *mut libc::c_char = 0 as *mut libc::c_char;
                let mut oprincipals: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
                if (*(*key).cert).nprincipals >= 256 as libc::c_int as libc::c_uint {
                    ret = -(4 as libc::c_int);
                    current_block = 15747115717569190648;
                    break;
                } else {
                    ret = sshbuf_get_cstring(principals, &mut principal, 0 as *mut size_t);
                    if ret != 0 as libc::c_int {
                        ret = -(4 as libc::c_int);
                        current_block = 15747115717569190648;
                        break;
                    } else {
                        oprincipals = (*(*key).cert).principals;
                        (*(*key).cert).principals = recallocarray(
                            (*(*key).cert).principals as *mut libc::c_void,
                            (*(*key).cert).nprincipals as size_t,
                            ((*(*key).cert).nprincipals)
                                .wrapping_add(1 as libc::c_int as libc::c_uint)
                                as size_t,
                            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                        )
                            as *mut *mut libc::c_char;
                        if ((*(*key).cert).principals).is_null() {
                            libc::free(principal as *mut libc::c_void);
                            (*(*key).cert).principals = oprincipals;
                            ret = -(2 as libc::c_int);
                            current_block = 15747115717569190648;
                            break;
                        } else {
                            let fresh27 = (*(*key).cert).nprincipals;
                            (*(*key).cert).nprincipals =
                                ((*(*key).cert).nprincipals).wrapping_add(1);
                            let ref mut fresh28 =
                                *((*(*key).cert).principals).offset(fresh27 as isize);
                            *fresh28 = principal;
                        }
                    }
                }
            }
            match current_block {
                15747115717569190648 => {}
                _ => {
                    ret = sshbuf_putb((*(*key).cert).critical, crit);
                    if !(ret != 0 as libc::c_int
                        || !exts.is_null() && {
                            ret = sshbuf_putb((*(*key).cert).extensions, exts);
                            ret != 0 as libc::c_int
                        })
                    {
                        loop {
                            if !(crate::sshbuf::sshbuf_len(crit)
                                != 0 as libc::c_int as libc::c_ulong)
                            {
                                current_block = 7056779235015430508;
                                break;
                            }
                            ret = sshbuf_get_string_direct(
                                crit,
                                0 as *mut *const u_char,
                                0 as *mut size_t,
                            );
                            if !(ret != 0 as libc::c_int || {
                                ret = sshbuf_get_string_direct(
                                    crit,
                                    0 as *mut *const u_char,
                                    0 as *mut size_t,
                                );
                                ret != 0 as libc::c_int
                            }) {
                                continue;
                            }
                            sshbuf_reset((*(*key).cert).critical);
                            ret = -(4 as libc::c_int);
                            current_block = 15747115717569190648;
                            break;
                        }
                        match current_block {
                            15747115717569190648 => {}
                            _ => {
                                loop {
                                    if !(!exts.is_null()
                                        && crate::sshbuf::sshbuf_len(exts)
                                            != 0 as libc::c_int as libc::c_ulong)
                                    {
                                        current_block = 8693738493027456495;
                                        break;
                                    }
                                    ret = sshbuf_get_string_direct(
                                        exts,
                                        0 as *mut *const u_char,
                                        0 as *mut size_t,
                                    );
                                    if !(ret != 0 as libc::c_int || {
                                        ret = sshbuf_get_string_direct(
                                            exts,
                                            0 as *mut *const u_char,
                                            0 as *mut size_t,
                                        );
                                        ret != 0 as libc::c_int
                                    }) {
                                        continue;
                                    }
                                    sshbuf_reset((*(*key).cert).extensions);
                                    ret = -(4 as libc::c_int);
                                    current_block = 15747115717569190648;
                                    break;
                                }
                                match current_block {
                                    15747115717569190648 => {}
                                    _ => {
                                        if sshkey_from_blob_internal(
                                            ca,
                                            &mut (*(*key).cert).signature_key,
                                            0 as libc::c_int,
                                        ) != 0 as libc::c_int
                                        {
                                            ret = -(19 as libc::c_int);
                                        } else if sshkey_type_is_valid_ca(
                                            (*(*(*key).cert).signature_key).type_0,
                                        ) == 0
                                        {
                                            ret = -(19 as libc::c_int);
                                        } else {
                                            ret = sshkey_verify(
                                                (*(*key).cert).signature_key,
                                                sig,
                                                slen,
                                                sshbuf_ptr((*(*key).cert).certblob),
                                                signed_len,
                                                0 as *const libc::c_char,
                                                0 as libc::c_int as u_int,
                                                0 as *mut *mut sshkey_sig_details,
                                            );
                                            if !(ret != 0 as libc::c_int) {
                                                ret = sshkey_get_sigtype(
                                                    sig,
                                                    slen,
                                                    &mut (*(*key).cert).signature_type,
                                                );
                                                if !(ret != 0 as libc::c_int) {
                                                    ret = 0 as libc::c_int;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    crate::sshbuf::sshbuf_free(ca);
    crate::sshbuf::sshbuf_free(crit);
    crate::sshbuf::sshbuf_free(exts);
    crate::sshbuf::sshbuf_free(principals);
    libc::free(sig as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn sshkey_deserialize_sk(
    mut b: *mut crate::sshbuf::sshbuf,
    mut key: *mut sshkey,
) -> libc::c_int {
    if sshbuf_get_cstring(b, &mut (*key).sk_application, 0 as *mut size_t) != 0 as libc::c_int {
        return -(4 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn sshkey_from_blob_internal(
    mut b: *mut crate::sshbuf::sshbuf,
    mut keyp: *mut *mut sshkey,
    mut allow_cert: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut type_0: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut ktype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut copy: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    if !keyp.is_null() {
        *keyp = 0 as *mut sshkey;
    }
    copy = sshbuf_fromb(b);
    if copy.is_null() {
        ret = -(2 as libc::c_int);
    } else if sshbuf_get_cstring(b, &mut ktype, 0 as *mut size_t) != 0 as libc::c_int {
        ret = -(4 as libc::c_int);
    } else {
        type_0 = sshkey_type_from_name(ktype);
        if allow_cert == 0 && sshkey_type_is_cert(type_0) != 0 {
            ret = -(19 as libc::c_int);
        } else {
            impl_0 = sshkey_impl_from_type(type_0);
            if impl_0.is_null() {
                ret = -(14 as libc::c_int);
            } else {
                key = sshkey_new(type_0);
                if key.is_null() {
                    ret = -(2 as libc::c_int);
                } else {
                    if sshkey_type_is_cert(type_0) != 0 {
                        if sshbuf_get_string_direct(b, 0 as *mut *const u_char, 0 as *mut size_t)
                            != 0 as libc::c_int
                        {
                            ret = -(4 as libc::c_int);
                            current_block = 4903584012820182898;
                        } else {
                            current_block = 15652330335145281839;
                        }
                    } else {
                        current_block = 15652330335145281839;
                    }
                    match current_block {
                        4903584012820182898 => {}
                        _ => {
                            ret = ((*(*impl_0).funcs).deserialize_public)
                                .expect("non-null function pointer")(
                                ktype, b, key
                            );
                            if !(ret != 0 as libc::c_int) {
                                if !(sshkey_is_cert(key) != 0 && {
                                    ret = cert_parse(b, key, copy);
                                    ret != 0 as libc::c_int
                                }) {
                                    if !key.is_null()
                                        && crate::sshbuf::sshbuf_len(b)
                                            != 0 as libc::c_int as libc::c_ulong
                                    {
                                        ret = -(4 as libc::c_int);
                                    } else {
                                        ret = 0 as libc::c_int;
                                        if !keyp.is_null() {
                                            *keyp = key;
                                            key = 0 as *mut sshkey;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    crate::sshbuf::sshbuf_free(copy);
    sshkey_free(key);
    libc::free(ktype as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn sshkey_from_blob(
    mut blob: *const u_char,
    mut blen: size_t,
    mut keyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    b = sshbuf_from(blob as *const libc::c_void, blen);
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshkey_from_blob_internal(b, keyp, 1 as libc::c_int);
    crate::sshbuf::sshbuf_free(b);
    return r;
}
pub unsafe extern "C" fn sshkey_fromb(
    mut b: *mut crate::sshbuf::sshbuf,
    mut keyp: *mut *mut sshkey,
) -> libc::c_int {
    return sshkey_from_blob_internal(b, keyp, 1 as libc::c_int);
}
pub unsafe extern "C" fn sshkey_froms(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut keyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    r = sshbuf_froms(buf, &mut b);
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshkey_from_blob_internal(b, keyp, 1 as libc::c_int);
    crate::sshbuf::sshbuf_free(b);
    return r;
}
pub unsafe extern "C" fn sshkey_get_sigtype(
    mut sig: *const u_char,
    mut siglen: size_t,
    mut sigtypep: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sigtype: *mut libc::c_char = 0 as *mut libc::c_char;
    if !sigtypep.is_null() {
        *sigtypep = 0 as *mut libc::c_char;
    }
    b = sshbuf_from(sig as *const libc::c_void, siglen);
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_get_cstring(b, &mut sigtype, 0 as *mut size_t);
    if !(r != 0 as libc::c_int) {
        if !sigtypep.is_null() {
            *sigtypep = sigtype;
            sigtype = 0 as *mut libc::c_char;
        }
        r = 0 as libc::c_int;
    }
    libc::free(sigtype as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(b);
    return r;
}
pub unsafe extern "C" fn sshkey_check_cert_sigtype(
    mut key: *const sshkey,
    mut allowed: *const libc::c_char,
) -> libc::c_int {
    if key.is_null() || allowed.is_null() {
        return -(10 as libc::c_int);
    }
    if sshkey_type_is_cert((*key).type_0) == 0 {
        return 0 as libc::c_int;
    }
    if ((*key).cert).is_null() || ((*(*key).cert).signature_type).is_null() {
        return -(10 as libc::c_int);
    }
    if match_pattern_list((*(*key).cert).signature_type, allowed, 0 as libc::c_int)
        != 1 as libc::c_int
    {
        return -(58 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_sigalg_by_name(
    mut name: *const libc::c_char,
) -> *const libc::c_char {
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while !(keyimpls[i as usize]).is_null() {
        impl_0 = keyimpls[i as usize];
        if libc::strcmp((*impl_0).name, name) != 0 as libc::c_int {
            i += 1;
            i;
        } else {
            if !((*impl_0).sigalg).is_null() {
                return (*impl_0).sigalg;
            }
            if (*impl_0).cert == 0 {
                return (*impl_0).name;
            }
            return sshkey_ssh_name_from_type_nid(
                sshkey_type_plain((*impl_0).type_0),
                (*impl_0).nid,
            );
        }
    }
    return 0 as *const libc::c_char;
}
pub unsafe extern "C" fn sshkey_check_sigtype(
    mut sig: *const u_char,
    mut siglen: size_t,
    mut requested_alg: *const libc::c_char,
) -> libc::c_int {
    let mut expected_alg: *const libc::c_char = 0 as *const libc::c_char;
    let mut sigtype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    if requested_alg.is_null() {
        return 0 as libc::c_int;
    }
    expected_alg = sshkey_sigalg_by_name(requested_alg);
    if expected_alg.is_null() {
        return -(10 as libc::c_int);
    }
    r = sshkey_get_sigtype(sig, siglen, &mut sigtype);
    if r != 0 as libc::c_int {
        return r;
    }
    r = (libc::strcmp(expected_alg, sigtype) == 0 as libc::c_int) as libc::c_int;
    libc::free(sigtype as *mut libc::c_void);
    return if r != 0 {
        0 as libc::c_int
    } else {
        -(58 as libc::c_int)
    };
}
pub unsafe extern "C" fn sshkey_sign(
    mut key: *mut sshkey,
    mut sigp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut data: *const u_char,
    mut datalen: size_t,
    mut alg: *const libc::c_char,
    mut sk_provider: *const libc::c_char,
    mut sk_pin: *const libc::c_char,
    mut compat: u_int,
) -> libc::c_int {
    let mut was_shielded: libc::c_int = sshkey_is_shielded(key);
    let mut r2: libc::c_int = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    if !sigp.is_null() {
        *sigp = 0 as *mut u_char;
    }
    if !lenp.is_null() {
        *lenp = 0 as libc::c_int as size_t;
    }
    if datalen > ((1 as libc::c_int) << 20 as libc::c_int) as libc::c_ulong {
        return -(10 as libc::c_int);
    }
    impl_0 = sshkey_impl_from_key(key);
    if impl_0.is_null() {
        return -(14 as libc::c_int);
    }
    r = sshkey_unshield_private(key);
    if r != 0 as libc::c_int {
        return r;
    }
    if sshkey_is_sk(key) != 0 {
        r = sshsk_sign(sk_provider, key, sigp, lenp, data, datalen, compat, sk_pin);
    } else if ((*(*impl_0).funcs).sign).is_none() {
        r = -(58 as libc::c_int);
    } else {
        r = ((*(*impl_0).funcs).sign).expect("non-null function pointer")(
            key,
            sigp,
            lenp,
            data,
            datalen,
            alg,
            sk_provider,
            sk_pin,
            compat,
        );
    }
    if was_shielded != 0 && {
        r2 = sshkey_shield_private(key);
        r2 != 0 as libc::c_int
    } {
        return r2;
    }
    return r;
}
pub unsafe extern "C" fn sshkey_verify(
    mut key: *const sshkey,
    mut sig: *const u_char,
    mut siglen: size_t,
    mut data: *const u_char,
    mut dlen: size_t,
    mut alg: *const libc::c_char,
    mut compat: u_int,
    mut detailsp: *mut *mut sshkey_sig_details,
) -> libc::c_int {
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    if !detailsp.is_null() {
        *detailsp = 0 as *mut sshkey_sig_details;
    }
    if siglen == 0 as libc::c_int as libc::c_ulong
        || dlen > ((1 as libc::c_int) << 20 as libc::c_int) as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    impl_0 = sshkey_impl_from_key(key);
    if impl_0.is_null() {
        return -(14 as libc::c_int);
    }
    return ((*(*impl_0).funcs).verify).expect("non-null function pointer")(
        key, sig, siglen, data, dlen, alg, compat, detailsp,
    );
}
pub unsafe extern "C" fn sshkey_to_certified(mut k: *mut sshkey) -> libc::c_int {
    let mut newtype: libc::c_int = 0;
    newtype = sshkey_type_certified((*k).type_0);
    if newtype == -(1 as libc::c_int) {
        return -(10 as libc::c_int);
    }
    (*k).cert = cert_new();
    if ((*k).cert).is_null() {
        return -(2 as libc::c_int);
    }
    (*k).type_0 = newtype;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_drop_cert(mut k: *mut sshkey) -> libc::c_int {
    if sshkey_type_is_cert((*k).type_0) == 0 {
        return -(14 as libc::c_int);
    }
    cert_free((*k).cert);
    (*k).cert = 0 as *mut sshkey_cert;
    (*k).type_0 = sshkey_type_plain((*k).type_0);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_certify_custom(
    mut k: *mut sshkey,
    mut ca: *mut sshkey,
    mut alg: *const libc::c_char,
    mut sk_provider: *const libc::c_char,
    mut sk_pin: *const libc::c_char,
    mut signer: Option<sshkey_certify_signer>,
    mut signer_ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut current_block: u64;
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    let mut principals: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut ca_blob: *mut u_char = 0 as *mut u_char;
    let mut sig_blob: *mut u_char = 0 as *mut u_char;
    let mut nonce: [u_char; 32] = [0; 32];
    let mut i: size_t = 0;
    let mut ca_len: size_t = 0;
    let mut sig_len: size_t = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut cert: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sigtype: *mut libc::c_char = 0 as *mut libc::c_char;
    if k.is_null() || ((*k).cert).is_null() || ((*(*k).cert).certblob).is_null() || ca.is_null() {
        return -(10 as libc::c_int);
    }
    if sshkey_is_cert(k) == 0 {
        return -(14 as libc::c_int);
    }
    if sshkey_type_is_valid_ca((*ca).type_0) == 0 {
        return -(19 as libc::c_int);
    }
    impl_0 = sshkey_impl_from_key(k);
    if impl_0.is_null() {
        return -(1 as libc::c_int);
    }
    if alg.is_null() {
        alg = (*(*k).cert).signature_type;
    } else if !((*(*k).cert).signature_type).is_null()
        && libc::strcmp(alg, (*(*k).cert).signature_type) != 0 as libc::c_int
    {
        return -(10 as libc::c_int);
    }
    if alg.is_null() && (*ca).type_0 == KEY_RSA as libc::c_int {
        alg = b"rsa-sha2-512\0" as *const u8 as *const libc::c_char;
    }
    ret = sshkey_to_blob(ca, &mut ca_blob, &mut ca_len);
    if ret != 0 as libc::c_int {
        return -(19 as libc::c_int);
    }
    cert = (*(*k).cert).certblob;
    sshbuf_reset(cert);
    ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k));
    if !(ret != 0 as libc::c_int) {
        arc4random_buf(
            &mut nonce as *mut [u_char; 32] as *mut libc::c_void,
            ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
        );
        ret = sshbuf_put_string(
            cert,
            nonce.as_mut_ptr() as *const libc::c_void,
            ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
        );
        if !(ret != 0 as libc::c_int) {
            ret = ((*(*impl_0).funcs).serialize_public).expect("non-null function pointer")(
                k,
                cert,
                SSHKEY_SERIALIZE_DEFAULT,
            );
            if !(ret != 0 as libc::c_int) {
                ret = sshbuf_put_u64(cert, (*(*k).cert).serial);
                if !(ret != 0 as libc::c_int
                    || {
                        ret = sshbuf_put_u32(cert, (*(*k).cert).type_0);
                        ret != 0 as libc::c_int
                    }
                    || {
                        ret = sshbuf_put_cstring(cert, (*(*k).cert).key_id);
                        ret != 0 as libc::c_int
                    })
                {
                    principals = crate::sshbuf::sshbuf_new();
                    if principals.is_null() {
                        ret = -(2 as libc::c_int);
                    } else {
                        i = 0 as libc::c_int as size_t;
                        loop {
                            if !(i < (*(*k).cert).nprincipals as libc::c_ulong) {
                                current_block = 18386322304582297246;
                                break;
                            }
                            ret = sshbuf_put_cstring(
                                principals,
                                *((*(*k).cert).principals).offset(i as isize),
                            );
                            if ret != 0 as libc::c_int {
                                current_block = 10874097833224312588;
                                break;
                            }
                            i = i.wrapping_add(1);
                            i;
                        }
                        match current_block {
                            10874097833224312588 => {}
                            _ => {
                                ret = sshbuf_put_stringb(cert, principals);
                                if !(ret != 0 as libc::c_int
                                    || {
                                        ret = sshbuf_put_u64(cert, (*(*k).cert).valid_after);
                                        ret != 0 as libc::c_int
                                    }
                                    || {
                                        ret = sshbuf_put_u64(cert, (*(*k).cert).valid_before);
                                        ret != 0 as libc::c_int
                                    }
                                    || {
                                        ret = sshbuf_put_stringb(cert, (*(*k).cert).critical);
                                        ret != 0 as libc::c_int
                                    }
                                    || {
                                        ret = sshbuf_put_stringb(cert, (*(*k).cert).extensions);
                                        ret != 0 as libc::c_int
                                    }
                                    || {
                                        ret = sshbuf_put_string(
                                            cert,
                                            0 as *const libc::c_void,
                                            0 as libc::c_int as size_t,
                                        );
                                        ret != 0 as libc::c_int
                                    }
                                    || {
                                        ret = sshbuf_put_string(
                                            cert,
                                            ca_blob as *const libc::c_void,
                                            ca_len,
                                        );
                                        ret != 0 as libc::c_int
                                    })
                                {
                                    ret = signer.expect("non-null function pointer")(
                                        ca,
                                        &mut sig_blob,
                                        &mut sig_len,
                                        sshbuf_ptr(cert),
                                        crate::sshbuf::sshbuf_len(cert),
                                        alg,
                                        sk_provider,
                                        sk_pin,
                                        0 as libc::c_int as u_int,
                                        signer_ctx,
                                    );
                                    if !(ret != 0 as libc::c_int) {
                                        ret = sshkey_get_sigtype(sig_blob, sig_len, &mut sigtype);
                                        if !(ret != 0 as libc::c_int) {
                                            if !alg.is_null()
                                                && libc::strcmp(alg, sigtype) != 0 as libc::c_int
                                            {
                                                ret = -(58 as libc::c_int);
                                            } else {
                                                if ((*(*k).cert).signature_type).is_null() {
                                                    (*(*k).cert).signature_type = sigtype;
                                                    sigtype = 0 as *mut libc::c_char;
                                                }
                                                ret = sshbuf_put_string(
                                                    cert,
                                                    sig_blob as *const libc::c_void,
                                                    sig_len,
                                                );
                                                if !(ret != 0 as libc::c_int) {
                                                    ret = 0 as libc::c_int;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if ret != 0 as libc::c_int {
        sshbuf_reset(cert);
    }
    libc::free(sig_blob as *mut libc::c_void);
    libc::free(ca_blob as *mut libc::c_void);
    libc::free(sigtype as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(principals);
    return ret;
}
unsafe extern "C" fn default_key_sign(
    mut key: *mut sshkey,
    mut sigp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut data: *const u_char,
    mut datalen: size_t,
    mut alg: *const libc::c_char,
    mut sk_provider: *const libc::c_char,
    mut sk_pin: *const libc::c_char,
    mut compat: u_int,
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    if !ctx.is_null() {
        return -(10 as libc::c_int);
    }
    return sshkey_sign(
        key,
        sigp,
        lenp,
        data,
        datalen,
        alg,
        sk_provider,
        sk_pin,
        compat,
    );
}
pub unsafe extern "C" fn sshkey_certify(
    mut k: *mut sshkey,
    mut ca: *mut sshkey,
    mut alg: *const libc::c_char,
    mut sk_provider: *const libc::c_char,
    mut sk_pin: *const libc::c_char,
) -> libc::c_int {
    return sshkey_certify_custom(
        k,
        ca,
        alg,
        sk_provider,
        sk_pin,
        Some(
            default_key_sign
                as unsafe extern "C" fn(
                    *mut sshkey,
                    *mut *mut u_char,
                    *mut size_t,
                    *const u_char,
                    size_t,
                    *const libc::c_char,
                    *const libc::c_char,
                    *const libc::c_char,
                    u_int,
                    *mut libc::c_void,
                ) -> libc::c_int,
        ),
        0 as *mut libc::c_void,
    );
}
pub unsafe extern "C" fn sshkey_cert_check_authority(
    mut k: *const sshkey,
    mut want_host: libc::c_int,
    mut require_principal: libc::c_int,
    mut wildcard_pattern: libc::c_int,
    mut verify_time: uint64_t,
    mut name: *const libc::c_char,
    mut reason: *mut *const libc::c_char,
) -> libc::c_int {
    let mut i: u_int = 0;
    let mut principal_matches: u_int = 0;
    if reason.is_null() {
        return -(10 as libc::c_int);
    }
    if sshkey_is_cert(k) == 0 {
        *reason = b"Key is not a certificate\0" as *const u8 as *const libc::c_char;
        return -(25 as libc::c_int);
    }
    if want_host != 0 {
        if (*(*k).cert).type_0 != 2 as libc::c_int as libc::c_uint {
            *reason = b"Certificate invalid: not a host certificate\0" as *const u8
                as *const libc::c_char;
            return -(25 as libc::c_int);
        }
    } else if (*(*k).cert).type_0 != 1 as libc::c_int as libc::c_uint {
        *reason =
            b"Certificate invalid: not a user certificate\0" as *const u8 as *const libc::c_char;
        return -(25 as libc::c_int);
    }
    if verify_time < (*(*k).cert).valid_after {
        *reason = b"Certificate invalid: not yet valid\0" as *const u8 as *const libc::c_char;
        return -(25 as libc::c_int);
    }
    if verify_time >= (*(*k).cert).valid_before {
        *reason = b"Certificate invalid: expired\0" as *const u8 as *const libc::c_char;
        return -(25 as libc::c_int);
    }
    if (*(*k).cert).nprincipals == 0 as libc::c_int as libc::c_uint {
        if require_principal != 0 {
            *reason = b"Certificate lacks principal list\0" as *const u8 as *const libc::c_char;
            return -(25 as libc::c_int);
        }
    } else if !name.is_null() {
        principal_matches = 0 as libc::c_int as u_int;
        i = 0 as libc::c_int as u_int;
        while i < (*(*k).cert).nprincipals {
            if wildcard_pattern != 0 {
                if match_pattern(*((*(*k).cert).principals).offset(i as isize), name) != 0 {
                    principal_matches = 1 as libc::c_int as u_int;
                    break;
                }
            } else if libc::strcmp(name, *((*(*k).cert).principals).offset(i as isize))
                == 0 as libc::c_int
            {
                principal_matches = 1 as libc::c_int as u_int;
                break;
            }
            i = i.wrapping_add(1);
            i;
        }
        if principal_matches == 0 {
            *reason = b"Certificate invalid: name is not a listed principal\0" as *const u8
                as *const libc::c_char;
            return -(25 as libc::c_int);
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_cert_check_authority_now(
    mut k: *const sshkey,
    mut want_host: libc::c_int,
    mut require_principal: libc::c_int,
    mut wildcard_pattern: libc::c_int,
    mut name: *const libc::c_char,
    mut reason: *mut *const libc::c_char,
) -> libc::c_int {
    let mut now: time_t = 0;
    now = time(0 as *mut time_t);
    if now < 0 as libc::c_int as libc::c_long {
        *reason = b"Certificate invalid: not yet valid\0" as *const u8 as *const libc::c_char;
        return -(25 as libc::c_int);
    }
    return sshkey_cert_check_authority(
        k,
        want_host,
        require_principal,
        wildcard_pattern,
        now as uint64_t,
        name,
        reason,
    );
}
pub unsafe extern "C" fn sshkey_cert_check_host(
    mut key: *const sshkey,
    mut host: *const libc::c_char,
    mut wildcard_principals: libc::c_int,
    mut ca_sign_algorithms: *const libc::c_char,
    mut reason: *mut *const libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = sshkey_cert_check_authority_now(
        key,
        1 as libc::c_int,
        0 as libc::c_int,
        wildcard_principals,
        host,
        reason,
    );
    if r != 0 as libc::c_int {
        return r;
    }
    if crate::sshbuf::sshbuf_len((*(*key).cert).critical) != 0 as libc::c_int as libc::c_ulong {
        *reason = b"Certificate contains unsupported critical options\0" as *const u8
            as *const libc::c_char;
        return -(25 as libc::c_int);
    }
    if !ca_sign_algorithms.is_null() && {
        r = sshkey_check_cert_sigtype(key, ca_sign_algorithms);
        r != 0 as libc::c_int
    } {
        *reason =
            b"Certificate signed with disallowed algorithm\0" as *const u8 as *const libc::c_char;
        return -(25 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_format_cert_validity(
    mut cert: *const sshkey_cert,
    mut s: *mut libc::c_char,
    mut l: size_t,
) -> size_t {
    let mut from: [libc::c_char; 32] = [0; 32];
    let mut to: [libc::c_char; 32] = [0; 32];
    let mut ret: [libc::c_char; 128] = [0; 128];
    let ref mut fresh29 = *to.as_mut_ptr();
    *fresh29 = '\0' as i32 as libc::c_char;
    *from.as_mut_ptr() = *fresh29;
    if (*cert).valid_after == 0 as libc::c_int as libc::c_ulong
        && (*cert).valid_before as libc::c_ulonglong == 0xffffffffffffffff as libc::c_ulonglong
    {
        return strlcpy(s, b"forever\0" as *const u8 as *const libc::c_char, l);
    }
    if (*cert).valid_after != 0 as libc::c_int as libc::c_ulong {
        format_absolute_time(
            (*cert).valid_after,
            from.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
        );
    }
    if (*cert).valid_before as libc::c_ulonglong != 0xffffffffffffffff as libc::c_ulonglong {
        format_absolute_time(
            (*cert).valid_before,
            to.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
        );
    }
    if (*cert).valid_after == 0 as libc::c_int as libc::c_ulong {
        libc::snprintf(
            ret.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 128]>() as usize,
            b"before %s\0" as *const u8 as *const libc::c_char,
            to.as_mut_ptr(),
        );
    } else if (*cert).valid_before as libc::c_ulonglong == 0xffffffffffffffff as libc::c_ulonglong {
        libc::snprintf(
            ret.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 128]>() as usize,
            b"after %s\0" as *const u8 as *const libc::c_char,
            from.as_mut_ptr(),
        );
    } else {
        libc::snprintf(
            ret.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 128]>() as usize,
            b"from %s to %s\0" as *const u8 as *const libc::c_char,
            from.as_mut_ptr(),
            to.as_mut_ptr(),
        );
    }
    return strlcpy(s, ret.as_mut_ptr(), l);
}
pub unsafe extern "C" fn sshkey_serialize_private_sk(
    mut key: *const sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = sshbuf_put_cstring(b, (*key).sk_application);
    if r != 0 as libc::c_int
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(b, (*key).sk_flags);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(b, (*key).sk_key_handle);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(b, (*key).sk_reserved);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_private_serialize_opt(
    mut key: *mut sshkey,
    mut buf: *mut crate::sshbuf::sshbuf,
    mut opts: sshkey_serialize_rep,
) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut was_shielded: libc::c_int = sshkey_is_shielded(key);
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    impl_0 = sshkey_impl_from_key(key);
    if impl_0.is_null() {
        return -(1 as libc::c_int);
    }
    r = sshkey_unshield_private(key);
    if r != 0 as libc::c_int {
        return r;
    }
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put_cstring(b, sshkey_ssh_name(key));
    if !(r != 0 as libc::c_int) {
        if sshkey_is_cert(key) != 0 {
            if ((*key).cert).is_null()
                || crate::sshbuf::sshbuf_len((*(*key).cert).certblob)
                    == 0 as libc::c_int as libc::c_ulong
            {
                r = -(10 as libc::c_int);
                current_block = 14051893294743041233;
            } else {
                r = sshbuf_put_stringb(b, (*(*key).cert).certblob);
                if r != 0 as libc::c_int {
                    current_block = 14051893294743041233;
                } else {
                    current_block = 13536709405535804910;
                }
            }
        } else {
            current_block = 13536709405535804910;
        }
        match current_block {
            14051893294743041233 => {}
            _ => {
                r = ((*(*impl_0).funcs).serialize_private).expect("non-null function pointer")(
                    key, b, opts,
                );
                if !(r != 0 as libc::c_int) {
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    if was_shielded != 0 {
        r = sshkey_shield_private(key);
    }
    if r == 0 as libc::c_int {
        r = sshbuf_putb(buf, b);
    }
    crate::sshbuf::sshbuf_free(b);
    return r;
}
pub unsafe extern "C" fn sshkey_private_serialize(
    mut key: *mut sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    return sshkey_private_serialize_opt(key, b, SSHKEY_SERIALIZE_DEFAULT);
}
pub unsafe extern "C" fn sshkey_private_deserialize_sk(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut k: *mut sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    (*k).sk_key_handle = crate::sshbuf::sshbuf_new();
    if ((*k).sk_key_handle).is_null() || {
        (*k).sk_reserved = crate::sshbuf::sshbuf_new();
        ((*k).sk_reserved).is_null()
    } {
        return -(2 as libc::c_int);
    }
    r = sshbuf_get_cstring(buf, &mut (*k).sk_application, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_u8(buf, &mut (*k).sk_flags);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_stringb(buf, (*k).sk_key_handle);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_stringb(buf, (*k).sk_reserved);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_private_deserialize(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut kp: *mut *mut sshkey,
) -> libc::c_int {
    let mut current_block: u64;
    let mut impl_0: *const sshkey_impl = 0 as *const sshkey_impl;
    let mut tname: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut expect_sk_application: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut expect_ed25519_pk: *mut u_char = 0 as *mut u_char;
    let mut k: *mut sshkey = 0 as *mut sshkey;
    let mut type_0: libc::c_int = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    if !kp.is_null() {
        *kp = 0 as *mut sshkey;
    }
    r = sshbuf_get_cstring(buf, &mut tname, 0 as *mut size_t);
    if !(r != 0 as libc::c_int) {
        type_0 = sshkey_type_from_name(tname);
        if sshkey_type_is_cert(type_0) != 0 {
            r = sshkey_froms(buf, &mut k);
            if r != 0 as libc::c_int {
                current_block = 305879874729359613;
            } else if (*k).type_0 != type_0 {
                r = -(45 as libc::c_int);
                current_block = 305879874729359613;
            } else if (*k).type_0 == KEY_ECDSA as libc::c_int
                && (*k).ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)
            {
                r = -(45 as libc::c_int);
                current_block = 305879874729359613;
            } else {
                expect_sk_application = (*k).sk_application;
                expect_ed25519_pk = (*k).ed25519_pk;
                (*k).sk_application = 0 as *mut libc::c_char;
                (*k).ed25519_pk = 0 as *mut u_char;
                current_block = 15976848397966268834;
            }
        } else {
            k = sshkey_new(type_0);
            if k.is_null() {
                r = -(2 as libc::c_int);
                current_block = 305879874729359613;
            } else {
                current_block = 15976848397966268834;
            }
        }
        match current_block {
            305879874729359613 => {}
            _ => {
                impl_0 = sshkey_impl_from_type(type_0);
                if impl_0.is_null() {
                    r = -(1 as libc::c_int);
                } else {
                    r = ((*(*impl_0).funcs).deserialize_private)
                        .expect("non-null function pointer")(tname, buf, k);
                    if !(r != 0 as libc::c_int) {
                        if !expect_sk_application.is_null()
                            && (((*k).sk_application).is_null()
                                || libc::strcmp(expect_sk_application, (*k).sk_application)
                                    != 0 as libc::c_int)
                            || !expect_ed25519_pk.is_null()
                                && (((*k).ed25519_pk).is_null()
                                    || memcmp(
                                        expect_ed25519_pk as *const libc::c_void,
                                        (*k).ed25519_pk as *const libc::c_void,
                                        32 as libc::c_uint as libc::c_ulong,
                                    ) != 0 as libc::c_int)
                        {
                            r = -(45 as libc::c_int);
                        } else {
                            r = 0 as libc::c_int;
                            if !kp.is_null() {
                                *kp = k;
                                k = 0 as *mut sshkey;
                            }
                        }
                    }
                }
            }
        }
    }
    libc::free(tname as *mut libc::c_void);
    sshkey_free(k);
    libc::free(expect_sk_application as *mut libc::c_void);
    libc::free(expect_ed25519_pk as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn sshkey_ec_validate_public(
    mut group: *const EC_GROUP,
    mut public: *const EC_POINT,
) -> libc::c_int {
    let mut nq: *mut EC_POINT = 0 as *mut EC_POINT;
    let mut order: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut x: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut y: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut tmp: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut ret: libc::c_int = -(20 as libc::c_int);
    if !(EC_METHOD_get_field_type(EC_GROUP_method_of(group)) != 406 as libc::c_int) {
        if !(EC_POINT_is_at_infinity(group, public) != 0) {
            x = BN_new();
            if x.is_null()
                || {
                    y = BN_new();
                    y.is_null()
                }
                || {
                    order = BN_new();
                    order.is_null()
                }
                || {
                    tmp = BN_new();
                    tmp.is_null()
                }
            {
                ret = -(2 as libc::c_int);
            } else if EC_GROUP_get_order(group, order, 0 as *mut BN_CTX) != 1 as libc::c_int
                || EC_POINT_get_affine_coordinates_GFp(group, public, x, y, 0 as *mut BN_CTX)
                    != 1 as libc::c_int
            {
                ret = -(22 as libc::c_int);
            } else if !(BN_num_bits(x) <= BN_num_bits(order) / 2 as libc::c_int
                || BN_num_bits(y) <= BN_num_bits(order) / 2 as libc::c_int)
            {
                nq = EC_POINT_new(group);
                if nq.is_null() {
                    ret = -(2 as libc::c_int);
                } else if EC_POINT_mul(
                    group,
                    nq,
                    0 as *const BIGNUM,
                    public,
                    order,
                    0 as *mut BN_CTX,
                ) != 1 as libc::c_int
                {
                    ret = -(22 as libc::c_int);
                } else if !(EC_POINT_is_at_infinity(group, nq) != 1 as libc::c_int) {
                    if BN_sub(tmp, order, BN_value_one()) == 0 {
                        ret = -(22 as libc::c_int);
                    } else if !(BN_cmp(x, tmp) >= 0 as libc::c_int
                        || BN_cmp(y, tmp) >= 0 as libc::c_int)
                    {
                        ret = 0 as libc::c_int;
                    }
                }
            }
        }
    }
    BN_clear_free(x);
    BN_clear_free(y);
    BN_clear_free(order);
    BN_clear_free(tmp);
    EC_POINT_free(nq);
    return ret;
}
pub unsafe extern "C" fn sshkey_ec_validate_private(mut key: *const EC_KEY) -> libc::c_int {
    let mut order: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut tmp: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut ret: libc::c_int = -(20 as libc::c_int);
    order = BN_new();
    if order.is_null() || {
        tmp = BN_new();
        tmp.is_null()
    } {
        ret = -(2 as libc::c_int);
    } else if EC_GROUP_get_order(EC_KEY_get0_group(key), order, 0 as *mut BN_CTX)
        != 1 as libc::c_int
    {
        ret = -(22 as libc::c_int);
    } else if !(BN_num_bits(EC_KEY_get0_private_key(key)) <= BN_num_bits(order) / 2 as libc::c_int)
    {
        if BN_sub(tmp, order, BN_value_one()) == 0 {
            ret = -(22 as libc::c_int);
        } else if !(BN_cmp(EC_KEY_get0_private_key(key), tmp) >= 0 as libc::c_int) {
            ret = 0 as libc::c_int;
        }
    }
    BN_clear_free(order);
    BN_clear_free(tmp);
    return ret;
}
pub unsafe extern "C" fn sshkey_dump_ec_point(
    mut group: *const EC_GROUP,
    mut point: *const EC_POINT,
) {
    let mut x: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut y: *mut BIGNUM = 0 as *mut BIGNUM;
    if point.is_null() {
        fputs(
            b"point=(NULL)\n\0" as *const u8 as *const libc::c_char,
            stderr,
        );
        return;
    }
    x = BN_new();
    if x.is_null() || {
        y = BN_new();
        y.is_null()
    } {
        libc::fprintf(
            stderr,
            b"%s: BN_new failed\n\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"sshkey_dump_ec_point\0"))
                .as_ptr(),
        );
    } else if EC_METHOD_get_field_type(EC_GROUP_method_of(group)) != 406 as libc::c_int {
        libc::fprintf(
            stderr,
            b"%s: group is not a prime field\n\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"sshkey_dump_ec_point\0"))
                .as_ptr(),
        );
    } else if EC_POINT_get_affine_coordinates_GFp(group, point, x, y, 0 as *mut BN_CTX)
        != 1 as libc::c_int
    {
        libc::fprintf(
            stderr,
            b"%s: EC_POINT_get_affine_coordinates_GFp\n\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"sshkey_dump_ec_point\0"))
                .as_ptr(),
        );
    } else {
        fputs(b"x=\0" as *const u8 as *const libc::c_char, stderr);
        BN_print_fp(stderr, x);
        fputs(b"\ny=\0" as *const u8 as *const libc::c_char, stderr);
        BN_print_fp(stderr, y);
        fputs(b"\n\0" as *const u8 as *const libc::c_char, stderr);
    }
    BN_clear_free(x);
    BN_clear_free(y);
}
pub unsafe extern "C" fn sshkey_dump_ec_key(mut key: *const EC_KEY) {
    let mut exponent: *const BIGNUM = 0 as *const BIGNUM;
    sshkey_dump_ec_point(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key));
    fputs(b"exponent=\0" as *const u8 as *const libc::c_char, stderr);
    exponent = EC_KEY_get0_private_key(key);
    if exponent.is_null() {
        fputs(b"(NULL)\0" as *const u8 as *const libc::c_char, stderr);
    } else {
        BN_print_fp(stderr, EC_KEY_get0_private_key(key));
    }
    fputs(b"\n\0" as *const u8 as *const libc::c_char, stderr);
}
unsafe extern "C" fn sshkey_private_to_blob2(
    mut prv: *mut sshkey,
    mut blob: *mut crate::sshbuf::sshbuf,
    mut passphrase: *const libc::c_char,
    mut comment: *const libc::c_char,
    mut ciphername: *const libc::c_char,
    mut rounds: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut cp: *mut u_char = 0 as *mut u_char;
    let mut key: *mut u_char = 0 as *mut u_char;
    let mut pubkeyblob: *mut u_char = 0 as *mut u_char;
    let mut salt: [u_char; 16] = [0; 16];
    let mut i: size_t = 0;
    let mut pubkeylen: size_t = 0;
    let mut keylen: size_t = 0;
    let mut ivlen: size_t = 0;
    let mut blocksize: size_t = 0;
    let mut authlen: size_t = 0;
    let mut check: u_int = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut ciphercontext: *mut sshcipher_ctx = 0 as *mut sshcipher_ctx;
    let mut cipher: *const sshcipher = 0 as *const sshcipher;
    let mut kdfname: *const libc::c_char = b"bcrypt\0" as *const u8 as *const libc::c_char;
    let mut encoded: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut encrypted: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut kdf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    if rounds <= 0 as libc::c_int {
        rounds = 16 as libc::c_int;
    }
    if passphrase.is_null() || strlen(passphrase) == 0 {
        ciphername = b"none\0" as *const u8 as *const libc::c_char;
        kdfname = b"none\0" as *const u8 as *const libc::c_char;
    } else if ciphername.is_null() {
        ciphername = b"aes256-ctr\0" as *const u8 as *const libc::c_char;
    }
    cipher = cipher_by_name(ciphername);
    if cipher.is_null() {
        r = -(10 as libc::c_int);
    } else {
        kdf = crate::sshbuf::sshbuf_new();
        if kdf.is_null()
            || {
                encoded = crate::sshbuf::sshbuf_new();
                encoded.is_null()
            }
            || {
                encrypted = crate::sshbuf::sshbuf_new();
                encrypted.is_null()
            }
        {
            r = -(2 as libc::c_int);
        } else {
            blocksize = cipher_blocksize(cipher) as size_t;
            keylen = cipher_keylen(cipher) as size_t;
            ivlen = cipher_ivlen(cipher) as size_t;
            authlen = cipher_authlen(cipher) as size_t;
            key = calloc(
                1 as libc::c_int as libc::c_ulong,
                keylen.wrapping_add(ivlen),
            ) as *mut u_char;
            if key.is_null() {
                r = -(2 as libc::c_int);
            } else {
                if libc::strcmp(kdfname, b"bcrypt\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    arc4random_buf(
                        salt.as_mut_ptr() as *mut libc::c_void,
                        16 as libc::c_int as size_t,
                    );
                    if bcrypt_pbkdf(
                        passphrase,
                        strlen(passphrase),
                        salt.as_mut_ptr(),
                        16 as libc::c_int as size_t,
                        key,
                        keylen.wrapping_add(ivlen),
                        rounds as libc::c_uint,
                    ) < 0 as libc::c_int
                    {
                        r = -(10 as libc::c_int);
                        current_block = 17160406918816213469;
                    } else {
                        r = sshbuf_put_string(
                            kdf,
                            salt.as_mut_ptr() as *const libc::c_void,
                            16 as libc::c_int as size_t,
                        );
                        if r != 0 as libc::c_int || {
                            r = sshbuf_put_u32(kdf, rounds as u_int32_t);
                            r != 0 as libc::c_int
                        } {
                            current_block = 17160406918816213469;
                        } else {
                            current_block = 16203760046146113240;
                        }
                    }
                } else if libc::strcmp(kdfname, b"none\0" as *const u8 as *const libc::c_char)
                    != 0 as libc::c_int
                {
                    r = -(42 as libc::c_int);
                    current_block = 17160406918816213469;
                } else {
                    current_block = 16203760046146113240;
                }
                match current_block {
                    17160406918816213469 => {}
                    _ => {
                        r = cipher_init(
                            &mut ciphercontext,
                            cipher,
                            key,
                            keylen as u_int,
                            key.offset(keylen as isize),
                            ivlen as u_int,
                            1 as libc::c_int,
                        );
                        if !(r != 0 as libc::c_int) {
                            r = sshbuf_put(
                                encoded,
                                b"openssh-key-v1\0" as *const u8 as *const libc::c_char
                                    as *const libc::c_void,
                                ::core::mem::size_of::<[libc::c_char; 15]>() as libc::c_ulong,
                            );
                            if !(r != 0 as libc::c_int
                                || {
                                    r = sshbuf_put_cstring(encoded, ciphername);
                                    r != 0 as libc::c_int
                                }
                                || {
                                    r = sshbuf_put_cstring(encoded, kdfname);
                                    r != 0 as libc::c_int
                                }
                                || {
                                    r = sshbuf_put_stringb(encoded, kdf);
                                    r != 0 as libc::c_int
                                }
                                || {
                                    r = sshbuf_put_u32(encoded, 1 as libc::c_int as u_int32_t);
                                    r != 0 as libc::c_int
                                }
                                || {
                                    r = sshkey_to_blob(prv, &mut pubkeyblob, &mut pubkeylen);
                                    r != 0 as libc::c_int
                                }
                                || {
                                    r = sshbuf_put_string(
                                        encoded,
                                        pubkeyblob as *const libc::c_void,
                                        pubkeylen,
                                    );
                                    r != 0 as libc::c_int
                                })
                            {
                                check = arc4random();
                                r = sshbuf_put_u32(encrypted, check);
                                if !(r != 0 as libc::c_int || {
                                    r = sshbuf_put_u32(encrypted, check);
                                    r != 0 as libc::c_int
                                }) {
                                    r = sshkey_private_serialize_opt(
                                        prv,
                                        encrypted,
                                        SSHKEY_SERIALIZE_FULL,
                                    );
                                    if !(r != 0 as libc::c_int || {
                                        r = sshbuf_put_cstring(encrypted, comment);
                                        r != 0 as libc::c_int
                                    }) {
                                        i = 0 as libc::c_int as size_t;
                                        loop {
                                            if !((crate::sshbuf::sshbuf_len(encrypted))
                                                .wrapping_rem(blocksize)
                                                != 0)
                                            {
                                                current_block = 17500079516916021833;
                                                break;
                                            }
                                            i = i.wrapping_add(1);
                                            r = crate::sshbuf_getput_basic::sshbuf_put_u8(
                                                encrypted,
                                                (i & 0xff as libc::c_int as libc::c_ulong)
                                                    as u_char,
                                            );
                                            if r != 0 as libc::c_int {
                                                current_block = 17160406918816213469;
                                                break;
                                            }
                                        }
                                        match current_block {
                                            17160406918816213469 => {}
                                            _ => {
                                                r = sshbuf_put_u32(
                                                    encoded,
                                                    crate::sshbuf::sshbuf_len(encrypted)
                                                        as u_int32_t,
                                                );
                                                if !(r != 0 as libc::c_int) {
                                                    r = sshbuf_reserve(
                                                        encoded,
                                                        (crate::sshbuf::sshbuf_len(encrypted))
                                                            .wrapping_add(authlen),
                                                        &mut cp,
                                                    );
                                                    if !(r != 0 as libc::c_int) {
                                                        r = cipher_crypt(
                                                            ciphercontext,
                                                            0 as libc::c_int as u_int,
                                                            cp,
                                                            sshbuf_ptr(encrypted),
                                                            crate::sshbuf::sshbuf_len(encrypted)
                                                                as u_int,
                                                            0 as libc::c_int as u_int,
                                                            authlen as u_int,
                                                        );
                                                        if !(r != 0 as libc::c_int) {
                                                            sshbuf_reset(blob);
                                                            r = sshbuf_put(
                                                                blob,
                                                                b"-----BEGIN OPENSSH PRIVATE KEY-----\n\0" as *const u8
                                                                    as *const libc::c_char as *const libc::c_void,
                                                                (::core::mem::size_of::<[libc::c_char; 37]>()
                                                                    as libc::c_ulong)
                                                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                                                            );
                                                            if !(r != 0 as libc::c_int
                                                                || {
                                                                    r = sshbuf_dtob64(
                                                                        encoded,
                                                                        blob,
                                                                        1 as libc::c_int,
                                                                    );
                                                                    r != 0 as libc::c_int
                                                                }
                                                                || {
                                                                    r = sshbuf_put(
                                                                        blob,
                                                                        b"-----END OPENSSH PRIVATE KEY-----\n\0" as *const u8
                                                                            as *const libc::c_char as *const libc::c_void,
                                                                        (::core::mem::size_of::<[libc::c_char; 35]>()
                                                                            as libc::c_ulong)
                                                                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                                                                    );
                                                                    r != 0 as libc::c_int
                                                                })
                                                            {
                                                                r = 0 as libc::c_int;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    crate::sshbuf::sshbuf_free(kdf);
    crate::sshbuf::sshbuf_free(encoded);
    crate::sshbuf::sshbuf_free(encrypted);
    cipher_free(ciphercontext);
    explicit_bzero(
        salt.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 16]>() as libc::c_ulong,
    );
    if !key.is_null() {
        freezero(key as *mut libc::c_void, keylen.wrapping_add(ivlen));
    }
    if !pubkeyblob.is_null() {
        freezero(pubkeyblob as *mut libc::c_void, pubkeylen);
    }
    return r;
}
unsafe extern "C" fn private2_uudecode(
    mut blob: *mut crate::sshbuf::sshbuf,
    mut decodedp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut cp: *const u_char = 0 as *const u_char;
    let mut encoded_len: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut last: u_char = 0;
    let mut encoded: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut decoded: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    if blob.is_null() || decodedp.is_null() {
        return -(10 as libc::c_int);
    }
    *decodedp = 0 as *mut crate::sshbuf::sshbuf;
    encoded = crate::sshbuf::sshbuf_new();
    if encoded.is_null() || {
        decoded = crate::sshbuf::sshbuf_new();
        decoded.is_null()
    } {
        r = -(2 as libc::c_int);
    } else {
        cp = sshbuf_ptr(blob);
        encoded_len = crate::sshbuf::sshbuf_len(blob);
        if encoded_len
            < (::core::mem::size_of::<[libc::c_char; 37]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                .wrapping_add(
                    (::core::mem::size_of::<[libc::c_char; 35]>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                )
            || memcmp(
                cp as *const libc::c_void,
                b"-----BEGIN OPENSSH PRIVATE KEY-----\n\0" as *const u8 as *const libc::c_char
                    as *const libc::c_void,
                (::core::mem::size_of::<[libc::c_char; 37]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            ) != 0 as libc::c_int
        {
            r = -(4 as libc::c_int);
        } else {
            cp = cp.offset(
                (::core::mem::size_of::<[libc::c_char; 37]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
            );
            encoded_len = (encoded_len as libc::c_ulong).wrapping_sub(
                (::core::mem::size_of::<[libc::c_char; 37]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            ) as size_t as size_t;
            loop {
                if !(encoded_len > 0 as libc::c_int as libc::c_ulong) {
                    current_block = 2838571290723028321;
                    break;
                }
                if *cp as libc::c_int != '\n' as i32 && *cp as libc::c_int != '\r' as i32 {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u8(encoded, *cp);
                    if r != 0 as libc::c_int {
                        current_block = 3973966692310782800;
                        break;
                    }
                }
                last = *cp;
                encoded_len = encoded_len.wrapping_sub(1);
                encoded_len;
                cp = cp.offset(1);
                cp;
                if !(last as libc::c_int == '\n' as i32) {
                    continue;
                }
                if !(encoded_len
                    >= (::core::mem::size_of::<[libc::c_char; 35]>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    && memcmp(
                        cp as *const libc::c_void,
                        b"-----END OPENSSH PRIVATE KEY-----\n\0" as *const u8 as *const libc::c_char
                            as *const libc::c_void,
                        (::core::mem::size_of::<[libc::c_char; 35]>() as libc::c_ulong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    ) == 0 as libc::c_int)
                {
                    continue;
                }
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(encoded, 0 as libc::c_int as u_char);
                if r != 0 as libc::c_int {
                    current_block = 3973966692310782800;
                    break;
                } else {
                    current_block = 2838571290723028321;
                    break;
                }
            }
            match current_block {
                3973966692310782800 => {}
                _ => {
                    if encoded_len == 0 as libc::c_int as libc::c_ulong {
                        r = -(4 as libc::c_int);
                    } else {
                        r = sshbuf_b64tod(decoded, sshbuf_ptr(encoded) as *mut libc::c_char);
                        if !(r != 0 as libc::c_int) {
                            if crate::sshbuf::sshbuf_len(decoded)
                                < ::core::mem::size_of::<[libc::c_char; 15]>() as libc::c_ulong
                                || memcmp(
                                    sshbuf_ptr(decoded) as *const libc::c_void,
                                    b"openssh-key-v1\0" as *const u8 as *const libc::c_char
                                        as *const libc::c_void,
                                    ::core::mem::size_of::<[libc::c_char; 15]>() as libc::c_ulong,
                                ) != 0
                            {
                                r = -(4 as libc::c_int);
                            } else {
                                *decodedp = decoded;
                                decoded = 0 as *mut crate::sshbuf::sshbuf;
                                r = 0 as libc::c_int;
                            }
                        }
                    }
                }
            }
        }
    }
    crate::sshbuf::sshbuf_free(encoded);
    crate::sshbuf::sshbuf_free(decoded);
    return r;
}
unsafe extern "C" fn private2_decrypt(
    mut decoded: *mut crate::sshbuf::sshbuf,
    mut passphrase: *const libc::c_char,
    mut decryptedp: *mut *mut crate::sshbuf::sshbuf,
    mut pubkeyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ciphername: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut kdfname: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cipher: *const sshcipher = 0 as *const sshcipher;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut keylen: size_t = 0 as libc::c_int as size_t;
    let mut ivlen: size_t = 0 as libc::c_int as size_t;
    let mut authlen: size_t = 0 as libc::c_int as size_t;
    let mut slen: size_t = 0 as libc::c_int as size_t;
    let mut kdf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut decrypted: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut ciphercontext: *mut sshcipher_ctx = 0 as *mut sshcipher_ctx;
    let mut pubkey: *mut sshkey = 0 as *mut sshkey;
    let mut key: *mut u_char = 0 as *mut u_char;
    let mut salt: *mut u_char = 0 as *mut u_char;
    let mut dp: *mut u_char = 0 as *mut u_char;
    let mut blocksize: u_int = 0;
    let mut rounds: u_int = 0;
    let mut nkeys: u_int = 0;
    let mut encrypted_len: u_int = 0;
    let mut check1: u_int = 0;
    let mut check2: u_int = 0;
    if decoded.is_null() || decryptedp.is_null() || pubkeyp.is_null() {
        return -(10 as libc::c_int);
    }
    *decryptedp = 0 as *mut crate::sshbuf::sshbuf;
    *pubkeyp = 0 as *mut sshkey;
    decrypted = crate::sshbuf::sshbuf_new();
    if decrypted.is_null() {
        r = -(2 as libc::c_int);
    } else {
        r = sshbuf_consume(
            decoded,
            ::core::mem::size_of::<[libc::c_char; 15]>() as libc::c_ulong,
        );
        if !(r != 0 as libc::c_int
            || {
                r = sshbuf_get_cstring(decoded, &mut ciphername, 0 as *mut size_t);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_get_cstring(decoded, &mut kdfname, 0 as *mut size_t);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_froms(decoded, &mut kdf);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_get_u32(decoded, &mut nkeys);
                r != 0 as libc::c_int
            })
        {
            if nkeys != 1 as libc::c_int as libc::c_uint {
                r = -(4 as libc::c_int);
            } else {
                r = sshkey_froms(decoded, &mut pubkey);
                if !(r != 0 as libc::c_int || {
                    r = sshbuf_get_u32(decoded, &mut encrypted_len);
                    r != 0 as libc::c_int
                }) {
                    cipher = cipher_by_name(ciphername);
                    if cipher.is_null() {
                        r = -(42 as libc::c_int);
                    } else if libc::strcmp(kdfname, b"none\0" as *const u8 as *const libc::c_char)
                        != 0 as libc::c_int
                        && libc::strcmp(kdfname, b"bcrypt\0" as *const u8 as *const libc::c_char)
                            != 0 as libc::c_int
                    {
                        r = -(42 as libc::c_int);
                    } else if libc::strcmp(kdfname, b"none\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                        && libc::strcmp(ciphername, b"none\0" as *const u8 as *const libc::c_char)
                            != 0 as libc::c_int
                    {
                        r = -(4 as libc::c_int);
                    } else if (passphrase.is_null()
                        || strlen(passphrase) == 0 as libc::c_int as libc::c_ulong)
                        && libc::strcmp(kdfname, b"none\0" as *const u8 as *const libc::c_char)
                            != 0 as libc::c_int
                    {
                        r = -(43 as libc::c_int);
                    } else {
                        blocksize = cipher_blocksize(cipher);
                        if encrypted_len < blocksize
                            || encrypted_len.wrapping_rem(blocksize)
                                != 0 as libc::c_int as libc::c_uint
                        {
                            r = -(4 as libc::c_int);
                        } else {
                            keylen = cipher_keylen(cipher) as size_t;
                            ivlen = cipher_ivlen(cipher) as size_t;
                            authlen = cipher_authlen(cipher) as size_t;
                            key = calloc(
                                1 as libc::c_int as libc::c_ulong,
                                keylen.wrapping_add(ivlen),
                            ) as *mut u_char;
                            if key.is_null() {
                                r = -(2 as libc::c_int);
                            } else {
                                if libc::strcmp(
                                    kdfname,
                                    b"bcrypt\0" as *const u8 as *const libc::c_char,
                                ) == 0 as libc::c_int
                                {
                                    r = sshbuf_get_string(kdf, &mut salt, &mut slen);
                                    if r != 0 as libc::c_int || {
                                        r = sshbuf_get_u32(kdf, &mut rounds);
                                        r != 0 as libc::c_int
                                    } {
                                        current_block = 9806652011558982115;
                                    } else if bcrypt_pbkdf(
                                        passphrase,
                                        strlen(passphrase),
                                        salt,
                                        slen,
                                        key,
                                        keylen.wrapping_add(ivlen),
                                        rounds,
                                    ) < 0 as libc::c_int
                                    {
                                        r = -(4 as libc::c_int);
                                        current_block = 9806652011558982115;
                                    } else {
                                        current_block = 11459959175219260272;
                                    }
                                } else {
                                    current_block = 11459959175219260272;
                                }
                                match current_block {
                                    9806652011558982115 => {}
                                    _ => {
                                        if crate::sshbuf::sshbuf_len(decoded) < authlen
                                            || (crate::sshbuf::sshbuf_len(decoded))
                                                .wrapping_sub(authlen)
                                                < encrypted_len as libc::c_ulong
                                        {
                                            r = -(4 as libc::c_int);
                                        } else {
                                            r = sshbuf_reserve(
                                                decrypted,
                                                encrypted_len as size_t,
                                                &mut dp,
                                            );
                                            if !(r != 0 as libc::c_int || {
                                                r = cipher_init(
                                                    &mut ciphercontext,
                                                    cipher,
                                                    key,
                                                    keylen as u_int,
                                                    key.offset(keylen as isize),
                                                    ivlen as u_int,
                                                    0 as libc::c_int,
                                                );
                                                r != 0 as libc::c_int
                                            }) {
                                                r = cipher_crypt(
                                                    ciphercontext,
                                                    0 as libc::c_int as u_int,
                                                    dp,
                                                    sshbuf_ptr(decoded),
                                                    encrypted_len,
                                                    0 as libc::c_int as u_int,
                                                    authlen as u_int,
                                                );
                                                if r != 0 as libc::c_int {
                                                    if r == -(30 as libc::c_int) {
                                                        r = -(43 as libc::c_int);
                                                    }
                                                } else {
                                                    r = sshbuf_consume(
                                                        decoded,
                                                        (encrypted_len as libc::c_ulong)
                                                            .wrapping_add(authlen),
                                                    );
                                                    if !(r != 0 as libc::c_int) {
                                                        if crate::sshbuf::sshbuf_len(decoded)
                                                            != 0 as libc::c_int as libc::c_ulong
                                                        {
                                                            r = -(4 as libc::c_int);
                                                        } else {
                                                            r = sshbuf_get_u32(
                                                                decrypted,
                                                                &mut check1,
                                                            );
                                                            if !(r != 0 as libc::c_int || {
                                                                r = sshbuf_get_u32(
                                                                    decrypted,
                                                                    &mut check2,
                                                                );
                                                                r != 0 as libc::c_int
                                                            }) {
                                                                if check1 != check2 {
                                                                    r = -(43 as libc::c_int);
                                                                } else {
                                                                    *decryptedp = decrypted;
                                                                    decrypted = 0 as *mut crate::sshbuf::sshbuf;
                                                                    *pubkeyp = pubkey;
                                                                    pubkey = 0 as *mut sshkey;
                                                                    r = 0 as libc::c_int;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    cipher_free(ciphercontext);
    libc::free(ciphername as *mut libc::c_void);
    libc::free(kdfname as *mut libc::c_void);
    sshkey_free(pubkey);
    if !salt.is_null() {
        explicit_bzero(salt as *mut libc::c_void, slen);
        libc::free(salt as *mut libc::c_void);
    }
    if !key.is_null() {
        explicit_bzero(key as *mut libc::c_void, keylen.wrapping_add(ivlen));
        libc::free(key as *mut libc::c_void);
    }
    crate::sshbuf::sshbuf_free(kdf);
    crate::sshbuf::sshbuf_free(decrypted);
    return r;
}
unsafe extern "C" fn sshkey_parse_private2(
    mut blob: *mut crate::sshbuf::sshbuf,
    mut type_0: libc::c_int,
    mut passphrase: *const libc::c_char,
    mut keyp: *mut *mut sshkey,
    mut commentp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut decoded: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut decrypted: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut k: *mut sshkey = 0 as *mut sshkey;
    let mut pubkey: *mut sshkey = 0 as *mut sshkey;
    if !keyp.is_null() {
        *keyp = 0 as *mut sshkey;
    }
    if !commentp.is_null() {
        *commentp = 0 as *mut libc::c_char;
    }
    r = private2_uudecode(blob, &mut decoded);
    if !(r != 0 as libc::c_int || {
        r = private2_decrypt(decoded, passphrase, &mut decrypted, &mut pubkey);
        r != 0 as libc::c_int
    }) {
        if type_0 != KEY_UNSPEC as libc::c_int
            && sshkey_type_plain(type_0) != sshkey_type_plain((*pubkey).type_0)
        {
            r = -(13 as libc::c_int);
        } else {
            r = sshkey_private_deserialize(decrypted, &mut k);
            if !(r != 0 as libc::c_int || {
                r = sshbuf_get_cstring(decrypted, &mut comment, 0 as *mut size_t);
                r != 0 as libc::c_int
            }) {
                r = private2_check_padding(decrypted);
                if !(r != 0 as libc::c_int) {
                    if sshkey_equal(pubkey, k) == 0 {
                        r = -(4 as libc::c_int);
                    } else {
                        r = 0 as libc::c_int;
                        if !keyp.is_null() {
                            *keyp = k;
                            k = 0 as *mut sshkey;
                        }
                        if !commentp.is_null() {
                            *commentp = comment;
                            comment = 0 as *mut libc::c_char;
                        }
                    }
                }
            }
        }
    }
    libc::free(comment as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(decoded);
    crate::sshbuf::sshbuf_free(decrypted);
    sshkey_free(k);
    sshkey_free(pubkey);
    return r;
}
unsafe extern "C" fn sshkey_parse_private2_pubkey(
    mut blob: *mut crate::sshbuf::sshbuf,
    mut type_0: libc::c_int,
    mut keyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut decoded: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut pubkey: *mut sshkey = 0 as *mut sshkey;
    let mut nkeys: u_int = 0 as libc::c_int as u_int;
    if !keyp.is_null() {
        *keyp = 0 as *mut sshkey;
    }
    r = private2_uudecode(blob, &mut decoded);
    if !(r != 0 as libc::c_int) {
        r = sshbuf_consume(
            decoded,
            ::core::mem::size_of::<[libc::c_char; 15]>() as libc::c_ulong,
        );
        if !(r != 0 as libc::c_int
            || {
                r = sshbuf_get_string_direct(decoded, 0 as *mut *const u_char, 0 as *mut size_t);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_get_string_direct(decoded, 0 as *mut *const u_char, 0 as *mut size_t);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_get_string_direct(decoded, 0 as *mut *const u_char, 0 as *mut size_t);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_get_u32(decoded, &mut nkeys);
                r != 0 as libc::c_int
            })
        {
            if nkeys != 1 as libc::c_int as libc::c_uint {
                r = -(4 as libc::c_int);
            } else {
                r = sshkey_froms(decoded, &mut pubkey);
                if !(r != 0 as libc::c_int) {
                    if type_0 != KEY_UNSPEC as libc::c_int
                        && sshkey_type_plain(type_0) != sshkey_type_plain((*pubkey).type_0)
                    {
                        r = -(13 as libc::c_int);
                    } else {
                        r = 0 as libc::c_int;
                        if !keyp.is_null() {
                            *keyp = pubkey;
                            pubkey = 0 as *mut sshkey;
                        }
                    }
                }
            }
        }
    }
    crate::sshbuf::sshbuf_free(decoded);
    sshkey_free(pubkey);
    return r;
}
unsafe extern "C" fn sshkey_private_to_blob_pem_pkcs8(
    mut key: *mut sshkey,
    mut buf: *mut crate::sshbuf::sshbuf,
    mut format: libc::c_int,
    mut _passphrase: *const libc::c_char,
    mut _comment: *const libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut was_shielded: libc::c_int = sshkey_is_shielded(key);
    let mut success: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut blen: libc::c_int = 0;
    let mut len: libc::c_int = strlen(_passphrase) as libc::c_int;
    let mut passphrase: *mut u_char = if len > 0 as libc::c_int {
        _passphrase as *mut u_char
    } else {
        0 as *mut u_char
    };
    let mut cipher: *const EVP_CIPHER = if len > 0 as libc::c_int {
        EVP_aes_128_cbc()
    } else {
        0 as *const EVP_CIPHER
    };
    let mut bptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut bio: *mut BIO = 0 as *mut BIO;
    let mut blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut pkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    if len > 0 as libc::c_int && len <= 4 as libc::c_int {
        return -(40 as libc::c_int);
    }
    blob = crate::sshbuf::sshbuf_new();
    if blob.is_null() {
        return -(2 as libc::c_int);
    }
    bio = BIO_new(BIO_s_mem());
    if bio.is_null() {
        r = -(2 as libc::c_int);
    } else if format == SSHKEY_PRIVATE_PKCS8 as libc::c_int && {
        pkey = EVP_PKEY_new();
        pkey.is_null()
    } {
        r = -(2 as libc::c_int);
    } else {
        r = sshkey_unshield_private(key);
        if !(r != 0 as libc::c_int) {
            match (*key).type_0 {
                1 => {
                    if format == SSHKEY_PRIVATE_PEM as libc::c_int {
                        success = PEM_write_bio_DSAPrivateKey(
                            bio,
                            (*key).dsa,
                            cipher,
                            passphrase,
                            len,
                            None,
                            0 as *mut libc::c_void,
                        );
                    } else {
                        success = EVP_PKEY_set1_DSA(pkey, (*key).dsa);
                    }
                }
                2 => {
                    if format == SSHKEY_PRIVATE_PEM as libc::c_int {
                        success = PEM_write_bio_ECPrivateKey(
                            bio,
                            (*key).ecdsa,
                            cipher,
                            passphrase,
                            len,
                            None,
                            0 as *mut libc::c_void,
                        );
                    } else {
                        success = EVP_PKEY_set1_EC_KEY(pkey, (*key).ecdsa);
                    }
                }
                0 => {
                    if format == SSHKEY_PRIVATE_PEM as libc::c_int {
                        success = PEM_write_bio_RSAPrivateKey(
                            bio,
                            (*key).rsa,
                            cipher,
                            passphrase,
                            len,
                            None,
                            0 as *mut libc::c_void,
                        );
                    } else {
                        success = EVP_PKEY_set1_RSA(pkey, (*key).rsa);
                    }
                }
                _ => {
                    success = 0 as libc::c_int;
                }
            }
            if success == 0 as libc::c_int {
                r = -(22 as libc::c_int);
            } else {
                if format == SSHKEY_PRIVATE_PKCS8 as libc::c_int {
                    success = PEM_write_bio_PrivateKey(
                        bio,
                        pkey,
                        cipher,
                        passphrase,
                        len,
                        None,
                        0 as *mut libc::c_void,
                    );
                    if success == 0 as libc::c_int {
                        r = -(22 as libc::c_int);
                        current_block = 5859173594782329820;
                    } else {
                        current_block = 14136749492126903395;
                    }
                } else {
                    current_block = 14136749492126903395;
                }
                match current_block {
                    5859173594782329820 => {}
                    _ => {
                        blen = BIO_ctrl(
                            bio,
                            3 as libc::c_int,
                            0 as libc::c_int as libc::c_long,
                            &mut bptr as *mut *mut libc::c_char as *mut libc::c_char
                                as *mut libc::c_void,
                        ) as libc::c_int;
                        if blen <= 0 as libc::c_int {
                            r = -(1 as libc::c_int);
                        } else {
                            r = sshbuf_put(blob, bptr as *const libc::c_void, blen as size_t);
                            if !(r != 0 as libc::c_int) {
                                r = 0 as libc::c_int;
                            }
                        }
                    }
                }
            }
        }
    }
    if was_shielded != 0 {
        r = sshkey_shield_private(key);
    }
    if r == 0 as libc::c_int {
        r = sshbuf_putb(buf, blob);
    }
    EVP_PKEY_free(pkey);
    crate::sshbuf::sshbuf_free(blob);
    BIO_free(bio);
    return r;
}
pub unsafe extern "C" fn sshkey_private_to_fileblob(
    mut key: *mut sshkey,
    mut blob: *mut crate::sshbuf::sshbuf,
    mut passphrase: *const libc::c_char,
    mut comment: *const libc::c_char,
    mut format: libc::c_int,
    mut openssh_format_cipher: *const libc::c_char,
    mut openssh_format_rounds: libc::c_int,
) -> libc::c_int {
    's_20: {
        match (*key).type_0 {
            1 | 2 | 0 => {
                break 's_20;
            }
            12 => {}
            3 | 10 => {}
            _ => return -(14 as libc::c_int),
        }
        return sshkey_private_to_blob2(
            key,
            blob,
            passphrase,
            comment,
            openssh_format_cipher,
            openssh_format_rounds,
        );
    }
    match format {
        0 => {
            return sshkey_private_to_blob2(
                key,
                blob,
                passphrase,
                comment,
                openssh_format_cipher,
                openssh_format_rounds,
            );
        }
        1 | 2 => {
            return sshkey_private_to_blob_pem_pkcs8(key, blob, format, passphrase, comment);
        }
        _ => return -(10 as libc::c_int),
    };
}
unsafe extern "C" fn translate_libcrypto_error(mut pem_err: libc::c_ulong) -> libc::c_int {
    let mut pem_reason: libc::c_int = ERR_GET_REASON(pem_err);
    match ERR_GET_LIB(pem_err) {
        9 => match pem_reason {
            104 | 109 | 101 => return -(43 as libc::c_int),
            _ => return -(4 as libc::c_int),
        },
        6 => match pem_reason {
            100 => return -(43 as libc::c_int),
            114 | 145 => return -(4 as libc::c_int),
            _ => return -(22 as libc::c_int),
        },
        13 => return -(4 as libc::c_int),
        _ => {}
    }
    return -(22 as libc::c_int);
}
unsafe extern "C" fn clear_libcrypto_errors() {
    while ERR_get_error() != 0 as libc::c_int as libc::c_ulong {}
}
unsafe extern "C" fn convert_libcrypto_error() -> libc::c_int {
    if translate_libcrypto_error(ERR_peek_error()) == -(43 as libc::c_int) {
        return -(43 as libc::c_int);
    }
    return translate_libcrypto_error(ERR_peek_last_error());
}
unsafe extern "C" fn pem_passphrase_cb(
    mut buf: *mut libc::c_char,
    mut size: libc::c_int,
    mut _rwflag: libc::c_int,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    let mut p: *mut libc::c_char = u as *mut libc::c_char;
    let mut len: size_t = 0;
    if p.is_null() || {
        len = strlen(p);
        len == 0 as libc::c_int as libc::c_ulong
    } {
        return -(1 as libc::c_int);
    }
    if size < 0 as libc::c_int || len > size as size_t {
        return -(1 as libc::c_int);
    }
    memcpy(buf as *mut libc::c_void, p as *const libc::c_void, len);
    return len as libc::c_int;
}
unsafe extern "C" fn sshkey_parse_private_pem_fileblob(
    mut blob: *mut crate::sshbuf::sshbuf,
    mut type_0: libc::c_int,
    mut passphrase: *const libc::c_char,
    mut keyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut current_block: u64;
    let mut pk: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    let mut prv: *mut sshkey = 0 as *mut sshkey;
    let mut bio: *mut BIO = 0 as *mut BIO;
    let mut r: libc::c_int = 0;
    if !keyp.is_null() {
        *keyp = 0 as *mut sshkey;
    }
    bio = BIO_new(BIO_s_mem());
    if bio.is_null() || crate::sshbuf::sshbuf_len(blob) > 2147483647 as libc::c_int as libc::c_ulong
    {
        return -(2 as libc::c_int);
    }
    if BIO_write(
        bio,
        sshbuf_ptr(blob) as *const libc::c_void,
        crate::sshbuf::sshbuf_len(blob) as libc::c_int,
    ) != crate::sshbuf::sshbuf_len(blob) as libc::c_int
    {
        r = -(2 as libc::c_int);
    } else {
        clear_libcrypto_errors();
        pk = PEM_read_bio_PrivateKey(
            bio,
            0 as *mut *mut EVP_PKEY,
            Some(
                pem_passphrase_cb
                    as unsafe extern "C" fn(
                        *mut libc::c_char,
                        libc::c_int,
                        libc::c_int,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            passphrase as *mut libc::c_char as *mut libc::c_void,
        );
        if pk.is_null() {
            if !passphrase.is_null() && *passphrase as libc::c_int != '\0' as i32 {
                r = -(43 as libc::c_int);
            } else {
                r = convert_libcrypto_error();
            }
        } else {
            if EVP_PKEY_get_base_id(pk) == 6 as libc::c_int
                && (type_0 == KEY_UNSPEC as libc::c_int || type_0 == KEY_RSA as libc::c_int)
            {
                prv = sshkey_new(KEY_UNSPEC as libc::c_int);
                if prv.is_null() {
                    r = -(2 as libc::c_int);
                    current_block = 10183881316869111092;
                } else {
                    (*prv).rsa = EVP_PKEY_get1_RSA(pk);
                    (*prv).type_0 = KEY_RSA as libc::c_int;
                    if RSA_blinding_on((*prv).rsa, 0 as *mut BN_CTX) != 1 as libc::c_int {
                        r = -(22 as libc::c_int);
                        current_block = 10183881316869111092;
                    } else {
                        r = sshkey_check_rsa_length(prv, 0 as libc::c_int);
                        if r != 0 as libc::c_int {
                            current_block = 10183881316869111092;
                        } else {
                            current_block = 2891135413264362348;
                        }
                    }
                }
            } else if EVP_PKEY_get_base_id(pk) == 116 as libc::c_int
                && (type_0 == KEY_UNSPEC as libc::c_int || type_0 == KEY_DSA as libc::c_int)
            {
                prv = sshkey_new(KEY_UNSPEC as libc::c_int);
                if prv.is_null() {
                    r = -(2 as libc::c_int);
                    current_block = 10183881316869111092;
                } else {
                    (*prv).dsa = EVP_PKEY_get1_DSA(pk);
                    (*prv).type_0 = KEY_DSA as libc::c_int;
                    current_block = 2891135413264362348;
                }
            } else if EVP_PKEY_get_base_id(pk) == 408 as libc::c_int
                && (type_0 == KEY_UNSPEC as libc::c_int || type_0 == KEY_ECDSA as libc::c_int)
            {
                prv = sshkey_new(KEY_UNSPEC as libc::c_int);
                if prv.is_null() {
                    r = -(2 as libc::c_int);
                    current_block = 10183881316869111092;
                } else {
                    (*prv).ecdsa = EVP_PKEY_get1_EC_KEY(pk);
                    (*prv).type_0 = KEY_ECDSA as libc::c_int;
                    (*prv).ecdsa_nid = sshkey_ecdsa_key_to_nid((*prv).ecdsa);
                    if (*prv).ecdsa_nid == -(1 as libc::c_int)
                        || (sshkey_curve_nid_to_name((*prv).ecdsa_nid)).is_null()
                        || sshkey_ec_validate_public(
                            EC_KEY_get0_group((*prv).ecdsa),
                            EC_KEY_get0_public_key((*prv).ecdsa),
                        ) != 0 as libc::c_int
                        || sshkey_ec_validate_private((*prv).ecdsa) != 0 as libc::c_int
                    {
                        r = -(4 as libc::c_int);
                        current_block = 10183881316869111092;
                    } else {
                        current_block = 2891135413264362348;
                    }
                }
            } else {
                r = -(4 as libc::c_int);
                current_block = 10183881316869111092;
            }
            match current_block {
                10183881316869111092 => {}
                _ => {
                    r = 0 as libc::c_int;
                    if !keyp.is_null() {
                        *keyp = prv;
                        prv = 0 as *mut sshkey;
                    }
                }
            }
        }
    }
    BIO_free(bio);
    EVP_PKEY_free(pk);
    sshkey_free(prv);
    return r;
}
pub unsafe extern "C" fn sshkey_parse_private_fileblob_type(
    mut blob: *mut crate::sshbuf::sshbuf,
    mut type_0: libc::c_int,
    mut passphrase: *const libc::c_char,
    mut keyp: *mut *mut sshkey,
    mut commentp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = -(1 as libc::c_int);
    if !keyp.is_null() {
        *keyp = 0 as *mut sshkey;
    }
    if !commentp.is_null() {
        *commentp = 0 as *mut libc::c_char;
    }
    match type_0 {
        3 | 8 => return sshkey_parse_private2(blob, type_0, passphrase, keyp, commentp),
        _ => {
            r = sshkey_parse_private2(blob, type_0, passphrase, keyp, commentp);
            if r != -(4 as libc::c_int) {
                return r;
            }
            return sshkey_parse_private_pem_fileblob(blob, type_0, passphrase, keyp);
        }
    };
}
pub unsafe extern "C" fn sshkey_parse_private_fileblob(
    mut buffer: *mut crate::sshbuf::sshbuf,
    mut passphrase: *const libc::c_char,
    mut keyp: *mut *mut sshkey,
    mut commentp: *mut *mut libc::c_char,
) -> libc::c_int {
    if !keyp.is_null() {
        *keyp = 0 as *mut sshkey;
    }
    if !commentp.is_null() {
        *commentp = 0 as *mut libc::c_char;
    }
    return sshkey_parse_private_fileblob_type(
        buffer,
        KEY_UNSPEC as libc::c_int,
        passphrase,
        keyp,
        commentp,
    );
}
pub unsafe extern "C" fn sshkey_sig_details_free(mut details: *mut sshkey_sig_details) {
    freezero(
        details as *mut libc::c_void,
        ::core::mem::size_of::<sshkey_sig_details>() as libc::c_ulong,
    );
}
pub unsafe extern "C" fn sshkey_parse_pubkey_from_private_fileblob_type(
    mut blob: *mut crate::sshbuf::sshbuf,
    mut type_0: libc::c_int,
    mut pubkeyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = -(1 as libc::c_int);
    if !pubkeyp.is_null() {
        *pubkeyp = 0 as *mut sshkey;
    }
    r = sshkey_parse_private2_pubkey(blob, type_0, pubkeyp);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_private_serialize_maxsign(
    mut k: *mut sshkey,
    mut b: *mut crate::sshbuf::sshbuf,
    mut _maxsign: u_int32_t,
    mut _printerror: libc::c_int,
) -> libc::c_int {
    return sshkey_private_serialize_opt(k, b, SSHKEY_SERIALIZE_DEFAULT);
}
pub unsafe extern "C" fn sshkey_signatures_left(mut _k: *const sshkey) -> u_int32_t {
    return 0 as libc::c_int as u_int32_t;
}
pub unsafe extern "C" fn sshkey_enable_maxsign(
    mut _k: *mut sshkey,
    mut _maxsign: u_int32_t,
) -> libc::c_int {
    return -(10 as libc::c_int);
}
pub unsafe extern "C" fn sshkey_set_filename(
    mut k: *mut sshkey,
    mut _filename: *const libc::c_char,
) -> libc::c_int {
    if k.is_null() {
        return -(10 as libc::c_int);
    }
    return 0 as libc::c_int;
}
