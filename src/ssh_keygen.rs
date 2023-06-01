use crate::atomicio::atomicio;
use crate::authfd::ssh_identitylist;
use crate::hostfile::hostkey_foreach_line;
use crate::sshbuf_getput_crypto::BIGNUM;
use crate::sshkey::sshkey_sig_details;

use crate::log::log_init;
use crate::utf8::msetlocale;
use ::libc;
use libc::close;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    pub type bignum_st;
    pub type evp_cipher_st;
    pub type evp_pkey_st;

    pub type notifier_ctx;
    pub type ssh_krl;

    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncasecmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong)
        -> libc::c_int;

    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;

    fn seed_rng();
    static mut BSDoptarg: *mut libc::c_char;
    static mut BSDoptind: libc::c_int;

    fn freezero(_: *mut libc::c_void, _: size_t);

    static mut stdin: *mut libc::FILE;
    static mut stdout: *mut libc::FILE;
    static mut stderr: *mut libc::FILE;
    fn rename(__old: *const libc::c_char, __new: *const libc::c_char) -> libc::c_int;
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;

    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::FILE;

    fn setvbuf(
        __stream: *mut libc::FILE,
        __buf: *mut libc::c_char,
        __modes: libc::c_int,
        __n: size_t,
    ) -> libc::c_int;

    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;

    fn fgetc(__stream: *mut libc::FILE) -> libc::c_int;
    fn fputc(__c: libc::c_int, __stream: *mut libc::FILE) -> libc::c_int;
    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> *mut libc::c_char;
    fn __getdelim(
        __lineptr: *mut *mut libc::c_char,
        __n: *mut size_t,
        __delimiter: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> __ssize_t;
    fn fputs(__s: *const libc::c_char, __stream: *mut libc::FILE) -> libc::c_int;
    fn puts(__s: *const libc::c_char) -> libc::c_int;
    fn ungetc(__c: libc::c_int, __stream: *mut libc::FILE) -> libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn _ssh_mkstemp(_: *mut libc::c_char) -> libc::c_int;
    fn link(__from: *const libc::c_char, __to: *const libc::c_char) -> libc::c_int;
    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    fn gethostname(__name: *mut libc::c_char, __len: size_t) -> libc::c_int;
    fn EVP_PKEY_get_base_id(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_get1_RSA(pkey: *mut EVP_PKEY) -> *mut crate::sshkey::rsa_st;
    fn EVP_PKEY_get1_DSA(pkey: *mut EVP_PKEY) -> *mut crate::sshkey::dsa_st;
    fn EVP_PKEY_get1_EC_KEY(pkey: *mut EVP_PKEY) -> *mut crate::sshkey::ec_key_st;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn strtol(_: *const libc::c_char, _: *mut *mut libc::c_char, _: libc::c_int) -> libc::c_long;
    fn strtoul(_: *const libc::c_char, _: *mut *mut libc::c_char, _: libc::c_int) -> libc::c_ulong;

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn qsort(__base: *mut libc::c_void, __nmemb: size_t, __size: size_t, __compar: __compar_fn_t);
    fn time(__timer: *mut time_t) -> time_t;
    fn BN_new() -> *mut BIGNUM;
    fn BN_clear_free(a: *mut BIGNUM);
    fn BN_bin2bn(s: *const libc::c_uchar, len: libc::c_int, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_set_word(a: *mut BIGNUM, w: libc::c_ulong) -> libc::c_int;
    fn BN_hex2bn(a: *mut *mut BIGNUM, str: *const libc::c_char) -> libc::c_int;
    fn DSA_set0_pqg(
        d: *mut crate::sshkey::DSA,
        p: *mut BIGNUM,
        q: *mut BIGNUM,
        g: *mut BIGNUM,
    ) -> libc::c_int;
    fn DSA_set0_key(
        d: *mut crate::sshkey::DSA,
        pub_key: *mut BIGNUM,
        priv_key: *mut BIGNUM,
    ) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;
    fn RSA_set0_key(
        r: *mut crate::sshkey::RSA,
        n: *mut BIGNUM,
        e: *mut BIGNUM,
        d: *mut BIGNUM,
    ) -> libc::c_int;
    fn RSA_set0_factors(r: *mut crate::sshkey::RSA, p: *mut BIGNUM, q: *mut BIGNUM) -> libc::c_int;
    fn strstr(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;

    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;

    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn PEM_read_PUBKEY(
        out: *mut libc::FILE,
        x: *mut *mut EVP_PKEY,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut EVP_PKEY;
    fn PEM_write_EC_PUBKEY(out: *mut libc::FILE, x: *const crate::sshkey::EC_KEY) -> libc::c_int;
    fn PEM_write_ECPrivateKey(
        out: *mut libc::FILE,
        x: *const crate::sshkey::EC_KEY,
        enc: *const EVP_CIPHER,
        kstr: *const libc::c_uchar,
        klen: libc::c_int,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn PEM_write_DSA_PUBKEY(out: *mut libc::FILE, x: *const crate::sshkey::DSA) -> libc::c_int;
    fn PEM_write_DSAPrivateKey(
        out: *mut libc::FILE,
        x: *const crate::sshkey::DSA,
        enc: *const EVP_CIPHER,
        kstr: *const libc::c_uchar,
        klen: libc::c_int,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn PEM_write_RSA_PUBKEY(out: *mut libc::FILE, x: *const crate::sshkey::RSA) -> libc::c_int;
    fn PEM_write_RSAPublicKey(out: *mut libc::FILE, x: *const crate::sshkey::RSA) -> libc::c_int;
    fn PEM_read_RSAPublicKey(
        out: *mut libc::FILE,
        x: *mut *mut crate::sshkey::RSA,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut crate::sshkey::RSA;
    fn PEM_write_RSAPrivateKey(
        out: *mut libc::FILE,
        x: *const crate::sshkey::RSA,
        enc: *const EVP_CIPHER,
        kstr: *const libc::c_uchar,
        klen: libc::c_int,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;

    fn xreallocarray(_: *mut libc::c_void, _: size_t, _: size_t) -> *mut libc::c_void;

    fn sshkey_new(_: libc::c_int) -> *mut crate::sshkey::sshkey;

    fn sshkey_equal(
        _: *const crate::sshkey::sshkey,
        _: *const crate::sshkey::sshkey,
    ) -> libc::c_int;

    fn sshkey_fingerprint_raw(
        k: *const crate::sshkey::sshkey,
        _: libc::c_int,
        retp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;

    fn sshkey_cert_type(_: *const crate::sshkey::sshkey) -> *const libc::c_char;
    fn sshkey_write(_: *const crate::sshkey::sshkey, _: *mut libc::FILE) -> libc::c_int;
    fn sshkey_read(_: *mut crate::sshkey::sshkey, _: *mut *mut libc::c_char) -> libc::c_int;
    fn sshkey_size(_: *const crate::sshkey::sshkey) -> u_int;
    fn sshkey_generate(
        type_0: libc::c_int,
        bits: u_int,
        keyp: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;

    fn sshkey_type_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_is_cert(_: *const crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_is_sk(_: *const crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn sshkey_to_certified(_: *mut crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_cert_copy(
        _: *const crate::sshkey::sshkey,
        _: *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_format_cert_validity(
        _: *const crate::sshkey::sshkey_cert,
        _: *mut libc::c_char,
        _: size_t,
    ) -> size_t;
    fn sshkey_certify(
        _: *mut crate::sshkey::sshkey,
        _: *mut crate::sshkey::sshkey,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn sshkey_certify_custom(
        _: *mut crate::sshkey::sshkey,
        _: *mut crate::sshkey::sshkey,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: Option<sshkey_certify_signer>,
        _: *mut libc::c_void,
    ) -> libc::c_int;
    fn sshkey_ecdsa_nid_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_curve_nid_to_bits(_: libc::c_int) -> u_int;
    fn sshkey_ecdsa_bits_to_nid(_: libc::c_int) -> libc::c_int;
    fn sshkey_ecdsa_key_to_nid(_: *mut crate::sshkey::EC_KEY) -> libc::c_int;
    fn sshkey_ssh_name(_: *const crate::sshkey::sshkey) -> *const libc::c_char;
    fn sshkey_fromb(
        _: *mut crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_putb(_: *const crate::sshkey::sshkey, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshkey_sign(
        _: *mut crate::sshkey::sshkey,
        _: *mut *mut u_char,
        _: *mut size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: u_int,
    ) -> libc::c_int;
    fn sshkey_verify(
        _: *const crate::sshkey::sshkey,
        _: *const u_char,
        _: size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: u_int,
        _: *mut *mut sshkey_sig_details,
    ) -> libc::c_int;
    fn ssh_rsa_complete_crt_parameters(
        _: *mut crate::sshkey::sshkey,
        _: *const BIGNUM,
    ) -> libc::c_int;
    fn sshkey_sig_details_free(_: *mut sshkey_sig_details);
    fn sshkey_save_private(
        _: *mut crate::sshkey::sshkey,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn sshkey_load_public(
        _: *const libc::c_char,
        _: *mut *mut crate::sshkey::sshkey,
        _: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sshkey_load_private(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut *mut crate::sshkey::sshkey,
        _: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sshkey_check_revoked(
        key: *mut crate::sshkey::sshkey,
        revoked_keys_file: *const libc::c_char,
    ) -> libc::c_int;
    fn sshkey_save_public(
        key: *const crate::sshkey::sshkey,
        path: *const libc::c_char,
        comment: *const libc::c_char,
    ) -> libc::c_int;

    fn sshbuf_fromb(buf: *mut crate::sshbuf::sshbuf) -> *mut crate::sshbuf::sshbuf;
    fn sshbuf_froms(
        buf: *mut crate::sshbuf::sshbuf,
        bufp: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;

    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_dtob16(buf: *mut crate::sshbuf::sshbuf) -> *mut libc::c_char;
    fn sshbuf_dtob64_string(
        buf: *const crate::sshbuf::sshbuf,
        wrap: libc::c_int,
    ) -> *mut libc::c_char;
    fn sshbuf_b64tod(buf: *mut crate::sshbuf::sshbuf, b64: *const libc::c_char) -> libc::c_int;

    fn sshbuf_load_file(_: *const libc::c_char, _: *mut *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshbuf_write_file(path: *const libc::c_char, buf: *mut crate::sshbuf::sshbuf)
        -> libc::c_int;
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn log_level_get() -> LogLevel;

    fn sshfatal(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: LogLevel,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: ...
    ) -> !;
    fn convtime(_: *const libc::c_char) -> libc::c_int;
    fn tilde_expand_filename(_: *const libc::c_char, _: uid_t) -> *mut libc::c_char;
    fn tohex(_: *const libc::c_void, _: size_t) -> *mut libc::c_char;
    fn xextendf(
        s: *mut *mut libc::c_char,
        sep: *const libc::c_char,
        fmt: *const libc::c_char,
        _: ...
    );

    fn lowercase(s: *mut libc::c_char);
    fn parse_absolute_time(_: *const libc::c_char, _: *mut uint64_t) -> libc::c_int;
    fn pwcopy(_: *mut libc::passwd) -> *mut libc::passwd;
    fn read_passphrase(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn notify_start(_: libc::c_int, _: *const libc::c_char, _: ...) -> *mut notifier_ctx;
    fn notify_complete(_: *mut notifier_ctx, _: *const libc::c_char, _: ...);
    fn addr_match_cidr_list(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn host_hash(_: *const libc::c_char, _: *const libc::c_char, _: u_int) -> *mut libc::c_char;
    fn hostkeys_foreach(
        path: *const libc::c_char,
        callback: Option<hostkeys_foreach_fn>,
        ctx: *mut libc::c_void,
        host: *const libc::c_char,
        ip: *const libc::c_char,
        options: u_int,
        note: u_int,
    ) -> libc::c_int;
    fn hostfile_create_user_ssh_dir(_: *const libc::c_char, _: libc::c_int);
    fn export_dns_rr(
        _: *const libc::c_char,
        _: *mut crate::sshkey::sshkey,
        _: *mut libc::FILE,
        _: libc::c_int,
        _: libc::c_int,
    ) -> libc::c_int;
    fn pkcs11_init(_: libc::c_int) -> libc::c_int;
    fn pkcs11_terminate();
    fn pkcs11_add_provider(
        _: *mut libc::c_char,
        _: *mut libc::c_char,
        _: *mut *mut *mut crate::sshkey::sshkey,
        _: *mut *mut *mut libc::c_char,
    ) -> libc::c_int;

    fn ssh_krl_init() -> *mut ssh_krl;
    fn ssh_krl_free(krl: *mut ssh_krl);
    fn ssh_krl_set_version(krl: *mut ssh_krl, version: u_int64_t);
    fn ssh_krl_set_comment(krl: *mut ssh_krl, comment: *const libc::c_char) -> libc::c_int;
    fn ssh_krl_revoke_cert_by_serial_range(
        krl: *mut ssh_krl,
        ca_key: *const crate::sshkey::sshkey,
        lo: u_int64_t,
        hi: u_int64_t,
    ) -> libc::c_int;
    fn ssh_krl_revoke_cert_by_key_id(
        krl: *mut ssh_krl,
        ca_key: *const crate::sshkey::sshkey,
        key_id: *const libc::c_char,
    ) -> libc::c_int;
    fn ssh_krl_revoke_key_explicit(
        krl: *mut ssh_krl,
        key: *const crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn ssh_krl_revoke_key_sha1(krl: *mut ssh_krl, p: *const u_char, len: size_t) -> libc::c_int;
    fn ssh_krl_revoke_key_sha256(krl: *mut ssh_krl, p: *const u_char, len: size_t) -> libc::c_int;
    fn ssh_krl_revoke_key(krl: *mut ssh_krl, key: *const crate::sshkey::sshkey) -> libc::c_int;
    fn ssh_krl_to_blob(
        krl: *mut ssh_krl,
        buf: *mut crate::sshbuf::sshbuf,
        sign_keys: *mut *mut crate::sshkey::sshkey,
        nsign_keys: u_int,
    ) -> libc::c_int;
    fn ssh_krl_from_blob(
        buf: *mut crate::sshbuf::sshbuf,
        krlp: *mut *mut ssh_krl,
        sign_ca_keys: *mut *const crate::sshkey::sshkey,
        nsign_ca_keys: size_t,
    ) -> libc::c_int;
    fn ssh_krl_check_key(krl: *mut ssh_krl, key: *const crate::sshkey::sshkey) -> libc::c_int;
    fn krl_dump(krl: *mut ssh_krl, f: *mut libc::FILE) -> libc::c_int;
    fn ssh_digest_alg_by_name(name: *const libc::c_char) -> libc::c_int;
    fn mprintf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn asmprintf(
        _: *mut *mut libc::c_char,
        _: size_t,
        _: *mut libc::c_int,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;

    fn ssh_get_authentication_socket(fdp: *mut libc::c_int) -> libc::c_int;
    fn ssh_fetch_identitylist(sock: libc::c_int, idlp: *mut *mut ssh_identitylist) -> libc::c_int;
    fn ssh_free_identitylist(idl: *mut ssh_identitylist);
    fn ssh_agent_has_key(sock: libc::c_int, key: *const crate::sshkey::sshkey) -> libc::c_int;
    fn ssh_agent_sign(
        sock: libc::c_int,
        key: *const crate::sshkey::sshkey,
        sigp: *mut *mut u_char,
        lenp: *mut size_t,
        data: *const u_char,
        datalen: size_t,
        alg: *const libc::c_char,
        compat: u_int,
    ) -> libc::c_int;
    fn sshsig_sign_fd(
        key: *mut crate::sshkey::sshkey,
        hashalg: *const libc::c_char,
        sk_provider_0: *const libc::c_char,
        sk_pin: *const libc::c_char,
        fd: libc::c_int,
        sig_namespace: *const libc::c_char,
        out: *mut *mut crate::sshbuf::sshbuf,
        signer: Option<sshsig_signer>,
        signer_ctx: *mut libc::c_void,
    ) -> libc::c_int;
    fn sshsig_verify_fd(
        signature: *mut crate::sshbuf::sshbuf,
        fd: libc::c_int,
        sig_namespace: *const libc::c_char,
        sign_keyp: *mut *mut crate::sshkey::sshkey,
        sig_details: *mut *mut sshkey_sig_details,
    ) -> libc::c_int;
    fn sshsig_armor(
        blob: *const crate::sshbuf::sshbuf,
        out: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshsig_dearmor(
        sig: *mut crate::sshbuf::sshbuf,
        out: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshsig_check_allowed_keys(
        path: *const libc::c_char,
        sign_key: *const crate::sshkey::sshkey,
        principal: *const libc::c_char,
        ns: *const libc::c_char,
        verify_time: uint64_t,
    ) -> libc::c_int;
    fn sshsig_get_pubkey(
        signature: *mut crate::sshbuf::sshbuf,
        pubkey: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshsig_find_principals(
        path: *const libc::c_char,
        sign_key: *const crate::sshkey::sshkey,
        verify_time: uint64_t,
        principal: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sshsig_match_principals(
        path: *const libc::c_char,
        principal: *const libc::c_char,
        principalsp: *mut *mut *mut libc::c_char,
        nprincipalsp: *mut size_t,
    ) -> libc::c_int;
    fn sshsk_enroll(
        type_0: libc::c_int,
        provider_path: *const libc::c_char,
        device: *const libc::c_char,
        application: *const libc::c_char,
        userid: *const libc::c_char,
        flags: uint8_t,
        pin: *const libc::c_char,
        challenge_buf: *mut crate::sshbuf::sshbuf,
        keyp: *mut *mut crate::sshkey::sshkey,
        attest: *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshsk_load_resident(
        provider_path: *const libc::c_char,
        device: *const libc::c_char,
        pin: *const libc::c_char,
        flags: u_int,
        srksp: *mut *mut *mut sshsk_resident_key,
        nsrksp: *mut size_t,
    ) -> libc::c_int;
    fn sshsk_free_resident_keys(srks: *mut *mut sshsk_resident_key, nsrks: size_t);

    static mut __progname: *mut libc::c_char;
    fn gen_candidates(
        _: *mut libc::FILE,
        _: u_int32_t,
        _: u_int32_t,
        _: *mut BIGNUM,
    ) -> libc::c_int;
    fn prime_test(
        _: *mut libc::FILE,
        _: *mut libc::FILE,
        _: u_int32_t,
        _: u_int32_t,
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: libc::c_ulong,
    ) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type mode_t = __mode_t;
pub type uid_t = __uid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;

pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;

pub type _IO_lock_t = ();

pub type EVP_CIPHER = evp_cipher_st;
pub type EVP_PKEY = evp_pkey_st;

pub type pem_password_cb = unsafe extern "C" fn(
    *mut libc::c_char,
    libc::c_int,
    libc::c_int,
    *mut libc::c_void,
) -> libc::c_int;
pub type __compar_fn_t =
    Option<unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int>;
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
pub type sshkey_private_format = libc::c_uint;
pub const SSHKEY_PRIVATE_PKCS8: sshkey_private_format = 2;
pub const SSHKEY_PRIVATE_PEM: sshkey_private_format = 1;
pub const SSHKEY_PRIVATE_OPENSSH: sshkey_private_format = 0;

pub type sshkey_certify_signer = unsafe extern "C" fn(
    *mut crate::sshkey::sshkey,
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
pub type SyslogFacility = libc::c_int;
pub const SYSLOG_FACILITY_NOT_SET: SyslogFacility = -1;
pub const SYSLOG_FACILITY_LOCAL7: SyslogFacility = 10;
pub const SYSLOG_FACILITY_LOCAL6: SyslogFacility = 9;
pub const SYSLOG_FACILITY_LOCAL5: SyslogFacility = 8;
pub const SYSLOG_FACILITY_LOCAL4: SyslogFacility = 7;
pub const SYSLOG_FACILITY_LOCAL3: SyslogFacility = 6;
pub const SYSLOG_FACILITY_LOCAL2: SyslogFacility = 5;
pub const SYSLOG_FACILITY_LOCAL1: SyslogFacility = 4;
pub const SYSLOG_FACILITY_LOCAL0: SyslogFacility = 3;
pub const SYSLOG_FACILITY_AUTH: SyslogFacility = 2;
pub const SYSLOG_FACILITY_USER: SyslogFacility = 1;
pub const SYSLOG_FACILITY_DAEMON: SyslogFacility = 0;
pub type LogLevel = libc::c_int;
pub const SYSLOG_LEVEL_NOT_SET: LogLevel = -1;
pub const SYSLOG_LEVEL_DEBUG3: LogLevel = 7;
pub const SYSLOG_LEVEL_DEBUG2: LogLevel = 6;
pub const SYSLOG_LEVEL_DEBUG1: LogLevel = 5;
pub const SYSLOG_LEVEL_VERBOSE: LogLevel = 4;
pub const SYSLOG_LEVEL_INFO: LogLevel = 3;
pub const SYSLOG_LEVEL_ERROR: LogLevel = 2;
pub const SYSLOG_LEVEL_FATAL: LogLevel = 1;
pub const SYSLOG_LEVEL_QUIET: LogLevel = 0;
pub type C2RustUnnamed = libc::c_uint;
pub const MRK_CA: C2RustUnnamed = 3;
pub const MRK_REVOKE: C2RustUnnamed = 2;
pub const MRK_NONE: C2RustUnnamed = 1;
pub const MRK_ERROR: C2RustUnnamed = 0;

pub type hostkeys_foreach_fn =
    unsafe extern "C" fn(*mut hostkey_foreach_line, *mut libc::c_void) -> libc::c_int;

pub type sshsig_signer = unsafe extern "C" fn(
    *mut crate::sshkey::sshkey,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshsk_resident_key {
    pub key: *mut crate::sshkey::sshkey,
    pub user_id: *mut uint8_t,
    pub user_id_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cert_ext {
    pub key: *mut libc::c_char,
    pub val: *mut libc::c_char,
    pub crit: libc::c_int,
}
pub type C2RustUnnamed_0 = libc::c_uint;
pub const FMT_PEM: C2RustUnnamed_0 = 2;
pub const FMT_PKCS8: C2RustUnnamed_0 = 1;
pub const FMT_RFC4716: C2RustUnnamed_0 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub key_type: *mut libc::c_char,
    pub key_type_display: *mut libc::c_char,
    pub path: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct known_hosts_ctx {
    pub host: *const libc::c_char,
    pub out: *mut libc::FILE,
    pub has_unhashed: libc::c_int,
    pub found_key: libc::c_int,
    pub invalid: libc::c_int,
    pub hash_hosts: libc::c_int,
    pub find_host: libc::c_int,
    pub delete_host: libc::c_int,
}
#[inline]
unsafe extern "C" fn getline(
    mut __lineptr: *mut *mut libc::c_char,
    mut __n: *mut size_t,
    mut __stream: *mut libc::FILE,
) -> __ssize_t {
    return __getdelim(__lineptr, __n, '\n' as i32, __stream);
}
static mut quiet: libc::c_int = 0 as libc::c_int;
static mut print_fingerprint: libc::c_int = 0 as libc::c_int;
static mut print_bubblebabble: libc::c_int = 0 as libc::c_int;
static mut fingerprint_hash: libc::c_int = 2 as libc::c_int;
static mut identity_file: [libc::c_char; 4096] = [0; 4096];
static mut have_identity: libc::c_int = 0 as libc::c_int;
static mut identity_passphrase: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut identity_new_passphrase: *mut libc::c_char =
    0 as *const libc::c_char as *mut libc::c_char;
static mut cert_key_type: u_int = 1 as libc::c_int as u_int;
static mut cert_key_id: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut cert_principals: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut cert_valid_from: u_int64_t = 0 as libc::c_int as u_int64_t;
static mut cert_valid_to: u_int64_t = !(0 as libc::c_ulonglong) as u_int64_t;
static mut certflags_flags: u_int32_t = (1 as libc::c_int
    | (1 as libc::c_int) << 1 as libc::c_int
    | (1 as libc::c_int) << 2 as libc::c_int
    | (1 as libc::c_int) << 3 as libc::c_int
    | (1 as libc::c_int) << 4 as libc::c_int) as u_int32_t;
static mut certflags_command: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut certflags_src_addr: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut cert_ext: *mut cert_ext = 0 as *const cert_ext as *mut cert_ext;
static mut ncert_ext: size_t = 0;
pub static mut convert_format: C2RustUnnamed_0 = FMT_RFC4716;
static mut key_type_name: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut pkcs11provider: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut sk_provider: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut private_key_format: libc::c_int = SSHKEY_PRIVATE_OPENSSH as libc::c_int;
static mut openssh_format_cipher: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut rounds: libc::c_int = 0 as libc::c_int;
static mut hostname: [libc::c_char; 1025] = [0; 1025];
unsafe extern "C" fn type_bits_valid(
    mut type_0: libc::c_int,
    mut name: *const libc::c_char,
    mut bitsp: *mut u_int32_t,
) {
    if type_0 == KEY_UNSPEC as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"type_bits_valid\0"))
                .as_ptr(),
            186 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"unknown key type %s\0" as *const u8 as *const libc::c_char,
            key_type_name,
        );
    }
    if *bitsp == 0 as libc::c_int as libc::c_uint {
        let mut nid: libc::c_int = 0;
        match type_0 {
            1 => {
                *bitsp = 1024 as libc::c_int as u_int32_t;
            }
            2 => {
                if !name.is_null() && {
                    nid = sshkey_ecdsa_nid_from_name(name);
                    nid > 0 as libc::c_int
                } {
                    *bitsp = sshkey_curve_nid_to_bits(nid);
                }
                if *bitsp == 0 as libc::c_int as libc::c_uint {
                    *bitsp = 256 as libc::c_int as u_int32_t;
                }
            }
            0 => {
                *bitsp = 3072 as libc::c_int as u_int32_t;
            }
            _ => {}
        }
    }
    match type_0 {
        1 => {
            if *bitsp != 1024 as libc::c_int as libc::c_uint {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"type_bits_valid\0",
                    ))
                    .as_ptr(),
                    212 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Invalid crate::sshkey::DSA key length: must be 1024 bits\0" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        0 => {
            if *bitsp < 1024 as libc::c_int as libc::c_uint {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"type_bits_valid\0",
                    ))
                    .as_ptr(),
                    217 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Invalid crate::sshkey::RSA key length: minimum is %d bits\0" as *const u8
                        as *const libc::c_char,
                    1024 as libc::c_int,
                );
            } else if *bitsp > 16384 as libc::c_int as libc::c_uint {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"type_bits_valid\0",
                    ))
                    .as_ptr(),
                    220 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Invalid crate::sshkey::RSA key length: maximum is %d bits\0" as *const u8
                        as *const libc::c_char,
                    16384 as libc::c_int,
                );
            }
        }
        2 => {
            if sshkey_ecdsa_bits_to_nid(*bitsp as libc::c_int) == -(1 as libc::c_int) {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"type_bits_valid\0",
                    ))
                    .as_ptr(),
                    226 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Invalid ECDSA key length: valid lengths are 256, 384 or 521 bits\0"
                        as *const u8 as *const libc::c_char,
                );
            }
        }
        _ => {}
    };
}
unsafe extern "C" fn confirm_overwrite(mut filename: *const libc::c_char) -> libc::c_int {
    let mut yesno: [libc::c_char; 3] = [0; 3];
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if libc::stat(filename, &mut st) != 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    printf(
        b"%s already exists.\n\0" as *const u8 as *const libc::c_char,
        filename,
    );
    printf(b"Overwrite (y/n)? \0" as *const u8 as *const libc::c_char);
    libc::fflush(stdout);
    if (fgets(
        yesno.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 3]>() as libc::c_ulong as libc::c_int,
        stdin,
    ))
    .is_null()
    {
        return 0 as libc::c_int;
    }
    if yesno[0 as libc::c_int as usize] as libc::c_int != 'y' as i32
        && yesno[0 as libc::c_int as usize] as libc::c_int != 'Y' as i32
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ask_filename(mut pw: *mut libc::passwd, mut prompt: *const libc::c_char) {
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    if key_type_name.is_null() {
        name = b".ssh/id_rsa\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    } else {
        match sshkey_type_from_name(key_type_name) {
            5 | 1 => {
                name = b".ssh/id_dsa\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            }
            6 | 2 => {
                name = b".ssh/id_ecdsa\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            }
            11 | 10 => {
                name =
                    b".ssh/id_ecdsa_sk\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            }
            4 | 0 => {
                name = b".ssh/id_rsa\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            }
            3 | 7 => {
                name =
                    b".ssh/id_ed25519\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            }
            12 | 13 => {
                name = b".ssh/id_ed25519_sk\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            8 | 9 => {
                name = b".ssh/id_xmss\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            }
            _ => {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ask_filename\0"))
                        .as_ptr(),
                    300 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"bad key type\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
    libc::snprintf(
        identity_file.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 4096]>() as usize,
        b"%s/%s\0" as *const u8 as *const libc::c_char,
        (*pw).pw_dir,
        name,
    );
    printf(
        b"%s (%s): \0" as *const u8 as *const libc::c_char,
        prompt,
        identity_file.as_mut_ptr(),
    );
    libc::fflush(stdout);
    if (fgets(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong as libc::c_int,
        stdin,
    ))
    .is_null()
    {
        libc::exit(1 as libc::c_int);
    }
    buf[strcspn(
        buf.as_mut_ptr(),
        b"\n\0" as *const u8 as *const libc::c_char,
    ) as usize] = '\0' as i32 as libc::c_char;
    if libc::strcmp(buf.as_mut_ptr(), b"\0" as *const u8 as *const libc::c_char) != 0 as libc::c_int
    {
        strlcpy(
            identity_file.as_mut_ptr(),
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        );
    }
    have_identity = 1 as libc::c_int;
}
unsafe extern "C" fn load_identity(
    mut filename: *const libc::c_char,
    mut commentp: *mut *mut libc::c_char,
) -> *mut crate::sshkey::sshkey {
    let mut pass: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut prv: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut r: libc::c_int = 0;
    if !commentp.is_null() {
        *commentp = 0 as *mut libc::c_char;
    }
    r = sshkey_load_private(
        filename,
        b"\0" as *const u8 as *const libc::c_char,
        &mut prv,
        commentp,
    );
    if r == 0 as libc::c_int {
        return prv;
    }
    if r != -(43 as libc::c_int) {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"load_identity\0"))
                .as_ptr(),
            327 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"Load key \"%s\"\0" as *const u8 as *const libc::c_char,
            filename,
        );
    }
    if !identity_passphrase.is_null() {
        pass = crate::xmalloc::xstrdup(identity_passphrase);
    } else {
        pass = read_passphrase(
            b"Enter passphrase: \0" as *const u8 as *const libc::c_char,
            0x2 as libc::c_int,
        );
    }
    r = sshkey_load_private(filename, pass, &mut prv, commentp);
    freezero(pass as *mut libc::c_void, strlen(pass));
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"load_identity\0"))
                .as_ptr(),
            335 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"Load key \"%s\"\0" as *const u8 as *const libc::c_char,
            filename,
        );
    }
    return prv;
}
unsafe extern "C" fn do_convert_to_ssh2(
    mut pw: *mut libc::passwd,
    mut k: *mut crate::sshkey::sshkey,
) {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut comment: [libc::c_char; 61] = [0; 61];
    let mut b64: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_convert_to_ssh2\0"))
                .as_ptr(),
            353 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshkey_putb(k, b);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_convert_to_ssh2\0"))
                .as_ptr(),
            355 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"put key\0" as *const u8 as *const libc::c_char,
        );
    }
    b64 = sshbuf_dtob64_string(b, 1 as libc::c_int);
    if b64.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_convert_to_ssh2\0"))
                .as_ptr(),
            357 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_dtob64_string failed\0" as *const u8 as *const libc::c_char,
        );
    }
    libc::snprintf(
        comment.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 61]>() as usize,
        b"%u-bit %s, converted by %s@%s from OpenSSH\0" as *const u8 as *const libc::c_char,
        sshkey_size(k),
        crate::sshkey::sshkey_type(k),
        (*pw).pw_name,
        hostname.as_mut_ptr(),
    );
    crate::sshkey::sshkey_free(k);
    crate::sshbuf::sshbuf_free(b);
    libc::fprintf(
        stdout,
        b"%s\n\0" as *const u8 as *const libc::c_char,
        b"---- BEGIN SSH2 PUBLIC KEY ----\0" as *const u8 as *const libc::c_char,
    );
    libc::fprintf(
        stdout,
        b"Comment: \"%s\"\n%s\0" as *const u8 as *const libc::c_char,
        comment.as_mut_ptr(),
        b64,
    );
    libc::fprintf(
        stdout,
        b"%s\n\0" as *const u8 as *const libc::c_char,
        b"---- END SSH2 PUBLIC KEY ----\0" as *const u8 as *const libc::c_char,
    );
    libc::free(b64 as *mut libc::c_void);
    libc::exit(0 as libc::c_int);
}
unsafe extern "C" fn do_convert_to_pkcs8(mut k: *mut crate::sshkey::sshkey) {
    match sshkey_type_plain((*k).type_0) {
        0 => {
            if PEM_write_RSA_PUBKEY(stdout, (*k).rsa) == 0 {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"do_convert_to_pkcs8\0",
                    ))
                    .as_ptr(),
                    381 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"PEM_write_RSA_PUBKEY failed\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        1 => {
            if PEM_write_DSA_PUBKEY(stdout, (*k).dsa) == 0 {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"do_convert_to_pkcs8\0",
                    ))
                    .as_ptr(),
                    385 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"PEM_write_DSA_PUBKEY failed\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        2 => {
            if PEM_write_EC_PUBKEY(stdout, (*k).ecdsa) == 0 {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"do_convert_to_pkcs8\0",
                    ))
                    .as_ptr(),
                    390 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"PEM_write_EC_PUBKEY failed\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        _ => {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"do_convert_to_pkcs8\0",
                ))
                .as_ptr(),
                394 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unsupported key type %s\0" as *const u8 as *const libc::c_char,
                crate::sshkey::sshkey_type(k),
            );
        }
    }
    libc::exit(0 as libc::c_int);
}
unsafe extern "C" fn do_convert_to_pem(mut k: *mut crate::sshkey::sshkey) {
    match sshkey_type_plain((*k).type_0) {
        0 => {
            if PEM_write_RSAPublicKey(stdout, (*k).rsa) == 0 {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"do_convert_to_pem\0",
                    ))
                    .as_ptr(),
                    405 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"PEM_write_RSAPublicKey failed\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        1 => {
            if PEM_write_DSA_PUBKEY(stdout, (*k).dsa) == 0 {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"do_convert_to_pem\0",
                    ))
                    .as_ptr(),
                    409 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"PEM_write_DSA_PUBKEY failed\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        2 => {
            if PEM_write_EC_PUBKEY(stdout, (*k).ecdsa) == 0 {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"do_convert_to_pem\0",
                    ))
                    .as_ptr(),
                    414 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"PEM_write_EC_PUBKEY failed\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        _ => {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"do_convert_to_pem\0"))
                    .as_ptr(),
                418 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unsupported key type %s\0" as *const u8 as *const libc::c_char,
                crate::sshkey::sshkey_type(k),
            );
        }
    }
    libc::exit(0 as libc::c_int);
}
unsafe extern "C" fn do_convert_to(mut pw: *mut libc::passwd) {
    let mut k: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut r: libc::c_int = 0;
    if have_identity == 0 {
        ask_filename(
            pw,
            b"Enter file in which the key is\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::stat(identity_file.as_mut_ptr(), &mut st) == -(1 as libc::c_int) {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"do_convert_to\0"))
                .as_ptr(),
            433 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: %s: %s\0" as *const u8 as *const libc::c_char,
            __progname,
            identity_file.as_mut_ptr(),
            libc::strerror(*libc::__errno_location()),
        );
    }
    r = sshkey_load_public(
        identity_file.as_mut_ptr(),
        &mut k,
        0 as *mut *mut libc::c_char,
    );
    if r != 0 as libc::c_int {
        k = load_identity(identity_file.as_mut_ptr(), 0 as *mut *mut libc::c_char);
    }
    match convert_format as libc::c_uint {
        0 => {
            do_convert_to_ssh2(pw, k);
        }
        1 => {
            do_convert_to_pkcs8(k);
        }
        2 => {
            do_convert_to_pem(k);
        }
        _ => {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"do_convert_to\0"))
                    .as_ptr(),
                447 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unknown key format %d\0" as *const u8 as *const libc::c_char,
                convert_format as libc::c_uint,
            );
        }
    }
    libc::exit(0 as libc::c_int);
}
unsafe extern "C" fn buffer_get_bignum_bits(
    mut b: *mut crate::sshbuf::sshbuf,
    mut value: *mut BIGNUM,
) {
    let mut bytes: u_int = 0;
    let mut bignum_bits: u_int = 0;
    let mut r: libc::c_int = 0;
    r = crate::sshbuf_getput_basic::sshbuf_get_u32(b, &mut bignum_bits);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"buffer_get_bignum_bits\0",
            ))
            .as_ptr(),
            463 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    bytes = bignum_bits
        .wrapping_add(7 as libc::c_int as libc::c_uint)
        .wrapping_div(8 as libc::c_int as libc::c_uint);
    if crate::sshbuf::sshbuf_len(b) < bytes as libc::c_ulong {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"buffer_get_bignum_bits\0",
            ))
            .as_ptr(),
            467 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"input buffer too small: need %d have %zu\0" as *const u8 as *const libc::c_char,
            bytes,
            crate::sshbuf::sshbuf_len(b),
        );
    }
    if (BN_bin2bn(crate::sshbuf::sshbuf_ptr(b), bytes as libc::c_int, value)).is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"buffer_get_bignum_bits\0",
            ))
            .as_ptr(),
            469 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"BN_bin2bn failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = crate::sshbuf::sshbuf_consume(b, bytes as size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"buffer_get_bignum_bits\0",
            ))
            .as_ptr(),
            471 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"consume\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn do_convert_private_ssh2(
    mut b: *mut crate::sshbuf::sshbuf,
) -> *mut crate::sshkey::sshkey {
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut type_0: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cipher: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut alg: *const libc::c_char = 0 as *const libc::c_char;
    let mut e1: u_char = 0;
    let mut e2: u_char = 0;
    let mut e3: u_char = 0;
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut data: [u_char; 11] =
        *::core::mem::transmute::<&[u8; 11], &mut [u_char; 11]>(b"abcde12345\0");
    let mut r: libc::c_int = 0;
    let mut rlen: libc::c_int = 0;
    let mut ktype: libc::c_int = 0;
    let mut magic: u_int = 0;
    let mut i1: u_int = 0;
    let mut i2: u_int = 0;
    let mut i3: u_int = 0;
    let mut i4: u_int = 0;
    let mut slen: size_t = 0;
    let mut e: u_long = 0;
    let mut dsa_p: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dsa_q: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dsa_g: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dsa_pub_key: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dsa_priv_key: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_n: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_e: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_d: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_p: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_q: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_iqmp: *mut BIGNUM = 0 as *mut BIGNUM;
    r = crate::sshbuf_getput_basic::sshbuf_get_u32(b, &mut magic);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"do_convert_private_ssh2\0",
            ))
            .as_ptr(),
            491 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse magic\0" as *const u8 as *const libc::c_char,
        );
    }
    if magic != 0x3f6ff9eb as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"do_convert_private_ssh2\0",
            ))
            .as_ptr(),
            495 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"bad magic 0x%x != 0x%x\0" as *const u8 as *const libc::c_char,
            magic,
            0x3f6ff9eb as libc::c_int,
        );
        return 0 as *mut crate::sshkey::sshkey;
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_u32(b, &mut i1);
    if r != 0 as libc::c_int
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut type_0, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut cipher, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(b, &mut i2);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(b, &mut i3);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(b, &mut i4);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"do_convert_private_ssh2\0",
            ))
            .as_ptr(),
            504 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"do_convert_private_ssh2\0"))
            .as_ptr(),
        505 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"ignore (%d %d %d %d)\0" as *const u8 as *const libc::c_char,
        i1,
        i2,
        i3,
        i4,
    );
    if libc::strcmp(cipher, b"none\0" as *const u8 as *const libc::c_char) != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"do_convert_private_ssh2\0",
            ))
            .as_ptr(),
            507 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"unsupported cipher %s\0" as *const u8 as *const libc::c_char,
            cipher,
        );
        libc::free(cipher as *mut libc::c_void);
        libc::free(type_0 as *mut libc::c_void);
        return 0 as *mut crate::sshkey::sshkey;
    }
    libc::free(cipher as *mut libc::c_void);
    if !(strstr(type_0, b"dsa\0" as *const u8 as *const libc::c_char)).is_null() {
        ktype = KEY_DSA as libc::c_int;
    } else if !(strstr(type_0, b"rsa\0" as *const u8 as *const libc::c_char)).is_null() {
        ktype = KEY_RSA as libc::c_int;
    } else {
        libc::free(type_0 as *mut libc::c_void);
        return 0 as *mut crate::sshkey::sshkey;
    }
    key = sshkey_new(ktype);
    if key.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"do_convert_private_ssh2\0",
            ))
            .as_ptr(),
            523 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    libc::free(type_0 as *mut libc::c_void);
    match (*key).type_0 {
        1 => {
            dsa_p = BN_new();
            if dsa_p.is_null()
                || {
                    dsa_q = BN_new();
                    dsa_q.is_null()
                }
                || {
                    dsa_g = BN_new();
                    dsa_g.is_null()
                }
                || {
                    dsa_pub_key = BN_new();
                    dsa_pub_key.is_null()
                }
                || {
                    dsa_priv_key = BN_new();
                    dsa_priv_key.is_null()
                }
            {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"do_convert_private_ssh2\0",
                    ))
                    .as_ptr(),
                    533 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"BN_new\0" as *const u8 as *const libc::c_char,
                );
            }
            buffer_get_bignum_bits(b, dsa_p);
            buffer_get_bignum_bits(b, dsa_g);
            buffer_get_bignum_bits(b, dsa_q);
            buffer_get_bignum_bits(b, dsa_pub_key);
            buffer_get_bignum_bits(b, dsa_priv_key);
            if DSA_set0_pqg((*key).dsa, dsa_p, dsa_q, dsa_g) == 0 {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"do_convert_private_ssh2\0",
                    ))
                    .as_ptr(),
                    540 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"DSA_set0_pqg failed\0" as *const u8 as *const libc::c_char,
                );
            }
            dsa_g = 0 as *mut BIGNUM;
            dsa_q = dsa_g;
            dsa_p = dsa_q;
            if DSA_set0_key((*key).dsa, dsa_pub_key, dsa_priv_key) == 0 {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"do_convert_private_ssh2\0",
                    ))
                    .as_ptr(),
                    543 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"DSA_set0_key failed\0" as *const u8 as *const libc::c_char,
                );
            }
            dsa_priv_key = 0 as *mut BIGNUM;
            dsa_pub_key = dsa_priv_key;
        }
        0 => {
            r = crate::sshbuf_getput_basic::sshbuf_get_u8(b, &mut e1);
            if r != 0 as libc::c_int
                || (e1 as libc::c_int) < 30 as libc::c_int && {
                    r = crate::sshbuf_getput_basic::sshbuf_get_u8(b, &mut e2);
                    r != 0 as libc::c_int
                }
                || (e1 as libc::c_int) < 30 as libc::c_int && {
                    r = crate::sshbuf_getput_basic::sshbuf_get_u8(b, &mut e3);
                    r != 0 as libc::c_int
                }
            {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"do_convert_private_ssh2\0",
                    ))
                    .as_ptr(),
                    550 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse crate::sshkey::RSA\0" as *const u8 as *const libc::c_char,
                );
            }
            e = e1 as u_long;
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"do_convert_private_ssh2\0",
                ))
                .as_ptr(),
                552 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"e %lx\0" as *const u8 as *const libc::c_char,
                e,
            );
            if e < 30 as libc::c_int as libc::c_ulong {
                e <<= 8 as libc::c_int;
                e = (e as libc::c_ulong).wrapping_add(e2 as libc::c_ulong) as u_long as u_long;
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"do_convert_private_ssh2\0",
                    ))
                    .as_ptr(),
                    556 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"e %lx\0" as *const u8 as *const libc::c_char,
                    e,
                );
                e <<= 8 as libc::c_int;
                e = (e as libc::c_ulong).wrapping_add(e3 as libc::c_ulong) as u_long as u_long;
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"do_convert_private_ssh2\0",
                    ))
                    .as_ptr(),
                    559 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"e %lx\0" as *const u8 as *const libc::c_char,
                    e,
                );
            }
            rsa_e = BN_new();
            if rsa_e.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"do_convert_private_ssh2\0",
                    ))
                    .as_ptr(),
                    562 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"BN_new\0" as *const u8 as *const libc::c_char,
                );
            }
            if BN_set_word(rsa_e, e) == 0 {
                BN_clear_free(rsa_e);
                crate::sshkey::sshkey_free(key);
                return 0 as *mut crate::sshkey::sshkey;
            }
            rsa_n = BN_new();
            if rsa_n.is_null()
                || {
                    rsa_d = BN_new();
                    rsa_d.is_null()
                }
                || {
                    rsa_p = BN_new();
                    rsa_p.is_null()
                }
                || {
                    rsa_q = BN_new();
                    rsa_q.is_null()
                }
                || {
                    rsa_iqmp = BN_new();
                    rsa_iqmp.is_null()
                }
            {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"do_convert_private_ssh2\0",
                    ))
                    .as_ptr(),
                    573 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"BN_new\0" as *const u8 as *const libc::c_char,
                );
            }
            buffer_get_bignum_bits(b, rsa_d);
            buffer_get_bignum_bits(b, rsa_n);
            buffer_get_bignum_bits(b, rsa_iqmp);
            buffer_get_bignum_bits(b, rsa_q);
            buffer_get_bignum_bits(b, rsa_p);
            if RSA_set0_key((*key).rsa, rsa_n, rsa_e, rsa_d) == 0 {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"do_convert_private_ssh2\0",
                    ))
                    .as_ptr(),
                    580 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"RSA_set0_key failed\0" as *const u8 as *const libc::c_char,
                );
            }
            rsa_d = 0 as *mut BIGNUM;
            rsa_e = rsa_d;
            rsa_n = rsa_e;
            if RSA_set0_factors((*key).rsa, rsa_p, rsa_q) == 0 {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"do_convert_private_ssh2\0",
                    ))
                    .as_ptr(),
                    583 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"RSA_set0_factors failed\0" as *const u8 as *const libc::c_char,
                );
            }
            rsa_q = 0 as *mut BIGNUM;
            rsa_p = rsa_q;
            r = ssh_rsa_complete_crt_parameters(key, rsa_iqmp);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"do_convert_private_ssh2\0",
                    ))
                    .as_ptr(),
                    586 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"generate crate::sshkey::RSA parameters\0" as *const u8 as *const libc::c_char,
                );
            }
            BN_clear_free(rsa_iqmp);
            alg = b"rsa-sha2-256\0" as *const u8 as *const libc::c_char;
        }
        _ => {}
    }
    rlen = crate::sshbuf::sshbuf_len(b) as libc::c_int;
    if rlen != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"do_convert_private_ssh2\0",
            ))
            .as_ptr(),
            593 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"remaining bytes in key blob %d\0" as *const u8 as *const libc::c_char,
            rlen,
        );
    }
    r = sshkey_sign(
        key,
        &mut sig,
        &mut slen,
        data.as_mut_ptr(),
        ::core::mem::size_of::<[u_char; 11]>() as libc::c_ulong,
        alg,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        0 as libc::c_int as u_int,
    );
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"do_convert_private_ssh2\0",
            ))
            .as_ptr(),
            598 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"signing with converted key failed\0" as *const u8 as *const libc::c_char,
        );
    } else {
        r = sshkey_verify(
            key,
            sig,
            slen,
            data.as_mut_ptr(),
            ::core::mem::size_of::<[u_char; 11]>() as libc::c_ulong,
            alg,
            0 as libc::c_int as u_int,
            0 as *mut *mut sshkey_sig_details,
        );
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"do_convert_private_ssh2\0",
                ))
                .as_ptr(),
                601 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"verification with converted key failed\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if r != 0 as libc::c_int {
        crate::sshkey::sshkey_free(key);
        libc::free(sig as *mut libc::c_void);
        return 0 as *mut crate::sshkey::sshkey;
    }
    libc::free(sig as *mut libc::c_void);
    return key;
}
unsafe extern "C" fn get_line(
    mut fp: *mut libc::FILE,
    mut line: *mut libc::c_char,
    mut len: size_t,
) -> libc::c_int {
    let mut c: libc::c_int = 0;
    let mut pos: size_t = 0 as libc::c_int as size_t;
    *line.offset(0 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
    loop {
        c = fgetc(fp);
        if !(c != -(1 as libc::c_int)) {
            break;
        }
        if pos >= len.wrapping_sub(1 as libc::c_int as libc::c_ulong) {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"get_line\0")).as_ptr(),
                620 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"input line too long.\0" as *const u8 as *const libc::c_char,
            );
        }
        match c {
            13 => {
                c = fgetc(fp);
                if c != -(1 as libc::c_int)
                    && c != '\n' as i32
                    && ungetc(c, fp) == -(1 as libc::c_int)
                {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"get_line\0"))
                            .as_ptr(),
                        625 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"unget: %s\0" as *const u8 as *const libc::c_char,
                        libc::strerror(*libc::__errno_location()),
                    );
                }
                return pos as libc::c_int;
            }
            10 => return pos as libc::c_int,
            _ => {}
        }
        let fresh0 = pos;
        pos = pos.wrapping_add(1);
        *line.offset(fresh0 as isize) = c as libc::c_char;
        *line.offset(pos as isize) = '\0' as i32 as libc::c_char;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn do_convert_from_ssh2(
    mut _pw: *mut libc::passwd,
    mut k: *mut *mut crate::sshkey::sshkey,
    mut private: *mut libc::c_int,
) {
    let mut r: libc::c_int = 0;
    let mut blen: libc::c_int = 0;
    let mut escaped: libc::c_int = 0 as libc::c_int;
    let mut len: u_int = 0;
    let mut line: [libc::c_char; 1024] = [0; 1024];
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut encoded: [libc::c_char; 8096] = [0; 8096];
    let mut fp: *mut libc::FILE = 0 as *mut libc::FILE;
    buf = crate::sshbuf::sshbuf_new();
    if buf.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"do_convert_from_ssh2\0"))
                .as_ptr(),
            648 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    fp = fopen(
        identity_file.as_mut_ptr(),
        b"r\0" as *const u8 as *const libc::c_char,
    );
    if fp.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"do_convert_from_ssh2\0"))
                .as_ptr(),
            650 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: %s: %s\0" as *const u8 as *const libc::c_char,
            __progname,
            identity_file.as_mut_ptr(),
            libc::strerror(*libc::__errno_location()),
        );
    }
    encoded[0 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
    loop {
        blen = get_line(
            fp,
            line.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        );
        if !(blen != -(1 as libc::c_int)) {
            break;
        }
        if blen > 0 as libc::c_int
            && line[(blen - 1 as libc::c_int) as usize] as libc::c_int == '\\' as i32
        {
            escaped += 1;
            escaped;
        }
        if strncmp(
            line.as_mut_ptr(),
            b"----\0" as *const u8 as *const libc::c_char,
            4 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
            || !(strstr(
                line.as_mut_ptr(),
                b": \0" as *const u8 as *const libc::c_char,
            ))
            .is_null()
        {
            if !(strstr(
                line.as_mut_ptr(),
                b"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\0" as *const u8 as *const libc::c_char,
            ))
            .is_null()
            {
                *private = 1 as libc::c_int;
            }
            if !(strstr(
                line.as_mut_ptr(),
                b" END \0" as *const u8 as *const libc::c_char,
            ))
            .is_null()
            {
                break;
            }
        } else if escaped != 0 {
            escaped -= 1;
            escaped;
        } else {
            strlcat(
                encoded.as_mut_ptr(),
                line.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 8096]>() as libc::c_ulong,
            );
        }
    }
    len = strlen(encoded.as_mut_ptr()) as u_int;
    if len.wrapping_rem(4 as libc::c_int as libc::c_uint) == 3 as libc::c_int as libc::c_uint
        && encoded[len.wrapping_sub(1 as libc::c_int as libc::c_uint) as usize] as libc::c_int
            == '=' as i32
        && encoded[len.wrapping_sub(2 as libc::c_int as libc::c_uint) as usize] as libc::c_int
            == '=' as i32
        && encoded[len.wrapping_sub(3 as libc::c_int as libc::c_uint) as usize] as libc::c_int
            == '=' as i32
    {
        encoded[len.wrapping_sub(3 as libc::c_int as libc::c_uint) as usize] =
            '\0' as i32 as libc::c_char;
    }
    r = sshbuf_b64tod(buf, encoded.as_mut_ptr());
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"do_convert_from_ssh2\0"))
                .as_ptr(),
            679 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"base64 decode\0" as *const u8 as *const libc::c_char,
        );
    }
    if *private != 0 {
        *k = do_convert_private_ssh2(buf);
        if (*k).is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"do_convert_from_ssh2\0",
                ))
                .as_ptr(),
                682 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"private key conversion failed\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        r = sshkey_fromb(buf, k);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"do_convert_from_ssh2\0",
                ))
                .as_ptr(),
                684 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse key\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    crate::sshbuf::sshbuf_free(buf);
    fclose(fp);
}
unsafe extern "C" fn do_convert_from_pkcs8(
    mut k: *mut *mut crate::sshkey::sshkey,
    mut _private: *mut libc::c_int,
) {
    let mut pubkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    let mut fp: *mut libc::FILE = 0 as *mut libc::FILE;
    fp = fopen(
        identity_file.as_mut_ptr(),
        b"r\0" as *const u8 as *const libc::c_char,
    );
    if fp.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"do_convert_from_pkcs8\0"))
                .as_ptr(),
            696 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: %s: %s\0" as *const u8 as *const libc::c_char,
            __progname,
            identity_file.as_mut_ptr(),
            libc::strerror(*libc::__errno_location()),
        );
    }
    pubkey = PEM_read_PUBKEY(fp, 0 as *mut *mut EVP_PKEY, None, 0 as *mut libc::c_void);
    if pubkey.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"do_convert_from_pkcs8\0"))
                .as_ptr(),
            699 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s is not a recognised public key format\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
        );
    }
    fclose(fp);
    match EVP_PKEY_get_base_id(pubkey) {
        6 => {
            *k = sshkey_new(KEY_UNSPEC as libc::c_int);
            if (*k).is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"do_convert_from_pkcs8\0",
                    ))
                    .as_ptr(),
                    705 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
                );
            }
            (**k).type_0 = KEY_RSA as libc::c_int;
            (**k).rsa = EVP_PKEY_get1_RSA(pubkey);
        }
        116 => {
            *k = sshkey_new(KEY_UNSPEC as libc::c_int);
            if (*k).is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"do_convert_from_pkcs8\0",
                    ))
                    .as_ptr(),
                    711 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
                );
            }
            (**k).type_0 = KEY_DSA as libc::c_int;
            (**k).dsa = EVP_PKEY_get1_DSA(pubkey);
        }
        408 => {
            *k = sshkey_new(KEY_UNSPEC as libc::c_int);
            if (*k).is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"do_convert_from_pkcs8\0",
                    ))
                    .as_ptr(),
                    718 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
                );
            }
            (**k).type_0 = KEY_ECDSA as libc::c_int;
            (**k).ecdsa = EVP_PKEY_get1_EC_KEY(pubkey);
            (**k).ecdsa_nid = sshkey_ecdsa_key_to_nid((**k).ecdsa);
        }
        _ => {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"do_convert_from_pkcs8\0",
                ))
                .as_ptr(),
                726 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unsupported pubkey type %d\0" as *const u8 as *const libc::c_char,
                EVP_PKEY_get_base_id(pubkey),
            );
        }
    }
    EVP_PKEY_free(pubkey);
}
unsafe extern "C" fn do_convert_from_pem(
    mut k: *mut *mut crate::sshkey::sshkey,
    mut _private: *mut libc::c_int,
) {
    let mut fp: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut rsa: *mut crate::sshkey::RSA = 0 as *mut crate::sshkey::RSA;
    fp = fopen(
        identity_file.as_mut_ptr(),
        b"r\0" as *const u8 as *const libc::c_char,
    );
    if fp.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"do_convert_from_pem\0"))
                .as_ptr(),
            739 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: %s: %s\0" as *const u8 as *const libc::c_char,
            __progname,
            identity_file.as_mut_ptr(),
            libc::strerror(*libc::__errno_location()),
        );
    }
    rsa = PEM_read_RSAPublicKey(
        fp,
        0 as *mut *mut crate::sshkey::RSA,
        None,
        0 as *mut libc::c_void,
    );
    if !rsa.is_null() {
        *k = sshkey_new(KEY_UNSPEC as libc::c_int);
        if (*k).is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"do_convert_from_pem\0",
                ))
                .as_ptr(),
                742 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
            );
        }
        (**k).type_0 = KEY_RSA as libc::c_int;
        (**k).rsa = rsa;
        fclose(fp);
        return;
    }
    sshfatal(
        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"do_convert_from_pem\0"))
            .as_ptr(),
        748 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_FATAL,
        0 as *const libc::c_char,
        b"unrecognised raw private key format\0" as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn do_convert_from(mut pw: *mut libc::passwd) {
    let mut k: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut r: libc::c_int = 0;
    let mut private: libc::c_int = 0 as libc::c_int;
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if have_identity == 0 {
        ask_filename(
            pw,
            b"Enter file in which the key is\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::stat(identity_file.as_mut_ptr(), &mut st) == -(1 as libc::c_int) {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"do_convert_from\0"))
                .as_ptr(),
            761 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: %s: %s\0" as *const u8 as *const libc::c_char,
            __progname,
            identity_file.as_mut_ptr(),
            libc::strerror(*libc::__errno_location()),
        );
    }
    match convert_format as libc::c_uint {
        0 => {
            do_convert_from_ssh2(pw, &mut k, &mut private);
        }
        1 => {
            do_convert_from_pkcs8(&mut k, &mut private);
        }
        2 => {
            do_convert_from_pem(&mut k, &mut private);
        }
        _ => {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"do_convert_from\0"))
                    .as_ptr(),
                774 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unknown key format %d\0" as *const u8 as *const libc::c_char,
                convert_format as libc::c_uint,
            );
        }
    }
    if private == 0 {
        r = sshkey_write(k, stdout);
        if r == 0 as libc::c_int {
            ok = 1 as libc::c_int;
        }
        if ok != 0 {
            libc::fprintf(stdout, b"\n\0" as *const u8 as *const libc::c_char);
        }
    } else {
        match (*k).type_0 {
            1 => {
                ok = PEM_write_DSAPrivateKey(
                    stdout,
                    (*k).dsa,
                    0 as *const EVP_CIPHER,
                    0 as *const libc::c_uchar,
                    0 as libc::c_int,
                    None,
                    0 as *mut libc::c_void,
                );
            }
            2 => {
                ok = PEM_write_ECPrivateKey(
                    stdout,
                    (*k).ecdsa,
                    0 as *const EVP_CIPHER,
                    0 as *const libc::c_uchar,
                    0 as libc::c_int,
                    None,
                    0 as *mut libc::c_void,
                );
            }
            0 => {
                ok = PEM_write_RSAPrivateKey(
                    stdout,
                    (*k).rsa,
                    0 as *const EVP_CIPHER,
                    0 as *const libc::c_uchar,
                    0 as libc::c_int,
                    None,
                    0 as *mut libc::c_void,
                );
            }
            _ => {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"do_convert_from\0",
                    ))
                    .as_ptr(),
                    799 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"unsupported key type %s\0" as *const u8 as *const libc::c_char,
                    crate::sshkey::sshkey_type(k),
                );
            }
        }
    }
    if ok == 0 {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"do_convert_from\0"))
                .as_ptr(),
            804 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"key write failed\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshkey::sshkey_free(k);
    libc::exit(0 as libc::c_int);
}
unsafe extern "C" fn do_print_public(mut pw: *mut libc::passwd) {
    let mut prv: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut r: libc::c_int = 0;
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    if have_identity == 0 {
        ask_filename(
            pw,
            b"Enter file in which the key is\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::stat(identity_file.as_mut_ptr(), &mut st) == -(1 as libc::c_int) {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"do_print_public\0"))
                .as_ptr(),
            821 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: %s\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
            libc::strerror(*libc::__errno_location()),
        );
    }
    prv = load_identity(identity_file.as_mut_ptr(), &mut comment);
    r = sshkey_write(prv, stdout);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"do_print_public\0"))
                .as_ptr(),
            824 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"write key\0" as *const u8 as *const libc::c_char,
        );
    }
    if !comment.is_null() && *comment as libc::c_int != '\0' as i32 {
        libc::fprintf(
            stdout,
            b" %s\0" as *const u8 as *const libc::c_char,
            comment,
        );
    }
    libc::fprintf(stdout, b"\n\0" as *const u8 as *const libc::c_char);
    if sshkey_is_sk(prv) != 0 {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"do_print_public\0"))
                .as_ptr(),
            830 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"sk_application: \"%s\", sk_flags 0x%02x\0" as *const u8 as *const libc::c_char,
            (*prv).sk_application,
            (*prv).sk_flags as libc::c_int,
        );
    }
    crate::sshkey::sshkey_free(prv);
    libc::free(comment as *mut libc::c_void);
    libc::exit(0 as libc::c_int);
}
unsafe extern "C" fn do_download(mut _pw: *mut libc::passwd) {
    let mut keys: *mut *mut crate::sshkey::sshkey = 0 as *mut *mut crate::sshkey::sshkey;
    let mut i: libc::c_int = 0;
    let mut nkeys: libc::c_int = 0;
    let mut rep: sshkey_fp_rep = SSH_FP_DEFAULT;
    let mut fptype: libc::c_int = 0;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ra: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut comments: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    fptype = if print_bubblebabble != 0 {
        1 as libc::c_int
    } else {
        fingerprint_hash
    };
    rep = (if print_bubblebabble != 0 {
        SSH_FP_BUBBLEBABBLE as libc::c_int
    } else {
        SSH_FP_DEFAULT as libc::c_int
    }) as sshkey_fp_rep;
    pkcs11_init(1 as libc::c_int);
    nkeys = pkcs11_add_provider(
        pkcs11provider,
        0 as *mut libc::c_char,
        &mut keys,
        &mut comments,
    );
    if nkeys <= 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_download\0")).as_ptr(),
            853 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"cannot read public key from pkcs11\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int;
    while i < nkeys {
        if print_fingerprint != 0 {
            fp = crate::sshkey::sshkey_fingerprint(*keys.offset(i as isize), fptype, rep);
            ra = crate::sshkey::sshkey_fingerprint(
                *keys.offset(i as isize),
                fingerprint_hash,
                SSH_FP_RANDOMART,
            );
            if fp.is_null() || ra.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_download\0"))
                        .as_ptr(),
                    860 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"crate::sshkey::sshkey_fingerprint fail\0" as *const u8 as *const libc::c_char,
                );
            }
            printf(
                b"%u %s %s (PKCS11 key)\n\0" as *const u8 as *const libc::c_char,
                sshkey_size(*keys.offset(i as isize)),
                fp,
                crate::sshkey::sshkey_type(*keys.offset(i as isize)),
            );
            if log_level_get() as libc::c_int >= SYSLOG_LEVEL_VERBOSE as libc::c_int {
                printf(b"%s\n\0" as *const u8 as *const libc::c_char, ra);
            }
            libc::free(ra as *mut libc::c_void);
            libc::free(fp as *mut libc::c_void);
        } else {
            sshkey_write(*keys.offset(i as isize), stdout);
            libc::fprintf(
                stdout,
                b"%s%s\n\0" as *const u8 as *const libc::c_char,
                if **comments.offset(i as isize) as libc::c_int == '\0' as i32 {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    b" \0" as *const u8 as *const libc::c_char
                },
                *comments.offset(i as isize),
            );
        }
        libc::free(*comments.offset(i as isize) as *mut libc::c_void);
        crate::sshkey::sshkey_free(*keys.offset(i as isize));
        i += 1;
        i;
    }
    libc::free(comments as *mut libc::c_void);
    libc::free(keys as *mut libc::c_void);
    pkcs11_terminate();
    libc::exit(0 as libc::c_int);
}
unsafe extern "C" fn try_read_key(mut cpp: *mut *mut libc::c_char) -> *mut crate::sshkey::sshkey {
    let mut ret: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut r: libc::c_int = 0;
    ret = sshkey_new(KEY_UNSPEC as libc::c_int);
    if ret.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"try_read_key\0")).as_ptr(),
            891 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshkey_read(ret, cpp);
    if r == 0 as libc::c_int {
        return ret;
    }
    crate::sshkey::sshkey_free(ret);
    return 0 as *mut crate::sshkey::sshkey;
}
unsafe extern "C" fn fingerprint_one_key(
    mut public: *const crate::sshkey::sshkey,
    mut comment: *const libc::c_char,
) {
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ra: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut rep: sshkey_fp_rep = SSH_FP_DEFAULT;
    let mut fptype: libc::c_int = 0;
    fptype = if print_bubblebabble != 0 {
        1 as libc::c_int
    } else {
        fingerprint_hash
    };
    rep = (if print_bubblebabble != 0 {
        SSH_FP_BUBBLEBABBLE as libc::c_int
    } else {
        SSH_FP_DEFAULT as libc::c_int
    }) as sshkey_fp_rep;
    fp = crate::sshkey::sshkey_fingerprint(public, fptype, rep);
    ra = crate::sshkey::sshkey_fingerprint(public, fingerprint_hash, SSH_FP_RANDOMART);
    if fp.is_null() || ra.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"fingerprint_one_key\0"))
                .as_ptr(),
            911 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::sshkey::sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
        );
    }
    mprintf(
        b"%u %s %s (%s)\n\0" as *const u8 as *const libc::c_char,
        sshkey_size(public),
        fp,
        if !comment.is_null() {
            comment
        } else {
            b"no comment\0" as *const u8 as *const libc::c_char
        },
        crate::sshkey::sshkey_type(public),
    );
    if log_level_get() as libc::c_int >= SYSLOG_LEVEL_VERBOSE as libc::c_int {
        printf(b"%s\n\0" as *const u8 as *const libc::c_char, ra);
    }
    libc::free(ra as *mut libc::c_void);
    libc::free(fp as *mut libc::c_void);
}
unsafe extern "C" fn fingerprint_private(mut path: *const libc::c_char) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut privkey: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut pubkey: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut r: libc::c_int = 0;
    if libc::stat(identity_file.as_mut_ptr(), &mut st) == -(1 as libc::c_int) {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"fingerprint_private\0"))
                .as_ptr(),
            929 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: %s\0" as *const u8 as *const libc::c_char,
            path,
            libc::strerror(*libc::__errno_location()),
        );
    }
    r = sshkey_load_public(path, &mut pubkey, &mut comment);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"fingerprint_private\0"))
                .as_ptr(),
            931 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            ssh_err(r),
            b"load public \"%s\"\0" as *const u8 as *const libc::c_char,
            path,
        );
    }
    if pubkey.is_null() || comment.is_null() || *comment as libc::c_int == '\0' as i32 {
        libc::free(comment as *mut libc::c_void);
        r = sshkey_load_private(path, 0 as *const libc::c_char, &mut privkey, &mut comment);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"fingerprint_private\0",
                ))
                .as_ptr(),
                936 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                ssh_err(r),
                b"load private \"%s\"\0" as *const u8 as *const libc::c_char,
                path,
            );
        }
    }
    if pubkey.is_null() && privkey.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"fingerprint_private\0"))
                .as_ptr(),
            939 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s is not a key file.\0" as *const u8 as *const libc::c_char,
            path,
        );
    }
    fingerprint_one_key(if pubkey.is_null() { privkey } else { pubkey }, comment);
    crate::sshkey::sshkey_free(pubkey);
    crate::sshkey::sshkey_free(privkey);
    libc::free(comment as *mut libc::c_void);
}
unsafe extern "C" fn do_fingerprint(mut pw: *mut libc::passwd) {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut public: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut i: libc::c_int = 0;
    let mut invalid: libc::c_int = 1 as libc::c_int;
    let mut path: *const libc::c_char = 0 as *const libc::c_char;
    let mut lnum: u_long = 0 as libc::c_int as u_long;
    if have_identity == 0 {
        ask_filename(
            pw,
            b"Enter file in which the key is\0" as *const u8 as *const libc::c_char,
        );
    }
    path = identity_file.as_mut_ptr();
    if libc::strcmp(
        identity_file.as_mut_ptr(),
        b"-\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        f = stdin;
        path = b"(stdin)\0" as *const u8 as *const libc::c_char;
    } else {
        f = fopen(path, b"r\0" as *const u8 as *const libc::c_char);
        if f.is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_fingerprint\0"))
                    .as_ptr(),
                966 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s: %s: %s\0" as *const u8 as *const libc::c_char,
                __progname,
                path,
                libc::strerror(*libc::__errno_location()),
            );
        }
    }
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        lnum = lnum.wrapping_add(1);
        lnum;
        cp = line;
        *cp.offset(strcspn(cp, b"\n\0" as *const u8 as *const libc::c_char) as isize) =
            '\0' as i32 as libc::c_char;
        cp = line.offset(strspn(line, b" \t\0" as *const u8 as *const libc::c_char) as isize);
        if *cp as libc::c_int == '#' as i32 || *cp as libc::c_int == '\0' as i32 {
            continue;
        }
        if lnum == 1 as libc::c_int as libc::c_ulong
            && libc::strcmp(
                identity_file.as_mut_ptr(),
                b"-\0" as *const u8 as *const libc::c_char,
            ) != 0 as libc::c_int
            && !(strstr(cp, b"PRIVATE KEY\0" as *const u8 as *const libc::c_char)).is_null()
        {
            libc::free(line as *mut libc::c_void);
            fclose(f);
            fingerprint_private(path);
            libc::exit(0 as libc::c_int);
        }
        public = try_read_key(&mut cp);
        if public.is_null() {
            i = strtol(cp, &mut ep, 10 as libc::c_int) as libc::c_int;
            if i == 0 as libc::c_int
                || ep.is_null()
                || *ep as libc::c_int != ' ' as i32 && *ep as libc::c_int != '\t' as i32
            {
                let mut quoted: libc::c_int = 0 as libc::c_int;
                comment = cp;
                while *cp as libc::c_int != 0
                    && (quoted != 0
                        || *cp as libc::c_int != ' ' as i32 && *cp as libc::c_int != '\t' as i32)
                {
                    if *cp as libc::c_int == '\\' as i32
                        && *cp.offset(1 as libc::c_int as isize) as libc::c_int == '"' as i32
                    {
                        cp = cp.offset(1);
                        cp;
                    } else if *cp as libc::c_int == '"' as i32 {
                        quoted = (quoted == 0) as libc::c_int;
                    }
                    cp = cp.offset(1);
                    cp;
                }
                if *cp == 0 {
                    continue;
                }
                let fresh1 = cp;
                cp = cp.offset(1);
                *fresh1 = '\0' as i32 as libc::c_char;
            }
        }
        if public.is_null() && {
            public = try_read_key(&mut cp);
            public.is_null()
        } {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_fingerprint\0"))
                    .as_ptr(),
                1021 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"%s:%lu: not a public key\0" as *const u8 as *const libc::c_char,
                path,
                lnum,
            );
        } else {
            while *cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32 {
                cp = cp.offset(1);
                cp;
            }
            if *cp as libc::c_int != '\0' as i32 && *cp as libc::c_int != '#' as i32 {
                comment = cp;
            }
            fingerprint_one_key(public, comment);
            crate::sshkey::sshkey_free(public);
            invalid = 0 as libc::c_int;
        }
    }
    fclose(f);
    libc::free(line as *mut libc::c_void);
    if invalid != 0 {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_fingerprint\0"))
                .as_ptr(),
            1039 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s is not a public key file.\0" as *const u8 as *const libc::c_char,
            path,
        );
    }
    libc::exit(0 as libc::c_int);
}
unsafe extern "C" fn do_gen_all_hostkeys(mut pw: *mut libc::passwd) {
    let mut current_block: u64;
    let mut key_types: [C2RustUnnamed_1; 4] = [
        {
            let mut init = C2RustUnnamed_1 {
                key_type: b"rsa\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                key_type_display: b"crate::sshkey::RSA\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                path: b"/usr/local/etc/ssh_host_rsa_key\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_1 {
                key_type: b"ecdsa\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                key_type_display: b"ECDSA\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                path: b"/usr/local/etc/ssh_host_ecdsa_key\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_1 {
                key_type: b"ed25519\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                key_type_display: b"ED25519\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                path: b"/usr/local/etc/ssh_host_ed25519_key\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_1 {
                key_type: 0 as *mut libc::c_char,
                key_type_display: 0 as *mut libc::c_char,
                path: 0 as *mut libc::c_char,
            };
            init
        },
    ];
    let mut bits: u_int32_t = 0 as libc::c_int as u_int32_t;
    let mut first: libc::c_int = 0 as libc::c_int;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut private: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut public: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut comment: [libc::c_char; 1024] = [0; 1024];
    let mut prv_tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pub_tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut prv_file: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pub_file: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: libc::c_int = 0;
    let mut type_0: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    i = 0 as libc::c_int;
    while !(key_types[i as usize].key_type).is_null() {
        private = 0 as *mut crate::sshkey::sshkey;
        public = private;
        pub_file = 0 as *mut libc::c_char;
        prv_file = pub_file;
        pub_tmp = prv_file;
        prv_tmp = pub_tmp;
        crate::xmalloc::xasprintf(
            &mut prv_file as *mut *mut libc::c_char,
            b"%s%s\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
            key_types[i as usize].path,
        );
        if libc::stat(prv_file, &mut st) == 0 as libc::c_int {
            if st.st_size != 0 as libc::c_int as libc::c_long {
                current_block = 5360600777957461733;
            } else {
                current_block = 11650488183268122163;
            }
        } else if *libc::__errno_location() != 2 as libc::c_int {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"do_gen_all_hostkeys\0",
                ))
                .as_ptr(),
                1084 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Could not libc::stat %s: %s\0" as *const u8 as *const libc::c_char,
                key_types[i as usize].path,
                libc::strerror(*libc::__errno_location()),
            );
            current_block = 10340423718687530949;
        } else {
            current_block = 11650488183268122163;
        }
        match current_block {
            11650488183268122163 => {
                crate::xmalloc::xasprintf(
                    &mut prv_tmp as *mut *mut libc::c_char,
                    b"%s%s.XXXXXXXXXX\0" as *const u8 as *const libc::c_char,
                    identity_file.as_mut_ptr(),
                    key_types[i as usize].path,
                );
                crate::xmalloc::xasprintf(
                    &mut pub_tmp as *mut *mut libc::c_char,
                    b"%s%s.pub.XXXXXXXXXX\0" as *const u8 as *const libc::c_char,
                    identity_file.as_mut_ptr(),
                    key_types[i as usize].path,
                );
                crate::xmalloc::xasprintf(
                    &mut pub_file as *mut *mut libc::c_char,
                    b"%s%s.pub\0" as *const u8 as *const libc::c_char,
                    identity_file.as_mut_ptr(),
                    key_types[i as usize].path,
                );
                if first == 0 as libc::c_int {
                    first = 1 as libc::c_int;
                    printf(
                        b"%s: generating new host keys: \0" as *const u8 as *const libc::c_char,
                        __progname,
                    );
                }
                printf(
                    b"%s \0" as *const u8 as *const libc::c_char,
                    key_types[i as usize].key_type_display,
                );
                libc::fflush(stdout);
                type_0 = sshkey_type_from_name(key_types[i as usize].key_type);
                fd = _ssh_mkstemp(prv_tmp);
                if fd == -(1 as libc::c_int) {
                    crate::log::sshlog(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"do_gen_all_hostkeys\0",
                        ))
                        .as_ptr(),
                        1108 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Could not save your private key in %s: %s\0" as *const u8
                            as *const libc::c_char,
                        prv_tmp,
                        libc::strerror(*libc::__errno_location()),
                    );
                    current_block = 10340423718687530949;
                } else {
                    close(fd);
                    bits = 0 as libc::c_int as u_int32_t;
                    type_bits_valid(type_0, 0 as *const libc::c_char, &mut bits);
                    r = sshkey_generate(type_0, bits, &mut private);
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                b"do_gen_all_hostkeys\0",
                            ))
                            .as_ptr(),
                            1115 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"sshkey_generate failed\0" as *const u8 as *const libc::c_char,
                        );
                        current_block = 10340423718687530949;
                    } else {
                        r = crate::sshkey::sshkey_from_private(private, &mut public);
                        if r != 0 as libc::c_int {
                            sshfatal(
                                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                    b"do_gen_all_hostkeys\0",
                                ))
                                .as_ptr(),
                                1119 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                ssh_err(r),
                                b"crate::sshkey::sshkey_from_private\0" as *const u8
                                    as *const libc::c_char,
                            );
                        }
                        libc::snprintf(
                            comment.as_mut_ptr(),
                            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
                            b"%s@%s\0" as *const u8 as *const libc::c_char,
                            (*pw).pw_name,
                            hostname.as_mut_ptr(),
                        );
                        r = sshkey_save_private(
                            private,
                            prv_tmp,
                            b"\0" as *const u8 as *const libc::c_char,
                            comment.as_mut_ptr(),
                            private_key_format,
                            openssh_format_cipher,
                            rounds,
                        );
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                    b"do_gen_all_hostkeys\0",
                                ))
                                .as_ptr(),
                                1125 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"Saving key \"%s\" failed\0" as *const u8 as *const libc::c_char,
                                prv_tmp,
                            );
                            current_block = 10340423718687530949;
                        } else {
                            fd = _ssh_mkstemp(pub_tmp);
                            if fd == -(1 as libc::c_int) {
                                crate::log::sshlog(
                                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                        b"do_gen_all_hostkeys\0",
                                    ))
                                    .as_ptr(),
                                    1130 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"Could not save your public key in %s: %s\0" as *const u8
                                        as *const libc::c_char,
                                    pub_tmp,
                                    libc::strerror(*libc::__errno_location()),
                                );
                                current_block = 10340423718687530949;
                            } else {
                                libc::fchmod(fd, 0o644 as libc::c_int as __mode_t);
                                close(fd);
                                r = sshkey_save_public(public, pub_tmp, comment.as_mut_ptr());
                                if r != 0 as libc::c_int {
                                    crate::log::sshlog(
                                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                            b"do_gen_all_hostkeys\0",
                                        ))
                                        .as_ptr(),
                                        1137 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        ssh_err(r),
                                        b"Unable to save public key to %s\0" as *const u8
                                            as *const libc::c_char,
                                        identity_file.as_mut_ptr(),
                                    );
                                    current_block = 10340423718687530949;
                                } else if rename(pub_tmp, pub_file) != 0 as libc::c_int {
                                    crate::log::sshlog(
                                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                            b"do_gen_all_hostkeys\0",
                                        ))
                                        .as_ptr(),
                                        1144 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"Unable to move %s into position: %s\0" as *const u8
                                            as *const libc::c_char,
                                        pub_file,
                                        libc::strerror(*libc::__errno_location()),
                                    );
                                    current_block = 10340423718687530949;
                                } else if rename(prv_tmp, prv_file) != 0 as libc::c_int {
                                    crate::log::sshlog(
                                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                            b"do_gen_all_hostkeys\0",
                                        ))
                                        .as_ptr(),
                                        1149 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"Unable to move %s into position: %s\0" as *const u8
                                            as *const libc::c_char,
                                        key_types[i as usize].path,
                                        libc::strerror(*libc::__errno_location()),
                                    );
                                    current_block = 10340423718687530949;
                                } else {
                                    current_block = 5360600777957461733;
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        match current_block {
            10340423718687530949 => {
                first = 0 as libc::c_int;
            }
            _ => {}
        }
        crate::sshkey::sshkey_free(private);
        crate::sshkey::sshkey_free(public);
        libc::free(prv_tmp as *mut libc::c_void);
        libc::free(pub_tmp as *mut libc::c_void);
        libc::free(prv_file as *mut libc::c_void);
        libc::free(pub_file as *mut libc::c_void);
        i += 1;
        i;
    }
    if first != 0 as libc::c_int {
        printf(b"\n\0" as *const u8 as *const libc::c_char);
    }
}
unsafe extern "C" fn known_hosts_hash(
    mut l: *mut hostkey_foreach_line,
    mut _ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut ctx: *mut known_hosts_ctx = _ctx as *mut known_hosts_ctx;
    let mut hashed: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hosts: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ohosts: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut has_wild: libc::c_int = (!((*l).hosts).is_null()
        && strcspn((*l).hosts, b"*?!\0" as *const u8 as *const libc::c_char) != strlen((*l).hosts))
        as libc::c_int;
    let mut was_hashed: libc::c_int = (!((*l).hosts).is_null()
        && *((*l).hosts).offset(0 as libc::c_int as isize) as libc::c_int == '|' as i32)
        as libc::c_int;
    match (*l).status {
        0 | 3 => {
            if was_hashed != 0 || has_wild != 0 || (*l).marker != MRK_NONE as libc::c_int {
                libc::fprintf(
                    (*ctx).out,
                    b"%s\n\0" as *const u8 as *const libc::c_char,
                    (*l).line,
                );
                if has_wild != 0 && (*ctx).find_host == 0 {
                    crate::log::sshlog(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                            b"known_hosts_hash\0",
                        ))
                        .as_ptr(),
                        1197 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        0 as *const libc::c_char,
                        b"%s:%lu: ignoring host name with wildcard: %.64s\0" as *const u8
                            as *const libc::c_char,
                        (*l).path,
                        (*l).linenum,
                        (*l).hosts,
                    );
                }
                return 0 as libc::c_int;
            }
            hosts = crate::xmalloc::xstrdup((*l).hosts);
            ohosts = hosts;
            loop {
                cp = strsep(&mut hosts, b",\0" as *const u8 as *const libc::c_char);
                if !(!cp.is_null() && *cp as libc::c_int != '\0' as i32) {
                    break;
                }
                lowercase(cp);
                hashed = host_hash(cp, 0 as *const libc::c_char, 0 as libc::c_int as u_int);
                if hashed.is_null() {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                            b"known_hosts_hash\0",
                        ))
                        .as_ptr(),
                        1209 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"hash_host failed\0" as *const u8 as *const libc::c_char,
                    );
                }
                libc::fprintf(
                    (*ctx).out,
                    b"%s %s\n\0" as *const u8 as *const libc::c_char,
                    hashed,
                    (*l).rawkey,
                );
                libc::free(hashed as *mut libc::c_void);
                (*ctx).has_unhashed = 1 as libc::c_int;
            }
            libc::free(ohosts as *mut libc::c_void);
            return 0 as libc::c_int;
        }
        1 => {
            (*ctx).invalid = 1 as libc::c_int;
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"known_hosts_hash\0"))
                    .as_ptr(),
                1219 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"%s:%lu: invalid line\0" as *const u8 as *const libc::c_char,
                (*l).path,
                (*l).linenum,
            );
        }
        _ => {}
    }
    libc::fprintf(
        (*ctx).out,
        b"%s\n\0" as *const u8 as *const libc::c_char,
        (*l).line,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn known_hosts_find_delete(
    mut l: *mut hostkey_foreach_line,
    mut _ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut ctx: *mut known_hosts_ctx = _ctx as *mut known_hosts_ctx;
    let mut rep: sshkey_fp_rep = SSH_FP_DEFAULT;
    let mut fptype: libc::c_int = 0;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ra: *mut libc::c_char = 0 as *mut libc::c_char;
    fptype = if print_bubblebabble != 0 {
        1 as libc::c_int
    } else {
        fingerprint_hash
    };
    rep = (if print_bubblebabble != 0 {
        SSH_FP_BUBBLEBABBLE as libc::c_int
    } else {
        SSH_FP_DEFAULT as libc::c_int
    }) as sshkey_fp_rep;
    if (*l).status == 3 as libc::c_int as libc::c_uint {
        if (*ctx).delete_host != 0 {
            if (*l).marker != MRK_NONE as libc::c_int {
                libc::fprintf(
                    (*ctx).out,
                    b"%s\n\0" as *const u8 as *const libc::c_char,
                    (*l).line,
                );
            } else {
                (*ctx).found_key = 1 as libc::c_int;
                if quiet == 0 {
                    printf(
                        b"# Host %s found: line %lu\n\0" as *const u8 as *const libc::c_char,
                        (*ctx).host,
                        (*l).linenum,
                    );
                }
            }
            return 0 as libc::c_int;
        } else if (*ctx).find_host != 0 {
            (*ctx).found_key = 1 as libc::c_int;
            if quiet == 0 {
                printf(
                    b"# Host %s found: line %lu %s\n\0" as *const u8 as *const libc::c_char,
                    (*ctx).host,
                    (*l).linenum,
                    if (*l).marker == MRK_CA as libc::c_int {
                        b"CA\0" as *const u8 as *const libc::c_char
                    } else if (*l).marker == MRK_REVOKE as libc::c_int {
                        b"REVOKED\0" as *const u8 as *const libc::c_char
                    } else {
                        b"\0" as *const u8 as *const libc::c_char
                    },
                );
            }
            if (*ctx).hash_hosts != 0 {
                known_hosts_hash(l, ctx as *mut libc::c_void);
            } else if print_fingerprint != 0 {
                fp = crate::sshkey::sshkey_fingerprint((*l).key, fptype, rep);
                ra =
                    crate::sshkey::sshkey_fingerprint((*l).key, fingerprint_hash, SSH_FP_RANDOMART);
                if fp.is_null() || ra.is_null() {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                            b"known_hosts_find_delete\0",
                        ))
                        .as_ptr(),
                        1272 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"crate::sshkey::sshkey_fingerprint failed\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                mprintf(
                    b"%s %s %s%s%s\n\0" as *const u8 as *const libc::c_char,
                    (*ctx).host,
                    crate::sshkey::sshkey_type((*l).key),
                    fp,
                    if *((*l).comment).offset(0 as libc::c_int as isize) as libc::c_int != 0 {
                        b" \0" as *const u8 as *const libc::c_char
                    } else {
                        b"\0" as *const u8 as *const libc::c_char
                    },
                    (*l).comment,
                );
                if log_level_get() as libc::c_int >= SYSLOG_LEVEL_VERBOSE as libc::c_int {
                    printf(b"%s\n\0" as *const u8 as *const libc::c_char, ra);
                }
                libc::free(ra as *mut libc::c_void);
                libc::free(fp as *mut libc::c_void);
            } else {
                libc::fprintf(
                    (*ctx).out,
                    b"%s\n\0" as *const u8 as *const libc::c_char,
                    (*l).line,
                );
            }
            return 0 as libc::c_int;
        }
    } else if (*ctx).delete_host != 0 {
        if (*l).status == 1 as libc::c_int as libc::c_uint {
            (*ctx).invalid = 1 as libc::c_int;
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"known_hosts_find_delete\0",
                ))
                .as_ptr(),
                1289 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"%s:%lu: invalid line\0" as *const u8 as *const libc::c_char,
                (*l).path,
                (*l).linenum,
            );
        }
        libc::fprintf(
            (*ctx).out,
            b"%s\n\0" as *const u8 as *const libc::c_char,
            (*l).line,
        );
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn do_known_hosts(
    mut pw: *mut libc::passwd,
    mut name: *const libc::c_char,
    mut find_host: libc::c_int,
    mut delete_host: libc::c_int,
    mut hash_hosts: libc::c_int,
) {
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: [libc::c_char; 4096] = [0; 4096];
    let mut old: [libc::c_char; 4096] = [0; 4096];
    let mut r: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    let mut inplace: libc::c_int = 0 as libc::c_int;
    let mut ctx: known_hosts_ctx = known_hosts_ctx {
        host: 0 as *const libc::c_char,
        out: 0 as *mut libc::FILE,
        has_unhashed: 0,
        found_key: 0,
        invalid: 0,
        hash_hosts: 0,
        find_host: 0,
        delete_host: 0,
    };
    let mut foreach_options: u_int = 0;
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    if have_identity == 0 {
        cp = tilde_expand_filename(
            b"~/.ssh/known_hosts\0" as *const u8 as *const libc::c_char,
            (*pw).pw_uid,
        );
        if strlcpy(
            identity_file.as_mut_ptr(),
            cp,
            ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        ) >= ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
        {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                    .as_ptr(),
                1310 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Specified known hosts path too long\0" as *const u8 as *const libc::c_char,
            );
        }
        libc::free(cp as *mut libc::c_void);
        have_identity = 1 as libc::c_int;
    }
    if libc::stat(identity_file.as_mut_ptr(), &mut sb) != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                .as_ptr(),
            1315 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Cannot libc::stat %s: %s\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
            libc::strerror(*libc::__errno_location()),
        );
    }
    memset(
        &mut ctx as *mut known_hosts_ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<known_hosts_ctx>() as libc::c_ulong,
    );
    ctx.out = stdout;
    ctx.host = name;
    ctx.hash_hosts = hash_hosts;
    ctx.find_host = find_host;
    ctx.delete_host = delete_host;
    if find_host == 0 && (hash_hosts != 0 || delete_host != 0) {
        if strlcpy(
            tmp.as_mut_ptr(),
            identity_file.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        ) >= ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
            || strlcat(
                tmp.as_mut_ptr(),
                b".XXXXXXXXXX\0" as *const u8 as *const libc::c_char,
                ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
            ) >= ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
            || strlcpy(
                old.as_mut_ptr(),
                identity_file.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
            ) >= ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
            || strlcat(
                old.as_mut_ptr(),
                b".old\0" as *const u8 as *const libc::c_char,
                ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
            ) >= ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
        {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                    .as_ptr(),
                1333 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"known_hosts path too long\0" as *const u8 as *const libc::c_char,
            );
        }
        libc::umask(0o77 as libc::c_int as __mode_t);
        fd = _ssh_mkstemp(tmp.as_mut_ptr());
        if fd == -(1 as libc::c_int) {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                    .as_ptr(),
                1336 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"mkstemp: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        ctx.out = libc::fdopen(fd, b"w\0" as *const u8 as *const libc::c_char);
        if (ctx.out).is_null() {
            oerrno = *libc::__errno_location();
            unlink(tmp.as_mut_ptr());
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                    .as_ptr(),
                1340 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"libc::fdopen: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(oerrno),
            );
        }
        libc::fchmod(fd, sb.st_mode & 0o644 as libc::c_int as libc::c_uint);
        inplace = 1 as libc::c_int;
    }
    foreach_options = (if find_host != 0 {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    }) as u_int;
    foreach_options |= (if print_fingerprint != 0 {
        (1 as libc::c_int) << 1 as libc::c_int
    } else {
        0 as libc::c_int
    }) as libc::c_uint;
    r = hostkeys_foreach(
        identity_file.as_mut_ptr(),
        if find_host != 0 || hash_hosts == 0 {
            Some(
                known_hosts_find_delete
                    as unsafe extern "C" fn(
                        *mut hostkey_foreach_line,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            )
        } else {
            Some(
                known_hosts_hash
                    as unsafe extern "C" fn(
                        *mut hostkey_foreach_line,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            )
        },
        &mut ctx as *mut known_hosts_ctx as *mut libc::c_void,
        name,
        0 as *const libc::c_char,
        foreach_options,
        0 as libc::c_int as u_int,
    );
    if r != 0 as libc::c_int {
        if inplace != 0 {
            unlink(tmp.as_mut_ptr());
        }
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                .as_ptr(),
            1353 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"hostkeys_foreach\0" as *const u8 as *const libc::c_char,
        );
    }
    if inplace != 0 {
        fclose(ctx.out);
    }
    if ctx.invalid != 0 {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                .as_ptr(),
            1360 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s is not a valid known_hosts file.\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
        );
        if inplace != 0 {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                    .as_ptr(),
                1363 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Not replacing existing known_hosts file because of errors\0" as *const u8
                    as *const libc::c_char,
            );
            unlink(tmp.as_mut_ptr());
        }
        libc::exit(1 as libc::c_int);
    } else if delete_host != 0 && ctx.found_key == 0 {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                .as_ptr(),
            1368 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Host %s not found in %s\0" as *const u8 as *const libc::c_char,
            name,
            identity_file.as_mut_ptr(),
        );
        if inplace != 0 {
            unlink(tmp.as_mut_ptr());
        }
    } else if inplace != 0 {
        if unlink(old.as_mut_ptr()) == -(1 as libc::c_int)
            && *libc::__errno_location() != 2 as libc::c_int
        {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                    .as_ptr(),
                1374 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unlink %.100s: %s\0" as *const u8 as *const libc::c_char,
                old.as_mut_ptr(),
                libc::strerror(*libc::__errno_location()),
            );
        }
        if link(identity_file.as_mut_ptr(), old.as_mut_ptr()) == -(1 as libc::c_int) {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                    .as_ptr(),
                1377 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"link %.100s to %.100s: %s\0" as *const u8 as *const libc::c_char,
                identity_file.as_mut_ptr(),
                old.as_mut_ptr(),
                libc::strerror(*libc::__errno_location()),
            );
        }
        if rename(tmp.as_mut_ptr(), identity_file.as_mut_ptr()) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                    .as_ptr(),
                1381 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"rename\"%s\" to \"%s\": %s\0" as *const u8 as *const libc::c_char,
                tmp.as_mut_ptr(),
                identity_file.as_mut_ptr(),
                libc::strerror(*libc::__errno_location()),
            );
            unlink(tmp.as_mut_ptr());
            unlink(old.as_mut_ptr());
            libc::exit(1 as libc::c_int);
        }
        printf(
            b"%s updated.\n\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
        );
        printf(
            b"Original contents retained as %s\n\0" as *const u8 as *const libc::c_char,
            old.as_mut_ptr(),
        );
        if ctx.has_unhashed != 0 {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                    .as_ptr(),
                1390 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"WARNING: %s contains unhashed entries\0" as *const u8 as *const libc::c_char,
                old.as_mut_ptr(),
            );
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_known_hosts\0"))
                    .as_ptr(),
                1392 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Delete this file to ensure privacy of hostnames\0" as *const u8
                    as *const libc::c_char,
            );
        }
    }
    libc::exit((find_host != 0 && ctx.found_key == 0) as libc::c_int);
}
unsafe extern "C" fn do_change_passphrase(mut pw: *mut libc::passwd) {
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut old_passphrase: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut passphrase1: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut passphrase2: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut private: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut r: libc::c_int = 0;
    if have_identity == 0 {
        ask_filename(
            pw,
            b"Enter file in which the key is\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::stat(identity_file.as_mut_ptr(), &mut st) == -(1 as libc::c_int) {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"do_change_passphrase\0"))
                .as_ptr(),
            1415 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: %s\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
            libc::strerror(*libc::__errno_location()),
        );
    }
    r = sshkey_load_private(
        identity_file.as_mut_ptr(),
        b"\0" as *const u8 as *const libc::c_char,
        &mut private,
        &mut comment,
    );
    let mut current_block_10: u64;
    if r == -(43 as libc::c_int) {
        if !identity_passphrase.is_null() {
            old_passphrase = crate::xmalloc::xstrdup(identity_passphrase);
        } else {
            old_passphrase = read_passphrase(
                b"Enter old passphrase: \0" as *const u8 as *const libc::c_char,
                0x2 as libc::c_int,
            );
        }
        r = sshkey_load_private(
            identity_file.as_mut_ptr(),
            old_passphrase,
            &mut private,
            &mut comment,
        );
        freezero(old_passphrase as *mut libc::c_void, strlen(old_passphrase));
        if r != 0 as libc::c_int {
            current_block_10 = 12745785064350241450;
        } else {
            current_block_10 = 13586036798005543211;
        }
    } else if r != 0 as libc::c_int {
        current_block_10 = 12745785064350241450;
    } else {
        current_block_10 = 13586036798005543211;
    }
    match current_block_10 {
        13586036798005543211 => {}
        _ => {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"do_change_passphrase\0",
                ))
                .as_ptr(),
                1432 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"Failed to load key %s\0" as *const u8 as *const libc::c_char,
                identity_file.as_mut_ptr(),
            );
        }
    }
    if !comment.is_null() {
        mprintf(
            b"Key has comment '%s'\n\0" as *const u8 as *const libc::c_char,
            comment,
        );
    }
    if !identity_new_passphrase.is_null() {
        passphrase1 = crate::xmalloc::xstrdup(identity_new_passphrase);
        passphrase2 = 0 as *mut libc::c_char;
    } else {
        passphrase1 = read_passphrase(
            b"Enter new passphrase (empty for no passphrase): \0" as *const u8
                as *const libc::c_char,
            0x2 as libc::c_int,
        );
        passphrase2 = read_passphrase(
            b"Enter same passphrase again: \0" as *const u8 as *const libc::c_char,
            0x2 as libc::c_int,
        );
        if libc::strcmp(passphrase1, passphrase2) != 0 as libc::c_int {
            explicit_bzero(passphrase1 as *mut libc::c_void, strlen(passphrase1));
            explicit_bzero(passphrase2 as *mut libc::c_void, strlen(passphrase2));
            libc::free(passphrase1 as *mut libc::c_void);
            libc::free(passphrase2 as *mut libc::c_void);
            printf(
                b"Pass phrases do not match.  Try again.\n\0" as *const u8 as *const libc::c_char,
            );
            libc::exit(1 as libc::c_int);
        }
        freezero(passphrase2 as *mut libc::c_void, strlen(passphrase2));
    }
    r = sshkey_save_private(
        private,
        identity_file.as_mut_ptr(),
        passphrase1,
        comment,
        private_key_format,
        openssh_format_cipher,
        rounds,
    );
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"do_change_passphrase\0"))
                .as_ptr(),
            1464 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"Saving key \"%s\" failed\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
        );
        freezero(passphrase1 as *mut libc::c_void, strlen(passphrase1));
        crate::sshkey::sshkey_free(private);
        libc::free(comment as *mut libc::c_void);
        libc::exit(1 as libc::c_int);
    }
    freezero(passphrase1 as *mut libc::c_void, strlen(passphrase1));
    crate::sshkey::sshkey_free(private);
    libc::free(comment as *mut libc::c_void);
    printf(
        b"Your identification has been saved with the new passphrase.\n\0" as *const u8
            as *const libc::c_char,
    );
    libc::exit(0 as libc::c_int);
}
unsafe extern "C" fn do_print_resource_record(
    mut _pw: *mut libc::passwd,
    mut fname: *mut libc::c_char,
    mut hname: *mut libc::c_char,
    mut print_generic: libc::c_int,
    mut opts: *const *mut libc::c_char,
    mut nopts: size_t,
) -> libc::c_int {
    let mut public: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut r: libc::c_int = 0;
    let mut hash: libc::c_int = -(1 as libc::c_int);
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < nopts {
        if strncasecmp(
            *opts.offset(i as isize),
            b"hashalg=\0" as *const u8 as *const libc::c_char,
            8 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            hash = ssh_digest_alg_by_name(
                (*opts.offset(i as isize)).offset(8 as libc::c_int as isize),
            );
            if hash == -(1 as libc::c_int) {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                        b"do_print_resource_record\0",
                    ))
                    .as_ptr(),
                    1495 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Unsupported hash algorithm\0" as *const u8 as *const libc::c_char,
                );
            }
        } else {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"do_print_resource_record\0",
                ))
                .as_ptr(),
                1497 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Invalid option \"%s\"\0" as *const u8 as *const libc::c_char,
                *opts.offset(i as isize),
            );
            return -(10 as libc::c_int);
        }
        i = i.wrapping_add(1);
        i;
    }
    if fname.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"do_print_resource_record\0",
            ))
            .as_ptr(),
            1502 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no filename\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::stat(fname, &mut st) == -(1 as libc::c_int) {
        if *libc::__errno_location() == 2 as libc::c_int {
            return 0 as libc::c_int;
        }
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"do_print_resource_record\0",
            ))
            .as_ptr(),
            1506 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: %s\0" as *const u8 as *const libc::c_char,
            fname,
            libc::strerror(*libc::__errno_location()),
        );
    }
    r = sshkey_load_public(fname, &mut public, &mut comment);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"do_print_resource_record\0",
            ))
            .as_ptr(),
            1509 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"Failed to read v2 public key from \"%s\"\0" as *const u8 as *const libc::c_char,
            fname,
        );
    }
    export_dns_rr(hname, public, stdout, print_generic, hash);
    crate::sshkey::sshkey_free(public);
    libc::free(comment as *mut libc::c_void);
    return 1 as libc::c_int;
}
unsafe extern "C" fn do_change_comment(
    mut pw: *mut libc::passwd,
    mut identity_comment: *const libc::c_char,
) {
    let mut new_comment: [libc::c_char; 1024] = [0; 1024];
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut passphrase: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut private: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut public: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut r: libc::c_int = 0;
    if have_identity == 0 {
        ask_filename(
            pw,
            b"Enter file in which the key is\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::stat(identity_file.as_mut_ptr(), &mut st) == -(1 as libc::c_int) {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"do_change_comment\0"))
                .as_ptr(),
            1531 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: %s\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
            libc::strerror(*libc::__errno_location()),
        );
    }
    r = sshkey_load_private(
        identity_file.as_mut_ptr(),
        b"\0" as *const u8 as *const libc::c_char,
        &mut private,
        &mut comment,
    );
    if r == 0 as libc::c_int {
        passphrase = crate::xmalloc::xstrdup(b"\0" as *const u8 as *const libc::c_char);
    } else if r != -(43 as libc::c_int) {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"do_change_comment\0"))
                .as_ptr(),
            1536 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"Cannot load private key \"%s\"\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
        );
    } else {
        if !identity_passphrase.is_null() {
            passphrase = crate::xmalloc::xstrdup(identity_passphrase);
        } else if !identity_new_passphrase.is_null() {
            passphrase = crate::xmalloc::xstrdup(identity_new_passphrase);
        } else {
            passphrase = read_passphrase(
                b"Enter passphrase: \0" as *const u8 as *const libc::c_char,
                0x2 as libc::c_int,
            );
        }
        r = sshkey_load_private(
            identity_file.as_mut_ptr(),
            passphrase,
            &mut private,
            &mut comment,
        );
        if r != 0 as libc::c_int {
            freezero(passphrase as *mut libc::c_void, strlen(passphrase));
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"do_change_comment\0"))
                    .as_ptr(),
                1550 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"Cannot load private key \"%s\"\0" as *const u8 as *const libc::c_char,
                identity_file.as_mut_ptr(),
            );
        }
    }
    if (*private).type_0 != KEY_ED25519 as libc::c_int
        && (*private).type_0 != KEY_XMSS as libc::c_int
        && private_key_format != SSHKEY_PRIVATE_OPENSSH as libc::c_int
    {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"do_change_comment\0"))
                .as_ptr(),
            1557 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Comments are only supported for keys stored in the new format (-o).\0" as *const u8
                as *const libc::c_char,
        );
        explicit_bzero(passphrase as *mut libc::c_void, strlen(passphrase));
        crate::sshkey::sshkey_free(private);
        libc::exit(1 as libc::c_int);
    }
    if !comment.is_null() {
        printf(
            b"Old comment: %s\n\0" as *const u8 as *const libc::c_char,
            comment,
        );
    } else {
        printf(b"No existing comment\n\0" as *const u8 as *const libc::c_char);
    }
    if !identity_comment.is_null() {
        strlcpy(
            new_comment.as_mut_ptr(),
            identity_comment,
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        );
    } else {
        printf(b"New comment: \0" as *const u8 as *const libc::c_char);
        libc::fflush(stdout);
        if (fgets(
            new_comment.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong as libc::c_int,
            stdin,
        ))
        .is_null()
        {
            explicit_bzero(passphrase as *mut libc::c_void, strlen(passphrase));
            crate::sshkey::sshkey_free(private);
            libc::exit(1 as libc::c_int);
        }
        new_comment[strcspn(
            new_comment.as_mut_ptr(),
            b"\n\0" as *const u8 as *const libc::c_char,
        ) as usize] = '\0' as i32 as libc::c_char;
    }
    if !comment.is_null() && libc::strcmp(comment, new_comment.as_mut_ptr()) == 0 as libc::c_int {
        printf(b"No change to comment\n\0" as *const u8 as *const libc::c_char);
        libc::free(passphrase as *mut libc::c_void);
        crate::sshkey::sshkey_free(private);
        libc::free(comment as *mut libc::c_void);
        libc::exit(0 as libc::c_int);
    }
    r = sshkey_save_private(
        private,
        identity_file.as_mut_ptr(),
        passphrase,
        new_comment.as_mut_ptr(),
        private_key_format,
        openssh_format_cipher,
        rounds,
    );
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"do_change_comment\0"))
                .as_ptr(),
            1591 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"Saving key \"%s\" failed\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
        );
        freezero(passphrase as *mut libc::c_void, strlen(passphrase));
        crate::sshkey::sshkey_free(private);
        libc::free(comment as *mut libc::c_void);
        libc::exit(1 as libc::c_int);
    }
    freezero(passphrase as *mut libc::c_void, strlen(passphrase));
    r = crate::sshkey::sshkey_from_private(private, &mut public);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"do_change_comment\0"))
                .as_ptr(),
            1599 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"crate::sshkey::sshkey_from_private\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshkey::sshkey_free(private);
    strlcat(
        identity_file.as_mut_ptr(),
        b".pub\0" as *const u8 as *const libc::c_char,
        ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
    );
    r = sshkey_save_public(public, identity_file.as_mut_ptr(), new_comment.as_mut_ptr());
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"do_change_comment\0"))
                .as_ptr(),
            1604 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"Unable to save public key to %s\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
        );
    }
    crate::sshkey::sshkey_free(public);
    libc::free(comment as *mut libc::c_void);
    if strlen(new_comment.as_mut_ptr()) > 0 as libc::c_int as libc::c_ulong {
        printf(
            b"Comment '%s' applied\n\0" as *const u8 as *const libc::c_char,
            new_comment.as_mut_ptr(),
        );
    } else {
        printf(b"Comment removed\n\0" as *const u8 as *const libc::c_char);
    }
    libc::exit(0 as libc::c_int);
}
unsafe extern "C" fn cert_ext_add(
    mut key: *const libc::c_char,
    mut value: *const libc::c_char,
    mut iscrit: libc::c_int,
) {
    cert_ext = xreallocarray(
        cert_ext as *mut libc::c_void,
        ncert_ext.wrapping_add(1 as libc::c_int as libc::c_ulong),
        ::core::mem::size_of::<cert_ext>() as libc::c_ulong,
    ) as *mut cert_ext;
    let ref mut fresh2 = (*cert_ext.offset(ncert_ext as isize)).key;
    *fresh2 = crate::xmalloc::xstrdup(key);
    let ref mut fresh3 = (*cert_ext.offset(ncert_ext as isize)).val;
    *fresh3 = if value.is_null() {
        0 as *mut libc::c_char
    } else {
        crate::xmalloc::xstrdup(value)
    };
    (*cert_ext.offset(ncert_ext as isize)).crit = iscrit;
    ncert_ext = ncert_ext.wrapping_add(1);
    ncert_ext;
}
unsafe extern "C" fn cert_ext_cmp(
    mut _a: *const libc::c_void,
    mut _b: *const libc::c_void,
) -> libc::c_int {
    let mut a: *const cert_ext = _a as *const cert_ext;
    let mut b: *const cert_ext = _b as *const cert_ext;
    let mut r: libc::c_int = 0;
    if (*a).crit != (*b).crit {
        return if (*a).crit < (*b).crit {
            -(1 as libc::c_int)
        } else {
            1 as libc::c_int
        };
    }
    r = libc::strcmp((*a).key, (*b).key);
    if r != 0 as libc::c_int {
        return r;
    }
    if ((*a).val == 0 as *mut libc::c_void as *mut libc::c_char) as libc::c_int
        != ((*b).val == 0 as *mut libc::c_void as *mut libc::c_char) as libc::c_int
    {
        return if ((*a).val).is_null() {
            -(1 as libc::c_int)
        } else {
            1 as libc::c_int
        };
    }
    if !((*a).val).is_null() && {
        r = libc::strcmp((*a).val, (*b).val);
        r != 0 as libc::c_int
    } {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn prepare_options_buf(
    mut c: *mut crate::sshbuf::sshbuf,
    mut which: libc::c_int,
) {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut i: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut ext: *const cert_ext = 0 as *const cert_ext;
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"prepare_options_buf\0"))
                .as_ptr(),
            1656 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_reset(c);
    i = 0 as libc::c_int as size_t;
    while i < ncert_ext {
        ext = &mut *cert_ext.offset(i as isize) as *mut cert_ext;
        if !((*ext).crit != 0 && which & 2 as libc::c_int != 0
            || (*ext).crit == 0 && which & 1 as libc::c_int != 0)
        {
            if ((*ext).val).is_null() {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"prepare_options_buf\0",
                    ))
                    .as_ptr(),
                    1665 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"%s\0" as *const u8 as *const libc::c_char,
                    (*ext).key,
                );
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(c, (*ext).key);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_string(
                        c,
                        0 as *const libc::c_void,
                        0 as libc::c_int as size_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"prepare_options_buf\0",
                        ))
                        .as_ptr(),
                        1668 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"prepare flag\0" as *const u8 as *const libc::c_char,
                    );
                }
            } else {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"prepare_options_buf\0",
                    ))
                    .as_ptr(),
                    1671 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"%s=%s\0" as *const u8 as *const libc::c_char,
                    (*ext).key,
                    (*ext).val,
                );
                crate::sshbuf::sshbuf_reset(b);
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(c, (*ext).key);
                if r != 0 as libc::c_int
                    || {
                        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(b, (*ext).val);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_stringb(c, b);
                        r != 0 as libc::c_int
                    }
                {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"prepare_options_buf\0",
                        ))
                        .as_ptr(),
                        1676 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"prepare k/v\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    crate::sshbuf::sshbuf_free(b);
}
unsafe extern "C" fn finalise_cert_exts() {
    if !certflags_command.is_null() {
        cert_ext_add(
            b"force-command\0" as *const u8 as *const libc::c_char,
            certflags_command,
            1 as libc::c_int,
        );
    }
    if !certflags_src_addr.is_null() {
        cert_ext_add(
            b"source-address\0" as *const u8 as *const libc::c_char,
            certflags_src_addr,
            1 as libc::c_int,
        );
    }
    if certflags_flags & ((1 as libc::c_int) << 6 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        cert_ext_add(
            b"verify-required\0" as *const u8 as *const libc::c_char,
            0 as *const libc::c_char,
            1 as libc::c_int,
        );
    }
    if certflags_flags & 1 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint {
        cert_ext_add(
            b"permit-X11-forwarding\0" as *const u8 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
        );
    }
    if certflags_flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        cert_ext_add(
            b"permit-agent-forwarding\0" as *const u8 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
        );
    }
    if certflags_flags & ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        cert_ext_add(
            b"permit-port-forwarding\0" as *const u8 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
        );
    }
    if certflags_flags & ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        cert_ext_add(
            b"permit-pty\0" as *const u8 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
        );
    }
    if certflags_flags & ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        cert_ext_add(
            b"permit-user-rc\0" as *const u8 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
        );
    }
    if certflags_flags & ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        cert_ext_add(
            b"no-touch-required\0" as *const u8 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
        );
    }
    if ncert_ext > 0 as libc::c_int as libc::c_ulong {
        qsort(
            cert_ext as *mut libc::c_void,
            ncert_ext,
            ::core::mem::size_of::<cert_ext>() as libc::c_ulong,
            Some(
                cert_ext_cmp
                    as unsafe extern "C" fn(
                        *const libc::c_void,
                        *const libc::c_void,
                    ) -> libc::c_int,
            ),
        );
    }
}
unsafe extern "C" fn load_pkcs11_key(mut path: *mut libc::c_char) -> *mut crate::sshkey::sshkey {
    let mut keys: *mut *mut crate::sshkey::sshkey = 0 as *mut *mut crate::sshkey::sshkey;
    let mut public: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut private: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut r: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut nkeys: libc::c_int = 0;
    r = sshkey_load_public(path, &mut public, 0 as *mut *mut libc::c_char);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"load_pkcs11_key\0"))
                .as_ptr(),
            1718 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"Couldn't load CA public key \"%s\"\0" as *const u8 as *const libc::c_char,
            path,
        );
    }
    nkeys = pkcs11_add_provider(
        pkcs11provider,
        identity_passphrase,
        &mut keys,
        0 as *mut *mut *mut libc::c_char,
    );
    crate::log::sshlog(
        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"load_pkcs11_key\0")).as_ptr(),
        1722 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%d keys\0" as *const u8 as *const libc::c_char,
        nkeys,
    );
    if nkeys <= 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"load_pkcs11_key\0"))
                .as_ptr(),
            1724 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"cannot read public key from pkcs11\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int;
    while i < nkeys {
        if crate::sshkey::sshkey_equal_public(public, *keys.offset(i as isize)) != 0 {
            private = *keys.offset(i as isize);
        } else {
            crate::sshkey::sshkey_free(*keys.offset(i as isize));
        }
        i += 1;
        i;
    }
    libc::free(keys as *mut libc::c_void);
    crate::sshkey::sshkey_free(public);
    return private;
}
unsafe extern "C" fn agent_signer(
    mut key: *mut crate::sshkey::sshkey,
    mut sigp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut data: *const u_char,
    mut datalen: size_t,
    mut alg: *const libc::c_char,
    mut _provider: *const libc::c_char,
    mut _pin: *const libc::c_char,
    mut compat: u_int,
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut agent_fdp: *mut libc::c_int = ctx as *mut libc::c_int;
    return ssh_agent_sign(*agent_fdp, key, sigp, lenp, data, datalen, alg, compat);
}
unsafe extern "C" fn do_ca_sign(
    mut pw: *mut libc::passwd,
    mut ca_key_path: *const libc::c_char,
    mut prefer_agent: libc::c_int,
    mut cert_serial: libc::c_ulonglong,
    mut cert_serial_autoinc: libc::c_int,
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) {
    let mut r: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut found: libc::c_int = 0;
    let mut agent_fd: libc::c_int = -(1 as libc::c_int);
    let mut n: u_int = 0;
    let mut ca: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut public: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut valid: [libc::c_char; 64] = [0; 64];
    let mut otmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ca_fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut plist: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut agent_ids: *mut ssh_identitylist = 0 as *mut ssh_identitylist;
    let mut j: size_t = 0;
    let mut notifier: *mut notifier_ctx = 0 as *mut notifier_ctx;
    pkcs11_init(1 as libc::c_int);
    tmp = tilde_expand_filename(ca_key_path, (*pw).pw_uid);
    if !pkcs11provider.is_null() {
        ca = load_pkcs11_key(tmp);
        if ca.is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1774 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"No PKCS#11 key matching %s found\0" as *const u8 as *const libc::c_char,
                ca_key_path,
            );
        }
    } else if prefer_agent != 0 {
        r = sshkey_load_public(tmp, &mut ca, 0 as *mut *mut libc::c_char);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1782 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"Cannot load CA public key %s\0" as *const u8 as *const libc::c_char,
                tmp,
            );
        }
        r = ssh_get_authentication_socket(&mut agent_fd);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1784 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"Cannot use public key for CA signature\0" as *const u8 as *const libc::c_char,
            );
        }
        r = ssh_fetch_identitylist(agent_fd, &mut agent_ids);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1786 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"Retrieve agent key list\0" as *const u8 as *const libc::c_char,
            );
        }
        found = 0 as libc::c_int;
        j = 0 as libc::c_int as size_t;
        while j < (*agent_ids).nkeys {
            if sshkey_equal(ca, *((*agent_ids).keys).offset(j as isize)) != 0 {
                found = 1 as libc::c_int;
                break;
            } else {
                j = j.wrapping_add(1);
                j;
            }
        }
        if found == 0 {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1795 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"CA key %s not found in agent\0" as *const u8 as *const libc::c_char,
                tmp,
            );
        }
        ssh_free_identitylist(agent_ids);
        (*ca).flags |= 0x1 as libc::c_int;
    } else {
        ca = load_identity(tmp, 0 as *mut *mut libc::c_char);
        if sshkey_is_sk(ca) != 0 && (*ca).sk_flags as libc::c_int & 0x4 as libc::c_int != 0 {
            pin = read_passphrase(
                b"Enter PIN for CA key: \0" as *const u8 as *const libc::c_char,
                0x2 as libc::c_int,
            );
            if pin.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                        .as_ptr(),
                    1805 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"couldn't read PIN\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
    libc::free(tmp as *mut libc::c_void);
    if !key_type_name.is_null() {
        if sshkey_type_from_name(key_type_name) != (*ca).type_0 {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1813 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"CA key type %s doesn't match specified %s\0" as *const u8 as *const libc::c_char,
                sshkey_ssh_name(ca),
                key_type_name,
            );
        }
    } else if (*ca).type_0 == KEY_RSA as libc::c_int {
        key_type_name = b"rsa-sha2-512\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    ca_fp = crate::sshkey::sshkey_fingerprint(ca, fingerprint_hash, SSH_FP_DEFAULT);
    finalise_cert_exts();
    i = 0 as libc::c_int;
    while i < argc {
        n = 0 as libc::c_int as u_int;
        if !cert_principals.is_null() {
            tmp = crate::xmalloc::xstrdup(cert_principals);
            otmp = tmp;
            plist = 0 as *mut *mut libc::c_char;
            loop {
                cp = strsep(&mut tmp, b",\0" as *const u8 as *const libc::c_char);
                if cp.is_null() {
                    break;
                }
                plist = xreallocarray(
                    plist as *mut libc::c_void,
                    n.wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
                    ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                ) as *mut *mut libc::c_char;
                let ref mut fresh4 = *plist.offset(n as isize);
                *fresh4 = crate::xmalloc::xstrdup(cp);
                if **fresh4 as libc::c_int == '\0' as i32 {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"do_ca_sign\0",
                        ))
                        .as_ptr(),
                        1831 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Empty principal name\0" as *const u8 as *const libc::c_char,
                    );
                }
                n = n.wrapping_add(1);
                n;
            }
            libc::free(otmp as *mut libc::c_void);
        }
        if n > 256 as libc::c_int as libc::c_uint {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1836 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Too many certificate principals specified\0" as *const u8 as *const libc::c_char,
            );
        }
        tmp = tilde_expand_filename(*argv.offset(i as isize), (*pw).pw_uid);
        r = sshkey_load_public(tmp, &mut public, &mut comment);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1840 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"load pubkey \"%s\"\0" as *const u8 as *const libc::c_char,
                tmp,
            );
        }
        if sshkey_is_cert(public) != 0 {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1843 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"key \"%s\" type %s cannot be certified\0" as *const u8 as *const libc::c_char,
                tmp,
                crate::sshkey::sshkey_type(public),
            );
        }
        r = sshkey_to_certified(public);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1847 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"Could not upgrade key %s to certificate\0" as *const u8 as *const libc::c_char,
                tmp,
            );
        }
        (*(*public).cert).type_0 = cert_key_type;
        (*(*public).cert).serial = cert_serial as u_int64_t;
        (*(*public).cert).key_id = crate::xmalloc::xstrdup(cert_key_id);
        (*(*public).cert).nprincipals = n;
        (*(*public).cert).principals = plist;
        (*(*public).cert).valid_after = cert_valid_from;
        (*(*public).cert).valid_before = cert_valid_to;
        prepare_options_buf((*(*public).cert).critical, 1 as libc::c_int);
        prepare_options_buf((*(*public).cert).extensions, 2 as libc::c_int);
        r = crate::sshkey::sshkey_from_private(ca, &mut (*(*public).cert).signature_key);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1860 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"crate::sshkey::sshkey_from_private (ca key)\0" as *const u8
                    as *const libc::c_char,
            );
        }
        if agent_fd != -(1 as libc::c_int) && (*ca).flags & 0x1 as libc::c_int != 0 as libc::c_int {
            r = sshkey_certify_custom(
                public,
                ca,
                key_type_name,
                sk_provider,
                0 as *const libc::c_char,
                Some(
                    agent_signer
                        as unsafe extern "C" fn(
                            *mut crate::sshkey::sshkey,
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
                &mut agent_fd as *mut libc::c_int as *mut libc::c_void,
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                        .as_ptr(),
                    1866 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"Couldn't certify %s via agent\0" as *const u8 as *const libc::c_char,
                    tmp,
                );
            }
        } else {
            if sshkey_is_sk(ca) != 0 && (*ca).sk_flags as libc::c_int & 0x1 as libc::c_int != 0 {
                notifier = notify_start(
                    0 as libc::c_int,
                    b"Confirm user presence for key %s %s\0" as *const u8 as *const libc::c_char,
                    crate::sshkey::sshkey_type(ca),
                    ca_fp,
                );
            }
            r = sshkey_certify(public, ca, key_type_name, sk_provider, pin);
            notify_complete(
                notifier,
                b"User presence confirmed\0" as *const u8 as *const libc::c_char,
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                        .as_ptr(),
                    1878 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"Couldn't certify key %s\0" as *const u8 as *const libc::c_char,
                    tmp,
                );
            }
        }
        cp = libc::strrchr(tmp, '.' as i32);
        if !cp.is_null()
            && libc::strcmp(cp, b".pub\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            *cp = '\0' as i32 as libc::c_char;
        }
        crate::xmalloc::xasprintf(
            &mut out as *mut *mut libc::c_char,
            b"%s-cert.pub\0" as *const u8 as *const libc::c_char,
            tmp,
        );
        libc::free(tmp as *mut libc::c_void);
        r = sshkey_save_public(public, out, comment);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1888 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"Unable to save public key to %s\0" as *const u8 as *const libc::c_char,
                identity_file.as_mut_ptr(),
            );
        }
        if quiet == 0 {
            sshkey_format_cert_validity(
                (*public).cert,
                valid.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
            );
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_ca_sign\0"))
                    .as_ptr(),
                1900 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Signed %s key %s: id \"%s\" serial %llu%s%s valid %s\0" as *const u8
                    as *const libc::c_char,
                sshkey_cert_type(public),
                out,
                (*(*public).cert).key_id,
                (*(*public).cert).serial as libc::c_ulonglong,
                if !cert_principals.is_null() {
                    b" for \0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                if !cert_principals.is_null() {
                    cert_principals as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                valid.as_mut_ptr(),
            );
        }
        crate::sshkey::sshkey_free(public);
        libc::free(out as *mut libc::c_void);
        if cert_serial_autoinc != 0 {
            cert_serial = cert_serial.wrapping_add(1);
            cert_serial;
        }
        i += 1;
        i;
    }
    if !pin.is_null() {
        freezero(pin as *mut libc::c_void, strlen(pin));
    }
    libc::free(ca_fp as *mut libc::c_void);
    pkcs11_terminate();
    libc::exit(0 as libc::c_int);
}
unsafe extern "C" fn parse_relative_time(mut s: *const libc::c_char, mut now: time_t) -> u_int64_t {
    let mut mul: int64_t = 0;
    let mut secs: int64_t = 0;
    mul = (if *s as libc::c_int == '-' as i32 {
        -(1 as libc::c_int)
    } else {
        1 as libc::c_int
    }) as int64_t;
    secs = convtime(s.offset(1 as libc::c_int as isize)) as int64_t;
    if secs == -(1 as libc::c_int) as libc::c_long {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"parse_relative_time\0"))
                .as_ptr(),
            1925 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Invalid relative certificate time %s\0" as *const u8 as *const libc::c_char,
            s,
        );
    }
    if mul == -(1 as libc::c_int) as libc::c_long && secs > now {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"parse_relative_time\0"))
                .as_ptr(),
            1927 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Certificate time %s cannot be represented\0" as *const u8 as *const libc::c_char,
            s,
        );
    }
    return (now as libc::c_ulong).wrapping_add((secs * mul) as u_int64_t);
}
unsafe extern "C" fn parse_hex_u64(mut s: *const libc::c_char, mut up: *mut uint64_t) {
    let mut ep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ull: libc::c_ulonglong = 0;
    *libc::__errno_location() = 0 as libc::c_int;
    ull = libc::strtoull(s, &mut ep, 16 as libc::c_int);
    if *s as libc::c_int == '\0' as i32 || *ep as libc::c_int != '\0' as i32 {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"parse_hex_u64\0"))
                .as_ptr(),
            1940 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Invalid certificate time: not a number\0" as *const u8 as *const libc::c_char,
        );
    }
    if *libc::__errno_location() == 34 as libc::c_int
        && ull
            == (9223372036854775807 as libc::c_long as libc::c_ulong)
                .wrapping_mul(2 as libc::c_ulong)
                .wrapping_add(1 as libc::c_ulong) as libc::c_ulonglong
    {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"parse_hex_u64\0"))
                .as_ptr(),
            1942 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(-(24 as libc::c_int)),
            b"Invalid certificate time\0" as *const u8 as *const libc::c_char,
        );
    }
    *up = ull as uint64_t;
}
unsafe extern "C" fn parse_cert_times(mut timespec: *mut libc::c_char) {
    let mut from: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut to: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut now: time_t = time(0 as *mut time_t);
    let mut secs: int64_t = 0;
    if *timespec as libc::c_int == '+' as i32 && (libc::strchr(timespec, ':' as i32)).is_null() {
        secs = convtime(timespec.offset(1 as libc::c_int as isize)) as int64_t;
        if secs == -(1 as libc::c_int) as libc::c_long {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"parse_cert_times\0"))
                    .as_ptr(),
                1956 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Invalid relative certificate life %s\0" as *const u8 as *const libc::c_char,
                timespec,
            );
        }
        cert_valid_to = (now + secs) as u_int64_t;
        cert_valid_from = ((now - 59 as libc::c_int as libc::c_long)
            / 60 as libc::c_int as libc::c_long
            * 60 as libc::c_int as libc::c_long) as u_int64_t;
        return;
    }
    from = crate::xmalloc::xstrdup(timespec);
    to = libc::strchr(from, ':' as i32);
    if to.is_null()
        || from == to
        || *to.offset(1 as libc::c_int as isize) as libc::c_int == '\0' as i32
    {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"parse_cert_times\0"))
                .as_ptr(),
            1974 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Invalid certificate life specification %s\0" as *const u8 as *const libc::c_char,
            timespec,
        );
    }
    let fresh5 = to;
    to = to.offset(1);
    *fresh5 = '\0' as i32 as libc::c_char;
    if *from as libc::c_int == '-' as i32 || *from as libc::c_int == '+' as i32 {
        cert_valid_from = parse_relative_time(from, now);
    } else if libc::strcmp(from, b"always\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        cert_valid_from = 0 as libc::c_int as u_int64_t;
    } else if strncmp(
        from,
        b"0x\0" as *const u8 as *const libc::c_char,
        2 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        parse_hex_u64(from, &mut cert_valid_from);
    } else if parse_absolute_time(from, &mut cert_valid_from) != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"parse_cert_times\0"))
                .as_ptr(),
            1984 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Invalid from time \"%s\"\0" as *const u8 as *const libc::c_char,
            from,
        );
    }
    if *to as libc::c_int == '-' as i32 || *to as libc::c_int == '+' as i32 {
        cert_valid_to = parse_relative_time(to, now);
    } else if libc::strcmp(to, b"forever\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        cert_valid_to = !(0 as libc::c_int as u_int64_t);
    } else if strncmp(
        to,
        b"0x\0" as *const u8 as *const libc::c_char,
        2 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        parse_hex_u64(to, &mut cert_valid_to);
    } else if parse_absolute_time(to, &mut cert_valid_to) != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"parse_cert_times\0"))
                .as_ptr(),
            1993 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Invalid to time \"%s\"\0" as *const u8 as *const libc::c_char,
            to,
        );
    }
    if cert_valid_to <= cert_valid_from {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"parse_cert_times\0"))
                .as_ptr(),
            1996 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Empty certificate validity interval\0" as *const u8 as *const libc::c_char,
        );
    }
    libc::free(from as *mut libc::c_void);
}
unsafe extern "C" fn add_cert_option(mut opt: *mut libc::c_char) {
    let mut val: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut iscrit: libc::c_int = 0 as libc::c_int;
    if strcasecmp(opt, b"clear\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        certflags_flags = 0 as libc::c_int as u_int32_t;
    } else if strcasecmp(
        opt,
        b"no-x11-forwarding\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        certflags_flags &= !(1 as libc::c_int) as libc::c_uint;
    } else if strcasecmp(
        opt,
        b"permit-x11-forwarding\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        certflags_flags |= 1 as libc::c_int as libc::c_uint;
    } else if strcasecmp(
        opt,
        b"no-agent-forwarding\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        certflags_flags &= !((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint;
    } else if strcasecmp(
        opt,
        b"permit-agent-forwarding\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        certflags_flags |= ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint;
    } else if strcasecmp(
        opt,
        b"no-port-forwarding\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        certflags_flags &= !((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint;
    } else if strcasecmp(
        opt,
        b"permit-port-forwarding\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        certflags_flags |= ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint;
    } else if strcasecmp(opt, b"no-pty\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        certflags_flags &= !((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint;
    } else if strcasecmp(opt, b"permit-pty\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        certflags_flags |= ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint;
    } else if strcasecmp(opt, b"no-user-rc\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        certflags_flags &= !((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint;
    } else if strcasecmp(opt, b"permit-user-rc\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        certflags_flags |= ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint;
    } else if strcasecmp(opt, b"touch-required\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        certflags_flags &= !((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uint;
    } else if strcasecmp(
        opt,
        b"no-touch-required\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        certflags_flags |= ((1 as libc::c_int) << 5 as libc::c_int) as libc::c_uint;
    } else if strcasecmp(
        opt,
        b"no-verify-required\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        certflags_flags &= !((1 as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
    } else if strcasecmp(
        opt,
        b"verify-required\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        certflags_flags |= ((1 as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
    } else if strncasecmp(
        opt,
        b"force-command=\0" as *const u8 as *const libc::c_char,
        14 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        val = opt.offset(14 as libc::c_int as isize);
        if *val as libc::c_int == '\0' as i32 {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"add_cert_option\0"))
                    .as_ptr(),
                2039 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Empty force-command option\0" as *const u8 as *const libc::c_char,
            );
        }
        if !certflags_command.is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"add_cert_option\0"))
                    .as_ptr(),
                2041 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"force-command already specified\0" as *const u8 as *const libc::c_char,
            );
        }
        certflags_command = crate::xmalloc::xstrdup(val);
    } else if strncasecmp(
        opt,
        b"source-address=\0" as *const u8 as *const libc::c_char,
        15 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        val = opt.offset(15 as libc::c_int as isize);
        if *val as libc::c_int == '\0' as i32 {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"add_cert_option\0"))
                    .as_ptr(),
                2046 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Empty source-address option\0" as *const u8 as *const libc::c_char,
            );
        }
        if !certflags_src_addr.is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"add_cert_option\0"))
                    .as_ptr(),
                2048 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"source-address already specified\0" as *const u8 as *const libc::c_char,
            );
        }
        if addr_match_cidr_list(0 as *const libc::c_char, val) != 0 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"add_cert_option\0"))
                    .as_ptr(),
                2050 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Invalid source-address list\0" as *const u8 as *const libc::c_char,
            );
        }
        certflags_src_addr = crate::xmalloc::xstrdup(val);
    } else if strncasecmp(
        opt,
        b"extension:\0" as *const u8 as *const libc::c_char,
        10 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
        || {
            iscrit = (strncasecmp(
                opt,
                b"critical:\0" as *const u8 as *const libc::c_char,
                9 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int) as libc::c_int;
            iscrit != 0
        }
    {
        val = crate::xmalloc::xstrdup(
            (libc::strchr(opt, ':' as i32)).offset(1 as libc::c_int as isize),
        );
        cp = libc::strchr(val, '=' as i32);
        if !cp.is_null() {
            let fresh6 = cp;
            cp = cp.offset(1);
            *fresh6 = '\0' as i32 as libc::c_char;
        }
        cert_ext_add(val, cp, iscrit);
        libc::free(val as *mut libc::c_void);
    } else {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"add_cert_option\0"))
                .as_ptr(),
            2060 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Unsupported certificate option \"%s\"\0" as *const u8 as *const libc::c_char,
            opt,
        );
    };
}
unsafe extern "C" fn show_options(
    mut optbuf: *mut crate::sshbuf::sshbuf,
    mut in_critical: libc::c_int,
) {
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut arg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hex: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut option: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    options = sshbuf_fromb(optbuf);
    if options.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"show_options\0")).as_ptr(),
            2071 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_fromb failed\0" as *const u8 as *const libc::c_char,
        );
    }
    while crate::sshbuf::sshbuf_len(options) != 0 as libc::c_int as libc::c_ulong {
        crate::sshbuf::sshbuf_free(option);
        option = 0 as *mut crate::sshbuf::sshbuf;
        r = crate::sshbuf_getput_basic::sshbuf_get_cstring(options, &mut name, 0 as *mut size_t);
        if r != 0 as libc::c_int || {
            r = sshbuf_froms(options, &mut option);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"show_options\0"))
                    .as_ptr(),
                2077 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse option\0" as *const u8 as *const libc::c_char,
            );
        }
        printf(
            b"                %s\0" as *const u8 as *const libc::c_char,
            name,
        );
        if in_critical == 0
            && (libc::strcmp(
                name,
                b"permit-X11-forwarding\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
                || libc::strcmp(
                    name,
                    b"permit-agent-forwarding\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
                || libc::strcmp(
                    name,
                    b"permit-port-forwarding\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
                || libc::strcmp(name, b"permit-pty\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                || libc::strcmp(
                    name,
                    b"permit-user-rc\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
                || libc::strcmp(
                    name,
                    b"no-touch-required\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int)
        {
            printf(b"\n\0" as *const u8 as *const libc::c_char);
        } else if in_critical != 0
            && (libc::strcmp(name, b"force-command\0" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
                || libc::strcmp(
                    name,
                    b"source-address\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int)
        {
            r = crate::sshbuf_getput_basic::sshbuf_get_cstring(option, &mut arg, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"show_options\0"))
                        .as_ptr(),
                    2091 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse critical\0" as *const u8 as *const libc::c_char,
                );
            }
            printf(b" %s\n\0" as *const u8 as *const libc::c_char, arg);
            libc::free(arg as *mut libc::c_void);
        } else if in_critical != 0
            && libc::strcmp(
                name,
                b"verify-required\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            printf(b"\n\0" as *const u8 as *const libc::c_char);
        } else if crate::sshbuf::sshbuf_len(option) > 0 as libc::c_int as libc::c_ulong {
            hex = sshbuf_dtob16(option);
            printf(
                b" UNKNOWN OPTION: %s (len %zu)\n\0" as *const u8 as *const libc::c_char,
                hex,
                crate::sshbuf::sshbuf_len(option),
            );
            crate::sshbuf::sshbuf_reset(option);
            libc::free(hex as *mut libc::c_void);
        } else {
            printf(b" UNKNOWN FLAG OPTION\n\0" as *const u8 as *const libc::c_char);
        }
        libc::free(name as *mut libc::c_void);
        if crate::sshbuf::sshbuf_len(option) != 0 as libc::c_int as libc::c_ulong {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"show_options\0"))
                    .as_ptr(),
                2107 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Option corrupt: extra data at end\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    crate::sshbuf::sshbuf_free(option);
    crate::sshbuf::sshbuf_free(options);
}
unsafe extern "C" fn print_cert(mut key: *mut crate::sshkey::sshkey) {
    let mut valid: [libc::c_char; 64] = [0; 64];
    let mut key_fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ca_fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: u_int = 0;
    key_fp = crate::sshkey::sshkey_fingerprint(key, fingerprint_hash, SSH_FP_DEFAULT);
    ca_fp = crate::sshkey::sshkey_fingerprint(
        (*(*key).cert).signature_key,
        fingerprint_hash,
        SSH_FP_DEFAULT,
    );
    if key_fp.is_null() || ca_fp.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"print_cert\0")).as_ptr(),
            2123 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::sshkey::sshkey_fingerprint fail\0" as *const u8 as *const libc::c_char,
        );
    }
    sshkey_format_cert_validity(
        (*key).cert,
        valid.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
    );
    printf(
        b"        Type: %s %s certificate\n\0" as *const u8 as *const libc::c_char,
        sshkey_ssh_name(key),
        sshkey_cert_type(key),
    );
    printf(
        b"        Public key: %s %s\n\0" as *const u8 as *const libc::c_char,
        crate::sshkey::sshkey_type(key),
        key_fp,
    );
    printf(
        b"        Signing CA: %s %s (using %s)\n\0" as *const u8 as *const libc::c_char,
        crate::sshkey::sshkey_type((*(*key).cert).signature_key),
        ca_fp,
        (*(*key).cert).signature_type,
    );
    printf(
        b"        Key ID: \"%s\"\n\0" as *const u8 as *const libc::c_char,
        (*(*key).cert).key_id,
    );
    printf(
        b"        Serial: %llu\n\0" as *const u8 as *const libc::c_char,
        (*(*key).cert).serial as libc::c_ulonglong,
    );
    printf(
        b"        Valid: %s\n\0" as *const u8 as *const libc::c_char,
        valid.as_mut_ptr(),
    );
    printf(b"        Principals: \0" as *const u8 as *const libc::c_char);
    if (*(*key).cert).nprincipals == 0 as libc::c_int as libc::c_uint {
        printf(b"(none)\n\0" as *const u8 as *const libc::c_char);
    } else {
        i = 0 as libc::c_int as u_int;
        while i < (*(*key).cert).nprincipals {
            printf(
                b"\n                %s\0" as *const u8 as *const libc::c_char,
                *((*(*key).cert).principals).offset(i as isize),
            );
            i = i.wrapping_add(1);
            i;
        }
        printf(b"\n\0" as *const u8 as *const libc::c_char);
    }
    printf(b"        Critical Options: \0" as *const u8 as *const libc::c_char);
    if crate::sshbuf::sshbuf_len((*(*key).cert).critical) == 0 as libc::c_int as libc::c_ulong {
        printf(b"(none)\n\0" as *const u8 as *const libc::c_char);
    } else {
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        show_options((*(*key).cert).critical, 1 as libc::c_int);
    }
    printf(b"        Extensions: \0" as *const u8 as *const libc::c_char);
    if crate::sshbuf::sshbuf_len((*(*key).cert).extensions) == 0 as libc::c_int as libc::c_ulong {
        printf(b"(none)\n\0" as *const u8 as *const libc::c_char);
    } else {
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        show_options((*(*key).cert).extensions, 0 as libc::c_int);
    };
}
unsafe extern "C" fn do_show_cert(mut pw: *mut libc::passwd) {
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut r: libc::c_int = 0;
    let mut is_stdin: libc::c_int = 0 as libc::c_int;
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut path: *const libc::c_char = 0 as *const libc::c_char;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut lnum: u_long = 0 as libc::c_int as u_long;
    if have_identity == 0 {
        ask_filename(
            pw,
            b"Enter file in which the key is\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::strcmp(
        identity_file.as_mut_ptr(),
        b"-\0" as *const u8 as *const libc::c_char,
    ) != 0 as libc::c_int
        && libc::stat(identity_file.as_mut_ptr(), &mut st) == -(1 as libc::c_int)
    {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_show_cert\0")).as_ptr(),
            2175 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: %s: %s\0" as *const u8 as *const libc::c_char,
            __progname,
            identity_file.as_mut_ptr(),
            libc::strerror(*libc::__errno_location()),
        );
    }
    path = identity_file.as_mut_ptr();
    if libc::strcmp(path, b"-\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        f = stdin;
        path = b"(stdin)\0" as *const u8 as *const libc::c_char;
        is_stdin = 1 as libc::c_int;
    } else {
        f = fopen(
            identity_file.as_mut_ptr(),
            b"r\0" as *const u8 as *const libc::c_char,
        );
        if f.is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_show_cert\0"))
                    .as_ptr(),
                2183 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"fopen %s: %s\0" as *const u8 as *const libc::c_char,
                identity_file.as_mut_ptr(),
                libc::strerror(*libc::__errno_location()),
            );
        }
    }
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        lnum = lnum.wrapping_add(1);
        lnum;
        crate::sshkey::sshkey_free(key);
        key = 0 as *mut crate::sshkey::sshkey;
        cp = line.offset(strspn(line, b" \t\0" as *const u8 as *const libc::c_char) as isize);
        if *cp as libc::c_int == '#' as i32 || *cp as libc::c_int == '\0' as i32 {
            continue;
        }
        key = sshkey_new(KEY_UNSPEC as libc::c_int);
        if key.is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_show_cert\0"))
                    .as_ptr(),
                2194 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"sshkey_new\0" as *const u8 as *const libc::c_char,
            );
        }
        r = sshkey_read(key, &mut cp);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_show_cert\0"))
                    .as_ptr(),
                2196 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"%s:%lu: invalid key\0" as *const u8 as *const libc::c_char,
                path,
                lnum,
            );
        } else if sshkey_is_cert(key) == 0 {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_show_cert\0"))
                    .as_ptr(),
                2200 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"%s:%lu is not a certificate\0" as *const u8 as *const libc::c_char,
                path,
                lnum,
            );
        } else {
            ok = 1 as libc::c_int;
            if is_stdin == 0 && lnum == 1 as libc::c_int as libc::c_ulong {
                printf(b"%s:\n\0" as *const u8 as *const libc::c_char, path);
            } else {
                printf(
                    b"%s:%lu:\n\0" as *const u8 as *const libc::c_char,
                    path,
                    lnum,
                );
            }
            print_cert(key);
        }
    }
    libc::free(line as *mut libc::c_void);
    crate::sshkey::sshkey_free(key);
    fclose(f);
    libc::exit(if ok != 0 {
        0 as libc::c_int
    } else {
        1 as libc::c_int
    });
}
unsafe extern "C" fn load_krl(mut path: *const libc::c_char, mut krlp: *mut *mut ssh_krl) {
    let mut krlbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    r = sshbuf_load_file(path, &mut krlbuf);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"load_krl\0")).as_ptr(),
            2223 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"Unable to load KRL %s\0" as *const u8 as *const libc::c_char,
            path,
        );
    }
    r = ssh_krl_from_blob(
        krlbuf,
        krlp,
        0 as *mut *const crate::sshkey::sshkey,
        0 as libc::c_int as size_t,
    );
    if r != 0 as libc::c_int || (*krlp).is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"load_krl\0")).as_ptr(),
            2227 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"Invalid KRL file %s\0" as *const u8 as *const libc::c_char,
            path,
        );
    }
    crate::sshbuf::sshbuf_free(krlbuf);
}
unsafe extern "C" fn hash_to_blob(
    mut cp: *const libc::c_char,
    mut blobp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut file: *const libc::c_char,
    mut lnum: u_long,
) {
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tlen: size_t = 0;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    if strncmp(
        cp,
        b"SHA256:\0" as *const u8 as *const libc::c_char,
        7 as libc::c_int as libc::c_ulong,
    ) != 0 as libc::c_int
    {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"hash_to_blob\0")).as_ptr(),
            2241 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s:%lu: unsupported hash algorithm\0" as *const u8 as *const libc::c_char,
            file,
            lnum,
        );
    }
    cp = cp.offset(7 as libc::c_int as isize);
    tlen = strlen(cp);
    tmp = crate::xmalloc::xmalloc(
        tlen.wrapping_add(4 as libc::c_int as libc::c_ulong)
            .wrapping_add(1 as libc::c_int as libc::c_ulong),
    ) as *mut libc::c_char;
    strlcpy(
        tmp,
        cp,
        tlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
    );
    while tlen.wrapping_rem(4 as libc::c_int as libc::c_ulong) != 0 as libc::c_int as libc::c_ulong
    {
        let fresh7 = tlen;
        tlen = tlen.wrapping_add(1);
        *tmp.offset(fresh7 as isize) = '=' as i32 as libc::c_char;
        *tmp.offset(tlen as isize) = '\0' as i32 as libc::c_char;
    }
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"hash_to_blob\0")).as_ptr(),
            2256 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshbuf_b64tod(b, tmp);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"hash_to_blob\0")).as_ptr(),
            2258 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s:%lu: decode hash failed\0" as *const u8 as *const libc::c_char,
            file,
            lnum,
        );
    }
    libc::free(tmp as *mut libc::c_void);
    *lenp = crate::sshbuf::sshbuf_len(b);
    *blobp = crate::xmalloc::xmalloc(*lenp) as *mut u_char;
    memcpy(
        *blobp as *mut libc::c_void,
        crate::sshbuf::sshbuf_ptr(b) as *const libc::c_void,
        *lenp,
    );
    crate::sshbuf::sshbuf_free(b);
}
unsafe extern "C" fn update_krl_from_file(
    mut pw: *mut libc::passwd,
    mut file: *const libc::c_char,
    mut wild_ca: libc::c_int,
    mut ca: *const crate::sshkey::sshkey,
    mut krl: *mut ssh_krl,
) {
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut lnum: u_long = 0 as libc::c_int as u_long;
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut blob: *mut u_char = 0 as *mut u_char;
    let mut blen: size_t = 0 as libc::c_int as size_t;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut serial: libc::c_ulonglong = 0;
    let mut serial2: libc::c_ulonglong = 0;
    let mut i: libc::c_int = 0;
    let mut was_explicit_key: libc::c_int = 0;
    let mut was_sha1: libc::c_int = 0;
    let mut was_sha256: libc::c_int = 0;
    let mut was_hash: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut krl_spec: *mut libc::FILE = 0 as *mut libc::FILE;
    path = tilde_expand_filename(file, (*pw).pw_uid);
    if libc::strcmp(path, b"-\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        krl_spec = stdin;
        libc::free(path as *mut libc::c_void);
        path = crate::xmalloc::xstrdup(b"(standard input)\0" as *const u8 as *const libc::c_char);
    } else {
        krl_spec = fopen(path, b"r\0" as *const u8 as *const libc::c_char);
        if krl_spec.is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"update_krl_from_file\0",
                ))
                .as_ptr(),
                2285 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"fopen %s: %s\0" as *const u8 as *const libc::c_char,
                path,
                libc::strerror(*libc::__errno_location()),
            );
        }
    }
    if quiet == 0 {
        printf(
            b"Revoking from %s\n\0" as *const u8 as *const libc::c_char,
            path,
        );
    }
    while getline(&mut line, &mut linesize, krl_spec) != -(1 as libc::c_int) as libc::c_long {
        lnum = lnum.wrapping_add(1);
        lnum;
        was_hash = 0 as libc::c_int;
        was_sha256 = was_hash;
        was_sha1 = was_sha256;
        was_explicit_key = was_sha1;
        cp = line.offset(strspn(line, b" \t\0" as *const u8 as *const libc::c_char) as isize);
        i = 0 as libc::c_int;
        r = -(1 as libc::c_int);
        while *cp.offset(i as isize) as libc::c_int != '\0' as i32 {
            if *cp.offset(i as isize) as libc::c_int == '#' as i32
                || *cp.offset(i as isize) as libc::c_int == '\n' as i32
            {
                *cp.offset(i as isize) = '\0' as i32 as libc::c_char;
                break;
            } else {
                if *cp.offset(i as isize) as libc::c_int == ' ' as i32
                    || *cp.offset(i as isize) as libc::c_int == '\t' as i32
                {
                    if r == -(1 as libc::c_int) {
                        r = i;
                    }
                } else {
                    r = -(1 as libc::c_int);
                }
                i += 1;
                i;
            }
        }
        if r != -(1 as libc::c_int) {
            *cp.offset(r as isize) = '\0' as i32 as libc::c_char;
        }
        if *cp as libc::c_int == '\0' as i32 {
            continue;
        }
        if strncasecmp(
            cp,
            b"serial:\0" as *const u8 as *const libc::c_char,
            7 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            if ca.is_null() && wild_ca == 0 {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"update_krl_from_file\0",
                    ))
                    .as_ptr(),
                    2313 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"revoking certificates by serial number requires specification of a CA key\0"
                        as *const u8 as *const libc::c_char,
                );
            }
            cp = cp.offset(7 as libc::c_int as isize);
            cp = cp.offset(strspn(cp, b" \t\0" as *const u8 as *const libc::c_char) as isize);
            *libc::__errno_location() = 0 as libc::c_int;
            serial = libc::strtoull(cp, &mut ep, 0 as libc::c_int);
            if *cp as libc::c_int == '\0' as i32
                || *ep as libc::c_int != '\0' as i32 && *ep as libc::c_int != '-' as i32
            {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"update_krl_from_file\0",
                    ))
                    .as_ptr(),
                    2321 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"%s:%lu: invalid serial \"%s\"\0" as *const u8 as *const libc::c_char,
                    path,
                    lnum,
                    cp,
                );
            }
            if *libc::__errno_location() == 34 as libc::c_int
                && serial
                    == (9223372036854775807 as libc::c_longlong as libc::c_ulonglong)
                        .wrapping_mul(2 as libc::c_ulonglong)
                        .wrapping_add(1 as libc::c_ulonglong)
            {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"update_krl_from_file\0",
                    ))
                    .as_ptr(),
                    2324 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"%s:%lu: serial out of range\0" as *const u8 as *const libc::c_char,
                    path,
                    lnum,
                );
            }
            serial2 = serial;
            if *ep as libc::c_int == '-' as i32 {
                cp = ep.offset(1 as libc::c_int as isize);
                *libc::__errno_location() = 0 as libc::c_int;
                serial2 = libc::strtoull(cp, &mut ep, 0 as libc::c_int);
                if *cp as libc::c_int == '\0' as i32 || *ep as libc::c_int != '\0' as i32 {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"update_krl_from_file\0",
                        ))
                        .as_ptr(),
                        2332 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"%s:%lu: invalid serial \"%s\"\0" as *const u8 as *const libc::c_char,
                        path,
                        lnum,
                        cp,
                    );
                }
                if *libc::__errno_location() == 34 as libc::c_int
                    && serial2
                        == (9223372036854775807 as libc::c_longlong as libc::c_ulonglong)
                            .wrapping_mul(2 as libc::c_ulonglong)
                            .wrapping_add(1 as libc::c_ulonglong)
                {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"update_krl_from_file\0",
                        ))
                        .as_ptr(),
                        2335 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"%s:%lu: serial out of range\0" as *const u8 as *const libc::c_char,
                        path,
                        lnum,
                    );
                }
                if serial2 <= serial {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"update_krl_from_file\0",
                        ))
                        .as_ptr(),
                        2340 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"%s:%lu: invalid serial range %llu:%llu\0" as *const u8
                            as *const libc::c_char,
                        path,
                        lnum,
                        serial,
                        serial2,
                    );
                }
            }
            if ssh_krl_revoke_cert_by_serial_range(
                krl,
                ca,
                serial as u_int64_t,
                serial2 as u_int64_t,
            ) != 0 as libc::c_int
            {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"update_krl_from_file\0",
                    ))
                    .as_ptr(),
                    2344 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"revoke serial failed\0" as *const u8 as *const libc::c_char,
                );
            }
        } else if strncasecmp(
            cp,
            b"id:\0" as *const u8 as *const libc::c_char,
            3 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            if ca.is_null() && wild_ca == 0 {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"update_krl_from_file\0",
                    ))
                    .as_ptr(),
                    2349 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"revoking certificates by key ID requires specification of a CA key\0"
                        as *const u8 as *const libc::c_char,
                );
            }
            cp = cp.offset(3 as libc::c_int as isize);
            cp = cp.offset(strspn(cp, b" \t\0" as *const u8 as *const libc::c_char) as isize);
            if ssh_krl_revoke_cert_by_key_id(krl, ca, cp) != 0 as libc::c_int {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"update_krl_from_file\0",
                    ))
                    .as_ptr(),
                    2354 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"revoke key ID failed\0" as *const u8 as *const libc::c_char,
                );
            }
        } else if strncasecmp(
            cp,
            b"hash:\0" as *const u8 as *const libc::c_char,
            5 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            cp = cp.offset(5 as libc::c_int as isize);
            cp = cp.offset(strspn(cp, b" \t\0" as *const u8 as *const libc::c_char) as isize);
            hash_to_blob(cp, &mut blob, &mut blen, file, lnum);
            r = ssh_krl_revoke_key_sha256(krl, blob, blen);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"update_krl_from_file\0",
                    ))
                    .as_ptr(),
                    2361 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"revoke key failed\0" as *const u8 as *const libc::c_char,
                );
            }
        } else {
            if strncasecmp(
                cp,
                b"key:\0" as *const u8 as *const libc::c_char,
                4 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
            {
                cp = cp.offset(4 as libc::c_int as isize);
                cp = cp.offset(strspn(cp, b" \t\0" as *const u8 as *const libc::c_char) as isize);
                was_explicit_key = 1 as libc::c_int;
            } else if strncasecmp(
                cp,
                b"sha1:\0" as *const u8 as *const libc::c_char,
                5 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
            {
                cp = cp.offset(5 as libc::c_int as isize);
                cp = cp.offset(strspn(cp, b" \t\0" as *const u8 as *const libc::c_char) as isize);
                was_sha1 = 1 as libc::c_int;
            } else if strncasecmp(
                cp,
                b"sha256:\0" as *const u8 as *const libc::c_char,
                7 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
            {
                cp = cp.offset(7 as libc::c_int as isize);
                cp = cp.offset(strspn(cp, b" \t\0" as *const u8 as *const libc::c_char) as isize);
                was_sha256 = 1 as libc::c_int;
            }
            key = sshkey_new(KEY_UNSPEC as libc::c_int);
            if key.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"update_krl_from_file\0",
                    ))
                    .as_ptr(),
                    2381 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"sshkey_new\0" as *const u8 as *const libc::c_char,
                );
            }
            r = sshkey_read(key, &mut cp);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"update_krl_from_file\0",
                    ))
                    .as_ptr(),
                    2383 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"%s:%lu: invalid key\0" as *const u8 as *const libc::c_char,
                    path,
                    lnum,
                );
            }
            if was_explicit_key != 0 {
                r = ssh_krl_revoke_key_explicit(krl, key);
            } else if was_sha1 != 0 {
                if sshkey_fingerprint_raw(key, 1 as libc::c_int, &mut blob, &mut blen)
                    != 0 as libc::c_int
                {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"update_krl_from_file\0",
                        ))
                        .as_ptr(),
                        2390 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"%s:%lu: fingerprint failed\0" as *const u8 as *const libc::c_char,
                        file,
                        lnum,
                    );
                }
                r = ssh_krl_revoke_key_sha1(krl, blob, blen);
            } else if was_sha256 != 0 {
                if sshkey_fingerprint_raw(key, 2 as libc::c_int, &mut blob, &mut blen)
                    != 0 as libc::c_int
                {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"update_krl_from_file\0",
                        ))
                        .as_ptr(),
                        2397 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"%s:%lu: fingerprint failed\0" as *const u8 as *const libc::c_char,
                        file,
                        lnum,
                    );
                }
                r = ssh_krl_revoke_key_sha256(krl, blob, blen);
            } else {
                r = ssh_krl_revoke_key(krl, key);
            }
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"update_krl_from_file\0",
                    ))
                    .as_ptr(),
                    2403 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"revoke key failed\0" as *const u8 as *const libc::c_char,
                );
            }
            freezero(blob as *mut libc::c_void, blen);
            blob = 0 as *mut u_char;
            blen = 0 as libc::c_int as size_t;
            crate::sshkey::sshkey_free(key);
        }
    }
    if libc::strcmp(path, b"-\0" as *const u8 as *const libc::c_char) != 0 as libc::c_int {
        fclose(krl_spec);
    }
    libc::free(line as *mut libc::c_void);
    libc::free(path as *mut libc::c_void);
}
unsafe extern "C" fn do_gen_krl(
    mut pw: *mut libc::passwd,
    mut updating: libc::c_int,
    mut ca_key_path: *const libc::c_char,
    mut krl_version: libc::c_ulonglong,
    mut krl_comment: *const libc::c_char,
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) {
    let mut krl: *mut ssh_krl = 0 as *mut ssh_krl;
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    let mut ca: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut wild_ca: libc::c_int = 0 as libc::c_int;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut kbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    if *identity_file.as_mut_ptr() as libc::c_int == '\0' as i32 {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_gen_krl\0")).as_ptr(),
            2429 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"KRL generation requires an output file\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::stat(identity_file.as_mut_ptr(), &mut sb) == -(1 as libc::c_int) {
        if *libc::__errno_location() != 2 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_gen_krl\0"))
                    .as_ptr(),
                2433 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Cannot access KRL \"%s\": %s\0" as *const u8 as *const libc::c_char,
                identity_file.as_mut_ptr(),
                libc::strerror(*libc::__errno_location()),
            );
        }
        if updating != 0 {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_gen_krl\0"))
                    .as_ptr(),
                2435 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"KRL \"%s\" does not exist\0" as *const u8 as *const libc::c_char,
                identity_file.as_mut_ptr(),
            );
        }
    }
    if !ca_key_path.is_null() {
        if strcasecmp(ca_key_path, b"none\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            wild_ca = 1 as libc::c_int;
        } else {
            tmp = tilde_expand_filename(ca_key_path, (*pw).pw_uid);
            r = sshkey_load_public(tmp, &mut ca, 0 as *mut *mut libc::c_char);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_gen_krl\0"))
                        .as_ptr(),
                    2443 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"Cannot load CA public key %s\0" as *const u8 as *const libc::c_char,
                    tmp,
                );
            }
            libc::free(tmp as *mut libc::c_void);
        }
    }
    if updating != 0 {
        load_krl(identity_file.as_mut_ptr(), &mut krl);
    } else {
        krl = ssh_krl_init();
        if krl.is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_gen_krl\0"))
                    .as_ptr(),
                2451 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"couldn't create KRL\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if krl_version != 0 as libc::c_int as libc::c_ulonglong {
        ssh_krl_set_version(krl, krl_version as u_int64_t);
    }
    if !krl_comment.is_null() {
        ssh_krl_set_comment(krl, krl_comment);
    }
    i = 0 as libc::c_int;
    while i < argc {
        update_krl_from_file(pw, *argv.offset(i as isize), wild_ca, ca, krl);
        i += 1;
        i;
    }
    kbuf = crate::sshbuf::sshbuf_new();
    if kbuf.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_gen_krl\0")).as_ptr(),
            2462 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    if ssh_krl_to_blob(
        krl,
        kbuf,
        0 as *mut *mut crate::sshkey::sshkey,
        0 as libc::c_int as u_int,
    ) != 0 as libc::c_int
    {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_gen_krl\0")).as_ptr(),
            2464 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Couldn't generate KRL\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_write_file(identity_file.as_mut_ptr(), kbuf);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_gen_krl\0")).as_ptr(),
            2466 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"write %s: %s\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
            libc::strerror(*libc::__errno_location()),
        );
    }
    crate::sshbuf::sshbuf_free(kbuf);
    ssh_krl_free(krl);
    crate::sshkey::sshkey_free(ca);
}
unsafe extern "C" fn do_check_krl(
    mut _pw: *mut libc::passwd,
    mut print_krl: libc::c_int,
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) {
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut krl: *mut ssh_krl = 0 as *mut ssh_krl;
    let mut k: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    if *identity_file.as_mut_ptr() as libc::c_int == '\0' as i32 {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_check_krl\0")).as_ptr(),
            2481 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"KRL checking requires an input file\0" as *const u8 as *const libc::c_char,
        );
    }
    load_krl(identity_file.as_mut_ptr(), &mut krl);
    if print_krl != 0 {
        krl_dump(krl, stdout);
    }
    i = 0 as libc::c_int;
    while i < argc {
        r = sshkey_load_public(*argv.offset(i as isize), &mut k, &mut comment);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_check_krl\0"))
                    .as_ptr(),
                2487 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"Cannot load public key %s\0" as *const u8 as *const libc::c_char,
                *argv.offset(i as isize),
            );
        }
        r = ssh_krl_check_key(krl, k);
        printf(
            b"%s%s%s%s: %s\n\0" as *const u8 as *const libc::c_char,
            *argv.offset(i as isize),
            if *comment as libc::c_int != 0 {
                b" (\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            comment,
            if *comment as libc::c_int != 0 {
                b")\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if r == 0 as libc::c_int {
                b"ok\0" as *const u8 as *const libc::c_char
            } else {
                b"REVOKED\0" as *const u8 as *const libc::c_char
            },
        );
        if r != 0 as libc::c_int {
            ret = 1 as libc::c_int;
        }
        crate::sshkey::sshkey_free(k);
        libc::free(comment as *mut libc::c_void);
        i += 1;
        i;
    }
    ssh_krl_free(krl);
    libc::exit(ret);
}
unsafe extern "C" fn load_sign_key(
    mut keypath: *const libc::c_char,
    mut pubkey: *const crate::sshkey::sshkey,
) -> *mut crate::sshkey::sshkey {
    let mut current_block: u64;
    let mut i: size_t = 0;
    let mut slen: size_t = 0;
    let mut plen: size_t = strlen(keypath);
    let mut privpath: *mut libc::c_char = crate::xmalloc::xstrdup(keypath);
    static mut suffixes: [*const libc::c_char; 3] = [
        b"-cert.pub\0" as *const u8 as *const libc::c_char,
        b".pub\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    let mut ret: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut privkey: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut r: libc::c_int = 0;
    let mut waspub: libc::c_int = 0 as libc::c_int;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    i = 0 as libc::c_int as size_t;
    while !(suffixes[i as usize]).is_null() {
        slen = strlen(suffixes[i as usize]);
        if !(plen <= slen
            || libc::strcmp(
                privpath.offset(plen as isize).offset(-(slen as isize)),
                suffixes[i as usize],
            ) != 0 as libc::c_int)
        {
            *privpath.offset(plen.wrapping_sub(slen) as isize) = '\0' as i32 as libc::c_char;
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"load_sign_key\0"))
                    .as_ptr(),
                2523 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"%s looks like a public key, using private key path %s instead\0" as *const u8
                    as *const libc::c_char,
                keypath,
                privpath,
            );
            waspub = 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    if waspub != 0
        && libc::stat(privpath, &mut st) != 0 as libc::c_int
        && *libc::__errno_location() == 2 as libc::c_int
    {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"load_sign_key\0"))
                .as_ptr(),
            2527 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"No private key found for public key \"%s\"\0" as *const u8 as *const libc::c_char,
            keypath,
        );
    }
    r = sshkey_load_private(
        privpath,
        b"\0" as *const u8 as *const libc::c_char,
        &mut privkey,
        0 as *mut *mut libc::c_char,
    );
    if r != 0 as libc::c_int && r != -(43 as libc::c_int) {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"load_sign_key\0"))
                .as_ptr(),
            2530 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            ssh_err(r),
            b"load private key \"%s\"\0" as *const u8 as *const libc::c_char,
            privpath,
        );
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"load_sign_key\0"))
                .as_ptr(),
            2531 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"No private key found for \"%s\"\0" as *const u8 as *const libc::c_char,
            privpath,
        );
    } else if privkey.is_null() {
        privkey = load_identity(privpath, 0 as *mut *mut libc::c_char);
    }
    if crate::sshkey::sshkey_equal_public(pubkey, privkey) == 0 {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"load_sign_key\0"))
                .as_ptr(),
            2537 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Public key %s doesn't match private %s\0" as *const u8 as *const libc::c_char,
            keypath,
            privpath,
        );
    } else {
        if sshkey_is_cert(pubkey) != 0 && sshkey_is_cert(privkey) == 0 {
            r = sshkey_to_certified(privkey);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"load_sign_key\0"))
                        .as_ptr(),
                    2546 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"sshkey_to_certified\0" as *const u8 as *const libc::c_char,
                );
                current_block = 18227936247217982644;
            } else {
                r = sshkey_cert_copy(pubkey, privkey);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(
                            b"load_sign_key\0",
                        ))
                        .as_ptr(),
                        2550 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"sshkey_cert_copy\0" as *const u8 as *const libc::c_char,
                    );
                    current_block = 18227936247217982644;
                } else {
                    current_block = 15089075282327824602;
                }
            }
        } else {
            current_block = 15089075282327824602;
        }
        match current_block {
            18227936247217982644 => {}
            _ => {
                ret = privkey;
                privkey = 0 as *mut crate::sshkey::sshkey;
            }
        }
    }
    crate::sshkey::sshkey_free(privkey);
    libc::free(privpath as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn sign_one(
    mut signkey: *mut crate::sshkey::sshkey,
    mut filename: *const libc::c_char,
    mut fd: libc::c_int,
    mut sig_namespace: *const libc::c_char,
    mut hashalg: *const libc::c_char,
    mut signer: Option<sshsig_signer>,
    mut signer_ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut current_block: u64;
    let mut sigbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut abuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut wfd: libc::c_int = -(1 as libc::c_int);
    let mut oerrno: libc::c_int = 0;
    let mut wfile: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut asig: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut prompt: *mut libc::c_char = 0 as *mut libc::c_char;
    if quiet == 0 {
        if fd == 0 as libc::c_int {
            libc::fprintf(
                stderr,
                b"Signing data on standard input\n\0" as *const u8 as *const libc::c_char,
            );
        } else {
            libc::fprintf(
                stderr,
                b"Signing file %s\n\0" as *const u8 as *const libc::c_char,
                filename,
            );
        }
    }
    if signer.is_none() && sshkey_is_sk(signkey) != 0 {
        if (*signkey).sk_flags as libc::c_int & 0x4 as libc::c_int != 0 {
            crate::xmalloc::xasprintf(
                &mut prompt as *mut *mut libc::c_char,
                b"Enter PIN for %s key: \0" as *const u8 as *const libc::c_char,
                crate::sshkey::sshkey_type(signkey),
            );
            pin = read_passphrase(prompt, 0x2 as libc::c_int);
            if pin.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"sign_one\0"))
                        .as_ptr(),
                    2585 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"couldn't read PIN\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        if (*signkey).sk_flags as libc::c_int & 0x1 as libc::c_int != 0 {
            fp = crate::sshkey::sshkey_fingerprint(signkey, fingerprint_hash, SSH_FP_DEFAULT);
            if fp.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"sign_one\0"))
                        .as_ptr(),
                    2590 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"fingerprint failed\0" as *const u8 as *const libc::c_char,
                );
            }
            libc::fprintf(
                stderr,
                b"Confirm user presence for key %s %s\n\0" as *const u8 as *const libc::c_char,
                crate::sshkey::sshkey_type(signkey),
                fp,
            );
            libc::free(fp as *mut libc::c_void);
        }
    }
    r = sshsig_sign_fd(
        signkey,
        hashalg,
        sk_provider,
        pin,
        fd,
        sig_namespace,
        &mut sigbuf,
        signer,
        signer_ctx,
    );
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"sign_one\0")).as_ptr(),
            2598 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"Signing %s failed\0" as *const u8 as *const libc::c_char,
            filename,
        );
    } else {
        r = sshsig_armor(sigbuf, &mut abuf);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"sign_one\0")).as_ptr(),
                2602 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"sshsig_armor\0" as *const u8 as *const libc::c_char,
            );
        } else {
            asig = crate::sshbuf_misc::sshbuf_dup_string(abuf);
            if asig.is_null() {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"sign_one\0"))
                        .as_ptr(),
                    2606 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"buffer error\0" as *const u8 as *const libc::c_char,
                );
                r = -(2 as libc::c_int);
            } else {
                if fd == 0 as libc::c_int {
                    fputs(asig, stdout);
                    libc::fflush(stdout);
                    current_block = 14832935472441733737;
                } else {
                    crate::xmalloc::xasprintf(
                        &mut wfile as *mut *mut libc::c_char,
                        b"%s.sig\0" as *const u8 as *const libc::c_char,
                        filename,
                    );
                    if confirm_overwrite(wfile) != 0 {
                        wfd = libc::open(
                            wfile,
                            0o1 as libc::c_int | 0o100 as libc::c_int | 0o1000 as libc::c_int,
                            0o666 as libc::c_int,
                        );
                        if wfd == -(1 as libc::c_int) {
                            oerrno = *libc::__errno_location();
                            crate::log::sshlog(
                                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(
                                    b"sign_one\0",
                                ))
                                .as_ptr(),
                                2621 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"Cannot open %s: %s\0" as *const u8 as *const libc::c_char,
                                wfile,
                                libc::strerror(*libc::__errno_location()),
                            );
                            *libc::__errno_location() = oerrno;
                            r = -(24 as libc::c_int);
                            current_block = 6958312750300924261;
                        } else if atomicio(
                            ::core::mem::transmute::<
                                Option<
                                    unsafe extern "C" fn(
                                        libc::c_int,
                                        *const libc::c_void,
                                        size_t,
                                    )
                                        -> ssize_t,
                                >,
                                Option<
                                    unsafe extern "C" fn(
                                        libc::c_int,
                                        *mut libc::c_void,
                                        size_t,
                                    )
                                        -> ssize_t,
                                >,
                            >(Some(
                                write
                                    as unsafe extern "C" fn(
                                        libc::c_int,
                                        *const libc::c_void,
                                        size_t,
                                    )
                                        -> ssize_t,
                            )),
                            wfd,
                            asig as *mut libc::c_void,
                            strlen(asig),
                        ) != strlen(asig)
                        {
                            oerrno = *libc::__errno_location();
                            crate::log::sshlog(
                                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(
                                    b"sign_one\0",
                                ))
                                .as_ptr(),
                                2630 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"Cannot write to %s: %s\0" as *const u8 as *const libc::c_char,
                                wfile,
                                libc::strerror(*libc::__errno_location()),
                            );
                            *libc::__errno_location() = oerrno;
                            r = -(24 as libc::c_int);
                            current_block = 6958312750300924261;
                        } else {
                            if quiet == 0 {
                                libc::fprintf(
                                    stderr,
                                    b"Write signature to %s\n\0" as *const u8
                                        as *const libc::c_char,
                                    wfile,
                                );
                            }
                            current_block = 14832935472441733737;
                        }
                    } else {
                        current_block = 14832935472441733737;
                    }
                }
                match current_block {
                    6958312750300924261 => {}
                    _ => {
                        r = 0 as libc::c_int;
                    }
                }
            }
        }
    }
    libc::free(wfile as *mut libc::c_void);
    libc::free(prompt as *mut libc::c_void);
    libc::free(asig as *mut libc::c_void);
    if !pin.is_null() {
        freezero(pin as *mut libc::c_void, strlen(pin));
    }
    crate::sshbuf::sshbuf_free(abuf);
    crate::sshbuf::sshbuf_free(sigbuf);
    if wfd != -(1 as libc::c_int) {
        close(wfd);
    }
    return r;
}
unsafe extern "C" fn sig_process_opts(
    mut opts: *const *mut libc::c_char,
    mut nopts: size_t,
    mut hashalgp: *mut *mut libc::c_char,
    mut verify_timep: *mut uint64_t,
    mut print_pubkey: *mut libc::c_int,
) -> libc::c_int {
    let mut i: size_t = 0;
    let mut now: time_t = 0;
    if !verify_timep.is_null() {
        *verify_timep = 0 as libc::c_int as uint64_t;
    }
    if !print_pubkey.is_null() {
        *print_pubkey = 0 as libc::c_int;
    }
    if !hashalgp.is_null() {
        *hashalgp = 0 as *mut libc::c_char;
    }
    i = 0 as libc::c_int as size_t;
    while i < nopts {
        if !hashalgp.is_null()
            && strncasecmp(
                *opts.offset(i as isize),
                b"hashalg=\0" as *const u8 as *const libc::c_char,
                8 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
        {
            *hashalgp = crate::xmalloc::xstrdup(
                (*opts.offset(i as isize)).offset(8 as libc::c_int as isize),
            );
        } else if !verify_timep.is_null()
            && strncasecmp(
                *opts.offset(i as isize),
                b"verify-time=\0" as *const u8 as *const libc::c_char,
                12 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
        {
            if parse_absolute_time(
                (*opts.offset(i as isize)).offset(12 as libc::c_int as isize),
                verify_timep,
            ) != 0 as libc::c_int
                || *verify_timep == 0 as libc::c_int as libc::c_ulong
            {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"sig_process_opts\0",
                    ))
                    .as_ptr(),
                    2677 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Invalid \"verify-time\" option\0" as *const u8 as *const libc::c_char,
                );
                return -(10 as libc::c_int);
            }
        } else if !print_pubkey.is_null()
            && strcasecmp(
                *opts.offset(i as isize),
                b"print-pubkey\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            *print_pubkey = 1 as libc::c_int;
        } else {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"sig_process_opts\0"))
                    .as_ptr(),
                2684 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Invalid option \"%s\"\0" as *const u8 as *const libc::c_char,
                *opts.offset(i as isize),
            );
            return -(10 as libc::c_int);
        }
        i = i.wrapping_add(1);
        i;
    }
    if !verify_timep.is_null() && *verify_timep == 0 as libc::c_int as libc::c_ulong {
        now = time(0 as *mut time_t);
        if now < 0 as libc::c_int as libc::c_long {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"sig_process_opts\0"))
                    .as_ptr(),
                2690 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Time is before epoch\0" as *const u8 as *const libc::c_char,
            );
            return -(10 as libc::c_int);
        }
        *verify_timep = now as uint64_t;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn sig_sign(
    mut keypath: *const libc::c_char,
    mut sig_namespace: *const libc::c_char,
    mut require_agent: libc::c_int,
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
    mut opts: *const *mut libc::c_char,
    mut nopts: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: libc::c_int = 0;
    let mut fd: libc::c_int = -(1 as libc::c_int);
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut agent_fd: libc::c_int = -(1 as libc::c_int);
    let mut pubkey: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut privkey: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut signkey: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut signer: Option<sshsig_signer> = None;
    let mut hashalg: *mut libc::c_char = 0 as *mut libc::c_char;
    i = 0 as libc::c_int;
    while i < argc {
        if !(libc::strcmp(
            *argv.offset(i as isize),
            b"-\0" as *const u8 as *const libc::c_char,
        ) != 0 as libc::c_int)
        {
            if i > 0 as libc::c_int || argc > 1 as libc::c_int {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"sig_sign\0"))
                        .as_ptr(),
                    2714 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Cannot sign mix of paths and standard input\0" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        i += 1;
        i;
    }
    if !(sig_process_opts(
        opts,
        nopts,
        &mut hashalg,
        0 as *mut uint64_t,
        0 as *mut libc::c_int,
    ) != 0 as libc::c_int)
    {
        r = sshkey_load_public(keypath, &mut pubkey, 0 as *mut *mut libc::c_char);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"sig_sign\0")).as_ptr(),
                2721 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"Couldn't load public key %s\0" as *const u8 as *const libc::c_char,
                keypath,
            );
        } else {
            r = ssh_get_authentication_socket(&mut agent_fd);
            if r != 0 as libc::c_int {
                if require_agent != 0 {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"sig_sign\0"))
                            .as_ptr(),
                        2727 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Couldn't get agent socket\0" as *const u8 as *const libc::c_char,
                    );
                }
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"sig_sign\0"))
                        .as_ptr(),
                    2728 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    ssh_err(r),
                    b"Couldn't get agent socket\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = ssh_agent_has_key(agent_fd, pubkey);
                if r == 0 as libc::c_int {
                    signer = Some(
                        agent_signer
                            as unsafe extern "C" fn(
                                *mut crate::sshkey::sshkey,
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
                    );
                } else {
                    if require_agent != 0 {
                        sshfatal(
                            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(
                                b"sig_sign\0",
                            ))
                            .as_ptr(),
                            2734 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Couldn't find key in agent\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    crate::log::sshlog(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"sig_sign\0"))
                            .as_ptr(),
                        2735 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        ssh_err(r),
                        b"Couldn't find key in agent\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if signer.is_none() {
                privkey = load_sign_key(keypath, pubkey);
                if privkey.is_null() {
                    current_block = 15713335055486353288;
                } else {
                    signkey = privkey;
                    current_block = 11194104282611034094;
                }
            } else {
                signkey = pubkey;
                current_block = 11194104282611034094;
            }
            match current_block {
                15713335055486353288 => {}
                _ => {
                    if argc == 0 as libc::c_int {
                        r = sign_one(
                            signkey,
                            b"(stdin)\0" as *const u8 as *const libc::c_char,
                            0 as libc::c_int,
                            sig_namespace,
                            hashalg,
                            signer,
                            &mut agent_fd as *mut libc::c_int as *mut libc::c_void,
                        );
                        if r != 0 as libc::c_int {
                            current_block = 15713335055486353288;
                        } else {
                            current_block = 6450636197030046351;
                        }
                    } else {
                        i = 0 as libc::c_int;
                        loop {
                            if !(i < argc) {
                                current_block = 6450636197030046351;
                                break;
                            }
                            if libc::strcmp(
                                *argv.offset(i as isize),
                                b"-\0" as *const u8 as *const libc::c_char,
                            ) == 0 as libc::c_int
                            {
                                fd = 0 as libc::c_int;
                            } else {
                                fd = libc::open(*argv.offset(i as isize), 0 as libc::c_int);
                                if fd == -(1 as libc::c_int) {
                                    crate::log::sshlog(
                                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(
                                            b"sig_sign\0",
                                        ))
                                        .as_ptr(),
                                        2759 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"Cannot open %s for signing: %s\0" as *const u8
                                            as *const libc::c_char,
                                        *argv.offset(i as isize),
                                        libc::strerror(*libc::__errno_location()),
                                    );
                                    current_block = 15713335055486353288;
                                    break;
                                }
                            }
                            r = sign_one(
                                signkey,
                                *argv.offset(i as isize),
                                fd,
                                sig_namespace,
                                hashalg,
                                signer,
                                &mut agent_fd as *mut libc::c_int as *mut libc::c_void,
                            );
                            if r != 0 as libc::c_int {
                                current_block = 15713335055486353288;
                                break;
                            }
                            if fd != 0 as libc::c_int {
                                close(fd);
                            }
                            fd = -(1 as libc::c_int);
                            i += 1;
                            i;
                        }
                    }
                    match current_block {
                        15713335055486353288 => {}
                        _ => {
                            ret = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    if fd != -(1 as libc::c_int) && fd != 0 as libc::c_int {
        close(fd);
    }
    crate::sshkey::sshkey_free(pubkey);
    crate::sshkey::sshkey_free(privkey);
    libc::free(hashalg as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn sig_verify(
    mut signature: *const libc::c_char,
    mut sig_namespace: *const libc::c_char,
    mut principal: *const libc::c_char,
    mut allowed_keys: *const libc::c_char,
    mut revoked_keys: *const libc::c_char,
    mut opts: *const *mut libc::c_char,
    mut nopts: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut print_pubkey: libc::c_int = 0 as libc::c_int;
    let mut sigbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut abuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sign_key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sig_details: *mut sshkey_sig_details = 0 as *mut sshkey_sig_details;
    let mut verify_time: uint64_t = 0 as libc::c_int as uint64_t;
    if !(sig_process_opts(
        opts,
        nopts,
        0 as *mut *mut libc::c_char,
        &mut verify_time,
        &mut print_pubkey,
    ) != 0 as libc::c_int)
    {
        memset(
            &mut sig_details as *mut *mut sshkey_sig_details as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<*mut sshkey_sig_details>() as libc::c_ulong,
        );
        r = sshbuf_load_file(signature, &mut abuf);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sig_verify\0"))
                    .as_ptr(),
                2800 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"Couldn't read signature file\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = sshsig_dearmor(abuf, &mut sigbuf);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sig_verify\0"))
                        .as_ptr(),
                    2805 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"sshsig_armor\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = sshsig_verify_fd(
                    sigbuf,
                    0 as libc::c_int,
                    sig_namespace,
                    &mut sign_key,
                    &mut sig_details,
                );
                if !(r != 0 as libc::c_int) {
                    fp = crate::sshkey::sshkey_fingerprint(
                        sign_key,
                        fingerprint_hash,
                        SSH_FP_DEFAULT,
                    );
                    if fp.is_null() {
                        sshfatal(
                            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                b"sig_verify\0",
                            ))
                            .as_ptr(),
                            2814 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"crate::sshkey::sshkey_fingerprint failed\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    crate::log::sshlog(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"sig_verify\0",
                        ))
                        .as_ptr(),
                        2815 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"Valid (unverified) signature from key %s\0" as *const u8
                            as *const libc::c_char,
                        fp,
                    );
                    if !sig_details.is_null() {
                        crate::log::sshlog(
                            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                b"sig_verify\0",
                            ))
                            .as_ptr(),
                            2818 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"signature details: counter = %u, flags = 0x%02x\0" as *const u8
                                as *const libc::c_char,
                            (*sig_details).sk_counter,
                            (*sig_details).sk_flags as libc::c_int,
                        );
                    }
                    libc::free(fp as *mut libc::c_void);
                    fp = 0 as *mut libc::c_char;
                    if !revoked_keys.is_null() {
                        r = sshkey_check_revoked(sign_key, revoked_keys);
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                    b"sig_verify\0",
                                ))
                                .as_ptr(),
                                2825 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG3,
                                ssh_err(r),
                                b"sshkey_check_revoked\0" as *const u8 as *const libc::c_char,
                            );
                            current_block = 1689576451005301918;
                        } else {
                            current_block = 5689001924483802034;
                        }
                    } else {
                        current_block = 5689001924483802034;
                    }
                    match current_block {
                        1689576451005301918 => {}
                        _ => {
                            if !allowed_keys.is_null() && {
                                r = sshsig_check_allowed_keys(
                                    allowed_keys,
                                    sign_key,
                                    principal,
                                    sig_namespace,
                                    verify_time,
                                );
                                r != 0 as libc::c_int
                            } {
                                crate::log::sshlog(
                                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                        b"sig_verify\0",
                                    ))
                                    .as_ptr(),
                                    2832 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG3,
                                    ssh_err(r),
                                    b"sshsig_check_allowed_keys\0" as *const u8
                                        as *const libc::c_char,
                                );
                            } else {
                                ret = 0 as libc::c_int;
                            }
                        }
                    }
                }
            }
        }
    }
    if quiet == 0 {
        if ret == 0 as libc::c_int {
            fp = crate::sshkey::sshkey_fingerprint(sign_key, fingerprint_hash, SSH_FP_DEFAULT);
            if fp.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sig_verify\0"))
                        .as_ptr(),
                    2842 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"crate::sshkey::sshkey_fingerprint failed\0" as *const u8
                        as *const libc::c_char,
                );
            }
            if principal.is_null() {
                printf(
                    b"Good \"%s\" signature with %s key %s\n\0" as *const u8 as *const libc::c_char,
                    sig_namespace,
                    crate::sshkey::sshkey_type(sign_key),
                    fp,
                );
            } else {
                printf(
                    b"Good \"%s\" signature for %s with %s key %s\n\0" as *const u8
                        as *const libc::c_char,
                    sig_namespace,
                    principal,
                    crate::sshkey::sshkey_type(sign_key),
                    fp,
                );
            }
        } else {
            printf(b"Could not verify signature.\n\0" as *const u8 as *const libc::c_char);
        }
    }
    if ret == 0 as libc::c_int && print_pubkey != 0 && !sign_key.is_null() {
        r = sshkey_write(sign_key, stdout);
        if r == 0 as libc::c_int {
            fputc('\n' as i32, stdout);
        } else {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sig_verify\0"))
                    .as_ptr(),
                2861 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"Could not print public key.\n\0" as *const u8 as *const libc::c_char,
            );
            ret = -(1 as libc::c_int);
        }
    }
    crate::sshbuf::sshbuf_free(sigbuf);
    crate::sshbuf::sshbuf_free(abuf);
    crate::sshkey::sshkey_free(sign_key);
    sshkey_sig_details_free(sig_details);
    libc::free(fp as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn sig_find_principals(
    mut signature: *const libc::c_char,
    mut allowed_keys: *const libc::c_char,
    mut opts: *const *mut libc::c_char,
    mut nopts: size_t,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut sigbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut abuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sign_key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut principals: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut verify_time: uint64_t = 0 as libc::c_int as uint64_t;
    if !(sig_process_opts(
        opts,
        nopts,
        0 as *mut *mut libc::c_char,
        &mut verify_time,
        0 as *mut libc::c_int,
    ) != 0 as libc::c_int)
    {
        r = sshbuf_load_file(signature, &mut abuf);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"sig_find_principals\0",
                ))
                .as_ptr(),
                2887 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"Couldn't read signature file\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = sshsig_dearmor(abuf, &mut sigbuf);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"sig_find_principals\0",
                    ))
                    .as_ptr(),
                    2891 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"sshsig_armor\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = sshsig_get_pubkey(sigbuf, &mut sign_key);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"sig_find_principals\0",
                        ))
                        .as_ptr(),
                        2895 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"sshsig_get_pubkey\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    r = sshsig_find_principals(
                        allowed_keys,
                        sign_key,
                        verify_time,
                        &mut principals,
                    );
                    if r != 0 as libc::c_int {
                        if r != -(46 as libc::c_int) {
                            crate::log::sshlog(
                                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                    b"sig_find_principals\0",
                                ))
                                .as_ptr(),
                                2901 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"sshsig_find_principal\0" as *const u8 as *const libc::c_char,
                            );
                        }
                    } else {
                        ret = 0 as libc::c_int;
                    }
                }
            }
        }
    }
    if ret == 0 as libc::c_int {
        tmp = principals;
        loop {
            cp = strsep(&mut tmp, b",\0" as *const u8 as *const libc::c_char);
            if !(!cp.is_null() && *cp as libc::c_int != '\0' as i32) {
                break;
            }
            puts(cp);
        }
    } else {
        libc::fprintf(
            stderr,
            b"No principal matched.\n\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_free(sigbuf);
    crate::sshbuf::sshbuf_free(abuf);
    crate::sshkey::sshkey_free(sign_key);
    libc::free(principals as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn sig_match_principals(
    mut allowed_keys: *const libc::c_char,
    mut principal: *mut libc::c_char,
    mut opts: *const *mut libc::c_char,
    mut nopts: size_t,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut principals: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut i: size_t = 0;
    let mut nprincipals: size_t = 0 as libc::c_int as size_t;
    r = sig_process_opts(
        opts,
        nopts,
        0 as *mut *mut libc::c_char,
        0 as *mut uint64_t,
        0 as *mut libc::c_int,
    );
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshsig_match_principals(allowed_keys, principal, &mut principals, &mut nprincipals);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"sig_match_principals\0"))
                .as_ptr(),
            2934 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"match: %s\0" as *const u8 as *const libc::c_char,
            ssh_err(r),
        );
        libc::fprintf(
            stderr,
            b"No principal matched.\n\0" as *const u8 as *const libc::c_char,
        );
        return r;
    }
    i = 0 as libc::c_int as size_t;
    while i < nprincipals {
        printf(
            b"%s\n\0" as *const u8 as *const libc::c_char,
            *principals.offset(i as isize),
        );
        libc::free(*principals.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(principals as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn do_moduli_gen(
    mut out_file: *const libc::c_char,
    mut opts: *mut *mut libc::c_char,
    mut nopts: size_t,
) {
    let mut memory: u_int32_t = 0 as libc::c_int as u_int32_t;
    let mut start: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut moduli_bits: libc::c_int = 0 as libc::c_int;
    let mut out: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut i: size_t = 0;
    let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
    i = 0 as libc::c_int as size_t;
    while i < nopts {
        if strncmp(
            *opts.offset(i as isize),
            b"memory=\0" as *const u8 as *const libc::c_char,
            7 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            memory = crate::openbsd_compat::strtonum::strtonum(
                (*opts.offset(i as isize)).offset(7 as libc::c_int as isize),
                1 as libc::c_int as libc::c_longlong,
                (2147483647 as libc::c_int as libc::c_uint)
                    .wrapping_mul(2 as libc::c_uint)
                    .wrapping_add(1 as libc::c_uint) as libc::c_longlong,
                &mut errstr,
            ) as u_int32_t;
            if !errstr.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"do_moduli_gen\0"))
                        .as_ptr(),
                    2966 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Memory limit is %s: %s\0" as *const u8 as *const libc::c_char,
                    errstr,
                    (*opts.offset(i as isize)).offset(7 as libc::c_int as isize),
                );
            }
        } else if strncmp(
            *opts.offset(i as isize),
            b"start=\0" as *const u8 as *const libc::c_char,
            6 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            if BN_hex2bn(
                &mut start,
                (*opts.offset(i as isize)).offset(6 as libc::c_int as isize),
            ) == 0 as libc::c_int
            {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"do_moduli_gen\0"))
                        .as_ptr(),
                    2971 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Invalid start point.\0" as *const u8 as *const libc::c_char,
                );
            }
        } else if strncmp(
            *opts.offset(i as isize),
            b"bits=\0" as *const u8 as *const libc::c_char,
            5 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            moduli_bits = crate::openbsd_compat::strtonum::strtonum(
                (*opts.offset(i as isize)).offset(5 as libc::c_int as isize),
                1 as libc::c_int as libc::c_longlong,
                2147483647 as libc::c_int as libc::c_longlong,
                &mut errstr,
            ) as libc::c_int;
            if !errstr.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"do_moduli_gen\0"))
                        .as_ptr(),
                    2977 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Invalid number: %s (%s)\0" as *const u8 as *const libc::c_char,
                    (*opts.offset(i as isize)).offset(12 as libc::c_int as isize),
                    errstr,
                );
            }
        } else {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"do_moduli_gen\0"))
                    .as_ptr(),
                2981 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Option \"%s\" is unsupported for moduli generation\0" as *const u8
                    as *const libc::c_char,
                *opts.offset(i as isize),
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    out = fopen(out_file, b"w\0" as *const u8 as *const libc::c_char);
    if out.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"do_moduli_gen\0"))
                .as_ptr(),
            2987 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Couldn't open modulus candidate file \"%s\": %s\0" as *const u8
                as *const libc::c_char,
            out_file,
            libc::strerror(*libc::__errno_location()),
        );
    }
    setvbuf(
        out,
        0 as *mut libc::c_char,
        1 as libc::c_int,
        0 as libc::c_int as size_t,
    );
    if moduli_bits == 0 as libc::c_int {
        moduli_bits = 3072 as libc::c_int;
    }
    if gen_candidates(out, memory, moduli_bits as u_int32_t, start) != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"do_moduli_gen\0"))
                .as_ptr(),
            2994 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"modulus candidate generation failed\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn do_moduli_screen(
    mut out_file: *const libc::c_char,
    mut opts: *mut *mut libc::c_char,
    mut nopts: size_t,
) {
    let mut checkpoint: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut generator_wanted: u_int32_t = 0 as libc::c_int as u_int32_t;
    let mut start_lineno: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
    let mut lines_to_process: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
    let mut prime_tests: libc::c_int = 0 as libc::c_int;
    let mut out: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut in_0: *mut libc::FILE = stdin;
    let mut i: size_t = 0;
    let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
    i = 0 as libc::c_int as size_t;
    while i < nopts {
        if strncmp(
            *opts.offset(i as isize),
            b"lines=\0" as *const u8 as *const libc::c_char,
            6 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            lines_to_process = strtoul(
                (*opts.offset(i as isize)).offset(6 as libc::c_int as isize),
                0 as *mut *mut libc::c_char,
                10 as libc::c_int,
            );
        } else if strncmp(
            *opts.offset(i as isize),
            b"start-line=\0" as *const u8 as *const libc::c_char,
            11 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            start_lineno = strtoul(
                (*opts.offset(i as isize)).offset(11 as libc::c_int as isize),
                0 as *mut *mut libc::c_char,
                10 as libc::c_int,
            );
        } else if strncmp(
            *opts.offset(i as isize),
            b"checkpoint=\0" as *const u8 as *const libc::c_char,
            11 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            libc::free(checkpoint as *mut libc::c_void);
            checkpoint = crate::xmalloc::xstrdup(
                (*opts.offset(i as isize)).offset(11 as libc::c_int as isize),
            );
        } else if strncmp(
            *opts.offset(i as isize),
            b"generator=\0" as *const u8 as *const libc::c_char,
            10 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            generator_wanted = crate::openbsd_compat::strtonum::strtonum(
                (*opts.offset(i as isize)).offset(10 as libc::c_int as isize),
                1 as libc::c_int as libc::c_longlong,
                (2147483647 as libc::c_int as libc::c_uint)
                    .wrapping_mul(2 as libc::c_uint)
                    .wrapping_add(1 as libc::c_uint) as libc::c_longlong,
                &mut errstr,
            ) as u_int32_t;
            if !errstr.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"do_moduli_screen\0",
                    ))
                    .as_ptr(),
                    3027 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Generator invalid: %s (%s)\0" as *const u8 as *const libc::c_char,
                    (*opts.offset(i as isize)).offset(10 as libc::c_int as isize),
                    errstr,
                );
            }
        } else if strncmp(
            *opts.offset(i as isize),
            b"prime-tests=\0" as *const u8 as *const libc::c_char,
            12 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            prime_tests = crate::openbsd_compat::strtonum::strtonum(
                (*opts.offset(i as isize)).offset(12 as libc::c_int as isize),
                1 as libc::c_int as libc::c_longlong,
                2147483647 as libc::c_int as libc::c_longlong,
                &mut errstr,
            ) as libc::c_int;
            if !errstr.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"do_moduli_screen\0",
                    ))
                    .as_ptr(),
                    3034 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Invalid number: %s (%s)\0" as *const u8 as *const libc::c_char,
                    (*opts.offset(i as isize)).offset(12 as libc::c_int as isize),
                    errstr,
                );
            }
        } else {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"do_moduli_screen\0"))
                    .as_ptr(),
                3038 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Option \"%s\" is unsupported for moduli screening\0" as *const u8
                    as *const libc::c_char,
                *opts.offset(i as isize),
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    if have_identity != 0
        && libc::strcmp(
            identity_file.as_mut_ptr(),
            b"-\0" as *const u8 as *const libc::c_char,
        ) != 0 as libc::c_int
    {
        in_0 = fopen(
            identity_file.as_mut_ptr(),
            b"r\0" as *const u8 as *const libc::c_char,
        );
        if in_0.is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"do_moduli_screen\0"))
                    .as_ptr(),
                3046 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Couldn't open modulus candidate file \"%s\": %s\0" as *const u8
                    as *const libc::c_char,
                identity_file.as_mut_ptr(),
                libc::strerror(*libc::__errno_location()),
            );
        }
    }
    out = fopen(out_file, b"a\0" as *const u8 as *const libc::c_char);
    if out.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"do_moduli_screen\0"))
                .as_ptr(),
            3052 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Couldn't open moduli file \"%s\": %s\0" as *const u8 as *const libc::c_char,
            out_file,
            libc::strerror(*libc::__errno_location()),
        );
    }
    setvbuf(
        out,
        0 as *mut libc::c_char,
        1 as libc::c_int,
        0 as libc::c_int as size_t,
    );
    if prime_test(
        in_0,
        out,
        (if prime_tests == 0 as libc::c_int {
            100 as libc::c_int
        } else {
            prime_tests
        }) as u_int32_t,
        generator_wanted,
        checkpoint,
        start_lineno,
        lines_to_process,
    ) != 0 as libc::c_int
    {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"do_moduli_screen\0"))
                .as_ptr(),
            3058 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"modulus screening failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if in_0 != stdin {
        fclose(in_0);
    }
    libc::free(checkpoint as *mut libc::c_void);
}
unsafe extern "C" fn read_check_passphrase(
    mut prompt1: *const libc::c_char,
    mut prompt2: *const libc::c_char,
    mut retry_prompt: *const libc::c_char,
) -> *mut libc::c_char {
    let mut passphrase1: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut passphrase2: *mut libc::c_char = 0 as *mut libc::c_char;
    loop {
        passphrase1 = read_passphrase(prompt1, 0x2 as libc::c_int);
        passphrase2 = read_passphrase(prompt2, 0x2 as libc::c_int);
        if libc::strcmp(passphrase1, passphrase2) == 0 as libc::c_int {
            freezero(passphrase2 as *mut libc::c_void, strlen(passphrase2));
            return passphrase1;
        }
        freezero(passphrase1 as *mut libc::c_void, strlen(passphrase1));
        freezero(passphrase2 as *mut libc::c_void, strlen(passphrase2));
        fputs(retry_prompt, stdout);
        fputc('\n' as i32, stdout);
        libc::fflush(stdout);
    }
}
unsafe extern "C" fn private_key_passphrase() -> *mut libc::c_char {
    if !identity_passphrase.is_null() {
        return crate::xmalloc::xstrdup(identity_passphrase);
    }
    if !identity_new_passphrase.is_null() {
        return crate::xmalloc::xstrdup(identity_new_passphrase);
    }
    return read_check_passphrase(
        b"Enter passphrase (empty for no passphrase): \0" as *const u8 as *const libc::c_char,
        b"Enter same passphrase again: \0" as *const u8 as *const libc::c_char,
        b"Passphrases do not match.  Try again.\0" as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn sk_suffix(
    mut application: *const libc::c_char,
    mut user: *const uint8_t,
    mut userlen: size_t,
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut slen: size_t = 0;
    let mut i: size_t = 0;
    if strncmp(
        application,
        b"ssh://\0" as *const u8 as *const libc::c_char,
        6 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        ret = crate::xmalloc::xstrdup(application.offset(6 as libc::c_int as isize));
    } else if strncmp(
        application,
        b"ssh:\0" as *const u8 as *const libc::c_char,
        4 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        ret = crate::xmalloc::xstrdup(application.offset(4 as libc::c_int as isize));
    } else {
        ret = crate::xmalloc::xstrdup(application);
    }
    i = 0 as libc::c_int as size_t;
    while i < userlen {
        if *user.offset(
            userlen
                .wrapping_sub(i)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
        ) as libc::c_int
            != 0 as libc::c_int
        {
            break;
        }
        i = i.wrapping_add(1);
        i;
    }
    if i >= userlen {
        return ret;
    }
    slen = userlen.wrapping_sub(i);
    if asmprintf(
        &mut cp as *mut *mut libc::c_char,
        2147483647 as libc::c_int as size_t,
        0 as *mut libc::c_int,
        b"%.*s\0" as *const u8 as *const libc::c_char,
        slen as libc::c_int,
        user,
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"sk_suffix\0")).as_ptr(),
            3131 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"asmprintf failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(libc::strchr(cp, '/' as i32)).is_null()
        || !(strstr(cp, b"..\0" as *const u8 as *const libc::c_char)).is_null()
        || !(libc::strchr(cp, '\\' as i32)).is_null()
    {
        libc::free(cp as *mut libc::c_void);
        cp = tohex(user as *const libc::c_void, slen);
    }
    xextendf(
        &mut ret as *mut *mut libc::c_char,
        b"_\0" as *const u8 as *const libc::c_char,
        b"%s\0" as *const u8 as *const libc::c_char,
        cp,
    );
    libc::free(cp as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn do_download_sk(
    mut skprovider: *const libc::c_char,
    mut device: *const libc::c_char,
) -> libc::c_int {
    let mut srks: *mut *mut sshsk_resident_key = 0 as *mut *mut sshsk_resident_key;
    let mut nsrks: size_t = 0;
    let mut i: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pass: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pubpath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ext: *const libc::c_char = 0 as *const libc::c_char;
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    if skprovider.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_download_sk\0"))
                .as_ptr(),
            3154 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Cannot download keys without provider\0" as *const u8 as *const libc::c_char,
        );
    }
    pin = read_passphrase(
        b"Enter PIN for authenticator: \0" as *const u8 as *const libc::c_char,
        0x2 as libc::c_int,
    );
    if quiet == 0 {
        printf(
            b"You may need to touch your authenticator to authorize key download.\n\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshsk_load_resident(
        skprovider,
        device,
        pin,
        0 as libc::c_int as u_int,
        &mut srks,
        &mut nsrks,
    );
    if r != 0 as libc::c_int {
        if !pin.is_null() {
            freezero(pin as *mut libc::c_void, strlen(pin));
        }
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_download_sk\0"))
                .as_ptr(),
            3165 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"Unable to load resident keys\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if nsrks == 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_download_sk\0"))
                .as_ptr(),
            3169 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"No keys to download\0" as *const u8 as *const libc::c_char,
        );
    }
    if !pin.is_null() {
        freezero(pin as *mut libc::c_void, strlen(pin));
    }
    i = 0 as libc::c_int as size_t;
    while i < nsrks {
        key = (**srks.offset(i as isize)).key;
        if (*key).type_0 != KEY_ECDSA_SK as libc::c_int
            && (*key).type_0 != KEY_ED25519_SK as libc::c_int
        {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_download_sk\0"))
                    .as_ptr(),
                3177 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Unsupported key type %s (%d)\0" as *const u8 as *const libc::c_char,
                crate::sshkey::sshkey_type(key),
                (*key).type_0,
            );
        } else {
            fp = crate::sshkey::sshkey_fingerprint(key, fingerprint_hash, SSH_FP_DEFAULT);
            if fp.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"do_download_sk\0",
                    ))
                    .as_ptr(),
                    3182 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"crate::sshkey::sshkey_fingerprint failed\0" as *const u8
                        as *const libc::c_char,
                );
            }
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_download_sk\0"))
                    .as_ptr(),
                3184 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"key %zu: %s %s %s (flags 0x%02x)\0" as *const u8 as *const libc::c_char,
                i,
                crate::sshkey::sshkey_type(key),
                fp,
                (*key).sk_application,
                (*key).sk_flags as libc::c_int,
            );
            ext = sk_suffix(
                (*key).sk_application,
                (**srks.offset(i as isize)).user_id,
                (**srks.offset(i as isize)).user_id_len,
            );
            crate::xmalloc::xasprintf(
                &mut path as *mut *mut libc::c_char,
                b"id_%s_rk%s%s\0" as *const u8 as *const libc::c_char,
                if (*key).type_0 == KEY_ECDSA_SK as libc::c_int {
                    b"ecdsa_sk\0" as *const u8 as *const libc::c_char
                } else {
                    b"ed25519_sk\0" as *const u8 as *const libc::c_char
                },
                if *ext as libc::c_int == '\0' as i32 {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    b"_\0" as *const u8 as *const libc::c_char
                },
                ext,
            );
            if confirm_overwrite(path) == 0 {
                libc::free(path as *mut libc::c_void);
                break;
            } else {
                if pass.is_null() {
                    pass = private_key_passphrase();
                }
                r = sshkey_save_private(
                    key,
                    path,
                    pass,
                    (*key).sk_application,
                    private_key_format,
                    openssh_format_cipher,
                    rounds,
                );
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"do_download_sk\0",
                        ))
                        .as_ptr(),
                        3203 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"Saving key \"%s\" failed\0" as *const u8 as *const libc::c_char,
                        path,
                    );
                    libc::free(path as *mut libc::c_void);
                    break;
                } else {
                    if quiet == 0 {
                        printf(
                            b"Saved %s key%s%s to %s\n\0" as *const u8 as *const libc::c_char,
                            crate::sshkey::sshkey_type(key),
                            if *ext as libc::c_int != '\0' as i32 {
                                b" \0" as *const u8 as *const libc::c_char
                            } else {
                                b"\0" as *const u8 as *const libc::c_char
                            },
                            if *ext as libc::c_int != '\0' as i32 {
                                (*key).sk_application as *const libc::c_char
                            } else {
                                b"\0" as *const u8 as *const libc::c_char
                            },
                            path,
                        );
                    }
                    crate::xmalloc::xasprintf(
                        &mut pubpath as *mut *mut libc::c_char,
                        b"%s.pub\0" as *const u8 as *const libc::c_char,
                        path,
                    );
                    libc::free(path as *mut libc::c_void);
                    r = sshkey_save_public(key, pubpath, (*key).sk_application);
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"do_download_sk\0",
                            ))
                            .as_ptr(),
                            3219 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"Saving public key \"%s\" failed\0" as *const u8
                                as *const libc::c_char,
                            pubpath,
                        );
                        libc::free(pubpath as *mut libc::c_void);
                        break;
                    } else {
                        libc::free(pubpath as *mut libc::c_void);
                    }
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    if i >= nsrks {
        ret = 0 as libc::c_int;
    }
    if !pass.is_null() {
        freezero(pass as *mut libc::c_void, strlen(pass));
    }
    sshsk_free_resident_keys(srks, nsrks);
    return ret;
}
unsafe extern "C" fn save_attestation(
    mut attest: *mut crate::sshbuf::sshbuf,
    mut path: *const libc::c_char,
) {
    let mut omask: mode_t = 0;
    let mut r: libc::c_int = 0;
    if path.is_null() {
        return;
    }
    if attest.is_null() || crate::sshbuf::sshbuf_len(attest) == 0 as libc::c_int as libc::c_ulong {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"save_attestation\0"))
                .as_ptr(),
            3243 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Enrollment did not return attestation data\0" as *const u8 as *const libc::c_char,
        );
    }
    omask = libc::umask(0o77 as libc::c_int as __mode_t);
    r = sshbuf_write_file(path, attest);
    libc::umask(omask);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"save_attestation\0"))
                .as_ptr(),
            3248 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"Unable to write attestation data \"%s\"\0" as *const u8 as *const libc::c_char,
            path,
        );
    }
    if quiet == 0 {
        printf(
            b"Your FIDO attestation certificate has been saved in %s\n\0" as *const u8
                as *const libc::c_char,
            path,
        );
    }
}
unsafe extern "C" fn confirm_sk_overwrite(
    mut application: *const libc::c_char,
    mut user: *const libc::c_char,
) -> libc::c_int {
    let mut yesno: [libc::c_char; 3] = [0; 3];
    printf(
        b"A resident key scoped to '%s' with user id '%s' already exists.\n\0" as *const u8
            as *const libc::c_char,
        if application.is_null() {
            b"ssh:\0" as *const u8 as *const libc::c_char
        } else {
            application
        },
        if user.is_null() {
            b"null\0" as *const u8 as *const libc::c_char
        } else {
            user
        },
    );
    printf(b"Overwrite key in token (y/n)? \0" as *const u8 as *const libc::c_char);
    libc::fflush(stdout);
    if (fgets(
        yesno.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 3]>() as libc::c_ulong as libc::c_int,
        stdin,
    ))
    .is_null()
    {
        return 0 as libc::c_int;
    }
    if yesno[0 as libc::c_int as usize] as libc::c_int != 'y' as i32
        && yesno[0 as libc::c_int as usize] as libc::c_int != 'Y' as i32
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn usage() {
    libc::fprintf(
        stderr,
        b"usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]\n                  [-m format] [-N new_passphrase] [-O option]\n                  [-t dsa | ecdsa | ecdsa-sk | ed25519 | ed25519-sk | rsa]\n                  [-w provider] [-Z cipher]\n       ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase]\n                   [-P old_passphrase] [-Z cipher]\n       ssh-keygen -i [-f input_keyfile] [-m key_format]\n       ssh-keygen -e [-f input_keyfile] [-m key_format]\n       ssh-keygen -y [-f input_keyfile]\n       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n       ssh-keygen -B [-f input_keyfile]\n\0"
            as *const u8 as *const libc::c_char,
    );
    libc::fprintf(
        stderr,
        b"       ssh-keygen -D pkcs11\n\0" as *const u8 as *const libc::c_char,
    );
    libc::fprintf(
        stderr,
        b"       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n       ssh-keygen -H [-f known_hosts_file]\n       ssh-keygen -K [-a rounds] [-w provider]\n       ssh-keygen -R hostname [-f known_hosts_file]\n       ssh-keygen -r hostname [-g] [-f input_keyfile]\n       ssh-keygen -M generate [-O option] output_file\n       ssh-keygen -M screen [-f input_file] [-O option] output_file\n       ssh-keygen -I certificate_identity -s ca_key [-hU] [-D pkcs11_provider]\n                  [-n principals] [-O option] [-V validity_interval]\n                  [-z serial_number] file ...\n       ssh-keygen -L [-f input_keyfile]\n       ssh-keygen -A [-a rounds] [-f prefix_path]\n       ssh-keygen -k -f krl_file [-u] [-s ca_public] [-z version_number]\n                  file ...\n       ssh-keygen -Q [-l] -f krl_file [file ...]\n       ssh-keygen -Y find-principals -s signature_file -f allowed_signers_file\n       ssh-keygen -Y match-principals -I signer_identity -f allowed_signers_file\n       ssh-keygen -Y check-novalidate -n namespace -s signature_file\n       ssh-keygen -Y sign -f key_file -n namespace file [-O option] ...\n       ssh-keygen -Y verify -f allowed_signers_file -I signer_identity\n                  -n namespace -s signature_file [-r krl_file] [-O option]\n\0"
            as *const u8 as *const libc::c_char,
    );
    libc::exit(1 as libc::c_int);
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char) -> libc::c_int {
    let mut comment: [libc::c_char; 1024] = [0; 1024];
    let mut passphrase: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut rr_hostname: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ra: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut private: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut public: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut pw: *mut libc::passwd = 0 as *mut libc::passwd;
    let mut r: libc::c_int = 0;
    let mut opt: libc::c_int = 0;
    let mut type_0: libc::c_int = 0;
    let mut change_passphrase: libc::c_int = 0 as libc::c_int;
    let mut change_comment: libc::c_int = 0 as libc::c_int;
    let mut show_cert: libc::c_int = 0 as libc::c_int;
    let mut find_host: libc::c_int = 0 as libc::c_int;
    let mut delete_host: libc::c_int = 0 as libc::c_int;
    let mut hash_hosts: libc::c_int = 0 as libc::c_int;
    let mut gen_all_hostkeys: libc::c_int = 0 as libc::c_int;
    let mut gen_krl: libc::c_int = 0 as libc::c_int;
    let mut update_krl: libc::c_int = 0 as libc::c_int;
    let mut check_krl: libc::c_int = 0 as libc::c_int;
    let mut prefer_agent: libc::c_int = 0 as libc::c_int;
    let mut convert_to: libc::c_int = 0 as libc::c_int;
    let mut convert_from: libc::c_int = 0 as libc::c_int;
    let mut print_public: libc::c_int = 0 as libc::c_int;
    let mut print_generic: libc::c_int = 0 as libc::c_int;
    let mut cert_serial_autoinc: libc::c_int = 0 as libc::c_int;
    let mut do_gen_candidates: libc::c_int = 0 as libc::c_int;
    let mut do_screen_candidates: libc::c_int = 0 as libc::c_int;
    let mut download_sk: libc::c_int = 0 as libc::c_int;
    let mut cert_serial: libc::c_ulonglong = 0 as libc::c_int as libc::c_ulonglong;
    let mut identity_comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ca_key_path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut opts: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut sk_application: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sk_device: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sk_user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sk_attestation_path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut challenge: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut attest: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut i: size_t = 0;
    let mut nopts: size_t = 0 as libc::c_int as size_t;
    let mut bits: u_int32_t = 0 as libc::c_int as u_int32_t;
    let mut sk_flags: uint8_t = 0x1 as libc::c_int as uint8_t;
    let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
    let mut log_level: libc::c_int = SYSLOG_LEVEL_INFO as libc::c_int;
    let mut sign_op: *mut libc::c_char = 0 as *mut libc::c_char;
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptarg"]
        static mut BSDoptarg_0: *mut libc::c_char;
    }
    crate::misc::sanitise_stdfd();
    __progname =
        crate::openbsd_compat::bsd_misc::ssh_get_progname(*argv.offset(0 as libc::c_int as isize));
    seed_rng();
    log_init(
        *argv.offset(0 as libc::c_int as isize),
        SYSLOG_LEVEL_INFO,
        SYSLOG_FACILITY_USER,
        1 as libc::c_int,
    );
    msetlocale();
    pw = libc::getpwuid(libc::getuid());
    if pw.is_null() {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            3366 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"No user exists for uid %lu\0" as *const u8 as *const libc::c_char,
            libc::getuid() as u_long,
        );
    }
    pw = pwcopy(pw);
    if gethostname(
        hostname.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            3369 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"gethostname: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    sk_provider = getenv(b"SSH_SK_PROVIDER\0" as *const u8 as *const libc::c_char);
    loop {
        opt = crate::openbsd_compat::getopt_long::BSDgetopt(
            argc,
            argv,
            b"ABHKLQUXceghiklopquvyC:D:E:F:I:M:N:O:P:R:V:Y:Z:a:b:f:g:m:n:r:s:t:w:z:\0" as *const u8
                as *const libc::c_char,
        );
        if !(opt != -(1 as libc::c_int)) {
            break;
        }
        match opt {
            65 => {
                gen_all_hostkeys = 1 as libc::c_int;
            }
            98 => {
                bits = crate::openbsd_compat::strtonum::strtonum(
                    BSDoptarg,
                    1 as libc::c_int as libc::c_longlong,
                    4294967295 as libc::c_uint as libc::c_longlong,
                    &mut errstr,
                ) as u_int32_t;
                if !errstr.is_null() {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        3386 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Bits has bad value %s (%s)\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                        errstr,
                    );
                }
            }
            69 => {
                fingerprint_hash = ssh_digest_alg_by_name(BSDoptarg);
                if fingerprint_hash == -(1 as libc::c_int) {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        3391 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Invalid hash algorithm \"%s\"\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                    );
                }
            }
            70 => {
                find_host = 1 as libc::c_int;
                rr_hostname = BSDoptarg;
            }
            72 => {
                hash_hosts = 1 as libc::c_int;
            }
            73 => {
                cert_key_id = BSDoptarg;
            }
            82 => {
                delete_host = 1 as libc::c_int;
                rr_hostname = BSDoptarg;
            }
            76 => {
                show_cert = 1 as libc::c_int;
            }
            108 => {
                print_fingerprint = 1 as libc::c_int;
            }
            66 => {
                print_bubblebabble = 1 as libc::c_int;
            }
            109 => {
                if strcasecmp(BSDoptarg, b"RFC4716\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                    || strcasecmp(BSDoptarg, b"ssh2\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                {
                    convert_format = FMT_RFC4716;
                } else if strcasecmp(BSDoptarg, b"PKCS8\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    convert_format = FMT_PKCS8;
                    private_key_format = SSHKEY_PRIVATE_PKCS8 as libc::c_int;
                } else if strcasecmp(BSDoptarg, b"PEM\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    convert_format = FMT_PEM;
                    private_key_format = SSHKEY_PRIVATE_PEM as libc::c_int;
                } else {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        3432 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Unsupported conversion format \"%s\"\0" as *const u8
                            as *const libc::c_char,
                        BSDoptarg,
                    );
                }
            }
            110 => {
                cert_principals = BSDoptarg;
            }
            111 => {}
            112 => {
                change_passphrase = 1 as libc::c_int;
            }
            99 => {
                change_comment = 1 as libc::c_int;
            }
            102 => {
                if strlcpy(
                    identity_file.as_mut_ptr(),
                    BSDoptarg,
                    ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
                ) >= ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
                {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        3448 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Identity filename too long\0" as *const u8 as *const libc::c_char,
                    );
                }
                have_identity = 1 as libc::c_int;
            }
            103 => {
                print_generic = 1 as libc::c_int;
            }
            75 => {
                download_sk = 1 as libc::c_int;
            }
            80 => {
                identity_passphrase = BSDoptarg;
            }
            78 => {
                identity_new_passphrase = BSDoptarg;
            }
            81 => {
                check_krl = 1 as libc::c_int;
            }
            79 => {
                opts = crate::xmalloc::xrecallocarray(
                    opts as *mut libc::c_void,
                    nopts,
                    nopts.wrapping_add(1 as libc::c_int as libc::c_ulong),
                    ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                ) as *mut *mut libc::c_char;
                let fresh8 = nopts;
                nopts = nopts.wrapping_add(1);
                let ref mut fresh9 = *opts.offset(fresh8 as isize);
                *fresh9 = crate::xmalloc::xstrdup(BSDoptarg);
            }
            90 => {
                openssh_format_cipher = BSDoptarg;
                if (crate::cipher::cipher_by_name(openssh_format_cipher)).is_null() {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        3475 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Invalid OpenSSH-format cipher '%s'\0" as *const u8 as *const libc::c_char,
                        openssh_format_cipher,
                    );
                }
            }
            67 => {
                identity_comment = BSDoptarg;
            }
            113 => {
                quiet = 1 as libc::c_int;
            }
            101 => {
                convert_to = 1 as libc::c_int;
            }
            104 => {
                cert_key_type = 2 as libc::c_int as u_int;
                certflags_flags = 0 as libc::c_int as u_int32_t;
            }
            107 => {
                gen_krl = 1 as libc::c_int;
            }
            105 | 88 => {
                convert_from = 1 as libc::c_int;
            }
            121 => {
                print_public = 1 as libc::c_int;
            }
            115 => {
                ca_key_path = BSDoptarg;
            }
            116 => {
                key_type_name = BSDoptarg;
            }
            68 => {
                pkcs11provider = BSDoptarg;
            }
            85 => {
                prefer_agent = 1 as libc::c_int;
            }
            117 => {
                update_krl = 1 as libc::c_int;
            }
            118 => {
                if log_level == SYSLOG_LEVEL_INFO as libc::c_int {
                    log_level = SYSLOG_LEVEL_DEBUG1 as libc::c_int;
                } else if log_level >= SYSLOG_LEVEL_DEBUG1 as libc::c_int
                    && log_level < SYSLOG_LEVEL_DEBUG3 as libc::c_int
                {
                    log_level += 1;
                    log_level;
                }
            }
            114 => {
                rr_hostname = BSDoptarg;
            }
            97 => {
                rounds = crate::openbsd_compat::strtonum::strtonum(
                    BSDoptarg,
                    1 as libc::c_int as libc::c_longlong,
                    2147483647 as libc::c_int as libc::c_longlong,
                    &mut errstr,
                ) as libc::c_int;
                if !errstr.is_null() {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        3533 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Invalid number: %s (%s)\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                        errstr,
                    );
                }
            }
            86 => {
                parse_cert_times(BSDoptarg);
            }
            89 => {
                sign_op = BSDoptarg;
            }
            119 => {
                sk_provider = BSDoptarg;
            }
            122 => {
                *libc::__errno_location() = 0 as libc::c_int;
                if *BSDoptarg as libc::c_int == '+' as i32 {
                    cert_serial_autoinc = 1 as libc::c_int;
                    BSDoptarg = BSDoptarg.offset(1);
                    BSDoptarg;
                }
                cert_serial = libc::strtoull(BSDoptarg, &mut ep, 10 as libc::c_int);
                if (*BSDoptarg as libc::c_int) < '0' as i32
                    || *BSDoptarg as libc::c_int > '9' as i32
                    || *ep as libc::c_int != '\0' as i32
                    || *libc::__errno_location() == 34 as libc::c_int
                        && cert_serial
                            == (9223372036854775807 as libc::c_longlong as libc::c_ulonglong)
                                .wrapping_mul(2 as libc::c_ulonglong)
                                .wrapping_add(1 as libc::c_ulonglong)
                {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        3553 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Invalid serial number \"%s\"\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                    );
                }
            }
            77 => {
                if libc::strcmp(BSDoptarg, b"generate\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    do_gen_candidates = 1 as libc::c_int;
                } else if libc::strcmp(BSDoptarg, b"screen\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    do_screen_candidates = 1 as libc::c_int;
                } else {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        3561 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Unsupported moduli option %s\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                    );
                }
            }
            _ => {
                usage();
            }
        }
    }
    log_init(
        *argv.offset(0 as libc::c_int as isize),
        log_level as LogLevel,
        SYSLOG_FACILITY_USER,
        1 as libc::c_int,
    );
    argv = argv.offset(BSDoptind as isize);
    argc -= BSDoptind;
    if !sign_op.is_null() {
        if strncmp(
            sign_op,
            b"find-principals\0" as *const u8 as *const libc::c_char,
            15 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            if ca_key_path.is_null() {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3583 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too few arguments for find-principals:missing signature file\0" as *const u8
                        as *const libc::c_char,
                );
                libc::exit(1 as libc::c_int);
            }
            if have_identity == 0 {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3588 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too few arguments for find-principals:missing allowed keys file\0"
                        as *const u8 as *const libc::c_char,
                );
                libc::exit(1 as libc::c_int);
            }
            return sig_find_principals(ca_key_path, identity_file.as_mut_ptr(), opts, nopts);
        } else if strncmp(
            sign_op,
            b"match-principals\0" as *const u8 as *const libc::c_char,
            16 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            if have_identity == 0 {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3596 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too few arguments for match-principals:missing allowed keys file\0"
                        as *const u8 as *const libc::c_char,
                );
                libc::exit(1 as libc::c_int);
            }
            if cert_key_id.is_null() {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3601 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too few arguments for match-principals: missing principal ID\0" as *const u8
                        as *const libc::c_char,
                );
                libc::exit(1 as libc::c_int);
            }
            return sig_match_principals(identity_file.as_mut_ptr(), cert_key_id, opts, nopts);
        } else if strncmp(
            sign_op,
            b"sign\0" as *const u8 as *const libc::c_char,
            4 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            if cert_principals.is_null() || *cert_principals as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3611 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too few arguments for sign: missing namespace\0" as *const u8
                        as *const libc::c_char,
                );
                libc::exit(1 as libc::c_int);
            }
            if have_identity == 0 {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3616 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too few arguments for sign: missing key\0" as *const u8
                        as *const libc::c_char,
                );
                libc::exit(1 as libc::c_int);
            }
            return sig_sign(
                identity_file.as_mut_ptr(),
                cert_principals,
                prefer_agent,
                argc,
                argv,
                opts,
                nopts,
            );
        } else if strncmp(
            sign_op,
            b"check-novalidate\0" as *const u8 as *const libc::c_char,
            16 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            if cert_principals.is_null() || *cert_principals as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3626 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too few arguments for check-novalidate: missing namespace\0" as *const u8
                        as *const libc::c_char,
                );
                libc::exit(1 as libc::c_int);
            }
            if ca_key_path.is_null() {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3631 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too few arguments for check-novalidate: missing signature file\0" as *const u8
                        as *const libc::c_char,
                );
                libc::exit(1 as libc::c_int);
            }
            return sig_verify(
                ca_key_path,
                cert_principals,
                0 as *const libc::c_char,
                0 as *const libc::c_char,
                0 as *const libc::c_char,
                opts,
                nopts,
            );
        } else if strncmp(
            sign_op,
            b"verify\0" as *const u8 as *const libc::c_char,
            6 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            if cert_principals.is_null() || *cert_principals as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3641 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too few arguments for verify: missing namespace\0" as *const u8
                        as *const libc::c_char,
                );
                libc::exit(1 as libc::c_int);
            }
            if ca_key_path.is_null() {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3646 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too few arguments for verify: missing signature file\0" as *const u8
                        as *const libc::c_char,
                );
                libc::exit(1 as libc::c_int);
            }
            if have_identity == 0 {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3651 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too few arguments for sign: missing allowed keys file\0" as *const u8
                        as *const libc::c_char,
                );
                libc::exit(1 as libc::c_int);
            }
            if cert_key_id.is_null() {
                crate::log::sshlog(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3656 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too few arguments for verify: missing principal identity\0" as *const u8
                        as *const libc::c_char,
                );
                libc::exit(1 as libc::c_int);
            }
            return sig_verify(
                ca_key_path,
                cert_principals,
                cert_key_id,
                identity_file.as_mut_ptr(),
                rr_hostname,
                opts,
                nopts,
            );
        }
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            3663 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Unsupported operation for -Y: \"%s\"\0" as *const u8 as *const libc::c_char,
            sign_op,
        );
        usage();
    }
    if !ca_key_path.is_null() {
        if argc < 1 as libc::c_int && gen_krl == 0 {
            crate::log::sshlog(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                3670 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Too few arguments.\0" as *const u8 as *const libc::c_char,
            );
            usage();
        }
    } else if argc > 0 as libc::c_int
        && gen_krl == 0
        && check_krl == 0
        && do_gen_candidates == 0
        && do_screen_candidates == 0
    {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            3675 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Too many arguments.\0" as *const u8 as *const libc::c_char,
        );
        usage();
    }
    if change_passphrase != 0 && change_comment != 0 {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            3679 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Can only have one of -p and -c.\0" as *const u8 as *const libc::c_char,
        );
        usage();
    }
    if print_fingerprint != 0 && (delete_host != 0 || hash_hosts != 0) {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            3683 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Cannot use -l with -H or -R.\0" as *const u8 as *const libc::c_char,
        );
        usage();
    }
    if gen_krl != 0 {
        do_gen_krl(
            pw,
            update_krl,
            ca_key_path,
            cert_serial,
            identity_comment,
            argc,
            argv,
        );
        return 0 as libc::c_int;
    }
    if check_krl != 0 {
        do_check_krl(pw, print_fingerprint, argc, argv);
        return 0 as libc::c_int;
    }
    if !ca_key_path.is_null() {
        if cert_key_id.is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                3697 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Must specify key id (-I) when certifying\0" as *const u8 as *const libc::c_char,
            );
        }
        i = 0 as libc::c_int as size_t;
        while i < nopts {
            add_cert_option(*opts.offset(i as isize));
            i = i.wrapping_add(1);
            i;
        }
        do_ca_sign(
            pw,
            ca_key_path,
            prefer_agent,
            cert_serial,
            cert_serial_autoinc,
            argc,
            argv,
        );
    }
    if show_cert != 0 {
        do_show_cert(pw);
    }
    if delete_host != 0 || hash_hosts != 0 || find_host != 0 {
        do_known_hosts(pw, rr_hostname, find_host, delete_host, hash_hosts);
    }
    if !pkcs11provider.is_null() {
        do_download(pw);
    }
    if download_sk != 0 {
        i = 0 as libc::c_int as size_t;
        while i < nopts {
            if strncasecmp(
                *opts.offset(i as isize),
                b"device=\0" as *const u8 as *const libc::c_char,
                7 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
            {
                sk_device = crate::xmalloc::xstrdup(
                    (*opts.offset(i as isize)).offset(7 as libc::c_int as isize),
                );
            } else {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3717 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Option \"%s\" is unsupported for FIDO authenticator download\0" as *const u8
                        as *const libc::c_char,
                    *opts.offset(i as isize),
                );
            }
            i = i.wrapping_add(1);
            i;
        }
        return do_download_sk(sk_provider, sk_device);
    }
    if print_fingerprint != 0 || print_bubblebabble != 0 {
        do_fingerprint(pw);
    }
    if change_passphrase != 0 {
        do_change_passphrase(pw);
    }
    if change_comment != 0 {
        do_change_comment(pw, identity_comment);
    }
    if convert_to != 0 {
        do_convert_to(pw);
    }
    if convert_from != 0 {
        do_convert_from(pw);
    }
    if print_public != 0 {
        do_print_public(pw);
    }
    if !rr_hostname.is_null() {
        let mut n: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        if have_identity != 0 {
            n = do_print_resource_record(
                pw,
                identity_file.as_mut_ptr(),
                rr_hostname,
                print_generic,
                opts,
                nopts,
            ) as libc::c_uint;
            if n == 0 as libc::c_int as libc::c_uint {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3746 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"%s: %s\0" as *const u8 as *const libc::c_char,
                    identity_file.as_mut_ptr(),
                    libc::strerror(*libc::__errno_location()),
                );
            }
            libc::exit(0 as libc::c_int);
        } else {
            n = n.wrapping_add(do_print_resource_record(
                pw,
                b"/usr/local/etc/ssh_host_rsa_key\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                rr_hostname,
                print_generic,
                opts,
                nopts,
            ) as libc::c_uint);
            n = n.wrapping_add(do_print_resource_record(
                pw,
                b"/usr/local/etc/ssh_host_dsa_key\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                rr_hostname,
                print_generic,
                opts,
                nopts,
            ) as libc::c_uint);
            n = n.wrapping_add(do_print_resource_record(
                pw,
                b"/usr/local/etc/ssh_host_ecdsa_key\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                rr_hostname,
                print_generic,
                opts,
                nopts,
            ) as libc::c_uint);
            n = n.wrapping_add(do_print_resource_record(
                pw,
                b"/usr/local/etc/ssh_host_ed25519_key\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                rr_hostname,
                print_generic,
                opts,
                nopts,
            ) as libc::c_uint);
            n = n.wrapping_add(do_print_resource_record(
                pw,
                b"/usr/local/etc/ssh_host_xmss_key\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                rr_hostname,
                print_generic,
                opts,
                nopts,
            ) as libc::c_uint);
            if n == 0 as libc::c_int as libc::c_uint {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3766 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"no keys found.\0" as *const u8 as *const libc::c_char,
                );
            }
            libc::exit(0 as libc::c_int);
        }
    }
    if do_gen_candidates != 0 || do_screen_candidates != 0 {
        if argc <= 0 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                3773 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"No output file specified\0" as *const u8 as *const libc::c_char,
            );
        } else if argc > 1 as libc::c_int {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                3775 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Too many output files specified\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if do_gen_candidates != 0 {
        do_moduli_gen(*argv.offset(0 as libc::c_int as isize), opts, nopts);
        return 0 as libc::c_int;
    }
    if do_screen_candidates != 0 {
        do_moduli_screen(*argv.offset(0 as libc::c_int as isize), opts, nopts);
        return 0 as libc::c_int;
    }
    if gen_all_hostkeys != 0 {
        do_gen_all_hostkeys(pw);
        return 0 as libc::c_int;
    }
    if key_type_name.is_null() {
        key_type_name = b"rsa\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    type_0 = sshkey_type_from_name(key_type_name);
    type_bits_valid(type_0, key_type_name, &mut bits);
    if quiet == 0 {
        printf(
            b"Generating public/private %s key pair.\n\0" as *const u8 as *const libc::c_char,
            key_type_name,
        );
    }
    match type_0 {
        10 | 12 => {
            i = 0 as libc::c_int as size_t;
            while i < nopts {
                if strcasecmp(
                    *opts.offset(i as isize),
                    b"no-touch-required\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
                {
                    sk_flags = (sk_flags as libc::c_int & !(0x1 as libc::c_int)) as uint8_t;
                } else if strcasecmp(
                    *opts.offset(i as isize),
                    b"verify-required\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
                {
                    sk_flags = (sk_flags as libc::c_int | 0x4 as libc::c_int) as uint8_t;
                } else if strcasecmp(
                    *opts.offset(i as isize),
                    b"resident\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
                {
                    sk_flags = (sk_flags as libc::c_int | 0x20 as libc::c_int) as uint8_t;
                } else if strncasecmp(
                    *opts.offset(i as isize),
                    b"device=\0" as *const u8 as *const libc::c_char,
                    7 as libc::c_int as libc::c_ulong,
                ) == 0 as libc::c_int
                {
                    sk_device = crate::xmalloc::xstrdup(
                        (*opts.offset(i as isize)).offset(7 as libc::c_int as isize),
                    );
                } else if strncasecmp(
                    *opts.offset(i as isize),
                    b"user=\0" as *const u8 as *const libc::c_char,
                    5 as libc::c_int as libc::c_ulong,
                ) == 0 as libc::c_int
                {
                    sk_user = crate::xmalloc::xstrdup(
                        (*opts.offset(i as isize)).offset(5 as libc::c_int as isize),
                    );
                } else if strncasecmp(
                    *opts.offset(i as isize),
                    b"challenge=\0" as *const u8 as *const libc::c_char,
                    10 as libc::c_int as libc::c_ulong,
                ) == 0 as libc::c_int
                {
                    r = sshbuf_load_file(
                        (*opts.offset(i as isize)).offset(10 as libc::c_int as isize),
                        &mut challenge,
                    );
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            3819 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"Unable to load FIDO enrollment challenge \"%s\"\0" as *const u8
                                as *const libc::c_char,
                            (*opts.offset(i as isize)).offset(10 as libc::c_int as isize),
                        );
                    }
                } else if strncasecmp(
                    *opts.offset(i as isize),
                    b"write-attestation=\0" as *const u8 as *const libc::c_char,
                    18 as libc::c_int as libc::c_ulong,
                ) == 0 as libc::c_int
                {
                    sk_attestation_path =
                        (*opts.offset(i as isize)).offset(18 as libc::c_int as isize);
                } else if strncasecmp(
                    *opts.offset(i as isize),
                    b"application=\0" as *const u8 as *const libc::c_char,
                    12 as libc::c_int as libc::c_ulong,
                ) == 0 as libc::c_int
                {
                    sk_application = crate::xmalloc::xstrdup(
                        (*opts.offset(i as isize)).offset(12 as libc::c_int as isize),
                    );
                    if strncmp(
                        sk_application,
                        b"ssh:\0" as *const u8 as *const libc::c_char,
                        4 as libc::c_int as libc::c_ulong,
                    ) != 0 as libc::c_int
                    {
                        sshfatal(
                            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            3829 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"FIDO application string must begin with \"ssh:\"\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                } else {
                    sshfatal(
                        b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        3833 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Option \"%s\" is unsupported for FIDO authenticator enrollment\0"
                            as *const u8 as *const libc::c_char,
                        *opts.offset(i as isize),
                    );
                }
                i = i.wrapping_add(1);
                i;
            }
            attest = crate::sshbuf::sshbuf_new();
            if attest.is_null() {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3837 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                        as *const libc::c_char,
                );
            }
            r = 0 as libc::c_int;
            i = 0 as libc::c_int as size_t;
            loop {
                if quiet == 0 {
                    printf(
                        b"You may need to touch your authenticator%s to authorize key generation.\n\0"
                            as *const u8 as *const libc::c_char,
                        if r == 0 as libc::c_int {
                            b"\0" as *const u8 as *const libc::c_char
                        } else {
                            b" again\0" as *const u8 as *const libc::c_char
                        },
                    );
                }
                libc::fflush(stdout);
                r = sshsk_enroll(
                    type_0,
                    sk_provider,
                    sk_device,
                    if sk_application.is_null() {
                        b"ssh:\0" as *const u8 as *const libc::c_char
                    } else {
                        sk_application as *const libc::c_char
                    },
                    sk_user,
                    sk_flags,
                    passphrase,
                    challenge,
                    &mut private,
                    attest,
                );
                if r == 0 as libc::c_int {
                    break;
                }
                if r == -(44 as libc::c_int)
                    && sk_flags as libc::c_int & 0x20 as libc::c_int != 0 as libc::c_int
                    && sk_flags as libc::c_int & 0x10 as libc::c_int == 0 as libc::c_int
                    && confirm_sk_overwrite(sk_application, sk_user) != 0
                {
                    sk_flags = (sk_flags as libc::c_int | 0x10 as libc::c_int) as uint8_t;
                } else {
                    if r != -(43 as libc::c_int) {
                        sshfatal(
                            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            3861 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"Key enrollment failed\0" as *const u8 as *const libc::c_char,
                        );
                    } else if !passphrase.is_null() {
                        crate::log::sshlog(
                            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            3863 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"PIN incorrect\0" as *const u8 as *const libc::c_char,
                        );
                        freezero(passphrase as *mut libc::c_void, strlen(passphrase));
                        passphrase = 0 as *mut libc::c_char;
                    }
                    i = i.wrapping_add(1);
                    if i >= 3 as libc::c_int as libc::c_ulong {
                        sshfatal(
                            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            3868 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Too many incorrect PINs\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    passphrase = read_passphrase(
                        b"Enter PIN for authenticator: \0" as *const u8 as *const libc::c_char,
                        0x2 as libc::c_int,
                    );
                }
            }
            if !passphrase.is_null() {
                freezero(passphrase as *mut libc::c_void, strlen(passphrase));
                passphrase = 0 as *mut libc::c_char;
            }
        }
        _ => {
            r = sshkey_generate(type_0, bits, &mut private);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    3879 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"sshkey_generate failed\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
    r = crate::sshkey::sshkey_from_private(private, &mut public);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            3883 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"crate::sshkey::sshkey_from_private\0" as *const u8 as *const libc::c_char,
        );
    }
    if have_identity == 0 {
        ask_filename(
            pw,
            b"Enter file in which to save the key\0" as *const u8 as *const libc::c_char,
        );
    }
    hostfile_create_user_ssh_dir(identity_file.as_mut_ptr(), (quiet == 0) as libc::c_int);
    if confirm_overwrite(identity_file.as_mut_ptr()) == 0 {
        libc::exit(1 as libc::c_int);
    }
    passphrase = private_key_passphrase();
    if !identity_comment.is_null() {
        strlcpy(
            comment.as_mut_ptr(),
            identity_comment,
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        );
    } else {
        libc::snprintf(
            comment.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
            b"%s@%s\0" as *const u8 as *const libc::c_char,
            (*pw).pw_name,
            hostname.as_mut_ptr(),
        );
    }
    r = sshkey_save_private(
        private,
        identity_file.as_mut_ptr(),
        passphrase,
        comment.as_mut_ptr(),
        private_key_format,
        openssh_format_cipher,
        rounds,
    );
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            3907 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"Saving key \"%s\" failed\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
        );
        freezero(passphrase as *mut libc::c_void, strlen(passphrase));
        libc::exit(1 as libc::c_int);
    }
    freezero(passphrase as *mut libc::c_void, strlen(passphrase));
    crate::sshkey::sshkey_free(private);
    if quiet == 0 {
        printf(
            b"Your identification has been saved in %s\n\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
        );
    }
    strlcat(
        identity_file.as_mut_ptr(),
        b".pub\0" as *const u8 as *const libc::c_char,
        ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
    );
    r = sshkey_save_public(public, identity_file.as_mut_ptr(), comment.as_mut_ptr());
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            3921 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"Unable to save public key to %s\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
        );
    }
    if quiet == 0 {
        fp = crate::sshkey::sshkey_fingerprint(public, fingerprint_hash, SSH_FP_DEFAULT);
        ra = crate::sshkey::sshkey_fingerprint(public, fingerprint_hash, SSH_FP_RANDOMART);
        if fp.is_null() || ra.is_null() {
            sshfatal(
                b"ssh-keygen.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                3929 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::sshkey::sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
            );
        }
        printf(
            b"Your public key has been saved in %s\n\0" as *const u8 as *const libc::c_char,
            identity_file.as_mut_ptr(),
        );
        printf(b"The key fingerprint is:\n\0" as *const u8 as *const libc::c_char);
        printf(
            b"%s %s\n\0" as *const u8 as *const libc::c_char,
            fp,
            comment.as_mut_ptr(),
        );
        printf(b"The key's randomart image is:\n\0" as *const u8 as *const libc::c_char);
        printf(b"%s\n\0" as *const u8 as *const libc::c_char, ra);
        libc::free(ra as *mut libc::c_void);
        libc::free(fp as *mut libc::c_void);
    }
    if !sk_attestation_path.is_null() {
        save_attestation(attest, sk_attestation_path);
    }
    crate::sshbuf::sshbuf_free(attest);
    crate::sshkey::sshkey_free(public);
    libc::exit(0 as libc::c_int);
}
pub fn main() {
    let mut args: Vec<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::core::ptr::null_mut());
    unsafe {
        ::std::process::exit(main_0(
            (args.len() - 1) as libc::c_int,
            args.as_mut_ptr() as *mut *mut libc::c_char,
        ) as i32)
    }
}
