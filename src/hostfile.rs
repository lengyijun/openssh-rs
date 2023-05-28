use ::libc;
use libc::close;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type sshbuf;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    pub type ssh_hmac_ctx;

    fn link(__from: *const libc::c_char, __to: *const libc::c_char) -> libc::c_int;
    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    fn rename(__old: *const libc::c_char, __new: *const libc::c_char) -> libc::c_int;
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::FILE;

    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char, _: ...) -> libc::c_int;
    fn fgetc(__stream: *mut libc::FILE) -> libc::c_int;
    fn fputc(__c: libc::c_int, __stream: *mut libc::FILE) -> libc::c_int;
    fn __getdelim(
        __lineptr: *mut *mut libc::c_char,
        __n: *mut size_t,
        __delimiter: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> __ssize_t;
    fn fseek(__stream: *mut libc::FILE, __off: libc::c_long, __whence: libc::c_int) -> libc::c_int;
    fn __b64_ntop(
        _: *const libc::c_uchar,
        _: size_t,
        _: *mut libc::c_char,
        _: size_t,
    ) -> libc::c_int;
    fn __b64_pton(_: *const libc::c_char, _: *mut libc::c_uchar, _: size_t) -> libc::c_int;
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn _ssh_mkstemp(_: *mut libc::c_char) -> libc::c_int;
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn memchr(_: *const libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;

    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn match_hostname(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn sshkey_ssh_name(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn sshkey_is_cert(_: *const sshkey) -> libc::c_int;
    fn sshkey_type_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_size(_: *const sshkey) -> u_int;
    fn sshkey_read(_: *mut sshkey, _: *mut *mut libc::c_char) -> libc::c_int;
    fn sshkey_write(_: *const sshkey, _: *mut libc::FILE) -> libc::c_int;
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_fingerprint(_: *const sshkey, _: libc::c_int, _: sshkey_fp_rep) -> *mut libc::c_char;
    fn sshkey_equal(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_equal_public(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_new(_: libc::c_int) -> *mut sshkey;

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
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn tilde_expand_filename(_: *const libc::c_char, _: uid_t) -> *mut libc::c_char;
    fn lowercase(s: *mut libc::c_char);
    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_hmac_bytes(alg: libc::c_int) -> size_t;
    fn ssh_hmac_start(alg: libc::c_int) -> *mut ssh_hmac_ctx;
    fn ssh_hmac_init(ctx: *mut ssh_hmac_ctx, key: *const libc::c_void, klen: size_t)
        -> libc::c_int;
    fn ssh_hmac_update(ctx: *mut ssh_hmac_ctx, m: *const libc::c_void, mlen: size_t)
        -> libc::c_int;
    fn ssh_hmac_final(ctx: *mut ssh_hmac_ctx, d: *mut u_char, dlen: size_t) -> libc::c_int;
    fn ssh_hmac_free(ctx: *mut ssh_hmac_ctx);
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
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
pub type size_t = libc::c_ulong;
pub type u_int64_t = __uint64_t;

pub type uint8_t = __uint8_t;

pub type _IO_lock_t = ();

pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type EC_KEY = ec_key_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_cert {
    pub certblob: *mut sshbuf,
    pub type_0: u_int,
    pub serial: u_int64_t,
    pub key_id: *mut libc::c_char,
    pub nprincipals: u_int,
    pub principals: *mut *mut libc::c_char,
    pub valid_after: u_int64_t,
    pub valid_before: u_int64_t,
    pub critical: *mut sshbuf,
    pub extensions: *mut sshbuf,
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
    pub sk_key_handle: *mut sshbuf,
    pub sk_reserved: *mut sshbuf,
    pub cert: *mut sshkey_cert,
    pub shielded_private: *mut u_char,
    pub shielded_len: size_t,
    pub shield_prekey: *mut u_char,
    pub shield_prekey_len: size_t,
}
pub type HostStatus = libc::c_uint;
pub const HOST_FOUND: HostStatus = 4;
pub const HOST_REVOKED: HostStatus = 3;
pub const HOST_CHANGED: HostStatus = 2;
pub const HOST_NEW: HostStatus = 1;
pub const HOST_OK: HostStatus = 0;
pub type HostkeyMarker = libc::c_uint;
pub const MRK_CA: HostkeyMarker = 3;
pub const MRK_REVOKE: HostkeyMarker = 2;
pub const MRK_NONE: HostkeyMarker = 1;
pub const MRK_ERROR: HostkeyMarker = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostkey_entry {
    pub host: *mut libc::c_char,
    pub file: *mut libc::c_char,
    pub line: u_long,
    pub key: *mut sshkey,
    pub marker: HostkeyMarker,
    pub note: u_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostkeys {
    pub entries: *mut hostkey_entry,
    pub num_entries: u_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct load_callback_ctx {
    pub host: *const libc::c_char,
    pub num_loaded: u_long,
    pub hostkeys: *mut hostkeys,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostkey_foreach_line {
    pub path: *const libc::c_char,
    pub linenum: u_long,
    pub status: u_int,
    pub match_0: u_int,
    pub line: *mut libc::c_char,
    pub marker: libc::c_int,
    pub hosts: *const libc::c_char,
    pub rawkey: *const libc::c_char,
    pub keytype: libc::c_int,
    pub key: *mut sshkey,
    pub comment: *const libc::c_char,
    pub note: u_int,
}
pub type hostkeys_foreach_fn =
    unsafe extern "C" fn(*mut hostkey_foreach_line, *mut libc::c_void) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct host_delete_ctx {
    pub out: *mut libc::FILE,
    pub quiet: libc::c_int,
    pub host: *const libc::c_char,
    pub ip: *const libc::c_char,
    pub match_keys: *mut u_int,
    pub keys: *const *mut sshkey,
    pub nkeys: size_t,
    pub modified: libc::c_int,
}
#[inline]
unsafe extern "C" fn getline(
    mut __lineptr: *mut *mut libc::c_char,
    mut __n: *mut size_t,
    mut __stream: *mut libc::FILE,
) -> __ssize_t {
    return __getdelim(__lineptr, __n, '\n' as i32, __stream);
}
unsafe extern "C" fn extract_salt(
    mut s: *const libc::c_char,
    mut l: u_int,
    mut salt: *mut u_char,
    mut salt_len: size_t,
) -> libc::c_int {
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut b64salt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut b64len: u_int = 0;
    let mut ret: libc::c_int = 0;
    if (l as libc::c_ulong)
        < (::core::mem::size_of::<[libc::c_char; 4]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
    {
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"extract_salt\0")).as_ptr(),
            76 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"extract_salt: string too short\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if strncmp(
        s,
        b"|1|\0" as *const u8 as *const libc::c_char,
        (::core::mem::size_of::<[libc::c_char; 4]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    ) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"extract_salt\0")).as_ptr(),
            80 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"extract_salt: invalid magic identifier\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    s = s.offset(
        (::core::mem::size_of::<[libc::c_char; 4]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
    );
    l = (l as libc::c_ulong).wrapping_sub(
        (::core::mem::size_of::<[libc::c_char; 4]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    ) as u_int as u_int;
    p = memchr(s as *const libc::c_void, '|' as i32, l as libc::c_ulong) as *mut libc::c_char;
    if p.is_null() {
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"extract_salt\0")).as_ptr(),
            86 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"extract_salt: missing salt termination character\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    b64len = p.offset_from(s) as libc::c_long as u_int;
    if b64len == 0 as libc::c_int as libc::c_uint || b64len > 1024 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"extract_salt\0")).as_ptr(),
            93 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"extract_salt: bad encoded salt length %u\0" as *const u8 as *const libc::c_char,
            b64len,
        );
        return -(1 as libc::c_int);
    }
    b64salt =
        crate::xmalloc::xmalloc((1 as libc::c_int as libc::c_uint).wrapping_add(b64len) as size_t)
            as *mut libc::c_char;
    memcpy(
        b64salt as *mut libc::c_void,
        s as *const libc::c_void,
        b64len as libc::c_ulong,
    );
    *b64salt.offset(b64len as isize) = '\0' as i32 as libc::c_char;
    ret = __b64_pton(b64salt, salt, salt_len);
    libc::free(b64salt as *mut libc::c_void);
    if ret == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"extract_salt\0")).as_ptr(),
            103 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"extract_salt: salt decode error\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if ret != ssh_hmac_bytes(1 as libc::c_int) as libc::c_int {
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"extract_salt\0")).as_ptr(),
            108 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"extract_salt: expected salt len %zd, got %d\0" as *const u8 as *const libc::c_char,
            ssh_hmac_bytes(1 as libc::c_int),
            ret,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn host_hash(
    mut host: *const libc::c_char,
    mut name_from_hostfile: *const libc::c_char,
    mut src_len: u_int,
) -> *mut libc::c_char {
    let mut ctx: *mut ssh_hmac_ctx = 0 as *mut ssh_hmac_ctx;
    let mut salt: [u_char; 256] = [0; 256];
    let mut result: [u_char; 256] = [0; 256];
    let mut uu_salt: [libc::c_char; 512] = [0; 512];
    let mut uu_result: [libc::c_char; 512] = [0; 512];
    let mut encoded: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: u_int = 0;
    len = ssh_digest_bytes(1 as libc::c_int) as u_int;
    if name_from_hostfile.is_null() {
        arc4random_buf(salt.as_mut_ptr() as *mut libc::c_void, len as size_t);
    } else if extract_salt(
        name_from_hostfile,
        src_len,
        salt.as_mut_ptr(),
        ::core::mem::size_of::<[u_char; 256]>() as libc::c_ulong,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut libc::c_char;
    }
    ctx = ssh_hmac_start(1 as libc::c_int);
    if ctx.is_null()
        || ssh_hmac_init(ctx, salt.as_mut_ptr() as *const libc::c_void, len as size_t)
            < 0 as libc::c_int
        || ssh_hmac_update(ctx, host as *const libc::c_void, strlen(host)) < 0 as libc::c_int
        || ssh_hmac_final(
            ctx,
            result.as_mut_ptr(),
            ::core::mem::size_of::<[u_char; 256]>() as libc::c_ulong,
        ) != 0
    {
        sshfatal(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"host_hash\0")).as_ptr(),
            140 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ssh_hmac failed\0" as *const u8 as *const libc::c_char,
        );
    }
    ssh_hmac_free(ctx);
    if __b64_ntop(
        salt.as_mut_ptr(),
        len as size_t,
        uu_salt.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
    ) == -(1 as libc::c_int)
        || __b64_ntop(
            result.as_mut_ptr(),
            len as size_t,
            uu_result.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
        ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"host_hash\0")).as_ptr(),
            145 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"__b64_ntop failed\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::xmalloc::xasprintf(
        &mut encoded as *mut *mut libc::c_char,
        b"%s%s%c%s\0" as *const u8 as *const libc::c_char,
        b"|1|\0" as *const u8 as *const libc::c_char,
        uu_salt.as_mut_ptr(),
        '|' as i32,
        uu_result.as_mut_ptr(),
    );
    return encoded;
}
pub unsafe extern "C" fn hostfile_read_key(
    mut cpp: *mut *mut libc::c_char,
    mut bitsp: *mut u_int,
    mut ret: *mut sshkey,
) -> libc::c_int {
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    cp = *cpp;
    while *cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32 {
        cp = cp.offset(1);
        cp;
    }
    if sshkey_read(ret, &mut cp) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    while *cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32 {
        cp = cp.offset(1);
        cp;
    }
    *cpp = cp;
    if !bitsp.is_null() {
        *bitsp = sshkey_size(ret);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn check_markers(mut cpp: *mut *mut libc::c_char) -> HostkeyMarker {
    let mut marker: [libc::c_char; 32] = [0; 32];
    let mut sp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = *cpp;
    let mut ret: libc::c_int = MRK_NONE as libc::c_int;
    while *cp as libc::c_int == '@' as i32 {
        if ret != MRK_NONE as libc::c_int {
            return MRK_ERROR;
        }
        sp = strchr(cp, ' ' as i32);
        if sp.is_null() && {
            sp = strchr(cp, '\t' as i32);
            sp.is_null()
        } {
            return MRK_ERROR;
        }
        if sp <= cp.offset(1 as libc::c_int as isize)
            || sp
                >= cp.offset(::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong as isize)
        {
            return MRK_ERROR;
        }
        memcpy(
            marker.as_mut_ptr() as *mut libc::c_void,
            cp as *const libc::c_void,
            sp.offset_from(cp) as libc::c_long as libc::c_ulong,
        );
        marker[sp.offset_from(cp) as libc::c_long as usize] = '\0' as i32 as libc::c_char;
        if libc::strcmp(
            marker.as_mut_ptr(),
            b"@cert-authority\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            ret = MRK_CA as libc::c_int;
        } else if libc::strcmp(
            marker.as_mut_ptr(),
            b"@revoked\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            ret = MRK_REVOKE as libc::c_int;
        } else {
            return MRK_ERROR;
        }
        cp = sp;
        while *cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32 {
            cp = cp.offset(1);
            cp;
        }
    }
    *cpp = cp;
    return ret as HostkeyMarker;
}
pub unsafe extern "C" fn init_hostkeys() -> *mut hostkeys {
    let mut ret: *mut hostkeys = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<hostkeys>() as libc::c_ulong,
    ) as *mut hostkeys;
    (*ret).entries = 0 as *mut hostkey_entry;
    return ret;
}
unsafe extern "C" fn record_hostkey(
    mut l: *mut hostkey_foreach_line,
    mut _ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut ctx: *mut load_callback_ctx = _ctx as *mut load_callback_ctx;
    let mut hostkeys: *mut hostkeys = (*ctx).hostkeys;
    let mut tmp: *mut hostkey_entry = 0 as *mut hostkey_entry;
    if (*l).status == 1 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"record_hostkey\0"))
                .as_ptr(),
            240 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s:%ld: parse error in hostkeys file\0" as *const u8 as *const libc::c_char,
            (*l).path,
            (*l).linenum,
        );
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"hostfile.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"record_hostkey\0")).as_ptr(),
        247 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"found %skey type %s in file %s:%lu\0" as *const u8 as *const libc::c_char,
        if (*l).marker == MRK_NONE as libc::c_int {
            b"\0" as *const u8 as *const libc::c_char
        } else if (*l).marker == MRK_CA as libc::c_int {
            b"ca \0" as *const u8 as *const libc::c_char
        } else {
            b"revoked \0" as *const u8 as *const libc::c_char
        },
        sshkey_type((*l).key),
        (*l).path,
        (*l).linenum,
    );
    tmp = recallocarray(
        (*hostkeys).entries as *mut libc::c_void,
        (*hostkeys).num_entries as size_t,
        ((*hostkeys).num_entries).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
        ::core::mem::size_of::<hostkey_entry>() as libc::c_ulong,
    ) as *mut hostkey_entry;
    if tmp.is_null() {
        return -(2 as libc::c_int);
    }
    (*hostkeys).entries = tmp;
    let ref mut fresh0 = (*((*hostkeys).entries).offset((*hostkeys).num_entries as isize)).host;
    *fresh0 = crate::xmalloc::xstrdup((*ctx).host);
    let ref mut fresh1 = (*((*hostkeys).entries).offset((*hostkeys).num_entries as isize)).file;
    *fresh1 = crate::xmalloc::xstrdup((*l).path);
    (*((*hostkeys).entries).offset((*hostkeys).num_entries as isize)).line = (*l).linenum;
    let ref mut fresh2 = (*((*hostkeys).entries).offset((*hostkeys).num_entries as isize)).key;
    *fresh2 = (*l).key;
    (*l).key = 0 as *mut sshkey;
    (*((*hostkeys).entries).offset((*hostkeys).num_entries as isize)).marker =
        (*l).marker as HostkeyMarker;
    (*((*hostkeys).entries).offset((*hostkeys).num_entries as isize)).note = (*l).note;
    (*hostkeys).num_entries = ((*hostkeys).num_entries).wrapping_add(1);
    (*hostkeys).num_entries;
    (*ctx).num_loaded = ((*ctx).num_loaded).wrapping_add(1);
    (*ctx).num_loaded;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn load_hostkeys_file(
    mut hostkeys: *mut hostkeys,
    mut host: *const libc::c_char,
    mut path: *const libc::c_char,
    mut f: *mut libc::FILE,
    mut note: u_int,
) {
    let mut r: libc::c_int = 0;
    let mut ctx: load_callback_ctx = load_callback_ctx {
        host: 0 as *const libc::c_char,
        num_loaded: 0,
        hostkeys: 0 as *mut hostkeys,
    };
    ctx.host = host;
    ctx.num_loaded = 0 as libc::c_int as u_long;
    ctx.hostkeys = hostkeys;
    r = hostkeys_foreach_file(
        path,
        f,
        Some(
            record_hostkey
                as unsafe extern "C" fn(
                    *mut hostkey_foreach_line,
                    *mut libc::c_void,
                ) -> libc::c_int,
        ),
        &mut ctx as *mut load_callback_ctx as *mut libc::c_void,
        host,
        0 as *const libc::c_char,
        (1 as libc::c_int | (1 as libc::c_int) << 1 as libc::c_int) as u_int,
        note,
    );
    if r != 0 as libc::c_int {
        if r != -(24 as libc::c_int) && *libc::__errno_location() != 2 as libc::c_int {
            crate::log::sshlog(
                b"hostfile.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"load_hostkeys_file\0",
                ))
                .as_ptr(),
                279 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                ssh_err(r),
                b"hostkeys_foreach failed for %s\0" as *const u8 as *const libc::c_char,
                path,
            );
        }
    }
    if ctx.num_loaded != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"load_hostkeys_file\0"))
                .as_ptr(),
            282 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"loaded %lu keys from %s\0" as *const u8 as *const libc::c_char,
            ctx.num_loaded,
            host,
        );
    }
}
pub unsafe extern "C" fn load_hostkeys(
    mut hostkeys: *mut hostkeys,
    mut host: *const libc::c_char,
    mut path: *const libc::c_char,
    mut note: u_int,
) {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    f = fopen(path, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"load_hostkeys\0"))
                .as_ptr(),
            292 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"fopen %s: %s\0" as *const u8 as *const libc::c_char,
            path,
            libc::strerror(*libc::__errno_location()),
        );
        return;
    }
    load_hostkeys_file(hostkeys, host, path, f, note);
    fclose(f);
}
pub unsafe extern "C" fn free_hostkeys(mut hostkeys: *mut hostkeys) {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < (*hostkeys).num_entries {
        libc::free((*((*hostkeys).entries).offset(i as isize)).host as *mut libc::c_void);
        libc::free((*((*hostkeys).entries).offset(i as isize)).file as *mut libc::c_void);
        sshkey_free((*((*hostkeys).entries).offset(i as isize)).key);
        explicit_bzero(
            ((*hostkeys).entries).offset(i as isize) as *mut libc::c_void,
            ::core::mem::size_of::<hostkey_entry>() as libc::c_ulong,
        );
        i = i.wrapping_add(1);
        i;
    }
    libc::free((*hostkeys).entries as *mut libc::c_void);
    freezero(
        hostkeys as *mut libc::c_void,
        ::core::mem::size_of::<hostkeys>() as libc::c_ulong,
    );
}
unsafe extern "C" fn check_key_not_revoked(
    mut hostkeys: *mut hostkeys,
    mut k: *mut sshkey,
) -> libc::c_int {
    let mut is_cert: libc::c_int = sshkey_is_cert(k);
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < (*hostkeys).num_entries {
        if !((*((*hostkeys).entries).offset(i as isize)).marker as libc::c_uint
            != MRK_REVOKE as libc::c_int as libc::c_uint)
        {
            if sshkey_equal_public(k, (*((*hostkeys).entries).offset(i as isize)).key) != 0 {
                return -(1 as libc::c_int);
            }
            if is_cert != 0
                && !k.is_null()
                && sshkey_equal_public(
                    (*(*k).cert).signature_key,
                    (*((*hostkeys).entries).offset(i as isize)).key,
                ) != 0
            {
                return -(1 as libc::c_int);
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn check_hostkeys_by_key_or_type(
    mut hostkeys: *mut hostkeys,
    mut k: *mut sshkey,
    mut keytype: libc::c_int,
    mut nid: libc::c_int,
    mut found: *mut *const hostkey_entry,
) -> HostStatus {
    let mut i: u_int = 0;
    let mut end_return: HostStatus = HOST_NEW;
    let mut want_cert: libc::c_int = sshkey_is_cert(k);
    let mut want_marker: HostkeyMarker = (if want_cert != 0 {
        MRK_CA as libc::c_int
    } else {
        MRK_NONE as libc::c_int
    }) as HostkeyMarker;
    if !found.is_null() {
        *found = 0 as *const hostkey_entry;
    }
    i = 0 as libc::c_int as u_int;
    while i < (*hostkeys).num_entries {
        if !((*((*hostkeys).entries).offset(i as isize)).marker as libc::c_uint
            != want_marker as libc::c_uint)
        {
            if k.is_null() {
                if !((*(*((*hostkeys).entries).offset(i as isize)).key).type_0 != keytype) {
                    if !(nid != -(1 as libc::c_int)
                        && sshkey_type_plain(keytype) == KEY_ECDSA as libc::c_int
                        && (*(*((*hostkeys).entries).offset(i as isize)).key).ecdsa_nid != nid)
                    {
                        end_return = HOST_FOUND;
                        if !found.is_null() {
                            *found = ((*hostkeys).entries).offset(i as isize);
                        }
                        k = (*((*hostkeys).entries).offset(i as isize)).key;
                        break;
                    }
                }
            } else if want_cert != 0 {
                if sshkey_equal_public(
                    (*(*k).cert).signature_key,
                    (*((*hostkeys).entries).offset(i as isize)).key,
                ) != 0
                {
                    end_return = HOST_OK;
                    if !found.is_null() {
                        *found = ((*hostkeys).entries).offset(i as isize);
                    }
                    break;
                }
            } else if sshkey_equal(k, (*((*hostkeys).entries).offset(i as isize)).key) != 0 {
                end_return = HOST_OK;
                if !found.is_null() {
                    *found = ((*hostkeys).entries).offset(i as isize);
                }
                break;
            } else {
                end_return = HOST_CHANGED;
                if !found.is_null() {
                    *found = ((*hostkeys).entries).offset(i as isize);
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    if check_key_not_revoked(hostkeys, k) != 0 as libc::c_int {
        end_return = HOST_REVOKED;
        if !found.is_null() {
            *found = 0 as *const hostkey_entry;
        }
    }
    return end_return;
}
pub unsafe extern "C" fn check_key_in_hostkeys(
    mut hostkeys: *mut hostkeys,
    mut key: *mut sshkey,
    mut found: *mut *const hostkey_entry,
) -> HostStatus {
    if key.is_null() {
        sshfatal(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"check_key_in_hostkeys\0"))
                .as_ptr(),
            412 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no key to look up\0" as *const u8 as *const libc::c_char,
        );
    }
    return check_hostkeys_by_key_or_type(
        hostkeys,
        key,
        0 as libc::c_int,
        -(1 as libc::c_int),
        found,
    );
}
pub unsafe extern "C" fn lookup_key_in_hostkeys_by_type(
    mut hostkeys: *mut hostkeys,
    mut keytype: libc::c_int,
    mut nid: libc::c_int,
    mut found: *mut *const hostkey_entry,
) -> libc::c_int {
    return (check_hostkeys_by_key_or_type(hostkeys, 0 as *mut sshkey, keytype, nid, found)
        as libc::c_uint
        == HOST_FOUND as libc::c_int as libc::c_uint) as libc::c_int;
}
pub unsafe extern "C" fn lookup_marker_in_hostkeys(
    mut hostkeys: *mut hostkeys,
    mut want_marker: libc::c_int,
) -> libc::c_int {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < (*hostkeys).num_entries {
        if (*((*hostkeys).entries).offset(i as isize)).marker as libc::c_uint
            == want_marker as HostkeyMarker as libc::c_uint
        {
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn write_host_entry(
    mut f: *mut libc::FILE,
    mut host: *const libc::c_char,
    mut ip: *const libc::c_char,
    mut key: *const sshkey,
    mut store_hash: libc::c_int,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut hashed_host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut lhost: *mut libc::c_char = 0 as *mut libc::c_char;
    lhost = crate::xmalloc::xstrdup(host);
    lowercase(lhost);
    if store_hash != 0 {
        hashed_host = host_hash(lhost, 0 as *const libc::c_char, 0 as libc::c_int as u_int);
        if hashed_host.is_null() {
            crate::log::sshlog(
                b"hostfile.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"write_host_entry\0"))
                    .as_ptr(),
                448 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"host_hash failed\0" as *const u8 as *const libc::c_char,
            );
            libc::free(lhost as *mut libc::c_void);
            return 0 as libc::c_int;
        }
        libc::fprintf(f, b"%s \0" as *const u8 as *const libc::c_char, hashed_host);
    } else if !ip.is_null() {
        libc::fprintf(
            f,
            b"%s,%s \0" as *const u8 as *const libc::c_char,
            lhost,
            ip,
        );
    } else {
        libc::fprintf(f, b"%s \0" as *const u8 as *const libc::c_char, lhost);
    }
    libc::free(hashed_host as *mut libc::c_void);
    libc::free(lhost as *mut libc::c_void);
    r = sshkey_write(key, f);
    if r == 0 as libc::c_int {
        success = 1 as libc::c_int;
    } else {
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"write_host_entry\0"))
                .as_ptr(),
            463 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"sshkey_write\0" as *const u8 as *const libc::c_char,
        );
    }
    fputc('\n' as i32, f);
    if success != 0 && store_hash != 0 && !ip.is_null() {
        success = write_host_entry(f, ip, 0 as *const libc::c_char, key, 1 as libc::c_int);
    }
    return success;
}
pub unsafe extern "C" fn hostfile_create_user_ssh_dir(
    mut filename: *const libc::c_char,
    mut notify: libc::c_int,
) {
    let mut dotsshdir: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    p = strrchr(filename, '/' as i32);
    if p.is_null() {
        return;
    }
    len = p.offset_from(filename) as libc::c_long as size_t;
    dotsshdir = tilde_expand_filename(
        b"~/.ssh\0" as *const u8 as *const libc::c_char,
        libc::getuid(),
    );
    if !(strlen(dotsshdir) > len || strncmp(filename, dotsshdir, len) != 0 as libc::c_int) {
        if !(libc::stat(dotsshdir, &mut st) == 0 as libc::c_int) {
            if *libc::__errno_location() != 2 as libc::c_int {
                crate::log::sshlog(
                    b"hostfile.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"hostfile_create_user_ssh_dir\0",
                    ))
                    .as_ptr(),
                    491 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Could not libc::stat %s: %s\0" as *const u8 as *const libc::c_char,
                    dotsshdir,
                    libc::strerror(*libc::__errno_location()),
                );
            } else if libc::mkdir(dotsshdir, 0o700 as libc::c_int as __mode_t)
                == -(1 as libc::c_int)
            {
                crate::log::sshlog(
                    b"hostfile.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"hostfile_create_user_ssh_dir\0",
                    ))
                    .as_ptr(),
                    498 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Could not create directory '%.200s' (%s).\0" as *const u8
                        as *const libc::c_char,
                    dotsshdir,
                    libc::strerror(*libc::__errno_location()),
                );
            } else if notify != 0 {
                crate::log::sshlog(
                    b"hostfile.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"hostfile_create_user_ssh_dir\0",
                    ))
                    .as_ptr(),
                    500 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"Created directory '%s'.\0" as *const u8 as *const libc::c_char,
                    dotsshdir,
                );
            }
        }
    }
    libc::free(dotsshdir as *mut libc::c_void);
}
pub unsafe extern "C" fn add_host_to_hostfile(
    mut filename: *const libc::c_char,
    mut host: *const libc::c_char,
    mut key: *const sshkey,
    mut store_hash: libc::c_int,
) -> libc::c_int {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut success: libc::c_int = 0;
    let mut addnl: libc::c_int = 0 as libc::c_int;
    if key.is_null() {
        return 1 as libc::c_int;
    }
    hostfile_create_user_ssh_dir(filename, 0 as libc::c_int);
    f = fopen(filename, b"a+\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        return 0 as libc::c_int;
    }
    if fseek(f, -(1 as libc::c_long), 2 as libc::c_int) == 0 as libc::c_int
        && fgetc(f) != '\n' as i32
    {
        addnl = 1 as libc::c_int;
    }
    if fseek(f, 0 as libc::c_long, 2 as libc::c_int) != 0 as libc::c_int
        || addnl != 0 && fputc('\n' as i32, f) != '\n' as i32
    {
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"add_host_to_hostfile\0"))
                .as_ptr(),
            531 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Failed to add terminating newline to %s: %s\0" as *const u8 as *const libc::c_char,
            filename,
            libc::strerror(*libc::__errno_location()),
        );
        fclose(f);
        return 0 as libc::c_int;
    }
    success = write_host_entry(f, host, 0 as *const libc::c_char, key, store_hash);
    fclose(f);
    return success;
}
unsafe extern "C" fn host_delete(
    mut l: *mut hostkey_foreach_line,
    mut _ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut ctx: *mut host_delete_ctx = _ctx as *mut host_delete_ctx;
    let mut loglevel: libc::c_int = if (*ctx).quiet != 0 {
        SYSLOG_LEVEL_DEBUG1 as libc::c_int
    } else {
        SYSLOG_LEVEL_VERBOSE as libc::c_int
    };
    let mut i: size_t = 0;
    if (*l).status == 3 as libc::c_int as libc::c_uint && (*l).marker == MRK_NONE as libc::c_int {
        i = 0 as libc::c_int as size_t;
        while i < (*ctx).nkeys {
            if sshkey_equal(*((*ctx).keys).offset(i as isize), (*l).key) == 0 {
                i = i.wrapping_add(1);
                i;
            } else {
                let ref mut fresh3 = *((*ctx).match_keys).offset(i as isize);
                *fresh3 |= (*l).match_0;
                libc::fprintf(
                    (*ctx).out,
                    b"%s\n\0" as *const u8 as *const libc::c_char,
                    (*l).line,
                );
                crate::log::sshlog(
                    b"hostfile.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"host_delete\0"))
                        .as_ptr(),
                    570 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"%s key already at %s:%ld\0" as *const u8 as *const libc::c_char,
                    sshkey_type((*l).key),
                    (*l).path,
                    (*l).linenum,
                );
                return 0 as libc::c_int;
            }
        }
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"host_delete\0")).as_ptr(),
            580 as libc::c_int,
            0 as libc::c_int,
            loglevel as LogLevel,
            0 as *const libc::c_char,
            b"%s%s%s:%ld: Removed %s key for host %s\0" as *const u8 as *const libc::c_char,
            if (*ctx).quiet != 0 {
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"host_delete\0"))
                    .as_ptr()
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if (*ctx).quiet != 0 {
                b": \0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            (*l).path,
            (*l).linenum,
            sshkey_type((*l).key),
            (*ctx).host,
        );
        (*ctx).modified = 1 as libc::c_int;
        return 0 as libc::c_int;
    }
    if (*l).status == 1 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"hostfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"host_delete\0")).as_ptr(),
            588 as libc::c_int,
            0 as libc::c_int,
            loglevel as LogLevel,
            0 as *const libc::c_char,
            b"%s%s%s:%ld: invalid known_hosts entry\0" as *const u8 as *const libc::c_char,
            if (*ctx).quiet != 0 {
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"host_delete\0"))
                    .as_ptr()
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if (*ctx).quiet != 0 {
                b": \0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            (*l).path,
            (*l).linenum,
        );
    }
    libc::fprintf(
        (*ctx).out,
        b"%s\n\0" as *const u8 as *const libc::c_char,
        (*l).line,
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn hostfile_replace_entries(
    mut filename: *const libc::c_char,
    mut host: *const libc::c_char,
    mut ip: *const libc::c_char,
    mut keys: *mut *mut sshkey,
    mut nkeys: size_t,
    mut store_hash: libc::c_int,
    mut quiet: libc::c_int,
    mut hash_alg: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0 as libc::c_int;
    let mut loglevel: libc::c_int = if quiet != 0 {
        SYSLOG_LEVEL_DEBUG1 as libc::c_int
    } else {
        SYSLOG_LEVEL_VERBOSE as libc::c_int
    };
    let mut ctx: host_delete_ctx = host_delete_ctx {
        out: 0 as *mut libc::FILE,
        quiet: 0,
        host: 0 as *const libc::c_char,
        ip: 0 as *const libc::c_char,
        match_keys: 0 as *mut u_int,
        keys: 0 as *const *mut sshkey,
        nkeys: 0,
        modified: 0,
    };
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut temp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut back: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut what: *const libc::c_char = 0 as *const libc::c_char;
    let mut omask: mode_t = 0;
    let mut i: size_t = 0;
    let mut want: u_int = 0;
    omask = libc::umask(0o77 as libc::c_int as __mode_t);
    memset(
        &mut ctx as *mut host_delete_ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<host_delete_ctx>() as libc::c_ulong,
    );
    ctx.host = host;
    ctx.ip = ip;
    ctx.quiet = quiet;
    ctx.match_keys = calloc(nkeys, ::core::mem::size_of::<u_int>() as libc::c_ulong) as *mut u_int;
    if (ctx.match_keys).is_null() {
        return -(2 as libc::c_int);
    }
    ctx.keys = keys;
    ctx.nkeys = nkeys;
    ctx.modified = 0 as libc::c_int;
    r = asprintf(
        &mut temp as *mut *mut libc::c_char,
        b"%s.XXXXXXXXXXX\0" as *const u8 as *const libc::c_char,
        filename,
    );
    if r == -(1 as libc::c_int) || {
        r = asprintf(
            &mut back as *mut *mut libc::c_char,
            b"%s.old\0" as *const u8 as *const libc::c_char,
            filename,
        );
        r == -(1 as libc::c_int)
    } {
        r = -(2 as libc::c_int);
    } else {
        fd = _ssh_mkstemp(temp);
        if fd == -(1 as libc::c_int) {
            oerrno = *libc::__errno_location();
            crate::log::sshlog(
                b"hostfile.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"hostfile_replace_entries\0",
                ))
                .as_ptr(),
                631 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"mkstemp: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(oerrno),
            );
            r = -(24 as libc::c_int);
        } else {
            ctx.out = libc::fdopen(fd, b"w\0" as *const u8 as *const libc::c_char);
            if (ctx.out).is_null() {
                oerrno = *libc::__errno_location();
                close(fd);
                crate::log::sshlog(
                    b"hostfile.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                        b"hostfile_replace_entries\0",
                    ))
                    .as_ptr(),
                    638 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"libc::fdopen: %s\0" as *const u8 as *const libc::c_char,
                    libc::strerror(oerrno),
                );
                r = -(24 as libc::c_int);
            } else {
                r = hostkeys_foreach(
                    filename,
                    Some(
                        host_delete
                            as unsafe extern "C" fn(
                                *mut hostkey_foreach_line,
                                *mut libc::c_void,
                            ) -> libc::c_int,
                    ),
                    &mut ctx as *mut host_delete_ctx as *mut libc::c_void,
                    host,
                    ip,
                    ((1 as libc::c_int) << 1 as libc::c_int) as u_int,
                    0 as libc::c_int as u_int,
                );
                if r != 0 as libc::c_int {
                    oerrno = *libc::__errno_location();
                    crate::log::sshlog(
                        b"hostfile.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                            b"hostfile_replace_entries\0",
                        ))
                        .as_ptr(),
                        647 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"hostkeys_foreach\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    want = (1 as libc::c_int
                        | (if ip.is_null() {
                            0 as libc::c_int
                        } else {
                            (1 as libc::c_int) << 1 as libc::c_int
                        })) as u_int;
                    i = 0 as libc::c_int as size_t;
                    loop {
                        if !(i < nkeys) {
                            current_block = 12199444798915819164;
                            break;
                        }
                        if !((*keys.offset(i as isize)).is_null()
                            || want & *(ctx.match_keys).offset(i as isize) == want)
                        {
                            fp = sshkey_fingerprint(
                                *keys.offset(i as isize),
                                hash_alg,
                                SSH_FP_DEFAULT,
                            );
                            if fp.is_null() {
                                r = -(2 as libc::c_int);
                                current_block = 3224374282125147660;
                                break;
                            } else {
                                what = b"\0" as *const u8 as *const libc::c_char;
                                if *(ctx.match_keys).offset(i as isize)
                                    == 0 as libc::c_int as libc::c_uint
                                {
                                    what = b"Adding new key\0" as *const u8 as *const libc::c_char;
                                    if write_host_entry(
                                        ctx.out,
                                        host,
                                        ip,
                                        *keys.offset(i as isize),
                                        store_hash,
                                    ) == 0
                                    {
                                        r = -(1 as libc::c_int);
                                        current_block = 3224374282125147660;
                                        break;
                                    }
                                } else if want & !*(ctx.match_keys).offset(i as isize)
                                    == 1 as libc::c_int as libc::c_uint
                                {
                                    what = b"Fixing match (hostname)\0" as *const u8
                                        as *const libc::c_char;
                                    if write_host_entry(
                                        ctx.out,
                                        host,
                                        0 as *const libc::c_char,
                                        *keys.offset(i as isize),
                                        store_hash,
                                    ) == 0
                                    {
                                        r = -(1 as libc::c_int);
                                        current_block = 3224374282125147660;
                                        break;
                                    }
                                } else if want & !*(ctx.match_keys).offset(i as isize)
                                    == ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
                                {
                                    what = b"Fixing match (address)\0" as *const u8
                                        as *const libc::c_char;
                                    if write_host_entry(
                                        ctx.out,
                                        ip,
                                        0 as *const libc::c_char,
                                        *keys.offset(i as isize),
                                        store_hash,
                                    ) == 0
                                    {
                                        r = -(1 as libc::c_int);
                                        current_block = 3224374282125147660;
                                        break;
                                    }
                                }
                                crate::log::sshlog(
                                    b"hostfile.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                        b"hostfile_replace_entries\0",
                                    ))
                                    .as_ptr(),
                                    688 as libc::c_int,
                                    0 as libc::c_int,
                                    loglevel as LogLevel,
                                    0 as *const libc::c_char,
                                    b"%s%s%s for %s%s%s to %s: %s %s\0" as *const u8
                                        as *const libc::c_char,
                                    if quiet != 0 {
                                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                            b"hostfile_replace_entries\0",
                                        ))
                                        .as_ptr()
                                    } else {
                                        b"\0" as *const u8 as *const libc::c_char
                                    },
                                    if quiet != 0 {
                                        b": \0" as *const u8 as *const libc::c_char
                                    } else {
                                        b"\0" as *const u8 as *const libc::c_char
                                    },
                                    what,
                                    host,
                                    if ip.is_null() {
                                        b"\0" as *const u8 as *const libc::c_char
                                    } else {
                                        b",\0" as *const u8 as *const libc::c_char
                                    },
                                    if ip.is_null() {
                                        b"\0" as *const u8 as *const libc::c_char
                                    } else {
                                        ip
                                    },
                                    filename,
                                    sshkey_ssh_name(*keys.offset(i as isize)),
                                    fp,
                                );
                                libc::free(fp as *mut libc::c_void);
                                ctx.modified = 1 as libc::c_int;
                            }
                        }
                        i = i.wrapping_add(1);
                        i;
                    }
                    match current_block {
                        3224374282125147660 => {}
                        _ => {
                            fclose(ctx.out);
                            ctx.out = 0 as *mut libc::FILE;
                            if ctx.modified != 0 {
                                if unlink(back) == -(1 as libc::c_int)
                                    && *libc::__errno_location() != 2 as libc::c_int
                                {
                                    oerrno = *libc::__errno_location();
                                    crate::log::sshlog(
                                        b"hostfile.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                            b"hostfile_replace_entries\0",
                                        ))
                                        .as_ptr(),
                                        699 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"unlink %.100s: %s\0" as *const u8 as *const libc::c_char,
                                        back,
                                        libc::strerror(*libc::__errno_location()),
                                    );
                                    r = -(24 as libc::c_int);
                                    current_block = 3224374282125147660;
                                } else if link(filename, back) == -(1 as libc::c_int) {
                                    oerrno = *libc::__errno_location();
                                    crate::log::sshlog(
                                        b"hostfile.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                            b"hostfile_replace_entries\0",
                                        ))
                                        .as_ptr(),
                                        706 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"link %.100s to %.100s: %s\0" as *const u8
                                            as *const libc::c_char,
                                        filename,
                                        back,
                                        libc::strerror(*libc::__errno_location()),
                                    );
                                    r = -(24 as libc::c_int);
                                    current_block = 3224374282125147660;
                                } else if rename(temp, filename) == -(1 as libc::c_int) {
                                    oerrno = *libc::__errno_location();
                                    crate::log::sshlog(
                                        b"hostfile.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                            b"hostfile_replace_entries\0",
                                        ))
                                        .as_ptr(),
                                        713 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"rename \"%s\" to \"%s\": %s\0" as *const u8
                                            as *const libc::c_char,
                                        temp,
                                        filename,
                                        libc::strerror(*libc::__errno_location()),
                                    );
                                    r = -(24 as libc::c_int);
                                    current_block = 3224374282125147660;
                                } else {
                                    current_block = 8545136480011357681;
                                }
                            } else {
                                if unlink(temp) != 0 as libc::c_int {
                                    crate::log::sshlog(
                                        b"hostfile.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                            b"hostfile_replace_entries\0",
                                        ))
                                        .as_ptr(),
                                        720 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"unlink \"%s\": %s\0" as *const u8 as *const libc::c_char,
                                        temp,
                                        libc::strerror(*libc::__errno_location()),
                                    );
                                }
                                current_block = 8545136480011357681;
                            }
                            match current_block {
                                3224374282125147660 => {}
                                _ => {
                                    r = 0 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !temp.is_null() && r != 0 as libc::c_int {
        unlink(temp);
    }
    libc::free(temp as *mut libc::c_void);
    libc::free(back as *mut libc::c_void);
    if !(ctx.out).is_null() {
        fclose(ctx.out);
    }
    libc::free(ctx.match_keys as *mut libc::c_void);
    libc::umask(omask);
    if r == -(24 as libc::c_int) {
        *libc::__errno_location() = oerrno;
    }
    return r;
}
unsafe extern "C" fn match_maybe_hashed(
    mut host: *const libc::c_char,
    mut names: *const libc::c_char,
    mut was_hashed: *mut libc::c_int,
) -> libc::c_int {
    let mut hashed: libc::c_int = (*names as libc::c_int == '|' as i32) as libc::c_int;
    let mut ret: libc::c_int = 0;
    let mut hashed_host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut nlen: size_t = strlen(names);
    if !was_hashed.is_null() {
        *was_hashed = hashed;
    }
    if hashed != 0 {
        hashed_host = host_hash(host, names, nlen as u_int);
        if hashed_host.is_null() {
            return -(1 as libc::c_int);
        }
        ret = (nlen == strlen(hashed_host) && strncmp(hashed_host, names, nlen) == 0 as libc::c_int)
            as libc::c_int;
        libc::free(hashed_host as *mut libc::c_void);
        return ret;
    }
    return (match_hostname(host, names) == 1 as libc::c_int) as libc::c_int;
}
pub unsafe extern "C" fn hostkeys_foreach_file(
    mut path: *const libc::c_char,
    mut f: *mut libc::FILE,
    mut callback: Option<hostkeys_foreach_fn>,
    mut ctx: *mut libc::c_void,
    mut host: *const libc::c_char,
    mut ip: *const libc::c_char,
    mut options: u_int,
    mut note: u_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ktype: [libc::c_char; 128] = [0; 128];
    let mut linenum: u_long = 0 as libc::c_int as u_long;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp2: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut kbits: u_int = 0;
    let mut hashed: libc::c_int = 0;
    let mut s: libc::c_int = 0;
    let mut r: libc::c_int = 0 as libc::c_int;
    let mut lineinfo: hostkey_foreach_line = hostkey_foreach_line {
        path: 0 as *const libc::c_char,
        linenum: 0,
        status: 0,
        match_0: 0,
        line: 0 as *mut libc::c_char,
        marker: 0,
        hosts: 0 as *const libc::c_char,
        rawkey: 0 as *const libc::c_char,
        keytype: 0,
        key: 0 as *mut sshkey,
        comment: 0 as *const libc::c_char,
        note: 0,
    };
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut l: size_t = 0;
    memset(
        &mut lineinfo as *mut hostkey_foreach_line as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<hostkey_foreach_line>() as libc::c_ulong,
    );
    if host.is_null()
        && options & 1 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
    {
        return -(10 as libc::c_int);
    }
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        linenum = linenum.wrapping_add(1);
        linenum;
        *line.offset(strcspn(line, b"\n\0" as *const u8 as *const libc::c_char) as isize) =
            '\0' as i32 as libc::c_char;
        libc::free(lineinfo.line as *mut libc::c_void);
        sshkey_free(lineinfo.key);
        memset(
            &mut lineinfo as *mut hostkey_foreach_line as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<hostkey_foreach_line>() as libc::c_ulong,
        );
        lineinfo.path = path;
        lineinfo.linenum = linenum;
        lineinfo.line = crate::xmalloc::xstrdup(line);
        lineinfo.marker = MRK_NONE as libc::c_int;
        lineinfo.status = 0 as libc::c_int as u_int;
        lineinfo.keytype = KEY_UNSPEC as libc::c_int;
        lineinfo.note = note;
        cp = line;
        while *cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32 {
            cp = cp.offset(1);
            cp;
        }
        if *cp == 0 || *cp as libc::c_int == '#' as i32 || *cp as libc::c_int == '\n' as i32 {
            if !(options & 1 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint) {
                continue;
            }
            lineinfo.status = 2 as libc::c_int as u_int;
            r = callback.expect("non-null function pointer")(&mut lineinfo, ctx);
            if r != 0 as libc::c_int {
                break;
            }
        } else {
            lineinfo.marker = check_markers(&mut cp) as libc::c_int;
            if lineinfo.marker == MRK_ERROR as libc::c_int {
                crate::log::sshlog(
                    b"hostfile.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"hostkeys_foreach_file\0",
                    ))
                    .as_ptr(),
                    804 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_VERBOSE,
                    0 as *const libc::c_char,
                    b"invalid marker at %s:%lu\0" as *const u8 as *const libc::c_char,
                    path,
                    linenum,
                );
                if !(options & 1 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint)
                {
                    continue;
                }
            } else {
                cp2 = cp;
                while *cp2 as libc::c_int != 0
                    && *cp2 as libc::c_int != ' ' as i32
                    && *cp2 as libc::c_int != '\t' as i32
                {
                    cp2 = cp2.offset(1);
                    cp2;
                }
                lineinfo.hosts = cp;
                let fresh4 = cp2;
                cp2 = cp2.offset(1);
                *fresh4 = '\0' as i32 as libc::c_char;
                if !host.is_null() {
                    s = match_maybe_hashed(host, lineinfo.hosts, &mut hashed);
                    if s == -(1 as libc::c_int) {
                        crate::log::sshlog(
                            b"hostfile.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                b"hostkeys_foreach_file\0",
                            ))
                            .as_ptr(),
                            821 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"%s:%ld: bad host hash \"%.32s\"\0" as *const u8
                                as *const libc::c_char,
                            path,
                            linenum,
                            lineinfo.hosts,
                        );
                        current_block = 1717368149607069082;
                    } else {
                        if s == 1 as libc::c_int {
                            lineinfo.status = 3 as libc::c_int as u_int;
                            lineinfo.match_0 |= (1 as libc::c_int
                                | (if hashed != 0 {
                                    (1 as libc::c_int) << 2 as libc::c_int
                                } else {
                                    0 as libc::c_int
                                })) as libc::c_uint;
                        }
                        if !ip.is_null() {
                            s = match_maybe_hashed(ip, lineinfo.hosts, &mut hashed);
                            if s == -(1 as libc::c_int) {
                                crate::log::sshlog(
                                    b"hostfile.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                        b"hostkeys_foreach_file\0",
                                    ))
                                    .as_ptr(),
                                    835 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG2,
                                    0 as *const libc::c_char,
                                    b"%s:%ld: bad ip hash \"%.32s\"\0" as *const u8
                                        as *const libc::c_char,
                                    path,
                                    linenum,
                                    lineinfo.hosts,
                                );
                                current_block = 1717368149607069082;
                            } else {
                                if s == 1 as libc::c_int {
                                    lineinfo.status = 3 as libc::c_int as u_int;
                                    lineinfo.match_0 |= ((1 as libc::c_int) << 1 as libc::c_int
                                        | (if hashed != 0 {
                                            (1 as libc::c_int) << 3 as libc::c_int
                                        } else {
                                            0 as libc::c_int
                                        }))
                                        as libc::c_uint;
                                }
                                current_block = 13131896068329595644;
                            }
                        } else {
                            current_block = 13131896068329595644;
                        }
                        match current_block {
                            1717368149607069082 => {}
                            _ => {
                                if options & 1 as libc::c_int as libc::c_uint
                                    != 0 as libc::c_int as libc::c_uint
                                    && lineinfo.status != 3 as libc::c_int as libc::c_uint
                                {
                                    continue;
                                }
                                current_block = 10891380440665537214;
                            }
                        }
                    }
                } else {
                    current_block = 10891380440665537214;
                }
                match current_block {
                    1717368149607069082 => {}
                    _ => {
                        while *cp2 as libc::c_int == ' ' as i32
                            || *cp2 as libc::c_int == '\t' as i32
                        {
                            cp2 = cp2.offset(1);
                            cp2;
                        }
                        if *cp2 as libc::c_int == '\0' as i32 || *cp2 as libc::c_int == '#' as i32 {
                            crate::log::sshlog(
                                b"hostfile.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                    b"hostkeys_foreach_file\0",
                                ))
                                .as_ptr(),
                                858 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"%s:%ld: truncated before key type\0" as *const u8
                                    as *const libc::c_char,
                                path,
                                linenum,
                            );
                        } else {
                            cp = cp2;
                            lineinfo.rawkey = cp;
                            if options & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
                                != 0 as libc::c_int as libc::c_uint
                            {
                                lineinfo.key = sshkey_new(KEY_UNSPEC as libc::c_int);
                                if (lineinfo.key).is_null() {
                                    crate::log::sshlog(
                                        b"hostfile.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                            b"hostkeys_foreach_file\0",
                                        ))
                                        .as_ptr(),
                                        870 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
                                    );
                                    r = -(2 as libc::c_int);
                                    break;
                                } else if hostfile_read_key(&mut cp, &mut kbits, lineinfo.key) == 0
                                {
                                    current_block = 1717368149607069082;
                                } else {
                                    lineinfo.keytype = (*lineinfo.key).type_0;
                                    lineinfo.comment = cp;
                                    current_block = 16779030619667747692;
                                }
                            } else {
                                l = strcspn(
                                    lineinfo.rawkey,
                                    b" \t\0" as *const u8 as *const libc::c_char,
                                );
                                if l <= 1 as libc::c_int as libc::c_ulong
                                    || l >= ::core::mem::size_of::<[libc::c_char; 128]>()
                                        as libc::c_ulong
                                    || *(lineinfo.rawkey).offset(l as isize) as libc::c_int
                                        == '\0' as i32
                                {
                                    current_block = 1717368149607069082;
                                } else {
                                    memcpy(
                                        ktype.as_mut_ptr() as *mut libc::c_void,
                                        lineinfo.rawkey as *const libc::c_void,
                                        l,
                                    );
                                    ktype[l as usize] = '\0' as i32 as libc::c_char;
                                    lineinfo.keytype = sshkey_type_from_name(ktype.as_mut_ptr());
                                    if lineinfo.keytype == KEY_UNSPEC as libc::c_int
                                        && l < 8 as libc::c_int as libc::c_ulong
                                        && strspn(
                                            ktype.as_mut_ptr(),
                                            b"0123456789\0" as *const u8 as *const libc::c_char,
                                        ) == l
                                    {
                                        current_block = 1717368149607069082;
                                    } else {
                                        cp2 = cp2.offset(l as isize);
                                        while *cp2 as libc::c_int == ' ' as i32
                                            || *cp2 as libc::c_int == '\t' as i32
                                        {
                                            cp2 = cp2.offset(1);
                                            cp2;
                                        }
                                        if *cp2 as libc::c_int == '\0' as i32
                                            || *cp2 as libc::c_int == '#' as i32
                                        {
                                            crate::log::sshlog(
                                                b"hostfile.c\0" as *const u8 as *const libc::c_char,
                                                (*::core::mem::transmute::<
                                                    &[u8; 22],
                                                    &[libc::c_char; 22],
                                                >(
                                                    b"hostkeys_foreach_file\0"
                                                ))
                                                .as_ptr(),
                                                907 as libc::c_int,
                                                0 as libc::c_int,
                                                SYSLOG_LEVEL_DEBUG2,
                                                0 as *const libc::c_char,
                                                b"%s:%ld: truncated after key type\0" as *const u8
                                                    as *const libc::c_char,
                                                path,
                                                linenum,
                                            );
                                            lineinfo.keytype = KEY_UNSPEC as libc::c_int;
                                        }
                                        if lineinfo.keytype == KEY_UNSPEC as libc::c_int {
                                            current_block = 1717368149607069082;
                                        } else {
                                            current_block = 16779030619667747692;
                                        }
                                    }
                                }
                            }
                            match current_block {
                                1717368149607069082 => {}
                                _ => {
                                    r = callback.expect("non-null function pointer")(
                                        &mut lineinfo,
                                        ctx,
                                    );
                                    if r != 0 as libc::c_int {
                                        break;
                                    } else {
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            sshkey_free(lineinfo.key);
            lineinfo.key = 0 as *mut sshkey;
            lineinfo.status = 1 as libc::c_int as u_int;
            r = callback.expect("non-null function pointer")(&mut lineinfo, ctx);
            if r != 0 as libc::c_int {
                break;
            }
        }
    }
    sshkey_free(lineinfo.key);
    libc::free(lineinfo.line as *mut libc::c_void);
    libc::free(line as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn hostkeys_foreach(
    mut path: *const libc::c_char,
    mut callback: Option<hostkeys_foreach_fn>,
    mut ctx: *mut libc::c_void,
    mut host: *const libc::c_char,
    mut ip: *const libc::c_char,
    mut options: u_int,
    mut note: u_int,
) -> libc::c_int {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut r: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    f = fopen(path, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        return -(24 as libc::c_int);
    }
    crate::log::sshlog(
        b"hostfile.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"hostkeys_foreach\0")).as_ptr(),
        939 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"reading file \"%s\"\0" as *const u8 as *const libc::c_char,
        path,
    );
    r = hostkeys_foreach_file(path, f, callback, ctx, host, ip, options, note);
    oerrno = *libc::__errno_location();
    fclose(f);
    *libc::__errno_location() = oerrno;
    return r;
}
