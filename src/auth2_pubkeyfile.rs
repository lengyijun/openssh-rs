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
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;

    fn fstat(__fd: libc::c_int, __buf: *mut stat) -> libc::c_int;
    fn __errno_location() -> *mut libc::c_int;

    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn __getdelim(
        __lineptr: *mut *mut libc::c_char,
        __n: *mut size_t,
        __delimiter: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> __ssize_t;
    fn fileno(__stream: *mut libc::FILE) -> libc::c_int;
    fn free(_: *mut libc::c_void);

    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn time(__timer: *mut time_t) -> time_t;

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
    fn skip_space(_: *mut *mut libc::c_char);
    fn unset_nonblock(_: libc::c_int) -> libc::c_int;
    fn format_absolute_time(_: uint64_t, _: *mut libc::c_char, _: size_t);
    fn safe_path_fd(
        _: libc::c_int,
        _: *const libc::c_char,
        _: *mut passwd,
        err: *mut libc::c_char,
        errlen: size_t,
    ) -> libc::c_int;
    fn sshkey_cert_check_authority_now(
        _: *const sshkey,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: *const libc::c_char,
        _: *mut *const libc::c_char,
    ) -> libc::c_int;
    fn sshkey_is_cert(_: *const sshkey) -> libc::c_int;
    fn sshkey_read(_: *mut sshkey, _: *mut *mut libc::c_char) -> libc::c_int;
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_fingerprint(_: *const sshkey, _: libc::c_int, _: sshkey_fp_rep) -> *mut libc::c_char;
    fn sshkey_equal(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_new(_: libc::c_int) -> *mut sshkey;
    fn auth_log_authopts(_: *const libc::c_char, _: *const sshauthopt, _: libc::c_int);
    fn auth_debug_add(fmt: *const libc::c_char, _: ...);
    fn sshauthopt_free(opts: *mut sshauthopt);
    fn sshauthopt_parse(
        s: *const libc::c_char,
        errstr: *mut *const libc::c_char,
    ) -> *mut sshauthopt;
    fn sshauthopt_from_cert(k: *mut sshkey) -> *mut sshauthopt;
    fn sshauthopt_merge(
        primary: *const sshauthopt,
        additional: *const sshauthopt,
        errstrp: *mut *const libc::c_char,
    ) -> *mut sshauthopt;
    fn sshkey_advance_past_options(cpp: *mut *mut libc::c_char) -> libc::c_int;
    fn match_host_and_ip(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn match_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut u_int,
    ) -> *mut libc::c_char;
    fn addr_match_cidr_list(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
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
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type u_int64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: libc::c_int,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atim: timespec,
    pub st_mtim: timespec,
    pub st_ctim: timespec,
    pub __glibc_reserved: [__syscall_slong_t; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct passwd {
    pub pw_name: *mut libc::c_char,
    pub pw_passwd: *mut libc::c_char,
    pub pw_uid: __uid_t,
    pub pw_gid: __gid_t,
    pub pw_gecos: *mut libc::c_char,
    pub pw_dir: *mut libc::c_char,
    pub pw_shell: *mut libc::c_char,
}

pub type _IO_lock_t = ();

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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshauthopt {
    pub permit_port_forwarding_flag: libc::c_int,
    pub permit_agent_forwarding_flag: libc::c_int,
    pub permit_x11_forwarding_flag: libc::c_int,
    pub permit_pty_flag: libc::c_int,
    pub permit_user_rc: libc::c_int,
    pub restricted: libc::c_int,
    pub valid_before: uint64_t,
    pub cert_authority: libc::c_int,
    pub cert_principals: *mut libc::c_char,
    pub force_tun_device: libc::c_int,
    pub force_command: *mut libc::c_char,
    pub nenv: size_t,
    pub env: *mut *mut libc::c_char,
    pub npermitopen: size_t,
    pub permitopen: *mut *mut libc::c_char,
    pub npermitlisten: size_t,
    pub permitlisten: *mut *mut libc::c_char,
    pub required_from_host_cert: *mut libc::c_char,
    pub required_from_host_keys: *mut libc::c_char,
    pub no_require_user_presence: libc::c_int,
    pub require_verify: libc::c_int,
}
#[inline]
unsafe extern "C" fn getline(
    mut __lineptr: *mut *mut libc::c_char,
    mut __n: *mut size_t,
    mut __stream: *mut libc::FILE,
) -> __ssize_t {
    return __getdelim(__lineptr, __n, '\n' as i32, __stream);
}
pub unsafe extern "C" fn auth_authorise_keyopts(
    mut pw: *mut passwd,
    mut opts: *mut sshauthopt,
    mut allow_cert_authority: libc::c_int,
    mut remote_ip: *const libc::c_char,
    mut remote_host: *const libc::c_char,
    mut loc: *const libc::c_char,
) -> libc::c_int {
    let mut now: time_t = time(0 as *mut time_t);
    let mut buf: [libc::c_char; 64] = [0; 64];
    if (*opts).valid_before != 0
        && now > 0 as libc::c_int as libc::c_long
        && (*opts).valid_before < now as uint64_t
    {
        format_absolute_time(
            (*opts).valid_before,
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
        );
        crate::log::sshlog(
            b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"auth_authorise_keyopts\0",
            ))
            .as_ptr(),
            69 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s: entry expired at %s\0" as *const u8 as *const libc::c_char,
            loc,
            buf.as_mut_ptr(),
        );
        auth_debug_add(
            b"%s: entry expired at %s\0" as *const u8 as *const libc::c_char,
            loc,
            buf.as_mut_ptr(),
        );
        return -(1 as libc::c_int);
    }
    if !((*opts).cert_principals).is_null() && (*opts).cert_authority == 0 {
        crate::log::sshlog(
            b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"auth_authorise_keyopts\0",
            ))
            .as_ptr(),
            75 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s: principals on non-CA key\0" as *const u8 as *const libc::c_char,
            loc,
        );
        auth_debug_add(
            b"%s: principals on non-CA key\0" as *const u8 as *const libc::c_char,
            loc,
        );
        return -(1 as libc::c_int);
    }
    if allow_cert_authority == 0 && (*opts).cert_authority != 0 {
        crate::log::sshlog(
            b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"auth_authorise_keyopts\0",
            ))
            .as_ptr(),
            82 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s: cert-authority flag invalid here\0" as *const u8 as *const libc::c_char,
            loc,
        );
        auth_debug_add(
            b"%s: cert-authority flag invalid here\0" as *const u8 as *const libc::c_char,
            loc,
        );
        return -(1 as libc::c_int);
    }
    if !((*opts).required_from_host_keys).is_null() {
        's_87: {
            match match_host_and_ip(remote_host, remote_ip, (*opts).required_from_host_keys) {
                1 => {
                    break 's_87;
                }
                0 => {}
                -1 | _ => {
                    crate::log::sshlog(
                        b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                            b"auth_authorise_keyopts\0",
                        ))
                        .as_ptr(),
                        97 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"%s: invalid from criteria\0" as *const u8 as *const libc::c_char,
                        loc,
                    );
                    auth_debug_add(
                        b"%s: invalid from criteria\0" as *const u8 as *const libc::c_char,
                        loc,
                    );
                }
            }
            crate::log::sshlog(
                b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<
                    &[u8; 23],
                    &[libc::c_char; 23],
                >(b"auth_authorise_keyopts\0"))
                    .as_ptr(),
                105 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"%s: Authentication tried for %.100s with correct key but not from a permitted host (host=%.200s, ip=%.200s, required=%.200s).\0"
                    as *const u8 as *const libc::c_char,
                loc,
                (*pw).pw_name,
                remote_host,
                remote_ip,
                (*opts).required_from_host_keys,
            );
            auth_debug_add(
                b"%s: Your host '%.200s' is not permitted to use this key for login.\0" as *const u8
                    as *const libc::c_char,
                loc,
                remote_host,
            );
            return -(1 as libc::c_int);
        }
    }
    if !((*opts).required_from_host_cert).is_null() {
        's_123: {
            match addr_match_cidr_list(remote_ip, (*opts).required_from_host_cert) {
                1 => {
                    break 's_123;
                }
                0 => {}
                -1 | _ => {
                    crate::log::sshlog(
                        b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                            b"auth_authorise_keyopts\0",
                        ))
                        .as_ptr(),
                        123 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s: Certificate source-address invalid\0" as *const u8
                            as *const libc::c_char,
                        loc,
                    );
                }
            }
            crate::log::sshlog(
                b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<
                    &[u8; 23],
                    &[libc::c_char; 23],
                >(b"auth_authorise_keyopts\0"))
                    .as_ptr(),
                128 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"%s: Authentication tried for %.100s with valid certificate but not from a permitted source address (%.200s).\0"
                    as *const u8 as *const libc::c_char,
                loc,
                (*pw).pw_name,
                remote_ip,
            );
            auth_debug_add(
                b"%s: Your address '%.200s' is not permitted to use this certificate for login.\0"
                    as *const u8 as *const libc::c_char,
                loc,
                remote_ip,
            );
            return -(1 as libc::c_int);
        }
    }
    auth_log_authopts(loc, opts, 1 as libc::c_int);
    return 0 as libc::c_int;
}
unsafe extern "C" fn match_principals_option(
    mut principal_list: *const libc::c_char,
    mut cert: *mut sshkey_cert,
) -> libc::c_int {
    let mut result: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < (*cert).nprincipals {
        result = match_list(
            *((*cert).principals).offset(i as isize),
            principal_list,
            0 as *mut u_int,
        );
        if !result.is_null() {
            crate::log::sshlog(
                b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"match_principals_option\0",
                ))
                .as_ptr(),
                158 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"matched principal from key options \"%.100s\"\0" as *const u8
                    as *const libc::c_char,
                result,
            );
            free(result as *mut libc::c_void);
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn auth_check_principals_line(
    mut cp: *mut libc::c_char,
    mut cert: *const sshkey_cert,
    mut loc: *const libc::c_char,
    mut authoptsp: *mut *mut sshauthopt,
) -> libc::c_int {
    let mut i: u_int = 0;
    let mut found: u_int = 0 as libc::c_int as u_int;
    let mut ep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut line_opts: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut reason: *const libc::c_char = 0 as *const libc::c_char;
    let mut opts: *mut sshauthopt = 0 as *mut sshauthopt;
    if !authoptsp.is_null() {
        *authoptsp = 0 as *mut sshauthopt;
    }
    ep = cp
        .offset(strlen(cp) as isize)
        .offset(-(1 as libc::c_int as isize));
    while ep > cp
        && (*ep as libc::c_int == '\n' as i32
            || *ep as libc::c_int == ' ' as i32
            || *ep as libc::c_int == '\t' as i32)
    {
        let fresh0 = ep;
        ep = ep.offset(-1);
        *fresh0 = '\0' as i32 as libc::c_char;
    }
    line_opts = 0 as *mut libc::c_char;
    ep = strrchr(cp, ' ' as i32);
    if !ep.is_null() || {
        ep = strrchr(cp, '\t' as i32);
        !ep.is_null()
    } {
        while *ep as libc::c_int == ' ' as i32 || *ep as libc::c_int == '\t' as i32 {
            ep = ep.offset(1);
            ep;
        }
        line_opts = cp;
        cp = ep;
    }
    opts = sshauthopt_parse(line_opts, &mut reason);
    if opts.is_null() {
        crate::log::sshlog(
            b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"auth_check_principals_line\0",
            ))
            .as_ptr(),
            201 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s: bad principals options: %s\0" as *const u8 as *const libc::c_char,
            loc,
            reason,
        );
        auth_debug_add(
            b"%s: bad principals options: %s\0" as *const u8 as *const libc::c_char,
            loc,
            reason,
        );
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int as u_int;
    while i < (*cert).nprincipals {
        if !(strcmp(cp, *((*cert).principals).offset(i as isize)) != 0 as libc::c_int) {
            crate::log::sshlog(
                b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"auth_check_principals_line\0",
                ))
                .as_ptr(),
                210 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"%s: matched principal \"%.100s\"\0" as *const u8 as *const libc::c_char,
                loc,
                *((*cert).principals).offset(i as isize),
            );
            found = 1 as libc::c_int as u_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    if found != 0 && !authoptsp.is_null() {
        *authoptsp = opts;
        opts = 0 as *mut sshauthopt;
    }
    sshauthopt_free(opts);
    return if found != 0 {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
pub unsafe extern "C" fn auth_process_principals(
    mut f: *mut libc::FILE,
    mut file: *const libc::c_char,
    mut cert: *const sshkey_cert,
    mut authoptsp: *mut *mut sshauthopt,
) -> libc::c_int {
    let mut loc: [libc::c_char; 256] = [0; 256];
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut linenum: u_long = 0 as libc::c_int as u_long;
    let mut nonblank: u_long = 0 as libc::c_int as u_long;
    let mut found_principal: u_int = 0 as libc::c_int as u_int;
    if !authoptsp.is_null() {
        *authoptsp = 0 as *mut sshauthopt;
    }
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        linenum = linenum.wrapping_add(1);
        linenum;
        if found_principal != 0 {
            continue;
        }
        cp = line;
        while *cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32 {
            cp = cp.offset(1);
            cp;
        }
        ep = strchr(cp, '#' as i32);
        if !ep.is_null() {
            *ep = '\0' as i32 as libc::c_char;
        }
        if *cp == 0 || *cp as libc::c_int == '\n' as i32 {
            continue;
        }
        nonblank = nonblank.wrapping_add(1);
        nonblank;
        snprintf(
            loc.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
            b"%.200s:%lu\0" as *const u8 as *const libc::c_char,
            file,
            linenum,
        );
        if auth_check_principals_line(cp, cert, loc.as_mut_ptr(), authoptsp) == 0 as libc::c_int {
            found_principal = 1 as libc::c_int as u_int;
        }
    }
    crate::log::sshlog(
        b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"auth_process_principals\0"))
            .as_ptr(),
        253 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"%s: processed %lu/%lu lines\0" as *const u8 as *const libc::c_char,
        file,
        nonblank,
        linenum,
    );
    free(line as *mut libc::c_void);
    return found_principal as libc::c_int;
}
pub unsafe extern "C" fn auth_check_authkey_line(
    mut pw: *mut passwd,
    mut key: *mut sshkey,
    mut cp: *mut libc::c_char,
    mut remote_ip: *const libc::c_char,
    mut remote_host: *const libc::c_char,
    mut loc: *const libc::c_char,
    mut authoptsp: *mut *mut sshauthopt,
) -> libc::c_int {
    let mut current_block: u64;
    let mut want_keytype: libc::c_int = if sshkey_is_cert(key) != 0 {
        KEY_UNSPEC as libc::c_int
    } else {
        (*key).type_0
    };
    let mut found: *mut sshkey = 0 as *mut sshkey;
    let mut keyopts: *mut sshauthopt = 0 as *mut sshauthopt;
    let mut certopts: *mut sshauthopt = 0 as *mut sshauthopt;
    let mut finalopts: *mut sshauthopt = 0 as *mut sshauthopt;
    let mut key_options: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut reason: *const libc::c_char = 0 as *const libc::c_char;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if !authoptsp.is_null() {
        *authoptsp = 0 as *mut sshauthopt;
    }
    found = sshkey_new(want_keytype);
    if found.is_null() {
        crate::log::sshlog(
            b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"auth_check_authkey_line\0",
            ))
            .as_ptr(),
            279 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"keytype %d failed\0" as *const u8 as *const libc::c_char,
            want_keytype,
        );
    } else {
        if sshkey_read(found, &mut cp) != 0 as libc::c_int {
            crate::log::sshlog(
                b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"auth_check_authkey_line\0",
                ))
                .as_ptr(),
                287 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"%s: check options: '%s'\0" as *const u8 as *const libc::c_char,
                loc,
                cp,
            );
            key_options = cp;
            if sshkey_advance_past_options(&mut cp) != 0 as libc::c_int {
                reason = b"invalid key option string\0" as *const u8 as *const libc::c_char;
                current_block = 13338124556963691996;
            } else {
                skip_space(&mut cp);
                if sshkey_read(found, &mut cp) != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                            b"auth_check_authkey_line\0",
                        ))
                        .as_ptr(),
                        296 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"%s: advance: '%s'\0" as *const u8 as *const libc::c_char,
                        loc,
                        cp,
                    );
                    current_block = 15639534262997179764;
                } else {
                    current_block = 11050875288958768710;
                }
            }
        } else {
            current_block = 11050875288958768710;
        }
        match current_block {
            15639534262997179764 => {}
            _ => {
                match current_block {
                    11050875288958768710 => {
                        keyopts = sshauthopt_parse(key_options, &mut reason);
                        if keyopts.is_null() {
                            crate::log::sshlog(
                                b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                    b"auth_check_authkey_line\0",
                                ))
                                .as_ptr(),
                                302 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"%s: bad key options: %s\0" as *const u8 as *const libc::c_char,
                                loc,
                                reason,
                            );
                            auth_debug_add(
                                b"%s: bad key options: %s\0" as *const u8 as *const libc::c_char,
                                loc,
                                reason,
                            );
                            current_block = 15639534262997179764;
                        } else {
                            if sshkey_is_cert(key) != 0 {
                                if sshkey_equal(found, (*(*key).cert).signature_key) == 0
                                    || (*keyopts).cert_authority == 0
                                {
                                    current_block = 15639534262997179764;
                                } else {
                                    current_block = 2838571290723028321;
                                }
                            } else if sshkey_equal(found, key) == 0
                                || (*keyopts).cert_authority != 0
                            {
                                current_block = 15639534262997179764;
                            } else {
                                current_block = 2838571290723028321;
                            }
                            match current_block {
                                15639534262997179764 => {}
                                _ => {
                                    fp =
                                        sshkey_fingerprint(found, 2 as libc::c_int, SSH_FP_DEFAULT);
                                    if fp.is_null() {
                                        sshfatal(
                                            b"auth2-pubkeyfile.c\0" as *const u8
                                                as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 24],
                                                &[libc::c_char; 24],
                                            >(
                                                b"auth_check_authkey_line\0"
                                            ))
                                            .as_ptr(),
                                            321 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_FATAL,
                                            0 as *const libc::c_char,
                                            b"fingerprint failed\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                    }
                                    crate::log::sshlog(
                                        b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                            b"auth_check_authkey_line\0",
                                        ))
                                        .as_ptr(),
                                        324 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG1,
                                        0 as *const libc::c_char,
                                        b"%s: matching %s found: %s %s\0" as *const u8
                                            as *const libc::c_char,
                                        loc,
                                        if sshkey_is_cert(key) != 0 {
                                            b"CA\0" as *const u8 as *const libc::c_char
                                        } else {
                                            b"key\0" as *const u8 as *const libc::c_char
                                        },
                                        sshkey_type(found),
                                        fp,
                                    );
                                    if auth_authorise_keyopts(
                                        pw,
                                        keyopts,
                                        sshkey_is_cert(key),
                                        remote_ip,
                                        remote_host,
                                        loc,
                                    ) != 0 as libc::c_int
                                    {
                                        reason = b"Refused by key options\0" as *const u8
                                            as *const libc::c_char;
                                        current_block = 13338124556963691996;
                                    } else {
                                        if sshkey_is_cert(key) == 0 {
                                            crate::log::sshlog(
                                                b"auth2-pubkeyfile.c\0" as *const u8
                                                    as *const libc::c_char,
                                                (*::core::mem::transmute::<
                                                    &[u8; 24],
                                                    &[libc::c_char; 24],
                                                >(
                                                    b"auth_check_authkey_line\0"
                                                ))
                                                .as_ptr(),
                                                334 as libc::c_int,
                                                0 as libc::c_int,
                                                SYSLOG_LEVEL_VERBOSE,
                                                0 as *const libc::c_char,
                                                b"Accepted key %s %s found at %s\0" as *const u8
                                                    as *const libc::c_char,
                                                sshkey_type(found),
                                                fp,
                                                loc,
                                            );
                                            finalopts = keyopts;
                                            keyopts = 0 as *mut sshauthopt;
                                            current_block = 10374278110229209357;
                                        } else {
                                            certopts = sshauthopt_from_cert(key);
                                            if certopts.is_null() {
                                                reason = b"Invalid certificate options\0"
                                                    as *const u8
                                                    as *const libc::c_char;
                                                current_block = 13338124556963691996;
                                            } else if auth_authorise_keyopts(
                                                pw,
                                                certopts,
                                                0 as libc::c_int,
                                                remote_ip,
                                                remote_host,
                                                loc,
                                            ) != 0 as libc::c_int
                                            {
                                                reason = b"Refused by certificate options\0"
                                                    as *const u8
                                                    as *const libc::c_char;
                                                current_block = 13338124556963691996;
                                            } else {
                                                finalopts = sshauthopt_merge(
                                                    keyopts,
                                                    certopts,
                                                    &mut reason,
                                                );
                                                if finalopts.is_null() {
                                                    current_block = 13338124556963691996;
                                                } else if !((*keyopts).cert_principals).is_null()
                                                    && match_principals_option(
                                                        (*keyopts).cert_principals,
                                                        (*key).cert,
                                                    ) == 0
                                                {
                                                    reason = b"Certificate does not contain an authorized principal\0"
                                                        as *const u8 as *const libc::c_char;
                                                    current_block = 13338124556963691996;
                                                } else if sshkey_cert_check_authority_now(
                                                    key,
                                                    0 as libc::c_int,
                                                    0 as libc::c_int,
                                                    0 as libc::c_int,
                                                    if ((*keyopts).cert_principals).is_null() {
                                                        (*pw).pw_name
                                                    } else {
                                                        0 as *mut libc::c_char
                                                    },
                                                    &mut reason,
                                                ) != 0 as libc::c_int
                                                {
                                                    current_block = 13338124556963691996;
                                                } else {
                                                    crate::log::sshlog(
                                                        b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                                                        (*::core::mem::transmute::<
                                                            &[u8; 24],
                                                            &[libc::c_char; 24],
                                                        >(b"auth_check_authkey_line\0"))
                                                            .as_ptr(),
                                                        376 as libc::c_int,
                                                        0 as libc::c_int,
                                                        SYSLOG_LEVEL_VERBOSE,
                                                        0 as *const libc::c_char,
                                                        b"Accepted certificate ID \"%s\" (serial %llu) signed by CA %s %s found at %s\0"
                                                            as *const u8 as *const libc::c_char,
                                                        (*(*key).cert).key_id,
                                                        (*(*key).cert).serial as libc::c_ulonglong,
                                                        sshkey_type(found),
                                                        fp,
                                                        loc,
                                                    );
                                                    current_block = 10374278110229209357;
                                                }
                                            }
                                        }
                                        match current_block {
                                            13338124556963691996 => {}
                                            _ => {
                                                if finalopts.is_null() {
                                                    sshfatal(
                                                        b"auth2-pubkeyfile.c\0" as *const u8
                                                            as *const libc::c_char,
                                                        (*::core::mem::transmute::<
                                                            &[u8; 24],
                                                            &[libc::c_char; 24],
                                                        >(
                                                            b"auth_check_authkey_line\0"
                                                        ))
                                                        .as_ptr(),
                                                        380 as libc::c_int,
                                                        1 as libc::c_int,
                                                        SYSLOG_LEVEL_FATAL,
                                                        0 as *const libc::c_char,
                                                        b"internal error: missing options\0"
                                                            as *const u8
                                                            as *const libc::c_char,
                                                    );
                                                }
                                                if !authoptsp.is_null() {
                                                    *authoptsp = finalopts;
                                                    finalopts = 0 as *mut sshauthopt;
                                                }
                                                ret = 0 as libc::c_int;
                                                current_block = 15639534262997179764;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
                match current_block {
                    15639534262997179764 => {}
                    _ => {
                        crate::log::sshlog(
                            b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                b"auth_check_authkey_line\0",
                            ))
                            .as_ptr(),
                            390 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s\0" as *const u8 as *const libc::c_char,
                            reason,
                        );
                        auth_debug_add(b"%s\0" as *const u8 as *const libc::c_char, reason);
                    }
                }
            }
        }
    }
    free(fp as *mut libc::c_void);
    sshauthopt_free(keyopts);
    sshauthopt_free(certopts);
    sshauthopt_free(finalopts);
    sshkey_free(found);
    return ret;
}
pub unsafe extern "C" fn auth_check_authkeys_file(
    mut pw: *mut passwd,
    mut f: *mut libc::FILE,
    mut file: *mut libc::c_char,
    mut key: *mut sshkey,
    mut remote_ip: *const libc::c_char,
    mut remote_host: *const libc::c_char,
    mut authoptsp: *mut *mut sshauthopt,
) -> libc::c_int {
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut loc: [libc::c_char; 256] = [0; 256];
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut found_key: libc::c_int = 0 as libc::c_int;
    let mut linenum: u_long = 0 as libc::c_int as u_long;
    let mut nonblank: u_long = 0 as libc::c_int as u_long;
    if !authoptsp.is_null() {
        *authoptsp = 0 as *mut sshauthopt;
    }
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        linenum = linenum.wrapping_add(1);
        linenum;
        if found_key != 0 {
            continue;
        }
        cp = line;
        skip_space(&mut cp);
        if *cp == 0 || *cp as libc::c_int == '\n' as i32 || *cp as libc::c_int == '#' as i32 {
            continue;
        }
        nonblank = nonblank.wrapping_add(1);
        nonblank;
        snprintf(
            loc.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
            b"%.200s:%lu\0" as *const u8 as *const libc::c_char,
            file,
            linenum,
        );
        if auth_check_authkey_line(
            pw,
            key,
            cp,
            remote_ip,
            remote_host,
            loc.as_mut_ptr(),
            authoptsp,
        ) == 0 as libc::c_int
        {
            found_key = 1 as libc::c_int;
        }
    }
    free(line as *mut libc::c_void);
    crate::log::sshlog(
        b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"auth_check_authkeys_file\0"))
            .as_ptr(),
        437 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"%s: processed %lu/%lu lines\0" as *const u8 as *const libc::c_char,
        file,
        nonblank,
        linenum,
    );
    return found_key;
}
unsafe extern "C" fn auth_openfile(
    mut file: *const libc::c_char,
    mut pw: *mut passwd,
    mut strict_modes: libc::c_int,
    mut log_missing: libc::c_int,
    mut file_type: *mut libc::c_char,
) -> *mut libc::FILE {
    let mut line: [libc::c_char; 1024] = [0; 1024];
    let mut st: stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_mtim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_ctim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        __glibc_reserved: [0; 3],
    };
    let mut fd: libc::c_int = 0;
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    fd = libc::open(file, 0 as libc::c_int | 0o4000 as libc::c_int);
    if fd == -(1 as libc::c_int) {
        if *__errno_location() != 2 as libc::c_int {
            crate::log::sshlog(
                b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"auth_openfile\0"))
                    .as_ptr(),
                453 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Could not open user '%s' %s '%s': %s\0" as *const u8 as *const libc::c_char,
                (*pw).pw_name,
                file_type,
                file,
                strerror(*__errno_location()),
            );
        } else if log_missing != 0 {
            crate::log::sshlog(
                b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"auth_openfile\0"))
                    .as_ptr(),
                456 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Could not open user '%s' %s '%s': %s\0" as *const u8 as *const libc::c_char,
                (*pw).pw_name,
                file_type,
                file,
                strerror(*__errno_location()),
            );
        }
        return 0 as *mut libc::FILE;
    }
    if fstat(fd, &mut st) == -(1 as libc::c_int) {
        close(fd);
        return 0 as *mut libc::FILE;
    }
    if !(st.st_mode & 0o170000 as libc::c_int as libc::c_uint
        == 0o100000 as libc::c_int as libc::c_uint)
    {
        crate::log::sshlog(
            b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"auth_openfile\0"))
                .as_ptr(),
            467 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"User '%s' %s '%s' is not a regular file\0" as *const u8 as *const libc::c_char,
            (*pw).pw_name,
            file_type,
            file,
        );
        close(fd);
        return 0 as *mut libc::FILE;
    }
    unset_nonblock(fd);
    f = libc::fdopen(fd, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        close(fd);
        return 0 as *mut libc::FILE;
    }
    if strict_modes != 0
        && safe_path_fd(
            fileno(f),
            file,
            pw,
            line.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        ) != 0 as libc::c_int
    {
        fclose(f);
        crate::log::sshlog(
            b"auth2-pubkeyfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"auth_openfile\0"))
                .as_ptr(),
            479 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Authentication refused: %s\0" as *const u8 as *const libc::c_char,
            line.as_mut_ptr(),
        );
        auth_debug_add(
            b"Ignored %s: %s\0" as *const u8 as *const libc::c_char,
            file_type,
            line.as_mut_ptr(),
        );
        return 0 as *mut libc::FILE;
    }
    return f;
}
pub unsafe extern "C" fn auth_openkeyfile(
    mut file: *const libc::c_char,
    mut pw: *mut passwd,
    mut strict_modes: libc::c_int,
) -> *mut libc::FILE {
    return auth_openfile(
        file,
        pw,
        strict_modes,
        1 as libc::c_int,
        b"authorized keys\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
}
pub unsafe extern "C" fn auth_openprincipals(
    mut file: *const libc::c_char,
    mut pw: *mut passwd,
    mut strict_modes: libc::c_int,
) -> *mut libc::FILE {
    return auth_openfile(
        file,
        pw,
        strict_modes,
        0 as libc::c_int,
        b"authorized principals\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
}
