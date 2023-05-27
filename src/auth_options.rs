use ::libc;

extern "C" {
    pub type sshbuf;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char, _: ...) -> libc::c_int;
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;

    fn sshbuf_put_stringb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_u8(buf: *mut sshbuf, val: u_char) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_put_u64(buf: *mut sshbuf, val: u_int64_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_get_u64(buf: *mut sshbuf, valp: *mut u_int64_t) -> libc::c_int;
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_froms(buf: *mut sshbuf, bufp: *mut *mut sshbuf) -> libc::c_int;
    fn sshbuf_fromb(buf: *mut sshbuf) -> *mut sshbuf;
    fn sshbuf_new() -> *mut sshbuf;

    fn a2tun(_: *const libc::c_char, _: *mut libc::c_int) -> libc::c_int;
    fn hpdelim2(_: *mut *mut libc::c_char, _: *mut libc::c_char) -> *mut libc::c_char;
    fn valid_env_name(_: *const libc::c_char) -> libc::c_int;
    fn parse_absolute_time(_: *const libc::c_char, _: *mut uint64_t) -> libc::c_int;
    fn opt_flag(
        opt: *const libc::c_char,
        allow_negate: libc::c_int,
        optsp: *mut *const libc::c_char,
    ) -> libc::c_int;
    fn opt_dequote(
        sp: *mut *const libc::c_char,
        errstrp: *mut *const libc::c_char,
    ) -> *mut libc::c_char;
    fn opt_match(opts: *mut *const libc::c_char, term: *const libc::c_char) -> libc::c_int;
    fn sshkey_type_is_cert(_: libc::c_int) -> libc::c_int;
    fn addr_match_cidr_list(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
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
unsafe extern "C" fn dup_strings(
    mut dstp: *mut *mut *mut libc::c_char,
    mut ndstp: *mut size_t,
    mut src: *mut *mut libc::c_char,
    mut nsrc: size_t,
) -> libc::c_int {
    let mut dst: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    *dstp = 0 as *mut *mut libc::c_char;
    *ndstp = 0 as libc::c_int as size_t;
    if nsrc == 0 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    dst = calloc(
        nsrc,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    if dst.is_null() {
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int as size_t;
    while i < nsrc {
        let ref mut fresh0 = *dst.offset(i as isize);
        *fresh0 = strdup(*src.offset(i as isize));
        if (*fresh0).is_null() {
            j = 0 as libc::c_int as size_t;
            while j < i {
                libc::free(*dst.offset(j as isize) as *mut libc::c_void);
                j = j.wrapping_add(1);
                j;
            }
            libc::free(dst as *mut libc::c_void);
            return -(1 as libc::c_int);
        }
        i = i.wrapping_add(1);
        i;
    }
    *dstp = dst;
    *ndstp = nsrc;
    return 0 as libc::c_int;
}
unsafe extern "C" fn cert_option_list(
    mut opts: *mut sshauthopt,
    mut oblob: *mut sshbuf,
    mut which: u_int,
    mut crit: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut command: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut allowed: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut c: *mut sshbuf = 0 as *mut sshbuf;
    let mut data: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut found: libc::c_int = 0;
    c = sshbuf_fromb(oblob);
    if c.is_null() {
        crate::log::sshlog(
            b"auth-options.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"cert_option_list\0"))
                .as_ptr(),
            82 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"sshbuf_fromb failed\0" as *const u8 as *const libc::c_char,
        );
    } else {
        loop {
            if !(sshbuf_len(c) > 0 as libc::c_int as libc::c_ulong) {
                current_block = 4741994311446740739;
                break;
            }
            sshbuf_free(data);
            data = 0 as *mut sshbuf;
            r = sshbuf_get_cstring(c, &mut name, 0 as *mut size_t);
            if r != 0 as libc::c_int || {
                r = sshbuf_froms(c, &mut data);
                r != 0 as libc::c_int
            } {
                crate::log::sshlog(
                    b"auth-options.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"cert_option_list\0",
                    ))
                    .as_ptr(),
                    91 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"Unable to parse certificate options\0" as *const u8 as *const libc::c_char,
                );
                current_block = 10905793257652027281;
                break;
            } else {
                crate::log::sshlog(
                    b"auth-options.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"cert_option_list\0",
                    ))
                    .as_ptr(),
                    95 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"found certificate option \"%.100s\" len %zu\0" as *const u8
                        as *const libc::c_char,
                    name,
                    sshbuf_len(data),
                );
                found = 0 as libc::c_int;
                if which & 2 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint {
                    if strcmp(
                        name,
                        b"no-touch-required\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        (*opts).no_require_user_presence = 1 as libc::c_int;
                        found = 1 as libc::c_int;
                    } else if strcmp(
                        name,
                        b"permit-X11-forwarding\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        (*opts).permit_x11_forwarding_flag = 1 as libc::c_int;
                        found = 1 as libc::c_int;
                    } else if strcmp(
                        name,
                        b"permit-agent-forwarding\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        (*opts).permit_agent_forwarding_flag = 1 as libc::c_int;
                        found = 1 as libc::c_int;
                    } else if strcmp(
                        name,
                        b"permit-port-forwarding\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        (*opts).permit_port_forwarding_flag = 1 as libc::c_int;
                        found = 1 as libc::c_int;
                    } else if strcmp(name, b"permit-pty\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                    {
                        (*opts).permit_pty_flag = 1 as libc::c_int;
                        found = 1 as libc::c_int;
                    } else if strcmp(
                        name,
                        b"permit-user-rc\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        (*opts).permit_user_rc = 1 as libc::c_int;
                        found = 1 as libc::c_int;
                    }
                }
                if found == 0
                    && which & 1 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
                {
                    if strcmp(
                        name,
                        b"verify-required\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        (*opts).require_verify = 1 as libc::c_int;
                        found = 1 as libc::c_int;
                    } else if strcmp(name, b"force-command\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                    {
                        r = sshbuf_get_cstring(data, &mut command, 0 as *mut size_t);
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"auth-options.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                                    b"cert_option_list\0",
                                ))
                                .as_ptr(),
                                128 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"Unable to parse \"%s\" section\0" as *const u8
                                    as *const libc::c_char,
                                name,
                            );
                            current_block = 10905793257652027281;
                            break;
                        } else if !((*opts).force_command).is_null() {
                            crate::log::sshlog(
                                b"auth-options.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                                    b"cert_option_list\0",
                                ))
                                .as_ptr(),
                                133 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"Certificate has multiple force-command options\0" as *const u8
                                    as *const libc::c_char,
                            );
                            libc::free(command as *mut libc::c_void);
                            current_block = 10905793257652027281;
                            break;
                        } else {
                            (*opts).force_command = command;
                            found = 1 as libc::c_int;
                        }
                    } else if strcmp(
                        name,
                        b"source-address\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        r = sshbuf_get_cstring(data, &mut allowed, 0 as *mut size_t);
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"auth-options.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                                    b"cert_option_list\0",
                                ))
                                .as_ptr(),
                                143 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"Unable to parse \"%s\" section\0" as *const u8
                                    as *const libc::c_char,
                                name,
                            );
                            current_block = 10905793257652027281;
                            break;
                        } else if !((*opts).required_from_host_cert).is_null() {
                            crate::log::sshlog(
                                b"auth-options.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                                    b"cert_option_list\0",
                                ))
                                .as_ptr(),
                                148 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"Certificate has multiple source-address options\0" as *const u8
                                    as *const libc::c_char,
                            );
                            libc::free(allowed as *mut libc::c_void);
                            current_block = 10905793257652027281;
                            break;
                        } else if addr_match_cidr_list(0 as *const libc::c_char, allowed)
                            == -(1 as libc::c_int)
                        {
                            crate::log::sshlog(
                                b"auth-options.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                                    b"cert_option_list\0",
                                ))
                                .as_ptr(),
                                155 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"Certificate source-address contents invalid\0" as *const u8
                                    as *const libc::c_char,
                            );
                            current_block = 10905793257652027281;
                            break;
                        } else {
                            (*opts).required_from_host_cert = allowed;
                            found = 1 as libc::c_int;
                        }
                    }
                }
                if found == 0 {
                    if crit != 0 {
                        crate::log::sshlog(
                            b"auth-options.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                                b"cert_option_list\0",
                            ))
                            .as_ptr(),
                            166 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"Certificate critical option \"%s\" is not supported\0" as *const u8
                                as *const libc::c_char,
                            name,
                        );
                        current_block = 10905793257652027281;
                        break;
                    } else {
                        crate::log::sshlog(
                            b"auth-options.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                                b"cert_option_list\0",
                            ))
                            .as_ptr(),
                            170 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_INFO,
                            0 as *const libc::c_char,
                            b"Certificate extension \"%s\" is not supported\0" as *const u8
                                as *const libc::c_char,
                            name,
                        );
                    }
                } else if sshbuf_len(data) != 0 as libc::c_int as libc::c_ulong {
                    crate::log::sshlog(
                        b"auth-options.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                            b"cert_option_list\0",
                        ))
                        .as_ptr(),
                        174 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Certificate option \"%s\" corrupt (extra data)\0" as *const u8
                            as *const libc::c_char,
                        name,
                    );
                    current_block = 10905793257652027281;
                    break;
                }
                libc::free(name as *mut libc::c_void);
                name = 0 as *mut libc::c_char;
            }
        }
        match current_block {
            10905793257652027281 => {}
            _ => {
                ret = 0 as libc::c_int;
            }
        }
    }
    libc::free(name as *mut libc::c_void);
    sshbuf_free(data);
    sshbuf_free(c);
    return ret;
}
pub unsafe extern "C" fn sshauthopt_new() -> *mut sshauthopt {
    let mut ret: *mut sshauthopt = 0 as *mut sshauthopt;
    ret = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<sshauthopt>() as libc::c_ulong,
    ) as *mut sshauthopt;
    if ret.is_null() {
        return 0 as *mut sshauthopt;
    }
    (*ret).force_tun_device = -(1 as libc::c_int);
    return ret;
}
pub unsafe extern "C" fn sshauthopt_free(mut opts: *mut sshauthopt) {
    let mut i: size_t = 0;
    if opts.is_null() {
        return;
    }
    libc::free((*opts).cert_principals as *mut libc::c_void);
    libc::free((*opts).force_command as *mut libc::c_void);
    libc::free((*opts).required_from_host_cert as *mut libc::c_void);
    libc::free((*opts).required_from_host_keys as *mut libc::c_void);
    i = 0 as libc::c_int as size_t;
    while i < (*opts).nenv {
        libc::free(*((*opts).env).offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free((*opts).env as *mut libc::c_void);
    i = 0 as libc::c_int as size_t;
    while i < (*opts).npermitopen {
        libc::free(*((*opts).permitopen).offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free((*opts).permitopen as *mut libc::c_void);
    i = 0 as libc::c_int as size_t;
    while i < (*opts).npermitlisten {
        libc::free(*((*opts).permitlisten).offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free((*opts).permitlisten as *mut libc::c_void);
    freezero(
        opts as *mut libc::c_void,
        ::core::mem::size_of::<sshauthopt>() as libc::c_ulong,
    );
}
pub unsafe extern "C" fn sshauthopt_new_with_keys_defaults() -> *mut sshauthopt {
    let mut ret: *mut sshauthopt = 0 as *mut sshauthopt;
    ret = sshauthopt_new();
    if ret.is_null() {
        return 0 as *mut sshauthopt;
    }
    (*ret).permit_port_forwarding_flag = 1 as libc::c_int;
    (*ret).permit_agent_forwarding_flag = 1 as libc::c_int;
    (*ret).permit_x11_forwarding_flag = 1 as libc::c_int;
    (*ret).permit_pty_flag = 1 as libc::c_int;
    (*ret).permit_user_rc = 1 as libc::c_int;
    return ret;
}
unsafe extern "C" fn handle_permit(
    mut optsp: *mut *const libc::c_char,
    mut allow_bare_port: libc::c_int,
    mut permitsp: *mut *mut *mut libc::c_char,
    mut npermitsp: *mut size_t,
    mut errstrp: *mut *const libc::c_char,
) -> libc::c_int {
    let mut opt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut permits: *mut *mut libc::c_char = *permitsp;
    let mut npermits: size_t = *npermitsp;
    let mut errstr: *const libc::c_char = b"unknown error\0" as *const u8 as *const libc::c_char;
    if npermits > 4096 as libc::c_int as libc::c_ulong {
        *errstrp = b"too many permission directives\0" as *const u8 as *const libc::c_char;
        return -(1 as libc::c_int);
    }
    opt = opt_dequote(optsp, &mut errstr);
    if opt.is_null() {
        return -(1 as libc::c_int);
    }
    if allow_bare_port != 0 && (strchr(opt, ':' as i32)).is_null() {
        if asprintf(
            &mut tmp as *mut *mut libc::c_char,
            b"*:%s\0" as *const u8 as *const libc::c_char,
            opt,
        ) == -(1 as libc::c_int)
        {
            libc::free(opt as *mut libc::c_void);
            *errstrp = b"memory allocation failed\0" as *const u8 as *const libc::c_char;
            return -(1 as libc::c_int);
        }
        libc::free(opt as *mut libc::c_void);
        opt = tmp;
    }
    tmp = strdup(opt);
    if tmp.is_null() {
        libc::free(opt as *mut libc::c_void);
        *errstrp = b"memory allocation failed\0" as *const u8 as *const libc::c_char;
        return -(1 as libc::c_int);
    }
    cp = tmp;
    host = hpdelim2(&mut cp, 0 as *mut libc::c_char);
    if host.is_null() || strlen(host) >= 1025 as libc::c_int as libc::c_ulong {
        libc::free(tmp as *mut libc::c_void);
        libc::free(opt as *mut libc::c_void);
        *errstrp = b"invalid permission hostname\0" as *const u8 as *const libc::c_char;
        return -(1 as libc::c_int);
    }
    if cp.is_null()
        || strcmp(cp, b"*\0" as *const u8 as *const libc::c_char) != 0 as libc::c_int
            && crate::misc::a2port(cp) <= 0 as libc::c_int
    {
        libc::free(tmp as *mut libc::c_void);
        libc::free(opt as *mut libc::c_void);
        *errstrp = b"invalid permission port\0" as *const u8 as *const libc::c_char;
        return -(1 as libc::c_int);
    }
    libc::free(tmp as *mut libc::c_void);
    permits = recallocarray(
        permits as *mut libc::c_void,
        npermits,
        npermits.wrapping_add(1 as libc::c_int as libc::c_ulong),
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    if permits.is_null() {
        libc::free(opt as *mut libc::c_void);
        *errstrp = b"memory allocation failed\0" as *const u8 as *const libc::c_char;
        return -(1 as libc::c_int);
    }
    let fresh1 = npermits;
    npermits = npermits.wrapping_add(1);
    let ref mut fresh2 = *permits.offset(fresh1 as isize);
    *fresh2 = opt;
    *permitsp = permits;
    *npermitsp = npermits;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshauthopt_parse(
    mut opts: *const libc::c_char,
    mut errstrp: *mut *const libc::c_char,
) -> *mut sshauthopt {
    let mut current_block: u64;
    let mut oarray: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut opt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut ret: *mut sshauthopt = 0 as *mut sshauthopt;
    let mut errstr: *const libc::c_char = b"unknown error\0" as *const u8 as *const libc::c_char;
    let mut valid_before: uint64_t = 0;
    let mut i: size_t = 0;
    let mut l: size_t = 0;
    if !errstrp.is_null() {
        *errstrp = 0 as *const libc::c_char;
    }
    ret = sshauthopt_new_with_keys_defaults();
    if ret.is_null() {
        current_block = 1642512663562863647;
    } else {
        if opts.is_null() {
            return ret;
        }
        loop {
            if !(*opts as libc::c_int != 0
                && *opts as libc::c_int != ' ' as i32
                && *opts as libc::c_int != '\t' as i32)
            {
                current_block = 7416055328783156979;
                break;
            }
            r = opt_flag(
                b"restrict\0" as *const u8 as *const libc::c_char,
                0 as libc::c_int,
                &mut opts,
            );
            if r != -(1 as libc::c_int) {
                (*ret).restricted = 1 as libc::c_int;
                (*ret).permit_port_forwarding_flag = 0 as libc::c_int;
                (*ret).permit_agent_forwarding_flag = 0 as libc::c_int;
                (*ret).permit_x11_forwarding_flag = 0 as libc::c_int;
                (*ret).permit_pty_flag = 0 as libc::c_int;
                (*ret).permit_user_rc = 0 as libc::c_int;
            } else {
                r = opt_flag(
                    b"cert-authority\0" as *const u8 as *const libc::c_char,
                    0 as libc::c_int,
                    &mut opts,
                );
                if r != -(1 as libc::c_int) {
                    (*ret).cert_authority = r;
                } else {
                    r = opt_flag(
                        b"port-forwarding\0" as *const u8 as *const libc::c_char,
                        1 as libc::c_int,
                        &mut opts,
                    );
                    if r != -(1 as libc::c_int) {
                        (*ret).permit_port_forwarding_flag = (r == 1 as libc::c_int) as libc::c_int;
                    } else {
                        r = opt_flag(
                            b"agent-forwarding\0" as *const u8 as *const libc::c_char,
                            1 as libc::c_int,
                            &mut opts,
                        );
                        if r != -(1 as libc::c_int) {
                            (*ret).permit_agent_forwarding_flag =
                                (r == 1 as libc::c_int) as libc::c_int;
                        } else {
                            r = opt_flag(
                                b"x11-forwarding\0" as *const u8 as *const libc::c_char,
                                1 as libc::c_int,
                                &mut opts,
                            );
                            if r != -(1 as libc::c_int) {
                                (*ret).permit_x11_forwarding_flag =
                                    (r == 1 as libc::c_int) as libc::c_int;
                            } else {
                                r = opt_flag(
                                    b"touch-required\0" as *const u8 as *const libc::c_char,
                                    1 as libc::c_int,
                                    &mut opts,
                                );
                                if r != -(1 as libc::c_int) {
                                    (*ret).no_require_user_presence =
                                        (r != 1 as libc::c_int) as libc::c_int;
                                } else {
                                    r = opt_flag(
                                        b"verify-required\0" as *const u8 as *const libc::c_char,
                                        1 as libc::c_int,
                                        &mut opts,
                                    );
                                    if r != -(1 as libc::c_int) {
                                        (*ret).require_verify =
                                            (r == 1 as libc::c_int) as libc::c_int;
                                    } else {
                                        r = opt_flag(
                                            b"pty\0" as *const u8 as *const libc::c_char,
                                            1 as libc::c_int,
                                            &mut opts,
                                        );
                                        if r != -(1 as libc::c_int) {
                                            (*ret).permit_pty_flag =
                                                (r == 1 as libc::c_int) as libc::c_int;
                                        } else {
                                            r = opt_flag(
                                                b"user-rc\0" as *const u8 as *const libc::c_char,
                                                1 as libc::c_int,
                                                &mut opts,
                                            );
                                            if r != -(1 as libc::c_int) {
                                                (*ret).permit_user_rc =
                                                    (r == 1 as libc::c_int) as libc::c_int;
                                            } else if opt_match(
                                                &mut opts,
                                                b"command\0" as *const u8 as *const libc::c_char,
                                            ) != 0
                                            {
                                                if !((*ret).force_command).is_null() {
                                                    errstr = b"multiple \"command\" clauses\0"
                                                        as *const u8
                                                        as *const libc::c_char;
                                                    current_block = 2182509200741687066;
                                                    break;
                                                } else {
                                                    (*ret).force_command =
                                                        opt_dequote(&mut opts, &mut errstr);
                                                    if ((*ret).force_command).is_null() {
                                                        current_block = 2182509200741687066;
                                                        break;
                                                    }
                                                }
                                            } else if opt_match(
                                                &mut opts,
                                                b"principals\0" as *const u8 as *const libc::c_char,
                                            ) != 0
                                            {
                                                if !((*ret).cert_principals).is_null() {
                                                    errstr = b"multiple \"principals\" clauses\0"
                                                        as *const u8
                                                        as *const libc::c_char;
                                                    current_block = 2182509200741687066;
                                                    break;
                                                } else {
                                                    (*ret).cert_principals =
                                                        opt_dequote(&mut opts, &mut errstr);
                                                    if ((*ret).cert_principals).is_null() {
                                                        current_block = 2182509200741687066;
                                                        break;
                                                    }
                                                }
                                            } else if opt_match(
                                                &mut opts,
                                                b"from\0" as *const u8 as *const libc::c_char,
                                            ) != 0
                                            {
                                                if !((*ret).required_from_host_keys).is_null() {
                                                    errstr = b"multiple \"from\" clauses\0"
                                                        as *const u8
                                                        as *const libc::c_char;
                                                    current_block = 2182509200741687066;
                                                    break;
                                                } else {
                                                    (*ret).required_from_host_keys =
                                                        opt_dequote(&mut opts, &mut errstr);
                                                    if ((*ret).required_from_host_keys).is_null() {
                                                        current_block = 2182509200741687066;
                                                        break;
                                                    }
                                                }
                                            } else if opt_match(
                                                &mut opts,
                                                b"expiry-time\0" as *const u8
                                                    as *const libc::c_char,
                                            ) != 0
                                            {
                                                opt = opt_dequote(&mut opts, &mut errstr);
                                                if opt.is_null() {
                                                    current_block = 2182509200741687066;
                                                    break;
                                                }
                                                if parse_absolute_time(opt, &mut valid_before)
                                                    != 0 as libc::c_int
                                                    || valid_before
                                                        == 0 as libc::c_int as libc::c_ulong
                                                {
                                                    libc::free(opt as *mut libc::c_void);
                                                    errstr = b"invalid expires time\0" as *const u8
                                                        as *const libc::c_char;
                                                    current_block = 2182509200741687066;
                                                    break;
                                                } else {
                                                    libc::free(opt as *mut libc::c_void);
                                                    if (*ret).valid_before
                                                        == 0 as libc::c_int as libc::c_ulong
                                                        || valid_before < (*ret).valid_before
                                                    {
                                                        (*ret).valid_before = valid_before;
                                                    }
                                                }
                                            } else if opt_match(
                                                &mut opts,
                                                b"environment\0" as *const u8
                                                    as *const libc::c_char,
                                            ) != 0
                                            {
                                                if (*ret).nenv
                                                    > 1024 as libc::c_int as libc::c_ulong
                                                {
                                                    errstr = b"too many environment strings\0"
                                                        as *const u8
                                                        as *const libc::c_char;
                                                    current_block = 2182509200741687066;
                                                    break;
                                                } else {
                                                    opt = opt_dequote(&mut opts, &mut errstr);
                                                    if opt.is_null() {
                                                        current_block = 2182509200741687066;
                                                        break;
                                                    }
                                                    tmp = strchr(opt, '=' as i32);
                                                    if tmp.is_null() {
                                                        libc::free(opt as *mut libc::c_void);
                                                        errstr = b"invalid environment string\0"
                                                            as *const u8
                                                            as *const libc::c_char;
                                                        current_block = 2182509200741687066;
                                                        break;
                                                    } else {
                                                        cp = strdup(opt);
                                                        if cp.is_null() {
                                                            libc::free(opt as *mut libc::c_void);
                                                            current_block = 1642512663562863647;
                                                            break;
                                                        } else {
                                                            l = tmp.offset_from(opt) as libc::c_long
                                                                as size_t;
                                                            *cp.offset(l as isize) =
                                                                '\0' as i32 as libc::c_char;
                                                            if valid_env_name(cp) == 0 {
                                                                libc::free(cp as *mut libc::c_void);
                                                                libc::free(
                                                                    opt as *mut libc::c_void,
                                                                );
                                                                errstr =
                                                                    b"invalid environment string\0"
                                                                        as *const u8
                                                                        as *const libc::c_char;
                                                                current_block = 2182509200741687066;
                                                                break;
                                                            } else {
                                                                i = 0 as libc::c_int as size_t;
                                                                while i < (*ret).nenv {
                                                                    if strncmp(
                                                                        *((*ret).env)
                                                                            .offset(i as isize),
                                                                        cp,
                                                                        l,
                                                                    ) == 0 as libc::c_int
                                                                        && *(*((*ret).env)
                                                                            .offset(i as isize))
                                                                        .offset(l as isize)
                                                                            as libc::c_int
                                                                            == '=' as i32
                                                                    {
                                                                        break;
                                                                    }
                                                                    i = i.wrapping_add(1);
                                                                    i;
                                                                }
                                                                libc::free(cp as *mut libc::c_void);
                                                                if i >= (*ret).nenv {
                                                                    oarray = (*ret).env;
                                                                    (*ret).env = recallocarray(
                                                                        (*ret).env
                                                                            as *mut libc::c_void,
                                                                        (*ret).nenv,
                                                                        ((*ret).nenv).wrapping_add(
                                                                            1 as libc::c_int
                                                                                as libc::c_ulong,
                                                                        ),
                                                                        ::core::mem::size_of::<
                                                                            *mut libc::c_char,
                                                                        >(
                                                                        )
                                                                            as libc::c_ulong,
                                                                    )
                                                                        as *mut *mut libc::c_char;
                                                                    if ((*ret).env).is_null() {
                                                                        libc::free(opt as *mut libc::c_void);
                                                                        (*ret).env = oarray;
                                                                        current_block =
                                                                            1642512663562863647;
                                                                        break;
                                                                    } else {
                                                                        let fresh3 = (*ret).nenv;
                                                                        (*ret).nenv = ((*ret).nenv)
                                                                            .wrapping_add(1);
                                                                        let ref mut fresh4 =
                                                                            *((*ret).env).offset(
                                                                                fresh3 as isize,
                                                                            );
                                                                        *fresh4 = opt;
                                                                        opt =
                                                                            0 as *mut libc::c_char;
                                                                    }
                                                                }
                                                                libc::free(
                                                                    opt as *mut libc::c_void,
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                            } else if opt_match(
                                                &mut opts,
                                                b"permitopen\0" as *const u8 as *const libc::c_char,
                                            ) != 0
                                            {
                                                if handle_permit(
                                                    &mut opts,
                                                    0 as libc::c_int,
                                                    &mut (*ret).permitopen,
                                                    &mut (*ret).npermitopen,
                                                    &mut errstr,
                                                ) != 0 as libc::c_int
                                                {
                                                    current_block = 2182509200741687066;
                                                    break;
                                                }
                                            } else if opt_match(
                                                &mut opts,
                                                b"permitlisten\0" as *const u8
                                                    as *const libc::c_char,
                                            ) != 0
                                            {
                                                if handle_permit(
                                                    &mut opts,
                                                    1 as libc::c_int,
                                                    &mut (*ret).permitlisten,
                                                    &mut (*ret).npermitlisten,
                                                    &mut errstr,
                                                ) != 0 as libc::c_int
                                                {
                                                    current_block = 2182509200741687066;
                                                    break;
                                                }
                                            } else if opt_match(
                                                &mut opts,
                                                b"tunnel\0" as *const u8 as *const libc::c_char,
                                            ) != 0
                                            {
                                                opt = opt_dequote(&mut opts, &mut errstr);
                                                if opt.is_null() {
                                                    current_block = 2182509200741687066;
                                                    break;
                                                }
                                                (*ret).force_tun_device =
                                                    a2tun(opt, 0 as *mut libc::c_int);
                                                libc::free(opt as *mut libc::c_void);
                                                if (*ret).force_tun_device
                                                    == 0x7fffffff as libc::c_int - 1 as libc::c_int
                                                {
                                                    errstr = b"invalid tun device\0" as *const u8
                                                        as *const libc::c_char;
                                                    current_block = 2182509200741687066;
                                                    break;
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
            if *opts as libc::c_int == '\0' as i32
                || *opts as libc::c_int == ' ' as i32
                || *opts as libc::c_int == '\t' as i32
            {
                current_block = 7416055328783156979;
                break;
            }
            if *opts as libc::c_int != ',' as i32 {
                errstr = b"unknown key option\0" as *const u8 as *const libc::c_char;
                current_block = 2182509200741687066;
                break;
            } else {
                opts = opts.offset(1);
                opts;
                if !(*opts as libc::c_int == '\0' as i32) {
                    continue;
                }
                errstr = b"unexpected end-of-options\0" as *const u8 as *const libc::c_char;
                current_block = 2182509200741687066;
                break;
            }
        }
        match current_block {
            2182509200741687066 => {}
            1642512663562863647 => {}
            _ => {
                if !errstrp.is_null() {
                    *errstrp = 0 as *const libc::c_char;
                }
                return ret;
            }
        }
    }
    match current_block {
        1642512663562863647 => {
            errstr = b"memory allocation failed\0" as *const u8 as *const libc::c_char;
        }
        _ => {}
    }
    sshauthopt_free(ret);
    if !errstrp.is_null() {
        *errstrp = errstr;
    }
    return 0 as *mut sshauthopt;
}
pub unsafe extern "C" fn sshauthopt_from_cert(mut k: *mut sshkey) -> *mut sshauthopt {
    let mut ret: *mut sshauthopt = 0 as *mut sshauthopt;
    if k.is_null()
        || sshkey_type_is_cert((*k).type_0) == 0
        || ((*k).cert).is_null()
        || (*(*k).cert).type_0 != 1 as libc::c_int as libc::c_uint
    {
        return 0 as *mut sshauthopt;
    }
    ret = sshauthopt_new();
    if ret.is_null() {
        return 0 as *mut sshauthopt;
    }
    if cert_option_list(
        ret,
        (*(*k).cert).critical,
        1 as libc::c_int as u_int,
        1 as libc::c_int,
    ) == -(1 as libc::c_int)
    {
        sshauthopt_free(ret);
        return 0 as *mut sshauthopt;
    }
    if cert_option_list(
        ret,
        (*(*k).cert).extensions,
        2 as libc::c_int as u_int,
        0 as libc::c_int,
    ) == -(1 as libc::c_int)
    {
        sshauthopt_free(ret);
        return 0 as *mut sshauthopt;
    }
    return ret;
}
pub unsafe extern "C" fn sshauthopt_merge(
    mut primary: *const sshauthopt,
    mut additional: *const sshauthopt,
    mut errstrp: *mut *const libc::c_char,
) -> *mut sshauthopt {
    let mut current_block: u64;
    let mut ret: *mut sshauthopt = 0 as *mut sshauthopt;
    let mut errstr: *const libc::c_char = b"internal error\0" as *const u8 as *const libc::c_char;
    let mut tmp: *const libc::c_char = 0 as *const libc::c_char;
    if !errstrp.is_null() {
        *errstrp = 0 as *const libc::c_char;
    }
    ret = sshauthopt_new();
    if ret.is_null() {
        current_block = 3334247120203540815;
    } else {
        tmp = (*primary).required_from_host_cert;
        if tmp.is_null() {
            tmp = (*additional).required_from_host_cert;
        }
        if !tmp.is_null() && {
            (*ret).required_from_host_cert = strdup(tmp);
            ((*ret).required_from_host_cert).is_null()
        } {
            current_block = 3334247120203540815;
        } else {
            tmp = (*primary).required_from_host_keys;
            if tmp.is_null() {
                tmp = (*additional).required_from_host_keys;
            }
            if !tmp.is_null() && {
                (*ret).required_from_host_keys = strdup(tmp);
                ((*ret).required_from_host_keys).is_null()
            } {
                current_block = 3334247120203540815;
            } else {
                (*ret).force_tun_device = (*primary).force_tun_device;
                if (*ret).force_tun_device == -(1 as libc::c_int) {
                    (*ret).force_tun_device = (*additional).force_tun_device;
                }
                if (*primary).nenv > 0 as libc::c_int as libc::c_ulong {
                    if dup_strings(
                        &mut (*ret).env,
                        &mut (*ret).nenv,
                        (*primary).env,
                        (*primary).nenv,
                    ) != 0 as libc::c_int
                    {
                        current_block = 3334247120203540815;
                    } else {
                        current_block = 4956146061682418353;
                    }
                } else if (*additional).nenv != 0 {
                    if dup_strings(
                        &mut (*ret).env,
                        &mut (*ret).nenv,
                        (*additional).env,
                        (*additional).nenv,
                    ) != 0 as libc::c_int
                    {
                        current_block = 3334247120203540815;
                    } else {
                        current_block = 4956146061682418353;
                    }
                } else {
                    current_block = 4956146061682418353;
                }
                match current_block {
                    3334247120203540815 => {}
                    _ => {
                        if (*primary).npermitopen > 0 as libc::c_int as libc::c_ulong {
                            if dup_strings(
                                &mut (*ret).permitopen,
                                &mut (*ret).npermitopen,
                                (*primary).permitopen,
                                (*primary).npermitopen,
                            ) != 0 as libc::c_int
                            {
                                current_block = 3334247120203540815;
                            } else {
                                current_block = 11042950489265723346;
                            }
                        } else if (*additional).npermitopen > 0 as libc::c_int as libc::c_ulong {
                            if dup_strings(
                                &mut (*ret).permitopen,
                                &mut (*ret).npermitopen,
                                (*additional).permitopen,
                                (*additional).npermitopen,
                            ) != 0 as libc::c_int
                            {
                                current_block = 3334247120203540815;
                            } else {
                                current_block = 11042950489265723346;
                            }
                        } else {
                            current_block = 11042950489265723346;
                        }
                        match current_block {
                            3334247120203540815 => {}
                            _ => {
                                if (*primary).npermitlisten > 0 as libc::c_int as libc::c_ulong {
                                    if dup_strings(
                                        &mut (*ret).permitlisten,
                                        &mut (*ret).npermitlisten,
                                        (*primary).permitlisten,
                                        (*primary).npermitlisten,
                                    ) != 0 as libc::c_int
                                    {
                                        current_block = 3334247120203540815;
                                    } else {
                                        current_block = 14818589718467733107;
                                    }
                                } else if (*additional).npermitlisten
                                    > 0 as libc::c_int as libc::c_ulong
                                {
                                    if dup_strings(
                                        &mut (*ret).permitlisten,
                                        &mut (*ret).npermitlisten,
                                        (*additional).permitlisten,
                                        (*additional).npermitlisten,
                                    ) != 0 as libc::c_int
                                    {
                                        current_block = 3334247120203540815;
                                    } else {
                                        current_block = 14818589718467733107;
                                    }
                                } else {
                                    current_block = 14818589718467733107;
                                }
                                match current_block {
                                    3334247120203540815 => {}
                                    _ => {
                                        (*ret).permit_port_forwarding_flag = ((*primary)
                                            .permit_port_forwarding_flag
                                            == 1 as libc::c_int
                                            && (*additional).permit_port_forwarding_flag
                                                == 1 as libc::c_int)
                                            as libc::c_int;
                                        (*ret).permit_agent_forwarding_flag = ((*primary)
                                            .permit_agent_forwarding_flag
                                            == 1 as libc::c_int
                                            && (*additional).permit_agent_forwarding_flag
                                                == 1 as libc::c_int)
                                            as libc::c_int;
                                        (*ret).permit_x11_forwarding_flag = ((*primary)
                                            .permit_x11_forwarding_flag
                                            == 1 as libc::c_int
                                            && (*additional).permit_x11_forwarding_flag
                                                == 1 as libc::c_int)
                                            as libc::c_int;
                                        (*ret).permit_pty_flag = ((*primary).permit_pty_flag
                                            == 1 as libc::c_int
                                            && (*additional).permit_pty_flag == 1 as libc::c_int)
                                            as libc::c_int;
                                        (*ret).permit_user_rc = ((*primary).permit_user_rc
                                            == 1 as libc::c_int
                                            && (*additional).permit_user_rc == 1 as libc::c_int)
                                            as libc::c_int;
                                        (*ret).no_require_user_presence = ((*primary)
                                            .no_require_user_presence
                                            == 1 as libc::c_int
                                            && (*additional).no_require_user_presence
                                                == 1 as libc::c_int)
                                            as libc::c_int;
                                        (*ret).require_verify = ((*primary).require_verify
                                            == 1 as libc::c_int
                                            || (*additional).require_verify == 1 as libc::c_int)
                                            as libc::c_int;
                                        if (*primary).valid_before
                                            != 0 as libc::c_int as libc::c_ulong
                                        {
                                            (*ret).valid_before = (*primary).valid_before;
                                        }
                                        if (*additional).valid_before
                                            != 0 as libc::c_int as libc::c_ulong
                                            && (*additional).valid_before < (*ret).valid_before
                                        {
                                            (*ret).valid_before = (*additional).valid_before;
                                        }
                                        if !((*primary).force_command).is_null()
                                            && !((*additional).force_command).is_null()
                                        {
                                            if strcmp(
                                                (*primary).force_command,
                                                (*additional).force_command,
                                            ) == 0 as libc::c_int
                                            {
                                                (*ret).force_command =
                                                    strdup((*primary).force_command);
                                                if ((*ret).force_command).is_null() {
                                                    current_block = 3334247120203540815;
                                                } else {
                                                    current_block = 6717214610478484138;
                                                }
                                            } else {
                                                errstr = b"forced command options do not match\0"
                                                    as *const u8
                                                    as *const libc::c_char;
                                                current_block = 13480256700474103225;
                                            }
                                        } else if !((*primary).force_command).is_null() {
                                            (*ret).force_command = strdup((*primary).force_command);
                                            if ((*ret).force_command).is_null() {
                                                current_block = 3334247120203540815;
                                            } else {
                                                current_block = 6717214610478484138;
                                            }
                                        } else if !((*additional).force_command).is_null() {
                                            (*ret).force_command =
                                                strdup((*additional).force_command);
                                            if ((*ret).force_command).is_null() {
                                                current_block = 3334247120203540815;
                                            } else {
                                                current_block = 6717214610478484138;
                                            }
                                        } else {
                                            current_block = 6717214610478484138;
                                        }
                                        match current_block {
                                            13480256700474103225 => {}
                                            3334247120203540815 => {}
                                            _ => {
                                                if !errstrp.is_null() {
                                                    *errstrp = 0 as *const libc::c_char;
                                                }
                                                return ret;
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
    match current_block {
        3334247120203540815 => {
            errstr = b"memory allocation failed\0" as *const u8 as *const libc::c_char;
        }
        _ => {}
    }
    if !errstrp.is_null() {
        *errstrp = errstr;
    }
    sshauthopt_free(ret);
    return 0 as *mut sshauthopt;
}
pub unsafe extern "C" fn sshauthopt_copy(mut orig: *const sshauthopt) -> *mut sshauthopt {
    let mut ret: *mut sshauthopt = 0 as *mut sshauthopt;
    ret = sshauthopt_new();
    if ret.is_null() {
        return 0 as *mut sshauthopt;
    }
    (*ret).permit_port_forwarding_flag = (*orig).permit_port_forwarding_flag;
    (*ret).permit_agent_forwarding_flag = (*orig).permit_agent_forwarding_flag;
    (*ret).permit_x11_forwarding_flag = (*orig).permit_x11_forwarding_flag;
    (*ret).permit_pty_flag = (*orig).permit_pty_flag;
    (*ret).permit_user_rc = (*orig).permit_user_rc;
    (*ret).restricted = (*orig).restricted;
    (*ret).cert_authority = (*orig).cert_authority;
    (*ret).force_tun_device = (*orig).force_tun_device;
    (*ret).valid_before = (*orig).valid_before;
    (*ret).no_require_user_presence = (*orig).no_require_user_presence;
    (*ret).require_verify = (*orig).require_verify;
    if !((*orig).cert_principals).is_null() && {
        (*ret).cert_principals = strdup((*orig).cert_principals);
        ((*ret).cert_principals).is_null()
    } {
        sshauthopt_free(ret);
        return 0 as *mut sshauthopt;
    }
    if !((*orig).force_command).is_null() && {
        (*ret).force_command = strdup((*orig).force_command);
        ((*ret).force_command).is_null()
    } {
        sshauthopt_free(ret);
        return 0 as *mut sshauthopt;
    }
    if !((*orig).required_from_host_cert).is_null() && {
        (*ret).required_from_host_cert = strdup((*orig).required_from_host_cert);
        ((*ret).required_from_host_cert).is_null()
    } {
        sshauthopt_free(ret);
        return 0 as *mut sshauthopt;
    }
    if !((*orig).required_from_host_keys).is_null() && {
        (*ret).required_from_host_keys = strdup((*orig).required_from_host_keys);
        ((*ret).required_from_host_keys).is_null()
    } {
        sshauthopt_free(ret);
        return 0 as *mut sshauthopt;
    }
    if dup_strings(&mut (*ret).env, &mut (*ret).nenv, (*orig).env, (*orig).nenv) != 0 as libc::c_int
        || dup_strings(
            &mut (*ret).permitopen,
            &mut (*ret).npermitopen,
            (*orig).permitopen,
            (*orig).npermitopen,
        ) != 0 as libc::c_int
        || dup_strings(
            &mut (*ret).permitlisten,
            &mut (*ret).npermitlisten,
            (*orig).permitlisten,
            (*orig).npermitlisten,
        ) != 0 as libc::c_int
    {
        sshauthopt_free(ret);
        return 0 as *mut sshauthopt;
    }
    return ret;
}
unsafe extern "C" fn serialise_array(
    mut m: *mut sshbuf,
    mut a: *mut *mut libc::c_char,
    mut n: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut b: *mut sshbuf = 0 as *mut sshbuf;
    let mut i: size_t = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    if n > 2147483647 as libc::c_int as libc::c_ulong {
        return -(1 as libc::c_int);
    }
    b = sshbuf_new();
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    i = 0 as libc::c_int as size_t;
    loop {
        if !(i < n) {
            current_block = 10886091980245723256;
            break;
        }
        r = sshbuf_put_cstring(b, *a.offset(i as isize));
        if r != 0 as libc::c_int {
            current_block = 16579542207699466909;
            break;
        }
        i = i.wrapping_add(1);
        i;
    }
    match current_block {
        10886091980245723256 => {
            r = sshbuf_put_u32(m, n as u_int32_t);
            if !(r != 0 as libc::c_int || {
                r = sshbuf_put_stringb(m, b);
                r != 0 as libc::c_int
            }) {
                r = 0 as libc::c_int;
            }
        }
        _ => {}
    }
    sshbuf_free(b);
    return r;
}
unsafe extern "C" fn deserialise_array(
    mut m: *mut sshbuf,
    mut ap: *mut *mut *mut libc::c_char,
    mut np: *mut size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut a: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut i: size_t = 0;
    let mut n: size_t = 0 as libc::c_int as size_t;
    let mut b: *mut sshbuf = 0 as *mut sshbuf;
    let mut tmp: u_int = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    r = sshbuf_get_u32(m, &mut tmp);
    if !(r != 0 as libc::c_int || {
        r = sshbuf_froms(m, &mut b);
        r != 0 as libc::c_int
    }) {
        if tmp > 2147483647 as libc::c_int as libc::c_uint {
            r = -(4 as libc::c_int);
        } else {
            n = tmp as size_t;
            if n > 0 as libc::c_int as libc::c_ulong && {
                a = calloc(
                    n,
                    ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                ) as *mut *mut libc::c_char;
                a.is_null()
            } {
                r = -(2 as libc::c_int);
            } else {
                i = 0 as libc::c_int as size_t;
                loop {
                    if !(i < n) {
                        current_block = 13536709405535804910;
                        break;
                    }
                    r = sshbuf_get_cstring(b, &mut *a.offset(i as isize), 0 as *mut size_t);
                    if r != 0 as libc::c_int {
                        current_block = 10872474994193263422;
                        break;
                    }
                    i = i.wrapping_add(1);
                    i;
                }
                match current_block {
                    10872474994193263422 => {}
                    _ => {
                        r = 0 as libc::c_int;
                        *ap = a;
                        a = 0 as *mut *mut libc::c_char;
                        *np = n;
                        n = 0 as libc::c_int as size_t;
                    }
                }
            }
        }
    }
    if !a.is_null() {
        i = 0 as libc::c_int as size_t;
        while i < n {
            libc::free(*a.offset(i as isize) as *mut libc::c_void);
            i = i.wrapping_add(1);
            i;
        }
        libc::free(a as *mut libc::c_void);
    }
    sshbuf_free(b);
    return r;
}
unsafe extern "C" fn serialise_nullable_string(
    mut m: *mut sshbuf,
    mut s: *const libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = sshbuf_put_u8(
        m,
        (s == 0 as *mut libc::c_void as *const libc::c_char) as libc::c_int as u_char,
    );
    if r != 0 as libc::c_int || {
        r = sshbuf_put_cstring(m, s);
        r != 0 as libc::c_int
    } {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn deserialise_nullable_string(
    mut m: *mut sshbuf,
    mut sp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut flag: u_char = 0;
    *sp = 0 as *mut libc::c_char;
    r = sshbuf_get_u8(m, &mut flag);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_cstring(
            m,
            if flag as libc::c_int != 0 {
                0 as *mut *mut libc::c_char
            } else {
                sp
            },
            0 as *mut size_t,
        );
        r != 0 as libc::c_int
    } {
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshauthopt_serialise(
    mut opts: *const sshauthopt,
    mut m: *mut sshbuf,
    mut untrusted: libc::c_int,
) -> libc::c_int {
    let mut r: libc::c_int = -(1 as libc::c_int);
    r = sshbuf_put_u8(m, (*opts).permit_port_forwarding_flag as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u8(m, (*opts).permit_agent_forwarding_flag as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u8(m, (*opts).permit_x11_forwarding_flag as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u8(m, (*opts).permit_pty_flag as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u8(m, (*opts).permit_user_rc as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u8(m, (*opts).restricted as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u8(m, (*opts).cert_authority as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u8(m, (*opts).no_require_user_presence as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u8(m, (*opts).require_verify as u_char);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    r = sshbuf_put_u64(m, (*opts).valid_before);
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshbuf_put_u8(
        m,
        ((*opts).force_tun_device == -(1 as libc::c_int)) as libc::c_int as u_char,
    );
    if r != 0 as libc::c_int || {
        r = sshbuf_put_u32(
            m,
            if (*opts).force_tun_device < 0 as libc::c_int {
                0 as libc::c_int as libc::c_uint
            } else {
                (*opts).force_tun_device as u_int
            },
        );
        r != 0 as libc::c_int
    } {
        return r;
    }
    r = serialise_nullable_string(
        m,
        if untrusted != 0 {
            b"yes\0" as *const u8 as *const libc::c_char
        } else {
            (*opts).cert_principals as *const libc::c_char
        },
    );
    if r != 0 as libc::c_int
        || {
            r = serialise_nullable_string(
                m,
                if untrusted != 0 {
                    b"true\0" as *const u8 as *const libc::c_char
                } else {
                    (*opts).force_command as *const libc::c_char
                },
            );
            r != 0 as libc::c_int
        }
        || {
            r = serialise_nullable_string(
                m,
                if untrusted != 0 {
                    0 as *mut libc::c_char
                } else {
                    (*opts).required_from_host_cert
                },
            );
            r != 0 as libc::c_int
        }
        || {
            r = serialise_nullable_string(
                m,
                if untrusted != 0 {
                    0 as *mut libc::c_char
                } else {
                    (*opts).required_from_host_keys
                },
            );
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    r = serialise_array(
        m,
        (*opts).env,
        if untrusted != 0 {
            0 as libc::c_int as libc::c_ulong
        } else {
            (*opts).nenv
        },
    );
    if r != 0 as libc::c_int
        || {
            r = serialise_array(
                m,
                (*opts).permitopen,
                if untrusted != 0 {
                    0 as libc::c_int as libc::c_ulong
                } else {
                    (*opts).npermitopen
                },
            );
            r != 0 as libc::c_int
        }
        || {
            r = serialise_array(
                m,
                (*opts).permitlisten,
                if untrusted != 0 {
                    0 as libc::c_int as libc::c_ulong
                } else {
                    (*opts).npermitlisten
                },
            );
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshauthopt_deserialise(
    mut m: *mut sshbuf,
    mut optsp: *mut *mut sshauthopt,
) -> libc::c_int {
    let mut opts: *mut sshauthopt = 0 as *mut sshauthopt;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut f: u_char = 0;
    let mut tmp: u_int = 0;
    opts = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<sshauthopt>() as libc::c_ulong,
    ) as *mut sshauthopt;
    if opts.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_get_u8(m, &mut f);
    if !(r != 0 as libc::c_int) {
        (*opts).permit_port_forwarding_flag = f as libc::c_int;
        r = sshbuf_get_u8(m, &mut f);
        if !(r != 0 as libc::c_int) {
            (*opts).permit_agent_forwarding_flag = f as libc::c_int;
            r = sshbuf_get_u8(m, &mut f);
            if !(r != 0 as libc::c_int) {
                (*opts).permit_x11_forwarding_flag = f as libc::c_int;
                r = sshbuf_get_u8(m, &mut f);
                if !(r != 0 as libc::c_int) {
                    (*opts).permit_pty_flag = f as libc::c_int;
                    r = sshbuf_get_u8(m, &mut f);
                    if !(r != 0 as libc::c_int) {
                        (*opts).permit_user_rc = f as libc::c_int;
                        r = sshbuf_get_u8(m, &mut f);
                        if !(r != 0 as libc::c_int) {
                            (*opts).restricted = f as libc::c_int;
                            r = sshbuf_get_u8(m, &mut f);
                            if !(r != 0 as libc::c_int) {
                                (*opts).cert_authority = f as libc::c_int;
                                r = sshbuf_get_u8(m, &mut f);
                                if !(r != 0 as libc::c_int) {
                                    (*opts).no_require_user_presence = f as libc::c_int;
                                    r = sshbuf_get_u8(m, &mut f);
                                    if !(r != 0 as libc::c_int) {
                                        (*opts).require_verify = f as libc::c_int;
                                        r = sshbuf_get_u64(m, &mut (*opts).valid_before);
                                        if !(r != 0 as libc::c_int) {
                                            r = sshbuf_get_u8(m, &mut f);
                                            if !(r != 0 as libc::c_int || {
                                                r = sshbuf_get_u32(m, &mut tmp);
                                                r != 0 as libc::c_int
                                            }) {
                                                (*opts).force_tun_device = if f as libc::c_int != 0
                                                {
                                                    -(1 as libc::c_int)
                                                } else {
                                                    tmp as libc::c_int
                                                };
                                                r = deserialise_nullable_string(
                                                    m,
                                                    &mut (*opts).cert_principals,
                                                );
                                                if !(r != 0 as libc::c_int
                                                    || {
                                                        r = deserialise_nullable_string(
                                                            m,
                                                            &mut (*opts).force_command,
                                                        );
                                                        r != 0 as libc::c_int
                                                    }
                                                    || {
                                                        r = deserialise_nullable_string(
                                                            m,
                                                            &mut (*opts).required_from_host_cert,
                                                        );
                                                        r != 0 as libc::c_int
                                                    }
                                                    || {
                                                        r = deserialise_nullable_string(
                                                            m,
                                                            &mut (*opts).required_from_host_keys,
                                                        );
                                                        r != 0 as libc::c_int
                                                    })
                                                {
                                                    r = deserialise_array(
                                                        m,
                                                        &mut (*opts).env,
                                                        &mut (*opts).nenv,
                                                    );
                                                    if !(r != 0 as libc::c_int
                                                        || {
                                                            r = deserialise_array(
                                                                m,
                                                                &mut (*opts).permitopen,
                                                                &mut (*opts).npermitopen,
                                                            );
                                                            r != 0 as libc::c_int
                                                        }
                                                        || {
                                                            r = deserialise_array(
                                                                m,
                                                                &mut (*opts).permitlisten,
                                                                &mut (*opts).npermitlisten,
                                                            );
                                                            r != 0 as libc::c_int
                                                        })
                                                    {
                                                        r = 0 as libc::c_int;
                                                        *optsp = opts;
                                                        opts = 0 as *mut sshauthopt;
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
    sshauthopt_free(opts);
    return r;
}
