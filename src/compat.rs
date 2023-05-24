use ::libc;
extern "C" {
    pub type ssh_channels;
    pub type sshkey;
    pub type kex;
    pub type session_state;
    fn free(_: *mut libc::c_void);
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;

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
    fn match_pattern_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn match_filter_denylist(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
}
pub type __uint32_t = libc::c_uint;
pub type u_int32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh {
    pub state: *mut session_state,
    pub kex: *mut kex,
    pub remote_ipaddr: *mut libc::c_char,
    pub remote_port: libc::c_int,
    pub local_ipaddr: *mut libc::c_char,
    pub local_port: libc::c_int,
    pub rdomain_in: *mut libc::c_char,
    pub log_preamble: *mut libc::c_char,
    pub dispatch: [Option<dispatch_fn>; 255],
    pub dispatch_skip_packets: libc::c_int,
    pub compat: libc::c_int,
    pub private_keys: C2RustUnnamed_1,
    pub public_keys: C2RustUnnamed,
    pub authctxt: *mut libc::c_void,
    pub chanctxt: *mut ssh_channels,
    pub app_data: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct key_entry {
    pub next: C2RustUnnamed_0,
    pub key: *mut sshkey,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub tqe_next: *mut key_entry,
    pub tqe_prev: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
pub type dispatch_fn = unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int;
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
pub struct C2RustUnnamed_2 {
    pub pat: *mut libc::c_char,
    pub bugs: libc::c_int,
}
pub unsafe extern "C" fn compat_banner(mut ssh: *mut ssh, mut version: *const libc::c_char) {
    let mut i: libc::c_int = 0;
    static mut check: [C2RustUnnamed_2; 25] = [
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"OpenSSH_2.*,OpenSSH_3.0*,OpenSSH_3.1*\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                bugs: 0x200000 as libc::c_int | 0x1000000 as libc::c_int | 0x2 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"OpenSSH_3.*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x1000000 as libc::c_int | 0x2 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"Sun_SSH_1.0*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x8000 as libc::c_int | 0x200000 as libc::c_int | 0x2 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"OpenSSH_2*,OpenSSH_3*,OpenSSH_4*\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                bugs: 0x2 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"OpenSSH_5*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x4000000 as libc::c_int | 0x8000000 as libc::c_int | 0x2 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"OpenSSH_6.6.1*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x4000000 as libc::c_int | 0x2 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"OpenSSH_6.5*,OpenSSH_6.6*\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                bugs: 0x4000000 as libc::c_int | 0x10000000 as libc::c_int | 0x2 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"OpenSSH_7.4*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x4000000 as libc::c_int | 0x2 as libc::c_int | 0x4 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"OpenSSH_7.0*,OpenSSH_7.1*,OpenSSH_7.2*,OpenSSH_7.3*,OpenSSH_7.5*,OpenSSH_7.6*,OpenSSH_7.7*\0"
                    as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x4000000 as libc::c_int | 0x2 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"OpenSSH*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x4000000 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"*MindTerm*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"3.0.*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x40 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"3.0 SecureCRT*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"1.7 SecureFX*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x10 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"Cisco-1.*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x40000000 as libc::c_int | 0x20000000 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"*SSH_Version_Mapper*\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                bugs: 0x800 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"PuTTY_Local:*,PuTTY-Release-0.5*,PuTTY_Release_0.5*,PuTTY_Release_0.60*,PuTTY_Release_0.61*,PuTTY_Release_0.62*,PuTTY_Release_0.63*,PuTTY_Release_0.64*\0"
                    as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x4000 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"FuTTY*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x4000 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"Probe-*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x400000 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"TeraTerm SSH*,TTSSH/1.5.*,TTSSH/2.1*,TTSSH/2.2*,TTSSH/2.3*,TTSSH/2.4*,TTSSH/2.5*,TTSSH/2.6*,TTSSH/2.70*,TTSSH/2.71*,TTSSH/2.72*\0"
                    as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x20000000 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"WinSCP_release_4*,WinSCP_release_5.0*,WinSCP_release_5.1,WinSCP_release_5.1.*,WinSCP_release_5.5,WinSCP_release_5.5.*,WinSCP_release_5.6,WinSCP_release_5.6.*,WinSCP_release_5.7,WinSCP_release_5.7.1,WinSCP_release_5.7.2,WinSCP_release_5.7.3,WinSCP_release_5.7.4\0"
                    as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x4000 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"ConfD-*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x1 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"Twisted_*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: b"Twisted*\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                bugs: 0x40 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                pat: 0 as *const libc::c_char as *mut libc::c_char,
                bugs: 0 as libc::c_int,
            };
            init
        },
    ];
    (*ssh).compat = 0 as libc::c_int;
    i = 0 as libc::c_int;
    while !(check[i as usize].pat).is_null() {
        if match_pattern_list(version, check[i as usize].pat, 0 as libc::c_int) == 1 as libc::c_int
        {
            crate::log::sshlog(
                b"compat.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"compat_banner\0"))
                    .as_ptr(),
                132 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"match: %s pat %s compat 0x%08x\0" as *const u8 as *const libc::c_char,
                version,
                check[i as usize].pat,
                check[i as usize].bugs,
            );
            (*ssh).compat = check[i as usize].bugs;
            return;
        }
        i += 1;
        i;
    }
    crate::log::sshlog(
        b"compat.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"compat_banner\0")).as_ptr(),
        137 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"no match: %s\0" as *const u8 as *const libc::c_char,
        version,
    );
}
pub unsafe extern "C" fn compat_kex_proposal(
    mut ssh: *mut ssh,
    mut p: *const libc::c_char,
) -> *mut libc::c_char {
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp2: *mut libc::c_char = 0 as *mut libc::c_char;
    if (*ssh).compat & (0x10000000 as libc::c_int | 0x4000 as libc::c_int) == 0 as libc::c_int {
        return xstrdup(p);
    }
    crate::log::sshlog(
        b"compat.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"compat_kex_proposal\0"))
            .as_ptr(),
        148 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"original KEX proposal: %s\0" as *const u8 as *const libc::c_char,
        p,
    );
    if (*ssh).compat & 0x10000000 as libc::c_int != 0 as libc::c_int {
        cp = match_filter_denylist(
            p,
            b"curve25519-sha256@libssh.org\0" as *const u8 as *const libc::c_char,
        );
        if cp.is_null() {
            sshfatal(
                b"compat.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"compat_kex_proposal\0",
                ))
                .as_ptr(),
                152 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"match_filter_denylist failed\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if (*ssh).compat & 0x4000 as libc::c_int != 0 as libc::c_int {
        cp2 = match_filter_denylist(
            if !cp.is_null() {
                cp as *const libc::c_char
            } else {
                p
            },
            b"diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1\0"
                as *const u8 as *const libc::c_char,
        );
        if cp2.is_null() {
            sshfatal(
                b"compat.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"compat_kex_proposal\0",
                ))
                .as_ptr(),
                157 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"match_filter_denylist failed\0" as *const u8 as *const libc::c_char,
            );
        }
        free(cp as *mut libc::c_void);
        cp = cp2;
    }
    if cp.is_null() || *cp as libc::c_int == '\0' as i32 {
        sshfatal(
            b"compat.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"compat_kex_proposal\0"))
                .as_ptr(),
            162 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"No supported key exchange algorithms found\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"compat.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"compat_kex_proposal\0"))
            .as_ptr(),
        163 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"compat KEX proposal: %s\0" as *const u8 as *const libc::c_char,
        cp,
    );
    return cp;
}
