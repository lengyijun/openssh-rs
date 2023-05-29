use ::libc;
extern "C" {

    fn getspnam(__name: *const libc::c_char) -> *mut spwd;
    fn time(__timer: *mut time_t) -> time_t;

    fn ssh_err(n: libc::c_int) -> *const libc::c_char;

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
    static mut loginmsg: *mut crate::sshbuf::sshbuf;
}
pub type __u_int = libc::c_uint;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __time_t = libc::c_long;
pub type __sig_atomic_t = libc::c_int;
pub type u_int = __u_int;
pub type time_t = __time_t;

pub type sig_atomic_t = __sig_atomic_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct spwd {
    pub sp_namp: *mut libc::c_char,
    pub sp_pwdp: *mut libc::c_char,
    pub sp_lstchg: libc::c_long,
    pub sp_min: libc::c_long,
    pub sp_max: libc::c_long,
    pub sp_warn: libc::c_long,
    pub sp_inact: libc::c_long,
    pub sp_expire: libc::c_long,
    pub sp_flag: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Authctxt {
    pub success: sig_atomic_t,
    pub authenticated: libc::c_int,
    pub postponed: libc::c_int,
    pub valid: libc::c_int,
    pub attempt: libc::c_int,
    pub failures: libc::c_int,
    pub server_caused_failure: libc::c_int,
    pub force_pwchange: libc::c_int,
    pub user: *mut libc::c_char,
    pub service: *mut libc::c_char,
    pub pw: *mut libc::passwd,
    pub style: *mut libc::c_char,
    pub auth_methods: *mut *mut libc::c_char,
    pub num_auth_methods: u_int,
    pub methoddata: *mut libc::c_void,
    pub kbdintctxt: *mut libc::c_void,
    pub loginmsg: *mut crate::sshbuf::sshbuf,
    pub prev_keys: *mut *mut crate::sshkey::sshkey,
    pub nprev_keys: u_int,
    pub auth_method_key: *mut crate::sshkey::sshkey,
    pub auth_method_info: *mut libc::c_char,
    pub session_info: *mut crate::sshbuf::sshbuf,
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
pub unsafe extern "C" fn auth_shadow_acctexpired(mut spw: *mut spwd) -> libc::c_int {
    let mut today: time_t = 0;
    let mut daysleft: libc::c_longlong = 0;
    let mut r: libc::c_int = 0;
    today = time(0 as *mut time_t)
        / (24 as libc::c_long
            * 60 as libc::c_int as libc::c_long
            * 60 as libc::c_int as libc::c_long);
    daysleft = ((*spw).sp_expire - today) as libc::c_longlong;
    crate::log::sshlog(
        b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"auth_shadow_acctexpired\0"))
            .as_ptr(),
        65 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s: today %lld sp_expire %lld days left %lld\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"auth_shadow_acctexpired\0"))
            .as_ptr(),
        today as libc::c_longlong,
        (*spw).sp_expire as libc::c_longlong,
        daysleft,
    );
    if (*spw).sp_expire == -(1 as libc::c_int) as libc::c_long {
        crate::log::sshlog(
            b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"auth_shadow_acctexpired\0",
            ))
            .as_ptr(),
            68 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"account expiration disabled\0" as *const u8 as *const libc::c_char,
        );
    } else if daysleft < 0 as libc::c_int as libc::c_longlong {
        crate::log::sshlog(
            b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"auth_shadow_acctexpired\0",
            ))
            .as_ptr(),
            70 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Account %.100s has expired\0" as *const u8 as *const libc::c_char,
            (*spw).sp_namp,
        );
        return 1 as libc::c_int;
    } else if daysleft <= (*spw).sp_warn as libc::c_longlong {
        crate::log::sshlog(
            b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"auth_shadow_acctexpired\0",
            ))
            .as_ptr(),
            73 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"account will expire in %lld days\0" as *const u8 as *const libc::c_char,
            daysleft,
        );
        r = crate::sshbuf_getput_basic::sshbuf_putf(
            loginmsg,
            b"Your account will expire in %lld day%s.\n\0" as *const u8 as *const libc::c_char,
            daysleft,
            if daysleft == 1 as libc::c_int as libc::c_longlong {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b"s\0" as *const u8 as *const libc::c_char
            },
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"auth_shadow_acctexpired\0",
                ))
                .as_ptr(),
                77 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s: buffer error: %s\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"auth_shadow_acctexpired\0",
                ))
                .as_ptr(),
                ssh_err(r),
            );
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn auth_shadow_pwexpired(mut ctxt: *mut Authctxt) -> libc::c_int {
    let mut spw: *mut spwd = 0 as *mut spwd;
    let mut user: *const libc::c_char = (*(*ctxt).pw).pw_name;
    let mut today: time_t = 0;
    let mut r: libc::c_int = 0;
    let mut daysleft: libc::c_int = 0;
    let mut disabled: libc::c_int = 0 as libc::c_int;
    spw = getspnam(user as *mut libc::c_char);
    if spw.is_null() {
        crate::log::sshlog(
            b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth_shadow_pwexpired\0"))
                .as_ptr(),
            96 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Could not get shadow information for %.100s\0" as *const u8 as *const libc::c_char,
            user,
        );
        return 0 as libc::c_int;
    }
    today = time(0 as *mut time_t)
        / (24 as libc::c_long
            * 60 as libc::c_int as libc::c_long
            * 60 as libc::c_int as libc::c_long);
    crate::log::sshlog(
        b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth_shadow_pwexpired\0"))
            .as_ptr(),
        102 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"today %lld sp_lstchg %lld sp_max %lld\0" as *const u8 as *const libc::c_char,
        today as libc::c_longlong,
        (*spw).sp_lstchg as libc::c_longlong,
        (*spw).sp_max as libc::c_longlong,
    );
    daysleft = ((*spw).sp_lstchg + (*spw).sp_max - today) as libc::c_int;
    if disabled != 0 {
        crate::log::sshlog(
            b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth_shadow_pwexpired\0"))
                .as_ptr(),
            122 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"password expiration disabled\0" as *const u8 as *const libc::c_char,
        );
    } else if (*spw).sp_lstchg == 0 as libc::c_int as libc::c_long {
        crate::log::sshlog(
            b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth_shadow_pwexpired\0"))
                .as_ptr(),
            124 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"User %.100s password has expired (root forced)\0" as *const u8 as *const libc::c_char,
            user,
        );
        return 1 as libc::c_int;
    } else if (*spw).sp_max == -(1 as libc::c_int) as libc::c_long {
        crate::log::sshlog(
            b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth_shadow_pwexpired\0"))
                .as_ptr(),
            127 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"password expiration disabled\0" as *const u8 as *const libc::c_char,
        );
    } else if daysleft < 0 as libc::c_int {
        crate::log::sshlog(
            b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth_shadow_pwexpired\0"))
                .as_ptr(),
            129 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"User %.100s password has expired (password aged)\0" as *const u8
                as *const libc::c_char,
            user,
        );
        return 1 as libc::c_int;
    } else if daysleft as libc::c_long <= (*spw).sp_warn {
        crate::log::sshlog(
            b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth_shadow_pwexpired\0"))
                .as_ptr(),
            132 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"password will expire in %d days\0" as *const u8 as *const libc::c_char,
            daysleft,
        );
        r = crate::sshbuf_getput_basic::sshbuf_putf(
            loginmsg,
            b"Your password will expire in %d day%s.\n\0" as *const u8 as *const libc::c_char,
            daysleft,
            if daysleft == 1 as libc::c_int {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b"s\0" as *const u8 as *const libc::c_char
            },
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"auth-shadow.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"auth_shadow_pwexpired\0",
                ))
                .as_ptr(),
                136 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s: buffer error: %s\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"auth_shadow_pwexpired\0",
                ))
                .as_ptr(),
                ssh_err(r),
            );
        }
    }
    return 0 as libc::c_int;
}
