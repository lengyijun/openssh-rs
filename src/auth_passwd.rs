use crate::auth::Authctxt;
use crate::packet::key_entry;
use crate::servconf::ServerOptions;

use crate::packet::ssh;
use ::libc;
extern "C" {

    fn xcrypt(password: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
    fn shadow_pw(pw: *mut libc::passwd) -> *mut libc::c_char;

    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn auth_restrict_session(_: *mut ssh);
    fn auth_shadow_pwexpired(_: *mut Authctxt) -> libc::c_int;
    static mut options: ServerOptions;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __mode_t = libc::c_uint;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;

pub type uint8_t = __uint8_t;

pub type sig_atomic_t = __sig_atomic_t;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
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

pub unsafe extern "C" fn auth_password(
    mut ssh: *mut ssh,
    mut password: *const libc::c_char,
) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut pw: *mut libc::passwd = (*authctxt).pw;
    let mut result: libc::c_int = 0;
    let mut ok: libc::c_int = (*authctxt).valid;
    static mut expire_checked: libc::c_int = 0 as libc::c_int;
    if strlen(password) > 1024 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    if (*pw).pw_uid == 0 as libc::c_int as libc::c_uint
        && options.permit_root_login != 3 as libc::c_int
    {
        ok = 0 as libc::c_int;
    }
    if *password as libc::c_int == '\0' as i32 && options.permit_empty_passwd == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if expire_checked == 0 {
        expire_checked = 1 as libc::c_int;
        if auth_shadow_pwexpired(authctxt) != 0 {
            (*authctxt).force_pwchange = 1 as libc::c_int;
        }
    }
    result = sys_auth_passwd(ssh, password);
    if (*authctxt).force_pwchange != 0 {
        auth_restrict_session(ssh);
    }
    return (result != 0 && ok != 0) as libc::c_int;
}
pub unsafe extern "C" fn sys_auth_passwd(
    mut ssh: *mut ssh,
    mut password: *const libc::c_char,
) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut pw: *mut libc::passwd = (*authctxt).pw;
    let mut encrypted_password: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut salt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pw_password: *mut libc::c_char = if (*authctxt).valid != 0 {
        shadow_pw(pw)
    } else {
        (*pw).pw_passwd
    };
    if pw_password.is_null() {
        return 0 as libc::c_int;
    }
    if libc::strcmp(pw_password, b"\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        && libc::strcmp(password, b"\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        return 1 as libc::c_int;
    }
    if (*authctxt).valid != 0
        && *pw_password.offset(0 as libc::c_int as isize) as libc::c_int != 0
        && *pw_password.offset(1 as libc::c_int as isize) as libc::c_int != 0
    {
        salt = pw_password;
    }
    encrypted_password = xcrypt(password, salt);
    return (!encrypted_password.is_null()
        && libc::strcmp(encrypted_password, pw_password) == 0 as libc::c_int)
        as libc::c_int;
}
