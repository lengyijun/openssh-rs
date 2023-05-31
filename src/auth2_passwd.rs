use crate::packet::key_entry;
use crate::servconf::ServerOptions;

use crate::packet::ssh;
use ::libc;
extern "C" {

    fn freezero(_: *mut libc::c_void, _: size_t);

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
    fn auth_password(_: *mut ssh, _: *const libc::c_char) -> libc::c_int;
    static mut use_privsep: libc::c_int;
    fn mm_auth_password(_: *mut ssh, _: *mut libc::c_char) -> libc::c_int;
    static mut options: ServerOptions;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __socklen_t = libc::c_uint;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Authmethod {
    pub name: *mut libc::c_char,
    pub synonym: *mut libc::c_char,
    pub userauth: Option<unsafe extern "C" fn(*mut ssh, *const libc::c_char) -> libc::c_int>,
    pub enabled: *mut libc::c_int,
}

unsafe extern "C" fn userauth_passwd(
    mut ssh: *mut ssh,
    mut _method: *const libc::c_char,
) -> libc::c_int {
    let mut password: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut authenticated: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    let mut change: u_char = 0;
    let mut len: size_t = 0 as libc::c_int as size_t;
    r = crate::packet::sshpkt_get_u8(ssh, &mut change);
    if r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_get_cstring(ssh, &mut password, &mut len);
            r != 0 as libc::c_int
        }
        || change as libc::c_int != 0 && {
            r = crate::packet::sshpkt_get_cstring(
                ssh,
                0 as *mut *mut libc::c_char,
                0 as *mut size_t,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        freezero(password as *mut libc::c_void, len);
        sshfatal(
            b"auth2-libc::passwd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_passwd\0"))
                .as_ptr(),
            64 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse packet\0" as *const u8 as *const libc::c_char,
        );
    }
    if change != 0 {
        crate::log::sshlog(
            b"auth2-libc::passwd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_passwd\0"))
                .as_ptr(),
            68 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"password change not supported\0" as *const u8 as *const libc::c_char,
        );
    } else if (if use_privsep != 0 {
        mm_auth_password(ssh, password)
    } else {
        auth_password(ssh, password)
    }) == 1 as libc::c_int
    {
        authenticated = 1 as libc::c_int;
    }
    freezero(password as *mut libc::c_void, len);
    return authenticated;
}
pub static mut method_passwd: Authmethod = Authmethod {
    name: 0 as *const libc::c_char as *mut libc::c_char,
    synonym: 0 as *const libc::c_char as *mut libc::c_char,
    userauth: None,
    enabled: 0 as *const libc::c_int as *mut libc::c_int,
};
unsafe extern "C" fn run_static_initializers() {
    method_passwd = {
        let mut init = Authmethod {
            name: b"password\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            synonym: 0 as *mut libc::c_char,
            userauth: Some(
                userauth_passwd
                    as unsafe extern "C" fn(*mut ssh, *const libc::c_char) -> libc::c_int,
            ),
            enabled: &mut options.password_authentication,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
