use crate::servconf::ServerOptions;
use libc::sockaddr_storage;

use ::libc;

use libc::pid_t;
use libc::sockaddr;
extern "C" {

    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;

    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn ctime(__timer: *const time_t) -> *mut libc::c_char;
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn login_alloc_entry(
        pid: pid_t,
        username: *const libc::c_char,
        hostname: *const libc::c_char,
        line: *const libc::c_char,
    ) -> *mut logininfo;
    fn login_free_entry(li: *mut logininfo);
    fn login_login(li: *mut logininfo) -> libc::c_int;
    fn login_logout(li: *mut logininfo) -> libc::c_int;
    fn login_set_addr(li: *mut logininfo, sa: *const sockaddr, sa_size: libc::c_uint);
    fn login_get_lastlog(li: *mut logininfo, uid: uid_t) -> *mut logininfo;
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
    static mut options: ServerOptions;
}
pub type __u_int = libc::c_uint;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __mode_t = libc::c_uint;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type uid_t = __uid_t;

pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int64_t = __uint64_t;
pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;

pub type uint32_t = __uint32_t;
pub type uint16_t = __uint16_t;
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_addr_t = uint32_t;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct logininfo {
    pub progname: [libc::c_char; 64],
    pub progname_null: libc::c_int,
    pub type_0: libc::c_short,
    pub pid: pid_t,
    pub uid: uid_t,
    pub line: [libc::c_char; 64],
    pub username: [libc::c_char; 512],
    pub hostname: [libc::c_char; 256],
    pub exit: libc::c_int,
    pub termination: libc::c_int,
    pub tv_sec: libc::c_uint,
    pub tv_usec: libc::c_uint,
    pub hostaddr: login_netinfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union login_netinfo {
    pub sa: sockaddr,
    pub sa_in: sockaddr_in,
    pub sa_storage: sockaddr_storage,
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

pub unsafe extern "C" fn get_last_login_time(
    mut uid: uid_t,
    mut _logname: *const libc::c_char,
    mut buf: *mut libc::c_char,
    mut bufsize: size_t,
) -> time_t {
    let mut li: logininfo = logininfo {
        progname: [0; 64],
        progname_null: 0,
        type_0: 0,
        pid: 0,
        uid: 0,
        line: [0; 64],
        username: [0; 512],
        hostname: [0; 256],
        exit: 0,
        termination: 0,
        tv_sec: 0,
        tv_usec: 0,
        hostaddr: login_netinfo {
            sa: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    login_get_lastlog(&mut li, uid);
    strlcpy(buf, (li.hostname).as_mut_ptr(), bufsize);
    return li.tv_sec as time_t;
}
unsafe extern "C" fn store_lastlog_message(mut user: *const libc::c_char, mut uid: uid_t) {
    let mut hostname: [libc::c_char; 65] = *::core::mem::transmute::<
        &[u8; 65],
        &mut [libc::c_char; 65],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut last_login_time: time_t = 0;
    let mut time_string: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    if options.print_lastlog == 0 {
        return;
    }
    last_login_time = get_last_login_time(
        uid,
        user,
        hostname.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 65]>() as libc::c_ulong,
    );
    if last_login_time != 0 as libc::c_int as libc::c_long {
        time_string = ctime(&mut last_login_time);
        *time_string
            .offset(strcspn(time_string, b"\n\0" as *const u8 as *const libc::c_char) as isize) =
            '\0' as i32 as libc::c_char;
        if libc::strcmp(
            hostname.as_mut_ptr(),
            b"\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            r = crate::sshbuf_getput_basic::sshbuf_putf(
                loginmsg,
                b"Last login: %s\r\n\0" as *const u8 as *const libc::c_char,
                time_string,
            );
        } else {
            r = crate::sshbuf_getput_basic::sshbuf_putf(
                loginmsg,
                b"Last login: %s from %s\r\n\0" as *const u8 as *const libc::c_char,
                time_string,
                hostname.as_mut_ptr(),
            );
        }
        if r != 0 as libc::c_int {
            sshfatal(
                b"sshlogin.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"store_lastlog_message\0",
                ))
                .as_ptr(),
                126 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"crate::sshbuf_getput_basic::sshbuf_putf\0" as *const u8 as *const libc::c_char,
            );
        }
    }
}
pub unsafe extern "C" fn record_login(
    mut pid: pid_t,
    mut tty: *const libc::c_char,
    mut user: *const libc::c_char,
    mut uid: uid_t,
    mut host: *const libc::c_char,
    mut addr: *mut sockaddr,
    mut addrlen: socklen_t,
) {
    let mut li: *mut logininfo = 0 as *mut logininfo;
    store_lastlog_message(user, uid);
    li = login_alloc_entry(pid, user, host, tty);
    login_set_addr(li, addr, addrlen);
    login_login(li);
    login_free_entry(li);
}
pub unsafe extern "C" fn record_logout(
    mut pid: pid_t,
    mut tty: *const libc::c_char,
    mut user: *const libc::c_char,
) {
    let mut li: *mut logininfo = 0 as *mut logininfo;
    li = login_alloc_entry(pid, user, 0 as *const libc::c_char, tty);
    login_logout(li);
    login_free_entry(li);
}
