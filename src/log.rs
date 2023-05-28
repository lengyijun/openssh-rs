use crate::openbsd_compat::vis::strnvis;
use ::libc;
use libc::close;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;

    static mut stderr: *mut libc::FILE;

    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;

    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn closelog();
    fn openlog(__ident: *const libc::c_char, __option: libc::c_int, __facility: libc::c_int);
    fn syslog(__pri: libc::c_int, __fmt: *const libc::c_char, _: ...);
    fn cleanup_exit(_: libc::c_int) -> !;
    fn match_pattern_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    static mut __progname: *mut libc::c_char;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type __u_int = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __ssize_t = libc::c_long;
pub type u_int = __u_int;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;

pub type _IO_lock_t = ();

pub type va_list = __builtin_va_list;
pub type SyslogFacility = libc::c_int;
pub const SYSLOG_FACILITY_NOT_SET: SyslogFacility = -1;
pub const SYSLOG_FACILITY_LOCAL7: SyslogFacility = 11;
pub const SYSLOG_FACILITY_LOCAL6: SyslogFacility = 10;
pub const SYSLOG_FACILITY_LOCAL5: SyslogFacility = 9;
pub const SYSLOG_FACILITY_LOCAL4: SyslogFacility = 8;
pub const SYSLOG_FACILITY_LOCAL3: SyslogFacility = 7;
pub const SYSLOG_FACILITY_LOCAL2: SyslogFacility = 6;
pub const SYSLOG_FACILITY_LOCAL1: SyslogFacility = 5;
pub const SYSLOG_FACILITY_LOCAL0: SyslogFacility = 4;
pub const SYSLOG_FACILITY_AUTHPRIV: SyslogFacility = 3;
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
pub type log_handler_fn =
    unsafe extern "C" fn(LogLevel, libc::c_int, *const libc::c_char, *mut libc::c_void) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub name: *const libc::c_char,
    pub val: SyslogFacility,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub name: *const libc::c_char,
    pub val: LogLevel,
}
static mut log_level: LogLevel = SYSLOG_LEVEL_INFO;
static mut log_on_stderr: libc::c_int = 1 as libc::c_int;
static mut log_stderr_fd: libc::c_int = 2 as libc::c_int;
static mut log_facility: libc::c_int = (4 as libc::c_int) << 3 as libc::c_int;
static mut argv0: *const libc::c_char = 0 as *const libc::c_char;
static mut log_handler: Option<log_handler_fn> = None;
static mut log_handler_ctx: *mut libc::c_void = 0 as *const libc::c_void as *mut libc::c_void;
static mut log_verbose: *mut *mut libc::c_char =
    0 as *const *mut libc::c_char as *mut *mut libc::c_char;
static mut nlog_verbose: size_t = 0;
static mut log_facilities: [C2RustUnnamed; 13] = [
    {
        let mut init = C2RustUnnamed {
            name: b"DAEMON\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_FACILITY_DAEMON,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            name: b"USER\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_FACILITY_USER,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            name: b"AUTH\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_FACILITY_AUTH,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            name: b"AUTHPRIV\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_FACILITY_AUTHPRIV,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            name: b"LOCAL0\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_FACILITY_LOCAL0,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            name: b"LOCAL1\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_FACILITY_LOCAL1,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            name: b"LOCAL2\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_FACILITY_LOCAL2,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            name: b"LOCAL3\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_FACILITY_LOCAL3,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            name: b"LOCAL4\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_FACILITY_LOCAL4,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            name: b"LOCAL5\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_FACILITY_LOCAL5,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            name: b"LOCAL6\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_FACILITY_LOCAL6,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            name: b"LOCAL7\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_FACILITY_LOCAL7,
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            name: 0 as *const libc::c_char,
            val: SYSLOG_FACILITY_NOT_SET,
        };
        init
    },
];
static mut log_levels: [C2RustUnnamed_0; 10] = [
    {
        let mut init = C2RustUnnamed_0 {
            name: b"QUIET\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_LEVEL_QUIET,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"FATAL\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_LEVEL_FATAL,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"ERROR\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_LEVEL_ERROR,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"INFO\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_LEVEL_INFO,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"VERBOSE\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_LEVEL_VERBOSE,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"DEBUG\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_LEVEL_DEBUG1,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"DEBUG1\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_LEVEL_DEBUG1,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"DEBUG2\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_LEVEL_DEBUG2,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"DEBUG3\0" as *const u8 as *const libc::c_char,
            val: SYSLOG_LEVEL_DEBUG3,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: 0 as *const libc::c_char,
            val: SYSLOG_LEVEL_NOT_SET,
        };
        init
    },
];
pub unsafe extern "C" fn log_level_get() -> LogLevel {
    return log_level;
}
pub unsafe extern "C" fn log_facility_number(mut name: *mut libc::c_char) -> SyslogFacility {
    let mut i: libc::c_int = 0;
    if !name.is_null() {
        i = 0 as libc::c_int;
        while !(log_facilities[i as usize].name).is_null() {
            if strcasecmp(log_facilities[i as usize].name, name) == 0 as libc::c_int {
                return log_facilities[i as usize].val;
            }
            i += 1;
            i;
        }
    }
    return SYSLOG_FACILITY_NOT_SET;
}
pub unsafe extern "C" fn log_facility_name(mut facility: SyslogFacility) -> *const libc::c_char {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while !(log_facilities[i as usize].name).is_null() {
        if log_facilities[i as usize].val as libc::c_int == facility as libc::c_int {
            return log_facilities[i as usize].name;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const libc::c_char;
}
pub unsafe extern "C" fn log_level_number(mut name: *mut libc::c_char) -> LogLevel {
    let mut i: libc::c_int = 0;
    if !name.is_null() {
        i = 0 as libc::c_int;
        while !(log_levels[i as usize].name).is_null() {
            if strcasecmp(log_levels[i as usize].name, name) == 0 as libc::c_int {
                return log_levels[i as usize].val;
            }
            i += 1;
            i;
        }
    }
    return SYSLOG_LEVEL_NOT_SET;
}
pub unsafe extern "C" fn log_level_name(mut level: LogLevel) -> *const libc::c_char {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while !(log_levels[i as usize].name).is_null() {
        if log_levels[i as usize].val as libc::c_int == level as libc::c_int {
            return log_levels[i as usize].name;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const libc::c_char;
}
pub unsafe extern "C" fn log_verbose_add(mut s: *const libc::c_char) {
    let mut tmp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    tmp = recallocarray(
        log_verbose as *mut libc::c_void,
        nlog_verbose,
        nlog_verbose.wrapping_add(1 as libc::c_int as libc::c_ulong),
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    if !tmp.is_null() {
        log_verbose = tmp;
        let ref mut fresh0 = *log_verbose.offset(nlog_verbose as isize);
        *fresh0 = strdup(s);
        if !(*fresh0).is_null() {
            nlog_verbose = nlog_verbose.wrapping_add(1);
            nlog_verbose;
        }
    }
}
pub unsafe extern "C" fn log_verbose_reset() {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < nlog_verbose {
        libc::free(*log_verbose.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(log_verbose as *mut libc::c_void);
    log_verbose = 0 as *mut *mut libc::c_char;
    nlog_verbose = 0 as libc::c_int as size_t;
}
pub unsafe extern "C" fn log_init(
    mut av0: *const libc::c_char,
    mut level: LogLevel,
    mut facility: SyslogFacility,
    mut on_stderr: libc::c_int,
) {
    argv0 = av0;
    if log_change_level(level) != 0 as libc::c_int {
        libc::fprintf(
            stderr,
            b"Unrecognized internal syslog level code %d\n\0" as *const u8 as *const libc::c_char,
            level as libc::c_int,
        );
        libc::exit(1 as libc::c_int);
    }
    log_handler = None;
    log_handler_ctx = 0 as *mut libc::c_void;
    log_on_stderr = on_stderr;
    if on_stderr != 0 {
        return;
    }
    match facility as libc::c_int {
        0 => {
            log_facility = (3 as libc::c_int) << 3 as libc::c_int;
        }
        1 => {
            log_facility = (1 as libc::c_int) << 3 as libc::c_int;
        }
        2 => {
            log_facility = (4 as libc::c_int) << 3 as libc::c_int;
        }
        3 => {
            log_facility = (10 as libc::c_int) << 3 as libc::c_int;
        }
        4 => {
            log_facility = (16 as libc::c_int) << 3 as libc::c_int;
        }
        5 => {
            log_facility = (17 as libc::c_int) << 3 as libc::c_int;
        }
        6 => {
            log_facility = (18 as libc::c_int) << 3 as libc::c_int;
        }
        7 => {
            log_facility = (19 as libc::c_int) << 3 as libc::c_int;
        }
        8 => {
            log_facility = (20 as libc::c_int) << 3 as libc::c_int;
        }
        9 => {
            log_facility = (21 as libc::c_int) << 3 as libc::c_int;
        }
        10 => {
            log_facility = (22 as libc::c_int) << 3 as libc::c_int;
        }
        11 => {
            log_facility = (23 as libc::c_int) << 3 as libc::c_int;
        }
        _ => {
            libc::fprintf(
                stderr,
                b"Unrecognized internal syslog facility code %d\n\0" as *const u8
                    as *const libc::c_char,
                facility as libc::c_int,
            );
            libc::exit(1 as libc::c_int);
        }
    }
    openlog(
        if !argv0.is_null() {
            argv0
        } else {
            __progname as *const libc::c_char
        },
        0x1 as libc::c_int,
        log_facility,
    );
    closelog();
}
pub unsafe extern "C" fn log_change_level(mut new_log_level: LogLevel) -> libc::c_int {
    if argv0.is_null() {
        return 0 as libc::c_int;
    }
    match new_log_level as libc::c_int {
        0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 => {
            log_level = new_log_level;
            return 0 as libc::c_int;
        }
        _ => return -(1 as libc::c_int),
    };
}
pub unsafe extern "C" fn log_is_on_stderr() -> libc::c_int {
    return (log_on_stderr != 0 && log_stderr_fd == 2 as libc::c_int) as libc::c_int;
}
pub unsafe extern "C" fn log_redirect_stderr_to(mut logfile: *const libc::c_char) {
    let mut fd: libc::c_int = 0;
    if logfile.is_null() {
        if log_stderr_fd != 2 as libc::c_int {
            close(log_stderr_fd);
            log_stderr_fd = 2 as libc::c_int;
        }
        return;
    }
    fd = libc::open(
        logfile,
        0o1 as libc::c_int | 0o100 as libc::c_int | 0o2000 as libc::c_int,
        0o600 as libc::c_int,
    );
    if fd == -(1 as libc::c_int) {
        libc::fprintf(
            stderr,
            b"Couldn't open logfile %s: %s\n\0" as *const u8 as *const libc::c_char,
            logfile,
            strerror(*libc::__errno_location()),
        );
        libc::exit(1 as libc::c_int);
    }
    log_stderr_fd = fd;
}
pub unsafe extern "C" fn set_log_handler(
    mut handler: Option<log_handler_fn>,
    mut ctx: *mut libc::c_void,
) {
    log_handler = handler;
    log_handler_ctx = ctx;
}
unsafe extern "C" fn do_log(
    mut level: LogLevel,
    mut force: libc::c_int,
    mut suffix: *const libc::c_char,
    mut fmt: *const libc::c_char,
    mut args: ::core::ffi::VaList,
) {
    let mut msgbuf: [libc::c_char; 1024] = [0; 1024];
    let mut fmtbuf: [libc::c_char; 1024] = [0; 1024];
    let mut txt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pri: libc::c_int = 6 as libc::c_int;
    let mut saved_errno: libc::c_int = *libc::__errno_location();
    let mut tmp_handler: Option<log_handler_fn> = None;
    let mut progname: *const libc::c_char = if !argv0.is_null() {
        argv0
    } else {
        __progname as *const libc::c_char
    };
    if force == 0 && level as libc::c_int > log_level as libc::c_int {
        return;
    }
    match level as libc::c_int {
        1 => {
            if log_on_stderr == 0 {
                txt = b"fatal\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            }
            pri = 2 as libc::c_int;
        }
        2 => {
            if log_on_stderr == 0 {
                txt = b"error\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            }
            pri = 3 as libc::c_int;
        }
        3 => {
            pri = 6 as libc::c_int;
        }
        4 => {
            pri = 6 as libc::c_int;
        }
        5 => {
            txt = b"debug1\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            pri = 7 as libc::c_int;
        }
        6 => {
            txt = b"debug2\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            pri = 7 as libc::c_int;
        }
        7 => {
            txt = b"debug3\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            pri = 7 as libc::c_int;
        }
        _ => {
            txt = b"internal error\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            pri = 3 as libc::c_int;
        }
    }
    if !txt.is_null() && log_handler.is_none() {
        libc::snprintf(
            fmtbuf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
            b"%s: %s\0" as *const u8 as *const libc::c_char,
            txt,
            fmt,
        );
        vsnprintf(
            msgbuf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
            fmtbuf.as_mut_ptr(),
            args.as_va_list(),
        );
    } else {
        vsnprintf(
            msgbuf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
            fmt,
            args.as_va_list(),
        );
    }
    if !suffix.is_null() {
        libc::snprintf(
            fmtbuf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
            b"%s: %s\0" as *const u8 as *const libc::c_char,
            msgbuf.as_mut_ptr(),
            suffix,
        );
        strlcpy(
            msgbuf.as_mut_ptr(),
            fmtbuf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        );
    }
    strnvis(
        fmtbuf.as_mut_ptr(),
        msgbuf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        if log_on_stderr != 0 {
            0x20 as libc::c_int | 0x1 as libc::c_int
        } else {
            0x2 as libc::c_int | 0x10 as libc::c_int | 0x8 as libc::c_int | 0x1 as libc::c_int
        },
    );
    if log_handler.is_some() {
        tmp_handler = log_handler;
        log_handler = None;
        tmp_handler.expect("non-null function pointer")(
            level,
            force,
            fmtbuf.as_mut_ptr(),
            log_handler_ctx,
        );
        log_handler = tmp_handler;
    } else if log_on_stderr != 0 {
        libc::snprintf(
            msgbuf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
            b"%s%s%.*s\r\n\0" as *const u8 as *const libc::c_char,
            if log_on_stderr > 1 as libc::c_int {
                progname
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if log_on_stderr > 1 as libc::c_int {
                b": \0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong as libc::c_int
                - 3 as libc::c_int,
            fmtbuf.as_mut_ptr(),
        );
        write(
            log_stderr_fd,
            msgbuf.as_mut_ptr() as *const libc::c_void,
            strlen(msgbuf.as_mut_ptr()),
        );
    } else {
        openlog(progname, 0x1 as libc::c_int, log_facility);
        syslog(
            pri,
            b"%.500s\0" as *const u8 as *const libc::c_char,
            fmtbuf.as_mut_ptr(),
        );
        closelog();
    }
    *libc::__errno_location() = saved_errno;
}
pub unsafe extern "C" fn sshlog(
    mut file: *const libc::c_char,
    mut func: *const libc::c_char,
    mut line: libc::c_int,
    mut showfunc: libc::c_int,
    mut level: LogLevel,
    mut suffix: *const libc::c_char,
    mut fmt: *const libc::c_char,
    mut args: ...
) {
    let mut args_0: ::core::ffi::VaListImpl;
    args_0 = args.clone();
    sshlogv(
        file,
        func,
        line,
        showfunc,
        level,
        suffix,
        fmt,
        args_0.as_va_list(),
    );
}
pub unsafe extern "C" fn sshlogdie(
    mut file: *const libc::c_char,
    mut func: *const libc::c_char,
    mut line: libc::c_int,
    mut showfunc: libc::c_int,
    mut _level: LogLevel,
    mut suffix: *const libc::c_char,
    mut fmt: *const libc::c_char,
    mut args: ...
) -> ! {
    let mut args_0: ::core::ffi::VaListImpl;
    args_0 = args.clone();
    sshlogv(
        file,
        func,
        line,
        showfunc,
        SYSLOG_LEVEL_INFO,
        suffix,
        fmt,
        args_0.as_va_list(),
    );
    cleanup_exit(255 as libc::c_int);
}
pub unsafe extern "C" fn sshsigdie(
    mut file: *const libc::c_char,
    mut func: *const libc::c_char,
    mut line: libc::c_int,
    mut showfunc: libc::c_int,
    mut _level: LogLevel,
    mut suffix: *const libc::c_char,
    mut fmt: *const libc::c_char,
    mut args: ...
) -> ! {
    let mut args_0: ::core::ffi::VaListImpl;
    args_0 = args.clone();
    sshlogv(
        file,
        func,
        line,
        showfunc,
        SYSLOG_LEVEL_FATAL,
        suffix,
        fmt,
        args_0.as_va_list(),
    );
    libc::_exit(1 as libc::c_int);
}
pub unsafe extern "C" fn sshlogv(
    mut file: *const libc::c_char,
    mut func: *const libc::c_char,
    mut line: libc::c_int,
    mut showfunc: libc::c_int,
    mut level: LogLevel,
    mut suffix: *const libc::c_char,
    mut fmt: *const libc::c_char,
    mut args: ::core::ffi::VaList,
) {
    let mut tag: [libc::c_char; 128] = [0; 128];
    let mut fmt2: [libc::c_char; 1152] = [0; 1152];
    let mut forced: libc::c_int = 0 as libc::c_int;
    let mut cp: *const libc::c_char = 0 as *const libc::c_char;
    let mut i: size_t = 0;
    cp = strrchr(file, '/' as i32);
    libc::snprintf(
        tag.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 128]>() as usize,
        b"%.48s:%.48s():%d (pid=%ld)\0" as *const u8 as *const libc::c_char,
        if cp.is_null() {
            file
        } else {
            cp.offset(1 as libc::c_int as isize)
        },
        func,
        line,
        libc::getpid() as libc::c_long,
    );
    i = 0 as libc::c_int as size_t;
    while i < nlog_verbose {
        if match_pattern_list(
            tag.as_mut_ptr(),
            *log_verbose.offset(i as isize),
            0 as libc::c_int,
        ) == 1 as libc::c_int
        {
            forced = 1 as libc::c_int;
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    if forced != 0 {
        libc::snprintf(
            fmt2.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1152]>() as usize,
            b"%s: %s\0" as *const u8 as *const libc::c_char,
            tag.as_mut_ptr(),
            fmt,
        );
    } else if showfunc != 0 {
        libc::snprintf(
            fmt2.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1152]>() as usize,
            b"%s: %s\0" as *const u8 as *const libc::c_char,
            func,
            fmt,
        );
    } else {
        strlcpy(
            fmt2.as_mut_ptr(),
            fmt,
            ::core::mem::size_of::<[libc::c_char; 1152]>() as libc::c_ulong,
        );
    }
    do_log(level, forced, suffix, fmt2.as_mut_ptr(), args.as_va_list());
}
pub unsafe extern "C" fn sshlogdirect(
    mut level: LogLevel,
    mut forced: libc::c_int,
    mut fmt: *const libc::c_char,
    mut args: ...
) {
    let mut args_0: ::core::ffi::VaListImpl;
    args_0 = args.clone();
    do_log(
        level,
        forced,
        0 as *const libc::c_char,
        fmt,
        args_0.as_va_list(),
    );
}
