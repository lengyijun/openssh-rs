use crate::atomicio::atomicio;
use crate::auth::Authctxt;
use crate::packet::key_entry;
use crate::servconf::ServerOptions;

use crate::packet::ssh;
use ::libc;
use libc::close;

extern "C" {

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn setproctitle(fmt: *const libc::c_char, _: ...);
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;

    fn vasprintf(
        __ptr: *mut *mut libc::c_char,
        __f: *const libc::c_char,
        __arg: ::core::ffi::VaList,
    ) -> libc::c_int;

    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;

    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;
    fn nanosleep(
        __requested_time: *const libc::timespec,
        __remaining: *mut libc::timespec,
    ) -> libc::c_int;

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

    static mut use_privsep: libc::c_int;

    static mut options: ServerOptions;
    static mut method_none: Authmethod;
    static mut method_pubkey: Authmethod;
    static mut method_passwd: Authmethod;
    static mut method_kbdint: Authmethod;
    static mut method_hostbased: Authmethod;
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
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
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
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;

pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;

pub type uint8_t = __uint8_t;

pub type sig_atomic_t = __sig_atomic_t;

pub type va_list = __builtin_va_list;

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
pub type C2RustUnnamed_2 = libc::c_uint;
pub const DISPATCH_NONBLOCK: C2RustUnnamed_2 = 1;
pub const DISPATCH_BLOCK: C2RustUnnamed_2 = 0;
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

pub type sshkey_fp_rep = libc::c_uint;
pub const SSH_FP_RANDOMART: sshkey_fp_rep = 4;
pub const SSH_FP_BUBBLEBABBLE: sshkey_fp_rep = 3;
pub const SSH_FP_BASE64: sshkey_fp_rep = 2;
pub const SSH_FP_HEX: sshkey_fp_rep = 1;
pub const SSH_FP_DEFAULT: sshkey_fp_rep = 0;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Authmethod {
    pub name: *mut libc::c_char,
    pub synonym: *mut libc::c_char,
    pub userauth: Option<unsafe extern "C" fn(*mut ssh, *const libc::c_char) -> libc::c_int>,
    pub enabled: *mut libc::c_int,
}
pub static mut authmethods: [*mut Authmethod; 6] = unsafe {
    [
        &method_none as *const Authmethod as *mut Authmethod,
        &method_pubkey as *const Authmethod as *mut Authmethod,
        &method_passwd as *const Authmethod as *mut Authmethod,
        &method_kbdint as *const Authmethod as *mut Authmethod,
        &method_hostbased as *const Authmethod as *mut Authmethod,
        0 as *const Authmethod as *mut Authmethod,
    ]
};
pub unsafe extern "C" fn auth2_read_banner() -> *mut libc::c_char {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut banner: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;
    let mut n: size_t = 0;
    let mut fd: libc::c_int = 0;
    fd = libc::open(options.banner, 0 as libc::c_int);
    if fd == -(1 as libc::c_int) {
        return 0 as *mut libc::c_char;
    }
    if libc::fstat(fd, &mut st) == -(1 as libc::c_int) {
        close(fd);
        return 0 as *mut libc::c_char;
    }
    if st.st_size <= 0 as libc::c_int as libc::c_long
        || st.st_size
            > (1 as libc::c_int * 1024 as libc::c_int * 1024 as libc::c_int) as libc::c_long
    {
        close(fd);
        return 0 as *mut libc::c_char;
    }
    len = st.st_size as size_t;
    banner = crate::xmalloc::xmalloc(len.wrapping_add(1 as libc::c_int as libc::c_ulong))
        as *mut libc::c_char;
    n = atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        fd,
        banner as *mut libc::c_void,
        len,
    );
    close(fd);
    if n != len {
        libc::free(banner as *mut libc::c_void);
        return 0 as *mut libc::c_char;
    }
    *banner.offset(n as isize) = '\0' as i32 as libc::c_char;
    return banner;
}
unsafe extern "C" fn userauth_send_banner(mut ssh: *mut ssh, mut msg: *const libc::c_char) {
    let mut r: libc::c_int = 0;
    r = crate::packet::sshpkt_start(ssh, 53 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_put_cstring(ssh, msg as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_cstring(
                ssh,
                b"\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"userauth_send_banner\0"))
                .as_ptr(),
            146 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send packet\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"auth2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"userauth_send_banner\0"))
            .as_ptr(),
        147 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"%s: sent\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"userauth_send_banner\0"))
            .as_ptr(),
    );
}
unsafe extern "C" fn userauth_banner(mut ssh: *mut ssh) {
    let mut banner: *mut libc::c_char = 0 as *mut libc::c_char;
    if (options.banner).is_null() {
        return;
    }
    banner = if use_privsep != 0 {
        crate::monitor_wrap::mm_auth2_read_banner()
    } else {
        auth2_read_banner()
    };
    if !banner.is_null() {
        userauth_send_banner(ssh, banner);
    }
    libc::free(banner as *mut libc::c_void);
}
pub unsafe extern "C" fn do_authentication2(mut ssh: *mut ssh) {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    crate::dispatch::ssh_dispatch_init(
        ssh,
        Some(
            crate::dispatch::dispatch_protocol_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        5 as libc::c_int,
        Some(
            input_service_request
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_run_fatal(
        ssh,
        DISPATCH_BLOCK as libc::c_int,
        &mut (*authctxt).success as *mut sig_atomic_t as *mut sig_atomic_t,
    );
    (*ssh).authctxt = 0 as *mut libc::c_void;
}
unsafe extern "C" fn input_service_request(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut service: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut acceptit: libc::c_int = 0 as libc::c_int;
    r = crate::packet::sshpkt_get_cstring(ssh, &mut service, 0 as *mut size_t);
    if !(r != 0 as libc::c_int || {
        r = crate::packet::sshpkt_get_end(ssh);
        r != 0 as libc::c_int
    }) {
        if authctxt.is_null() {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"input_service_request\0",
                ))
                .as_ptr(),
                192 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"input_service_request: no authctxt\0" as *const u8 as *const libc::c_char,
            );
        }
        if libc::strcmp(
            service,
            b"ssh-userauth\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            if (*authctxt).success == 0 {
                acceptit = 1 as libc::c_int;
                crate::dispatch::ssh_dispatch_set(
                    ssh,
                    50 as libc::c_int,
                    Some(
                        input_userauth_request
                            as unsafe extern "C" fn(
                                libc::c_int,
                                u_int32_t,
                                *mut ssh,
                            ) -> libc::c_int,
                    ),
                );
            }
        }
        if acceptit != 0 {
            r = crate::packet::sshpkt_start(ssh, 6 as libc::c_int as u_char);
            if !(r != 0 as libc::c_int
                || {
                    r = crate::packet::sshpkt_put_cstring(ssh, service as *const libc::c_void);
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::packet::sshpkt_send(ssh);
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::packet::ssh_packet_write_wait(ssh);
                    r != 0 as libc::c_int
                })
            {
                r = 0 as libc::c_int;
            }
        } else {
            crate::log::sshlog(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"input_service_request\0",
                ))
                .as_ptr(),
                211 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"bad service request %s\0" as *const u8 as *const libc::c_char,
                service,
            );
            crate::packet::ssh_packet_disconnect(
                ssh,
                b"bad service request %s\0" as *const u8 as *const libc::c_char,
                service,
            );
        }
    }
    libc::free(service as *mut libc::c_void);
    return r;
}
unsafe extern "C" fn user_specific_delay(mut user: *const libc::c_char) -> libc::c_double {
    let mut b: [libc::c_char; 512] = [0; 512];
    let mut len: size_t = crate::digest_openssl::ssh_digest_bytes(4 as libc::c_int);
    let mut hash: *mut u_char = crate::xmalloc::xmalloc(len) as *mut u_char;
    let mut delay: libc::c_double = 0.;
    libc::snprintf(
        b.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 512]>() as usize,
        b"%llu%s\0" as *const u8 as *const libc::c_char,
        options.timing_secret as libc::c_ulonglong,
        user,
    );
    if crate::digest_openssl::ssh_digest_memory(
        4 as libc::c_int,
        b.as_mut_ptr() as *const libc::c_void,
        strlen(b.as_mut_ptr()),
        hash,
        len,
    ) != 0 as libc::c_int
    {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"user_specific_delay\0"))
                .as_ptr(),
            232 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::digest_openssl::ssh_digest_memory\0" as *const u8 as *const libc::c_char,
        );
    }
    delay = ((*(hash as *const u_char).offset(0 as libc::c_int as isize) as u_int32_t)
        << 24 as libc::c_int
        | (*(hash as *const u_char).offset(1 as libc::c_int as isize) as u_int32_t)
            << 16 as libc::c_int
        | (*(hash as *const u_char).offset(2 as libc::c_int as isize) as u_int32_t)
            << 8 as libc::c_int
        | *(hash as *const u_char).offset(3 as libc::c_int as isize) as u_int32_t)
        as libc::c_double
        / 1000 as libc::c_int as libc::c_double
        / 1000 as libc::c_int as libc::c_double
        / 1000 as libc::c_int as libc::c_double
        / 1000 as libc::c_int as libc::c_double;
    freezero(hash as *mut libc::c_void, len);
    crate::log::sshlog(
        b"auth2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"user_specific_delay\0"))
            .as_ptr(),
        236 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"user specific delay %0.3lfms\0" as *const u8 as *const libc::c_char,
        delay / 1000 as libc::c_int as libc::c_double,
    );
    return 0.005f64 + delay;
}
unsafe extern "C" fn ensure_minimum_time_since(
    mut start: libc::c_double,
    mut seconds: libc::c_double,
) {
    let mut ts: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut elapsed: libc::c_double = crate::misc::monotime_double() - start;
    let mut req: libc::c_double = seconds;
    let mut remain: libc::c_double = 0.;
    loop {
        remain = seconds - elapsed;
        if !(remain < 0.0f64) {
            break;
        }
        seconds *= 2 as libc::c_int as libc::c_double;
    }
    ts.tv_sec = remain as __time_t;
    ts.tv_nsec = ((remain - ts.tv_sec as libc::c_double)
        * 1000000000 as libc::c_int as libc::c_double) as __syscall_slong_t;
    crate::log::sshlog(
        b"auth2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"ensure_minimum_time_since\0"))
            .as_ptr(),
        253 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)\0" as *const u8
            as *const libc::c_char,
        elapsed * 1000 as libc::c_int as libc::c_double,
        remain * 1000 as libc::c_int as libc::c_double,
        req * 1000 as libc::c_int as libc::c_double,
    );
    nanosleep(&mut ts, 0 as *mut libc::timespec);
}
unsafe extern "C" fn input_userauth_request(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut m: *mut Authmethod = 0 as *mut Authmethod;
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut service: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut method: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut style: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut authenticated: libc::c_int = 0 as libc::c_int;
    let mut tstart: libc::c_double = crate::misc::monotime_double();
    if authctxt.is_null() {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"input_userauth_request\0",
            ))
            .as_ptr(),
            267 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"input_userauth_request: no authctxt\0" as *const u8 as *const libc::c_char,
        );
    }
    r = crate::packet::sshpkt_get_cstring(ssh, &mut user, 0 as *mut size_t);
    if !(r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_get_cstring(ssh, &mut service, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_cstring(ssh, &mut method, 0 as *mut size_t);
            r != 0 as libc::c_int
        })
    {
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"input_userauth_request\0",
            ))
            .as_ptr(),
            273 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"userauth-request for user %s service %s method %s\0" as *const u8
                as *const libc::c_char,
            user,
            service,
            method,
        );
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"input_userauth_request\0",
            ))
            .as_ptr(),
            274 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"attempt %d failures %d\0" as *const u8 as *const libc::c_char,
            (*authctxt).attempt,
            (*authctxt).failures,
        );
        style = libc::strchr(user, ':' as i32);
        if !style.is_null() {
            let fresh0 = style;
            style = style.offset(1);
            *fresh0 = 0 as libc::c_int as libc::c_char;
        }
        if (*authctxt).attempt >= 1024 as libc::c_int {
            crate::auth::auth_maxtries_exceeded(ssh);
        }
        let fresh1 = (*authctxt).attempt;
        (*authctxt).attempt = (*authctxt).attempt + 1;
        if fresh1 == 0 as libc::c_int {
            (*authctxt).pw = if use_privsep != 0 {
                crate::monitor_wrap::mm_getpwnamallow(ssh, user)
            } else {
                crate::auth::getpwnamallow(ssh, user)
            };
            (*authctxt).user = crate::xmalloc::xstrdup(user);
            if !((*authctxt).pw).is_null()
                && libc::strcmp(
                    service,
                    b"ssh-connection\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
            {
                (*authctxt).valid = 1 as libc::c_int;
                crate::log::sshlog(
                    b"auth2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"input_userauth_request\0",
                    ))
                    .as_ptr(),
                    287 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"setting up authctxt for %s\0" as *const u8 as *const libc::c_char,
                    user,
                );
            } else {
                (*authctxt).valid = 0 as libc::c_int;
                (*authctxt).pw = crate::auth::fakepw();
            }
            crate::packet::ssh_packet_set_log_preamble(
                ssh,
                b"%suser %s\0" as *const u8 as *const libc::c_char,
                if (*authctxt).valid != 0 {
                    b"authenticating \0" as *const u8 as *const libc::c_char
                } else {
                    b"invalid \0" as *const u8 as *const libc::c_char
                },
                user,
            );
            setproctitle(
                b"%s%s\0" as *const u8 as *const libc::c_char,
                if (*authctxt).valid != 0 {
                    user as *const libc::c_char
                } else {
                    b"unknown\0" as *const u8 as *const libc::c_char
                },
                if use_privsep != 0 {
                    b" [net]\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
            );
            (*authctxt).service = crate::xmalloc::xstrdup(service);
            (*authctxt).style = if !style.is_null() {
                crate::xmalloc::xstrdup(style)
            } else {
                0 as *mut libc::c_char
            };
            if use_privsep != 0 {
                crate::monitor_wrap::mm_inform_authserv(service, style);
            }
            userauth_banner(ssh);
            if auth2_setup_methods_lists(authctxt) != 0 as libc::c_int {
                crate::packet::ssh_packet_disconnect(
                    ssh,
                    b"no authentication methods enabled\0" as *const u8 as *const libc::c_char,
                );
            }
        } else if libc::strcmp(user, (*authctxt).user) != 0 as libc::c_int
            || libc::strcmp(service, (*authctxt).service) != 0 as libc::c_int
        {
            crate::packet::ssh_packet_disconnect(
                ssh,
                b"Change of username or service not allowed: (%s,%s) -> (%s,%s)\0" as *const u8
                    as *const libc::c_char,
                (*authctxt).user,
                (*authctxt).service,
                user,
                service,
            );
        }
        crate::auth2_chall::auth2_challenge_stop(ssh);
        auth2_authctxt_reset_info(authctxt);
        (*authctxt).postponed = 0 as libc::c_int;
        (*authctxt).server_caused_failure = 0 as libc::c_int;
        m = authmethod_lookup(authctxt, method);
        if !m.is_null() && (*authctxt).failures < options.max_authtries {
            crate::log::sshlog(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"input_userauth_request\0",
                ))
                .as_ptr(),
                334 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"input_userauth_request: try method %s\0" as *const u8 as *const libc::c_char,
                method,
            );
            authenticated = ((*m).userauth).expect("non-null function pointer")(ssh, method);
        }
        if (*authctxt).authenticated == 0 {
            ensure_minimum_time_since(tstart, user_specific_delay((*authctxt).user));
        }
        userauth_finish(ssh, authenticated, method, 0 as *const libc::c_char);
        r = 0 as libc::c_int;
    }
    libc::free(service as *mut libc::c_void);
    libc::free(user as *mut libc::c_void);
    libc::free(method as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn userauth_finish(
    mut ssh: *mut ssh,
    mut authenticated: libc::c_int,
    mut packet_method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut m: *mut Authmethod = 0 as *mut Authmethod;
    let mut method: *const libc::c_char = packet_method;
    let mut methods: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut partial: libc::c_int = 0 as libc::c_int;
    if authenticated != 0 {
        if (*authctxt).valid == 0 {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_finish\0"))
                    .as_ptr(),
                362 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"INTERNAL ERROR: authenticated invalid user %s\0" as *const u8
                    as *const libc::c_char,
                (*authctxt).user,
            );
        }
        if (*authctxt).postponed != 0 {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_finish\0"))
                    .as_ptr(),
                365 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"INTERNAL ERROR: authenticated and postponed\0" as *const u8
                    as *const libc::c_char,
            );
        }
        m = authmethod_byname(method);
        if m.is_null() {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_finish\0"))
                    .as_ptr(),
                368 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"INTERNAL ERROR: bad method %s\0" as *const u8 as *const libc::c_char,
                method,
            );
        }
        method = (*m).name;
    }
    if authenticated != 0
        && (*(*authctxt).pw).pw_uid == 0 as libc::c_int as libc::c_uint
        && crate::auth::auth_root_allowed(ssh, method) == 0
    {
        authenticated = 0 as libc::c_int;
    }
    if authenticated != 0 && options.num_auth_methods != 0 as libc::c_int as libc::c_uint {
        if auth2_update_methods_lists(authctxt, method, submethod) == 0 {
            authenticated = 0 as libc::c_int;
            partial = 1 as libc::c_int;
        }
    }
    crate::auth::auth_log(ssh, authenticated, partial, method, submethod);
    if authenticated != 0 || partial != 0 {
        auth2_update_session_info(authctxt, method, submethod);
    }
    if (*authctxt).postponed != 0 {
        return;
    }
    if authenticated == 1 as libc::c_int {
        crate::dispatch::ssh_dispatch_set(
            ssh,
            50 as libc::c_int,
            Some(
                crate::dispatch::dispatch_protocol_ignore
                    as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
            ),
        );
        r = crate::packet::sshpkt_start(ssh, 52 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = crate::packet::sshpkt_send(ssh);
                r != 0 as libc::c_int
            }
            || {
                r = crate::packet::ssh_packet_write_wait(ssh);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_finish\0"))
                    .as_ptr(),
                427 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"send success packet\0" as *const u8 as *const libc::c_char,
            );
        }
        (*authctxt).success = 1 as libc::c_int;
        crate::packet::ssh_packet_set_log_preamble(
            ssh,
            b"user %s\0" as *const u8 as *const libc::c_char,
            (*authctxt).user,
        );
    } else {
        if partial == 0
            && (*authctxt).server_caused_failure == 0
            && ((*authctxt).attempt > 1 as libc::c_int
                || libc::strcmp(method, b"none\0" as *const u8 as *const libc::c_char)
                    != 0 as libc::c_int)
        {
            (*authctxt).failures += 1;
            (*authctxt).failures;
        }
        if (*authctxt).failures >= options.max_authtries {
            crate::auth::auth_maxtries_exceeded(ssh);
        }
        methods = authmethods_get(authctxt);
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_finish\0"))
                .as_ptr(),
            444 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"failure partial=%d next methods=\"%s\"\0" as *const u8 as *const libc::c_char,
            partial,
            methods,
        );
        r = crate::packet::sshpkt_start(ssh, 51 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = crate::packet::sshpkt_put_cstring(ssh, methods as *const libc::c_void);
                r != 0 as libc::c_int
            }
            || {
                r = crate::packet::sshpkt_put_u8(ssh, partial as u_char);
                r != 0 as libc::c_int
            }
            || {
                r = crate::packet::sshpkt_send(ssh);
                r != 0 as libc::c_int
            }
            || {
                r = crate::packet::ssh_packet_write_wait(ssh);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_finish\0"))
                    .as_ptr(),
                450 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"send failure packet\0" as *const u8 as *const libc::c_char,
            );
        }
        libc::free(methods as *mut libc::c_void);
    };
}
pub unsafe extern "C" fn auth2_method_allowed(
    mut authctxt: *mut Authctxt,
    mut method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) -> libc::c_int {
    let mut i: u_int = 0;
    if options.num_auth_methods == 0 as libc::c_int as libc::c_uint {
        return 1 as libc::c_int;
    }
    i = 0 as libc::c_int as u_int;
    while i < (*authctxt).num_auth_methods {
        if list_starts_with(
            *((*authctxt).auth_methods).offset(i as isize),
            method,
            submethod,
        ) != 0 as libc::c_int
        {
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn authmethods_get(mut authctxt: *mut Authctxt) -> *mut libc::c_char {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut list: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"authmethods_get\0"))
                .as_ptr(),
            488 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int;
    while !(authmethods[i as usize]).is_null() {
        if !(libc::strcmp(
            (*authmethods[i as usize]).name,
            b"none\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int)
        {
            if !(((*authmethods[i as usize]).enabled).is_null()
                || *(*authmethods[i as usize]).enabled == 0 as libc::c_int)
            {
                if !(auth2_method_allowed(
                    authctxt,
                    (*authmethods[i as usize]).name,
                    0 as *const libc::c_char,
                ) == 0)
                {
                    r = crate::sshbuf_getput_basic::sshbuf_putf(
                        b,
                        b"%s%s\0" as *const u8 as *const libc::c_char,
                        if crate::sshbuf::sshbuf_len(b) != 0 {
                            b",\0" as *const u8 as *const libc::c_char
                        } else {
                            b"\0" as *const u8 as *const libc::c_char
                        },
                        (*authmethods[i as usize]).name,
                    );
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"auth2.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"authmethods_get\0",
                            ))
                            .as_ptr(),
                            500 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"buffer error\0" as *const u8 as *const libc::c_char,
                        );
                    }
                }
            }
        }
        i += 1;
        i;
    }
    list = crate::sshbuf_misc::sshbuf_dup_string(b);
    if list.is_null() {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"authmethods_get\0"))
                .as_ptr(),
            503 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::sshbuf_misc::sshbuf_dup_string failed\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_free(b);
    return list;
}
unsafe extern "C" fn authmethod_byname(mut name: *const libc::c_char) -> *mut Authmethod {
    let mut i: libc::c_int = 0;
    if name.is_null() {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"authmethod_byname\0"))
                .as_ptr(),
            514 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"NULL authentication method name\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int;
    while !(authmethods[i as usize]).is_null() {
        if libc::strcmp(name, (*authmethods[i as usize]).name) == 0 as libc::c_int
            || !((*authmethods[i as usize]).synonym).is_null()
                && libc::strcmp(name, (*authmethods[i as usize]).synonym) == 0 as libc::c_int
        {
            return authmethods[i as usize];
        }
        i += 1;
        i;
    }
    crate::log::sshlog(
        b"auth2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"authmethod_byname\0"))
            .as_ptr(),
        521 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"unrecognized authentication method name: %s\0" as *const u8 as *const libc::c_char,
        name,
    );
    return 0 as *mut Authmethod;
}
unsafe extern "C" fn authmethod_lookup(
    mut authctxt: *mut Authctxt,
    mut name: *const libc::c_char,
) -> *mut Authmethod {
    let mut method: *mut Authmethod = 0 as *mut Authmethod;
    method = authmethod_byname(name);
    if method.is_null() {
        return 0 as *mut Authmethod;
    }
    if ((*method).enabled).is_null() || *(*method).enabled == 0 as libc::c_int {
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"authmethod_lookup\0"))
                .as_ptr(),
            534 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"method %s not enabled\0" as *const u8 as *const libc::c_char,
            name,
        );
        return 0 as *mut Authmethod;
    }
    if auth2_method_allowed(authctxt, (*method).name, 0 as *const libc::c_char) == 0 {
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"authmethod_lookup\0"))
                .as_ptr(),
            539 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"method %s not allowed by AuthenticationMethods\0" as *const u8 as *const libc::c_char,
            name,
        );
        return 0 as *mut Authmethod;
    }
    return method;
}
pub unsafe extern "C" fn auth2_methods_valid(
    mut _methods: *const libc::c_char,
    mut need_enable: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut methods: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut omethods: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut method: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: u_int = 0;
    let mut found: u_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if *_methods as libc::c_int == '\0' as i32 {
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"auth2_methods_valid\0"))
                .as_ptr(),
            558 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"empty authentication method list\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    methods = crate::xmalloc::xstrdup(_methods);
    omethods = methods;
    's_23: loop {
        method = strsep(&mut methods, b",\0" as *const u8 as *const libc::c_char);
        if method.is_null() {
            current_block = 15976848397966268834;
            break;
        }
        i = 0 as libc::c_int as u_int;
        found = i;
        while found == 0 && !(authmethods[i as usize]).is_null() {
            p = libc::strchr(method, ':' as i32);
            if !p.is_null() {
                *p = '\0' as i32 as libc::c_char;
            }
            if libc::strcmp(method, (*authmethods[i as usize]).name) != 0 as libc::c_int {
                i = i.wrapping_add(1);
                i;
            } else {
                if need_enable != 0 {
                    if ((*authmethods[i as usize]).enabled).is_null()
                        || *(*authmethods[i as usize]).enabled == 0 as libc::c_int
                    {
                        crate::log::sshlog(
                            b"auth2.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                b"auth2_methods_valid\0",
                            ))
                            .as_ptr(),
                            573 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"Disabled method \"%s\" in AuthenticationMethods list \"%s\"\0"
                                as *const u8 as *const libc::c_char,
                            method,
                            _methods,
                        );
                        current_block = 4927200084332449060;
                        break 's_23;
                    }
                }
                found = 1 as libc::c_int as u_int;
                break;
            }
        }
        if !(found == 0) {
            continue;
        }
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"auth2_methods_valid\0"))
                .as_ptr(),
            582 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Unknown authentication method \"%s\" in list\0" as *const u8 as *const libc::c_char,
            method,
        );
        current_block = 4927200084332449060;
        break;
    }
    match current_block {
        15976848397966268834 => {
            ret = 0 as libc::c_int;
        }
        _ => {}
    }
    libc::free(omethods as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn auth2_setup_methods_lists(mut authctxt: *mut Authctxt) -> libc::c_int {
    let mut i: u_int = 0;
    if options.num_auth_methods == 1 as libc::c_int as libc::c_uint
        && libc::strcmp(
            *(options.auth_methods).offset(0 as libc::c_int as isize),
            b"any\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
    {
        libc::free(*(options.auth_methods).offset(0 as libc::c_int as isize) as *mut libc::c_void);
        let ref mut fresh2 = *(options.auth_methods).offset(0 as libc::c_int as isize);
        *fresh2 = 0 as *mut libc::c_char;
        options.num_auth_methods = 0 as libc::c_int as u_int;
    }
    if options.num_auth_methods == 0 as libc::c_int as libc::c_uint {
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"auth2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"auth2_setup_methods_lists\0"))
            .as_ptr(),
        614 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"checking methods\0" as *const u8 as *const libc::c_char,
    );
    (*authctxt).auth_methods = crate::xmalloc::xcalloc(
        options.num_auth_methods as size_t,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    (*authctxt).num_auth_methods = 0 as libc::c_int as u_int;
    i = 0 as libc::c_int as u_int;
    while i < options.num_auth_methods {
        if auth2_methods_valid(*(options.auth_methods).offset(i as isize), 1 as libc::c_int)
            != 0 as libc::c_int
        {
            crate::log::sshlog(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"auth2_setup_methods_lists\0",
                ))
                .as_ptr(),
                622 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Authentication methods list \"%s\" contains disabled method, skipping\0"
                    as *const u8 as *const libc::c_char,
                *(options.auth_methods).offset(i as isize),
            );
        } else {
            crate::log::sshlog(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"auth2_setup_methods_lists\0",
                ))
                .as_ptr(),
                626 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"authentication methods list %d: %s\0" as *const u8 as *const libc::c_char,
                (*authctxt).num_auth_methods,
                *(options.auth_methods).offset(i as isize),
            );
            let fresh3 = (*authctxt).num_auth_methods;
            (*authctxt).num_auth_methods = ((*authctxt).num_auth_methods).wrapping_add(1);
            let ref mut fresh4 = *((*authctxt).auth_methods).offset(fresh3 as isize);
            *fresh4 = crate::xmalloc::xstrdup(*(options.auth_methods).offset(i as isize));
        }
        i = i.wrapping_add(1);
        i;
    }
    if (*authctxt).num_auth_methods == 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"auth2_setup_methods_lists\0",
            ))
            .as_ptr(),
            632 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"No AuthenticationMethods left after eliminating disabled methods\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn list_starts_with(
    mut methods: *const libc::c_char,
    mut method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) -> libc::c_int {
    let mut l: size_t = strlen(method);
    let mut match_0: libc::c_int = 0;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    if strncmp(methods, method, l) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    p = methods.offset(l as isize);
    match_0 = 1 as libc::c_int;
    if *p as libc::c_int == ':' as i32 {
        if submethod.is_null() {
            return 3 as libc::c_int;
        }
        l = strlen(submethod);
        p = p.offset(1 as libc::c_int as isize);
        if strncmp(submethod, p, l) != 0 {
            return 0 as libc::c_int;
        }
        p = p.offset(l as isize);
        match_0 = 2 as libc::c_int;
    }
    if *p as libc::c_int != ',' as i32 && *p as libc::c_int != '\0' as i32 {
        return 0 as libc::c_int;
    }
    return match_0;
}
unsafe extern "C" fn remove_method(
    mut methods: *mut *mut libc::c_char,
    mut method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) -> libc::c_int {
    let mut omethods: *mut libc::c_char = *methods;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut l: size_t = strlen(method);
    let mut match_0: libc::c_int = 0;
    match_0 = list_starts_with(omethods, method, submethod);
    if match_0 != 1 as libc::c_int && match_0 != 2 as libc::c_int {
        return 0 as libc::c_int;
    }
    p = omethods.offset(l as isize);
    if !submethod.is_null() && match_0 == 2 as libc::c_int {
        p = p.offset((1 as libc::c_int as libc::c_ulong).wrapping_add(strlen(submethod)) as isize);
    }
    if *p as libc::c_int == ',' as i32 {
        p = p.offset(1);
        p;
    }
    *methods = crate::xmalloc::xstrdup(p);
    libc::free(omethods as *mut libc::c_void);
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn auth2_update_methods_lists(
    mut authctxt: *mut Authctxt,
    mut method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) -> libc::c_int {
    let mut i: u_int = 0;
    let mut found: u_int = 0 as libc::c_int as u_int;
    crate::log::sshlog(
        b"auth2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"auth2_update_methods_lists\0",
        ))
        .as_ptr(),
        702 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"updating methods list after \"%s\"\0" as *const u8 as *const libc::c_char,
        method,
    );
    i = 0 as libc::c_int as u_int;
    while i < (*authctxt).num_auth_methods {
        if !(remove_method(
            &mut *((*authctxt).auth_methods).offset(i as isize),
            method,
            submethod,
        ) == 0)
        {
            found = 1 as libc::c_int as u_int;
            if **((*authctxt).auth_methods).offset(i as isize) as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"auth2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"auth2_update_methods_lists\0",
                    ))
                    .as_ptr(),
                    709 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"authentication methods list %d complete\0" as *const u8
                        as *const libc::c_char,
                    i,
                );
                return 1 as libc::c_int;
            }
            crate::log::sshlog(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"auth2_update_methods_lists\0",
                ))
                .as_ptr(),
                713 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"authentication methods list %d remaining: \"%s\"\0" as *const u8
                    as *const libc::c_char,
                i,
                *((*authctxt).auth_methods).offset(i as isize),
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    if found == 0 {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"auth2_update_methods_lists\0",
            ))
            .as_ptr(),
            717 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"method not in AuthenticationMethods\0" as *const u8 as *const libc::c_char,
        );
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn auth2_authctxt_reset_info(mut authctxt: *mut Authctxt) {
    crate::sshkey::sshkey_free((*authctxt).auth_method_key);
    libc::free((*authctxt).auth_method_info as *mut libc::c_void);
    (*authctxt).auth_method_key = 0 as *mut crate::sshkey::sshkey;
    (*authctxt).auth_method_info = 0 as *mut libc::c_char;
}
pub unsafe extern "C" fn auth2_record_info(
    mut authctxt: *mut Authctxt,
    mut fmt: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::core::ffi::VaListImpl;
    let mut i: libc::c_int = 0;
    libc::free((*authctxt).auth_method_info as *mut libc::c_void);
    (*authctxt).auth_method_info = 0 as *mut libc::c_char;
    ap = args.clone();
    i = vasprintf(&mut (*authctxt).auth_method_info, fmt, ap.as_va_list());
    if i == -(1 as libc::c_int) {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"auth2_record_info\0"))
                .as_ptr(),
            745 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"vasprintf failed\0" as *const u8 as *const libc::c_char,
        );
    }
}
pub unsafe extern "C" fn auth2_record_key(
    mut authctxt: *mut Authctxt,
    mut authenticated: libc::c_int,
    mut key: *const crate::sshkey::sshkey,
) {
    let mut tmp: *mut *mut crate::sshkey::sshkey = 0 as *mut *mut crate::sshkey::sshkey;
    let mut dup: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut r: libc::c_int = 0;
    r = crate::sshkey::sshkey_from_private(key, &mut dup);
    if r != 0 as libc::c_int {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"auth2_record_key\0"))
                .as_ptr(),
            761 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"copy key\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshkey::sshkey_free((*authctxt).auth_method_key);
    (*authctxt).auth_method_key = dup;
    if authenticated == 0 {
        return;
    }
    r = crate::sshkey::sshkey_from_private(key, &mut dup);
    if r != 0 as libc::c_int {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"auth2_record_key\0"))
                .as_ptr(),
            770 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"copy key\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*authctxt).nprev_keys >= 2147483647 as libc::c_int as libc::c_uint || {
        tmp = recallocarray(
            (*authctxt).prev_keys as *mut libc::c_void,
            (*authctxt).nprev_keys as size_t,
            ((*authctxt).nprev_keys).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
            ::core::mem::size_of::<*mut crate::sshkey::sshkey>() as libc::c_ulong,
        ) as *mut *mut crate::sshkey::sshkey;
        tmp.is_null()
    } {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"auth2_record_key\0"))
                .as_ptr(),
            774 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"reallocarray failed\0" as *const u8 as *const libc::c_char,
        );
    }
    (*authctxt).prev_keys = tmp;
    let ref mut fresh5 = *((*authctxt).prev_keys).offset((*authctxt).nprev_keys as isize);
    *fresh5 = dup;
    (*authctxt).nprev_keys = ((*authctxt).nprev_keys).wrapping_add(1);
    (*authctxt).nprev_keys;
}
pub unsafe extern "C" fn auth2_key_already_used(
    mut authctxt: *mut Authctxt,
    mut key: *const crate::sshkey::sshkey,
) -> libc::c_int {
    let mut i: u_int = 0;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*authctxt).nprev_keys {
        if crate::sshkey::sshkey_equal_public(key, *((*authctxt).prev_keys).offset(i as isize)) != 0
        {
            fp = crate::sshkey::sshkey_fingerprint(
                *((*authctxt).prev_keys).offset(i as isize),
                options.fingerprint_hash,
                SSH_FP_DEFAULT,
            );
            crate::log::sshlog(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"auth2_key_already_used\0",
                ))
                .as_ptr(),
                794 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"key already used: %s %s\0" as *const u8 as *const libc::c_char,
                crate::sshkey::sshkey_type(*((*authctxt).prev_keys).offset(i as isize)),
                if fp.is_null() {
                    b"UNKNOWN\0" as *const u8 as *const libc::c_char
                } else {
                    fp as *const libc::c_char
                },
            );
            libc::free(fp as *mut libc::c_void);
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn auth2_update_session_info(
    mut authctxt: *mut Authctxt,
    mut method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) {
    let mut r: libc::c_int = 0;
    if ((*authctxt).session_info).is_null() {
        (*authctxt).session_info = crate::sshbuf::sshbuf_new();
        if ((*authctxt).session_info).is_null() {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"auth2_update_session_info\0",
                ))
                .as_ptr(),
                814 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::crate::sshbuf::sshbuf::sshbuf_new\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    r = crate::sshbuf_getput_basic::sshbuf_putf(
        (*authctxt).session_info,
        b"%s%s%s\0" as *const u8 as *const libc::c_char,
        method,
        if submethod.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b"/\0" as *const u8 as *const libc::c_char
        },
        if submethod.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            submethod
        },
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"auth2_update_session_info\0",
            ))
            .as_ptr(),
            821 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"append method\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*authctxt).auth_method_key).is_null() {
        r = crate::sshbuf_getput_basic::sshbuf_put_u8(
            (*authctxt).session_info,
            ' ' as i32 as u_char,
        );
        if r != 0 as libc::c_int || {
            r = crate::sshkey::sshkey_format_text(
                (*authctxt).auth_method_key,
                (*authctxt).session_info,
            );
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"auth2_update_session_info\0",
                ))
                .as_ptr(),
                828 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"append key\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if !((*authctxt).auth_method_info).is_null() {
        if !(libc::strchr((*authctxt).auth_method_info, '\n' as i32)).is_null() {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"auth2_update_session_info\0",
                ))
                .as_ptr(),
                834 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"auth_method_info contains \\n\0" as *const u8 as *const libc::c_char,
            );
        }
        r = crate::sshbuf_getput_basic::sshbuf_put_u8(
            (*authctxt).session_info,
            ' ' as i32 as u_char,
        );
        if r != 0 as libc::c_int || {
            r = crate::sshbuf_getput_basic::sshbuf_putf(
                (*authctxt).session_info,
                b"%s\0" as *const u8 as *const libc::c_char,
                (*authctxt).auth_method_info,
            );
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"auth2_update_session_info\0",
                ))
                .as_ptr(),
                838 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"append method info\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u8((*authctxt).session_info, '\n' as i32 as u_char);
    if r != 0 as libc::c_int {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"auth2_update_session_info\0",
            ))
            .as_ptr(),
            842 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"append\0" as *const u8 as *const libc::c_char,
        );
    }
}
