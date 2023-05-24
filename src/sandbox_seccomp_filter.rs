use ::libc;
extern "C" {
    pub type monitor;
    fn __errno_location() -> *mut libc::c_int;
    fn setrlimit(__resource: __rlimit_resource_t, __rlimits: *const rlimit) -> libc::c_int;
    fn prctl(__option: libc::c_int, _: ...) -> libc::c_int;
    fn free(_: *mut libc::c_void);
    fn strerror(_: libc::c_int) -> *mut libc::c_char;

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
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
}
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __pid_t = libc::c_int;
pub type __rlim_t = libc::c_ulong;
pub type pid_t = __pid_t;
pub type size_t = libc::c_ulong;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type __u8 = libc::c_uchar;
pub type __u16 = libc::c_ushort;
pub type __u32 = libc::c_uint;
pub type __rlimit_resource = libc::c_uint;
pub const __RLIM_NLIMITS: __rlimit_resource = 16;
pub const __RLIMIT_NLIMITS: __rlimit_resource = 16;
pub const __RLIMIT_RTTIME: __rlimit_resource = 15;
pub const __RLIMIT_RTPRIO: __rlimit_resource = 14;
pub const __RLIMIT_NICE: __rlimit_resource = 13;
pub const __RLIMIT_MSGQUEUE: __rlimit_resource = 12;
pub const __RLIMIT_SIGPENDING: __rlimit_resource = 11;
pub const __RLIMIT_LOCKS: __rlimit_resource = 10;
pub const __RLIMIT_MEMLOCK: __rlimit_resource = 8;
pub const __RLIMIT_NPROC: __rlimit_resource = 6;
pub const RLIMIT_AS: __rlimit_resource = 9;
pub const __RLIMIT_OFILE: __rlimit_resource = 7;
pub const RLIMIT_NOFILE: __rlimit_resource = 7;
pub const __RLIMIT_RSS: __rlimit_resource = 5;
pub const RLIMIT_CORE: __rlimit_resource = 4;
pub const RLIMIT_STACK: __rlimit_resource = 3;
pub const RLIMIT_DATA: __rlimit_resource = 2;
pub const RLIMIT_FSIZE: __rlimit_resource = 1;
pub const RLIMIT_CPU: __rlimit_resource = 0;
pub type rlim_t = __rlim_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rlimit {
    pub rlim_cur: rlim_t,
    pub rlim_max: rlim_t,
}
pub type __rlimit_resource_t = __rlimit_resource;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sock_filter {
    pub code: __u16,
    pub jt: __u8,
    pub jf: __u8,
    pub k: __u32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sock_fprog {
    pub len: libc::c_ushort,
    pub filter: *mut sock_filter,
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
pub struct ssh_sandbox {
    pub child_pid: pid_t,
}
static mut preauth_insns: [sock_filter; 202] = [sock_filter {
    code: 0,
    jt: 0,
    jf: 0,
    k: 0,
}; 202];
static mut preauth_program: sock_fprog = sock_fprog {
    len: 0,
    filter: 0 as *const sock_filter as *mut sock_filter,
};
pub unsafe extern "C" fn ssh_sandbox_init(mut _monitor: *mut monitor) -> *mut ssh_sandbox {
    let mut box_0: *mut ssh_sandbox = 0 as *mut ssh_sandbox;
    crate::log::sshlog(
        b"sandbox-seccomp-filter.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"ssh_sandbox_init\0")).as_ptr(),
        445 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s: preparing seccomp filter sandbox\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"ssh_sandbox_init\0")).as_ptr(),
    );
    box_0 = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<ssh_sandbox>() as libc::c_ulong,
    ) as *mut ssh_sandbox;
    (*box_0).child_pid = 0 as libc::c_int;
    return box_0;
}
pub unsafe extern "C" fn ssh_sandbox_child(mut _box_0: *mut ssh_sandbox) {
    let mut rl_zero: rlimit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let mut rl_one: rlimit = {
        let mut init = rlimit {
            rlim_cur: 1 as libc::c_int as rlim_t,
            rlim_max: 1 as libc::c_int as rlim_t,
        };
        init
    };
    let mut nnp_failed: libc::c_int = 0 as libc::c_int;
    rl_zero.rlim_max = 0 as libc::c_int as rlim_t;
    rl_zero.rlim_cur = rl_zero.rlim_max;
    if setrlimit(RLIMIT_FSIZE, &mut rl_zero) == -(1 as libc::c_int) {
        sshfatal(
            b"sandbox-seccomp-filter.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
                .as_ptr(),
            499 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
                .as_ptr(),
            strerror(*__errno_location()),
        );
    }
    if setrlimit(RLIMIT_NOFILE, &mut rl_one) == -(1 as libc::c_int) {
        sshfatal(
            b"sandbox-seccomp-filter.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
                .as_ptr(),
            506 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: setrlimit(RLIMIT_NOFILE, { 0, 0 }): %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
                .as_ptr(),
            strerror(*__errno_location()),
        );
    }
    if setrlimit(__RLIMIT_NPROC, &mut rl_zero) == -(1 as libc::c_int) {
        sshfatal(
            b"sandbox-seccomp-filter.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
                .as_ptr(),
            509 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: setrlimit(RLIMIT_NPROC, { 0, 0 }): %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
                .as_ptr(),
            strerror(*__errno_location()),
        );
    }
    crate::log::sshlog(
        b"sandbox-seccomp-filter.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
            .as_ptr(),
        515 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s: setting PR_SET_NO_NEW_PRIVS\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
            .as_ptr(),
    );
    if prctl(
        38 as libc::c_int,
        1 as libc::c_int,
        0 as libc::c_int,
        0 as libc::c_int,
        0 as libc::c_int,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"sandbox-seccomp-filter.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
                .as_ptr(),
            518 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s: prctl(PR_SET_NO_NEW_PRIVS): %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
                .as_ptr(),
            strerror(*__errno_location()),
        );
        nnp_failed = 1 as libc::c_int;
    }
    crate::log::sshlog(
        b"sandbox-seccomp-filter.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
            .as_ptr(),
        521 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s: attaching seccomp filter program\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
            .as_ptr(),
    );
    if prctl(
        22 as libc::c_int,
        2 as libc::c_int,
        &preauth_program as *const sock_fprog,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"sandbox-seccomp-filter.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
                .as_ptr(),
            524 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s: prctl(PR_SET_SECCOMP): %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
                .as_ptr(),
            strerror(*__errno_location()),
        );
    } else if nnp_failed != 0 {
        sshfatal(
            b"sandbox-seccomp-filter.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
                .as_ptr(),
            527 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: SECCOMP_MODE_FILTER activated but PR_SET_NO_NEW_PRIVS failed\0" as *const u8
                as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_sandbox_child\0"))
                .as_ptr(),
        );
    }
}
pub unsafe extern "C" fn ssh_sandbox_parent_finish(mut box_0: *mut ssh_sandbox) {
    free(box_0 as *mut libc::c_void);
    crate::log::sshlog(
        b"sandbox-seccomp-filter.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"ssh_sandbox_parent_finish\0"))
            .as_ptr(),
        534 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s: finished\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"ssh_sandbox_parent_finish\0"))
            .as_ptr(),
    );
}
pub unsafe extern "C" fn ssh_sandbox_parent_preauth(
    mut box_0: *mut ssh_sandbox,
    mut child_pid: pid_t,
) {
    (*box_0).child_pid = child_pid;
}
unsafe extern "C" fn run_static_initializers() {
    preauth_insns = [
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 4 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 1 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 62 as libc::c_int as libc::c_uint
                    | 0x80000000 as libc::c_uint
                    | 0x40000000 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 6 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x50000 as libc::c_uint | 13 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 5 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x50000 as libc::c_uint | 13 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 2 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x50000 as libc::c_uint | 13 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 257 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x50000 as libc::c_uint | 13 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 262 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x50000 as libc::c_uint | 13 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 4 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x50000 as libc::c_uint | 13 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 29 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x50000 as libc::c_uint | 13 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 30 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x50000 as libc::c_uint | 13 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 67 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x50000 as libc::c_uint | 13 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 332 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x50000 as libc::c_uint | 13 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 12 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 228 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 3 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 60 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 231 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 8 as libc::c_int as __u8,
                k: 202 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (24 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !((128 as libc::c_int | 256 as libc::c_int) as libc::c_uint
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 4 as libc::c_int as __u8,
                k: 0 as libc::c_int as libc::c_uint & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (24 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !(((128 as libc::c_int | 256 as libc::c_int) as uint64_t >> 32 as libc::c_int)
                    as uint32_t
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: (0 as libc::c_int as uint64_t >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 8 as libc::c_int as __u8,
                k: 202 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (24 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !((128 as libc::c_int | 256 as libc::c_int) as libc::c_uint
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 4 as libc::c_int as __u8,
                k: 9 as libc::c_int as libc::c_uint & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (24 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !(((128 as libc::c_int | 256 as libc::c_int) as uint64_t >> 32 as libc::c_int)
                    as uint32_t
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: (9 as libc::c_int as uint64_t >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 8 as libc::c_int as __u8,
                k: 202 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (24 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !((128 as libc::c_int | 256 as libc::c_int) as libc::c_uint
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 4 as libc::c_int as __u8,
                k: 1 as libc::c_int as libc::c_uint & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (24 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !(((128 as libc::c_int | 256 as libc::c_int) as uint64_t >> 32 as libc::c_int)
                    as uint32_t
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: (1 as libc::c_int as uint64_t >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 8 as libc::c_int as __u8,
                k: 202 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (24 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !((128 as libc::c_int | 256 as libc::c_int) as libc::c_uint
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 4 as libc::c_int as __u8,
                k: 10 as libc::c_int as libc::c_uint & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (24 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !(((128 as libc::c_int | 256 as libc::c_int) as uint64_t >> 32 as libc::c_int)
                    as uint32_t
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: (10 as libc::c_int as uint64_t >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 8 as libc::c_int as __u8,
                k: 202 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (24 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !((128 as libc::c_int | 256 as libc::c_int) as libc::c_uint
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 4 as libc::c_int as __u8,
                k: 3 as libc::c_int as libc::c_uint & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (24 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !(((128 as libc::c_int | 256 as libc::c_int) as uint64_t >> 32 as libc::c_int)
                    as uint32_t
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: (3 as libc::c_int as uint64_t >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 8 as libc::c_int as __u8,
                k: 202 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (24 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !((128 as libc::c_int | 256 as libc::c_int) as libc::c_uint
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 4 as libc::c_int as __u8,
                k: 4 as libc::c_int as libc::c_uint & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (24 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !(((128 as libc::c_int | 256 as libc::c_int) as uint64_t >> 32 as libc::c_int)
                    as uint32_t
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: (4 as libc::c_int as uint64_t >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 107 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 121 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 39 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 318 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 186 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 96 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 102 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 6 as libc::c_int as __u8,
                k: 28 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 3 as libc::c_int as __u8,
                k: 0 as libc::c_int as libc::c_uint & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: (0 as libc::c_int as uint64_t >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 6 as libc::c_int as __u8,
                k: 28 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 3 as libc::c_int as __u8,
                k: 8 as libc::c_int as libc::c_uint & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: (8 as libc::c_int as uint64_t >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 6 as libc::c_int as __u8,
                k: 28 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 3 as libc::c_int as __u8,
                k: 4 as libc::c_int as libc::c_uint & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: (4 as libc::c_int as uint64_t >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 6 as libc::c_int as __u8,
                k: 28 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 3 as libc::c_int as __u8,
                k: 10 as libc::c_int as libc::c_uint & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: (10 as libc::c_int as uint64_t >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 6 as libc::c_int as __u8,
                k: 28 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 3 as libc::c_int as __u8,
                k: 16 as libc::c_int as libc::c_uint & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: (16 as libc::c_int as uint64_t >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 6 as libc::c_int as __u8,
                k: 28 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 3 as libc::c_int as __u8,
                k: 18 as libc::c_int as libc::c_uint & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: (18 as libc::c_int as uint64_t >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 28 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x50000 as libc::c_uint | 22 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 8 as libc::c_int as __u8,
                k: 9 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (40 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !((0x2 as libc::c_int
                    | 0x20 as libc::c_int
                    | 0x10 as libc::c_int
                    | 0x100000 as libc::c_int) as libc::c_uint
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 3 as libc::c_int as __u8,
                k: 0 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (40 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !(((0x2 as libc::c_int
                    | 0x20 as libc::c_int
                    | 0x10 as libc::c_int
                    | 0x100000 as libc::c_int) as uint64_t
                    >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 1 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x50000 as libc::c_uint | 22 as libc::c_int as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 8 as libc::c_int as __u8,
                k: 9 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !((0x1 as libc::c_int | 0x2 as libc::c_int | 0 as libc::c_int) as libc::c_uint
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 4 as libc::c_int as __u8,
                k: 0 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !(((0x1 as libc::c_int | 0x2 as libc::c_int | 0 as libc::c_int) as uint64_t
                    >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 0 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 8 as libc::c_int as __u8,
                k: 10 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong).wrapping_add(0 as libc::c_int as libc::c_ulong) as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !((0x1 as libc::c_int | 0x2 as libc::c_int | 0 as libc::c_int) as libc::c_uint
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 4 as libc::c_int as __u8,
                k: 0 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: (32 as libc::c_ulong)
                    .wrapping_add(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                    as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x4 as libc::c_int + 0x50 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: !(((0x1 as libc::c_int | 0x2 as libc::c_int | 0 as libc::c_int) as uint64_t
                    >> 32 as libc::c_int) as uint32_t
                    & 0xffffffff as libc::c_uint),
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 0 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0 as libc::c_int + 0 as libc::c_int + 0x20 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_ulong as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 25 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 11 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 35 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 230 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 271 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 7 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 270 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 0 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 14 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 23 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 48 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 201 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 1 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x5 as libc::c_int + 0x10 as libc::c_int + 0 as libc::c_int)
                    as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 1 as libc::c_int as __u8,
                k: 20 as libc::c_int as __u32,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0x7fff0000 as libc::c_uint,
            };
            init
        },
        {
            let mut init = sock_filter {
                code: (0x6 as libc::c_int + 0 as libc::c_int) as libc::c_ushort,
                jt: 0 as libc::c_int as __u8,
                jf: 0 as libc::c_int as __u8,
                k: 0 as libc::c_uint,
            };
            init
        },
    ];
    preauth_program = {
        let mut init = sock_fprog {
            len: (::core::mem::size_of::<[sock_filter; 202]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<sock_filter>() as libc::c_ulong)
                as libc::c_ushort,
            filter: preauth_insns.as_ptr() as *mut sock_filter,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
