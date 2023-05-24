use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn __errno_location() -> *mut libc::c_int;
    fn readpassphrase(
        _: *const libc::c_char,
        _: *mut libc::c_char,
        _: size_t,
        _: libc::c_int,
    ) -> *mut libc::c_char;
    fn kill(__pid: __pid_t, __sig: libc::c_int) -> libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn closefrom(__lowfd: libc::c_int);
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn pipe(__pipedes: *mut libc::c_int) -> libc::c_int;
    fn dup2(__fd: libc::c_int, __fd2: libc::c_int) -> libc::c_int;
    fn execlp(__file: *const libc::c_char, __arg: *const libc::c_char, _: ...) -> libc::c_int;
    fn _exit(_: libc::c_int) -> !;
    fn fork() -> __pid_t;
    fn isatty(__fd: libc::c_int) -> libc::c_int;
    static mut stdout: *mut FILE;
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn waitpid(__pid: __pid_t, __stat_loc: *mut libc::c_int, __options: libc::c_int) -> __pid_t;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn setenv(
        __name: *const libc::c_char,
        __value: *const libc::c_char,
        __replace: libc::c_int,
    ) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn xvasprintf(
        _: *mut *mut libc::c_char,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn stdfd_devnull(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn ssh_signal(_: libc::c_int, _: sshsig_t) -> sshsig_t;
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
    fn sshlog(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: LogLevel,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: ...
    );
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
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __ssize_t = libc::c_long;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type __sighandler_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
pub type va_list = __builtin_va_list;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct notifier_ctx {
    pub pid: pid_t,
    pub osigchld: Option<unsafe extern "C" fn(libc::c_int) -> ()>,
}
pub type sshsig_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
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
unsafe extern "C" fn ssh_askpass(
    mut askpass: *mut libc::c_char,
    mut msg: *const libc::c_char,
    mut env_hint: *const libc::c_char,
) -> *mut libc::c_char {
    let mut pid: pid_t = 0;
    let mut ret: pid_t = 0;
    let mut len: size_t = 0;
    let mut pass: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: [libc::c_int; 2] = [0; 2];
    let mut status: libc::c_int = 0;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut osigchld: Option<unsafe extern "C" fn(libc::c_int) -> ()> = None;
    if fflush(stdout) != 0 as libc::c_int {
        sshlog(
            b"readpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_askpass\0")).as_ptr(),
            61 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"fflush: %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
    }
    if askpass.is_null() {
        sshfatal(
            b"readpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_askpass\0")).as_ptr(),
            63 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"internal error: askpass undefined\0" as *const u8 as *const libc::c_char,
        );
    }
    if pipe(p.as_mut_ptr()) == -(1 as libc::c_int) {
        sshlog(
            b"readpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_askpass\0")).as_ptr(),
            65 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"pipe: %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        return 0 as *mut libc::c_char;
    }
    osigchld = ssh_signal(17 as libc::c_int, None);
    pid = fork();
    if pid == -(1 as libc::c_int) {
        sshlog(
            b"readpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_askpass\0")).as_ptr(),
            70 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"fork: %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        ssh_signal(17 as libc::c_int, osigchld);
        return 0 as *mut libc::c_char;
    }
    if pid == 0 as libc::c_int {
        close(p[0 as libc::c_int as usize]);
        if dup2(p[1 as libc::c_int as usize], 1 as libc::c_int) == -(1 as libc::c_int) {
            sshfatal(
                b"readpass.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_askpass\0"))
                    .as_ptr(),
                77 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"dup2: %s\0" as *const u8 as *const libc::c_char,
                strerror(*__errno_location()),
            );
        }
        if !env_hint.is_null() {
            setenv(
                b"SSH_ASKPASS_PROMPT\0" as *const u8 as *const libc::c_char,
                env_hint,
                1 as libc::c_int,
            );
        }
        execlp(
            askpass,
            askpass,
            msg,
            0 as *mut libc::c_void as *mut libc::c_char,
        );
        sshfatal(
            b"readpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_askpass\0")).as_ptr(),
            81 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"exec(%s): %s\0" as *const u8 as *const libc::c_char,
            askpass,
            strerror(*__errno_location()),
        );
    }
    close(p[1 as libc::c_int as usize]);
    len = 0 as libc::c_int as size_t;
    loop {
        let mut r: ssize_t = read(
            p[0 as libc::c_int as usize],
            buf.as_mut_ptr().offset(len as isize) as *mut libc::c_void,
            (::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                .wrapping_sub(len),
        );
        if !(r == -(1 as libc::c_int) as libc::c_long && *__errno_location() == 4 as libc::c_int) {
            if r <= 0 as libc::c_int as libc::c_long {
                break;
            }
            len = (len as libc::c_ulong).wrapping_add(r as libc::c_ulong) as size_t as size_t;
        }
        if !((::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_sub(len)
            > 0 as libc::c_int as libc::c_ulong)
        {
            break;
        }
    }
    buf[len as usize] = '\0' as i32 as libc::c_char;
    close(p[0 as libc::c_int as usize]);
    loop {
        ret = waitpid(pid, &mut status, 0 as libc::c_int);
        if !(ret == -(1 as libc::c_int)) {
            break;
        }
        if *__errno_location() != 4 as libc::c_int {
            break;
        }
    }
    ssh_signal(17 as libc::c_int, osigchld);
    if ret == -(1 as libc::c_int)
        || !(status & 0x7f as libc::c_int == 0 as libc::c_int)
        || (status & 0xff00 as libc::c_int) >> 8 as libc::c_int != 0 as libc::c_int
    {
        explicit_bzero(
            buf.as_mut_ptr() as *mut libc::c_void,
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        );
        return 0 as *mut libc::c_char;
    }
    buf[strcspn(
        buf.as_mut_ptr(),
        b"\r\n\0" as *const u8 as *const libc::c_char,
    ) as usize] = '\0' as i32 as libc::c_char;
    pass = xstrdup(buf.as_mut_ptr());
    explicit_bzero(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
    );
    return pass;
}
pub unsafe extern "C" fn read_passphrase(
    mut prompt: *const libc::c_char,
    mut flags: libc::c_int,
) -> *mut libc::c_char {
    let mut cr: libc::c_char = '\r' as i32 as libc::c_char;
    let mut askpass: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut rppflags: libc::c_int = 0;
    let mut ttyfd: libc::c_int = 0;
    let mut use_askpass: libc::c_int = 0 as libc::c_int;
    let mut allow_askpass: libc::c_int = 0 as libc::c_int;
    let mut askpass_hint: *const libc::c_char = 0 as *const libc::c_char;
    let mut s: *const libc::c_char = 0 as *const libc::c_char;
    s = getenv(b"DISPLAY\0" as *const u8 as *const libc::c_char);
    if !s.is_null() {
        allow_askpass = (*s as libc::c_int != '\0' as i32) as libc::c_int;
    }
    s = getenv(b"SSH_ASKPASS_REQUIRE\0" as *const u8 as *const libc::c_char);
    if !s.is_null() {
        if strcasecmp(s, b"force\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
            use_askpass = 1 as libc::c_int;
            allow_askpass = 1 as libc::c_int;
        } else if strcasecmp(s, b"prefer\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            use_askpass = allow_askpass;
        } else if strcasecmp(s, b"never\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            allow_askpass = 0 as libc::c_int;
        }
    }
    rppflags = if flags & 0x1 as libc::c_int != 0 {
        0x1 as libc::c_int
    } else {
        0 as libc::c_int
    };
    if use_askpass != 0 {
        sshlog(
            b"readpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"read_passphrase\0"))
                .as_ptr(),
            144 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"requested to askpass\0" as *const u8 as *const libc::c_char,
        );
    } else if flags & 0x8 as libc::c_int != 0 {
        use_askpass = 1 as libc::c_int;
    } else if flags & 0x2 as libc::c_int != 0 {
        if isatty(0 as libc::c_int) == 0 {
            sshlog(
                b"readpass.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"read_passphrase\0"))
                    .as_ptr(),
                149 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"stdin is not a tty\0" as *const u8 as *const libc::c_char,
            );
            use_askpass = 1 as libc::c_int;
        }
    } else {
        rppflags |= 0x2 as libc::c_int;
        ttyfd = open(
            b"/dev/tty\0" as *const u8 as *const libc::c_char,
            0o2 as libc::c_int,
        );
        if ttyfd >= 0 as libc::c_int {
            write(
                ttyfd,
                &mut cr as *mut libc::c_char as *const libc::c_void,
                1 as libc::c_int as size_t,
            );
            close(ttyfd);
        } else {
            sshlog(
                b"readpass.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"read_passphrase\0"))
                    .as_ptr(),
                166 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"can't open %s: %s\0" as *const u8 as *const libc::c_char,
                b"/dev/tty\0" as *const u8 as *const libc::c_char,
                strerror(*__errno_location()),
            );
            use_askpass = 1 as libc::c_int;
        }
    }
    if flags & 0x8 as libc::c_int != 0 && allow_askpass == 0 {
        return if flags & 0x4 as libc::c_int != 0 {
            0 as *mut libc::c_char
        } else {
            xstrdup(b"\0" as *const u8 as *const libc::c_char)
        };
    }
    if use_askpass != 0 && allow_askpass != 0 {
        if !(getenv(b"SSH_ASKPASS\0" as *const u8 as *const libc::c_char)).is_null() {
            askpass = getenv(b"SSH_ASKPASS\0" as *const u8 as *const libc::c_char);
        } else {
            askpass = b"/usr/local/libexec/ssh-askpass\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        }
        if flags & 0x8000 as libc::c_int != 0 as libc::c_int {
            askpass_hint = b"confirm\0" as *const u8 as *const libc::c_char;
        }
        ret = ssh_askpass(askpass, prompt, askpass_hint);
        if ret.is_null() {
            if flags & 0x4 as libc::c_int == 0 {
                return xstrdup(b"\0" as *const u8 as *const libc::c_char);
            }
        }
        return ret;
    }
    if (readpassphrase(
        prompt,
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        rppflags,
    ))
    .is_null()
    {
        if flags & 0x4 as libc::c_int != 0 {
            return 0 as *mut libc::c_char;
        }
        return xstrdup(b"\0" as *const u8 as *const libc::c_char);
    }
    ret = xstrdup(buf.as_mut_ptr());
    explicit_bzero(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
    );
    return ret;
}
pub unsafe extern "C" fn ask_permission(
    mut fmt: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut args_0: ::core::ffi::VaListImpl;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut prompt: [libc::c_char; 1024] = [0; 1024];
    let mut allowed: libc::c_int = 0 as libc::c_int;
    args_0 = args.clone();
    vsnprintf(
        prompt.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        fmt,
        args_0.as_va_list(),
    );
    p = read_passphrase(
        prompt.as_mut_ptr(),
        0x8 as libc::c_int | 0x4 as libc::c_int | 0x8000 as libc::c_int,
    );
    if !p.is_null() {
        if *p as libc::c_int == '\0' as i32
            || *p as libc::c_int == '\n' as i32
            || strcasecmp(p, b"yes\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            allowed = 1 as libc::c_int;
        }
        free(p as *mut libc::c_void);
    }
    return allowed;
}
unsafe extern "C" fn writemsg(mut msg: *const libc::c_char) {
    write(
        2 as libc::c_int,
        b"\r\0" as *const u8 as *const libc::c_char as *const libc::c_void,
        1 as libc::c_int as size_t,
    );
    write(2 as libc::c_int, msg as *const libc::c_void, strlen(msg));
    write(
        2 as libc::c_int,
        b"\r\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
        2 as libc::c_int as size_t,
    );
}
pub unsafe extern "C" fn notify_start(
    mut force_askpass: libc::c_int,
    mut fmt: *const libc::c_char,
    mut args: ...
) -> *mut notifier_ctx {
    let mut current_block: u64;
    let mut args_0: ::core::ffi::VaListImpl;
    let mut prompt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pid: pid_t = -(1 as libc::c_int);
    let mut osigchld: Option<unsafe extern "C" fn(libc::c_int) -> ()> = None;
    let mut askpass: *const libc::c_char = 0 as *const libc::c_char;
    let mut s: *const libc::c_char = 0 as *const libc::c_char;
    let mut ret: *mut notifier_ctx = 0 as *mut notifier_ctx;
    args_0 = args.clone();
    xvasprintf(&mut prompt, fmt, args_0.as_va_list());
    if fflush(0 as *mut FILE) != 0 as libc::c_int {
        sshlog(
            b"readpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"notify_start\0")).as_ptr(),
            253 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"fflush: %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
    }
    if force_askpass == 0 && isatty(2 as libc::c_int) != 0 {
        writemsg(prompt);
        current_block = 8351141560393962031;
    } else {
        askpass = getenv(b"SSH_ASKPASS\0" as *const u8 as *const libc::c_char);
        if askpass.is_null() {
            askpass = b"/usr/local/libexec/ssh-askpass\0" as *const u8 as *const libc::c_char;
        }
        if *askpass as libc::c_int == '\0' as i32 {
            sshlog(
                b"readpass.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"notify_start\0"))
                    .as_ptr(),
                261 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"cannot notify: no askpass\0" as *const u8 as *const libc::c_char,
            );
            current_block = 13051439020340349553;
        } else if (getenv(b"DISPLAY\0" as *const u8 as *const libc::c_char)).is_null() && {
            s = getenv(b"SSH_ASKPASS_REQUIRE\0" as *const u8 as *const libc::c_char);
            s.is_null()
                || strcmp(s, b"force\0" as *const u8 as *const libc::c_char) != 0 as libc::c_int
        } {
            sshlog(
                b"readpass.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"notify_start\0"))
                    .as_ptr(),
                267 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"cannot notify: no display\0" as *const u8 as *const libc::c_char,
            );
            current_block = 13051439020340349553;
        } else {
            osigchld = ssh_signal(17 as libc::c_int, None);
            pid = fork();
            if pid == -(1 as libc::c_int) {
                sshlog(
                    b"readpass.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"notify_start\0"))
                        .as_ptr(),
                    272 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"fork: %s\0" as *const u8 as *const libc::c_char,
                    strerror(*__errno_location()),
                );
                ssh_signal(17 as libc::c_int, osigchld);
                free(prompt as *mut libc::c_void);
                return 0 as *mut notifier_ctx;
            }
            if pid == 0 as libc::c_int {
                if stdfd_devnull(1 as libc::c_int, 1 as libc::c_int, 0 as libc::c_int)
                    == -(1 as libc::c_int)
                {
                    sshfatal(
                        b"readpass.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"notify_start\0",
                        ))
                        .as_ptr(),
                        279 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"stdfd_devnull failed\0" as *const u8 as *const libc::c_char,
                    );
                }
                closefrom(2 as libc::c_int + 1 as libc::c_int);
                setenv(
                    b"SSH_ASKPASS_PROMPT\0" as *const u8 as *const libc::c_char,
                    b"none\0" as *const u8 as *const libc::c_char,
                    1 as libc::c_int,
                );
                execlp(
                    askpass,
                    askpass,
                    prompt,
                    0 as *mut libc::c_void as *mut libc::c_char,
                );
                sshlog(
                    b"readpass.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"notify_start\0"))
                        .as_ptr(),
                    283 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"exec(%s): %s\0" as *const u8 as *const libc::c_char,
                    askpass,
                    strerror(*__errno_location()),
                );
                _exit(1 as libc::c_int);
            }
            current_block = 8351141560393962031;
        }
    }
    match current_block {
        8351141560393962031 => {
            ret = calloc(
                1 as libc::c_int as libc::c_ulong,
                ::core::mem::size_of::<notifier_ctx>() as libc::c_ulong,
            ) as *mut notifier_ctx;
            if ret.is_null() {
                if pid != -(1 as libc::c_int) {
                    kill(pid, 15 as libc::c_int);
                }
                sshfatal(
                    b"readpass.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"notify_start\0"))
                        .as_ptr(),
                    291 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"calloc failed\0" as *const u8 as *const libc::c_char,
                );
            }
            (*ret).pid = pid;
            (*ret).osigchld = osigchld;
        }
        _ => {}
    }
    free(prompt as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn notify_complete(
    mut ctx: *mut notifier_ctx,
    mut fmt: *const libc::c_char,
    mut args: ...
) {
    let mut ret: libc::c_int = 0;
    let mut msg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut args_0: ::core::ffi::VaListImpl;
    if !ctx.is_null() && !fmt.is_null() && (*ctx).pid == -(1 as libc::c_int) {
        args_0 = args.clone();
        xvasprintf(&mut msg, fmt, args_0.as_va_list());
        writemsg(msg);
        free(msg as *mut libc::c_void);
    }
    if ctx.is_null() || (*ctx).pid <= 0 as libc::c_int {
        free(ctx as *mut libc::c_void);
        return;
    }
    kill((*ctx).pid, 15 as libc::c_int);
    loop {
        ret = waitpid((*ctx).pid, 0 as *mut libc::c_int, 0 as libc::c_int);
        if !(ret == -(1 as libc::c_int)) {
            break;
        }
        if *__errno_location() != 4 as libc::c_int {
            break;
        }
    }
    if ret == -(1 as libc::c_int) {
        sshfatal(
            b"readpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"notify_complete\0"))
                .as_ptr(),
            329 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"waitpid: %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
    }
    ssh_signal(17 as libc::c_int, (*ctx).osigchld);
    free(ctx as *mut libc::c_void);
}
