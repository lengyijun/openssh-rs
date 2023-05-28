use ::libc;
use libc::close;
extern "C" {

    fn chown(__file: *const libc::c_char, __owner: __uid_t, __group: __gid_t) -> libc::c_int;
    fn setsid() -> __pid_t;
    fn ttyname(__fd: libc::c_int) -> *mut libc::c_char;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn ioctl(__fd: libc::c_int, __request: libc::c_ulong, _: ...) -> libc::c_int;

    fn getgrnam(__name: *const libc::c_char) -> *mut group;
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
    fn openpty(
        __amaster: *mut libc::c_int,
        __aslave: *mut libc::c_int,
        __name: *mut libc::c_char,
        __termp: *const termios,
        __winp: *const winsize,
    ) -> libc::c_int;
}
pub type __u_int = libc::c_uint;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type u_int = __u_int;
pub type gid_t = __gid_t;
pub type mode_t = __mode_t;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
pub type cc_t = libc::c_uchar;
pub type speed_t = libc::c_uint;
pub type tcflag_t = libc::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; 32],
    pub c_ispeed: speed_t,
    pub c_ospeed: speed_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct passwd {
    pub pw_name: *mut libc::c_char,
    pub pw_passwd: *mut libc::c_char,
    pub pw_uid: __uid_t,
    pub pw_gid: __gid_t,
    pub pw_gecos: *mut libc::c_char,
    pub pw_dir: *mut libc::c_char,
    pub pw_shell: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct winsize {
    pub ws_row: libc::c_ushort,
    pub ws_col: libc::c_ushort,
    pub ws_xpixel: libc::c_ushort,
    pub ws_ypixel: libc::c_ushort,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct group {
    pub gr_name: *mut libc::c_char,
    pub gr_passwd: *mut libc::c_char,
    pub gr_gid: __gid_t,
    pub gr_mem: *mut *mut libc::c_char,
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
pub unsafe extern "C" fn pty_allocate(
    mut ptyfd: *mut libc::c_int,
    mut ttyfd: *mut libc::c_int,
    mut namebuf: *mut libc::c_char,
    mut namebuflen: size_t,
) -> libc::c_int {
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: libc::c_int = 0;
    i = openpty(
        ptyfd,
        ttyfd,
        0 as *mut libc::c_char,
        0 as *const termios,
        0 as *const winsize,
    );
    if i == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshpty.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"pty_allocate\0")).as_ptr(),
            73 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"openpty: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        return 0 as libc::c_int;
    }
    name = ttyname(*ttyfd);
    if name.is_null() {
        sshfatal(
            b"sshpty.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"pty_allocate\0")).as_ptr(),
            78 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"openpty returns device for which ttyname fails.\0" as *const u8
                as *const libc::c_char,
        );
    }
    strlcpy(namebuf, name, namebuflen);
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn pty_release(mut _tty: *const libc::c_char) {}
pub unsafe extern "C" fn pty_make_controlling_tty(
    mut ttyfd: *mut libc::c_int,
    mut tty: *const libc::c_char,
) {
    let mut fd: libc::c_int = 0;
    fd = libc::open(
        b"/dev/tty\0" as *const u8 as *const libc::c_char,
        0o2 as libc::c_int | 0o400 as libc::c_int,
    );
    if fd >= 0 as libc::c_int {
        ioctl(
            fd,
            0x5422 as libc::c_int as libc::c_ulong,
            0 as *mut libc::c_void,
        );
        close(fd);
    }
    if setsid() == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshpty.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"pty_make_controlling_tty\0",
            ))
            .as_ptr(),
            113 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"setsid: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    fd = libc::open(
        b"/dev/tty\0" as *const u8 as *const libc::c_char,
        0o2 as libc::c_int | 0o400 as libc::c_int,
    );
    if fd >= 0 as libc::c_int {
        crate::log::sshlog(
            b"sshpty.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"pty_make_controlling_tty\0",
            ))
            .as_ptr(),
            121 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Failed to disconnect from controlling tty.\0" as *const u8 as *const libc::c_char,
        );
        close(fd);
    }
    crate::log::sshlog(
        b"sshpty.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"pty_make_controlling_tty\0"))
            .as_ptr(),
        126 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Setting controlling tty using TIOCSCTTY.\0" as *const u8 as *const libc::c_char,
    );
    if ioctl(
        *ttyfd,
        0x540e as libc::c_int as libc::c_ulong,
        0 as *mut libc::c_void,
    ) < 0 as libc::c_int
    {
        crate::log::sshlog(
            b"sshpty.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"pty_make_controlling_tty\0",
            ))
            .as_ptr(),
            128 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"ioctl(TIOCSCTTY): %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    fd = libc::open(tty, 0o2 as libc::c_int);
    if fd == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshpty.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"pty_make_controlling_tty\0",
            ))
            .as_ptr(),
            136 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%.100s: %.100s\0" as *const u8 as *const libc::c_char,
            tty,
            strerror(*libc::__errno_location()),
        );
    } else {
        close(fd);
    }
    fd = libc::open(
        b"/dev/tty\0" as *const u8 as *const libc::c_char,
        0o1 as libc::c_int,
    );
    if fd == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshpty.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"pty_make_controlling_tty\0",
            ))
            .as_ptr(),
            144 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"open /dev/tty failed - could not set controlling tty: %.100s\0" as *const u8
                as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    } else {
        close(fd);
    };
}
pub unsafe extern "C" fn pty_change_window_size(
    mut ptyfd: libc::c_int,
    mut row: u_int,
    mut col: u_int,
    mut xpixel: u_int,
    mut ypixel: u_int,
) {
    let mut w: winsize = winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    w.ws_row = row as libc::c_ushort;
    w.ws_col = col as libc::c_ushort;
    w.ws_xpixel = xpixel as libc::c_ushort;
    w.ws_ypixel = ypixel as libc::c_ushort;
    ioctl(
        ptyfd,
        0x5414 as libc::c_int as libc::c_ulong,
        &mut w as *mut winsize,
    );
}
pub unsafe extern "C" fn pty_setowner(mut pw: *mut passwd, mut tty: *const libc::c_char) {
    let mut grp: *mut group = 0 as *mut group;
    let mut gid: gid_t = 0;
    let mut mode: mode_t = 0;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    grp = getgrnam(b"tty\0" as *const u8 as *const libc::c_char);
    if grp.is_null() {
        crate::log::sshlog(
            b"sshpty.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"pty_setowner\0")).as_ptr(),
            176 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s: no tty group\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"pty_setowner\0")).as_ptr(),
        );
    }
    gid = if !grp.is_null() {
        (*grp).gr_gid
    } else {
        (*pw).pw_gid
    };
    mode = (if !grp.is_null() {
        0o620 as libc::c_int
    } else {
        0o600 as libc::c_int
    }) as mode_t;
    if libc::stat(tty, &mut st) == -(1 as libc::c_int) {
        sshfatal(
            b"sshpty.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"pty_setowner\0")).as_ptr(),
            187 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::stat(%.100s) failed: %.100s\0" as *const u8 as *const libc::c_char,
            tty,
            strerror(*libc::__errno_location()),
        );
    }
    if st.st_uid != (*pw).pw_uid || st.st_gid != gid {
        if chown(tty, (*pw).pw_uid, gid) == -(1 as libc::c_int) {
            if *libc::__errno_location() == 30 as libc::c_int
                && (st.st_uid == (*pw).pw_uid || st.st_uid == 0 as libc::c_int as libc::c_uint)
            {
                crate::log::sshlog(
                    b"sshpty.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"pty_setowner\0"))
                        .as_ptr(),
                    199 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"chown(%.100s, %u, %u) failed: %.100s\0" as *const u8 as *const libc::c_char,
                    tty,
                    (*pw).pw_uid,
                    gid,
                    strerror(*libc::__errno_location()),
                );
            } else {
                sshfatal(
                    b"sshpty.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"pty_setowner\0"))
                        .as_ptr(),
                    203 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"chown(%.100s, %u, %u) failed: %.100s\0" as *const u8 as *const libc::c_char,
                    tty,
                    (*pw).pw_uid,
                    gid,
                    strerror(*libc::__errno_location()),
                );
            }
        }
    }
    if st.st_mode
        & (0o400 as libc::c_int
            | 0o200 as libc::c_int
            | 0o100 as libc::c_int
            | (0o400 as libc::c_int | 0o200 as libc::c_int | 0o100 as libc::c_int)
                >> 3 as libc::c_int
            | (0o400 as libc::c_int | 0o200 as libc::c_int | 0o100 as libc::c_int)
                >> 3 as libc::c_int
                >> 3 as libc::c_int) as libc::c_uint
        != mode
    {
        if libc::chmod(tty, mode) == -(1 as libc::c_int) {
            if *libc::__errno_location() == 30 as libc::c_int
                && st.st_mode
                    & (0o400 as libc::c_int >> 3 as libc::c_int
                        | 0o400 as libc::c_int >> 3 as libc::c_int >> 3 as libc::c_int)
                        as libc::c_uint
                    == 0 as libc::c_int as libc::c_uint
            {
                crate::log::sshlog(
                    b"sshpty.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"pty_setowner\0"))
                        .as_ptr(),
                    212 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"chmod(%.100s, 0%o) failed: %.100s\0" as *const u8 as *const libc::c_char,
                    tty,
                    mode,
                    strerror(*libc::__errno_location()),
                );
            } else {
                sshfatal(
                    b"sshpty.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"pty_setowner\0"))
                        .as_ptr(),
                    215 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"chmod(%.100s, 0%o) failed: %.100s\0" as *const u8 as *const libc::c_char,
                    tty,
                    mode,
                    strerror(*libc::__errno_location()),
                );
            }
        }
    }
}
pub unsafe extern "C" fn disconnect_controlling_tty() {
    let mut fd: libc::c_int = 0;
    fd = libc::open(
        b"/dev/tty\0" as *const u8 as *const libc::c_char,
        0o2 as libc::c_int | 0o400 as libc::c_int,
    );
    if fd >= 0 as libc::c_int {
        ioctl(
            fd,
            0x5422 as libc::c_int as libc::c_ulong,
            0 as *mut libc::c_void,
        );
        close(fd);
    }
}
