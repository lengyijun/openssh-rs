use ::libc;
extern "C" {
    fn sendmsg(__fd: libc::c_int, __message: *const msghdr, __flags: libc::c_int) -> ssize_t;
    fn recvmsg(__fd: libc::c_int, __message: *mut msghdr, __flags: libc::c_int) -> ssize_t;
    fn __errno_location() -> *mut libc::c_int;
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: libc::c_int) -> libc::c_int;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
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
pub type __ssize_t = libc::c_long;
pub type __caddr_t = *mut libc::c_char;
pub type __socklen_t = libc::c_uint;
pub type ssize_t = __ssize_t;
pub type caddr_t = __caddr_t;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct iovec {
    pub iov_base: *mut libc::c_void,
    pub iov_len: size_t,
}
pub type socklen_t = __socklen_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct msghdr {
    pub msg_name: *mut libc::c_void,
    pub msg_namelen: socklen_t,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: size_t,
    pub msg_control: *mut libc::c_void,
    pub msg_controllen: size_t,
    pub msg_flags: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cmsghdr {
    pub cmsg_len: size_t,
    pub cmsg_level: libc::c_int,
    pub cmsg_type: libc::c_int,
    pub __cmsg_data: [libc::c_uchar; 0],
}
pub type C2RustUnnamed = libc::c_uint;
pub const SCM_CREDENTIALS: C2RustUnnamed = 2;
pub const SCM_RIGHTS: C2RustUnnamed = 1;
pub type nfds_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: libc::c_int,
    pub events: libc::c_short,
    pub revents: libc::c_short,
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
pub union C2RustUnnamed_0 {
    pub hdr: cmsghdr,
    pub buf: [libc::c_char; 24],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub hdr: cmsghdr,
    pub buf: [libc::c_char; 24],
}
pub unsafe extern "C" fn mm_send_fd(mut sock: libc::c_int, mut fd: libc::c_int) -> libc::c_int {
    let mut msg: msghdr = msghdr {
        msg_name: 0 as *mut libc::c_void,
        msg_namelen: 0,
        msg_iov: 0 as *mut iovec,
        msg_iovlen: 0,
        msg_control: 0 as *mut libc::c_void,
        msg_controllen: 0,
        msg_flags: 0,
    };
    let mut cmsgbuf: C2RustUnnamed_0 = C2RustUnnamed_0 {
        hdr: cmsghdr {
            cmsg_len: 0,
            cmsg_level: 0,
            cmsg_type: 0,
            __cmsg_data: [],
        },
    };
    let mut cmsg: *mut cmsghdr = 0 as *mut cmsghdr;
    let mut vec: iovec = iovec {
        iov_base: 0 as *mut libc::c_void,
        iov_len: 0,
    };
    let mut ch: libc::c_char = '\0' as i32 as libc::c_char;
    let mut n: ssize_t = 0;
    let mut pfd: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    memset(
        &mut msg as *mut msghdr as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<msghdr>() as libc::c_ulong,
    );
    memset(
        &mut cmsgbuf as *mut C2RustUnnamed_0 as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<C2RustUnnamed_0>() as libc::c_ulong,
    );
    msg.msg_control = &mut cmsgbuf.buf as *mut [libc::c_char; 24] as caddr_t as *mut libc::c_void;
    msg.msg_controllen = ::core::mem::size_of::<[libc::c_char; 24]>() as libc::c_ulong;
    cmsg = if msg.msg_controllen >= ::core::mem::size_of::<cmsghdr>() as libc::c_ulong {
        msg.msg_control as *mut cmsghdr
    } else {
        0 as *mut cmsghdr
    };
    (*cmsg).cmsg_len = ((::core::mem::size_of::<cmsghdr>() as libc::c_ulong)
        .wrapping_add(::core::mem::size_of::<size_t>() as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        & !(::core::mem::size_of::<size_t>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong))
    .wrapping_add(::core::mem::size_of::<libc::c_int>() as libc::c_ulong);
    (*cmsg).cmsg_level = 1 as libc::c_int;
    (*cmsg).cmsg_type = SCM_RIGHTS as libc::c_int;
    *(((*cmsg).__cmsg_data).as_mut_ptr() as *mut libc::c_int) = fd;
    vec.iov_base = &mut ch as *mut libc::c_char as *mut libc::c_void;
    vec.iov_len = 1 as libc::c_int as size_t;
    msg.msg_iov = &mut vec;
    msg.msg_iovlen = 1 as libc::c_int as size_t;
    pfd.fd = sock;
    pfd.events = 0x4 as libc::c_int as libc::c_short;
    loop {
        n = sendmsg(sock, &mut msg, 0 as libc::c_int);
        if !(n == -(1 as libc::c_int) as libc::c_long
            && (*__errno_location() == 11 as libc::c_int
                || *__errno_location() == 4 as libc::c_int))
        {
            break;
        }
        sshlog(
            b"monitor_fdpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"mm_send_fd\0")).as_ptr(),
            92 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"sendmsg(%d): %s\0" as *const u8 as *const libc::c_char,
            fd,
            strerror(*__errno_location()),
        );
        poll(&mut pfd, 1 as libc::c_int as nfds_t, -(1 as libc::c_int));
    }
    if n == -(1 as libc::c_int) as libc::c_long {
        sshlog(
            b"monitor_fdpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"mm_send_fd\0")).as_ptr(),
            96 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"sendmsg(%d): %s\0" as *const u8 as *const libc::c_char,
            fd,
            strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if n != 1 as libc::c_int as libc::c_long {
        sshlog(
            b"monitor_fdpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"mm_send_fd\0")).as_ptr(),
            101 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"sendmsg: expected sent 1 got %zd\0" as *const u8 as *const libc::c_char,
            n,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn mm_receive_fd(mut sock: libc::c_int) -> libc::c_int {
    let mut msg: msghdr = msghdr {
        msg_name: 0 as *mut libc::c_void,
        msg_namelen: 0,
        msg_iov: 0 as *mut iovec,
        msg_iovlen: 0,
        msg_control: 0 as *mut libc::c_void,
        msg_controllen: 0,
        msg_flags: 0,
    };
    let mut cmsgbuf: C2RustUnnamed_1 = C2RustUnnamed_1 {
        hdr: cmsghdr {
            cmsg_len: 0,
            cmsg_level: 0,
            cmsg_type: 0,
            __cmsg_data: [],
        },
    };
    let mut cmsg: *mut cmsghdr = 0 as *mut cmsghdr;
    let mut vec: iovec = iovec {
        iov_base: 0 as *mut libc::c_void,
        iov_len: 0,
    };
    let mut n: ssize_t = 0;
    let mut ch: libc::c_char = 0;
    let mut fd: libc::c_int = 0;
    let mut pfd: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    memset(
        &mut msg as *mut msghdr as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<msghdr>() as libc::c_ulong,
    );
    vec.iov_base = &mut ch as *mut libc::c_char as *mut libc::c_void;
    vec.iov_len = 1 as libc::c_int as size_t;
    msg.msg_iov = &mut vec;
    msg.msg_iovlen = 1 as libc::c_int as size_t;
    memset(
        &mut cmsgbuf as *mut C2RustUnnamed_1 as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<C2RustUnnamed_1>() as libc::c_ulong,
    );
    msg.msg_control = &mut cmsgbuf.buf as *mut [libc::c_char; 24] as *mut libc::c_void;
    msg.msg_controllen = ::core::mem::size_of::<[libc::c_char; 24]>() as libc::c_ulong;
    pfd.fd = sock;
    pfd.events = 0x1 as libc::c_int as libc::c_short;
    loop {
        n = recvmsg(sock, &mut msg, 0 as libc::c_int);
        if !(n == -(1 as libc::c_int) as libc::c_long
            && (*__errno_location() == 11 as libc::c_int
                || *__errno_location() == 4 as libc::c_int))
        {
            break;
        }
        sshlog(
            b"monitor_fdpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_receive_fd\0"))
                .as_ptr(),
            147 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"recvmsg: %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        poll(&mut pfd, 1 as libc::c_int as nfds_t, -(1 as libc::c_int));
    }
    if n == -(1 as libc::c_int) as libc::c_long {
        sshlog(
            b"monitor_fdpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_receive_fd\0"))
                .as_ptr(),
            151 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"recvmsg: %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if n != 1 as libc::c_int as libc::c_long {
        sshlog(
            b"monitor_fdpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_receive_fd\0"))
                .as_ptr(),
            156 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"recvmsg: expected received 1 got %zd\0" as *const u8 as *const libc::c_char,
            n,
        );
        return -(1 as libc::c_int);
    }
    cmsg = if msg.msg_controllen >= ::core::mem::size_of::<cmsghdr>() as libc::c_ulong {
        msg.msg_control as *mut cmsghdr
    } else {
        0 as *mut cmsghdr
    };
    if cmsg.is_null() {
        sshlog(
            b"monitor_fdpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_receive_fd\0"))
                .as_ptr(),
            168 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no message header\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if (*cmsg).cmsg_type != SCM_RIGHTS as libc::c_int {
        sshlog(
            b"monitor_fdpass.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_receive_fd\0"))
                .as_ptr(),
            174 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"expected %d got %d\0" as *const u8 as *const libc::c_char,
            SCM_RIGHTS as libc::c_int,
            (*cmsg).cmsg_type,
        );
        return -(1 as libc::c_int);
    }
    fd = *(((*cmsg).__cmsg_data).as_mut_ptr() as *mut libc::c_int);
    return fd;
}
