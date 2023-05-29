use crate::atomicio::atomicio;
use ::libc;

extern "C" {

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;

    fn sshbuf_reserve(
        buf: *mut crate::sshbuf::sshbuf,
        len: size_t,
        dpp: *mut *mut u_char,
    ) -> libc::c_int;
    fn sshbuf_mutable_ptr(buf: *const crate::sshbuf::sshbuf) -> *mut u_char;
    fn sshbuf_len(buf: *const crate::sshbuf::sshbuf) -> size_t;
    fn sshbuf_max_size(buf: *const crate::sshbuf::sshbuf) -> size_t;
    fn sshbuf_reset(buf: *mut crate::sshbuf::sshbuf);
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;

    fn get_u32(_: *const libc::c_void) -> u_int32_t;
    fn put_u32(_: *mut libc::c_void, _: u_int32_t);
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint32_t = libc::c_uint;
pub type __ssize_t = libc::c_long;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
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
pub unsafe extern "C" fn ssh_msg_send(
    mut fd: libc::c_int,
    mut type_0: u_char,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut buf: [u_char; 5] = [0; 5];
    let mut mlen: u_int = sshbuf_len(m) as u_int;
    crate::log::sshlog(
        b"msg.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_msg_send\0")).as_ptr(),
        50 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"type %u\0" as *const u8 as *const libc::c_char,
        type_0 as libc::c_uint & 0xff as libc::c_int as libc::c_uint,
    );
    put_u32(
        buf.as_mut_ptr() as *mut libc::c_void,
        mlen.wrapping_add(1 as libc::c_int as libc::c_uint),
    );
    buf[4 as libc::c_int as usize] = type_0;
    if atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        fd,
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 5]>() as libc::c_ulong,
    ) != ::core::mem::size_of::<[u_char; 5]>() as libc::c_ulong
    {
        crate::log::sshlog(
            b"msg.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_msg_send\0")).as_ptr(),
            55 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"write: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        fd,
        sshbuf_mutable_ptr(m) as *mut libc::c_void,
        mlen as size_t,
    ) != mlen as libc::c_ulong
    {
        crate::log::sshlog(
            b"msg.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_msg_send\0")).as_ptr(),
            59 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"write: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_msg_recv(
    mut fd: libc::c_int,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut buf: [u_char; 4] = [0; 4];
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut msg_len: u_int = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"msg.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_msg_recv\0")).as_ptr(),
        72 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"ssh_msg_recv entering\0" as *const u8 as *const libc::c_char,
    );
    if atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        fd,
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 4]>() as libc::c_ulong,
    ) != ::core::mem::size_of::<[u_char; 4]>() as libc::c_ulong
    {
        if *libc::__errno_location() != 32 as libc::c_int {
            crate::log::sshlog(
                b"msg.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_msg_recv\0"))
                    .as_ptr(),
                76 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"read header: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        return -(1 as libc::c_int);
    }
    msg_len = get_u32(buf.as_mut_ptr() as *const libc::c_void);
    if msg_len as libc::c_ulong > sshbuf_max_size(m) {
        crate::log::sshlog(
            b"msg.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_msg_recv\0")).as_ptr(),
            81 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"read: bad msg_len %u\0" as *const u8 as *const libc::c_char,
            msg_len,
        );
        return -(1 as libc::c_int);
    }
    sshbuf_reset(m);
    r = sshbuf_reserve(m, msg_len as size_t, &mut p);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"msg.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_msg_recv\0")).as_ptr(),
            86 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"reserve\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        fd,
        p as *mut libc::c_void,
        msg_len as size_t,
    ) != msg_len as libc::c_ulong
    {
        crate::log::sshlog(
            b"msg.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_msg_recv\0")).as_ptr(),
            90 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"read: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
