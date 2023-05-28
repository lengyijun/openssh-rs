use crate::atomicio::atomicio;
use crate::sftp_common::Attrib;
use ::libc;
use libc::close;

extern "C" {
    pub type sshbuf;
    pub type __dirstream;

    fn lseek(__fd: libc::c_int, __offset: __off_t, __whence: libc::c_int) -> __off_t;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn fsync(__fd: libc::c_int) -> libc::c_int;
    fn ftruncate(__fd: libc::c_int, __length: __off_t) -> libc::c_int;
    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: libc::c_int) -> libc::c_int;

    fn lstat(__file: *const libc::c_char, __buf: *mut libc::stat) -> libc::c_int;
    fn writev(__fd: libc::c_int, __iovec: *const iovec, __count: libc::c_int) -> ssize_t;
    fn opendir(__name: *const libc::c_char) -> *mut DIR;
    fn closedir(__dirp: *mut DIR) -> libc::c_int;
    fn readdir(__dirp: *mut DIR) -> *mut dirent;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strpbrk(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn xmalloc(_: size_t) -> *mut libc::c_void;
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn xreallocarray(_: *mut libc::c_void, _: size_t, _: size_t) -> *mut libc::c_void;
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn sshbuf_put_stringb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_string(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_string(
        buf: *mut sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_u8(buf: *mut sshbuf, val: u_char) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_put_u64(buf: *mut sshbuf, val: u_int64_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_get_u64(buf: *mut sshbuf, valp: *mut u_int64_t) -> libc::c_int;
    fn sshbuf_reserve(buf: *mut sshbuf, len: size_t, dpp: *mut *mut u_char) -> libc::c_int;
    fn sshbuf_ptr(buf: *const sshbuf) -> *const u_char;
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_reset(buf: *mut sshbuf);
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_froms(buf: *mut sshbuf, bufp: *mut *mut sshbuf) -> libc::c_int;
    fn sshbuf_new() -> *mut sshbuf;

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
    fn atomicio6(
        f: Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        fd: libc::c_int,
        _s: *mut libc::c_void,
        n: size_t,
        cb: Option<unsafe extern "C" fn(*mut libc::c_void, size_t) -> libc::c_int>,
        _: *mut libc::c_void,
    ) -> size_t;

    fn atomiciov6(
        f: Option<unsafe extern "C" fn(libc::c_int, *const iovec, libc::c_int) -> ssize_t>,
        fd: libc::c_int,
        _iov: *const iovec,
        iovcnt: libc::c_int,
        cb: Option<unsafe extern "C" fn(*mut libc::c_void, size_t) -> libc::c_int>,
        _: *mut libc::c_void,
    ) -> size_t;
    fn start_progress_meter(_: *const libc::c_char, _: off_t, _: *mut off_t);
    fn refresh_progress_meter(_: libc::c_int);
    fn stop_progress_meter();
    fn path_absolute(_: *const libc::c_char) -> libc::c_int;
    fn put_u32(_: *mut libc::c_void, _: u_int32_t);

    
    fn mprintf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn attrib_clear(_: *mut Attrib);
    fn stat_to_attrib(_: *const libc::stat, _: *mut Attrib);
    fn decode_attrib(_: *mut sshbuf, _: *mut Attrib) -> libc::c_int;
    fn encode_attrib(_: *mut sshbuf, _: *const Attrib) -> libc::c_int;
    fn fx2txt(_: libc::c_int) -> *const libc::c_char;
    static mut interrupted: sig_atomic_t;
    static mut showprogress: libc::c_int;
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
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type off_t = __off_t;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct iovec {
    pub iov_base: *mut libc::c_void,
    pub iov_len: size_t,
}
pub type uint64_t = __uint64_t;

pub type sig_atomic_t = __sig_atomic_t;
pub type va_list = __builtin_va_list;
pub type nfds_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: libc::c_int,
    pub events: libc::c_short,
    pub revents: libc::c_short,
}
pub type C2RustUnnamed = libc::c_uint;
pub const ST_RELATIME: C2RustUnnamed = 4096;
pub const ST_NODIRATIME: C2RustUnnamed = 2048;
pub const ST_NOATIME: C2RustUnnamed = 1024;
pub const ST_IMMUTABLE: C2RustUnnamed = 512;
pub const ST_APPEND: C2RustUnnamed = 256;
pub const ST_WRITE: C2RustUnnamed = 128;
pub const ST_MANDLOCK: C2RustUnnamed = 64;
pub const ST_SYNCHRONOUS: C2RustUnnamed = 16;
pub const ST_NOEXEC: C2RustUnnamed = 8;
pub const ST_NODEV: C2RustUnnamed = 4;
pub const ST_NOSUID: C2RustUnnamed = 2;
pub const ST_RDONLY: C2RustUnnamed = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dirent {
    pub d_ino: __ino_t,
    pub d_off: __off_t,
    pub d_reclen: libc::c_ushort,
    pub d_type: libc::c_uchar,
    pub d_name: [libc::c_char; 256],
}
pub type DIR = __dirstream;
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
pub struct SFTP_DIRENT {
    pub filename: *mut libc::c_char,
    pub longname: *mut libc::c_char,
    pub a: Attrib,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sftp_statvfs {
    pub f_bsize: u_int64_t,
    pub f_frsize: u_int64_t,
    pub f_blocks: u_int64_t,
    pub f_bfree: u_int64_t,
    pub f_bavail: u_int64_t,
    pub f_files: u_int64_t,
    pub f_ffree: u_int64_t,
    pub f_favail: u_int64_t,
    pub f_fsid: u_int64_t,
    pub f_flag: u_int64_t,
    pub f_namemax: u_int64_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sftp_limits {
    pub packet_length: u_int64_t,
    pub read_length: u_int64_t,
    pub write_length: u_int64_t,
    pub open_handles: u_int64_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sftp_conn {
    pub fd_in: libc::c_int,
    pub fd_out: libc::c_int,
    pub download_buflen: u_int,
    pub upload_buflen: u_int,
    pub num_requests: u_int,
    pub version: u_int,
    pub msg_id: u_int,
    pub exts: u_int,
    pub limit_kbps: u_int64_t,
    pub bwlimit_in: crate::misc::bwlimit,
    pub bwlimit_out: crate::misc::bwlimit,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct request {
    pub id: u_int,
    pub len: size_t,
    pub offset: u_int64_t,
    pub tq: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub tqe_next: *mut request,
    pub tqe_prev: *mut *mut request,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct requests {
    pub tqh_first: *mut request,
    pub tqh_last: *mut *mut request,
}
unsafe extern "C" fn request_enqueue(
    mut requests: *mut requests,
    mut id: u_int,
    mut len: size_t,
    mut offset: uint64_t,
) -> *mut request {
    let mut req: *mut request = 0 as *mut request;
    req = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<request>() as libc::c_ulong,
    ) as *mut request;
    (*req).id = id;
    (*req).len = len;
    (*req).offset = offset;
    (*req).tq.tqe_next = 0 as *mut request;
    (*req).tq.tqe_prev = (*requests).tqh_last;
    *(*requests).tqh_last = req;
    (*requests).tqh_last = &mut (*req).tq.tqe_next;
    return req;
}
unsafe extern "C" fn request_find(mut requests: *mut requests, mut id: u_int) -> *mut request {
    let mut req: *mut request = 0 as *mut request;
    req = (*requests).tqh_first;
    while !req.is_null() && (*req).id != id {
        req = (*req).tq.tqe_next;
    }
    return req;
}
unsafe extern "C" fn sftpio(mut _bwlimit: *mut libc::c_void, mut amount: size_t) -> libc::c_int {
    let mut bwlimit: *mut crate::misc::bwlimit = _bwlimit as *mut crate::misc::bwlimit;
    refresh_progress_meter(0 as libc::c_int);
    if !bwlimit.is_null() {
        crate::misc::bandwidth_limit(bwlimit, amount);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn send_msg(mut conn: *mut sftp_conn, mut m: *mut sshbuf) {
    let mut mlen: [u_char; 4] = [0; 4];
    let mut iov: [iovec; 2] = [iovec {
        iov_base: 0 as *mut libc::c_void,
        iov_len: 0,
    }; 2];
    if sshbuf_len(m) > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_ulong {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"send_msg\0")).as_ptr(),
            170 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Outbound message too long %zu\0" as *const u8 as *const libc::c_char,
            sshbuf_len(m),
        );
    }
    put_u32(
        mlen.as_mut_ptr() as *mut libc::c_void,
        sshbuf_len(m) as u_int32_t,
    );
    iov[0 as libc::c_int as usize].iov_base = mlen.as_mut_ptr() as *mut libc::c_void;
    iov[0 as libc::c_int as usize].iov_len = ::core::mem::size_of::<[u_char; 4]>() as libc::c_ulong;
    iov[1 as libc::c_int as usize].iov_base = sshbuf_ptr(m) as *mut u_char as *mut libc::c_void;
    iov[1 as libc::c_int as usize].iov_len = sshbuf_len(m);
    if atomiciov6(
        Some(writev as unsafe extern "C" fn(libc::c_int, *const iovec, libc::c_int) -> ssize_t),
        (*conn).fd_out,
        iov.as_mut_ptr(),
        2 as libc::c_int,
        Some(sftpio as unsafe extern "C" fn(*mut libc::c_void, size_t) -> libc::c_int),
        (if (*conn).limit_kbps > 0 as libc::c_int as libc::c_ulong {
            &mut (*conn).bwlimit_out as *mut crate::misc::bwlimit
        } else {
            0 as *mut crate::misc::bwlimit
        }) as *mut libc::c_void,
    ) != (sshbuf_len(m)).wrapping_add(::core::mem::size_of::<[u_char; 4]>() as libc::c_ulong)
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"send_msg\0")).as_ptr(),
            182 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Couldn't send packet: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    sshbuf_reset(m);
}
unsafe extern "C" fn get_msg_extended(
    mut conn: *mut sftp_conn,
    mut m: *mut sshbuf,
    mut initial: libc::c_int,
) {
    let mut msg_len: u_int = 0;
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    sshbuf_reset(m);
    r = sshbuf_reserve(m, 4 as libc::c_int as size_t, &mut p);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"get_msg_extended\0"))
                .as_ptr(),
            196 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"reserve\0" as *const u8 as *const libc::c_char,
        );
    }
    if atomicio6(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        (*conn).fd_in,
        p as *mut libc::c_void,
        4 as libc::c_int as size_t,
        Some(sftpio as unsafe extern "C" fn(*mut libc::c_void, size_t) -> libc::c_int),
        (if (*conn).limit_kbps > 0 as libc::c_int as libc::c_ulong {
            &mut (*conn).bwlimit_in as *mut crate::misc::bwlimit
        } else {
            0 as *mut crate::misc::bwlimit
        }) as *mut libc::c_void,
    ) != 4 as libc::c_int as libc::c_ulong
    {
        if *libc::__errno_location() == 32 as libc::c_int
            || *libc::__errno_location() == 104 as libc::c_int
        {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"get_msg_extended\0"))
                    .as_ptr(),
                200 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Connection closed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"get_msg_extended\0"))
                    .as_ptr(),
                202 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Couldn't read packet: %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
    }
    r = sshbuf_get_u32(m, &mut msg_len);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"get_msg_extended\0"))
                .as_ptr(),
            206 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"sshbuf_get_u32\0" as *const u8 as *const libc::c_char,
        );
    }
    if msg_len > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"get_msg_extended\0"))
                .as_ptr(),
            209 as libc::c_int,
            0 as libc::c_int,
            (if initial != 0 {
                SYSLOG_LEVEL_ERROR as libc::c_int
            } else {
                SYSLOG_LEVEL_FATAL as libc::c_int
            }) as LogLevel,
            0 as *const libc::c_char,
            b"Received message too long %u\0" as *const u8 as *const libc::c_char,
            msg_len,
        );
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"get_msg_extended\0"))
                .as_ptr(),
            211 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Ensure the remote shell produces no output for non-interactive sessions.\0"
                as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_reserve(m, msg_len as size_t, &mut p);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"get_msg_extended\0"))
                .as_ptr(),
            215 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"reserve\0" as *const u8 as *const libc::c_char,
        );
    }
    if atomicio6(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        (*conn).fd_in,
        p as *mut libc::c_void,
        msg_len as size_t,
        Some(sftpio as unsafe extern "C" fn(*mut libc::c_void, size_t) -> libc::c_int),
        (if (*conn).limit_kbps > 0 as libc::c_int as libc::c_ulong {
            &mut (*conn).bwlimit_in as *mut crate::misc::bwlimit
        } else {
            0 as *mut crate::misc::bwlimit
        }) as *mut libc::c_void,
    ) != msg_len as libc::c_ulong
    {
        if *libc::__errno_location() == 32 as libc::c_int {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"get_msg_extended\0"))
                    .as_ptr(),
                220 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Connection closed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"get_msg_extended\0"))
                    .as_ptr(),
                222 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Read packet: %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
    }
}
unsafe extern "C" fn get_msg(mut conn: *mut sftp_conn, mut m: *mut sshbuf) {
    get_msg_extended(conn, m, 0 as libc::c_int);
}
unsafe extern "C" fn send_string_request(
    mut conn: *mut sftp_conn,
    mut id: u_int,
    mut code: u_int,
    mut s: *const libc::c_char,
    mut len: u_int,
) {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"send_string_request\0"))
                .as_ptr(),
            240 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u8(msg, code as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(msg, s as *const libc::c_void, len as size_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"send_string_request\0"))
                .as_ptr(),
            244 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"send_string_request\0"))
            .as_ptr(),
        246 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Sent message fd %d T:%u I:%u\0" as *const u8 as *const libc::c_char,
        (*conn).fd_out,
        code,
        id,
    );
    sshbuf_free(msg);
}
unsafe extern "C" fn send_string_attrs_request(
    mut conn: *mut sftp_conn,
    mut id: u_int,
    mut code: u_int,
    mut s: *const libc::c_void,
    mut len: u_int,
    mut a: *mut Attrib,
) {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"send_string_attrs_request\0",
            ))
            .as_ptr(),
            258 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u8(msg, code as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(msg, s, len as size_t);
            r != 0 as libc::c_int
        }
        || {
            r = encode_attrib(msg, a);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"send_string_attrs_request\0",
            ))
            .as_ptr(),
            263 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"send_string_attrs_request\0"))
            .as_ptr(),
        266 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Sent message fd %d T:%u I:%u F:0x%04x M:%05o\0" as *const u8 as *const libc::c_char,
        (*conn).fd_out,
        code,
        id,
        (*a).flags,
        (*a).perm,
    );
    sshbuf_free(msg);
}
unsafe extern "C" fn get_status(mut conn: *mut sftp_conn, mut expected_id: u_int) -> u_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut type_0: u_char = 0;
    let mut id: u_int = 0;
    let mut status: u_int = 0;
    let mut r: libc::c_int = 0;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_status\0")).as_ptr(),
            279 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    get_msg(conn, msg);
    r = sshbuf_get_u8(msg, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(msg, &mut id);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_status\0")).as_ptr(),
            283 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    if id != expected_id {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_status\0")).as_ptr(),
            286 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ID mismatch (%u != %u)\0" as *const u8 as *const libc::c_char,
            id,
            expected_id,
        );
    }
    if type_0 as libc::c_int != 101 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_status\0")).as_ptr(),
            289 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Expected SSH2_FXP_STATUS(%u) packet, got %u\0" as *const u8 as *const libc::c_char,
            101 as libc::c_int,
            type_0 as libc::c_int,
        );
    }
    r = sshbuf_get_u32(msg, &mut status);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_status\0")).as_ptr(),
            292 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_status\0")).as_ptr(),
        295 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"SSH2_FXP_STATUS %u\0" as *const u8 as *const libc::c_char,
        status,
    );
    return status;
}
unsafe extern "C" fn get_handle(
    mut conn: *mut sftp_conn,
    mut expected_id: u_int,
    mut len: *mut size_t,
    mut errfmt: *const libc::c_char,
    mut args: ...
) -> *mut u_char {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut id: u_int = 0;
    let mut status: u_int = 0;
    let mut type_0: u_char = 0;
    let mut handle: *mut u_char = 0 as *mut u_char;
    let mut errmsg: [libc::c_char; 256] = [0; 256];
    let mut args_0: ::core::ffi::VaListImpl;
    let mut r: libc::c_int = 0;
    args_0 = args.clone();
    if !errfmt.is_null() {
        vsnprintf(
            errmsg.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
            errfmt,
            args_0.as_va_list(),
        );
    }
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_handle\0")).as_ptr(),
            318 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    get_msg(conn, msg);
    r = sshbuf_get_u8(msg, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(msg, &mut id);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_handle\0")).as_ptr(),
            322 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if id != expected_id {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_handle\0")).as_ptr(),
            326 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: ID mismatch (%u != %u)\0" as *const u8 as *const libc::c_char,
            if errfmt.is_null() {
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_handle\0"))
                    .as_ptr()
            } else {
                errmsg.as_mut_ptr() as *const libc::c_char
            },
            id,
            expected_id,
        );
    }
    if type_0 as libc::c_int == 101 as libc::c_int {
        r = sshbuf_get_u32(msg, &mut status);
        if r != 0 as libc::c_int {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_handle\0"))
                    .as_ptr(),
                329 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse status\0" as *const u8 as *const libc::c_char,
            );
        }
        if !errfmt.is_null() {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_handle\0"))
                    .as_ptr(),
                331 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"%s: %s\0" as *const u8 as *const libc::c_char,
                errmsg.as_mut_ptr(),
                fx2txt(status as libc::c_int),
            );
        }
        sshbuf_free(msg);
        return 0 as *mut u_char;
    } else if type_0 as libc::c_int != 102 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_handle\0")).as_ptr(),
            336 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: Expected SSH2_FXP_HANDLE(%u) packet, got %u\0" as *const u8
                as *const libc::c_char,
            if errfmt.is_null() {
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_handle\0"))
                    .as_ptr()
            } else {
                errmsg.as_mut_ptr() as *const libc::c_char
            },
            102 as libc::c_int,
            type_0 as libc::c_int,
        );
    }
    r = sshbuf_get_string(msg, &mut handle, len);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"get_handle\0")).as_ptr(),
            339 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse handle\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(msg);
    return handle;
}
unsafe extern "C" fn get_decode_stat(
    mut conn: *mut sftp_conn,
    mut expected_id: u_int,
    mut quiet: libc::c_int,
) -> *mut Attrib {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut id: u_int = 0;
    let mut type_0: u_char = 0;
    let mut r: libc::c_int = 0;
    static mut a: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"get_decode_stat\0"))
                .as_ptr(),
            356 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    get_msg(conn, msg);
    r = sshbuf_get_u8(msg, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(msg, &mut id);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"get_decode_stat\0"))
                .as_ptr(),
            361 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if id != expected_id {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"get_decode_stat\0"))
                .as_ptr(),
            364 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ID mismatch (%u != %u)\0" as *const u8 as *const libc::c_char,
            id,
            expected_id,
        );
    }
    if type_0 as libc::c_int == 101 as libc::c_int {
        let mut status: u_int = 0;
        r = sshbuf_get_u32(msg, &mut status);
        if r != 0 as libc::c_int {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"get_decode_stat\0"))
                    .as_ptr(),
                369 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse status\0" as *const u8 as *const libc::c_char,
            );
        }
        if quiet != 0 {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"get_decode_stat\0"))
                    .as_ptr(),
                371 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"libc::stat remote: %s\0" as *const u8 as *const libc::c_char,
                fx2txt(status as libc::c_int),
            );
        } else {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"get_decode_stat\0"))
                    .as_ptr(),
                373 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"libc::stat remote: %s\0" as *const u8 as *const libc::c_char,
                fx2txt(status as libc::c_int),
            );
        }
        sshbuf_free(msg);
        return 0 as *mut Attrib;
    } else if type_0 as libc::c_int != 105 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"get_decode_stat\0"))
                .as_ptr(),
            378 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Expected SSH2_FXP_ATTRS(%u) packet, got %u\0" as *const u8 as *const libc::c_char,
            105 as libc::c_int,
            type_0 as libc::c_int,
        );
    }
    r = decode_attrib(msg, &mut a);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"get_decode_stat\0"))
                .as_ptr(),
            381 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"decode_attrib\0" as *const u8 as *const libc::c_char,
        );
        sshbuf_free(msg);
        return 0 as *mut Attrib;
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"get_decode_stat\0")).as_ptr(),
        386 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Received libc::stat reply T:%u I:%u F:0x%04x M:%05o\0" as *const u8
            as *const libc::c_char,
        type_0 as libc::c_int,
        id,
        a.flags,
        a.perm,
    );
    sshbuf_free(msg);
    return &mut a;
}
unsafe extern "C" fn get_decode_statvfs(
    mut conn: *mut sftp_conn,
    mut st: *mut sftp_statvfs,
    mut expected_id: u_int,
    mut quiet: libc::c_int,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut type_0: u_char = 0;
    let mut id: u_int = 0;
    let mut flag: u_int64_t = 0;
    let mut r: libc::c_int = 0;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"get_decode_statvfs\0"))
                .as_ptr(),
            403 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    get_msg(conn, msg);
    r = sshbuf_get_u8(msg, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(msg, &mut id);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"get_decode_statvfs\0"))
                .as_ptr(),
            408 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"get_decode_statvfs\0"))
            .as_ptr(),
        410 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Received statvfs reply T:%u I:%u\0" as *const u8 as *const libc::c_char,
        type_0 as libc::c_int,
        id,
    );
    if id != expected_id {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"get_decode_statvfs\0"))
                .as_ptr(),
            412 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ID mismatch (%u != %u)\0" as *const u8 as *const libc::c_char,
            id,
            expected_id,
        );
    }
    if type_0 as libc::c_int == 101 as libc::c_int {
        let mut status: u_int = 0;
        r = sshbuf_get_u32(msg, &mut status);
        if r != 0 as libc::c_int {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"get_decode_statvfs\0",
                ))
                .as_ptr(),
                417 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse status\0" as *const u8 as *const libc::c_char,
            );
        }
        if quiet != 0 {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"get_decode_statvfs\0",
                ))
                .as_ptr(),
                419 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"remote statvfs: %s\0" as *const u8 as *const libc::c_char,
                fx2txt(status as libc::c_int),
            );
        } else {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"get_decode_statvfs\0",
                ))
                .as_ptr(),
                421 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"remote statvfs: %s\0" as *const u8 as *const libc::c_char,
                fx2txt(status as libc::c_int),
            );
        }
        sshbuf_free(msg);
        return -(1 as libc::c_int);
    } else if type_0 as libc::c_int != 201 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"get_decode_statvfs\0"))
                .as_ptr(),
            426 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u\0" as *const u8
                as *const libc::c_char,
            201 as libc::c_int,
            type_0 as libc::c_int,
        );
    }
    memset(
        st as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sftp_statvfs>() as libc::c_ulong,
    );
    r = sshbuf_get_u64(msg, &mut (*st).f_bsize);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_u64(msg, &mut (*st).f_frsize);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(msg, &mut (*st).f_blocks);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(msg, &mut (*st).f_bfree);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(msg, &mut (*st).f_bavail);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(msg, &mut (*st).f_files);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(msg, &mut (*st).f_ffree);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(msg, &mut (*st).f_favail);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(msg, &mut (*st).f_fsid);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(msg, &mut flag);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(msg, &mut (*st).f_namemax);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"get_decode_statvfs\0"))
                .as_ptr(),
            441 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse statvfs\0" as *const u8 as *const libc::c_char,
        );
    }
    (*st).f_flag = (if flag & 0x1 as libc::c_int as libc::c_ulong != 0 {
        ST_RDONLY as libc::c_int
    } else {
        0 as libc::c_int
    }) as u_int64_t;
    (*st).f_flag |= (if flag & 0x2 as libc::c_int as libc::c_ulong != 0 {
        ST_NOSUID as libc::c_int
    } else {
        0 as libc::c_int
    }) as libc::c_ulong;
    sshbuf_free(msg);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn do_init(
    mut fd_in: libc::c_int,
    mut fd_out: libc::c_int,
    mut transfer_buflen: u_int,
    mut num_requests: u_int,
    mut limit_kbps: u_int64_t,
) -> *mut sftp_conn {
    let mut type_0: u_char = 0;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut ret: *mut sftp_conn = 0 as *mut sftp_conn;
    let mut r: libc::c_int = 0;
    ret = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<sftp_conn>() as libc::c_ulong,
    ) as *mut sftp_conn;
    (*ret).msg_id = 1 as libc::c_int as u_int;
    (*ret).fd_in = fd_in;
    (*ret).fd_out = fd_out;
    (*ret).upload_buflen = if transfer_buflen != 0 {
        transfer_buflen
    } else {
        32768 as libc::c_int as libc::c_uint
    };
    (*ret).download_buflen = (*ret).upload_buflen;
    (*ret).num_requests = if num_requests != 0 {
        num_requests
    } else {
        64 as libc::c_int as libc::c_uint
    };
    (*ret).exts = 0 as libc::c_int as u_int;
    (*ret).limit_kbps = 0 as libc::c_int as u_int64_t;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_init\0")).as_ptr(),
            472 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u8(msg, 1 as libc::c_int as u_char);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_u32(msg, 3 as libc::c_int as u_int32_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_init\0")).as_ptr(),
            475 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(ret, msg);
    get_msg_extended(ret, msg, 1 as libc::c_int);
    r = sshbuf_get_u8(msg, &mut type_0);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_init\0")).as_ptr(),
            483 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse type\0" as *const u8 as *const libc::c_char,
        );
    }
    if type_0 as libc::c_int != 2 as libc::c_int {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_init\0")).as_ptr(),
            486 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Invalid packet back from SSH2_FXP_INIT (type %u)\0" as *const u8
                as *const libc::c_char,
            type_0 as libc::c_int,
        );
        sshbuf_free(msg);
        libc::free(ret as *mut libc::c_void);
        return 0 as *mut sftp_conn;
    }
    r = sshbuf_get_u32(msg, &mut (*ret).version);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_init\0")).as_ptr(),
            492 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse version\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_init\0")).as_ptr(),
        494 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Remote version: %u\0" as *const u8 as *const libc::c_char,
        (*ret).version,
    );
    while sshbuf_len(msg) > 0 as libc::c_int as libc::c_ulong {
        let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut value: *mut u_char = 0 as *mut u_char;
        let mut vlen: size_t = 0;
        let mut known: libc::c_int = 0 as libc::c_int;
        r = sshbuf_get_cstring(msg, &mut name, 0 as *mut size_t);
        if r != 0 as libc::c_int || {
            r = sshbuf_get_string(msg, &mut value, &mut vlen);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_init\0")).as_ptr(),
                505 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse extension\0" as *const u8 as *const libc::c_char,
            );
        }
        if strcmp(
            name,
            b"posix-rename@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
            && strcmp(
                value as *mut libc::c_char,
                b"1\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            (*ret).exts |= 0x1 as libc::c_int as libc::c_uint;
            known = 1 as libc::c_int;
        } else if strcmp(
            name,
            b"statvfs@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
            && strcmp(
                value as *mut libc::c_char,
                b"2\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            (*ret).exts |= 0x2 as libc::c_int as libc::c_uint;
            known = 1 as libc::c_int;
        } else if strcmp(
            name,
            b"fstatvfs@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
            && strcmp(
                value as *mut libc::c_char,
                b"2\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            (*ret).exts |= 0x4 as libc::c_int as libc::c_uint;
            known = 1 as libc::c_int;
        } else if strcmp(
            name,
            b"hardlink@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
            && strcmp(
                value as *mut libc::c_char,
                b"1\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            (*ret).exts |= 0x8 as libc::c_int as libc::c_uint;
            known = 1 as libc::c_int;
        } else if strcmp(
            name,
            b"fsync@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
            && strcmp(
                value as *mut libc::c_char,
                b"1\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            (*ret).exts |= 0x10 as libc::c_int as libc::c_uint;
            known = 1 as libc::c_int;
        } else if strcmp(
            name,
            b"lsetstat@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
            && strcmp(
                value as *mut libc::c_char,
                b"1\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            (*ret).exts |= 0x20 as libc::c_int as libc::c_uint;
            known = 1 as libc::c_int;
        } else if strcmp(
            name,
            b"limits@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
            && strcmp(
                value as *mut libc::c_char,
                b"1\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            (*ret).exts |= 0x40 as libc::c_int as libc::c_uint;
            known = 1 as libc::c_int;
        } else if strcmp(
            name,
            b"expand-path@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
            && strcmp(
                value as *mut libc::c_char,
                b"1\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            (*ret).exts |= 0x80 as libc::c_int as libc::c_uint;
            known = 1 as libc::c_int;
        } else if strcmp(name, b"copy-data\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
            && strcmp(
                value as *mut libc::c_char,
                b"1\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            (*ret).exts |= 0x100 as libc::c_int as libc::c_uint;
            known = 1 as libc::c_int;
        } else if strcmp(
            name,
            b"users-groups-by-id@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
            && strcmp(
                value as *mut libc::c_char,
                b"1\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            (*ret).exts |= 0x200 as libc::c_int as libc::c_uint;
            known = 1 as libc::c_int;
        }
        if known != 0 {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_init\0")).as_ptr(),
                550 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"Server supports extension \"%s\" revision %s\0" as *const u8
                    as *const libc::c_char,
                name,
                value,
            );
        } else {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_init\0")).as_ptr(),
                552 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"Unrecognised server extension \"%s\"\0" as *const u8 as *const libc::c_char,
                name,
            );
        }
        libc::free(name as *mut libc::c_void);
        libc::free(value as *mut libc::c_void);
    }
    sshbuf_free(msg);
    if (*ret).exts & 0x40 as libc::c_int as libc::c_uint != 0 {
        let mut limits: sftp_limits = sftp_limits {
            packet_length: 0,
            read_length: 0,
            write_length: 0,
            open_handles: 0,
        };
        if do_limits(ret, &mut limits) != 0 as libc::c_int {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_init\0")).as_ptr(),
                564 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"limits failed\0" as *const u8 as *const libc::c_char,
            );
        }
        if transfer_buflen == 0 as libc::c_int as libc::c_uint {
            (*ret).download_buflen = (if limits.read_length
                < (256 as libc::c_int * 1024 as libc::c_int - 1024 as libc::c_int) as libc::c_ulong
            {
                limits.read_length
            } else {
                (256 as libc::c_int * 1024 as libc::c_int - 1024 as libc::c_int) as libc::c_ulong
            }) as u_int;
            (*ret).upload_buflen = (if limits.write_length
                < (256 as libc::c_int * 1024 as libc::c_int - 1024 as libc::c_int) as libc::c_ulong
            {
                limits.write_length
            } else {
                (256 as libc::c_int * 1024 as libc::c_int - 1024 as libc::c_int) as libc::c_ulong
            }) as u_int;
            (*ret).download_buflen = if (*ret).download_buflen > 64 as libc::c_int as libc::c_uint {
                (*ret).download_buflen
            } else {
                64 as libc::c_int as libc::c_uint
            };
            (*ret).upload_buflen = if (*ret).upload_buflen > 64 as libc::c_int as libc::c_uint {
                (*ret).upload_buflen
            } else {
                64 as libc::c_int as libc::c_uint
            };
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_init\0")).as_ptr(),
                578 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"server upload/download buffer sizes %llu / %llu; using %u / %u\0" as *const u8
                    as *const libc::c_char,
                limits.write_length as libc::c_ulonglong,
                limits.read_length as libc::c_ulonglong,
                (*ret).upload_buflen,
                (*ret).download_buflen,
            );
        }
        if num_requests == 0 as libc::c_int as libc::c_uint && limits.open_handles != 0 {
            (*ret).num_requests = (if (64 as libc::c_int as libc::c_ulong) < limits.open_handles {
                64 as libc::c_int as libc::c_ulong
            } else {
                limits.open_handles
            }) as u_int;
            if (*ret).num_requests == 0 as libc::c_int as libc::c_uint {
                (*ret).num_requests = 1 as libc::c_int as u_int;
            }
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_init\0")).as_ptr(),
                589 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"server handle limit %llu; using %u\0" as *const u8 as *const libc::c_char,
                limits.open_handles as libc::c_ulonglong,
                (*ret).num_requests,
            );
        }
    }
    if (*ret).version == 0 as libc::c_int as libc::c_uint {
        (*ret).download_buflen = if (*ret).download_buflen < 20480 as libc::c_int as libc::c_uint {
            (*ret).download_buflen
        } else {
            20480 as libc::c_int as libc::c_uint
        };
        (*ret).upload_buflen = if (*ret).upload_buflen < 20480 as libc::c_int as libc::c_uint {
            (*ret).upload_buflen
        } else {
            20480 as libc::c_int as libc::c_uint
        };
    }
    (*ret).limit_kbps = limit_kbps;
    if (*ret).limit_kbps > 0 as libc::c_int as libc::c_ulong {
        crate::misc::bandwidth_limit_init(
            &mut (*ret).bwlimit_in,
            (*ret).limit_kbps,
            (*ret).download_buflen as size_t,
        );
        crate::misc::bandwidth_limit_init(
            &mut (*ret).bwlimit_out,
            (*ret).limit_kbps,
            (*ret).upload_buflen as size_t,
        );
    }
    return ret;
}
pub unsafe extern "C" fn sftp_proto_version(mut conn: *mut sftp_conn) -> u_int {
    return (*conn).version;
}
pub unsafe extern "C" fn do_limits(
    mut conn: *mut sftp_conn,
    mut limits: *mut sftp_limits,
) -> libc::c_int {
    let mut id: u_int = 0;
    let mut msg_id: u_int = 0;
    let mut type_0: u_char = 0;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    if (*conn).exts & 0x40 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_limits\0")).as_ptr(),
            625 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Server does not support limits@openssh.com extension\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_limits\0")).as_ptr(),
            630 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    let fresh0 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh0;
    r = sshbuf_put_u8(msg, 200 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(
                msg,
                b"limits@openssh.com\0" as *const u8 as *const libc::c_char,
            );
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_limits\0")).as_ptr(),
            636 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_limits\0")).as_ptr(),
        638 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Sent message limits@openssh.com I:%u\0" as *const u8 as *const libc::c_char,
        id,
    );
    get_msg(conn, msg);
    r = sshbuf_get_u8(msg, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(msg, &mut msg_id);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_limits\0")).as_ptr(),
            644 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_limits\0")).as_ptr(),
        646 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Received limits reply T:%u I:%u\0" as *const u8 as *const libc::c_char,
        type_0 as libc::c_int,
        msg_id,
    );
    if id != msg_id {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_limits\0")).as_ptr(),
            648 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ID mismatch (%u != %u)\0" as *const u8 as *const libc::c_char,
            msg_id,
            id,
        );
    }
    if type_0 as libc::c_int != 201 as libc::c_int {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_limits\0")).as_ptr(),
            651 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u\0" as *const u8
                as *const libc::c_char,
            201 as libc::c_int,
            type_0 as libc::c_int,
        );
        (*conn).exts &= !(0x40 as libc::c_int) as libc::c_uint;
        sshbuf_free(msg);
        return 0 as libc::c_int;
    }
    memset(
        limits as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sftp_limits>() as libc::c_ulong,
    );
    r = sshbuf_get_u64(msg, &mut (*limits).packet_length);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_u64(msg, &mut (*limits).read_length);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(msg, &mut (*limits).write_length);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(msg, &mut (*limits).open_handles);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_limits\0")).as_ptr(),
            663 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse limits\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(msg);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn do_close(
    mut conn: *mut sftp_conn,
    mut handle: *const u_char,
    mut handle_len: u_int,
) -> libc::c_int {
    let mut id: u_int = 0;
    let mut status: u_int = 0;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_close\0")).as_ptr(),
            678 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    let fresh1 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh1;
    r = sshbuf_put_u8(msg, 4 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(msg, handle as *const libc::c_void, handle_len as size_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_close\0")).as_ptr(),
            684 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_close\0")).as_ptr(),
        686 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Sent message SSH2_FXP_CLOSE I:%u\0" as *const u8 as *const libc::c_char,
        id,
    );
    status = get_status(conn, id);
    if status != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_close\0")).as_ptr(),
            690 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"close remote: %s\0" as *const u8 as *const libc::c_char,
            fx2txt(status as libc::c_int),
        );
    }
    sshbuf_free(msg);
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
unsafe extern "C" fn do_lsreaddir(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut print_flag: libc::c_int,
    mut dir: *mut *mut *mut SFTP_DIRENT,
) -> libc::c_int {
    let mut current_block: u64;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut count: u_int = 0;
    let mut id: u_int = 0;
    let mut i: u_int = 0;
    let mut expected_id: u_int = 0;
    let mut ents: u_int = 0 as libc::c_int as u_int;
    let mut handle_len: size_t = 0;
    let mut type_0: u_char = 0;
    let mut handle: *mut u_char = 0 as *mut u_char;
    let mut status: libc::c_int = 4 as libc::c_int;
    let mut r: libc::c_int = 0;
    if !dir.is_null() {
        *dir = 0 as *mut *mut SFTP_DIRENT;
    }
    let fresh2 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh2;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0")).as_ptr(),
            715 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u8(msg, 11 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, path);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0")).as_ptr(),
            719 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose OPENDIR\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    handle = get_handle(
        conn,
        id,
        &mut handle_len as *mut size_t,
        b"remote readdir(\"%s\")\0" as *const u8 as *const libc::c_char,
        path,
    );
    if handle.is_null() {
        sshbuf_free(msg);
        return -(1 as libc::c_int);
    }
    if !dir.is_null() {
        ents = 0 as libc::c_int as u_int;
        *dir = xcalloc(
            1 as libc::c_int as size_t,
            ::core::mem::size_of::<*mut SFTP_DIRENT>() as libc::c_ulong,
        ) as *mut *mut SFTP_DIRENT;
        let ref mut fresh3 = *(*dir).offset(0 as libc::c_int as isize);
        *fresh3 = 0 as *mut SFTP_DIRENT;
    }
    's_76: loop {
        if !(interrupted == 0) {
            current_block = 17233182392562552756;
            break;
        }
        let fresh4 = (*conn).msg_id;
        (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
        expected_id = fresh4;
        id = expected_id;
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0")).as_ptr(),
            738 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"Sending SSH2_FXP_READDIR I:%u\0" as *const u8 as *const libc::c_char,
            id,
        );
        sshbuf_reset(msg);
        r = sshbuf_put_u8(msg, 12 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshbuf_put_u32(msg, id);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_string(msg, handle as *const libc::c_void, handle_len);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0"))
                    .as_ptr(),
                744 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose READDIR\0" as *const u8 as *const libc::c_char,
            );
        }
        send_msg(conn, msg);
        sshbuf_reset(msg);
        get_msg(conn, msg);
        r = sshbuf_get_u8(msg, &mut type_0);
        if r != 0 as libc::c_int || {
            r = sshbuf_get_u32(msg, &mut id);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0"))
                    .as_ptr(),
                753 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0")).as_ptr(),
            755 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"Received reply T:%u I:%u\0" as *const u8 as *const libc::c_char,
            type_0 as libc::c_int,
            id,
        );
        if id != expected_id {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0"))
                    .as_ptr(),
                758 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"ID mismatch (%u != %u)\0" as *const u8 as *const libc::c_char,
                id,
                expected_id,
            );
        }
        if type_0 as libc::c_int == 101 as libc::c_int {
            let mut rstatus: u_int = 0;
            r = sshbuf_get_u32(msg, &mut rstatus);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0"))
                        .as_ptr(),
                    764 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse status\0" as *const u8 as *const libc::c_char,
                );
            }
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0"))
                    .as_ptr(),
                765 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"Received SSH2_FXP_STATUS %d\0" as *const u8 as *const libc::c_char,
                rstatus,
            );
            if rstatus == 1 as libc::c_int as libc::c_uint {
                current_block = 17233182392562552756;
                break;
            }
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0"))
                    .as_ptr(),
                768 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Couldn't read directory: %s\0" as *const u8 as *const libc::c_char,
                fx2txt(rstatus as libc::c_int),
            );
            current_block = 12100910119561751479;
            break;
        } else {
            if type_0 as libc::c_int != 104 as libc::c_int {
                sshfatal(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0"))
                        .as_ptr(),
                    772 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Expected SSH2_FXP_NAME(%u) packet, got %u\0" as *const u8
                        as *const libc::c_char,
                    104 as libc::c_int,
                    type_0 as libc::c_int,
                );
            }
            r = sshbuf_get_u32(msg, &mut count);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0"))
                        .as_ptr(),
                    775 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse count\0" as *const u8 as *const libc::c_char,
                );
            }
            if count > 0x8000000 as libc::c_int as libc::c_uint {
                sshfatal(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0"))
                        .as_ptr(),
                    777 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"nonsensical number of entries\0" as *const u8 as *const libc::c_char,
                );
            }
            if count == 0 as libc::c_int as libc::c_uint {
                current_block = 17233182392562552756;
                break;
            }
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_lsreaddir\0"))
                    .as_ptr(),
                780 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"Received %d SSH2_FXP_NAME responses\0" as *const u8 as *const libc::c_char,
                count,
            );
            i = 0 as libc::c_int as u_int;
            while i < count {
                let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
                let mut longname: *mut libc::c_char = 0 as *mut libc::c_char;
                let mut a: Attrib = Attrib {
                    flags: 0,
                    size: 0,
                    uid: 0,
                    gid: 0,
                    perm: 0,
                    atime: 0,
                    mtime: 0,
                };
                r = sshbuf_get_cstring(msg, &mut filename, 0 as *mut size_t);
                if r != 0 as libc::c_int || {
                    r = sshbuf_get_cstring(msg, &mut longname, 0 as *mut size_t);
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"do_lsreaddir\0",
                        ))
                        .as_ptr(),
                        789 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse filenames\0" as *const u8 as *const libc::c_char,
                    );
                }
                r = decode_attrib(msg, &mut a);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"do_lsreaddir\0",
                        ))
                        .as_ptr(),
                        791 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"couldn't decode attrib\0" as *const u8 as *const libc::c_char,
                    );
                    libc::free(filename as *mut libc::c_void);
                    libc::free(longname as *mut libc::c_void);
                    current_block = 12100910119561751479;
                    break 's_76;
                } else {
                    if print_flag != 0 {
                        mprintf(b"%s\n\0" as *const u8 as *const libc::c_char, longname);
                    }
                    if !(strpbrk(filename, b"/\0" as *const u8 as *const libc::c_char)).is_null() {
                        crate::log::sshlog(
                            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"do_lsreaddir\0",
                            ))
                            .as_ptr(),
                            807 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"Server sent suspect path \"%s\" during readdir of \"%s\"\0"
                                as *const u8 as *const libc::c_char,
                            filename,
                            path,
                        );
                    } else if !dir.is_null() {
                        *dir = xreallocarray(
                            *dir as *mut libc::c_void,
                            ents.wrapping_add(2 as libc::c_int as libc::c_uint) as size_t,
                            ::core::mem::size_of::<*mut SFTP_DIRENT>() as libc::c_ulong,
                        ) as *mut *mut SFTP_DIRENT;
                        let ref mut fresh5 = *(*dir).offset(ents as isize);
                        *fresh5 = xcalloc(
                            1 as libc::c_int as size_t,
                            ::core::mem::size_of::<SFTP_DIRENT>() as libc::c_ulong,
                        ) as *mut SFTP_DIRENT;
                        let ref mut fresh6 = (**(*dir).offset(ents as isize)).filename;
                        *fresh6 = xstrdup(filename);
                        let ref mut fresh7 = (**(*dir).offset(ents as isize)).longname;
                        *fresh7 = xstrdup(longname);
                        memcpy(
                            &mut (**(*dir).offset(ents as isize)).a as *mut Attrib
                                as *mut libc::c_void,
                            &mut a as *mut Attrib as *const libc::c_void,
                            ::core::mem::size_of::<Attrib>() as libc::c_ulong,
                        );
                        ents = ents.wrapping_add(1);
                        let ref mut fresh8 = *(*dir).offset(ents as isize);
                        *fresh8 = 0 as *mut SFTP_DIRENT;
                    }
                    libc::free(filename as *mut libc::c_void);
                    libc::free(longname as *mut libc::c_void);
                    i = i.wrapping_add(1);
                    i;
                }
            }
        }
    }
    match current_block {
        17233182392562552756 => {
            status = 0 as libc::c_int;
        }
        _ => {}
    }
    sshbuf_free(msg);
    do_close(conn, handle, handle_len as u_int);
    libc::free(handle as *mut libc::c_void);
    if status != 0 as libc::c_int && !dir.is_null() {
        free_sftp_dirents(*dir);
        *dir = 0 as *mut *mut SFTP_DIRENT;
    } else if interrupted != 0 && !dir.is_null() && !(*dir).is_null() {
        free_sftp_dirents(*dir);
        *dir = xcalloc(
            1 as libc::c_int as size_t,
            ::core::mem::size_of::<*mut SFTP_DIRENT>() as libc::c_ulong,
        ) as *mut *mut SFTP_DIRENT;
        **dir = 0 as *mut SFTP_DIRENT;
    }
    return if status == 0 as libc::c_int {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
pub unsafe extern "C" fn do_readdir(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut dir: *mut *mut *mut SFTP_DIRENT,
) -> libc::c_int {
    return do_lsreaddir(conn, path, 0 as libc::c_int, dir);
}
pub unsafe extern "C" fn free_sftp_dirents(mut s: *mut *mut SFTP_DIRENT) {
    let mut i: libc::c_int = 0;
    if s.is_null() {
        return;
    }
    i = 0 as libc::c_int;
    while !(*s.offset(i as isize)).is_null() {
        libc::free((**s.offset(i as isize)).filename as *mut libc::c_void);
        libc::free((**s.offset(i as isize)).longname as *mut libc::c_void);
        libc::free(*s.offset(i as isize) as *mut libc::c_void);
        i += 1;
        i;
    }
    libc::free(s as *mut libc::c_void);
}
pub unsafe extern "C" fn do_rm(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
) -> libc::c_int {
    let mut status: u_int = 0;
    let mut id: u_int = 0;
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 6], &[libc::c_char; 6]>(b"do_rm\0")).as_ptr(),
        866 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_REMOVE \"%s\"\0" as *const u8 as *const libc::c_char,
        path,
    );
    let fresh9 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh9;
    send_string_request(
        conn,
        id,
        13 as libc::c_int as u_int,
        path,
        strlen(path) as u_int,
    );
    status = get_status(conn, id);
    if status != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 6], &[libc::c_char; 6]>(b"do_rm\0")).as_ptr(),
            872 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"remote delete %s: %s\0" as *const u8 as *const libc::c_char,
            path,
            fx2txt(status as libc::c_int),
        );
    }
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
pub unsafe extern "C" fn do_mkdir(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut a: *mut Attrib,
    mut print_flag: libc::c_int,
) -> libc::c_int {
    let mut status: u_int = 0;
    let mut id: u_int = 0;
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_mkdir\0")).as_ptr(),
        881 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_MKDIR \"%s\"\0" as *const u8 as *const libc::c_char,
        path,
    );
    let fresh10 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh10;
    send_string_attrs_request(
        conn,
        id,
        14 as libc::c_int as u_int,
        path as *const libc::c_void,
        strlen(path) as u_int,
        a,
    );
    status = get_status(conn, id);
    if status != 0 as libc::c_int as libc::c_uint && print_flag != 0 {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_mkdir\0")).as_ptr(),
            889 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"remote mkdir \"%s\": %s\0" as *const u8 as *const libc::c_char,
            path,
            fx2txt(status as libc::c_int),
        );
    }
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
pub unsafe extern "C" fn do_rmdir(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
) -> libc::c_int {
    let mut status: u_int = 0;
    let mut id: u_int = 0;
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_rmdir\0")).as_ptr(),
        899 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_RMDIR \"%s\"\0" as *const u8 as *const libc::c_char,
        path,
    );
    let fresh11 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh11;
    send_string_request(
        conn,
        id,
        15 as libc::c_int as u_int,
        path,
        strlen(path) as u_int,
    );
    status = get_status(conn, id);
    if status != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_rmdir\0")).as_ptr(),
            907 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"remote rmdir \"%s\": %s\0" as *const u8 as *const libc::c_char,
            path,
            fx2txt(status as libc::c_int),
        );
    }
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
pub unsafe extern "C" fn do_stat(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut quiet: libc::c_int,
) -> *mut Attrib {
    let mut id: u_int = 0;
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_stat\0")).as_ptr(),
        917 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_STAT \"%s\"\0" as *const u8 as *const libc::c_char,
        path,
    );
    let fresh12 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh12;
    send_string_request(
        conn,
        id,
        (if (*conn).version == 0 as libc::c_int as libc::c_uint {
            7 as libc::c_int
        } else {
            17 as libc::c_int
        }) as u_int,
        path,
        strlen(path) as u_int,
    );
    return get_decode_stat(conn, id, quiet);
}
pub unsafe extern "C" fn do_lstat(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut quiet: libc::c_int,
) -> *mut Attrib {
    let mut id: u_int = 0;
    if (*conn).version == 0 as libc::c_int as libc::c_uint {
        if quiet != 0 {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_lstat\0")).as_ptr(),
                935 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Server version does not support lstat operation\0" as *const u8
                    as *const libc::c_char,
            );
        } else {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_lstat\0")).as_ptr(),
                937 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Server version does not support lstat operation\0" as *const u8
                    as *const libc::c_char,
            );
        }
        return do_stat(conn, path, quiet);
    }
    let fresh13 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh13;
    send_string_request(
        conn,
        id,
        7 as libc::c_int as u_int,
        path,
        strlen(path) as u_int,
    );
    return get_decode_stat(conn, id, quiet);
}
pub unsafe extern "C" fn do_setstat(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut a: *mut Attrib,
) -> libc::c_int {
    let mut status: u_int = 0;
    let mut id: u_int = 0;
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_setstat\0")).as_ptr(),
        970 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_SETSTAT \"%s\"\0" as *const u8 as *const libc::c_char,
        path,
    );
    let fresh14 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh14;
    send_string_attrs_request(
        conn,
        id,
        9 as libc::c_int as u_int,
        path as *const libc::c_void,
        strlen(path) as u_int,
        a,
    );
    status = get_status(conn, id);
    if status != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_setstat\0")).as_ptr(),
            978 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"remote setstat \"%s\": %s\0" as *const u8 as *const libc::c_char,
            path,
            fx2txt(status as libc::c_int),
        );
    }
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
pub unsafe extern "C" fn do_fsetstat(
    mut conn: *mut sftp_conn,
    mut handle: *const u_char,
    mut handle_len: u_int,
    mut a: *mut Attrib,
) -> libc::c_int {
    let mut status: u_int = 0;
    let mut id: u_int = 0;
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_fsetstat\0")).as_ptr(),
        989 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_FSETSTAT\0" as *const u8 as *const libc::c_char,
    );
    let fresh15 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh15;
    send_string_attrs_request(
        conn,
        id,
        10 as libc::c_int as u_int,
        handle as *const libc::c_void,
        handle_len,
        a,
    );
    status = get_status(conn, id);
    if status != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_fsetstat\0")).as_ptr(),
            997 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"remote fsetstat: %s\0" as *const u8 as *const libc::c_char,
            fx2txt(status as libc::c_int),
        );
    }
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
unsafe extern "C" fn do_realpath_expand(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut expand: libc::c_int,
) -> *mut libc::c_char {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut expected_id: u_int = 0;
    let mut count: u_int = 0;
    let mut id: u_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut longname: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut a: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut type_0: u_char = 0;
    let mut r: libc::c_int = 0;
    let mut what: *const libc::c_char = b"SSH2_FXP_REALPATH\0" as *const u8 as *const libc::c_char;
    if expand != 0 {
        what = b"expand-path@openssh.com\0" as *const u8 as *const libc::c_char;
    }
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_realpath_expand\0"))
                .as_ptr(),
            1017 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    let fresh16 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh16;
    expected_id = id;
    if expand != 0 {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_realpath_expand\0"))
                .as_ptr(),
            1022 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) \"%s\"\0" as *const u8
                as *const libc::c_char,
            path,
        );
        r = sshbuf_put_u8(msg, 200 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshbuf_put_u32(msg, id);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_cstring(
                    msg,
                    b"expand-path@openssh.com\0" as *const u8 as *const libc::c_char,
                );
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_cstring(msg, path);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"do_realpath_expand\0",
                ))
                .as_ptr(),
                1028 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose %s\0" as *const u8 as *const libc::c_char,
                what,
            );
        }
        send_msg(conn, msg);
    } else {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_realpath_expand\0"))
                .as_ptr(),
            1031 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Sending SSH2_FXP_REALPATH \"%s\"\0" as *const u8 as *const libc::c_char,
            path,
        );
        send_string_request(
            conn,
            id,
            16 as libc::c_int as u_int,
            path,
            strlen(path) as u_int,
        );
    }
    get_msg(conn, msg);
    r = sshbuf_get_u8(msg, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(msg, &mut id);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_realpath_expand\0"))
                .as_ptr(),
            1038 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if id != expected_id {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_realpath_expand\0"))
                .as_ptr(),
            1041 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ID mismatch (%u != %u)\0" as *const u8 as *const libc::c_char,
            id,
            expected_id,
        );
    }
    if type_0 as libc::c_int == 101 as libc::c_int {
        let mut status: u_int = 0;
        let mut errmsg: *mut libc::c_char = 0 as *mut libc::c_char;
        r = sshbuf_get_u32(msg, &mut status);
        if r != 0 as libc::c_int || {
            r = sshbuf_get_cstring(msg, &mut errmsg, 0 as *mut size_t);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"do_realpath_expand\0",
                ))
                .as_ptr(),
                1049 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse status\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_realpath_expand\0"))
                .as_ptr(),
            1051 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s %s: %s\0" as *const u8 as *const libc::c_char,
            if expand != 0 {
                b"expand\0" as *const u8 as *const libc::c_char
            } else {
                b"realpath\0" as *const u8 as *const libc::c_char
            },
            path,
            if *errmsg as libc::c_int == '\0' as i32 {
                fx2txt(status as libc::c_int)
            } else {
                errmsg as *const libc::c_char
            },
        );
        libc::free(errmsg as *mut libc::c_void);
        sshbuf_free(msg);
        return 0 as *mut libc::c_char;
    } else if type_0 as libc::c_int != 104 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_realpath_expand\0"))
                .as_ptr(),
            1057 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Expected SSH2_FXP_NAME(%u) packet, got %u\0" as *const u8 as *const libc::c_char,
            104 as libc::c_int,
            type_0 as libc::c_int,
        );
    }
    r = sshbuf_get_u32(msg, &mut count);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_realpath_expand\0"))
                .as_ptr(),
            1060 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse count\0" as *const u8 as *const libc::c_char,
        );
    }
    if count != 1 as libc::c_int as libc::c_uint {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_realpath_expand\0"))
                .as_ptr(),
            1062 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Got multiple names (%d) from %s\0" as *const u8 as *const libc::c_char,
            count,
            what,
        );
    }
    r = sshbuf_get_cstring(msg, &mut filename, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_cstring(msg, &mut longname, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = decode_attrib(msg, &mut a);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_realpath_expand\0"))
                .as_ptr(),
            1067 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse filename/attrib\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"do_realpath_expand\0"))
            .as_ptr(),
        1069 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s %s -> %s\0" as *const u8 as *const libc::c_char,
        what,
        path,
        filename,
    );
    libc::free(longname as *mut libc::c_void);
    sshbuf_free(msg);
    return filename;
}
pub unsafe extern "C" fn do_realpath(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
) -> *mut libc::c_char {
    return do_realpath_expand(conn, path, 0 as libc::c_int);
}
pub unsafe extern "C" fn can_expand_path(mut conn: *mut sftp_conn) -> libc::c_int {
    return ((*conn).exts & 0x80 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint)
        as libc::c_int;
}
pub unsafe extern "C" fn do_expand_path(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
) -> *mut libc::c_char {
    if can_expand_path(conn) == 0 {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_expand_path\0"))
                .as_ptr(),
            1094 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"no server support, fallback to realpath\0" as *const u8 as *const libc::c_char,
        );
        return do_realpath_expand(conn, path, 0 as libc::c_int);
    }
    return do_realpath_expand(conn, path, 1 as libc::c_int);
}
pub unsafe extern "C" fn do_copy(
    mut conn: *mut sftp_conn,
    mut oldpath: *const libc::c_char,
    mut newpath: *const libc::c_char,
) -> libc::c_int {
    let mut junk: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut a: *mut Attrib = 0 as *mut Attrib;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut old_handle: *mut u_char = 0 as *mut u_char;
    let mut new_handle: *mut u_char = 0 as *mut u_char;
    let mut mode: u_int = 0;
    let mut status: u_int = 0;
    let mut id: u_int = 0;
    let mut old_handle_len: size_t = 0;
    let mut new_handle_len: size_t = 0;
    let mut r: libc::c_int = 0;
    if (*conn).exts & 0x100 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
            1112 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Server does not support copy-data extension\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    a = do_stat(conn, oldpath, 0 as libc::c_int);
    if a.is_null() {
        return -(1 as libc::c_int);
    }
    if (*a).flags & 0x4 as libc::c_int as libc::c_uint != 0 {
        mode = (*a).perm & 0o777 as libc::c_int as libc::c_uint;
        if !((*a).perm & 0o170000 as libc::c_int as libc::c_uint
            == 0o100000 as libc::c_int as libc::c_uint)
        {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
                1125 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Cannot copy non-regular file: %s\0" as *const u8 as *const libc::c_char,
                oldpath,
            );
            return -(1 as libc::c_int);
        }
    } else {
        mode = 0o666 as libc::c_int as u_int;
    }
    attrib_clear(a);
    (*a).perm = mode;
    (*a).flags |= 0x4 as libc::c_int as libc::c_uint;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
            1139 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: sshbuf_new failed\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
        );
    }
    attrib_clear(&mut junk);
    let fresh17 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh17;
    r = sshbuf_put_u8(msg, 3 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, oldpath);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(msg, 0x1 as libc::c_int as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = encode_attrib(msg, &mut junk);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
            1150 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: buffer error: %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
            ssh_err(r),
        );
    }
    send_msg(conn, msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
        1152 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Sent message SSH2_FXP_OPEN I:%u P:%s\0" as *const u8 as *const libc::c_char,
        id,
        oldpath,
    );
    sshbuf_reset(msg);
    old_handle = get_handle(
        conn,
        id,
        &mut old_handle_len as *mut size_t,
        b"remote open(\"%s\")\0" as *const u8 as *const libc::c_char,
        oldpath,
    );
    if old_handle.is_null() {
        sshbuf_free(msg);
        return -(1 as libc::c_int);
    }
    let fresh18 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh18;
    r = sshbuf_put_u8(msg, 3 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, newpath);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(
                msg,
                (0x2 as libc::c_int | 0x8 as libc::c_int | 0x10 as libc::c_int) as u_int32_t,
            );
            r != 0 as libc::c_int
        }
        || {
            r = encode_attrib(msg, a);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
            1171 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: buffer error: %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
            ssh_err(r),
        );
    }
    send_msg(conn, msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
        1173 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Sent message SSH2_FXP_OPEN I:%u P:%s\0" as *const u8 as *const libc::c_char,
        id,
        newpath,
    );
    sshbuf_reset(msg);
    new_handle = get_handle(
        conn,
        id,
        &mut new_handle_len as *mut size_t,
        b"remote open(\"%s\")\0" as *const u8 as *const libc::c_char,
        newpath,
    );
    if new_handle.is_null() {
        sshbuf_free(msg);
        libc::free(old_handle as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    let fresh19 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh19;
    r = sshbuf_put_u8(msg, 200 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, b"copy-data\0" as *const u8 as *const libc::c_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(msg, old_handle as *const libc::c_void, old_handle_len);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, 0 as libc::c_int as u_int64_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, 0 as libc::c_int as u_int64_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(msg, new_handle as *const libc::c_void, new_handle_len);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, 0 as libc::c_int as u_int64_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
            1195 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: buffer error: %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
            ssh_err(r),
        );
    }
    send_msg(conn, msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
        1198 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Sent message copy-data \"%s\" 0 0 -> \"%s\" 0\0" as *const u8 as *const libc::c_char,
        oldpath,
        newpath,
    );
    status = get_status(conn, id);
    if status != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_copy\0")).as_ptr(),
            1203 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Couldn't copy file \"%s\" to \"%s\": %s\0" as *const u8 as *const libc::c_char,
            oldpath,
            newpath,
            fx2txt(status as libc::c_int),
        );
    }
    sshbuf_free(msg);
    do_close(conn, old_handle, old_handle_len as u_int);
    do_close(conn, new_handle, new_handle_len as u_int);
    libc::free(old_handle as *mut libc::c_void);
    libc::free(new_handle as *mut libc::c_void);
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
pub unsafe extern "C" fn do_rename(
    mut conn: *mut sftp_conn,
    mut oldpath: *const libc::c_char,
    mut newpath: *const libc::c_char,
    mut force_legacy: libc::c_int,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut status: u_int = 0;
    let mut id: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut use_ext: libc::c_int = ((*conn).exts & 0x1 as libc::c_int as libc::c_uint != 0
        && force_legacy == 0) as libc::c_int;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_rename\0")).as_ptr(),
            1224 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    let fresh20 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh20;
    if use_ext != 0 {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_rename\0")).as_ptr(),
            1230 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) \"%s\" to \"%s\"\0" as *const u8
                as *const libc::c_char,
            oldpath,
            newpath,
        );
        r = sshbuf_put_u8(msg, 200 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshbuf_put_u32(msg, id);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_cstring(
                    msg,
                    b"posix-rename@openssh.com\0" as *const u8 as *const libc::c_char,
                );
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_rename\0"))
                    .as_ptr(),
                1235 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose posix-rename\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_rename\0")).as_ptr(),
            1238 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Sending SSH2_FXP_RENAME \"%s\" to \"%s\"\0" as *const u8 as *const libc::c_char,
            oldpath,
            newpath,
        );
        r = sshbuf_put_u8(msg, 18 as libc::c_int as u_char);
        if r != 0 as libc::c_int || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_rename\0"))
                    .as_ptr(),
                1241 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose rename\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    r = sshbuf_put_cstring(msg, oldpath);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_cstring(msg, newpath);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_rename\0")).as_ptr(),
            1245 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose paths\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_rename\0")).as_ptr(),
        1249 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Sent message %s \"%s\" -> \"%s\"\0" as *const u8 as *const libc::c_char,
        if use_ext != 0 {
            b"posix-rename@openssh.com\0" as *const u8 as *const libc::c_char
        } else {
            b"SSH2_FXP_RENAME\0" as *const u8 as *const libc::c_char
        },
        oldpath,
        newpath,
    );
    sshbuf_free(msg);
    status = get_status(conn, id);
    if status != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_rename\0")).as_ptr(),
            1255 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"remote rename \"%s\" to \"%s\": %s\0" as *const u8 as *const libc::c_char,
            oldpath,
            newpath,
            fx2txt(status as libc::c_int),
        );
    }
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
pub unsafe extern "C" fn do_hardlink(
    mut conn: *mut sftp_conn,
    mut oldpath: *const libc::c_char,
    mut newpath: *const libc::c_char,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut status: u_int = 0;
    let mut id: u_int = 0;
    let mut r: libc::c_int = 0;
    if (*conn).exts & 0x8 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_hardlink\0")).as_ptr(),
            1268 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Server does not support hardlink@openssh.com extension\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_hardlink\0")).as_ptr(),
        1272 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) \"%s\" to \"%s\"\0" as *const u8
            as *const libc::c_char,
        oldpath,
        newpath,
    );
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_hardlink\0")).as_ptr(),
            1275 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    let fresh21 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh21;
    r = sshbuf_put_u8(msg, 200 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(
                msg,
                b"hardlink@openssh.com\0" as *const u8 as *const libc::c_char,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, oldpath);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, newpath);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_hardlink\0")).as_ptr(),
            1284 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_hardlink\0")).as_ptr(),
        1287 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Sent message hardlink@openssh.com \"%s\" -> \"%s\"\0" as *const u8 as *const libc::c_char,
        oldpath,
        newpath,
    );
    sshbuf_free(msg);
    status = get_status(conn, id);
    if status != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_hardlink\0")).as_ptr(),
            1293 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"remote link \"%s\" to \"%s\": %s\0" as *const u8 as *const libc::c_char,
            oldpath,
            newpath,
            fx2txt(status as libc::c_int),
        );
    }
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
pub unsafe extern "C" fn do_symlink(
    mut conn: *mut sftp_conn,
    mut oldpath: *const libc::c_char,
    mut newpath: *const libc::c_char,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut status: u_int = 0;
    let mut id: u_int = 0;
    let mut r: libc::c_int = 0;
    if (*conn).version < 3 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_symlink\0")).as_ptr(),
            1306 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"This server does not support the symlink operation\0" as *const u8
                as *const libc::c_char,
        );
        return 8 as libc::c_int;
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_symlink\0")).as_ptr(),
        1309 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"\0" as *const u8 as *const libc::c_char,
        oldpath,
        newpath,
    );
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_symlink\0")).as_ptr(),
            1312 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    let fresh22 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh22;
    r = sshbuf_put_u8(msg, 20 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, oldpath);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, newpath);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_symlink\0")).as_ptr(),
            1320 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_symlink\0")).as_ptr(),
        1323 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"\0" as *const u8 as *const libc::c_char,
        oldpath,
        newpath,
    );
    sshbuf_free(msg);
    status = get_status(conn, id);
    if status != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_symlink\0")).as_ptr(),
            1329 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"remote symlink file \"%s\" to \"%s\": %s\0" as *const u8 as *const libc::c_char,
            oldpath,
            newpath,
            fx2txt(status as libc::c_int),
        );
    }
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
pub unsafe extern "C" fn do_fsync(
    mut conn: *mut sftp_conn,
    mut handle: *mut u_char,
    mut handle_len: u_int,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut status: u_int = 0;
    let mut id: u_int = 0;
    let mut r: libc::c_int = 0;
    if (*conn).exts & 0x10 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        return -(1 as libc::c_int);
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_fsync\0")).as_ptr(),
        1344 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_EXTENDED(fsync@openssh.com)\0" as *const u8 as *const libc::c_char,
    );
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_fsync\0")).as_ptr(),
            1348 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    let fresh23 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh23;
    r = sshbuf_put_u8(msg, 200 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(
                msg,
                b"fsync@openssh.com\0" as *const u8 as *const libc::c_char,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(msg, handle as *const libc::c_void, handle_len as size_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_fsync\0")).as_ptr(),
            1354 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_fsync\0")).as_ptr(),
        1356 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Sent message fsync@openssh.com I:%u\0" as *const u8 as *const libc::c_char,
        id,
    );
    sshbuf_free(msg);
    status = get_status(conn, id);
    if status != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_fsync\0")).as_ptr(),
            1361 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"remote fsync: %s\0" as *const u8 as *const libc::c_char,
            fx2txt(status as libc::c_int),
        );
    }
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
pub unsafe extern "C" fn do_statvfs(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut st: *mut sftp_statvfs,
    mut quiet: libc::c_int,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut id: u_int = 0;
    let mut r: libc::c_int = 0;
    if (*conn).exts & 0x2 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_statvfs\0")).as_ptr(),
            1434 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Server does not support statvfs@openssh.com extension\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_statvfs\0")).as_ptr(),
        1438 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"\0" as *const u8
            as *const libc::c_char,
        path,
    );
    let fresh24 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh24;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_statvfs\0")).as_ptr(),
            1443 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u8(msg, 200 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(
                msg,
                b"statvfs@openssh.com\0" as *const u8 as *const libc::c_char,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, path);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_statvfs\0")).as_ptr(),
            1448 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    sshbuf_free(msg);
    return get_decode_statvfs(conn, st, id, quiet);
}
pub unsafe extern "C" fn do_lsetstat(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut a: *mut Attrib,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut status: u_int = 0;
    let mut id: u_int = 0;
    let mut r: libc::c_int = 0;
    if (*conn).exts & 0x20 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_lsetstat\0")).as_ptr(),
            1494 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Server does not support lsetstat@openssh.com extension\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_lsetstat\0")).as_ptr(),
        1498 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"\0" as *const u8
            as *const libc::c_char,
        path,
    );
    let fresh25 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh25;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_lsetstat\0")).as_ptr(),
            1502 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u8(msg, 200 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(
                msg,
                b"lsetstat@openssh.com\0" as *const u8 as *const libc::c_char,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, path);
            r != 0 as libc::c_int
        }
        || {
            r = encode_attrib(msg, a);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_lsetstat\0")).as_ptr(),
            1508 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    sshbuf_free(msg);
    status = get_status(conn, id);
    if status != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_lsetstat\0")).as_ptr(),
            1514 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"remote lsetstat \"%s\": %s\0" as *const u8 as *const libc::c_char,
            path,
            fx2txt(status as libc::c_int),
        );
    }
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
unsafe extern "C" fn send_read_request(
    mut conn: *mut sftp_conn,
    mut id: u_int,
    mut offset: u_int64_t,
    mut len: u_int,
    mut handle: *const u_char,
    mut handle_len: u_int,
) {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"send_read_request\0"))
                .as_ptr(),
            1527 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u8(msg, 5 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(msg, handle as *const libc::c_void, handle_len as size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, offset);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(msg, len);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"send_read_request\0"))
                .as_ptr(),
            1533 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    sshbuf_free(msg);
}
unsafe extern "C" fn send_open(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut tag: *const libc::c_char,
    mut openmode: u_int,
    mut a: *mut Attrib,
    mut handlep: *mut *mut u_char,
    mut handle_lenp: *mut size_t,
) -> libc::c_int {
    let mut junk: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut handle: *mut u_char = 0 as *mut u_char;
    let mut handle_len: size_t = 0;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    let mut id: u_int = 0;
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"send_open\0")).as_ptr(),
        1549 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_OPEN \"%s\"\0" as *const u8 as *const libc::c_char,
        path,
    );
    *handlep = 0 as *mut u_char;
    *handle_lenp = 0 as libc::c_int as size_t;
    if a.is_null() {
        attrib_clear(&mut junk);
        a = &mut junk;
    }
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"send_open\0")).as_ptr(),
            1560 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    let fresh26 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh26;
    r = sshbuf_put_u8(msg, 3 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, path);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(msg, openmode);
            r != 0 as libc::c_int
        }
        || {
            r = encode_attrib(msg, a);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"send_open\0")).as_ptr(),
            1567 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose %s open\0" as *const u8 as *const libc::c_char,
            tag,
        );
    }
    send_msg(conn, msg);
    sshbuf_free(msg);
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"send_open\0")).as_ptr(),
        1571 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x\0" as *const u8 as *const libc::c_char,
        tag,
        id,
        path,
        openmode,
    );
    handle = get_handle(
        conn,
        id,
        &mut handle_len as *mut size_t,
        b"%s open \"%s\"\0" as *const u8 as *const libc::c_char,
        tag,
        path,
    );
    if handle.is_null() {
        return -(1 as libc::c_int);
    }
    *handlep = handle;
    *handle_lenp = handle_len;
    return 0 as libc::c_int;
}
unsafe extern "C" fn progress_meter_path(mut path: *const libc::c_char) -> *const libc::c_char {
    let mut progresspath: *const libc::c_char = 0 as *const libc::c_char;
    progresspath = strrchr(path, '/' as i32);
    if progresspath.is_null() {
        return path;
    }
    progresspath = progresspath.offset(1);
    progresspath;
    if *progresspath as libc::c_int == '\0' as i32 {
        return path;
    }
    return progresspath;
}
pub unsafe extern "C" fn do_download(
    mut conn: *mut sftp_conn,
    mut remote_path: *const libc::c_char,
    mut local_path: *const libc::c_char,
    mut a: *mut Attrib,
    mut preserve_flag: libc::c_int,
    mut resume_flag: libc::c_int,
    mut fsync_flag: libc::c_int,
    mut inplace_flag: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut handle: *mut u_char = 0 as *mut u_char;
    let mut local_fd: libc::c_int = -(1 as libc::c_int);
    let mut write_error: libc::c_int = 0;
    let mut read_error: libc::c_int = 0;
    let mut write_errno: libc::c_int = 0;
    let mut lmodified: libc::c_int = 0 as libc::c_int;
    let mut reordered: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    let mut offset: u_int64_t = 0 as libc::c_int as u_int64_t;
    let mut size: u_int64_t = 0;
    let mut highwater: u_int64_t = 0 as libc::c_int as u_int64_t;
    let mut maxack: u_int64_t = 0 as libc::c_int as u_int64_t;
    let mut mode: u_int = 0;
    let mut id: u_int = 0;
    let mut buflen: u_int = 0;
    let mut num_req: u_int = 0;
    let mut max_req: u_int = 0;
    let mut status: u_int = 0 as libc::c_int as u_int;
    let mut progress_counter: off_t = 0;
    let mut handle_len: size_t = 0;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut requests: requests = requests {
        tqh_first: 0 as *mut request,
        tqh_last: 0 as *mut *mut request,
    };
    let mut req: *mut request = 0 as *mut request;
    let mut type_0: u_char = 0;
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_download\0")).as_ptr(),
        1613 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"download remote \"%s\" to local \"%s\"\0" as *const u8 as *const libc::c_char,
        remote_path,
        local_path,
    );
    requests.tqh_first = 0 as *mut request;
    requests.tqh_last = &mut requests.tqh_first;
    if a.is_null() && {
        a = do_stat(conn, remote_path, 0 as libc::c_int);
        a.is_null()
    } {
        return -(1 as libc::c_int);
    }
    if (*a).flags & 0x4 as libc::c_int as libc::c_uint != 0 {
        mode = (*a).perm & 0o777 as libc::c_int as libc::c_uint;
    } else {
        mode = 0o666 as libc::c_int as u_int;
    }
    if (*a).flags & 0x4 as libc::c_int as libc::c_uint != 0
        && !((*a).perm & 0o170000 as libc::c_int as libc::c_uint
            == 0o100000 as libc::c_int as libc::c_uint)
    {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_download\0")).as_ptr(),
            1628 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"download %s: not a regular file\0" as *const u8 as *const libc::c_char,
            remote_path,
        );
        return -(1 as libc::c_int);
    }
    if (*a).flags & 0x1 as libc::c_int as libc::c_uint != 0 {
        size = (*a).size;
    } else {
        size = 0 as libc::c_int as u_int64_t;
    }
    buflen = (*conn).download_buflen;
    if send_open(
        conn,
        remote_path,
        b"remote\0" as *const u8 as *const libc::c_char,
        0x1 as libc::c_int as u_int,
        0 as *mut Attrib,
        &mut handle,
        &mut handle_len,
    ) != 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    local_fd = libc::open(
        local_path,
        0o1 as libc::c_int
            | 0o100 as libc::c_int
            | (if resume_flag != 0 || inplace_flag != 0 {
                0 as libc::c_int
            } else {
                0o1000 as libc::c_int
            }),
        mode | 0o200 as libc::c_int as libc::c_uint,
    );
    if local_fd == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_download\0")).as_ptr(),
            1647 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"open local \"%s\": %s\0" as *const u8 as *const libc::c_char,
            local_path,
            strerror(*libc::__errno_location()),
        );
    } else {
        if resume_flag != 0 {
            if libc::fstat(local_fd, &mut st) == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_download\0"))
                        .as_ptr(),
                    1653 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"libc::stat local \"%s\": %s\0" as *const u8 as *const libc::c_char,
                    local_path,
                    strerror(*libc::__errno_location()),
                );
                current_block = 1623598053124096515;
            } else if st.st_size < 0 as libc::c_int as libc::c_long {
                crate::log::sshlog(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_download\0"))
                        .as_ptr(),
                    1657 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"\"%s\" has negative size\0" as *const u8 as *const libc::c_char,
                    local_path,
                );
                current_block = 1623598053124096515;
            } else if st.st_size as u_int64_t > size {
                crate::log::sshlog(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_download\0"))
                        .as_ptr(),
                    1662 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Unable to resume download of \"%s\": local file is larger than remote\0"
                        as *const u8 as *const libc::c_char,
                    local_path,
                );
                current_block = 1623598053124096515;
            } else {
                maxack = st.st_size as u_int64_t;
                highwater = maxack;
                offset = highwater;
                current_block = 17500079516916021833;
            }
        } else {
            current_block = 17500079516916021833;
        }
        match current_block {
            1623598053124096515 => {}
            _ => {
                num_req = 0 as libc::c_int as u_int;
                write_errno = num_req as libc::c_int;
                read_error = write_errno;
                write_error = read_error;
                max_req = 1 as libc::c_int as u_int;
                progress_counter = offset as off_t;
                if showprogress != 0 && size != 0 as libc::c_int as libc::c_ulong {
                    start_progress_meter(
                        progress_meter_path(remote_path),
                        size as off_t,
                        &mut progress_counter,
                    );
                }
                msg = sshbuf_new();
                if msg.is_null() {
                    sshfatal(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                            b"do_download\0",
                        ))
                        .as_ptr(),
                        1684 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
                    );
                }
                while num_req > 0 as libc::c_int as libc::c_uint
                    || max_req > 0 as libc::c_int as libc::c_uint
                {
                    let mut data: *mut u_char = 0 as *mut u_char;
                    let mut len: size_t = 0;
                    if interrupted != 0 {
                        if num_req == 0 as libc::c_int as libc::c_uint {
                            break;
                        }
                        max_req = 0 as libc::c_int as u_int;
                    }
                    while num_req < max_req {
                        crate::log::sshlog(
                            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"do_download\0",
                            ))
                            .as_ptr(),
                            1705 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG3,
                            0 as *const libc::c_char,
                            b"Request range %llu -> %llu (%d/%d)\0" as *const u8
                                as *const libc::c_char,
                            offset as libc::c_ulonglong,
                            (offset as libc::c_ulonglong)
                                .wrapping_add(buflen as libc::c_ulonglong)
                                .wrapping_sub(1 as libc::c_int as libc::c_ulonglong),
                            num_req,
                            max_req,
                        );
                        let fresh27 = (*conn).msg_id;
                        (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
                        req = request_enqueue(&mut requests, fresh27, buflen as size_t, offset);
                        offset = (offset as libc::c_ulong).wrapping_add(buflen as libc::c_ulong)
                            as u_int64_t as u_int64_t;
                        num_req = num_req.wrapping_add(1);
                        num_req;
                        send_read_request(
                            conn,
                            (*req).id,
                            (*req).offset,
                            (*req).len as u_int,
                            handle,
                            handle_len as u_int,
                        );
                    }
                    sshbuf_reset(msg);
                    get_msg(conn, msg);
                    r = sshbuf_get_u8(msg, &mut type_0);
                    if r != 0 as libc::c_int || {
                        r = sshbuf_get_u32(msg, &mut id);
                        r != 0 as libc::c_int
                    } {
                        sshfatal(
                            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"do_download\0",
                            ))
                            .as_ptr(),
                            1718 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"parse\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    crate::log::sshlog(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                            b"do_download\0",
                        ))
                        .as_ptr(),
                        1719 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"Received reply T:%u I:%u R:%d\0" as *const u8 as *const libc::c_char,
                        type_0 as libc::c_int,
                        id,
                        max_req,
                    );
                    req = request_find(&mut requests, id);
                    if req.is_null() {
                        sshfatal(
                            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"do_download\0",
                            ))
                            .as_ptr(),
                            1723 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Unexpected reply %u\0" as *const u8 as *const libc::c_char,
                            id,
                        );
                    }
                    match type_0 as libc::c_int {
                        101 => {
                            r = sshbuf_get_u32(msg, &mut status);
                            if r != 0 as libc::c_int {
                                sshfatal(
                                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                        b"do_download\0",
                                    ))
                                    .as_ptr(),
                                    1728 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"parse status\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            if status != 1 as libc::c_int as libc::c_uint {
                                read_error = 1 as libc::c_int;
                            }
                            max_req = 0 as libc::c_int as u_int;
                            if !((*req).tq.tqe_next).is_null() {
                                (*(*req).tq.tqe_next).tq.tqe_prev = (*req).tq.tqe_prev;
                            } else {
                                requests.tqh_last = (*req).tq.tqe_prev;
                            }
                            *(*req).tq.tqe_prev = (*req).tq.tqe_next;
                            libc::free(req as *mut libc::c_void);
                            num_req = num_req.wrapping_sub(1);
                            num_req;
                        }
                        103 => {
                            r = sshbuf_get_string(msg, &mut data, &mut len);
                            if r != 0 as libc::c_int {
                                sshfatal(
                                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                        b"do_download\0",
                                    ))
                                    .as_ptr(),
                                    1738 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"parse data\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            crate::log::sshlog(
                                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                    b"do_download\0",
                                ))
                                .as_ptr(),
                                1741 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG3,
                                0 as *const libc::c_char,
                                b"Received data %llu -> %llu\0" as *const u8 as *const libc::c_char,
                                (*req).offset as libc::c_ulonglong,
                                ((*req).offset as libc::c_ulonglong)
                                    .wrapping_add(len as libc::c_ulonglong)
                                    .wrapping_sub(1 as libc::c_int as libc::c_ulonglong),
                            );
                            if len > (*req).len {
                                sshfatal(
                                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                        b"do_download\0",
                                    ))
                                    .as_ptr(),
                                    1744 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"Received more data than asked for %zu > %zu\0" as *const u8
                                        as *const libc::c_char,
                                    len,
                                    (*req).len,
                                );
                            }
                            lmodified = 1 as libc::c_int;
                            if (lseek(local_fd, (*req).offset as __off_t, 0 as libc::c_int)
                                == -(1 as libc::c_int) as libc::c_long
                                || atomicio(
                                    ::core::mem::transmute::<
                                        Option<
                                            unsafe extern "C" fn(
                                                libc::c_int,
                                                *const libc::c_void,
                                                size_t,
                                            )
                                                -> ssize_t,
                                        >,
                                        Option<
                                            unsafe extern "C" fn(
                                                libc::c_int,
                                                *mut libc::c_void,
                                                size_t,
                                            )
                                                -> ssize_t,
                                        >,
                                    >(Some(
                                        write
                                            as unsafe extern "C" fn(
                                                libc::c_int,
                                                *const libc::c_void,
                                                size_t,
                                            )
                                                -> ssize_t,
                                    )),
                                    local_fd,
                                    data as *mut libc::c_void,
                                    len,
                                ) != len)
                                && write_error == 0
                            {
                                write_errno = *libc::__errno_location();
                                write_error = 1 as libc::c_int;
                                max_req = 0 as libc::c_int as u_int;
                            } else {
                                if maxack < ((*req).offset).wrapping_add(len) {
                                    maxack = ((*req).offset).wrapping_add(len);
                                }
                                if reordered == 0 && (*req).offset <= highwater {
                                    highwater = maxack;
                                } else if reordered == 0 && (*req).offset > highwater {
                                    reordered = 1 as libc::c_int;
                                }
                            }
                            progress_counter = (progress_counter as libc::c_ulong).wrapping_add(len)
                                as off_t as off_t;
                            libc::free(data as *mut libc::c_void);
                            if len == (*req).len {
                                if !((*req).tq.tqe_next).is_null() {
                                    (*(*req).tq.tqe_next).tq.tqe_prev = (*req).tq.tqe_prev;
                                } else {
                                    requests.tqh_last = (*req).tq.tqe_prev;
                                }
                                *(*req).tq.tqe_prev = (*req).tq.tqe_next;
                                libc::free(req as *mut libc::c_void);
                                num_req = num_req.wrapping_sub(1);
                                num_req;
                            } else {
                                crate::log::sshlog(
                                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                        b"do_download\0",
                                    ))
                                    .as_ptr(),
                                    1780 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG3,
                                    0 as *const libc::c_char,
                                    b"Short data block, re-requesting %llu -> %llu (%2d)\0"
                                        as *const u8
                                        as *const libc::c_char,
                                    ((*req).offset as libc::c_ulonglong)
                                        .wrapping_add(len as libc::c_ulonglong),
                                    ((*req).offset as libc::c_ulonglong)
                                        .wrapping_add((*req).len as libc::c_ulonglong)
                                        .wrapping_sub(1 as libc::c_int as libc::c_ulonglong),
                                    num_req,
                                );
                                let fresh28 = (*conn).msg_id;
                                (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
                                (*req).id = fresh28;
                                (*req).len = ((*req).len as libc::c_ulong).wrapping_sub(len)
                                    as size_t
                                    as size_t;
                                (*req).offset = ((*req).offset as libc::c_ulong).wrapping_add(len)
                                    as u_int64_t
                                    as u_int64_t;
                                send_read_request(
                                    conn,
                                    (*req).id,
                                    (*req).offset,
                                    (*req).len as u_int,
                                    handle,
                                    handle_len as u_int,
                                );
                                if len < buflen as libc::c_ulong {
                                    buflen = (if 512 as libc::c_int as libc::c_ulong > len {
                                        512 as libc::c_int as libc::c_ulong
                                    } else {
                                        len
                                    }) as u_int;
                                }
                            }
                            if max_req > 0 as libc::c_int as libc::c_uint {
                                if size > 0 as libc::c_int as libc::c_ulong && offset > size {
                                    crate::log::sshlog(
                                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                            b"do_download\0",
                                        ))
                                        .as_ptr(),
                                        1796 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG3,
                                        0 as *const libc::c_char,
                                        b"Finish at %llu (%2d)\0" as *const u8
                                            as *const libc::c_char,
                                        offset as libc::c_ulonglong,
                                        num_req,
                                    );
                                    max_req = 1 as libc::c_int as u_int;
                                } else if max_req < (*conn).num_requests {
                                    max_req = max_req.wrapping_add(1);
                                    max_req;
                                }
                            }
                        }
                        _ => {
                            sshfatal(
                                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                    b"do_download\0",
                                ))
                                .as_ptr(),
                                1805 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                0 as *const libc::c_char,
                                b"Expected SSH2_FXP_DATA(%u) packet, got %u\0" as *const u8
                                    as *const libc::c_char,
                                103 as libc::c_int,
                                type_0 as libc::c_int,
                            );
                        }
                    }
                }
                if showprogress != 0 && size != 0 {
                    stop_progress_meter();
                }
                if !(requests.tqh_first).is_null() {
                    sshfatal(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                            b"do_download\0",
                        ))
                        .as_ptr(),
                        1814 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Transfer complete, but requests still in queue\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                if read_error == 0 && write_error == 0 && interrupted == 0 {
                    highwater = maxack;
                }
                if inplace_flag != 0 || read_error != 0 || write_error != 0 || interrupted != 0 {
                    if reordered != 0
                        && resume_flag != 0
                        && (read_error != 0 || write_error != 0 || interrupted != 0)
                    {
                        crate::log::sshlog(
                            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"do_download\0",
                            ))
                            .as_ptr(),
                            1829 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"Unable to resume download of \"%s\": server reordered requests\0"
                                as *const u8 as *const libc::c_char,
                            local_path,
                        );
                    }
                    crate::log::sshlog(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                            b"do_download\0",
                        ))
                        .as_ptr(),
                        1831 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"truncating at %llu\0" as *const u8 as *const libc::c_char,
                        highwater as libc::c_ulonglong,
                    );
                    if ftruncate(local_fd, highwater as __off_t) == -(1 as libc::c_int) {
                        crate::log::sshlog(
                            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"do_download\0",
                            ))
                            .as_ptr(),
                            1834 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"local ftruncate \"%s\": %s\0" as *const u8 as *const libc::c_char,
                            local_path,
                            strerror(*libc::__errno_location()),
                        );
                    }
                }
                if read_error != 0 {
                    crate::log::sshlog(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                            b"do_download\0",
                        ))
                        .as_ptr(),
                        1837 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"read remote \"%s\" : %s\0" as *const u8 as *const libc::c_char,
                        remote_path,
                        fx2txt(status as libc::c_int),
                    );
                    status = -(1 as libc::c_int) as u_int;
                    do_close(conn, handle, handle_len as u_int);
                } else if write_error != 0 {
                    crate::log::sshlog(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                            b"do_download\0",
                        ))
                        .as_ptr(),
                        1842 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"write local \"%s\": %s\0" as *const u8 as *const libc::c_char,
                        local_path,
                        strerror(write_errno),
                    );
                    status = 4 as libc::c_int as u_int;
                    do_close(conn, handle, handle_len as u_int);
                } else {
                    if do_close(conn, handle, handle_len as u_int) != 0 as libc::c_int
                        || interrupted != 0
                    {
                        status = 4 as libc::c_int as u_int;
                    } else {
                        status = 0 as libc::c_int as u_int;
                    }
                    if preserve_flag != 0 && libc::fchmod(local_fd, mode) == -(1 as libc::c_int) {
                        crate::log::sshlog(
                            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"do_download\0",
                            ))
                            .as_ptr(),
                            1857 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"local chmod \"%s\": %s\0" as *const u8 as *const libc::c_char,
                            local_path,
                            strerror(*libc::__errno_location()),
                        );
                    }
                    if preserve_flag != 0 && (*a).flags & 0x8 as libc::c_int as libc::c_uint != 0 {
                        let mut tv: [libc::timeval; 2] = [libc::timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        }; 2];
                        tv[0 as libc::c_int as usize].tv_sec = (*a).atime as __time_t;
                        tv[1 as libc::c_int as usize].tv_sec = (*a).mtime as __time_t;
                        tv[1 as libc::c_int as usize].tv_usec = 0 as libc::c_int as __suseconds_t;
                        tv[0 as libc::c_int as usize].tv_usec =
                            tv[1 as libc::c_int as usize].tv_usec;
                        if libc::utimes(local_path, tv.as_mut_ptr() as *const libc::timeval)
                            == -(1 as libc::c_int)
                        {
                            crate::log::sshlog(
                                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                    b"do_download\0",
                                ))
                                .as_ptr(),
                                1866 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"local set times \"%s\": %s\0" as *const u8 as *const libc::c_char,
                                local_path,
                                strerror(*libc::__errno_location()),
                            );
                        }
                    }
                    if resume_flag != 0 && lmodified == 0 {
                        crate::log::sshlog(
                            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"do_download\0",
                            ))
                            .as_ptr(),
                            1869 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_INFO,
                            0 as *const libc::c_char,
                            b"File \"%s\" was not modified\0" as *const u8 as *const libc::c_char,
                            local_path,
                        );
                    } else if fsync_flag != 0 {
                        crate::log::sshlog(
                            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"do_download\0",
                            ))
                            .as_ptr(),
                            1871 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"syncing \"%s\"\0" as *const u8 as *const libc::c_char,
                            local_path,
                        );
                        if fsync(local_fd) == -(1 as libc::c_int) {
                            crate::log::sshlog(
                                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                    b"do_download\0",
                                ))
                                .as_ptr(),
                                1874 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"local sync \"%s\": %s\0" as *const u8 as *const libc::c_char,
                                local_path,
                                strerror(*libc::__errno_location()),
                            );
                        }
                    }
                }
                close(local_fd);
                sshbuf_free(msg);
                libc::free(handle as *mut libc::c_void);
                return if status == 0 as libc::c_int as libc::c_uint {
                    0 as libc::c_int
                } else {
                    -(1 as libc::c_int)
                };
            }
        }
    }
    do_close(conn, handle, handle_len as u_int);
    libc::free(handle as *mut libc::c_void);
    if local_fd != -(1 as libc::c_int) {
        close(local_fd);
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn download_dir_internal(
    mut conn: *mut sftp_conn,
    mut src: *const libc::c_char,
    mut dst: *const libc::c_char,
    mut depth: libc::c_int,
    mut dirattrib: *mut Attrib,
    mut preserve_flag: libc::c_int,
    mut print_flag: libc::c_int,
    mut resume_flag: libc::c_int,
    mut fsync_flag: libc::c_int,
    mut follow_link_flag: libc::c_int,
    mut inplace_flag: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut dir_entries: *mut *mut SFTP_DIRENT = 0 as *mut *mut SFTP_DIRENT;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut new_src: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut new_dst: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut mode: mode_t = 0o777 as libc::c_int as mode_t;
    let mut tmpmode: mode_t = mode;
    if depth >= 64 as libc::c_int {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"download_dir_internal\0"))
                .as_ptr(),
            1895 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Maximum directory depth exceeded: %d levels\0" as *const u8 as *const libc::c_char,
            depth,
        );
        return -(1 as libc::c_int);
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"download_dir_internal\0"))
            .as_ptr(),
        1899 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"download dir remote \"%s\" to local \"%s\"\0" as *const u8 as *const libc::c_char,
        src,
        dst,
    );
    if dirattrib.is_null() && {
        dirattrib = do_stat(conn, src, 1 as libc::c_int);
        dirattrib.is_null()
    } {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"download_dir_internal\0"))
                .as_ptr(),
            1903 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libc::stat remote \"%s\" directory failed\0" as *const u8 as *const libc::c_char,
            src,
        );
        return -(1 as libc::c_int);
    }
    if !((*dirattrib).perm & 0o170000 as libc::c_int as libc::c_uint
        == 0o40000 as libc::c_int as libc::c_uint)
    {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"download_dir_internal\0"))
                .as_ptr(),
            1907 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"\"%s\" is not a directory\0" as *const u8 as *const libc::c_char,
            src,
        );
        return -(1 as libc::c_int);
    }
    if print_flag != 0 && print_flag != 2 as libc::c_int {
        mprintf(
            b"Retrieving %s\n\0" as *const u8 as *const libc::c_char,
            src,
        );
    }
    if (*dirattrib).flags & 0x4 as libc::c_int as libc::c_uint != 0 {
        mode = (*dirattrib).perm & 0o1777 as libc::c_int as libc::c_uint;
        tmpmode = mode | (0o200 as libc::c_int | 0o100 as libc::c_int) as libc::c_uint;
    } else {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"download_dir_internal\0"))
                .as_ptr(),
            1918 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"download remote \"%s\": server did not send permissions\0" as *const u8
                as *const libc::c_char,
            dst,
        );
    }
    if libc::mkdir(dst, tmpmode) == -(1 as libc::c_int)
        && *libc::__errno_location() != 17 as libc::c_int
    {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"download_dir_internal\0"))
                .as_ptr(),
            1922 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"mkdir %s: %s\0" as *const u8 as *const libc::c_char,
            dst,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if do_readdir(conn, src, &mut dir_entries) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"download_dir_internal\0"))
                .as_ptr(),
            1927 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"remote readdir \"%s\" failed\0" as *const u8 as *const libc::c_char,
            src,
        );
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int;
    while !(*dir_entries.offset(i as isize)).is_null() && interrupted == 0 {
        libc::free(new_dst as *mut libc::c_void);
        libc::free(new_src as *mut libc::c_void);
        filename = (**dir_entries.offset(i as isize)).filename;
        new_dst = path_append(dst, filename);
        new_src = path_append(src, filename);
        if (**dir_entries.offset(i as isize)).a.perm & 0o170000 as libc::c_int as libc::c_uint
            == 0o40000 as libc::c_int as libc::c_uint
        {
            if !(strcmp(filename, b".\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
                || strcmp(filename, b"..\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int)
            {
                if download_dir_internal(
                    conn,
                    new_src,
                    new_dst,
                    depth + 1 as libc::c_int,
                    &mut (**dir_entries.offset(i as isize)).a,
                    preserve_flag,
                    print_flag,
                    resume_flag,
                    fsync_flag,
                    follow_link_flag,
                    inplace_flag,
                ) == -(1 as libc::c_int)
                {
                    ret = -(1 as libc::c_int);
                }
            }
        } else if (**dir_entries.offset(i as isize)).a.perm
            & 0o170000 as libc::c_int as libc::c_uint
            == 0o100000 as libc::c_int as libc::c_uint
            || follow_link_flag != 0
                && (**dir_entries.offset(i as isize)).a.perm
                    & 0o170000 as libc::c_int as libc::c_uint
                    == 0o120000 as libc::c_int as libc::c_uint
        {
            if do_download(
                conn,
                new_src,
                new_dst,
                if (**dir_entries.offset(i as isize)).a.perm
                    & 0o170000 as libc::c_int as libc::c_uint
                    == 0o120000 as libc::c_int as libc::c_uint
                {
                    0 as *mut Attrib
                } else {
                    &mut (**dir_entries.offset(i as isize)).a
                },
                preserve_flag,
                resume_flag,
                fsync_flag,
                inplace_flag,
            ) == -(1 as libc::c_int)
            {
                crate::log::sshlog(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"download_dir_internal\0",
                    ))
                    .as_ptr(),
                    1961 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Download of file %s to %s failed\0" as *const u8 as *const libc::c_char,
                    new_src,
                    new_dst,
                );
                ret = -(1 as libc::c_int);
            }
        } else {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"download_dir_internal\0",
                ))
                .as_ptr(),
                1965 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"download \"%s\": not a regular file\0" as *const u8 as *const libc::c_char,
                new_src,
            );
        }
        i += 1;
        i;
    }
    libc::free(new_dst as *mut libc::c_void);
    libc::free(new_src as *mut libc::c_void);
    if preserve_flag != 0 {
        if (*dirattrib).flags & 0x8 as libc::c_int as libc::c_uint != 0 {
            let mut tv: [libc::timeval; 2] = [libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            }; 2];
            tv[0 as libc::c_int as usize].tv_sec = (*dirattrib).atime as __time_t;
            tv[1 as libc::c_int as usize].tv_sec = (*dirattrib).mtime as __time_t;
            tv[1 as libc::c_int as usize].tv_usec = 0 as libc::c_int as __suseconds_t;
            tv[0 as libc::c_int as usize].tv_usec = tv[1 as libc::c_int as usize].tv_usec;
            if libc::utimes(dst, tv.as_mut_ptr() as *const libc::timeval) == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"download_dir_internal\0",
                    ))
                    .as_ptr(),
                    1979 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"local set times on \"%s\": %s\0" as *const u8 as *const libc::c_char,
                    dst,
                    strerror(*libc::__errno_location()),
                );
            }
        } else {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"download_dir_internal\0",
                ))
                .as_ptr(),
                1982 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Server did not send times for directory \"%s\"\0" as *const u8
                    as *const libc::c_char,
                dst,
            );
        }
    }
    if mode != tmpmode && libc::chmod(dst, mode) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"download_dir_internal\0"))
                .as_ptr(),
            1987 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"local chmod directory \"%s\": %s\0" as *const u8 as *const libc::c_char,
            dst,
            strerror(*libc::__errno_location()),
        );
    }
    free_sftp_dirents(dir_entries);
    return ret;
}
pub unsafe extern "C" fn download_dir(
    mut conn: *mut sftp_conn,
    mut src: *const libc::c_char,
    mut dst: *const libc::c_char,
    mut dirattrib: *mut Attrib,
    mut preserve_flag: libc::c_int,
    mut print_flag: libc::c_int,
    mut resume_flag: libc::c_int,
    mut fsync_flag: libc::c_int,
    mut follow_link_flag: libc::c_int,
    mut inplace_flag: libc::c_int,
) -> libc::c_int {
    let mut src_canon: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: libc::c_int = 0;
    src_canon = do_realpath(conn, src);
    if src_canon.is_null() {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"download_dir\0")).as_ptr(),
            2003 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"download \"%s\": path canonicalization failed\0" as *const u8 as *const libc::c_char,
            src,
        );
        return -(1 as libc::c_int);
    }
    ret = download_dir_internal(
        conn,
        src_canon,
        dst,
        0 as libc::c_int,
        dirattrib,
        preserve_flag,
        print_flag,
        resume_flag,
        fsync_flag,
        follow_link_flag,
        inplace_flag,
    );
    libc::free(src_canon as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn do_upload(
    mut conn: *mut sftp_conn,
    mut local_path: *const libc::c_char,
    mut remote_path: *const libc::c_char,
    mut preserve_flag: libc::c_int,
    mut resume: libc::c_int,
    mut fsync_flag: libc::c_int,
    mut inplace_flag: libc::c_int,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut local_fd: libc::c_int = 0;
    let mut openmode: u_int = 0;
    let mut id: u_int = 0;
    let mut status: u_int = 0 as libc::c_int as u_int;
    let mut reordered: u_int = 0 as libc::c_int as u_int;
    let mut offset: off_t = 0;
    let mut progress_counter: off_t = 0;
    let mut type_0: u_char = 0;
    let mut handle: *mut u_char = 0 as *mut u_char;
    let mut data: *mut u_char = 0 as *mut u_char;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    let mut a: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut t: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut c: *mut Attrib = 0 as *mut Attrib;
    let mut startid: u_int32_t = 0;
    let mut ackid: u_int32_t = 0;
    let mut highwater: u_int64_t = 0 as libc::c_int as u_int64_t;
    let mut maxack: u_int64_t = 0 as libc::c_int as u_int64_t;
    let mut ack: *mut request = 0 as *mut request;
    let mut acks: requests = requests {
        tqh_first: 0 as *mut request,
        tqh_last: 0 as *mut *mut request,
    };
    let mut handle_len: size_t = 0;
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0")).as_ptr(),
        2033 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"upload local \"%s\" to remote \"%s\"\0" as *const u8 as *const libc::c_char,
        local_path,
        remote_path,
    );
    acks.tqh_first = 0 as *mut request;
    acks.tqh_last = &mut acks.tqh_first;
    local_fd = libc::open(local_path, 0 as libc::c_int);
    if local_fd == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0")).as_ptr(),
            2038 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"open local \"%s\": %s\0" as *const u8 as *const libc::c_char,
            local_path,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if libc::fstat(local_fd, &mut sb) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0")).as_ptr(),
            2042 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libc::fstat local \"%s\": %s\0" as *const u8 as *const libc::c_char,
            local_path,
            strerror(*libc::__errno_location()),
        );
        close(local_fd);
        return -(1 as libc::c_int);
    }
    if !(sb.st_mode & 0o170000 as libc::c_int as libc::c_uint
        == 0o100000 as libc::c_int as libc::c_uint)
    {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0")).as_ptr(),
            2047 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"local \"%s\" is not a regular file\0" as *const u8 as *const libc::c_char,
            local_path,
        );
        close(local_fd);
        return -(1 as libc::c_int);
    }
    stat_to_attrib(&mut sb, &mut a);
    a.flags &= !(0x1 as libc::c_int) as libc::c_uint;
    a.flags &= !(0x2 as libc::c_int) as libc::c_uint;
    a.perm &= 0o777 as libc::c_int as libc::c_uint;
    if preserve_flag == 0 {
        a.flags &= !(0x8 as libc::c_int) as libc::c_uint;
    }
    if resume != 0 {
        c = do_stat(conn, remote_path, 0 as libc::c_int);
        if c.is_null() {
            close(local_fd);
            return -(1 as libc::c_int);
        }
        if (*c).size as off_t >= sb.st_size {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                    .as_ptr(),
                2068 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"resume \"%s\": destination file same size or larger\0" as *const u8
                    as *const libc::c_char,
                local_path,
            );
            close(local_fd);
            return -(1 as libc::c_int);
        }
        if lseek(local_fd, (*c).size as off_t, 0 as libc::c_int)
            == -(1 as libc::c_int) as libc::c_long
        {
            close(local_fd);
            return -(1 as libc::c_int);
        }
    }
    openmode = (0x2 as libc::c_int | 0x8 as libc::c_int) as u_int;
    if resume != 0 {
        openmode |= 0x4 as libc::c_int as libc::c_uint;
    } else if inplace_flag == 0 {
        openmode |= 0x10 as libc::c_int as libc::c_uint;
    }
    if send_open(
        conn,
        remote_path,
        b"dest\0" as *const u8 as *const libc::c_char,
        openmode,
        &mut a,
        &mut handle,
        &mut handle_len,
    ) != 0 as libc::c_int
    {
        close(local_fd);
        return -(1 as libc::c_int);
    }
    id = (*conn).msg_id;
    ackid = id.wrapping_add(1 as libc::c_int as libc::c_uint);
    startid = ackid;
    data = xmalloc((*conn).upload_buflen as size_t) as *mut u_char;
    progress_counter = (if resume != 0 {
        (*c).size
    } else {
        0 as libc::c_int as libc::c_ulong
    }) as off_t;
    offset = progress_counter;
    if showprogress != 0 {
        start_progress_meter(
            progress_meter_path(local_path),
            sb.st_size,
            &mut progress_counter,
        );
    }
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0")).as_ptr(),
            2104 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    loop {
        let mut len: libc::c_int = 0;
        if interrupted != 0 || status != 0 as libc::c_int as libc::c_uint {
            len = 0 as libc::c_int;
        } else {
            loop {
                len = read(
                    local_fd,
                    data as *mut libc::c_void,
                    (*conn).upload_buflen as size_t,
                ) as libc::c_int;
                if !(len == -(1 as libc::c_int)
                    && (*libc::__errno_location() == 4 as libc::c_int
                        || *libc::__errno_location() == 11 as libc::c_int
                        || *libc::__errno_location() == 11 as libc::c_int))
                {
                    break;
                }
            }
        }
        if len == -(1 as libc::c_int) {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                    .as_ptr(),
                2123 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"read local \"%s\": %s\0" as *const u8 as *const libc::c_char,
                local_path,
                strerror(*libc::__errno_location()),
            );
        } else {
            if len != 0 as libc::c_int {
                id = id.wrapping_add(1);
                ack = request_enqueue(&mut acks, id, len as size_t, offset as uint64_t);
                sshbuf_reset(msg);
                r = sshbuf_put_u8(msg, 6 as libc::c_int as u_char);
                if r != 0 as libc::c_int
                    || {
                        r = sshbuf_put_u32(msg, (*ack).id);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_string(msg, handle as *const libc::c_void, handle_len);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_u64(msg, offset as u_int64_t);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_string(msg, data as *const libc::c_void, len as size_t);
                        r != 0 as libc::c_int
                    }
                {
                    sshfatal(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                            .as_ptr(),
                        2133 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose\0" as *const u8 as *const libc::c_char,
                    );
                }
                send_msg(conn, msg);
                crate::log::sshlog(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                        .as_ptr(),
                    2136 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u\0" as *const u8
                        as *const libc::c_char,
                    id,
                    offset as libc::c_ulonglong,
                    len,
                );
            } else if (acks.tqh_first).is_null() {
                break;
            }
            if ack.is_null() {
                sshfatal(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                        .as_ptr(),
                    2141 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Unexpected ACK %u\0" as *const u8 as *const libc::c_char,
                    id,
                );
            }
            if id == startid
                || len == 0 as libc::c_int
                || id.wrapping_sub(ackid) >= (*conn).num_requests
            {
                let mut rid: u_int = 0;
                sshbuf_reset(msg);
                get_msg(conn, msg);
                r = sshbuf_get_u8(msg, &mut type_0);
                if r != 0 as libc::c_int || {
                    r = sshbuf_get_u32(msg, &mut rid);
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                            .as_ptr(),
                        2151 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse\0" as *const u8 as *const libc::c_char,
                    );
                }
                if type_0 as libc::c_int != 101 as libc::c_int {
                    sshfatal(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                            .as_ptr(),
                        2155 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Expected SSH2_FXP_STATUS(%d) packet, got %d\0" as *const u8
                            as *const libc::c_char,
                        101 as libc::c_int,
                        type_0 as libc::c_int,
                    );
                }
                r = sshbuf_get_u32(msg, &mut status);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                            .as_ptr(),
                        2158 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse status\0" as *const u8 as *const libc::c_char,
                    );
                }
                crate::log::sshlog(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                        .as_ptr(),
                    2159 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH2_FXP_STATUS %u\0" as *const u8 as *const libc::c_char,
                    status,
                );
                ack = request_find(&mut acks, rid);
                if ack.is_null() {
                    sshfatal(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                            .as_ptr(),
                        2163 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Can't find request for ID %u\0" as *const u8 as *const libc::c_char,
                        rid,
                    );
                }
                if !((*ack).tq.tqe_next).is_null() {
                    (*(*ack).tq.tqe_next).tq.tqe_prev = (*ack).tq.tqe_prev;
                } else {
                    acks.tqh_last = (*ack).tq.tqe_prev;
                }
                *(*ack).tq.tqe_prev = (*ack).tq.tqe_next;
                crate::log::sshlog(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                        .as_ptr(),
                    2166 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"In write loop, ack for %u %zu bytes at %lld\0" as *const u8
                        as *const libc::c_char,
                    (*ack).id,
                    (*ack).len,
                    (*ack).offset as libc::c_ulonglong,
                );
                ackid = ackid.wrapping_add(1);
                ackid;
                progress_counter =
                    (progress_counter as libc::c_ulong).wrapping_add((*ack).len) as off_t as off_t;
                if maxack < ((*ack).offset).wrapping_add((*ack).len) {
                    maxack = ((*ack).offset).wrapping_add((*ack).len);
                }
                if reordered == 0 && (*ack).offset <= highwater {
                    highwater = maxack;
                } else if reordered == 0 && (*ack).offset > highwater {
                    crate::log::sshlog(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                            .as_ptr(),
                        2180 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"server reordered ACKs\0" as *const u8 as *const libc::c_char,
                    );
                    reordered = 1 as libc::c_int as u_int;
                }
                libc::free(ack as *mut libc::c_void);
            }
            offset += len as libc::c_long;
            if offset < 0 as libc::c_int as libc::c_long {
                sshfatal(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0"))
                        .as_ptr(),
                    2187 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"offset < 0\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
    sshbuf_free(msg);
    if showprogress != 0 {
        stop_progress_meter();
    }
    libc::free(data as *mut libc::c_void);
    if status == 0 as libc::c_int as libc::c_uint && interrupted == 0 {
        highwater = maxack;
    }
    if status != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0")).as_ptr(),
            2200 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"write remote \"%s\": %s\0" as *const u8 as *const libc::c_char,
            remote_path,
            fx2txt(status as libc::c_int),
        );
        status = 4 as libc::c_int as u_int;
    }
    if inplace_flag != 0
        || resume != 0 && (status != 0 as libc::c_int as libc::c_uint || interrupted != 0)
    {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0")).as_ptr(),
            2205 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"truncating at %llu\0" as *const u8 as *const libc::c_char,
            highwater as libc::c_ulonglong,
        );
        attrib_clear(&mut t);
        t.flags = 0x1 as libc::c_int as u_int32_t;
        t.size = highwater;
        do_fsetstat(conn, handle, handle_len as u_int, &mut t);
    }
    if close(local_fd) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"do_upload\0")).as_ptr(),
            2213 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"close local \"%s\": %s\0" as *const u8 as *const libc::c_char,
            local_path,
            strerror(*libc::__errno_location()),
        );
        status = 4 as libc::c_int as u_int;
    }
    if preserve_flag != 0 {
        do_fsetstat(conn, handle, handle_len as u_int, &mut a);
    }
    if fsync_flag != 0 {
        do_fsync(conn, handle, handle_len as u_int);
    }
    if do_close(conn, handle, handle_len as u_int) != 0 as libc::c_int {
        status = 4 as libc::c_int as u_int;
    }
    libc::free(handle as *mut libc::c_void);
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
unsafe extern "C" fn upload_dir_internal(
    mut conn: *mut sftp_conn,
    mut src: *const libc::c_char,
    mut dst: *const libc::c_char,
    mut depth: libc::c_int,
    mut preserve_flag: libc::c_int,
    mut print_flag: libc::c_int,
    mut resume: libc::c_int,
    mut fsync_flag: libc::c_int,
    mut follow_link_flag: libc::c_int,
    mut inplace_flag: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut dirp: *mut DIR = 0 as *mut DIR;
    let mut dp: *mut dirent = 0 as *mut dirent;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut new_src: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut new_dst: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    let mut a: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut dirattrib: *mut Attrib = 0 as *mut Attrib;
    let mut saved_perm: u_int32_t = 0;
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"upload_dir_internal\0"))
            .as_ptr(),
        2245 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"upload local dir \"%s\" to remote \"%s\"\0" as *const u8 as *const libc::c_char,
        src,
        dst,
    );
    if depth >= 64 as libc::c_int {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"upload_dir_internal\0"))
                .as_ptr(),
            2248 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Maximum directory depth exceeded: %d levels\0" as *const u8 as *const libc::c_char,
            depth,
        );
        return -(1 as libc::c_int);
    }
    if libc::stat(src, &mut sb) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"upload_dir_internal\0"))
                .as_ptr(),
            2253 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libc::stat local \"%s\": %s\0" as *const u8 as *const libc::c_char,
            src,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if !(sb.st_mode & 0o170000 as libc::c_int as libc::c_uint
        == 0o40000 as libc::c_int as libc::c_uint)
    {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"upload_dir_internal\0"))
                .as_ptr(),
            2257 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"\"%s\" is not a directory\0" as *const u8 as *const libc::c_char,
            src,
        );
        return -(1 as libc::c_int);
    }
    if print_flag != 0 && print_flag != 2 as libc::c_int {
        mprintf(b"Entering %s\n\0" as *const u8 as *const libc::c_char, src);
    }
    stat_to_attrib(&mut sb, &mut a);
    a.flags &= !(0x1 as libc::c_int) as libc::c_uint;
    a.flags &= !(0x2 as libc::c_int) as libc::c_uint;
    a.perm &= 0o1777 as libc::c_int as libc::c_uint;
    if preserve_flag == 0 {
        a.flags &= !(0x8 as libc::c_int) as libc::c_uint;
    }
    saved_perm = a.perm;
    a.perm |= (0o200 as libc::c_int | 0o100 as libc::c_int) as libc::c_uint;
    if do_mkdir(conn, dst, &mut a, 0 as libc::c_int) != 0 as libc::c_int {
        dirattrib = do_stat(conn, dst, 0 as libc::c_int);
        if dirattrib.is_null() {
            return -(1 as libc::c_int);
        }
        if !((*dirattrib).perm & 0o170000 as libc::c_int as libc::c_uint
            == 0o40000 as libc::c_int as libc::c_uint)
        {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"upload_dir_internal\0",
                ))
                .as_ptr(),
                2282 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"\"%s\" exists but is not a directory\0" as *const u8 as *const libc::c_char,
                dst,
            );
            return -(1 as libc::c_int);
        }
    }
    a.perm = saved_perm;
    dirp = opendir(src);
    if dirp.is_null() {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"upload_dir_internal\0"))
                .as_ptr(),
            2289 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"local opendir \"%s\": %s\0" as *const u8 as *const libc::c_char,
            src,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    loop {
        dp = readdir(dirp);
        if !(!dp.is_null() && interrupted == 0) {
            break;
        }
        if (*dp).d_ino == 0 as libc::c_int as libc::c_ulong {
            continue;
        }
        libc::free(new_dst as *mut libc::c_void);
        libc::free(new_src as *mut libc::c_void);
        filename = ((*dp).d_name).as_mut_ptr();
        new_dst = path_append(dst, filename);
        new_src = path_append(src, filename);
        if lstat(new_src, &mut sb) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"upload_dir_internal\0",
                ))
                .as_ptr(),
                2304 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"local lstat \"%s\": %s\0" as *const u8 as *const libc::c_char,
                filename,
                strerror(*libc::__errno_location()),
            );
            ret = -(1 as libc::c_int);
        } else if sb.st_mode & 0o170000 as libc::c_int as libc::c_uint
            == 0o40000 as libc::c_int as libc::c_uint
        {
            if strcmp(filename, b".\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
                || strcmp(filename, b"..\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            {
                continue;
            }
            if upload_dir_internal(
                conn,
                new_src,
                new_dst,
                depth + 1 as libc::c_int,
                preserve_flag,
                print_flag,
                resume,
                fsync_flag,
                follow_link_flag,
                inplace_flag,
            ) == -(1 as libc::c_int)
            {
                ret = -(1 as libc::c_int);
            }
        } else if sb.st_mode & 0o170000 as libc::c_int as libc::c_uint
            == 0o100000 as libc::c_int as libc::c_uint
            || follow_link_flag != 0
                && sb.st_mode & 0o170000 as libc::c_int as libc::c_uint
                    == 0o120000 as libc::c_int as libc::c_uint
        {
            if do_upload(
                conn,
                new_src,
                new_dst,
                preserve_flag,
                resume,
                fsync_flag,
                inplace_flag,
            ) == -(1 as libc::c_int)
            {
                crate::log::sshlog(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"upload_dir_internal\0",
                    ))
                    .as_ptr(),
                    2321 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"upload \"%s\" to \"%s\" failed\0" as *const u8 as *const libc::c_char,
                    new_src,
                    new_dst,
                );
                ret = -(1 as libc::c_int);
            }
        } else {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"upload_dir_internal\0",
                ))
                .as_ptr(),
                2325 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"%s: not a regular file\0" as *const u8 as *const libc::c_char,
                filename,
            );
        }
    }
    libc::free(new_dst as *mut libc::c_void);
    libc::free(new_src as *mut libc::c_void);
    do_setstat(conn, dst, &mut a);
    closedir(dirp);
    return ret;
}
pub unsafe extern "C" fn upload_dir(
    mut conn: *mut sftp_conn,
    mut src: *const libc::c_char,
    mut dst: *const libc::c_char,
    mut preserve_flag: libc::c_int,
    mut print_flag: libc::c_int,
    mut resume: libc::c_int,
    mut fsync_flag: libc::c_int,
    mut follow_link_flag: libc::c_int,
    mut inplace_flag: libc::c_int,
) -> libc::c_int {
    let mut dst_canon: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: libc::c_int = 0;
    dst_canon = do_realpath(conn, dst);
    if dst_canon.is_null() {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"upload_dir\0")).as_ptr(),
            2345 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"upload \"%s\": path canonicalization failed\0" as *const u8 as *const libc::c_char,
            dst,
        );
        return -(1 as libc::c_int);
    }
    ret = upload_dir_internal(
        conn,
        src,
        dst_canon,
        0 as libc::c_int,
        preserve_flag,
        print_flag,
        resume,
        fsync_flag,
        follow_link_flag,
        inplace_flag,
    );
    libc::free(dst_canon as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn handle_dest_replies(
    mut to: *mut sftp_conn,
    mut _to_path: *const libc::c_char,
    mut synchronous: libc::c_int,
    mut nreqsp: *mut u_int,
    mut write_errorp: *mut u_int,
) {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut type_0: u_char = 0;
    let mut id: u_int = 0;
    let mut status: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut pfd: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"handle_dest_replies\0"))
                .as_ptr(),
            2367 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    while *nreqsp > 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"handle_dest_replies\0"))
                .as_ptr(),
            2371 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"%u outstanding replies\0" as *const u8 as *const libc::c_char,
            *nreqsp,
        );
        if synchronous == 0 {
            pfd.fd = (*to).fd_in;
            pfd.events = 0x1 as libc::c_int as libc::c_short;
            r = poll(&mut pfd, 1 as libc::c_int as nfds_t, 0 as libc::c_int);
            if r == -(1 as libc::c_int) {
                if *libc::__errno_location() == 4 as libc::c_int {
                    break;
                }
                sshfatal(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"handle_dest_replies\0",
                    ))
                    .as_ptr(),
                    2379 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"poll: %s\0" as *const u8 as *const libc::c_char,
                    strerror(*libc::__errno_location()),
                );
            } else if r == 0 as libc::c_int {
                break;
            }
        }
        sshbuf_reset(msg);
        get_msg(to, msg);
        r = sshbuf_get_u8(msg, &mut type_0);
        if r != 0 as libc::c_int || {
            r = sshbuf_get_u32(msg, &mut id);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"handle_dest_replies\0",
                ))
                .as_ptr(),
                2388 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"dest parse\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"handle_dest_replies\0"))
                .as_ptr(),
            2389 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"Received dest reply T:%u I:%u R:%u\0" as *const u8 as *const libc::c_char,
            type_0 as libc::c_int,
            id,
            *nreqsp,
        );
        if type_0 as libc::c_int != 101 as libc::c_int {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"handle_dest_replies\0",
                ))
                .as_ptr(),
                2392 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Expected SSH2_FXP_STATUS(%d) packet, got %d\0" as *const u8
                    as *const libc::c_char,
                101 as libc::c_int,
                type_0 as libc::c_int,
            );
        }
        r = sshbuf_get_u32(msg, &mut status);
        if r != 0 as libc::c_int {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"handle_dest_replies\0",
                ))
                .as_ptr(),
                2395 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse dest status\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"handle_dest_replies\0"))
                .as_ptr(),
            2396 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"dest SSH2_FXP_STATUS %u\0" as *const u8 as *const libc::c_char,
            status,
        );
        if status != 0 as libc::c_int as libc::c_uint {
            if *write_errorp == 0 as libc::c_int as libc::c_uint {
                *write_errorp = status;
            }
        }
        *nreqsp = (*nreqsp).wrapping_sub(1);
        *nreqsp;
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"handle_dest_replies\0"))
            .as_ptr(),
        2419 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"done: %u outstanding replies\0" as *const u8 as *const libc::c_char,
        *nreqsp,
    );
    sshbuf_free(msg);
}
pub unsafe extern "C" fn do_crossload(
    mut from: *mut sftp_conn,
    mut to: *mut sftp_conn,
    mut from_path: *const libc::c_char,
    mut to_path: *const libc::c_char,
    mut a: *mut Attrib,
    mut preserve_flag: libc::c_int,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut write_error: libc::c_int = 0;
    let mut read_error: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut offset: u_int64_t = 0 as libc::c_int as u_int64_t;
    let mut size: u_int64_t = 0;
    let mut id: u_int = 0;
    let mut buflen: u_int = 0;
    let mut num_req: u_int = 0;
    let mut max_req: u_int = 0;
    let mut status: u_int = 0 as libc::c_int as u_int;
    let mut num_upload_req: u_int = 0;
    let mut progress_counter: off_t = 0;
    let mut from_handle: *mut u_char = 0 as *mut u_char;
    let mut to_handle: *mut u_char = 0 as *mut u_char;
    let mut from_handle_len: size_t = 0;
    let mut to_handle_len: size_t = 0;
    let mut requests: requests = requests {
        tqh_first: 0 as *mut request,
        tqh_last: 0 as *mut *mut request,
    };
    let mut req: *mut request = 0 as *mut request;
    let mut type_0: u_char = 0;
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0")).as_ptr(),
        2440 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"crossload src \"%s\" to dst \"%s\"\0" as *const u8 as *const libc::c_char,
        from_path,
        to_path,
    );
    requests.tqh_first = 0 as *mut request;
    requests.tqh_last = &mut requests.tqh_first;
    if a.is_null() && {
        a = do_stat(from, from_path, 0 as libc::c_int);
        a.is_null()
    } {
        return -(1 as libc::c_int);
    }
    if (*a).flags & 0x4 as libc::c_int as libc::c_uint != 0
        && !((*a).perm & 0o170000 as libc::c_int as libc::c_uint
            == 0o100000 as libc::c_int as libc::c_uint)
    {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0")).as_ptr(),
            2449 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"download \"%s\": not a regular file\0" as *const u8 as *const libc::c_char,
            from_path,
        );
        return -(1 as libc::c_int);
    }
    if (*a).flags & 0x1 as libc::c_int as libc::c_uint != 0 {
        size = (*a).size;
    } else {
        size = 0 as libc::c_int as u_int64_t;
    }
    buflen = (*from).download_buflen;
    if buflen > (*to).upload_buflen {
        buflen = (*to).upload_buflen;
    }
    if send_open(
        from,
        from_path,
        b"origin\0" as *const u8 as *const libc::c_char,
        0x1 as libc::c_int as u_int,
        0 as *mut Attrib,
        &mut from_handle,
        &mut from_handle_len,
    ) != 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    (*a).flags &= !(0x1 as libc::c_int) as libc::c_uint;
    (*a).flags &= !(0x2 as libc::c_int) as libc::c_uint;
    (*a).perm &= 0o777 as libc::c_int as libc::c_uint;
    if preserve_flag == 0 {
        (*a).flags &= !(0x8 as libc::c_int) as libc::c_uint;
    }
    if send_open(
        to,
        to_path,
        b"dest\0" as *const u8 as *const libc::c_char,
        (0x2 as libc::c_int | 0x8 as libc::c_int | 0x10 as libc::c_int) as u_int,
        a,
        &mut to_handle,
        &mut to_handle_len,
    ) != 0 as libc::c_int
    {
        do_close(from, from_handle, from_handle_len as u_int);
        return -(1 as libc::c_int);
    }
    offset = 0 as libc::c_int as u_int64_t;
    num_upload_req = 0 as libc::c_int as u_int;
    num_req = num_upload_req;
    read_error = num_req as libc::c_int;
    write_error = read_error;
    max_req = 1 as libc::c_int as u_int;
    progress_counter = 0 as libc::c_int as off_t;
    if showprogress != 0 && size != 0 as libc::c_int as libc::c_ulong {
        start_progress_meter(
            progress_meter_path(from_path),
            size as off_t,
            &mut progress_counter,
        );
    }
    msg = sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0")).as_ptr(),
            2490 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    while num_req > 0 as libc::c_int as libc::c_uint || max_req > 0 as libc::c_int as libc::c_uint {
        let mut data: *mut u_char = 0 as *mut u_char;
        let mut len: size_t = 0;
        if interrupted != 0 {
            if num_req == 0 as libc::c_int as libc::c_uint {
                break;
            }
            max_req = 0 as libc::c_int as u_int;
        }
        while num_req < max_req {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0"))
                    .as_ptr(),
                2510 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"Request range %llu -> %llu (%d/%d)\0" as *const u8 as *const libc::c_char,
                offset as libc::c_ulonglong,
                (offset as libc::c_ulonglong)
                    .wrapping_add(buflen as libc::c_ulonglong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulonglong),
                num_req,
                max_req,
            );
            let fresh29 = (*from).msg_id;
            (*from).msg_id = ((*from).msg_id).wrapping_add(1);
            req = request_enqueue(&mut requests, fresh29, buflen as size_t, offset);
            offset = (offset as libc::c_ulong).wrapping_add(buflen as libc::c_ulong) as u_int64_t
                as u_int64_t;
            num_req = num_req.wrapping_add(1);
            num_req;
            send_read_request(
                from,
                (*req).id,
                (*req).offset,
                (*req).len as u_int,
                from_handle,
                from_handle_len as u_int,
            );
        }
        handle_dest_replies(
            to,
            to_path,
            0 as libc::c_int,
            &mut num_upload_req,
            &mut write_error as *mut libc::c_int as *mut u_int,
        );
        sshbuf_reset(msg);
        get_msg(from, msg);
        r = sshbuf_get_u8(msg, &mut type_0);
        if r != 0 as libc::c_int || {
            r = sshbuf_get_u32(msg, &mut id);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0"))
                    .as_ptr(),
                2527 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0")).as_ptr(),
            2529 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"Received origin reply T:%u I:%u R:%d\0" as *const u8 as *const libc::c_char,
            type_0 as libc::c_int,
            id,
            max_req,
        );
        req = request_find(&mut requests, id);
        if req.is_null() {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0"))
                    .as_ptr(),
                2533 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Unexpected reply %u\0" as *const u8 as *const libc::c_char,
                id,
            );
        }
        match type_0 as libc::c_int {
            101 => {
                r = sshbuf_get_u32(msg, &mut status);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"do_crossload\0",
                        ))
                        .as_ptr(),
                        2538 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse status\0" as *const u8 as *const libc::c_char,
                    );
                }
                if status != 1 as libc::c_int as libc::c_uint {
                    read_error = 1 as libc::c_int;
                }
                max_req = 0 as libc::c_int as u_int;
                if !((*req).tq.tqe_next).is_null() {
                    (*(*req).tq.tqe_next).tq.tqe_prev = (*req).tq.tqe_prev;
                } else {
                    requests.tqh_last = (*req).tq.tqe_prev;
                }
                *(*req).tq.tqe_prev = (*req).tq.tqe_next;
                libc::free(req as *mut libc::c_void);
                num_req = num_req.wrapping_sub(1);
                num_req;
            }
            103 => {
                r = sshbuf_get_string(msg, &mut data, &mut len);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"do_crossload\0",
                        ))
                        .as_ptr(),
                        2548 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse data\0" as *const u8 as *const libc::c_char,
                    );
                }
                crate::log::sshlog(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0"))
                        .as_ptr(),
                    2551 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"Received data %llu -> %llu\0" as *const u8 as *const libc::c_char,
                    (*req).offset as libc::c_ulonglong,
                    ((*req).offset as libc::c_ulonglong)
                        .wrapping_add(len as libc::c_ulonglong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulonglong),
                );
                if len > (*req).len {
                    sshfatal(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"do_crossload\0",
                        ))
                        .as_ptr(),
                        2554 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Received more data than asked for %zu > %zu\0" as *const u8
                            as *const libc::c_char,
                        len,
                        (*req).len,
                    );
                }
                sshbuf_reset(msg);
                r = sshbuf_put_u8(msg, 6 as libc::c_int as u_char);
                if r != 0 as libc::c_int
                    || {
                        let fresh30 = (*to).msg_id;
                        (*to).msg_id = ((*to).msg_id).wrapping_add(1);
                        r = sshbuf_put_u32(msg, fresh30);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_string(msg, to_handle as *const libc::c_void, to_handle_len);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_u64(msg, (*req).offset);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_string(msg, data as *const libc::c_void, len);
                        r != 0 as libc::c_int
                    }
                {
                    sshfatal(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"do_crossload\0",
                        ))
                        .as_ptr(),
                        2564 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose write\0" as *const u8 as *const libc::c_char,
                    );
                }
                send_msg(to, msg);
                crate::log::sshlog(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0"))
                        .as_ptr(),
                    2567 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu\0" as *const u8
                        as *const libc::c_char,
                    id,
                    offset as libc::c_ulonglong,
                    len,
                );
                num_upload_req = num_upload_req.wrapping_add(1);
                num_upload_req;
                progress_counter =
                    (progress_counter as libc::c_ulong).wrapping_add(len) as off_t as off_t;
                libc::free(data as *mut libc::c_void);
                if len == (*req).len {
                    if !((*req).tq.tqe_next).is_null() {
                        (*(*req).tq.tqe_next).tq.tqe_prev = (*req).tq.tqe_prev;
                    } else {
                        requests.tqh_last = (*req).tq.tqe_prev;
                    }
                    *(*req).tq.tqe_prev = (*req).tq.tqe_next;
                    libc::free(req as *mut libc::c_void);
                    num_req = num_req.wrapping_sub(1);
                    num_req;
                } else {
                    crate::log::sshlog(
                        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"do_crossload\0",
                        ))
                        .as_ptr(),
                        2582 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"Short data block, re-requesting %llu -> %llu (%2d)\0" as *const u8
                            as *const libc::c_char,
                        ((*req).offset as libc::c_ulonglong).wrapping_add(len as libc::c_ulonglong),
                        ((*req).offset as libc::c_ulonglong)
                            .wrapping_add((*req).len as libc::c_ulonglong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulonglong),
                        num_req,
                    );
                    let fresh31 = (*from).msg_id;
                    (*from).msg_id = ((*from).msg_id).wrapping_add(1);
                    (*req).id = fresh31;
                    (*req).len =
                        ((*req).len as libc::c_ulong).wrapping_sub(len) as size_t as size_t;
                    (*req).offset = ((*req).offset as libc::c_ulong).wrapping_add(len) as u_int64_t
                        as u_int64_t;
                    send_read_request(
                        from,
                        (*req).id,
                        (*req).offset,
                        (*req).len as u_int,
                        from_handle,
                        from_handle_len as u_int,
                    );
                    if len < buflen as libc::c_ulong {
                        buflen = (if 512 as libc::c_int as libc::c_ulong > len {
                            512 as libc::c_int as libc::c_ulong
                        } else {
                            len
                        }) as u_int;
                    }
                }
                if max_req > 0 as libc::c_int as libc::c_uint {
                    if size > 0 as libc::c_int as libc::c_ulong && offset > size {
                        crate::log::sshlog(
                            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"do_crossload\0",
                            ))
                            .as_ptr(),
                            2599 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG3,
                            0 as *const libc::c_char,
                            b"Finish at %llu (%2d)\0" as *const u8 as *const libc::c_char,
                            offset as libc::c_ulonglong,
                            num_req,
                        );
                        max_req = 1 as libc::c_int as u_int;
                    } else if max_req < (*from).num_requests {
                        max_req = max_req.wrapping_add(1);
                        max_req;
                    }
                }
            }
            _ => {
                sshfatal(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0"))
                        .as_ptr(),
                    2608 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Expected SSH2_FXP_DATA(%u) packet, got %u\0" as *const u8
                        as *const libc::c_char,
                    103 as libc::c_int,
                    type_0 as libc::c_int,
                );
            }
        }
    }
    if showprogress != 0 && size != 0 {
        stop_progress_meter();
    }
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0")).as_ptr(),
        2616 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"waiting for %u replies from destination\0" as *const u8 as *const libc::c_char,
        num_upload_req,
    );
    handle_dest_replies(
        to,
        to_path,
        1 as libc::c_int,
        &mut num_upload_req,
        &mut write_error as *mut libc::c_int as *mut u_int,
    );
    if !(requests.tqh_first).is_null() {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0")).as_ptr(),
            2621 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Transfer complete, but requests still in queue\0" as *const u8 as *const libc::c_char,
        );
    }
    if read_error != 0 || write_error != 0 || interrupted != 0 {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0")).as_ptr(),
            2624 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"truncating \"%s\" at 0\0" as *const u8 as *const libc::c_char,
            to_path,
        );
        do_close(to, to_handle, to_handle_len as u_int);
        libc::free(to_handle as *mut libc::c_void);
        if send_open(
            to,
            to_path,
            b"dest\0" as *const u8 as *const libc::c_char,
            (0x2 as libc::c_int | 0x8 as libc::c_int | 0x10 as libc::c_int) as u_int,
            a,
            &mut to_handle,
            &mut to_handle_len,
        ) != 0 as libc::c_int
        {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0"))
                    .as_ptr(),
                2630 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"dest truncate \"%s\" failed\0" as *const u8 as *const libc::c_char,
                to_path,
            );
            to_handle = 0 as *mut u_char;
        }
    }
    if read_error != 0 {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0")).as_ptr(),
            2635 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"read origin \"%s\": %s\0" as *const u8 as *const libc::c_char,
            from_path,
            fx2txt(status as libc::c_int),
        );
        status = -(1 as libc::c_int) as u_int;
        do_close(from, from_handle, from_handle_len as u_int);
        if !to_handle.is_null() {
            do_close(to, to_handle, to_handle_len as u_int);
        }
    } else if write_error != 0 {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_crossload\0")).as_ptr(),
            2641 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"write dest \"%s\": %s\0" as *const u8 as *const libc::c_char,
            to_path,
            fx2txt(write_error),
        );
        status = 4 as libc::c_int as u_int;
        do_close(from, from_handle, from_handle_len as u_int);
        if !to_handle.is_null() {
            do_close(to, to_handle, to_handle_len as u_int);
        }
    } else {
        if do_close(from, from_handle, from_handle_len as u_int) != 0 as libc::c_int
            || interrupted != 0
        {
            status = -(1 as libc::c_int) as u_int;
        } else {
            status = 0 as libc::c_int as u_int;
        }
        if !to_handle.is_null() {
            if preserve_flag != 0 {
                do_fsetstat(to, to_handle, to_handle_len as u_int, a);
            }
            do_close(to, to_handle, to_handle_len as u_int);
        }
    }
    sshbuf_free(msg);
    libc::free(from_handle as *mut libc::c_void);
    libc::free(to_handle as *mut libc::c_void);
    return if status == 0 as libc::c_int as libc::c_uint {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
unsafe extern "C" fn crossload_dir_internal(
    mut from: *mut sftp_conn,
    mut to: *mut sftp_conn,
    mut from_path: *const libc::c_char,
    mut to_path: *const libc::c_char,
    mut depth: libc::c_int,
    mut dirattrib: *mut Attrib,
    mut preserve_flag: libc::c_int,
    mut print_flag: libc::c_int,
    mut follow_link_flag: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut dir_entries: *mut *mut SFTP_DIRENT = 0 as *mut *mut SFTP_DIRENT;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut new_from_path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut new_to_path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut mode: mode_t = 0o777 as libc::c_int as mode_t;
    let mut curdir: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"crossload_dir_internal\0"))
            .as_ptr(),
        2678 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"crossload dir src \"%s\" to dst \"%s\"\0" as *const u8 as *const libc::c_char,
        from_path,
        to_path,
    );
    if depth >= 64 as libc::c_int {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"crossload_dir_internal\0",
            ))
            .as_ptr(),
            2681 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Maximum directory depth exceeded: %d levels\0" as *const u8 as *const libc::c_char,
            depth,
        );
        return -(1 as libc::c_int);
    }
    if dirattrib.is_null() && {
        dirattrib = do_stat(from, from_path, 1 as libc::c_int);
        dirattrib.is_null()
    } {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"crossload_dir_internal\0",
            ))
            .as_ptr(),
            2687 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libc::stat remote \"%s\" failed\0" as *const u8 as *const libc::c_char,
            from_path,
        );
        return -(1 as libc::c_int);
    }
    if !((*dirattrib).perm & 0o170000 as libc::c_int as libc::c_uint
        == 0o40000 as libc::c_int as libc::c_uint)
    {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"crossload_dir_internal\0",
            ))
            .as_ptr(),
            2691 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"\"%s\" is not a directory\0" as *const u8 as *const libc::c_char,
            from_path,
        );
        return -(1 as libc::c_int);
    }
    if print_flag != 0 && print_flag != 2 as libc::c_int {
        mprintf(
            b"Retrieving %s\n\0" as *const u8 as *const libc::c_char,
            from_path,
        );
    }
    curdir = *dirattrib;
    curdir.flags &= !(0x1 as libc::c_int) as libc::c_uint;
    curdir.flags &= !(0x2 as libc::c_int) as libc::c_uint;
    if curdir.flags & 0x4 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"crossload_dir_internal\0",
            ))
            .as_ptr(),
            2702 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Origin did not send permissions for directory \"%s\"\0" as *const u8
                as *const libc::c_char,
            to_path,
        );
        curdir.perm = (0o200 as libc::c_int | 0o100 as libc::c_int) as u_int32_t;
        curdir.flags |= 0x4 as libc::c_int as libc::c_uint;
    }
    mode = curdir.perm & 0o1777 as libc::c_int as libc::c_uint;
    curdir.perm = mode | (0o200 as libc::c_int | 0o100 as libc::c_int) as libc::c_uint;
    if do_mkdir(to, to_path, &mut curdir, 0 as libc::c_int) != 0 as libc::c_int {
        dirattrib = do_stat(to, to_path, 0 as libc::c_int);
        if dirattrib.is_null() {
            return -(1 as libc::c_int);
        }
        if !((*dirattrib).perm & 0o170000 as libc::c_int as libc::c_uint
            == 0o40000 as libc::c_int as libc::c_uint)
        {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"crossload_dir_internal\0",
                ))
                .as_ptr(),
                2720 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"\"%s\" exists but is not a directory\0" as *const u8 as *const libc::c_char,
                to_path,
            );
            return -(1 as libc::c_int);
        }
    }
    curdir.perm = mode;
    if do_readdir(from, from_path, &mut dir_entries) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"crossload_dir_internal\0",
            ))
            .as_ptr(),
            2727 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"origin readdir \"%s\" failed\0" as *const u8 as *const libc::c_char,
            from_path,
        );
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int;
    while !(*dir_entries.offset(i as isize)).is_null() && interrupted == 0 {
        libc::free(new_from_path as *mut libc::c_void);
        libc::free(new_to_path as *mut libc::c_void);
        filename = (**dir_entries.offset(i as isize)).filename;
        new_from_path = path_append(from_path, filename);
        new_to_path = path_append(to_path, filename);
        if (**dir_entries.offset(i as isize)).a.perm & 0o170000 as libc::c_int as libc::c_uint
            == 0o40000 as libc::c_int as libc::c_uint
        {
            if !(strcmp(filename, b".\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
                || strcmp(filename, b"..\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int)
            {
                if crossload_dir_internal(
                    from,
                    to,
                    new_from_path,
                    new_to_path,
                    depth + 1 as libc::c_int,
                    &mut (**dir_entries.offset(i as isize)).a,
                    preserve_flag,
                    print_flag,
                    follow_link_flag,
                ) == -(1 as libc::c_int)
                {
                    ret = -(1 as libc::c_int);
                }
            }
        } else if (**dir_entries.offset(i as isize)).a.perm
            & 0o170000 as libc::c_int as libc::c_uint
            == 0o100000 as libc::c_int as libc::c_uint
            || follow_link_flag != 0
                && (**dir_entries.offset(i as isize)).a.perm
                    & 0o170000 as libc::c_int as libc::c_uint
                    == 0o120000 as libc::c_int as libc::c_uint
        {
            if do_crossload(
                from,
                to,
                new_from_path,
                new_to_path,
                if (**dir_entries.offset(i as isize)).a.perm
                    & 0o170000 as libc::c_int as libc::c_uint
                    == 0o120000 as libc::c_int as libc::c_uint
                {
                    0 as *mut Attrib
                } else {
                    &mut (**dir_entries.offset(i as isize)).a
                },
                preserve_flag,
            ) == -(1 as libc::c_int)
            {
                crate::log::sshlog(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"crossload_dir_internal\0",
                    ))
                    .as_ptr(),
                    2759 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"crossload \"%s\" to \"%s\" failed\0" as *const u8 as *const libc::c_char,
                    new_from_path,
                    new_to_path,
                );
                ret = -(1 as libc::c_int);
            }
        } else {
            crate::log::sshlog(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"crossload_dir_internal\0",
                ))
                .as_ptr(),
                2764 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"origin \"%s\": not a regular file\0" as *const u8 as *const libc::c_char,
                new_from_path,
            );
        }
        i += 1;
        i;
    }
    libc::free(new_to_path as *mut libc::c_void);
    libc::free(new_from_path as *mut libc::c_void);
    do_setstat(to, to_path, &mut curdir);
    free_sftp_dirents(dir_entries);
    return ret;
}
pub unsafe extern "C" fn crossload_dir(
    mut from: *mut sftp_conn,
    mut to: *mut sftp_conn,
    mut from_path: *const libc::c_char,
    mut to_path: *const libc::c_char,
    mut dirattrib: *mut Attrib,
    mut preserve_flag: libc::c_int,
    mut print_flag: libc::c_int,
    mut follow_link_flag: libc::c_int,
) -> libc::c_int {
    let mut from_path_canon: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: libc::c_int = 0;
    from_path_canon = do_realpath(from, from_path);
    if from_path_canon.is_null() {
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"crossload_dir\0"))
                .as_ptr(),
            2787 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"crossload \"%s\": path canonicalization failed\0" as *const u8 as *const libc::c_char,
            from_path,
        );
        return -(1 as libc::c_int);
    }
    ret = crossload_dir_internal(
        from,
        to,
        from_path_canon,
        to_path,
        0 as libc::c_int,
        dirattrib,
        preserve_flag,
        print_flag,
        follow_link_flag,
    );
    libc::free(from_path_canon as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn can_get_users_groups_by_id(mut conn: *mut sftp_conn) -> libc::c_int {
    return ((*conn).exts & 0x200 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint)
        as libc::c_int;
}
pub unsafe extern "C" fn do_get_users_groups_by_id(
    mut conn: *mut sftp_conn,
    mut uids: *const u_int,
    mut nuids: u_int,
    mut gids: *const u_int,
    mut ngids: u_int,
    mut usernamesp: *mut *mut *mut libc::c_char,
    mut groupnamesp: *mut *mut *mut libc::c_char,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut uidbuf: *mut sshbuf = 0 as *mut sshbuf;
    let mut gidbuf: *mut sshbuf = 0 as *mut sshbuf;
    let mut i: u_int = 0;
    let mut expected_id: u_int = 0;
    let mut id: u_int = 0;
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut usernames: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut groupnames: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut type_0: u_char = 0;
    let mut r: libc::c_int = 0;
    *groupnamesp = 0 as *mut *mut libc::c_char;
    *usernamesp = *groupnamesp;
    if can_get_users_groups_by_id(conn) == 0 {
        return -(59 as libc::c_int);
    }
    msg = sshbuf_new();
    if msg.is_null()
        || {
            uidbuf = sshbuf_new();
            uidbuf.is_null()
        }
        || {
            gidbuf = sshbuf_new();
            gidbuf.is_null()
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"do_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            2822 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    let fresh32 = (*conn).msg_id;
    (*conn).msg_id = ((*conn).msg_id).wrapping_add(1);
    id = fresh32;
    expected_id = id;
    crate::log::sshlog(
        b"sftp-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"do_get_users_groups_by_id\0"))
            .as_ptr(),
        2824 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)\0" as *const u8
            as *const libc::c_char,
    );
    i = 0 as libc::c_int as u_int;
    while i < nuids {
        r = sshbuf_put_u32(uidbuf, *uids.offset(i as isize));
        if r != 0 as libc::c_int {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"do_get_users_groups_by_id\0",
                ))
                .as_ptr(),
                2827 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose uids\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < ngids {
        r = sshbuf_put_u32(gidbuf, *gids.offset(i as isize));
        if r != 0 as libc::c_int {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"do_get_users_groups_by_id\0",
                ))
                .as_ptr(),
                2831 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose gids\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    r = sshbuf_put_u8(msg, 200 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(
                msg,
                b"users-groups-by-id@openssh.com\0" as *const u8 as *const libc::c_char,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(msg, uidbuf);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(msg, gidbuf);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"do_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            2839 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(conn, msg);
    get_msg(conn, msg);
    r = sshbuf_get_u8(msg, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(msg, &mut id);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"do_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            2844 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if id != expected_id {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"do_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            2846 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ID mismatch (%u != %u)\0" as *const u8 as *const libc::c_char,
            id,
            expected_id,
        );
    }
    if type_0 as libc::c_int == 101 as libc::c_int {
        let mut status: u_int = 0;
        let mut errmsg: *mut libc::c_char = 0 as *mut libc::c_char;
        r = sshbuf_get_u32(msg, &mut status);
        if r != 0 as libc::c_int || {
            r = sshbuf_get_cstring(msg, &mut errmsg, 0 as *mut size_t);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"do_get_users_groups_by_id\0",
                ))
                .as_ptr(),
                2853 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse status\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::log::sshlog(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"do_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            2855 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"users-groups-by-id %s\0" as *const u8 as *const libc::c_char,
            if *errmsg as libc::c_int == '\0' as i32 {
                fx2txt(status as libc::c_int)
            } else {
                errmsg as *const libc::c_char
            },
        );
        libc::free(errmsg as *mut libc::c_void);
        sshbuf_free(msg);
        sshbuf_free(uidbuf);
        sshbuf_free(gidbuf);
        return -(1 as libc::c_int);
    } else if type_0 as libc::c_int != 201 as libc::c_int {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"do_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            2863 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u\0" as *const u8
                as *const libc::c_char,
            201 as libc::c_int,
            type_0 as libc::c_int,
        );
    }
    sshbuf_free(uidbuf);
    sshbuf_free(gidbuf);
    gidbuf = 0 as *mut sshbuf;
    uidbuf = gidbuf;
    r = sshbuf_froms(msg, &mut uidbuf);
    if r != 0 as libc::c_int || {
        r = sshbuf_froms(msg, &mut gidbuf);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"do_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            2871 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse response\0" as *const u8 as *const libc::c_char,
        );
    }
    if nuids > 0 as libc::c_int as libc::c_uint {
        usernames = xcalloc(
            nuids as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        ) as *mut *mut libc::c_char;
        i = 0 as libc::c_int as u_int;
        while i < nuids {
            r = sshbuf_get_cstring(uidbuf, &mut name, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"do_get_users_groups_by_id\0",
                    ))
                    .as_ptr(),
                    2876 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse user name\0" as *const u8 as *const libc::c_char,
                );
            }
            if *name as libc::c_int == '\0' as i32 {
                libc::free(name as *mut libc::c_void);
                name = 0 as *mut libc::c_char;
            }
            let ref mut fresh33 = *usernames.offset(i as isize);
            *fresh33 = name;
            i = i.wrapping_add(1);
            i;
        }
    }
    if ngids > 0 as libc::c_int as libc::c_uint {
        groupnames = xcalloc(
            ngids as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        ) as *mut *mut libc::c_char;
        i = 0 as libc::c_int as u_int;
        while i < ngids {
            r = sshbuf_get_cstring(gidbuf, &mut name, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sftp-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"do_get_users_groups_by_id\0",
                    ))
                    .as_ptr(),
                    2889 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse user name\0" as *const u8 as *const libc::c_char,
                );
            }
            if *name as libc::c_int == '\0' as i32 {
                libc::free(name as *mut libc::c_void);
                name = 0 as *mut libc::c_char;
            }
            let ref mut fresh34 = *groupnames.offset(i as isize);
            *fresh34 = name;
            i = i.wrapping_add(1);
            i;
        }
    }
    if sshbuf_len(uidbuf) != 0 as libc::c_int as libc::c_ulong {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"do_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            2899 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"unexpected extra username data\0" as *const u8 as *const libc::c_char,
        );
    }
    if sshbuf_len(gidbuf) != 0 as libc::c_int as libc::c_ulong {
        sshfatal(
            b"sftp-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"do_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            2901 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"unexpected extra groupname data\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(uidbuf);
    sshbuf_free(gidbuf);
    sshbuf_free(msg);
    *usernamesp = usernames;
    *groupnamesp = groupnames;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn path_append(
    mut p1: *const libc::c_char,
    mut p2: *const libc::c_char,
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = (strlen(p1))
        .wrapping_add(strlen(p2))
        .wrapping_add(2 as libc::c_int as libc::c_ulong);
    ret = xmalloc(len) as *mut libc::c_char;
    strlcpy(ret, p1, len);
    if *p1.offset(0 as libc::c_int as isize) as libc::c_int != '\0' as i32
        && *p1.offset((strlen(p1)).wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
            as libc::c_int
            != '/' as i32
    {
        strlcat(ret, b"/\0" as *const u8 as *const libc::c_char, len);
    }
    strlcat(ret, p2, len);
    return ret;
}
pub unsafe extern "C" fn make_absolute(
    mut p: *mut libc::c_char,
    mut pwd: *const libc::c_char,
) -> *mut libc::c_char {
    let mut abs_str: *mut libc::c_char = 0 as *mut libc::c_char;
    if !p.is_null() && path_absolute(p) == 0 {
        abs_str = path_append(pwd, p);
        libc::free(p as *mut libc::c_void);
        return abs_str;
    } else {
        return p;
    };
}
pub unsafe extern "C" fn remote_is_dir(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
) -> libc::c_int {
    let mut a: *mut Attrib = 0 as *mut Attrib;
    a = do_stat(conn, path, 1 as libc::c_int);
    if a.is_null() {
        return 0 as libc::c_int;
    }
    if (*a).flags & 0x4 as libc::c_int as libc::c_uint == 0 {
        return 0 as libc::c_int;
    }
    return ((*a).perm & 0o170000 as libc::c_int as libc::c_uint
        == 0o40000 as libc::c_int as libc::c_uint) as libc::c_int;
}
pub unsafe extern "C" fn local_is_dir(mut path: *const libc::c_char) -> libc::c_int {
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    if libc::stat(path, &mut sb) == -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    return (sb.st_mode & 0o170000 as libc::c_int as libc::c_uint
        == 0o40000 as libc::c_int as libc::c_uint) as libc::c_int;
}
pub unsafe extern "C" fn globpath_is_dir(mut pathname: *const libc::c_char) -> libc::c_int {
    let mut l: size_t = strlen(pathname);
    return (l > 0 as libc::c_int as libc::c_ulong
        && *pathname.offset(l.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
            as libc::c_int
            == '/' as i32) as libc::c_int;
}
