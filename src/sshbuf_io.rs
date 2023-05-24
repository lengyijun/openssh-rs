use ::libc;
extern "C" {
    pub type sshbuf;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn fstat(__fd: libc::c_int, __buf: *mut stat) -> libc::c_int;
    fn __errno_location() -> *mut libc::c_int;
    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn sshbuf_new() -> *mut sshbuf;
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_mutable_ptr(buf: *const sshbuf) -> *mut u_char;
    fn sshbuf_put(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn atomicio(
        _: Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        _: libc::c_int,
        _: *mut libc::c_void,
        _: size_t,
    ) -> size_t;
}
pub type __u_char = libc::c_uchar;
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
pub type u_char = __u_char;
pub type off_t = __off_t;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: libc::c_int,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atim: timespec,
    pub st_mtim: timespec,
    pub st_ctim: timespec,
    pub __glibc_reserved: [__syscall_slong_t; 3],
}
pub unsafe extern "C" fn sshbuf_load_fd(
    mut fd: libc::c_int,
    mut blobp: *mut *mut sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut buf: [u_char; 4096] = [0; 4096];
    let mut len: size_t = 0;
    let mut st: stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_mtim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_ctim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        __glibc_reserved: [0; 3],
    };
    let mut r: libc::c_int = 0;
    let mut blob: *mut sshbuf = 0 as *mut sshbuf;
    *blobp = 0 as *mut sshbuf;
    if fstat(fd, &mut st) == -(1 as libc::c_int) {
        return -(24 as libc::c_int);
    }
    if st.st_mode
        & (0o140000 as libc::c_int | 0o20000 as libc::c_int | 0o10000 as libc::c_int)
            as libc::c_uint
        == 0 as libc::c_int as libc::c_uint
        && st.st_size > 0x8000000 as libc::c_int as libc::c_long
    {
        return -(4 as libc::c_int);
    }
    blob = sshbuf_new();
    if blob.is_null() {
        return -(2 as libc::c_int);
    }
    loop {
        len = atomicio(
            Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::core::mem::size_of::<[u_char; 4096]>() as libc::c_ulong,
        );
        if len == 0 as libc::c_int as libc::c_ulong {
            if *__errno_location() == 32 as libc::c_int {
                current_block = 10048703153582371463;
                break;
            }
            r = -(24 as libc::c_int);
            current_block = 10795476747093546695;
            break;
        } else {
            r = sshbuf_put(blob, buf.as_mut_ptr() as *const libc::c_void, len);
            if r != 0 as libc::c_int {
                current_block = 10795476747093546695;
                break;
            }
            if !(sshbuf_len(blob) > 0x8000000 as libc::c_int as libc::c_ulong) {
                continue;
            }
            r = -(4 as libc::c_int);
            current_block = 10795476747093546695;
            break;
        }
    }
    match current_block {
        10048703153582371463 => {
            if st.st_mode
                & (0o140000 as libc::c_int | 0o20000 as libc::c_int | 0o10000 as libc::c_int)
                    as libc::c_uint
                == 0 as libc::c_int as libc::c_uint
                && st.st_size != sshbuf_len(blob) as off_t
            {
                r = -(41 as libc::c_int);
            } else {
                *blobp = blob;
                blob = 0 as *mut sshbuf;
                r = 0 as libc::c_int;
            }
        }
        _ => {}
    }
    explicit_bzero(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 4096]>() as libc::c_ulong,
    );
    sshbuf_free(blob);
    return r;
}
pub unsafe extern "C" fn sshbuf_load_file(
    mut path: *const libc::c_char,
    mut bufp: *mut *mut sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    *bufp = 0 as *mut sshbuf;
    fd = open(path, 0 as libc::c_int);
    if fd == -(1 as libc::c_int) {
        return -(24 as libc::c_int);
    }
    r = sshbuf_load_fd(fd, bufp);
    if !(r != 0 as libc::c_int) {
        r = 0 as libc::c_int;
    }
    oerrno = *__errno_location();
    close(fd);
    if r != 0 as libc::c_int {
        *__errno_location() = oerrno;
    }
    return r;
}
pub unsafe extern "C" fn sshbuf_write_file(
    mut path: *const libc::c_char,
    mut buf: *mut sshbuf,
) -> libc::c_int {
    let mut fd: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    fd = open(
        path,
        0o1 as libc::c_int | 0o100 as libc::c_int | 0o1000 as libc::c_int,
        0o644 as libc::c_int,
    );
    if fd == -(1 as libc::c_int) {
        return -(24 as libc::c_int);
    }
    if atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        fd,
        sshbuf_mutable_ptr(buf) as *mut libc::c_void,
        sshbuf_len(buf),
    ) != sshbuf_len(buf)
        || close(fd) != 0 as libc::c_int
    {
        oerrno = *__errno_location();
        close(fd);
        unlink(path);
        *__errno_location() = oerrno;
        return -(24 as libc::c_int);
    }
    return 0 as libc::c_int;
}
