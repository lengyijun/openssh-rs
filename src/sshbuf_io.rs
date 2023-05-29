use crate::atomicio::atomicio;
use ::libc;
use libc::close;
extern "C" {

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;

    fn unlink(__name: *const libc::c_char) -> libc::c_int;

    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn sshbuf_mutable_ptr(buf: *const crate::sshbuf::sshbuf) -> *mut u_char;
    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;

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

pub unsafe extern "C" fn sshbuf_load_fd(
    mut fd: libc::c_int,
    mut blobp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut buf: [u_char; 4096] = [0; 4096];
    let mut len: size_t = 0;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut r: libc::c_int = 0;
    let mut blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    *blobp = 0 as *mut crate::sshbuf::sshbuf;
    if libc::fstat(fd, &mut st) == -(1 as libc::c_int) {
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
    blob = crate::sshbuf::sshbuf_new();
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
            if *libc::__errno_location() == 32 as libc::c_int {
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
            if !(crate::sshbuf::sshbuf_len(blob) > 0x8000000 as libc::c_int as libc::c_ulong) {
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
                && st.st_size != crate::sshbuf::sshbuf_len(blob) as off_t
            {
                r = -(41 as libc::c_int);
            } else {
                *blobp = blob;
                blob = 0 as *mut crate::sshbuf::sshbuf;
                r = 0 as libc::c_int;
            }
        }
        _ => {}
    }
    explicit_bzero(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 4096]>() as libc::c_ulong,
    );
    crate::sshbuf::sshbuf_free(blob);
    return r;
}
pub unsafe extern "C" fn sshbuf_load_file(
    mut path: *const libc::c_char,
    mut bufp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    *bufp = 0 as *mut crate::sshbuf::sshbuf;
    fd = libc::open(path, 0 as libc::c_int);
    if fd == -(1 as libc::c_int) {
        return -(24 as libc::c_int);
    }
    r = sshbuf_load_fd(fd, bufp);
    if !(r != 0 as libc::c_int) {
        r = 0 as libc::c_int;
    }
    oerrno = *libc::__errno_location();
    close(fd);
    if r != 0 as libc::c_int {
        *libc::__errno_location() = oerrno;
    }
    return r;
}
pub unsafe extern "C" fn sshbuf_write_file(
    mut path: *const libc::c_char,
    mut buf: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut fd: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    fd = libc::open(
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
        crate::sshbuf::sshbuf_len(buf),
    ) != crate::sshbuf::sshbuf_len(buf)
        || close(fd) != 0 as libc::c_int
    {
        oerrno = *libc::__errno_location();
        close(fd);
        unlink(path);
        *libc::__errno_location() = oerrno;
        return -(24 as libc::c_int);
    }
    return 0 as libc::c_int;
}
