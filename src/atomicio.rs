use ::libc;
extern "C" {
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn __errno_location() -> *mut libc::c_int;
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: libc::c_int) -> libc::c_int;
    fn readv(__fd: libc::c_int, __iovec: *const iovec, __count: libc::c_int) -> ssize_t;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
}
pub type __ssize_t = libc::c_long;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct iovec {
    pub iov_base: *mut libc::c_void,
    pub iov_len: size_t,
}
pub type nfds_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: libc::c_int,
    pub events: libc::c_short,
    pub revents: libc::c_short,
}
pub unsafe extern "C" fn atomicio6(
    mut f: Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
    mut fd: libc::c_int,
    mut _s: *mut libc::c_void,
    mut n: size_t,
    mut cb: Option<unsafe extern "C" fn(*mut libc::c_void, size_t) -> libc::c_int>,
    mut cb_arg: *mut libc::c_void,
) -> size_t {
    let mut s: *mut libc::c_char = _s as *mut libc::c_char;
    let mut pos: size_t = 0 as libc::c_int as size_t;
    let mut res: ssize_t = 0;
    let mut pfd: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    pfd.fd = fd;
    pfd.events = (if f
        == Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t)
    {
        0x1 as libc::c_int
    } else {
        0x4 as libc::c_int
    }) as libc::c_short;
    while n > pos {
        res = f.expect("non-null function pointer")(
            fd,
            s.offset(pos as isize) as *mut libc::c_void,
            n.wrapping_sub(pos),
        );
        match res {
            -1 => {
                if *__errno_location() == 4 as libc::c_int {
                    if cb.is_some()
                        && cb.expect("non-null function pointer")(
                            cb_arg,
                            0 as libc::c_int as size_t,
                        ) == -(1 as libc::c_int)
                    {
                        *__errno_location() = 4 as libc::c_int;
                        return pos;
                    }
                } else if *__errno_location() == 11 as libc::c_int
                    || *__errno_location() == 11 as libc::c_int
                {
                    poll(&mut pfd, 1 as libc::c_int as nfds_t, -(1 as libc::c_int));
                } else {
                    return 0 as libc::c_int as size_t;
                }
            }
            0 => {
                *__errno_location() = 32 as libc::c_int;
                return pos;
            }
            _ => {
                pos = (pos as libc::c_ulong).wrapping_add(res as size_t) as size_t as size_t;
                if cb.is_some()
                    && cb.expect("non-null function pointer")(cb_arg, res as size_t)
                        == -(1 as libc::c_int)
                {
                    *__errno_location() = 4 as libc::c_int;
                    return pos;
                }
            }
        }
    }
    return pos;
}
pub unsafe extern "C" fn atomicio(
    mut f: Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
    mut fd: libc::c_int,
    mut _s: *mut libc::c_void,
    mut n: size_t,
) -> size_t {
    return atomicio6(f, fd, _s, n, None, 0 as *mut libc::c_void);
}
pub unsafe extern "C" fn atomiciov6(
    mut f: Option<unsafe extern "C" fn(libc::c_int, *const iovec, libc::c_int) -> ssize_t>,
    mut fd: libc::c_int,
    mut _iov: *const iovec,
    mut iovcnt: libc::c_int,
    mut cb: Option<unsafe extern "C" fn(*mut libc::c_void, size_t) -> libc::c_int>,
    mut cb_arg: *mut libc::c_void,
) -> size_t {
    let mut pos: size_t = 0 as libc::c_int as size_t;
    let mut rem: size_t = 0;
    let mut res: ssize_t = 0;
    let mut iov_array: [iovec; 1024] = [iovec {
        iov_base: 0 as *mut libc::c_void,
        iov_len: 0,
    }; 1024];
    let mut iov: *mut iovec = iov_array.as_mut_ptr();
    let mut pfd: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    if iovcnt < 0 as libc::c_int || iovcnt > 1024 as libc::c_int {
        *__errno_location() = 22 as libc::c_int;
        return 0 as libc::c_int as size_t;
    }
    memcpy(
        iov as *mut libc::c_void,
        _iov as *const libc::c_void,
        (iovcnt as size_t).wrapping_mul(::core::mem::size_of::<iovec>() as libc::c_ulong),
    );
    pfd.fd = fd;
    pfd.events = (if f
        == Some(readv as unsafe extern "C" fn(libc::c_int, *const iovec, libc::c_int) -> ssize_t)
    {
        0x1 as libc::c_int
    } else {
        0x4 as libc::c_int
    }) as libc::c_short;
    while iovcnt > 0 as libc::c_int
        && (*iov.offset(0 as libc::c_int as isize)).iov_len > 0 as libc::c_int as libc::c_ulong
    {
        res = f.expect("non-null function pointer")(fd, iov, iovcnt);
        match res {
            -1 => {
                if *__errno_location() == 4 as libc::c_int {
                    if cb.is_some()
                        && cb.expect("non-null function pointer")(
                            cb_arg,
                            0 as libc::c_int as size_t,
                        ) == -(1 as libc::c_int)
                    {
                        *__errno_location() = 4 as libc::c_int;
                        return pos;
                    }
                } else if *__errno_location() == 11 as libc::c_int
                    || *__errno_location() == 11 as libc::c_int
                {
                    poll(&mut pfd, 1 as libc::c_int as nfds_t, -(1 as libc::c_int));
                } else {
                    return 0 as libc::c_int as size_t;
                }
            }
            0 => {
                *__errno_location() = 32 as libc::c_int;
                return pos;
            }
            _ => {
                rem = res as size_t;
                pos = (pos as libc::c_ulong).wrapping_add(rem) as size_t as size_t;
                while iovcnt > 0 as libc::c_int
                    && rem >= (*iov.offset(0 as libc::c_int as isize)).iov_len
                {
                    rem = (rem as libc::c_ulong)
                        .wrapping_sub((*iov.offset(0 as libc::c_int as isize)).iov_len)
                        as size_t as size_t;
                    iov = iov.offset(1);
                    iov;
                    iovcnt -= 1;
                    iovcnt;
                }
                if rem > 0 as libc::c_int as libc::c_ulong
                    && (iovcnt <= 0 as libc::c_int
                        || rem > (*iov.offset(0 as libc::c_int as isize)).iov_len)
                {
                    *__errno_location() = 14 as libc::c_int;
                    return 0 as libc::c_int as size_t;
                }
                if !(iovcnt == 0 as libc::c_int) {
                    let ref mut fresh0 = (*iov.offset(0 as libc::c_int as isize)).iov_base;
                    *fresh0 = ((*iov.offset(0 as libc::c_int as isize)).iov_base
                        as *mut libc::c_char)
                        .offset(rem as isize) as *mut libc::c_void;
                    let ref mut fresh1 = (*iov.offset(0 as libc::c_int as isize)).iov_len;
                    *fresh1 = (*fresh1 as libc::c_ulong).wrapping_sub(rem) as size_t as size_t;
                }
                if cb.is_some()
                    && cb.expect("non-null function pointer")(cb_arg, res as size_t)
                        == -(1 as libc::c_int)
                {
                    *__errno_location() = 4 as libc::c_int;
                    return pos;
                }
            }
        }
    }
    return pos;
}
pub unsafe extern "C" fn atomiciov(
    mut f: Option<unsafe extern "C" fn(libc::c_int, *const iovec, libc::c_int) -> ssize_t>,
    mut fd: libc::c_int,
    mut _iov: *const iovec,
    mut iovcnt: libc::c_int,
) -> size_t {
    return atomiciov6(f, fd, _iov, iovcnt, None, 0 as *mut libc::c_void);
}
