use ::libc;
extern "C" {
    fn getcwd(__buf: *mut libc::c_char, __size: size_t) -> *mut libc::c_char;
    fn readlink(__path: *const libc::c_char, __buf: *mut libc::c_char, __len: size_t) -> ssize_t;
    fn lstat(__file: *const libc::c_char, __buf: *mut stat) -> libc::c_int;
    fn __errno_location() -> *mut libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
        -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
}
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
pub type ptrdiff_t = libc::c_long;
pub unsafe extern "C" fn sftp_realpath(
    mut path: *const libc::c_char,
    mut resolved: *mut libc::c_char,
) -> *mut libc::c_char {
    let mut current_block: u64;
    let mut sb: stat = stat {
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
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut q: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut left_len: size_t = 0;
    let mut resolved_len: size_t = 0;
    let mut symlinks: libc::c_uint = 0;
    let mut serrno: libc::c_int = 0;
    let mut slen: libc::c_int = 0;
    let mut mem_allocated: libc::c_int = 0;
    let mut left: [libc::c_char; 4096] = [0; 4096];
    let mut next_token: [libc::c_char; 4096] = [0; 4096];
    let mut symlink: [libc::c_char; 4096] = [0; 4096];
    if *path.offset(0 as libc::c_int as isize) as libc::c_int == '\0' as i32 {
        *__errno_location() = 2 as libc::c_int;
        return 0 as *mut libc::c_char;
    }
    serrno = *__errno_location();
    if resolved.is_null() {
        resolved = malloc(4096 as libc::c_int as libc::c_ulong) as *mut libc::c_char;
        if resolved.is_null() {
            return 0 as *mut libc::c_char;
        }
        mem_allocated = 1 as libc::c_int;
    } else {
        mem_allocated = 0 as libc::c_int;
    }
    symlinks = 0 as libc::c_int as libc::c_uint;
    if *path.offset(0 as libc::c_int as isize) as libc::c_int == '/' as i32 {
        *resolved.offset(0 as libc::c_int as isize) = '/' as i32 as libc::c_char;
        *resolved.offset(1 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
        if *path.offset(1 as libc::c_int as isize) as libc::c_int == '\0' as i32 {
            return resolved;
        }
        resolved_len = 1 as libc::c_int as size_t;
        left_len = strlcpy(
            left.as_mut_ptr(),
            path.offset(1 as libc::c_int as isize),
            ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        );
    } else {
        if (getcwd(resolved, 4096 as libc::c_int as size_t)).is_null() {
            if mem_allocated != 0 {
                free(resolved as *mut libc::c_void);
            } else {
                strlcpy(
                    resolved,
                    b".\0" as *const u8 as *const libc::c_char,
                    4096 as libc::c_int as size_t,
                );
            }
            return 0 as *mut libc::c_char;
        }
        resolved_len = strlen(resolved);
        left_len = strlcpy(
            left.as_mut_ptr(),
            path,
            ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        );
    }
    if left_len >= ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
        || resolved_len >= 4096 as libc::c_int as libc::c_ulong
    {
        *__errno_location() = 36 as libc::c_int;
    } else {
        loop {
            if !(left_len != 0 as libc::c_int as libc::c_ulong) {
                current_block = 17515716450947708786;
                break;
            }
            p = strchr(left.as_mut_ptr(), '/' as i32);
            s = if !p.is_null() {
                p
            } else {
                left.as_mut_ptr().offset(left_len as isize)
            };
            if s.offset_from(left.as_mut_ptr()) as libc::c_long
                >= ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong as ptrdiff_t
            {
                *__errno_location() = 36 as libc::c_int;
                current_block = 1606475609200722585;
                break;
            } else {
                memcpy(
                    next_token.as_mut_ptr() as *mut libc::c_void,
                    left.as_mut_ptr() as *const libc::c_void,
                    s.offset_from(left.as_mut_ptr()) as libc::c_long as libc::c_ulong,
                );
                next_token[s.offset_from(left.as_mut_ptr()) as libc::c_long as usize] =
                    '\0' as i32 as libc::c_char;
                left_len = (left_len as libc::c_ulong)
                    .wrapping_sub(s.offset_from(left.as_mut_ptr()) as libc::c_long as libc::c_ulong)
                    as size_t as size_t;
                if !p.is_null() {
                    memmove(
                        left.as_mut_ptr() as *mut libc::c_void,
                        s.offset(1 as libc::c_int as isize) as *const libc::c_void,
                        left_len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                    );
                }
                if *resolved
                    .offset(resolved_len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
                    as libc::c_int
                    != '/' as i32
                {
                    if resolved_len.wrapping_add(1 as libc::c_int as libc::c_ulong)
                        >= 4096 as libc::c_int as libc::c_ulong
                    {
                        *__errno_location() = 36 as libc::c_int;
                        current_block = 1606475609200722585;
                        break;
                    } else {
                        let fresh0 = resolved_len;
                        resolved_len = resolved_len.wrapping_add(1);
                        *resolved.offset(fresh0 as isize) = '/' as i32 as libc::c_char;
                        *resolved.offset(resolved_len as isize) = '\0' as i32 as libc::c_char;
                    }
                }
                if next_token[0 as libc::c_int as usize] as libc::c_int == '\0' as i32 {
                    continue;
                }
                if strcmp(
                    next_token.as_mut_ptr(),
                    b".\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
                {
                    continue;
                }
                if strcmp(
                    next_token.as_mut_ptr(),
                    b"..\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
                {
                    if resolved_len > 1 as libc::c_int as libc::c_ulong {
                        *resolved
                            .offset(resolved_len.wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                as isize) = '\0' as i32 as libc::c_char;
                        q = (strrchr(resolved, '/' as i32)).offset(1 as libc::c_int as isize);
                        *q = '\0' as i32 as libc::c_char;
                        resolved_len = q.offset_from(resolved) as libc::c_long as size_t;
                    }
                } else {
                    resolved_len = strlcat(
                        resolved,
                        next_token.as_mut_ptr(),
                        4096 as libc::c_int as size_t,
                    );
                    if resolved_len >= 4096 as libc::c_int as libc::c_ulong {
                        *__errno_location() = 36 as libc::c_int;
                        current_block = 1606475609200722585;
                        break;
                    } else if lstat(resolved, &mut sb) != 0 as libc::c_int {
                        if *__errno_location() == 2 as libc::c_int && p.is_null() {
                            *__errno_location() = serrno;
                            return resolved;
                        }
                        current_block = 1606475609200722585;
                        break;
                    } else {
                        if !(sb.st_mode & 0o170000 as libc::c_int as libc::c_uint
                            == 0o120000 as libc::c_int as libc::c_uint)
                        {
                            continue;
                        }
                        let fresh1 = symlinks;
                        symlinks = symlinks.wrapping_add(1);
                        if fresh1 > 32 as libc::c_int as libc::c_uint {
                            *__errno_location() = 40 as libc::c_int;
                            current_block = 1606475609200722585;
                            break;
                        } else {
                            slen = readlink(
                                resolved,
                                symlink.as_mut_ptr(),
                                (::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong)
                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                            ) as libc::c_int;
                            if slen < 0 as libc::c_int {
                                current_block = 1606475609200722585;
                                break;
                            }
                            symlink[slen as usize] = '\0' as i32 as libc::c_char;
                            if symlink[0 as libc::c_int as usize] as libc::c_int == '/' as i32 {
                                *resolved.offset(1 as libc::c_int as isize) =
                                    0 as libc::c_int as libc::c_char;
                                resolved_len = 1 as libc::c_int as size_t;
                            } else if resolved_len > 1 as libc::c_int as libc::c_ulong {
                                *resolved.offset(
                                    resolved_len.wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                        as isize,
                                ) = '\0' as i32 as libc::c_char;
                                q = (strrchr(resolved, '/' as i32))
                                    .offset(1 as libc::c_int as isize);
                                *q = '\0' as i32 as libc::c_char;
                                resolved_len = q.offset_from(resolved) as libc::c_long as size_t;
                            }
                            if !p.is_null() {
                                if symlink[(slen - 1 as libc::c_int) as usize] as libc::c_int
                                    != '/' as i32
                                {
                                    if (slen + 1 as libc::c_int) as libc::c_long
                                        >= ::core::mem::size_of::<[libc::c_char; 4096]>()
                                            as libc::c_ulong
                                            as ptrdiff_t
                                    {
                                        *__errno_location() = 36 as libc::c_int;
                                        current_block = 1606475609200722585;
                                        break;
                                    } else {
                                        symlink[slen as usize] = '/' as i32 as libc::c_char;
                                        symlink[(slen + 1 as libc::c_int) as usize] =
                                            0 as libc::c_int as libc::c_char;
                                    }
                                }
                                left_len = strlcat(
                                    symlink.as_mut_ptr(),
                                    left.as_mut_ptr(),
                                    ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
                                );
                                if left_len
                                    >= ::core::mem::size_of::<[libc::c_char; 4096]>()
                                        as libc::c_ulong
                                {
                                    *__errno_location() = 36 as libc::c_int;
                                    current_block = 1606475609200722585;
                                    break;
                                }
                            }
                            left_len = strlcpy(
                                left.as_mut_ptr(),
                                symlink.as_mut_ptr(),
                                ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
                            );
                        }
                    }
                }
            }
        }
        match current_block {
            1606475609200722585 => {}
            _ => {
                if resolved_len > 1 as libc::c_int as libc::c_ulong
                    && *resolved.offset(
                        resolved_len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                    ) as libc::c_int
                        == '/' as i32
                {
                    *resolved.offset(
                        resolved_len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                    ) = '\0' as i32 as libc::c_char;
                }
                return resolved;
            }
        }
    }
    if mem_allocated != 0 {
        free(resolved as *mut libc::c_void);
    }
    return 0 as *mut libc::c_char;
}
