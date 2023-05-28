use ::libc;
extern "C" {
    pub type sshbuf;

    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn strmode(mode: libc::c_int, p: *mut libc::c_char);
    fn fmt_scaled(number: libc::c_longlong, result: *mut libc::c_char) -> libc::c_int;
    fn user_from_uid(_: uid_t, _: libc::c_int) -> *mut libc::c_char;
    fn group_from_gid(_: gid_t, _: libc::c_int) -> *mut libc::c_char;

    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn time(__timer: *mut time_t) -> time_t;
    fn strftime(
        __s: *mut libc::c_char,
        __maxsize: size_t,
        __format: *const libc::c_char,
        __tp: *const tm,
    ) -> size_t;
    fn localtime(__timer: *const time_t) -> *mut tm;

    fn sshbuf_get_cstring(
        buf: *mut sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_u64(buf: *mut sshbuf, valp: *mut u_int64_t) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_put_u64(buf: *mut sshbuf, val: u_int64_t) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_get_string(
        buf: *mut sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;

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
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type gid_t = __gid_t;
pub type uid_t = __uid_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub tm_gmtoff: libc::c_long,
    pub tm_zone: *const libc::c_char,
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
pub struct Attrib {
    pub flags: u_int32_t,
    pub size: u_int64_t,
    pub uid: u_int32_t,
    pub gid: u_int32_t,
    pub perm: u_int32_t,
    pub atime: u_int32_t,
    pub mtime: u_int32_t,
}
pub unsafe extern "C" fn attrib_clear(mut a: *mut Attrib) {
    (*a).flags = 0 as libc::c_int as u_int32_t;
    (*a).size = 0 as libc::c_int as u_int64_t;
    (*a).uid = 0 as libc::c_int as u_int32_t;
    (*a).gid = 0 as libc::c_int as u_int32_t;
    (*a).perm = 0 as libc::c_int as u_int32_t;
    (*a).atime = 0 as libc::c_int as u_int32_t;
    (*a).mtime = 0 as libc::c_int as u_int32_t;
}
pub unsafe extern "C" fn stat_to_attrib(mut st: *const libc::stat, mut a: *mut Attrib) {
    attrib_clear(a);
    (*a).flags = 0 as libc::c_int as u_int32_t;
    (*a).flags |= 0x1 as libc::c_int as libc::c_uint;
    (*a).size = (*st).st_size as u_int64_t;
    (*a).flags |= 0x2 as libc::c_int as libc::c_uint;
    (*a).uid = (*st).st_uid;
    (*a).gid = (*st).st_gid;
    (*a).flags |= 0x4 as libc::c_int as libc::c_uint;
    (*a).perm = (*st).st_mode;
    (*a).flags |= 0x8 as libc::c_int as libc::c_uint;
    (*a).atime = (*st).st_atime as u_int32_t;
    (*a).mtime = (*st).st_mtime as u_int32_t;
}
pub unsafe extern "C" fn attrib_to_stat(mut a: *const Attrib, mut st: *mut libc::stat) {
    memset(
        st as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<libc::stat>() as libc::c_ulong,
    );
    if (*a).flags & 0x1 as libc::c_int as libc::c_uint != 0 {
        (*st).st_size = (*a).size as __off_t;
    }
    if (*a).flags & 0x2 as libc::c_int as libc::c_uint != 0 {
        (*st).st_uid = (*a).uid;
        (*st).st_gid = (*a).gid;
    }
    if (*a).flags & 0x4 as libc::c_int as libc::c_uint != 0 {
        (*st).st_mode = (*a).perm;
    }
    if (*a).flags & 0x8 as libc::c_int as libc::c_uint != 0 {
        (*st).st_atime = (*a).atime as __time_t;
        (*st).st_mtime = (*a).mtime as __time_t;
    }
}
pub unsafe extern "C" fn decode_attrib(mut b: *mut sshbuf, mut a: *mut Attrib) -> libc::c_int {
    let mut r: libc::c_int = 0;
    attrib_clear(a);
    r = sshbuf_get_u32(b, &mut (*a).flags);
    if r != 0 as libc::c_int {
        return r;
    }
    if (*a).flags & 0x1 as libc::c_int as libc::c_uint != 0 {
        r = sshbuf_get_u64(b, &mut (*a).size);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    if (*a).flags & 0x2 as libc::c_int as libc::c_uint != 0 {
        r = sshbuf_get_u32(b, &mut (*a).uid);
        if r != 0 as libc::c_int || {
            r = sshbuf_get_u32(b, &mut (*a).gid);
            r != 0 as libc::c_int
        } {
            return r;
        }
    }
    if (*a).flags & 0x4 as libc::c_int as libc::c_uint != 0 {
        r = sshbuf_get_u32(b, &mut (*a).perm);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    if (*a).flags & 0x8 as libc::c_int as libc::c_uint != 0 {
        r = sshbuf_get_u32(b, &mut (*a).atime);
        if r != 0 as libc::c_int || {
            r = sshbuf_get_u32(b, &mut (*a).mtime);
            r != 0 as libc::c_int
        } {
            return r;
        }
    }
    if (*a).flags & 0x80000000 as libc::c_uint != 0 {
        let mut type_0: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut data: *mut u_char = 0 as *mut u_char;
        let mut dlen: size_t = 0;
        let mut i: u_int = 0;
        let mut count: u_int = 0;
        r = sshbuf_get_u32(b, &mut count);
        if r != 0 as libc::c_int {
            return r;
        }
        if count > 0x100000 as libc::c_int as libc::c_uint {
            return -(4 as libc::c_int);
        }
        i = 0 as libc::c_int as u_int;
        while i < count {
            r = sshbuf_get_cstring(b, &mut type_0, 0 as *mut size_t);
            if r != 0 as libc::c_int || {
                r = sshbuf_get_string(b, &mut data, &mut dlen);
                r != 0 as libc::c_int
            } {
                return r;
            }
            crate::log::sshlog(
                b"sftp-common.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"decode_attrib\0"))
                    .as_ptr(),
                147 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"Got file attribute \"%.100s\" len %zu\0" as *const u8 as *const libc::c_char,
                type_0,
                dlen,
            );
            libc::free(type_0 as *mut libc::c_void);
            libc::free(data as *mut libc::c_void);
            i = i.wrapping_add(1);
            i;
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn encode_attrib(mut b: *mut sshbuf, mut a: *const Attrib) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = sshbuf_put_u32(b, (*a).flags);
    if r != 0 as libc::c_int {
        return r;
    }
    if (*a).flags & 0x1 as libc::c_int as libc::c_uint != 0 {
        r = sshbuf_put_u64(b, (*a).size);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    if (*a).flags & 0x2 as libc::c_int as libc::c_uint != 0 {
        r = sshbuf_put_u32(b, (*a).uid);
        if r != 0 as libc::c_int || {
            r = sshbuf_put_u32(b, (*a).gid);
            r != 0 as libc::c_int
        } {
            return r;
        }
    }
    if (*a).flags & 0x4 as libc::c_int as libc::c_uint != 0 {
        r = sshbuf_put_u32(b, (*a).perm);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    if (*a).flags & 0x8 as libc::c_int as libc::c_uint != 0 {
        r = sshbuf_put_u32(b, (*a).atime);
        if r != 0 as libc::c_int || {
            r = sshbuf_put_u32(b, (*a).mtime);
            r != 0 as libc::c_int
        } {
            return r;
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn fx2txt(mut status: libc::c_int) -> *const libc::c_char {
    match status {
        0 => return b"No error\0" as *const u8 as *const libc::c_char,
        1 => return b"End of file\0" as *const u8 as *const libc::c_char,
        2 => return b"No such file or directory\0" as *const u8 as *const libc::c_char,
        3 => return b"Permission denied\0" as *const u8 as *const libc::c_char,
        4 => return b"Failure\0" as *const u8 as *const libc::c_char,
        5 => return b"Bad message\0" as *const u8 as *const libc::c_char,
        6 => return b"No connection\0" as *const u8 as *const libc::c_char,
        7 => return b"Connection lost\0" as *const u8 as *const libc::c_char,
        8 => return b"Operation unsupported\0" as *const u8 as *const libc::c_char,
        _ => return b"Unknown status\0" as *const u8 as *const libc::c_char,
    };
}
pub unsafe extern "C" fn ls_file(
    mut name: *const libc::c_char,
    mut st: *const libc::stat,
    mut remote: libc::c_int,
    mut si_units: libc::c_int,
    mut user: *const libc::c_char,
    mut group: *const libc::c_char,
) -> *mut libc::c_char {
    let mut ulen: libc::c_int = 0;
    let mut glen: libc::c_int = 0;
    let mut sz: libc::c_int = 0 as libc::c_int;
    let mut ltime: *mut tm = localtime(&(*st).st_mtime);
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut lc: [libc::c_char; 8] = [0; 8];
    let mut mode: [libc::c_char; 12] = [0; 12];
    let mut tbuf: [libc::c_char; 13] = [0; 13];
    let mut ubuf: [libc::c_char; 12] = [0; 12];
    let mut gbuf: [libc::c_char; 12] = [0; 12];
    let mut sbuf: [libc::c_char; 7] = [0; 7];
    let mut now: time_t = 0;
    strmode((*st).st_mode as libc::c_int, mode.as_mut_ptr());
    if remote != 0 {
        if user.is_null() {
            libc::snprintf(
                ubuf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 12]>() as usize,
                b"%u\0" as *const u8 as *const libc::c_char,
                (*st).st_uid,
            );
            user = ubuf.as_mut_ptr();
        }
        if group.is_null() {
            libc::snprintf(
                gbuf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 12]>() as usize,
                b"%u\0" as *const u8 as *const libc::c_char,
                (*st).st_gid,
            );
            group = gbuf.as_mut_ptr();
        }
        strlcpy(
            lc.as_mut_ptr(),
            b"?\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 8]>() as libc::c_ulong,
        );
    } else {
        user = user_from_uid((*st).st_uid, 0 as libc::c_int);
        group = group_from_gid((*st).st_gid, 0 as libc::c_int);
        libc::snprintf(
            lc.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 8]>() as usize,
            b"%u\0" as *const u8 as *const libc::c_char,
            (*st).st_nlink as u_int,
        );
    }
    if !ltime.is_null() {
        now = time(0 as *mut time_t);
        if (now
            - (365 as libc::c_int * 24 as libc::c_int * 60 as libc::c_int * 60 as libc::c_int
                / 2 as libc::c_int) as libc::c_long)
            < (*st).st_mtime
            && now >= (*st).st_mtime
        {
            sz = strftime(
                tbuf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 13]>() as libc::c_ulong,
                b"%b %e %H:%M\0" as *const u8 as *const libc::c_char,
                ltime,
            ) as libc::c_int;
        } else {
            sz = strftime(
                tbuf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 13]>() as libc::c_ulong,
                b"%b %e  %Y\0" as *const u8 as *const libc::c_char,
                ltime,
            ) as libc::c_int;
        }
    }
    if sz == 0 as libc::c_int {
        tbuf[0 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
    }
    ulen = (if strlen(user) > 8 as libc::c_int as libc::c_ulong {
        strlen(user)
    } else {
        8 as libc::c_int as libc::c_ulong
    }) as libc::c_int;
    glen = (if strlen(group) > 8 as libc::c_int as libc::c_ulong {
        strlen(group)
    } else {
        8 as libc::c_int as libc::c_ulong
    }) as libc::c_int;
    if si_units != 0 {
        fmt_scaled((*st).st_size as libc::c_longlong, sbuf.as_mut_ptr());
        libc::snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
            b"%s %3s %-*s %-*s %8s %s %s\0" as *const u8 as *const libc::c_char,
            mode.as_mut_ptr(),
            lc.as_mut_ptr(),
            ulen,
            user,
            glen,
            group,
            sbuf.as_mut_ptr(),
            tbuf.as_mut_ptr(),
            name,
        );
    } else {
        libc::snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
            b"%s %3s %-*s %-*s %8llu %s %s\0" as *const u8 as *const libc::c_char,
            mode.as_mut_ptr(),
            lc.as_mut_ptr(),
            ulen,
            user,
            glen,
            group,
            (*st).st_size as libc::c_ulonglong,
            tbuf.as_mut_ptr(),
            name,
        );
    }
    return crate::xmalloc::xstrdup(buf.as_mut_ptr());
}
