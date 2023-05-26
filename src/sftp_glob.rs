use crate::sftp_client::sftp_conn;
use crate::sftp_common::Attrib;
use ::libc;

extern "C" {
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn attrib_to_stat(_: *const Attrib, _: *mut stat);
    fn do_readdir(
        _: *mut sftp_conn,
        _: *const libc::c_char,
        _: *mut *mut *mut SFTP_DIRENT,
    ) -> libc::c_int;
    fn free_sftp_dirents(_: *mut *mut SFTP_DIRENT);
    fn do_stat(_: *mut sftp_conn, _: *const libc::c_char, _: libc::c_int) -> *mut Attrib;
    fn do_lstat(_: *mut sftp_conn, _: *const libc::c_char, _: libc::c_int) -> *mut Attrib;
    fn _ssh__compat_glob(
        _: *const libc::c_char,
        _: libc::c_int,
        _: Option<unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int>,
        _: *mut _ssh_compat_glob_t,
    ) -> libc::c_int;
}
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
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dirent {
    pub d_ino: __ino_t,
    pub d_off: __off_t,
    pub d_reclen: libc::c_ushort,
    pub d_type: libc::c_uchar,
    pub d_name: [libc::c_char; 256],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _ssh_compat_glob_t {
    pub gl_pathc: size_t,
    pub gl_matchc: size_t,
    pub gl_offs: size_t,
    pub gl_flags: libc::c_int,
    pub gl_pathv: *mut *mut libc::c_char,
    pub gl_statv: *mut *mut stat,
    pub gl_errfunc: Option<unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int>,
    pub gl_closedir: Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    pub gl_readdir: Option<unsafe extern "C" fn(*mut libc::c_void) -> *mut dirent>,
    pub gl_opendir: Option<unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_void>,
    pub gl_lstat: Option<unsafe extern "C" fn(*const libc::c_char, *mut stat) -> libc::c_int>,
    pub gl_stat: Option<unsafe extern "C" fn(*const libc::c_char, *mut stat) -> libc::c_int>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SFTP_DIRENT {
    pub filename: *mut libc::c_char,
    pub longname: *mut libc::c_char,
    pub a: Attrib,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub conn: *mut sftp_conn,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SFTP_OPENDIR {
    pub dir: *mut *mut SFTP_DIRENT,
    pub offset: libc::c_int,
}
static mut cur: C2RustUnnamed = C2RustUnnamed {
    conn: 0 as *const sftp_conn as *mut sftp_conn,
};
unsafe extern "C" fn fudge_opendir(mut path: *const libc::c_char) -> *mut libc::c_void {
    let mut r: *mut SFTP_OPENDIR = 0 as *mut SFTP_OPENDIR;
    r = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<SFTP_OPENDIR>() as libc::c_ulong,
    ) as *mut SFTP_OPENDIR;
    if do_readdir(cur.conn, path, &mut (*r).dir) != 0 {
        free(r as *mut libc::c_void);
        return 0 as *mut libc::c_void;
    }
    (*r).offset = 0 as libc::c_int;
    return r as *mut libc::c_void;
}
unsafe extern "C" fn fudge_readdir(mut od: *mut SFTP_OPENDIR) -> *mut dirent {
    static mut buf: [libc::c_char; 4376] = [0; 4376];
    let mut ret: *mut dirent = buf.as_mut_ptr() as *mut dirent;
    static mut inum: libc::c_int = 1 as libc::c_int;
    if (*((*od).dir).offset((*od).offset as isize)).is_null() {
        return 0 as *mut dirent;
    }
    memset(
        buf.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[libc::c_char; 4376]>() as libc::c_ulong,
    );
    let fresh0 = (*od).offset;
    (*od).offset = (*od).offset + 1;
    strlcpy(
        ((*ret).d_name).as_mut_ptr(),
        (**((*od).dir).offset(fresh0 as isize)).filename,
        ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
    );
    let fresh1 = inum;
    inum = inum + 1;
    (*ret).d_ino = fresh1 as __ino_t;
    if inum == 0 {
        inum = 1 as libc::c_int;
    }
    return ret;
}
unsafe extern "C" fn fudge_closedir(mut od: *mut SFTP_OPENDIR) {
    free_sftp_dirents((*od).dir);
    free(od as *mut libc::c_void);
}
unsafe extern "C" fn fudge_lstat(mut path: *const libc::c_char, mut st: *mut stat) -> libc::c_int {
    let mut a: *mut Attrib = 0 as *mut Attrib;
    a = do_lstat(cur.conn, path, 1 as libc::c_int);
    if a.is_null() {
        return -(1 as libc::c_int);
    }
    attrib_to_stat(a, st);
    return 0 as libc::c_int;
}
unsafe extern "C" fn fudge_stat(mut path: *const libc::c_char, mut st: *mut stat) -> libc::c_int {
    let mut a: *mut Attrib = 0 as *mut Attrib;
    a = do_stat(cur.conn, path, 1 as libc::c_int);
    if a.is_null() {
        return -(1 as libc::c_int);
    }
    attrib_to_stat(a, st);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn remote_glob(
    mut conn: *mut sftp_conn,
    mut pattern: *const libc::c_char,
    mut flags: libc::c_int,
    mut errfunc: Option<unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int>,
    mut pglob: *mut _ssh_compat_glob_t,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut l: size_t = 0;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
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
    (*pglob).gl_opendir =
        Some(fudge_opendir as unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_void);
    (*pglob).gl_readdir = ::core::mem::transmute::<
        Option<unsafe extern "C" fn(*mut SFTP_OPENDIR) -> *mut dirent>,
        Option<unsafe extern "C" fn(*mut libc::c_void) -> *mut dirent>,
    >(Some(
        fudge_readdir as unsafe extern "C" fn(*mut SFTP_OPENDIR) -> *mut dirent,
    ));
    (*pglob).gl_closedir = ::core::mem::transmute::<
        Option<unsafe extern "C" fn(*mut SFTP_OPENDIR) -> ()>,
        Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    >(Some(
        fudge_closedir as unsafe extern "C" fn(*mut SFTP_OPENDIR) -> (),
    ));
    (*pglob).gl_lstat =
        Some(fudge_lstat as unsafe extern "C" fn(*const libc::c_char, *mut stat) -> libc::c_int);
    (*pglob).gl_stat =
        Some(fudge_stat as unsafe extern "C" fn(*const libc::c_char, *mut stat) -> libc::c_int);
    memset(
        &mut cur as *mut C2RustUnnamed as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<C2RustUnnamed>() as libc::c_ulong,
    );
    cur.conn = conn;
    r = _ssh__compat_glob(pattern, flags | 0x40 as libc::c_int, errfunc, pglob);
    if r != 0 as libc::c_int {
        return r;
    }
    if flags & (0x10 as libc::c_int | 0x8 as libc::c_int)
        == 0x10 as libc::c_int | 0x8 as libc::c_int
        && (*pglob).gl_matchc == 0 as libc::c_int as libc::c_ulong
        && (*pglob).gl_offs == 0 as libc::c_int as libc::c_ulong
        && (*pglob).gl_pathc == 1 as libc::c_int as libc::c_ulong
        && {
            s = *((*pglob).gl_pathv).offset(0 as libc::c_int as isize);
            !s.is_null()
        }
        && {
            l = strlen(s);
            l > 0 as libc::c_int as libc::c_ulong
        }
        && *s.offset(l.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize) as libc::c_int
            != '/' as i32
    {
        if fudge_stat(s, &mut sb) == 0 as libc::c_int
            && sb.st_mode & 0o170000 as libc::c_int as libc::c_uint
                == 0o40000 as libc::c_int as libc::c_uint
        {
            s = realloc(
                s as *mut libc::c_void,
                l.wrapping_add(2 as libc::c_int as libc::c_ulong),
            ) as *mut libc::c_char;
            if !s.is_null() {
                memcpy(
                    s.offset(l as isize) as *mut libc::c_void,
                    b"/\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                    2 as libc::c_int as libc::c_ulong,
                );
                let ref mut fresh2 = *((*pglob).gl_pathv).offset(0 as libc::c_int as isize);
                *fresh2 = s;
            }
        }
    }
    return 0 as libc::c_int;
}
