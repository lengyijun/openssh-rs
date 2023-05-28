use ::libc;
extern "C" {
    pub type __dirstream;

    fn lstat(__file: *const libc::c_char, __buf: *mut libc::stat) -> libc::c_int;

    fn getpwuid(__uid: __uid_t) -> *mut libc::passwd;
    fn getpwnam(__name: *const libc::c_char) -> *mut libc::passwd;
    
    fn geteuid() -> __uid_t;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn opendir(__name: *const libc::c_char) -> *mut DIR;
    fn closedir(__dirp: *mut DIR) -> libc::c_int;
    fn readdir(__dirp: *mut DIR) -> *mut dirent;
    fn isalnum(_: libc::c_int) -> libc::c_int;
    fn isalpha(_: libc::c_int) -> libc::c_int;
    fn iscntrl(_: libc::c_int) -> libc::c_int;
    fn isdigit(_: libc::c_int) -> libc::c_int;
    fn islower(_: libc::c_int) -> libc::c_int;
    fn isgraph(_: libc::c_int) -> libc::c_int;
    fn isprint(_: libc::c_int) -> libc::c_int;
    fn ispunct(_: libc::c_int) -> libc::c_int;
    fn isspace(_: libc::c_int) -> libc::c_int;
    fn isupper(_: libc::c_int) -> libc::c_int;
    fn isxdigit(_: libc::c_int) -> libc::c_int;
    fn isblank(_: libc::c_int) -> libc::c_int;

    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn reallocarray(__ptr: *mut libc::c_void, __nmemb: size_t, __size: size_t)
        -> *mut libc::c_void;
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn qsort(__base: *mut libc::c_void, __nmemb: size_t, __size: size_t, __compar: __compar_fn_t);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strnlen(__string: *const libc::c_char, __maxlen: size_t) -> size_t;
}
pub type __u_char = libc::c_uchar;
pub type __u_short = libc::c_ushort;
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
pub type u_short = __u_short;
pub type size_t = libc::c_ulong;


#[derive(Copy, Clone)]
#[repr(C)]
pub struct _ssh_compat_glob_t {
    pub gl_pathc: size_t,
    pub gl_matchc: size_t,
    pub gl_offs: size_t,
    pub gl_flags: libc::c_int,
    pub gl_pathv: *mut *mut libc::c_char,
    pub gl_statv: *mut *mut libc::stat,
    pub gl_errfunc: Option<unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int>,
    pub gl_closedir: Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    pub gl_readdir: Option<unsafe extern "C" fn(*mut libc::c_void) -> *mut dirent>,
    pub gl_opendir: Option<unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_void>,
    pub gl_lstat: Option<unsafe extern "C" fn(*const libc::c_char, *mut libc::stat) -> libc::c_int>,
    pub gl_stat: Option<unsafe extern "C" fn(*const libc::c_char, *mut libc::stat) -> libc::c_int>,
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
pub struct glob_lim {
    pub glim_malloc: size_t,
    pub glim_stat: size_t,
    pub glim_readdir: size_t,
}
pub type Char = u_short;
pub type __compar_fn_t =
    Option<unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct glob_path_stat {
    pub gps_path: *mut libc::c_char,
    pub gps_stat: *mut libc::stat,
}
pub type DIR = __dirstream;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cclass {
    pub name: *const libc::c_char,
    pub isctype: Option<unsafe extern "C" fn(libc::c_int) -> libc::c_int>,
}
static mut cclasses: [cclass; 13] = unsafe {
    [
        {
            let mut init = cclass {
                name: b"alnum\0" as *const u8 as *const libc::c_char,
                isctype: Some(isalnum as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
            };
            init
        },
        {
            let mut init = cclass {
                name: b"alpha\0" as *const u8 as *const libc::c_char,
                isctype: Some(isalpha as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
            };
            init
        },
        {
            let mut init = cclass {
                name: b"blank\0" as *const u8 as *const libc::c_char,
                isctype: Some(isblank as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
            };
            init
        },
        {
            let mut init = cclass {
                name: b"cntrl\0" as *const u8 as *const libc::c_char,
                isctype: Some(iscntrl as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
            };
            init
        },
        {
            let mut init = cclass {
                name: b"digit\0" as *const u8 as *const libc::c_char,
                isctype: Some(isdigit as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
            };
            init
        },
        {
            let mut init = cclass {
                name: b"graph\0" as *const u8 as *const libc::c_char,
                isctype: Some(isgraph as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
            };
            init
        },
        {
            let mut init = cclass {
                name: b"lower\0" as *const u8 as *const libc::c_char,
                isctype: Some(islower as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
            };
            init
        },
        {
            let mut init = cclass {
                name: b"print\0" as *const u8 as *const libc::c_char,
                isctype: Some(isprint as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
            };
            init
        },
        {
            let mut init = cclass {
                name: b"punct\0" as *const u8 as *const libc::c_char,
                isctype: Some(ispunct as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
            };
            init
        },
        {
            let mut init = cclass {
                name: b"space\0" as *const u8 as *const libc::c_char,
                isctype: Some(isspace as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
            };
            init
        },
        {
            let mut init = cclass {
                name: b"upper\0" as *const u8 as *const libc::c_char,
                isctype: Some(isupper as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
            };
            init
        },
        {
            let mut init = cclass {
                name: b"xdigit\0" as *const u8 as *const libc::c_char,
                isctype: Some(isxdigit as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
            };
            init
        },
        {
            let mut init = cclass {
                name: 0 as *const libc::c_char,
                isctype: None,
            };
            init
        },
    ]
};
#[no_mangle]
pub unsafe extern "C" fn _ssh__compat_glob(
    mut pattern: *const libc::c_char,
    mut flags: libc::c_int,
    mut errfunc: Option<unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int>,
    mut pglob: *mut _ssh_compat_glob_t,
) -> libc::c_int {
    let mut patnext: *const u_char = 0 as *const u_char;
    let mut c: libc::c_int = 0;
    let mut bufnext: *mut Char = 0 as *mut Char;
    let mut bufend: *mut Char = 0 as *mut Char;
    let mut patbuf: [Char; 4096] = [0; 4096];
    let mut limit: glob_lim = {
        let mut init = glob_lim {
            glim_malloc: 0 as libc::c_int as size_t,
            glim_stat: 0 as libc::c_int as size_t,
            glim_readdir: 0 as libc::c_int as size_t,
        };
        init
    };
    patnext = pattern as *mut u_char;
    if flags & 0x1 as libc::c_int == 0 {
        (*pglob).gl_pathc = 0 as libc::c_int as size_t;
        (*pglob).gl_pathv = 0 as *mut *mut libc::c_char;
        (*pglob).gl_statv = 0 as *mut *mut libc::stat;
        if flags & 0x2 as libc::c_int == 0 {
            (*pglob).gl_offs = 0 as libc::c_int as size_t;
        }
    }
    (*pglob).gl_flags = flags & !(0x100 as libc::c_int);
    (*pglob).gl_errfunc = errfunc;
    (*pglob).gl_matchc = 0 as libc::c_int as size_t;
    if strnlen(pattern, 4096 as libc::c_int as size_t) == 4096 as libc::c_int as libc::c_ulong {
        return -(3 as libc::c_int);
    }
    if (*pglob).gl_offs >= 9223372036854775807 as libc::c_long as libc::c_ulong
        || (*pglob).gl_pathc >= 9223372036854775807 as libc::c_long as libc::c_ulong
        || (*pglob).gl_pathc
            >= (9223372036854775807 as libc::c_long as libc::c_ulong)
                .wrapping_sub((*pglob).gl_offs)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
    {
        return -(1 as libc::c_int);
    }
    bufnext = patbuf.as_mut_ptr();
    bufend = bufnext
        .offset(4096 as libc::c_int as isize)
        .offset(-(1 as libc::c_int as isize));
    if flags & 0x1000 as libc::c_int != 0 {
        while bufnext < bufend && {
            let fresh0 = patnext;
            patnext = patnext.offset(1);
            c = *fresh0 as libc::c_int;
            c != '\0' as i32
        } {
            let fresh1 = bufnext;
            bufnext = bufnext.offset(1);
            *fresh1 = c as Char;
        }
    } else {
        while bufnext < bufend && {
            let fresh2 = patnext;
            patnext = patnext.offset(1);
            c = *fresh2 as libc::c_int;
            c != '\0' as i32
        } {
            if c == '\\' as i32 {
                let fresh3 = patnext;
                patnext = patnext.offset(1);
                c = *fresh3 as libc::c_int;
                if c == '\0' as i32 {
                    c = '\\' as i32;
                    patnext = patnext.offset(-1);
                    patnext;
                }
                let fresh4 = bufnext;
                bufnext = bufnext.offset(1);
                *fresh4 = (c | 0x4000 as libc::c_int) as Char;
            } else {
                let fresh5 = bufnext;
                bufnext = bufnext.offset(1);
                *fresh5 = c as Char;
            }
        }
    }
    *bufnext = '\0' as i32 as Char;
    if flags & 0x80 as libc::c_int != 0 {
        return globexp1(patbuf.as_mut_ptr(), pglob, &mut limit);
    } else {
        return glob0(patbuf.as_mut_ptr(), pglob, &mut limit);
    };
}
unsafe extern "C" fn globexp1(
    mut pattern: *const Char,
    mut pglob: *mut _ssh_compat_glob_t,
    mut limitp: *mut glob_lim,
) -> libc::c_int {
    let mut ptr: *const Char = pattern;
    if *pattern.offset(0 as libc::c_int as isize) as libc::c_int == '{' as i32
        && *pattern.offset(1 as libc::c_int as isize) as libc::c_int == '}' as i32
        && *pattern.offset(2 as libc::c_int as isize) as libc::c_int == '\0' as i32
    {
        return glob0(pattern, pglob, limitp);
    }
    ptr = g_strchr(ptr, '{' as i32) as *const Char;
    if !ptr.is_null() {
        return globexp2(ptr, pattern, pglob, limitp);
    }
    return glob0(pattern, pglob, limitp);
}
unsafe extern "C" fn globexp2(
    mut ptr: *const Char,
    mut pattern: *const Char,
    mut pglob: *mut _ssh_compat_glob_t,
    mut limitp: *mut glob_lim,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut rv: libc::c_int = 0;
    let mut lm: *mut Char = 0 as *mut Char;
    let mut ls: *mut Char = 0 as *mut Char;
    let mut pe: *const Char = 0 as *const Char;
    let mut pm: *const Char = 0 as *const Char;
    let mut pl: *const Char = 0 as *const Char;
    let mut patbuf: [Char; 4096] = [0; 4096];
    lm = patbuf.as_mut_ptr();
    pm = pattern;
    while pm != ptr {
        let fresh6 = pm;
        pm = pm.offset(1);
        let fresh7 = lm;
        lm = lm.offset(1);
        *fresh7 = *fresh6;
    }
    *lm = '\0' as i32 as Char;
    ls = lm;
    i = 0 as libc::c_int;
    ptr = ptr.offset(1);
    pe = ptr;
    while *pe != 0 {
        if *pe as libc::c_int == '[' as i32 {
            let fresh8 = pe;
            pe = pe.offset(1);
            pm = fresh8;
            while *pe as libc::c_int != ']' as i32 && *pe as libc::c_int != '\0' as i32 {
                pe = pe.offset(1);
                pe;
            }
            if *pe as libc::c_int == '\0' as i32 {
                pe = pm;
            }
        } else if *pe as libc::c_int == '{' as i32 {
            i += 1;
            i;
        } else if *pe as libc::c_int == '}' as i32 {
            if i == 0 as libc::c_int {
                break;
            }
            i -= 1;
            i;
        }
        pe = pe.offset(1);
        pe;
    }
    if i != 0 as libc::c_int || *pe as libc::c_int == '\0' as i32 {
        return glob0(patbuf.as_mut_ptr(), pglob, limitp);
    }
    i = 0 as libc::c_int;
    pm = ptr;
    pl = pm;
    while pm <= pe {
        let mut current_block_37: u64;
        match *pm as libc::c_int {
            91 => {
                let fresh9 = pm;
                pm = pm.offset(1);
                pl = fresh9;
                while *pm as libc::c_int != ']' as i32 && *pm as libc::c_int != '\0' as i32 {
                    pm = pm.offset(1);
                    pm;
                }
                if *pm as libc::c_int == '\0' as i32 {
                    pm = pl;
                }
                current_block_37 = 1622411330066726685;
            }
            123 => {
                i += 1;
                i;
                current_block_37 = 1622411330066726685;
            }
            125 => {
                if i != 0 {
                    i -= 1;
                    i;
                    current_block_37 = 1622411330066726685;
                } else {
                    current_block_37 = 1319635546938210828;
                }
            }
            44 => {
                current_block_37 = 1319635546938210828;
            }
            _ => {
                current_block_37 = 1622411330066726685;
            }
        }
        match current_block_37 {
            1319635546938210828 => {
                if !(i != 0 && *pm as libc::c_int == ',' as i32) {
                    lm = ls;
                    while pl < pm {
                        let fresh10 = pl;
                        pl = pl.offset(1);
                        let fresh11 = lm;
                        lm = lm.offset(1);
                        *fresh11 = *fresh10;
                    }
                    pl = pe.offset(1 as libc::c_int as isize);
                    loop {
                        let fresh12 = pl;
                        pl = pl.offset(1);
                        let fresh13 = lm;
                        lm = lm.offset(1);
                        *fresh13 = *fresh12;
                        if !(*fresh13 as libc::c_int != '\0' as i32) {
                            break;
                        }
                    }
                    rv = globexp1(patbuf.as_mut_ptr(), pglob, limitp);
                    if rv != 0 && rv != -(3 as libc::c_int) {
                        return rv;
                    }
                    pl = pm.offset(1 as libc::c_int as isize);
                }
            }
            _ => {}
        }
        pm = pm.offset(1);
        pm;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn globtilde(
    mut pattern: *const Char,
    mut patbuf: *mut Char,
    mut patbuf_len: size_t,
    mut pglob: *mut _ssh_compat_glob_t,
) -> *const Char {
    let mut pwd: *mut libc::passwd = 0 as *mut libc::passwd;
    let mut h: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *const Char = 0 as *const Char;
    let mut b: *mut Char = 0 as *mut Char;
    let mut eb: *mut Char = 0 as *mut Char;
    if *pattern as libc::c_int != '~' as i32 || (*pglob).gl_flags & 0x800 as libc::c_int == 0 {
        return pattern;
    }
    eb = &mut *patbuf.offset(patbuf_len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
        as *mut Char;
    p = pattern.offset(1 as libc::c_int as isize);
    h = patbuf as *mut libc::c_char;
    while h < eb as *mut libc::c_char && *p as libc::c_int != 0 && *p as libc::c_int != '/' as i32 {
        let fresh14 = p;
        p = p.offset(1);
        let fresh15 = h;
        h = h.offset(1);
        *fresh15 = *fresh14 as libc::c_char;
    }
    *h = '\0' as i32 as libc::c_char;
    if *(patbuf as *mut libc::c_char).offset(0 as libc::c_int as isize) as libc::c_int
        == '\0' as i32
    {
        if libc::getuid() != geteuid() || {
            h = getenv(b"HOME\0" as *const u8 as *const libc::c_char);
            h.is_null()
        } {
            pwd = getpwuid(libc::getuid());
            if pwd.is_null() {
                return pattern;
            } else {
                h = (*pwd).pw_dir;
            }
        }
    } else {
        pwd = getpwnam(patbuf as *mut libc::c_char);
        if pwd.is_null() {
            return pattern;
        } else {
            h = (*pwd).pw_dir;
        }
    }
    b = patbuf;
    while b < eb && *h as libc::c_int != 0 {
        let fresh16 = h;
        h = h.offset(1);
        let fresh17 = b;
        b = b.offset(1);
        *fresh17 = *fresh16 as Char;
    }
    while b < eb && {
        let fresh18 = p;
        p = p.offset(1);
        let fresh19 = b;
        b = b.offset(1);
        *fresh19 = *fresh18;
        *fresh19 as libc::c_int != '\0' as i32
    } {}
    *b = '\0' as i32 as Char;
    return patbuf;
}
unsafe extern "C" fn g_strncmp(
    mut s1: *const Char,
    mut s2: *const libc::c_char,
    mut n: size_t,
) -> libc::c_int {
    let mut rv: libc::c_int = 0 as libc::c_int;
    loop {
        let fresh20 = n;
        n = n.wrapping_sub(1);
        if !(fresh20 != 0) {
            break;
        }
        let fresh21 = s2;
        s2 = s2.offset(1);
        rv = *(s1 as *mut Char) as libc::c_int - *(fresh21 as *const libc::c_uchar) as libc::c_int;
        if rv != 0 {
            break;
        }
        let fresh22 = s1;
        s1 = s1.offset(1);
        if *fresh22 as libc::c_int == '\0' as i32 {
            break;
        }
    }
    return rv;
}
unsafe extern "C" fn g_charclass(
    mut patternp: *mut *const Char,
    mut bufnextp: *mut *mut Char,
) -> libc::c_int {
    let mut pattern: *const Char = (*patternp).offset(1 as libc::c_int as isize);
    let mut bufnext: *mut Char = *bufnextp;
    let mut colon: *const Char = 0 as *const Char;
    let mut cc: *mut cclass = 0 as *mut cclass;
    let mut len: size_t = 0;
    colon = g_strchr(pattern, ':' as i32);
    if colon.is_null() || *colon.offset(1 as libc::c_int as isize) as libc::c_int != ']' as i32 {
        return 1 as libc::c_int;
    }
    len = colon.offset_from(pattern) as libc::c_long as size_t;
    cc = cclasses.as_mut_ptr();
    while !((*cc).name).is_null() {
        if g_strncmp(pattern, (*cc).name, len) == 0
            && *((*cc).name).offset(len as isize) as libc::c_int == '\0' as i32
        {
            break;
        }
        cc = cc.offset(1);
        cc;
    }
    if ((*cc).name).is_null() {
        return -(1 as libc::c_int);
    }
    let fresh23 = bufnext;
    bufnext = bufnext.offset(1);
    *fresh23 = (':' as i32 | 0x8000 as libc::c_int) as Char;
    let fresh24 = bufnext;
    bufnext = bufnext.offset(1);
    *fresh24 = cc
        .offset_from(&mut *cclasses.as_mut_ptr().offset(0 as libc::c_int as isize) as *mut cclass)
        as libc::c_long as Char;
    *bufnextp = bufnext;
    *patternp = (*patternp).offset(len.wrapping_add(3 as libc::c_int as libc::c_ulong) as isize);
    return 0 as libc::c_int;
}
unsafe extern "C" fn glob0(
    mut pattern: *const Char,
    mut pglob: *mut _ssh_compat_glob_t,
    mut limitp: *mut glob_lim,
) -> libc::c_int {
    let mut qpatnext: *const Char = 0 as *const Char;
    let mut c: libc::c_int = 0;
    let mut err: libc::c_int = 0;
    let mut oldpathc: size_t = 0;
    let mut bufnext: *mut Char = 0 as *mut Char;
    let mut patbuf: [Char; 4096] = [0; 4096];
    qpatnext = globtilde(
        pattern,
        patbuf.as_mut_ptr(),
        4096 as libc::c_int as size_t,
        pglob,
    );
    oldpathc = (*pglob).gl_pathc;
    bufnext = patbuf.as_mut_ptr();
    loop {
        let fresh25 = qpatnext;
        qpatnext = qpatnext.offset(1);
        c = *fresh25 as libc::c_int;
        if !(c != '\0' as i32) {
            break;
        }
        match c {
            91 => {
                c = *qpatnext as libc::c_int;
                if c == '!' as i32 {
                    qpatnext = qpatnext.offset(1);
                    qpatnext;
                }
                if *qpatnext as libc::c_int == '\0' as i32
                    || (g_strchr(qpatnext.offset(1 as libc::c_int as isize), ']' as i32)).is_null()
                {
                    let fresh26 = bufnext;
                    bufnext = bufnext.offset(1);
                    *fresh26 = '[' as i32 as Char;
                    if c == '!' as i32 {
                        qpatnext = qpatnext.offset(-1);
                        qpatnext;
                    }
                } else {
                    let fresh27 = bufnext;
                    bufnext = bufnext.offset(1);
                    *fresh27 = ('[' as i32 | 0x8000 as libc::c_int) as Char;
                    if c == '!' as i32 {
                        let fresh28 = bufnext;
                        bufnext = bufnext.offset(1);
                        *fresh28 = ('!' as i32 | 0x8000 as libc::c_int) as Char;
                    }
                    let fresh29 = qpatnext;
                    qpatnext = qpatnext.offset(1);
                    c = *fresh29 as libc::c_int;
                    loop {
                        if c == '[' as i32 && *qpatnext as libc::c_int == ':' as i32 {
                            loop {
                                err = g_charclass(&mut qpatnext, &mut bufnext);
                                if err != 0 {
                                    break;
                                }
                                let fresh30 = qpatnext;
                                qpatnext = qpatnext.offset(1);
                                c = *fresh30 as libc::c_int;
                                if !(c == '[' as i32 && *qpatnext as libc::c_int == ':' as i32) {
                                    break;
                                }
                            }
                            if err == -(1 as libc::c_int)
                                && (*pglob).gl_flags & 0x10 as libc::c_int == 0
                            {
                                return -(3 as libc::c_int);
                            }
                            if c == ']' as i32 {
                                break;
                            }
                        }
                        let fresh31 = bufnext;
                        bufnext = bufnext.offset(1);
                        *fresh31 = (c & 0xff as libc::c_int) as Char;
                        if *qpatnext as libc::c_int == '-' as i32 && {
                            c = *qpatnext.offset(1 as libc::c_int as isize) as libc::c_int;
                            c != ']' as i32
                        } {
                            let fresh32 = bufnext;
                            bufnext = bufnext.offset(1);
                            *fresh32 = ('-' as i32 | 0x8000 as libc::c_int) as Char;
                            let fresh33 = bufnext;
                            bufnext = bufnext.offset(1);
                            *fresh33 = (c & 0xff as libc::c_int) as Char;
                            qpatnext = qpatnext.offset(2 as libc::c_int as isize);
                        }
                        let fresh34 = qpatnext;
                        qpatnext = qpatnext.offset(1);
                        c = *fresh34 as libc::c_int;
                        if !(c != ']' as i32) {
                            break;
                        }
                    }
                    (*pglob).gl_flags |= 0x100 as libc::c_int;
                    let fresh35 = bufnext;
                    bufnext = bufnext.offset(1);
                    *fresh35 = (']' as i32 | 0x8000 as libc::c_int) as Char;
                }
            }
            63 => {
                (*pglob).gl_flags |= 0x100 as libc::c_int;
                let fresh36 = bufnext;
                bufnext = bufnext.offset(1);
                *fresh36 = ('?' as i32 | 0x8000 as libc::c_int) as Char;
            }
            42 => {
                (*pglob).gl_flags |= 0x100 as libc::c_int;
                if bufnext == patbuf.as_mut_ptr()
                    || *bufnext.offset(-(1 as libc::c_int) as isize) as libc::c_int
                        != ('*' as i32 | 0x8000 as libc::c_int) as Char as libc::c_int
                {
                    let fresh37 = bufnext;
                    bufnext = bufnext.offset(1);
                    *fresh37 = ('*' as i32 | 0x8000 as libc::c_int) as Char;
                }
            }
            _ => {
                let fresh38 = bufnext;
                bufnext = bufnext.offset(1);
                *fresh38 = (c & 0xff as libc::c_int) as Char;
            }
        }
    }
    *bufnext = '\0' as i32 as Char;
    err = glob1(
        patbuf.as_mut_ptr(),
        patbuf
            .as_mut_ptr()
            .offset(4096 as libc::c_int as isize)
            .offset(-(1 as libc::c_int as isize)),
        pglob,
        limitp,
    );
    if err != 0 as libc::c_int {
        return err;
    }
    if (*pglob).gl_pathc == oldpathc {
        if (*pglob).gl_flags & 0x10 as libc::c_int != 0
            || (*pglob).gl_flags & 0x200 as libc::c_int != 0
                && (*pglob).gl_flags & 0x100 as libc::c_int == 0
        {
            return globextend(pattern, pglob, limitp, 0 as *mut libc::stat);
        } else {
            return -(3 as libc::c_int);
        }
    }
    if (*pglob).gl_flags & 0x20 as libc::c_int == 0 {
        if (*pglob).gl_flags & 0x4000 as libc::c_int != 0 {
            let mut path_stat: *mut glob_path_stat = 0 as *mut glob_path_stat;
            let mut i: size_t = 0;
            let mut n: size_t = ((*pglob).gl_pathc).wrapping_sub(oldpathc);
            let mut o: size_t = ((*pglob).gl_offs).wrapping_add(oldpathc);
            path_stat = calloc(n, ::core::mem::size_of::<glob_path_stat>() as libc::c_ulong)
                as *mut glob_path_stat;
            if path_stat.is_null() {
                return -(1 as libc::c_int);
            }
            i = 0 as libc::c_int as size_t;
            while i < n {
                let ref mut fresh39 = (*path_stat.offset(i as isize)).gps_path;
                *fresh39 = *((*pglob).gl_pathv).offset(o.wrapping_add(i) as isize);
                let ref mut fresh40 = (*path_stat.offset(i as isize)).gps_stat;
                *fresh40 = *((*pglob).gl_statv).offset(o.wrapping_add(i) as isize);
                i = i.wrapping_add(1);
                i;
            }
            qsort(
                path_stat as *mut libc::c_void,
                n,
                ::core::mem::size_of::<glob_path_stat>() as libc::c_ulong,
                Some(
                    compare_gps
                        as unsafe extern "C" fn(
                            *const libc::c_void,
                            *const libc::c_void,
                        ) -> libc::c_int,
                ),
            );
            i = 0 as libc::c_int as size_t;
            while i < n {
                let ref mut fresh41 = *((*pglob).gl_pathv).offset(o.wrapping_add(i) as isize);
                *fresh41 = (*path_stat.offset(i as isize)).gps_path;
                let ref mut fresh42 = *((*pglob).gl_statv).offset(o.wrapping_add(i) as isize);
                *fresh42 = (*path_stat.offset(i as isize)).gps_stat;
                i = i.wrapping_add(1);
                i;
            }
            libc::free(path_stat as *mut libc::c_void);
        } else {
            qsort(
                ((*pglob).gl_pathv)
                    .offset((*pglob).gl_offs as isize)
                    .offset(oldpathc as isize) as *mut libc::c_void,
                ((*pglob).gl_pathc).wrapping_sub(oldpathc),
                ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                Some(
                    compare
                        as unsafe extern "C" fn(
                            *const libc::c_void,
                            *const libc::c_void,
                        ) -> libc::c_int,
                ),
            );
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn compare(
    mut p: *const libc::c_void,
    mut q: *const libc::c_void,
) -> libc::c_int {
    return strcmp(
        *(p as *mut *mut libc::c_char),
        *(q as *mut *mut libc::c_char),
    );
}
unsafe extern "C" fn compare_gps(
    mut _p: *const libc::c_void,
    mut _q: *const libc::c_void,
) -> libc::c_int {
    let mut p: *const glob_path_stat = _p as *const glob_path_stat;
    let mut q: *const glob_path_stat = _q as *const glob_path_stat;
    return strcmp((*p).gps_path, (*q).gps_path);
}
unsafe extern "C" fn glob1(
    mut pattern: *mut Char,
    mut pattern_last: *mut Char,
    mut pglob: *mut _ssh_compat_glob_t,
    mut limitp: *mut glob_lim,
) -> libc::c_int {
    let mut pathbuf: [Char; 4096] = [0; 4096];
    if *pattern as libc::c_int == '\0' as i32 {
        return 0 as libc::c_int;
    }
    return glob2(
        pathbuf.as_mut_ptr(),
        pathbuf
            .as_mut_ptr()
            .offset(4096 as libc::c_int as isize)
            .offset(-(1 as libc::c_int as isize)),
        pathbuf.as_mut_ptr(),
        pathbuf
            .as_mut_ptr()
            .offset(4096 as libc::c_int as isize)
            .offset(-(1 as libc::c_int as isize)),
        pattern,
        pattern_last,
        pglob,
        limitp,
    );
}
unsafe extern "C" fn glob2(
    mut pathbuf: *mut Char,
    mut pathbuf_last: *mut Char,
    mut pathend: *mut Char,
    mut pathend_last: *mut Char,
    mut pattern: *mut Char,
    mut pattern_last: *mut Char,
    mut pglob: *mut _ssh_compat_glob_t,
    mut limitp: *mut glob_lim,
) -> libc::c_int {
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    let mut p: *mut Char = 0 as *mut Char;
    let mut q: *mut Char = 0 as *mut Char;
    let mut anymeta: libc::c_int = 0;
    anymeta = 0 as libc::c_int;
    loop {
        if *pattern as libc::c_int == '\0' as i32 {
            *pathend = '\0' as i32 as Char;
            if (*pglob).gl_flags & 0x2000 as libc::c_int != 0 && {
                let fresh43 = (*limitp).glim_stat;
                (*limitp).glim_stat = ((*limitp).glim_stat).wrapping_add(1);
                fresh43 >= 2048 as libc::c_int as libc::c_ulong
            } {
                *libc::__errno_location() = 0 as libc::c_int;
                let fresh44 = pathend;
                pathend = pathend.offset(1);
                *fresh44 = '/' as i32 as Char;
                *pathend = '\0' as i32 as Char;
                return -(1 as libc::c_int);
            }
            if g_lstat(pathbuf, &mut sb, pglob) != 0 {
                return 0 as libc::c_int;
            }
            if (*pglob).gl_flags & 0x8 as libc::c_int != 0
                && *pathend.offset(-(1 as libc::c_int) as isize) as libc::c_int != '/' as i32
                && (sb.st_mode & 0o170000 as libc::c_int as libc::c_uint
                    == 0o40000 as libc::c_int as libc::c_uint
                    || sb.st_mode & 0o170000 as libc::c_int as libc::c_uint
                        == 0o120000 as libc::c_int as libc::c_uint
                        && g_stat(pathbuf, &mut sb, pglob) == 0 as libc::c_int
                        && sb.st_mode & 0o170000 as libc::c_int as libc::c_uint
                            == 0o40000 as libc::c_int as libc::c_uint)
            {
                if pathend.offset(1 as libc::c_int as isize) > pathend_last {
                    return 1 as libc::c_int;
                }
                let fresh45 = pathend;
                pathend = pathend.offset(1);
                *fresh45 = '/' as i32 as Char;
                *pathend = '\0' as i32 as Char;
            }
            (*pglob).gl_matchc = ((*pglob).gl_matchc).wrapping_add(1);
            (*pglob).gl_matchc;
            return globextend(pathbuf, pglob, limitp, &mut sb);
        }
        q = pathend;
        p = pattern;
        while *p as libc::c_int != '\0' as i32 && *p as libc::c_int != '/' as i32 {
            if *p as libc::c_int & 0x8000 as libc::c_int != 0 as libc::c_int {
                anymeta = 1 as libc::c_int;
            }
            if q.offset(1 as libc::c_int as isize) > pathend_last {
                return 1 as libc::c_int;
            }
            let fresh46 = p;
            p = p.offset(1);
            let fresh47 = q;
            q = q.offset(1);
            *fresh47 = *fresh46;
        }
        if anymeta == 0 {
            pathend = q;
            pattern = p;
            while *pattern as libc::c_int == '/' as i32 {
                if pathend.offset(1 as libc::c_int as isize) > pathend_last {
                    return 1 as libc::c_int;
                }
                let fresh48 = pattern;
                pattern = pattern.offset(1);
                let fresh49 = pathend;
                pathend = pathend.offset(1);
                *fresh49 = *fresh48;
            }
        } else {
            return glob3(
                pathbuf,
                pathbuf_last,
                pathend,
                pathend_last,
                pattern,
                p,
                pattern_last,
                pglob,
                limitp,
            );
        }
    }
}
unsafe extern "C" fn glob3(
    mut pathbuf: *mut Char,
    mut pathbuf_last: *mut Char,
    mut pathend: *mut Char,
    mut pathend_last: *mut Char,
    mut pattern: *mut Char,
    mut restpattern: *mut Char,
    mut restpattern_last: *mut Char,
    mut pglob: *mut _ssh_compat_glob_t,
    mut limitp: *mut glob_lim,
) -> libc::c_int {
    let mut dp: *mut dirent = 0 as *mut dirent;
    let mut dirp: *mut DIR = 0 as *mut DIR;
    let mut err: libc::c_int = 0;
    let mut buf: [libc::c_char; 4096] = [0; 4096];
    let mut readdirfunc: Option<unsafe extern "C" fn(*mut libc::c_void) -> *mut dirent> = None;
    if pathend > pathend_last {
        return 1 as libc::c_int;
    }
    *pathend = '\0' as i32 as Char;
    *libc::__errno_location() = 0 as libc::c_int;
    dirp = g_opendir(pathbuf, pglob);
    if dirp.is_null() {
        if ((*pglob).gl_errfunc).is_some() {
            if g_Ctoc(
                pathbuf,
                buf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
            ) != 0
            {
                return -(2 as libc::c_int);
            }
            if ((*pglob).gl_errfunc).expect("non-null function pointer")(
                buf.as_mut_ptr(),
                *libc::__errno_location(),
            ) != 0
                || (*pglob).gl_flags & 0x4 as libc::c_int != 0
            {
                return -(2 as libc::c_int);
            }
        }
        return 0 as libc::c_int;
    }
    err = 0 as libc::c_int;
    if (*pglob).gl_flags & 0x40 as libc::c_int != 0 {
        readdirfunc = (*pglob).gl_readdir;
    } else {
        readdirfunc = ::core::mem::transmute::<
            Option<unsafe extern "C" fn(*mut DIR) -> *mut dirent>,
            Option<unsafe extern "C" fn(*mut libc::c_void) -> *mut dirent>,
        >(Some(
            readdir as unsafe extern "C" fn(*mut DIR) -> *mut dirent,
        ));
    }
    loop {
        dp = (Some(readdirfunc.expect("non-null function pointer")))
            .expect("non-null function pointer")(dirp as *mut libc::c_void);
        if dp.is_null() {
            break;
        }
        let mut sc: *mut u_char = 0 as *mut u_char;
        let mut dc: *mut Char = 0 as *mut Char;
        if (*pglob).gl_flags & 0x2000 as libc::c_int != 0 && {
            let fresh50 = (*limitp).glim_readdir;
            (*limitp).glim_readdir = ((*limitp).glim_readdir).wrapping_add(1);
            fresh50 >= 16384 as libc::c_int as libc::c_ulong
        } {
            *libc::__errno_location() = 0 as libc::c_int;
            let fresh51 = pathend;
            pathend = pathend.offset(1);
            *fresh51 = '/' as i32 as Char;
            *pathend = '\0' as i32 as Char;
            err = -(1 as libc::c_int);
            break;
        } else {
            if (*dp).d_name[0 as libc::c_int as usize] as libc::c_int == '.' as i32
                && *pattern as libc::c_int != '.' as i32
            {
                continue;
            }
            dc = pathend;
            sc = ((*dp).d_name).as_mut_ptr() as *mut u_char;
            while dc < pathend_last && {
                let fresh52 = sc;
                sc = sc.offset(1);
                let fresh53 = dc;
                dc = dc.offset(1);
                *fresh53 = *fresh52 as Char;
                *fresh53 as libc::c_int != '\0' as i32
            } {}
            if dc >= pathend_last {
                *dc = '\0' as i32 as Char;
                err = 1 as libc::c_int;
                break;
            } else if match_0(pathend, pattern, restpattern) == 0 {
                *pathend = '\0' as i32 as Char;
            } else {
                dc = dc.offset(-1);
                err = glob2(
                    pathbuf,
                    pathbuf_last,
                    dc,
                    pathend_last,
                    restpattern,
                    restpattern_last,
                    pglob,
                    limitp,
                );
                if err != 0 {
                    break;
                }
            }
        }
    }
    if (*pglob).gl_flags & 0x40 as libc::c_int != 0 {
        (Some(((*pglob).gl_closedir).expect("non-null function pointer")))
            .expect("non-null function pointer")(dirp as *mut libc::c_void);
    } else {
        closedir(dirp);
    }
    return err;
}
unsafe extern "C" fn globextend(
    mut path: *const Char,
    mut pglob: *mut _ssh_compat_glob_t,
    mut limitp: *mut glob_lim,
    mut sb: *mut libc::stat,
) -> libc::c_int {
    let mut current_block: u64;
    let mut pathv: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut i: size_t = 0;
    let mut newn: size_t = 0;
    let mut len: size_t = 0;
    let mut copy: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *const Char = 0 as *const Char;
    let mut statv: *mut *mut libc::stat = 0 as *mut *mut libc::stat;
    newn = (2 as libc::c_int as libc::c_ulong)
        .wrapping_add((*pglob).gl_pathc)
        .wrapping_add((*pglob).gl_offs);
    if !((*pglob).gl_offs >= 9223372036854775807 as libc::c_long as libc::c_ulong
        || (*pglob).gl_pathc >= 9223372036854775807 as libc::c_long as libc::c_ulong
        || newn >= 9223372036854775807 as libc::c_long as libc::c_ulong
        || (18446744073709551615 as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong)
            <= newn
        || (18446744073709551615 as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<*mut libc::stat>() as libc::c_ulong)
            <= newn)
    {
        pathv = reallocarray(
            (*pglob).gl_pathv as *mut libc::c_void,
            newn,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        ) as *mut *mut libc::c_char;
        if !pathv.is_null() {
            if ((*pglob).gl_pathv).is_null() && (*pglob).gl_offs > 0 as libc::c_int as libc::c_ulong
            {
                pathv = pathv.offset((*pglob).gl_offs as isize);
                i = (*pglob).gl_offs;
                while i > 0 as libc::c_int as libc::c_ulong {
                    pathv = pathv.offset(-1);
                    *pathv = 0 as *mut libc::c_char;
                    i = i.wrapping_sub(1);
                    i;
                }
            }
            (*pglob).gl_pathv = pathv;
            if (*pglob).gl_flags & 0x4000 as libc::c_int != 0 as libc::c_int {
                statv = reallocarray(
                    (*pglob).gl_statv as *mut libc::c_void,
                    newn,
                    ::core::mem::size_of::<*mut libc::stat>() as libc::c_ulong,
                ) as *mut *mut libc::stat;
                if statv.is_null() {
                    current_block = 6471419056600271664;
                } else {
                    if ((*pglob).gl_statv).is_null()
                        && (*pglob).gl_offs > 0 as libc::c_int as libc::c_ulong
                    {
                        statv = statv.offset((*pglob).gl_offs as isize);
                        i = (*pglob).gl_offs;
                        while i > 0 as libc::c_int as libc::c_ulong {
                            statv = statv.offset(-1);
                            *statv = 0 as *mut libc::stat;
                            i = i.wrapping_sub(1);
                            i;
                        }
                    }
                    (*pglob).gl_statv = statv;
                    if sb.is_null() {
                        let ref mut fresh54 = *statv
                            .offset(((*pglob).gl_offs).wrapping_add((*pglob).gl_pathc) as isize);
                        *fresh54 = 0 as *mut libc::stat;
                        current_block = 7245201122033322888;
                    } else {
                        (*limitp).glim_malloc = ((*limitp).glim_malloc as libc::c_ulong)
                            .wrapping_add(::core::mem::size_of::<libc::stat>() as libc::c_ulong)
                            as size_t as size_t;
                        if (*pglob).gl_flags & 0x2000 as libc::c_int != 0
                            && (*limitp).glim_malloc >= 65536 as libc::c_int as libc::c_ulong
                        {
                            *libc::__errno_location() = 0 as libc::c_int;
                            return -(1 as libc::c_int);
                        }
                        let ref mut fresh55 = *statv
                            .offset(((*pglob).gl_offs).wrapping_add((*pglob).gl_pathc) as isize);
                        *fresh55 = libc::malloc(::core::mem::size_of::<libc::stat>() as usize)
                            as *mut libc::stat;
                        if (*fresh55).is_null() {
                            current_block = 15014530240646645919;
                        } else {
                            memcpy(
                                *statv.offset(
                                    ((*pglob).gl_offs).wrapping_add((*pglob).gl_pathc) as isize
                                ) as *mut libc::c_void,
                                sb as *const libc::c_void,
                                ::core::mem::size_of::<libc::stat>() as libc::c_ulong,
                            );
                            current_block = 7245201122033322888;
                        }
                    }
                    match current_block {
                        15014530240646645919 => {}
                        _ => {
                            let ref mut fresh56 = *statv.offset(
                                ((*pglob).gl_offs)
                                    .wrapping_add((*pglob).gl_pathc)
                                    .wrapping_add(1 as libc::c_int as libc::c_ulong)
                                    as isize,
                            );
                            *fresh56 = 0 as *mut libc::stat;
                            current_block = 11048769245176032998;
                        }
                    }
                }
            } else {
                current_block = 11048769245176032998;
            }
            match current_block {
                6471419056600271664 => {}
                _ => {
                    match current_block {
                        11048769245176032998 => {
                            p = path;
                            loop {
                                let fresh57 = p;
                                p = p.offset(1);
                                if !(*fresh57 != 0) {
                                    break;
                                }
                            }
                            len = p.offset_from(path) as libc::c_long as size_t;
                            (*limitp).glim_malloc = ((*limitp).glim_malloc as libc::c_ulong)
                                .wrapping_add(len)
                                as size_t
                                as size_t;
                            copy = libc::malloc(len as usize) as *mut libc::c_char;
                            if !copy.is_null() {
                                if g_Ctoc(path, copy, len) != 0 {
                                    libc::free(copy as *mut libc::c_void);
                                    return -(1 as libc::c_int);
                                }
                                let fresh58 = (*pglob).gl_pathc;
                                (*pglob).gl_pathc = ((*pglob).gl_pathc).wrapping_add(1);
                                let ref mut fresh59 = *pathv
                                    .offset(((*pglob).gl_offs).wrapping_add(fresh58) as isize);
                                *fresh59 = copy;
                            }
                            let ref mut fresh60 =
                                *pathv.offset(
                                    ((*pglob).gl_offs).wrapping_add((*pglob).gl_pathc) as isize
                                );
                            *fresh60 = 0 as *mut libc::c_char;
                            if (*pglob).gl_flags & 0x2000 as libc::c_int != 0
                                && newn
                                    .wrapping_mul(::core::mem::size_of::<*mut libc::c_char>()
                                        as libc::c_ulong)
                                    .wrapping_add((*limitp).glim_malloc)
                                    > 65536 as libc::c_int as libc::c_ulong
                            {
                                *libc::__errno_location() = 0 as libc::c_int;
                                return -(1 as libc::c_int);
                            }
                        }
                        _ => {}
                    }
                    return if copy.is_null() {
                        -(1 as libc::c_int)
                    } else {
                        0 as libc::c_int
                    };
                }
            }
        }
    }
    i = (*pglob).gl_offs;
    while i < newn.wrapping_sub(2 as libc::c_int as libc::c_ulong) {
        if !((*pglob).gl_pathv).is_null() && !(*((*pglob).gl_pathv).offset(i as isize)).is_null() {
            libc::free(*((*pglob).gl_pathv).offset(i as isize) as *mut libc::c_void);
        }
        if (*pglob).gl_flags & 0x4000 as libc::c_int != 0 as libc::c_int
            && !((*pglob).gl_pathv).is_null()
            && !(*((*pglob).gl_pathv).offset(i as isize)).is_null()
        {
            libc::free(*((*pglob).gl_statv).offset(i as isize) as *mut libc::c_void);
        }
        i = i.wrapping_add(1);
        i;
    }
    libc::free((*pglob).gl_pathv as *mut libc::c_void);
    (*pglob).gl_pathv = 0 as *mut *mut libc::c_char;
    libc::free((*pglob).gl_statv as *mut libc::c_void);
    (*pglob).gl_statv = 0 as *mut *mut libc::stat;
    return -(1 as libc::c_int);
}
unsafe extern "C" fn match_0(
    mut name: *mut Char,
    mut pat: *mut Char,
    mut patend: *mut Char,
) -> libc::c_int {
    let mut ok: libc::c_int = 0;
    let mut negate_range: libc::c_int = 0;
    let mut c: Char = 0;
    let mut k: Char = 0;
    let mut nextp: *mut Char = 0 as *mut Char;
    let mut nextn: *mut Char = 0 as *mut Char;
    loop {
        if pat < patend {
            let fresh61 = pat;
            pat = pat.offset(1);
            c = *fresh61;
            match c as libc::c_int & 0xffff as libc::c_int {
                32810 => {
                    while pat < patend
                        && *pat as libc::c_int & 0xffff as libc::c_int
                            == ('*' as i32 | 0x8000 as libc::c_int) as Char as libc::c_int
                    {
                        pat = pat.offset(1);
                        pat;
                    }
                    if pat == patend {
                        return 1 as libc::c_int;
                    }
                    if *name as libc::c_int == '\0' as i32 {
                        return 0 as libc::c_int;
                    }
                    nextn = name.offset(1 as libc::c_int as isize);
                    nextp = pat.offset(-(1 as libc::c_int as isize));
                    continue;
                }
                32831 => {
                    let fresh62 = name;
                    name = name.offset(1);
                    if !(*fresh62 as libc::c_int == '\0' as i32) {
                        continue;
                    }
                }
                32859 => {
                    ok = 0 as libc::c_int;
                    let fresh63 = name;
                    name = name.offset(1);
                    k = *fresh63;
                    if !(k as libc::c_int == '\0' as i32) {
                        negate_range = (*pat as libc::c_int & 0xffff as libc::c_int
                            == ('!' as i32 | 0x8000 as libc::c_int) as Char as libc::c_int)
                            as libc::c_int;
                        if negate_range != '\0' as i32 {
                            pat = pat.offset(1);
                            pat;
                        }
                        loop {
                            let fresh64 = pat;
                            pat = pat.offset(1);
                            c = *fresh64;
                            if !(c as libc::c_int & 0xffff as libc::c_int
                                != (']' as i32 | 0x8000 as libc::c_int) as Char as libc::c_int)
                            {
                                break;
                            }
                            if c as libc::c_int & 0xffff as libc::c_int
                                == (':' as i32 | 0x8000 as libc::c_int) as Char as libc::c_int
                            {
                                let mut idx: Char =
                                    (*pat as libc::c_int & 0xffff as libc::c_int) as Char;
                                if (idx as libc::c_ulong)
                                    < (::core::mem::size_of::<[cclass; 13]>() as libc::c_ulong)
                                        .wrapping_div(
                                            ::core::mem::size_of::<cclass>() as libc::c_ulong
                                        )
                                        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                    && (cclasses[idx as usize].isctype)
                                        .expect("non-null function pointer")(
                                        k as libc::c_int
                                    ) != 0
                                {
                                    ok = 1 as libc::c_int;
                                }
                                pat = pat.offset(1);
                                pat;
                            }
                            if *pat as libc::c_int & 0xffff as libc::c_int
                                == ('-' as i32 | 0x8000 as libc::c_int) as Char as libc::c_int
                            {
                                if c as libc::c_int <= k as libc::c_int
                                    && k as libc::c_int
                                        <= *pat.offset(1 as libc::c_int as isize) as libc::c_int
                                {
                                    ok = 1 as libc::c_int;
                                }
                                pat = pat.offset(2 as libc::c_int as isize);
                            } else if c as libc::c_int == k as libc::c_int {
                                ok = 1 as libc::c_int;
                            }
                        }
                        if !(ok == negate_range) {
                            continue;
                        }
                    }
                }
                _ => {
                    let fresh65 = name;
                    name = name.offset(1);
                    if !(*fresh65 as libc::c_int != c as libc::c_int) {
                        continue;
                    }
                }
            }
        } else if *name as libc::c_int == '\0' as i32 {
            return 1 as libc::c_int;
        }
        if nextn.is_null() {
            break;
        }
        pat = nextp;
        name = nextn;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn _ssh__compat_globfree(mut pglob: *mut _ssh_compat_glob_t) {
    let mut i: size_t = 0;
    let mut pp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    if !((*pglob).gl_pathv).is_null() {
        pp = ((*pglob).gl_pathv).offset((*pglob).gl_offs as isize);
        i = (*pglob).gl_pathc;
        loop {
            let fresh66 = i;
            i = i.wrapping_sub(1);
            if !(fresh66 != 0) {
                break;
            }
            libc::free(*pp as *mut libc::c_void);
            pp = pp.offset(1);
            pp;
        }
        libc::free((*pglob).gl_pathv as *mut libc::c_void);
        (*pglob).gl_pathv = 0 as *mut *mut libc::c_char;
    }
    if !((*pglob).gl_statv).is_null() {
        i = 0 as libc::c_int as size_t;
        while i < (*pglob).gl_pathc {
            libc::free(*((*pglob).gl_statv).offset(i as isize) as *mut libc::c_void);
            i = i.wrapping_add(1);
            i;
        }
        libc::free((*pglob).gl_statv as *mut libc::c_void);
        (*pglob).gl_statv = 0 as *mut *mut libc::stat;
    }
}
unsafe extern "C" fn g_opendir(mut str: *mut Char, mut pglob: *mut _ssh_compat_glob_t) -> *mut DIR {
    let mut buf: [libc::c_char; 4096] = [0; 4096];
    if *str == 0 {
        strlcpy(
            buf.as_mut_ptr(),
            b".\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        );
    } else if g_Ctoc(
        str,
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
    ) != 0
    {
        return 0 as *mut DIR;
    }
    if (*pglob).gl_flags & 0x40 as libc::c_int != 0 {
        return (Some(((*pglob).gl_opendir).expect("non-null function pointer")))
            .expect("non-null function pointer")(buf.as_mut_ptr()) as *mut DIR;
    }
    return opendir(buf.as_mut_ptr());
}
unsafe extern "C" fn g_lstat(
    mut fn_0: *mut Char,
    mut sb: *mut libc::stat,
    mut pglob: *mut _ssh_compat_glob_t,
) -> libc::c_int {
    let mut buf: [libc::c_char; 4096] = [0; 4096];
    if g_Ctoc(
        fn_0,
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
    ) != 0
    {
        return -(1 as libc::c_int);
    }
    if (*pglob).gl_flags & 0x40 as libc::c_int != 0 {
        return (Some(((*pglob).gl_lstat).expect("non-null function pointer")))
            .expect("non-null function pointer")(buf.as_mut_ptr(), sb);
    }
    return lstat(buf.as_mut_ptr(), sb);
}
unsafe extern "C" fn g_stat(
    mut fn_0: *mut Char,
    mut sb: *mut libc::stat,
    mut pglob: *mut _ssh_compat_glob_t,
) -> libc::c_int {
    let mut buf: [libc::c_char; 4096] = [0; 4096];
    if g_Ctoc(
        fn_0,
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
    ) != 0
    {
        return -(1 as libc::c_int);
    }
    if (*pglob).gl_flags & 0x40 as libc::c_int != 0 {
        return (Some(((*pglob).gl_stat).expect("non-null function pointer")))
            .expect("non-null function pointer")(buf.as_mut_ptr(), sb);
    }
    return libc::stat(buf.as_mut_ptr(), sb);
}
unsafe extern "C" fn g_strchr(mut str: *const Char, mut ch: libc::c_int) -> *mut Char {
    loop {
        if *str as libc::c_int == ch {
            return str as *mut Char;
        }
        let fresh67 = str;
        str = str.offset(1);
        if !(*fresh67 != 0) {
            break;
        }
    }
    return 0 as *mut Char;
}
unsafe extern "C" fn g_Ctoc(
    mut str: *const Char,
    mut buf: *mut libc::c_char,
    mut len: size_t,
) -> libc::c_int {
    loop {
        let fresh68 = len;
        len = len.wrapping_sub(1);
        if !(fresh68 != 0) {
            break;
        }
        let fresh69 = str;
        str = str.offset(1);
        let fresh70 = buf;
        buf = buf.offset(1);
        *fresh70 = *fresh69 as libc::c_char;
        if *fresh70 as libc::c_int == '\0' as i32 {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
