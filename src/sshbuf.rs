use ::libc;
extern "C" {
    fn raise(__sig: libc::c_int) -> libc::c_int;
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
        -> *mut libc::c_void;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn ssh_signal(_: libc::c_int, _: sshsig_t) -> sshsig_t;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type __sighandler_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshbuf {
    pub d: *mut u_char,
    pub cd: *const u_char,
    pub off: size_t,
    pub size: size_t,
    pub max_size: size_t,
    pub alloc: size_t,
    pub readonly: libc::c_int,
    pub refcount: u_int,
    pub parent: *mut sshbuf,
}
pub type sshsig_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
#[inline]
unsafe extern "C" fn sshbuf_check_sanity(mut buf: *const sshbuf) -> libc::c_int {
    if ((buf.is_null()
        || (*buf).readonly == 0 && (*buf).d != (*buf).cd as *mut u_char
        || (*buf).refcount < 1 as libc::c_int as libc::c_uint
        || (*buf).refcount > 0x100000 as libc::c_int as libc::c_uint
        || ((*buf).cd).is_null()
        || (*buf).max_size > 0x8000000 as libc::c_int as libc::c_ulong
        || (*buf).alloc > (*buf).max_size
        || (*buf).size > (*buf).alloc
        || (*buf).off > (*buf).size) as libc::c_int
        != 0 as libc::c_int) as libc::c_int as libc::c_long
        != 0
    {
        ssh_signal(11 as libc::c_int, None);
        raise(11 as libc::c_int);
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn sshbuf_maybe_pack(mut buf: *mut sshbuf, mut force: libc::c_int) {
    if (*buf).off == 0 as libc::c_int as libc::c_ulong
        || (*buf).readonly != 0
        || (*buf).refcount > 1 as libc::c_int as libc::c_uint
    {
        return;
    }
    if force != 0
        || (*buf).off >= 8192 as libc::c_int as libc::c_ulong
            && (*buf).off >= ((*buf).size).wrapping_div(2 as libc::c_int as libc::c_ulong)
    {
        memmove(
            (*buf).d as *mut libc::c_void,
            ((*buf).d).offset((*buf).off as isize) as *const libc::c_void,
            ((*buf).size).wrapping_sub((*buf).off),
        );
        (*buf).size = ((*buf).size as libc::c_ulong).wrapping_sub((*buf).off) as size_t as size_t;
        (*buf).off = 0 as libc::c_int as size_t;
    }
}
pub unsafe extern "C" fn sshbuf_new() -> *mut sshbuf {
    let mut ret: *mut sshbuf = 0 as *mut sshbuf;
    ret = calloc(
        ::core::mem::size_of::<sshbuf>() as libc::c_ulong,
        1 as libc::c_int as libc::c_ulong,
    ) as *mut sshbuf;
    if ret.is_null() {
        return 0 as *mut sshbuf;
    }
    (*ret).alloc = 256 as libc::c_int as size_t;
    (*ret).max_size = 0x8000000 as libc::c_int as size_t;
    (*ret).readonly = 0 as libc::c_int;
    (*ret).refcount = 1 as libc::c_int as u_int;
    (*ret).parent = 0 as *mut sshbuf;
    (*ret).d = calloc(1 as libc::c_int as libc::c_ulong, (*ret).alloc) as *mut u_char;
    (*ret).cd = (*ret).d;
    if ((*ret).cd).is_null() {
        free(ret as *mut libc::c_void);
        return 0 as *mut sshbuf;
    }
    return ret;
}
pub unsafe extern "C" fn sshbuf_from(
    mut blob: *const libc::c_void,
    mut len: size_t,
) -> *mut sshbuf {
    let mut ret: *mut sshbuf = 0 as *mut sshbuf;
    if blob.is_null() || len > 0x8000000 as libc::c_int as libc::c_ulong || {
        ret = calloc(
            ::core::mem::size_of::<sshbuf>() as libc::c_ulong,
            1 as libc::c_int as libc::c_ulong,
        ) as *mut sshbuf;
        ret.is_null()
    } {
        return 0 as *mut sshbuf;
    }
    (*ret).max_size = len;
    (*ret).size = (*ret).max_size;
    (*ret).alloc = (*ret).size;
    (*ret).readonly = 1 as libc::c_int;
    (*ret).refcount = 1 as libc::c_int as u_int;
    (*ret).parent = 0 as *mut sshbuf;
    (*ret).cd = blob as *const u_char;
    (*ret).d = 0 as *mut u_char;
    return ret;
}
pub unsafe extern "C" fn sshbuf_set_parent(
    mut child: *mut sshbuf,
    mut parent: *mut sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = sshbuf_check_sanity(child);
    if r != 0 as libc::c_int || {
        r = sshbuf_check_sanity(parent);
        r != 0 as libc::c_int
    } {
        return r;
    }
    if !((*child).parent).is_null() && (*child).parent != parent {
        return -(1 as libc::c_int);
    }
    (*child).parent = parent;
    (*(*child).parent).refcount = ((*(*child).parent).refcount).wrapping_add(1);
    (*(*child).parent).refcount;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_fromb(mut buf: *mut sshbuf) -> *mut sshbuf {
    let mut ret: *mut sshbuf = 0 as *mut sshbuf;
    if sshbuf_check_sanity(buf) != 0 as libc::c_int {
        return 0 as *mut sshbuf;
    }
    ret = sshbuf_from(sshbuf_ptr(buf) as *const libc::c_void, sshbuf_len(buf));
    if ret.is_null() {
        return 0 as *mut sshbuf;
    }
    if sshbuf_set_parent(ret, buf) != 0 as libc::c_int {
        sshbuf_free(ret);
        return 0 as *mut sshbuf;
    }
    return ret;
}
pub unsafe extern "C" fn sshbuf_free(mut buf: *mut sshbuf) {
    if buf.is_null() {
        return;
    }
    if sshbuf_check_sanity(buf) != 0 as libc::c_int {
        return;
    }
    (*buf).refcount = ((*buf).refcount).wrapping_sub(1);
    (*buf).refcount;
    if (*buf).refcount > 0 as libc::c_int as libc::c_uint {
        return;
    }
    sshbuf_free((*buf).parent);
    (*buf).parent = 0 as *mut sshbuf;
    if (*buf).readonly == 0 {
        explicit_bzero((*buf).d as *mut libc::c_void, (*buf).alloc);
        free((*buf).d as *mut libc::c_void);
    }
    freezero(
        buf as *mut libc::c_void,
        ::core::mem::size_of::<sshbuf>() as libc::c_ulong,
    );
}
pub unsafe extern "C" fn sshbuf_reset(mut buf: *mut sshbuf) {
    let mut d: *mut u_char = 0 as *mut u_char;
    if (*buf).readonly != 0 || (*buf).refcount > 1 as libc::c_int as libc::c_uint {
        (*buf).off = (*buf).size;
        return;
    }
    if sshbuf_check_sanity(buf) != 0 as libc::c_int {
        return;
    }
    (*buf).size = 0 as libc::c_int as size_t;
    (*buf).off = (*buf).size;
    if (*buf).alloc != 256 as libc::c_int as libc::c_ulong {
        d = recallocarray(
            (*buf).d as *mut libc::c_void,
            (*buf).alloc,
            256 as libc::c_int as size_t,
            1 as libc::c_int as size_t,
        ) as *mut u_char;
        if !d.is_null() {
            (*buf).d = d;
            (*buf).cd = (*buf).d;
            (*buf).alloc = 256 as libc::c_int as size_t;
        }
    }
    explicit_bzero((*buf).d as *mut libc::c_void, (*buf).alloc);
}
pub unsafe extern "C" fn sshbuf_max_size(mut buf: *const sshbuf) -> size_t {
    return (*buf).max_size;
}
pub unsafe extern "C" fn sshbuf_alloc(mut buf: *const sshbuf) -> size_t {
    return (*buf).alloc;
}
pub unsafe extern "C" fn sshbuf_parent(mut buf: *const sshbuf) -> *const sshbuf {
    return (*buf).parent;
}
pub unsafe extern "C" fn sshbuf_refcount(mut buf: *const sshbuf) -> u_int {
    return (*buf).refcount;
}
pub unsafe extern "C" fn sshbuf_set_max_size(
    mut buf: *mut sshbuf,
    mut max_size: size_t,
) -> libc::c_int {
    let mut rlen: size_t = 0;
    let mut dp: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = sshbuf_check_sanity(buf);
    if r != 0 as libc::c_int {
        return r;
    }
    if max_size == (*buf).max_size {
        return 0 as libc::c_int;
    }
    if (*buf).readonly != 0 || (*buf).refcount > 1 as libc::c_int as libc::c_uint {
        return -(49 as libc::c_int);
    }
    if max_size > 0x8000000 as libc::c_int as libc::c_ulong {
        return -(9 as libc::c_int);
    }
    sshbuf_maybe_pack(buf, (max_size < (*buf).size) as libc::c_int);
    if max_size < (*buf).alloc && max_size > (*buf).size {
        if (*buf).size < 256 as libc::c_int as libc::c_ulong {
            rlen = 256 as libc::c_int as size_t;
        } else {
            rlen = ((*buf).size)
                .wrapping_add((256 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                .wrapping_div(256 as libc::c_int as libc::c_ulong)
                .wrapping_mul(256 as libc::c_int as libc::c_ulong);
        }
        if rlen > max_size {
            rlen = max_size;
        }
        dp = recallocarray(
            (*buf).d as *mut libc::c_void,
            (*buf).alloc,
            rlen,
            1 as libc::c_int as size_t,
        ) as *mut u_char;
        if dp.is_null() {
            return -(2 as libc::c_int);
        }
        (*buf).d = dp;
        (*buf).cd = (*buf).d;
        (*buf).alloc = rlen;
    }
    if max_size < (*buf).alloc {
        return -(9 as libc::c_int);
    }
    (*buf).max_size = max_size;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_len(mut buf: *const sshbuf) -> size_t {
    if sshbuf_check_sanity(buf) != 0 as libc::c_int {
        return 0 as libc::c_int as size_t;
    }
    return ((*buf).size).wrapping_sub((*buf).off);
}
pub unsafe extern "C" fn sshbuf_avail(mut buf: *const sshbuf) -> size_t {
    if sshbuf_check_sanity(buf) != 0 as libc::c_int
        || (*buf).readonly != 0
        || (*buf).refcount > 1 as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int as size_t;
    }
    return ((*buf).max_size).wrapping_sub(((*buf).size).wrapping_sub((*buf).off));
}
pub unsafe extern "C" fn sshbuf_ptr(mut buf: *const sshbuf) -> *const u_char {
    if sshbuf_check_sanity(buf) != 0 as libc::c_int {
        return 0 as *const u_char;
    }
    return ((*buf).cd).offset((*buf).off as isize);
}
pub unsafe extern "C" fn sshbuf_mutable_ptr(mut buf: *const sshbuf) -> *mut u_char {
    if sshbuf_check_sanity(buf) != 0 as libc::c_int
        || (*buf).readonly != 0
        || (*buf).refcount > 1 as libc::c_int as libc::c_uint
    {
        return 0 as *mut u_char;
    }
    return ((*buf).d).offset((*buf).off as isize);
}
pub unsafe extern "C" fn sshbuf_check_reserve(
    mut buf: *const sshbuf,
    mut len: size_t,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = sshbuf_check_sanity(buf);
    if r != 0 as libc::c_int {
        return r;
    }
    if (*buf).readonly != 0 || (*buf).refcount > 1 as libc::c_int as libc::c_uint {
        return -(49 as libc::c_int);
    }
    if len > (*buf).max_size
        || ((*buf).max_size).wrapping_sub(len) < ((*buf).size).wrapping_sub((*buf).off)
    {
        return -(9 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_allocate(mut buf: *mut sshbuf, mut len: size_t) -> libc::c_int {
    let mut rlen: size_t = 0;
    let mut need: size_t = 0;
    let mut dp: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = sshbuf_check_reserve(buf, len);
    if r != 0 as libc::c_int {
        return r;
    }
    sshbuf_maybe_pack(
        buf,
        (((*buf).size).wrapping_add(len) > (*buf).max_size) as libc::c_int,
    );
    if len.wrapping_add((*buf).size) <= (*buf).alloc {
        return 0 as libc::c_int;
    }
    need = len.wrapping_add((*buf).size).wrapping_sub((*buf).alloc);
    rlen = ((*buf).alloc)
        .wrapping_add(need)
        .wrapping_add((256 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
        .wrapping_div(256 as libc::c_int as libc::c_ulong)
        .wrapping_mul(256 as libc::c_int as libc::c_ulong);
    if rlen > (*buf).max_size {
        rlen = ((*buf).alloc).wrapping_add(need);
    }
    dp = recallocarray(
        (*buf).d as *mut libc::c_void,
        (*buf).alloc,
        rlen,
        1 as libc::c_int as size_t,
    ) as *mut u_char;
    if dp.is_null() {
        return -(2 as libc::c_int);
    }
    (*buf).alloc = rlen;
    (*buf).d = dp;
    (*buf).cd = (*buf).d;
    r = sshbuf_check_reserve(buf, len);
    if r < 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_reserve(
    mut buf: *mut sshbuf,
    mut len: size_t,
    mut dpp: *mut *mut u_char,
) -> libc::c_int {
    let mut dp: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    if !dpp.is_null() {
        *dpp = 0 as *mut u_char;
    }
    r = sshbuf_allocate(buf, len);
    if r != 0 as libc::c_int {
        return r;
    }
    dp = ((*buf).d).offset((*buf).size as isize);
    (*buf).size = ((*buf).size as libc::c_ulong).wrapping_add(len) as size_t as size_t;
    if !dpp.is_null() {
        *dpp = dp;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_consume(mut buf: *mut sshbuf, mut len: size_t) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = sshbuf_check_sanity(buf);
    if r != 0 as libc::c_int {
        return r;
    }
    if len == 0 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    if len > sshbuf_len(buf) {
        return -(3 as libc::c_int);
    }
    (*buf).off = ((*buf).off as libc::c_ulong).wrapping_add(len) as size_t as size_t;
    if (*buf).off == (*buf).size {
        (*buf).size = 0 as libc::c_int as size_t;
        (*buf).off = (*buf).size;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_consume_end(mut buf: *mut sshbuf, mut len: size_t) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = sshbuf_check_sanity(buf);
    if r != 0 as libc::c_int {
        return r;
    }
    if len == 0 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    if len > sshbuf_len(buf) {
        return -(3 as libc::c_int);
    }
    (*buf).size = ((*buf).size as libc::c_ulong).wrapping_sub(len) as size_t as size_t;
    return 0 as libc::c_int;
}
