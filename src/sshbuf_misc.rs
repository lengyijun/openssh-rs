use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;

    fn __b64_ntop(
        _: *const libc::c_uchar,
        _: size_t,
        _: *mut libc::c_char,
        _: size_t,
    ) -> libc::c_int;
    fn __b64_pton(_: *const libc::c_char, _: *mut libc::c_uchar, _: size_t) -> libc::c_int;
    fn timingsafe_bcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;
    fn freezero(_: *mut libc::c_void, _: size_t);

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn memchr(_: *const libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;

    fn memmem(
        __haystack: *const libc::c_void,
        __haystacklen: size_t,
        __needle: *const libc::c_void,
        __needlelen: size_t,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;

    fn sshbuf_putb(buf: *mut crate::sshbuf::sshbuf, v: *const crate::sshbuf::sshbuf)
        -> libc::c_int;

    fn sshbuf_reserve(
        buf: *mut crate::sshbuf::sshbuf,
        len: size_t,
        dpp: *mut *mut u_char,
    ) -> libc::c_int;

}
pub type __u_char = libc::c_uchar;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type u_char = __u_char;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;

pub type _IO_lock_t = ();

pub type C2RustUnnamed = libc::c_uint;
pub const _ISalnum: C2RustUnnamed = 8;
pub const _ISpunct: C2RustUnnamed = 4;
pub const _IScntrl: C2RustUnnamed = 2;
pub const _ISblank: C2RustUnnamed = 1;
pub const _ISgraph: C2RustUnnamed = 32768;
pub const _ISprint: C2RustUnnamed = 16384;
pub const _ISspace: C2RustUnnamed = 8192;
pub const _ISxdigit: C2RustUnnamed = 4096;
pub const _ISdigit: C2RustUnnamed = 2048;
pub const _ISalpha: C2RustUnnamed = 1024;
pub const _ISlower: C2RustUnnamed = 512;
pub const _ISupper: C2RustUnnamed = 256;
pub unsafe extern "C" fn sshbuf_dump_data(
    mut s: *const libc::c_void,
    mut len: size_t,
    mut f: *mut libc::FILE,
) {
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut p: *const u_char = s as *const u_char;
    i = 0 as libc::c_int as size_t;
    while i < len {
        libc::fprintf(f, b"%.4zu: \0" as *const u8 as *const libc::c_char, i);
        j = i;
        while j < i.wrapping_add(16 as libc::c_int as libc::c_ulong) {
            if j < len {
                libc::fprintf(
                    f,
                    b"%02x \0" as *const u8 as *const libc::c_char,
                    *p.offset(j as isize) as libc::c_int,
                );
            } else {
                libc::fprintf(f, b"   \0" as *const u8 as *const libc::c_char);
            }
            j = j.wrapping_add(1);
            j;
        }
        libc::fprintf(f, b" \0" as *const u8 as *const libc::c_char);
        j = i;
        while j < i.wrapping_add(16 as libc::c_int as libc::c_ulong) {
            if j < len {
                if *p.offset(j as isize) as libc::c_int & !(0x7f as libc::c_int) == 0 as libc::c_int
                    && *(*__ctype_b_loc()).offset(*p.offset(j as isize) as libc::c_int as isize)
                        as libc::c_int
                        & _ISprint as libc::c_int as libc::c_ushort as libc::c_int
                        != 0
                {
                    libc::fprintf(
                        f,
                        b"%c\0" as *const u8 as *const libc::c_char,
                        *p.offset(j as isize) as libc::c_int,
                    );
                } else {
                    libc::fprintf(f, b".\0" as *const u8 as *const libc::c_char);
                }
            }
            j = j.wrapping_add(1);
            j;
        }
        libc::fprintf(f, b"\n\0" as *const u8 as *const libc::c_char);
        i = (i as libc::c_ulong).wrapping_add(16 as libc::c_int as libc::c_ulong) as size_t
            as size_t;
    }
}
pub unsafe extern "C" fn sshbuf_dump(
    mut buf: *const crate::sshbuf::sshbuf,
    mut f: *mut libc::FILE,
) {
    libc::fprintf(
        f,
        b"buffer len = %zu\n\0" as *const u8 as *const libc::c_char,
        crate::sshbuf::sshbuf_len(buf),
    );
    sshbuf_dump_data(
        crate::sshbuf::sshbuf_ptr(buf) as *const libc::c_void,
        crate::sshbuf::sshbuf_len(buf),
        f,
    );
}
pub unsafe extern "C" fn sshbuf_dtob16(mut buf: *mut crate::sshbuf::sshbuf) -> *mut libc::c_char {
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut len: size_t = crate::sshbuf::sshbuf_len(buf);
    let mut p: *const u_char = crate::sshbuf::sshbuf_ptr(buf);
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let hex: [libc::c_char; 17] =
        *::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"0123456789abcdef\0");
    if len == 0 as libc::c_int as libc::c_ulong {
        return libc::strdup(b"\0" as *const u8 as *const libc::c_char);
    }
    if (18446744073709551615 as libc::c_ulong).wrapping_div(2 as libc::c_int as libc::c_ulong)
        <= len
        || {
            ret = libc::malloc(
                (len.wrapping_mul(2 as libc::c_int as libc::c_ulong)
                    .wrapping_add(1 as libc::c_int as libc::c_ulong)) as usize,
            ) as *mut libc::c_char;
            ret.is_null()
        }
    {
        return 0 as *mut libc::c_char;
    }
    j = 0 as libc::c_int as size_t;
    i = j;
    while i < len {
        let fresh0 = j;
        j = j.wrapping_add(1);
        *ret.offset(fresh0 as isize) = hex[(*p.offset(i as isize) as libc::c_int
            >> 4 as libc::c_int
            & 0xf as libc::c_int) as usize];
        let fresh1 = j;
        j = j.wrapping_add(1);
        *ret.offset(fresh1 as isize) =
            hex[(*p.offset(i as isize) as libc::c_int & 0xf as libc::c_int) as usize];
        i = i.wrapping_add(1);
        i;
    }
    *ret.offset(j as isize) = '\0' as i32 as libc::c_char;
    return ret;
}
pub unsafe extern "C" fn sshbuf_dtob64(
    mut d: *const crate::sshbuf::sshbuf,
    mut b64: *mut crate::sshbuf::sshbuf,
    mut wrap: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: size_t = 0;
    let mut slen: size_t = 0 as libc::c_int as size_t;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    if d.is_null()
        || b64.is_null()
        || crate::sshbuf::sshbuf_len(d)
            >= (18446744073709551615 as libc::c_ulong)
                .wrapping_div(2 as libc::c_int as libc::c_ulong)
    {
        return -(10 as libc::c_int);
    }
    if crate::sshbuf::sshbuf_len(d) == 0 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    slen = (crate::sshbuf::sshbuf_len(d))
        .wrapping_add(2 as libc::c_int as libc::c_ulong)
        .wrapping_div(3 as libc::c_int as libc::c_ulong)
        .wrapping_mul(4 as libc::c_int as libc::c_ulong)
        .wrapping_add(1 as libc::c_int as libc::c_ulong);
    s = libc::malloc(slen as usize) as *mut libc::c_char;
    if s.is_null() {
        return -(2 as libc::c_int);
    }
    if __b64_ntop(
        crate::sshbuf::sshbuf_ptr(d),
        crate::sshbuf::sshbuf_len(d),
        s,
        slen,
    ) == -(1 as libc::c_int)
    {
        r = -(1 as libc::c_int);
    } else {
        if wrap != 0 {
            i = 0 as libc::c_int as size_t;
            loop {
                if !(*s.offset(i as isize) as libc::c_int != '\0' as i32) {
                    current_block = 13586036798005543211;
                    break;
                }
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(b64, *s.offset(i as isize) as u_char);
                if r != 0 as libc::c_int {
                    current_block = 5734119236069516492;
                    break;
                }
                if i.wrapping_rem(70 as libc::c_int as libc::c_ulong)
                    == 69 as libc::c_int as libc::c_ulong
                    && {
                        r = crate::sshbuf_getput_basic::sshbuf_put_u8(b64, '\n' as i32 as u_char);
                        r != 0 as libc::c_int
                    }
                {
                    current_block = 5734119236069516492;
                    break;
                }
                i = i.wrapping_add(1);
                i;
            }
            match current_block {
                5734119236069516492 => {}
                _ => {
                    if i.wrapping_sub(1 as libc::c_int as libc::c_ulong)
                        .wrapping_rem(70 as libc::c_int as libc::c_ulong)
                        != 69 as libc::c_int as libc::c_ulong
                        && {
                            r = crate::sshbuf_getput_basic::sshbuf_put_u8(
                                b64,
                                '\n' as i32 as u_char,
                            );
                            r != 0 as libc::c_int
                        }
                    {
                        current_block = 5734119236069516492;
                    } else {
                        current_block = 7149356873433890176;
                    }
                }
            }
        } else {
            r = crate::sshbuf_getput_basic::sshbuf_put(b64, s as *const libc::c_void, strlen(s));
            if r != 0 as libc::c_int {
                current_block = 5734119236069516492;
            } else {
                current_block = 7149356873433890176;
            }
        }
        match current_block {
            5734119236069516492 => {}
            _ => {
                r = 0 as libc::c_int;
            }
        }
    }
    freezero(s as *mut libc::c_void, slen);
    return r;
}
pub unsafe extern "C" fn sshbuf_dtob64_string(
    mut buf: *const crate::sshbuf::sshbuf,
    mut wrap: libc::c_int,
) -> *mut libc::c_char {
    let mut tmp: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    tmp = crate::sshbuf::sshbuf_new();
    if tmp.is_null() {
        return 0 as *mut libc::c_char;
    }
    if sshbuf_dtob64(buf, tmp, wrap) != 0 as libc::c_int {
        crate::sshbuf::sshbuf_free(tmp);
        return 0 as *mut libc::c_char;
    }
    ret = sshbuf_dup_string(tmp);
    crate::sshbuf::sshbuf_free(tmp);
    return ret;
}
pub unsafe extern "C" fn sshbuf_b64tod(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut b64: *const libc::c_char,
) -> libc::c_int {
    let mut plen: size_t = strlen(b64);
    let mut nlen: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut p: *mut u_char = 0 as *mut u_char;
    if plen == 0 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    p = libc::malloc(plen as usize) as *mut u_char;
    if p.is_null() {
        return -(2 as libc::c_int);
    }
    nlen = __b64_pton(b64, p, plen);
    if nlen < 0 as libc::c_int {
        freezero(p as *mut libc::c_void, plen);
        return -(4 as libc::c_int);
    }
    r = crate::sshbuf_getput_basic::sshbuf_put(buf, p as *const libc::c_void, nlen as size_t);
    if r < 0 as libc::c_int {
        freezero(p as *mut libc::c_void, plen);
        return r;
    }
    freezero(p as *mut libc::c_void, plen);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_dtourlb64(
    mut d: *const crate::sshbuf::sshbuf,
    mut b64: *mut crate::sshbuf::sshbuf,
    mut wrap: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut i: size_t = 0;
    let mut l: size_t = 0;
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_dtob64(d, b, wrap);
    if r != 0 as libc::c_int {
        current_block = 16561732456181174644;
    } else {
        current_block = 820271813250567934;
    }
    loop {
        match current_block {
            16561732456181174644 => {
                crate::sshbuf::sshbuf_free(b);
                break;
            }
            _ => {
                l = crate::sshbuf::sshbuf_len(b);
                if l <= 1 as libc::c_int as libc::c_ulong
                    || (crate::sshbuf::sshbuf_ptr(b)).is_null()
                {
                    r = -(1 as libc::c_int);
                    current_block = 16561732456181174644;
                } else if *(crate::sshbuf::sshbuf_ptr(b))
                    .offset(l.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
                    as libc::c_int
                    != '=' as i32
                {
                    l = crate::sshbuf::sshbuf_len(b);
                    p = crate::sshbuf::sshbuf_mutable_ptr(b);
                    if p.is_null() {
                        r = -(1 as libc::c_int);
                        current_block = 16561732456181174644;
                    } else {
                        i = 0 as libc::c_int as size_t;
                        while i < l {
                            if *p.offset(i as isize) as libc::c_int == '+' as i32 {
                                *p.offset(i as isize) = '-' as i32 as u_char;
                            } else if *p.offset(i as isize) as libc::c_int == '/' as i32 {
                                *p.offset(i as isize) = '_' as i32 as u_char;
                            }
                            i = i.wrapping_add(1);
                            i;
                        }
                        r = sshbuf_putb(b64, b);
                        current_block = 16561732456181174644;
                    }
                } else {
                    r = crate::sshbuf::sshbuf_consume_end(b, 1 as libc::c_int as size_t);
                    if r != 0 as libc::c_int {
                        current_block = 16561732456181174644;
                    } else {
                        current_block = 820271813250567934;
                    }
                }
            }
        }
    }
    return r;
}
pub unsafe extern "C" fn sshbuf_dup_string(
    mut buf: *mut crate::sshbuf::sshbuf,
) -> *mut libc::c_char {
    let mut p: *const u_char = 0 as *const u_char;
    let mut s: *const u_char = crate::sshbuf::sshbuf_ptr(buf);
    let mut l: size_t = crate::sshbuf::sshbuf_len(buf);
    let mut r: *mut libc::c_char = 0 as *mut libc::c_char;
    if s.is_null() || l > 18446744073709551615 as libc::c_ulong {
        return 0 as *mut libc::c_char;
    }
    if l > 0 as libc::c_int as libc::c_ulong && {
        p = memchr(s as *const libc::c_void, '\0' as i32, l) as *const u_char;
        !p.is_null()
    } {
        if p != s.offset(l as isize).offset(-(1 as libc::c_int as isize)) {
            return 0 as *mut libc::c_char;
        }
        l = l.wrapping_sub(1);
        l;
    }
    r = libc::malloc((l.wrapping_add(1 as libc::c_int as libc::c_ulong)) as usize)
        as *mut libc::c_char;
    if r.is_null() {
        return 0 as *mut libc::c_char;
    }
    if l > 0 as libc::c_int as libc::c_ulong {
        memcpy(r as *mut libc::c_void, s as *const libc::c_void, l);
    }
    *r.offset(l as isize) = '\0' as i32 as libc::c_char;
    return r;
}
pub unsafe extern "C" fn sshbuf_cmp(
    mut b: *const crate::sshbuf::sshbuf,
    mut offset: size_t,
    mut s: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    if (crate::sshbuf::sshbuf_ptr(b)).is_null() {
        return -(1 as libc::c_int);
    }
    if offset > 0x8000000 as libc::c_int as libc::c_ulong
        || len > 0x8000000 as libc::c_int as libc::c_ulong
        || len == 0 as libc::c_int as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    if offset.wrapping_add(len) > crate::sshbuf::sshbuf_len(b) {
        return -(3 as libc::c_int);
    }
    if timingsafe_bcmp(
        (crate::sshbuf::sshbuf_ptr(b)).offset(offset as isize) as *const libc::c_void,
        s,
        len,
    ) != 0 as libc::c_int
    {
        return -(4 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_find(
    mut b: *const crate::sshbuf::sshbuf,
    mut start_offset: size_t,
    mut s: *const libc::c_void,
    mut len: size_t,
    mut offsetp: *mut size_t,
) -> libc::c_int {
    let mut p: *mut libc::c_void = 0 as *mut libc::c_void;
    if !offsetp.is_null() {
        *offsetp = 0 as libc::c_int as size_t;
    }
    if (crate::sshbuf::sshbuf_ptr(b)).is_null() {
        return -(1 as libc::c_int);
    }
    if start_offset > 0x8000000 as libc::c_int as libc::c_ulong
        || len > 0x8000000 as libc::c_int as libc::c_ulong
        || len == 0 as libc::c_int as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    if start_offset > crate::sshbuf::sshbuf_len(b)
        || start_offset.wrapping_add(len) > crate::sshbuf::sshbuf_len(b)
    {
        return -(3 as libc::c_int);
    }
    p = memmem(
        (crate::sshbuf::sshbuf_ptr(b)).offset(start_offset as isize) as *const libc::c_void,
        (crate::sshbuf::sshbuf_len(b)).wrapping_sub(start_offset),
        s,
        len,
    );
    if p.is_null() {
        return -(4 as libc::c_int);
    }
    if !offsetp.is_null() {
        *offsetp = (p as *const u_char).offset_from(crate::sshbuf::sshbuf_ptr(b)) as libc::c_long
            as size_t;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_read(
    mut fd: libc::c_int,
    mut buf: *mut crate::sshbuf::sshbuf,
    mut maxlen: size_t,
    mut rlen: *mut size_t,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    let mut adjust: size_t = 0;
    let mut rr: ssize_t = 0;
    let mut d: *mut u_char = 0 as *mut u_char;
    if !rlen.is_null() {
        *rlen = 0 as libc::c_int as size_t;
    }
    r = sshbuf_reserve(buf, maxlen, &mut d);
    if r != 0 as libc::c_int {
        return r;
    }
    rr = read(fd, d as *mut libc::c_void, maxlen);
    oerrno = *libc::__errno_location();
    adjust = maxlen.wrapping_sub(
        (if rr > 0 as libc::c_int as libc::c_long {
            rr
        } else {
            0 as libc::c_int as libc::c_long
        }) as libc::c_ulong,
    );
    if adjust != 0 as libc::c_int as libc::c_ulong {
        r = crate::sshbuf::sshbuf_consume_end(buf, adjust);
        if r != 0 as libc::c_int {
            memset(
                d.offset(rr as isize) as *mut libc::c_void,
                '\0' as i32,
                adjust,
            );
            return -(1 as libc::c_int);
        }
    }
    if rr < 0 as libc::c_int as libc::c_long {
        *libc::__errno_location() = oerrno;
        return -(24 as libc::c_int);
    } else if rr == 0 as libc::c_int as libc::c_long {
        *libc::__errno_location() = 32 as libc::c_int;
        return -(24 as libc::c_int);
    }
    if !rlen.is_null() {
        *rlen = rr as size_t;
    }
    return 0 as libc::c_int;
}
