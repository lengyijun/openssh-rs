use ::libc;
extern "C" {

    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memchr(_: *const libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn sshbuf_consume_end(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_reserve(
        buf: *mut crate::sshbuf::sshbuf,
        len: size_t,
        dpp: *mut *mut u_char,
    ) -> libc::c_int;
    fn sshbuf_mutable_ptr(buf: *const crate::sshbuf::sshbuf) -> *mut u_char;
    fn sshbuf_len(buf: *const crate::sshbuf::sshbuf) -> size_t;
    fn sshbuf_ptr(buf: *const crate::sshbuf::sshbuf) -> *const u_char;
    fn sshbuf_consume(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_set_parent(
        child: *mut crate::sshbuf::sshbuf,
        parent: *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_free(buf: *mut crate::sshbuf::sshbuf);
    fn sshbuf_from(blob: *const libc::c_void, len: size_t) -> *mut crate::sshbuf::sshbuf;
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
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type u_char = __u_char;
pub type size_t = libc::c_ulong;
pub type u_int8_t = __uint8_t;
pub type u_int16_t = __uint16_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type va_list = __builtin_va_list;
pub unsafe extern "C" fn sshbuf_get(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *mut libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    let mut p: *const u_char = sshbuf_ptr(buf);
    let mut r: libc::c_int = 0;
    r = sshbuf_consume(buf, len);
    if r < 0 as libc::c_int {
        return r;
    }
    if !v.is_null() && len != 0 as libc::c_int as libc::c_ulong {
        memcpy(v, p as *const libc::c_void, len);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_get_u64(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut valp: *mut u_int64_t,
) -> libc::c_int {
    let mut p: *const u_char = sshbuf_ptr(buf);
    let mut r: libc::c_int = 0;
    r = sshbuf_consume(buf, 8 as libc::c_int as size_t);
    if r < 0 as libc::c_int {
        return r;
    }
    if !valp.is_null() {
        *valp = (*p.offset(0 as libc::c_int as isize) as u_int64_t) << 56 as libc::c_int
            | (*p.offset(1 as libc::c_int as isize) as u_int64_t) << 48 as libc::c_int
            | (*p.offset(2 as libc::c_int as isize) as u_int64_t) << 40 as libc::c_int
            | (*p.offset(3 as libc::c_int as isize) as u_int64_t) << 32 as libc::c_int
            | (*p.offset(4 as libc::c_int as isize) as u_int64_t) << 24 as libc::c_int
            | (*p.offset(5 as libc::c_int as isize) as u_int64_t) << 16 as libc::c_int
            | (*p.offset(6 as libc::c_int as isize) as u_int64_t) << 8 as libc::c_int
            | *p.offset(7 as libc::c_int as isize) as u_int64_t;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_get_u32(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut valp: *mut u_int32_t,
) -> libc::c_int {
    let mut p: *const u_char = sshbuf_ptr(buf);
    let mut r: libc::c_int = 0;
    r = sshbuf_consume(buf, 4 as libc::c_int as size_t);
    if r < 0 as libc::c_int {
        return r;
    }
    if !valp.is_null() {
        *valp = (*p.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int
            | (*p.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
            | (*p.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
            | *p.offset(3 as libc::c_int as isize) as u_int32_t;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_get_u16(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut valp: *mut u_int16_t,
) -> libc::c_int {
    let mut p: *const u_char = sshbuf_ptr(buf);
    let mut r: libc::c_int = 0;
    r = sshbuf_consume(buf, 2 as libc::c_int as size_t);
    if r < 0 as libc::c_int {
        return r;
    }
    if !valp.is_null() {
        *valp = ((*p.offset(0 as libc::c_int as isize) as u_int16_t as libc::c_int)
            << 8 as libc::c_int
            | *p.offset(1 as libc::c_int as isize) as u_int16_t as libc::c_int)
            as u_int16_t;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_get_u8(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut valp: *mut u_char,
) -> libc::c_int {
    let mut p: *const u_char = sshbuf_ptr(buf);
    let mut r: libc::c_int = 0;
    r = sshbuf_consume(buf, 1 as libc::c_int as size_t);
    if r < 0 as libc::c_int {
        return r;
    }
    if !valp.is_null() {
        *valp = *p;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn check_offset(
    mut buf: *const crate::sshbuf::sshbuf,
    mut wr: libc::c_int,
    mut offset: size_t,
    mut len: size_t,
) -> libc::c_int {
    if (sshbuf_ptr(buf)).is_null() {
        return -(1 as libc::c_int);
    }
    if offset >= (18446744073709551615 as libc::c_ulong).wrapping_sub(len) {
        return -(10 as libc::c_int);
    }
    if offset.wrapping_add(len) > sshbuf_len(buf) {
        return if wr != 0 {
            -(9 as libc::c_int)
        } else {
            -(3 as libc::c_int)
        };
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn check_roffset(
    mut buf: *const crate::sshbuf::sshbuf,
    mut offset: size_t,
    mut len: size_t,
    mut p: *mut *const u_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    *p = 0 as *const u_char;
    r = check_offset(buf, 0 as libc::c_int, offset, len);
    if r != 0 as libc::c_int {
        return r;
    }
    *p = (sshbuf_ptr(buf)).offset(offset as isize);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_peek_u64(
    mut buf: *const crate::sshbuf::sshbuf,
    mut offset: size_t,
    mut valp: *mut u_int64_t,
) -> libc::c_int {
    let mut p: *const u_char = 0 as *const u_char;
    let mut r: libc::c_int = 0;
    if !valp.is_null() {
        *valp = 0 as libc::c_int as u_int64_t;
    }
    r = check_roffset(buf, offset, 8 as libc::c_int as size_t, &mut p);
    if r != 0 as libc::c_int {
        return r;
    }
    if !valp.is_null() {
        *valp = (*p.offset(0 as libc::c_int as isize) as u_int64_t) << 56 as libc::c_int
            | (*p.offset(1 as libc::c_int as isize) as u_int64_t) << 48 as libc::c_int
            | (*p.offset(2 as libc::c_int as isize) as u_int64_t) << 40 as libc::c_int
            | (*p.offset(3 as libc::c_int as isize) as u_int64_t) << 32 as libc::c_int
            | (*p.offset(4 as libc::c_int as isize) as u_int64_t) << 24 as libc::c_int
            | (*p.offset(5 as libc::c_int as isize) as u_int64_t) << 16 as libc::c_int
            | (*p.offset(6 as libc::c_int as isize) as u_int64_t) << 8 as libc::c_int
            | *p.offset(7 as libc::c_int as isize) as u_int64_t;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_peek_u32(
    mut buf: *const crate::sshbuf::sshbuf,
    mut offset: size_t,
    mut valp: *mut u_int32_t,
) -> libc::c_int {
    let mut p: *const u_char = 0 as *const u_char;
    let mut r: libc::c_int = 0;
    if !valp.is_null() {
        *valp = 0 as libc::c_int as u_int32_t;
    }
    r = check_roffset(buf, offset, 4 as libc::c_int as size_t, &mut p);
    if r != 0 as libc::c_int {
        return r;
    }
    if !valp.is_null() {
        *valp = (*p.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int
            | (*p.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
            | (*p.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
            | *p.offset(3 as libc::c_int as isize) as u_int32_t;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_peek_u16(
    mut buf: *const crate::sshbuf::sshbuf,
    mut offset: size_t,
    mut valp: *mut u_int16_t,
) -> libc::c_int {
    let mut p: *const u_char = 0 as *const u_char;
    let mut r: libc::c_int = 0;
    if !valp.is_null() {
        *valp = 0 as libc::c_int as u_int16_t;
    }
    r = check_roffset(buf, offset, 2 as libc::c_int as size_t, &mut p);
    if r != 0 as libc::c_int {
        return r;
    }
    if !valp.is_null() {
        *valp = ((*p.offset(0 as libc::c_int as isize) as u_int16_t as libc::c_int)
            << 8 as libc::c_int
            | *p.offset(1 as libc::c_int as isize) as u_int16_t as libc::c_int)
            as u_int16_t;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_peek_u8(
    mut buf: *const crate::sshbuf::sshbuf,
    mut offset: size_t,
    mut valp: *mut u_char,
) -> libc::c_int {
    let mut p: *const u_char = 0 as *const u_char;
    let mut r: libc::c_int = 0;
    if !valp.is_null() {
        *valp = 0 as libc::c_int as u_char;
    }
    r = check_roffset(buf, offset, 1 as libc::c_int as size_t, &mut p);
    if r != 0 as libc::c_int {
        return r;
    }
    if !valp.is_null() {
        *valp = *p;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_get_string(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut valp: *mut *mut u_char,
    mut lenp: *mut size_t,
) -> libc::c_int {
    let mut val: *const u_char = 0 as *const u_char;
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    if !valp.is_null() {
        *valp = 0 as *mut u_char;
    }
    if !lenp.is_null() {
        *lenp = 0 as libc::c_int as size_t;
    }
    r = sshbuf_get_string_direct(buf, &mut val, &mut len);
    if r < 0 as libc::c_int {
        return r;
    }
    if !valp.is_null() {
        *valp = libc::malloc((len.wrapping_add(1 as libc::c_int as libc::c_ulong)) as usize)
            as *mut u_char;
        if (*valp).is_null() {
            return -(2 as libc::c_int);
        }
        if len != 0 as libc::c_int as libc::c_ulong {
            memcpy(*valp as *mut libc::c_void, val as *const libc::c_void, len);
        }
        *(*valp).offset(len as isize) = '\0' as i32 as u_char;
    }
    if !lenp.is_null() {
        *lenp = len;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_get_string_direct(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut valp: *mut *const u_char,
    mut lenp: *mut size_t,
) -> libc::c_int {
    let mut len: size_t = 0;
    let mut p: *const u_char = 0 as *const u_char;
    let mut r: libc::c_int = 0;
    if !valp.is_null() {
        *valp = 0 as *const u_char;
    }
    if !lenp.is_null() {
        *lenp = 0 as libc::c_int as size_t;
    }
    r = sshbuf_peek_string_direct(buf, &mut p, &mut len);
    if r < 0 as libc::c_int {
        return r;
    }
    if !valp.is_null() {
        *valp = p;
    }
    if !lenp.is_null() {
        *lenp = len;
    }
    if sshbuf_consume(buf, len.wrapping_add(4 as libc::c_int as libc::c_ulong)) != 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_peek_string_direct(
    mut buf: *const crate::sshbuf::sshbuf,
    mut valp: *mut *const u_char,
    mut lenp: *mut size_t,
) -> libc::c_int {
    let mut len: u_int32_t = 0;
    let mut p: *const u_char = sshbuf_ptr(buf);
    if !valp.is_null() {
        *valp = 0 as *const u_char;
    }
    if !lenp.is_null() {
        *lenp = 0 as libc::c_int as size_t;
    }
    if sshbuf_len(buf) < 4 as libc::c_int as libc::c_ulong {
        return -(3 as libc::c_int);
    }
    len = (*p.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int
        | (*p.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
        | (*p.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
        | *p.offset(3 as libc::c_int as isize) as u_int32_t;
    if len > (0x8000000 as libc::c_int - 4 as libc::c_int) as libc::c_uint {
        return -(6 as libc::c_int);
    }
    if (sshbuf_len(buf)).wrapping_sub(4 as libc::c_int as libc::c_ulong) < len as libc::c_ulong {
        return -(3 as libc::c_int);
    }
    if !valp.is_null() {
        *valp = p.offset(4 as libc::c_int as isize);
    }
    if !lenp.is_null() {
        *lenp = len as size_t;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_get_cstring(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut valp: *mut *mut libc::c_char,
    mut lenp: *mut size_t,
) -> libc::c_int {
    let mut len: size_t = 0;
    let mut p: *const u_char = 0 as *const u_char;
    let mut z: *const u_char = 0 as *const u_char;
    let mut r: libc::c_int = 0;
    if !valp.is_null() {
        *valp = 0 as *mut libc::c_char;
    }
    if !lenp.is_null() {
        *lenp = 0 as libc::c_int as size_t;
    }
    r = sshbuf_peek_string_direct(buf, &mut p, &mut len);
    if r != 0 as libc::c_int {
        return r;
    }
    if len > 0 as libc::c_int as libc::c_ulong
        && {
            z = memchr(p as *const libc::c_void, '\0' as i32, len) as *const u_char;
            !z.is_null()
        }
        && z < p.offset(len as isize).offset(-(1 as libc::c_int as isize))
    {
        return -(4 as libc::c_int);
    }
    r = sshbuf_get_string_direct(buf, 0 as *mut *const u_char, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if !valp.is_null() {
        *valp = libc::malloc((len.wrapping_add(1 as libc::c_int as libc::c_ulong)) as usize)
            as *mut libc::c_char;
        if (*valp).is_null() {
            return -(2 as libc::c_int);
        }
        if len != 0 as libc::c_int as libc::c_ulong {
            memcpy(*valp as *mut libc::c_void, p as *const libc::c_void, len);
        }
        *(*valp).offset(len as isize) = '\0' as i32 as libc::c_char;
    }
    if !lenp.is_null() {
        *lenp = len;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_get_stringb(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut len: u_int32_t = 0;
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = sshbuf_peek_string_direct(buf, 0 as *mut *const u_char, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_u32(buf, &mut len);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_reserve(v, len as size_t, &mut p);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get(buf, p as *mut libc::c_void, len as size_t);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_put(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = sshbuf_reserve(buf, len, &mut p);
    if r < 0 as libc::c_int {
        return r;
    }
    if len != 0 as libc::c_int as libc::c_ulong {
        memcpy(p as *mut libc::c_void, v, len);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_putb(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *const crate::sshbuf::sshbuf,
) -> libc::c_int {
    if v.is_null() {
        return 0 as libc::c_int;
    }
    return sshbuf_put(buf, sshbuf_ptr(v) as *const libc::c_void, sshbuf_len(v));
}
pub unsafe extern "C" fn sshbuf_putf(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut fmt: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut ap: ::core::ffi::VaListImpl;
    let mut r: libc::c_int = 0;
    ap = args.clone();
    r = sshbuf_putfv(buf, fmt, ap.as_va_list());
    return r;
}
pub unsafe extern "C" fn sshbuf_putfv(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut fmt: *const libc::c_char,
    mut ap: ::core::ffi::VaList,
) -> libc::c_int {
    let mut ap2: ::core::ffi::VaListImpl;
    let mut r: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut p: *mut u_char = 0 as *mut u_char;
    ap2 = ap.clone();
    len = vsnprintf(
        0 as *mut libc::c_char,
        0 as libc::c_int as libc::c_ulong,
        fmt,
        ap2.as_va_list(),
    );
    if len < 0 as libc::c_int {
        r = -(10 as libc::c_int);
    } else if len == 0 as libc::c_int {
        r = 0 as libc::c_int;
    } else {
        ap2 = ap.clone();
        r = sshbuf_reserve(
            buf,
            (len as size_t).wrapping_add(1 as libc::c_int as libc::c_ulong),
            &mut p,
        );
        if !(r < 0 as libc::c_int) {
            r = vsnprintf(
                p as *mut libc::c_char,
                (len + 1 as libc::c_int) as libc::c_ulong,
                fmt,
                ap2.as_va_list(),
            );
            if r != len {
                r = -(1 as libc::c_int);
            } else {
                r = sshbuf_consume_end(buf, 1 as libc::c_int as size_t);
                if !(r != 0 as libc::c_int) {
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    return r;
}
pub unsafe extern "C" fn sshbuf_put_u64(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut val: u_int64_t,
) -> libc::c_int {
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = sshbuf_reserve(buf, 8 as libc::c_int as size_t, &mut p);
    if r < 0 as libc::c_int {
        return r;
    }
    let __v: u_int64_t = val;
    *p.offset(0 as libc::c_int as isize) =
        (__v >> 56 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(1 as libc::c_int as isize) =
        (__v >> 48 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(2 as libc::c_int as isize) =
        (__v >> 40 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(3 as libc::c_int as isize) =
        (__v >> 32 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(4 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(5 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(6 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(7 as libc::c_int as isize) = (__v & 0xff as libc::c_int as libc::c_ulong) as u_char;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_put_u32(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut val: u_int32_t,
) -> libc::c_int {
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = sshbuf_reserve(buf, 4 as libc::c_int as size_t, &mut p);
    if r < 0 as libc::c_int {
        return r;
    }
    let __v: u_int32_t = val;
    *p.offset(0 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *p.offset(1 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *p.offset(2 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *p.offset(3 as libc::c_int as isize) = (__v & 0xff as libc::c_int as libc::c_uint) as u_char;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_put_u16(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut val: u_int16_t,
) -> libc::c_int {
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = sshbuf_reserve(buf, 2 as libc::c_int as size_t, &mut p);
    if r < 0 as libc::c_int {
        return r;
    }
    let __v: u_int16_t = val;
    *p.offset(0 as libc::c_int as isize) =
        (__v as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(1 as libc::c_int as isize) = (__v as libc::c_int & 0xff as libc::c_int) as u_char;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_put_u8(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut val: u_char,
) -> libc::c_int {
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = sshbuf_reserve(buf, 1 as libc::c_int as size_t, &mut p);
    if r < 0 as libc::c_int {
        return r;
    }
    *p.offset(0 as libc::c_int as isize) = val;
    return 0 as libc::c_int;
}
unsafe extern "C" fn check_woffset(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut offset: size_t,
    mut len: size_t,
    mut p: *mut *mut u_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    *p = 0 as *mut u_char;
    r = check_offset(buf, 1 as libc::c_int, offset, len);
    if r != 0 as libc::c_int {
        return r;
    }
    if (sshbuf_mutable_ptr(buf)).is_null() {
        return -(49 as libc::c_int);
    }
    *p = (sshbuf_mutable_ptr(buf)).offset(offset as isize);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_poke_u64(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut offset: size_t,
    mut val: u_int64_t,
) -> libc::c_int {
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = check_woffset(buf, offset, 8 as libc::c_int as size_t, &mut p);
    if r != 0 as libc::c_int {
        return r;
    }
    let __v: u_int64_t = val;
    *p.offset(0 as libc::c_int as isize) =
        (__v >> 56 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(1 as libc::c_int as isize) =
        (__v >> 48 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(2 as libc::c_int as isize) =
        (__v >> 40 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(3 as libc::c_int as isize) =
        (__v >> 32 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(4 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(5 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(6 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
    *p.offset(7 as libc::c_int as isize) = (__v & 0xff as libc::c_int as libc::c_ulong) as u_char;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_poke_u32(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut offset: size_t,
    mut val: u_int32_t,
) -> libc::c_int {
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = check_woffset(buf, offset, 4 as libc::c_int as size_t, &mut p);
    if r != 0 as libc::c_int {
        return r;
    }
    let __v: u_int32_t = val;
    *p.offset(0 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *p.offset(1 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *p.offset(2 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *p.offset(3 as libc::c_int as isize) = (__v & 0xff as libc::c_int as libc::c_uint) as u_char;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_poke_u16(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut offset: size_t,
    mut val: u_int16_t,
) -> libc::c_int {
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = check_woffset(buf, offset, 2 as libc::c_int as size_t, &mut p);
    if r != 0 as libc::c_int {
        return r;
    }
    let __v: u_int16_t = val;
    *p.offset(0 as libc::c_int as isize) =
        (__v as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(1 as libc::c_int as isize) = (__v as libc::c_int & 0xff as libc::c_int) as u_char;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_poke_u8(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut offset: size_t,
    mut val: u_char,
) -> libc::c_int {
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = check_woffset(buf, offset, 1 as libc::c_int as size_t, &mut p);
    if r != 0 as libc::c_int {
        return r;
    }
    *p = val;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_poke(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut offset: size_t,
    mut v: *mut libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    r = check_woffset(buf, offset, len, &mut p);
    if r != 0 as libc::c_int {
        return r;
    }
    memcpy(p as *mut libc::c_void, v, len);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_put_string(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    let mut d: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    if len > (0x8000000 as libc::c_int - 4 as libc::c_int) as libc::c_ulong {
        return -(9 as libc::c_int);
    }
    r = sshbuf_reserve(
        buf,
        len.wrapping_add(4 as libc::c_int as libc::c_ulong),
        &mut d,
    );
    if r < 0 as libc::c_int {
        return r;
    }
    let __v: u_int32_t = len as u_int32_t;
    *d.offset(0 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *d.offset(1 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *d.offset(2 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *d.offset(3 as libc::c_int as isize) = (__v & 0xff as libc::c_int as libc::c_uint) as u_char;
    if len != 0 as libc::c_int as libc::c_ulong {
        memcpy(
            d.offset(4 as libc::c_int as isize) as *mut libc::c_void,
            v,
            len,
        );
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_put_cstring(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *const libc::c_char,
) -> libc::c_int {
    return sshbuf_put_string(
        buf,
        v as *const libc::c_void,
        if v.is_null() {
            0 as libc::c_int as libc::c_ulong
        } else {
            strlen(v)
        },
    );
}
pub unsafe extern "C" fn sshbuf_put_stringb(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *const crate::sshbuf::sshbuf,
) -> libc::c_int {
    if v.is_null() {
        return sshbuf_put_string(buf, 0 as *const libc::c_void, 0 as libc::c_int as size_t);
    }
    return sshbuf_put_string(buf, sshbuf_ptr(v) as *const libc::c_void, sshbuf_len(v));
}
pub unsafe extern "C" fn sshbuf_froms(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut bufp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut p: *const u_char = 0 as *const u_char;
    let mut len: size_t = 0;
    let mut ret: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    if buf.is_null() || bufp.is_null() {
        return -(10 as libc::c_int);
    }
    *bufp = 0 as *mut crate::sshbuf::sshbuf;
    r = sshbuf_peek_string_direct(buf, &mut p, &mut len);
    if r != 0 as libc::c_int {
        return r;
    }
    ret = sshbuf_from(p as *const libc::c_void, len);
    if ret.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_consume(buf, len.wrapping_add(4 as libc::c_int as libc::c_ulong));
    if r != 0 as libc::c_int || {
        r = sshbuf_set_parent(ret, buf);
        r != 0 as libc::c_int
    } {
        sshbuf_free(ret);
        return r;
    }
    *bufp = ret;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_put_bignum2_bytes(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    let mut d: *mut u_char = 0 as *mut u_char;
    let mut s: *const u_char = v as *const u_char;
    let mut r: libc::c_int = 0;
    let mut prepend: libc::c_int = 0;
    if len > (0x8000000 as libc::c_int - 5 as libc::c_int) as libc::c_ulong {
        return -(9 as libc::c_int);
    }
    while len > 0 as libc::c_int as libc::c_ulong && *s as libc::c_int == 0 as libc::c_int {
        len = len.wrapping_sub(1);
        len;
        s = s.offset(1);
        s;
    }
    prepend = (len > 0 as libc::c_int as libc::c_ulong
        && *s.offset(0 as libc::c_int as isize) as libc::c_int & 0x80 as libc::c_int
            != 0 as libc::c_int) as libc::c_int;
    r = sshbuf_reserve(
        buf,
        len.wrapping_add(4 as libc::c_int as libc::c_ulong)
            .wrapping_add(prepend as libc::c_ulong),
        &mut d,
    );
    if r < 0 as libc::c_int {
        return r;
    }
    let __v: u_int32_t = len.wrapping_add(prepend as libc::c_ulong) as u_int32_t;
    *d.offset(0 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *d.offset(1 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *d.offset(2 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *d.offset(3 as libc::c_int as isize) = (__v & 0xff as libc::c_int as libc::c_uint) as u_char;
    if prepend != 0 {
        *d.offset(4 as libc::c_int as isize) = 0 as libc::c_int as u_char;
    }
    if len != 0 as libc::c_int as libc::c_ulong {
        memcpy(
            d.offset(4 as libc::c_int as isize).offset(prepend as isize) as *mut libc::c_void,
            s as *const libc::c_void,
            len,
        );
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_get_bignum2_bytes_direct(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut valp: *mut *const u_char,
    mut lenp: *mut size_t,
) -> libc::c_int {
    let mut d: *const u_char = 0 as *const u_char;
    let mut len: size_t = 0;
    let mut olen: size_t = 0;
    let mut r: libc::c_int = 0;
    r = sshbuf_peek_string_direct(buf, &mut d, &mut olen);
    if r < 0 as libc::c_int {
        return r;
    }
    len = olen;
    if len != 0 as libc::c_int as libc::c_ulong
        && *d as libc::c_int & 0x80 as libc::c_int != 0 as libc::c_int
    {
        return -(5 as libc::c_int);
    }
    if len > (16384 as libc::c_int / 8 as libc::c_int + 1 as libc::c_int) as libc::c_ulong
        || len == (16384 as libc::c_int / 8 as libc::c_int + 1 as libc::c_int) as libc::c_ulong
            && *d as libc::c_int != 0 as libc::c_int
    {
        return -(7 as libc::c_int);
    }
    while len > 0 as libc::c_int as libc::c_ulong && *d as libc::c_int == 0 as libc::c_int {
        d = d.offset(1);
        d;
        len = len.wrapping_sub(1);
        len;
    }
    if !valp.is_null() {
        *valp = d;
    }
    if !lenp.is_null() {
        *lenp = len;
    }
    if sshbuf_consume(buf, olen.wrapping_add(4 as libc::c_int as libc::c_ulong)) != 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
