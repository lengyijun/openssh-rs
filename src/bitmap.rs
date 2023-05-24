use ::libc;
extern "C" {
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bitmap {
    pub d: *mut u_int,
    pub len: size_t,
    pub top: size_t,
}
pub unsafe extern "C" fn bitmap_new() -> *mut bitmap {
    let mut ret: *mut bitmap = 0 as *mut bitmap;
    ret = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<bitmap>() as libc::c_ulong,
    ) as *mut bitmap;
    if ret.is_null() {
        return 0 as *mut bitmap;
    }
    (*ret).d = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<u_int>() as libc::c_ulong,
    ) as *mut u_int;
    if ((*ret).d).is_null() {
        free(ret as *mut libc::c_void);
        return 0 as *mut bitmap;
    }
    (*ret).len = 1 as libc::c_int as size_t;
    (*ret).top = 0 as libc::c_int as size_t;
    return ret;
}
pub unsafe extern "C" fn bitmap_free(mut b: *mut bitmap) {
    if !b.is_null() && !((*b).d).is_null() {
        bitmap_zero(b);
        free((*b).d as *mut libc::c_void);
        (*b).d = 0 as *mut u_int;
    }
    free(b as *mut libc::c_void);
}
pub unsafe extern "C" fn bitmap_zero(mut b: *mut bitmap) {
    memset(
        (*b).d as *mut libc::c_void,
        0 as libc::c_int,
        ((*b).len).wrapping_mul(::core::mem::size_of::<u_int>() as libc::c_ulong),
    );
    (*b).top = 0 as libc::c_int as size_t;
}
pub unsafe extern "C" fn bitmap_test_bit(mut b: *mut bitmap, mut n: u_int) -> libc::c_int {
    if (*b).top >= (*b).len {
        return 0 as libc::c_int;
    }
    if (*b).len == 0 as libc::c_int as libc::c_ulong
        || (n as libc::c_ulong).wrapping_div(
            (::core::mem::size_of::<u_int>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        ) > (*b).top
    {
        return 0 as libc::c_int;
    }
    return (*((*b).d).offset(
        (n as libc::c_ulong).wrapping_div(
            (::core::mem::size_of::<u_int>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        ) as isize,
    ) >> (n
        & ((::core::mem::size_of::<u_int>() as libc::c_ulong)
            .wrapping_mul(8 as libc::c_int as libc::c_ulong) as u_int)
            .wrapping_sub(1 as libc::c_int as libc::c_uint))
        & 1 as libc::c_int as libc::c_uint) as libc::c_int;
}
unsafe extern "C" fn reserve(mut b: *mut bitmap, mut n: u_int) -> libc::c_int {
    let mut tmp: *mut u_int = 0 as *mut u_int;
    let mut nlen: size_t = 0;
    if (*b).top >= (*b).len || n > ((1 as libc::c_int) << 24 as libc::c_int) as libc::c_uint {
        return -(1 as libc::c_int);
    }
    nlen = (n as libc::c_ulong)
        .wrapping_div(
            (::core::mem::size_of::<u_int>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_add(1 as libc::c_int as libc::c_ulong);
    if (*b).len < nlen {
        tmp = recallocarray(
            (*b).d as *mut libc::c_void,
            (*b).len,
            nlen,
            ::core::mem::size_of::<u_int>() as libc::c_ulong,
        ) as *mut u_int;
        if tmp.is_null() {
            return -(1 as libc::c_int);
        }
        (*b).d = tmp;
        (*b).len = nlen;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn bitmap_set_bit(mut b: *mut bitmap, mut n: u_int) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut offset: size_t = 0;
    r = reserve(b, n);
    if r != 0 as libc::c_int {
        return r;
    }
    offset = (n as libc::c_ulong).wrapping_div(
        (::core::mem::size_of::<u_int>() as libc::c_ulong)
            .wrapping_mul(8 as libc::c_int as libc::c_ulong),
    );
    if offset > (*b).top {
        (*b).top = offset;
    }
    let ref mut fresh0 = *((*b).d).offset(offset as isize);
    *fresh0 |= (1 as libc::c_int as u_int)
        << (n
            & ((::core::mem::size_of::<u_int>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong) as u_int)
                .wrapping_sub(1 as libc::c_int as libc::c_uint));
    return 0 as libc::c_int;
}
unsafe extern "C" fn retop(mut b: *mut bitmap) {
    if (*b).top >= (*b).len {
        return;
    }
    while (*b).top > 0 as libc::c_int as libc::c_ulong
        && *((*b).d).offset((*b).top as isize) == 0 as libc::c_int as libc::c_uint
    {
        (*b).top = ((*b).top).wrapping_sub(1);
        (*b).top;
    }
}
pub unsafe extern "C" fn bitmap_clear_bit(mut b: *mut bitmap, mut n: u_int) {
    let mut offset: size_t = 0;
    if (*b).top >= (*b).len || n > ((1 as libc::c_int) << 24 as libc::c_int) as libc::c_uint {
        return;
    }
    offset = (n as libc::c_ulong).wrapping_div(
        (::core::mem::size_of::<u_int>() as libc::c_ulong)
            .wrapping_mul(8 as libc::c_int as libc::c_ulong),
    );
    if offset > (*b).top {
        return;
    }
    let ref mut fresh1 = *((*b).d).offset(offset as isize);
    *fresh1 &= !((1 as libc::c_int as u_int)
        << (n
            & ((::core::mem::size_of::<u_int>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong) as u_int)
                .wrapping_sub(1 as libc::c_int as libc::c_uint)));
    retop(b);
}
pub unsafe extern "C" fn bitmap_nbits(mut b: *mut bitmap) -> size_t {
    let mut bits: size_t = 0;
    let mut w: u_int = 0;
    retop(b);
    if (*b).top >= (*b).len {
        return 0 as libc::c_int as size_t;
    }
    if (*b).len == 0 as libc::c_int as libc::c_ulong
        || (*b).top == 0 as libc::c_int as libc::c_ulong
            && *((*b).d).offset(0 as libc::c_int as isize) == 0 as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int as size_t;
    }
    w = *((*b).d).offset((*b).top as isize);
    bits = ((*b).top)
        .wrapping_add(1 as libc::c_int as libc::c_ulong)
        .wrapping_mul(
            (::core::mem::size_of::<u_int>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        );
    while w
        & (1 as libc::c_int as u_int)
            << (::core::mem::size_of::<u_int>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        == 0
    {
        w <<= 1 as libc::c_int;
        bits = bits.wrapping_sub(1);
        bits;
    }
    return bits;
}
pub unsafe extern "C" fn bitmap_nbytes(mut b: *mut bitmap) -> size_t {
    return (bitmap_nbits(b))
        .wrapping_add(7 as libc::c_int as libc::c_ulong)
        .wrapping_div(8 as libc::c_int as libc::c_ulong);
}
pub unsafe extern "C" fn bitmap_to_string(
    mut b: *mut bitmap,
    mut p: *mut libc::c_void,
    mut l: size_t,
) -> libc::c_int {
    let mut s: *mut u_char = p as *mut u_char;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut k: size_t = 0;
    let mut need: size_t = bitmap_nbytes(b);
    if l < need || (*b).top >= (*b).len {
        return -(1 as libc::c_int);
    }
    if l > need {
        l = need;
    }
    k = 0 as libc::c_int as size_t;
    i = k;
    while i < ((*b).top).wrapping_add(1 as libc::c_int as libc::c_ulong) {
        j = 0 as libc::c_int as size_t;
        while j < ::core::mem::size_of::<u_int>() as libc::c_ulong {
            if k >= l {
                break;
            }
            let fresh2 = k;
            k = k.wrapping_add(1);
            *s.offset(
                need.wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(fresh2) as isize,
            ) = (*((*b).d).offset(i as isize) >> j.wrapping_mul(8 as libc::c_int as libc::c_ulong)
                & 0xff as libc::c_int as libc::c_uint) as u_char;
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn bitmap_from_string(
    mut b: *mut bitmap,
    mut p: *const libc::c_void,
    mut l: size_t,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut i: size_t = 0;
    let mut offset: size_t = 0;
    let mut shift: size_t = 0;
    let mut s: *const u_char = p as *const u_char;
    if l > (((1 as libc::c_int) << 24 as libc::c_int) / 8 as libc::c_int) as libc::c_ulong {
        return -(1 as libc::c_int);
    }
    r = reserve(
        b,
        l.wrapping_mul(8 as libc::c_int as libc::c_ulong) as u_int,
    );
    if r != 0 as libc::c_int {
        return r;
    }
    bitmap_zero(b);
    if l == 0 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    offset = l
        .wrapping_add(
            (::core::mem::size_of::<u_int>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        )
        .wrapping_div(::core::mem::size_of::<u_int>() as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong);
    (*b).top = offset;
    shift = l
        .wrapping_add(
            (::core::mem::size_of::<u_int>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        )
        .wrapping_rem(::core::mem::size_of::<u_int>() as libc::c_ulong)
        .wrapping_mul(8 as libc::c_int as libc::c_ulong);
    i = 0 as libc::c_int as size_t;
    while i < l {
        let ref mut fresh3 = *((*b).d).offset(offset as isize);
        *fresh3 |= (*s.offset(i as isize) as u_int) << shift;
        if shift == 0 as libc::c_int as libc::c_ulong {
            offset = offset.wrapping_sub(1);
            offset;
            shift = (::core::mem::size_of::<u_int>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                .wrapping_sub(8 as libc::c_int as libc::c_ulong);
        } else {
            shift = (shift as libc::c_ulong).wrapping_sub(8 as libc::c_int as libc::c_ulong)
                as size_t as size_t;
        }
        i = i.wrapping_add(1);
        i;
    }
    retop(b);
    return 0 as libc::c_int;
}
