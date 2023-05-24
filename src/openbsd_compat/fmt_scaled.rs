use ::libc;
extern "C" {
    fn __errno_location() -> *mut libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn llabs(_: libc::c_longlong) -> libc::c_longlong;
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn __ctype_tolower_loc() -> *mut *const __int32_t;
}
pub type __int32_t = libc::c_int;
pub type size_t = libc::c_ulong;
pub type unit_type = libc::c_uint;
pub const EXA: unit_type = 6;
pub const PETA: unit_type = 5;
pub const TERA: unit_type = 4;
pub const GIGA: unit_type = 3;
pub const MEGA: unit_type = 2;
pub const KILO: unit_type = 1;
pub const NONE: unit_type = 0;
pub const _ISalnum: C2RustUnnamed = 8;
pub const _ISdigit: C2RustUnnamed = 2048;
pub const _ISspace: C2RustUnnamed = 8192;
pub type C2RustUnnamed = libc::c_uint;
pub const _ISpunct: C2RustUnnamed = 4;
pub const _IScntrl: C2RustUnnamed = 2;
pub const _ISblank: C2RustUnnamed = 1;
pub const _ISgraph: C2RustUnnamed = 32768;
pub const _ISprint: C2RustUnnamed = 16384;
pub const _ISxdigit: C2RustUnnamed = 4096;
pub const _ISalpha: C2RustUnnamed = 1024;
pub const _ISlower: C2RustUnnamed = 512;
pub const _ISupper: C2RustUnnamed = 256;
#[inline]
unsafe extern "C" fn tolower(mut __c: libc::c_int) -> libc::c_int {
    return if __c >= -(128 as libc::c_int) && __c < 256 as libc::c_int {
        *(*__ctype_tolower_loc()).offset(__c as isize)
    } else {
        __c
    };
}
static mut units: [unit_type; 7] = [NONE, KILO, MEGA, GIGA, TERA, PETA, EXA];
static mut scale_chars: [libc::c_char; 8] =
    unsafe { *::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"BKMGTPE\0") };
static mut scale_factors: [libc::c_longlong; 7] = [
    1 as libc::c_longlong,
    1024 as libc::c_longlong,
    1024 as libc::c_longlong * 1024 as libc::c_int as libc::c_longlong,
    1024 as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong,
    1024 as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong,
    1024 as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong,
    1024 as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong
        * 1024 as libc::c_int as libc::c_longlong,
];
#[no_mangle]
pub unsafe extern "C" fn scan_scaled(
    mut scaled: *mut libc::c_char,
    mut result: *mut libc::c_longlong,
) -> libc::c_int {
    let mut p: *mut libc::c_char = scaled;
    let mut sign: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_uint = 0;
    let mut ndigits: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut fract_digits: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut scale_fact: libc::c_longlong = 1 as libc::c_int as libc::c_longlong;
    let mut whole: libc::c_longlong = 0 as libc::c_int as libc::c_longlong;
    let mut fpart: libc::c_longlong = 0 as libc::c_int as libc::c_longlong;
    while *p as libc::c_uchar as libc::c_int & !(0x7f as libc::c_int) == 0 as libc::c_int
        && *(*__ctype_b_loc()).offset(*p as libc::c_uchar as libc::c_int as isize) as libc::c_int
            & _ISspace as libc::c_int as libc::c_ushort as libc::c_int
            != 0
    {
        p = p.offset(1);
        p;
    }
    while *p as libc::c_int == '-' as i32 || *p as libc::c_int == '+' as i32 {
        if *p as libc::c_int == '-' as i32 {
            if sign != 0 {
                *__errno_location() = 22 as libc::c_int;
                return -(1 as libc::c_int);
            }
            sign = -(1 as libc::c_int);
            p = p.offset(1);
            p;
        } else if *p as libc::c_int == '+' as i32 {
            if sign != 0 {
                *__errno_location() = 22 as libc::c_int;
                return -(1 as libc::c_int);
            }
            sign = 1 as libc::c_int;
            p = p.offset(1);
            p;
        }
    }
    while *p as libc::c_uchar as libc::c_int & !(0x7f as libc::c_int) == 0 as libc::c_int
        && (*(*__ctype_b_loc()).offset(*p as libc::c_uchar as libc::c_int as isize) as libc::c_int
            & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int
            != 0
            || *p as libc::c_int == '.' as i32)
    {
        if *p as libc::c_int == '.' as i32 {
            if fract_digits > 0 as libc::c_int as libc::c_uint {
                *__errno_location() = 22 as libc::c_int;
                return -(1 as libc::c_int);
            }
            fract_digits = 1 as libc::c_int as libc::c_uint;
        } else {
            i = (*p as libc::c_int - '0' as i32) as libc::c_uint;
            if fract_digits > 0 as libc::c_int as libc::c_uint {
                if !(fract_digits as libc::c_ulong
                    >= (::core::mem::size_of::<[unit_type; 7]>() as libc::c_ulong)
                        .wrapping_div(::core::mem::size_of::<unit_type>() as libc::c_ulong)
                        .wrapping_mul(3 as libc::c_int as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong))
                {
                    fract_digits = fract_digits.wrapping_add(1);
                    fract_digits;
                    if fpart
                        > 9223372036854775807 as libc::c_longlong
                            / 10 as libc::c_int as libc::c_longlong
                    {
                        *__errno_location() = 34 as libc::c_int;
                        return -(1 as libc::c_int);
                    }
                    fpart *= 10 as libc::c_int as libc::c_longlong;
                    if i as libc::c_longlong > 9223372036854775807 as libc::c_longlong - fpart {
                        *__errno_location() = 34 as libc::c_int;
                        return -(1 as libc::c_int);
                    }
                    fpart += i as libc::c_longlong;
                }
            } else {
                ndigits = ndigits.wrapping_add(1);
                if ndigits as libc::c_ulong
                    >= (::core::mem::size_of::<[unit_type; 7]>() as libc::c_ulong)
                        .wrapping_div(::core::mem::size_of::<unit_type>() as libc::c_ulong)
                        .wrapping_mul(3 as libc::c_int as libc::c_ulong)
                {
                    *__errno_location() = 34 as libc::c_int;
                    return -(1 as libc::c_int);
                }
                if whole
                    > 9223372036854775807 as libc::c_longlong
                        / 10 as libc::c_int as libc::c_longlong
                {
                    *__errno_location() = 34 as libc::c_int;
                    return -(1 as libc::c_int);
                }
                whole *= 10 as libc::c_int as libc::c_longlong;
                if i as libc::c_longlong > 9223372036854775807 as libc::c_longlong - whole {
                    *__errno_location() = 34 as libc::c_int;
                    return -(1 as libc::c_int);
                }
                whole += i as libc::c_longlong;
            }
        }
        p = p.offset(1);
        p;
    }
    if sign != 0 {
        whole *= sign as libc::c_longlong;
    }
    if *p == 0 {
        *result = whole;
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::core::mem::size_of::<[unit_type; 7]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<unit_type>() as libc::c_ulong)
    {
        if *p as libc::c_int == scale_chars[i as usize] as libc::c_int
            || *p as libc::c_int
                == ({
                    let mut __res: libc::c_int = 0;
                    if ::core::mem::size_of::<libc::c_uchar>() as libc::c_ulong
                        > 1 as libc::c_int as libc::c_ulong
                    {
                        if 0 != 0 {
                            let mut __c: libc::c_int =
                                scale_chars[i as usize] as libc::c_uchar as libc::c_int;
                            __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                                __c
                            } else {
                                *(*__ctype_tolower_loc()).offset(__c as isize)
                            });
                        } else {
                            __res =
                                tolower(scale_chars[i as usize] as libc::c_uchar as libc::c_int);
                        }
                    } else {
                        __res = *(*__ctype_tolower_loc()).offset(
                            scale_chars[i as usize] as libc::c_uchar as libc::c_int as isize,
                        );
                    }
                    __res
                })
        {
            if *(*__ctype_b_loc()).offset(
                *p.offset(1 as libc::c_int as isize) as libc::c_uchar as libc::c_int as isize
            ) as libc::c_int
                & _ISalnum as libc::c_int as libc::c_ushort as libc::c_int
                != 0
            {
                *__errno_location() = 22 as libc::c_int;
                return -(1 as libc::c_int);
            }
            scale_fact = scale_factors[i as usize];
            if whole > 9223372036854775807 as libc::c_longlong / scale_fact
                || whole
                    < (-(9223372036854775807 as libc::c_longlong) - 1 as libc::c_longlong)
                        / scale_fact
            {
                *__errno_location() = 34 as libc::c_int;
                return -(1 as libc::c_int);
            }
            whole *= scale_fact;
            while fpart >= 9223372036854775807 as libc::c_longlong / scale_fact
                || fpart
                    <= (-(9223372036854775807 as libc::c_longlong) - 1 as libc::c_longlong)
                        / scale_fact
            {
                fpart /= 10 as libc::c_int as libc::c_longlong;
                fract_digits = fract_digits.wrapping_sub(1);
                fract_digits;
            }
            fpart *= scale_fact;
            if fract_digits > 0 as libc::c_int as libc::c_uint {
                i = 0 as libc::c_int as libc::c_uint;
                while i < fract_digits.wrapping_sub(1 as libc::c_int as libc::c_uint) {
                    fpart /= 10 as libc::c_int as libc::c_longlong;
                    i = i.wrapping_add(1);
                    i;
                }
            }
            if sign == -(1 as libc::c_int) {
                whole -= fpart;
            } else {
                whole += fpart;
            }
            *result = whole;
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    *__errno_location() = 22 as libc::c_int;
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn fmt_scaled(
    mut number: libc::c_longlong,
    mut result: *mut libc::c_char,
) -> libc::c_int {
    let mut abval: libc::c_longlong = 0;
    let mut fract: libc::c_longlong = 0 as libc::c_int as libc::c_longlong;
    let mut i: libc::c_uint = 0;
    let mut unit: unit_type = NONE;
    if number == -(9223372036854775807 as libc::c_longlong) - 1 as libc::c_longlong {
        *__errno_location() = 34 as libc::c_int;
        return -(1 as libc::c_int);
    }
    abval = llabs(number);
    if abval / 1024 as libc::c_int as libc::c_longlong
        >= scale_factors[(::core::mem::size_of::<[unit_type; 7]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<unit_type>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize]
    {
        *__errno_location() = 34 as libc::c_int;
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::core::mem::size_of::<[unit_type; 7]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<unit_type>() as libc::c_ulong)
    {
        if (abval / 1024 as libc::c_int as libc::c_longlong) < scale_factors[i as usize] {
            unit = units[i as usize];
            fract = if i == 0 as libc::c_int as libc::c_uint {
                0 as libc::c_int as libc::c_longlong
            } else {
                abval % scale_factors[i as usize]
            };
            number /= scale_factors[i as usize];
            if i > 0 as libc::c_int as libc::c_uint {
                fract /= scale_factors[i.wrapping_sub(1 as libc::c_int as libc::c_uint) as usize];
            }
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    fract = (10 as libc::c_int as libc::c_longlong * fract
        + 512 as libc::c_int as libc::c_longlong)
        / 1024 as libc::c_int as libc::c_longlong;
    if fract >= 10 as libc::c_int as libc::c_longlong {
        if number >= 0 as libc::c_int as libc::c_longlong {
            number += 1;
            number;
        } else {
            number -= 1;
            number;
        }
        fract = 0 as libc::c_int as libc::c_longlong;
    } else if fract < 0 as libc::c_int as libc::c_longlong {
        fract = 0 as libc::c_int as libc::c_longlong;
    }
    if number == 0 as libc::c_int as libc::c_longlong {
        strlcpy(
            result,
            b"0B\0" as *const u8 as *const libc::c_char,
            7 as libc::c_int as size_t,
        );
    } else if unit as libc::c_uint == NONE as libc::c_int as libc::c_uint
        || number >= 100 as libc::c_int as libc::c_longlong
        || number <= -(100 as libc::c_int) as libc::c_longlong
    {
        if fract >= 5 as libc::c_int as libc::c_longlong {
            if number >= 0 as libc::c_int as libc::c_longlong {
                number += 1;
                number;
            } else {
                number -= 1;
                number;
            }
        }
        snprintf(
            result,
            7 as libc::c_int as libc::c_ulong,
            b"%lld%c\0" as *const u8 as *const libc::c_char,
            number,
            scale_chars[unit as usize] as libc::c_int,
        );
    } else {
        snprintf(
            result,
            7 as libc::c_int as libc::c_ulong,
            b"%lld.%1lld%c\0" as *const u8 as *const libc::c_char,
            number,
            fract,
            scale_chars[unit as usize] as libc::c_int,
        );
    }
    return 0 as libc::c_int;
}
