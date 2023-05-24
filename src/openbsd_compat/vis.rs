use ::libc;
extern "C" {
    fn __errno_location() -> *mut libc::c_int;
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn reallocarray(__ptr: *mut libc::c_void, __nmemb: size_t, __size: size_t)
        -> *mut libc::c_void;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub const _IScntrl: C2RustUnnamed = 2;
pub const _ISgraph: C2RustUnnamed = 32768;
pub type C2RustUnnamed = libc::c_uint;
pub const _ISalnum: C2RustUnnamed = 8;
pub const _ISpunct: C2RustUnnamed = 4;
pub const _ISblank: C2RustUnnamed = 1;
pub const _ISprint: C2RustUnnamed = 16384;
pub const _ISspace: C2RustUnnamed = 8192;
pub const _ISxdigit: C2RustUnnamed = 4096;
pub const _ISdigit: C2RustUnnamed = 2048;
pub const _ISalpha: C2RustUnnamed = 1024;
pub const _ISlower: C2RustUnnamed = 512;
pub const _ISupper: C2RustUnnamed = 256;
#[no_mangle]
pub unsafe extern "C" fn vis(
    mut dst: *mut libc::c_char,
    mut c: libc::c_int,
    mut flag: libc::c_int,
    mut nextc: libc::c_int,
) -> *mut libc::c_char {
    let mut current_block: u64;
    if (c == '\\' as i32 || flag & 0x400 as libc::c_int == 0 as libc::c_int)
        && (c as u_int
            <= (127 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as libc::c_uint
            && c as u_char as libc::c_int & !(0x7f as libc::c_int) == 0 as libc::c_int
            && (c != '*' as i32 && c != '?' as i32 && c != '[' as i32 && c != '#' as i32
                || flag & 0x100 as libc::c_int == 0 as libc::c_int)
            && *(*__ctype_b_loc()).offset(c as u_char as libc::c_int as isize) as libc::c_int
                & _ISgraph as libc::c_int as libc::c_ushort as libc::c_int
                != 0
            || flag & 0x4 as libc::c_int == 0 as libc::c_int && c == ' ' as i32
            || flag & 0x8 as libc::c_int == 0 as libc::c_int && c == '\t' as i32
            || flag & 0x10 as libc::c_int == 0 as libc::c_int && c == '\n' as i32
            || flag & 0x20 as libc::c_int != 0
                && (c == '\u{8}' as i32
                    || c == '\u{7}' as i32
                    || c == '\r' as i32
                    || *(*__ctype_b_loc()).offset(c as u_char as libc::c_int as isize)
                        as libc::c_int
                        & _ISgraph as libc::c_int as libc::c_ushort as libc::c_int
                        != 0))
    {
        if c == '"' as i32 && flag & 0x200 as libc::c_int != 0 as libc::c_int
            || c == '\\' as i32 && flag & 0x40 as libc::c_int == 0 as libc::c_int
        {
            let fresh0 = dst;
            dst = dst.offset(1);
            *fresh0 = '\\' as i32 as libc::c_char;
        }
        let fresh1 = dst;
        dst = dst.offset(1);
        *fresh1 = c as libc::c_char;
        *dst = '\0' as i32 as libc::c_char;
        return dst;
    }
    if flag & 0x2 as libc::c_int != 0 {
        match c {
            10 => {
                current_block = 1055447727977355648;
                match current_block {
                    1055447727977355648 => {
                        let fresh2 = dst;
                        dst = dst.offset(1);
                        *fresh2 = '\\' as i32 as libc::c_char;
                        let fresh3 = dst;
                        dst = dst.offset(1);
                        *fresh3 = 'n' as i32 as libc::c_char;
                    }
                    5980836898072119616 => {
                        let fresh16 = dst;
                        dst = dst.offset(1);
                        *fresh16 = '\\' as i32 as libc::c_char;
                        let fresh17 = dst;
                        dst = dst.offset(1);
                        *fresh17 = 's' as i32 as libc::c_char;
                    }
                    515494939214571372 => {
                        let fresh14 = dst;
                        dst = dst.offset(1);
                        *fresh14 = '\\' as i32 as libc::c_char;
                        let fresh15 = dst;
                        dst = dst.offset(1);
                        *fresh15 = 'f' as i32 as libc::c_char;
                    }
                    2537717513725769387 => {
                        let fresh12 = dst;
                        dst = dst.offset(1);
                        *fresh12 = '\\' as i32 as libc::c_char;
                        let fresh13 = dst;
                        dst = dst.offset(1);
                        *fresh13 = 't' as i32 as libc::c_char;
                    }
                    8830394740817982550 => {
                        let fresh10 = dst;
                        dst = dst.offset(1);
                        *fresh10 = '\\' as i32 as libc::c_char;
                        let fresh11 = dst;
                        dst = dst.offset(1);
                        *fresh11 = 'v' as i32 as libc::c_char;
                    }
                    17861474099278515877 => {
                        let fresh8 = dst;
                        dst = dst.offset(1);
                        *fresh8 = '\\' as i32 as libc::c_char;
                        let fresh9 = dst;
                        dst = dst.offset(1);
                        *fresh9 = 'a' as i32 as libc::c_char;
                    }
                    15122898966093540124 => {
                        let fresh6 = dst;
                        dst = dst.offset(1);
                        *fresh6 = '\\' as i32 as libc::c_char;
                        let fresh7 = dst;
                        dst = dst.offset(1);
                        *fresh7 = 'b' as i32 as libc::c_char;
                    }
                    16609396842949031630 => {
                        let fresh4 = dst;
                        dst = dst.offset(1);
                        *fresh4 = '\\' as i32 as libc::c_char;
                        let fresh5 = dst;
                        dst = dst.offset(1);
                        *fresh5 = 'r' as i32 as libc::c_char;
                    }
                    _ => {
                        let fresh18 = dst;
                        dst = dst.offset(1);
                        *fresh18 = '\\' as i32 as libc::c_char;
                        let fresh19 = dst;
                        dst = dst.offset(1);
                        *fresh19 = '0' as i32 as libc::c_char;
                        if nextc as u_char as libc::c_int >= '0' as i32
                            && nextc as u_char as libc::c_int <= '7' as i32
                        {
                            let fresh20 = dst;
                            dst = dst.offset(1);
                            *fresh20 = '0' as i32 as libc::c_char;
                            let fresh21 = dst;
                            dst = dst.offset(1);
                            *fresh21 = '0' as i32 as libc::c_char;
                        }
                    }
                }
                current_block = 7120606017689137369;
            }
            13 => {
                current_block = 16609396842949031630;
                match current_block {
                    1055447727977355648 => {
                        let fresh2 = dst;
                        dst = dst.offset(1);
                        *fresh2 = '\\' as i32 as libc::c_char;
                        let fresh3 = dst;
                        dst = dst.offset(1);
                        *fresh3 = 'n' as i32 as libc::c_char;
                    }
                    5980836898072119616 => {
                        let fresh16 = dst;
                        dst = dst.offset(1);
                        *fresh16 = '\\' as i32 as libc::c_char;
                        let fresh17 = dst;
                        dst = dst.offset(1);
                        *fresh17 = 's' as i32 as libc::c_char;
                    }
                    515494939214571372 => {
                        let fresh14 = dst;
                        dst = dst.offset(1);
                        *fresh14 = '\\' as i32 as libc::c_char;
                        let fresh15 = dst;
                        dst = dst.offset(1);
                        *fresh15 = 'f' as i32 as libc::c_char;
                    }
                    2537717513725769387 => {
                        let fresh12 = dst;
                        dst = dst.offset(1);
                        *fresh12 = '\\' as i32 as libc::c_char;
                        let fresh13 = dst;
                        dst = dst.offset(1);
                        *fresh13 = 't' as i32 as libc::c_char;
                    }
                    8830394740817982550 => {
                        let fresh10 = dst;
                        dst = dst.offset(1);
                        *fresh10 = '\\' as i32 as libc::c_char;
                        let fresh11 = dst;
                        dst = dst.offset(1);
                        *fresh11 = 'v' as i32 as libc::c_char;
                    }
                    17861474099278515877 => {
                        let fresh8 = dst;
                        dst = dst.offset(1);
                        *fresh8 = '\\' as i32 as libc::c_char;
                        let fresh9 = dst;
                        dst = dst.offset(1);
                        *fresh9 = 'a' as i32 as libc::c_char;
                    }
                    15122898966093540124 => {
                        let fresh6 = dst;
                        dst = dst.offset(1);
                        *fresh6 = '\\' as i32 as libc::c_char;
                        let fresh7 = dst;
                        dst = dst.offset(1);
                        *fresh7 = 'b' as i32 as libc::c_char;
                    }
                    16609396842949031630 => {
                        let fresh4 = dst;
                        dst = dst.offset(1);
                        *fresh4 = '\\' as i32 as libc::c_char;
                        let fresh5 = dst;
                        dst = dst.offset(1);
                        *fresh5 = 'r' as i32 as libc::c_char;
                    }
                    _ => {
                        let fresh18 = dst;
                        dst = dst.offset(1);
                        *fresh18 = '\\' as i32 as libc::c_char;
                        let fresh19 = dst;
                        dst = dst.offset(1);
                        *fresh19 = '0' as i32 as libc::c_char;
                        if nextc as u_char as libc::c_int >= '0' as i32
                            && nextc as u_char as libc::c_int <= '7' as i32
                        {
                            let fresh20 = dst;
                            dst = dst.offset(1);
                            *fresh20 = '0' as i32 as libc::c_char;
                            let fresh21 = dst;
                            dst = dst.offset(1);
                            *fresh21 = '0' as i32 as libc::c_char;
                        }
                    }
                }
                current_block = 7120606017689137369;
            }
            8 => {
                current_block = 15122898966093540124;
                match current_block {
                    1055447727977355648 => {
                        let fresh2 = dst;
                        dst = dst.offset(1);
                        *fresh2 = '\\' as i32 as libc::c_char;
                        let fresh3 = dst;
                        dst = dst.offset(1);
                        *fresh3 = 'n' as i32 as libc::c_char;
                    }
                    5980836898072119616 => {
                        let fresh16 = dst;
                        dst = dst.offset(1);
                        *fresh16 = '\\' as i32 as libc::c_char;
                        let fresh17 = dst;
                        dst = dst.offset(1);
                        *fresh17 = 's' as i32 as libc::c_char;
                    }
                    515494939214571372 => {
                        let fresh14 = dst;
                        dst = dst.offset(1);
                        *fresh14 = '\\' as i32 as libc::c_char;
                        let fresh15 = dst;
                        dst = dst.offset(1);
                        *fresh15 = 'f' as i32 as libc::c_char;
                    }
                    2537717513725769387 => {
                        let fresh12 = dst;
                        dst = dst.offset(1);
                        *fresh12 = '\\' as i32 as libc::c_char;
                        let fresh13 = dst;
                        dst = dst.offset(1);
                        *fresh13 = 't' as i32 as libc::c_char;
                    }
                    8830394740817982550 => {
                        let fresh10 = dst;
                        dst = dst.offset(1);
                        *fresh10 = '\\' as i32 as libc::c_char;
                        let fresh11 = dst;
                        dst = dst.offset(1);
                        *fresh11 = 'v' as i32 as libc::c_char;
                    }
                    17861474099278515877 => {
                        let fresh8 = dst;
                        dst = dst.offset(1);
                        *fresh8 = '\\' as i32 as libc::c_char;
                        let fresh9 = dst;
                        dst = dst.offset(1);
                        *fresh9 = 'a' as i32 as libc::c_char;
                    }
                    15122898966093540124 => {
                        let fresh6 = dst;
                        dst = dst.offset(1);
                        *fresh6 = '\\' as i32 as libc::c_char;
                        let fresh7 = dst;
                        dst = dst.offset(1);
                        *fresh7 = 'b' as i32 as libc::c_char;
                    }
                    16609396842949031630 => {
                        let fresh4 = dst;
                        dst = dst.offset(1);
                        *fresh4 = '\\' as i32 as libc::c_char;
                        let fresh5 = dst;
                        dst = dst.offset(1);
                        *fresh5 = 'r' as i32 as libc::c_char;
                    }
                    _ => {
                        let fresh18 = dst;
                        dst = dst.offset(1);
                        *fresh18 = '\\' as i32 as libc::c_char;
                        let fresh19 = dst;
                        dst = dst.offset(1);
                        *fresh19 = '0' as i32 as libc::c_char;
                        if nextc as u_char as libc::c_int >= '0' as i32
                            && nextc as u_char as libc::c_int <= '7' as i32
                        {
                            let fresh20 = dst;
                            dst = dst.offset(1);
                            *fresh20 = '0' as i32 as libc::c_char;
                            let fresh21 = dst;
                            dst = dst.offset(1);
                            *fresh21 = '0' as i32 as libc::c_char;
                        }
                    }
                }
                current_block = 7120606017689137369;
            }
            7 => {
                current_block = 17861474099278515877;
                match current_block {
                    1055447727977355648 => {
                        let fresh2 = dst;
                        dst = dst.offset(1);
                        *fresh2 = '\\' as i32 as libc::c_char;
                        let fresh3 = dst;
                        dst = dst.offset(1);
                        *fresh3 = 'n' as i32 as libc::c_char;
                    }
                    5980836898072119616 => {
                        let fresh16 = dst;
                        dst = dst.offset(1);
                        *fresh16 = '\\' as i32 as libc::c_char;
                        let fresh17 = dst;
                        dst = dst.offset(1);
                        *fresh17 = 's' as i32 as libc::c_char;
                    }
                    515494939214571372 => {
                        let fresh14 = dst;
                        dst = dst.offset(1);
                        *fresh14 = '\\' as i32 as libc::c_char;
                        let fresh15 = dst;
                        dst = dst.offset(1);
                        *fresh15 = 'f' as i32 as libc::c_char;
                    }
                    2537717513725769387 => {
                        let fresh12 = dst;
                        dst = dst.offset(1);
                        *fresh12 = '\\' as i32 as libc::c_char;
                        let fresh13 = dst;
                        dst = dst.offset(1);
                        *fresh13 = 't' as i32 as libc::c_char;
                    }
                    8830394740817982550 => {
                        let fresh10 = dst;
                        dst = dst.offset(1);
                        *fresh10 = '\\' as i32 as libc::c_char;
                        let fresh11 = dst;
                        dst = dst.offset(1);
                        *fresh11 = 'v' as i32 as libc::c_char;
                    }
                    17861474099278515877 => {
                        let fresh8 = dst;
                        dst = dst.offset(1);
                        *fresh8 = '\\' as i32 as libc::c_char;
                        let fresh9 = dst;
                        dst = dst.offset(1);
                        *fresh9 = 'a' as i32 as libc::c_char;
                    }
                    15122898966093540124 => {
                        let fresh6 = dst;
                        dst = dst.offset(1);
                        *fresh6 = '\\' as i32 as libc::c_char;
                        let fresh7 = dst;
                        dst = dst.offset(1);
                        *fresh7 = 'b' as i32 as libc::c_char;
                    }
                    16609396842949031630 => {
                        let fresh4 = dst;
                        dst = dst.offset(1);
                        *fresh4 = '\\' as i32 as libc::c_char;
                        let fresh5 = dst;
                        dst = dst.offset(1);
                        *fresh5 = 'r' as i32 as libc::c_char;
                    }
                    _ => {
                        let fresh18 = dst;
                        dst = dst.offset(1);
                        *fresh18 = '\\' as i32 as libc::c_char;
                        let fresh19 = dst;
                        dst = dst.offset(1);
                        *fresh19 = '0' as i32 as libc::c_char;
                        if nextc as u_char as libc::c_int >= '0' as i32
                            && nextc as u_char as libc::c_int <= '7' as i32
                        {
                            let fresh20 = dst;
                            dst = dst.offset(1);
                            *fresh20 = '0' as i32 as libc::c_char;
                            let fresh21 = dst;
                            dst = dst.offset(1);
                            *fresh21 = '0' as i32 as libc::c_char;
                        }
                    }
                }
                current_block = 7120606017689137369;
            }
            11 => {
                current_block = 8830394740817982550;
                match current_block {
                    1055447727977355648 => {
                        let fresh2 = dst;
                        dst = dst.offset(1);
                        *fresh2 = '\\' as i32 as libc::c_char;
                        let fresh3 = dst;
                        dst = dst.offset(1);
                        *fresh3 = 'n' as i32 as libc::c_char;
                    }
                    5980836898072119616 => {
                        let fresh16 = dst;
                        dst = dst.offset(1);
                        *fresh16 = '\\' as i32 as libc::c_char;
                        let fresh17 = dst;
                        dst = dst.offset(1);
                        *fresh17 = 's' as i32 as libc::c_char;
                    }
                    515494939214571372 => {
                        let fresh14 = dst;
                        dst = dst.offset(1);
                        *fresh14 = '\\' as i32 as libc::c_char;
                        let fresh15 = dst;
                        dst = dst.offset(1);
                        *fresh15 = 'f' as i32 as libc::c_char;
                    }
                    2537717513725769387 => {
                        let fresh12 = dst;
                        dst = dst.offset(1);
                        *fresh12 = '\\' as i32 as libc::c_char;
                        let fresh13 = dst;
                        dst = dst.offset(1);
                        *fresh13 = 't' as i32 as libc::c_char;
                    }
                    8830394740817982550 => {
                        let fresh10 = dst;
                        dst = dst.offset(1);
                        *fresh10 = '\\' as i32 as libc::c_char;
                        let fresh11 = dst;
                        dst = dst.offset(1);
                        *fresh11 = 'v' as i32 as libc::c_char;
                    }
                    17861474099278515877 => {
                        let fresh8 = dst;
                        dst = dst.offset(1);
                        *fresh8 = '\\' as i32 as libc::c_char;
                        let fresh9 = dst;
                        dst = dst.offset(1);
                        *fresh9 = 'a' as i32 as libc::c_char;
                    }
                    15122898966093540124 => {
                        let fresh6 = dst;
                        dst = dst.offset(1);
                        *fresh6 = '\\' as i32 as libc::c_char;
                        let fresh7 = dst;
                        dst = dst.offset(1);
                        *fresh7 = 'b' as i32 as libc::c_char;
                    }
                    16609396842949031630 => {
                        let fresh4 = dst;
                        dst = dst.offset(1);
                        *fresh4 = '\\' as i32 as libc::c_char;
                        let fresh5 = dst;
                        dst = dst.offset(1);
                        *fresh5 = 'r' as i32 as libc::c_char;
                    }
                    _ => {
                        let fresh18 = dst;
                        dst = dst.offset(1);
                        *fresh18 = '\\' as i32 as libc::c_char;
                        let fresh19 = dst;
                        dst = dst.offset(1);
                        *fresh19 = '0' as i32 as libc::c_char;
                        if nextc as u_char as libc::c_int >= '0' as i32
                            && nextc as u_char as libc::c_int <= '7' as i32
                        {
                            let fresh20 = dst;
                            dst = dst.offset(1);
                            *fresh20 = '0' as i32 as libc::c_char;
                            let fresh21 = dst;
                            dst = dst.offset(1);
                            *fresh21 = '0' as i32 as libc::c_char;
                        }
                    }
                }
                current_block = 7120606017689137369;
            }
            9 => {
                current_block = 2537717513725769387;
                match current_block {
                    1055447727977355648 => {
                        let fresh2 = dst;
                        dst = dst.offset(1);
                        *fresh2 = '\\' as i32 as libc::c_char;
                        let fresh3 = dst;
                        dst = dst.offset(1);
                        *fresh3 = 'n' as i32 as libc::c_char;
                    }
                    5980836898072119616 => {
                        let fresh16 = dst;
                        dst = dst.offset(1);
                        *fresh16 = '\\' as i32 as libc::c_char;
                        let fresh17 = dst;
                        dst = dst.offset(1);
                        *fresh17 = 's' as i32 as libc::c_char;
                    }
                    515494939214571372 => {
                        let fresh14 = dst;
                        dst = dst.offset(1);
                        *fresh14 = '\\' as i32 as libc::c_char;
                        let fresh15 = dst;
                        dst = dst.offset(1);
                        *fresh15 = 'f' as i32 as libc::c_char;
                    }
                    2537717513725769387 => {
                        let fresh12 = dst;
                        dst = dst.offset(1);
                        *fresh12 = '\\' as i32 as libc::c_char;
                        let fresh13 = dst;
                        dst = dst.offset(1);
                        *fresh13 = 't' as i32 as libc::c_char;
                    }
                    8830394740817982550 => {
                        let fresh10 = dst;
                        dst = dst.offset(1);
                        *fresh10 = '\\' as i32 as libc::c_char;
                        let fresh11 = dst;
                        dst = dst.offset(1);
                        *fresh11 = 'v' as i32 as libc::c_char;
                    }
                    17861474099278515877 => {
                        let fresh8 = dst;
                        dst = dst.offset(1);
                        *fresh8 = '\\' as i32 as libc::c_char;
                        let fresh9 = dst;
                        dst = dst.offset(1);
                        *fresh9 = 'a' as i32 as libc::c_char;
                    }
                    15122898966093540124 => {
                        let fresh6 = dst;
                        dst = dst.offset(1);
                        *fresh6 = '\\' as i32 as libc::c_char;
                        let fresh7 = dst;
                        dst = dst.offset(1);
                        *fresh7 = 'b' as i32 as libc::c_char;
                    }
                    16609396842949031630 => {
                        let fresh4 = dst;
                        dst = dst.offset(1);
                        *fresh4 = '\\' as i32 as libc::c_char;
                        let fresh5 = dst;
                        dst = dst.offset(1);
                        *fresh5 = 'r' as i32 as libc::c_char;
                    }
                    _ => {
                        let fresh18 = dst;
                        dst = dst.offset(1);
                        *fresh18 = '\\' as i32 as libc::c_char;
                        let fresh19 = dst;
                        dst = dst.offset(1);
                        *fresh19 = '0' as i32 as libc::c_char;
                        if nextc as u_char as libc::c_int >= '0' as i32
                            && nextc as u_char as libc::c_int <= '7' as i32
                        {
                            let fresh20 = dst;
                            dst = dst.offset(1);
                            *fresh20 = '0' as i32 as libc::c_char;
                            let fresh21 = dst;
                            dst = dst.offset(1);
                            *fresh21 = '0' as i32 as libc::c_char;
                        }
                    }
                }
                current_block = 7120606017689137369;
            }
            12 => {
                current_block = 515494939214571372;
                match current_block {
                    1055447727977355648 => {
                        let fresh2 = dst;
                        dst = dst.offset(1);
                        *fresh2 = '\\' as i32 as libc::c_char;
                        let fresh3 = dst;
                        dst = dst.offset(1);
                        *fresh3 = 'n' as i32 as libc::c_char;
                    }
                    5980836898072119616 => {
                        let fresh16 = dst;
                        dst = dst.offset(1);
                        *fresh16 = '\\' as i32 as libc::c_char;
                        let fresh17 = dst;
                        dst = dst.offset(1);
                        *fresh17 = 's' as i32 as libc::c_char;
                    }
                    515494939214571372 => {
                        let fresh14 = dst;
                        dst = dst.offset(1);
                        *fresh14 = '\\' as i32 as libc::c_char;
                        let fresh15 = dst;
                        dst = dst.offset(1);
                        *fresh15 = 'f' as i32 as libc::c_char;
                    }
                    2537717513725769387 => {
                        let fresh12 = dst;
                        dst = dst.offset(1);
                        *fresh12 = '\\' as i32 as libc::c_char;
                        let fresh13 = dst;
                        dst = dst.offset(1);
                        *fresh13 = 't' as i32 as libc::c_char;
                    }
                    8830394740817982550 => {
                        let fresh10 = dst;
                        dst = dst.offset(1);
                        *fresh10 = '\\' as i32 as libc::c_char;
                        let fresh11 = dst;
                        dst = dst.offset(1);
                        *fresh11 = 'v' as i32 as libc::c_char;
                    }
                    17861474099278515877 => {
                        let fresh8 = dst;
                        dst = dst.offset(1);
                        *fresh8 = '\\' as i32 as libc::c_char;
                        let fresh9 = dst;
                        dst = dst.offset(1);
                        *fresh9 = 'a' as i32 as libc::c_char;
                    }
                    15122898966093540124 => {
                        let fresh6 = dst;
                        dst = dst.offset(1);
                        *fresh6 = '\\' as i32 as libc::c_char;
                        let fresh7 = dst;
                        dst = dst.offset(1);
                        *fresh7 = 'b' as i32 as libc::c_char;
                    }
                    16609396842949031630 => {
                        let fresh4 = dst;
                        dst = dst.offset(1);
                        *fresh4 = '\\' as i32 as libc::c_char;
                        let fresh5 = dst;
                        dst = dst.offset(1);
                        *fresh5 = 'r' as i32 as libc::c_char;
                    }
                    _ => {
                        let fresh18 = dst;
                        dst = dst.offset(1);
                        *fresh18 = '\\' as i32 as libc::c_char;
                        let fresh19 = dst;
                        dst = dst.offset(1);
                        *fresh19 = '0' as i32 as libc::c_char;
                        if nextc as u_char as libc::c_int >= '0' as i32
                            && nextc as u_char as libc::c_int <= '7' as i32
                        {
                            let fresh20 = dst;
                            dst = dst.offset(1);
                            *fresh20 = '0' as i32 as libc::c_char;
                            let fresh21 = dst;
                            dst = dst.offset(1);
                            *fresh21 = '0' as i32 as libc::c_char;
                        }
                    }
                }
                current_block = 7120606017689137369;
            }
            32 => {
                current_block = 5980836898072119616;
                match current_block {
                    1055447727977355648 => {
                        let fresh2 = dst;
                        dst = dst.offset(1);
                        *fresh2 = '\\' as i32 as libc::c_char;
                        let fresh3 = dst;
                        dst = dst.offset(1);
                        *fresh3 = 'n' as i32 as libc::c_char;
                    }
                    5980836898072119616 => {
                        let fresh16 = dst;
                        dst = dst.offset(1);
                        *fresh16 = '\\' as i32 as libc::c_char;
                        let fresh17 = dst;
                        dst = dst.offset(1);
                        *fresh17 = 's' as i32 as libc::c_char;
                    }
                    515494939214571372 => {
                        let fresh14 = dst;
                        dst = dst.offset(1);
                        *fresh14 = '\\' as i32 as libc::c_char;
                        let fresh15 = dst;
                        dst = dst.offset(1);
                        *fresh15 = 'f' as i32 as libc::c_char;
                    }
                    2537717513725769387 => {
                        let fresh12 = dst;
                        dst = dst.offset(1);
                        *fresh12 = '\\' as i32 as libc::c_char;
                        let fresh13 = dst;
                        dst = dst.offset(1);
                        *fresh13 = 't' as i32 as libc::c_char;
                    }
                    8830394740817982550 => {
                        let fresh10 = dst;
                        dst = dst.offset(1);
                        *fresh10 = '\\' as i32 as libc::c_char;
                        let fresh11 = dst;
                        dst = dst.offset(1);
                        *fresh11 = 'v' as i32 as libc::c_char;
                    }
                    17861474099278515877 => {
                        let fresh8 = dst;
                        dst = dst.offset(1);
                        *fresh8 = '\\' as i32 as libc::c_char;
                        let fresh9 = dst;
                        dst = dst.offset(1);
                        *fresh9 = 'a' as i32 as libc::c_char;
                    }
                    15122898966093540124 => {
                        let fresh6 = dst;
                        dst = dst.offset(1);
                        *fresh6 = '\\' as i32 as libc::c_char;
                        let fresh7 = dst;
                        dst = dst.offset(1);
                        *fresh7 = 'b' as i32 as libc::c_char;
                    }
                    16609396842949031630 => {
                        let fresh4 = dst;
                        dst = dst.offset(1);
                        *fresh4 = '\\' as i32 as libc::c_char;
                        let fresh5 = dst;
                        dst = dst.offset(1);
                        *fresh5 = 'r' as i32 as libc::c_char;
                    }
                    _ => {
                        let fresh18 = dst;
                        dst = dst.offset(1);
                        *fresh18 = '\\' as i32 as libc::c_char;
                        let fresh19 = dst;
                        dst = dst.offset(1);
                        *fresh19 = '0' as i32 as libc::c_char;
                        if nextc as u_char as libc::c_int >= '0' as i32
                            && nextc as u_char as libc::c_int <= '7' as i32
                        {
                            let fresh20 = dst;
                            dst = dst.offset(1);
                            *fresh20 = '0' as i32 as libc::c_char;
                            let fresh21 = dst;
                            dst = dst.offset(1);
                            *fresh21 = '0' as i32 as libc::c_char;
                        }
                    }
                }
                current_block = 7120606017689137369;
            }
            0 => {
                current_block = 11854332676852958198;
                match current_block {
                    1055447727977355648 => {
                        let fresh2 = dst;
                        dst = dst.offset(1);
                        *fresh2 = '\\' as i32 as libc::c_char;
                        let fresh3 = dst;
                        dst = dst.offset(1);
                        *fresh3 = 'n' as i32 as libc::c_char;
                    }
                    5980836898072119616 => {
                        let fresh16 = dst;
                        dst = dst.offset(1);
                        *fresh16 = '\\' as i32 as libc::c_char;
                        let fresh17 = dst;
                        dst = dst.offset(1);
                        *fresh17 = 's' as i32 as libc::c_char;
                    }
                    515494939214571372 => {
                        let fresh14 = dst;
                        dst = dst.offset(1);
                        *fresh14 = '\\' as i32 as libc::c_char;
                        let fresh15 = dst;
                        dst = dst.offset(1);
                        *fresh15 = 'f' as i32 as libc::c_char;
                    }
                    2537717513725769387 => {
                        let fresh12 = dst;
                        dst = dst.offset(1);
                        *fresh12 = '\\' as i32 as libc::c_char;
                        let fresh13 = dst;
                        dst = dst.offset(1);
                        *fresh13 = 't' as i32 as libc::c_char;
                    }
                    8830394740817982550 => {
                        let fresh10 = dst;
                        dst = dst.offset(1);
                        *fresh10 = '\\' as i32 as libc::c_char;
                        let fresh11 = dst;
                        dst = dst.offset(1);
                        *fresh11 = 'v' as i32 as libc::c_char;
                    }
                    17861474099278515877 => {
                        let fresh8 = dst;
                        dst = dst.offset(1);
                        *fresh8 = '\\' as i32 as libc::c_char;
                        let fresh9 = dst;
                        dst = dst.offset(1);
                        *fresh9 = 'a' as i32 as libc::c_char;
                    }
                    15122898966093540124 => {
                        let fresh6 = dst;
                        dst = dst.offset(1);
                        *fresh6 = '\\' as i32 as libc::c_char;
                        let fresh7 = dst;
                        dst = dst.offset(1);
                        *fresh7 = 'b' as i32 as libc::c_char;
                    }
                    16609396842949031630 => {
                        let fresh4 = dst;
                        dst = dst.offset(1);
                        *fresh4 = '\\' as i32 as libc::c_char;
                        let fresh5 = dst;
                        dst = dst.offset(1);
                        *fresh5 = 'r' as i32 as libc::c_char;
                    }
                    _ => {
                        let fresh18 = dst;
                        dst = dst.offset(1);
                        *fresh18 = '\\' as i32 as libc::c_char;
                        let fresh19 = dst;
                        dst = dst.offset(1);
                        *fresh19 = '0' as i32 as libc::c_char;
                        if nextc as u_char as libc::c_int >= '0' as i32
                            && nextc as u_char as libc::c_int <= '7' as i32
                        {
                            let fresh20 = dst;
                            dst = dst.offset(1);
                            *fresh20 = '0' as i32 as libc::c_char;
                            let fresh21 = dst;
                            dst = dst.offset(1);
                            *fresh21 = '0' as i32 as libc::c_char;
                        }
                    }
                }
                current_block = 7120606017689137369;
            }
            _ => {
                current_block = 15345278821338558188;
            }
        }
    } else {
        current_block = 15345278821338558188;
    }
    match current_block {
        15345278821338558188 => {
            if c & 0o177 as libc::c_int == ' ' as i32
                || flag & 0x1 as libc::c_int != 0
                || flag & 0x100 as libc::c_int != 0
                    && (c == '*' as i32 || c == '?' as i32 || c == '[' as i32 || c == '#' as i32)
            {
                let fresh22 = dst;
                dst = dst.offset(1);
                *fresh22 = '\\' as i32 as libc::c_char;
                let fresh23 = dst;
                dst = dst.offset(1);
                *fresh23 = ((c as u_char as libc::c_int >> 6 as libc::c_int & 0o7 as libc::c_int)
                    + '0' as i32) as libc::c_char;
                let fresh24 = dst;
                dst = dst.offset(1);
                *fresh24 = ((c as u_char as libc::c_int >> 3 as libc::c_int & 0o7 as libc::c_int)
                    + '0' as i32) as libc::c_char;
                let fresh25 = dst;
                dst = dst.offset(1);
                *fresh25 = ((c as u_char as libc::c_int & 0o7 as libc::c_int) + '0' as i32)
                    as libc::c_char;
            } else {
                if flag & 0x40 as libc::c_int == 0 as libc::c_int {
                    let fresh26 = dst;
                    dst = dst.offset(1);
                    *fresh26 = '\\' as i32 as libc::c_char;
                }
                if c & 0o200 as libc::c_int != 0 {
                    c &= 0o177 as libc::c_int;
                    let fresh27 = dst;
                    dst = dst.offset(1);
                    *fresh27 = 'M' as i32 as libc::c_char;
                }
                if *(*__ctype_b_loc()).offset(c as u_char as libc::c_int as isize) as libc::c_int
                    & _IScntrl as libc::c_int as libc::c_ushort as libc::c_int
                    != 0
                {
                    let fresh28 = dst;
                    dst = dst.offset(1);
                    *fresh28 = '^' as i32 as libc::c_char;
                    if c == 0o177 as libc::c_int {
                        let fresh29 = dst;
                        dst = dst.offset(1);
                        *fresh29 = '?' as i32 as libc::c_char;
                    } else {
                        let fresh30 = dst;
                        dst = dst.offset(1);
                        *fresh30 = (c + '@' as i32) as libc::c_char;
                    }
                } else {
                    let fresh31 = dst;
                    dst = dst.offset(1);
                    *fresh31 = '-' as i32 as libc::c_char;
                    let fresh32 = dst;
                    dst = dst.offset(1);
                    *fresh32 = c as libc::c_char;
                }
            }
        }
        _ => {}
    }
    *dst = '\0' as i32 as libc::c_char;
    return dst;
}
#[no_mangle]
pub unsafe extern "C" fn strvis(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut flag: libc::c_int,
) -> libc::c_int {
    let mut c: libc::c_char = 0;
    let mut start: *mut libc::c_char = 0 as *mut libc::c_char;
    start = dst;
    loop {
        c = *src;
        if !(c != 0) {
            break;
        }
        src = src.offset(1);
        dst = vis(dst, c as libc::c_int, flag, *src as libc::c_int);
    }
    *dst = '\0' as i32 as libc::c_char;
    return dst.offset_from(start) as libc::c_long as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn strnvis(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut siz: size_t,
    mut flag: libc::c_int,
) -> libc::c_int {
    let mut start: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut end: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tbuf: [libc::c_char; 5] = [0; 5];
    let mut c: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    start = dst;
    end = start
        .offset(siz as isize)
        .offset(-(1 as libc::c_int as isize));
    loop {
        c = *src as libc::c_int;
        if !(c != 0 && dst < end) {
            break;
        }
        if (c == '\\' as i32 || flag & 0x400 as libc::c_int == 0 as libc::c_int)
            && (c as u_int
                <= (127 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as libc::c_uint
                && c as u_char as libc::c_int & !(0x7f as libc::c_int) == 0 as libc::c_int
                && (c != '*' as i32 && c != '?' as i32 && c != '[' as i32 && c != '#' as i32
                    || flag & 0x100 as libc::c_int == 0 as libc::c_int)
                && *(*__ctype_b_loc()).offset(c as u_char as libc::c_int as isize) as libc::c_int
                    & _ISgraph as libc::c_int as libc::c_ushort as libc::c_int
                    != 0
                || flag & 0x4 as libc::c_int == 0 as libc::c_int && c == ' ' as i32
                || flag & 0x8 as libc::c_int == 0 as libc::c_int && c == '\t' as i32
                || flag & 0x10 as libc::c_int == 0 as libc::c_int && c == '\n' as i32
                || flag & 0x20 as libc::c_int != 0
                    && (c == '\u{8}' as i32
                        || c == '\u{7}' as i32
                        || c == '\r' as i32
                        || *(*__ctype_b_loc()).offset(c as u_char as libc::c_int as isize)
                            as libc::c_int
                            & _ISgraph as libc::c_int as libc::c_ushort as libc::c_int
                            != 0))
        {
            if c == '"' as i32 && flag & 0x200 as libc::c_int != 0 as libc::c_int
                || c == '\\' as i32 && flag & 0x40 as libc::c_int == 0 as libc::c_int
            {
                if dst.offset(1 as libc::c_int as isize) >= end {
                    i = 2 as libc::c_int;
                    break;
                } else {
                    let fresh33 = dst;
                    dst = dst.offset(1);
                    *fresh33 = '\\' as i32 as libc::c_char;
                }
            }
            i = 1 as libc::c_int;
            let fresh34 = dst;
            dst = dst.offset(1);
            *fresh34 = c as libc::c_char;
            src = src.offset(1);
            src;
        } else {
            src = src.offset(1);
            i = (vis(tbuf.as_mut_ptr(), c, flag, *src as libc::c_int))
                .offset_from(tbuf.as_mut_ptr()) as libc::c_long as libc::c_int;
            if dst.offset(i as isize) <= end {
                memcpy(
                    dst as *mut libc::c_void,
                    tbuf.as_mut_ptr() as *const libc::c_void,
                    i as libc::c_ulong,
                );
                dst = dst.offset(i as isize);
            } else {
                src = src.offset(-1);
                src;
                break;
            }
        }
    }
    if siz > 0 as libc::c_int as libc::c_ulong {
        *dst = '\0' as i32 as libc::c_char;
    }
    if dst.offset(i as isize) > end {
        loop {
            c = *src as libc::c_int;
            if !(c != 0) {
                break;
            }
            src = src.offset(1);
            dst = dst.offset(
                (vis(tbuf.as_mut_ptr(), c, flag, *src as libc::c_int))
                    .offset_from(tbuf.as_mut_ptr()) as libc::c_long as isize,
            );
        }
    }
    return dst.offset_from(start) as libc::c_long as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn stravis(
    mut outp: *mut *mut libc::c_char,
    mut src: *const libc::c_char,
    mut flag: libc::c_int,
) -> libc::c_int {
    let mut buf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: libc::c_int = 0;
    let mut serrno: libc::c_int = 0;
    buf = reallocarray(
        0 as *mut libc::c_void,
        4 as libc::c_int as size_t,
        (strlen(src)).wrapping_add(1 as libc::c_int as libc::c_ulong),
    ) as *mut libc::c_char;
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    len = strvis(buf, src, flag);
    serrno = *__errno_location();
    *outp = realloc(
        buf as *mut libc::c_void,
        (len + 1 as libc::c_int) as libc::c_ulong,
    ) as *mut libc::c_char;
    if (*outp).is_null() {
        *outp = buf;
        *__errno_location() = serrno;
    }
    return len;
}
#[no_mangle]
pub unsafe extern "C" fn strvisx(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut len: size_t,
    mut flag: libc::c_int,
) -> libc::c_int {
    let mut c: libc::c_char = 0;
    let mut start: *mut libc::c_char = 0 as *mut libc::c_char;
    start = dst;
    while len > 1 as libc::c_int as libc::c_ulong {
        c = *src;
        src = src.offset(1);
        dst = vis(dst, c as libc::c_int, flag, *src as libc::c_int);
        len = len.wrapping_sub(1);
        len;
    }
    if len != 0 {
        dst = vis(dst, *src as libc::c_int, flag, '\0' as i32);
    }
    *dst = '\0' as i32 as libc::c_char;
    return dst.offset_from(start) as libc::c_long as libc::c_int;
}
