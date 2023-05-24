use ::libc;
pub type size_t = libc::c_ulong;
#[no_mangle]
pub unsafe extern "C" fn strlcpy(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut siz: size_t,
) -> size_t {
    let mut d: *mut libc::c_char = dst;
    let mut s: *const libc::c_char = src;
    let mut n: size_t = siz;
    if n != 0 as libc::c_int as libc::c_ulong {
        loop {
            n = n.wrapping_sub(1);
            if !(n != 0 as libc::c_int as libc::c_ulong) {
                break;
            }
            let fresh0 = s;
            s = s.offset(1);
            let fresh1 = d;
            d = d.offset(1);
            *fresh1 = *fresh0;
            if *fresh1 as libc::c_int == '\0' as i32 {
                break;
            }
        }
    }
    if n == 0 as libc::c_int as libc::c_ulong {
        if siz != 0 as libc::c_int as libc::c_ulong {
            *d = '\0' as i32 as libc::c_char;
        }
        loop {
            let fresh2 = s;
            s = s.offset(1);
            if !(*fresh2 != 0) {
                break;
            }
        }
    }
    return (s.offset_from(src) as libc::c_long - 1 as libc::c_int as libc::c_long) as size_t;
}
