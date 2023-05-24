use ::libc;
extern "C" {
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
}
pub type size_t = libc::c_ulong;
#[no_mangle]
pub unsafe extern "C" fn strlcat(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut siz: size_t,
) -> size_t {
    let mut d: *mut libc::c_char = dst;
    let mut s: *const libc::c_char = src;
    let mut n: size_t = siz;
    let mut dlen: size_t = 0;
    loop {
        let fresh0 = n;
        n = n.wrapping_sub(1);
        if !(fresh0 != 0 as libc::c_int as libc::c_ulong && *d as libc::c_int != '\0' as i32) {
            break;
        }
        d = d.offset(1);
        d;
    }
    dlen = d.offset_from(dst) as libc::c_long as size_t;
    n = siz.wrapping_sub(dlen);
    if n == 0 as libc::c_int as libc::c_ulong {
        return dlen.wrapping_add(strlen(s));
    }
    while *s as libc::c_int != '\0' as i32 {
        if n != 1 as libc::c_int as libc::c_ulong {
            let fresh1 = d;
            d = d.offset(1);
            *fresh1 = *s;
            n = n.wrapping_sub(1);
            n;
        }
        s = s.offset(1);
        s;
    }
    *d = '\0' as i32 as libc::c_char;
    return dlen.wrapping_add(s.offset_from(src) as libc::c_long as libc::c_ulong);
}
