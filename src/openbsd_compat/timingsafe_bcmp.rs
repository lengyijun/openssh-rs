use ::libc;
pub type size_t = libc::c_ulong;
#[no_mangle]
pub unsafe extern "C" fn timingsafe_bcmp(
    mut b1: *const libc::c_void,
    mut b2: *const libc::c_void,
    mut n: size_t,
) -> libc::c_int {
    let mut p1: *const libc::c_uchar = b1 as *const libc::c_uchar;
    let mut p2: *const libc::c_uchar = b2 as *const libc::c_uchar;
    let mut ret: libc::c_int = 0 as libc::c_int;
    while n > 0 as libc::c_int as libc::c_ulong {
        let fresh0 = p1;
        p1 = p1.offset(1);
        let fresh1 = p2;
        p2 = p2.offset(1);
        ret |= *fresh0 as libc::c_int ^ *fresh1 as libc::c_int;
        n = n.wrapping_sub(1);
        n;
    }
    return (ret != 0 as libc::c_int) as libc::c_int;
}
