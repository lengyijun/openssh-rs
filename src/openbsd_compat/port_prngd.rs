use ::libc;
pub type size_t = libc::c_ulong;
#[no_mangle]
pub unsafe extern "C" fn seed_from_prngd(
    mut _buf: *mut libc::c_uchar,
    mut _bytes: size_t,
) -> libc::c_int {
    return -(1 as libc::c_int);
}
