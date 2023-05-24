use ::libc;
pub type size_t = libc::c_ulong;
#[no_mangle]
pub unsafe extern "C" fn seed_from_prngd(
    mut buf: *mut libc::c_uchar,
    mut bytes: size_t,
) -> libc::c_int {
    return -(1 as libc::c_int);
}
