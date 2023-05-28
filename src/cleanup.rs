use ::libc;
extern "C" {}
pub unsafe extern "C" fn cleanup_exit(mut i: libc::c_int) -> ! {
    libc::_exit(i);
}
