use ::libc;
extern "C" {
    fn _exit(_: libc::c_int) -> !;
}
pub unsafe extern "C" fn cleanup_exit(mut i: libc::c_int) -> ! {
    _exit(i);
}
