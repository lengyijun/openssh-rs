use ::libc;
extern "C" {
    fn free(_: *mut libc::c_void);
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
}
pub type size_t = libc::c_ulong;
#[no_mangle]
pub unsafe extern "C" fn freezero(mut ptr: *mut libc::c_void, mut sz: size_t) {
    if ptr.is_null() {
        return;
    }
    explicit_bzero(ptr, sz);
    free(ptr);
}
