use ::libc;

pub type __mode_t = libc::c_uint;
pub type mode_t = __mode_t;
#[no_mangle]
pub unsafe extern "C" fn _ssh_mkstemp(mut template: *mut libc::c_char) -> libc::c_int {
    let mut mask: mode_t = 0;
    let mut ret: libc::c_int = 0;
    mask = libc::umask(0o177 as libc::c_int as __mode_t);
    ret = libc::mkstemp(template);
    libc::umask(mask);
    return ret;
}
