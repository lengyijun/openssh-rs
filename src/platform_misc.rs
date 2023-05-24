use ::libc;
pub type __uid_t = libc::c_uint;
pub type uid_t = __uid_t;
pub unsafe extern "C" fn platform_sys_dir_uid(mut uid: uid_t) -> libc::c_int {
    if uid == 0 as libc::c_int as libc::c_uint {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
