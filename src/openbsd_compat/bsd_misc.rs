use ::libc;
extern "C" {
    fn perror(__s: *const libc::c_char);
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn exit(_: libc::c_int) -> !;
}
#[no_mangle]
pub unsafe extern "C" fn ssh_get_progname(mut _argv0: *mut libc::c_char) -> *mut libc::c_char {
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut q: *mut libc::c_char = 0 as *mut libc::c_char;
    extern "C" {
        static mut __progname: *mut libc::c_char;
    }
    p = __progname;
    q = strdup(p);
    if q.is_null() {
        perror(b"strdup\0" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    return q;
}
#[no_mangle]
pub unsafe extern "C" fn setlogin(mut _name: *const libc::c_char) -> libc::c_int {
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn pledge(
    mut _promises: *const libc::c_char,
    mut _paths: *mut *const libc::c_char,
) -> libc::c_int {
    return 0 as libc::c_int;
}
