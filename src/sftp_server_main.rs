use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn getuid() -> __uid_t;
    fn getpwuid(__uid: __uid_t) -> *mut passwd;
    static mut stderr: *mut libc::FILE;
    fn fprintf(_: *mut libc::FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn sftp_server_main(_: libc::c_int, _: *mut *mut libc::c_char, _: *mut passwd) -> libc::c_int;
    fn sftp_server_cleanup_exit(_: libc::c_int) -> !;

}
pub type __u_long = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type u_long = __u_long;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct passwd {
    pub pw_name: *mut libc::c_char,
    pub pw_passwd: *mut libc::c_char,
    pub pw_uid: __uid_t,
    pub pw_gid: __gid_t,
    pub pw_gecos: *mut libc::c_char,
    pub pw_dir: *mut libc::c_char,
    pub pw_shell: *mut libc::c_char,
}

pub type _IO_lock_t = ();

pub unsafe extern "C" fn cleanup_exit(mut i: libc::c_int) -> ! {
    sftp_server_cleanup_exit(i);
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char) -> libc::c_int {
    let mut user_pw: *mut passwd = 0 as *mut passwd;
    crate::misc::sanitise_stdfd();
    user_pw = getpwuid(getuid());
    if user_pw.is_null() {
        fprintf(
            stderr,
            b"No user found for uid %lu\n\0" as *const u8 as *const libc::c_char,
            getuid() as u_long,
        );
        return 1 as libc::c_int;
    }
    return sftp_server_main(argc, argv, user_pw);
}
pub fn main() {
    let mut args: Vec<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::core::ptr::null_mut());
    unsafe {
        ::std::process::exit(main_0(
            (args.len() - 1) as libc::c_int,
            args.as_mut_ptr() as *mut *mut libc::c_char,
        ) as i32)
    }
}
