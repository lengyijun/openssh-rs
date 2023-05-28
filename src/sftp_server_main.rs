use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    
    
    static mut stderr: *mut libc::FILE;

    fn sftp_server_main(_: libc::c_int, _: *mut *mut libc::c_char, _: *mut libc::passwd) -> libc::c_int;
    fn sftp_server_cleanup_exit(_: libc::c_int) -> !;

}
pub type __u_long = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type u_long = __u_long;
pub type size_t = libc::c_ulong;


pub type _IO_lock_t = ();

pub unsafe extern "C" fn cleanup_exit(mut i: libc::c_int) -> ! {
    sftp_server_cleanup_exit(i);
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char) -> libc::c_int {
    let mut user_pw: *mut libc::passwd = 0 as *mut libc::passwd;
    crate::misc::sanitise_stdfd();
    user_pw = libc::getpwuid(libc::getuid());
    if user_pw.is_null() {
        libc::fprintf(
            stderr,
            b"No user found for uid %lu\n\0" as *const u8 as *const libc::c_char,
            libc::getuid() as u_long,
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
