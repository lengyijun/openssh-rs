use ::libc;
extern "C" {
    fn cleanup_exit(_: libc::c_int) -> !;

}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type va_list = __builtin_va_list;
pub type LogLevel = libc::c_int;
pub const SYSLOG_LEVEL_NOT_SET: LogLevel = -1;
pub const SYSLOG_LEVEL_DEBUG3: LogLevel = 7;
pub const SYSLOG_LEVEL_DEBUG2: LogLevel = 6;
pub const SYSLOG_LEVEL_DEBUG1: LogLevel = 5;
pub const SYSLOG_LEVEL_VERBOSE: LogLevel = 4;
pub const SYSLOG_LEVEL_INFO: LogLevel = 3;
pub const SYSLOG_LEVEL_ERROR: LogLevel = 2;
pub const SYSLOG_LEVEL_FATAL: LogLevel = 1;
pub const SYSLOG_LEVEL_QUIET: LogLevel = 0;
pub unsafe extern "C" fn sshfatal(
    mut file: *const libc::c_char,
    mut func: *const libc::c_char,
    mut line: libc::c_int,
    mut showfunc: libc::c_int,
    mut level: LogLevel,
    mut suffix: *const libc::c_char,
    mut fmt: *const libc::c_char,
    mut args: ...
) -> ! {
    let mut args_0: ::core::ffi::VaListImpl;
    args_0 = args.clone();
    crate::log::sshlogv(
        file,
        func,
        line,
        showfunc,
        level,
        suffix,
        fmt,
        args_0.as_va_list(),
    );
    cleanup_exit(255 as libc::c_int);
}
