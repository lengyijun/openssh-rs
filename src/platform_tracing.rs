use ::libc;
extern "C" {

    fn prctl(__option: libc::c_int, _: ...) -> libc::c_int;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn sshfatal(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: LogLevel,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: ...
    ) -> !;
}
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
pub unsafe extern "C" fn platform_disable_tracing(mut strict: libc::c_int) {
    if prctl(4 as libc::c_int, 0 as libc::c_int) != 0 as libc::c_int && strict != 0 {
        sshfatal(
            b"platform-tracing.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"platform_disable_tracing\0",
            ))
            .as_ptr(),
            63 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"unable to make the process undumpable: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
}
