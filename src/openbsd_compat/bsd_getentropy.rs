use ::libc;
extern "C" {
    fn RAND_bytes(buf: *mut libc::c_uchar, num: libc::c_int) -> libc::c_int;
    fn ERR_get_error() -> libc::c_ulong;
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
pub type size_t = libc::c_ulong;
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
#[no_mangle]
pub unsafe extern "C" fn _ssh_compat_getentropy(
    mut s: *mut libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    if RAND_bytes(s as *mut libc::c_uchar, len as libc::c_int) <= 0 as libc::c_int {
        sshfatal(
            b"bsd-getentropy.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"_ssh_compat_getentropy\0",
            ))
            .as_ptr(),
            47 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Couldn't obtain random bytes (error 0x%lx)\0" as *const u8 as *const libc::c_char,
            ERR_get_error(),
        );
    }
    return 0 as libc::c_int;
}
