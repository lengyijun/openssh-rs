use ::libc;
extern "C" {
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn OpenSSL_version_num() -> libc::c_ulong;
    fn RAND_status() -> libc::c_int;
    fn ssh_libcrypto_init();
    fn ssh_compatible_openssl(_: libc::c_long, _: libc::c_long) -> libc::c_int;
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
pub type __u_long = libc::c_ulong;
pub type u_long = __u_long;
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
pub unsafe extern "C" fn seed_rng() {
    let mut buf: [libc::c_uchar; 48] = [0; 48];
    ssh_libcrypto_init();
    if ssh_compatible_openssl(
        ((3 as libc::c_int) << 28 as libc::c_int
            | (0 as libc::c_int) << 20 as libc::c_int
            | (2 as libc::c_int) << 4 as libc::c_int) as libc::c_long
            | 0 as libc::c_long,
        OpenSSL_version_num() as libc::c_long,
    ) == 0
    {
        sshfatal(
            b"entropy.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"seed_rng\0")).as_ptr(),
            73 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"OpenSSL version mismatch. Built against %lx, you have %lx\0" as *const u8
                as *const libc::c_char,
            (((3 as libc::c_int) << 28 as libc::c_int
                | (0 as libc::c_int) << 20 as libc::c_int
                | (2 as libc::c_int) << 4 as libc::c_int) as libc::c_long
                | 0 as libc::c_long) as u_long,
            OpenSSL_version_num(),
        );
    }
    if RAND_status() != 1 as libc::c_int {
        sshfatal(
            b"entropy.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"seed_rng\0")).as_ptr(),
            86 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"PRNG is not seeded\0" as *const u8 as *const libc::c_char,
        );
    }
    arc4random_buf(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_uchar; 48]>() as libc::c_ulong,
    );
    explicit_bzero(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_uchar; 48]>() as libc::c_ulong,
    );
}
