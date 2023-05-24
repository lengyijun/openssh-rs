use ::libc;
extern "C" {
    fn vasprintf(
        __ptr: *mut *mut libc::c_char,
        __f: *const libc::c_char,
        __arg: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn reallocarray(__ptr: *mut libc::c_void, __nmemb: size_t, __size: size_t)
        -> *mut libc::c_void;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
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
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type size_t = libc::c_ulong;
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
pub unsafe extern "C" fn xmalloc(mut size: size_t) -> *mut libc::c_void {
    let mut ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    if size == 0 as libc::c_int as libc::c_ulong {
        sshfatal(
            b"xmalloc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"xmalloc\0")).as_ptr(),
            39 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"xmalloc: zero size\0" as *const u8 as *const libc::c_char,
        );
    }
    ptr = malloc(size);
    if ptr.is_null() {
        sshfatal(
            b"xmalloc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"xmalloc\0")).as_ptr(),
            42 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"xmalloc: out of memory (allocating %zu bytes)\0" as *const u8 as *const libc::c_char,
            size,
        );
    }
    return ptr;
}
pub unsafe extern "C" fn xcalloc(mut nmemb: size_t, mut size: size_t) -> *mut libc::c_void {
    let mut ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    if size == 0 as libc::c_int as libc::c_ulong || nmemb == 0 as libc::c_int as libc::c_ulong {
        sshfatal(
            b"xmalloc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"xcalloc\0")).as_ptr(),
            52 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"xcalloc: zero size\0" as *const u8 as *const libc::c_char,
        );
    }
    if (18446744073709551615 as libc::c_ulong).wrapping_div(nmemb) < size {
        sshfatal(
            b"xmalloc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"xcalloc\0")).as_ptr(),
            54 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"xcalloc: nmemb * size > SIZE_MAX\0" as *const u8 as *const libc::c_char,
        );
    }
    ptr = calloc(nmemb, size);
    if ptr.is_null() {
        sshfatal(
            b"xmalloc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"xcalloc\0")).as_ptr(),
            58 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"xcalloc: out of memory (allocating %zu bytes)\0" as *const u8 as *const libc::c_char,
            size.wrapping_mul(nmemb),
        );
    }
    return ptr;
}
pub unsafe extern "C" fn xreallocarray(
    mut ptr: *mut libc::c_void,
    mut nmemb: size_t,
    mut size: size_t,
) -> *mut libc::c_void {
    let mut new_ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    new_ptr = reallocarray(ptr, nmemb, size);
    if new_ptr.is_null() {
        sshfatal(
            b"xmalloc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"xreallocarray\0"))
                .as_ptr(),
            70 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"xreallocarray: out of memory (%zu elements of %zu bytes)\0" as *const u8
                as *const libc::c_char,
            nmemb,
            size,
        );
    }
    return new_ptr;
}
pub unsafe extern "C" fn xrecallocarray(
    mut ptr: *mut libc::c_void,
    mut onmemb: size_t,
    mut nmemb: size_t,
    mut size: size_t,
) -> *mut libc::c_void {
    let mut new_ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    new_ptr = recallocarray(ptr, onmemb, nmemb, size);
    if new_ptr.is_null() {
        sshfatal(
            b"xmalloc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"xrecallocarray\0"))
                .as_ptr(),
            82 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"xrecallocarray: out of memory (%zu elements of %zu bytes)\0" as *const u8
                as *const libc::c_char,
            nmemb,
            size,
        );
    }
    return new_ptr;
}
pub unsafe extern "C" fn xstrdup(mut str: *const libc::c_char) -> *mut libc::c_char {
    let mut len: size_t = 0;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    len = (strlen(str)).wrapping_add(1 as libc::c_int as libc::c_ulong);
    cp = xmalloc(len) as *mut libc::c_char;
    return memcpy(cp as *mut libc::c_void, str as *const libc::c_void, len) as *mut libc::c_char;
}
pub unsafe extern "C" fn xvasprintf(
    mut ret: *mut *mut libc::c_char,
    mut fmt: *const libc::c_char,
    mut ap: ::core::ffi::VaList,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    i = vasprintf(ret, fmt, ap.as_va_list());
    if i < 0 as libc::c_int || (*ret).is_null() {
        sshfatal(
            b"xmalloc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"xvasprintf\0")).as_ptr(),
            104 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"xvasprintf: could not allocate memory\0" as *const u8 as *const libc::c_char,
        );
    }
    return i;
}
pub unsafe extern "C" fn xasprintf(
    mut ret: *mut *mut libc::c_char,
    mut fmt: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut ap: ::core::ffi::VaListImpl;
    let mut i: libc::c_int = 0;
    ap = args.clone();
    i = xvasprintf(ret, fmt, ap.as_va_list());
    return i;
}
