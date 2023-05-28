use crate::openbsd_compat::vis::strnvis;
use ::libc;

extern "C" {
    static mut environ: *mut *mut libc::c_char;

    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
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
static mut argv_start: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut argv_env_len: size_t = 0 as libc::c_int as size_t;
#[no_mangle]
pub unsafe extern "C" fn compat_init_setproctitle(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) {
    extern "C" {
        #[link_name = "environ"]
        static mut environ_0: *mut *mut libc::c_char;
    }
    let mut lastargv: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut envp: *mut *mut libc::c_char = environ;
    let mut i: libc::c_int = 0;
    if argc == 0 as libc::c_int || (*argv.offset(0 as libc::c_int as isize)).is_null() {
        return;
    }
    i = 0 as libc::c_int;
    while !(*envp.offset(i as isize)).is_null() {
        i += 1;
        i;
    }
    environ = calloc(
        (i + 1 as libc::c_int) as libc::c_ulong,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    if environ.is_null() {
        environ = envp;
        return;
    }
    i = 0 as libc::c_int;
    while i < argc {
        if lastargv.is_null()
            || lastargv.offset(1 as libc::c_int as isize) == *argv.offset(i as isize)
        {
            lastargv = (*argv.offset(i as isize)).offset(strlen(*argv.offset(i as isize)) as isize);
        }
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while !(*envp.offset(i as isize)).is_null() {
        if lastargv.offset(1 as libc::c_int as isize) == *envp.offset(i as isize) {
            lastargv = (*envp.offset(i as isize)).offset(strlen(*envp.offset(i as isize)) as isize);
        }
        i += 1;
        i;
    }
    let ref mut fresh0 = *argv.offset(1 as libc::c_int as isize);
    *fresh0 = 0 as *mut libc::c_char;
    argv_start = *argv.offset(0 as libc::c_int as isize);
    argv_env_len = (lastargv.offset_from(*argv.offset(0 as libc::c_int as isize)) as libc::c_long
        - 1 as libc::c_int as libc::c_long) as size_t;
    i = 0 as libc::c_int;
    while !(*envp.offset(i as isize)).is_null() {
        let ref mut fresh1 = *environ.offset(i as isize);
        *fresh1 = libc::strdup(*envp.offset(i as isize));
        i += 1;
        i;
    }
    let ref mut fresh2 = *environ.offset(i as isize);
    *fresh2 = 0 as *mut libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn setproctitle(mut fmt: *const libc::c_char, mut args: ...) {
    let mut ap: ::core::ffi::VaListImpl;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut ptitle: [libc::c_char; 1024] = [0; 1024];
    let mut len: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    extern "C" {
        static mut __progname: *mut libc::c_char;
    }
    if argv_env_len <= 0 as libc::c_int as libc::c_ulong {
        return;
    }
    strlcpy(
        buf.as_mut_ptr(),
        __progname,
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
    );
    r = -(1 as libc::c_int);
    ap = args.clone();
    if !fmt.is_null() {
        len = strlcat(
            buf.as_mut_ptr(),
            b": \0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        );
        if len < ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong {
            r = vsnprintf(
                buf.as_mut_ptr().offset(len as isize),
                (::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong).wrapping_sub(len),
                fmt,
                ap.as_va_list(),
            );
        }
    }
    if r == -(1 as libc::c_int)
        || r as size_t
            >= (::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong).wrapping_sub(len)
    {
        return;
    }
    strnvis(
        ptitle.as_mut_ptr(),
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        0x2 as libc::c_int | 0x10 as libc::c_int | 0x8 as libc::c_int | 0x1 as libc::c_int,
    );
    len = strlcpy(argv_start, ptitle.as_mut_ptr(), argv_env_len);
    while len < argv_env_len {
        *argv_start.offset(len as isize) = '\0' as i32 as libc::c_char;
        len = len.wrapping_add(1);
        len;
    }
}
