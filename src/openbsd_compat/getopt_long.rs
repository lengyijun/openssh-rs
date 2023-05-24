use ::libc;
extern "C" {
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn sshlog(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: LogLevel,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: ...
    );
}
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct option {
    pub name: *const libc::c_char,
    pub has_arg: libc::c_int,
    pub flag: *mut libc::c_int,
    pub val: libc::c_int,
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
#[no_mangle]
pub static mut BSDopterr: libc::c_int = 1 as libc::c_int;
#[no_mangle]
pub static mut BSDoptind: libc::c_int = 1 as libc::c_int;
#[no_mangle]
pub static mut BSDoptopt: libc::c_int = '?' as i32;
#[no_mangle]
pub static mut BSDoptreset: libc::c_int = 0;
#[no_mangle]
pub static mut BSDoptarg: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut place: *mut libc::c_char =
    b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
static mut nonopt_start: libc::c_int = -(1 as libc::c_int);
static mut nonopt_end: libc::c_int = -(1 as libc::c_int);
static mut recargchar: [libc::c_char; 34] = unsafe {
    *::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
        b"option requires an argument -- %c\0",
    )
};
static mut recargstring: [libc::c_char; 34] = unsafe {
    *::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
        b"option requires an argument -- %s\0",
    )
};
static mut ambig: [libc::c_char; 25] = unsafe {
    *::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"ambiguous option -- %.*s\0")
};
static mut noarg: [libc::c_char; 40] = unsafe {
    *::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
        b"option doesn't take an argument -- %.*s\0",
    )
};
static mut illoptchar: [libc::c_char; 21] =
    unsafe { *::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"unknown option -- %c\0") };
static mut illoptstring: [libc::c_char; 21] =
    unsafe { *::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"unknown option -- %s\0") };
unsafe extern "C" fn gcd(mut a: libc::c_int, mut b: libc::c_int) -> libc::c_int {
    let mut c: libc::c_int = 0;
    c = a % b;
    while c != 0 as libc::c_int {
        a = b;
        b = c;
        c = a % b;
    }
    return b;
}
unsafe extern "C" fn permute_args(
    mut panonopt_start: libc::c_int,
    mut panonopt_end: libc::c_int,
    mut opt_end: libc::c_int,
    mut nargv: *const *mut libc::c_char,
) {
    let mut cstart: libc::c_int = 0;
    let mut cyclelen: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut ncycle: libc::c_int = 0;
    let mut nnonopts: libc::c_int = 0;
    let mut nopts: libc::c_int = 0;
    let mut pos: libc::c_int = 0;
    let mut swap: *mut libc::c_char = 0 as *mut libc::c_char;
    nnonopts = panonopt_end - panonopt_start;
    nopts = opt_end - panonopt_end;
    ncycle = gcd(nnonopts, nopts);
    cyclelen = (opt_end - panonopt_start) / ncycle;
    i = 0 as libc::c_int;
    while i < ncycle {
        cstart = panonopt_end + i;
        pos = cstart;
        j = 0 as libc::c_int;
        while j < cyclelen {
            if pos >= panonopt_end {
                pos -= nnonopts;
            } else {
                pos += nopts;
            }
            swap = *nargv.offset(pos as isize);
            let ref mut fresh0 = *(nargv as *mut *mut libc::c_char).offset(pos as isize);
            *fresh0 = *nargv.offset(cstart as isize);
            let ref mut fresh1 = *(nargv as *mut *mut libc::c_char).offset(cstart as isize);
            *fresh1 = swap;
            j += 1;
            j;
        }
        i += 1;
        i;
    }
}
unsafe extern "C" fn parse_long_options(
    mut nargv: *const *mut libc::c_char,
    mut options: *const libc::c_char,
    mut long_options: *const option,
    mut idx: *mut libc::c_int,
    mut short_too: libc::c_int,
) -> libc::c_int {
    let mut current_argv: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut has_equal: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut current_argv_len: size_t = 0;
    let mut i: libc::c_int = 0;
    let mut match_0: libc::c_int = 0;
    current_argv = place;
    match_0 = -(1 as libc::c_int);
    BSDoptind += 1;
    BSDoptind;
    has_equal = strchr(current_argv, '=' as i32);
    if !has_equal.is_null() {
        current_argv_len = has_equal.offset_from(current_argv) as libc::c_long as size_t;
        has_equal = has_equal.offset(1);
        has_equal;
    } else {
        current_argv_len = strlen(current_argv);
    }
    i = 0 as libc::c_int;
    while !((*long_options.offset(i as isize)).name).is_null() {
        if !(strncmp(
            current_argv,
            (*long_options.offset(i as isize)).name,
            current_argv_len,
        ) != 0)
        {
            if strlen((*long_options.offset(i as isize)).name) == current_argv_len {
                match_0 = i;
                break;
            } else if !(short_too != 0 && current_argv_len == 1 as libc::c_int as libc::c_ulong) {
                if match_0 == -(1 as libc::c_int) {
                    match_0 = i;
                } else {
                    if BSDopterr != 0 && *options as libc::c_int != ':' as i32 {
                        sshlog(
                            b"getopt_long.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                b"parse_long_options\0",
                            ))
                            .as_ptr(),
                            233 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_INFO,
                            0 as *const libc::c_char,
                            ambig.as_ptr(),
                            current_argv_len as libc::c_int,
                            current_argv,
                        );
                    }
                    BSDoptopt = 0 as libc::c_int;
                    return '?' as i32;
                }
            }
        }
        i += 1;
        i;
    }
    if match_0 != -(1 as libc::c_int) {
        if (*long_options.offset(match_0 as isize)).has_arg == 0 as libc::c_int
            && !has_equal.is_null()
        {
            if BSDopterr != 0 && *options as libc::c_int != ':' as i32 {
                sshlog(
                    b"getopt_long.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"parse_long_options\0",
                    ))
                    .as_ptr(),
                    243 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    noarg.as_ptr(),
                    current_argv_len as libc::c_int,
                    current_argv,
                );
            }
            if ((*long_options.offset(match_0 as isize)).flag).is_null() {
                BSDoptopt = (*long_options.offset(match_0 as isize)).val;
            } else {
                BSDoptopt = 0 as libc::c_int;
            }
            return if *options as libc::c_int == ':' as i32 {
                ':' as i32
            } else {
                '?' as i32
            };
        }
        if (*long_options.offset(match_0 as isize)).has_arg == 1 as libc::c_int
            || (*long_options.offset(match_0 as isize)).has_arg == 2 as libc::c_int
        {
            if !has_equal.is_null() {
                BSDoptarg = has_equal;
            } else if (*long_options.offset(match_0 as isize)).has_arg == 1 as libc::c_int {
                let fresh2 = BSDoptind;
                BSDoptind = BSDoptind + 1;
                BSDoptarg = *nargv.offset(fresh2 as isize);
            }
        }
        if (*long_options.offset(match_0 as isize)).has_arg == 1 as libc::c_int
            && BSDoptarg.is_null()
        {
            if BSDopterr != 0 && *options as libc::c_int != ':' as i32 {
                sshlog(
                    b"getopt_long.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"parse_long_options\0",
                    ))
                    .as_ptr(),
                    273 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    recargstring.as_ptr(),
                    current_argv,
                );
            }
            if ((*long_options.offset(match_0 as isize)).flag).is_null() {
                BSDoptopt = (*long_options.offset(match_0 as isize)).val;
            } else {
                BSDoptopt = 0 as libc::c_int;
            }
            BSDoptind -= 1;
            BSDoptind;
            return if *options as libc::c_int == ':' as i32 {
                ':' as i32
            } else {
                '?' as i32
            };
        }
    } else {
        if short_too != 0 {
            BSDoptind -= 1;
            BSDoptind;
            return -(1 as libc::c_int);
        }
        if BSDopterr != 0 && *options as libc::c_int != ':' as i32 {
            sshlog(
                b"getopt_long.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"parse_long_options\0",
                ))
                .as_ptr(),
                290 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                illoptstring.as_ptr(),
                current_argv,
            );
        }
        BSDoptopt = 0 as libc::c_int;
        return '?' as i32;
    }
    if !idx.is_null() {
        *idx = match_0;
    }
    if !((*long_options.offset(match_0 as isize)).flag).is_null() {
        *(*long_options.offset(match_0 as isize)).flag =
            (*long_options.offset(match_0 as isize)).val;
        return 0 as libc::c_int;
    } else {
        return (*long_options.offset(match_0 as isize)).val;
    };
}
unsafe extern "C" fn getopt_internal(
    mut nargc: libc::c_int,
    mut nargv: *const *mut libc::c_char,
    mut options: *const libc::c_char,
    mut long_options: *const option,
    mut idx: *mut libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    let mut oli: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut optchar: libc::c_int = 0;
    let mut short_too: libc::c_int = 0;
    static mut posixly_correct: libc::c_int = -(1 as libc::c_int);
    if options.is_null() {
        return -(1 as libc::c_int);
    }
    if BSDoptind == 0 as libc::c_int {
        BSDoptreset = 1 as libc::c_int;
        BSDoptind = BSDoptreset;
    }
    if posixly_correct == -(1 as libc::c_int) || BSDoptreset != 0 {
        posixly_correct = (getenv(b"POSIXLY_CORRECT\0" as *const u8 as *const libc::c_char)
            != 0 as *mut libc::c_void as *mut libc::c_char)
            as libc::c_int;
    }
    if *options as libc::c_int == '-' as i32 {
        flags |= 0x2 as libc::c_int;
    } else if posixly_correct != 0 || *options as libc::c_int == '+' as i32 {
        flags &= !(0x1 as libc::c_int);
    }
    if *options as libc::c_int == '+' as i32 || *options as libc::c_int == '-' as i32 {
        options = options.offset(1);
        options;
    }
    BSDoptarg = 0 as *mut libc::c_char;
    if BSDoptreset != 0 {
        nonopt_end = -(1 as libc::c_int);
        nonopt_start = nonopt_end;
    }
    while BSDoptreset != 0 || *place == 0 {
        BSDoptreset = 0 as libc::c_int;
        if BSDoptind >= nargc {
            place = b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            if nonopt_end != -(1 as libc::c_int) {
                permute_args(nonopt_start, nonopt_end, BSDoptind, nargv);
                BSDoptind -= nonopt_end - nonopt_start;
            } else if nonopt_start != -(1 as libc::c_int) {
                BSDoptind = nonopt_start;
            }
            nonopt_end = -(1 as libc::c_int);
            nonopt_start = nonopt_end;
            return -(1 as libc::c_int);
        }
        place = *nargv.offset(BSDoptind as isize);
        if *place as libc::c_int != '-' as i32
            || *place.offset(1 as libc::c_int as isize) as libc::c_int == '\0' as i32
                && (strchr(options, '-' as i32)).is_null()
        {
            place = b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            if flags & 0x2 as libc::c_int != 0 {
                let fresh3 = BSDoptind;
                BSDoptind = BSDoptind + 1;
                BSDoptarg = *nargv.offset(fresh3 as isize);
                return 1 as libc::c_int;
            }
            if flags & 0x1 as libc::c_int == 0 {
                return -(1 as libc::c_int);
            }
            if nonopt_start == -(1 as libc::c_int) {
                nonopt_start = BSDoptind;
            } else if nonopt_end != -(1 as libc::c_int) {
                permute_args(nonopt_start, nonopt_end, BSDoptind, nargv);
                nonopt_start = BSDoptind - (nonopt_end - nonopt_start);
                nonopt_end = -(1 as libc::c_int);
            }
            BSDoptind += 1;
            BSDoptind;
        } else {
            if nonopt_start != -(1 as libc::c_int) && nonopt_end == -(1 as libc::c_int) {
                nonopt_end = BSDoptind;
            }
            if *place.offset(1 as libc::c_int as isize) as libc::c_int != '\0' as i32
                && {
                    place = place.offset(1);
                    *place as libc::c_int == '-' as i32
                }
                && *place.offset(1 as libc::c_int as isize) as libc::c_int == '\0' as i32
            {
                BSDoptind += 1;
                BSDoptind;
                place = b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
                if nonopt_end != -(1 as libc::c_int) {
                    permute_args(nonopt_start, nonopt_end, BSDoptind, nargv);
                    BSDoptind -= nonopt_end - nonopt_start;
                }
                nonopt_end = -(1 as libc::c_int);
                nonopt_start = nonopt_end;
                return -(1 as libc::c_int);
            }
            break;
        }
    }
    if !long_options.is_null()
        && place != *nargv.offset(BSDoptind as isize)
        && (*place as libc::c_int == '-' as i32 || flags & 0x4 as libc::c_int != 0)
    {
        short_too = 0 as libc::c_int;
        if *place as libc::c_int == '-' as i32 {
            place = place.offset(1);
            place;
        } else if *place as libc::c_int != ':' as i32
            && !(strchr(options, *place as libc::c_int)).is_null()
        {
            short_too = 1 as libc::c_int;
        }
        optchar = parse_long_options(nargv, options, long_options, idx, short_too);
        if optchar != -(1 as libc::c_int) {
            place = b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            return optchar;
        }
    }
    let fresh4 = place;
    place = place.offset(1);
    optchar = *fresh4 as libc::c_int;
    if optchar == ':' as i32 || optchar == '-' as i32 && *place as libc::c_int != '\0' as i32 || {
        oli = strchr(options, optchar);
        oli.is_null()
    } {
        if optchar == '-' as i32 && *place as libc::c_int == '\0' as i32 {
            return -(1 as libc::c_int);
        }
        if *place == 0 {
            BSDoptind += 1;
            BSDoptind;
        }
        if BSDopterr != 0 && *options as libc::c_int != ':' as i32 {
            sshlog(
                b"getopt_long.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"getopt_internal\0"))
                    .as_ptr(),
                452 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                illoptchar.as_ptr(),
                optchar,
            );
        }
        BSDoptopt = optchar;
        return '?' as i32;
    }
    if !long_options.is_null()
        && optchar == 'W' as i32
        && *oli.offset(1 as libc::c_int as isize) as libc::c_int == ';' as i32
    {
        if !(*place != 0) {
            BSDoptind += 1;
            if BSDoptind >= nargc {
                place = b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
                if BSDopterr != 0 && *options as libc::c_int != ':' as i32 {
                    sshlog(
                        b"getopt_long.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"getopt_internal\0",
                        ))
                        .as_ptr(),
                        463 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        0 as *const libc::c_char,
                        recargchar.as_ptr(),
                        optchar,
                    );
                }
                BSDoptopt = optchar;
                return if *options as libc::c_int == ':' as i32 {
                    ':' as i32
                } else {
                    '?' as i32
                };
            } else {
                place = *nargv.offset(BSDoptind as isize);
            }
        }
        optchar = parse_long_options(nargv, options, long_options, idx, 0 as libc::c_int);
        place = b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        return optchar;
    }
    oli = oli.offset(1);
    if *oli as libc::c_int != ':' as i32 {
        if *place == 0 {
            BSDoptind += 1;
            BSDoptind;
        }
    } else {
        BSDoptarg = 0 as *mut libc::c_char;
        if *place != 0 {
            BSDoptarg = place;
        } else if *oli.offset(1 as libc::c_int as isize) as libc::c_int != ':' as i32 {
            BSDoptind += 1;
            if BSDoptind >= nargc {
                place = b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
                if BSDopterr != 0 && *options as libc::c_int != ':' as i32 {
                    sshlog(
                        b"getopt_long.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"getopt_internal\0",
                        ))
                        .as_ptr(),
                        484 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        0 as *const libc::c_char,
                        recargchar.as_ptr(),
                        optchar,
                    );
                }
                BSDoptopt = optchar;
                return if *options as libc::c_int == ':' as i32 {
                    ':' as i32
                } else {
                    '?' as i32
                };
            } else {
                BSDoptarg = *nargv.offset(BSDoptind as isize);
            }
        }
        place = b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        BSDoptind += 1;
        BSDoptind;
    }
    return optchar;
}
#[no_mangle]
pub unsafe extern "C" fn BSDgetopt(
    mut nargc: libc::c_int,
    mut nargv: *const *mut libc::c_char,
    mut options: *const libc::c_char,
) -> libc::c_int {
    return getopt_internal(
        nargc,
        nargv,
        options,
        0 as *const option,
        0 as *mut libc::c_int,
        0 as libc::c_int,
    );
}
