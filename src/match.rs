use ::libc;
extern "C" {
    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn __ctype_tolower_loc() -> *mut *const __int32_t;

    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;

    fn addr_match_list(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn lowercase(s: *mut libc::c_char);
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __int32_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type C2RustUnnamed = libc::c_uint;
pub const _ISalnum: C2RustUnnamed = 8;
pub const _ISpunct: C2RustUnnamed = 4;
pub const _IScntrl: C2RustUnnamed = 2;
pub const _ISblank: C2RustUnnamed = 1;
pub const _ISgraph: C2RustUnnamed = 32768;
pub const _ISprint: C2RustUnnamed = 16384;
pub const _ISspace: C2RustUnnamed = 8192;
pub const _ISxdigit: C2RustUnnamed = 4096;
pub const _ISdigit: C2RustUnnamed = 2048;
pub const _ISalpha: C2RustUnnamed = 1024;
pub const _ISlower: C2RustUnnamed = 512;
pub const _ISupper: C2RustUnnamed = 256;
#[inline]
unsafe extern "C" fn tolower(mut __c: libc::c_int) -> libc::c_int {
    return if __c >= -(128 as libc::c_int) && __c < 256 as libc::c_int {
        *(*__ctype_tolower_loc()).offset(__c as isize)
    } else {
        __c
    };
}
pub unsafe extern "C" fn match_pattern(
    mut s: *const libc::c_char,
    mut pattern: *const libc::c_char,
) -> libc::c_int {
    loop {
        if *pattern == 0 {
            return (*s == 0) as libc::c_int;
        }
        if *pattern as libc::c_int == '*' as i32 {
            while *pattern as libc::c_int == '*' as i32 {
                pattern = pattern.offset(1);
                pattern;
            }
            if *pattern == 0 {
                return 1 as libc::c_int;
            }
            if *pattern as libc::c_int != '?' as i32 && *pattern as libc::c_int != '*' as i32 {
                while *s != 0 {
                    if *s as libc::c_int == *pattern as libc::c_int
                        && match_pattern(
                            s.offset(1 as libc::c_int as isize),
                            pattern.offset(1 as libc::c_int as isize),
                        ) != 0
                    {
                        return 1 as libc::c_int;
                    }
                    s = s.offset(1);
                    s;
                }
                return 0 as libc::c_int;
            }
            while *s != 0 {
                if match_pattern(s, pattern) != 0 {
                    return 1 as libc::c_int;
                }
                s = s.offset(1);
                s;
            }
            return 0 as libc::c_int;
        }
        if *s == 0 {
            return 0 as libc::c_int;
        }
        if *pattern as libc::c_int != '?' as i32 && *pattern as libc::c_int != *s as libc::c_int {
            return 0 as libc::c_int;
        }
        s = s.offset(1);
        s;
        pattern = pattern.offset(1);
        pattern;
    }
}
pub unsafe extern "C" fn match_pattern_list(
    mut string: *const libc::c_char,
    mut pattern: *const libc::c_char,
    mut dolower: libc::c_int,
) -> libc::c_int {
    let mut sub: [libc::c_char; 1024] = [0; 1024];
    let mut negated: libc::c_int = 0;
    let mut got_positive: libc::c_int = 0;
    let mut i: u_int = 0;
    let mut subi: u_int = 0;
    let mut len: u_int = strlen(pattern) as u_int;
    got_positive = 0 as libc::c_int;
    i = 0 as libc::c_int as u_int;
    while i < len {
        if *pattern.offset(i as isize) as libc::c_int == '!' as i32 {
            negated = 1 as libc::c_int;
            i = i.wrapping_add(1);
            i;
        } else {
            negated = 0 as libc::c_int;
        }
        subi = 0 as libc::c_int as u_int;
        while i < len
            && (subi as libc::c_ulong)
                < (::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            && *pattern.offset(i as isize) as libc::c_int != ',' as i32
        {
            sub[subi as usize] = (if dolower != 0
                && *(*__ctype_b_loc())
                    .offset(*pattern.offset(i as isize) as u_char as libc::c_int as isize)
                    as libc::c_int
                    & _ISupper as libc::c_int as libc::c_ushort as libc::c_int
                    != 0
            {
                {
                    let mut __res: libc::c_int = 0;
                    if ::core::mem::size_of::<u_char>() as libc::c_ulong
                        > 1 as libc::c_int as libc::c_ulong
                    {
                        if 0 != 0 {
                            let mut __c: libc::c_int =
                                *pattern.offset(i as isize) as u_char as libc::c_int;
                            __res = if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                                __c
                            } else {
                                *(*__ctype_tolower_loc()).offset(__c as isize)
                            };
                        } else {
                            __res = tolower(*pattern.offset(i as isize) as u_char as libc::c_int);
                        }
                    } else {
                        __res = *(*__ctype_tolower_loc())
                            .offset(*pattern.offset(i as isize) as u_char as libc::c_int as isize);
                    }
                    __res
                }
            } else {
                *pattern.offset(i as isize) as libc::c_int
            }) as libc::c_char;
            subi = subi.wrapping_add(1);
            subi;
            i = i.wrapping_add(1);
            i;
        }
        if subi as libc::c_ulong
            >= (::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        {
            return 0 as libc::c_int;
        }
        if i < len && *pattern.offset(i as isize) as libc::c_int == ',' as i32 {
            i = i.wrapping_add(1);
            i;
        }
        sub[subi as usize] = '\0' as i32 as libc::c_char;
        if match_pattern(string, sub.as_mut_ptr()) != 0 {
            if negated != 0 {
                return -(1 as libc::c_int);
            } else {
                got_positive = 1 as libc::c_int;
            }
        }
    }
    return got_positive;
}
pub unsafe extern "C" fn match_usergroup_pattern_list(
    mut string: *const libc::c_char,
    mut pattern: *const libc::c_char,
) -> libc::c_int {
    return match_pattern_list(string, pattern, 0 as libc::c_int);
}
pub unsafe extern "C" fn match_hostname(
    mut host: *const libc::c_char,
    mut pattern: *const libc::c_char,
) -> libc::c_int {
    let mut hostcopy: *mut libc::c_char = crate::xmalloc::xstrdup(host);
    let mut r: libc::c_int = 0;
    lowercase(hostcopy);
    r = match_pattern_list(hostcopy, pattern, 1 as libc::c_int);
    libc::free(hostcopy as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn match_host_and_ip(
    mut host: *const libc::c_char,
    mut ipaddr: *const libc::c_char,
    mut patterns: *const libc::c_char,
) -> libc::c_int {
    let mut mhost: libc::c_int = 0;
    let mut mip: libc::c_int = 0;
    mip = addr_match_list(ipaddr, patterns);
    if mip == -(2 as libc::c_int) {
        return -(1 as libc::c_int);
    } else if host.is_null() || ipaddr.is_null() || mip == -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    mhost = match_hostname(host, patterns);
    if mhost == -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    if mhost == 0 as libc::c_int && mip == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn match_user(
    mut user: *const libc::c_char,
    mut host: *const libc::c_char,
    mut ipaddr: *const libc::c_char,
    mut pattern: *const libc::c_char,
) -> libc::c_int {
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pat: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: libc::c_int = 0;
    if user.is_null() && host.is_null() && ipaddr.is_null() {
        p = strchr(pattern, '@' as i32);
        if !p.is_null()
            && match_host_and_ip(
                0 as *const libc::c_char,
                0 as *const libc::c_char,
                p.offset(1 as libc::c_int as isize),
            ) < 0 as libc::c_int
        {
            return -(1 as libc::c_int);
        }
        return 0 as libc::c_int;
    }
    if user.is_null() {
        return 0 as libc::c_int;
    }
    p = strchr(pattern, '@' as i32);
    if p.is_null() {
        return match_pattern(user, pattern);
    }
    pat = crate::xmalloc::xstrdup(pattern);
    p = strchr(pat, '@' as i32);
    let fresh0 = p;
    p = p.offset(1);
    *fresh0 = '\0' as i32 as libc::c_char;
    ret = match_pattern(user, pat);
    if ret == 1 as libc::c_int {
        ret = match_host_and_ip(host, ipaddr, p);
    }
    libc::free(pat as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn match_list(
    mut client: *const libc::c_char,
    mut server: *const libc::c_char,
    mut next: *mut u_int,
) -> *mut libc::c_char {
    let mut sproposals: [*mut libc::c_char; 40] = [0 as *mut libc::c_char; 40];
    let mut c: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut nproposals: libc::c_int = 0;
    cp = crate::xmalloc::xstrdup(client);
    c = cp;
    sp = crate::xmalloc::xstrdup(server);
    s = sp;
    p = strsep(&mut sp, b",\0" as *const u8 as *const libc::c_char);
    i = 0 as libc::c_int;
    while !p.is_null() && *p as libc::c_int != '\0' as i32 {
        if !(i < 40 as libc::c_int) {
            break;
        }
        sproposals[i as usize] = p;
        p = strsep(&mut sp, b",\0" as *const u8 as *const libc::c_char);
        i += 1;
        i;
    }
    nproposals = i;
    p = strsep(&mut cp, b",\0" as *const u8 as *const libc::c_char);
    i = 0 as libc::c_int;
    while !p.is_null() && *p as libc::c_int != '\0' as i32 {
        j = 0 as libc::c_int;
        while j < nproposals {
            if strcmp(p, sproposals[j as usize]) == 0 as libc::c_int {
                ret = crate::xmalloc::xstrdup(p);
                if !next.is_null() {
                    *next = (if cp.is_null() {
                        strlen(c)
                    } else {
                        cp.offset_from(c) as libc::c_long as u_int as libc::c_ulong
                    }) as u_int;
                }
                libc::free(c as *mut libc::c_void);
                libc::free(s as *mut libc::c_void);
                return ret;
            }
            j += 1;
            j;
        }
        p = strsep(&mut cp, b",\0" as *const u8 as *const libc::c_char);
        i += 1;
        i;
    }
    if !next.is_null() {
        *next = strlen(c) as u_int;
    }
    libc::free(c as *mut libc::c_void);
    libc::free(s as *mut libc::c_void);
    return 0 as *mut libc::c_char;
}
unsafe extern "C" fn filter_list(
    mut proposal: *const libc::c_char,
    mut filter: *const libc::c_char,
    mut denylist: libc::c_int,
) -> *mut libc::c_char {
    let mut len: size_t = (strlen(proposal)).wrapping_add(1 as libc::c_int as libc::c_ulong);
    let mut fix_prop: *mut libc::c_char = libc::malloc(len as usize) as *mut libc::c_char;
    let mut orig_prop: *mut libc::c_char = strdup(proposal);
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    if fix_prop.is_null() || orig_prop.is_null() {
        libc::free(orig_prop as *mut libc::c_void);
        libc::free(fix_prop as *mut libc::c_void);
        return 0 as *mut libc::c_char;
    }
    tmp = orig_prop;
    *fix_prop = '\0' as i32 as libc::c_char;
    loop {
        cp = strsep(&mut tmp, b",\0" as *const u8 as *const libc::c_char);
        if cp.is_null() {
            break;
        }
        r = match_pattern_list(cp, filter, 0 as libc::c_int);
        if denylist != 0 && r != 1 as libc::c_int || denylist == 0 && r == 1 as libc::c_int {
            if *fix_prop as libc::c_int != '\0' as i32 {
                strlcat(fix_prop, b",\0" as *const u8 as *const libc::c_char, len);
            }
            strlcat(fix_prop, cp, len);
        }
    }
    libc::free(orig_prop as *mut libc::c_void);
    return fix_prop;
}
pub unsafe extern "C" fn match_filter_denylist(
    mut proposal: *const libc::c_char,
    mut filter: *const libc::c_char,
) -> *mut libc::c_char {
    return filter_list(proposal, filter, 1 as libc::c_int);
}
pub unsafe extern "C" fn match_filter_allowlist(
    mut proposal: *const libc::c_char,
    mut filter: *const libc::c_char,
) -> *mut libc::c_char {
    return filter_list(proposal, filter, 0 as libc::c_int);
}
