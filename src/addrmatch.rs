use ::libc;

extern "C" {
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;

    fn addr_pton(p: *const libc::c_char, n: *mut xaddr) -> libc::c_int;
    fn addr_pton_cidr(p: *const libc::c_char, n: *mut xaddr, l: *mut u_int) -> libc::c_int;
    fn addr_netmatch(host: *const xaddr, net: *const xaddr, masklen: u_int) -> libc::c_int;
    fn match_pattern(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

}
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type u_int = __u_int;
pub type u_int8_t = __uint8_t;
pub type u_int16_t = __uint16_t;
pub type u_int32_t = __uint32_t;
pub type sa_family_t = libc::c_ushort;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
pub type uint16_t = __uint16_t;
pub type uint8_t = __uint8_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xaddr {
    pub af: sa_family_t,
    pub xa: C2RustUnnamed_0,
    pub scope_id: u_int32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub v4: in_addr,
    pub v6: in6_addr,
    pub addr8: [u_int8_t; 16],
    pub addr16: [u_int16_t; 8],
    pub addr32: [u_int32_t; 4],
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
pub unsafe extern "C" fn addr_match_list(
    mut addr: *const libc::c_char,
    mut _list: *const libc::c_char,
) -> libc::c_int {
    let mut list: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut o: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut try_addr: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut match_addr: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut masklen: u_int = 0;
    let mut neg: u_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    if !addr.is_null() && addr_pton(addr, &mut try_addr) != 0 as libc::c_int {
        crate::log::sshlog(
            b"addrmatch.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"addr_match_list\0"))
                .as_ptr(),
            57 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"couldn't parse address %.100s\0" as *const u8 as *const libc::c_char,
            addr,
        );
        return 0 as libc::c_int;
    }
    list = strdup(_list);
    o = list;
    if o.is_null() {
        return -(1 as libc::c_int);
    }
    loop {
        cp = strsep(&mut list, b",\0" as *const u8 as *const libc::c_char);
        if cp.is_null() {
            break;
        }
        neg = (*cp as libc::c_int == '!' as i32) as libc::c_int as u_int;
        if neg != 0 {
            cp = cp.offset(1);
            cp;
        }
        if *cp as libc::c_int == '\0' as i32 {
            ret = -(2 as libc::c_int);
            break;
        } else {
            r = addr_pton_cidr(cp, &mut match_addr, &mut masklen);
            if r == -(2 as libc::c_int) {
                crate::log::sshlog(
                    b"addrmatch.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"addr_match_list\0",
                    ))
                    .as_ptr(),
                    74 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"inconsistent mask length for match network \"%.100s\"\0" as *const u8
                        as *const libc::c_char,
                    cp,
                );
                ret = -(2 as libc::c_int);
                break;
            } else {
                if r == 0 as libc::c_int {
                    if !(!addr.is_null()
                        && addr_netmatch(&mut try_addr, &mut match_addr, masklen)
                            == 0 as libc::c_int)
                    {
                        continue;
                    }
                } else if !(!addr.is_null() && match_pattern(addr, cp) == 1 as libc::c_int) {
                    continue;
                }
                if neg != 0 {
                    ret = -(1 as libc::c_int);
                    break;
                } else {
                    ret = 1 as libc::c_int;
                }
            }
        }
    }
    libc::free(o as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn addr_match_cidr_list(
    mut addr: *const libc::c_char,
    mut _list: *const libc::c_char,
) -> libc::c_int {
    let mut list: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut o: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut try_addr: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut match_addr: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut masklen: u_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    if !addr.is_null() && addr_pton(addr, &mut try_addr) != 0 as libc::c_int {
        crate::log::sshlog(
            b"addrmatch.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"addr_match_cidr_list\0"))
                .as_ptr(),
            117 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"couldn't parse address %.100s\0" as *const u8 as *const libc::c_char,
            addr,
        );
        return 0 as libc::c_int;
    }
    list = strdup(_list);
    o = list;
    if o.is_null() {
        return -(1 as libc::c_int);
    }
    loop {
        cp = strsep(&mut list, b",\0" as *const u8 as *const libc::c_char);
        if cp.is_null() {
            break;
        }
        if *cp as libc::c_int == '\0' as i32 {
            crate::log::sshlog(
                b"addrmatch.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"addr_match_cidr_list\0",
                ))
                .as_ptr(),
                124 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"empty entry in list \"%.100s\"\0" as *const u8 as *const libc::c_char,
                o,
            );
            ret = -(1 as libc::c_int);
            break;
        } else if strlen(cp) > (46 as libc::c_int + 3 as libc::c_int) as libc::c_ulong {
            crate::log::sshlog(
                b"addrmatch.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"addr_match_cidr_list\0",
                ))
                .as_ptr(),
                137 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"list entry \"%.100s\" too long\0" as *const u8 as *const libc::c_char,
                cp,
            );
            ret = -(1 as libc::c_int);
            break;
        } else {
            if strspn(
                cp,
                b"0123456789abcdefABCDEF.:/\0" as *const u8 as *const libc::c_char,
            ) != strlen(cp)
            {
                crate::log::sshlog(
                    b"addrmatch.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"addr_match_cidr_list\0",
                    ))
                    .as_ptr(),
                    144 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"list entry \"%.100s\" contains invalid characters\0" as *const u8
                        as *const libc::c_char,
                    cp,
                );
                ret = -(1 as libc::c_int);
            }
            r = addr_pton_cidr(cp, &mut match_addr, &mut masklen);
            if r == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"addrmatch.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"addr_match_cidr_list\0",
                    ))
                    .as_ptr(),
                    151 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Invalid network entry \"%.100s\"\0" as *const u8 as *const libc::c_char,
                    cp,
                );
                ret = -(1 as libc::c_int);
                break;
            } else if r == -(2 as libc::c_int) {
                crate::log::sshlog(
                    b"addrmatch.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"addr_match_cidr_list\0",
                    ))
                    .as_ptr(),
                    156 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Inconsistent mask length for network \"%.100s\"\0" as *const u8
                        as *const libc::c_char,
                    cp,
                );
                ret = -(1 as libc::c_int);
                break;
            } else {
                if !(r == 0 as libc::c_int && !addr.is_null()) {
                    continue;
                }
                if addr_netmatch(&mut try_addr, &mut match_addr, masklen) == 0 as libc::c_int {
                    ret = 1 as libc::c_int;
                }
            }
        }
    }
    libc::free(o as *mut libc::c_void);
    return ret;
}
