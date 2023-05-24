use ::libc;
extern "C" {
    pub type sockaddr_x25;
    pub type sockaddr_un;
    pub type sockaddr_ns;
    pub type sockaddr_iso;
    pub type sockaddr_ipx;
    pub type sockaddr_inarp;
    pub type sockaddr_eon;
    pub type sockaddr_dl;
    pub type sockaddr_ax25;
    pub type sockaddr_at;
    fn getpeername(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __len: *mut socklen_t)
        -> libc::c_int;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn addr_sa_to_xaddr(sa: *mut sockaddr, slen: socklen_t, xa: *mut xaddr) -> libc::c_int;
    fn addr_netmask(af: libc::c_int, l: u_int, n: *mut xaddr) -> libc::c_int;
    fn addr_ntop(n: *const xaddr, p: *mut libc::c_char, len: size_t) -> libc::c_int;
    fn addr_and(dst: *mut xaddr, a: *const xaddr, b: *const xaddr) -> libc::c_int;
    fn addr_cmp(a: *const xaddr, b: *const xaddr) -> libc::c_int;

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
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
}
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __socklen_t = libc::c_uint;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int8_t = __uint8_t;
pub type u_int16_t = __uint16_t;
pub type u_int32_t = __uint32_t;
pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union __SOCKADDR_ARG {
    pub __sockaddr__: *mut sockaddr,
    pub __sockaddr_at__: *mut sockaddr_at,
    pub __sockaddr_ax25__: *mut sockaddr_ax25,
    pub __sockaddr_dl__: *mut sockaddr_dl,
    pub __sockaddr_eon__: *mut sockaddr_eon,
    pub __sockaddr_in__: *mut sockaddr_in,
    pub __sockaddr_in6__: *mut sockaddr_in6,
    pub __sockaddr_inarp__: *mut sockaddr_inarp,
    pub __sockaddr_ipx__: *mut sockaddr_ipx,
    pub __sockaddr_iso__: *mut sockaddr_iso,
    pub __sockaddr_ns__: *mut sockaddr_ns,
    pub __sockaddr_un__: *mut sockaddr_un,
    pub __sockaddr_x25__: *mut sockaddr_x25,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
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
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct child_info {
    pub id: libc::c_int,
    pub addr: xaddr,
}
static mut max_children: libc::c_int = 0;
static mut max_persource: libc::c_int = 0;
static mut ipv4_masklen: libc::c_int = 0;
static mut ipv6_masklen: libc::c_int = 0;
static mut child: *mut child_info = 0 as *const child_info as *mut child_info;
pub unsafe extern "C" fn srclimit_init(
    mut max: libc::c_int,
    mut persource: libc::c_int,
    mut ipv4len: libc::c_int,
    mut ipv6len: libc::c_int,
) {
    let mut i: libc::c_int = 0;
    max_children = max;
    ipv4_masklen = ipv4len;
    ipv6_masklen = ipv6len;
    max_persource = persource;
    if max_persource == 2147483647 as libc::c_int {
        return;
    }
    crate::log::sshlog(
        b"srclimit.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"srclimit_init\0")).as_ptr(),
        54 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"%s: max connections %d, per source %d, masks %d,%d\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"srclimit_init\0")).as_ptr(),
        max,
        persource,
        ipv4len,
        ipv6len,
    );
    if max <= 0 as libc::c_int {
        sshfatal(
            b"srclimit.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"srclimit_init\0"))
                .as_ptr(),
            56 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: invalid number of sockets: %d\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"srclimit_init\0"))
                .as_ptr(),
            max,
        );
    }
    child = xcalloc(
        max_children as size_t,
        ::core::mem::size_of::<child_info>() as libc::c_ulong,
    ) as *mut child_info;
    i = 0 as libc::c_int;
    while i < max_children {
        (*child.offset(i as isize)).id = -(1 as libc::c_int);
        i += 1;
        i;
    }
}
pub unsafe extern "C" fn srclimit_check_allow(
    mut sock: libc::c_int,
    mut id: libc::c_int,
) -> libc::c_int {
    let mut xa: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut xb: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut xmask: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut addr: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut addrlen: socklen_t =
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    let mut sa: *mut sockaddr = &mut addr as *mut sockaddr_storage as *mut sockaddr;
    let mut i: libc::c_int = 0;
    let mut bits: libc::c_int = 0;
    let mut first_unused: libc::c_int = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    let mut xas: [libc::c_char; 1025] = [0; 1025];
    if max_persource == 2147483647 as libc::c_int {
        return 1 as libc::c_int;
    }
    crate::log::sshlog(
        b"srclimit.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"srclimit_check_allow\0"))
            .as_ptr(),
        76 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"%s: sock %d id %d limit %d\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"srclimit_check_allow\0"))
            .as_ptr(),
        sock,
        id,
        max_persource,
    );
    if getpeername(sock, __SOCKADDR_ARG { __sockaddr__: sa }, &mut addrlen) != 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    if addr_sa_to_xaddr(sa, addrlen, &mut xa) != 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    bits = if xa.af as libc::c_int == 2 as libc::c_int {
        ipv4_masklen
    } else {
        ipv6_masklen
    };
    if addr_netmask(xa.af as libc::c_int, bits as u_int, &mut xmask) != 0 as libc::c_int
        || addr_and(&mut xb, &mut xa, &mut xmask) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"srclimit.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"srclimit_check_allow\0"))
                .as_ptr(),
            86 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"%s: invalid mask %d bits\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"srclimit_check_allow\0"))
                .as_ptr(),
            bits,
        );
        return 1 as libc::c_int;
    }
    first_unused = max_children;
    i = 0 as libc::c_int;
    while i < max_children {
        if (*child.offset(i as isize)).id == -(1 as libc::c_int) {
            if i < first_unused {
                first_unused = i;
            }
        } else if addr_cmp(&mut (*child.offset(i as isize)).addr, &mut xb) == 0 as libc::c_int {
            count += 1;
            count;
        }
        i += 1;
        i;
    }
    if addr_ntop(
        &mut xa,
        xas.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
    ) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"srclimit.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"srclimit_check_allow\0"))
                .as_ptr(),
            101 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"%s: addr ntop failed\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"srclimit_check_allow\0"))
                .as_ptr(),
        );
        return 1 as libc::c_int;
    }
    crate::log::sshlog(
        b"srclimit.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"srclimit_check_allow\0"))
            .as_ptr(),
        105 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s: new unauthenticated connection from %s/%d, at %d of %d\0" as *const u8
            as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"srclimit_check_allow\0"))
            .as_ptr(),
        xas.as_mut_ptr(),
        bits,
        count,
        max_persource,
    );
    if first_unused == max_children {
        crate::log::sshlog(
            b"srclimit.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"srclimit_check_allow\0"))
                .as_ptr(),
            108 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"%s: no free slot\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"srclimit_check_allow\0"))
                .as_ptr(),
        );
        return 0 as libc::c_int;
    }
    if first_unused < 0 as libc::c_int || first_unused >= max_children {
        sshfatal(
            b"srclimit.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"srclimit_check_allow\0"))
                .as_ptr(),
            113 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: internal error: first_unused out of range\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"srclimit_check_allow\0"))
                .as_ptr(),
        );
    }
    if count >= max_persource {
        return 0 as libc::c_int;
    }
    (*child.offset(first_unused as isize)).id = id;
    memcpy(
        &mut (*child.offset(first_unused as isize)).addr as *mut xaddr as *mut libc::c_void,
        &mut xb as *mut xaddr as *const libc::c_void,
        ::core::mem::size_of::<xaddr>() as libc::c_ulong,
    );
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn srclimit_done(mut id: libc::c_int) {
    let mut i: libc::c_int = 0;
    if max_persource == 2147483647 as libc::c_int {
        return;
    }
    crate::log::sshlog(
        b"srclimit.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"srclimit_done\0")).as_ptr(),
        132 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"%s: id %d\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"srclimit_done\0")).as_ptr(),
        id,
    );
    i = 0 as libc::c_int;
    while i < max_children {
        if (*child.offset(i as isize)).id == id {
            (*child.offset(i as isize)).id = -(1 as libc::c_int);
            return;
        }
        i += 1;
        i;
    }
}
