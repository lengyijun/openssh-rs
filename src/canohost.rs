use ::libc;
extern "C" {
    pub type sockaddr_x25;
    pub type sockaddr_ns;
    pub type sockaddr_iso;
    pub type sockaddr_ipx;
    pub type sockaddr_inarp;
    pub type sockaddr_eon;
    pub type sockaddr_dl;
    pub type sockaddr_ax25;
    pub type sockaddr_at;
    fn getsockname(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __len: *mut socklen_t)
        -> libc::c_int;
    fn getpeername(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __len: *mut socklen_t)
        -> libc::c_int;
    fn __errno_location() -> *mut libc::c_int;
    fn gethostname(__name: *mut libc::c_char, __len: size_t) -> libc::c_int;
    fn getnameinfo(
        __sa: *const sockaddr,
        __salen: socklen_t,
        __host: *mut libc::c_char,
        __hostlen: socklen_t,
        __serv: *mut libc::c_char,
        __servlen: socklen_t,
        __flags: libc::c_int,
    ) -> libc::c_int;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn strtol(_: *const libc::c_char, _: *mut *mut libc::c_char, _: libc::c_int) -> libc::c_long;
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;

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
    fn ssh_gai_strerror(_: libc::c_int) -> *const libc::c_char;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __socklen_t = libc::c_uint;
pub type size_t = libc::c_ulong;
pub type u_int16_t = __uint16_t;
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
pub struct sockaddr_un {
    pub sun_family: sa_family_t,
    pub sun_path: [libc::c_char; 108],
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
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
#[inline]
unsafe extern "C" fn atoi(mut __nptr: *const libc::c_char) -> libc::c_int {
    return strtol(
        __nptr,
        0 as *mut libc::c_void as *mut *mut libc::c_char,
        10 as libc::c_int,
    ) as libc::c_int;
}
pub unsafe extern "C" fn ipv64_normalise_mapped(
    mut addr: *mut sockaddr_storage,
    mut len: *mut socklen_t,
) {
    let mut a6: *mut sockaddr_in6 = addr as *mut sockaddr_in6;
    let mut a4: *mut sockaddr_in = addr as *mut sockaddr_in;
    let mut inaddr: in_addr = in_addr { s_addr: 0 };
    let mut port: u_int16_t = 0;
    if (*addr).ss_family as libc::c_int != 10 as libc::c_int
        || ({
            let mut __a: *const in6_addr = &mut (*a6).sin6_addr as *mut in6_addr as *const in6_addr;
            ((*__a).__in6_u.__u6_addr32[0 as libc::c_int as usize]
                == 0 as libc::c_int as libc::c_uint
                && (*__a).__in6_u.__u6_addr32[1 as libc::c_int as usize]
                    == 0 as libc::c_int as libc::c_uint
                && (*__a).__in6_u.__u6_addr32[2 as libc::c_int as usize]
                    == __bswap_32(0xffff as libc::c_int as __uint32_t)) as libc::c_int
        }) == 0
    {
        return;
    }
    crate::log::sshlog(
        b"canohost.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"ipv64_normalise_mapped\0"))
            .as_ptr(),
        50 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Normalising mapped IPv4 in IPv6 address\0" as *const u8 as *const libc::c_char,
    );
    memcpy(
        &mut inaddr as *mut in_addr as *mut libc::c_void,
        (&mut (*a6).sin6_addr as *mut in6_addr as *mut libc::c_char)
            .offset(12 as libc::c_int as isize) as *const libc::c_void,
        ::core::mem::size_of::<in_addr>() as libc::c_ulong,
    );
    port = (*a6).sin6_port;
    memset(
        a4 as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong,
    );
    (*a4).sin_family = 2 as libc::c_int as sa_family_t;
    *len = ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong as socklen_t;
    memcpy(
        &mut (*a4).sin_addr as *mut in_addr as *mut libc::c_void,
        &mut inaddr as *mut in_addr as *const libc::c_void,
        ::core::mem::size_of::<in_addr>() as libc::c_ulong,
    );
    (*a4).sin_port = port;
}
unsafe extern "C" fn get_socket_address(
    mut sock: libc::c_int,
    mut remote: libc::c_int,
    mut flags: libc::c_int,
) -> *mut libc::c_char {
    let mut addr: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut addrlen: socklen_t = 0;
    let mut ntop: [libc::c_char; 1025] = [0; 1025];
    let mut r: libc::c_int = 0;
    if sock < 0 as libc::c_int {
        return 0 as *mut libc::c_char;
    }
    addrlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    memset(
        &mut addr as *mut sockaddr_storage as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong,
    );
    if remote != 0 {
        if getpeername(
            sock,
            __SOCKADDR_ARG {
                __sockaddr__: &mut addr as *mut sockaddr_storage as *mut sockaddr,
            },
            &mut addrlen,
        ) != 0 as libc::c_int
        {
            return 0 as *mut libc::c_char;
        }
    } else if getsockname(
        sock,
        __SOCKADDR_ARG {
            __sockaddr__: &mut addr as *mut sockaddr_storage as *mut sockaddr,
        },
        &mut addrlen,
    ) != 0 as libc::c_int
    {
        return 0 as *mut libc::c_char;
    }
    if addr.ss_family as libc::c_int == 10 as libc::c_int {
        addrlen = ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong as socklen_t;
        ipv64_normalise_mapped(&mut addr, &mut addrlen);
    }
    match addr.ss_family as libc::c_int {
        2 | 10 => {
            r = getnameinfo(
                &mut addr as *mut sockaddr_storage as *mut sockaddr,
                addrlen,
                ntop.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as socklen_t,
                0 as *mut libc::c_char,
                0 as libc::c_int as socklen_t,
                flags,
            );
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"canohost.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"get_socket_address\0",
                    ))
                    .as_ptr(),
                    103 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"getnameinfo %d failed: %s\0" as *const u8 as *const libc::c_char,
                    flags,
                    ssh_gai_strerror(r),
                );
                return 0 as *mut libc::c_char;
            }
            return xstrdup(ntop.as_mut_ptr());
        }
        1 => {
            return xstrdup(
                ((*(&mut addr as *mut sockaddr_storage as *mut sockaddr_un)).sun_path).as_mut_ptr(),
            );
        }
        _ => return 0 as *mut libc::c_char,
    };
}
pub unsafe extern "C" fn get_peer_ipaddr(mut sock: libc::c_int) -> *mut libc::c_char {
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    p = get_socket_address(sock, 1 as libc::c_int, 1 as libc::c_int);
    if !p.is_null() {
        return p;
    }
    return xstrdup(b"UNKNOWN\0" as *const u8 as *const libc::c_char);
}
pub unsafe extern "C" fn get_local_ipaddr(mut sock: libc::c_int) -> *mut libc::c_char {
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    p = get_socket_address(sock, 0 as libc::c_int, 1 as libc::c_int);
    if !p.is_null() {
        return p;
    }
    return xstrdup(b"UNKNOWN\0" as *const u8 as *const libc::c_char);
}
pub unsafe extern "C" fn get_local_name(mut fd: libc::c_int) -> *mut libc::c_char {
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut myname: [libc::c_char; 1025] = [0; 1025];
    host = get_socket_address(fd, 0 as libc::c_int, 8 as libc::c_int);
    if !host.is_null() {
        return host;
    }
    if gethostname(
        myname.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"canohost.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"get_local_name\0"))
                .as_ptr(),
            147 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"gethostname: %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        host = xstrdup(b"UNKNOWN\0" as *const u8 as *const libc::c_char);
    } else {
        host = xstrdup(myname.as_mut_ptr());
    }
    return host;
}
unsafe extern "C" fn get_sock_port(mut sock: libc::c_int, mut local: libc::c_int) -> libc::c_int {
    let mut from: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut fromlen: socklen_t = 0;
    let mut strport: [libc::c_char; 32] = [0; 32];
    let mut r: libc::c_int = 0;
    if sock < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    fromlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    memset(
        &mut from as *mut sockaddr_storage as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong,
    );
    if local != 0 {
        if getsockname(
            sock,
            __SOCKADDR_ARG {
                __sockaddr__: &mut from as *mut sockaddr_storage as *mut sockaddr,
            },
            &mut fromlen,
        ) == -(1 as libc::c_int)
        {
            crate::log::sshlog(
                b"canohost.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"get_sock_port\0"))
                    .as_ptr(),
                173 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"getsockname failed: %.100s\0" as *const u8 as *const libc::c_char,
                strerror(*__errno_location()),
            );
            return 0 as libc::c_int;
        }
    } else if getpeername(
        sock,
        __SOCKADDR_ARG {
            __sockaddr__: &mut from as *mut sockaddr_storage as *mut sockaddr,
        },
        &mut fromlen,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"canohost.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"get_sock_port\0"))
                .as_ptr(),
            178 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"getpeername failed: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if from.ss_family as libc::c_int == 10 as libc::c_int {
        fromlen = ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong as socklen_t;
    }
    if from.ss_family as libc::c_int != 2 as libc::c_int
        && from.ss_family as libc::c_int != 10 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    r = getnameinfo(
        &mut from as *mut sockaddr_storage as *mut sockaddr,
        fromlen,
        0 as *mut libc::c_char,
        0 as libc::c_int as socklen_t,
        strport.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong as socklen_t,
        2 as libc::c_int,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"canohost.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"get_sock_port\0"))
                .as_ptr(),
            195 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"getnameinfo NI_NUMERICSERV failed: %s\0" as *const u8 as *const libc::c_char,
            ssh_gai_strerror(r),
        );
    }
    return atoi(strport.as_mut_ptr());
}
pub unsafe extern "C" fn get_peer_port(mut sock: libc::c_int) -> libc::c_int {
    return get_sock_port(sock, 0 as libc::c_int);
}
pub unsafe extern "C" fn get_local_port(mut sock: libc::c_int) -> libc::c_int {
    return get_sock_port(sock, 1 as libc::c_int);
}
