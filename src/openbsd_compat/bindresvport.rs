use ::libc;
use libc::sockaddr;
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
    fn bind(__fd: libc::c_int, __addr: __CONST_SOCKADDR_ARG, __len: socklen_t) -> libc::c_int;
    fn getsockname(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __len: *mut socklen_t)
        -> libc::c_int;

    fn arc4random_uniform(_: uint32_t) -> uint32_t;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
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
pub union __CONST_SOCKADDR_ARG {
    pub __sockaddr__: *const sockaddr,
    pub __sockaddr_at__: *const sockaddr_at,
    pub __sockaddr_ax25__: *const sockaddr_ax25,
    pub __sockaddr_dl__: *const sockaddr_dl,
    pub __sockaddr_eon__: *const sockaddr_eon,
    pub __sockaddr_in__: *const sockaddr_in,
    pub __sockaddr_in6__: *const sockaddr_in6,
    pub __sockaddr_inarp__: *const sockaddr_inarp,
    pub __sockaddr_ipx__: *const sockaddr_ipx,
    pub __sockaddr_iso__: *const sockaddr_iso,
    pub __sockaddr_ns__: *const sockaddr_ns,
    pub __sockaddr_un__: *const sockaddr_un,
    pub __sockaddr_x25__: *const sockaddr_x25,
}
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
#[no_mangle]
pub unsafe extern "C" fn bindresvport_sa(
    mut sd: libc::c_int,
    mut sa: *mut sockaddr,
) -> libc::c_int {
    let mut error: libc::c_int = 0;
    let mut af: libc::c_int = 0;
    let mut myaddr: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut in_0: *mut sockaddr_in = 0 as *mut sockaddr_in;
    let mut in6: *mut sockaddr_in6 = 0 as *mut sockaddr_in6;
    let mut portp: *mut u_int16_t = 0 as *mut u_int16_t;
    let mut port: u_int16_t = 0;
    let mut salen: socklen_t = 0;
    let mut i: libc::c_int = 0;
    if sa.is_null() {
        memset(
            &mut myaddr as *mut sockaddr_storage as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong,
        );
        sa = &mut myaddr as *mut sockaddr_storage as *mut sockaddr;
        salen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
        if getsockname(sd, __SOCKADDR_ARG { __sockaddr__: sa }, &mut salen) == -(1 as libc::c_int) {
            return -(1 as libc::c_int);
        }
        af = (*sa).sa_family as libc::c_int;
        memset(
            &mut myaddr as *mut sockaddr_storage as *mut libc::c_void,
            0 as libc::c_int,
            salen as size_t,
        );
    } else {
        af = (*sa).sa_family as libc::c_int;
    }
    if af == 2 as libc::c_int {
        in_0 = sa as *mut sockaddr_in;
        salen = ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong as socklen_t;
        portp = &mut (*in_0).sin_port;
    } else if af == 10 as libc::c_int {
        in6 = sa as *mut sockaddr_in6;
        salen = ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong as socklen_t;
        portp = &mut (*in6).sin6_port;
    } else {
        *libc::__errno_location() = 96 as libc::c_int;
        return -(1 as libc::c_int);
    }
    (*sa).sa_family = af as sa_family_t;
    port = __bswap_16(*portp);
    if port as libc::c_int == 0 as libc::c_int {
        port = (arc4random_uniform(
            (1024 as libc::c_int - 1 as libc::c_int - 600 as libc::c_int + 1 as libc::c_int)
                as uint32_t,
        ))
        .wrapping_add(600 as libc::c_int as libc::c_uint) as u_int16_t;
    }
    error = -(1 as libc::c_int);
    i = 0 as libc::c_int;
    while i < 1024 as libc::c_int - 1 as libc::c_int - 600 as libc::c_int + 1 as libc::c_int {
        *portp = __bswap_16(port);
        error = bind(sd, __CONST_SOCKADDR_ARG { __sockaddr__: sa }, salen);
        if error == 0 as libc::c_int {
            break;
        }
        if error < 0 as libc::c_int
            && !(*libc::__errno_location() == 98 as libc::c_int
                || *libc::__errno_location() == 22 as libc::c_int)
        {
            break;
        }
        port = port.wrapping_add(1);
        port;
        if port as libc::c_int > 1024 as libc::c_int - 1 as libc::c_int {
            port = 600 as libc::c_int as u_int16_t;
        }
        i += 1;
        i;
    }
    return error;
}
