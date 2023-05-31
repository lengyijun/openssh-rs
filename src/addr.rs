use ::libc;
use libc::sockaddr;
extern "C" {
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn getaddrinfo(
        __name: *const libc::c_char,
        __service: *const libc::c_char,
        __req: *const addrinfo,
        __pai: *mut *mut addrinfo,
    ) -> libc::c_int;
    fn freeaddrinfo(__ai: *mut addrinfo);
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

    fn strtoul(_: *const libc::c_char, _: *mut *mut libc::c_char, _: libc::c_int) -> libc::c_ulong;
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
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
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
pub struct addrinfo {
    pub ai_flags: libc::c_int,
    pub ai_family: libc::c_int,
    pub ai_socktype: libc::c_int,
    pub ai_protocol: libc::c_int,
    pub ai_addrlen: socklen_t,
    pub ai_addr: *mut sockaddr,
    pub ai_canonname: *mut libc::c_char,
    pub ai_next: *mut addrinfo,
}
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
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
pub unsafe extern "C" fn addr_unicast_masklen(mut af: libc::c_int) -> libc::c_int {
    match af {
        2 => return 32 as libc::c_int,
        10 => return 128 as libc::c_int,
        _ => return -(1 as libc::c_int),
    };
}
#[inline]
unsafe extern "C" fn masklen_valid(mut af: libc::c_int, mut masklen: u_int) -> libc::c_int {
    match af {
        2 => {
            return if masklen <= 32 as libc::c_int as libc::c_uint {
                0 as libc::c_int
            } else {
                -(1 as libc::c_int)
            };
        }
        10 => {
            return if masklen <= 128 as libc::c_int as libc::c_uint {
                0 as libc::c_int
            } else {
                -(1 as libc::c_int)
            };
        }
        _ => return -(1 as libc::c_int),
    };
}
pub unsafe extern "C" fn addr_xaddr_to_sa(
    mut xa: *const xaddr,
    mut sa: *mut sockaddr,
    mut len: *mut socklen_t,
    mut port: u_int16_t,
) -> libc::c_int {
    let mut in4: *mut sockaddr_in = sa as *mut sockaddr_in;
    let mut in6: *mut sockaddr_in6 = sa as *mut sockaddr_in6;
    if xa.is_null() || sa.is_null() || len.is_null() {
        return -(1 as libc::c_int);
    }
    match (*xa).af as libc::c_int {
        2 => {
            if (*len as libc::c_ulong) < ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong {
                return -(1 as libc::c_int);
            }
            memset(
                sa as *mut libc::c_void,
                '\0' as i32,
                ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong,
            );
            *len = ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong as socklen_t;
            (*in4).sin_family = 2 as libc::c_int as sa_family_t;
            (*in4).sin_port = __bswap_16(port);
            memcpy(
                &mut (*in4).sin_addr as *mut in_addr as *mut libc::c_void,
                &(*xa).xa.v4 as *const in_addr as *const libc::c_void,
                ::core::mem::size_of::<in_addr>() as libc::c_ulong,
            );
        }
        10 => {
            if (*len as libc::c_ulong) < ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong {
                return -(1 as libc::c_int);
            }
            memset(
                sa as *mut libc::c_void,
                '\0' as i32,
                ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
            );
            *len = ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong as socklen_t;
            (*in6).sin6_family = 10 as libc::c_int as sa_family_t;
            (*in6).sin6_port = __bswap_16(port);
            memcpy(
                &mut (*in6).sin6_addr as *mut in6_addr as *mut libc::c_void,
                &(*xa).xa.v6 as *const in6_addr as *const libc::c_void,
                ::core::mem::size_of::<in6_addr>() as libc::c_ulong,
            );
            (*in6).sin6_scope_id = (*xa).scope_id;
        }
        _ => return -(1 as libc::c_int),
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn addr_sa_to_xaddr(
    mut sa: *mut sockaddr,
    mut slen: socklen_t,
    mut xa: *mut xaddr,
) -> libc::c_int {
    let mut in4: *mut sockaddr_in = sa as *mut sockaddr_in;
    let mut in6: *mut sockaddr_in6 = sa as *mut sockaddr_in6;
    memset(
        xa as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<xaddr>() as libc::c_ulong,
    );
    match (*sa).sa_family as libc::c_int {
        2 => {
            if slen < ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong as socklen_t {
                return -(1 as libc::c_int);
            }
            (*xa).af = 2 as libc::c_int as sa_family_t;
            memcpy(
                &mut (*xa).xa.v4 as *mut in_addr as *mut libc::c_void,
                &mut (*in4).sin_addr as *mut in_addr as *const libc::c_void,
                ::core::mem::size_of::<in_addr>() as libc::c_ulong,
            );
        }
        10 => {
            if slen < ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong as socklen_t {
                return -(1 as libc::c_int);
            }
            (*xa).af = 10 as libc::c_int as sa_family_t;
            memcpy(
                &mut (*xa).xa.v6 as *mut in6_addr as *mut libc::c_void,
                &mut (*in6).sin6_addr as *mut in6_addr as *const libc::c_void,
                ::core::mem::size_of::<in6_addr>() as libc::c_ulong,
            );
            (*xa).scope_id = (*in6).sin6_scope_id;
        }
        _ => return -(1 as libc::c_int),
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn addr_invert(mut n: *mut xaddr) -> libc::c_int {
    let mut i: libc::c_int = 0;
    if n.is_null() {
        return -(1 as libc::c_int);
    }
    match (*n).af as libc::c_int {
        2 => {
            (*n).xa.v4.s_addr = !(*n).xa.v4.s_addr;
            return 0 as libc::c_int;
        }
        10 => {
            i = 0 as libc::c_int;
            while i < 4 as libc::c_int {
                (*n).xa.addr32[i as usize] = !(*n).xa.addr32[i as usize];
                i += 1;
                i;
            }
            return 0 as libc::c_int;
        }
        _ => return -(1 as libc::c_int),
    };
}
pub unsafe extern "C" fn addr_netmask(
    mut af: libc::c_int,
    mut l: u_int,
    mut n: *mut xaddr,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    if masklen_valid(af, l) != 0 as libc::c_int || n.is_null() {
        return -(1 as libc::c_int);
    }
    memset(
        n as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<xaddr>() as libc::c_ulong,
    );
    match af {
        2 => {
            (*n).af = 2 as libc::c_int as sa_family_t;
            if l == 0 as libc::c_int as libc::c_uint {
                return 0 as libc::c_int;
            }
            (*n).xa.v4.s_addr = __bswap_32(
                (0xffffffff as libc::c_uint) << (32 as libc::c_int as libc::c_uint).wrapping_sub(l)
                    & 0xffffffff as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        10 => {
            (*n).af = 10 as libc::c_int as sa_family_t;
            i = 0 as libc::c_int;
            while i < 4 as libc::c_int && l >= 32 as libc::c_int as libc::c_uint {
                (*n).xa.addr32[i as usize] = 0xffffffff as libc::c_uint;
                i += 1;
                i;
                l = (l as libc::c_uint).wrapping_sub(32 as libc::c_int as libc::c_uint) as u_int
                    as u_int;
            }
            if i < 4 as libc::c_int && l != 0 as libc::c_int as libc::c_uint {
                (*n).xa.addr32[i as usize] = __bswap_32(
                    (0xffffffff as libc::c_uint)
                        << (32 as libc::c_int as libc::c_uint).wrapping_sub(l)
                        & 0xffffffff as libc::c_uint,
                );
            }
            return 0 as libc::c_int;
        }
        _ => return -(1 as libc::c_int),
    };
}
pub unsafe extern "C" fn addr_hostmask(
    mut af: libc::c_int,
    mut l: u_int,
    mut n: *mut xaddr,
) -> libc::c_int {
    if addr_netmask(af, l, n) == -(1 as libc::c_int) || addr_invert(n) == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn addr_and(
    mut dst: *mut xaddr,
    mut a: *const xaddr,
    mut b: *const xaddr,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    if dst.is_null()
        || a.is_null()
        || b.is_null()
        || (*a).af as libc::c_int != (*b).af as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    memcpy(
        dst as *mut libc::c_void,
        a as *const libc::c_void,
        ::core::mem::size_of::<xaddr>() as libc::c_ulong,
    );
    match (*a).af as libc::c_int {
        2 => {
            (*dst).xa.v4.s_addr &= (*b).xa.v4.s_addr;
            return 0 as libc::c_int;
        }
        10 => {
            (*dst).scope_id = (*a).scope_id;
            i = 0 as libc::c_int;
            while i < 4 as libc::c_int {
                (*dst).xa.addr32[i as usize] &= (*b).xa.addr32[i as usize];
                i += 1;
                i;
            }
            return 0 as libc::c_int;
        }
        _ => return -(1 as libc::c_int),
    };
}
pub unsafe extern "C" fn addr_or(
    mut dst: *mut xaddr,
    mut a: *const xaddr,
    mut b: *const xaddr,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    if dst.is_null()
        || a.is_null()
        || b.is_null()
        || (*a).af as libc::c_int != (*b).af as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    memcpy(
        dst as *mut libc::c_void,
        a as *const libc::c_void,
        ::core::mem::size_of::<xaddr>() as libc::c_ulong,
    );
    match (*a).af as libc::c_int {
        2 => {
            (*dst).xa.v4.s_addr |= (*b).xa.v4.s_addr;
            return 0 as libc::c_int;
        }
        10 => {
            i = 0 as libc::c_int;
            while i < 4 as libc::c_int {
                (*dst).xa.addr32[i as usize] |= (*b).xa.addr32[i as usize];
                i += 1;
                i;
            }
            return 0 as libc::c_int;
        }
        _ => return -(1 as libc::c_int),
    };
}
pub unsafe extern "C" fn addr_cmp(mut a: *const xaddr, mut b: *const xaddr) -> libc::c_int {
    let mut i: libc::c_int = 0;
    if (*a).af as libc::c_int != (*b).af as libc::c_int {
        return if (*a).af as libc::c_int == 10 as libc::c_int {
            1 as libc::c_int
        } else {
            -(1 as libc::c_int)
        };
    }
    match (*a).af as libc::c_int {
        2 => {
            if (*a).xa.v4.s_addr == (*b).xa.v4.s_addr {
                return 0 as libc::c_int;
            }
            return if __bswap_32((*a).xa.v4.s_addr) > __bswap_32((*b).xa.v4.s_addr) {
                1 as libc::c_int
            } else {
                -(1 as libc::c_int)
            };
        }
        10 => {
            i = 0 as libc::c_int;
            while i < 16 as libc::c_int {
                if (*a).xa.addr8[i as usize] as libc::c_int
                    - (*b).xa.addr8[i as usize] as libc::c_int
                    != 0 as libc::c_int
                {
                    return (*a).xa.addr8[i as usize] as libc::c_int
                        - (*b).xa.addr8[i as usize] as libc::c_int;
                }
                i += 1;
                i;
            }
            if (*a).scope_id == (*b).scope_id {
                return 0 as libc::c_int;
            }
            return if (*a).scope_id > (*b).scope_id {
                1 as libc::c_int
            } else {
                -(1 as libc::c_int)
            };
        }
        _ => return -(1 as libc::c_int),
    };
}
pub unsafe extern "C" fn addr_is_all0s(mut a: *const xaddr) -> libc::c_int {
    let mut i: libc::c_int = 0;
    match (*a).af as libc::c_int {
        2 => {
            return if (*a).xa.v4.s_addr == 0 as libc::c_int as libc::c_uint {
                0 as libc::c_int
            } else {
                -(1 as libc::c_int)
            };
        }
        10 => {
            i = 0 as libc::c_int;
            while i < 4 as libc::c_int {
                if (*a).xa.addr32[i as usize] != 0 as libc::c_int as libc::c_uint {
                    return -(1 as libc::c_int);
                }
                i += 1;
                i;
            }
            return 0 as libc::c_int;
        }
        _ => return -(1 as libc::c_int),
    };
}
pub unsafe extern "C" fn addr_increment(mut a: *mut xaddr) {
    let mut i: libc::c_int = 0;
    let mut n: uint32_t = 0;
    match (*a).af as libc::c_int {
        2 => {
            (*a).xa.v4.s_addr = __bswap_32(
                (__bswap_32((*a).xa.v4.s_addr)).wrapping_add(1 as libc::c_int as libc::c_uint),
            );
        }
        10 => {
            i = 0 as libc::c_int;
            while i < 4 as libc::c_int {
                n = (__bswap_32((*a).xa.addr32[(3 as libc::c_int - i) as usize]))
                    .wrapping_add(1 as libc::c_int as libc::c_uint);
                (*a).xa.addr32[(3 as libc::c_int - i) as usize] = __bswap_32(n);
                if n != 0 as libc::c_int as libc::c_uint {
                    break;
                }
                i += 1;
                i;
            }
        }
        _ => {}
    };
}
pub unsafe extern "C" fn addr_host_is_all0s(
    mut a: *const xaddr,
    mut masklen: u_int,
) -> libc::c_int {
    let mut tmp_addr: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut tmp_mask: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut tmp_result: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    memcpy(
        &mut tmp_addr as *mut xaddr as *mut libc::c_void,
        a as *const libc::c_void,
        ::core::mem::size_of::<xaddr>() as libc::c_ulong,
    );
    if addr_hostmask((*a).af as libc::c_int, masklen, &mut tmp_mask) == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    if addr_and(&mut tmp_result, &mut tmp_addr, &mut tmp_mask) == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    return addr_is_all0s(&mut tmp_result);
}
pub unsafe extern "C" fn addr_host_to_all1s(mut a: *mut xaddr, mut masklen: u_int) -> libc::c_int {
    let mut tmp_mask: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    if addr_hostmask((*a).af as libc::c_int, masklen, &mut tmp_mask) == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    if addr_or(a, a, &mut tmp_mask) == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn addr_pton(mut p: *const libc::c_char, mut n: *mut xaddr) -> libc::c_int {
    let mut hints: addrinfo = addrinfo {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: 0 as *mut sockaddr,
        ai_canonname: 0 as *mut libc::c_char,
        ai_next: 0 as *mut addrinfo,
    };
    let mut ai: *mut addrinfo = 0 as *mut addrinfo;
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_flags = 0x4 as libc::c_int;
    if p.is_null()
        || getaddrinfo(p, 0 as *const libc::c_char, &mut hints, &mut ai) != 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    if ai.is_null() {
        return -(1 as libc::c_int);
    }
    if ((*ai).ai_addr).is_null() {
        freeaddrinfo(ai);
        return -(1 as libc::c_int);
    }
    if !n.is_null() && addr_sa_to_xaddr((*ai).ai_addr, (*ai).ai_addrlen, n) == -(1 as libc::c_int) {
        freeaddrinfo(ai);
        return -(1 as libc::c_int);
    }
    freeaddrinfo(ai);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn addr_sa_pton(
    mut h: *const libc::c_char,
    mut s: *const libc::c_char,
    mut sa: *mut sockaddr,
    mut slen: socklen_t,
) -> libc::c_int {
    let mut hints: addrinfo = addrinfo {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: 0 as *mut sockaddr,
        ai_canonname: 0 as *mut libc::c_char,
        ai_next: 0 as *mut addrinfo,
    };
    let mut ai: *mut addrinfo = 0 as *mut addrinfo;
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_flags = 0x4 as libc::c_int;
    if h.is_null() || getaddrinfo(h, s, &mut hints, &mut ai) != 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if ai.is_null() {
        return -(1 as libc::c_int);
    }
    if ((*ai).ai_addr).is_null() {
        freeaddrinfo(ai);
        return -(1 as libc::c_int);
    }
    if !sa.is_null() {
        if slen < (*ai).ai_addrlen {
            freeaddrinfo(ai);
            return -(1 as libc::c_int);
        }
        memcpy(
            sa as *mut libc::c_void,
            &mut (*ai).ai_addr as *mut *mut sockaddr as *const libc::c_void,
            (*ai).ai_addrlen as libc::c_ulong,
        );
    }
    freeaddrinfo(ai);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn addr_ntop(
    mut n: *const xaddr,
    mut p: *mut libc::c_char,
    mut len: size_t,
) -> libc::c_int {
    let mut ss: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut slen: socklen_t =
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    if addr_xaddr_to_sa(
        n,
        &mut ss as *mut sockaddr_storage as *mut sockaddr,
        &mut slen,
        0 as libc::c_int as u_int16_t,
    ) == -(1 as libc::c_int)
    {
        return -(1 as libc::c_int);
    }
    if p.is_null() || len == 0 as libc::c_int as libc::c_ulong {
        return -(1 as libc::c_int);
    }
    if getnameinfo(
        &mut ss as *mut sockaddr_storage as *mut sockaddr,
        slen,
        p,
        len as socklen_t,
        0 as *mut libc::c_char,
        0 as libc::c_int as socklen_t,
        1 as libc::c_int,
    ) != 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn addr_pton_cidr(
    mut p: *const libc::c_char,
    mut n: *mut xaddr,
    mut l: *mut u_int,
) -> libc::c_int {
    let mut tmp: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut masklen: libc::c_ulong = 999 as libc::c_int as libc::c_ulong;
    let mut addrbuf: [libc::c_char; 64] = [0; 64];
    let mut mp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    if p.is_null()
        || strlcpy(
            addrbuf.as_mut_ptr(),
            p,
            ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
        ) >= ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong
    {
        return -(1 as libc::c_int);
    }
    mp = libc::strchr(addrbuf.as_mut_ptr(), '/' as i32);
    if !mp.is_null() {
        *mp = '\0' as i32 as libc::c_char;
        mp = mp.offset(1);
        mp;
        masklen = strtoul(mp, &mut cp, 10 as libc::c_int);
        if (*mp as libc::c_int) < '0' as i32
            || *mp as libc::c_int > '9' as i32
            || *cp as libc::c_int != '\0' as i32
            || masklen > 128 as libc::c_int as libc::c_ulong
        {
            return -(1 as libc::c_int);
        }
    }
    if addr_pton(addrbuf.as_mut_ptr(), &mut tmp) == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    if mp.is_null() {
        masklen = addr_unicast_masklen(tmp.af as libc::c_int) as libc::c_ulong;
    }
    if masklen_valid(tmp.af as libc::c_int, masklen as u_int) == -(1 as libc::c_int) {
        return -(2 as libc::c_int);
    }
    if addr_host_is_all0s(&mut tmp, masklen as u_int) != 0 as libc::c_int {
        return -(2 as libc::c_int);
    }
    if !n.is_null() {
        memcpy(
            n as *mut libc::c_void,
            &mut tmp as *mut xaddr as *const libc::c_void,
            ::core::mem::size_of::<xaddr>() as libc::c_ulong,
        );
    }
    if !l.is_null() {
        *l = masklen as u_int;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn addr_netmatch(
    mut host: *const xaddr,
    mut net: *const xaddr,
    mut masklen: u_int,
) -> libc::c_int {
    let mut tmp_mask: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut tmp_result: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_0 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    if (*host).af as libc::c_int != (*net).af as libc::c_int {
        return -(1 as libc::c_int);
    }
    if addr_netmask((*host).af as libc::c_int, masklen, &mut tmp_mask) == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    if addr_and(&mut tmp_result, host, &mut tmp_mask) == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    return addr_cmp(&mut tmp_result, net);
}
