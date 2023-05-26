use ::libc;
use libc::close;

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
    pub type sshbuf;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    fn socket(__domain: libc::c_int, __type: libc::c_int, __protocol: libc::c_int) -> libc::c_int;
    fn connect(__fd: libc::c_int, __addr: __CONST_SOCKADDR_ARG, __len: socklen_t) -> libc::c_int;
    fn __errno_location() -> *mut libc::c_int;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn sshbuf_get_string_direct(
        buf: *mut sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_stringb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_string(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_string(
        buf: *mut sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_u8(buf: *mut sshbuf, val: u_char) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_put(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_mutable_ptr(buf: *const sshbuf) -> *mut u_char;
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_reset(buf: *mut sshbuf);
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_new() -> *mut sshbuf;
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_equal_public(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn sshkey_from_blob(_: *const u_char, _: size_t, _: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_to_blob(_: *const sshkey, _: *mut *mut u_char, _: *mut size_t) -> libc::c_int;
    fn sshkey_puts(_: *const sshkey, _: *mut sshbuf) -> libc::c_int;
    fn sshkey_check_sigtype(_: *const u_char, _: size_t, _: *const libc::c_char) -> libc::c_int;
    fn sshkey_private_serialize_maxsign(
        key: *mut sshkey,
        buf: *mut sshbuf,
        maxsign: u_int32_t,
        _: libc::c_int,
    ) -> libc::c_int;

    fn atomicio(
        _: Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        _: libc::c_int,
        _: *mut libc::c_void,
        _: size_t,
    ) -> size_t;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type socklen_t = __socklen_t;
pub type __socket_type = libc::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
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
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type EC_KEY = ec_key_st;
pub type sshkey_types = libc::c_uint;
pub const KEY_UNSPEC: sshkey_types = 14;
pub const KEY_ED25519_SK_CERT: sshkey_types = 13;
pub const KEY_ED25519_SK: sshkey_types = 12;
pub const KEY_ECDSA_SK_CERT: sshkey_types = 11;
pub const KEY_ECDSA_SK: sshkey_types = 10;
pub const KEY_XMSS_CERT: sshkey_types = 9;
pub const KEY_XMSS: sshkey_types = 8;
pub const KEY_ED25519_CERT: sshkey_types = 7;
pub const KEY_ECDSA_CERT: sshkey_types = 6;
pub const KEY_DSA_CERT: sshkey_types = 5;
pub const KEY_RSA_CERT: sshkey_types = 4;
pub const KEY_ED25519: sshkey_types = 3;
pub const KEY_ECDSA: sshkey_types = 2;
pub const KEY_DSA: sshkey_types = 1;
pub const KEY_RSA: sshkey_types = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_cert {
    pub certblob: *mut sshbuf,
    pub type_0: u_int,
    pub serial: u_int64_t,
    pub key_id: *mut libc::c_char,
    pub nprincipals: u_int,
    pub principals: *mut *mut libc::c_char,
    pub valid_after: u_int64_t,
    pub valid_before: u_int64_t,
    pub critical: *mut sshbuf,
    pub extensions: *mut sshbuf,
    pub signature_key: *mut sshkey,
    pub signature_type: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey {
    pub type_0: libc::c_int,
    pub flags: libc::c_int,
    pub rsa: *mut RSA,
    pub dsa: *mut DSA,
    pub ecdsa_nid: libc::c_int,
    pub ecdsa: *mut EC_KEY,
    pub ed25519_sk: *mut u_char,
    pub ed25519_pk: *mut u_char,
    pub xmss_name: *mut libc::c_char,
    pub xmss_filename: *mut libc::c_char,
    pub xmss_state: *mut libc::c_void,
    pub xmss_sk: *mut u_char,
    pub xmss_pk: *mut u_char,
    pub sk_application: *mut libc::c_char,
    pub sk_flags: uint8_t,
    pub sk_key_handle: *mut sshbuf,
    pub sk_reserved: *mut sshbuf,
    pub cert: *mut sshkey_cert,
    pub shielded_private: *mut u_char,
    pub shielded_len: size_t,
    pub shield_prekey: *mut u_char,
    pub shield_prekey_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh_identitylist {
    pub nkeys: size_t,
    pub keys: *mut *mut sshkey,
    pub comments: *mut *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dest_constraint_hop {
    pub user: *mut libc::c_char,
    pub hostname: *mut libc::c_char,
    pub is_ca: libc::c_int,
    pub nkeys: u_int,
    pub keys: *mut *mut sshkey,
    pub key_is_ca: *mut libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dest_constraint {
    pub from: dest_constraint_hop,
    pub to: dest_constraint_hop,
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
unsafe extern "C" fn decode_reply(mut type_0: u_char) -> libc::c_int {
    if type_0 as libc::c_int == 5 as libc::c_int
        || type_0 as libc::c_int == 102 as libc::c_int
        || type_0 as libc::c_int == 30 as libc::c_int
    {
        return -(27 as libc::c_int);
    } else if type_0 as libc::c_int == 6 as libc::c_int {
        return 0 as libc::c_int;
    } else {
        return -(4 as libc::c_int);
    };
}
pub unsafe extern "C" fn ssh_get_authentication_socket_path(
    mut authsocket: *const libc::c_char,
    mut fdp: *mut libc::c_int,
) -> libc::c_int {
    let mut sock: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    let mut sunaddr: sockaddr_un = sockaddr_un {
        sun_family: 0,
        sun_path: [0; 108],
    };
    crate::log::sshlog(
        b"authfd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 35], &[libc::c_char; 35]>(
            b"ssh_get_authentication_socket_path\0",
        ))
        .as_ptr(),
        94 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"path '%s'\0" as *const u8 as *const libc::c_char,
        authsocket,
    );
    memset(
        &mut sunaddr as *mut sockaddr_un as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_un>() as libc::c_ulong,
    );
    sunaddr.sun_family = 1 as libc::c_int as sa_family_t;
    strlcpy(
        (sunaddr.sun_path).as_mut_ptr(),
        authsocket,
        ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong,
    );
    sock = socket(
        1 as libc::c_int,
        SOCK_STREAM as libc::c_int,
        0 as libc::c_int,
    );
    if sock == -(1 as libc::c_int) {
        return -(24 as libc::c_int);
    }
    if fcntl(sock, 2 as libc::c_int, 1 as libc::c_int) == -(1 as libc::c_int)
        || connect(
            sock,
            __CONST_SOCKADDR_ARG {
                __sockaddr__: &mut sunaddr as *mut sockaddr_un as *mut sockaddr,
            },
            ::core::mem::size_of::<sockaddr_un>() as libc::c_ulong as socklen_t,
        ) == -(1 as libc::c_int)
    {
        oerrno = *__errno_location();
        close(sock);
        *__errno_location() = oerrno;
        return -(24 as libc::c_int);
    }
    if !fdp.is_null() {
        *fdp = sock;
    } else {
        close(sock);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_get_authentication_socket(mut fdp: *mut libc::c_int) -> libc::c_int {
    let mut authsocket: *const libc::c_char = 0 as *const libc::c_char;
    if !fdp.is_null() {
        *fdp = -(1 as libc::c_int);
    }
    authsocket = getenv(b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char);
    if authsocket.is_null() || *authsocket as libc::c_int == '\0' as i32 {
        return -(47 as libc::c_int);
    }
    return ssh_get_authentication_socket_path(authsocket, fdp);
}
unsafe extern "C" fn ssh_request_reply(
    mut sock: libc::c_int,
    mut request: *mut sshbuf,
    mut reply: *mut sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut l: size_t = 0;
    let mut len: size_t = 0;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    len = sshbuf_len(request);
    let __v: u_int32_t = len as u_int32_t;
    *(buf.as_mut_ptr() as *mut u_char).offset(0 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *(buf.as_mut_ptr() as *mut u_char).offset(1 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *(buf.as_mut_ptr() as *mut u_char).offset(2 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *(buf.as_mut_ptr() as *mut u_char).offset(3 as libc::c_int as isize) =
        (__v & 0xff as libc::c_int as libc::c_uint) as u_char;
    if atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        sock,
        buf.as_mut_ptr() as *mut libc::c_void,
        4 as libc::c_int as size_t,
    ) != 4 as libc::c_int as libc::c_ulong
        || atomicio(
            ::core::mem::transmute::<
                Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
                Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
            >(Some(
                write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
            )),
            sock,
            sshbuf_mutable_ptr(request) as *mut libc::c_void,
            sshbuf_len(request),
        ) != sshbuf_len(request)
    {
        return -(26 as libc::c_int);
    }
    if atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        sock,
        buf.as_mut_ptr() as *mut libc::c_void,
        4 as libc::c_int as size_t,
    ) != 4 as libc::c_int as libc::c_ulong
    {
        return -(26 as libc::c_int);
    }
    len = ((*(buf.as_mut_ptr() as *const u_char).offset(0 as libc::c_int as isize) as u_int32_t)
        << 24 as libc::c_int
        | (*(buf.as_mut_ptr() as *const u_char).offset(1 as libc::c_int as isize) as u_int32_t)
            << 16 as libc::c_int
        | (*(buf.as_mut_ptr() as *const u_char).offset(2 as libc::c_int as isize) as u_int32_t)
            << 8 as libc::c_int
        | *(buf.as_mut_ptr() as *const u_char).offset(3 as libc::c_int as isize) as u_int32_t)
        as size_t;
    if len > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_ulong {
        return -(4 as libc::c_int);
    }
    sshbuf_reset(reply);
    while len > 0 as libc::c_int as libc::c_ulong {
        l = len;
        if l > ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong {
            l = ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong;
        }
        if atomicio(
            Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
            sock,
            buf.as_mut_ptr() as *mut libc::c_void,
            l,
        ) != l
        {
            return -(26 as libc::c_int);
        }
        r = sshbuf_put(reply, buf.as_mut_ptr() as *const libc::c_void, l);
        if r != 0 as libc::c_int {
            return r;
        }
        len = (len as libc::c_ulong).wrapping_sub(l) as size_t as size_t;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_request_reply_decode(
    mut sock: libc::c_int,
    mut request: *mut sshbuf,
) -> libc::c_int {
    let mut reply: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    let mut type_0: u_char = 0;
    reply = sshbuf_new();
    if reply.is_null() {
        return -(2 as libc::c_int);
    }
    r = ssh_request_reply(sock, request, reply);
    if !(r != 0 as libc::c_int
        || {
            r = sshbuf_get_u8(reply, &mut type_0);
            r != 0 as libc::c_int
        }
        || {
            r = decode_reply(type_0);
            r != 0 as libc::c_int
        })
    {
        r = 0 as libc::c_int;
    }
    sshbuf_free(reply);
    return r;
}
pub unsafe extern "C" fn ssh_close_authentication_socket(mut sock: libc::c_int) {
    if !(getenv(b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char)).is_null() {
        close(sock);
    }
}
pub unsafe extern "C" fn ssh_lock_agent(
    mut sock: libc::c_int,
    mut lock: libc::c_int,
    mut password: *const libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut type_0: u_char = (if lock != 0 {
        22 as libc::c_int
    } else {
        23 as libc::c_int
    }) as u_char;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    msg = sshbuf_new();
    if msg.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put_u8(msg, type_0);
    if !(r != 0 as libc::c_int
        || {
            r = sshbuf_put_cstring(msg, password);
            r != 0 as libc::c_int
        }
        || {
            r = ssh_request_reply_decode(sock, msg);
            r != 0 as libc::c_int
        })
    {
        r = 0 as libc::c_int;
    }
    sshbuf_free(msg);
    return r;
}
unsafe extern "C" fn deserialise_identity2(
    mut ids: *mut sshbuf,
    mut keyp: *mut *mut sshkey,
    mut commentp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut blob: *const u_char = 0 as *const u_char;
    let mut blen: size_t = 0;
    r = sshbuf_get_string_direct(ids, &mut blob, &mut blen);
    if !(r != 0 as libc::c_int || {
        r = sshbuf_get_cstring(ids, &mut comment, 0 as *mut size_t);
        r != 0 as libc::c_int
    }) {
        r = sshkey_from_blob(blob, blen, keyp);
        if !(r != 0 as libc::c_int) {
            if !commentp.is_null() {
                *commentp = comment;
                comment = 0 as *mut libc::c_char;
            }
            r = 0 as libc::c_int;
        }
    }
    free(comment as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn ssh_fetch_identitylist(
    mut sock: libc::c_int,
    mut idlp: *mut *mut ssh_identitylist,
) -> libc::c_int {
    let mut current_block: u64;
    let mut type_0: u_char = 0;
    let mut num: u_int32_t = 0;
    let mut i: u_int32_t = 0;
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut idl: *mut ssh_identitylist = 0 as *mut ssh_identitylist;
    let mut r: libc::c_int = 0;
    msg = sshbuf_new();
    if msg.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put_u8(msg, 11 as libc::c_int as u_char);
    if !(r != 0 as libc::c_int) {
        r = ssh_request_reply(sock, msg, msg);
        if !(r != 0 as libc::c_int) {
            r = sshbuf_get_u8(msg, &mut type_0);
            if !(r != 0 as libc::c_int) {
                if type_0 as libc::c_int == 5 as libc::c_int
                    || type_0 as libc::c_int == 102 as libc::c_int
                    || type_0 as libc::c_int == 30 as libc::c_int
                {
                    r = -(27 as libc::c_int);
                } else if type_0 as libc::c_int != 12 as libc::c_int {
                    r = -(4 as libc::c_int);
                } else {
                    r = sshbuf_get_u32(msg, &mut num);
                    if !(r != 0 as libc::c_int) {
                        if num > 2048 as libc::c_int as libc::c_uint {
                            r = -(4 as libc::c_int);
                        } else if num == 0 as libc::c_int as libc::c_uint {
                            r = -(48 as libc::c_int);
                        } else {
                            idl = calloc(
                                1 as libc::c_int as libc::c_ulong,
                                ::core::mem::size_of::<ssh_identitylist>() as libc::c_ulong,
                            ) as *mut ssh_identitylist;
                            if idl.is_null()
                                || {
                                    (*idl).keys = calloc(
                                        num as libc::c_ulong,
                                        ::core::mem::size_of::<*mut sshkey>() as libc::c_ulong,
                                    )
                                        as *mut *mut sshkey;
                                    ((*idl).keys).is_null()
                                }
                                || {
                                    (*idl).comments = calloc(
                                        num as libc::c_ulong,
                                        ::core::mem::size_of::<*mut libc::c_char>()
                                            as libc::c_ulong,
                                    )
                                        as *mut *mut libc::c_char;
                                    ((*idl).comments).is_null()
                                }
                            {
                                r = -(2 as libc::c_int);
                            } else {
                                i = 0 as libc::c_int as u_int32_t;
                                loop {
                                    if !(i < num) {
                                        current_block = 13472856163611868459;
                                        break;
                                    }
                                    r = deserialise_identity2(
                                        msg,
                                        &mut *((*idl).keys).offset(i as isize),
                                        &mut *((*idl).comments).offset(i as isize),
                                    );
                                    if r != 0 as libc::c_int {
                                        if !(r == -(14 as libc::c_int)) {
                                            current_block = 12827022141075416476;
                                            break;
                                        }
                                        num = num.wrapping_sub(1);
                                        num;
                                    } else {
                                        i = i.wrapping_add(1);
                                        i;
                                    }
                                }
                                match current_block {
                                    12827022141075416476 => {}
                                    _ => {
                                        (*idl).nkeys = num as size_t;
                                        *idlp = idl;
                                        idl = 0 as *mut ssh_identitylist;
                                        r = 0 as libc::c_int;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    sshbuf_free(msg);
    if !idl.is_null() {
        ssh_free_identitylist(idl);
    }
    return r;
}
pub unsafe extern "C" fn ssh_free_identitylist(mut idl: *mut ssh_identitylist) {
    let mut i: size_t = 0;
    if idl.is_null() {
        return;
    }
    i = 0 as libc::c_int as size_t;
    while i < (*idl).nkeys {
        if !((*idl).keys).is_null() {
            sshkey_free(*((*idl).keys).offset(i as isize));
        }
        if !((*idl).comments).is_null() {
            free(*((*idl).comments).offset(i as isize) as *mut libc::c_void);
        }
        i = i.wrapping_add(1);
        i;
    }
    free((*idl).keys as *mut libc::c_void);
    free((*idl).comments as *mut libc::c_void);
    free(idl as *mut libc::c_void);
}
pub unsafe extern "C" fn ssh_agent_has_key(
    mut sock: libc::c_int,
    mut key: *const sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(46 as libc::c_int);
    let mut i: size_t = 0;
    let mut idlist: *mut ssh_identitylist = 0 as *mut ssh_identitylist;
    r = ssh_fetch_identitylist(sock, &mut idlist);
    if r != 0 as libc::c_int {
        return r;
    }
    i = 0 as libc::c_int as size_t;
    while i < (*idlist).nkeys {
        if sshkey_equal_public(*((*idlist).keys).offset(i as isize), key) != 0 {
            ret = 0 as libc::c_int;
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    ssh_free_identitylist(idlist);
    return ret;
}
unsafe extern "C" fn agent_encode_alg(
    mut key: *const sshkey,
    mut alg: *const libc::c_char,
) -> u_int {
    if !alg.is_null() && sshkey_type_plain((*key).type_0) == KEY_RSA as libc::c_int {
        if strcmp(alg, b"rsa-sha2-256\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            || strcmp(
                alg,
                b"rsa-sha2-256-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            return 0x2 as libc::c_int as u_int;
        }
        if strcmp(alg, b"rsa-sha2-512\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            || strcmp(
                alg,
                b"rsa-sha2-512-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            return 0x4 as libc::c_int as u_int;
        }
    }
    return 0 as libc::c_int as u_int;
}
pub unsafe extern "C" fn ssh_agent_sign(
    mut sock: libc::c_int,
    mut key: *const sshkey,
    mut sigp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut data: *const u_char,
    mut datalen: size_t,
    mut alg: *const libc::c_char,
    mut _compat: u_int,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut type_0: u_char = 0 as libc::c_int as u_char;
    let mut len: size_t = 0 as libc::c_int as size_t;
    let mut flags: u_int = 0 as libc::c_int as u_int;
    let mut r: libc::c_int = -(1 as libc::c_int);
    *sigp = 0 as *mut u_char;
    *lenp = 0 as libc::c_int as size_t;
    if datalen > ((1 as libc::c_int) << 20 as libc::c_int) as libc::c_ulong {
        return -(10 as libc::c_int);
    }
    msg = sshbuf_new();
    if msg.is_null() {
        return -(2 as libc::c_int);
    }
    flags |= agent_encode_alg(key, alg);
    r = sshbuf_put_u8(msg, 13 as libc::c_int as u_char);
    if !(r != 0 as libc::c_int
        || {
            r = sshkey_puts(key, msg);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(msg, data as *const libc::c_void, datalen);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(msg, flags);
            r != 0 as libc::c_int
        })
    {
        r = ssh_request_reply(sock, msg, msg);
        if !(r != 0 as libc::c_int) {
            r = sshbuf_get_u8(msg, &mut type_0);
            if !(r != 0 as libc::c_int) {
                if type_0 as libc::c_int == 5 as libc::c_int
                    || type_0 as libc::c_int == 102 as libc::c_int
                    || type_0 as libc::c_int == 30 as libc::c_int
                {
                    r = -(27 as libc::c_int);
                } else if type_0 as libc::c_int != 14 as libc::c_int {
                    r = -(4 as libc::c_int);
                } else {
                    r = sshbuf_get_string(msg, &mut sig, &mut len);
                    if !(r != 0 as libc::c_int) {
                        r = sshkey_check_sigtype(sig, len, alg);
                        if !(r != 0 as libc::c_int) {
                            *sigp = sig;
                            *lenp = len;
                            sig = 0 as *mut u_char;
                            len = 0 as libc::c_int as size_t;
                            r = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    freezero(sig as *mut libc::c_void, len);
    sshbuf_free(msg);
    return r;
}
unsafe extern "C" fn encode_dest_constraint_hop(
    mut m: *mut sshbuf,
    mut dch: *const dest_constraint_hop,
) -> libc::c_int {
    let mut current_block: u64;
    let mut b: *mut sshbuf = 0 as *mut sshbuf;
    let mut i: u_int = 0;
    let mut r: libc::c_int = 0;
    b = sshbuf_new();
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put_cstring(b, (*dch).user);
    if !(r != 0 as libc::c_int
        || {
            r = sshbuf_put_cstring(b, (*dch).hostname);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(b, 0 as *const libc::c_void, 0 as libc::c_int as size_t);
            r != 0 as libc::c_int
        })
    {
        i = 0 as libc::c_int as u_int;
        loop {
            if !(i < (*dch).nkeys) {
                current_block = 10879442775620481940;
                break;
            }
            r = sshkey_puts(*((*dch).keys).offset(i as isize), b);
            if r != 0 as libc::c_int || {
                r = sshbuf_put_u8(
                    b,
                    (*((*dch).key_is_ca).offset(i as isize) != 0 as libc::c_int) as libc::c_int
                        as u_char,
                );
                r != 0 as libc::c_int
            } {
                current_block = 8205818978362050805;
                break;
            }
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            8205818978362050805 => {}
            _ => {
                r = sshbuf_put_stringb(m, b);
                if !(r != 0 as libc::c_int) {
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    sshbuf_free(b);
    return r;
}
unsafe extern "C" fn encode_dest_constraint(
    mut m: *mut sshbuf,
    mut dc: *const dest_constraint,
) -> libc::c_int {
    let mut b: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    b = sshbuf_new();
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    r = encode_dest_constraint_hop(b, &(*dc).from);
    if !(r != 0 as libc::c_int
        || {
            r = encode_dest_constraint_hop(b, &(*dc).to);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(b, 0 as *const libc::c_void, 0 as libc::c_int as size_t);
            r != 0 as libc::c_int
        })
    {
        r = sshbuf_put_stringb(m, b);
        if !(r != 0 as libc::c_int) {
            r = 0 as libc::c_int;
        }
    }
    sshbuf_free(b);
    return r;
}
unsafe extern "C" fn encode_constraints(
    mut m: *mut sshbuf,
    mut life: u_int,
    mut confirm: u_int,
    mut maxsign: u_int,
    mut provider: *const libc::c_char,
    mut dest_constraints: *mut *mut dest_constraint,
    mut ndest_constraints: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = 0;
    let mut b: *mut sshbuf = 0 as *mut sshbuf;
    let mut i: size_t = 0;
    if life != 0 as libc::c_int as libc::c_uint {
        r = sshbuf_put_u8(m, 1 as libc::c_int as u_char);
        if r != 0 as libc::c_int || {
            r = sshbuf_put_u32(m, life);
            r != 0 as libc::c_int
        } {
            current_block = 4970921734680953786;
        } else {
            current_block = 16658872821858055392;
        }
    } else {
        current_block = 16658872821858055392;
    }
    match current_block {
        16658872821858055392 => {
            if confirm != 0 as libc::c_int as libc::c_uint {
                r = sshbuf_put_u8(m, 2 as libc::c_int as u_char);
                if r != 0 as libc::c_int {
                    current_block = 4970921734680953786;
                } else {
                    current_block = 6873731126896040597;
                }
            } else {
                current_block = 6873731126896040597;
            }
            match current_block {
                4970921734680953786 => {}
                _ => {
                    if maxsign != 0 as libc::c_int as libc::c_uint {
                        r = sshbuf_put_u8(m, 3 as libc::c_int as u_char);
                        if r != 0 as libc::c_int || {
                            r = sshbuf_put_u32(m, maxsign);
                            r != 0 as libc::c_int
                        } {
                            current_block = 4970921734680953786;
                        } else {
                            current_block = 14523784380283086299;
                        }
                    } else {
                        current_block = 14523784380283086299;
                    }
                    match current_block {
                        4970921734680953786 => {}
                        _ => {
                            if !provider.is_null() {
                                r = sshbuf_put_u8(m, 255 as libc::c_int as u_char);
                                if r != 0 as libc::c_int
                                    || {
                                        r = sshbuf_put_cstring(
                                            m,
                                            b"sk-provider@openssh.com\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        r != 0 as libc::c_int
                                    }
                                    || {
                                        r = sshbuf_put_cstring(m, provider);
                                        r != 0 as libc::c_int
                                    }
                                {
                                    current_block = 4970921734680953786;
                                } else {
                                    current_block = 2868539653012386629;
                                }
                            } else {
                                current_block = 2868539653012386629;
                            }
                            match current_block {
                                4970921734680953786 => {}
                                _ => {
                                    if !dest_constraints.is_null()
                                        && ndest_constraints > 0 as libc::c_int as libc::c_ulong
                                    {
                                        b = sshbuf_new();
                                        if b.is_null() {
                                            r = -(2 as libc::c_int);
                                            current_block = 4970921734680953786;
                                        } else {
                                            i = 0 as libc::c_int as size_t;
                                            loop {
                                                if !(i < ndest_constraints) {
                                                    current_block = 5143058163439228106;
                                                    break;
                                                }
                                                r = encode_dest_constraint(
                                                    b,
                                                    *dest_constraints.offset(i as isize),
                                                );
                                                if r != 0 as libc::c_int {
                                                    current_block = 4970921734680953786;
                                                    break;
                                                }
                                                i = i.wrapping_add(1);
                                                i;
                                            }
                                            match current_block {
                                                4970921734680953786 => {}
                                                _ => {
                                                    r = sshbuf_put_u8(
                                                        m,
                                                        255 as libc::c_int as u_char,
                                                    );
                                                    if r != 0 as libc::c_int
                                                        || {
                                                            r = sshbuf_put_cstring(
                                                                m,
                                                                b"restrict-destination-v00@openssh.com\0" as *const u8
                                                                    as *const libc::c_char,
                                                            );
                                                            r != 0 as libc::c_int
                                                        }
                                                        || {
                                                            r = sshbuf_put_stringb(m, b);
                                                            r != 0 as libc::c_int
                                                        }
                                                    {
                                                        current_block = 4970921734680953786;
                                                    } else {
                                                        current_block = 15904375183555213903;
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        current_block = 15904375183555213903;
                                    }
                                    match current_block {
                                        4970921734680953786 => {}
                                        _ => {
                                            r = 0 as libc::c_int;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    sshbuf_free(b);
    return r;
}
pub unsafe extern "C" fn ssh_add_identity_constrained(
    mut sock: libc::c_int,
    mut key: *mut sshkey,
    mut comment: *const libc::c_char,
    mut life: u_int,
    mut confirm: u_int,
    mut maxsign: u_int,
    mut provider: *const libc::c_char,
    mut dest_constraints: *mut *mut dest_constraint,
    mut ndest_constraints: size_t,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    let mut constrained: libc::c_int = (life != 0
        || confirm != 0
        || maxsign != 0
        || !provider.is_null()
        || !dest_constraints.is_null()) as libc::c_int;
    let mut type_0: u_char = 0;
    msg = sshbuf_new();
    if msg.is_null() {
        return -(2 as libc::c_int);
    }
    match (*key).type_0 {
        0 | 4 | 1 | 5 | 2 | 6 | 10 | 11 | 3 | 7 | 12 | 13 | 8 | 9 => {
            type_0 = (if constrained != 0 {
                25 as libc::c_int
            } else {
                17 as libc::c_int
            }) as u_char;
            r = sshbuf_put_u8(msg, type_0);
            if !(r != 0 as libc::c_int
                || {
                    r = sshkey_private_serialize_maxsign(key, msg, maxsign, 0 as libc::c_int);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_cstring(msg, comment);
                    r != 0 as libc::c_int
                })
            {
                if !(constrained != 0 && {
                    r = encode_constraints(
                        msg,
                        life,
                        confirm,
                        maxsign,
                        provider,
                        dest_constraints,
                        ndest_constraints,
                    );
                    r != 0 as libc::c_int
                }) {
                    r = ssh_request_reply_decode(sock, msg);
                    if !(r != 0 as libc::c_int) {
                        r = 0 as libc::c_int;
                    }
                }
            }
        }
        _ => {
            r = -(10 as libc::c_int);
        }
    }
    sshbuf_free(msg);
    return r;
}
pub unsafe extern "C" fn ssh_remove_identity(
    mut sock: libc::c_int,
    mut key: *const sshkey,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    let mut blob: *mut u_char = 0 as *mut u_char;
    let mut blen: size_t = 0;
    msg = sshbuf_new();
    if msg.is_null() {
        return -(2 as libc::c_int);
    }
    if (*key).type_0 != KEY_UNSPEC as libc::c_int {
        r = sshkey_to_blob(key, &mut blob, &mut blen);
        if !(r != 0 as libc::c_int) {
            r = sshbuf_put_u8(msg, 18 as libc::c_int as u_char);
            if !(r != 0 as libc::c_int || {
                r = sshbuf_put_string(msg, blob as *const libc::c_void, blen);
                r != 0 as libc::c_int
            }) {
                r = ssh_request_reply_decode(sock, msg);
                if !(r != 0 as libc::c_int) {
                    r = 0 as libc::c_int;
                }
            }
        }
    } else {
        r = -(10 as libc::c_int);
    }
    if !blob.is_null() {
        freezero(blob as *mut libc::c_void, blen);
    }
    sshbuf_free(msg);
    return r;
}
pub unsafe extern "C" fn ssh_update_card(
    mut sock: libc::c_int,
    mut add: libc::c_int,
    mut reader_id: *const libc::c_char,
    mut pin: *const libc::c_char,
    mut life: u_int,
    mut confirm: u_int,
    mut dest_constraints: *mut *mut dest_constraint,
    mut ndest_constraints: size_t,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    let mut constrained: libc::c_int =
        (life != 0 || confirm != 0 || !dest_constraints.is_null()) as libc::c_int;
    let mut type_0: u_char = 0;
    if add != 0 {
        type_0 = (if constrained != 0 {
            26 as libc::c_int
        } else {
            20 as libc::c_int
        }) as u_char;
    } else {
        type_0 = 21 as libc::c_int as u_char;
    }
    msg = sshbuf_new();
    if msg.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put_u8(msg, type_0);
    if !(r != 0 as libc::c_int
        || {
            r = sshbuf_put_cstring(msg, reader_id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(msg, pin);
            r != 0 as libc::c_int
        })
    {
        if !(constrained != 0 && {
            r = encode_constraints(
                msg,
                life,
                confirm,
                0 as libc::c_int as u_int,
                0 as *const libc::c_char,
                dest_constraints,
                ndest_constraints,
            );
            r != 0 as libc::c_int
        }) {
            r = ssh_request_reply_decode(sock, msg);
            if !(r != 0 as libc::c_int) {
                r = 0 as libc::c_int;
            }
        }
    }
    sshbuf_free(msg);
    return r;
}
pub unsafe extern "C" fn ssh_remove_all_identities(
    mut sock: libc::c_int,
    mut version: libc::c_int,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut type_0: u_char = (if version == 1 as libc::c_int {
        9 as libc::c_int
    } else {
        19 as libc::c_int
    }) as u_char;
    let mut r: libc::c_int = 0;
    msg = sshbuf_new();
    if msg.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put_u8(msg, type_0);
    if !(r != 0 as libc::c_int) {
        r = ssh_request_reply_decode(sock, msg);
        if !(r != 0 as libc::c_int) {
            r = 0 as libc::c_int;
        }
    }
    sshbuf_free(msg);
    return r;
}
pub unsafe extern "C" fn ssh_agent_bind_hostkey(
    mut sock: libc::c_int,
    mut key: *const sshkey,
    mut session_id: *const sshbuf,
    mut signature: *const sshbuf,
    mut forwarding: libc::c_int,
) -> libc::c_int {
    let mut msg: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    if key.is_null() || session_id.is_null() || signature.is_null() {
        return -(10 as libc::c_int);
    }
    msg = sshbuf_new();
    if msg.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put_u8(msg, 27 as libc::c_int as u_char);
    if !(r != 0 as libc::c_int
        || {
            r = sshbuf_put_cstring(
                msg,
                b"session-bind@openssh.com\0" as *const u8 as *const libc::c_char,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshkey_puts(key, msg);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(msg, session_id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(msg, signature);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u8(
                msg,
                (if forwarding != 0 {
                    1 as libc::c_int
                } else {
                    0 as libc::c_int
                }) as u_char,
            );
            r != 0 as libc::c_int
        })
    {
        r = ssh_request_reply_decode(sock, msg);
        if !(r != 0 as libc::c_int) {
            r = 0 as libc::c_int;
        }
    }
    sshbuf_free(msg);
    return r;
}
