use crate::atomicio::atomicio;
use ::libc;
use libc::close;

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
    pub type ssh_channels;
    pub type sshbuf;
    pub type ec_key_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type kex;
    pub type session_state;
    fn getpeername(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __len: *mut socklen_t)
        -> libc::c_int;
    fn gettimeofday(__tv: *mut libc::timeval, __tz: *mut libc::c_void) -> libc::c_int;
    fn login(__entry: *const utmp);
    fn logout(__ut_line: *const libc::c_char) -> libc::c_int;
    fn logwtmp(
        __ut_line: *const libc::c_char,
        __ut_name: *const libc::c_char,
        __ut_host: *const libc::c_char,
    );

    
    fn getpwnam(__name: *const libc::c_char) -> *mut libc::passwd;
    fn lseek(__fd: libc::c_int, __offset: __off_t, __whence: libc::c_int) -> __off_t;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    
    fn geteuid() -> __uid_t;

    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strncpy(_: *mut libc::c_char, _: *const libc::c_char, _: libc::c_ulong)
        -> *mut libc::c_char;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn time(__timer: *mut time_t) -> time_t;
    fn xmalloc(_: size_t) -> *mut libc::c_void;

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

    fn ssh_packet_get_connection_in(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_connection_is_on_socket(_: *mut ssh) -> libc::c_int;
    fn ipv64_normalise_mapped(_: *mut sockaddr_storage, _: *mut socklen_t);
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type uid_t = __uid_t;
pub type off_t = __off_t;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type int32_t = __int32_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;

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
pub struct lastlog {
    pub ll_time: int32_t,
    pub ll_line: [libc::c_char; 32],
    pub ll_host: [libc::c_char; 256],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct exit_status {
    pub e_termination: libc::c_short,
    pub e_exit: libc::c_short,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct utmp {
    pub ut_type: libc::c_short,
    pub ut_pid: pid_t,
    pub ut_line: [libc::c_char; 32],
    pub ut_id: [libc::c_char; 4],
    pub ut_user: [libc::c_char; 32],
    pub ut_host: [libc::c_char; 256],
    pub ut_exit: exit_status,
    pub ut_session: int32_t,
    pub ut_tv: C2RustUnnamed_0,
    pub ut_addr_v6: [int32_t; 4],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub tv_sec: int32_t,
    pub tv_usec: int32_t,
}


#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh {
    pub state: *mut session_state,
    pub kex: *mut kex,
    pub remote_ipaddr: *mut libc::c_char,
    pub remote_port: libc::c_int,
    pub local_ipaddr: *mut libc::c_char,
    pub local_port: libc::c_int,
    pub rdomain_in: *mut libc::c_char,
    pub log_preamble: *mut libc::c_char,
    pub dispatch: [Option<dispatch_fn>; 255],
    pub dispatch_skip_packets: libc::c_int,
    pub compat: libc::c_int,
    pub private_keys: C2RustUnnamed_3,
    pub public_keys: C2RustUnnamed_1,
    pub authctxt: *mut libc::c_void,
    pub chanctxt: *mut ssh_channels,
    pub app_data: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct key_entry {
    pub next: C2RustUnnamed_2,
    pub key: *mut sshkey,
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
pub type EC_KEY = ec_key_st;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub tqe_next: *mut key_entry,
    pub tqe_prev: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
pub type dispatch_fn = unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub union login_netinfo {
    pub sa: sockaddr,
    pub sa_in: sockaddr_in,
    pub sa_storage: sockaddr_storage,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct logininfo {
    pub progname: [libc::c_char; 64],
    pub progname_null: libc::c_int,
    pub type_0: libc::c_short,
    pub pid: pid_t,
    pub uid: uid_t,
    pub line: [libc::c_char; 64],
    pub username: [libc::c_char; 512],
    pub hostname: [libc::c_char; 256],
    pub exit: libc::c_int,
    pub termination: libc::c_int,
    pub tv_sec: libc::c_uint,
    pub tv_usec: libc::c_uint,
    pub hostaddr: login_netinfo,
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
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
pub unsafe extern "C" fn login_login(mut li: *mut logininfo) -> libc::c_int {
    (*li).type_0 = 7 as libc::c_int as libc::c_short;
    return login_write(li);
}
pub unsafe extern "C" fn login_logout(mut li: *mut logininfo) -> libc::c_int {
    (*li).type_0 = 8 as libc::c_int as libc::c_short;
    return login_write(li);
}
pub unsafe extern "C" fn login_get_lastlog_time(uid: uid_t) -> libc::c_uint {
    let mut li: logininfo = logininfo {
        progname: [0; 64],
        progname_null: 0,
        type_0: 0,
        pid: 0,
        uid: 0,
        line: [0; 64],
        username: [0; 512],
        hostname: [0; 256],
        exit: 0,
        termination: 0,
        tv_sec: 0,
        tv_usec: 0,
        hostaddr: login_netinfo {
            sa: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    if !(login_get_lastlog(&mut li, uid)).is_null() {
        return li.tv_sec;
    } else {
        return 0 as libc::c_int as libc::c_uint;
    };
}
pub unsafe extern "C" fn login_get_lastlog(mut li: *mut logininfo, uid: uid_t) -> *mut logininfo {
    let mut pw: *mut libc::passwd = 0 as *mut libc::passwd;
    memset(
        li as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<logininfo>() as libc::c_ulong,
    );
    (*li).uid = uid;
    pw = libc::getpwuid(uid);
    if pw.is_null() {
        sshfatal(
            b"loginrec.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"login_get_lastlog\0"))
                .as_ptr(),
            318 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: Cannot find account for uid %ld\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"login_get_lastlog\0"))
                .as_ptr(),
            uid as libc::c_long,
        );
    }
    if strlcpy(
        ((*li).username).as_mut_ptr(),
        (*pw).pw_name,
        ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
    ) >= ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong
    {
        crate::log::sshlog(
            b"loginrec.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"login_get_lastlog\0"))
                .as_ptr(),
            324 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s: username too long (%lu > max %lu)\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"login_get_lastlog\0"))
                .as_ptr(),
            strlen((*pw).pw_name),
            (::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
        return 0 as *mut logininfo;
    }
    if getlast_entry(li) != 0 {
        return li;
    } else {
        return 0 as *mut logininfo;
    };
}
pub unsafe extern "C" fn login_alloc_entry(
    mut pid: pid_t,
    mut username: *const libc::c_char,
    mut hostname: *const libc::c_char,
    mut line: *const libc::c_char,
) -> *mut logininfo {
    let mut newli: *mut logininfo = 0 as *mut logininfo;
    newli = xmalloc(::core::mem::size_of::<logininfo>() as libc::c_ulong) as *mut logininfo;
    login_init_entry(newli, pid, username, hostname, line);
    return newli;
}
pub unsafe extern "C" fn login_free_entry(mut li: *mut logininfo) {
    libc::free(li as *mut libc::c_void);
}
pub unsafe extern "C" fn login_init_entry(
    mut li: *mut logininfo,
    mut pid: pid_t,
    mut username: *const libc::c_char,
    mut hostname: *const libc::c_char,
    mut line: *const libc::c_char,
) -> libc::c_int {
    let mut pw: *mut libc::passwd = 0 as *mut libc::passwd;
    memset(
        li as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<logininfo>() as libc::c_ulong,
    );
    (*li).pid = pid;
    if !line.is_null() {
        line_fullname(
            ((*li).line).as_mut_ptr(),
            line,
            ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong as u_int,
        );
    }
    if !username.is_null() {
        strlcpy(
            ((*li).username).as_mut_ptr(),
            username,
            ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
        );
        pw = getpwnam(((*li).username).as_mut_ptr());
        if pw.is_null() {
            sshfatal(
                b"loginrec.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"login_init_entry\0"))
                    .as_ptr(),
                391 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s: Cannot find user \"%s\"\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"login_init_entry\0"))
                    .as_ptr(),
                ((*li).username).as_mut_ptr(),
            );
        }
        (*li).uid = (*pw).pw_uid;
    }
    if !hostname.is_null() {
        strlcpy(
            ((*li).hostname).as_mut_ptr(),
            hostname,
            ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
        );
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn login_set_current_time(mut li: *mut logininfo) {
    let mut tv: libc::timeval = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    gettimeofday(&mut tv, 0 as *mut libc::c_void);
    (*li).tv_sec = tv.tv_sec as libc::c_uint;
    (*li).tv_usec = tv.tv_usec as libc::c_uint;
}
pub unsafe extern "C" fn login_set_addr(
    mut li: *mut logininfo,
    mut sa: *const sockaddr,
    sa_size: libc::c_uint,
) {
    let mut bufsize: libc::c_uint = sa_size;
    if (::core::mem::size_of::<login_netinfo>() as libc::c_ulong) < sa_size as libc::c_ulong {
        bufsize = ::core::mem::size_of::<login_netinfo>() as libc::c_ulong as libc::c_uint;
    }
    memcpy(
        &mut (*li).hostaddr.sa as *mut sockaddr as *mut libc::c_void,
        sa as *const libc::c_void,
        bufsize as libc::c_ulong,
    );
}
pub unsafe extern "C" fn login_write(mut li: *mut logininfo) -> libc::c_int {
    if geteuid() != 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"loginrec.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"login_write\0")).as_ptr(),
            444 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Attempt to write login records by non-root user (aborting)\0" as *const u8
                as *const libc::c_char,
        );
        return 1 as libc::c_int;
    }
    login_set_current_time(li);
    syslogin_write_entry(li);
    if (*li).type_0 as libc::c_int == 7 as libc::c_int {
        lastlog_write_entry(li);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn getlast_entry(mut li: *mut logininfo) -> libc::c_int {
    return lastlog_get_entry(li);
}
pub unsafe extern "C" fn line_fullname(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut dstsize: u_int,
) -> *mut libc::c_char {
    memset(dst as *mut libc::c_void, '\0' as i32, dstsize as size_t);
    if strncmp(
        src,
        b"/dev/\0" as *const u8 as *const libc::c_char,
        5 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
        || (dstsize as libc::c_ulong)
            < (strlen(src)).wrapping_add(5 as libc::c_int as libc::c_ulong)
    {
        strlcpy(dst, src, dstsize as size_t);
    } else {
        strlcpy(
            dst,
            b"/dev/\0" as *const u8 as *const libc::c_char,
            dstsize as size_t,
        );
        strlcat(dst, src, dstsize as size_t);
    }
    return dst;
}
pub unsafe extern "C" fn line_stripname(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut dstsize: libc::c_int,
) -> *mut libc::c_char {
    memset(dst as *mut libc::c_void, '\0' as i32, dstsize as size_t);
    if strncmp(
        src,
        b"/dev/\0" as *const u8 as *const libc::c_char,
        5 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        strlcpy(
            dst,
            src.offset(5 as libc::c_int as isize),
            dstsize as size_t,
        );
    } else {
        strlcpy(dst, src, dstsize as size_t);
    }
    return dst;
}
pub unsafe extern "C" fn line_abbrevname(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut dstsize: libc::c_int,
) -> *mut libc::c_char {
    let mut len: size_t = 0;
    memset(dst as *mut libc::c_void, '\0' as i32, dstsize as size_t);
    if strncmp(
        src,
        b"/dev/\0" as *const u8 as *const libc::c_char,
        5 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        src = src.offset(5 as libc::c_int as isize);
    }
    len = strlen(src);
    if len > 0 as libc::c_int as libc::c_ulong {
        if len as libc::c_int - dstsize > 0 as libc::c_int {
            src = src.offset((len as libc::c_int - dstsize) as isize);
        }
        strncpy(dst, src, dstsize as size_t);
    }
    return dst;
}
pub unsafe extern "C" fn set_utmp_time(mut li: *mut logininfo, mut ut: *mut utmp) {
    (*ut).ut_tv.tv_sec = (*li).tv_sec as int32_t;
    (*ut).ut_tv.tv_usec = (*li).tv_usec as int32_t;
}
pub unsafe extern "C" fn construct_utmp(mut li: *mut logininfo, mut ut: *mut utmp) {
    let mut sa6: *mut sockaddr_in6 = 0 as *mut sockaddr_in6;
    memset(
        ut as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<utmp>() as libc::c_ulong,
    );
    line_abbrevname(
        ((*ut).ut_id).as_mut_ptr(),
        ((*li).line).as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 4]>() as libc::c_ulong as libc::c_int,
    );
    match (*li).type_0 as libc::c_int {
        7 => {
            (*ut).ut_type = 7 as libc::c_int as libc::c_short;
        }
        8 => {
            (*ut).ut_type = 8 as libc::c_int as libc::c_short;
        }
        _ => {}
    }
    set_utmp_time(li, ut);
    line_stripname(
        ((*ut).ut_line).as_mut_ptr(),
        ((*li).line).as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong as libc::c_int,
    );
    (*ut).ut_pid = (*li).pid;
    if (*li).type_0 as libc::c_int == 8 as libc::c_int {
        return;
    }
    strncpy(
        ((*ut).ut_user).as_mut_ptr(),
        ((*li).username).as_mut_ptr(),
        if (::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong)
            < ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong
        {
            ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong
        } else {
            ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong
        },
    );
    strncpy(
        ((*ut).ut_host).as_mut_ptr(),
        ((*li).hostname).as_mut_ptr(),
        if (::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
            < ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong
        {
            ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong
        } else {
            ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong
        },
    );
    if (*li).hostaddr.sa.sa_family as libc::c_int == 2 as libc::c_int {
        (*ut).ut_addr_v6[0 as libc::c_int as usize] =
            (*li).hostaddr.sa_in.sin_addr.s_addr as int32_t;
    }
    if (*li).hostaddr.sa.sa_family as libc::c_int == 10 as libc::c_int {
        sa6 = &mut (*li).hostaddr.sa as *mut sockaddr as *mut sockaddr_in6;
        memcpy(
            ((*ut).ut_addr_v6).as_mut_ptr() as *mut libc::c_void,
            ((*sa6).sin6_addr.__in6_u.__u6_addr8).as_mut_ptr() as *const libc::c_void,
            16 as libc::c_int as libc::c_ulong,
        );
        if ({
            let mut __a: *const in6_addr =
                &mut (*sa6).sin6_addr as *mut in6_addr as *const in6_addr;
            ((*__a).__in6_u.__u6_addr32[0 as libc::c_int as usize]
                == 0 as libc::c_int as libc::c_uint
                && (*__a).__in6_u.__u6_addr32[1 as libc::c_int as usize]
                    == 0 as libc::c_int as libc::c_uint
                && (*__a).__in6_u.__u6_addr32[2 as libc::c_int as usize]
                    == __bswap_32(0xffff as libc::c_int as __uint32_t)) as libc::c_int
        }) != 0
        {
            (*ut).ut_addr_v6[0 as libc::c_int as usize] =
                (*ut).ut_addr_v6[3 as libc::c_int as usize];
            (*ut).ut_addr_v6[1 as libc::c_int as usize] = 0 as libc::c_int;
            (*ut).ut_addr_v6[2 as libc::c_int as usize] = 0 as libc::c_int;
            (*ut).ut_addr_v6[3 as libc::c_int as usize] = 0 as libc::c_int;
        }
    }
}
unsafe extern "C" fn syslogin_perform_login(mut li: *mut logininfo) -> libc::c_int {
    let mut ut: *mut utmp = 0 as *mut utmp;
    ut = xmalloc(::core::mem::size_of::<utmp>() as libc::c_ulong) as *mut utmp;
    construct_utmp(li, ut);
    login(ut);
    libc::free(ut as *mut libc::c_void);
    return 1 as libc::c_int;
}
unsafe extern "C" fn syslogin_perform_logout(mut li: *mut logininfo) -> libc::c_int {
    let mut line: [libc::c_char; 32] = [0; 32];
    line_stripname(
        line.as_mut_ptr(),
        ((*li).line).as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong as libc::c_int,
    );
    if logout(line.as_mut_ptr()) == 0 {
        crate::log::sshlog(
            b"loginrec.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"syslogin_perform_logout\0",
            ))
            .as_ptr(),
            1439 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%s: logout() returned an error\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"syslogin_perform_logout\0",
            ))
            .as_ptr(),
        );
    } else {
        logwtmp(
            line.as_mut_ptr(),
            b"\0" as *const u8 as *const libc::c_char,
            b"\0" as *const u8 as *const libc::c_char,
        );
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn syslogin_write_entry(mut li: *mut logininfo) -> libc::c_int {
    match (*li).type_0 as libc::c_int {
        7 => return syslogin_perform_login(li),
        8 => return syslogin_perform_logout(li),
        _ => {
            crate::log::sshlog(
                b"loginrec.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"syslogin_write_entry\0",
                ))
                .as_ptr(),
                1461 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"%s: Invalid type field\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"syslogin_write_entry\0",
                ))
                .as_ptr(),
            );
            return 0 as libc::c_int;
        }
    };
}
unsafe extern "C" fn lastlog_openseek(
    mut li: *mut logininfo,
    mut fd: *mut libc::c_int,
    mut filemode: libc::c_int,
) -> libc::c_int {
    let mut offset: off_t = 0;
    let mut lastlog_file: [libc::c_char; 1024] = [0; 1024];
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if libc::stat(
        b"/var/log/lastlog\0" as *const u8 as *const libc::c_char,
        &mut st,
    ) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"loginrec.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"lastlog_openseek\0"))
                .as_ptr(),
            1486 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%s: Couldn't libc::stat %s: %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"lastlog_openseek\0"))
                .as_ptr(),
            b"/var/log/lastlog\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        return 0 as libc::c_int;
    }
    if st.st_mode & 0o170000 as libc::c_int as libc::c_uint
        == 0o40000 as libc::c_int as libc::c_uint
    {
        libc::snprintf(
            lastlog_file.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
            b"%s/%s\0" as *const u8 as *const libc::c_char,
            b"/var/log/lastlog\0" as *const u8 as *const libc::c_char,
            ((*li).username).as_mut_ptr(),
        );
    } else if st.st_mode & 0o170000 as libc::c_int as libc::c_uint
        == 0o100000 as libc::c_int as libc::c_uint
    {
        strlcpy(
            lastlog_file.as_mut_ptr(),
            b"/var/log/lastlog\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        );
    } else {
        crate::log::sshlog(
            b"loginrec.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"lastlog_openseek\0"))
                .as_ptr(),
            1496 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%s: %.100s is not a file or directory!\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"lastlog_openseek\0"))
                .as_ptr(),
            b"/var/log/lastlog\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    *fd = libc::open(lastlog_file.as_mut_ptr(), filemode, 0o600 as libc::c_int);
    if *fd < 0 as libc::c_int {
        crate::log::sshlog(
            b"loginrec.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"lastlog_openseek\0"))
                .as_ptr(),
            1503 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s: Couldn't open %s: %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"lastlog_openseek\0"))
                .as_ptr(),
            lastlog_file.as_mut_ptr(),
            strerror(*libc::__errno_location()),
        );
        return 0 as libc::c_int;
    }
    if st.st_mode & 0o170000 as libc::c_int as libc::c_uint
        == 0o100000 as libc::c_int as libc::c_uint
    {
        offset = ((*li).uid as u_long)
            .wrapping_mul(::core::mem::size_of::<lastlog>() as libc::c_ulong)
            as off_t;
        if lseek(*fd, offset, 0 as libc::c_int) != offset {
            crate::log::sshlog(
                b"loginrec.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"lastlog_openseek\0"))
                    .as_ptr(),
                1513 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"%s: %s->lseek(): %s\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"lastlog_openseek\0"))
                    .as_ptr(),
                lastlog_file.as_mut_ptr(),
                strerror(*libc::__errno_location()),
            );
            close(*fd);
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn lastlog_write_entry(mut li: *mut logininfo) -> libc::c_int {
    let mut last: lastlog = lastlog {
        ll_time: 0,
        ll_line: [0; 32],
        ll_host: [0; 256],
    };
    let mut fd: libc::c_int = 0;
    match (*li).type_0 as libc::c_int {
        7 => {
            memset(
                &mut last as *mut lastlog as *mut libc::c_void,
                '\0' as i32,
                ::core::mem::size_of::<lastlog>() as libc::c_ulong,
            );
            line_stripname(
                (last.ll_line).as_mut_ptr(),
                ((*li).line).as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong as libc::c_int,
            );
            strlcpy(
                (last.ll_host).as_mut_ptr(),
                ((*li).hostname).as_mut_ptr(),
                if (::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
                    < ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong
                {
                    ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong
                } else {
                    ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong
                },
            );
            last.ll_time = (*li).tv_sec as int32_t;
            if lastlog_openseek(li, &mut fd, 0o2 as libc::c_int | 0o100 as libc::c_int) == 0 {
                return 0 as libc::c_int;
            }
            if atomicio(
                ::core::mem::transmute::<
                    Option<
                        unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
                    >,
                    Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
                >(Some(
                    write
                        as unsafe extern "C" fn(
                            libc::c_int,
                            *const libc::c_void,
                            size_t,
                        ) -> ssize_t,
                )),
                fd,
                &mut last as *mut lastlog as *mut libc::c_void,
                ::core::mem::size_of::<lastlog>() as libc::c_ulong,
            ) != ::core::mem::size_of::<lastlog>() as libc::c_ulong
            {
                close(fd);
                crate::log::sshlog(
                    b"loginrec.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"lastlog_write_entry\0",
                    ))
                    .as_ptr(),
                    1558 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"%s: Error writing to %s: %s\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"lastlog_write_entry\0",
                    ))
                    .as_ptr(),
                    b"/var/log/lastlog\0" as *const u8 as *const libc::c_char,
                    strerror(*libc::__errno_location()),
                );
                return 0 as libc::c_int;
            }
            close(fd);
            return 1 as libc::c_int;
        }
        _ => {
            crate::log::sshlog(
                b"loginrec.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"lastlog_write_entry\0",
                ))
                .as_ptr(),
                1565 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"%s: Invalid type field\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"lastlog_write_entry\0",
                ))
                .as_ptr(),
            );
            return 0 as libc::c_int;
        }
    };
}
pub unsafe extern "C" fn lastlog_get_entry(mut li: *mut logininfo) -> libc::c_int {
    let mut last: lastlog = lastlog {
        ll_time: 0,
        ll_line: [0; 32],
        ll_host: [0; 256],
    };
    let mut fd: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    if lastlog_openseek(li, &mut fd, 0 as libc::c_int) == 0 {
        return 0 as libc::c_int;
    }
    ret = atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        fd,
        &mut last as *mut lastlog as *mut libc::c_void,
        ::core::mem::size_of::<lastlog>() as libc::c_ulong,
    ) as libc::c_int;
    close(fd);
    match ret {
        0 => {
            memset(
                &mut last as *mut lastlog as *mut libc::c_void,
                '\0' as i32,
                ::core::mem::size_of::<lastlog>() as libc::c_ulong,
            );
        }
        292 => {}
        -1 => {
            crate::log::sshlog(
                b"loginrec.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"lastlog_get_entry\0"))
                    .as_ptr(),
                1613 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"%s: Error reading from %s: %s\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"lastlog_get_entry\0"))
                    .as_ptr(),
                b"/var/log/lastlog\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
            return 0 as libc::c_int;
        }
        _ => {
            crate::log::sshlog(
                b"loginrec.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"lastlog_get_entry\0"))
                    .as_ptr(),
                1617 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"%s: Error reading from %s: Expecting %d, got %d\0" as *const u8
                    as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"lastlog_get_entry\0"))
                    .as_ptr(),
                b"/var/log/lastlog\0" as *const u8 as *const libc::c_char,
                ::core::mem::size_of::<lastlog>() as libc::c_ulong as libc::c_int,
                ret,
            );
            return 0 as libc::c_int;
        }
    }
    line_fullname(
        ((*li).line).as_mut_ptr(),
        (last.ll_line).as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong as u_int,
    );
    strlcpy(
        ((*li).hostname).as_mut_ptr(),
        (last.ll_host).as_mut_ptr(),
        if (::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
            < ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong
        {
            ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong
        } else {
            ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong
        },
    );
    (*li).tv_sec = last.ll_time as libc::c_uint;
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn record_failed_login(
    mut ssh: *mut ssh,
    mut username: *const libc::c_char,
    mut hostname: *const libc::c_char,
    mut _ttyn: *const libc::c_char,
) {
    let mut fd: libc::c_int = 0;
    let mut ut: utmp = utmp {
        ut_type: 0,
        ut_pid: 0,
        ut_line: [0; 32],
        ut_id: [0; 4],
        ut_user: [0; 32],
        ut_host: [0; 256],
        ut_exit: exit_status {
            e_termination: 0,
            e_exit: 0,
        },
        ut_session: 0,
        ut_tv: C2RustUnnamed_0 {
            tv_sec: 0,
            tv_usec: 0,
        },
        ut_addr_v6: [0; 4],
    };
    let mut from: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut fromlen: socklen_t =
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    let mut a4: *mut sockaddr_in = 0 as *mut sockaddr_in;
    let mut a6: *mut sockaddr_in6 = 0 as *mut sockaddr_in6;
    let mut t: time_t = 0;
    let mut fst: libc::stat = unsafe { std::mem::zeroed() };
    if geteuid() != 0 as libc::c_int as libc::c_uint {
        return;
    }
    fd = libc::open(
        b"/var/log/btmp\0" as *const u8 as *const libc::c_char,
        0o1 as libc::c_int | 0o2000 as libc::c_int,
    );
    if fd < 0 as libc::c_int {
        crate::log::sshlog(
            b"loginrec.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"record_failed_login\0"))
                .as_ptr(),
            1678 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Unable to open the btmp file %s: %s\0" as *const u8 as *const libc::c_char,
            b"/var/log/btmp\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        return;
    }
    if libc::fstat(fd, &mut fst) < 0 as libc::c_int {
        crate::log::sshlog(
            b"loginrec.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"record_failed_login\0"))
                .as_ptr(),
            1683 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%s: libc::fstat of %s failed: %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"record_failed_login\0"))
                .as_ptr(),
            b"/var/log/btmp\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    } else if fst.st_mode
        & (0o100 as libc::c_int >> 3 as libc::c_int
            | (0o400 as libc::c_int | 0o200 as libc::c_int | 0o100 as libc::c_int)
                >> 3 as libc::c_int
                >> 3 as libc::c_int) as libc::c_uint
        != 0
        || fst.st_uid != 0 as libc::c_int as libc::c_uint
    {
        crate::log::sshlog(
            b"loginrec.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"record_failed_login\0"))
                .as_ptr(),
            1688 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Excess permission or bad ownership on file %s\0" as *const u8 as *const libc::c_char,
            b"/var/log/btmp\0" as *const u8 as *const libc::c_char,
        );
    } else {
        memset(
            &mut ut as *mut utmp as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<utmp>() as libc::c_ulong,
        );
        strncpy(
            (ut.ut_user).as_mut_ptr(),
            username,
            ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
        );
        strlcpy(
            (ut.ut_line).as_mut_ptr(),
            b"ssh:notty\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
        );
        time(&mut t);
        ut.ut_tv.tv_sec = t as int32_t;
        ut.ut_type = 6 as libc::c_int as libc::c_short;
        ut.ut_pid = libc::getpid();
        strncpy(
            (ut.ut_host).as_mut_ptr(),
            hostname,
            ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
        );
        if ssh_packet_connection_is_on_socket(ssh) != 0
            && getpeername(
                ssh_packet_get_connection_in(ssh),
                __SOCKADDR_ARG {
                    __sockaddr__: &mut from as *mut sockaddr_storage as *mut sockaddr,
                },
                &mut fromlen,
            ) == 0 as libc::c_int
        {
            ipv64_normalise_mapped(&mut from, &mut fromlen);
            if from.ss_family as libc::c_int == 2 as libc::c_int {
                a4 = &mut from as *mut sockaddr_storage as *mut sockaddr_in;
                memcpy(
                    &mut *(ut.ut_addr_v6)
                        .as_mut_ptr()
                        .offset(0 as libc::c_int as isize) as *mut int32_t
                        as *mut libc::c_void,
                    &mut (*a4).sin_addr as *mut in_addr as *const libc::c_void,
                    if (::core::mem::size_of::<int32_t>() as libc::c_ulong)
                        < ::core::mem::size_of::<in_addr>() as libc::c_ulong
                    {
                        ::core::mem::size_of::<int32_t>() as libc::c_ulong
                    } else {
                        ::core::mem::size_of::<in_addr>() as libc::c_ulong
                    },
                );
            }
            if from.ss_family as libc::c_int == 10 as libc::c_int {
                a6 = &mut from as *mut sockaddr_storage as *mut sockaddr_in6;
                memcpy(
                    &mut ut.ut_addr_v6 as *mut [int32_t; 4] as *mut libc::c_void,
                    &mut (*a6).sin6_addr as *mut in6_addr as *const libc::c_void,
                    if (::core::mem::size_of::<[int32_t; 4]>() as libc::c_ulong)
                        < ::core::mem::size_of::<in6_addr>() as libc::c_ulong
                    {
                        ::core::mem::size_of::<[int32_t; 4]>() as libc::c_ulong
                    } else {
                        ::core::mem::size_of::<in6_addr>() as libc::c_ulong
                    },
                );
            }
        }
        if atomicio(
            ::core::mem::transmute::<
                Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
                Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
            >(Some(
                write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
            )),
            fd,
            &mut ut as *mut utmp as *mut libc::c_void,
            ::core::mem::size_of::<utmp>() as libc::c_ulong,
        ) != ::core::mem::size_of::<utmp>() as libc::c_ulong
        {
            crate::log::sshlog(
                b"loginrec.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"record_failed_login\0",
                ))
                .as_ptr(),
                1725 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Failed to write to %s: %s\0" as *const u8 as *const libc::c_char,
                b"/var/log/btmp\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
    }
    close(fd);
}
