use ::libc;
use libc::close;
use libc::kill;

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
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type sshbuf;

    fn socket(__domain: libc::c_int, __type: libc::c_int, __protocol: libc::c_int) -> libc::c_int;
    fn bind(__fd: libc::c_int, __addr: __CONST_SOCKADDR_ARG, __len: socklen_t) -> libc::c_int;
    fn getsockname(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __len: *mut socklen_t)
        -> libc::c_int;
    fn connect(__fd: libc::c_int, __addr: __CONST_SOCKADDR_ARG, __len: socklen_t) -> libc::c_int;
    fn getsockopt(
        __fd: libc::c_int,
        __level: libc::c_int,
        __optname: libc::c_int,
        __optval: *mut libc::c_void,
        __optlen: *mut socklen_t,
    ) -> libc::c_int;
    fn setsockopt(
        __fd: libc::c_int,
        __level: libc::c_int,
        __optname: libc::c_int,
        __optval: *const libc::c_void,
        __optlen: socklen_t,
    ) -> libc::c_int;
    fn listen(__fd: libc::c_int, __n: libc::c_int) -> libc::c_int;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncasecmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong)
        -> libc::c_int;
    fn gettimeofday(__tv: *mut libc::timeval, __tz: *mut libc::c_void) -> libc::c_int;

    fn getpwnam(__name: *const libc::c_char) -> *mut libc::passwd;
    fn platform_sys_dir_uid(_: uid_t) -> libc::c_int;

    fn sigfillset(__set: *mut sigset_t) -> libc::c_int;
    fn sigaction(
        __sig: libc::c_int,
        __act: *const sigaction,
        __oact: *mut sigaction,
    ) -> libc::c_int;

    fn closefrom(__lowfd: libc::c_int);
    fn pipe(__pipedes: *mut libc::c_int) -> libc::c_int;
    fn getservbyname(__name: *const libc::c_char, __proto: *const libc::c_char) -> *mut servent;
    fn gai_strerror(__ecode: libc::c_int) -> *const libc::c_char;
    static mut stderr: *mut libc::FILE;

    fn vasprintf(
        __ptr: *mut *mut libc::c_char,
        __f: *const libc::c_char,
        __arg: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char, _: ...) -> libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: libc::c_int) -> libc::c_int;

    fn sys_tun_open(_: libc::c_int, _: libc::c_int, _: *mut *mut libc::c_char) -> libc::c_int;
    fn sys_get_rdomain(fd: libc::c_int) -> *mut libc::c_char;
    fn sys_set_rdomain(fd: libc::c_int, name: *const libc::c_char) -> libc::c_int;

    fn setresgid(__rgid: __gid_t, __egid: __gid_t, __sgid: __gid_t) -> libc::c_int;
    fn execve(
        __path: *const libc::c_char,
        __argv: *const *mut libc::c_char,
        __envp: *const *mut libc::c_char,
    ) -> libc::c_int;
    fn setresuid(__ruid: __uid_t, __euid: __uid_t, __suid: __uid_t) -> libc::c_int;
    fn geteuid() -> __uid_t;

    fn getsid(__pid: __pid_t) -> __pid_t;
    fn getppid() -> __pid_t;

    fn execv(__path: *const libc::c_char, __argv: *const *mut libc::c_char) -> libc::c_int;

    fn unlink(__name: *const libc::c_char) -> libc::c_int;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
        -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strpbrk(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn strsignal(__sig: libc::c_int) -> *mut libc::c_char;
    fn dirname(__path: *mut libc::c_char) -> *mut libc::c_char;
    fn strtol(_: *const libc::c_char, _: *mut *mut libc::c_char, _: libc::c_int) -> libc::c_long;

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn realpath(__name: *const libc::c_char, __resolved: *mut libc::c_char) -> *mut libc::c_char;
    fn mktime(__tp: *mut tm) -> time_t;
    fn strftime(
        __s: *mut libc::c_char,
        __maxsize: size_t,
        __format: *const libc::c_char,
        __tp: *const tm,
    ) -> size_t;
    fn strptime(
        __s: *const libc::c_char,
        __fmt: *const libc::c_char,
        __tp: *mut tm,
    ) -> *mut libc::c_char;
    fn localtime_r(__timer: *const time_t, __tp: *mut tm) -> *mut tm;
    fn timegm(__tp: *mut tm) -> time_t;
    fn nanosleep(
        __requested_time: *const libc::timespec,
        __remaining: *mut libc::timespec,
    ) -> libc::c_int;
    fn clock_gettime(__clock_id: clockid_t, __tp: *mut libc::timespec) -> libc::c_int;
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn __ctype_tolower_loc() -> *mut *const __int32_t;
    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;

    fn initgroups(__user: *const libc::c_char, __group: __gid_t) -> libc::c_int;

    fn xreallocarray(_: *mut libc::c_void, _: size_t, _: size_t) -> *mut libc::c_void;

    fn xvasprintf(
        _: *mut *mut libc::c_char,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn cleanup_exit(_: libc::c_int) -> !;

    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
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
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_dup_string(buf: *mut sshbuf) -> *mut libc::c_char;
    fn sshbuf_put(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_put_u8(buf: *mut sshbuf, val: u_char) -> libc::c_int;
    fn sshbuf_new() -> *mut sshbuf;
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_ptr(buf: *const sshbuf) -> *const u_char;
    fn sshbuf_putb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_reset(buf: *mut sshbuf);
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
pub type __u_char = libc::c_uchar;
pub type __u_short = libc::c_ushort;
pub type __u_int = libc::c_uint;
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
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __clock_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __clockid_t = libc::c_int;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type u_char = __u_char;
pub type u_short = __u_short;
pub type u_int = __u_int;
pub type uid_t = __uid_t;
pub type pid_t = __pid_t;
pub type clockid_t = __clockid_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type u_int16_t = __uint16_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [libc::c_ulong; 16],
}
pub type sigset_t = __sigset_t;

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
pub type uint64_t = __uint64_t;

pub type C2RustUnnamed_0 = libc::c_uint;
pub const IPPROTO_MAX: C2RustUnnamed_0 = 263;
pub const IPPROTO_MPTCP: C2RustUnnamed_0 = 262;
pub const IPPROTO_RAW: C2RustUnnamed_0 = 255;
pub const IPPROTO_ETHERNET: C2RustUnnamed_0 = 143;
pub const IPPROTO_MPLS: C2RustUnnamed_0 = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed_0 = 136;
pub const IPPROTO_SCTP: C2RustUnnamed_0 = 132;
pub const IPPROTO_COMP: C2RustUnnamed_0 = 108;
pub const IPPROTO_PIM: C2RustUnnamed_0 = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed_0 = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed_0 = 94;
pub const IPPROTO_MTP: C2RustUnnamed_0 = 92;
pub const IPPROTO_AH: C2RustUnnamed_0 = 51;
pub const IPPROTO_ESP: C2RustUnnamed_0 = 50;
pub const IPPROTO_GRE: C2RustUnnamed_0 = 47;
pub const IPPROTO_RSVP: C2RustUnnamed_0 = 46;
pub const IPPROTO_IPV6: C2RustUnnamed_0 = 41;
pub const IPPROTO_DCCP: C2RustUnnamed_0 = 33;
pub const IPPROTO_TP: C2RustUnnamed_0 = 29;
pub const IPPROTO_IDP: C2RustUnnamed_0 = 22;
pub const IPPROTO_UDP: C2RustUnnamed_0 = 17;
pub const IPPROTO_PUP: C2RustUnnamed_0 = 12;
pub const IPPROTO_EGP: C2RustUnnamed_0 = 8;
pub const IPPROTO_TCP: C2RustUnnamed_0 = 6;
pub const IPPROTO_IPIP: C2RustUnnamed_0 = 4;
pub const IPPROTO_IGMP: C2RustUnnamed_0 = 2;
pub const IPPROTO_ICMP: C2RustUnnamed_0 = 1;
pub const IPPROTO_IP: C2RustUnnamed_0 = 0;

pub type _IO_lock_t = ();

#[derive(Copy, Clone)]
#[repr(C)]
pub union sigval {
    pub sival_int: libc::c_int,
    pub sival_ptr: *mut libc::c_void,
}
pub type __sigval_t = sigval;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct siginfo_t {
    pub si_signo: libc::c_int,
    pub si_errno: libc::c_int,
    pub si_code: libc::c_int,
    pub _sifields: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub _pad: [libc::c_int; 28],
    pub _kill: C2RustUnnamed_10,
    pub _timer: C2RustUnnamed_9,
    pub _rt: C2RustUnnamed_8,
    pub _sigchld: C2RustUnnamed_7,
    pub _sigfault: C2RustUnnamed_4,
    pub _sigpoll: C2RustUnnamed_3,
    pub _sigsys: C2RustUnnamed_2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub _call_addr: *mut libc::c_void,
    pub _syscall: libc::c_int,
    pub _arch: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
    pub si_band: libc::c_long,
    pub si_fd: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub si_addr: *mut libc::c_void,
    pub si_addr_lsb: libc::c_short,
    pub _bounds: C2RustUnnamed_5,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_5 {
    pub _addr_bnd: C2RustUnnamed_6,
    pub _pkey: __uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_6 {
    pub _lower: *mut libc::c_void,
    pub _upper: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_7 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
    pub si_status: libc::c_int,
    pub si_utime: __clock_t,
    pub si_stime: __clock_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_8 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
    pub si_sigval: __sigval_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_9 {
    pub si_tid: libc::c_int,
    pub si_overrun: libc::c_int,
    pub si_sigval: __sigval_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_10 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
}
pub type __sighandler_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sigaction {
    pub __sigaction_handler: C2RustUnnamed_11,
    pub sa_mask: __sigset_t,
    pub sa_flags: libc::c_int,
    pub sa_restorer: Option<unsafe extern "C" fn() -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_11 {
    pub sa_handler: __sighandler_t,
    pub sa_sigaction:
        Option<unsafe extern "C" fn(libc::c_int, *mut siginfo_t, *mut libc::c_void) -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct servent {
    pub s_name: *mut libc::c_char,
    pub s_aliases: *mut *mut libc::c_char,
    pub s_port: libc::c_int,
    pub s_proto: *mut libc::c_char,
}
pub type va_list = __builtin_va_list;
pub type nfds_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: libc::c_int,
    pub events: libc::c_short,
    pub revents: libc::c_short,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub tm_gmtoff: libc::c_long,
    pub tm_zone: *const libc::c_char,
}
pub type C2RustUnnamed_12 = libc::c_uint;
pub const _ISalnum: C2RustUnnamed_12 = 8;
pub const _ISpunct: C2RustUnnamed_12 = 4;
pub const _IScntrl: C2RustUnnamed_12 = 2;
pub const _ISblank: C2RustUnnamed_12 = 1;
pub const _ISgraph: C2RustUnnamed_12 = 32768;
pub const _ISprint: C2RustUnnamed_12 = 16384;
pub const _ISspace: C2RustUnnamed_12 = 8192;
pub const _ISxdigit: C2RustUnnamed_12 = 4096;
pub const _ISdigit: C2RustUnnamed_12 = 2048;
pub const _ISalpha: C2RustUnnamed_12 = 1024;
pub const _ISlower: C2RustUnnamed_12 = 512;
pub const _ISupper: C2RustUnnamed_12 = 256;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Forward {
    pub listen_host: *mut libc::c_char,
    pub listen_port: libc::c_int,
    pub listen_path: *mut libc::c_char,
    pub connect_host: *mut libc::c_char,
    pub connect_port: libc::c_int,
    pub connect_path: *mut libc::c_char,
    pub allocated_port: libc::c_int,
    pub handle: libc::c_int,
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
pub struct C2RustUnnamed_13 {
    pub key: *const libc::c_char,
    pub repl: *const libc::c_char,
}
pub type privdrop_fn = unsafe extern "C" fn(*mut libc::passwd) -> ();
pub type privrestore_fn = unsafe extern "C" fn() -> ();
pub type sshsig_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct arglist {
    pub list: *mut *mut libc::c_char,
    pub num: u_int,
    pub nalloc: u_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bwlimit {
    pub buflen: size_t,
    pub rate: u_int64_t,
    pub thresh: u_int64_t,
    pub lamt: u_int64_t,
    pub bwstart: libc::timeval,
    pub bwend: libc::timeval,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_14 {
    pub name: *const libc::c_char,
    pub value: libc::c_int,
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
#[inline]
unsafe extern "C" fn tolower(mut __c: libc::c_int) -> libc::c_int {
    return if __c >= -(128 as libc::c_int) && __c < 256 as libc::c_int {
        *(*__ctype_tolower_loc()).offset(__c as isize)
    } else {
        __c
    };
}
pub unsafe extern "C" fn chop(mut s: *mut libc::c_char) -> *mut libc::c_char {
    let mut t: *mut libc::c_char = s;
    while *t != 0 {
        if *t as libc::c_int == '\n' as i32 || *t as libc::c_int == '\r' as i32 {
            *t = '\0' as i32 as libc::c_char;
            return s;
        }
        t = t.offset(1);
        t;
    }
    return s;
}
pub unsafe extern "C" fn rtrim(mut s: *mut libc::c_char) {
    let mut i: size_t = 0;
    i = strlen(s);
    if i == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    i = i.wrapping_sub(1);
    i;
    while i > 0 as libc::c_int as libc::c_ulong {
        if *(*__ctype_b_loc())
            .offset(*s.offset(i as isize) as libc::c_uchar as libc::c_int as isize)
            as libc::c_int
            & _ISspace as libc::c_int as libc::c_ushort as libc::c_int
            != 0
        {
            *s.offset(i as isize) = '\0' as i32 as libc::c_char;
        }
        i = i.wrapping_sub(1);
        i;
    }
}
pub unsafe extern "C" fn set_nonblock(mut fd: libc::c_int) -> libc::c_int {
    let mut val: libc::c_int = 0;
    val = fcntl(fd, 3 as libc::c_int);
    if val == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"set_nonblock\0")).as_ptr(),
            111 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"fcntl(%d, F_GETFL): %s\0" as *const u8 as *const libc::c_char,
            fd,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if val & 0o4000 as libc::c_int != 0 {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"set_nonblock\0")).as_ptr(),
            115 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"fd %d is O_NONBLOCK\0" as *const u8 as *const libc::c_char,
            fd,
        );
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"misc.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"set_nonblock\0")).as_ptr(),
        118 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"fd %d setting O_NONBLOCK\0" as *const u8 as *const libc::c_char,
        fd,
    );
    val |= 0o4000 as libc::c_int;
    if fcntl(fd, 4 as libc::c_int, val) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"set_nonblock\0")).as_ptr(),
            122 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"fcntl(%d, F_SETFL, O_NONBLOCK): %s\0" as *const u8 as *const libc::c_char,
            fd,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn unset_nonblock(mut fd: libc::c_int) -> libc::c_int {
    let mut val: libc::c_int = 0;
    val = fcntl(fd, 3 as libc::c_int);
    if val == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"unset_nonblock\0"))
                .as_ptr(),
            135 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"fcntl(%d, F_GETFL): %s\0" as *const u8 as *const libc::c_char,
            fd,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if val & 0o4000 as libc::c_int == 0 {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"unset_nonblock\0"))
                .as_ptr(),
            139 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"fd %d is not O_NONBLOCK\0" as *const u8 as *const libc::c_char,
            fd,
        );
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"misc.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"unset_nonblock\0")).as_ptr(),
        142 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"fd %d clearing O_NONBLOCK\0" as *const u8 as *const libc::c_char,
        fd,
    );
    val &= !(0o4000 as libc::c_int);
    if fcntl(fd, 4 as libc::c_int, val) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"unset_nonblock\0"))
                .as_ptr(),
            146 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"fcntl(%d, F_SETFL, ~O_NONBLOCK): %s\0" as *const u8 as *const libc::c_char,
            fd,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_gai_strerror(mut gaierr: libc::c_int) -> *const libc::c_char {
    if gaierr == -(11 as libc::c_int) && *libc::__errno_location() != 0 as libc::c_int {
        return strerror(*libc::__errno_location());
    }
    return gai_strerror(gaierr);
}
pub unsafe extern "C" fn set_nodelay(mut fd: libc::c_int) {
    let mut opt: libc::c_int = 0;
    let mut optlen: socklen_t = 0;
    optlen = ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t;
    if getsockopt(
        fd,
        IPPROTO_TCP as libc::c_int,
        1 as libc::c_int,
        &mut opt as *mut libc::c_int as *mut libc::c_void,
        &mut optlen,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"set_nodelay\0")).as_ptr(),
            169 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"getsockopt TCP_NODELAY: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        return;
    }
    if opt == 1 as libc::c_int {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"set_nodelay\0")).as_ptr(),
            173 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"fd %d is TCP_NODELAY\0" as *const u8 as *const libc::c_char,
            fd,
        );
        return;
    }
    opt = 1 as libc::c_int;
    crate::log::sshlog(
        b"misc.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"set_nodelay\0")).as_ptr(),
        177 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"fd %d setting TCP_NODELAY\0" as *const u8 as *const libc::c_char,
        fd,
    );
    if setsockopt(
        fd,
        IPPROTO_TCP as libc::c_int,
        1 as libc::c_int,
        &mut opt as *mut libc::c_int as *const libc::c_void,
        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"set_nodelay\0")).as_ptr(),
            179 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"setsockopt TCP_NODELAY: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
}
pub unsafe extern "C" fn set_reuseaddr(mut fd: libc::c_int) -> libc::c_int {
    let mut on: libc::c_int = 1 as libc::c_int;
    if setsockopt(
        fd,
        1 as libc::c_int,
        2 as libc::c_int,
        &mut on as *mut libc::c_int as *const libc::c_void,
        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"set_reuseaddr\0"))
                .as_ptr(),
            189 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"setsockopt SO_REUSEADDR fd %d: %s\0" as *const u8 as *const libc::c_char,
            fd,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn get_rdomain(mut fd: libc::c_int) -> *mut libc::c_char {
    return sys_get_rdomain(fd);
}
pub unsafe extern "C" fn set_rdomain(
    mut fd: libc::c_int,
    mut name: *const libc::c_char,
) -> libc::c_int {
    return sys_set_rdomain(fd, name);
}
pub unsafe extern "C" fn get_sock_af(mut fd: libc::c_int) -> libc::c_int {
    let mut to: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut tolen: socklen_t =
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    memset(
        &mut to as *mut sockaddr_storage as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong,
    );
    if getsockname(
        fd,
        __SOCKADDR_ARG {
            __sockaddr__: &mut to as *mut sockaddr_storage as *mut sockaddr,
        },
        &mut tolen,
    ) == -(1 as libc::c_int)
    {
        return -(1 as libc::c_int);
    }
    if to.ss_family as libc::c_int == 10 as libc::c_int
        && ({
            let mut __a: *const in6_addr =
                &mut (*(&mut to as *mut sockaddr_storage as *mut sockaddr_in6)).sin6_addr
                    as *mut in6_addr as *const in6_addr;
            ((*__a).__in6_u.__u6_addr32[0 as libc::c_int as usize]
                == 0 as libc::c_int as libc::c_uint
                && (*__a).__in6_u.__u6_addr32[1 as libc::c_int as usize]
                    == 0 as libc::c_int as libc::c_uint
                && (*__a).__in6_u.__u6_addr32[2 as libc::c_int as usize]
                    == __bswap_32(0xffff as libc::c_int as __uint32_t)) as libc::c_int
        }) != 0
    {
        return 2 as libc::c_int;
    }
    return to.ss_family as libc::c_int;
}
pub unsafe extern "C" fn set_sock_tos(mut fd: libc::c_int, mut tos: libc::c_int) {
    let mut af: libc::c_int = 0;
    af = get_sock_af(fd);
    match af {
        -1 => {}
        2 => {
            crate::log::sshlog(
                b"misc.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"set_sock_tos\0"))
                    .as_ptr(),
                278 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"set socket %d IP_TOS 0x%02x\0" as *const u8 as *const libc::c_char,
                fd,
                tos,
            );
            if setsockopt(
                fd,
                IPPROTO_IP as libc::c_int,
                1 as libc::c_int,
                &mut tos as *mut libc::c_int as *const libc::c_void,
                ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
            ) == -(1 as libc::c_int)
            {
                crate::log::sshlog(
                    b"misc.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"set_sock_tos\0"))
                        .as_ptr(),
                    282 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"setsockopt socket %d IP_TOS %d: %s\0" as *const u8 as *const libc::c_char,
                    fd,
                    tos,
                    strerror(*libc::__errno_location()),
                );
            }
        }
        10 => {
            crate::log::sshlog(
                b"misc.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"set_sock_tos\0"))
                    .as_ptr(),
                288 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"set socket %d IPV6_TCLASS 0x%02x\0" as *const u8 as *const libc::c_char,
                fd,
                tos,
            );
            if setsockopt(
                fd,
                IPPROTO_IPV6 as libc::c_int,
                67 as libc::c_int,
                &mut tos as *mut libc::c_int as *const libc::c_void,
                ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
            ) == -(1 as libc::c_int)
            {
                crate::log::sshlog(
                    b"misc.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"set_sock_tos\0"))
                        .as_ptr(),
                    292 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"setsockopt socket %d IPV6_TCLASS %d: %s\0" as *const u8
                        as *const libc::c_char,
                    fd,
                    tos,
                    strerror(*libc::__errno_location()),
                );
            }
        }
        _ => {
            crate::log::sshlog(
                b"misc.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"set_sock_tos\0"))
                    .as_ptr(),
                297 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"unsupported socket family %d\0" as *const u8 as *const libc::c_char,
                af,
            );
        }
    };
}
unsafe extern "C" fn waitfd(
    mut fd: libc::c_int,
    mut timeoutp: *mut libc::c_int,
    mut events: libc::c_short,
) -> libc::c_int {
    let mut pfd: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    let mut t_start: libc::timeval = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut oerrno: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    pfd.fd = fd;
    pfd.events = events;
    while *timeoutp >= 0 as libc::c_int {
        monotime_tv(&mut t_start);
        r = poll(&mut pfd, 1 as libc::c_int as nfds_t, *timeoutp);
        oerrno = *libc::__errno_location();
        ms_subtract_diff(&mut t_start, timeoutp);
        *libc::__errno_location() = oerrno;
        if r > 0 as libc::c_int {
            return 0 as libc::c_int;
        } else if r == -(1 as libc::c_int)
            && *libc::__errno_location() != 11 as libc::c_int
            && *libc::__errno_location() != 4 as libc::c_int
        {
            return -(1 as libc::c_int);
        } else if r == 0 as libc::c_int {
            break;
        }
    }
    *libc::__errno_location() = 110 as libc::c_int;
    return -(1 as libc::c_int);
}
pub unsafe extern "C" fn waitrfd(
    mut fd: libc::c_int,
    mut timeoutp: *mut libc::c_int,
) -> libc::c_int {
    return waitfd(fd, timeoutp, 0x1 as libc::c_int as libc::c_short);
}
pub unsafe extern "C" fn timeout_connect(
    mut sockfd: libc::c_int,
    mut serv_addr: *const sockaddr,
    mut addrlen: socklen_t,
    mut timeoutp: *mut libc::c_int,
) -> libc::c_int {
    let mut optval: libc::c_int = 0 as libc::c_int;
    let mut optlen: socklen_t = ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t;
    if timeoutp.is_null() || *timeoutp <= 0 as libc::c_int {
        return connect(
            sockfd,
            __CONST_SOCKADDR_ARG {
                __sockaddr__: serv_addr,
            },
            addrlen,
        );
    }
    set_nonblock(sockfd);
    loop {
        if connect(
            sockfd,
            __CONST_SOCKADDR_ARG {
                __sockaddr__: serv_addr,
            },
            addrlen,
        ) == 0 as libc::c_int
        {
            unset_nonblock(sockfd);
            return 0 as libc::c_int;
        } else {
            if *libc::__errno_location() == 4 as libc::c_int {
                continue;
            }
            if *libc::__errno_location() != 115 as libc::c_int {
                return -(1 as libc::c_int);
            }
            break;
        }
    }
    if waitfd(
        sockfd,
        timeoutp,
        (0x1 as libc::c_int | 0x4 as libc::c_int) as libc::c_short,
    ) == -(1 as libc::c_int)
    {
        return -(1 as libc::c_int);
    }
    if getsockopt(
        sockfd,
        1 as libc::c_int,
        4 as libc::c_int,
        &mut optval as *mut libc::c_int as *mut libc::c_void,
        &mut optlen,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"timeout_connect\0"))
                .as_ptr(),
            381 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"getsockopt: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if optval != 0 as libc::c_int {
        *libc::__errno_location() = optval;
        return -(1 as libc::c_int);
    }
    unset_nonblock(sockfd);
    return 0 as libc::c_int;
}
unsafe extern "C" fn strdelim_internal(
    mut s: *mut *mut libc::c_char,
    mut split_equals: libc::c_int,
) -> *mut libc::c_char {
    let mut old: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut wspace: libc::c_int = 0 as libc::c_int;
    if (*s).is_null() {
        return 0 as *mut libc::c_char;
    }
    old = *s;
    *s = strpbrk(
        *s,
        if split_equals != 0 {
            b" \t\r\n\"=\0" as *const u8 as *const libc::c_char
        } else {
            b" \t\r\n\"\0" as *const u8 as *const libc::c_char
        },
    );
    if (*s).is_null() {
        return old;
    }
    if **s.offset(0 as libc::c_int as isize) as libc::c_int == '"' as i32 {
        memmove(
            *s as *mut libc::c_void,
            (*s).offset(1 as libc::c_int as isize) as *const libc::c_void,
            strlen(*s),
        );
        *s = strpbrk(*s, b"\"\0" as *const u8 as *const libc::c_char);
        if (*s).is_null() {
            return 0 as *mut libc::c_char;
        } else {
            **s.offset(0 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
            *s = (*s).offset(
                (strspn(
                    (*s).offset(1 as libc::c_int as isize),
                    b" \t\r\n\0" as *const u8 as *const libc::c_char,
                ))
                .wrapping_add(1 as libc::c_int as libc::c_ulong) as isize,
            );
            return old;
        }
    }
    if split_equals != 0 && **s.offset(0 as libc::c_int as isize) as libc::c_int == '=' as i32 {
        wspace = 1 as libc::c_int;
    }
    **s.offset(0 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
    *s = (*s).offset(
        (strspn(
            (*s).offset(1 as libc::c_int as isize),
            b" \t\r\n\0" as *const u8 as *const libc::c_char,
        ))
        .wrapping_add(1 as libc::c_int as libc::c_ulong) as isize,
    );
    if split_equals != 0
        && **s.offset(0 as libc::c_int as isize) as libc::c_int == '=' as i32
        && wspace == 0
    {
        *s = (*s).offset(
            (strspn(
                (*s).offset(1 as libc::c_int as isize),
                b" \t\r\n\0" as *const u8 as *const libc::c_char,
            ))
            .wrapping_add(1 as libc::c_int as libc::c_ulong) as isize,
        );
    }
    return old;
}
pub unsafe extern "C" fn strdelim(mut s: *mut *mut libc::c_char) -> *mut libc::c_char {
    return strdelim_internal(s, 1 as libc::c_int);
}
pub unsafe extern "C" fn strdelimw(mut s: *mut *mut libc::c_char) -> *mut libc::c_char {
    return strdelim_internal(s, 0 as libc::c_int);
}
pub unsafe extern "C" fn pwcopy(mut pw: *mut libc::passwd) -> *mut libc::passwd {
    let mut copy: *mut libc::passwd = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<libc::passwd>() as libc::c_ulong,
    ) as *mut libc::passwd;
    (*copy).pw_name = crate::xmalloc::xstrdup((*pw).pw_name);
    (*copy).pw_passwd = crate::xmalloc::xstrdup(if ((*pw).pw_passwd).is_null() {
        b"*\0" as *const u8 as *const libc::c_char
    } else {
        (*pw).pw_passwd as *const libc::c_char
    });
    (*copy).pw_gecos = crate::xmalloc::xstrdup((*pw).pw_gecos);
    (*copy).pw_uid = (*pw).pw_uid;
    (*copy).pw_gid = (*pw).pw_gid;
    (*copy).pw_dir = crate::xmalloc::xstrdup((*pw).pw_dir);
    (*copy).pw_shell = crate::xmalloc::xstrdup((*pw).pw_shell);
    return copy;
}
pub unsafe extern "C" fn a2port(mut s: *const libc::c_char) -> libc::c_int {
    let mut se: *mut servent = 0 as *mut servent;
    let mut port: libc::c_longlong = 0;
    let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
    port = crate::openbsd_compat::strtonum::strtonum(
        s,
        0 as libc::c_int as libc::c_longlong,
        65535 as libc::c_int as libc::c_longlong,
        &mut errstr,
    );
    if errstr.is_null() {
        return port as libc::c_int;
    }
    se = getservbyname(s, b"tcp\0" as *const u8 as *const libc::c_char);
    if !se.is_null() {
        return __bswap_16((*se).s_port as __uint16_t) as libc::c_int;
    }
    return -(1 as libc::c_int);
}
pub unsafe extern "C" fn a2tun(
    mut s: *const libc::c_char,
    mut remote: *mut libc::c_int,
) -> libc::c_int {
    let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
    let mut sp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tun: libc::c_int = 0;
    if !remote.is_null() {
        *remote = 0x7fffffff as libc::c_int;
        sp = crate::xmalloc::xstrdup(s);
        ep = strchr(sp, ':' as i32);
        if ep.is_null() {
            libc::free(sp as *mut libc::c_void);
            return a2tun(s, 0 as *mut libc::c_int);
        }
        *ep.offset(0 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
        ep = ep.offset(1);
        ep;
        *remote = a2tun(ep, 0 as *mut libc::c_int);
        tun = a2tun(sp, 0 as *mut libc::c_int);
        libc::free(sp as *mut libc::c_void);
        return if *remote == 0x7fffffff as libc::c_int - 1 as libc::c_int {
            *remote
        } else {
            tun
        };
    }
    if strcasecmp(s, b"any\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 0x7fffffff as libc::c_int;
    }
    tun = crate::openbsd_compat::strtonum::strtonum(
        s,
        0 as libc::c_int as libc::c_longlong,
        (0x7fffffff as libc::c_int - 2 as libc::c_int) as libc::c_longlong,
        &mut errstr,
    ) as libc::c_int;
    if !errstr.is_null() {
        return 0x7fffffff as libc::c_int - 1 as libc::c_int;
    }
    return tun;
}
pub unsafe extern "C" fn convtime(mut s: *const libc::c_char) -> libc::c_int {
    let mut total: libc::c_long = 0;
    let mut secs: libc::c_long = 0;
    let mut multiplier: libc::c_long = 0;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut endp: *mut libc::c_char = 0 as *mut libc::c_char;
    *libc::__errno_location() = 0 as libc::c_int;
    total = 0 as libc::c_int as libc::c_long;
    p = s;
    if p.is_null() || *p as libc::c_int == '\0' as i32 {
        return -(1 as libc::c_int);
    }
    while *p != 0 {
        secs = strtol(p, &mut endp, 10 as libc::c_int);
        if p == endp as *const libc::c_char
            || *libc::__errno_location() == 34 as libc::c_int
                && (secs == (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
                    || secs == 2147483647 as libc::c_int as libc::c_long)
            || secs < 0 as libc::c_int as libc::c_long
        {
            return -(1 as libc::c_int);
        }
        multiplier = 1 as libc::c_int as libc::c_long;
        let fresh0 = endp;
        endp = endp.offset(1);
        match *fresh0 as libc::c_int {
            0 => {
                endp = endp.offset(-1);
                endp;
            }
            115 | 83 => {}
            109 | 77 => {
                multiplier = (1 as libc::c_int * 60 as libc::c_int) as libc::c_long;
            }
            104 | 72 => {
                multiplier =
                    (1 as libc::c_int * 60 as libc::c_int * 60 as libc::c_int) as libc::c_long;
            }
            100 | 68 => {
                multiplier =
                    (1 as libc::c_int * 60 as libc::c_int * 60 as libc::c_int * 24 as libc::c_int)
                        as libc::c_long;
            }
            119 | 87 => {
                multiplier = (1 as libc::c_int
                    * 60 as libc::c_int
                    * 60 as libc::c_int
                    * 24 as libc::c_int
                    * 7 as libc::c_int) as libc::c_long;
            }
            _ => return -(1 as libc::c_int),
        }
        if secs > 2147483647 as libc::c_int as libc::c_long / multiplier {
            return -(1 as libc::c_int);
        }
        secs *= multiplier;
        if total > 2147483647 as libc::c_int as libc::c_long - secs {
            return -(1 as libc::c_int);
        }
        total += secs;
        if total < 0 as libc::c_int as libc::c_long {
            return -(1 as libc::c_int);
        }
        p = endp;
    }
    return total as libc::c_int;
}
pub unsafe extern "C" fn fmt_timeframe(mut t: time_t) -> *const libc::c_char {
    let mut buf: *mut libc::c_char = 0 as *mut libc::c_char;
    static mut tfbuf: [[libc::c_char; 9]; 8] = [[0; 9]; 8];
    static mut idx: libc::c_int = 0 as libc::c_int;
    let mut sec: libc::c_uint = 0;
    let mut min: libc::c_uint = 0;
    let mut hrs: libc::c_uint = 0;
    let mut day: libc::c_uint = 0;
    let mut week: libc::c_ulonglong = 0;
    let fresh1 = idx;
    idx = idx + 1;
    buf = (tfbuf[fresh1 as usize]).as_mut_ptr();
    if idx == 8 as libc::c_int {
        idx = 0 as libc::c_int;
    }
    week = t as libc::c_ulonglong;
    sec = week.wrapping_rem(60 as libc::c_int as libc::c_ulonglong) as libc::c_uint;
    week = week.wrapping_div(60 as libc::c_int as libc::c_ulonglong);
    min = week.wrapping_rem(60 as libc::c_int as libc::c_ulonglong) as libc::c_uint;
    week = week.wrapping_div(60 as libc::c_int as libc::c_ulonglong);
    hrs = week.wrapping_rem(24 as libc::c_int as libc::c_ulonglong) as libc::c_uint;
    week = week.wrapping_div(24 as libc::c_int as libc::c_ulonglong);
    day = week.wrapping_rem(7 as libc::c_int as libc::c_ulonglong) as libc::c_uint;
    week = week.wrapping_div(7 as libc::c_int as libc::c_ulonglong);
    if week > 0 as libc::c_int as libc::c_ulonglong {
        libc::snprintf(
            buf,
            9 as libc::c_int as usize,
            b"%02lluw%01ud%02uh\0" as *const u8 as *const libc::c_char,
            week,
            day,
            hrs,
        );
    } else if day > 0 as libc::c_int as libc::c_uint {
        libc::snprintf(
            buf,
            9 as libc::c_int as usize,
            b"%01ud%02uh%02um\0" as *const u8 as *const libc::c_char,
            day,
            hrs,
            min,
        );
    } else {
        libc::snprintf(
            buf,
            9 as libc::c_int as usize,
            b"%02u:%02u:%02u\0" as *const u8 as *const libc::c_char,
            hrs,
            min,
            sec,
        );
    }
    return buf;
}
pub unsafe extern "C" fn put_host_port(
    mut host: *const libc::c_char,
    mut port: u_short,
) -> *mut libc::c_char {
    let mut hoststr: *mut libc::c_char = 0 as *mut libc::c_char;
    if port as libc::c_int == 0 as libc::c_int || port as libc::c_int == 22 as libc::c_int {
        return crate::xmalloc::xstrdup(host);
    }
    if asprintf(
        &mut hoststr as *mut *mut libc::c_char,
        b"[%s]:%d\0" as *const u8 as *const libc::c_char,
        host,
        port as libc::c_int,
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"put_host_port\0"))
                .as_ptr(),
            672 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"put_host_port: asprintf: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    crate::log::sshlog(
        b"misc.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"put_host_port\0")).as_ptr(),
        673 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"put_host_port: %s\0" as *const u8 as *const libc::c_char,
        hoststr,
    );
    return hoststr;
}
pub unsafe extern "C" fn hpdelim2(
    mut cp: *mut *mut libc::c_char,
    mut delim: *mut libc::c_char,
) -> *mut libc::c_char {
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut old: *mut libc::c_char = 0 as *mut libc::c_char;
    if cp.is_null() || (*cp).is_null() {
        return 0 as *mut libc::c_char;
    }
    s = *cp;
    old = s;
    if *s as libc::c_int == '[' as i32 {
        s = strchr(s, ']' as i32);
        if s.is_null() {
            return 0 as *mut libc::c_char;
        } else {
            s = s.offset(1);
            s;
        }
    } else {
        s = strpbrk(s, b":/\0" as *const u8 as *const libc::c_char);
        if s.is_null() {
            s = (*cp).offset(strlen(*cp) as isize);
        }
    }
    match *s as libc::c_int {
        0 => {
            *cp = 0 as *mut libc::c_char;
        }
        58 | 47 => {
            if !delim.is_null() {
                *delim = *s;
            }
            *s = '\0' as i32 as libc::c_char;
            *cp = s.offset(1 as libc::c_int as isize);
        }
        _ => return 0 as *mut libc::c_char,
    }
    return old;
}
pub unsafe extern "C" fn hpdelim(mut cp: *mut *mut libc::c_char) -> *mut libc::c_char {
    let mut r: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut delim: libc::c_char = '\0' as i32 as libc::c_char;
    r = hpdelim2(cp, &mut delim);
    if delim as libc::c_int == '/' as i32 {
        return 0 as *mut libc::c_char;
    }
    return r;
}
pub unsafe extern "C" fn cleanhostname(mut host: *mut libc::c_char) -> *mut libc::c_char {
    if *host as libc::c_int == '[' as i32
        && *host.offset((strlen(host)).wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
            as libc::c_int
            == ']' as i32
    {
        *host.offset((strlen(host)).wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize) =
            '\0' as i32 as libc::c_char;
        return host.offset(1 as libc::c_int as isize);
    } else {
        return host;
    };
}
pub unsafe extern "C" fn colon(mut cp: *mut libc::c_char) -> *mut libc::c_char {
    let mut flag: libc::c_int = 0 as libc::c_int;
    if *cp as libc::c_int == ':' as i32 {
        return 0 as *mut libc::c_char;
    }
    if *cp as libc::c_int == '[' as i32 {
        flag = 1 as libc::c_int;
    }
    while *cp != 0 {
        if *cp as libc::c_int == '@' as i32
            && *cp.offset(1 as libc::c_int as isize) as libc::c_int == '[' as i32
        {
            flag = 1 as libc::c_int;
        }
        if *cp as libc::c_int == ']' as i32
            && *cp.offset(1 as libc::c_int as isize) as libc::c_int == ':' as i32
            && flag != 0
        {
            return cp.offset(1 as libc::c_int as isize);
        }
        if *cp as libc::c_int == ':' as i32 && flag == 0 {
            return cp;
        }
        if *cp as libc::c_int == '/' as i32 {
            return 0 as *mut libc::c_char;
        }
        cp = cp.offset(1);
        cp;
    }
    return 0 as *mut libc::c_char;
}
pub unsafe extern "C" fn parse_user_host_path(
    mut s: *const libc::c_char,
    mut userp: *mut *mut libc::c_char,
    mut hostp: *mut *mut libc::c_char,
    mut pathp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sdup: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if !userp.is_null() {
        *userp = 0 as *mut libc::c_char;
    }
    if !hostp.is_null() {
        *hostp = 0 as *mut libc::c_char;
    }
    if !pathp.is_null() {
        *pathp = 0 as *mut libc::c_char;
    }
    sdup = crate::xmalloc::xstrdup(s);
    tmp = colon(sdup);
    if !tmp.is_null() {
        let fresh2 = tmp;
        tmp = tmp.offset(1);
        *fresh2 = '\0' as i32 as libc::c_char;
        if *tmp as libc::c_int == '\0' as i32 {
            tmp = b".\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
        path = crate::xmalloc::xstrdup(tmp);
        tmp = strrchr(sdup, '@' as i32);
        if !tmp.is_null() {
            let fresh3 = tmp;
            tmp = tmp.offset(1);
            *fresh3 = '\0' as i32 as libc::c_char;
            host = crate::xmalloc::xstrdup(cleanhostname(tmp));
            if *sdup as libc::c_int != '\0' as i32 {
                user = crate::xmalloc::xstrdup(sdup);
            }
        } else {
            host = crate::xmalloc::xstrdup(cleanhostname(sdup));
            user = 0 as *mut libc::c_char;
        }
        if !userp.is_null() {
            *userp = user;
            user = 0 as *mut libc::c_char;
        }
        if !hostp.is_null() {
            *hostp = host;
            host = 0 as *mut libc::c_char;
        }
        if !pathp.is_null() {
            *pathp = path;
            path = 0 as *mut libc::c_char;
        }
        ret = 0 as libc::c_int;
    }
    libc::free(sdup as *mut libc::c_void);
    libc::free(user as *mut libc::c_void);
    libc::free(host as *mut libc::c_void);
    libc::free(path as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn parse_user_host_port(
    mut s: *const libc::c_char,
    mut userp: *mut *mut libc::c_char,
    mut hostp: *mut *mut libc::c_char,
    mut portp: *mut libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut sdup: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut port: libc::c_int = -(1 as libc::c_int);
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if !userp.is_null() {
        *userp = 0 as *mut libc::c_char;
    }
    if !hostp.is_null() {
        *hostp = 0 as *mut libc::c_char;
    }
    if !portp.is_null() {
        *portp = -(1 as libc::c_int);
    }
    tmp = strdup(s);
    sdup = tmp;
    if sdup.is_null() {
        return -(1 as libc::c_int);
    }
    cp = strrchr(tmp, '@' as i32);
    if !cp.is_null() {
        *cp = '\0' as i32 as libc::c_char;
        if *tmp as libc::c_int == '\0' as i32 {
            current_block = 13070338142174459458;
        } else {
            user = strdup(tmp);
            if user.is_null() {
                current_block = 13070338142174459458;
            } else {
                tmp = cp.offset(1 as libc::c_int as isize);
                current_block = 12209867499936983673;
            }
        }
    } else {
        current_block = 12209867499936983673;
    }
    match current_block {
        12209867499936983673 => {
            cp = hpdelim(&mut tmp);
            if !(cp.is_null() || *cp as libc::c_int == '\0' as i32) {
                host = crate::xmalloc::xstrdup(cleanhostname(cp));
                if !tmp.is_null() && *tmp as libc::c_int != '\0' as i32 {
                    port = a2port(tmp);
                    if port <= 0 as libc::c_int {
                        current_block = 13070338142174459458;
                    } else {
                        current_block = 13056961889198038528;
                    }
                } else {
                    current_block = 13056961889198038528;
                }
                match current_block {
                    13070338142174459458 => {}
                    _ => {
                        if !userp.is_null() {
                            *userp = user;
                            user = 0 as *mut libc::c_char;
                        }
                        if !hostp.is_null() {
                            *hostp = host;
                            host = 0 as *mut libc::c_char;
                        }
                        if !portp.is_null() {
                            *portp = port;
                        }
                        ret = 0 as libc::c_int;
                    }
                }
            }
        }
        _ => {}
    }
    libc::free(sdup as *mut libc::c_void);
    libc::free(user as *mut libc::c_void);
    libc::free(host as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn hexchar(mut s: *const libc::c_char) -> libc::c_int {
    let mut result: [libc::c_uchar; 2] = [0; 2];
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 2 as libc::c_int {
        if *s.offset(i as isize) as libc::c_int >= '0' as i32
            && *s.offset(i as isize) as libc::c_int <= '9' as i32
        {
            result[i as usize] =
                (*s.offset(i as isize) as libc::c_int - '0' as i32) as libc::c_uchar;
        } else if *s.offset(i as isize) as libc::c_int >= 'a' as i32
            && *s.offset(i as isize) as libc::c_int <= 'f' as i32
        {
            result[i as usize] = ((*s.offset(i as isize) as libc::c_int - 'a' as i32)
                as libc::c_uchar as libc::c_int
                + 10 as libc::c_int) as libc::c_uchar;
        } else if *s.offset(i as isize) as libc::c_int >= 'A' as i32
            && *s.offset(i as isize) as libc::c_int <= 'F' as i32
        {
            result[i as usize] = ((*s.offset(i as isize) as libc::c_int - 'A' as i32)
                as libc::c_uchar as libc::c_int
                + 10 as libc::c_int) as libc::c_uchar;
        } else {
            return -(1 as libc::c_int);
        }
        i += 1;
        i;
    }
    return (result[0 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int
        | result[1 as libc::c_int as usize] as libc::c_int;
}
unsafe extern "C" fn urldecode(mut src: *const libc::c_char) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut dst: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ch: libc::c_int = 0;
    ret = crate::xmalloc::xmalloc((strlen(src)).wrapping_add(1 as libc::c_int as libc::c_ulong))
        as *mut libc::c_char;
    dst = ret;
    while *src as libc::c_int != '\0' as i32 {
        match *src as libc::c_int {
            43 => {
                let fresh4 = dst;
                dst = dst.offset(1);
                *fresh4 = ' ' as i32 as libc::c_char;
            }
            37 => {
                if *(*__ctype_b_loc()).offset(*src.offset(1 as libc::c_int as isize)
                    as libc::c_uchar as libc::c_int
                    as isize) as libc::c_int
                    & _ISxdigit as libc::c_int as libc::c_ushort as libc::c_int
                    == 0
                    || *(*__ctype_b_loc())
                        .offset(*src.offset(2 as libc::c_int as isize) as libc::c_uchar
                            as libc::c_int as isize) as libc::c_int
                        & _ISxdigit as libc::c_int as libc::c_ushort as libc::c_int
                        == 0
                    || {
                        ch = hexchar(src.offset(1 as libc::c_int as isize));
                        ch == -(1 as libc::c_int)
                    }
                {
                    libc::free(ret as *mut libc::c_void);
                    return 0 as *mut libc::c_char;
                }
                let fresh5 = dst;
                dst = dst.offset(1);
                *fresh5 = ch as libc::c_char;
                src = src.offset(2 as libc::c_int as isize);
            }
            _ => {
                let fresh6 = dst;
                dst = dst.offset(1);
                *fresh6 = *src;
            }
        }
        src = src.offset(1);
        src;
    }
    *dst = '\0' as i32 as libc::c_char;
    return ret;
}
pub unsafe extern "C" fn parse_uri(
    mut scheme: *const libc::c_char,
    mut uri: *const libc::c_char,
    mut userp: *mut *mut libc::c_char,
    mut hostp: *mut *mut libc::c_char,
    mut portp: *mut libc::c_int,
    mut pathp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut uridup: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ch: libc::c_char = 0;
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut port: libc::c_int = -(1 as libc::c_int);
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut len: size_t = 0;
    len = strlen(scheme);
    if strncmp(uri, scheme, len) != 0 as libc::c_int
        || strncmp(
            uri.offset(len as isize),
            b"://\0" as *const u8 as *const libc::c_char,
            3 as libc::c_int as libc::c_ulong,
        ) != 0 as libc::c_int
    {
        return 1 as libc::c_int;
    }
    uri = uri.offset(len.wrapping_add(3 as libc::c_int as libc::c_ulong) as isize);
    if !userp.is_null() {
        *userp = 0 as *mut libc::c_char;
    }
    if !hostp.is_null() {
        *hostp = 0 as *mut libc::c_char;
    }
    if !portp.is_null() {
        *portp = -(1 as libc::c_int);
    }
    if !pathp.is_null() {
        *pathp = 0 as *mut libc::c_char;
    }
    tmp = crate::xmalloc::xstrdup(uri);
    uridup = tmp;
    cp = strchr(tmp, '@' as i32);
    if !cp.is_null() {
        let mut delim: *mut libc::c_char = 0 as *mut libc::c_char;
        *cp = '\0' as i32 as libc::c_char;
        delim = strchr(tmp, ';' as i32);
        if !delim.is_null() {
            *delim = '\0' as i32 as libc::c_char;
        }
        if *tmp as libc::c_int == '\0' as i32 {
            current_block = 2216349558745544267;
        } else {
            user = urldecode(tmp);
            if user.is_null() {
                current_block = 2216349558745544267;
            } else {
                tmp = cp.offset(1 as libc::c_int as isize);
                current_block = 6057473163062296781;
            }
        }
    } else {
        current_block = 6057473163062296781;
    }
    match current_block {
        6057473163062296781 => {
            cp = hpdelim2(&mut tmp, &mut ch);
            if !(cp.is_null() || *cp as libc::c_int == '\0' as i32) {
                host = crate::xmalloc::xstrdup(cleanhostname(cp));
                if !(valid_domain(host, 0 as libc::c_int, 0 as *mut *const libc::c_char) == 0) {
                    if !tmp.is_null() && *tmp as libc::c_int != '\0' as i32 {
                        if ch as libc::c_int == ':' as i32 {
                            cp = strchr(tmp, '/' as i32);
                            if !cp.is_null() {
                                *cp = '\0' as i32 as libc::c_char;
                            }
                            port = a2port(tmp);
                            if port <= 0 as libc::c_int {
                                current_block = 2216349558745544267;
                            } else {
                                tmp = if !cp.is_null() {
                                    cp.offset(1 as libc::c_int as isize)
                                } else {
                                    0 as *mut libc::c_char
                                };
                                current_block = 7056779235015430508;
                            }
                        } else {
                            current_block = 7056779235015430508;
                        }
                        match current_block {
                            2216349558745544267 => {}
                            _ => {
                                if !tmp.is_null() && *tmp as libc::c_int != '\0' as i32 {
                                    path = urldecode(tmp);
                                    if path.is_null() {
                                        current_block = 2216349558745544267;
                                    } else {
                                        current_block = 5689316957504528238;
                                    }
                                } else {
                                    current_block = 5689316957504528238;
                                }
                            }
                        }
                    } else {
                        current_block = 5689316957504528238;
                    }
                    match current_block {
                        2216349558745544267 => {}
                        _ => {
                            if !userp.is_null() {
                                *userp = user;
                                user = 0 as *mut libc::c_char;
                            }
                            if !hostp.is_null() {
                                *hostp = host;
                                host = 0 as *mut libc::c_char;
                            }
                            if !portp.is_null() {
                                *portp = port;
                            }
                            if !pathp.is_null() {
                                *pathp = path;
                                path = 0 as *mut libc::c_char;
                            }
                            ret = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    libc::free(uridup as *mut libc::c_void);
    libc::free(user as *mut libc::c_void);
    libc::free(host as *mut libc::c_void);
    libc::free(path as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn addargs(
    mut args: *mut arglist,
    mut fmt: *mut libc::c_char,
    mut args_0: ...
) {
    let mut ap: ::core::ffi::VaListImpl;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut nalloc: u_int = 0;
    let mut r: libc::c_int = 0;
    ap = args_0.clone();
    r = vasprintf(&mut cp, fmt, ap.as_va_list());
    if r == -(1 as libc::c_int) {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"addargs\0")).as_ptr(),
            1072 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"argument too long\0" as *const u8 as *const libc::c_char,
        );
    }
    nalloc = (*args).nalloc;
    if ((*args).list).is_null() {
        nalloc = 32 as libc::c_int as u_int;
        (*args).num = 0 as libc::c_int as u_int;
    } else if (*args).num > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_uint {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"addargs\0")).as_ptr(),
            1079 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"too many arguments\0" as *const u8 as *const libc::c_char,
        );
    } else if (*args).num >= (*args).nalloc {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"addargs\0")).as_ptr(),
            1081 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"arglist corrupt\0" as *const u8 as *const libc::c_char,
        );
    } else if ((*args).num).wrapping_add(2 as libc::c_int as libc::c_uint) >= nalloc {
        nalloc = (nalloc as libc::c_uint).wrapping_mul(2 as libc::c_int as libc::c_uint) as u_int
            as u_int;
    }
    (*args).list = crate::xmalloc::xrecallocarray(
        (*args).list as *mut libc::c_void,
        (*args).nalloc as size_t,
        nalloc as size_t,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    (*args).nalloc = nalloc;
    let fresh7 = (*args).num;
    (*args).num = ((*args).num).wrapping_add(1);
    let ref mut fresh8 = *((*args).list).offset(fresh7 as isize);
    *fresh8 = cp;
    let ref mut fresh9 = *((*args).list).offset((*args).num as isize);
    *fresh9 = 0 as *mut libc::c_char;
}
pub unsafe extern "C" fn replacearg(
    mut args: *mut arglist,
    mut which: u_int,
    mut fmt: *mut libc::c_char,
    mut args_0: ...
) {
    let mut ap: ::core::ffi::VaListImpl;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    ap = args_0.clone();
    r = vasprintf(&mut cp, fmt, ap.as_va_list());
    if r == -(1 as libc::c_int) {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"replacearg\0")).as_ptr(),
            1103 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"argument too long\0" as *const u8 as *const libc::c_char,
        );
    }
    if ((*args).list).is_null() || (*args).num >= (*args).nalloc {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"replacearg\0")).as_ptr(),
            1105 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"arglist corrupt\0" as *const u8 as *const libc::c_char,
        );
    }
    if which >= (*args).num {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"replacearg\0")).as_ptr(),
            1109 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"tried to replace invalid arg %d >= %d\0" as *const u8 as *const libc::c_char,
            which,
            (*args).num,
        );
    }
    libc::free(*((*args).list).offset(which as isize) as *mut libc::c_void);
    let ref mut fresh10 = *((*args).list).offset(which as isize);
    *fresh10 = cp;
}
pub unsafe extern "C" fn freeargs(mut args: *mut arglist) {
    let mut i: u_int = 0;
    if args.is_null() {
        return;
    }
    if !((*args).list).is_null() && (*args).num < (*args).nalloc {
        i = 0 as libc::c_int as u_int;
        while i < (*args).num {
            libc::free(*((*args).list).offset(i as isize) as *mut libc::c_void);
            i = i.wrapping_add(1);
            i;
        }
        libc::free((*args).list as *mut libc::c_void);
    }
    (*args).num = 0 as libc::c_int as u_int;
    (*args).nalloc = (*args).num;
    (*args).list = 0 as *mut *mut libc::c_char;
}
pub unsafe extern "C" fn tilde_expand(
    mut filename: *const libc::c_char,
    mut uid: uid_t,
    mut retp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ocopy: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut copy: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut path: *const libc::c_char = 0 as *const libc::c_char;
    let mut user: *const libc::c_char = 0 as *const libc::c_char;
    let mut pw: *mut libc::passwd = 0 as *mut libc::passwd;
    let mut len: size_t = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut r: libc::c_int = 0;
    let mut slash: libc::c_int = 0;
    *retp = 0 as *mut libc::c_char;
    if *filename as libc::c_int != '~' as i32 {
        *retp = crate::xmalloc::xstrdup(filename);
        return 0 as libc::c_int;
    }
    copy = crate::xmalloc::xstrdup(filename.offset(1 as libc::c_int as isize));
    ocopy = copy;
    if *copy as libc::c_int == '\0' as i32 {
        path = 0 as *const libc::c_char;
    } else if *copy as libc::c_int == '/' as i32 {
        copy = copy.offset(strspn(copy, b"/\0" as *const u8 as *const libc::c_char) as isize);
        if *copy as libc::c_int == '\0' as i32 {
            path = 0 as *const libc::c_char;
        } else {
            path = copy;
        }
    } else {
        user = copy;
        path = strchr(copy, '/' as i32);
        if !path.is_null() {
            *copy.offset(path.offset_from(copy) as libc::c_long as isize) =
                '\0' as i32 as libc::c_char;
            path = path.offset(1);
            path;
            path = path.offset(strspn(path, b"/\0" as *const u8 as *const libc::c_char) as isize);
            if *path as libc::c_int == '\0' as i32 {
                path = 0 as *const libc::c_char;
            }
        }
    }
    if !user.is_null() {
        pw = getpwnam(user);
        if pw.is_null() {
            crate::log::sshlog(
                b"misc.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"tilde_expand\0"))
                    .as_ptr(),
                1172 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"No such user %s\0" as *const u8 as *const libc::c_char,
                user,
            );
            current_block = 3447911797953833866;
        } else {
            current_block = 17478428563724192186;
        }
    } else {
        pw = libc::getpwuid(uid);
        if pw.is_null() {
            crate::log::sshlog(
                b"misc.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"tilde_expand\0"))
                    .as_ptr(),
                1176 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"No such uid %ld\0" as *const u8 as *const libc::c_char,
                uid as libc::c_long,
            );
            current_block = 3447911797953833866;
        } else {
            current_block = 17478428563724192186;
        }
    }
    match current_block {
        17478428563724192186 => {
            len = strlen((*pw).pw_dir);
            slash = (len == 0 as libc::c_int as libc::c_ulong
                || *((*pw).pw_dir)
                    .offset(len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
                    as libc::c_int
                    != '/' as i32) as libc::c_int;
            r = crate::xmalloc::xasprintf(
                &mut s as *mut *mut libc::c_char,
                b"%s%s%s\0" as *const u8 as *const libc::c_char,
                (*pw).pw_dir,
                if slash != 0 {
                    b"/\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                if !path.is_null() {
                    path
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
            );
            if r <= 0 as libc::c_int {
                crate::log::sshlog(
                    b"misc.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"tilde_expand\0"))
                        .as_ptr(),
                    1185 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"crate::xmalloc::xasprintf failed\0" as *const u8 as *const libc::c_char,
                );
            } else if r >= 4096 as libc::c_int {
                crate::log::sshlog(
                    b"misc.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"tilde_expand\0"))
                        .as_ptr(),
                    1189 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Path too long\0" as *const u8 as *const libc::c_char,
                );
            } else {
                ret = 0 as libc::c_int;
                *retp = s;
                s = 0 as *mut libc::c_char;
            }
        }
        _ => {}
    }
    libc::free(s as *mut libc::c_void);
    libc::free(ocopy as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn tilde_expand_filename(
    mut filename: *const libc::c_char,
    mut uid: uid_t,
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    if tilde_expand(filename, uid, &mut ret) != 0 as libc::c_int {
        cleanup_exit(255 as libc::c_int);
    }
    return ret;
}
unsafe extern "C" fn vdollar_percent_expand(
    mut parseerror: *mut libc::c_int,
    mut dollar: libc::c_int,
    mut percent: libc::c_int,
    mut string: *const libc::c_char,
    mut ap: ::core::ffi::VaList,
) -> *mut libc::c_char {
    let mut current_block: u64;
    let mut num_keys: u_int = 0 as libc::c_int as u_int;
    let mut i: u_int = 0;
    let mut keys: [C2RustUnnamed_13; 16] = [C2RustUnnamed_13 {
        key: 0 as *const libc::c_char,
        repl: 0 as *const libc::c_char,
    }; 16];
    let mut buf: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    let mut missingvar: libc::c_int = 0 as libc::c_int;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut var: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut varend: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut val: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;
    buf = sshbuf_new();
    if buf.is_null() {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"vdollar_percent_expand\0",
            ))
            .as_ptr(),
            1235 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if parseerror.is_null() {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"vdollar_percent_expand\0",
            ))
            .as_ptr(),
            1237 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"null parseerror arg\0" as *const u8 as *const libc::c_char,
        );
    }
    *parseerror = 1 as libc::c_int;
    if percent != 0 {
        num_keys = 0 as libc::c_int as u_int;
        while num_keys < 16 as libc::c_int as libc::c_uint {
            keys[num_keys as usize].key = ap.arg::<*mut libc::c_char>();
            if (keys[num_keys as usize].key).is_null() {
                break;
            }
            keys[num_keys as usize].repl = ap.arg::<*mut libc::c_char>();
            if (keys[num_keys as usize].repl).is_null() {
                sshfatal(
                    b"misc.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"vdollar_percent_expand\0",
                    ))
                    .as_ptr(),
                    1249 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"NULL replacement for token %s\0" as *const u8 as *const libc::c_char,
                    keys[num_keys as usize].key,
                );
            }
            num_keys = num_keys.wrapping_add(1);
            num_keys;
        }
        if num_keys == 16 as libc::c_int as libc::c_uint && !ap.arg::<*mut libc::c_char>().is_null()
        {
            sshfatal(
                b"misc.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"vdollar_percent_expand\0",
                ))
                .as_ptr(),
                1253 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"too many keys\0" as *const u8 as *const libc::c_char,
            );
        }
        if num_keys == 0 as libc::c_int as libc::c_uint {
            sshfatal(
                b"misc.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"vdollar_percent_expand\0",
                ))
                .as_ptr(),
                1255 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"percent expansion without token list\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    i = 0 as libc::c_int as u_int;
    loop {
        if !(*string as libc::c_int != '\0' as i32) {
            current_block = 13460095289871124136;
            break;
        }
        if dollar != 0
            && *string.offset(0 as libc::c_int as isize) as libc::c_int == '$' as i32
            && *string.offset(1 as libc::c_int as isize) as libc::c_int == '{' as i32
        {
            string = string.offset(2 as libc::c_int as isize);
            varend = strchr(string, '}' as i32);
            if varend.is_null() {
                crate::log::sshlog(
                    b"misc.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"vdollar_percent_expand\0",
                    ))
                    .as_ptr(),
                    1265 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"environment variable '%s' missing closing '}'\0" as *const u8
                        as *const libc::c_char,
                    string,
                );
                current_block = 17254736040813544624;
                break;
            } else {
                len = varend.offset_from(string) as libc::c_long as size_t;
                if len == 0 as libc::c_int as libc::c_ulong {
                    crate::log::sshlog(
                        b"misc.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                            b"vdollar_percent_expand\0",
                        ))
                        .as_ptr(),
                        1270 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"zero-length environment variable\0" as *const u8 as *const libc::c_char,
                    );
                    current_block = 17254736040813544624;
                    break;
                } else {
                    var = crate::xmalloc::xmalloc(
                        len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                    ) as *mut libc::c_char;
                    strlcpy(
                        var,
                        string,
                        len.wrapping_add(1 as libc::c_int as libc::c_ulong),
                    );
                    val = getenv(var);
                    if val.is_null() {
                        crate::log::sshlog(
                            b"misc.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                b"vdollar_percent_expand\0",
                            ))
                            .as_ptr(),
                            1276 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"env var ${%s} has no value\0" as *const u8 as *const libc::c_char,
                            var,
                        );
                        missingvar = 1 as libc::c_int;
                    } else {
                        crate::log::sshlog(
                            b"misc.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                b"vdollar_percent_expand\0",
                            ))
                            .as_ptr(),
                            1279 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG3,
                            0 as *const libc::c_char,
                            b"expand ${%s} -> '%s'\0" as *const u8 as *const libc::c_char,
                            var,
                            val,
                        );
                        r = sshbuf_put(buf, val as *const libc::c_void, strlen(val));
                        if r != 0 as libc::c_int {
                            sshfatal(
                                b"misc.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                    b"vdollar_percent_expand\0",
                                ))
                                .as_ptr(),
                                1281 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                ssh_err(r),
                                b"sshbuf_put ${}\0" as *const u8 as *const libc::c_char,
                            );
                        }
                    }
                    libc::free(var as *mut libc::c_void);
                    string = string.offset(len as isize);
                }
            }
        } else {
            if *string as libc::c_int != '%' as i32 || percent == 0 {
                current_block = 16144055239010142754;
            } else {
                string = string.offset(1);
                string;
                if *string as libc::c_int == '%' as i32 {
                    current_block = 16144055239010142754;
                } else {
                    if *string as libc::c_int == '\0' as i32 {
                        crate::log::sshlog(
                            b"misc.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                b"vdollar_percent_expand\0",
                            ))
                            .as_ptr(),
                            1304 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"invalid format\0" as *const u8 as *const libc::c_char,
                        );
                        current_block = 17254736040813544624;
                        break;
                    } else {
                        i = 0 as libc::c_int as u_int;
                        while i < num_keys {
                            if !(strchr(keys[i as usize].key, *string as libc::c_int)).is_null() {
                                r = sshbuf_put(
                                    buf,
                                    keys[i as usize].repl as *const libc::c_void,
                                    strlen(keys[i as usize].repl),
                                );
                                if r != 0 as libc::c_int {
                                    sshfatal(
                                        b"misc.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                            b"vdollar_percent_expand\0",
                                        ))
                                        .as_ptr(),
                                        1311 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_FATAL,
                                        ssh_err(r),
                                        b"sshbuf_put %%-repl\0" as *const u8 as *const libc::c_char,
                                    );
                                }
                                break;
                            } else {
                                i = i.wrapping_add(1);
                                i;
                            }
                        }
                        if i >= num_keys {
                            crate::log::sshlog(
                                b"misc.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                    b"vdollar_percent_expand\0",
                                ))
                                .as_ptr(),
                                1316 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"unknown key %%%c\0" as *const u8 as *const libc::c_char,
                                *string as libc::c_int,
                            );
                            current_block = 17254736040813544624;
                            break;
                        }
                    }
                    current_block = 6009453772311597924;
                }
            }
            match current_block {
                6009453772311597924 => {}
                _ => {
                    r = sshbuf_put_u8(buf, *string as u_char);
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"misc.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                b"vdollar_percent_expand\0",
                            ))
                            .as_ptr(),
                            1296 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"sshbuf_put_u8 %%\0" as *const u8 as *const libc::c_char,
                        );
                    }
                }
            }
        }
        string = string.offset(1);
        string;
    }
    match current_block {
        13460095289871124136 => {
            if missingvar == 0 && {
                ret = sshbuf_dup_string(buf);
                ret.is_null()
            } {
                sshfatal(
                    b"misc.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"vdollar_percent_expand\0",
                    ))
                    .as_ptr(),
                    1321 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"sshbuf_dup_string failed\0" as *const u8 as *const libc::c_char,
                );
            }
            *parseerror = 0 as libc::c_int;
        }
        _ => {}
    }
    sshbuf_free(buf);
    return if *parseerror != 0 {
        0 as *mut libc::c_char
    } else {
        ret
    };
}
pub unsafe extern "C" fn dollar_expand(
    mut parseerr: *mut libc::c_int,
    mut string: *const libc::c_char,
    mut args: ...
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut err: libc::c_int = 0;
    let mut ap: ::core::ffi::VaListImpl;
    ap = args.clone();
    ret = vdollar_percent_expand(
        &mut err,
        1 as libc::c_int,
        0 as libc::c_int,
        string,
        ap.as_va_list(),
    );
    if !parseerr.is_null() {
        *parseerr = err;
    }
    return ret;
}
pub unsafe extern "C" fn percent_expand(
    mut string: *const libc::c_char,
    mut args: ...
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut err: libc::c_int = 0;
    let mut ap: ::core::ffi::VaListImpl;
    ap = args.clone();
    ret = vdollar_percent_expand(
        &mut err,
        0 as libc::c_int,
        1 as libc::c_int,
        string,
        ap.as_va_list(),
    );
    if err != 0 {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"percent_expand\0"))
                .as_ptr(),
            1365 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"failed\0" as *const u8 as *const libc::c_char,
        );
    }
    return ret;
}
pub unsafe extern "C" fn percent_dollar_expand(
    mut string: *const libc::c_char,
    mut args: ...
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut err: libc::c_int = 0;
    let mut ap: ::core::ffi::VaListImpl;
    ap = args.clone();
    ret = vdollar_percent_expand(
        &mut err,
        1 as libc::c_int,
        1 as libc::c_int,
        string,
        ap.as_va_list(),
    );
    if err != 0 {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"percent_dollar_expand\0"))
                .as_ptr(),
            1384 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"failed\0" as *const u8 as *const libc::c_char,
        );
    }
    return ret;
}
pub unsafe extern "C" fn tun_open(
    mut tun: libc::c_int,
    mut mode: libc::c_int,
    mut ifname: *mut *mut libc::c_char,
) -> libc::c_int {
    return sys_tun_open(tun, mode, ifname);
}
pub unsafe extern "C" fn sanitise_stdfd() {
    let mut nullfd: libc::c_int = 0;
    let mut dupfd: libc::c_int = 0;
    dupfd = libc::open(
        b"/dev/null\0" as *const u8 as *const libc::c_char,
        0o2 as libc::c_int,
    );
    nullfd = dupfd;
    if nullfd == -(1 as libc::c_int) {
        libc::fprintf(
            stderr,
            b"Couldn't open /dev/null: %s\n\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        libc::exit(1 as libc::c_int);
    }
    loop {
        dupfd += 1;
        if !(dupfd <= 2 as libc::c_int) {
            break;
        }
        if fcntl(dupfd, 3 as libc::c_int) == -(1 as libc::c_int)
            && *libc::__errno_location() == 9 as libc::c_int
        {
            if libc::dup2(nullfd, dupfd) == -(1 as libc::c_int) {
                libc::fprintf(
                    stderr,
                    b"libc::dup2: %s\n\0" as *const u8 as *const libc::c_char,
                    strerror(*libc::__errno_location()),
                );
                libc::exit(1 as libc::c_int);
            }
        }
    }
    if nullfd > 2 as libc::c_int {
        close(nullfd);
    }
}
pub unsafe extern "C" fn tohex(mut vp: *const libc::c_void, mut l: size_t) -> *mut libc::c_char {
    let mut p: *const u_char = vp as *const u_char;
    let mut b: [libc::c_char; 3] = [0; 3];
    let mut r: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: size_t = 0;
    let mut hl: size_t = 0;
    if l > 65536 as libc::c_int as libc::c_ulong {
        return crate::xmalloc::xstrdup(
            b"tohex: length > 65536\0" as *const u8 as *const libc::c_char,
        );
    }
    hl = l
        .wrapping_mul(2 as libc::c_int as libc::c_ulong)
        .wrapping_add(1 as libc::c_int as libc::c_ulong);
    r = crate::xmalloc::xcalloc(1 as libc::c_int as size_t, hl) as *mut libc::c_char;
    i = 0 as libc::c_int as size_t;
    while i < l {
        libc::snprintf(
            b.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 3]>() as usize,
            b"%02x\0" as *const u8 as *const libc::c_char,
            *p.offset(i as isize) as libc::c_int,
        );
        strlcat(r, b.as_mut_ptr(), hl);
        i = i.wrapping_add(1);
        i;
    }
    return r;
}
pub unsafe extern "C" fn xextendf(
    mut sp: *mut *mut libc::c_char,
    mut sep: *const libc::c_char,
    mut fmt: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::core::ffi::VaListImpl;
    let mut tmp1: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp2: *mut libc::c_char = 0 as *mut libc::c_char;
    ap = args.clone();
    xvasprintf(&mut tmp1, fmt, ap.as_va_list());
    if (*sp).is_null() || **sp as libc::c_int == '\0' as i32 {
        libc::free(*sp as *mut libc::c_void);
        *sp = tmp1;
        return;
    }
    crate::xmalloc::xasprintf(
        &mut tmp2 as *mut *mut libc::c_char,
        b"%s%s%s\0" as *const u8 as *const libc::c_char,
        *sp,
        if sep.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            sep
        },
        tmp1,
    );
    libc::free(tmp1 as *mut libc::c_void);
    libc::free(*sp as *mut libc::c_void);
    *sp = tmp2;
}
pub unsafe extern "C" fn get_u64(mut vp: *const libc::c_void) -> u_int64_t {
    let mut p: *const u_char = vp as *const u_char;
    let mut v: u_int64_t = 0;
    v = (*p.offset(0 as libc::c_int as isize) as u_int64_t) << 56 as libc::c_int;
    v |= (*p.offset(1 as libc::c_int as isize) as u_int64_t) << 48 as libc::c_int;
    v |= (*p.offset(2 as libc::c_int as isize) as u_int64_t) << 40 as libc::c_int;
    v |= (*p.offset(3 as libc::c_int as isize) as u_int64_t) << 32 as libc::c_int;
    v |= (*p.offset(4 as libc::c_int as isize) as u_int64_t) << 24 as libc::c_int;
    v |= (*p.offset(5 as libc::c_int as isize) as u_int64_t) << 16 as libc::c_int;
    v |= (*p.offset(6 as libc::c_int as isize) as u_int64_t) << 8 as libc::c_int;
    v |= *p.offset(7 as libc::c_int as isize) as u_int64_t;
    return v;
}
pub unsafe extern "C" fn get_u32(mut vp: *const libc::c_void) -> u_int32_t {
    let mut p: *const u_char = vp as *const u_char;
    let mut v: u_int32_t = 0;
    v = (*p.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int;
    v |= (*p.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int;
    v |= (*p.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int;
    v |= *p.offset(3 as libc::c_int as isize) as u_int32_t;
    return v;
}
pub unsafe extern "C" fn get_u32_le(mut vp: *const libc::c_void) -> u_int32_t {
    let mut p: *const u_char = vp as *const u_char;
    let mut v: u_int32_t = 0;
    v = *p.offset(0 as libc::c_int as isize) as u_int32_t;
    v |= (*p.offset(1 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int;
    v |= (*p.offset(2 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int;
    v |= (*p.offset(3 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int;
    return v;
}
pub unsafe extern "C" fn get_u16(mut vp: *const libc::c_void) -> u_int16_t {
    let mut p: *const u_char = vp as *const u_char;
    let mut v: u_int16_t = 0;
    v = ((*p.offset(0 as libc::c_int as isize) as u_int16_t as libc::c_int) << 8 as libc::c_int)
        as u_int16_t;
    v = (v as libc::c_int | *p.offset(1 as libc::c_int as isize) as u_int16_t as libc::c_int)
        as u_int16_t;
    return v;
}
pub unsafe extern "C" fn put_u64(mut vp: *mut libc::c_void, mut v: u_int64_t) {
    let mut p: *mut u_char = vp as *mut u_char;
    *p.offset(0 as libc::c_int as isize) =
        ((v >> 56 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(1 as libc::c_int as isize) =
        ((v >> 48 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(2 as libc::c_int as isize) =
        ((v >> 40 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(3 as libc::c_int as isize) =
        ((v >> 32 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(4 as libc::c_int as isize) =
        ((v >> 24 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(5 as libc::c_int as isize) =
        ((v >> 16 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(6 as libc::c_int as isize) =
        ((v >> 8 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(7 as libc::c_int as isize) =
        (v as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
}
pub unsafe extern "C" fn put_u32(mut vp: *mut libc::c_void, mut v: u_int32_t) {
    let mut p: *mut u_char = vp as *mut u_char;
    *p.offset(0 as libc::c_int as isize) =
        ((v >> 24 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(1 as libc::c_int as isize) =
        ((v >> 16 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(2 as libc::c_int as isize) =
        ((v >> 8 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(3 as libc::c_int as isize) =
        (v as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
}
pub unsafe extern "C" fn put_u32_le(mut vp: *mut libc::c_void, mut v: u_int32_t) {
    let mut p: *mut u_char = vp as *mut u_char;
    *p.offset(0 as libc::c_int as isize) =
        (v as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(1 as libc::c_int as isize) =
        ((v >> 8 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(2 as libc::c_int as isize) =
        ((v >> 16 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
    *p.offset(3 as libc::c_int as isize) =
        ((v >> 24 as libc::c_int) as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
}
pub unsafe extern "C" fn put_u16(mut vp: *mut libc::c_void, mut v: u_int16_t) {
    let mut p: *mut u_char = vp as *mut u_char;
    *p.offset(0 as libc::c_int as isize) = ((v as libc::c_int >> 8 as libc::c_int) as u_char
        as libc::c_int
        & 0xff as libc::c_int) as u_char;
    *p.offset(1 as libc::c_int as isize) =
        (v as u_char as libc::c_int & 0xff as libc::c_int) as u_char;
}
pub unsafe extern "C" fn ms_subtract_diff(mut start: *mut libc::timeval, mut ms: *mut libc::c_int) {
    let mut diff: libc::timeval = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut finish: libc::timeval = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    monotime_tv(&mut finish);
    diff.tv_sec = finish.tv_sec - (*start).tv_sec;
    diff.tv_usec = finish.tv_usec - (*start).tv_usec;
    if diff.tv_usec < 0 as libc::c_int as libc::c_long {
        diff.tv_sec -= 1;
        diff.tv_sec;
        diff.tv_usec += 1000000 as libc::c_int as libc::c_long;
    }
    *ms = (*ms as libc::c_long
        - (diff.tv_sec * 1000 as libc::c_int as libc::c_long
            + diff.tv_usec / 1000 as libc::c_int as libc::c_long)) as libc::c_int;
}
pub unsafe extern "C" fn ms_to_timespec(mut ts: *mut libc::timespec, mut ms: libc::c_int) {
    if ms < 0 as libc::c_int {
        ms = 0 as libc::c_int;
    }
    (*ts).tv_sec = (ms / 1000 as libc::c_int) as __time_t;
    (*ts).tv_nsec =
        (ms % 1000 as libc::c_int * 1000 as libc::c_int * 1000 as libc::c_int) as __syscall_slong_t;
}
pub unsafe extern "C" fn monotime_ts(mut ts: *mut libc::timespec) {
    let mut tv: libc::timeval = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    static mut gettime_failed: libc::c_int = 0 as libc::c_int;
    if gettime_failed == 0 {
        if clock_gettime(7 as libc::c_int, ts) == 0 as libc::c_int {
            return;
        }
        if clock_gettime(1 as libc::c_int, ts) == 0 as libc::c_int {
            return;
        }
        if clock_gettime(0 as libc::c_int, ts) == 0 as libc::c_int {
            return;
        }
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"monotime_ts\0")).as_ptr(),
            1680 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"clock_gettime: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        gettime_failed = 1 as libc::c_int;
    }
    gettimeofday(&mut tv, 0 as *mut libc::c_void);
    (*ts).tv_sec = tv.tv_sec;
    (*ts).tv_nsec = tv.tv_usec * 1000 as libc::c_int as libc::c_long;
}
pub unsafe extern "C" fn monotime_tv(mut tv: *mut libc::timeval) {
    let mut ts: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    monotime_ts(&mut ts);
    (*tv).tv_sec = ts.tv_sec;
    (*tv).tv_usec = ts.tv_nsec / 1000 as libc::c_int as libc::c_long;
}
pub unsafe extern "C" fn monotime() -> time_t {
    let mut ts: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    monotime_ts(&mut ts);
    return ts.tv_sec;
}
pub unsafe extern "C" fn monotime_double() -> libc::c_double {
    let mut ts: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    monotime_ts(&mut ts);
    return ts.tv_sec as libc::c_double
        + ts.tv_nsec as libc::c_double / 1000000000 as libc::c_int as libc::c_double;
}
pub unsafe extern "C" fn bandwidth_limit_init(
    mut bw: *mut bwlimit,
    mut kbps: u_int64_t,
    mut buflen: size_t,
) {
    (*bw).buflen = buflen;
    (*bw).rate = kbps;
    (*bw).thresh = buflen;
    (*bw).lamt = 0 as libc::c_int as u_int64_t;
    (*bw).bwstart.tv_usec = 0 as libc::c_int as __suseconds_t;
    (*bw).bwstart.tv_sec = (*bw).bwstart.tv_usec;
    (*bw).bwend.tv_usec = 0 as libc::c_int as __suseconds_t;
    (*bw).bwend.tv_sec = (*bw).bwend.tv_usec;
}
pub unsafe extern "C" fn bandwidth_limit(mut bw: *mut bwlimit, mut read_len: size_t) {
    let mut waitlen: u_int64_t = 0;
    let mut ts: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut rm: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    (*bw).lamt = ((*bw).lamt as libc::c_ulong).wrapping_add(read_len) as u_int64_t as u_int64_t;
    if !((*bw).bwstart.tv_sec != 0 || (*bw).bwstart.tv_usec != 0) {
        monotime_tv(&mut (*bw).bwstart);
        return;
    }
    if (*bw).lamt < (*bw).thresh {
        return;
    }
    monotime_tv(&mut (*bw).bwend);
    (*bw).bwend.tv_sec = (*bw).bwend.tv_sec - (*bw).bwstart.tv_sec;
    (*bw).bwend.tv_usec = (*bw).bwend.tv_usec - (*bw).bwstart.tv_usec;
    if (*bw).bwend.tv_usec < 0 as libc::c_int as libc::c_long {
        (*bw).bwend.tv_sec -= 1;
        (*bw).bwend.tv_sec;
        (*bw).bwend.tv_usec += 1000000 as libc::c_int as libc::c_long;
    }
    if !((*bw).bwend.tv_sec != 0 || (*bw).bwend.tv_usec != 0) {
        return;
    }
    (*bw).lamt = ((*bw).lamt as libc::c_ulong).wrapping_mul(8 as libc::c_int as libc::c_ulong)
        as u_int64_t as u_int64_t;
    waitlen = (1000000 as libc::c_long as libc::c_double * (*bw).lamt as libc::c_double
        / (*bw).rate as libc::c_double) as u_int64_t;
    (*bw).bwstart.tv_sec =
        waitlen.wrapping_div(1000000 as libc::c_long as libc::c_ulong) as __time_t;
    (*bw).bwstart.tv_usec =
        waitlen.wrapping_rem(1000000 as libc::c_long as libc::c_ulong) as __suseconds_t;
    if if (*bw).bwstart.tv_sec == (*bw).bwend.tv_sec {
        ((*bw).bwstart.tv_usec > (*bw).bwend.tv_usec) as libc::c_int
    } else {
        ((*bw).bwstart.tv_sec > (*bw).bwend.tv_sec) as libc::c_int
    } != 0
    {
        (*bw).bwend.tv_sec = (*bw).bwstart.tv_sec - (*bw).bwend.tv_sec;
        (*bw).bwend.tv_usec = (*bw).bwstart.tv_usec - (*bw).bwend.tv_usec;
        if (*bw).bwend.tv_usec < 0 as libc::c_int as libc::c_long {
            (*bw).bwend.tv_sec -= 1;
            (*bw).bwend.tv_sec;
            (*bw).bwend.tv_usec += 1000000 as libc::c_int as libc::c_long;
        }
        if (*bw).bwend.tv_sec != 0 {
            (*bw).thresh = ((*bw).thresh as libc::c_ulong)
                .wrapping_div(2 as libc::c_int as libc::c_ulong)
                as u_int64_t as u_int64_t;
            if (*bw).thresh < ((*bw).buflen).wrapping_div(4 as libc::c_int as libc::c_ulong) {
                (*bw).thresh = ((*bw).buflen).wrapping_div(4 as libc::c_int as libc::c_ulong);
            }
        } else if (*bw).bwend.tv_usec < 10000 as libc::c_int as libc::c_long {
            (*bw).thresh = ((*bw).thresh as libc::c_ulong)
                .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                as u_int64_t as u_int64_t;
            if (*bw).thresh > ((*bw).buflen).wrapping_mul(8 as libc::c_int as libc::c_ulong) {
                (*bw).thresh = ((*bw).buflen).wrapping_mul(8 as libc::c_int as libc::c_ulong);
            }
        }
        ts.tv_sec = (*bw).bwend.tv_sec;
        ts.tv_nsec = (*bw).bwend.tv_usec * 1000 as libc::c_int as libc::c_long;
        while nanosleep(&mut ts, &mut rm) == -(1 as libc::c_int) {
            if *libc::__errno_location() != 4 as libc::c_int {
                break;
            }
            ts = rm;
        }
    }
    (*bw).lamt = 0 as libc::c_int as u_int64_t;
    monotime_tv(&mut (*bw).bwstart);
}
pub unsafe extern "C" fn mktemp_proto(mut s: *mut libc::c_char, mut len: size_t) {
    let mut tmpdir: *const libc::c_char = 0 as *const libc::c_char;
    let mut r: libc::c_int = 0;
    tmpdir = getenv(b"TMPDIR\0" as *const u8 as *const libc::c_char);
    if !tmpdir.is_null() {
        r = libc::snprintf(
            s,
            len as usize,
            b"%s/ssh-XXXXXXXXXXXX\0" as *const u8 as *const libc::c_char,
            tmpdir,
        );
        if r > 0 as libc::c_int && (r as size_t) < len {
            return;
        }
    }
    r = libc::snprintf(
        s,
        len as usize,
        b"/tmp/ssh-XXXXXXXXXXXX\0" as *const u8 as *const libc::c_char,
    );
    if r < 0 as libc::c_int || r as size_t >= len {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"mktemp_proto\0")).as_ptr(),
            1794 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"template string too short\0" as *const u8 as *const libc::c_char,
        );
    }
}
static mut ipqos: [C2RustUnnamed_14; 27] = [
    {
        let mut init = C2RustUnnamed_14 {
            name: b"none\0" as *const u8 as *const libc::c_char,
            value: 2147483647 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"af11\0" as *const u8 as *const libc::c_char,
            value: 0x28 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"af12\0" as *const u8 as *const libc::c_char,
            value: 0x30 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"af13\0" as *const u8 as *const libc::c_char,
            value: 0x38 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"af21\0" as *const u8 as *const libc::c_char,
            value: 0x48 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"af22\0" as *const u8 as *const libc::c_char,
            value: 0x50 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"af23\0" as *const u8 as *const libc::c_char,
            value: 0x58 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"af31\0" as *const u8 as *const libc::c_char,
            value: 0x68 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"af32\0" as *const u8 as *const libc::c_char,
            value: 0x70 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"af33\0" as *const u8 as *const libc::c_char,
            value: 0x78 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"af41\0" as *const u8 as *const libc::c_char,
            value: 0x88 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"af42\0" as *const u8 as *const libc::c_char,
            value: 0x90 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"af43\0" as *const u8 as *const libc::c_char,
            value: 0x98 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"cs0\0" as *const u8 as *const libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"cs1\0" as *const u8 as *const libc::c_char,
            value: 0x20 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"cs2\0" as *const u8 as *const libc::c_char,
            value: 0x40 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"cs3\0" as *const u8 as *const libc::c_char,
            value: 0x60 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"cs4\0" as *const u8 as *const libc::c_char,
            value: 0x80 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"cs5\0" as *const u8 as *const libc::c_char,
            value: 0xa0 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"cs6\0" as *const u8 as *const libc::c_char,
            value: 0xc0 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"cs7\0" as *const u8 as *const libc::c_char,
            value: 0xe0 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"ef\0" as *const u8 as *const libc::c_char,
            value: 0xb8 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"le\0" as *const u8 as *const libc::c_char,
            value: 0x4 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"lowdelay\0" as *const u8 as *const libc::c_char,
            value: 0x10 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"throughput\0" as *const u8 as *const libc::c_char,
            value: 0x8 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: b"reliability\0" as *const u8 as *const libc::c_char,
            value: 0x4 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_14 {
            name: 0 as *const libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
pub unsafe extern "C" fn parse_ipqos(mut cp: *const libc::c_char) -> libc::c_int {
    let mut i: u_int = 0;
    let mut ep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut val: libc::c_long = 0;
    if cp.is_null() {
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int as u_int;
    while !(ipqos[i as usize].name).is_null() {
        if strcasecmp(cp, ipqos[i as usize].name) == 0 as libc::c_int {
            return ipqos[i as usize].value;
        }
        i = i.wrapping_add(1);
        i;
    }
    val = strtol(cp, &mut ep, 0 as libc::c_int);
    if *cp as libc::c_int == '\0' as i32
        || *ep as libc::c_int != '\0' as i32
        || val < 0 as libc::c_int as libc::c_long
        || val > 255 as libc::c_int as libc::c_long
    {
        return -(1 as libc::c_int);
    }
    return val as libc::c_int;
}
pub unsafe extern "C" fn iptos2str(mut iptos: libc::c_int) -> *const libc::c_char {
    let mut i: libc::c_int = 0;
    static mut iptos_str: [libc::c_char; 5] = [0; 5];
    i = 0 as libc::c_int;
    while !(ipqos[i as usize].name).is_null() {
        if ipqos[i as usize].value == iptos {
            return ipqos[i as usize].name;
        }
        i += 1;
        i;
    }
    libc::snprintf(
        iptos_str.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 5]>() as usize,
        b"0x%02x\0" as *const u8 as *const libc::c_char,
        iptos,
    );
    return iptos_str.as_mut_ptr();
}
pub unsafe extern "C" fn lowercase(mut s: *mut libc::c_char) {
    while *s != 0 {
        *s = ({
            let mut __res: libc::c_int = 0;
            if ::core::mem::size_of::<u_char>() as libc::c_ulong > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *s as u_char as libc::c_int;
                    __res = if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_tolower_loc()).offset(__c as isize)
                    };
                } else {
                    __res = tolower(*s as u_char as libc::c_int);
                }
            } else {
                __res = *(*__ctype_tolower_loc()).offset(*s as u_char as libc::c_int as isize);
            }
            __res
        }) as libc::c_char;
        s = s.offset(1);
        s;
    }
}
pub unsafe extern "C" fn unix_listener(
    mut path: *const libc::c_char,
    mut backlog: libc::c_int,
    mut unlink_first: libc::c_int,
) -> libc::c_int {
    let mut sunaddr: sockaddr_un = sockaddr_un {
        sun_family: 0,
        sun_path: [0; 108],
    };
    let mut saved_errno: libc::c_int = 0;
    let mut sock: libc::c_int = 0;
    memset(
        &mut sunaddr as *mut sockaddr_un as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_un>() as libc::c_ulong,
    );
    sunaddr.sun_family = 1 as libc::c_int as sa_family_t;
    if strlcpy(
        (sunaddr.sun_path).as_mut_ptr(),
        path,
        ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong,
    ) >= ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong
    {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"unix_listener\0"))
                .as_ptr(),
            1881 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"path \"%s\" too long for Unix domain socket\0" as *const u8 as *const libc::c_char,
            path,
        );
        *libc::__errno_location() = 36 as libc::c_int;
        return -(1 as libc::c_int);
    }
    sock = socket(
        1 as libc::c_int,
        SOCK_STREAM as libc::c_int,
        0 as libc::c_int,
    );
    if sock == -(1 as libc::c_int) {
        saved_errno = *libc::__errno_location();
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"unix_listener\0"))
                .as_ptr(),
            1889 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"socket: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        *libc::__errno_location() = saved_errno;
        return -(1 as libc::c_int);
    }
    if unlink_first == 1 as libc::c_int {
        if unlink(path) != 0 as libc::c_int && *libc::__errno_location() != 2 as libc::c_int {
            crate::log::sshlog(
                b"misc.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"unix_listener\0"))
                    .as_ptr(),
                1895 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"unlink(%s): %.100s\0" as *const u8 as *const libc::c_char,
                path,
                strerror(*libc::__errno_location()),
            );
        }
    }
    if bind(
        sock,
        __CONST_SOCKADDR_ARG {
            __sockaddr__: &mut sunaddr as *mut sockaddr_un as *mut sockaddr,
        },
        ::core::mem::size_of::<sockaddr_un>() as libc::c_ulong as socklen_t,
    ) == -(1 as libc::c_int)
    {
        saved_errno = *libc::__errno_location();
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"unix_listener\0"))
                .as_ptr(),
            1899 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"cannot bind to path %s: %s\0" as *const u8 as *const libc::c_char,
            path,
            strerror(*libc::__errno_location()),
        );
        close(sock);
        *libc::__errno_location() = saved_errno;
        return -(1 as libc::c_int);
    }
    if listen(sock, backlog) == -(1 as libc::c_int) {
        saved_errno = *libc::__errno_location();
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"unix_listener\0"))
                .as_ptr(),
            1906 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"cannot listen on path %s: %s\0" as *const u8 as *const libc::c_char,
            path,
            strerror(*libc::__errno_location()),
        );
        close(sock);
        unlink(path);
        *libc::__errno_location() = saved_errno;
        return -(1 as libc::c_int);
    }
    return sock;
}
pub unsafe extern "C" fn sock_set_v6only(mut s: libc::c_int) {
    let mut on: libc::c_int = 1 as libc::c_int;
    crate::log::sshlog(
        b"misc.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"sock_set_v6only\0")).as_ptr(),
        1921 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s: set socket %d IPV6_V6ONLY\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"sock_set_v6only\0")).as_ptr(),
        s,
    );
    if setsockopt(
        s,
        IPPROTO_IPV6 as libc::c_int,
        26 as libc::c_int,
        &mut on as *mut libc::c_int as *const libc::c_void,
        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"sock_set_v6only\0"))
                .as_ptr(),
            1923 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"setsockopt IPV6_V6ONLY: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
}
unsafe extern "C" fn strcmp_maybe_null(
    mut a: *const libc::c_char,
    mut b: *const libc::c_char,
) -> libc::c_int {
    if a.is_null() && !b.is_null() || !a.is_null() && b.is_null() {
        return 0 as libc::c_int;
    }
    if !a.is_null() && strcmp(a, b) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn forward_equals(
    mut a: *const Forward,
    mut b: *const Forward,
) -> libc::c_int {
    if strcmp_maybe_null((*a).listen_host, (*b).listen_host) == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if (*a).listen_port != (*b).listen_port {
        return 0 as libc::c_int;
    }
    if strcmp_maybe_null((*a).listen_path, (*b).listen_path) == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if strcmp_maybe_null((*a).connect_host, (*b).connect_host) == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if (*a).connect_port != (*b).connect_port {
        return 0 as libc::c_int;
    }
    if strcmp_maybe_null((*a).connect_path, (*b).connect_path) == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn daemonized() -> libc::c_int {
    let mut fd: libc::c_int = 0;
    fd = libc::open(
        b"/dev/tty\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int | 0o400 as libc::c_int,
    );
    if fd >= 0 as libc::c_int {
        close(fd);
        return 0 as libc::c_int;
    }
    if getppid() != 1 as libc::c_int {
        return 0 as libc::c_int;
    }
    if getsid(0 as libc::c_int) != libc::getpid() {
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"misc.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"daemonized\0")).as_ptr(),
        1978 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"already daemonized\0" as *const u8 as *const libc::c_char,
    );
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn argv_split(
    mut s: *const libc::c_char,
    mut argcp: *mut libc::c_int,
    mut argvp: *mut *mut *mut libc::c_char,
    mut terminate_on_comment: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut argc: libc::c_int = 0 as libc::c_int;
    let mut quote: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut arg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut argv: *mut *mut libc::c_char = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    *argvp = 0 as *mut *mut libc::c_char;
    *argcp = 0 as libc::c_int;
    i = 0 as libc::c_int;
    loop {
        if !(*s.offset(i as isize) as libc::c_int != '\0' as i32) {
            current_block = 14818589718467733107;
            break;
        }
        if !(*s.offset(i as isize) as libc::c_int == ' ' as i32
            || *s.offset(i as isize) as libc::c_int == '\t' as i32)
        {
            if terminate_on_comment != 0 && *s.offset(i as isize) as libc::c_int == '#' as i32 {
                current_block = 14818589718467733107;
                break;
            }
            quote = 0 as libc::c_int;
            argv = xreallocarray(
                argv as *mut libc::c_void,
                (argc + 2 as libc::c_int) as size_t,
                ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
            ) as *mut *mut libc::c_char;
            let fresh11 = argc;
            argc = argc + 1;
            let ref mut fresh12 = *argv.offset(fresh11 as isize);
            *fresh12 = crate::xmalloc::xcalloc(
                1 as libc::c_int as size_t,
                (strlen(s.offset(i as isize))).wrapping_add(1 as libc::c_int as libc::c_ulong),
            ) as *mut libc::c_char;
            arg = *fresh12;
            let ref mut fresh13 = *argv.offset(argc as isize);
            *fresh13 = 0 as *mut libc::c_char;
            j = 0 as libc::c_int;
            while *s.offset(i as isize) as libc::c_int != '\0' as i32 {
                if *s.offset(i as isize) as libc::c_int == '\\' as i32 {
                    if *s.offset((i + 1 as libc::c_int) as isize) as libc::c_int == '\'' as i32
                        || *s.offset((i + 1 as libc::c_int) as isize) as libc::c_int == '"' as i32
                        || *s.offset((i + 1 as libc::c_int) as isize) as libc::c_int == '\\' as i32
                        || quote == 0 as libc::c_int
                            && *s.offset((i + 1 as libc::c_int) as isize) as libc::c_int
                                == ' ' as i32
                    {
                        i += 1;
                        i;
                        let fresh14 = j;
                        j = j + 1;
                        *arg.offset(fresh14 as isize) = *s.offset(i as isize);
                    } else {
                        let fresh15 = j;
                        j = j + 1;
                        *arg.offset(fresh15 as isize) = *s.offset(i as isize);
                    }
                } else {
                    if quote == 0 as libc::c_int
                        && (*s.offset(i as isize) as libc::c_int == ' ' as i32
                            || *s.offset(i as isize) as libc::c_int == '\t' as i32)
                    {
                        break;
                    }
                    if quote == 0 as libc::c_int
                        && (*s.offset(i as isize) as libc::c_int == '"' as i32
                            || *s.offset(i as isize) as libc::c_int == '\'' as i32)
                    {
                        quote = *s.offset(i as isize) as libc::c_int;
                    } else if quote != 0 as libc::c_int
                        && *s.offset(i as isize) as libc::c_int == quote
                    {
                        quote = 0 as libc::c_int;
                    } else {
                        let fresh16 = j;
                        j = j + 1;
                        *arg.offset(fresh16 as isize) = *s.offset(i as isize);
                    }
                }
                i += 1;
                i;
            }
            if *s.offset(i as isize) as libc::c_int == '\0' as i32 {
                if !(quote != 0 as libc::c_int) {
                    current_block = 14818589718467733107;
                    break;
                }
                r = -(4 as libc::c_int);
                current_block = 16843679328714460414;
                break;
            }
        }
        i += 1;
        i;
    }
    match current_block {
        14818589718467733107 => {
            *argcp = argc;
            *argvp = argv;
            argc = 0 as libc::c_int;
            argv = 0 as *mut *mut libc::c_char;
            r = 0 as libc::c_int;
        }
        _ => {}
    }
    if argc != 0 as libc::c_int && !argv.is_null() {
        i = 0 as libc::c_int;
        while i < argc {
            libc::free(*argv.offset(i as isize) as *mut libc::c_void);
            i += 1;
            i;
        }
        libc::free(argv as *mut libc::c_void);
    }
    return r;
}
pub unsafe extern "C" fn argv_assemble(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> *mut libc::c_char {
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut ws: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut c: libc::c_char = 0;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut buf: *mut sshbuf = 0 as *mut sshbuf;
    let mut arg: *mut sshbuf = 0 as *mut sshbuf;
    buf = sshbuf_new();
    if buf.is_null() || {
        arg = sshbuf_new();
        arg.is_null()
    } {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"argv_assemble\0"))
                .as_ptr(),
            2068 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int;
    while i < argc {
        ws = 0 as libc::c_int;
        sshbuf_reset(arg);
        j = 0 as libc::c_int;
        while *(*argv.offset(i as isize)).offset(j as isize) as libc::c_int != '\0' as i32 {
            r = 0 as libc::c_int;
            c = *(*argv.offset(i as isize)).offset(j as isize);
            let mut current_block_10: u64;
            match c as libc::c_int {
                32 | 9 => {
                    ws = 1 as libc::c_int;
                    r = sshbuf_put_u8(arg, c as u_char);
                    current_block_10 = 7976072742316086414;
                }
                92 | 39 | 34 => {
                    r = sshbuf_put_u8(arg, '\\' as i32 as u_char);
                    if r != 0 as libc::c_int {
                        current_block_10 = 7976072742316086414;
                    } else {
                        current_block_10 = 1440669349572724640;
                    }
                }
                _ => {
                    current_block_10 = 1440669349572724640;
                }
            }
            match current_block_10 {
                1440669349572724640 => {
                    r = sshbuf_put_u8(arg, c as u_char);
                }
                _ => {}
            }
            if r != 0 as libc::c_int {
                sshfatal(
                    b"misc.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"argv_assemble\0"))
                        .as_ptr(),
                    2093 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"sshbuf_put_u8\0" as *const u8 as *const libc::c_char,
                );
            }
            j += 1;
            j;
        }
        if i != 0 as libc::c_int && {
            r = sshbuf_put_u8(buf, ' ' as i32 as u_char);
            r != 0 as libc::c_int
        } || ws != 0 as libc::c_int && {
            r = sshbuf_put_u8(buf, '"' as i32 as u_char);
            r != 0 as libc::c_int
        } || {
            r = sshbuf_putb(buf, arg);
            r != 0 as libc::c_int
        } || ws != 0 as libc::c_int && {
            r = sshbuf_put_u8(buf, '"' as i32 as u_char);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"misc.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"argv_assemble\0"))
                    .as_ptr(),
                2099 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble\0" as *const u8 as *const libc::c_char,
            );
        }
        i += 1;
        i;
    }
    ret = libc::malloc((sshbuf_len(buf) as usize).wrapping_add(1 as libc::c_int as usize))
        as *mut libc::c_char;
    if ret.is_null() {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"argv_assemble\0"))
                .as_ptr(),
            2102 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::malloc failed\0" as *const u8 as *const libc::c_char,
        );
    }
    memcpy(
        ret as *mut libc::c_void,
        sshbuf_ptr(buf) as *const libc::c_void,
        sshbuf_len(buf),
    );
    *ret.offset(sshbuf_len(buf) as isize) = '\0' as i32 as libc::c_char;
    sshbuf_free(buf);
    sshbuf_free(arg);
    return ret;
}
pub unsafe extern "C" fn argv_next(
    mut argcp: *mut libc::c_int,
    mut argvp: *mut *mut *mut libc::c_char,
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = *(*argvp).offset(0 as libc::c_int as isize);
    if *argcp > 0 as libc::c_int && !ret.is_null() {
        *argcp -= 1;
        *argcp;
        *argvp = (*argvp).offset(1);
        *argvp;
    }
    return ret;
}
pub unsafe extern "C" fn argv_consume(mut argcp: *mut libc::c_int) {
    *argcp = 0 as libc::c_int;
}
pub unsafe extern "C" fn argv_free(mut av: *mut *mut libc::c_char, mut ac: libc::c_int) {
    let mut i: libc::c_int = 0;
    if av.is_null() {
        return;
    }
    i = 0 as libc::c_int;
    while i < ac {
        libc::free(*av.offset(i as isize) as *mut libc::c_void);
        i += 1;
        i;
    }
    libc::free(av as *mut libc::c_void);
}
pub unsafe extern "C" fn exited_cleanly(
    mut pid: pid_t,
    mut tag: *const libc::c_char,
    mut cmd: *const libc::c_char,
    mut quiet: libc::c_int,
) -> libc::c_int {
    let mut status: libc::c_int = 0;
    while libc::waitpid(pid, &mut status, 0 as libc::c_int) == -(1 as libc::c_int) {
        if *libc::__errno_location() != 4 as libc::c_int {
            crate::log::sshlog(
                b"misc.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"exited_cleanly\0"))
                    .as_ptr(),
                2148 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"%s libc::waitpid: %s\0" as *const u8 as *const libc::c_char,
                tag,
                strerror(*libc::__errno_location()),
            );
            return -(1 as libc::c_int);
        }
    }
    if ((status & 0x7f as libc::c_int) + 1 as libc::c_int) as libc::c_schar as libc::c_int
        >> 1 as libc::c_int
        > 0 as libc::c_int
    {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"exited_cleanly\0"))
                .as_ptr(),
            2153 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s %s exited on signal %d\0" as *const u8 as *const libc::c_char,
            tag,
            cmd,
            status & 0x7f as libc::c_int,
        );
        return -(1 as libc::c_int);
    } else if (status & 0xff00 as libc::c_int) >> 8 as libc::c_int != 0 as libc::c_int {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"exited_cleanly\0"))
                .as_ptr(),
            2157 as libc::c_int,
            0 as libc::c_int,
            (if quiet != 0 {
                SYSLOG_LEVEL_DEBUG1 as libc::c_int
            } else {
                SYSLOG_LEVEL_INFO as libc::c_int
            }) as LogLevel,
            0 as *const libc::c_char,
            b"%s %s failed, status %d\0" as *const u8 as *const libc::c_char,
            tag,
            cmd,
            (status & 0xff00 as libc::c_int) >> 8 as libc::c_int,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn safe_path(
    mut name: *const libc::c_char,
    mut stp: *mut libc::stat,
    mut pw_dir: *const libc::c_char,
    mut uid: uid_t,
    mut err: *mut libc::c_char,
    mut errlen: size_t,
) -> libc::c_int {
    let mut buf: [libc::c_char; 4096] = [0; 4096];
    let mut homedir: [libc::c_char; 4096] = [0; 4096];
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut comparehome: libc::c_int = 0 as libc::c_int;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if (realpath(name, buf.as_mut_ptr())).is_null() {
        libc::snprintf(
            err,
            errlen as usize,
            b"realpath %s failed: %s\0" as *const u8 as *const libc::c_char,
            name,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if !pw_dir.is_null() && !(realpath(pw_dir, homedir.as_mut_ptr())).is_null() {
        comparehome = 1 as libc::c_int;
    }
    if !((*stp).st_mode & 0o170000 as libc::c_int as libc::c_uint
        == 0o100000 as libc::c_int as libc::c_uint)
    {
        libc::snprintf(
            err,
            errlen as usize,
            b"%s is not a regular file\0" as *const u8 as *const libc::c_char,
            buf.as_mut_ptr(),
        );
        return -(1 as libc::c_int);
    }
    if platform_sys_dir_uid((*stp).st_uid) == 0 && (*stp).st_uid != uid
        || (*stp).st_mode & 0o22 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
    {
        libc::snprintf(
            err,
            errlen as usize,
            b"bad ownership or modes for file %s\0" as *const u8 as *const libc::c_char,
            buf.as_mut_ptr(),
        );
        return -(1 as libc::c_int);
    }
    loop {
        cp = dirname(buf.as_mut_ptr());
        if cp.is_null() {
            libc::snprintf(
                err,
                errlen as usize,
                b"dirname() failed\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        strlcpy(
            buf.as_mut_ptr(),
            cp,
            ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        );
        if libc::stat(buf.as_mut_ptr(), &mut st) == -(1 as libc::c_int)
            || platform_sys_dir_uid(st.st_uid) == 0 && st.st_uid != uid
            || st.st_mode & 0o22 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
        {
            libc::snprintf(
                err,
                errlen as usize,
                b"bad ownership or modes for directory %s\0" as *const u8 as *const libc::c_char,
                buf.as_mut_ptr(),
            );
            return -(1 as libc::c_int);
        }
        if comparehome != 0 && strcmp(homedir.as_mut_ptr(), buf.as_mut_ptr()) == 0 as libc::c_int {
            break;
        }
        if strcmp(b"/\0" as *const u8 as *const libc::c_char, buf.as_mut_ptr()) == 0 as libc::c_int
            || strcmp(b".\0" as *const u8 as *const libc::c_char, buf.as_mut_ptr())
                == 0 as libc::c_int
        {
            break;
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn safe_path_fd(
    mut fd: libc::c_int,
    mut file: *const libc::c_char,
    mut pw: *mut libc::passwd,
    mut err: *mut libc::c_char,
    mut errlen: size_t,
) -> libc::c_int {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if libc::fstat(fd, &mut st) == -(1 as libc::c_int) {
        libc::snprintf(
            err,
            errlen as usize,
            b"cannot libc::stat file %s: %s\0" as *const u8 as *const libc::c_char,
            file,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    return safe_path(file, &mut st, (*pw).pw_dir, (*pw).pw_uid, err, errlen);
}
pub unsafe extern "C" fn child_set_env(
    mut envp: *mut *mut *mut libc::c_char,
    mut envsizep: *mut u_int,
    mut name: *const libc::c_char,
    mut value: *const libc::c_char,
) {
    let mut env: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut envsize: u_int = 0;
    let mut i: u_int = 0;
    let mut namelen: u_int = 0;
    if !(strchr(name, '=' as i32)).is_null() {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"child_set_env\0"))
                .as_ptr(),
            2268 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Invalid environment variable \"%.100s\"\0" as *const u8 as *const libc::c_char,
            name,
        );
        return;
    }
    if (*envp == 0 as *mut libc::c_void as *mut *mut libc::c_char) as libc::c_int
        != (*envsizep == 0 as libc::c_int as libc::c_uint) as libc::c_int
    {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"child_set_env\0"))
                .as_ptr(),
            2277 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"environment size mismatch\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*envp).is_null() && *envsizep == 0 as libc::c_int as libc::c_uint {
        *envp = crate::xmalloc::xmalloc(::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong)
            as *mut *mut libc::c_char;
        let ref mut fresh17 = **envp.offset(0 as libc::c_int as isize);
        *fresh17 = 0 as *mut libc::c_char;
        *envsizep = 1 as libc::c_int as u_int;
    }
    env = *envp;
    namelen = strlen(name) as u_int;
    i = 0 as libc::c_int as u_int;
    while !(*env.offset(i as isize)).is_null() {
        if strncmp(*env.offset(i as isize), name, namelen as libc::c_ulong) == 0 as libc::c_int
            && *(*env.offset(i as isize)).offset(namelen as isize) as libc::c_int == '=' as i32
        {
            break;
        }
        i = i.wrapping_add(1);
        i;
    }
    if !(*env.offset(i as isize)).is_null() {
        libc::free(*env.offset(i as isize) as *mut libc::c_void);
    } else {
        envsize = *envsizep;
        if i >= envsize.wrapping_sub(1 as libc::c_int as libc::c_uint) {
            if envsize >= 1000 as libc::c_int as libc::c_uint {
                sshfatal(
                    b"misc.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"child_set_env\0"))
                        .as_ptr(),
                    2302 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"child_set_env: too many env vars\0" as *const u8 as *const libc::c_char,
                );
            }
            envsize = (envsize as libc::c_uint).wrapping_add(50 as libc::c_int as libc::c_uint)
                as u_int as u_int;
            *envp = xreallocarray(
                env as *mut libc::c_void,
                envsize as size_t,
                ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
            ) as *mut *mut libc::c_char;
            env = *envp;
            *envsizep = envsize;
        }
        let ref mut fresh18 =
            *env.offset(i.wrapping_add(1 as libc::c_int as libc::c_uint) as isize);
        *fresh18 = 0 as *mut libc::c_char;
    }
    let ref mut fresh19 = *env.offset(i as isize);
    *fresh19 = crate::xmalloc::xmalloc(
        (strlen(name))
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_add(strlen(value))
            .wrapping_add(1 as libc::c_int as libc::c_ulong),
    ) as *mut libc::c_char;
    libc::snprintf(
        *env.offset(i as isize),
        (strlen(name))
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_add(strlen(value))
            .wrapping_add(1 as libc::c_int as libc::c_ulong) as usize,
        b"%s=%s\0" as *const u8 as *const libc::c_char,
        name,
        value,
    );
}
pub unsafe extern "C" fn valid_domain(
    mut name: *mut libc::c_char,
    mut makelower: libc::c_int,
    mut errstr: *mut *const libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: size_t = 0;
    let mut l: size_t = strlen(name);
    let mut c: u_char = 0;
    let mut last: u_char = '\0' as i32 as u_char;
    static mut errbuf: [libc::c_char; 256] = [0; 256];
    if l == 0 as libc::c_int as libc::c_ulong {
        strlcpy(
            errbuf.as_mut_ptr(),
            b"empty domain name\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
        );
    } else if *(*__ctype_b_loc())
        .offset(*name.offset(0 as libc::c_int as isize) as u_char as libc::c_int as isize)
        as libc::c_int
        & _ISalpha as libc::c_int as libc::c_ushort as libc::c_int
        == 0
        && *(*__ctype_b_loc())
            .offset(*name.offset(0 as libc::c_int as isize) as u_char as libc::c_int as isize)
            as libc::c_int
            & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int
            == 0
    {
        libc::snprintf(
            errbuf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
            b"domain name \"%.100s\" starts with invalid character\0" as *const u8
                as *const libc::c_char,
            name,
        );
    } else {
        i = 0 as libc::c_int as size_t;
        loop {
            if !(i < l) {
                current_block = 12349973810996921269;
                break;
            }
            c = ({
                let mut __res: libc::c_int = 0;
                if ::core::mem::size_of::<u_char>() as libc::c_ulong
                    > 1 as libc::c_int as libc::c_ulong
                {
                    if 0 != 0 {
                        let mut __c: libc::c_int =
                            *name.offset(i as isize) as u_char as libc::c_int;
                        __res = if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                            __c
                        } else {
                            *(*__ctype_tolower_loc()).offset(__c as isize)
                        };
                    } else {
                        __res = tolower(*name.offset(i as isize) as u_char as libc::c_int);
                    }
                } else {
                    __res = *(*__ctype_tolower_loc())
                        .offset(*name.offset(i as isize) as u_char as libc::c_int as isize);
                }
                __res
            }) as u_char;
            if makelower != 0 {
                *name.offset(i as isize) = c as libc::c_char;
            }
            if last as libc::c_int == '.' as i32 && c as libc::c_int == '.' as i32 {
                libc::snprintf(
                    errbuf.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
                    b"domain name \"%.100s\" contains consecutive separators\0" as *const u8
                        as *const libc::c_char,
                    name,
                );
                current_block = 12560669222890188662;
                break;
            } else if c as libc::c_int != '.' as i32
                && c as libc::c_int != '-' as i32
                && *(*__ctype_b_loc()).offset(c as libc::c_int as isize) as libc::c_int
                    & _ISalnum as libc::c_int as libc::c_ushort as libc::c_int
                    == 0
                && c as libc::c_int != '_' as i32
            {
                libc::snprintf(
                    errbuf.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
                    b"domain name \"%.100s\" contains invalid characters\0" as *const u8
                        as *const libc::c_char,
                    name,
                );
                current_block = 12560669222890188662;
                break;
            } else {
                last = c;
                i = i.wrapping_add(1);
                i;
            }
        }
        match current_block {
            12560669222890188662 => {}
            _ => {
                if *name.offset(l.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
                    as libc::c_int
                    == '.' as i32
                {
                    *name.offset(l.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize) =
                        '\0' as i32 as libc::c_char;
                }
                if !errstr.is_null() {
                    *errstr = 0 as *const libc::c_char;
                }
                return 1 as libc::c_int;
            }
        }
    }
    if !errstr.is_null() {
        *errstr = errbuf.as_mut_ptr();
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn valid_env_name(mut name: *const libc::c_char) -> libc::c_int {
    let mut cp: *const libc::c_char = 0 as *const libc::c_char;
    if *name.offset(0 as libc::c_int as isize) as libc::c_int == '\0' as i32 {
        return 0 as libc::c_int;
    }
    cp = name;
    while *cp as libc::c_int != '\0' as i32 {
        if *(*__ctype_b_loc()).offset(*cp as u_char as libc::c_int as isize) as libc::c_int
            & _ISalnum as libc::c_int as libc::c_ushort as libc::c_int
            == 0
            && *cp as libc::c_int != '_' as i32
        {
            return 0 as libc::c_int;
        }
        cp = cp.offset(1);
        cp;
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn atoi_err(
    mut nptr: *const libc::c_char,
    mut val: *mut libc::c_int,
) -> *const libc::c_char {
    let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
    let mut num: libc::c_longlong = 0;
    if nptr.is_null() || *nptr as libc::c_int == '\0' as i32 {
        return b"missing\0" as *const u8 as *const libc::c_char;
    }
    num = crate::openbsd_compat::strtonum::strtonum(
        nptr,
        0 as libc::c_int as libc::c_longlong,
        2147483647 as libc::c_int as libc::c_longlong,
        &mut errstr,
    );
    if errstr.is_null() {
        *val = num as libc::c_int;
    }
    return errstr;
}
pub unsafe extern "C" fn parse_absolute_time(
    mut s: *const libc::c_char,
    mut tp: *mut uint64_t,
) -> libc::c_int {
    let mut tm: tm = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: 0 as *const libc::c_char,
    };
    let mut tt: time_t = 0;
    let mut buf: [libc::c_char; 32] = [0; 32];
    let mut fmt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *const libc::c_char = 0 as *const libc::c_char;
    let mut l: size_t = 0;
    let mut is_utc: libc::c_int = 0 as libc::c_int;
    *tp = 0 as libc::c_int as uint64_t;
    l = strlen(s);
    if l > 1 as libc::c_int as libc::c_ulong
        && strcasecmp(
            s.offset(l as isize).offset(-(1 as libc::c_int as isize)),
            b"Z\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
    {
        is_utc = 1 as libc::c_int;
        l = l.wrapping_sub(1);
        l;
    } else if l > 3 as libc::c_int as libc::c_ulong
        && strcasecmp(
            s.offset(l as isize).offset(-(3 as libc::c_int as isize)),
            b"UTC\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
    {
        is_utc = 1 as libc::c_int;
        l = (l as libc::c_ulong).wrapping_sub(3 as libc::c_int as libc::c_ulong) as size_t
            as size_t;
    }
    match l {
        8 => {
            fmt = b"%Y-%m-%d\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            libc::snprintf(
                buf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
                b"%.4s-%.2s-%.2s\0" as *const u8 as *const libc::c_char,
                s,
                s.offset(4 as libc::c_int as isize),
                s.offset(6 as libc::c_int as isize),
            );
        }
        12 => {
            fmt = b"%Y-%m-%dT%H:%M\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            libc::snprintf(
                buf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
                b"%.4s-%.2s-%.2sT%.2s:%.2s\0" as *const u8 as *const libc::c_char,
                s,
                s.offset(4 as libc::c_int as isize),
                s.offset(6 as libc::c_int as isize),
                s.offset(8 as libc::c_int as isize),
                s.offset(10 as libc::c_int as isize),
            );
        }
        14 => {
            fmt = b"%Y-%m-%dT%H:%M:%S\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
            libc::snprintf(
                buf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
                b"%.4s-%.2s-%.2sT%.2s:%.2s:%.2s\0" as *const u8 as *const libc::c_char,
                s,
                s.offset(4 as libc::c_int as isize),
                s.offset(6 as libc::c_int as isize),
                s.offset(8 as libc::c_int as isize),
                s.offset(10 as libc::c_int as isize),
                s.offset(12 as libc::c_int as isize),
            );
        }
        _ => return -(4 as libc::c_int),
    }
    memset(
        &mut tm as *mut tm as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<tm>() as libc::c_ulong,
    );
    cp = strptime(buf.as_mut_ptr(), fmt, &mut tm);
    if cp.is_null() || *cp as libc::c_int != '\0' as i32 {
        return -(4 as libc::c_int);
    }
    if is_utc != 0 {
        tt = timegm(&mut tm);
        if tt < 0 as libc::c_int as libc::c_long {
            return -(4 as libc::c_int);
        }
    } else {
        tt = mktime(&mut tm);
        if tt < 0 as libc::c_int as libc::c_long {
            return -(4 as libc::c_int);
        }
    }
    *tp = tt as uint64_t;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn format_absolute_time(
    mut t: uint64_t,
    mut buf: *mut libc::c_char,
    mut len: size_t,
) {
    let mut tt: time_t =
        (if t as libc::c_ulonglong > 9223372036854775807 as libc::c_longlong as libc::c_ulonglong {
            9223372036854775807 as libc::c_longlong as libc::c_ulonglong
        } else {
            t as libc::c_ulonglong
        }) as time_t;
    let mut tm: tm = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: 0 as *const libc::c_char,
    };
    localtime_r(&mut tt, &mut tm);
    strftime(
        buf,
        len,
        b"%Y-%m-%dT%H:%M:%S\0" as *const u8 as *const libc::c_char,
        &mut tm,
    );
}
pub unsafe extern "C" fn path_absolute(mut path: *const libc::c_char) -> libc::c_int {
    return if *path as libc::c_int == '/' as i32 {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    };
}
pub unsafe extern "C" fn skip_space(mut cpp: *mut *mut libc::c_char) {
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    cp = *cpp;
    while *cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32 {
        cp = cp.offset(1);
        cp;
    }
    *cpp = cp;
}
pub unsafe extern "C" fn opt_flag(
    mut opt: *const libc::c_char,
    mut allow_negate: libc::c_int,
    mut optsp: *mut *const libc::c_char,
) -> libc::c_int {
    let mut opt_len: size_t = strlen(opt);
    let mut opts: *const libc::c_char = *optsp;
    let mut negate: libc::c_int = 0 as libc::c_int;
    if allow_negate != 0
        && strncasecmp(
            opts,
            b"no-\0" as *const u8 as *const libc::c_char,
            3 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
    {
        opts = opts.offset(3 as libc::c_int as isize);
        negate = 1 as libc::c_int;
    }
    if strncasecmp(opts, opt, opt_len) == 0 as libc::c_int {
        *optsp = opts.offset(opt_len as isize);
        return if negate != 0 {
            0 as libc::c_int
        } else {
            1 as libc::c_int
        };
    }
    return -(1 as libc::c_int);
}
pub unsafe extern "C" fn opt_dequote(
    mut sp: *mut *const libc::c_char,
    mut errstrp: *mut *const libc::c_char,
) -> *mut libc::c_char {
    let mut s: *const libc::c_char = *sp;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: size_t = 0;
    *errstrp = 0 as *const libc::c_char;
    if *s as libc::c_int != '"' as i32 {
        *errstrp = b"missing start quote\0" as *const u8 as *const libc::c_char;
        return 0 as *mut libc::c_char;
    }
    s = s.offset(1);
    s;
    ret = libc::malloc(((strlen(s)).wrapping_add(1 as libc::c_int as libc::c_ulong)) as usize)
        as *mut libc::c_char;
    if ret.is_null() {
        *errstrp = b"memory allocation failed\0" as *const u8 as *const libc::c_char;
        return 0 as *mut libc::c_char;
    }
    i = 0 as libc::c_int as size_t;
    while *s as libc::c_int != '\0' as i32 && *s as libc::c_int != '"' as i32 {
        if *s.offset(0 as libc::c_int as isize) as libc::c_int == '\\' as i32
            && *s.offset(1 as libc::c_int as isize) as libc::c_int == '"' as i32
        {
            s = s.offset(1);
            s;
        }
        let fresh20 = s;
        s = s.offset(1);
        let fresh21 = i;
        i = i.wrapping_add(1);
        *ret.offset(fresh21 as isize) = *fresh20;
    }
    if *s as libc::c_int == '\0' as i32 {
        *errstrp = b"missing end quote\0" as *const u8 as *const libc::c_char;
        libc::free(ret as *mut libc::c_void);
        return 0 as *mut libc::c_char;
    }
    *ret.offset(i as isize) = '\0' as i32 as libc::c_char;
    s = s.offset(1);
    s;
    *sp = s;
    return ret;
}
pub unsafe extern "C" fn opt_match(
    mut opts: *mut *const libc::c_char,
    mut term: *const libc::c_char,
) -> libc::c_int {
    if strncasecmp(*opts, term, strlen(term)) == 0 as libc::c_int
        && *(*opts).offset(strlen(term) as isize) as libc::c_int == '=' as i32
    {
        *opts =
            (*opts).offset((strlen(term)).wrapping_add(1 as libc::c_int as libc::c_ulong) as isize);
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn opt_array_append2(
    mut file: *const libc::c_char,
    line: libc::c_int,
    mut directive: *const libc::c_char,
    mut array: *mut *mut *mut libc::c_char,
    mut iarray: *mut *mut libc::c_int,
    mut lp: *mut u_int,
    mut s: *const libc::c_char,
    mut i: libc::c_int,
) {
    if *lp >= 2147483647 as libc::c_int as libc::c_uint {
        sshfatal(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"opt_array_append2\0"))
                .as_ptr(),
            2561 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s line %d: Too many %s entries\0" as *const u8 as *const libc::c_char,
            file,
            line,
            directive,
        );
    }
    if !iarray.is_null() {
        *iarray = crate::xmalloc::xrecallocarray(
            *iarray as *mut libc::c_void,
            *lp as size_t,
            (*lp).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
            ::core::mem::size_of::<libc::c_int>() as libc::c_ulong,
        ) as *mut libc::c_int;
        *(*iarray).offset(*lp as isize) = i;
    }
    *array = crate::xmalloc::xrecallocarray(
        *array as *mut libc::c_void,
        *lp as size_t,
        (*lp).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    let ref mut fresh22 = *(*array).offset(*lp as isize);
    *fresh22 = crate::xmalloc::xstrdup(s);
    *lp = (*lp).wrapping_add(1);
    *lp;
}
pub unsafe extern "C" fn opt_array_append(
    mut file: *const libc::c_char,
    line: libc::c_int,
    mut directive: *const libc::c_char,
    mut array: *mut *mut *mut libc::c_char,
    mut lp: *mut u_int,
    mut s: *const libc::c_char,
) {
    opt_array_append2(
        file,
        line,
        directive,
        array,
        0 as *mut *mut libc::c_int,
        lp,
        s,
        0 as libc::c_int,
    );
}
pub unsafe extern "C" fn ssh_signal(mut signum: libc::c_int, mut handler: sshsig_t) -> sshsig_t {
    let mut sa: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed_11 { sa_handler: None },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut osa: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed_11 { sa_handler: None },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    memset(
        &mut sa as *mut sigaction as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sigaction>() as libc::c_ulong,
    );
    sa.__sigaction_handler.sa_handler = handler;
    sigfillset(&mut sa.sa_mask);
    if signum != 14 as libc::c_int {
        sa.sa_flags = 0x10000000 as libc::c_int;
    }
    if sigaction(signum, &mut sa, &mut osa) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"ssh_signal\0")).as_ptr(),
            2595 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"sigaction(%s): %s\0" as *const u8 as *const libc::c_char,
            strsignal(signum),
            strerror(*libc::__errno_location()),
        );
        return ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
            -(1 as libc::c_int) as libc::intptr_t,
        );
    }
    return osa.__sigaction_handler.sa_handler;
}
pub unsafe extern "C" fn stdfd_devnull(
    mut do_stdin: libc::c_int,
    mut do_stdout: libc::c_int,
    mut do_stderr: libc::c_int,
) -> libc::c_int {
    let mut devnull: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    devnull = libc::open(
        b"/dev/null\0" as *const u8 as *const libc::c_char,
        0o2 as libc::c_int,
    );
    if devnull == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"stdfd_devnull\0"))
                .as_ptr(),
            2608 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"open %s: %s\0" as *const u8 as *const libc::c_char,
            b"/dev/null\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if do_stdin != 0 && libc::dup2(devnull, 0 as libc::c_int) == -(1 as libc::c_int)
        || do_stdout != 0 && libc::dup2(devnull, 1 as libc::c_int) == -(1 as libc::c_int)
        || do_stderr != 0 && libc::dup2(devnull, 2 as libc::c_int) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"stdfd_devnull\0"))
                .as_ptr(),
            2614 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libc::dup2: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        ret = -(1 as libc::c_int);
    }
    if devnull > 2 as libc::c_int {
        close(devnull);
    }
    return ret;
}
pub unsafe extern "C" fn subprocess(
    mut tag: *const libc::c_char,
    mut command: *const libc::c_char,
    mut _ac: libc::c_int,
    mut av: *mut *mut libc::c_char,
    mut child: *mut *mut libc::FILE,
    mut flags: u_int,
    mut pw: *mut libc::passwd,
    mut drop_privs: Option<privdrop_fn>,
    mut restore_privs: Option<privrestore_fn>,
) -> pid_t {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut fd: libc::c_int = 0;
    let mut devnull: libc::c_int = 0;
    let mut p: [libc::c_int; 2] = [0; 2];
    let mut i: libc::c_int = 0;
    let mut pid: pid_t = 0;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut errmsg: [libc::c_char; 512] = [0; 512];
    let mut nenv: u_int = 0 as libc::c_int as u_int;
    let mut env: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    if drop_privs.is_some() && (pw.is_null() || restore_privs.is_none()) {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0")).as_ptr(),
            2646 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s: inconsistent arguments\0" as *const u8 as *const libc::c_char,
            tag,
        );
        return 0 as libc::c_int;
    }
    if pw.is_null() && {
        pw = libc::getpwuid(libc::getuid());
        pw.is_null()
    } {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0")).as_ptr(),
            2650 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s: no user for current uid\0" as *const u8 as *const libc::c_char,
            tag,
        );
        return 0 as libc::c_int;
    }
    if !child.is_null() {
        *child = 0 as *mut libc::FILE;
    }
    crate::log::sshlog(
        b"misc.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0")).as_ptr(),
        2657 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s command \"%s\" running as %s (flags 0x%x)\0" as *const u8 as *const libc::c_char,
        tag,
        command,
        (*pw).pw_name,
        flags,
    );
    if flags & 1 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
        && flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
            != 0 as libc::c_int as libc::c_uint
    {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0")).as_ptr(),
            2662 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"inconsistent flags\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if (flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
        == 0 as libc::c_int as libc::c_uint) as libc::c_int
        != (child == 0 as *mut libc::c_void as *mut *mut libc::FILE) as libc::c_int
    {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0")).as_ptr(),
            2666 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"inconsistent flags/output\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if path_absolute(*av.offset(0 as libc::c_int as isize)) == 0 {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0")).as_ptr(),
            2675 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s path is not absolute\0" as *const u8 as *const libc::c_char,
            tag,
        );
        return 0 as libc::c_int;
    }
    if drop_privs.is_some() {
        drop_privs.expect("non-null function pointer")(pw);
    }
    if libc::stat(*av.offset(0 as libc::c_int as isize), &mut st) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0")).as_ptr(),
            2682 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Could not libc::stat %s \"%s\": %s\0" as *const u8 as *const libc::c_char,
            tag,
            *av.offset(0 as libc::c_int as isize),
            strerror(*libc::__errno_location()),
        );
    } else if flags & ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint
        == 0 as libc::c_int as libc::c_uint
        && safe_path(
            *av.offset(0 as libc::c_int as isize),
            &mut st,
            0 as *const libc::c_char,
            0 as libc::c_int as uid_t,
            errmsg.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
        ) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0")).as_ptr(),
            2687 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Unsafe %s \"%s\": %s\0" as *const u8 as *const libc::c_char,
            tag,
            *av.offset(0 as libc::c_int as isize),
            errmsg.as_mut_ptr(),
        );
    } else if pipe(p.as_mut_ptr()) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0")).as_ptr(),
            2692 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s: pipe: %s\0" as *const u8 as *const libc::c_char,
            tag,
            strerror(*libc::__errno_location()),
        );
    } else {
        if restore_privs.is_some() {
            restore_privs.expect("non-null function pointer")();
        }
        pid = libc::fork();
        match pid {
            -1 => {
                crate::log::sshlog(
                    b"misc.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0"))
                        .as_ptr(),
                    2703 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: libc::fork: %s\0" as *const u8 as *const libc::c_char,
                    tag,
                    strerror(*libc::__errno_location()),
                );
                close(p[0 as libc::c_int as usize]);
                close(p[1 as libc::c_int as usize]);
                return 0 as libc::c_int;
            }
            0 => {
                if flags & ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint
                    == 0 as libc::c_int as libc::c_uint
                {
                    nenv = 5 as libc::c_int as u_int;
                    env = crate::xmalloc::xcalloc(
                        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                        nenv as size_t,
                    ) as *mut *mut libc::c_char;
                    child_set_env(
                        &mut env,
                        &mut nenv,
                        b"PATH\0" as *const u8 as *const libc::c_char,
                        b"/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin\0" as *const u8
                            as *const libc::c_char,
                    );
                    child_set_env(
                        &mut env,
                        &mut nenv,
                        b"USER\0" as *const u8 as *const libc::c_char,
                        (*pw).pw_name,
                    );
                    child_set_env(
                        &mut env,
                        &mut nenv,
                        b"LOGNAME\0" as *const u8 as *const libc::c_char,
                        (*pw).pw_name,
                    );
                    child_set_env(
                        &mut env,
                        &mut nenv,
                        b"HOME\0" as *const u8 as *const libc::c_char,
                        (*pw).pw_dir,
                    );
                    cp = getenv(b"LANG\0" as *const u8 as *const libc::c_char);
                    if !cp.is_null() {
                        child_set_env(
                            &mut env,
                            &mut nenv,
                            b"LANG\0" as *const u8 as *const libc::c_char,
                            cp,
                        );
                    }
                }
                i = 1 as libc::c_int;
                while i < 64 as libc::c_int + 1 as libc::c_int {
                    ssh_signal(i, None);
                    i += 1;
                    i;
                }
                devnull = libc::open(
                    b"/dev/null\0" as *const u8 as *const libc::c_char,
                    0o2 as libc::c_int,
                );
                if devnull == -(1 as libc::c_int) {
                    crate::log::sshlog(
                        b"misc.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"subprocess\0",
                        ))
                        .as_ptr(),
                        2725 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s: open %s: %s\0" as *const u8 as *const libc::c_char,
                        tag,
                        b"/dev/null\0" as *const u8 as *const libc::c_char,
                        strerror(*libc::__errno_location()),
                    );
                    libc::_exit(1 as libc::c_int);
                }
                if libc::dup2(devnull, 0 as libc::c_int) == -(1 as libc::c_int) {
                    crate::log::sshlog(
                        b"misc.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"subprocess\0",
                        ))
                        .as_ptr(),
                        2729 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s: libc::dup2: %s\0" as *const u8 as *const libc::c_char,
                        tag,
                        strerror(*libc::__errno_location()),
                    );
                    libc::_exit(1 as libc::c_int);
                }
                fd = -(1 as libc::c_int);
                if flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
                    != 0 as libc::c_int as libc::c_uint
                {
                    fd = p[1 as libc::c_int as usize];
                } else if flags & 1 as libc::c_int as libc::c_uint
                    != 0 as libc::c_int as libc::c_uint
                {
                    fd = devnull;
                }
                if fd != -(1 as libc::c_int)
                    && libc::dup2(fd, 1 as libc::c_int) == -(1 as libc::c_int)
                {
                    crate::log::sshlog(
                        b"misc.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"subprocess\0",
                        ))
                        .as_ptr(),
                        2740 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s: libc::dup2: %s\0" as *const u8 as *const libc::c_char,
                        tag,
                        strerror(*libc::__errno_location()),
                    );
                    libc::_exit(1 as libc::c_int);
                }
                closefrom(2 as libc::c_int + 1 as libc::c_int);
                if geteuid() == 0 as libc::c_int as libc::c_uint
                    && initgroups((*pw).pw_name, (*pw).pw_gid) == -(1 as libc::c_int)
                {
                    crate::log::sshlog(
                        b"misc.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"subprocess\0",
                        ))
                        .as_ptr(),
                        2748 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s: initgroups(%s, %u): %s\0" as *const u8 as *const libc::c_char,
                        tag,
                        (*pw).pw_name,
                        (*pw).pw_gid,
                        strerror(*libc::__errno_location()),
                    );
                    libc::_exit(1 as libc::c_int);
                }
                if setresgid((*pw).pw_gid, (*pw).pw_gid, (*pw).pw_gid) == -(1 as libc::c_int) {
                    crate::log::sshlog(
                        b"misc.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"subprocess\0",
                        ))
                        .as_ptr(),
                        2753 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s: setresgid %u: %s\0" as *const u8 as *const libc::c_char,
                        tag,
                        (*pw).pw_gid,
                        strerror(*libc::__errno_location()),
                    );
                    libc::_exit(1 as libc::c_int);
                }
                if setresuid((*pw).pw_uid, (*pw).pw_uid, (*pw).pw_uid) == -(1 as libc::c_int) {
                    crate::log::sshlog(
                        b"misc.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"subprocess\0",
                        ))
                        .as_ptr(),
                        2758 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s: setresuid %u: %s\0" as *const u8 as *const libc::c_char,
                        tag,
                        (*pw).pw_uid,
                        strerror(*libc::__errno_location()),
                    );
                    libc::_exit(1 as libc::c_int);
                }
                if flags & 1 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
                    && libc::dup2(0 as libc::c_int, 2 as libc::c_int) == -(1 as libc::c_int)
                {
                    crate::log::sshlog(
                        b"misc.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"subprocess\0",
                        ))
                        .as_ptr(),
                        2764 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s: libc::dup2: %s\0" as *const u8 as *const libc::c_char,
                        tag,
                        strerror(*libc::__errno_location()),
                    );
                    libc::_exit(1 as libc::c_int);
                }
                if !env.is_null() {
                    execve(
                        *av.offset(0 as libc::c_int as isize),
                        av as *const *mut libc::c_char,
                        env as *const *mut libc::c_char,
                    );
                } else {
                    execv(
                        *av.offset(0 as libc::c_int as isize),
                        av as *const *mut libc::c_char,
                    );
                }
                crate::log::sshlog(
                    b"misc.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0"))
                        .as_ptr(),
                    2772 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s %s \"%s\": %s\0" as *const u8 as *const libc::c_char,
                    tag,
                    if env.is_null() {
                        b"execv\0" as *const u8 as *const libc::c_char
                    } else {
                        b"execve\0" as *const u8 as *const libc::c_char
                    },
                    command,
                    strerror(*libc::__errno_location()),
                );
                libc::_exit(127 as libc::c_int);
            }
            _ => {}
        }
        close(p[1 as libc::c_int as usize]);
        if flags & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
            == 0 as libc::c_int as libc::c_uint
        {
            close(p[0 as libc::c_int as usize]);
        } else {
            f = libc::fdopen(
                p[0 as libc::c_int as usize],
                b"r\0" as *const u8 as *const libc::c_char,
            );
            if f.is_null() {
                crate::log::sshlog(
                    b"misc.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0"))
                        .as_ptr(),
                    2782 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: libc::fdopen: %s\0" as *const u8 as *const libc::c_char,
                    tag,
                    strerror(*libc::__errno_location()),
                );
                close(p[0 as libc::c_int as usize]);
                kill(pid, 15 as libc::c_int);
                while libc::waitpid(pid, 0 as *mut libc::c_int, 0 as libc::c_int)
                    == -(1 as libc::c_int)
                    && *libc::__errno_location() == 4 as libc::c_int
                {}
                return 0 as libc::c_int;
            }
        }
        crate::log::sshlog(
            b"misc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"subprocess\0")).as_ptr(),
            2791 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"%s pid %ld\0" as *const u8 as *const libc::c_char,
            tag,
            pid as libc::c_long,
        );
        if !child.is_null() {
            *child = f;
        }
        return pid;
    }
    if restore_privs.is_some() {
        restore_privs.expect("non-null function pointer")();
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn lookup_env_in_list(
    mut env: *const libc::c_char,
    mut envs: *const *mut libc::c_char,
    mut nenvs: size_t,
) -> *const libc::c_char {
    let mut i: size_t = 0;
    let mut envlen: size_t = 0;
    envlen = strlen(env);
    i = 0 as libc::c_int as size_t;
    while i < nenvs {
        if strncmp(*envs.offset(i as isize), env, envlen) == 0 as libc::c_int
            && *(*envs.offset(i as isize)).offset(envlen as isize) as libc::c_int == '=' as i32
        {
            return (*envs.offset(i as isize))
                .offset(envlen as isize)
                .offset(1 as libc::c_int as isize);
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const libc::c_char;
}
pub unsafe extern "C" fn lookup_setenv_in_list(
    mut env: *const libc::c_char,
    mut envs: *const *mut libc::c_char,
    mut nenvs: size_t,
) -> *const libc::c_char {
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *const libc::c_char = 0 as *const libc::c_char;
    name = crate::xmalloc::xstrdup(env);
    cp = strchr(name, '=' as i32);
    if cp.is_null() {
        libc::free(name as *mut libc::c_void);
        return 0 as *const libc::c_char;
    }
    *cp = '\0' as i32 as libc::c_char;
    ret = lookup_env_in_list(name, envs, nenvs);
    libc::free(name as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn ptimeout_init(mut pt: *mut libc::timespec) {
    (*pt).tv_sec = -(1 as libc::c_int) as __time_t;
    (*pt).tv_nsec = 0 as libc::c_int as __syscall_slong_t;
}
pub unsafe extern "C" fn ptimeout_deadline_sec(mut pt: *mut libc::timespec, mut sec: libc::c_long) {
    if (*pt).tv_sec == -(1 as libc::c_int) as libc::c_long || (*pt).tv_sec >= sec {
        (*pt).tv_sec = sec;
        (*pt).tv_nsec = 0 as libc::c_int as __syscall_slong_t;
    }
}
unsafe extern "C" fn ptimeout_deadline_tsp(
    mut pt: *mut libc::timespec,
    mut p: *mut libc::timespec,
) {
    if (*pt).tv_sec == -(1 as libc::c_int) as libc::c_long
        || (if (*pt).tv_sec == (*p).tv_sec {
            ((*pt).tv_nsec >= (*p).tv_nsec) as libc::c_int
        } else {
            ((*pt).tv_sec >= (*p).tv_sec) as libc::c_int
        }) != 0
    {
        *pt = *p;
    }
}
pub unsafe extern "C" fn ptimeout_deadline_ms(mut pt: *mut libc::timespec, mut ms: libc::c_long) {
    let mut p: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    p.tv_sec = ms / 1000 as libc::c_int as libc::c_long;
    p.tv_nsec = ms % 1000 as libc::c_int as libc::c_long * 1000000 as libc::c_int as libc::c_long;
    ptimeout_deadline_tsp(pt, &mut p);
}
pub unsafe extern "C" fn ptimeout_deadline_monotime(mut pt: *mut libc::timespec, mut when: time_t) {
    let mut now: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut t: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    t.tv_sec = when;
    t.tv_nsec = 0 as libc::c_int as __syscall_slong_t;
    monotime_ts(&mut now);
    if if now.tv_sec == t.tv_sec {
        (now.tv_nsec >= t.tv_nsec) as libc::c_int
    } else {
        (now.tv_sec >= t.tv_sec) as libc::c_int
    } != 0
    {
        ptimeout_deadline_sec(pt, 0 as libc::c_int as libc::c_long);
    } else {
        t.tv_sec = t.tv_sec - now.tv_sec;
        t.tv_nsec = t.tv_nsec - now.tv_nsec;
        if t.tv_nsec < 0 as libc::c_int as libc::c_long {
            t.tv_sec -= 1;
            t.tv_sec;
            t.tv_nsec += 1000000000 as libc::c_long;
        }
        ptimeout_deadline_tsp(pt, &mut t);
    };
}
pub unsafe extern "C" fn ptimeout_get_ms(mut pt: *mut libc::timespec) -> libc::c_int {
    if (*pt).tv_sec == -(1 as libc::c_int) as libc::c_long {
        return -(1 as libc::c_int);
    }
    if (*pt).tv_sec
        >= (2147483647 as libc::c_int as libc::c_long
            - (*pt).tv_nsec / 1000000 as libc::c_int as libc::c_long)
            / 1000 as libc::c_int as libc::c_long
    {
        return 2147483647 as libc::c_int;
    }
    return ((*pt).tv_sec * 1000 as libc::c_int as libc::c_long
        + (*pt).tv_nsec / 1000000 as libc::c_int as libc::c_long) as libc::c_int;
}
pub unsafe extern "C" fn ptimeout_get_tsp(mut pt: *mut libc::timespec) -> *mut libc::timespec {
    return if (*pt).tv_sec == -(1 as libc::c_int) as libc::c_long {
        0 as *mut libc::timespec
    } else {
        pt
    };
}
pub unsafe extern "C" fn ptimeout_isset(mut pt: *mut libc::timespec) -> libc::c_int {
    return ((*pt).tv_sec != -(1 as libc::c_int) as libc::c_long) as libc::c_int;
}
