use crate::atomicio::atomicio;
use crate::channels::ssh_channels;
use crate::hmac::ssh_hmac_ctx;
use crate::kex::sshenc;
use crate::packet::session_state;
use crate::umac::umac_ctx;

use crate::log::log_init;
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
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    pub type ec_group_st;
    pub type dh_st;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn socket(__domain: libc::c_int, __type: libc::c_int, __protocol: libc::c_int) -> libc::c_int;
    fn connect(__fd: libc::c_int, __addr: __CONST_SOCKADDR_ARG, __len: socklen_t) -> libc::c_int;

    fn sysconf(__name: libc::c_int) -> libc::c_long;
    static mut BSDoptarg: *mut libc::c_char;
    static mut BSDoptind: libc::c_int;

    fn getaddrinfo(
        __name: *const libc::c_char,
        __service: *const libc::c_char,
        __req: *const addrinfo,
        __pai: *mut *mut addrinfo,
    ) -> libc::c_int;
    fn freeaddrinfo(__ai: *mut addrinfo);
    static mut stdin: *mut libc::FILE;
    static mut stdout: *mut libc::FILE;
    static mut stderr: *mut libc::FILE;
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::FILE;

    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn __getdelim(
        __lineptr: *mut *mut libc::c_char,
        __n: *mut size_t,
        __delimiter: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> __ssize_t;
    fn fputs(__s: *const libc::c_char, __stream: *mut libc::FILE) -> libc::c_int;
    fn ferror(__stream: *mut libc::FILE) -> libc::c_int;
    fn seed_rng();

    fn ppoll(
        __fds: *mut pollfd,
        __nfds: nfds_t,
        __timeout: *const libc::timespec,
        __ss: *const __sigset_t,
    ) -> libc::c_int;
    fn getrlimit(__resource: __rlimit_resource_t, __rlimits: *mut rlimit) -> libc::c_int;
    fn setrlimit(__resource: __rlimit_resource_t, __rlimits: *const rlimit) -> libc::c_int;

    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;

    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;

    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strtok(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;

    fn sshkey_write(_: *const crate::sshkey::sshkey, _: *mut libc::FILE) -> libc::c_int;
    fn sshkey_type_from_name(_: *const libc::c_char) -> libc::c_int;
    fn ssh_digest_alg_by_name(name: *const libc::c_char) -> libc::c_int;
    fn kex_setup(_: *mut ssh, _: *mut *mut libc::c_char) -> libc::c_int;
    fn kexgex_client(_: *mut ssh) -> libc::c_int;
    fn kex_gen_client(_: *mut ssh) -> libc::c_int;
    fn compat_banner(_: *mut ssh, _: *const libc::c_char);
    fn ssh_packet_set_connection(_: *mut ssh, _: libc::c_int, _: libc::c_int) -> *mut ssh;
    fn ssh_packet_set_timeout(_: *mut ssh, _: libc::c_int, _: libc::c_int);
    fn ssh_packet_close(_: *mut ssh);
    fn ssh_dispatch_run(_: *mut ssh, _: libc::c_int, _: *mut sig_atomic_t) -> libc::c_int;

    fn cleanup_exit(_: libc::c_int) -> !;

    fn ssh_err(n: libc::c_int) -> *const libc::c_char;

    fn chop(_: *mut libc::c_char) -> *mut libc::c_char;

    fn put_host_port(_: *const libc::c_char, _: u_short) -> *mut libc::c_char;
    fn convtime(_: *const libc::c_char) -> libc::c_int;

    fn monotime_ts(_: *mut libc::timespec);
    fn lowercase(s: *mut libc::c_char);
    fn ssh_gai_strerror(_: libc::c_int) -> *const libc::c_char;
    fn host_hash(_: *const libc::c_char, _: *const libc::c_char, _: u_int) -> *mut libc::c_char;
    fn ssh_set_app_data(_: *mut ssh, _: *mut libc::c_void);
    fn ssh_get_app_data(_: *mut ssh) -> *mut libc::c_void;
    fn ssh_set_verify_host_key_callback(
        ssh: *mut ssh,
        cb: Option<unsafe extern "C" fn(*mut crate::sshkey::sshkey, *mut ssh) -> libc::c_int>,
    ) -> libc::c_int;
    fn export_dns_rr(
        _: *const libc::c_char,
        _: *mut crate::sshkey::sshkey,
        _: *mut libc::FILE,
        _: libc::c_int,
        _: libc::c_int,
    ) -> libc::c_int;
    fn addr_pton_cidr(p: *const libc::c_char, n: *mut xaddr, l: *mut u_int) -> libc::c_int;
    fn addr_ntop(n: *const xaddr, p: *mut libc::c_char, len: size_t) -> libc::c_int;
    fn addr_cmp(a: *const xaddr, b: *const xaddr) -> libc::c_int;
    fn addr_host_to_all1s(a: *mut xaddr, masklen: u_int) -> libc::c_int;
    fn addr_increment(a: *mut xaddr);
    static mut __progname: *mut libc::c_char;
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
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __rlim_t = libc::c_ulong;
pub type __time_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_short = __u_short;
pub type u_int = __u_int;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type u_int8_t = __uint8_t;
pub type u_int16_t = __uint16_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [libc::c_ulong; 16],
}

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

pub type _IO_lock_t = ();

pub type sig_atomic_t = __sig_atomic_t;
pub type C2RustUnnamed_0 = libc::c_uint;
pub const _SC_SIGSTKSZ: C2RustUnnamed_0 = 250;
pub const _SC_MINSIGSTKSZ: C2RustUnnamed_0 = 249;
pub const _SC_THREAD_ROBUST_PRIO_PROTECT: C2RustUnnamed_0 = 248;
pub const _SC_THREAD_ROBUST_PRIO_INHERIT: C2RustUnnamed_0 = 247;
pub const _SC_XOPEN_STREAMS: C2RustUnnamed_0 = 246;
pub const _SC_TRACE_USER_EVENT_MAX: C2RustUnnamed_0 = 245;
pub const _SC_TRACE_SYS_MAX: C2RustUnnamed_0 = 244;
pub const _SC_TRACE_NAME_MAX: C2RustUnnamed_0 = 243;
pub const _SC_TRACE_EVENT_NAME_MAX: C2RustUnnamed_0 = 242;
pub const _SC_SS_REPL_MAX: C2RustUnnamed_0 = 241;
pub const _SC_V7_LPBIG_OFFBIG: C2RustUnnamed_0 = 240;
pub const _SC_V7_LP64_OFF64: C2RustUnnamed_0 = 239;
pub const _SC_V7_ILP32_OFFBIG: C2RustUnnamed_0 = 238;
pub const _SC_V7_ILP32_OFF32: C2RustUnnamed_0 = 237;
pub const _SC_RAW_SOCKETS: C2RustUnnamed_0 = 236;
pub const _SC_IPV6: C2RustUnnamed_0 = 235;
pub const _SC_LEVEL4_CACHE_LINESIZE: C2RustUnnamed_0 = 199;
pub const _SC_LEVEL4_CACHE_ASSOC: C2RustUnnamed_0 = 198;
pub const _SC_LEVEL4_CACHE_SIZE: C2RustUnnamed_0 = 197;
pub const _SC_LEVEL3_CACHE_LINESIZE: C2RustUnnamed_0 = 196;
pub const _SC_LEVEL3_CACHE_ASSOC: C2RustUnnamed_0 = 195;
pub const _SC_LEVEL3_CACHE_SIZE: C2RustUnnamed_0 = 194;
pub const _SC_LEVEL2_CACHE_LINESIZE: C2RustUnnamed_0 = 193;
pub const _SC_LEVEL2_CACHE_ASSOC: C2RustUnnamed_0 = 192;
pub const _SC_LEVEL2_CACHE_SIZE: C2RustUnnamed_0 = 191;
pub const _SC_LEVEL1_DCACHE_LINESIZE: C2RustUnnamed_0 = 190;
pub const _SC_LEVEL1_DCACHE_ASSOC: C2RustUnnamed_0 = 189;
pub const _SC_LEVEL1_DCACHE_SIZE: C2RustUnnamed_0 = 188;
pub const _SC_LEVEL1_ICACHE_LINESIZE: C2RustUnnamed_0 = 187;
pub const _SC_LEVEL1_ICACHE_ASSOC: C2RustUnnamed_0 = 186;
pub const _SC_LEVEL1_ICACHE_SIZE: C2RustUnnamed_0 = 185;
pub const _SC_TRACE_LOG: C2RustUnnamed_0 = 184;
pub const _SC_TRACE_INHERIT: C2RustUnnamed_0 = 183;
pub const _SC_TRACE_EVENT_FILTER: C2RustUnnamed_0 = 182;
pub const _SC_TRACE: C2RustUnnamed_0 = 181;
pub const _SC_HOST_NAME_MAX: C2RustUnnamed_0 = 180;
pub const _SC_V6_LPBIG_OFFBIG: C2RustUnnamed_0 = 179;
pub const _SC_V6_LP64_OFF64: C2RustUnnamed_0 = 178;
pub const _SC_V6_ILP32_OFFBIG: C2RustUnnamed_0 = 177;
pub const _SC_V6_ILP32_OFF32: C2RustUnnamed_0 = 176;
pub const _SC_2_PBS_CHECKPOINT: C2RustUnnamed_0 = 175;
pub const _SC_STREAMS: C2RustUnnamed_0 = 174;
pub const _SC_SYMLOOP_MAX: C2RustUnnamed_0 = 173;
pub const _SC_2_PBS_TRACK: C2RustUnnamed_0 = 172;
pub const _SC_2_PBS_MESSAGE: C2RustUnnamed_0 = 171;
pub const _SC_2_PBS_LOCATE: C2RustUnnamed_0 = 170;
pub const _SC_2_PBS_ACCOUNTING: C2RustUnnamed_0 = 169;
pub const _SC_2_PBS: C2RustUnnamed_0 = 168;
pub const _SC_USER_GROUPS_R: C2RustUnnamed_0 = 167;
pub const _SC_USER_GROUPS: C2RustUnnamed_0 = 166;
pub const _SC_TYPED_MEMORY_OBJECTS: C2RustUnnamed_0 = 165;
pub const _SC_TIMEOUTS: C2RustUnnamed_0 = 164;
pub const _SC_SYSTEM_DATABASE_R: C2RustUnnamed_0 = 163;
pub const _SC_SYSTEM_DATABASE: C2RustUnnamed_0 = 162;
pub const _SC_THREAD_SPORADIC_SERVER: C2RustUnnamed_0 = 161;
pub const _SC_SPORADIC_SERVER: C2RustUnnamed_0 = 160;
pub const _SC_SPAWN: C2RustUnnamed_0 = 159;
pub const _SC_SIGNALS: C2RustUnnamed_0 = 158;
pub const _SC_SHELL: C2RustUnnamed_0 = 157;
pub const _SC_REGEX_VERSION: C2RustUnnamed_0 = 156;
pub const _SC_REGEXP: C2RustUnnamed_0 = 155;
pub const _SC_SPIN_LOCKS: C2RustUnnamed_0 = 154;
pub const _SC_READER_WRITER_LOCKS: C2RustUnnamed_0 = 153;
pub const _SC_NETWORKING: C2RustUnnamed_0 = 152;
pub const _SC_SINGLE_PROCESS: C2RustUnnamed_0 = 151;
pub const _SC_MULTI_PROCESS: C2RustUnnamed_0 = 150;
pub const _SC_MONOTONIC_CLOCK: C2RustUnnamed_0 = 149;
pub const _SC_FILE_SYSTEM: C2RustUnnamed_0 = 148;
pub const _SC_FILE_LOCKING: C2RustUnnamed_0 = 147;
pub const _SC_FILE_ATTRIBUTES: C2RustUnnamed_0 = 146;
pub const _SC_PIPE: C2RustUnnamed_0 = 145;
pub const _SC_FIFO: C2RustUnnamed_0 = 144;
pub const _SC_FD_MGMT: C2RustUnnamed_0 = 143;
pub const _SC_DEVICE_SPECIFIC_R: C2RustUnnamed_0 = 142;
pub const _SC_DEVICE_SPECIFIC: C2RustUnnamed_0 = 141;
pub const _SC_DEVICE_IO: C2RustUnnamed_0 = 140;
pub const _SC_THREAD_CPUTIME: C2RustUnnamed_0 = 139;
pub const _SC_CPUTIME: C2RustUnnamed_0 = 138;
pub const _SC_CLOCK_SELECTION: C2RustUnnamed_0 = 137;
pub const _SC_C_LANG_SUPPORT_R: C2RustUnnamed_0 = 136;
pub const _SC_C_LANG_SUPPORT: C2RustUnnamed_0 = 135;
pub const _SC_BASE: C2RustUnnamed_0 = 134;
pub const _SC_BARRIERS: C2RustUnnamed_0 = 133;
pub const _SC_ADVISORY_INFO: C2RustUnnamed_0 = 132;
pub const _SC_XOPEN_REALTIME_THREADS: C2RustUnnamed_0 = 131;
pub const _SC_XOPEN_REALTIME: C2RustUnnamed_0 = 130;
pub const _SC_XOPEN_LEGACY: C2RustUnnamed_0 = 129;
pub const _SC_XBS5_LPBIG_OFFBIG: C2RustUnnamed_0 = 128;
pub const _SC_XBS5_LP64_OFF64: C2RustUnnamed_0 = 127;
pub const _SC_XBS5_ILP32_OFFBIG: C2RustUnnamed_0 = 126;
pub const _SC_XBS5_ILP32_OFF32: C2RustUnnamed_0 = 125;
pub const _SC_NL_TEXTMAX: C2RustUnnamed_0 = 124;
pub const _SC_NL_SETMAX: C2RustUnnamed_0 = 123;
pub const _SC_NL_NMAX: C2RustUnnamed_0 = 122;
pub const _SC_NL_MSGMAX: C2RustUnnamed_0 = 121;
pub const _SC_NL_LANGMAX: C2RustUnnamed_0 = 120;
pub const _SC_NL_ARGMAX: C2RustUnnamed_0 = 119;
pub const _SC_USHRT_MAX: C2RustUnnamed_0 = 118;
pub const _SC_ULONG_MAX: C2RustUnnamed_0 = 117;
pub const _SC_UINT_MAX: C2RustUnnamed_0 = 116;
pub const _SC_UCHAR_MAX: C2RustUnnamed_0 = 115;
pub const _SC_SHRT_MIN: C2RustUnnamed_0 = 114;
pub const _SC_SHRT_MAX: C2RustUnnamed_0 = 113;
pub const _SC_SCHAR_MIN: C2RustUnnamed_0 = 112;
pub const _SC_SCHAR_MAX: C2RustUnnamed_0 = 111;
pub const _SC_SSIZE_MAX: C2RustUnnamed_0 = 110;
pub const _SC_NZERO: C2RustUnnamed_0 = 109;
pub const _SC_MB_LEN_MAX: C2RustUnnamed_0 = 108;
pub const _SC_WORD_BIT: C2RustUnnamed_0 = 107;
pub const _SC_LONG_BIT: C2RustUnnamed_0 = 106;
pub const _SC_INT_MIN: C2RustUnnamed_0 = 105;
pub const _SC_INT_MAX: C2RustUnnamed_0 = 104;
pub const _SC_CHAR_MIN: C2RustUnnamed_0 = 103;
pub const _SC_CHAR_MAX: C2RustUnnamed_0 = 102;
pub const _SC_CHAR_BIT: C2RustUnnamed_0 = 101;
pub const _SC_XOPEN_XPG4: C2RustUnnamed_0 = 100;
pub const _SC_XOPEN_XPG3: C2RustUnnamed_0 = 99;
pub const _SC_XOPEN_XPG2: C2RustUnnamed_0 = 98;
pub const _SC_2_UPE: C2RustUnnamed_0 = 97;
pub const _SC_2_C_VERSION: C2RustUnnamed_0 = 96;
pub const _SC_2_CHAR_TERM: C2RustUnnamed_0 = 95;
pub const _SC_XOPEN_SHM: C2RustUnnamed_0 = 94;
pub const _SC_XOPEN_ENH_I18N: C2RustUnnamed_0 = 93;
pub const _SC_XOPEN_CRYPT: C2RustUnnamed_0 = 92;
pub const _SC_XOPEN_UNIX: C2RustUnnamed_0 = 91;
pub const _SC_XOPEN_XCU_VERSION: C2RustUnnamed_0 = 90;
pub const _SC_XOPEN_VERSION: C2RustUnnamed_0 = 89;
pub const _SC_PASS_MAX: C2RustUnnamed_0 = 88;
pub const _SC_ATEXIT_MAX: C2RustUnnamed_0 = 87;
pub const _SC_AVPHYS_PAGES: C2RustUnnamed_0 = 86;
pub const _SC_PHYS_PAGES: C2RustUnnamed_0 = 85;
pub const _SC_NPROCESSORS_ONLN: C2RustUnnamed_0 = 84;
pub const _SC_NPROCESSORS_CONF: C2RustUnnamed_0 = 83;
pub const _SC_THREAD_PROCESS_SHARED: C2RustUnnamed_0 = 82;
pub const _SC_THREAD_PRIO_PROTECT: C2RustUnnamed_0 = 81;
pub const _SC_THREAD_PRIO_INHERIT: C2RustUnnamed_0 = 80;
pub const _SC_THREAD_PRIORITY_SCHEDULING: C2RustUnnamed_0 = 79;
pub const _SC_THREAD_ATTR_STACKSIZE: C2RustUnnamed_0 = 78;
pub const _SC_THREAD_ATTR_STACKADDR: C2RustUnnamed_0 = 77;
pub const _SC_THREAD_THREADS_MAX: C2RustUnnamed_0 = 76;
pub const _SC_THREAD_STACK_MIN: C2RustUnnamed_0 = 75;
pub const _SC_THREAD_KEYS_MAX: C2RustUnnamed_0 = 74;
pub const _SC_THREAD_DESTRUCTOR_ITERATIONS: C2RustUnnamed_0 = 73;
pub const _SC_TTY_NAME_MAX: C2RustUnnamed_0 = 72;
pub const _SC_LOGIN_NAME_MAX: C2RustUnnamed_0 = 71;
pub const _SC_GETPW_R_SIZE_MAX: C2RustUnnamed_0 = 70;
pub const _SC_GETGR_R_SIZE_MAX: C2RustUnnamed_0 = 69;
pub const _SC_THREAD_SAFE_FUNCTIONS: C2RustUnnamed_0 = 68;
pub const _SC_THREADS: C2RustUnnamed_0 = 67;
pub const _SC_T_IOV_MAX: C2RustUnnamed_0 = 66;
pub const _SC_PII_OSI_M: C2RustUnnamed_0 = 65;
pub const _SC_PII_OSI_CLTS: C2RustUnnamed_0 = 64;
pub const _SC_PII_OSI_COTS: C2RustUnnamed_0 = 63;
pub const _SC_PII_INTERNET_DGRAM: C2RustUnnamed_0 = 62;
pub const _SC_PII_INTERNET_STREAM: C2RustUnnamed_0 = 61;
pub const _SC_IOV_MAX: C2RustUnnamed_0 = 60;
pub const _SC_UIO_MAXIOV: C2RustUnnamed_0 = 60;
pub const _SC_SELECT: C2RustUnnamed_0 = 59;
pub const _SC_POLL: C2RustUnnamed_0 = 58;
pub const _SC_PII_OSI: C2RustUnnamed_0 = 57;
pub const _SC_PII_INTERNET: C2RustUnnamed_0 = 56;
pub const _SC_PII_SOCKET: C2RustUnnamed_0 = 55;
pub const _SC_PII_XTI: C2RustUnnamed_0 = 54;
pub const _SC_PII: C2RustUnnamed_0 = 53;
pub const _SC_2_LOCALEDEF: C2RustUnnamed_0 = 52;
pub const _SC_2_SW_DEV: C2RustUnnamed_0 = 51;
pub const _SC_2_FORT_RUN: C2RustUnnamed_0 = 50;
pub const _SC_2_FORT_DEV: C2RustUnnamed_0 = 49;
pub const _SC_2_C_DEV: C2RustUnnamed_0 = 48;
pub const _SC_2_C_BIND: C2RustUnnamed_0 = 47;
pub const _SC_2_VERSION: C2RustUnnamed_0 = 46;
pub const _SC_CHARCLASS_NAME_MAX: C2RustUnnamed_0 = 45;
pub const _SC_RE_DUP_MAX: C2RustUnnamed_0 = 44;
pub const _SC_LINE_MAX: C2RustUnnamed_0 = 43;
pub const _SC_EXPR_NEST_MAX: C2RustUnnamed_0 = 42;
pub const _SC_EQUIV_CLASS_MAX: C2RustUnnamed_0 = 41;
pub const _SC_COLL_WEIGHTS_MAX: C2RustUnnamed_0 = 40;
pub const _SC_BC_STRING_MAX: C2RustUnnamed_0 = 39;
pub const _SC_BC_SCALE_MAX: C2RustUnnamed_0 = 38;
pub const _SC_BC_DIM_MAX: C2RustUnnamed_0 = 37;
pub const _SC_BC_BASE_MAX: C2RustUnnamed_0 = 36;
pub const _SC_TIMER_MAX: C2RustUnnamed_0 = 35;
pub const _SC_SIGQUEUE_MAX: C2RustUnnamed_0 = 34;
pub const _SC_SEM_VALUE_MAX: C2RustUnnamed_0 = 33;
pub const _SC_SEM_NSEMS_MAX: C2RustUnnamed_0 = 32;
pub const _SC_RTSIG_MAX: C2RustUnnamed_0 = 31;
pub const _SC_PAGESIZE: C2RustUnnamed_0 = 30;
pub const _SC_VERSION: C2RustUnnamed_0 = 29;
pub const _SC_MQ_PRIO_MAX: C2RustUnnamed_0 = 28;
pub const _SC_MQ_OPEN_MAX: C2RustUnnamed_0 = 27;
pub const _SC_DELAYTIMER_MAX: C2RustUnnamed_0 = 26;
pub const _SC_AIO_PRIO_DELTA_MAX: C2RustUnnamed_0 = 25;
pub const _SC_AIO_MAX: C2RustUnnamed_0 = 24;
pub const _SC_AIO_LISTIO_MAX: C2RustUnnamed_0 = 23;
pub const _SC_SHARED_MEMORY_OBJECTS: C2RustUnnamed_0 = 22;
pub const _SC_SEMAPHORES: C2RustUnnamed_0 = 21;
pub const _SC_MESSAGE_PASSING: C2RustUnnamed_0 = 20;
pub const _SC_MEMORY_PROTECTION: C2RustUnnamed_0 = 19;
pub const _SC_MEMLOCK_RANGE: C2RustUnnamed_0 = 18;
pub const _SC_MEMLOCK: C2RustUnnamed_0 = 17;
pub const _SC_MAPPED_FILES: C2RustUnnamed_0 = 16;
pub const _SC_FSYNC: C2RustUnnamed_0 = 15;
pub const _SC_SYNCHRONIZED_IO: C2RustUnnamed_0 = 14;
pub const _SC_PRIORITIZED_IO: C2RustUnnamed_0 = 13;
pub const _SC_ASYNCHRONOUS_IO: C2RustUnnamed_0 = 12;
pub const _SC_TIMERS: C2RustUnnamed_0 = 11;
pub const _SC_PRIORITY_SCHEDULING: C2RustUnnamed_0 = 10;
pub const _SC_REALTIME_SIGNALS: C2RustUnnamed_0 = 9;
pub const _SC_SAVED_IDS: C2RustUnnamed_0 = 8;
pub const _SC_JOB_CONTROL: C2RustUnnamed_0 = 7;
pub const _SC_TZNAME_MAX: C2RustUnnamed_0 = 6;
pub const _SC_STREAM_MAX: C2RustUnnamed_0 = 5;
pub const _SC_OPEN_MAX: C2RustUnnamed_0 = 4;
pub const _SC_NGROUPS_MAX: C2RustUnnamed_0 = 3;
pub const _SC_CLK_TCK: C2RustUnnamed_0 = 2;
pub const _SC_CHILD_MAX: C2RustUnnamed_0 = 1;
pub const _SC_ARG_MAX: C2RustUnnamed_0 = 0;
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
    pub key: *mut crate::sshkey::sshkey,
}

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
pub struct kex {
    pub newkeys: [*mut newkeys; 2],
    pub we_need: u_int,
    pub dh_need: u_int,
    pub server: libc::c_int,
    pub name: *mut libc::c_char,
    pub hostkey_alg: *mut libc::c_char,
    pub hostkey_type: libc::c_int,
    pub hostkey_nid: libc::c_int,
    pub kex_type: u_int,
    pub server_sig_algs: *mut libc::c_char,
    pub ext_info_c: libc::c_int,
    pub my: *mut crate::sshbuf::sshbuf,
    pub peer: *mut crate::sshbuf::sshbuf,
    pub client_version: *mut crate::sshbuf::sshbuf,
    pub server_version: *mut crate::sshbuf::sshbuf,
    pub session_id: *mut crate::sshbuf::sshbuf,
    pub initial_sig: *mut crate::sshbuf::sshbuf,
    pub initial_hostkey: *mut crate::sshkey::sshkey,
    pub done: sig_atomic_t,
    pub flags: u_int,
    pub hash_alg: libc::c_int,
    pub ec_nid: libc::c_int,
    pub failed_choice: *mut libc::c_char,
    pub verify_host_key:
        Option<unsafe extern "C" fn(*mut crate::sshkey::sshkey, *mut ssh) -> libc::c_int>,
    pub load_host_public_key: Option<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut crate::sshkey::sshkey,
    >,
    pub load_host_private_key: Option<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut crate::sshkey::sshkey,
    >,
    pub host_key_index: Option<
        unsafe extern "C" fn(*mut crate::sshkey::sshkey, libc::c_int, *mut ssh) -> libc::c_int,
    >,
    pub sign: Option<
        unsafe extern "C" fn(
            *mut ssh,
            *mut crate::sshkey::sshkey,
            *mut crate::sshkey::sshkey,
            *mut *mut u_char,
            *mut size_t,
            *const u_char,
            size_t,
            *const libc::c_char,
        ) -> libc::c_int,
    >,
    pub kex: [Option<unsafe extern "C" fn(*mut ssh) -> libc::c_int>; 10],
    pub dh: *mut DH,
    pub min: u_int,
    pub max: u_int,
    pub nbits: u_int,
    pub ec_client_key: *mut crate::sshkey::EC_KEY,
    pub ec_group: *const EC_GROUP,
    pub c25519_client_key: [u_char; 32],
    pub c25519_client_pubkey: [u_char; 32],
    pub sntrup761_client_key: [u_char; 1763],
    pub client_pub: *mut crate::sshbuf::sshbuf,
}
pub type EC_GROUP = ec_group_st;
pub type DH = dh_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct newkeys {
    pub enc: sshenc,
    pub mac: sshmac,
    pub comp: sshcomp,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshcomp {
    pub type_0: u_int,
    pub enabled: libc::c_int,
    pub name: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshmac {
    pub name: *mut libc::c_char,
    pub enabled: libc::c_int,
    pub mac_len: u_int,
    pub key: *mut u_char,
    pub key_len: u_int,
    pub type_0: libc::c_int,
    pub etm: libc::c_int,
    pub hmac_ctx: *mut ssh_hmac_ctx,
    pub umac_ctx: *mut umac_ctx,
}

pub type __rlimit_resource = libc::c_uint;
pub const __RLIM_NLIMITS: __rlimit_resource = 16;
pub const __RLIMIT_NLIMITS: __rlimit_resource = 16;
pub const __RLIMIT_RTTIME: __rlimit_resource = 15;
pub const __RLIMIT_RTPRIO: __rlimit_resource = 14;
pub const __RLIMIT_NICE: __rlimit_resource = 13;
pub const __RLIMIT_MSGQUEUE: __rlimit_resource = 12;
pub const __RLIMIT_SIGPENDING: __rlimit_resource = 11;
pub const __RLIMIT_LOCKS: __rlimit_resource = 10;
pub const __RLIMIT_MEMLOCK: __rlimit_resource = 8;
pub const __RLIMIT_NPROC: __rlimit_resource = 6;
pub const RLIMIT_AS: __rlimit_resource = 9;
pub const __RLIMIT_OFILE: __rlimit_resource = 7;
pub const RLIMIT_NOFILE: __rlimit_resource = 7;
pub const __RLIMIT_RSS: __rlimit_resource = 5;
pub const RLIMIT_CORE: __rlimit_resource = 4;
pub const RLIMIT_STACK: __rlimit_resource = 3;
pub const RLIMIT_DATA: __rlimit_resource = 2;
pub const RLIMIT_FSIZE: __rlimit_resource = 1;
pub const RLIMIT_CPU: __rlimit_resource = 0;
pub type rlim_t = __rlim_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rlimit {
    pub rlim_cur: rlim_t,
    pub rlim_max: rlim_t,
}
pub type __rlimit_resource_t = __rlimit_resource;
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
pub type kex_init_proposals = libc::c_uint;
pub const PROPOSAL_MAX: kex_init_proposals = 10;
pub const PROPOSAL_LANG_STOC: kex_init_proposals = 9;
pub const PROPOSAL_LANG_CTOS: kex_init_proposals = 8;
pub const PROPOSAL_COMP_ALGS_STOC: kex_init_proposals = 7;
pub const PROPOSAL_COMP_ALGS_CTOS: kex_init_proposals = 6;
pub const PROPOSAL_MAC_ALGS_STOC: kex_init_proposals = 5;
pub const PROPOSAL_MAC_ALGS_CTOS: kex_init_proposals = 4;
pub const PROPOSAL_ENC_ALGS_STOC: kex_init_proposals = 3;
pub const PROPOSAL_ENC_ALGS_CTOS: kex_init_proposals = 2;
pub const PROPOSAL_SERVER_HOST_KEY_ALGS: kex_init_proposals = 1;
pub const PROPOSAL_KEX_ALGS: kex_init_proposals = 0;
pub type kex_exchange = libc::c_uint;
pub const KEX_MAX: kex_exchange = 10;
pub const KEX_KEM_SNTRUP761X25519_SHA512: kex_exchange = 9;
pub const KEX_C25519_SHA256: kex_exchange = 8;
pub const KEX_ECDH_SHA2: kex_exchange = 7;
pub const KEX_DH_GEX_SHA256: kex_exchange = 6;
pub const KEX_DH_GEX_SHA1: kex_exchange = 5;
pub const KEX_DH_GRP18_SHA512: kex_exchange = 4;
pub const KEX_DH_GRP16_SHA512: kex_exchange = 3;
pub const KEX_DH_GRP14_SHA256: kex_exchange = 2;
pub const KEX_DH_GRP14_SHA1: kex_exchange = 1;
pub const KEX_DH_GRP1_SHA1: kex_exchange = 0;
pub type C2RustUnnamed_4 = libc::c_uint;
pub const DISPATCH_NONBLOCK: C2RustUnnamed_4 = 1;
pub const DISPATCH_BLOCK: C2RustUnnamed_4 = 0;
pub type SyslogFacility = libc::c_int;
pub const SYSLOG_FACILITY_NOT_SET: SyslogFacility = -1;
pub const SYSLOG_FACILITY_LOCAL7: SyslogFacility = 10;
pub const SYSLOG_FACILITY_LOCAL6: SyslogFacility = 9;
pub const SYSLOG_FACILITY_LOCAL5: SyslogFacility = 8;
pub const SYSLOG_FACILITY_LOCAL4: SyslogFacility = 7;
pub const SYSLOG_FACILITY_LOCAL3: SyslogFacility = 6;
pub const SYSLOG_FACILITY_LOCAL2: SyslogFacility = 5;
pub const SYSLOG_FACILITY_LOCAL1: SyslogFacility = 4;
pub const SYSLOG_FACILITY_LOCAL0: SyslogFacility = 3;
pub const SYSLOG_FACILITY_AUTH: SyslogFacility = 2;
pub const SYSLOG_FACILITY_USER: SyslogFacility = 1;
pub const SYSLOG_FACILITY_DAEMON: SyslogFacility = 0;
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
pub struct xaddr {
    pub af: sa_family_t,
    pub xa: C2RustUnnamed_5,
    pub scope_id: u_int32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_5 {
    pub v4: in_addr,
    pub v6: in6_addr,
    pub addr8: [u_int8_t; 16],
    pub addr16: [u_int16_t; 8],
    pub addr32: [u_int32_t; 4],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Connection {
    pub c_status: u_char,
    pub c_fd: libc::c_int,
    pub c_plen: libc::c_int,
    pub c_len: libc::c_int,
    pub c_off: libc::c_int,
    pub c_keytype: libc::c_int,
    pub c_done: sig_atomic_t,
    pub c_namebase: *mut libc::c_char,
    pub c_name: *mut libc::c_char,
    pub c_namelist: *mut libc::c_char,
    pub c_output_name: *mut libc::c_char,
    pub c_data: *mut libc::c_char,
    pub c_ssh: *mut ssh,
    pub c_ts: libc::timespec,
    pub c_link: C2RustUnnamed_6,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_6 {
    pub tqe_next: *mut Connection,
    pub tqe_prev: *mut *mut Connection,
}
pub type con = Connection;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct conlist {
    pub tqh_first: *mut Connection,
    pub tqh_last: *mut *mut Connection,
}
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
#[inline]
unsafe extern "C" fn getline(
    mut __lineptr: *mut *mut libc::c_char,
    mut __n: *mut size_t,
    mut __stream: *mut libc::FILE,
) -> __ssize_t {
    return __getdelim(__lineptr, __n, '\n' as i32, __stream);
}
pub static mut IPv4or6: libc::c_int = 0 as libc::c_int;
pub static mut ssh_port: libc::c_int = 22 as libc::c_int;
pub static mut get_cert: libc::c_int = 0 as libc::c_int;
pub static mut get_keytypes: libc::c_int = (1 as libc::c_int) << 1 as libc::c_int
    | (1 as libc::c_int) << 2 as libc::c_int
    | (1 as libc::c_int) << 3 as libc::c_int
    | (1 as libc::c_int) << 5 as libc::c_int
    | (1 as libc::c_int) << 6 as libc::c_int;
pub static mut hash_hosts: libc::c_int = 0 as libc::c_int;
pub static mut print_sshfp: libc::c_int = 0 as libc::c_int;
pub static mut found_one: libc::c_int = 0 as libc::c_int;
pub static mut hashalg: libc::c_int = -(1 as libc::c_int);
pub static mut timeout: libc::c_int = 5 as libc::c_int;
pub static mut maxfd: libc::c_int = 0;
pub static mut read_wait: *mut pollfd = 0 as *const pollfd as *mut pollfd;
pub static mut ncon: libc::c_int = 0;
pub static mut tq: conlist = conlist {
    tqh_first: 0 as *const Connection as *mut Connection,
    tqh_last: 0 as *const *mut Connection as *mut *mut Connection,
};
pub static mut fdcon: *mut con = 0 as *const con as *mut con;
unsafe extern "C" fn fdlim_get(mut hard: libc::c_int) -> libc::c_int {
    let mut rlfd: rlimit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if getrlimit(RLIMIT_NOFILE, &mut rlfd) == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    if (if hard != 0 {
        rlfd.rlim_max
    } else {
        rlfd.rlim_cur
    }) == -(1 as libc::c_int) as __rlim_t
    {
        return sysconf(_SC_OPEN_MAX as libc::c_int) as libc::c_int;
    } else {
        return (if hard != 0 {
            rlfd.rlim_max
        } else {
            rlfd.rlim_cur
        }) as libc::c_int;
    };
}
unsafe extern "C" fn fdlim_set(mut lim: libc::c_int) -> libc::c_int {
    let mut rlfd: rlimit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if lim <= 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if getrlimit(RLIMIT_NOFILE, &mut rlfd) == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    rlfd.rlim_cur = lim as rlim_t;
    if setrlimit(RLIMIT_NOFILE, &mut rlfd) == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xstrsep(
    mut str: *mut *mut libc::c_char,
    mut delim: *const libc::c_char,
) -> *mut libc::c_char {
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut e: *mut libc::c_char = 0 as *mut libc::c_char;
    if **str == 0 {
        return 0 as *mut libc::c_char;
    }
    s = *str;
    e = s.offset(strcspn(s, delim) as isize);
    if *e as libc::c_int != '\0' as i32 {
        let fresh0 = e;
        e = e.offset(1);
        *fresh0 = '\0' as i32 as libc::c_char;
    }
    *str = e;
    return s;
}
unsafe extern "C" fn strnnsep(
    mut stringp: *mut *mut libc::c_char,
    mut delim: *mut libc::c_char,
) -> *mut libc::c_char {
    let mut tok: *mut libc::c_char = 0 as *mut libc::c_char;
    loop {
        tok = xstrsep(stringp, delim);
        if !(!tok.is_null() && *tok as libc::c_int == '\0' as i32) {
            break;
        }
    }
    return tok;
}
unsafe extern "C" fn key_print_wrapper(
    mut hostkey: *mut crate::sshkey::sshkey,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut c: *mut con = 0 as *mut con;
    c = ssh_get_app_data(ssh) as *mut con;
    if !c.is_null() {
        keyprint(c, hostkey);
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn ssh2_capable(
    mut remote_major: libc::c_int,
    mut remote_minor: libc::c_int,
) -> libc::c_int {
    match remote_major {
        1 => {
            if remote_minor == 99 as libc::c_int {
                return 1 as libc::c_int;
            }
        }
        2 => return 1 as libc::c_int,
        _ => {}
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn keygrab_ssh2(mut c: *mut con) {
    let mut myproposal: [*mut libc::c_char; 10] = [
        b"sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256\0"
            as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\0"
            as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\0"
            as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\0"
            as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\0"
            as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\0"
            as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"none,zlib@openssh.com\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        b"none,zlib@openssh.com\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ];
    let mut r: libc::c_int = 0;
    match (*c).c_keytype {
        1 => {
            myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as usize] = (if get_cert != 0 {
                b"ssh-dss-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char
            } else {
                b"ssh-dss\0" as *const u8 as *const libc::c_char
            })
                as *mut libc::c_char;
        }
        2 => {
            myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as usize] = (if get_cert != 0 {
                b"rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com\0"
                    as *const u8 as *const libc::c_char
            } else {
                b"rsa-sha2-512,rsa-sha2-256,ssh-rsa\0" as *const u8 as *const libc::c_char
            })
                as *mut libc::c_char;
        }
        8 => {
            myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as usize] = (if get_cert != 0 {
                b"ssh-ed25519-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char
            } else {
                b"ssh-ed25519\0" as *const u8 as *const libc::c_char
            })
                as *mut libc::c_char;
        }
        16 => {
            myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as usize] = (if get_cert != 0 {
                b"ssh-xmss-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char
            } else {
                b"ssh-xmss@openssh.com\0" as *const u8 as *const libc::c_char
            })
                as *mut libc::c_char;
        }
        4 => {
            myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as usize] = (if get_cert != 0 {
                b"ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com\0"
                    as *const u8 as *const libc::c_char
            } else {
                b"ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521\0" as *const u8
                    as *const libc::c_char
            })
                as *mut libc::c_char;
        }
        32 => {
            myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as usize] = (if get_cert != 0 {
                b"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char
            } else {
                b"sk-ecdsa-sha2-nistp256@openssh.com\0" as *const u8 as *const libc::c_char
            })
                as *mut libc::c_char;
        }
        64 => {
            myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as usize] = (if get_cert != 0 {
                b"sk-ssh-ed25519-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char
            } else {
                b"sk-ssh-ed25519@openssh.com\0" as *const u8 as *const libc::c_char
            })
                as *mut libc::c_char;
        }
        _ => {
            sshfatal(
                b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"keygrab_ssh2\0"))
                    .as_ptr(),
                281 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unknown key type %d\0" as *const u8 as *const libc::c_char,
                (*c).c_keytype,
            );
        }
    }
    r = kex_setup((*c).c_ssh, myproposal.as_mut_ptr());
    if r != 0 as libc::c_int {
        libc::free((*c).c_ssh as *mut libc::c_void);
        libc::fprintf(
            stderr,
            b"kex_setup: %s\n\0" as *const u8 as *const libc::c_char,
            ssh_err(r),
        );
        libc::exit(1 as libc::c_int);
    }
    (*(*(*c).c_ssh).kex).kex[KEX_DH_GRP1_SHA1 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*(*c).c_ssh).kex).kex[KEX_DH_GRP14_SHA1 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*(*c).c_ssh).kex).kex[KEX_DH_GRP14_SHA256 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*(*c).c_ssh).kex).kex[KEX_DH_GRP16_SHA512 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*(*c).c_ssh).kex).kex[KEX_DH_GRP18_SHA512 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*(*c).c_ssh).kex).kex[KEX_DH_GEX_SHA1 as libc::c_int as usize] =
        Some(kexgex_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*(*c).c_ssh).kex).kex[KEX_DH_GEX_SHA256 as libc::c_int as usize] =
        Some(kexgex_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*(*c).c_ssh).kex).kex[KEX_ECDH_SHA2 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*(*c).c_ssh).kex).kex[KEX_C25519_SHA256 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*(*c).c_ssh).kex).kex[KEX_KEM_SNTRUP761X25519_SHA512 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    ssh_set_verify_host_key_callback(
        (*c).c_ssh,
        Some(
            key_print_wrapper
                as unsafe extern "C" fn(*mut crate::sshkey::sshkey, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_run(
        (*c).c_ssh,
        DISPATCH_BLOCK as libc::c_int,
        &mut (*c).c_done as *mut sig_atomic_t as *mut sig_atomic_t,
    );
}
unsafe extern "C" fn keyprint_one(
    mut host: *const libc::c_char,
    mut key: *mut crate::sshkey::sshkey,
) {
    let mut hostport: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hashed: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut known_host: *const libc::c_char = 0 as *const libc::c_char;
    let mut r: libc::c_int = 0 as libc::c_int;
    found_one = 1 as libc::c_int;
    if print_sshfp != 0 {
        export_dns_rr(host, key, stdout, 0 as libc::c_int, hashalg);
        return;
    }
    hostport = put_host_port(host, ssh_port as u_short);
    lowercase(hostport);
    if hash_hosts != 0 && {
        hashed = host_hash(
            hostport,
            0 as *const libc::c_char,
            0 as libc::c_int as u_int,
        );
        hashed.is_null()
    } {
        sshfatal(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"keyprint_one\0")).as_ptr(),
            328 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"host_hash failed\0" as *const u8 as *const libc::c_char,
        );
    }
    known_host = if hash_hosts != 0 { hashed } else { hostport };
    if get_cert == 0 {
        r = libc::fprintf(
            stdout,
            b"%s \0" as *const u8 as *const libc::c_char,
            known_host,
        );
    }
    if r >= 0 as libc::c_int && sshkey_write(key, stdout) == 0 as libc::c_int {
        fputs(b"\n\0" as *const u8 as *const libc::c_char, stdout);
    }
    libc::free(hashed as *mut libc::c_void);
    libc::free(hostport as *mut libc::c_void);
}
unsafe extern "C" fn keyprint(mut c: *mut con, mut key: *mut crate::sshkey::sshkey) {
    let mut hosts: *mut libc::c_char = if !((*c).c_output_name).is_null() {
        (*c).c_output_name
    } else {
        (*c).c_name
    };
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ohosts: *mut libc::c_char = 0 as *mut libc::c_char;
    if key.is_null() {
        return;
    }
    if get_cert != 0 || hash_hosts == 0 && ssh_port == 22 as libc::c_int {
        keyprint_one(hosts, key);
        return;
    }
    hosts = crate::xmalloc::xstrdup(hosts);
    ohosts = hosts;
    loop {
        host = strsep(&mut hosts, b",\0" as *const u8 as *const libc::c_char);
        if host.is_null() {
            break;
        }
        keyprint_one(host, key);
    }
    libc::free(ohosts as *mut libc::c_void);
}
unsafe extern "C" fn tcpconnect(mut host: *mut libc::c_char) -> libc::c_int {
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
    let mut aitop: *mut addrinfo = 0 as *mut addrinfo;
    let mut strport: [libc::c_char; 32] = [0; 32];
    let mut gaierr: libc::c_int = 0;
    let mut s: libc::c_int = -(1 as libc::c_int);
    libc::snprintf(
        strport.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
        b"%d\0" as *const u8 as *const libc::c_char,
        ssh_port,
    );
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_family = IPv4or6;
    hints.ai_socktype = SOCK_STREAM as libc::c_int;
    gaierr = getaddrinfo(host, strport.as_mut_ptr(), &mut hints, &mut aitop);
    if gaierr != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"tcpconnect\0")).as_ptr(),
            368 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"getaddrinfo %s: %s\0" as *const u8 as *const libc::c_char,
            host,
            ssh_gai_strerror(gaierr),
        );
        return -(1 as libc::c_int);
    }
    ai = aitop;
    while !ai.is_null() {
        s = socket((*ai).ai_family, (*ai).ai_socktype, (*ai).ai_protocol);
        if s == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"tcpconnect\0"))
                    .as_ptr(),
                374 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"socket: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        } else {
            if crate::misc::set_nonblock(s) == -(1 as libc::c_int) {
                sshfatal(
                    b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"tcpconnect\0"))
                        .as_ptr(),
                    378 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"crate::misc::set_nonblock(%d)\0" as *const u8 as *const libc::c_char,
                    s,
                );
            }
            if !(connect(
                s,
                __CONST_SOCKADDR_ARG {
                    __sockaddr__: (*ai).ai_addr,
                },
                (*ai).ai_addrlen,
            ) == -(1 as libc::c_int)
                && *libc::__errno_location() != 115 as libc::c_int)
            {
                break;
            }
            crate::log::sshlog(
                b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"tcpconnect\0"))
                    .as_ptr(),
                381 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"connect (`%s'): %s\0" as *const u8 as *const libc::c_char,
                host,
                libc::strerror(*libc::__errno_location()),
            );
            close(s);
            s = -(1 as libc::c_int);
        }
        ai = (*ai).ai_next;
    }
    freeaddrinfo(aitop);
    return s;
}
unsafe extern "C" fn conalloc(
    mut iname: *const libc::c_char,
    mut oname: *const libc::c_char,
    mut keytype: libc::c_int,
) -> libc::c_int {
    let mut namebase: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut namelist: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut s: libc::c_int = 0;
    namelist = crate::xmalloc::xstrdup(iname);
    namebase = namelist;
    loop {
        name = xstrsep(&mut namelist, b",\0" as *const u8 as *const libc::c_char);
        if name.is_null() {
            libc::free(namebase as *mut libc::c_void);
            return -(1 as libc::c_int);
        }
        s = tcpconnect(name);
        if !(s < 0 as libc::c_int) {
            break;
        }
    }
    if s >= maxfd {
        sshfatal(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"conalloc\0")).as_ptr(),
            408 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"conalloc: fdno %d too high\0" as *const u8 as *const libc::c_char,
            s,
        );
    }
    if (*fdcon.offset(s as isize)).c_status != 0 {
        sshfatal(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"conalloc\0")).as_ptr(),
            410 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"conalloc: attempt to reuse fdno %d\0" as *const u8 as *const libc::c_char,
            s,
        );
    }
    crate::log::sshlog(
        b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"conalloc\0")).as_ptr(),
        412 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"oname %s kt %d\0" as *const u8 as *const libc::c_char,
        oname,
        keytype,
    );
    (*fdcon.offset(s as isize)).c_fd = s;
    (*fdcon.offset(s as isize)).c_status = 1 as libc::c_int as u_char;
    let ref mut fresh1 = (*fdcon.offset(s as isize)).c_namebase;
    *fresh1 = namebase;
    let ref mut fresh2 = (*fdcon.offset(s as isize)).c_name;
    *fresh2 = name;
    let ref mut fresh3 = (*fdcon.offset(s as isize)).c_namelist;
    *fresh3 = namelist;
    let ref mut fresh4 = (*fdcon.offset(s as isize)).c_output_name;
    *fresh4 = crate::xmalloc::xstrdup(oname);
    let ref mut fresh5 = (*fdcon.offset(s as isize)).c_data;
    *fresh5 = &mut (*fdcon.offset(s as isize)).c_plen as *mut libc::c_int as *mut libc::c_char;
    (*fdcon.offset(s as isize)).c_len = 4 as libc::c_int;
    (*fdcon.offset(s as isize)).c_off = 0 as libc::c_int;
    (*fdcon.offset(s as isize)).c_keytype = keytype;
    monotime_ts(&mut (*fdcon.offset(s as isize)).c_ts);
    let ref mut fresh6 = (*fdcon.offset(s as isize)).c_ts.tv_sec;
    *fresh6 += timeout as libc::c_long;
    let ref mut fresh7 = (*fdcon.offset(s as isize)).c_link.tqe_next;
    *fresh7 = 0 as *mut Connection;
    let ref mut fresh8 = (*fdcon.offset(s as isize)).c_link.tqe_prev;
    *fresh8 = tq.tqh_last;
    *tq.tqh_last = &mut *fdcon.offset(s as isize) as *mut con;
    tq.tqh_last = &mut (*fdcon.offset(s as isize)).c_link.tqe_next;
    (*read_wait.offset(s as isize)).fd = s;
    (*read_wait.offset(s as isize)).events = 0x1 as libc::c_int as libc::c_short;
    ncon += 1;
    ncon;
    return s;
}
unsafe extern "C" fn confree(mut s: libc::c_int) {
    if s >= maxfd || (*fdcon.offset(s as isize)).c_status as libc::c_int == 0 as libc::c_int {
        sshfatal(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"confree\0")).as_ptr(),
            436 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"confree: attempt to libc::free bad fdno %d\0" as *const u8 as *const libc::c_char,
            s,
        );
    }
    libc::free((*fdcon.offset(s as isize)).c_namebase as *mut libc::c_void);
    libc::free((*fdcon.offset(s as isize)).c_output_name as *mut libc::c_void);
    if (*fdcon.offset(s as isize)).c_status as libc::c_int == 3 as libc::c_int {
        libc::free((*fdcon.offset(s as isize)).c_data as *mut libc::c_void);
    }
    (*fdcon.offset(s as isize)).c_status = 0 as libc::c_int as u_char;
    (*fdcon.offset(s as isize)).c_keytype = 0 as libc::c_int;
    if !((*fdcon.offset(s as isize)).c_ssh).is_null() {
        ssh_packet_close((*fdcon.offset(s as isize)).c_ssh);
        libc::free((*fdcon.offset(s as isize)).c_ssh as *mut libc::c_void);
        let ref mut fresh9 = (*fdcon.offset(s as isize)).c_ssh;
        *fresh9 = 0 as *mut ssh;
    } else {
        close(s);
    }
    if !((*fdcon.offset(s as isize)).c_link.tqe_next).is_null() {
        let ref mut fresh10 = (*(*fdcon.offset(s as isize)).c_link.tqe_next)
            .c_link
            .tqe_prev;
        *fresh10 = (*fdcon.offset(s as isize)).c_link.tqe_prev;
    } else {
        tq.tqh_last = (*fdcon.offset(s as isize)).c_link.tqe_prev;
    }
    let ref mut fresh11 = *(*fdcon.offset(s as isize)).c_link.tqe_prev;
    *fresh11 = (*fdcon.offset(s as isize)).c_link.tqe_next;
    (*read_wait.offset(s as isize)).fd = -(1 as libc::c_int);
    (*read_wait.offset(s as isize)).events = 0 as libc::c_int as libc::c_short;
    ncon -= 1;
    ncon;
}
unsafe extern "C" fn contouch(mut s: libc::c_int) {
    if !((*fdcon.offset(s as isize)).c_link.tqe_next).is_null() {
        let ref mut fresh12 = (*(*fdcon.offset(s as isize)).c_link.tqe_next)
            .c_link
            .tqe_prev;
        *fresh12 = (*fdcon.offset(s as isize)).c_link.tqe_prev;
    } else {
        tq.tqh_last = (*fdcon.offset(s as isize)).c_link.tqe_prev;
    }
    let ref mut fresh13 = *(*fdcon.offset(s as isize)).c_link.tqe_prev;
    *fresh13 = (*fdcon.offset(s as isize)).c_link.tqe_next;
    monotime_ts(&mut (*fdcon.offset(s as isize)).c_ts);
    let ref mut fresh14 = (*fdcon.offset(s as isize)).c_ts.tv_sec;
    *fresh14 += timeout as libc::c_long;
    let ref mut fresh15 = (*fdcon.offset(s as isize)).c_link.tqe_next;
    *fresh15 = 0 as *mut Connection;
    let ref mut fresh16 = (*fdcon.offset(s as isize)).c_link.tqe_prev;
    *fresh16 = tq.tqh_last;
    *tq.tqh_last = &mut *fdcon.offset(s as isize) as *mut con;
    tq.tqh_last = &mut (*fdcon.offset(s as isize)).c_link.tqe_next;
}
unsafe extern "C" fn conrecycle(mut s: libc::c_int) -> libc::c_int {
    let mut c: *mut con = &mut *fdcon.offset(s as isize) as *mut con;
    let mut ret: libc::c_int = 0;
    ret = conalloc((*c).c_namelist, (*c).c_output_name, (*c).c_keytype);
    confree(s);
    return ret;
}
unsafe extern "C" fn congreet(mut s: libc::c_int) {
    let mut n: libc::c_int = 0 as libc::c_int;
    let mut remote_major: libc::c_int = 0 as libc::c_int;
    let mut remote_minor: libc::c_int = 0 as libc::c_int;
    let mut buf: [libc::c_char; 256] = [0; 256];
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut remote_version: [libc::c_char; 256] = [0; 256];
    let mut bufsiz: size_t = 0;
    let mut c: *mut con = &mut *fdcon.offset(s as isize) as *mut con;
    n = libc::snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
        b"SSH-%d.%d-OpenSSH-keyscan\r\n\0" as *const u8 as *const libc::c_char,
        2 as libc::c_int,
        0 as libc::c_int,
    );
    if n < 0 as libc::c_int
        || n as size_t >= ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong
    {
        crate::log::sshlog(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"congreet\0")).as_ptr(),
            488 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libc::snprintf: buffer too small\0" as *const u8 as *const libc::c_char,
        );
        confree(s);
        return;
    }
    if atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        s,
        buf.as_mut_ptr() as *mut libc::c_void,
        n as size_t,
    ) != n as size_t
    {
        crate::log::sshlog(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"congreet\0")).as_ptr(),
            493 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"write (%s): %s\0" as *const u8 as *const libc::c_char,
            (*c).c_name,
            libc::strerror(*libc::__errno_location()),
        );
        confree(s);
        return;
    }
    loop {
        memset(
            buf.as_mut_ptr() as *mut libc::c_void,
            '\0' as i32,
            ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
        );
        bufsiz = ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong;
        cp = buf.as_mut_ptr();
        loop {
            let fresh17 = bufsiz;
            bufsiz = bufsiz.wrapping_sub(1);
            if !(fresh17 != 0
                && {
                    n = atomicio(
                        Some(
                            read as unsafe extern "C" fn(
                                libc::c_int,
                                *mut libc::c_void,
                                size_t,
                            ) -> ssize_t,
                        ),
                        s,
                        cp as *mut libc::c_void,
                        1 as libc::c_int as size_t,
                    ) as libc::c_int;
                    n == 1 as libc::c_int
                }
                && *cp as libc::c_int != '\n' as i32)
            {
                break;
            }
            if *cp as libc::c_int == '\r' as i32 {
                *cp = '\n' as i32 as libc::c_char;
            }
            cp = cp.offset(1);
            cp;
        }
        if n != 1 as libc::c_int
            || strncmp(
                buf.as_mut_ptr(),
                b"SSH-\0" as *const u8 as *const libc::c_char,
                4 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
        {
            break;
        }
    }
    if n == 0 as libc::c_int {
        match *libc::__errno_location() {
            32 => {
                crate::log::sshlog(
                    b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"congreet\0"))
                        .as_ptr(),
                    523 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: Connection closed by remote host\0" as *const u8 as *const libc::c_char,
                    (*c).c_name,
                );
            }
            111 => {}
            _ => {
                crate::log::sshlog(
                    b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"congreet\0"))
                        .as_ptr(),
                    528 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"read (%s): %s\0" as *const u8 as *const libc::c_char,
                    (*c).c_name,
                    libc::strerror(*libc::__errno_location()),
                );
            }
        }
        conrecycle(s);
        return;
    }
    if cp
        >= buf
            .as_mut_ptr()
            .offset(::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong as isize)
    {
        crate::log::sshlog(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"congreet\0")).as_ptr(),
            535 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s: greeting exceeds allowable length\0" as *const u8 as *const libc::c_char,
            (*c).c_name,
        );
        confree(s);
        return;
    }
    if *cp as libc::c_int != '\n' as i32 && *cp as libc::c_int != '\r' as i32 {
        crate::log::sshlog(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"congreet\0")).as_ptr(),
            540 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s: bad greeting\0" as *const u8 as *const libc::c_char,
            (*c).c_name,
        );
        confree(s);
        return;
    }
    *cp = '\0' as i32 as libc::c_char;
    (*c).c_ssh = ssh_packet_set_connection(0 as *mut ssh, s, s);
    if ((*c).c_ssh).is_null() {
        sshfatal(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"congreet\0")).as_ptr(),
            546 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ssh_packet_set_connection failed\0" as *const u8 as *const libc::c_char,
        );
    }
    ssh_packet_set_timeout((*c).c_ssh, timeout, 1 as libc::c_int);
    ssh_set_app_data((*c).c_ssh, c as *mut libc::c_void);
    (*(*c).c_ssh).compat = 0 as libc::c_int;
    if sscanf(
        buf.as_mut_ptr(),
        b"SSH-%d.%d-%[^\n]\n\0" as *const u8 as *const libc::c_char,
        &mut remote_major as *mut libc::c_int,
        &mut remote_minor as *mut libc::c_int,
        remote_version.as_mut_ptr(),
    ) == 3 as libc::c_int
    {
        compat_banner((*c).c_ssh, remote_version.as_mut_ptr());
    }
    if ssh2_capable(remote_major, remote_minor) == 0 {
        crate::log::sshlog(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"congreet\0")).as_ptr(),
            554 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s doesn't support ssh2\0" as *const u8 as *const libc::c_char,
            (*c).c_name,
        );
        confree(s);
        return;
    }
    libc::fprintf(
        stderr,
        b"%c %s:%d %s\n\0" as *const u8 as *const libc::c_char,
        if print_sshfp != 0 {
            ';' as i32
        } else {
            '#' as i32
        },
        (*c).c_name,
        ssh_port,
        chop(buf.as_mut_ptr()),
    );
    keygrab_ssh2(c);
    confree(s);
}
unsafe extern "C" fn conread(mut s: libc::c_int) {
    let mut c: *mut con = &mut *fdcon.offset(s as isize) as *mut con;
    let mut n: size_t = 0;
    if (*c).c_status as libc::c_int == 1 as libc::c_int {
        congreet(s);
        return;
    }
    n = atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        s,
        ((*c).c_data).offset((*c).c_off as isize) as *mut libc::c_void,
        ((*c).c_len - (*c).c_off) as size_t,
    );
    if n == 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"conread\0")).as_ptr(),
            576 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"read (%s): %s\0" as *const u8 as *const libc::c_char,
            (*c).c_name,
            libc::strerror(*libc::__errno_location()),
        );
        confree(s);
        return;
    }
    (*c).c_off = ((*c).c_off as libc::c_ulong).wrapping_add(n) as libc::c_int as libc::c_int;
    if (*c).c_off == (*c).c_len {
        match (*c).c_status as libc::c_int {
            2 => {
                (*c).c_plen = __bswap_32((*c).c_plen as __uint32_t) as libc::c_int;
                (*c).c_len = (*c).c_plen + 8 as libc::c_int - ((*c).c_plen & 7 as libc::c_int);
                (*c).c_off = 0 as libc::c_int;
                (*c).c_data = crate::xmalloc::xmalloc((*c).c_len as size_t) as *mut libc::c_char;
                (*c).c_status = 3 as libc::c_int as u_char;
            }
            _ => {
                sshfatal(
                    b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"conread\0"))
                        .as_ptr(),
                    592 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"conread: invalid status %d\0" as *const u8 as *const libc::c_char,
                    (*c).c_status as libc::c_int,
                );
            }
        }
    }
    contouch(s);
}
unsafe extern "C" fn conloop() {
    let mut seltime: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut now: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut c: *mut con = 0 as *mut con;
    let mut i: libc::c_int = 0;
    monotime_ts(&mut now);
    c = tq.tqh_first;
    if !c.is_null()
        && (if (*c).c_ts.tv_sec == now.tv_sec {
            ((*c).c_ts.tv_nsec > now.tv_nsec) as libc::c_int
        } else {
            ((*c).c_ts.tv_sec > now.tv_sec) as libc::c_int
        }) != 0
    {
        seltime.tv_sec = (*c).c_ts.tv_sec - now.tv_sec;
        seltime.tv_nsec = (*c).c_ts.tv_nsec - now.tv_nsec;
        if seltime.tv_nsec < 0 as libc::c_int as libc::c_long {
            seltime.tv_sec -= 1;
            seltime.tv_sec;
            seltime.tv_nsec += 1000000000 as libc::c_long;
        }
    } else {
        seltime.tv_nsec = 0 as libc::c_int as __syscall_slong_t;
        seltime.tv_sec = seltime.tv_nsec;
    }
    while ppoll(
        read_wait,
        maxfd as nfds_t,
        &mut seltime,
        0 as *const __sigset_t,
    ) == -(1 as libc::c_int)
    {
        if *libc::__errno_location() == 11 as libc::c_int
            || *libc::__errno_location() == 4 as libc::c_int
            || *libc::__errno_location() == 11 as libc::c_int
        {
            continue;
        }
        crate::log::sshlog(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"conloop\0")).as_ptr(),
            617 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"poll error\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int;
    while i < maxfd {
        if (*read_wait.offset(i as isize)).revents as libc::c_int
            & (0x10 as libc::c_int | 0x8 as libc::c_int | 0x20 as libc::c_int)
            != 0
        {
            confree(i);
        } else if (*read_wait.offset(i as isize)).revents as libc::c_int
            & (0x1 as libc::c_int | 0x10 as libc::c_int)
            != 0
        {
            conread(i);
        }
        i += 1;
        i;
    }
    c = tq.tqh_first;
    while !c.is_null()
        && (if (*c).c_ts.tv_sec == now.tv_sec {
            ((*c).c_ts.tv_nsec < now.tv_nsec) as libc::c_int
        } else {
            ((*c).c_ts.tv_sec < now.tv_sec) as libc::c_int
        }) != 0
    {
        let mut s: libc::c_int = (*c).c_fd;
        c = (*c).c_link.tqe_next;
        conrecycle(s);
    }
}
unsafe extern "C" fn do_one_host(mut host: *mut libc::c_char) {
    let mut name: *mut libc::c_char = strnnsep(
        &mut host,
        b" \t\n\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    let mut j: libc::c_int = 0;
    if name.is_null() {
        return;
    }
    j = 1 as libc::c_int;
    while j <= (1 as libc::c_int) << 6 as libc::c_int {
        if get_keytypes & j != 0 {
            while ncon >= maxfd - 10 as libc::c_int {
                conloop();
            }
            conalloc(
                name,
                if *host as libc::c_int != 0 {
                    host
                } else {
                    name
                },
                j,
            );
        }
        j *= 2 as libc::c_int;
    }
}
unsafe extern "C" fn do_host(mut host: *mut libc::c_char) {
    let mut daddr: [libc::c_char; 128] = [0; 128];
    let mut addr: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_5 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut end_addr: xaddr = xaddr {
        af: 0,
        xa: C2RustUnnamed_5 {
            v4: in_addr { s_addr: 0 },
        },
        scope_id: 0,
    };
    let mut masklen: u_int = 0;
    if host.is_null() {
        return;
    }
    if addr_pton_cidr(host, &mut addr, &mut masklen) != 0 as libc::c_int {
        do_one_host(host);
    } else {
        let mut current_block_11: u64;
        crate::log::sshlog(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_host\0")).as_ptr(),
            667 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"CIDR range %s\0" as *const u8 as *const libc::c_char,
            host,
        );
        end_addr = addr;
        if addr_host_to_all1s(&mut end_addr, masklen) != 0 as libc::c_int {
            current_block_11 = 9291219946876342924;
        } else {
            current_block_11 = 10886091980245723256;
        }
        loop {
            match current_block_11 {
                9291219946876342924 => {
                    crate::log::sshlog(
                        b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_host\0"))
                            .as_ptr(),
                        677 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Invalid address %s\0" as *const u8 as *const libc::c_char,
                        host,
                    );
                    return;
                }
                _ => {
                    if addr_ntop(
                        &mut addr,
                        daddr.as_mut_ptr(),
                        ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                    ) != 0 as libc::c_int
                    {
                        current_block_11 = 9291219946876342924;
                        continue;
                    }
                    crate::log::sshlog(
                        b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_host\0"))
                            .as_ptr(),
                        680 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"CIDR expand: address %s\0" as *const u8 as *const libc::c_char,
                        daddr.as_mut_ptr(),
                    );
                    do_one_host(daddr.as_mut_ptr());
                    if addr_cmp(&mut addr, &mut end_addr) == 0 as libc::c_int {
                        break;
                    }
                    addr_increment(&mut addr);
                    current_block_11 = 10886091980245723256;
                }
            }
        }
    };
}
pub unsafe extern "C" fn sshfatal(
    mut file: *const libc::c_char,
    mut func: *const libc::c_char,
    mut line: libc::c_int,
    mut showfunc: libc::c_int,
    mut level: LogLevel,
    mut suffix: *const libc::c_char,
    mut fmt: *const libc::c_char,
    mut args: ...
) -> ! {
    let mut args_0: ::core::ffi::VaListImpl;
    args_0 = args.clone();
    crate::log::sshlogv(
        file,
        func,
        line,
        showfunc,
        level,
        suffix,
        fmt,
        args_0.as_va_list(),
    );
    cleanup_exit(255 as libc::c_int);
}
unsafe extern "C" fn usage() {
    libc::fprintf(
        stderr,
        b"usage: ssh-keyscan [-46cDHv] [-f file] [-O option] [-p port] [-T timeout]\n                   [-t type] [host | addrlist namelist]\n\0"
            as *const u8 as *const libc::c_char,
    );
    libc::exit(1 as libc::c_int);
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char) -> libc::c_int {
    let mut debug_flag: libc::c_int = 0 as libc::c_int;
    let mut log_level: libc::c_int = SYSLOG_LEVEL_INFO as libc::c_int;
    let mut opt: libc::c_int = 0;
    let mut fopt_count: libc::c_int = 0 as libc::c_int;
    let mut j: libc::c_int = 0;
    let mut tname: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut fp: *mut libc::FILE = 0 as *mut libc::FILE;
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptarg"]
        static mut BSDoptarg_0: *mut libc::c_char;
    }
    __progname =
        crate::openbsd_compat::bsd_misc::ssh_get_progname(*argv.offset(0 as libc::c_int as isize));
    seed_rng();
    tq.tqh_first = 0 as *mut Connection;
    tq.tqh_last = &mut tq.tqh_first;
    crate::misc::sanitise_stdfd();
    if argc <= 1 as libc::c_int {
        usage();
    }
    loop {
        opt = crate::openbsd_compat::getopt_long::BSDgetopt(
            argc,
            argv,
            b"cDHv46O:p:T:t:f:\0" as *const u8 as *const libc::c_char,
        );
        if !(opt != -(1 as libc::c_int)) {
            break;
        }
        match opt {
            72 => {
                hash_hosts = 1 as libc::c_int;
            }
            99 => {
                get_cert = 1 as libc::c_int;
            }
            68 => {
                print_sshfp = 1 as libc::c_int;
            }
            112 => {
                ssh_port = crate::misc::a2port(BSDoptarg);
                if ssh_port <= 0 as libc::c_int {
                    libc::fprintf(
                        stderr,
                        b"Bad port '%s'\n\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                    );
                    libc::exit(1 as libc::c_int);
                }
            }
            84 => {
                timeout = convtime(BSDoptarg);
                if timeout == -(1 as libc::c_int) || timeout == 0 as libc::c_int {
                    libc::fprintf(
                        stderr,
                        b"Bad timeout '%s'\n\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                    );
                    usage();
                }
            }
            118 => {
                if debug_flag == 0 {
                    debug_flag = 1 as libc::c_int;
                    log_level = SYSLOG_LEVEL_DEBUG1 as libc::c_int;
                } else if log_level < SYSLOG_LEVEL_DEBUG3 as libc::c_int {
                    log_level += 1;
                    log_level;
                } else {
                    sshfatal(
                        b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        765 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Too high debugging level.\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            102 => {
                if libc::strcmp(BSDoptarg, b"-\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    BSDoptarg = 0 as *mut libc::c_char;
                }
                let fresh18 = fopt_count;
                fopt_count = fopt_count + 1;
                let ref mut fresh19 = *argv.offset(fresh18 as isize);
                *fresh19 = BSDoptarg;
            }
            79 => {
                if strncmp(
                    BSDoptarg,
                    b"hashalg=\0" as *const u8 as *const libc::c_char,
                    8 as libc::c_int as libc::c_ulong,
                ) != 0 as libc::c_int
                {
                    sshfatal(
                        b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        775 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Unsupported -O option\0" as *const u8 as *const libc::c_char,
                    );
                }
                hashalg = ssh_digest_alg_by_name(BSDoptarg.offset(8 as libc::c_int as isize));
                if hashalg == -(1 as libc::c_int) {
                    sshfatal(
                        b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        778 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Unsupported hash algorithm\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            116 => {
                get_keytypes = 0 as libc::c_int;
                tname = strtok(BSDoptarg, b",\0" as *const u8 as *const libc::c_char);
                while !tname.is_null() {
                    let mut type_0: libc::c_int = sshkey_type_from_name(tname);
                    match type_0 {
                        1 => {
                            get_keytypes |= 1 as libc::c_int;
                        }
                        2 => {
                            get_keytypes |= (1 as libc::c_int) << 2 as libc::c_int;
                        }
                        0 => {
                            get_keytypes |= (1 as libc::c_int) << 1 as libc::c_int;
                        }
                        3 => {
                            get_keytypes |= (1 as libc::c_int) << 3 as libc::c_int;
                        }
                        8 => {
                            get_keytypes |= (1 as libc::c_int) << 4 as libc::c_int;
                        }
                        12 => {
                            get_keytypes |= (1 as libc::c_int) << 6 as libc::c_int;
                        }
                        10 => {
                            get_keytypes |= (1 as libc::c_int) << 5 as libc::c_int;
                        }
                        14 | _ => {
                            sshfatal(
                                b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(
                                    b"main\0",
                                ))
                                .as_ptr(),
                                810 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                0 as *const libc::c_char,
                                b"Unknown key type \"%s\"\0" as *const u8 as *const libc::c_char,
                                tname,
                            );
                        }
                    }
                    tname = strtok(
                        0 as *mut libc::c_char,
                        b",\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            52 => {
                IPv4or6 = 2 as libc::c_int;
            }
            54 => {
                IPv4or6 = 10 as libc::c_int;
            }
            _ => {
                usage();
            }
        }
    }
    if BSDoptind == argc && fopt_count == 0 {
        usage();
    }
    log_init(
        b"ssh-keyscan\0" as *const u8 as *const libc::c_char,
        log_level as LogLevel,
        SYSLOG_FACILITY_USER,
        1 as libc::c_int,
    );
    maxfd = fdlim_get(1 as libc::c_int);
    if maxfd < 0 as libc::c_int {
        sshfatal(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            832 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: fdlim_get: bad value\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if maxfd > 256 as libc::c_int {
        maxfd = 256 as libc::c_int;
    }
    if maxfd - 10 as libc::c_int <= 0 as libc::c_int {
        sshfatal(
            b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            836 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: not enough file descriptors\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if maxfd > fdlim_get(0 as libc::c_int) {
        fdlim_set(maxfd);
    }
    fdcon = crate::xmalloc::xcalloc(
        maxfd as size_t,
        ::core::mem::size_of::<con>() as libc::c_ulong,
    ) as *mut con;
    read_wait = crate::xmalloc::xcalloc(
        maxfd as size_t,
        ::core::mem::size_of::<pollfd>() as libc::c_ulong,
    ) as *mut pollfd;
    j = 0 as libc::c_int;
    while j < maxfd {
        (*read_wait.offset(j as isize)).fd = -(1 as libc::c_int);
        j += 1;
        j;
    }
    j = 0 as libc::c_int;
    while j < fopt_count {
        if (*argv.offset(j as isize)).is_null() {
            fp = stdin;
        } else {
            fp = fopen(
                *argv.offset(j as isize),
                b"r\0" as *const u8 as *const libc::c_char,
            );
            if fp.is_null() {
                sshfatal(
                    b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    848 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"%s: %s: %s\0" as *const u8 as *const libc::c_char,
                    __progname,
                    *argv.offset(j as isize),
                    libc::strerror(*libc::__errno_location()),
                );
            }
        }
        while getline(&mut line, &mut linesize, fp) != -(1 as libc::c_int) as libc::c_long {
            cp = libc::strchr(line, '#' as i32);
            if cp.is_null() {
                cp = line
                    .offset(strlen(line) as isize)
                    .offset(-(1 as libc::c_int as isize));
            }
            while cp >= line {
                if !(*cp as libc::c_int == ' ' as i32
                    || *cp as libc::c_int == '\t' as i32
                    || *cp as libc::c_int == '\n' as i32
                    || *cp as libc::c_int == '#' as i32)
                {
                    break;
                }
                let fresh20 = cp;
                cp = cp.offset(-1);
                *fresh20 = '\0' as i32 as libc::c_char;
            }
            if *line as libc::c_int == '\0' as i32 {
                continue;
            }
            do_host(line);
        }
        if ferror(fp) != 0 {
            sshfatal(
                b"ssh-keyscan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                870 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s: %s: %s\0" as *const u8 as *const libc::c_char,
                __progname,
                *argv.offset(j as isize),
                libc::strerror(*libc::__errno_location()),
            );
        }
        fclose(fp);
        j += 1;
        j;
    }
    libc::free(line as *mut libc::c_void);
    while BSDoptind < argc {
        let fresh21 = BSDoptind;
        BSDoptind = BSDoptind + 1;
        do_host(*argv.offset(fresh21 as isize));
    }
    while ncon > 0 as libc::c_int {
        conloop();
    }
    return if found_one != 0 {
        0 as libc::c_int
    } else {
        1 as libc::c_int
    };
}
pub fn main() {
    let mut args: Vec<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::core::ptr::null_mut());
    unsafe {
        ::std::process::exit(main_0(
            (args.len() - 1) as libc::c_int,
            args.as_mut_ptr() as *mut *mut libc::c_char,
        ) as i32)
    }
}
