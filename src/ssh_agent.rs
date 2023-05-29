use crate::log::log_init;
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

    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    pub type notifier_ctx;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn usleep(__useconds: __useconds_t) -> libc::c_int;
    fn chdir(__path: *const libc::c_char) -> libc::c_int;

    fn getppid() -> __pid_t;
    fn setsid() -> __pid_t;

    fn getgid() -> __gid_t;
    fn setgid(__gid: __gid_t) -> libc::c_int;
    fn accept(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __addr_len: *mut socklen_t)
        -> libc::c_int;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn platform_disable_tracing(_: libc::c_int);
    fn platform_pledge_agent();

    fn setegid(__gid: __gid_t) -> libc::c_int;

    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    fn rmdir(__path: *const libc::c_char) -> libc::c_int;
    static mut BSDoptarg: *mut libc::c_char;
    static mut BSDoptind: libc::c_int;

    static mut stdout: *mut libc::FILE;
    static mut stderr: *mut libc::FILE;

    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;

    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;

    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: libc::c_int) -> libc::c_int;
    fn getpeereid(_: libc::c_int, _: *mut uid_t, _: *mut gid_t) -> libc::c_int;
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);

    fn timingsafe_bcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;
    fn bcrypt_pbkdf(
        _: *const libc::c_char,
        _: size_t,
        _: *const uint8_t,
        _: size_t,
        _: *mut uint8_t,
        _: size_t,
        _: libc::c_uint,
    ) -> libc::c_int;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn seed_rng();
    fn getrlimit(__resource: __rlimit_resource_t, __rlimits: *mut rlimit) -> libc::c_int;
    fn setrlimit(__resource: __rlimit_resource_t, __rlimits: *const rlimit) -> libc::c_int;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;

    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn setenv(
        __name: *const libc::c_char,
        __value: *const libc::c_char,
        __replace: libc::c_int,
    ) -> libc::c_int;
    fn mkdtemp(__template: *mut libc::c_char) -> *mut libc::c_char;
    fn realpath(__name: *const libc::c_char, __resolved: *mut libc::c_char) -> *mut libc::c_char;

    fn sshbuf_fromb(buf: *mut crate::sshbuf::sshbuf) -> *mut crate::sshbuf::sshbuf;
    fn sshbuf_froms(
        buf: *mut crate::sshbuf::sshbuf,
        bufp: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_free(buf: *mut crate::sshbuf::sshbuf);
    fn sshbuf_reset(buf: *mut crate::sshbuf::sshbuf);
    fn sshbuf_len(buf: *const crate::sshbuf::sshbuf) -> size_t;
    fn sshbuf_ptr(buf: *const crate::sshbuf::sshbuf) -> *const u_char;
    fn sshbuf_check_reserve(buf: *const crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_consume(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_putb(buf: *mut crate::sshbuf::sshbuf, v: *const crate::sshbuf::sshbuf)
        -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut crate::sshbuf::sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut crate::sshbuf::sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut crate::sshbuf::sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_put_u8(buf: *mut crate::sshbuf::sshbuf, val: u_char) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_put_string(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut crate::sshbuf::sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_get_string_direct(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_cmp(
        b: *const crate::sshbuf::sshbuf,
        offset: size_t,
        s: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_equal(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_fingerprint(_: *const sshkey, _: libc::c_int, _: sshkey_fp_rep) -> *mut libc::c_char;
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_shield_private(_: *mut sshkey) -> libc::c_int;
    fn sshkey_type_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_is_cert(_: *const sshkey) -> libc::c_int;
    fn sshkey_is_sk(_: *const sshkey) -> libc::c_int;
    fn sshkey_cert_check_host(
        _: *const sshkey,
        _: *const libc::c_char,
        _: libc::c_int,
        _: *const libc::c_char,
        _: *mut *const libc::c_char,
    ) -> libc::c_int;
    fn sshkey_ssh_name(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_froms(_: *mut crate::sshbuf::sshbuf, _: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_puts_opts(
        _: *const sshkey,
        _: *mut crate::sshbuf::sshbuf,
        _: sshkey_serialize_rep,
    ) -> libc::c_int;
    fn sshkey_sign(
        _: *mut sshkey,
        _: *mut *mut u_char,
        _: *mut size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: u_int,
    ) -> libc::c_int;
    fn sshkey_verify(
        _: *const sshkey,
        _: *const u_char,
        _: size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: u_int,
        _: *mut *mut sshkey_sig_details,
    ) -> libc::c_int;
    fn sshkey_private_deserialize(
        buf: *mut crate::sshbuf::sshbuf,
        keyp: *mut *mut sshkey,
    ) -> libc::c_int;
    fn sshkey_enable_maxsign(_: *mut sshkey, _: u_int32_t) -> libc::c_int;

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

    fn convtime(_: *const libc::c_char) -> libc::c_int;

    fn monotime() -> time_t;
    fn unix_listener(_: *const libc::c_char, _: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn stdfd_devnull(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn mktemp_proto(_: *mut libc::c_char, _: size_t);
    fn read_passphrase(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn ask_permission(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn notify_start(_: libc::c_int, _: *const libc::c_char, _: ...) -> *mut notifier_ctx;
    fn notify_complete(_: *mut notifier_ctx, _: *const libc::c_char, _: ...);

    fn ssh_digest_alg_by_name(name: *const libc::c_char) -> libc::c_int;
    fn match_pattern(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn match_pattern_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn pkcs11_init(_: libc::c_int) -> libc::c_int;
    fn pkcs11_terminate();
    fn pkcs11_add_provider(
        _: *mut libc::c_char,
        _: *mut libc::c_char,
        _: *mut *mut *mut sshkey,
        _: *mut *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn pkcs11_del_provider(_: *mut libc::c_char) -> libc::c_int;
    static mut __progname: *mut libc::c_char;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __mode_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __rlim_t = libc::c_ulong;
pub type __time_t = libc::c_long;
pub type __useconds_t = libc::c_uint;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type gid_t = __gid_t;
pub type mode_t = __mode_t;
pub type uid_t = __uid_t;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
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

pub type _IO_lock_t = ();

pub type __sighandler_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
pub type nfds_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: libc::c_int,
    pub events: libc::c_short,
    pub revents: libc::c_short,
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
pub type sshkey_fp_rep = libc::c_uint;
pub const SSH_FP_RANDOMART: sshkey_fp_rep = 4;
pub const SSH_FP_BUBBLEBABBLE: sshkey_fp_rep = 3;
pub const SSH_FP_BASE64: sshkey_fp_rep = 2;
pub const SSH_FP_HEX: sshkey_fp_rep = 1;
pub const SSH_FP_DEFAULT: sshkey_fp_rep = 0;
pub type sshkey_serialize_rep = libc::c_uint;
pub const SSHKEY_SERIALIZE_INFO: sshkey_serialize_rep = 254;
pub const SSHKEY_SERIALIZE_SHIELD: sshkey_serialize_rep = 3;
pub const SSHKEY_SERIALIZE_FULL: sshkey_serialize_rep = 2;
pub const SSHKEY_SERIALIZE_STATE: sshkey_serialize_rep = 1;
pub const SSHKEY_SERIALIZE_DEFAULT: sshkey_serialize_rep = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_cert {
    pub certblob: *mut crate::sshbuf::sshbuf,
    pub type_0: u_int,
    pub serial: u_int64_t,
    pub key_id: *mut libc::c_char,
    pub nprincipals: u_int,
    pub principals: *mut *mut libc::c_char,
    pub valid_after: u_int64_t,
    pub valid_before: u_int64_t,
    pub critical: *mut crate::sshbuf::sshbuf,
    pub extensions: *mut crate::sshbuf::sshbuf,
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
    pub sk_key_handle: *mut crate::sshbuf::sshbuf,
    pub sk_reserved: *mut crate::sshbuf::sshbuf,
    pub cert: *mut sshkey_cert,
    pub shielded_private: *mut u_char,
    pub shielded_len: size_t,
    pub shield_prekey: *mut u_char,
    pub shield_prekey_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_sig_details {
    pub sk_counter: uint32_t,
    pub sk_flags: uint8_t,
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
pub type sshsig_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
pub type sock_type = libc::c_uint;
pub const AUTH_CONNECTION: sock_type = 2;
pub const AUTH_SOCKET: sock_type = 1;
pub const AUTH_UNUSED: sock_type = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostkey_sid {
    pub key: *mut sshkey,
    pub sid: *mut crate::sshbuf::sshbuf,
    pub forwarded: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct socket_entry {
    pub fd: libc::c_int,
    pub type_0: sock_type,
    pub input: *mut crate::sshbuf::sshbuf,
    pub output: *mut crate::sshbuf::sshbuf,
    pub request: *mut crate::sshbuf::sshbuf,
    pub nsession_ids: size_t,
    pub session_ids: *mut hostkey_sid,
}
pub type SocketEntry = socket_entry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct identity {
    pub next: C2RustUnnamed_0,
    pub key: *mut sshkey,
    pub comment: *mut libc::c_char,
    pub provider: *mut libc::c_char,
    pub death: time_t,
    pub confirm: u_int,
    pub sk_provider: *mut libc::c_char,
    pub dest_constraints: *mut dest_constraint,
    pub ndest_constraints: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub tqe_next: *mut identity,
    pub tqe_prev: *mut *mut identity,
}
pub type Identity = identity;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct idtable {
    pub nentries: libc::c_int,
    pub idlist: idqueue,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct idqueue {
    pub tqh_first: *mut identity,
    pub tqh_last: *mut *mut identity,
}
pub static mut sockets_alloc: u_int = 0 as libc::c_int as u_int;
pub static mut sockets: *mut SocketEntry = 0 as *const SocketEntry as *mut SocketEntry;
pub static mut idtab: *mut idtable = 0 as *const idtable as *mut idtable;
pub static mut max_fd: libc::c_int = 0 as libc::c_int;
pub static mut parent_pid: pid_t = -(1 as libc::c_int);
pub static mut parent_alive_interval: time_t = 0 as libc::c_int as time_t;
pub static mut cleanup_pid: pid_t = 0 as libc::c_int;
pub static mut socket_name: [libc::c_char; 4096] = [0; 4096];
pub static mut socket_dir: [libc::c_char; 4096] = [0; 4096];
static mut allowed_providers: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
pub static mut locked: libc::c_int = 0 as libc::c_int;
pub static mut lock_pwhash: [u_char; 32] = [0; 32];
pub static mut lock_salt: [u_char; 16] = [0; 16];
static mut lifetime: libc::c_int = 0 as libc::c_int;
static mut fingerprint_hash: libc::c_int = 2 as libc::c_int;
static mut restrict_websafe: libc::c_int = 1 as libc::c_int;
unsafe extern "C" fn close_socket(mut e: *mut SocketEntry) {
    let mut i: size_t = 0;
    close((*e).fd);
    sshbuf_free((*e).input);
    sshbuf_free((*e).output);
    sshbuf_free((*e).request);
    i = 0 as libc::c_int as size_t;
    while i < (*e).nsession_ids {
        sshkey_free((*((*e).session_ids).offset(i as isize)).key);
        sshbuf_free((*((*e).session_ids).offset(i as isize)).sid);
        i = i.wrapping_add(1);
        i;
    }
    libc::free((*e).session_ids as *mut libc::c_void);
    memset(
        e as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<SocketEntry>() as libc::c_ulong,
    );
    (*e).fd = -(1 as libc::c_int);
    (*e).type_0 = AUTH_UNUSED;
}
unsafe extern "C" fn idtab_init() {
    idtab = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<idtable>() as libc::c_ulong,
    ) as *mut idtable;
    (*idtab).idlist.tqh_first = 0 as *mut identity;
    (*idtab).idlist.tqh_last = &mut (*idtab).idlist.tqh_first;
    (*idtab).nentries = 0 as libc::c_int;
}
unsafe extern "C" fn free_dest_constraint_hop(mut dch: *mut dest_constraint_hop) {
    let mut i: u_int = 0;
    if dch.is_null() {
        return;
    }
    libc::free((*dch).user as *mut libc::c_void);
    libc::free((*dch).hostname as *mut libc::c_void);
    i = 0 as libc::c_int as u_int;
    while i < (*dch).nkeys {
        sshkey_free(*((*dch).keys).offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    libc::free((*dch).keys as *mut libc::c_void);
    libc::free((*dch).key_is_ca as *mut libc::c_void);
}
unsafe extern "C" fn free_dest_constraints(mut dcs: *mut dest_constraint, mut ndcs: size_t) {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < ndcs {
        free_dest_constraint_hop(&mut (*dcs.offset(i as isize)).from);
        free_dest_constraint_hop(&mut (*dcs.offset(i as isize)).to);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(dcs as *mut libc::c_void);
}
unsafe extern "C" fn free_identity(mut id: *mut Identity) {
    sshkey_free((*id).key);
    libc::free((*id).provider as *mut libc::c_void);
    libc::free((*id).comment as *mut libc::c_void);
    libc::free((*id).sk_provider as *mut libc::c_void);
    free_dest_constraints((*id).dest_constraints, (*id).ndest_constraints);
    libc::free(id as *mut libc::c_void);
}
unsafe extern "C" fn match_key_hop(
    mut tag: *const libc::c_char,
    mut key: *const sshkey,
    mut dch: *const dest_constraint_hop,
) -> libc::c_int {
    let mut reason: *const libc::c_char = 0 as *const libc::c_char;
    let mut hostname: *const libc::c_char = if !((*dch).hostname).is_null() {
        (*dch).hostname as *const libc::c_char
    } else {
        b"(ORIGIN)\0" as *const u8 as *const libc::c_char
    };
    let mut i: u_int = 0;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    if key.is_null() {
        return -(1 as libc::c_int);
    }
    fp = sshkey_fingerprint(key, 2 as libc::c_int, SSH_FP_DEFAULT);
    if fp.is_null() {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"match_key_hop\0"))
                .as_ptr(),
            273 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"fingerprint failed\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"match_key_hop\0")).as_ptr(),
        275 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s: entering hostname %s, requested key %s %s, %u keys avail\0" as *const u8
            as *const libc::c_char,
        tag,
        hostname,
        sshkey_type(key),
        fp,
        (*dch).nkeys,
    );
    libc::free(fp as *mut libc::c_void);
    i = 0 as libc::c_int as u_int;
    while i < (*dch).nkeys {
        if (*((*dch).keys).offset(i as isize)).is_null() {
            return -(1 as libc::c_int);
        }
        fp = sshkey_fingerprint(
            *((*dch).keys).offset(i as isize),
            2 as libc::c_int,
            SSH_FP_DEFAULT,
        );
        if fp.is_null() {
            sshfatal(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"match_key_hop\0"))
                    .as_ptr(),
                283 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"fingerprint failed\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"match_key_hop\0"))
                .as_ptr(),
            286 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"%s: key %u: %s%s %s\0" as *const u8 as *const libc::c_char,
            tag,
            i,
            if *((*dch).key_is_ca).offset(i as isize) != 0 {
                b"CA \0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            sshkey_type(*((*dch).keys).offset(i as isize)),
            fp,
        );
        libc::free(fp as *mut libc::c_void);
        if sshkey_is_cert(key) == 0 {
            if !(*((*dch).key_is_ca).offset(i as isize) != 0
                || sshkey_equal(key, *((*dch).keys).offset(i as isize)) == 0)
            {
                return 0 as libc::c_int;
            }
        } else if !(*((*dch).key_is_ca).offset(i as isize) == 0) {
            if ((*key).cert).is_null() || ((*(*key).cert).signature_key).is_null() {
                return -(1 as libc::c_int);
            }
            if !(sshkey_equal(
                (*(*key).cert).signature_key,
                *((*dch).keys).offset(i as isize),
            ) == 0)
            {
                if sshkey_cert_check_host(
                    key,
                    hostname,
                    1 as libc::c_int,
                    b"ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\0"
                        as *const u8 as *const libc::c_char,
                    &mut reason,
                ) != 0 as libc::c_int
                {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<
                            &[u8; 14],
                            &[libc::c_char; 14],
                        >(b"match_key_hop\0"))
                            .as_ptr(),
                        305 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"cert %s / hostname %s rejected: %s\0" as *const u8
                            as *const libc::c_char,
                        (*(*key).cert).key_id,
                        hostname,
                        reason,
                    );
                } else {
                    return 0 as libc::c_int
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn permitted_by_dest_constraints(
    mut fromkey: *const sshkey,
    mut tokey: *const sshkey,
    mut id: *mut Identity,
    mut user: *const libc::c_char,
    mut hostnamep: *mut *const libc::c_char,
) -> libc::c_int {
    let mut i: size_t = 0;
    let mut d: *mut dest_constraint = 0 as *mut dest_constraint;
    if !hostnamep.is_null() {
        *hostnamep = 0 as *const libc::c_char;
    }
    let mut current_block_8: u64;
    i = 0 as libc::c_int as size_t;
    while i < (*id).ndest_constraints {
        d = ((*id).dest_constraints).offset(i as isize);
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"permitted_by_dest_constraints\0",
            ))
            .as_ptr(),
            333 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"constraint %zu %s%s%s (%u keys) > %s%s%s (%u keys)\0" as *const u8
                as *const libc::c_char,
            i,
            if !((*d).from.user).is_null() {
                (*d).from.user as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if !((*d).from.user).is_null() {
                b"@\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if !((*d).from.hostname).is_null() {
                (*d).from.hostname as *const libc::c_char
            } else {
                b"(ORIGIN)\0" as *const u8 as *const libc::c_char
            },
            (*d).from.nkeys,
            if !((*d).to.user).is_null() {
                (*d).to.user as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if !((*d).to.user).is_null() {
                b"@\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if !((*d).to.hostname).is_null() {
                (*d).to.hostname as *const libc::c_char
            } else {
                b"(ANY)\0" as *const u8 as *const libc::c_char
            },
            (*d).to.nkeys,
        );
        if fromkey.is_null() {
            if !((*d).from.hostname).is_null()
                || (*d).from.nkeys != 0 as libc::c_int as libc::c_uint
            {
                current_block_8 = 12517898123489920830;
            } else {
                current_block_8 = 13513818773234778473;
            }
        } else if match_key_hop(
            b"from\0" as *const u8 as *const libc::c_char,
            fromkey,
            &mut (*d).from,
        ) != 0 as libc::c_int
        {
            current_block_8 = 12517898123489920830;
        } else {
            current_block_8 = 13513818773234778473;
        }
        match current_block_8 {
            13513818773234778473 => {
                if !(!tokey.is_null()
                    && match_key_hop(
                        b"to\0" as *const u8 as *const libc::c_char,
                        tokey,
                        &mut (*d).to,
                    ) != 0 as libc::c_int)
                {
                    if !(!((*d).to.user).is_null()
                        && !user.is_null()
                        && match_pattern(user, (*d).to.user) == 0)
                    {
                        if !hostnamep.is_null() {
                            *hostnamep = (*d).to.hostname;
                        }
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                                b"permitted_by_dest_constraints\0",
                            ))
                            .as_ptr(),
                            356 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"allowed for hostname %s\0" as *const u8 as *const libc::c_char,
                            if ((*d).to.hostname).is_null() {
                                b"*\0" as *const u8 as *const libc::c_char
                            } else {
                                (*d).to.hostname as *const libc::c_char
                            },
                        );
                        return 0 as libc::c_int;
                    }
                }
            }
            _ => {}
        }
        i = i.wrapping_add(1);
        i;
    }
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
            b"permitted_by_dest_constraints\0",
        ))
        .as_ptr(),
        361 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"%s identity \"%s\" not permitted for this destination\0" as *const u8
            as *const libc::c_char,
        sshkey_type((*id).key),
        (*id).comment,
    );
    return -(1 as libc::c_int);
}
unsafe extern "C" fn identity_permitted(
    mut id: *mut Identity,
    mut e: *mut SocketEntry,
    mut user: *mut libc::c_char,
    mut forward_hostnamep: *mut *const libc::c_char,
    mut last_hostnamep: *mut *const libc::c_char,
) -> libc::c_int {
    let mut i: size_t = 0;
    let mut hp: *mut *const libc::c_char = 0 as *mut *const libc::c_char;
    let mut hks: *mut hostkey_sid = 0 as *mut hostkey_sid;
    let mut fromkey: *const sshkey = 0 as *const sshkey;
    let mut test_user: *const libc::c_char = 0 as *const libc::c_char;
    let mut fp1: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fp2: *mut libc::c_char = 0 as *mut libc::c_char;
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"identity_permitted\0"))
            .as_ptr(),
        384 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering: key %s comment \"%s\", %zu socket bindings, %zu constraints\0" as *const u8
            as *const libc::c_char,
        sshkey_type((*id).key),
        (*id).comment,
        (*e).nsession_ids,
        (*id).ndest_constraints,
    );
    if (*id).ndest_constraints == 0 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    if (*e).nsession_ids == 0 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as size_t;
    while i < (*e).nsession_ids {
        hks = ((*e).session_ids).offset(i as isize);
        if ((*hks).key).is_null() {
            sshfatal(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"identity_permitted\0",
                ))
                .as_ptr(),
                396 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"internal error: no bound key\0" as *const u8 as *const libc::c_char,
            );
        }
        fp2 = 0 as *mut libc::c_char;
        fp1 = fp2;
        if !fromkey.is_null() && {
            fp1 = sshkey_fingerprint(fromkey, 2 as libc::c_int, SSH_FP_DEFAULT);
            fp1.is_null()
        } {
            sshfatal(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"identity_permitted\0",
                ))
                .as_ptr(),
                402 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"fingerprint failed\0" as *const u8 as *const libc::c_char,
            );
        }
        fp2 = sshkey_fingerprint((*hks).key, 2 as libc::c_int, SSH_FP_DEFAULT);
        if fp2.is_null() {
            sshfatal(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"identity_permitted\0",
                ))
                .as_ptr(),
                405 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"fingerprint failed\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"identity_permitted\0"))
                .as_ptr(),
            411 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"socketentry fd=%d, entry %zu %s, from hostkey %s %s to user %s hostkey %s %s\0"
                as *const u8 as *const libc::c_char,
            (*e).fd,
            i,
            if (*hks).forwarded != 0 {
                b"FORWARD\0" as *const u8 as *const libc::c_char
            } else {
                b"AUTH\0" as *const u8 as *const libc::c_char
            },
            if !fromkey.is_null() {
                sshkey_type(fromkey)
            } else {
                b"(ORIGIN)\0" as *const u8 as *const libc::c_char
            },
            if !fromkey.is_null() {
                fp1 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if !user.is_null() {
                user as *const libc::c_char
            } else {
                b"(ANY)\0" as *const u8 as *const libc::c_char
            },
            sshkey_type((*hks).key),
            fp2,
        );
        libc::free(fp1 as *mut libc::c_void);
        libc::free(fp2 as *mut libc::c_void);
        hp = 0 as *mut *const libc::c_char;
        if i == ((*e).nsession_ids).wrapping_sub(1 as libc::c_int as libc::c_ulong) {
            hp = last_hostnamep;
        } else if i == 0 as libc::c_int as libc::c_ulong {
            hp = forward_hostnamep;
        }
        test_user = 0 as *const libc::c_char;
        if i == ((*e).nsession_ids).wrapping_sub(1 as libc::c_int as libc::c_ulong) {
            test_user = user;
            if (*hks).forwarded != 0 && !user.is_null() {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"identity_permitted\0",
                    ))
                    .as_ptr(),
                    434 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"tried to sign on forwarding hop\0" as *const u8 as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
        } else if (*hks).forwarded == 0 {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"identity_permitted\0",
                ))
                .as_ptr(),
                438 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"tried to forward though signing bind\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        if permitted_by_dest_constraints(fromkey, (*hks).key, id, test_user, hp) != 0 as libc::c_int
        {
            return -(1 as libc::c_int);
        }
        fromkey = (*hks).key;
        i = i.wrapping_add(1);
        i;
    }
    hks = &mut *((*e).session_ids)
        .offset(((*e).nsession_ids).wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
        as *mut hostkey_sid;
    if (*hks).forwarded != 0
        && user.is_null()
        && permitted_by_dest_constraints(
            (*hks).key,
            0 as *const sshkey,
            id,
            0 as *const libc::c_char,
            0 as *mut *const libc::c_char,
        ) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"identity_permitted\0"))
                .as_ptr(),
            458 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"key permitted at host but not after\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn lookup_identity(mut key: *mut sshkey) -> *mut Identity {
    let mut id: *mut Identity = 0 as *mut Identity;
    id = (*idtab).idlist.tqh_first;
    while !id.is_null() {
        if sshkey_equal(key, (*id).key) != 0 {
            return id;
        }
        id = (*id).next.tqe_next;
    }
    return 0 as *mut Identity;
}
unsafe extern "C" fn confirm_key(
    mut id: *mut Identity,
    mut extra: *const libc::c_char,
) -> libc::c_int {
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    p = sshkey_fingerprint((*id).key, fingerprint_hash, SSH_FP_DEFAULT);
    if !p.is_null()
        && ask_permission(
            b"Allow use of key %s?\nKey fingerprint %s.%s%s\0" as *const u8 as *const libc::c_char,
            (*id).comment,
            p,
            if extra.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b"\n\0" as *const u8 as *const libc::c_char
            },
            if extra.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                extra
            },
        ) != 0
    {
        ret = 0 as libc::c_int;
    }
    libc::free(p as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn send_status(mut e: *mut SocketEntry, mut success: libc::c_int) {
    let mut r: libc::c_int = 0;
    r = sshbuf_put_u32((*e).output, 1 as libc::c_int as u_int32_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_u8(
            (*e).output,
            (if success != 0 {
                6 as libc::c_int
            } else {
                5 as libc::c_int
            }) as u_char,
        );
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"send_status\0")).as_ptr(),
            505 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn process_request_identities(mut e: *mut SocketEntry) {
    let mut id: *mut Identity = 0 as *mut Identity;
    let mut msg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut keys: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    let mut nentries: u_int = 0 as libc::c_int as u_int;
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"process_request_identities\0",
        ))
        .as_ptr(),
        517 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    msg = crate::sshbuf::sshbuf_new();
    if msg.is_null() || {
        keys = crate::sshbuf::sshbuf_new();
        keys.is_null()
    } {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"process_request_identities\0",
            ))
            .as_ptr(),
            520 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    id = (*idtab).idlist.tqh_first;
    while !id.is_null() {
        if !(identity_permitted(
            id,
            e,
            0 as *mut libc::c_char,
            0 as *mut *const libc::c_char,
            0 as *mut *const libc::c_char,
        ) != 0 as libc::c_int)
        {
            r = sshkey_puts_opts((*id).key, keys, SSHKEY_SERIALIZE_INFO);
            if r != 0 as libc::c_int || {
                r = sshbuf_put_cstring(keys, (*id).comment);
                r != 0 as libc::c_int
            } {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"process_request_identities\0",
                    ))
                    .as_ptr(),
                    528 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"compose key/comment\0" as *const u8 as *const libc::c_char,
                );
            } else {
                nentries = nentries.wrapping_add(1);
                nentries;
            }
        }
        id = (*id).next.tqe_next;
    }
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"process_request_identities\0",
        ))
        .as_ptr(),
        534 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"replying with %u allowed of %u available keys\0" as *const u8 as *const libc::c_char,
        nentries,
        (*idtab).nentries,
    );
    r = sshbuf_put_u8(msg, 12 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, nentries);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_putb(msg, keys);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"process_request_identities\0",
            ))
            .as_ptr(),
            538 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_stringb((*e).output, msg);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"process_request_identities\0",
            ))
            .as_ptr(),
            540 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"enqueue\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(msg);
    sshbuf_free(keys);
}
unsafe extern "C" fn agent_decode_alg(mut key: *mut sshkey, mut flags: u_int) -> *mut libc::c_char {
    if (*key).type_0 == KEY_RSA as libc::c_int {
        if flags & 0x2 as libc::c_int as libc::c_uint != 0 {
            return b"rsa-sha2-256\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        } else if flags & 0x4 as libc::c_int as libc::c_uint != 0 {
            return b"rsa-sha2-512\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
    } else if (*key).type_0 == KEY_RSA_CERT as libc::c_int {
        if flags & 0x2 as libc::c_int as libc::c_uint != 0 {
            return b"rsa-sha2-256-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        } else if flags & 0x4 as libc::c_int as libc::c_uint != 0 {
            return b"rsa-sha2-512-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        }
    }
    return 0 as *mut libc::c_char;
}
unsafe extern "C" fn parse_userauth_request(
    mut msg: *mut crate::sshbuf::sshbuf,
    mut expected_key: *const sshkey,
    mut userp: *mut *mut libc::c_char,
    mut sess_idp: *mut *mut crate::sshbuf::sshbuf,
    mut hostkeyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut current_block: u64;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sess_id: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut service: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut method: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pkalg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut t: u_char = 0;
    let mut sig_follows: u_char = 0;
    let mut mkey: *mut sshkey = 0 as *mut sshkey;
    let mut hostkey: *mut sshkey = 0 as *mut sshkey;
    if !userp.is_null() {
        *userp = 0 as *mut libc::c_char;
    }
    if !sess_idp.is_null() {
        *sess_idp = 0 as *mut crate::sshbuf::sshbuf;
    }
    if !hostkeyp.is_null() {
        *hostkeyp = 0 as *mut sshkey;
    }
    b = sshbuf_fromb(msg);
    if b.is_null() {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"parse_userauth_request\0",
            ))
            .as_ptr(),
            587 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_fromb\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_froms(b, &mut sess_id);
    if !(r != 0 as libc::c_int) {
        if sshbuf_len(sess_id) == 0 as libc::c_int as libc::c_ulong {
            r = -(4 as libc::c_int);
        } else {
            r = sshbuf_get_u8(b, &mut t);
            if !(r != 0 as libc::c_int
                || {
                    r = sshbuf_get_cstring(b, &mut user, 0 as *mut size_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_get_cstring(b, &mut service, 0 as *mut size_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_get_cstring(b, &mut method, 0 as *mut size_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_get_u8(b, &mut sig_follows);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_get_cstring(b, &mut pkalg, 0 as *mut size_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshkey_froms(b, &mut mkey);
                    r != 0 as libc::c_int
                })
            {
                if t as libc::c_int != 50 as libc::c_int
                    || sig_follows as libc::c_int != 1 as libc::c_int
                    || libc::strcmp(
                        service,
                        b"ssh-connection\0" as *const u8 as *const libc::c_char,
                    ) != 0 as libc::c_int
                    || sshkey_equal(expected_key, mkey) == 0
                    || sshkey_type_from_name(pkalg) != (*expected_key).type_0
                {
                    r = -(4 as libc::c_int);
                } else {
                    if libc::strcmp(
                        method,
                        b"publickey-hostbound-v00@openssh.com\0" as *const u8
                            as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        r = sshkey_froms(b, &mut hostkey);
                        if r != 0 as libc::c_int {
                            current_block = 1189788983119488299;
                        } else {
                            current_block = 15904375183555213903;
                        }
                    } else if libc::strcmp(
                        method,
                        b"publickey\0" as *const u8 as *const libc::c_char,
                    ) != 0 as libc::c_int
                    {
                        r = -(4 as libc::c_int);
                        current_block = 1189788983119488299;
                    } else {
                        current_block = 15904375183555213903;
                    }
                    match current_block {
                        1189788983119488299 => {}
                        _ => {
                            if sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong {
                                r = -(4 as libc::c_int);
                            } else {
                                r = 0 as libc::c_int;
                                crate::log::sshlog(
                                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                        b"parse_userauth_request\0",
                                    ))
                                    .as_ptr(),
                                    625 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG3,
                                    0 as *const libc::c_char,
                                    b"well formed userauth\0" as *const u8 as *const libc::c_char,
                                );
                                if !userp.is_null() {
                                    *userp = user;
                                    user = 0 as *mut libc::c_char;
                                }
                                if !sess_idp.is_null() {
                                    *sess_idp = sess_id;
                                    sess_id = 0 as *mut crate::sshbuf::sshbuf;
                                }
                                if !hostkeyp.is_null() {
                                    *hostkeyp = hostkey;
                                    hostkey = 0 as *mut sshkey;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    sshbuf_free(b);
    sshbuf_free(sess_id);
    libc::free(user as *mut libc::c_void);
    libc::free(service as *mut libc::c_void);
    libc::free(method as *mut libc::c_void);
    libc::free(pkalg as *mut libc::c_void);
    sshkey_free(mkey);
    sshkey_free(hostkey);
    return r;
}
unsafe extern "C" fn parse_sshsig_request(mut msg: *mut crate::sshbuf::sshbuf) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    b = sshbuf_fromb(msg);
    if b.is_null() {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"parse_sshsig_request\0"))
                .as_ptr(),
            661 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_fromb\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_cmp(
        b,
        0 as libc::c_int as size_t,
        b"SSHSIG\0" as *const u8 as *const libc::c_char as *const libc::c_void,
        6 as libc::c_int as size_t,
    );
    if !(r != 0 as libc::c_int
        || {
            r = sshbuf_consume(b, 6 as libc::c_int as size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(b, 0 as *mut *mut libc::c_char, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_string_direct(b, 0 as *mut *const u_char, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(b, 0 as *mut *mut libc::c_char, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_string_direct(b, 0 as *mut *const u_char, 0 as *mut size_t);
            r != 0 as libc::c_int
        })
    {
        if sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong {
            r = -(4 as libc::c_int);
        } else {
            r = 0 as libc::c_int;
        }
    }
    sshbuf_free(b);
    return r;
}
unsafe extern "C" fn check_websafe_message_contents(
    mut key: *mut sshkey,
    mut data: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    if parse_userauth_request(
        data,
        key,
        0 as *mut *mut libc::c_char,
        0 as *mut *mut crate::sshbuf::sshbuf,
        0 as *mut *mut sshkey,
    ) == 0 as libc::c_int
    {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                b"check_websafe_message_contents\0",
            ))
            .as_ptr(),
            692 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"signed data matches public key userauth request\0" as *const u8
                as *const libc::c_char,
        );
        return 1 as libc::c_int;
    }
    if parse_sshsig_request(data) == 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                b"check_websafe_message_contents\0",
            ))
            .as_ptr(),
            696 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"signed data matches SSHSIG signature request\0" as *const u8 as *const libc::c_char,
        );
        return 1 as libc::c_int;
    }
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
            b"check_websafe_message_contents\0",
        ))
        .as_ptr(),
        702 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"web-origin key attempting to sign non-SSH message\0" as *const u8 as *const libc::c_char,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn buf_equal(
    mut a: *const crate::sshbuf::sshbuf,
    mut b: *const crate::sshbuf::sshbuf,
) -> libc::c_int {
    if (sshbuf_ptr(a)).is_null() || (sshbuf_ptr(b)).is_null() {
        return -(10 as libc::c_int);
    }
    if sshbuf_len(a) != sshbuf_len(b) {
        return -(4 as libc::c_int);
    }
    if timingsafe_bcmp(
        sshbuf_ptr(a) as *const libc::c_void,
        sshbuf_ptr(b) as *const libc::c_void,
        sshbuf_len(a),
    ) != 0 as libc::c_int
    {
        return -(4 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn process_sign_request2(mut e: *mut SocketEntry) {
    let mut current_block: u64;
    let mut signature: *mut u_char = 0 as *mut u_char;
    let mut slen: size_t = 0 as libc::c_int as size_t;
    let mut compat: u_int = 0 as libc::c_int as u_int;
    let mut flags: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut ok: libc::c_int = -(1 as libc::c_int);
    let mut retried: libc::c_int = 0 as libc::c_int;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut prompt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sig_dest: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fwd_host: *const libc::c_char = 0 as *const libc::c_char;
    let mut dest_host: *const libc::c_char = 0 as *const libc::c_char;
    let mut msg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut data: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sid: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut hostkey: *mut sshkey = 0 as *mut sshkey;
    let mut id: *mut identity = 0 as *mut identity;
    let mut notifier: *mut notifier_ctx = 0 as *mut notifier_ctx;
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"process_sign_request2\0"))
            .as_ptr(),
        734 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    msg = crate::sshbuf::sshbuf_new();
    if msg.is_null() || {
        data = crate::sshbuf::sshbuf_new();
        data.is_null()
    } {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"process_sign_request2\0"))
                .as_ptr(),
            737 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshkey_froms((*e).request, &mut key);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_stringb((*e).request, data);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32((*e).request, &mut flags);
            r != 0 as libc::c_int
        }
    {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"process_sign_request2\0"))
                .as_ptr(),
            741 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    } else {
        id = lookup_identity(key);
        if id.is_null() {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"process_sign_request2\0",
                ))
                .as_ptr(),
                746 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_VERBOSE,
                0 as *const libc::c_char,
                b"%s key not found\0" as *const u8 as *const libc::c_char,
                sshkey_type(key),
            );
        } else {
            fp = sshkey_fingerprint(key, 2 as libc::c_int, SSH_FP_DEFAULT);
            if fp.is_null() {
                sshfatal(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"process_sign_request2\0",
                    ))
                    .as_ptr(),
                    751 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"fingerprint failed\0" as *const u8 as *const libc::c_char,
                );
            }
            if (*id).ndest_constraints != 0 as libc::c_int as libc::c_ulong {
                if (*e).nsession_ids == 0 as libc::c_int as libc::c_ulong {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<
                            &[u8; 22],
                            &[libc::c_char; 22],
                        >(b"process_sign_request2\0"))
                            .as_ptr(),
                        756 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        0 as *const libc::c_char,
                        b"refusing use of destination-constrained key to sign on unbound connection\0"
                            as *const u8 as *const libc::c_char,
                    );
                    current_block = 13457127675253637570;
                } else if parse_userauth_request(data, key, &mut user, &mut sid, &mut hostkey)
                    != 0 as libc::c_int
                {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<
                            &[u8; 22],
                            &[libc::c_char; 22],
                        >(b"process_sign_request2\0"))
                            .as_ptr(),
                        762 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        0 as *const libc::c_char,
                        b"refusing use of destination-constrained key to sign an unidentified signature\0"
                            as *const u8 as *const libc::c_char,
                    );
                    current_block = 13457127675253637570;
                } else {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                            b"process_sign_request2\0",
                        ))
                        .as_ptr(),
                        766 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"user=%s\0" as *const u8 as *const libc::c_char,
                        user,
                    );
                    if identity_permitted(id, e, user, &mut fwd_host, &mut dest_host)
                        != 0 as libc::c_int
                    {
                        current_block = 13457127675253637570;
                    } else if buf_equal(
                        sid,
                        (*((*e).session_ids).offset(
                            ((*e).nsession_ids).wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                as isize,
                        ))
                        .sid,
                    ) != 0 as libc::c_int
                    {
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<
                                &[u8; 22],
                                &[libc::c_char; 22],
                            >(b"process_sign_request2\0"))
                                .as_ptr(),
                            780 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"unexpected session ID (%zu listed) on signature request for target user %s with key %s %s\0"
                                as *const u8 as *const libc::c_char,
                            (*e).nsession_ids,
                            user,
                            sshkey_type((*id).key),
                            fp,
                        );
                        current_block = 13457127675253637570;
                    } else if (*e).nsession_ids > 1 as libc::c_int as libc::c_ulong
                        && hostkey.is_null()
                    {
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<
                                &[u8; 22],
                                &[libc::c_char; 22],
                            >(b"process_sign_request2\0"))
                                .as_ptr(),
                            791 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"refusing use of destination-constrained key: no hostkey recorded in signature for forwarded connection\0"
                                as *const u8 as *const libc::c_char,
                        );
                        current_block = 13457127675253637570;
                    } else if !hostkey.is_null()
                        && sshkey_equal(
                            hostkey,
                            (*((*e).session_ids).offset(
                                ((*e).nsession_ids).wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                    as isize,
                            ))
                            .key,
                        ) == 0
                    {
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<
                                &[u8; 22],
                                &[libc::c_char; 22],
                            >(b"process_sign_request2\0"))
                                .as_ptr(),
                            798 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"refusing use of destination-constrained key: mismatch between hostkey in request and most recently bound session\0"
                                as *const u8 as *const libc::c_char,
                        );
                        current_block = 13457127675253637570;
                    } else {
                        crate::xmalloc::xasprintf(
                            &mut sig_dest as *mut *mut libc::c_char,
                            b"public key authentication request for user \"%s\" to listed host\0"
                                as *const u8 as *const libc::c_char,
                            user,
                        );
                        current_block = 9828876828309294594;
                    }
                }
            } else {
                current_block = 9828876828309294594;
            }
            match current_block {
                13457127675253637570 => {}
                _ => {
                    if (*id).confirm != 0 && confirm_key(id, sig_dest) != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                b"process_sign_request2\0",
                            ))
                            .as_ptr(),
                            805 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_VERBOSE,
                            0 as *const libc::c_char,
                            b"user refused key\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        if sshkey_is_sk((*id).key) != 0 {
                            if restrict_websafe != 0
                                && strncmp(
                                    (*(*id).key).sk_application,
                                    b"ssh:\0" as *const u8 as *const libc::c_char,
                                    4 as libc::c_int as libc::c_ulong,
                                ) != 0 as libc::c_int
                                && check_websafe_message_contents(key, data) == 0
                            {
                                current_block = 13457127675253637570;
                            } else {
                                if (*(*id).key).sk_flags as libc::c_int & 0x1 as libc::c_int != 0 {
                                    notifier = notify_start(
                                        0 as libc::c_int,
                                        b"Confirm user presence for key %s %s%s%s\0" as *const u8
                                            as *const libc::c_char,
                                        sshkey_type((*id).key),
                                        fp,
                                        if sig_dest.is_null() {
                                            b"\0" as *const u8 as *const libc::c_char
                                        } else {
                                            b"\n\0" as *const u8 as *const libc::c_char
                                        },
                                        if sig_dest.is_null() {
                                            b"\0" as *const u8 as *const libc::c_char
                                        } else {
                                            sig_dest as *const libc::c_char
                                        },
                                    );
                                }
                                current_block = 2312987467839449876;
                            }
                        } else {
                            current_block = 2312987467839449876;
                        }
                        match current_block {
                            13457127675253637570 => {}
                            _ => loop {
                                r = sshkey_sign(
                                    (*id).key,
                                    &mut signature,
                                    &mut slen,
                                    sshbuf_ptr(data),
                                    sshbuf_len(data),
                                    agent_decode_alg(key, flags),
                                    (*id).sk_provider,
                                    pin,
                                    compat,
                                );
                                if r != 0 as libc::c_int {
                                    crate::log::sshlog(
                                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                            b"process_sign_request2\0",
                                        ))
                                        .as_ptr(),
                                        827 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG1,
                                        ssh_err(r),
                                        b"sshkey_sign\0" as *const u8 as *const libc::c_char,
                                    );
                                    if pin.is_null()
                                        && retried == 0
                                        && sshkey_is_sk((*id).key) != 0
                                        && r == -(43 as libc::c_int)
                                    {
                                        notify_complete(notifier, 0 as *const libc::c_char);
                                        notifier = 0 as *mut notifier_ctx;
                                        crate::xmalloc::xasprintf(
                                            &mut prompt as *mut *mut libc::c_char,
                                            b"Enter PIN%sfor %s key %s: \0" as *const u8
                                                as *const libc::c_char,
                                            if (*(*id).key).sk_flags as libc::c_int
                                                & 0x1 as libc::c_int
                                                != 0
                                            {
                                                b" and confirm user presence \0" as *const u8
                                                    as *const libc::c_char
                                            } else {
                                                b" \0" as *const u8 as *const libc::c_char
                                            },
                                            sshkey_type((*id).key),
                                            fp,
                                        );
                                        pin = read_passphrase(prompt, 0x8 as libc::c_int);
                                        retried = 1 as libc::c_int;
                                    } else {
                                        crate::log::sshlog(
                                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 22],
                                                &[libc::c_char; 22],
                                            >(
                                                b"process_sign_request2\0"
                                            ))
                                            .as_ptr(),
                                            841 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            ssh_err(r),
                                            b"sshkey_sign\0" as *const u8 as *const libc::c_char,
                                        );
                                        break;
                                    }
                                } else {
                                    ok = 0 as libc::c_int;
                                    break;
                                }
                            },
                        }
                    }
                }
            }
        }
    }
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"process_sign_request2\0"))
            .as_ptr(),
        847 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"good signature\0" as *const u8 as *const libc::c_char,
    );
    notify_complete(
        notifier,
        b"User presence confirmed\0" as *const u8 as *const libc::c_char,
    );
    if ok == 0 as libc::c_int {
        r = sshbuf_put_u8(msg, 14 as libc::c_int as u_char);
        if r != 0 as libc::c_int || {
            r = sshbuf_put_string(msg, signature as *const libc::c_void, slen);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"process_sign_request2\0",
                ))
                .as_ptr(),
                853 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        r = sshbuf_put_u8(msg, 5 as libc::c_int as u_char);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"process_sign_request2\0",
                ))
                .as_ptr(),
                855 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose failure\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    r = sshbuf_put_stringb((*e).output, msg);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"process_sign_request2\0"))
                .as_ptr(),
            858 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"enqueue\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(sid);
    sshbuf_free(data);
    sshbuf_free(msg);
    sshkey_free(key);
    sshkey_free(hostkey);
    libc::free(fp as *mut libc::c_void);
    libc::free(signature as *mut libc::c_void);
    libc::free(sig_dest as *mut libc::c_void);
    libc::free(user as *mut libc::c_void);
    libc::free(prompt as *mut libc::c_void);
    if !pin.is_null() {
        freezero(pin as *mut libc::c_void, strlen(pin));
    }
}
unsafe extern "C" fn process_remove_identity(mut e: *mut SocketEntry) {
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut id: *mut Identity = 0 as *mut Identity;
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"process_remove_identity\0"))
            .as_ptr(),
        882 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    r = sshkey_froms((*e).request, &mut key);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"process_remove_identity\0",
            ))
            .as_ptr(),
            884 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse key\0" as *const u8 as *const libc::c_char,
        );
    } else {
        id = lookup_identity(key);
        if id.is_null() {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"process_remove_identity\0",
                ))
                .as_ptr(),
                888 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"key not found\0" as *const u8 as *const libc::c_char,
            );
        } else if !(identity_permitted(
            id,
            e,
            0 as *mut libc::c_char,
            0 as *mut *const libc::c_char,
            0 as *mut *const libc::c_char,
        ) != 0 as libc::c_int)
        {
            if (*idtab).nentries < 1 as libc::c_int {
                sshfatal(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"process_remove_identity\0",
                    ))
                    .as_ptr(),
                    896 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"internal error: nentries %d\0" as *const u8 as *const libc::c_char,
                    (*idtab).nentries,
                );
            }
            if !((*id).next.tqe_next).is_null() {
                (*(*id).next.tqe_next).next.tqe_prev = (*id).next.tqe_prev;
            } else {
                (*idtab).idlist.tqh_last = (*id).next.tqe_prev;
            }
            *(*id).next.tqe_prev = (*id).next.tqe_next;
            free_identity(id);
            (*idtab).nentries -= 1;
            (*idtab).nentries;
            success = 1 as libc::c_int;
        }
    }
    sshkey_free(key);
    send_status(e, success);
}
unsafe extern "C" fn process_remove_all_identities(mut e: *mut SocketEntry) {
    let mut id: *mut Identity = 0 as *mut Identity;
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
            b"process_remove_all_identities\0",
        ))
        .as_ptr(),
        911 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    id = (*idtab).idlist.tqh_first;
    while !id.is_null() {
        if !((*id).next.tqe_next).is_null() {
            (*(*id).next.tqe_next).next.tqe_prev = (*id).next.tqe_prev;
        } else {
            (*idtab).idlist.tqh_last = (*id).next.tqe_prev;
        }
        *(*id).next.tqe_prev = (*id).next.tqe_next;
        free_identity(id);
        id = (*idtab).idlist.tqh_first;
    }
    (*idtab).nentries = 0 as libc::c_int;
    send_status(e, 1 as libc::c_int);
}
unsafe extern "C" fn reaper() -> time_t {
    let mut deadline: time_t = 0 as libc::c_int as time_t;
    let mut now: time_t = monotime();
    let mut id: *mut Identity = 0 as *mut Identity;
    let mut nxt: *mut Identity = 0 as *mut Identity;
    id = (*idtab).idlist.tqh_first;
    while !id.is_null() {
        nxt = (*id).next.tqe_next;
        if !((*id).death == 0 as libc::c_int as libc::c_long) {
            if now >= (*id).death {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 7], &[libc::c_char; 7]>(b"reaper\0")).as_ptr(),
                    938 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"expiring key '%s'\0" as *const u8 as *const libc::c_char,
                    (*id).comment,
                );
                if !((*id).next.tqe_next).is_null() {
                    (*(*id).next.tqe_next).next.tqe_prev = (*id).next.tqe_prev;
                } else {
                    (*idtab).idlist.tqh_last = (*id).next.tqe_prev;
                }
                *(*id).next.tqe_prev = (*id).next.tqe_next;
                free_identity(id);
                (*idtab).nentries -= 1;
                (*idtab).nentries;
            } else {
                deadline = if deadline == 0 as libc::c_int as libc::c_long {
                    (*id).death
                } else if deadline < (*id).death {
                    deadline
                } else {
                    (*id).death
                };
            }
        }
        id = nxt;
    }
    if deadline == 0 as libc::c_int as libc::c_long || deadline <= now {
        return 0 as libc::c_int as time_t;
    } else {
        return deadline - now;
    };
}
unsafe extern "C" fn parse_dest_constraint_hop(
    mut b: *mut crate::sshbuf::sshbuf,
    mut dch: *mut dest_constraint_hop,
) -> libc::c_int {
    let mut current_block: u64;
    let mut key_is_ca: u_char = 0;
    let mut elen: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    let mut k: *mut sshkey = 0 as *mut sshkey;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    memset(
        dch as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<dest_constraint_hop>() as libc::c_ulong,
    );
    r = sshbuf_get_cstring(b, &mut (*dch).user, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_cstring(b, &mut (*dch).hostname, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_string_direct(b, 0 as *mut *const u_char, &mut elen);
            r != 0 as libc::c_int
        }
    {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"parse_dest_constraint_hop\0",
            ))
            .as_ptr(),
            965 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    } else if elen != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"parse_dest_constraint_hop\0",
            ))
            .as_ptr(),
            969 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"unsupported extensions (len %zu)\0" as *const u8 as *const libc::c_char,
            elen,
        );
        r = -(59 as libc::c_int);
    } else {
        if *(*dch).hostname as libc::c_int == '\0' as i32 {
            libc::free((*dch).hostname as *mut libc::c_void);
            (*dch).hostname = 0 as *mut libc::c_char;
        }
        if *(*dch).user as libc::c_int == '\0' as i32 {
            libc::free((*dch).user as *mut libc::c_void);
            (*dch).user = 0 as *mut libc::c_char;
        }
        loop {
            if !(sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong) {
                current_block = 5783071609795492627;
                break;
            }
            (*dch).keys = crate::xmalloc::xrecallocarray(
                (*dch).keys as *mut libc::c_void,
                (*dch).nkeys as size_t,
                ((*dch).nkeys).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
                ::core::mem::size_of::<*mut sshkey>() as libc::c_ulong,
            ) as *mut *mut sshkey;
            (*dch).key_is_ca = crate::xmalloc::xrecallocarray(
                (*dch).key_is_ca as *mut libc::c_void,
                (*dch).nkeys as size_t,
                ((*dch).nkeys).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
                ::core::mem::size_of::<libc::c_int>() as libc::c_ulong,
            ) as *mut libc::c_int;
            r = sshkey_froms(b, &mut k);
            if r != 0 as libc::c_int || {
                r = sshbuf_get_u8(b, &mut key_is_ca);
                r != 0 as libc::c_int
            } {
                current_block = 11742207246258642460;
                break;
            }
            fp = sshkey_fingerprint(k, 2 as libc::c_int, SSH_FP_DEFAULT);
            if fp.is_null() {
                sshfatal(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"parse_dest_constraint_hop\0",
                    ))
                    .as_ptr(),
                    991 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"fingerprint failed\0" as *const u8 as *const libc::c_char,
                );
            }
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"parse_dest_constraint_hop\0",
                ))
                .as_ptr(),
                995 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"%s%s%s: adding %skey %s %s\0" as *const u8 as *const libc::c_char,
                if ((*dch).user).is_null() {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    (*dch).user as *const libc::c_char
                },
                if ((*dch).user).is_null() {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    b"@\0" as *const u8 as *const libc::c_char
                },
                (*dch).hostname,
                if key_is_ca as libc::c_int != 0 {
                    b"CA \0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                sshkey_type(k),
                fp,
            );
            libc::free(fp as *mut libc::c_void);
            let ref mut fresh0 = *((*dch).keys).offset((*dch).nkeys as isize);
            *fresh0 = k;
            *((*dch).key_is_ca).offset((*dch).nkeys as isize) =
                (key_is_ca as libc::c_int != 0 as libc::c_int) as libc::c_int;
            (*dch).nkeys = ((*dch).nkeys).wrapping_add(1);
            (*dch).nkeys;
            k = 0 as *mut sshkey;
        }
        match current_block {
            11742207246258642460 => {}
            _ => {
                r = 0 as libc::c_int;
            }
        }
    }
    sshkey_free(k);
    return r;
}
unsafe extern "C" fn parse_dest_constraint(
    mut m: *mut crate::sshbuf::sshbuf,
    mut dc: *mut dest_constraint,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut frombuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut tobuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    let mut elen: size_t = 0 as libc::c_int as size_t;
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"parse_dest_constraint\0"))
            .as_ptr(),
        1016 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    memset(
        dc as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<dest_constraint>() as libc::c_ulong,
    );
    r = sshbuf_froms(m, &mut b);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_froms(b, &mut frombuf);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_froms(b, &mut tobuf);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_string_direct(b, 0 as *mut *const u_char, &mut elen);
            r != 0 as libc::c_int
        }
    {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"parse_dest_constraint\0"))
                .as_ptr(),
            1023 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    } else {
        r = parse_dest_constraint_hop(frombuf, &mut (*dc).from);
        if !(r != 0 as libc::c_int || {
            r = parse_dest_constraint_hop(tobuf, &mut (*dc).to);
            r != 0 as libc::c_int
        }) {
            if elen != 0 as libc::c_int as libc::c_ulong {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"parse_dest_constraint\0",
                    ))
                    .as_ptr(),
                    1030 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"unsupported extensions (len %zu)\0" as *const u8 as *const libc::c_char,
                    elen,
                );
                r = -(59 as libc::c_int);
            } else {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"parse_dest_constraint\0",
                    ))
                    .as_ptr(),
                    1037 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"parsed %s (%u keys) > %s%s%s (%u keys)\0" as *const u8 as *const libc::c_char,
                    if !((*dc).from.hostname).is_null() {
                        (*dc).from.hostname as *const libc::c_char
                    } else {
                        b"(ORIGIN)\0" as *const u8 as *const libc::c_char
                    },
                    (*dc).from.nkeys,
                    if !((*dc).to.user).is_null() {
                        (*dc).to.user as *const libc::c_char
                    } else {
                        b"\0" as *const u8 as *const libc::c_char
                    },
                    if !((*dc).to.user).is_null() {
                        b"@\0" as *const u8 as *const libc::c_char
                    } else {
                        b"\0" as *const u8 as *const libc::c_char
                    },
                    if !((*dc).to.hostname).is_null() {
                        (*dc).to.hostname as *const libc::c_char
                    } else {
                        b"(ANY)\0" as *const u8 as *const libc::c_char
                    },
                    (*dc).to.nkeys,
                );
                if ((*dc).from.hostname == 0 as *mut libc::c_void as *mut libc::c_char)
                    as libc::c_int
                    != ((*dc).from.nkeys == 0 as libc::c_int as libc::c_uint) as libc::c_int
                    || !((*dc).from.user).is_null()
                {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                            b"parse_dest_constraint\0",
                        ))
                        .as_ptr(),
                        1041 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"inconsistent \"from\" specification\0" as *const u8
                            as *const libc::c_char,
                    );
                    r = -(4 as libc::c_int);
                } else if ((*dc).to.hostname).is_null()
                    || (*dc).to.nkeys == 0 as libc::c_int as libc::c_uint
                {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                            b"parse_dest_constraint\0",
                        ))
                        .as_ptr(),
                        1046 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"incomplete \"to\" specification\0" as *const u8 as *const libc::c_char,
                    );
                    r = -(4 as libc::c_int);
                } else {
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    sshbuf_free(b);
    sshbuf_free(frombuf);
    sshbuf_free(tobuf);
    return r;
}
unsafe extern "C" fn parse_key_constraint_extension(
    mut m: *mut crate::sshbuf::sshbuf,
    mut sk_providerp: *mut *mut libc::c_char,
    mut dcsp: *mut *mut dest_constraint,
    mut ndcsp: *mut size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ext_name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    r = sshbuf_get_cstring(m, &mut ext_name, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                b"parse_key_constraint_extension\0",
            ))
            .as_ptr(),
            1068 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse constraint extension\0" as *const u8 as *const libc::c_char,
        );
    } else {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                b"parse_key_constraint_extension\0",
            ))
            .as_ptr(),
            1071 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"constraint ext %s\0" as *const u8 as *const libc::c_char,
            ext_name,
        );
        if libc::strcmp(
            ext_name,
            b"sk-provider@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            if sk_providerp.is_null() {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                        b"parse_key_constraint_extension\0",
                    ))
                    .as_ptr(),
                    1074 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s not valid here\0" as *const u8 as *const libc::c_char,
                    ext_name,
                );
                r = -(4 as libc::c_int);
                current_block = 4252588936699793226;
            } else if !(*sk_providerp).is_null() {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                        b"parse_key_constraint_extension\0",
                    ))
                    .as_ptr(),
                    1079 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s already set\0" as *const u8 as *const libc::c_char,
                    ext_name,
                );
                r = -(4 as libc::c_int);
                current_block = 4252588936699793226;
            } else {
                r = sshbuf_get_cstring(m, sk_providerp, 0 as *mut size_t);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                            b"parse_key_constraint_extension\0",
                        ))
                        .as_ptr(),
                        1084 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        ext_name,
                    );
                    current_block = 4252588936699793226;
                } else {
                    current_block = 15768484401365413375;
                }
            }
        } else if libc::strcmp(
            ext_name,
            b"restrict-destination-v00@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            if !(*dcsp).is_null() {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                        b"parse_key_constraint_extension\0",
                    ))
                    .as_ptr(),
                    1090 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s already set\0" as *const u8 as *const libc::c_char,
                    ext_name,
                );
                current_block = 4252588936699793226;
            } else {
                r = sshbuf_froms(m, &mut b);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                            b"parse_key_constraint_extension\0",
                        ))
                        .as_ptr(),
                        1094 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"parse %s outer\0" as *const u8 as *const libc::c_char,
                        ext_name,
                    );
                    current_block = 4252588936699793226;
                } else {
                    loop {
                        if !(sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong) {
                            current_block = 15768484401365413375;
                            break;
                        }
                        if *ndcsp >= 1024 as libc::c_int as libc::c_ulong {
                            crate::log::sshlog(
                                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                                    b"parse_key_constraint_extension\0",
                                ))
                                .as_ptr(),
                                1099 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"too many %s constraints\0" as *const u8 as *const libc::c_char,
                                ext_name,
                            );
                            current_block = 4252588936699793226;
                            break;
                        } else {
                            *dcsp = crate::xmalloc::xrecallocarray(
                                *dcsp as *mut libc::c_void,
                                *ndcsp,
                                (*ndcsp).wrapping_add(1 as libc::c_int as libc::c_ulong),
                                ::core::mem::size_of::<dest_constraint>() as libc::c_ulong,
                            ) as *mut dest_constraint;
                            let fresh1 = *ndcsp;
                            *ndcsp = (*ndcsp).wrapping_add(1);
                            r = parse_dest_constraint(b, (*dcsp).offset(fresh1 as isize));
                            if r != 0 as libc::c_int {
                                current_block = 4252588936699793226;
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                    b"parse_key_constraint_extension\0",
                ))
                .as_ptr(),
                1109 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"unsupported constraint \"%s\"\0" as *const u8 as *const libc::c_char,
                ext_name,
            );
            r = -(59 as libc::c_int);
            current_block = 4252588936699793226;
        }
        match current_block {
            4252588936699793226 => {}
            _ => {
                r = 0 as libc::c_int;
            }
        }
    }
    libc::free(ext_name as *mut libc::c_void);
    sshbuf_free(b);
    return r;
}
unsafe extern "C" fn parse_key_constraints(
    mut m: *mut crate::sshbuf::sshbuf,
    mut k: *mut sshkey,
    mut deathp: *mut time_t,
    mut secondsp: *mut u_int,
    mut confirmp: *mut libc::c_int,
    mut sk_providerp: *mut *mut libc::c_char,
    mut dcsp: *mut *mut dest_constraint,
    mut ndcsp: *mut size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ctype: u_char = 0;
    let mut r: libc::c_int = 0;
    let mut seconds: u_int = 0;
    let mut maxsign: u_int = 0 as libc::c_int as u_int;
    loop {
        if !(sshbuf_len(m) != 0) {
            current_block = 7205609094909031804;
            break;
        }
        r = sshbuf_get_u8(m, &mut ctype);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"parse_key_constraints\0",
                ))
                .as_ptr(),
                1132 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"parse constraint type\0" as *const u8 as *const libc::c_char,
            );
            current_block = 16812902527858607079;
            break;
        } else {
            match ctype as libc::c_int {
                1 => {
                    if *deathp != 0 as libc::c_int as libc::c_long {
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                b"parse_key_constraints\0",
                            ))
                            .as_ptr(),
                            1138 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"lifetime already set\0" as *const u8 as *const libc::c_char,
                        );
                        r = -(4 as libc::c_int);
                        current_block = 16812902527858607079;
                        break;
                    } else {
                        r = sshbuf_get_u32(m, &mut seconds);
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                    b"parse_key_constraints\0",
                                ))
                                .as_ptr(),
                                1143 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"parse lifetime constraint\0" as *const u8 as *const libc::c_char,
                            );
                            current_block = 16812902527858607079;
                            break;
                        } else {
                            *deathp = monotime() + seconds as libc::c_long;
                            *secondsp = seconds;
                        }
                    }
                }
                2 => {
                    if *confirmp != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                b"parse_key_constraints\0",
                            ))
                            .as_ptr(),
                            1151 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"confirm already set\0" as *const u8 as *const libc::c_char,
                        );
                        r = -(4 as libc::c_int);
                        current_block = 16812902527858607079;
                        break;
                    } else {
                        *confirmp = 1 as libc::c_int;
                    }
                }
                3 => {
                    if k.is_null() {
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                b"parse_key_constraints\0",
                            ))
                            .as_ptr(),
                            1159 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"maxsign not valid here\0" as *const u8 as *const libc::c_char,
                        );
                        r = -(4 as libc::c_int);
                        current_block = 16812902527858607079;
                        break;
                    } else if maxsign != 0 as libc::c_int as libc::c_uint {
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                b"parse_key_constraints\0",
                            ))
                            .as_ptr(),
                            1164 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"maxsign already set\0" as *const u8 as *const libc::c_char,
                        );
                        r = -(4 as libc::c_int);
                        current_block = 16812902527858607079;
                        break;
                    } else {
                        r = sshbuf_get_u32(m, &mut maxsign);
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                    b"parse_key_constraints\0",
                                ))
                                .as_ptr(),
                                1169 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"parse maxsign constraint\0" as *const u8 as *const libc::c_char,
                            );
                            current_block = 16812902527858607079;
                            break;
                        } else {
                            r = sshkey_enable_maxsign(k, maxsign);
                            if !(r != 0 as libc::c_int) {
                                continue;
                            }
                            crate::log::sshlog(
                                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                    b"parse_key_constraints\0",
                                ))
                                .as_ptr(),
                                1173 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"enable maxsign\0" as *const u8 as *const libc::c_char,
                            );
                            current_block = 16812902527858607079;
                            break;
                        }
                    }
                }
                255 => {
                    r = parse_key_constraint_extension(m, sk_providerp, dcsp, ndcsp);
                    if r != 0 as libc::c_int {
                        current_block = 16812902527858607079;
                        break;
                    }
                }
                _ => {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                            b"parse_key_constraints\0",
                        ))
                        .as_ptr(),
                        1183 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Unknown constraint %d\0" as *const u8 as *const libc::c_char,
                        ctype as libc::c_int,
                    );
                    r = -(59 as libc::c_int);
                    current_block = 16812902527858607079;
                    break;
                }
            }
        }
    }
    match current_block {
        7205609094909031804 => {
            r = 0 as libc::c_int;
        }
        _ => {}
    }
    return r;
}
unsafe extern "C" fn process_add_identity(mut e: *mut SocketEntry) {
    let mut current_block: u64;
    let mut id: *mut Identity = 0 as *mut Identity;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut confirm: libc::c_int = 0 as libc::c_int;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sk_provider: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut canonical_provider: [libc::c_char; 4096] = [0; 4096];
    let mut death: time_t = 0 as libc::c_int as time_t;
    let mut seconds: u_int = 0 as libc::c_int as u_int;
    let mut dest_constraints: *mut dest_constraint = 0 as *mut dest_constraint;
    let mut ndest_constraints: size_t = 0 as libc::c_int as size_t;
    let mut k: *mut sshkey = 0 as *mut sshkey;
    let mut r: libc::c_int = -(1 as libc::c_int);
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"process_add_identity\0"))
            .as_ptr(),
        1208 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    r = sshkey_private_deserialize((*e).request, &mut k);
    if r != 0 as libc::c_int || k.is_null() || {
        r = sshbuf_get_cstring((*e).request, &mut comment, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"process_add_identity\0"))
                .as_ptr(),
            1212 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    } else if parse_key_constraints(
        (*e).request,
        k,
        &mut death,
        &mut seconds,
        &mut confirm,
        &mut sk_provider,
        &mut dest_constraints,
        &mut ndest_constraints,
    ) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"process_add_identity\0"))
                .as_ptr(),
            1217 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"failed to parse constraints\0" as *const u8 as *const libc::c_char,
        );
        sshbuf_reset((*e).request);
    } else {
        if !sk_provider.is_null() {
            if sshkey_is_sk(k) == 0 {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"process_add_identity\0",
                    ))
                    .as_ptr(),
                    1225 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Cannot add provider: %s is not an authenticator-hosted key\0" as *const u8
                        as *const libc::c_char,
                    sshkey_type(k),
                );
                current_block = 12326576695480106577;
            } else if strcasecmp(
                sk_provider,
                b"internal\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
            {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"process_add_identity\0",
                    ))
                    .as_ptr(),
                    1229 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"internal provider\0" as *const u8 as *const libc::c_char,
                );
                current_block = 11584701595673473500;
            } else if (realpath(sk_provider, canonical_provider.as_mut_ptr())).is_null() {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"process_add_identity\0",
                    ))
                    .as_ptr(),
                    1234 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_VERBOSE,
                    0 as *const libc::c_char,
                    b"failed provider \"%.100s\": realpath: %s\0" as *const u8
                        as *const libc::c_char,
                    sk_provider,
                    libc::strerror(*libc::__errno_location()),
                );
                current_block = 12326576695480106577;
            } else {
                libc::free(sk_provider as *mut libc::c_void);
                sk_provider = crate::xmalloc::xstrdup(canonical_provider.as_mut_ptr());
                if match_pattern_list(sk_provider, allowed_providers, 0 as libc::c_int)
                    != 1 as libc::c_int
                {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"process_add_identity\0",
                        ))
                        .as_ptr(),
                        1242 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Refusing add key: provider %s not allowed\0" as *const u8
                            as *const libc::c_char,
                        sk_provider,
                    );
                    current_block = 12326576695480106577;
                } else {
                    current_block = 11584701595673473500;
                }
            }
        } else {
            current_block = 11584701595673473500;
        }
        match current_block {
            12326576695480106577 => {}
            _ => {
                r = sshkey_shield_private(k);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"process_add_identity\0",
                        ))
                        .as_ptr(),
                        1248 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"shield private\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    if lifetime != 0 && death == 0 {
                        death = monotime() + lifetime as libc::c_long;
                    }
                    id = lookup_identity(k);
                    if id.is_null() {
                        id = crate::xmalloc::xcalloc(
                            1 as libc::c_int as size_t,
                            ::core::mem::size_of::<Identity>() as libc::c_ulong,
                        ) as *mut Identity;
                        (*id).next.tqe_next = 0 as *mut identity;
                        (*id).next.tqe_prev = (*idtab).idlist.tqh_last;
                        *(*idtab).idlist.tqh_last = id;
                        (*idtab).idlist.tqh_last = &mut (*id).next.tqe_next;
                        (*idtab).nentries += 1;
                        (*idtab).nentries;
                        current_block = 7828949454673616476;
                    } else if identity_permitted(
                        id,
                        e,
                        0 as *mut libc::c_char,
                        0 as *mut *const libc::c_char,
                        0 as *mut *const libc::c_char,
                    ) != 0 as libc::c_int
                    {
                        current_block = 12326576695480106577;
                    } else {
                        sshkey_free((*id).key);
                        libc::free((*id).comment as *mut libc::c_void);
                        libc::free((*id).sk_provider as *mut libc::c_void);
                        free_dest_constraints((*id).dest_constraints, (*id).ndest_constraints);
                        current_block = 7828949454673616476;
                    }
                    match current_block {
                        12326576695480106577 => {}
                        _ => {
                            (*id).key = k;
                            (*id).comment = comment;
                            (*id).death = death;
                            (*id).confirm = confirm as u_int;
                            (*id).sk_provider = sk_provider;
                            (*id).dest_constraints = dest_constraints;
                            (*id).ndest_constraints = ndest_constraints;
                            fp = sshkey_fingerprint(k, 2 as libc::c_int, SSH_FP_DEFAULT);
                            if fp.is_null() {
                                sshfatal(
                                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                                        b"process_add_identity\0",
                                    ))
                                    .as_ptr(),
                                    1280 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"sshkey_fingerprint failed\0" as *const u8
                                        as *const libc::c_char,
                                );
                            }
                            crate::log::sshlog(
                                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<
                                    &[u8; 21],
                                    &[libc::c_char; 21],
                                >(b"process_add_identity\0"))
                                    .as_ptr(),
                                1284 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"add %s %s \"%.100s\" (life: %u) (confirm: %u) (provider: %s) (destination constraints: %zu)\0"
                                    as *const u8 as *const libc::c_char,
                                sshkey_ssh_name(k),
                                fp,
                                comment,
                                seconds,
                                confirm,
                                if sk_provider.is_null() {
                                    b"none\0" as *const u8 as *const libc::c_char
                                } else {
                                    sk_provider as *const libc::c_char
                                },
                                ndest_constraints,
                            );
                            libc::free(fp as *mut libc::c_void);
                            k = 0 as *mut sshkey;
                            comment = 0 as *mut libc::c_char;
                            sk_provider = 0 as *mut libc::c_char;
                            dest_constraints = 0 as *mut dest_constraint;
                            ndest_constraints = 0 as libc::c_int as size_t;
                            success = 1 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    libc::free(sk_provider as *mut libc::c_void);
    libc::free(comment as *mut libc::c_void);
    sshkey_free(k);
    free_dest_constraints(dest_constraints, ndest_constraints);
    send_status(e, success);
}
unsafe extern "C" fn process_lock_agent(mut e: *mut SocketEntry, mut lock: libc::c_int) {
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut delay: libc::c_int = 0;
    let mut passwd: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut passwdhash: [u_char; 32] = [0; 32];
    static mut fail_count: u_int = 0 as libc::c_int as u_int;
    let mut pwlen: size_t = 0;
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"process_lock_agent\0"))
            .as_ptr(),
        1311 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    r = sshbuf_get_cstring((*e).request, &mut passwd, &mut pwlen);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"process_lock_agent\0"))
                .as_ptr(),
            1318 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if pwlen == 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"process_lock_agent\0"))
                .as_ptr(),
            1320 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"empty password not supported\0" as *const u8 as *const libc::c_char,
        );
    } else if locked != 0 && lock == 0 {
        if bcrypt_pbkdf(
            passwd,
            pwlen,
            lock_salt.as_mut_ptr(),
            ::core::mem::size_of::<[u_char; 16]>() as libc::c_ulong,
            passwdhash.as_mut_ptr(),
            ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
            1 as libc::c_int as libc::c_uint,
        ) < 0 as libc::c_int
        {
            sshfatal(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"process_lock_agent\0",
                ))
                .as_ptr(),
                1324 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"bcrypt_pbkdf\0" as *const u8 as *const libc::c_char,
            );
        }
        if timingsafe_bcmp(
            passwdhash.as_mut_ptr() as *const libc::c_void,
            lock_pwhash.as_mut_ptr() as *const libc::c_void,
            32 as libc::c_int as size_t,
        ) == 0 as libc::c_int
        {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"process_lock_agent\0",
                ))
                .as_ptr(),
                1326 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"agent unlocked\0" as *const u8 as *const libc::c_char,
            );
            locked = 0 as libc::c_int;
            fail_count = 0 as libc::c_int as u_int;
            explicit_bzero(
                lock_pwhash.as_mut_ptr() as *mut libc::c_void,
                ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
            );
            success = 1 as libc::c_int;
        } else {
            if fail_count < 100 as libc::c_int as libc::c_uint {
                fail_count = fail_count.wrapping_add(1);
                fail_count;
            }
            delay = (100000 as libc::c_int as libc::c_uint).wrapping_mul(fail_count) as libc::c_int;
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"process_lock_agent\0",
                ))
                .as_ptr(),
                1337 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"unlock failed, delaying %0.1lf seconds\0" as *const u8 as *const libc::c_char,
                delay as libc::c_double / 1000000 as libc::c_int as libc::c_double,
            );
            usleep(delay as __useconds_t);
        }
        explicit_bzero(
            passwdhash.as_mut_ptr() as *mut libc::c_void,
            ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
        );
    } else if locked == 0 && lock != 0 {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"process_lock_agent\0"))
                .as_ptr(),
            1342 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"agent locked\0" as *const u8 as *const libc::c_char,
        );
        locked = 1 as libc::c_int;
        arc4random_buf(
            lock_salt.as_mut_ptr() as *mut libc::c_void,
            ::core::mem::size_of::<[u_char; 16]>() as libc::c_ulong,
        );
        if bcrypt_pbkdf(
            passwd,
            pwlen,
            lock_salt.as_mut_ptr(),
            ::core::mem::size_of::<[u_char; 16]>() as libc::c_ulong,
            lock_pwhash.as_mut_ptr(),
            ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
            1 as libc::c_int as libc::c_uint,
        ) < 0 as libc::c_int
        {
            sshfatal(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"process_lock_agent\0",
                ))
                .as_ptr(),
                1347 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"bcrypt_pbkdf\0" as *const u8 as *const libc::c_char,
            );
        }
        success = 1 as libc::c_int;
    }
    freezero(passwd as *mut libc::c_void, pwlen);
    send_status(e, success);
}
unsafe extern "C" fn no_identities(mut e: *mut SocketEntry) {
    let mut msg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    msg = crate::sshbuf::sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"no_identities\0"))
                .as_ptr(),
            1361 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshbuf_put_u8(msg, 12 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, 0 as libc::c_int as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb((*e).output, msg);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"no_identities\0"))
                .as_ptr(),
            1365 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(msg);
}
unsafe extern "C" fn process_add_smartcard_key(mut e: *mut SocketEntry) {
    let mut provider: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut canonical_provider: [libc::c_char; 4096] = [0; 4096];
    let mut comments: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut confirm: libc::c_int = 0 as libc::c_int;
    let mut seconds: u_int = 0 as libc::c_int as u_int;
    let mut death: time_t = 0 as libc::c_int as time_t;
    let mut keys: *mut *mut sshkey = 0 as *mut *mut sshkey;
    let mut k: *mut sshkey = 0 as *mut sshkey;
    let mut id: *mut Identity = 0 as *mut Identity;
    let mut dest_constraints: *mut dest_constraint = 0 as *mut dest_constraint;
    let mut ndest_constraints: size_t = 0 as libc::c_int as size_t;
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"process_add_smartcard_key\0"))
            .as_ptr(),
        1383 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    r = sshbuf_get_cstring((*e).request, &mut provider, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_cstring((*e).request, &mut pin, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"process_add_smartcard_key\0",
            ))
            .as_ptr(),
            1386 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    } else if parse_key_constraints(
        (*e).request,
        0 as *mut sshkey,
        &mut death,
        &mut seconds,
        &mut confirm,
        0 as *mut *mut libc::c_char,
        &mut dest_constraints,
        &mut ndest_constraints,
    ) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"process_add_smartcard_key\0",
            ))
            .as_ptr(),
            1391 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"failed to parse constraints\0" as *const u8 as *const libc::c_char,
        );
    } else if (realpath(provider, canonical_provider.as_mut_ptr())).is_null() {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"process_add_smartcard_key\0",
            ))
            .as_ptr(),
            1396 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"failed PKCS#11 add of \"%.100s\": realpath: %s\0" as *const u8 as *const libc::c_char,
            provider,
            libc::strerror(*libc::__errno_location()),
        );
    } else if match_pattern_list(
        canonical_provider.as_mut_ptr(),
        allowed_providers,
        0 as libc::c_int,
    ) != 1 as libc::c_int
    {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"process_add_smartcard_key\0",
            ))
            .as_ptr(),
            1401 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"refusing PKCS#11 add of \"%.100s\": provider not allowed\0" as *const u8
                as *const libc::c_char,
            canonical_provider.as_mut_ptr(),
        );
    } else {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"process_add_smartcard_key\0",
            ))
            .as_ptr(),
            1404 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"add %.100s\0" as *const u8 as *const libc::c_char,
            canonical_provider.as_mut_ptr(),
        );
        if lifetime != 0 && death == 0 {
            death = monotime() + lifetime as libc::c_long;
        }
        count = pkcs11_add_provider(
            canonical_provider.as_mut_ptr(),
            pin,
            &mut keys,
            &mut comments,
        );
        i = 0 as libc::c_int;
        while i < count {
            k = *keys.offset(i as isize);
            if (lookup_identity(k)).is_null() {
                id = crate::xmalloc::xcalloc(
                    1 as libc::c_int as size_t,
                    ::core::mem::size_of::<Identity>() as libc::c_ulong,
                ) as *mut Identity;
                (*id).key = k;
                let ref mut fresh2 = *keys.offset(i as isize);
                *fresh2 = 0 as *mut sshkey;
                (*id).provider = crate::xmalloc::xstrdup(canonical_provider.as_mut_ptr());
                if **comments.offset(i as isize) as libc::c_int != '\0' as i32 {
                    (*id).comment = *comments.offset(i as isize);
                    let ref mut fresh3 = *comments.offset(i as isize);
                    *fresh3 = 0 as *mut libc::c_char;
                } else {
                    (*id).comment = crate::xmalloc::xstrdup(canonical_provider.as_mut_ptr());
                }
                (*id).death = death;
                (*id).confirm = confirm as u_int;
                (*id).dest_constraints = dest_constraints;
                (*id).ndest_constraints = ndest_constraints;
                dest_constraints = 0 as *mut dest_constraint;
                ndest_constraints = 0 as libc::c_int as size_t;
                (*id).next.tqe_next = 0 as *mut identity;
                (*id).next.tqe_prev = (*idtab).idlist.tqh_last;
                *(*idtab).idlist.tqh_last = id;
                (*idtab).idlist.tqh_last = &mut (*id).next.tqe_next;
                (*idtab).nentries += 1;
                (*idtab).nentries;
                success = 1 as libc::c_int;
            }
            sshkey_free(*keys.offset(i as isize));
            libc::free(*comments.offset(i as isize) as *mut libc::c_void);
            i += 1;
            i;
        }
    }
    libc::free(pin as *mut libc::c_void);
    libc::free(provider as *mut libc::c_void);
    libc::free(keys as *mut libc::c_void);
    libc::free(comments as *mut libc::c_void);
    free_dest_constraints(dest_constraints, ndest_constraints);
    send_status(e, success);
}
unsafe extern "C" fn process_remove_smartcard_key(mut e: *mut SocketEntry) {
    let mut provider: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut canonical_provider: [libc::c_char; 4096] = [0; 4096];
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut id: *mut Identity = 0 as *mut Identity;
    let mut nxt: *mut Identity = 0 as *mut Identity;
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
            b"process_remove_smartcard_key\0",
        ))
        .as_ptr(),
        1452 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    r = sshbuf_get_cstring((*e).request, &mut provider, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_cstring((*e).request, &mut pin, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"process_remove_smartcard_key\0",
            ))
            .as_ptr(),
            1455 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    } else {
        libc::free(pin as *mut libc::c_void);
        if (realpath(provider, canonical_provider.as_mut_ptr())).is_null() {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"process_remove_smartcard_key\0",
                ))
                .as_ptr(),
                1462 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_VERBOSE,
                0 as *const libc::c_char,
                b"failed PKCS#11 add of \"%.100s\": realpath: %s\0" as *const u8
                    as *const libc::c_char,
                provider,
                libc::strerror(*libc::__errno_location()),
            );
        } else {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"process_remove_smartcard_key\0",
                ))
                .as_ptr(),
                1466 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"remove %.100s\0" as *const u8 as *const libc::c_char,
                canonical_provider.as_mut_ptr(),
            );
            id = (*idtab).idlist.tqh_first;
            while !id.is_null() {
                nxt = (*id).next.tqe_next;
                if !((*id).provider).is_null() {
                    if libc::strcmp(canonical_provider.as_mut_ptr(), (*id).provider) == 0 {
                        if !((*id).next.tqe_next).is_null() {
                            (*(*id).next.tqe_next).next.tqe_prev = (*id).next.tqe_prev;
                        } else {
                            (*idtab).idlist.tqh_last = (*id).next.tqe_prev;
                        }
                        *(*id).next.tqe_prev = (*id).next.tqe_next;
                        free_identity(id);
                        (*idtab).nentries -= 1;
                        (*idtab).nentries;
                    }
                }
                id = nxt;
            }
            if pkcs11_del_provider(canonical_provider.as_mut_ptr()) == 0 as libc::c_int {
                success = 1 as libc::c_int;
            } else {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"process_remove_smartcard_key\0",
                    ))
                    .as_ptr(),
                    1481 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"pkcs11_del_provider failed\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
    libc::free(provider as *mut libc::c_void);
    send_status(e, success);
}
unsafe extern "C" fn process_ext_session_bind(mut e: *mut SocketEntry) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = 0;
    let mut sid_match: libc::c_int = 0;
    let mut key_match: libc::c_int = 0;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut sid: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sig: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: size_t = 0;
    let mut fwd: u_char = 0 as libc::c_int as u_char;
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"process_ext_session_bind\0"))
            .as_ptr(),
        1498 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    r = sshkey_froms((*e).request, &mut key);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_froms((*e).request, &mut sid);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_froms((*e).request, &mut sig);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u8((*e).request, &mut fwd);
            r != 0 as libc::c_int
        }
    {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"process_ext_session_bind\0",
            ))
            .as_ptr(),
            1503 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    } else {
        fp = sshkey_fingerprint(key, 2 as libc::c_int, SSH_FP_DEFAULT);
        if fp.is_null() {
            sshfatal(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"process_ext_session_bind\0",
                ))
                .as_ptr(),
                1508 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"fingerprint failed\0" as *const u8 as *const libc::c_char,
            );
        }
        r = sshkey_verify(
            key,
            sshbuf_ptr(sig),
            sshbuf_len(sig),
            sshbuf_ptr(sid),
            sshbuf_len(sid),
            0 as *const libc::c_char,
            0 as libc::c_int as u_int,
            0 as *mut *mut sshkey_sig_details,
        );
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"process_ext_session_bind\0",
                ))
                .as_ptr(),
                1512 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"sshkey_verify for %s %s\0" as *const u8 as *const libc::c_char,
                sshkey_type(key),
                fp,
            );
        } else {
            i = 0 as libc::c_int as size_t;
            loop {
                if !(i < (*e).nsession_ids) {
                    current_block = 13797916685926291137;
                    break;
                }
                if (*((*e).session_ids).offset(i as isize)).forwarded == 0 {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<
                            &[u8; 25],
                            &[libc::c_char; 25],
                        >(b"process_ext_session_bind\0"))
                            .as_ptr(),
                        1519 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"attempt to bind session ID to socket previously bound for authentication attempt\0"
                            as *const u8 as *const libc::c_char,
                    );
                    r = -(1 as libc::c_int);
                    current_block = 2759485078803402792;
                    break;
                } else {
                    sid_match = (buf_equal(sid, (*((*e).session_ids).offset(i as isize)).sid)
                        == 0 as libc::c_int) as libc::c_int;
                    key_match = sshkey_equal(key, (*((*e).session_ids).offset(i as isize)).key);
                    if sid_match != 0 && key_match != 0 {
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"process_ext_session_bind\0",
                            ))
                            .as_ptr(),
                            1527 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"session ID already recorded for %s %s\0" as *const u8
                                as *const libc::c_char,
                            sshkey_type(key),
                            fp,
                        );
                        r = 0 as libc::c_int;
                        current_block = 2759485078803402792;
                        break;
                    } else if sid_match != 0 {
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"process_ext_session_bind\0",
                            ))
                            .as_ptr(),
                            1532 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"session ID recorded against different key for %s %s\0" as *const u8
                                as *const libc::c_char,
                            sshkey_type(key),
                            fp,
                        );
                        r = -(1 as libc::c_int);
                        current_block = 2759485078803402792;
                        break;
                    } else {
                        i = i.wrapping_add(1);
                        i;
                    }
                }
            }
            match current_block {
                2759485078803402792 => {}
                _ => {
                    if (*e).nsession_ids >= 16 as libc::c_int as libc::c_ulong {
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"process_ext_session_bind\0",
                            ))
                            .as_ptr(),
                            1543 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"too many session IDs recorded\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        (*e).session_ids = crate::xmalloc::xrecallocarray(
                            (*e).session_ids as *mut libc::c_void,
                            (*e).nsession_ids,
                            ((*e).nsession_ids).wrapping_add(1 as libc::c_int as libc::c_ulong),
                            ::core::mem::size_of::<hostkey_sid>() as libc::c_ulong,
                        ) as *mut hostkey_sid;
                        let fresh4 = (*e).nsession_ids;
                        (*e).nsession_ids = ((*e).nsession_ids).wrapping_add(1);
                        i = fresh4;
                        crate::log::sshlog(
                            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"process_ext_session_bind\0",
                            ))
                            .as_ptr(),
                            1550 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"recorded %s %s (slot %zu of %d)\0" as *const u8
                                as *const libc::c_char,
                            sshkey_type(key),
                            fp,
                            i,
                            16 as libc::c_int,
                        );
                        let ref mut fresh5 = (*((*e).session_ids).offset(i as isize)).key;
                        *fresh5 = key;
                        (*((*e).session_ids).offset(i as isize)).forwarded =
                            (fwd as libc::c_int != 0 as libc::c_int) as libc::c_int;
                        key = 0 as *mut sshkey;
                        let ref mut fresh6 = (*((*e).session_ids).offset(i as isize)).sid;
                        *fresh6 = crate::sshbuf::sshbuf_new();
                        if (*fresh6).is_null() {
                            sshfatal(
                                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                    b"process_ext_session_bind\0",
                                ))
                                .as_ptr(),
                                1556 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                0 as *const libc::c_char,
                                b"crate::crate::sshbuf::sshbuf::sshbuf_new\0" as *const u8
                                    as *const libc::c_char,
                            );
                        }
                        r = sshbuf_putb((*((*e).session_ids).offset(i as isize)).sid, sid);
                        if r != 0 as libc::c_int {
                            sshfatal(
                                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                    b"process_ext_session_bind\0",
                                ))
                                .as_ptr(),
                                1558 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                ssh_err(r),
                                b"sshbuf_putb session ID\0" as *const u8 as *const libc::c_char,
                            );
                        }
                        r = 0 as libc::c_int;
                    }
                }
            }
        }
    }
    libc::free(fp as *mut libc::c_void);
    sshkey_free(key);
    sshbuf_free(sid);
    sshbuf_free(sig);
    return if r == 0 as libc::c_int {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    };
}
unsafe extern "C" fn process_extension(mut e: *mut SocketEntry) {
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"process_extension\0"))
            .as_ptr(),
        1575 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    r = sshbuf_get_cstring((*e).request, &mut name, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"process_extension\0"))
                .as_ptr(),
            1577 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    } else {
        if libc::strcmp(
            name,
            b"session-bind@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            success = process_ext_session_bind(e);
        } else {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"process_extension\0"))
                    .as_ptr(),
                1583 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"unsupported extension \"%s\"\0" as *const u8 as *const libc::c_char,
                name,
            );
        }
        libc::free(name as *mut libc::c_void);
    }
    send_status(e, success);
}
unsafe extern "C" fn process_message(mut socknum: u_int) -> libc::c_int {
    let mut msg_len: u_int = 0;
    let mut type_0: u_char = 0;
    let mut cp: *const u_char = 0 as *const u_char;
    let mut r: libc::c_int = 0;
    let mut e: *mut SocketEntry = 0 as *mut SocketEntry;
    if socknum >= sockets_alloc {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_message\0"))
                .as_ptr(),
            1602 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sock %u >= allocated %u\0" as *const u8 as *const libc::c_char,
            socknum,
            sockets_alloc,
        );
    }
    e = &mut *sockets.offset(socknum as isize) as *mut SocketEntry;
    if sshbuf_len((*e).input) < 5 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    cp = sshbuf_ptr((*e).input);
    msg_len = (*cp.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int
        | (*cp.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
        | (*cp.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
        | *cp.offset(3 as libc::c_int as isize) as u_int32_t;
    if msg_len > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_uint {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_message\0"))
                .as_ptr(),
            1611 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"socket %u (fd=%d) message too long %u > %u\0" as *const u8 as *const libc::c_char,
            socknum,
            (*e).fd,
            msg_len,
            256 as libc::c_int * 1024 as libc::c_int,
        );
        return -(1 as libc::c_int);
    }
    if sshbuf_len((*e).input)
        < msg_len.wrapping_add(4 as libc::c_int as libc::c_uint) as libc::c_ulong
    {
        return 0 as libc::c_int;
    }
    sshbuf_reset((*e).request);
    r = sshbuf_get_stringb((*e).input, (*e).request);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u8((*e).request, &mut type_0);
        r != 0 as libc::c_int
    } {
        if r == -(3 as libc::c_int) || r == -(6 as libc::c_int) {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_message\0"))
                    .as_ptr(),
                1623 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"parse\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_message\0"))
                .as_ptr(),
            1626 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_message\0")).as_ptr(),
        1629 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"socket %u (fd=%d) type %d\0" as *const u8 as *const libc::c_char,
        socknum,
        (*e).fd,
        type_0 as libc::c_int,
    );
    if locked != 0 && type_0 as libc::c_int != 23 as libc::c_int {
        sshbuf_reset((*e).request);
        match type_0 as libc::c_int {
            11 => {
                no_identities(e);
            }
            _ => {
                send_status(e, 0 as libc::c_int);
            }
        }
        return 1 as libc::c_int;
    }
    match type_0 as libc::c_int {
        22 | 23 => {
            process_lock_agent(
                e,
                (type_0 as libc::c_int == 22 as libc::c_int) as libc::c_int,
            );
        }
        9 => {
            process_remove_all_identities(e);
        }
        13 => {
            process_sign_request2(e);
        }
        11 => {
            process_request_identities(e);
        }
        17 | 25 => {
            process_add_identity(e);
        }
        18 => {
            process_remove_identity(e);
        }
        19 => {
            process_remove_all_identities(e);
        }
        20 | 26 => {
            process_add_smartcard_key(e);
        }
        21 => {
            process_remove_smartcard_key(e);
        }
        27 => {
            process_extension(e);
        }
        _ => {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_message\0"))
                    .as_ptr(),
                1685 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Unknown message %d\0" as *const u8 as *const libc::c_char,
                type_0 as libc::c_int,
            );
            sshbuf_reset((*e).request);
            send_status(e, 0 as libc::c_int);
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn new_socket(mut type_0: sock_type, mut fd: libc::c_int) {
    let mut i: u_int = 0;
    let mut old_alloc: u_int = 0;
    let mut new_alloc: u_int = 0;
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"new_socket\0")).as_ptr(),
        1699 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"type = %s\0" as *const u8 as *const libc::c_char,
        if type_0 as libc::c_uint == AUTH_CONNECTION as libc::c_int as libc::c_uint {
            b"CONNECTION\0" as *const u8 as *const libc::c_char
        } else if type_0 as libc::c_uint == AUTH_SOCKET as libc::c_int as libc::c_uint {
            b"SOCKET\0" as *const u8 as *const libc::c_char
        } else {
            b"UNKNOWN\0" as *const u8 as *const libc::c_char
        },
    );
    crate::misc::set_nonblock(fd);
    if fd > max_fd {
        max_fd = fd;
    }
    i = 0 as libc::c_int as u_int;
    while i < sockets_alloc {
        if (*sockets.offset(i as isize)).type_0 as libc::c_uint
            == AUTH_UNUSED as libc::c_int as libc::c_uint
        {
            (*sockets.offset(i as isize)).fd = fd;
            let ref mut fresh7 = (*sockets.offset(i as isize)).input;
            *fresh7 = crate::sshbuf::sshbuf_new();
            if (*fresh7).is_null()
                || {
                    let ref mut fresh8 = (*sockets.offset(i as isize)).output;
                    *fresh8 = crate::sshbuf::sshbuf_new();
                    (*fresh8).is_null()
                }
                || {
                    let ref mut fresh9 = (*sockets.offset(i as isize)).request;
                    *fresh9 = crate::sshbuf::sshbuf_new();
                    (*fresh9).is_null()
                }
            {
                sshfatal(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"new_socket\0"))
                        .as_ptr(),
                    1711 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                        as *const libc::c_char,
                );
            }
            (*sockets.offset(i as isize)).type_0 = type_0;
            return;
        }
        i = i.wrapping_add(1);
        i;
    }
    old_alloc = sockets_alloc;
    new_alloc = sockets_alloc.wrapping_add(10 as libc::c_int as libc::c_uint);
    sockets = crate::xmalloc::xrecallocarray(
        sockets as *mut libc::c_void,
        old_alloc as size_t,
        new_alloc as size_t,
        ::core::mem::size_of::<SocketEntry>() as libc::c_ulong,
    ) as *mut SocketEntry;
    i = old_alloc;
    while i < new_alloc {
        (*sockets.offset(i as isize)).type_0 = AUTH_UNUSED;
        i = i.wrapping_add(1);
        i;
    }
    sockets_alloc = new_alloc;
    (*sockets.offset(old_alloc as isize)).fd = fd;
    let ref mut fresh10 = (*sockets.offset(old_alloc as isize)).input;
    *fresh10 = crate::sshbuf::sshbuf_new();
    if (*fresh10).is_null()
        || {
            let ref mut fresh11 = (*sockets.offset(old_alloc as isize)).output;
            *fresh11 = crate::sshbuf::sshbuf_new();
            (*fresh11).is_null()
        }
        || {
            let ref mut fresh12 = (*sockets.offset(old_alloc as isize)).request;
            *fresh12 = crate::sshbuf::sshbuf_new();
            (*fresh12).is_null()
        }
    {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"new_socket\0")).as_ptr(),
            1726 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    (*sockets.offset(old_alloc as isize)).type_0 = type_0;
}
unsafe extern "C" fn handle_socket_read(mut socknum: u_int) -> libc::c_int {
    let mut sunaddr: sockaddr_un = sockaddr_un {
        sun_family: 0,
        sun_path: [0; 108],
    };
    let mut slen: socklen_t = 0;
    let mut euid: uid_t = 0;
    let mut egid: gid_t = 0;
    let mut fd: libc::c_int = 0;
    slen = ::core::mem::size_of::<sockaddr_un>() as libc::c_ulong as socklen_t;
    fd = accept(
        (*sockets.offset(socknum as isize)).fd,
        __SOCKADDR_ARG {
            __sockaddr__: &mut sunaddr as *mut sockaddr_un as *mut sockaddr,
        },
        &mut slen,
    );
    if fd == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"handle_socket_read\0"))
                .as_ptr(),
            1742 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"accept from AUTH_SOCKET: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if getpeereid(fd, &mut euid, &mut egid) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"handle_socket_read\0"))
                .as_ptr(),
            1746 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"getpeereid %d failed: %s\0" as *const u8 as *const libc::c_char,
            fd,
            libc::strerror(*libc::__errno_location()),
        );
        close(fd);
        return -(1 as libc::c_int);
    }
    if euid != 0 as libc::c_int as libc::c_uint && libc::getuid() != euid {
        crate::log::sshlog(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"handle_socket_read\0"))
                .as_ptr(),
            1752 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"uid mismatch: peer euid %u != uid %u\0" as *const u8 as *const libc::c_char,
            euid,
            libc::getuid(),
        );
        close(fd);
        return -(1 as libc::c_int);
    }
    new_socket(AUTH_CONNECTION, fd);
    return 0 as libc::c_int;
}
unsafe extern "C" fn handle_conn_read(mut socknum: u_int) -> libc::c_int {
    let mut buf: [libc::c_char; 4096] = [0; 4096];
    let mut len: ssize_t = 0;
    let mut r: libc::c_int = 0;
    len = read(
        (*sockets.offset(socknum as isize)).fd,
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
    );
    if len <= 0 as libc::c_int as libc::c_long {
        if len == -(1 as libc::c_int) as libc::c_long {
            if *libc::__errno_location() == 11 as libc::c_int
                || *libc::__errno_location() == 4 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"handle_conn_read\0"))
                    .as_ptr(),
                1772 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"read error on socket %u (fd %d): %s\0" as *const u8 as *const libc::c_char,
                socknum,
                (*sockets.offset(socknum as isize)).fd,
                libc::strerror(*libc::__errno_location()),
            );
        }
        return -(1 as libc::c_int);
    }
    r = sshbuf_put(
        (*sockets.offset(socknum as isize)).input,
        buf.as_mut_ptr() as *const libc::c_void,
        len as size_t,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"handle_conn_read\0"))
                .as_ptr(),
            1777 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    explicit_bzero(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
    );
    loop {
        r = process_message(socknum);
        if r == -(1 as libc::c_int) {
            return -(1 as libc::c_int);
        } else if r == 0 as libc::c_int {
            break;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn handle_conn_write(mut socknum: u_int) -> libc::c_int {
    let mut len: ssize_t = 0;
    let mut r: libc::c_int = 0;
    if sshbuf_len((*sockets.offset(socknum as isize)).output) == 0 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    len = write(
        (*sockets.offset(socknum as isize)).fd,
        sshbuf_ptr((*sockets.offset(socknum as isize)).output) as *const libc::c_void,
        sshbuf_len((*sockets.offset(socknum as isize)).output),
    );
    if len <= 0 as libc::c_int as libc::c_long {
        if len == -(1 as libc::c_int) as libc::c_long {
            if *libc::__errno_location() == 11 as libc::c_int
                || *libc::__errno_location() == 4 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"handle_conn_write\0"))
                    .as_ptr(),
                1803 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"read error on socket %u (fd %d): %s\0" as *const u8 as *const libc::c_char,
                socknum,
                (*sockets.offset(socknum as isize)).fd,
                libc::strerror(*libc::__errno_location()),
            );
        }
        return -(1 as libc::c_int);
    }
    r = sshbuf_consume((*sockets.offset(socknum as isize)).output, len as size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"handle_conn_write\0"))
                .as_ptr(),
            1808 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"consume\0" as *const u8 as *const libc::c_char,
        );
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn after_poll(mut pfd: *mut pollfd, mut npfd: size_t, mut maxfds: u_int) {
    let mut i: size_t = 0;
    let mut socknum: u_int = 0;
    let mut activefds: u_int = npfd as u_int;
    i = 0 as libc::c_int as size_t;
    while i < npfd {
        if !((*pfd.offset(i as isize)).revents as libc::c_int == 0 as libc::c_int) {
            socknum = 0 as libc::c_int as u_int;
            while socknum < sockets_alloc {
                if !((*sockets.offset(socknum as isize)).type_0 as libc::c_uint
                    != AUTH_SOCKET as libc::c_int as libc::c_uint
                    && (*sockets.offset(socknum as isize)).type_0 as libc::c_uint
                        != AUTH_CONNECTION as libc::c_int as libc::c_uint)
                {
                    if (*pfd.offset(i as isize)).fd == (*sockets.offset(socknum as isize)).fd {
                        break;
                    }
                }
                socknum = socknum.wrapping_add(1);
                socknum;
            }
            if socknum >= sockets_alloc {
                crate::log::sshlog(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"after_poll\0"))
                        .as_ptr(),
                    1830 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"no socket for fd %d\0" as *const u8 as *const libc::c_char,
                    (*pfd.offset(i as isize)).fd,
                );
            } else {
                let mut current_block_10: u64;
                match (*sockets.offset(socknum as isize)).type_0 as libc::c_uint {
                    1 => {
                        if !((*pfd.offset(i as isize)).revents as libc::c_int
                            & (0x1 as libc::c_int | 0x8 as libc::c_int)
                            == 0 as libc::c_int)
                        {
                            if npfd > maxfds as libc::c_ulong {
                                crate::log::sshlog(
                                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                        b"after_poll\0",
                                    ))
                                    .as_ptr(),
                                    1840 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG3,
                                    0 as *const libc::c_char,
                                    b"out of fds (active %u >= limit %u); skipping accept\0"
                                        as *const u8
                                        as *const libc::c_char,
                                    activefds,
                                    maxfds,
                                );
                            } else if handle_socket_read(socknum) == 0 as libc::c_int {
                                activefds = activefds.wrapping_add(1);
                                activefds;
                            }
                        }
                    }
                    2 => {
                        if (*pfd.offset(i as isize)).revents as libc::c_int
                            & (0x1 as libc::c_int | 0x10 as libc::c_int | 0x8 as libc::c_int)
                            != 0 as libc::c_int
                            && handle_conn_read(socknum) != 0 as libc::c_int
                        {
                            current_block_10 = 4240409622418015980;
                        } else if (*pfd.offset(i as isize)).revents as libc::c_int
                            & (0x4 as libc::c_int | 0x10 as libc::c_int)
                            != 0 as libc::c_int
                            && handle_conn_write(socknum) != 0 as libc::c_int
                        {
                            current_block_10 = 4240409622418015980;
                        } else {
                            current_block_10 = 5634871135123216486;
                        }
                        match current_block_10 {
                            5634871135123216486 => {}
                            _ => {
                                if activefds == 0 as libc::c_int as libc::c_uint {
                                    sshfatal(
                                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                            b"after_poll\0",
                                        ))
                                        .as_ptr(),
                                        1854 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_FATAL,
                                        0 as *const libc::c_char,
                                        b"activefds == 0 at close_sock\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                }
                                close_socket(&mut *sockets.offset(socknum as isize));
                                activefds = activefds.wrapping_sub(1);
                                activefds;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn prepare_poll(
    mut pfdp: *mut *mut pollfd,
    mut npfdp: *mut size_t,
    mut timeoutp: *mut libc::c_int,
    mut maxfds: u_int,
) -> libc::c_int {
    let mut pfd: *mut pollfd = *pfdp;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut npfd: size_t = 0 as libc::c_int as size_t;
    let mut deadline: time_t = 0;
    let mut r: libc::c_int = 0;
    i = 0 as libc::c_int as size_t;
    while i < sockets_alloc as libc::c_ulong {
        match (*sockets.offset(i as isize)).type_0 as libc::c_uint {
            1 | 2 => {
                npfd = npfd.wrapping_add(1);
                npfd;
            }
            0 => {}
            _ => {
                sshfatal(
                    b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"prepare_poll\0"))
                        .as_ptr(),
                    1884 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Unknown socket type %d\0" as *const u8 as *const libc::c_char,
                    (*sockets.offset(i as isize)).type_0 as libc::c_uint,
                );
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    if npfd != *npfdp && {
        pfd = recallocarray(
            pfd as *mut libc::c_void,
            *npfdp,
            npfd,
            ::core::mem::size_of::<pollfd>() as libc::c_ulong,
        ) as *mut pollfd;
        pfd.is_null()
    } {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"prepare_poll\0")).as_ptr(),
            1890 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"recallocarray failed\0" as *const u8 as *const libc::c_char,
        );
    }
    *pfdp = pfd;
    *npfdp = npfd;
    j = 0 as libc::c_int as size_t;
    i = j;
    while i < sockets_alloc as libc::c_ulong {
        match (*sockets.offset(i as isize)).type_0 as libc::c_uint {
            1 => {
                if npfd > maxfds as libc::c_ulong {
                    crate::log::sshlog(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"prepare_poll\0",
                        ))
                        .as_ptr(),
                        1899 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"out of fds (active %zu >= limit %u); skipping arming listener\0"
                            as *const u8 as *const libc::c_char,
                        npfd,
                        maxfds,
                    );
                } else {
                    (*pfd.offset(j as isize)).fd = (*sockets.offset(i as isize)).fd;
                    (*pfd.offset(j as isize)).revents = 0 as libc::c_int as libc::c_short;
                    (*pfd.offset(j as isize)).events = 0x1 as libc::c_int as libc::c_short;
                    j = j.wrapping_add(1);
                    j;
                }
            }
            2 => {
                (*pfd.offset(j as isize)).fd = (*sockets.offset(i as isize)).fd;
                (*pfd.offset(j as isize)).revents = 0 as libc::c_int as libc::c_short;
                r = sshbuf_check_reserve(
                    (*sockets.offset(i as isize)).input,
                    4096 as libc::c_int as size_t,
                );
                if r == 0 as libc::c_int && {
                    r = sshbuf_check_reserve(
                        (*sockets.offset(i as isize)).output,
                        (256 as libc::c_int * 1024 as libc::c_int) as size_t,
                    );
                    r == 0 as libc::c_int
                } {
                    (*pfd.offset(j as isize)).events = 0x1 as libc::c_int as libc::c_short;
                } else if r != -(9 as libc::c_int) {
                    sshfatal(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"prepare_poll\0",
                        ))
                        .as_ptr(),
                        1920 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"reserve\0" as *const u8 as *const libc::c_char,
                    );
                }
                if sshbuf_len((*sockets.offset(i as isize)).output)
                    > 0 as libc::c_int as libc::c_ulong
                {
                    let ref mut fresh13 = (*pfd.offset(j as isize)).events;
                    *fresh13 = (*fresh13 as libc::c_int | 0x4 as libc::c_int) as libc::c_short;
                }
                j = j.wrapping_add(1);
                j;
            }
            _ => {}
        }
        i = i.wrapping_add(1);
        i;
    }
    deadline = reaper();
    if parent_alive_interval != 0 as libc::c_int as libc::c_long {
        deadline = if deadline == 0 as libc::c_int as libc::c_long {
            parent_alive_interval
        } else if deadline < parent_alive_interval {
            deadline
        } else {
            parent_alive_interval
        };
    }
    if deadline == 0 as libc::c_int as libc::c_long {
        *timeoutp = -(1 as libc::c_int);
    } else if deadline > (2147483647 as libc::c_int / 1000 as libc::c_int) as libc::c_long {
        *timeoutp = 2147483647 as libc::c_int / 1000 as libc::c_int;
    } else {
        *timeoutp = (deadline * 1000 as libc::c_int as libc::c_long) as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn cleanup_socket() {
    if cleanup_pid != 0 as libc::c_int && libc::getpid() != cleanup_pid {
        return;
    }
    crate::log::sshlog(
        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"cleanup_socket\0")).as_ptr(),
        1949 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"cleanup\0" as *const u8 as *const libc::c_char,
    );
    if socket_name[0 as libc::c_int as usize] != 0 {
        unlink(socket_name.as_mut_ptr());
    }
    if socket_dir[0 as libc::c_int as usize] != 0 {
        rmdir(socket_dir.as_mut_ptr());
    }
}
pub unsafe extern "C" fn cleanup_exit(mut i: libc::c_int) -> ! {
    cleanup_socket();
    libc::_exit(i);
}
unsafe extern "C" fn cleanup_handler(mut _sig: libc::c_int) {
    cleanup_socket();
    pkcs11_terminate();
    libc::_exit(2 as libc::c_int);
}
unsafe extern "C" fn check_parent_exists() {
    if parent_pid != -(1 as libc::c_int) && getppid() != parent_pid {
        cleanup_socket();
        libc::_exit(2 as libc::c_int);
    }
}
unsafe extern "C" fn usage() {
    libc::fprintf(
        stderr,
        b"usage: ssh-agent [-c | -s] [-Dd] [-a bind_address] [-E fingerprint_hash]\n                 [-O option] [-P allowed_providers] [-t life]\n       ssh-agent [-a bind_address] [-E fingerprint_hash] [-O option]\n                 [-P allowed_providers] [-t life] command [arg ...]\n       ssh-agent [-c | -s] -k\n\0"
            as *const u8 as *const libc::c_char,
    );
    libc::exit(1 as libc::c_int);
}
unsafe fn main_0(mut ac: libc::c_int, mut av: *mut *mut libc::c_char) -> libc::c_int {
    let mut c_flag: libc::c_int = 0 as libc::c_int;
    let mut d_flag: libc::c_int = 0 as libc::c_int;
    let mut D_flag: libc::c_int = 0 as libc::c_int;
    let mut k_flag: libc::c_int = 0 as libc::c_int;
    let mut s_flag: libc::c_int = 0 as libc::c_int;
    let mut sock: libc::c_int = 0;
    let mut ch: libc::c_int = 0;
    let mut result: libc::c_int = 0;
    let mut saved_errno: libc::c_int = 0;
    let mut shell: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut format: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pidstr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut agentsocket: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut rlim: rlimit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptarg"]
        static mut BSDoptarg_0: *mut libc::c_char;
    }
    let mut pid: pid_t = 0;
    let mut pidstrbuf: [libc::c_char; 13] = [0; 13];
    let mut len: size_t = 0;
    let mut prev_mask: mode_t = 0;
    let mut timeout: libc::c_int = -(1 as libc::c_int);
    let mut pfd: *mut pollfd = 0 as *mut pollfd;
    let mut npfd: size_t = 0 as libc::c_int as size_t;
    let mut maxfds: u_int = 0;
    crate::misc::sanitise_stdfd();
    setegid(getgid());
    setgid(getgid());
    platform_disable_tracing(0 as libc::c_int);
    if getrlimit(RLIMIT_NOFILE, &mut rlim) == -(1 as libc::c_int) {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2030 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: getrlimit: %s\0" as *const u8 as *const libc::c_char,
            __progname,
            libc::strerror(*libc::__errno_location()),
        );
    }
    __progname =
        crate::openbsd_compat::bsd_misc::ssh_get_progname(*av.offset(0 as libc::c_int as isize));
    seed_rng();
    loop {
        ch = crate::openbsd_compat::getopt_long::BSDgetopt(
            ac,
            av,
            b"cDdksE:a:O:P:t:\0" as *const u8 as *const libc::c_char,
        );
        if !(ch != -(1 as libc::c_int)) {
            break;
        }
        match ch {
            69 => {
                fingerprint_hash = ssh_digest_alg_by_name(BSDoptarg);
                if fingerprint_hash == -(1 as libc::c_int) {
                    sshfatal(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        2041 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Invalid hash algorithm \"%s\"\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                    );
                }
            }
            99 => {
                if s_flag != 0 {
                    usage();
                }
                c_flag += 1;
                c_flag;
            }
            107 => {
                k_flag += 1;
                k_flag;
            }
            79 => {
                if libc::strcmp(
                    BSDoptarg,
                    b"no-restrict-websafe\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
                {
                    restrict_websafe = 0 as libc::c_int;
                } else {
                    sshfatal(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        2055 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Unknown -O option\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            80 => {
                if !allowed_providers.is_null() {
                    sshfatal(
                        b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        2059 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"-P option already specified\0" as *const u8 as *const libc::c_char,
                    );
                }
                allowed_providers = crate::xmalloc::xstrdup(BSDoptarg);
            }
            115 => {
                if c_flag != 0 {
                    usage();
                }
                s_flag += 1;
                s_flag;
            }
            100 => {
                if d_flag != 0 || D_flag != 0 {
                    usage();
                }
                d_flag += 1;
                d_flag;
            }
            68 => {
                if d_flag != 0 || D_flag != 0 {
                    usage();
                }
                D_flag += 1;
                D_flag;
            }
            97 => {
                agentsocket = BSDoptarg;
            }
            116 => {
                lifetime = convtime(BSDoptarg);
                if lifetime == -(1 as libc::c_int) {
                    libc::fprintf(
                        stderr,
                        b"Invalid lifetime\n\0" as *const u8 as *const libc::c_char,
                    );
                    usage();
                }
            }
            _ => {
                usage();
            }
        }
    }
    ac -= BSDoptind;
    av = av.offset(BSDoptind as isize);
    if ac > 0 as libc::c_int
        && (c_flag != 0 || k_flag != 0 || s_flag != 0 || d_flag != 0 || D_flag != 0)
    {
        usage();
    }
    if allowed_providers.is_null() {
        allowed_providers = crate::xmalloc::xstrdup(
            b"/usr/lib*/*,/usr/local/lib*/*\0" as *const u8 as *const libc::c_char,
        );
    }
    if ac == 0 as libc::c_int && c_flag == 0 && s_flag == 0 {
        shell = getenv(b"SHELL\0" as *const u8 as *const libc::c_char);
        if !shell.is_null()
            && {
                len = strlen(shell);
                len > 2 as libc::c_int as libc::c_ulong
            }
            && strncmp(
                shell
                    .offset(len as isize)
                    .offset(-(3 as libc::c_int as isize)),
                b"csh\0" as *const u8 as *const libc::c_char,
                3 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
        {
            c_flag = 1 as libc::c_int;
        }
    }
    if k_flag != 0 {
        let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
        pidstr = getenv(b"SSH_AGENT_PID\0" as *const u8 as *const libc::c_char);
        if pidstr.is_null() {
            libc::fprintf(
                stderr,
                b"%s not set, cannot kill agent\n\0" as *const u8 as *const libc::c_char,
                b"SSH_AGENT_PID\0" as *const u8 as *const libc::c_char,
            );
            libc::exit(1 as libc::c_int);
        }
        pid = crate::openbsd_compat::strtonum::strtonum(
            pidstr,
            2 as libc::c_int as libc::c_longlong,
            2147483647 as libc::c_int as libc::c_longlong,
            &mut errstr,
        ) as libc::c_int;
        if !errstr.is_null() {
            libc::fprintf(
                stderr,
                b"%s=\"%s\", which is not a good PID: %s\n\0" as *const u8 as *const libc::c_char,
                b"SSH_AGENT_PID\0" as *const u8 as *const libc::c_char,
                pidstr,
                errstr,
            );
            libc::exit(1 as libc::c_int);
        }
        if kill(pid, 15 as libc::c_int) == -(1 as libc::c_int) {
            libc::perror(b"kill\0" as *const u8 as *const libc::c_char);
            libc::exit(1 as libc::c_int);
        }
        format = (if c_flag != 0 {
            b"unsetenv %s;\n\0" as *const u8 as *const libc::c_char
        } else {
            b"unset %s;\n\0" as *const u8 as *const libc::c_char
        }) as *mut libc::c_char;
        printf(
            format,
            b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char,
        );
        printf(
            format,
            b"SSH_AGENT_PID\0" as *const u8 as *const libc::c_char,
        );
        printf(
            b"echo Agent pid %ld killed;\n\0" as *const u8 as *const libc::c_char,
            pid as libc::c_long,
        );
        libc::exit(0 as libc::c_int);
    }
    if rlim.rlim_cur
        < (3 as libc::c_int
            + 1 as libc::c_int
            + 1 as libc::c_int
            + 1 as libc::c_int
            + 4 as libc::c_int) as libc::c_ulong
    {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2140 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: file descriptor rlimit %lld too low (minimum %u)\0" as *const u8
                as *const libc::c_char,
            __progname,
            rlim.rlim_cur as libc::c_longlong,
            3 as libc::c_int
                + 1 as libc::c_int
                + 1 as libc::c_int
                + 1 as libc::c_int
                + 4 as libc::c_int,
        );
    }
    maxfds = (rlim.rlim_cur).wrapping_sub(
        (3 as libc::c_int
            + 1 as libc::c_int
            + 1 as libc::c_int
            + 1 as libc::c_int
            + 4 as libc::c_int) as libc::c_ulong,
    ) as u_int;
    parent_pid = libc::getpid();
    if agentsocket.is_null() {
        mktemp_proto(
            socket_dir.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        );
        if (mkdtemp(socket_dir.as_mut_ptr())).is_null() {
            libc::perror(b"mkdtemp: private socket dir\0" as *const u8 as *const libc::c_char);
            libc::exit(1 as libc::c_int);
        }
        libc::snprintf(
            socket_name.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 4096]>() as usize,
            b"%s/agent.%ld\0" as *const u8 as *const libc::c_char,
            socket_dir.as_mut_ptr(),
            parent_pid as libc::c_long,
        );
    } else {
        socket_dir[0 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
        strlcpy(
            socket_name.as_mut_ptr(),
            agentsocket,
            ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        );
    }
    prev_mask = libc::umask(0o177 as libc::c_int as __mode_t);
    sock = unix_listener(
        socket_name.as_mut_ptr(),
        128 as libc::c_int,
        0 as libc::c_int,
    );
    if sock < 0 as libc::c_int {
        *socket_name.as_mut_ptr() = '\0' as i32 as libc::c_char;
        cleanup_exit(1 as libc::c_int);
    }
    libc::umask(prev_mask);
    if D_flag != 0 || d_flag != 0 {
        log_init(
            __progname,
            (if d_flag != 0 {
                SYSLOG_LEVEL_DEBUG3 as libc::c_int
            } else {
                SYSLOG_LEVEL_INFO as libc::c_int
            }) as LogLevel,
            SYSLOG_FACILITY_AUTH,
            1 as libc::c_int,
        );
        format = (if c_flag != 0 {
            b"setenv %s %s;\n\0" as *const u8 as *const libc::c_char
        } else {
            b"%s=%s; export %s;\n\0" as *const u8 as *const libc::c_char
        }) as *mut libc::c_char;
        printf(
            format,
            b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char,
            socket_name.as_mut_ptr(),
            b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char,
        );
        printf(
            b"echo Agent pid %ld;\n\0" as *const u8 as *const libc::c_char,
            parent_pid as libc::c_long,
        );
        libc::fflush(stdout);
    } else {
        pid = libc::fork();
        if pid == -(1 as libc::c_int) {
            libc::perror(b"libc::fork\0" as *const u8 as *const libc::c_char);
            cleanup_exit(1 as libc::c_int);
        }
        if pid != 0 as libc::c_int {
            close(sock);
            libc::snprintf(
                pidstrbuf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 13]>() as usize,
                b"%ld\0" as *const u8 as *const libc::c_char,
                pid as libc::c_long,
            );
            if ac == 0 as libc::c_int {
                format = (if c_flag != 0 {
                    b"setenv %s %s;\n\0" as *const u8 as *const libc::c_char
                } else {
                    b"%s=%s; export %s;\n\0" as *const u8 as *const libc::c_char
                }) as *mut libc::c_char;
                printf(
                    format,
                    b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char,
                    socket_name.as_mut_ptr(),
                    b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char,
                );
                printf(
                    format,
                    b"SSH_AGENT_PID\0" as *const u8 as *const libc::c_char,
                    pidstrbuf.as_mut_ptr(),
                    b"SSH_AGENT_PID\0" as *const u8 as *const libc::c_char,
                );
                printf(
                    b"echo Agent pid %ld;\n\0" as *const u8 as *const libc::c_char,
                    pid as libc::c_long,
                );
                libc::exit(0 as libc::c_int);
            }
            if setenv(
                b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char,
                socket_name.as_mut_ptr(),
                1 as libc::c_int,
            ) == -(1 as libc::c_int)
                || setenv(
                    b"SSH_AGENT_PID\0" as *const u8 as *const libc::c_char,
                    pidstrbuf.as_mut_ptr(),
                    1 as libc::c_int,
                ) == -(1 as libc::c_int)
            {
                libc::perror(b"setenv\0" as *const u8 as *const libc::c_char);
                libc::exit(1 as libc::c_int);
            }
            libc::execvp(
                *av.offset(0 as libc::c_int as isize),
                av as *const *const libc::c_char,
            );
            libc::perror(*av.offset(0 as libc::c_int as isize));
            libc::exit(1 as libc::c_int);
        }
        log_init(
            __progname,
            SYSLOG_LEVEL_INFO,
            SYSLOG_FACILITY_AUTH,
            0 as libc::c_int,
        );
        if setsid() == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2218 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"setsid: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
            cleanup_exit(1 as libc::c_int);
        }
        chdir(b"/\0" as *const u8 as *const libc::c_char);
        if stdfd_devnull(1 as libc::c_int, 1 as libc::c_int, 1 as libc::c_int)
            == -(1 as libc::c_int)
        {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2224 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"stdfd_devnull failed\0" as *const u8 as *const libc::c_char,
            );
        }
        rlim.rlim_max = 0 as libc::c_int as rlim_t;
        rlim.rlim_cur = rlim.rlim_max;
        if setrlimit(RLIMIT_CORE, &mut rlim) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2230 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"setrlimit RLIMIT_CORE: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
            cleanup_exit(1 as libc::c_int);
        }
    }
    cleanup_pid = libc::getpid();
    pkcs11_init(0 as libc::c_int);
    new_socket(AUTH_SOCKET, sock);
    if ac > 0 as libc::c_int {
        parent_alive_interval = 10 as libc::c_int as time_t;
    }
    idtab_init();
    crate::misc::ssh_signal(
        13 as libc::c_int,
        ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
            1 as libc::c_int as libc::intptr_t,
        ),
    );
    crate::misc::ssh_signal(
        2 as libc::c_int,
        if d_flag | D_flag != 0 {
            Some(cleanup_handler as unsafe extern "C" fn(libc::c_int) -> ())
        } else {
            ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
                1 as libc::c_int as libc::intptr_t,
            )
        },
    );
    crate::misc::ssh_signal(
        1 as libc::c_int,
        Some(cleanup_handler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    crate::misc::ssh_signal(
        15 as libc::c_int,
        Some(cleanup_handler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    if crate::openbsd_compat::bsd_misc::pledge(
        b"stdio rpath cpath unix id proc exec\0" as *const u8 as *const libc::c_char,
        0 as *mut *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2252 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: crate::openbsd_compat::bsd_misc::pledge: %s\0" as *const u8
                as *const libc::c_char,
            __progname,
            libc::strerror(*libc::__errno_location()),
        );
    }
    platform_pledge_agent();
    loop {
        prepare_poll(&mut pfd, &mut npfd, &mut timeout, maxfds);
        result = poll(pfd, npfd, timeout);
        saved_errno = *libc::__errno_location();
        if parent_alive_interval != 0 as libc::c_int as libc::c_long {
            check_parent_exists();
        }
        reaper();
        if result == -(1 as libc::c_int) {
            if saved_errno == 4 as libc::c_int {
                continue;
            }
            sshfatal(
                b"ssh-agent.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2265 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"poll: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(saved_errno),
            );
        } else if result > 0 as libc::c_int {
            after_poll(pfd, npfd, maxfds);
        }
    }
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
