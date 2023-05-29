use crate::kex::dh_st;
use crate::kex::kex;
use crate::packet::key_entry;

use crate::packet::ssh;

use crate::atomicio::atomicio;

use ::libc;
use libc::close;
use libc::kill;

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

    pub type ec_group_st;

    pub type bignum_st;

    fn getpeername(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __len: *mut socklen_t)
        -> libc::c_int;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn pipe(__pipedes: *mut libc::c_int) -> libc::c_int;

    fn setproctitle(fmt: *const libc::c_char, _: ...);
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: libc::c_int) -> libc::c_int;
    fn timingsafe_bcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;
    fn freezero(_: *mut libc::c_void, _: size_t);

    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;

    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;
    fn DH_get0_pqg(
        dh: *const DH,
        p: *mut *const BIGNUM,
        q: *mut *const BIGNUM,
        g: *mut *const BIGNUM,
    );
    fn DH_free(dh: *mut DH);

    fn sshkey_type_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_ssh_name(_: *const crate::sshkey::sshkey) -> *const libc::c_char;
    fn sshkey_from_blob(
        _: *const u_char,
        _: size_t,
        _: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_froms(
        _: *mut crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_to_blob(
        _: *const crate::sshkey::sshkey,
        _: *mut *mut u_char,
        _: *mut size_t,
    ) -> libc::c_int;
    fn sshkey_puts(_: *const crate::sshkey::sshkey, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshkey_sign(
        _: *mut crate::sshkey::sshkey,
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
        _: *const crate::sshkey::sshkey,
        _: *const u_char,
        _: size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: u_int,
        _: *mut *mut sshkey_sig_details,
    ) -> libc::c_int;
    fn sshkey_sig_details_free(_: *mut sshkey_sig_details);

    fn sshbuf_reserve(
        buf: *mut crate::sshbuf::sshbuf,
        len: size_t,
        dpp: *mut *mut u_char,
    ) -> libc::c_int;
    fn sshbuf_consume(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;

    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_get_string_direct(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_bignum2(buf: *mut crate::sshbuf::sshbuf, v: *const BIGNUM) -> libc::c_int;
    fn get_hostkey_private_by_type(
        _: libc::c_int,
        _: libc::c_int,
        _: *mut ssh,
    ) -> *mut crate::sshkey::sshkey;
    fn auth_password(_: *mut ssh, _: *const libc::c_char) -> libc::c_int;
    fn hostbased_key_allowed(
        _: *mut ssh,
        _: *mut libc::passwd,
        _: *const libc::c_char,
        _: *mut libc::c_char,
        _: *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn user_key_allowed(
        ssh: *mut ssh,
        _: *mut libc::passwd,
        _: *mut crate::sshkey::sshkey,
        _: libc::c_int,
        _: *mut *mut sshauthopt,
    ) -> libc::c_int;
    fn auth2_key_already_used(_: *mut Authctxt, _: *const crate::sshkey::sshkey) -> libc::c_int;
    fn auth2_authctxt_reset_info(_: *mut Authctxt);
    fn auth2_record_key(_: *mut Authctxt, _: libc::c_int, _: *const crate::sshkey::sshkey);
    fn auth2_record_info(authctxt_0: *mut Authctxt, _: *const libc::c_char, _: ...);
    fn auth2_update_session_info(_: *mut Authctxt, _: *const libc::c_char, _: *const libc::c_char);
    fn auth_log(
        _: *mut ssh,
        _: libc::c_int,
        _: libc::c_int,
        _: *const libc::c_char,
        _: *const libc::c_char,
    );
    fn auth_root_allowed(_: *mut ssh, _: *const libc::c_char) -> libc::c_int;
    fn auth2_read_banner() -> *mut libc::c_char;
    fn auth2_update_methods_lists(
        _: *mut Authctxt,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn auth2_setup_methods_lists(_: *mut Authctxt) -> libc::c_int;
    fn getpwnamallow(_: *mut ssh, user: *const libc::c_char) -> *mut libc::passwd;
    fn get_hostkey_by_index(_: libc::c_int) -> *mut crate::sshkey::sshkey;
    fn get_hostkey_public_by_index(_: libc::c_int, _: *mut ssh) -> *mut crate::sshkey::sshkey;
    fn get_hostkey_public_by_type(
        _: libc::c_int,
        _: libc::c_int,
        _: *mut ssh,
    ) -> *mut crate::sshkey::sshkey;
    fn get_hostkey_index(_: *mut crate::sshkey::sshkey, _: libc::c_int, _: *mut ssh)
        -> libc::c_int;
    fn sshd_hostkey_sign(
        _: *mut ssh,
        _: *mut crate::sshkey::sshkey,
        _: *mut crate::sshkey::sshkey,
        _: *mut *mut u_char,
        _: *mut size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn auth_activate_options(_: *mut ssh, _: *mut sshauthopt) -> libc::c_int;
    fn fakepw() -> *mut libc::passwd;
    fn kexgex_server(_: *mut ssh) -> libc::c_int;
    fn kex_gen_server(_: *mut ssh) -> libc::c_int;
    fn choose_dh(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> *mut DH;
    fn ssh_packet_get_connection_in(_: *mut ssh) -> libc::c_int;
    fn ssh_clear_newkeys(_: *mut ssh, _: libc::c_int);

    fn ssh_packet_connection_is_on_socket(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_set_state(_: *mut ssh, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn ssh_remote_ipaddr(_: *mut ssh) -> *const libc::c_char;
    fn ssh_remote_port(_: *mut ssh) -> libc::c_int;
    fn sshauthopt_free(opts: *mut sshauthopt);
    fn sshauthopt_serialise(
        opts: *const sshauthopt,
        m: *mut crate::sshbuf::sshbuf,
        _: libc::c_int,
    ) -> libc::c_int;
    fn pty_allocate(
        _: *mut libc::c_int,
        _: *mut libc::c_int,
        _: *mut libc::c_char,
        _: size_t,
    ) -> libc::c_int;
    fn pty_setowner(_: *mut libc::passwd, _: *const libc::c_char);
    fn session_unused(_: libc::c_int);
    fn session_destroy_all(_: *mut ssh, _: Option<unsafe extern "C" fn(*mut Session) -> ()>);
    fn session_pty_cleanup2(_: *mut Session);
    fn session_new() -> *mut Session;
    fn session_by_tty(_: *mut libc::c_char) -> *mut Session;
    fn session_get_remote_name_or_ip(_: *mut ssh, _: u_int, _: libc::c_int) -> *const libc::c_char;
    fn record_login(
        _: pid_t,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: uid_t,
        _: *const libc::c_char,
        _: *mut sockaddr,
        _: socklen_t,
    );
    fn log_level_name(_: LogLevel) -> *const libc::c_char;
    fn cleanup_exit(_: libc::c_int) -> !;

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
    fn sshlogdirect(_: LogLevel, _: libc::c_int, _: *const libc::c_char, _: ...);
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;

    fn mm_request_send(_: libc::c_int, _: monitor_reqtype, _: *mut crate::sshbuf::sshbuf);
    fn mm_request_receive(_: libc::c_int, _: *mut crate::sshbuf::sshbuf);
    fn mm_request_receive_expect(_: libc::c_int, _: monitor_reqtype, _: *mut crate::sshbuf::sshbuf);
    fn mm_send_fd(_: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn ssh_agent_sign(
        sock: libc::c_int,
        key: *const crate::sshkey::sshkey,
        sigp: *mut *mut u_char,
        lenp: *mut size_t,
        data: *const u_char,
        datalen: size_t,
        alg: *const libc::c_char,
        compat: u_int,
    ) -> libc::c_int;
    static mut options: ServerOptions;
    static mut utmp_len: u_int;
    static mut loginmsg: *mut crate::sshbuf::sshbuf;
    static mut auth_opts: *mut sshauthopt;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __mode_t = libc::c_uint;
pub type __pid_t = libc::c_int;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type uid_t = __uid_t;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
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
pub type uint64_t = __uint64_t;

pub type sig_atomic_t = __sig_atomic_t;
pub type __sighandler_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
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
pub struct C2RustUnnamed_0 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub tqe_next: *mut key_entry,
    pub tqe_prev: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
pub type dispatch_fn = unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int;

pub type DH = dh_st;

pub type BIGNUM = bignum_st;
pub type sshkey_fp_rep = libc::c_uint;
pub const SSH_FP_RANDOMART: sshkey_fp_rep = 4;
pub const SSH_FP_BUBBLEBABBLE: sshkey_fp_rep = 3;
pub const SSH_FP_BASE64: sshkey_fp_rep = 2;
pub const SSH_FP_HEX: sshkey_fp_rep = 1;
pub const SSH_FP_DEFAULT: sshkey_fp_rep = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_sig_details {
    pub sk_counter: uint32_t,
    pub sk_flags: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshauthopt {
    pub permit_port_forwarding_flag: libc::c_int,
    pub permit_agent_forwarding_flag: libc::c_int,
    pub permit_x11_forwarding_flag: libc::c_int,
    pub permit_pty_flag: libc::c_int,
    pub permit_user_rc: libc::c_int,
    pub restricted: libc::c_int,
    pub valid_before: uint64_t,
    pub cert_authority: libc::c_int,
    pub cert_principals: *mut libc::c_char,
    pub force_tun_device: libc::c_int,
    pub force_command: *mut libc::c_char,
    pub nenv: size_t,
    pub env: *mut *mut libc::c_char,
    pub npermitopen: size_t,
    pub permitopen: *mut *mut libc::c_char,
    pub npermitlisten: size_t,
    pub permitlisten: *mut *mut libc::c_char,
    pub required_from_host_cert: *mut libc::c_char,
    pub required_from_host_keys: *mut libc::c_char,
    pub no_require_user_presence: libc::c_int,
    pub require_verify: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Authctxt {
    pub success: sig_atomic_t,
    pub authenticated: libc::c_int,
    pub postponed: libc::c_int,
    pub valid: libc::c_int,
    pub attempt: libc::c_int,
    pub failures: libc::c_int,
    pub server_caused_failure: libc::c_int,
    pub force_pwchange: libc::c_int,
    pub user: *mut libc::c_char,
    pub service: *mut libc::c_char,
    pub pw: *mut libc::passwd,
    pub style: *mut libc::c_char,
    pub auth_methods: *mut *mut libc::c_char,
    pub num_auth_methods: u_int,
    pub methoddata: *mut libc::c_void,
    pub kbdintctxt: *mut libc::c_void,
    pub loginmsg: *mut crate::sshbuf::sshbuf,
    pub prev_keys: *mut *mut crate::sshkey::sshkey,
    pub nprev_keys: u_int,
    pub auth_method_key: *mut crate::sshkey::sshkey,
    pub auth_method_info: *mut libc::c_char,
    pub session_info: *mut crate::sshbuf::sshbuf,
}
pub type kex_modes = libc::c_uint;
pub const MODE_MAX: kex_modes = 2;
pub const MODE_OUT: kex_modes = 1;
pub const MODE_IN: kex_modes = 0;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ForwardOptions {
    pub gateway_ports: libc::c_int,
    pub streamlocal_bind_mask: mode_t,
    pub streamlocal_bind_unlink: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Session {
    pub used: libc::c_int,
    pub self_0: libc::c_int,
    pub next_unused: libc::c_int,
    pub pw: *mut libc::passwd,
    pub authctxt: *mut Authctxt,
    pub pid: pid_t,
    pub forced: libc::c_int,
    pub term: *mut libc::c_char,
    pub ptyfd: libc::c_int,
    pub ttyfd: libc::c_int,
    pub ptymaster: libc::c_int,
    pub row: u_int,
    pub col: u_int,
    pub xpixel: u_int,
    pub ypixel: u_int,
    pub tty: [libc::c_char; 64],
    pub display_number: u_int,
    pub display: *mut libc::c_char,
    pub screen: u_int,
    pub auth_display: *mut libc::c_char,
    pub auth_proto: *mut libc::c_char,
    pub auth_data: *mut libc::c_char,
    pub single_connection: libc::c_int,
    pub chanid: libc::c_int,
    pub x11_chanids: *mut libc::c_int,
    pub is_subsystem: libc::c_int,
    pub subsys: *mut libc::c_char,
    pub num_env: u_int,
    pub env: *mut C2RustUnnamed_3,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
    pub name: *mut libc::c_char,
    pub val: *mut libc::c_char,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct queued_listenaddr {
    pub addr: *mut libc::c_char,
    pub port: libc::c_int,
    pub rdomain: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct listenaddr {
    pub rdomain: *mut libc::c_char,
    pub addrs: *mut addrinfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ServerOptions {
    pub num_ports: u_int,
    pub ports_from_cmdline: u_int,
    pub ports: [libc::c_int; 256],
    pub queued_listen_addrs: *mut queued_listenaddr,
    pub num_queued_listens: u_int,
    pub listen_addrs: *mut listenaddr,
    pub num_listen_addrs: u_int,
    pub address_family: libc::c_int,
    pub routing_domain: *mut libc::c_char,
    pub host_key_files: *mut *mut libc::c_char,
    pub host_key_file_userprovided: *mut libc::c_int,
    pub num_host_key_files: u_int,
    pub host_cert_files: *mut *mut libc::c_char,
    pub num_host_cert_files: u_int,
    pub host_key_agent: *mut libc::c_char,
    pub pid_file: *mut libc::c_char,
    pub moduli_file: *mut libc::c_char,
    pub login_grace_time: libc::c_int,
    pub permit_root_login: libc::c_int,
    pub ignore_rhosts: libc::c_int,
    pub ignore_user_known_hosts: libc::c_int,
    pub print_motd: libc::c_int,
    pub print_lastlog: libc::c_int,
    pub x11_forwarding: libc::c_int,
    pub x11_display_offset: libc::c_int,
    pub x11_use_localhost: libc::c_int,
    pub xauth_location: *mut libc::c_char,
    pub permit_tty: libc::c_int,
    pub permit_user_rc: libc::c_int,
    pub strict_modes: libc::c_int,
    pub tcp_keep_alive: libc::c_int,
    pub ip_qos_interactive: libc::c_int,
    pub ip_qos_bulk: libc::c_int,
    pub ciphers: *mut libc::c_char,
    pub macs: *mut libc::c_char,
    pub kex_algorithms: *mut libc::c_char,
    pub fwd_opts: ForwardOptions,
    pub log_facility: SyslogFacility,
    pub log_level: LogLevel,
    pub num_log_verbose: u_int,
    pub log_verbose: *mut *mut libc::c_char,
    pub hostbased_authentication: libc::c_int,
    pub hostbased_uses_name_from_packet_only: libc::c_int,
    pub hostbased_accepted_algos: *mut libc::c_char,
    pub hostkeyalgorithms: *mut libc::c_char,
    pub ca_sign_algorithms: *mut libc::c_char,
    pub pubkey_authentication: libc::c_int,
    pub pubkey_accepted_algos: *mut libc::c_char,
    pub pubkey_auth_options: libc::c_int,
    pub kerberos_authentication: libc::c_int,
    pub kerberos_or_local_passwd: libc::c_int,
    pub kerberos_ticket_cleanup: libc::c_int,
    pub kerberos_get_afs_token: libc::c_int,
    pub gss_authentication: libc::c_int,
    pub gss_cleanup_creds: libc::c_int,
    pub gss_strict_acceptor: libc::c_int,
    pub password_authentication: libc::c_int,
    pub kbd_interactive_authentication: libc::c_int,
    pub permit_empty_passwd: libc::c_int,
    pub permit_user_env: libc::c_int,
    pub permit_user_env_allowlist: *mut libc::c_char,
    pub compression: libc::c_int,
    pub allow_tcp_forwarding: libc::c_int,
    pub allow_streamlocal_forwarding: libc::c_int,
    pub allow_agent_forwarding: libc::c_int,
    pub disable_forwarding: libc::c_int,
    pub num_allow_users: u_int,
    pub allow_users: *mut *mut libc::c_char,
    pub num_deny_users: u_int,
    pub deny_users: *mut *mut libc::c_char,
    pub num_allow_groups: u_int,
    pub allow_groups: *mut *mut libc::c_char,
    pub num_deny_groups: u_int,
    pub deny_groups: *mut *mut libc::c_char,
    pub num_subsystems: u_int,
    pub subsystem_name: [*mut libc::c_char; 256],
    pub subsystem_command: [*mut libc::c_char; 256],
    pub subsystem_args: [*mut libc::c_char; 256],
    pub num_accept_env: u_int,
    pub accept_env: *mut *mut libc::c_char,
    pub num_setenv: u_int,
    pub setenv: *mut *mut libc::c_char,
    pub max_startups_begin: libc::c_int,
    pub max_startups_rate: libc::c_int,
    pub max_startups: libc::c_int,
    pub per_source_max_startups: libc::c_int,
    pub per_source_masklen_ipv4: libc::c_int,
    pub per_source_masklen_ipv6: libc::c_int,
    pub max_authtries: libc::c_int,
    pub max_sessions: libc::c_int,
    pub banner: *mut libc::c_char,
    pub use_dns: libc::c_int,
    pub client_alive_interval: libc::c_int,
    pub client_alive_count_max: libc::c_int,
    pub num_authkeys_files: u_int,
    pub authorized_keys_files: *mut *mut libc::c_char,
    pub adm_forced_command: *mut libc::c_char,
    pub use_pam: libc::c_int,
    pub permit_tun: libc::c_int,
    pub permitted_opens: *mut *mut libc::c_char,
    pub num_permitted_opens: u_int,
    pub permitted_listens: *mut *mut libc::c_char,
    pub num_permitted_listens: u_int,
    pub chroot_directory: *mut libc::c_char,
    pub revoked_keys_file: *mut libc::c_char,
    pub trusted_user_ca_keys: *mut libc::c_char,
    pub authorized_keys_command: *mut libc::c_char,
    pub authorized_keys_command_user: *mut libc::c_char,
    pub authorized_principals_file: *mut libc::c_char,
    pub authorized_principals_command: *mut libc::c_char,
    pub authorized_principals_command_user: *mut libc::c_char,
    pub rekey_limit: int64_t,
    pub rekey_interval: libc::c_int,
    pub version_addendum: *mut libc::c_char,
    pub num_auth_methods: u_int,
    pub auth_methods: *mut *mut libc::c_char,
    pub fingerprint_hash: libc::c_int,
    pub expose_userauth_info: libc::c_int,
    pub timing_secret: u_int64_t,
    pub sk_provider: *mut libc::c_char,
    pub required_rsa_size: libc::c_int,
    pub channel_timeouts: *mut *mut libc::c_char,
    pub num_channel_timeouts: u_int,
    pub unused_connection_timeout: libc::c_int,
}
pub type monitor_reqtype = libc::c_uint;
pub const MONITOR_REQ_AUDIT_COMMAND: monitor_reqtype = 113;
pub const MONITOR_REQ_AUDIT_EVENT: monitor_reqtype = 112;
pub const MONITOR_ANS_PAM_FREE_CTX: monitor_reqtype = 111;
pub const MONITOR_REQ_PAM_FREE_CTX: monitor_reqtype = 110;
pub const MONITOR_ANS_PAM_RESPOND: monitor_reqtype = 109;
pub const MONITOR_REQ_PAM_RESPOND: monitor_reqtype = 108;
pub const MONITOR_ANS_PAM_QUERY: monitor_reqtype = 107;
pub const MONITOR_REQ_PAM_QUERY: monitor_reqtype = 106;
pub const MONITOR_ANS_PAM_INIT_CTX: monitor_reqtype = 105;
pub const MONITOR_REQ_PAM_INIT_CTX: monitor_reqtype = 104;
pub const MONITOR_ANS_PAM_ACCOUNT: monitor_reqtype = 103;
pub const MONITOR_REQ_PAM_ACCOUNT: monitor_reqtype = 102;
pub const MONITOR_REQ_PAM_START: monitor_reqtype = 100;
pub const MONITOR_REQ_TERM: monitor_reqtype = 50;
pub const MONITOR_ANS_GSSCHECKMIC: monitor_reqtype = 49;
pub const MONITOR_REQ_GSSCHECKMIC: monitor_reqtype = 48;
pub const MONITOR_ANS_GSSUSEROK: monitor_reqtype = 47;
pub const MONITOR_REQ_GSSUSEROK: monitor_reqtype = 46;
pub const MONITOR_ANS_GSSSTEP: monitor_reqtype = 45;
pub const MONITOR_REQ_GSSSTEP: monitor_reqtype = 44;
pub const MONITOR_ANS_GSSSETUP: monitor_reqtype = 43;
pub const MONITOR_REQ_GSSSETUP: monitor_reqtype = 42;
pub const MONITOR_ANS_RSARESPONSE: monitor_reqtype = 41;
pub const MONITOR_REQ_RSARESPONSE: monitor_reqtype = 40;
pub const MONITOR_ANS_RSACHALLENGE: monitor_reqtype = 39;
pub const MONITOR_REQ_RSACHALLENGE: monitor_reqtype = 38;
pub const MONITOR_ANS_RSAKEYALLOWED: monitor_reqtype = 37;
pub const MONITOR_REQ_RSAKEYALLOWED: monitor_reqtype = 36;
pub const MONITOR_REQ_SESSID: monitor_reqtype = 34;
pub const MONITOR_ANS_SESSKEY: monitor_reqtype = 33;
pub const MONITOR_REQ_SESSKEY: monitor_reqtype = 32;
pub const MONITOR_REQ_PTYCLEANUP: monitor_reqtype = 30;
pub const MONITOR_ANS_PTY: monitor_reqtype = 29;
pub const MONITOR_REQ_PTY: monitor_reqtype = 28;
pub const MONITOR_REQ_KEYEXPORT: monitor_reqtype = 26;
pub const MONITOR_ANS_KEYVERIFY: monitor_reqtype = 25;
pub const MONITOR_REQ_KEYVERIFY: monitor_reqtype = 24;
pub const MONITOR_ANS_KEYALLOWED: monitor_reqtype = 23;
pub const MONITOR_REQ_KEYALLOWED: monitor_reqtype = 22;
pub const MONITOR_ANS_BSDAUTHRESPOND: monitor_reqtype = 17;
pub const MONITOR_REQ_BSDAUTHRESPOND: monitor_reqtype = 16;
pub const MONITOR_ANS_BSDAUTHQUERY: monitor_reqtype = 15;
pub const MONITOR_REQ_BSDAUTHQUERY: monitor_reqtype = 14;
pub const MONITOR_ANS_AUTHPASSWORD: monitor_reqtype = 13;
pub const MONITOR_REQ_AUTHPASSWORD: monitor_reqtype = 12;
pub const MONITOR_ANS_AUTH2_READ_BANNER: monitor_reqtype = 11;
pub const MONITOR_REQ_AUTH2_READ_BANNER: monitor_reqtype = 10;
pub const MONITOR_ANS_PWNAM: monitor_reqtype = 9;
pub const MONITOR_REQ_PWNAM: monitor_reqtype = 8;
pub const MONITOR_ANS_SIGN: monitor_reqtype = 7;
pub const MONITOR_REQ_SIGN: monitor_reqtype = 6;
pub const MONITOR_REQ_AUTHSERV: monitor_reqtype = 4;
pub const MONITOR_REQ_FREE: monitor_reqtype = 2;
pub const MONITOR_ANS_MODULI: monitor_reqtype = 1;
pub const MONITOR_REQ_MODULI: monitor_reqtype = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct monitor {
    pub m_recvfd: libc::c_int,
    pub m_sendfd: libc::c_int,
    pub m_log_recvfd: libc::c_int,
    pub m_log_sendfd: libc::c_int,
    pub m_pkex: *mut *mut kex,
    pub m_pid: pid_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mon_table {
    pub type_0: monitor_reqtype,
    pub flags: libc::c_int,
    pub f: Option<
        unsafe extern "C" fn(*mut ssh, libc::c_int, *mut crate::sshbuf::sshbuf) -> libc::c_int,
    >,
}
pub const MM_NOKEY: mm_keytype = 0;
pub const MM_USERKEY: mm_keytype = 2;
pub const MM_HOSTKEY: mm_keytype = 1;
pub type mm_keytype = libc::c_uint;
static mut child_state: *mut crate::sshbuf::sshbuf =
    0 as *const crate::sshbuf::sshbuf as *mut crate::sshbuf::sshbuf;
static mut authctxt: *mut Authctxt = 0 as *const Authctxt as *mut Authctxt;
static mut key_blob: *mut u_char = 0 as *const u_char as *mut u_char;
static mut key_bloblen: size_t = 0 as libc::c_int as size_t;
static mut key_blobtype: u_int = MM_NOKEY as libc::c_int as u_int;
static mut key_opts: *mut sshauthopt = 0 as *const sshauthopt as *mut sshauthopt;
static mut hostbased_cuser: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut hostbased_chost: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut auth_method: *mut libc::c_char =
    b"unknown\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
static mut auth_submethod: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut session_id2_len: u_int = 0 as libc::c_int as u_int;
static mut session_id2: *mut u_char = 0 as *const u_char as *mut u_char;
static mut monitor_child_pid: pid_t = 0;
pub static mut mon_dispatch_proto20: [mon_table; 9] = unsafe {
    [
        {
            let mut init = mon_table {
                type_0: MONITOR_REQ_MODULI,
                flags: 0x10 as libc::c_int,
                f: Some(
                    mm_answer_moduli
                        as unsafe extern "C" fn(
                            *mut ssh,
                            libc::c_int,
                            *mut crate::sshbuf::sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = mon_table {
                type_0: MONITOR_REQ_SIGN,
                flags: 0x10 as libc::c_int,
                f: Some(
                    mm_answer_sign
                        as unsafe extern "C" fn(
                            *mut ssh,
                            libc::c_int,
                            *mut crate::sshbuf::sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = mon_table {
                type_0: MONITOR_REQ_PWNAM,
                flags: 0x10 as libc::c_int,
                f: Some(
                    mm_answer_pwnamallow
                        as unsafe extern "C" fn(
                            *mut ssh,
                            libc::c_int,
                            *mut crate::sshbuf::sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = mon_table {
                type_0: MONITOR_REQ_AUTHSERV,
                flags: 0x10 as libc::c_int,
                f: Some(
                    mm_answer_authserv
                        as unsafe extern "C" fn(
                            *mut ssh,
                            libc::c_int,
                            *mut crate::sshbuf::sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = mon_table {
                type_0: MONITOR_REQ_AUTH2_READ_BANNER,
                flags: 0x10 as libc::c_int,
                f: Some(
                    mm_answer_auth2_read_banner
                        as unsafe extern "C" fn(
                            *mut ssh,
                            libc::c_int,
                            *mut crate::sshbuf::sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = mon_table {
                type_0: MONITOR_REQ_AUTHPASSWORD,
                flags: 0x4 as libc::c_int | 0x8 as libc::c_int,
                f: Some(
                    mm_answer_authpassword
                        as unsafe extern "C" fn(
                            *mut ssh,
                            libc::c_int,
                            *mut crate::sshbuf::sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = mon_table {
                type_0: MONITOR_REQ_KEYALLOWED,
                flags: 0x4 as libc::c_int,
                f: Some(
                    mm_answer_keyallowed
                        as unsafe extern "C" fn(
                            *mut ssh,
                            libc::c_int,
                            *mut crate::sshbuf::sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = mon_table {
                type_0: MONITOR_REQ_KEYVERIFY,
                flags: 0x4 as libc::c_int | 0x8 as libc::c_int,
                f: Some(
                    mm_answer_keyverify
                        as unsafe extern "C" fn(
                            *mut ssh,
                            libc::c_int,
                            *mut crate::sshbuf::sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = mon_table {
                type_0: MONITOR_REQ_MODULI,
                flags: 0 as libc::c_int,
                f: None,
            };
            init
        },
    ]
};
pub static mut mon_dispatch: *mut mon_table = 0 as *const mon_table as *mut mon_table;
unsafe extern "C" fn monitor_permit(
    mut ent: *mut mon_table,
    mut type_0: monitor_reqtype,
    mut permit: libc::c_int,
) {
    while ((*ent).f).is_some() {
        if (*ent).type_0 as libc::c_uint == type_0 as libc::c_uint {
            (*ent).flags &= !(0x1000 as libc::c_int);
            (*ent).flags |= if permit != 0 {
                0x1000 as libc::c_int
            } else {
                0 as libc::c_int
            };
            return;
        }
        ent = ent.offset(1);
        ent;
    }
}
unsafe extern "C" fn monitor_permit_authentications(mut permit: libc::c_int) {
    let mut ent: *mut mon_table = mon_dispatch;
    while ((*ent).f).is_some() {
        if (*ent).flags & (0x4 as libc::c_int | 0x8 as libc::c_int) != 0 {
            (*ent).flags &= !(0x1000 as libc::c_int);
            (*ent).flags |= if permit != 0 {
                0x1000 as libc::c_int
            } else {
                0 as libc::c_int
            };
        }
        ent = ent.offset(1);
        ent;
    }
}
pub unsafe extern "C" fn monitor_child_preauth(mut ssh: *mut ssh, mut pmonitor: *mut monitor) {
    let mut ent: *mut mon_table = 0 as *mut mon_table;
    let mut authenticated: libc::c_int = 0 as libc::c_int;
    let mut partial: libc::c_int = 0 as libc::c_int;
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"monitor_child_preauth\0"))
            .as_ptr(),
        272 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"preauth child monitor started\0" as *const u8 as *const libc::c_char,
    );
    if (*pmonitor).m_recvfd >= 0 as libc::c_int {
        close((*pmonitor).m_recvfd);
    }
    if (*pmonitor).m_log_sendfd >= 0 as libc::c_int {
        close((*pmonitor).m_log_sendfd);
    }
    (*pmonitor).m_recvfd = -(1 as libc::c_int);
    (*pmonitor).m_log_sendfd = (*pmonitor).m_recvfd;
    authctxt = (*ssh).authctxt as *mut Authctxt;
    memset(
        authctxt as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<Authctxt>() as libc::c_ulong,
    );
    (*ssh).authctxt = authctxt as *mut libc::c_void;
    (*authctxt).loginmsg = loginmsg;
    mon_dispatch = mon_dispatch_proto20.as_mut_ptr();
    monitor_permit(mon_dispatch, MONITOR_REQ_MODULI, 1 as libc::c_int);
    monitor_permit(mon_dispatch, MONITOR_REQ_SIGN, 1 as libc::c_int);
    while authenticated == 0 {
        partial = 0 as libc::c_int;
        auth_method = b"unknown\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        auth_submethod = 0 as *mut libc::c_char;
        auth2_authctxt_reset_info(authctxt);
        authenticated = (monitor_read(ssh, pmonitor, mon_dispatch, &mut ent) == 1 as libc::c_int)
            as libc::c_int;
        if options.num_auth_methods != 0 as libc::c_int as libc::c_uint {
            if authenticated != 0
                && auth2_update_methods_lists(authctxt, auth_method, auth_submethod) == 0
            {
                crate::log::sshlog(
                    b"monitor.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"monitor_child_preauth\0",
                    ))
                    .as_ptr(),
                    306 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"method %s: partial\0" as *const u8 as *const libc::c_char,
                    auth_method,
                );
                authenticated = 0 as libc::c_int;
                partial = 1 as libc::c_int;
            }
        }
        if authenticated != 0 {
            if (*ent).flags & 0x8 as libc::c_int == 0 {
                sshfatal(
                    b"monitor.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"monitor_child_preauth\0",
                    ))
                    .as_ptr(),
                    315 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"unexpected authentication from %d\0" as *const u8 as *const libc::c_char,
                    (*ent).type_0 as libc::c_uint,
                );
            }
            if (*(*authctxt).pw).pw_uid == 0 as libc::c_int as libc::c_uint
                && auth_root_allowed(ssh, auth_method) == 0
            {
                authenticated = 0 as libc::c_int;
            }
        }
        if (*ent).flags & (0x8 as libc::c_int | 0x20 as libc::c_int) != 0 {
            auth_log(ssh, authenticated, partial, auth_method, auth_submethod);
            if partial == 0 && authenticated == 0 {
                (*authctxt).failures += 1;
                (*authctxt).failures;
            }
            if authenticated != 0 || partial != 0 {
                auth2_update_session_info(authctxt, auth_method, auth_submethod);
            }
        }
    }
    if (*authctxt).valid == 0 {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"monitor_child_preauth\0"))
                .as_ptr(),
            348 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"authenticated invalid user\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::strcmp(
        auth_method,
        b"unknown\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"monitor_child_preauth\0"))
                .as_ptr(),
            350 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"authentication method name unknown\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"monitor_child_preauth\0"))
            .as_ptr(),
        352 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"user %s authenticated by privileged process\0" as *const u8 as *const libc::c_char,
        (*authctxt).user,
    );
    (*ssh).authctxt = 0 as *mut libc::c_void;
    crate::packet::ssh_packet_set_log_preamble(
        ssh,
        b"user %s\0" as *const u8 as *const libc::c_char,
        (*authctxt).user,
    );
    mm_get_keystate(ssh, pmonitor);
    while (*pmonitor).m_log_recvfd != -(1 as libc::c_int)
        && monitor_read_log(pmonitor) == 0 as libc::c_int
    {}
    if (*pmonitor).m_recvfd >= 0 as libc::c_int {
        close((*pmonitor).m_recvfd);
    }
    if (*pmonitor).m_log_sendfd >= 0 as libc::c_int {
        close((*pmonitor).m_log_sendfd);
    }
    (*pmonitor).m_log_recvfd = -(1 as libc::c_int);
    (*pmonitor).m_sendfd = (*pmonitor).m_log_recvfd;
}
unsafe extern "C" fn monitor_set_child_handler(mut pid: pid_t) {
    monitor_child_pid = pid;
}
unsafe extern "C" fn monitor_child_handler(mut sig: libc::c_int) {
    kill(monitor_child_pid, sig);
}
unsafe extern "C" fn monitor_read_log(mut pmonitor: *mut monitor) -> libc::c_int {
    let mut logmsg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut len: u_int = 0;
    let mut level: u_int = 0;
    let mut forced: u_int = 0;
    let mut msg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    logmsg = crate::sshbuf::sshbuf_new();
    if logmsg.is_null() {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"monitor_read_log\0"))
                .as_ptr(),
            421 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_reserve(logmsg, 4 as libc::c_int as size_t, &mut p);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"monitor_read_log\0"))
                .as_ptr(),
            425 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"reserve len\0" as *const u8 as *const libc::c_char,
        );
    }
    if atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        (*pmonitor).m_log_recvfd,
        p as *mut libc::c_void,
        4 as libc::c_int as size_t,
    ) != 4 as libc::c_int as libc::c_ulong
    {
        if *libc::__errno_location() == 32 as libc::c_int {
            crate::sshbuf::sshbuf_free(logmsg);
            crate::log::sshlog(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"monitor_read_log\0"))
                    .as_ptr(),
                429 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"child log fd closed\0" as *const u8 as *const libc::c_char,
            );
            close((*pmonitor).m_log_recvfd);
            (*pmonitor).m_log_recvfd = -(1 as libc::c_int);
            return -(1 as libc::c_int);
        }
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"monitor_read_log\0"))
                .as_ptr(),
            434 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"log fd read: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_u32(logmsg, &mut len);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"monitor_read_log\0"))
                .as_ptr(),
            437 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse len\0" as *const u8 as *const libc::c_char,
        );
    }
    if len <= 4 as libc::c_int as libc::c_uint || len > 8192 as libc::c_int as libc::c_uint {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"monitor_read_log\0"))
                .as_ptr(),
            439 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"invalid log message length %u\0" as *const u8 as *const libc::c_char,
            len,
        );
    }
    crate::sshbuf::sshbuf_reset(logmsg);
    r = sshbuf_reserve(logmsg, len as size_t, &mut p);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"monitor_read_log\0"))
                .as_ptr(),
            444 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"reserve msg\0" as *const u8 as *const libc::c_char,
        );
    }
    if atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        (*pmonitor).m_log_recvfd,
        p as *mut libc::c_void,
        len as size_t,
    ) != len as libc::c_ulong
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"monitor_read_log\0"))
                .as_ptr(),
            446 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"log fd read: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_u32(logmsg, &mut level);
    if r != 0 as libc::c_int
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(logmsg, &mut forced);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_cstring(logmsg, &mut msg, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"monitor_read_log\0"))
                .as_ptr(),
            450 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if (log_level_name(level as LogLevel)).is_null() {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"monitor_read_log\0"))
                .as_ptr(),
            454 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"invalid log level %u (corrupted message?)\0" as *const u8 as *const libc::c_char,
            level,
        );
    }
    sshlogdirect(
        level as LogLevel,
        forced as libc::c_int,
        b"%s [preauth]\0" as *const u8 as *const libc::c_char,
        msg,
    );
    crate::sshbuf::sshbuf_free(logmsg);
    libc::free(msg as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn monitor_read(
    mut ssh: *mut ssh,
    mut pmonitor: *mut monitor,
    mut ent: *mut mon_table,
    mut pent: *mut *mut mon_table,
) -> libc::c_int {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut type_0: u_char = 0;
    let mut pfd: [pollfd; 2] = [pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    }; 2];
    loop {
        memset(
            &mut pfd as *mut [pollfd; 2] as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<[pollfd; 2]>() as libc::c_ulong,
        );
        pfd[0 as libc::c_int as usize].fd = (*pmonitor).m_sendfd;
        pfd[0 as libc::c_int as usize].events = 0x1 as libc::c_int as libc::c_short;
        pfd[1 as libc::c_int as usize].fd = (*pmonitor).m_log_recvfd;
        pfd[1 as libc::c_int as usize].events =
            (if pfd[1 as libc::c_int as usize].fd == -(1 as libc::c_int) {
                0 as libc::c_int
            } else {
                0x1 as libc::c_int
            }) as libc::c_short;
        if poll(
            pfd.as_mut_ptr(),
            (if pfd[1 as libc::c_int as usize].fd == -(1 as libc::c_int) {
                1 as libc::c_int
            } else {
                2 as libc::c_int
            }) as nfds_t,
            -(1 as libc::c_int),
        ) == -(1 as libc::c_int)
        {
            if *libc::__errno_location() == 4 as libc::c_int
                || *libc::__errno_location() == 11 as libc::c_int
            {
                continue;
            }
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"monitor_read\0"))
                    .as_ptr(),
                481 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"poll: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        } else if pfd[1 as libc::c_int as usize].revents != 0 {
            monitor_read_log(pmonitor);
        } else if pfd[0 as libc::c_int as usize].revents != 0 {
            break;
        }
    }
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"monitor_read\0")).as_ptr(),
            496 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_receive((*pmonitor).m_sendfd, m);
    r = crate::sshbuf_getput_basic::sshbuf_get_u8(m, &mut type_0);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"monitor_read\0")).as_ptr(),
            500 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse type\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"monitor_read\0")).as_ptr(),
        502 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"checking request %d\0" as *const u8 as *const libc::c_char,
        type_0 as libc::c_int,
    );
    while ((*ent).f).is_some() {
        if (*ent).type_0 as libc::c_uint == type_0 as libc::c_uint {
            break;
        }
        ent = ent.offset(1);
        ent;
    }
    if ((*ent).f).is_some() {
        if (*ent).flags & 0x1000 as libc::c_int == 0 {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"monitor_read\0"))
                    .as_ptr(),
                512 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unpermitted request %d\0" as *const u8 as *const libc::c_char,
                type_0 as libc::c_int,
            );
        }
        ret = (Some(((*ent).f).expect("non-null function pointer")))
            .expect("non-null function pointer")(ssh, (*pmonitor).m_sendfd, m);
        crate::sshbuf::sshbuf_free(m);
        if (*ent).flags & 0x10 as libc::c_int != 0 {
            crate::log::sshlog(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"monitor_read\0"))
                    .as_ptr(),
                518 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"%d used once, disabling now\0" as *const u8 as *const libc::c_char,
                type_0 as libc::c_int,
            );
            (*ent).flags &= !(0x1000 as libc::c_int);
        }
        if !pent.is_null() {
            *pent = ent;
        }
        return ret;
    }
    sshfatal(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"monitor_read\0")).as_ptr(),
        528 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_FATAL,
        0 as *const libc::c_char,
        b"unsupported request: %d\0" as *const u8 as *const libc::c_char,
        type_0 as libc::c_int,
    );
}
unsafe extern "C" fn monitor_allowed_key(
    mut blob: *const u_char,
    mut bloblen: u_int,
) -> libc::c_int {
    if key_blob.is_null()
        || key_bloblen != bloblen as libc::c_ulong
        || timingsafe_bcmp(
            key_blob as *const libc::c_void,
            blob as *const libc::c_void,
            key_bloblen,
        ) != 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn monitor_reset_key_state() {
    libc::free(key_blob as *mut libc::c_void);
    libc::free(hostbased_cuser as *mut libc::c_void);
    libc::free(hostbased_chost as *mut libc::c_void);
    sshauthopt_free(key_opts);
    key_blob = 0 as *mut u_char;
    key_bloblen = 0 as libc::c_int as size_t;
    key_blobtype = MM_NOKEY as libc::c_int as u_int;
    key_opts = 0 as *mut sshauthopt;
    hostbased_cuser = 0 as *mut libc::c_char;
    hostbased_chost = 0 as *mut libc::c_char;
}
pub unsafe extern "C" fn mm_answer_moduli(
    mut _ssh: *mut ssh,
    mut sock: libc::c_int,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut dh: *mut DH = 0 as *mut DH;
    let mut dh_p: *const BIGNUM = 0 as *const BIGNUM;
    let mut dh_g: *const BIGNUM = 0 as *const BIGNUM;
    let mut r: libc::c_int = 0;
    let mut min: u_int = 0;
    let mut want: u_int = 0;
    let mut max: u_int = 0;
    r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut min);
    if r != 0 as libc::c_int
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut want);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut max);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_answer_moduli\0"))
                .as_ptr(),
            573 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_answer_moduli\0")).as_ptr(),
        575 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"got parameters: %d %d %d\0" as *const u8 as *const libc::c_char,
        min,
        want,
        max,
    );
    if max < min || want < min || max < want {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_answer_moduli\0"))
                .as_ptr(),
            578 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"bad parameters: %d %d %d\0" as *const u8 as *const libc::c_char,
            min,
            want,
            max,
        );
    }
    crate::sshbuf::sshbuf_reset(m);
    dh = choose_dh(min as libc::c_int, want as libc::c_int, max as libc::c_int);
    if dh.is_null() {
        r = crate::sshbuf_getput_basic::sshbuf_put_u8(m, 0 as libc::c_int as u_char);
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_answer_moduli\0"))
                    .as_ptr(),
                585 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble empty\0" as *const u8 as *const libc::c_char,
            );
        }
        return 0 as libc::c_int;
    } else {
        DH_get0_pqg(dh, &mut dh_p, 0 as *mut *const BIGNUM, &mut dh_g);
        r = crate::sshbuf_getput_basic::sshbuf_put_u8(m, 1 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshbuf_put_bignum2(m, dh_p);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_bignum2(m, dh_g);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_answer_moduli\0"))
                    .as_ptr(),
                593 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble\0" as *const u8 as *const libc::c_char,
            );
        }
        DH_free(dh);
    }
    mm_request_send(sock, MONITOR_ANS_MODULI, m);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn mm_answer_sign(
    mut ssh: *mut ssh,
    mut sock: libc::c_int,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    extern "C" {
        static mut auth_sock: libc::c_int;
    }
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut sigbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut signature: *mut u_char = 0 as *mut u_char;
    let mut alg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut datlen: size_t = 0;
    let mut siglen: size_t = 0;
    let mut alglen: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut is_proof: libc::c_int = 0 as libc::c_int;
    let mut keyid: u_int = 0;
    let mut compat: u_int = 0;
    let proof_req: [libc::c_char; 30] = *::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
        b"hostkeys-prove-00@openssh.com\0",
    );
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_answer_sign\0")).as_ptr(),
        615 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut keyid);
    if r != 0 as libc::c_int
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_string(m, &mut p, &mut datlen);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_cstring(m, &mut alg, &mut alglen);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut compat);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_answer_sign\0"))
                .as_ptr(),
            621 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if keyid > 2147483647 as libc::c_int as libc::c_uint {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_answer_sign\0"))
                .as_ptr(),
            623 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"invalid key ID\0" as *const u8 as *const libc::c_char,
        );
    }
    if datlen != 20 as libc::c_int as libc::c_ulong
        && datlen != 32 as libc::c_int as libc::c_ulong
        && datlen != 48 as libc::c_int as libc::c_ulong
        && datlen != 64 as libc::c_int as libc::c_ulong
    {
        if session_id2_len == 0 as libc::c_int as libc::c_uint {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_answer_sign\0"))
                    .as_ptr(),
                642 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"bad data length: %zu\0" as *const u8 as *const libc::c_char,
                datlen,
            );
        }
        key = get_hostkey_public_by_index(keyid as libc::c_int, ssh);
        if key.is_null() {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_answer_sign\0"))
                    .as_ptr(),
                644 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"no hostkey for index %d\0" as *const u8 as *const libc::c_char,
                keyid,
            );
        }
        sigbuf = crate::sshbuf::sshbuf_new();
        if sigbuf.is_null() {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_answer_sign\0"))
                    .as_ptr(),
                646 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::crate::sshbuf::sshbuf::sshbuf_new\0" as *const u8 as *const libc::c_char,
            );
        }
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(sigbuf, proof_req.as_ptr());
        if r != 0 as libc::c_int
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_string(
                    sigbuf,
                    session_id2 as *const libc::c_void,
                    session_id2_len as size_t,
                );
                r != 0 as libc::c_int
            }
            || {
                r = sshkey_puts(key, sigbuf);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_answer_sign\0"))
                    .as_ptr(),
                651 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble private key proof\0" as *const u8 as *const libc::c_char,
            );
        }
        if datlen != crate::sshbuf::sshbuf_len(sigbuf)
            || memcmp(
                p as *const libc::c_void,
                crate::sshbuf::sshbuf_ptr(sigbuf) as *const libc::c_void,
                crate::sshbuf::sshbuf_len(sigbuf),
            ) != 0 as libc::c_int
        {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_answer_sign\0"))
                    .as_ptr(),
                655 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"bad data length: %zu, hostkey proof len %zu\0" as *const u8
                    as *const libc::c_char,
                datlen,
                crate::sshbuf::sshbuf_len(sigbuf),
            );
        }
        crate::sshbuf::sshbuf_free(sigbuf);
        is_proof = 1 as libc::c_int;
    }
    if session_id2_len == 0 as libc::c_int as libc::c_uint {
        session_id2_len = datlen as u_int;
        session_id2 = crate::xmalloc::xmalloc(session_id2_len as size_t) as *mut u_char;
        memcpy(
            session_id2 as *mut libc::c_void,
            p as *const libc::c_void,
            session_id2_len as libc::c_ulong,
        );
    }
    key = get_hostkey_by_index(keyid as libc::c_int);
    if !key.is_null() {
        r = sshkey_sign(
            key,
            &mut signature,
            &mut siglen,
            p,
            datlen,
            alg,
            options.sk_provider,
            0 as *const libc::c_char,
            compat,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_answer_sign\0"))
                    .as_ptr(),
                670 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"sign\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        key = get_hostkey_public_by_index(keyid as libc::c_int, ssh);
        if !key.is_null() && auth_sock > 0 as libc::c_int {
            r = ssh_agent_sign(
                auth_sock,
                key,
                &mut signature,
                &mut siglen,
                p,
                datlen,
                alg,
                compat,
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"monitor.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"mm_answer_sign\0",
                    ))
                    .as_ptr(),
                    675 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"agent sign\0" as *const u8 as *const libc::c_char,
                );
            }
        } else {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_answer_sign\0"))
                    .as_ptr(),
                677 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"no hostkey from index %d\0" as *const u8 as *const libc::c_char,
                keyid,
            );
        }
    }
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_answer_sign\0")).as_ptr(),
        680 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s %s signature len=%zu\0" as *const u8 as *const libc::c_char,
        alg,
        if is_proof != 0 {
            b"hostkey proof\0" as *const u8 as *const libc::c_char
        } else {
            b"KEX\0" as *const u8 as *const libc::c_char
        },
        siglen,
    );
    crate::sshbuf::sshbuf_reset(m);
    r = crate::sshbuf_getput_basic::sshbuf_put_string(m, signature as *const libc::c_void, siglen);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_answer_sign\0"))
                .as_ptr(),
            684 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    libc::free(alg as *mut libc::c_void);
    libc::free(p as *mut libc::c_void);
    libc::free(signature as *mut libc::c_void);
    mm_request_send(sock, MONITOR_ANS_SIGN, m);
    monitor_permit(mon_dispatch, MONITOR_REQ_PWNAM, 1 as libc::c_int);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn mm_answer_pwnamallow(
    mut ssh: *mut ssh,
    mut sock: libc::c_int,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut pwent: *mut libc::passwd = 0 as *mut libc::passwd;
    let mut r: libc::c_int = 0;
    let mut allowed: libc::c_int = 0 as libc::c_int;
    let mut i: u_int = 0;
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
            .as_ptr(),
        713 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    let fresh0 = (*authctxt).attempt;
    (*authctxt).attempt = (*authctxt).attempt + 1;
    if fresh0 != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            716 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"multiple attempts for getpwnam\0" as *const u8 as *const libc::c_char,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_cstring(m, &mut (*authctxt).user, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            719 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    pwent = getpwnamallow(ssh, (*authctxt).user);
    setproctitle(
        b"%s [priv]\0" as *const u8 as *const libc::c_char,
        if !pwent.is_null() {
            (*authctxt).user as *const libc::c_char
        } else {
            b"unknown\0" as *const u8 as *const libc::c_char
        },
    );
    crate::sshbuf::sshbuf_reset(m);
    if pwent.is_null() {
        r = crate::sshbuf_getput_basic::sshbuf_put_u8(m, 0 as libc::c_int as u_char);
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                729 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble fakepw\0" as *const u8 as *const libc::c_char,
            );
        }
        (*authctxt).pw = fakepw();
    } else {
        allowed = 1 as libc::c_int;
        (*authctxt).pw = pwent;
        (*authctxt).valid = 1 as libc::c_int;
        r = crate::sshbuf_getput_basic::sshbuf_put_u8(m, 1 as libc::c_int as u_char);
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                740 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble ok\0" as *const u8 as *const libc::c_char,
            );
        }
        r = crate::sshbuf_getput_basic::sshbuf_put_string(
            m,
            &mut (*pwent).pw_uid as *mut __uid_t as *const libc::c_void,
            ::core::mem::size_of::<__uid_t>() as libc::c_ulong,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                741 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"pw_uid\0" as *const u8 as *const libc::c_char,
            );
        }
        r = crate::sshbuf_getput_basic::sshbuf_put_string(
            m,
            &mut (*pwent).pw_gid as *mut __gid_t as *const libc::c_void,
            ::core::mem::size_of::<__gid_t>() as libc::c_ulong,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                742 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"pw_gid\0" as *const u8 as *const libc::c_char,
            );
        }
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, (*pwent).pw_name);
        if r != 0 as libc::c_int
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
                    m,
                    b"*\0" as *const u8 as *const libc::c_char,
                );
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, (*pwent).pw_gecos);
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, (*pwent).pw_dir);
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, (*pwent).pw_shell);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                759 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble pw\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    crate::packet::ssh_packet_set_log_preamble(
        ssh,
        b"%suser %s\0" as *const u8 as *const libc::c_char,
        if (*authctxt).valid != 0 {
            b"authenticating\0" as *const u8 as *const libc::c_char
        } else {
            b"invalid \0" as *const u8 as *const libc::c_char
        },
        (*authctxt).user,
    );
    r = crate::sshbuf_getput_basic::sshbuf_put_string(
        m,
        &mut options as *mut ServerOptions as *const libc::c_void,
        ::core::mem::size_of::<ServerOptions>() as libc::c_ulong,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            765 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble options\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.banner).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, options.banner);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"banner\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.trusted_user_ca_keys).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, options.trusted_user_ca_keys);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"trusted_user_ca_keys\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.revoked_keys_file).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, options.revoked_keys_file);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"revoked_keys_file\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.authorized_keys_command).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, options.authorized_keys_command);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"authorized_keys_command\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.authorized_keys_command_user).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, options.authorized_keys_command_user);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"authorized_keys_command_user\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.authorized_principals_file).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, options.authorized_principals_file);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"authorized_principals_file\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.authorized_principals_command).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            options.authorized_principals_command,
        );
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"authorized_principals_command\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.authorized_principals_command_user).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            options.authorized_principals_command_user,
        );
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"authorized_principals_command_user\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.hostbased_accepted_algos).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, options.hostbased_accepted_algos);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"hostbased_accepted_algos\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.pubkey_accepted_algos).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, options.pubkey_accepted_algos);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"pubkey_accepted_algos\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.ca_sign_algorithms).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, options.ca_sign_algorithms);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"ca_sign_algorithms\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.routing_domain).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, options.routing_domain);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"routing_domain\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.permit_user_env_allowlist).is_null() && {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, options.permit_user_env_allowlist);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            779 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble %s\0" as *const u8 as *const libc::c_char,
            b"permit_user_env_allowlist\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_authkeys_files {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            *(options.authorized_keys_files).offset(i as isize),
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"authorized_keys_files\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_allow_users {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            *(options.allow_users).offset(i as isize),
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"allow_users\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_deny_users {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            *(options.deny_users).offset(i as isize),
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"deny_users\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_allow_groups {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            *(options.allow_groups).offset(i as isize),
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"allow_groups\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_deny_groups {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            *(options.deny_groups).offset(i as isize),
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"deny_groups\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_accept_env {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            *(options.accept_env).offset(i as isize),
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"accept_env\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_setenv {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, *(options.setenv).offset(i as isize));
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"setenv\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_auth_methods {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            *(options.auth_methods).offset(i as isize),
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"auth_methods\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_permitted_opens {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            *(options.permitted_opens).offset(i as isize),
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"permitted_opens\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_permitted_listens {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            *(options.permitted_listens).offset(i as isize),
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"permitted_listens\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_channel_timeouts {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            *(options.channel_timeouts).offset(i as isize),
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"channel_timeouts\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_log_verbose {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
            m,
            *(options.log_verbose).offset(i as isize),
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_pwnamallow\0",
                ))
                .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble %s\0" as *const u8 as *const libc::c_char,
                b"log_verbose\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    if auth2_setup_methods_lists(authctxt) != 0 as libc::c_int {
        crate::log::sshlog(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
                .as_ptr(),
            790 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"no valid authentication method lists\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_pwnamallow\0"))
            .as_ptr(),
        793 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"sending MONITOR_ANS_PWNAM: %d\0" as *const u8 as *const libc::c_char,
        allowed,
    );
    mm_request_send(sock, MONITOR_ANS_PWNAM, m);
    monitor_permit(mon_dispatch, MONITOR_REQ_AUTHSERV, 1 as libc::c_int);
    monitor_permit(
        mon_dispatch,
        MONITOR_REQ_AUTH2_READ_BANNER,
        1 as libc::c_int,
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn mm_answer_auth2_read_banner(
    mut _ssh: *mut ssh,
    mut sock: libc::c_int,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut banner: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    crate::sshbuf::sshbuf_reset(m);
    banner = auth2_read_banner();
    r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
        m,
        if !banner.is_null() {
            banner as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"mm_answer_auth2_read_banner\0",
            ))
            .as_ptr(),
            816 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send(sock, MONITOR_ANS_AUTH2_READ_BANNER, m);
    libc::free(banner as *mut libc::c_void);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn mm_answer_authserv(
    mut _ssh: *mut ssh,
    mut _sock: libc::c_int,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    monitor_permit_authentications(1 as libc::c_int);
    r = crate::sshbuf_getput_basic::sshbuf_get_cstring(
        m,
        &mut (*authctxt).service,
        0 as *mut size_t,
    );
    if r != 0 as libc::c_int || {
        r = crate::sshbuf_getput_basic::sshbuf_get_cstring(
            m,
            &mut (*authctxt).style,
            0 as *mut size_t,
        );
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_answer_authserv\0"))
                .as_ptr(),
            832 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_answer_authserv\0"))
            .as_ptr(),
        833 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"service=%s, style=%s\0" as *const u8 as *const libc::c_char,
        (*authctxt).service,
        (*authctxt).style,
    );
    if strlen((*authctxt).style) == 0 as libc::c_int as libc::c_ulong {
        libc::free((*authctxt).style as *mut libc::c_void);
        (*authctxt).style = 0 as *mut libc::c_char;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn key_base_type_match(
    mut method: *const libc::c_char,
    mut key: *const crate::sshkey::sshkey,
    mut list: *const libc::c_char,
) -> libc::c_int {
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut l: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ol: *mut libc::c_char = crate::xmalloc::xstrdup(list);
    let mut found: libc::c_int = 0 as libc::c_int;
    l = ol;
    s = strsep(&mut l, b",\0" as *const u8 as *const libc::c_char);
    while !s.is_null() && *s as libc::c_int != '\0' as i32 {
        if sshkey_type_from_name(s) == (*key).type_0 {
            found = 1 as libc::c_int;
            break;
        } else {
            s = strsep(&mut l, b",\0" as *const u8 as *const libc::c_char);
        }
    }
    if found == 0 {
        crate::log::sshlog(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"key_base_type_match\0"))
                .as_ptr(),
            865 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s key type %s is not in permitted list %s\0" as *const u8 as *const libc::c_char,
            method,
            sshkey_ssh_name(key),
            list,
        );
    }
    libc::free(ol as *mut libc::c_void);
    return found;
}
pub unsafe extern "C" fn mm_answer_authpassword(
    mut ssh: *mut ssh,
    mut sock: libc::c_int,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    static mut call_count: libc::c_int = 0;
    let mut passwd: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut authenticated: libc::c_int = 0;
    let mut plen: size_t = 0;
    if options.password_authentication == 0 {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"mm_answer_authpassword\0",
            ))
            .as_ptr(),
            881 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"password authentication not enabled\0" as *const u8 as *const libc::c_char,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_cstring(m, &mut passwd, &mut plen);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"mm_answer_authpassword\0",
            ))
            .as_ptr(),
            883 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    authenticated =
        (options.password_authentication != 0 && auth_password(ssh, passwd) != 0) as libc::c_int;
    freezero(passwd as *mut libc::c_void, plen);
    crate::sshbuf::sshbuf_reset(m);
    r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, authenticated as u_int32_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"mm_answer_authpassword\0",
            ))
            .as_ptr(),
            891 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"mm_answer_authpassword\0"))
            .as_ptr(),
        897 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s: sending result %d\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"mm_answer_authpassword\0"))
            .as_ptr(),
        authenticated,
    );
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"mm_answer_authpassword\0"))
            .as_ptr(),
        898 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"sending result %d\0" as *const u8 as *const libc::c_char,
        authenticated,
    );
    mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);
    call_count += 1;
    call_count;
    if plen == 0 as libc::c_int as libc::c_ulong && call_count == 1 as libc::c_int {
        auth_method = b"none\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    } else {
        auth_method = b"password\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    return authenticated;
}
pub unsafe extern "C" fn mm_answer_keyallowed(
    mut ssh: *mut ssh,
    mut sock: libc::c_int,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut cuser: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut chost: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pubkey_auth_attempt: u_int = 0;
    let mut type_0: u_int = 0 as libc::c_int as u_int;
    let mut r: libc::c_int = 0;
    let mut allowed: libc::c_int = 0 as libc::c_int;
    let mut opts: *mut sshauthopt = 0 as *mut sshauthopt;
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_keyallowed\0"))
            .as_ptr(),
        1156 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut type_0);
    if r != 0 as libc::c_int
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_cstring(m, &mut cuser, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_cstring(m, &mut chost, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshkey_froms(m, &mut key);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut pubkey_auth_attempt);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_keyallowed\0"))
                .as_ptr(),
            1162 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if !key.is_null() && (*authctxt).valid != 0 {
        match type_0 {
            2 => {
                auth_method =
                    b"publickey\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
                if !(options.pubkey_authentication == 0) {
                    if !(auth2_key_already_used(authctxt, key) != 0) {
                        if !(key_base_type_match(auth_method, key, options.pubkey_accepted_algos)
                            == 0)
                        {
                            allowed = user_key_allowed(
                                ssh,
                                (*authctxt).pw,
                                key,
                                pubkey_auth_attempt as libc::c_int,
                                &mut opts,
                            );
                        }
                    }
                }
            }
            1 => {
                auth_method =
                    b"hostbased\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
                if !(options.hostbased_authentication == 0) {
                    if !(auth2_key_already_used(authctxt, key) != 0) {
                        if !(key_base_type_match(
                            auth_method,
                            key,
                            options.hostbased_accepted_algos,
                        ) == 0)
                        {
                            allowed = hostbased_key_allowed(ssh, (*authctxt).pw, cuser, chost, key);
                            auth2_record_info(
                                authctxt,
                                b"client user \"%.100s\", client host \"%.100s\"\0" as *const u8
                                    as *const libc::c_char,
                                cuser,
                                chost,
                            );
                        }
                    }
                }
            }
            _ => {
                sshfatal(
                    b"monitor.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"mm_answer_keyallowed\0",
                    ))
                    .as_ptr(),
                    1194 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"unknown key type %u\0" as *const u8 as *const libc::c_char,
                    type_0,
                );
            }
        }
    }
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_keyallowed\0"))
            .as_ptr(),
        1202 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s authentication%s: %s key is %s\0" as *const u8 as *const libc::c_char,
        auth_method,
        if pubkey_auth_attempt != 0 {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b" test\0" as *const u8 as *const libc::c_char
        },
        if key.is_null() || (*authctxt).valid == 0 {
            b"invalid\0" as *const u8 as *const libc::c_char
        } else {
            crate::sshkey::sshkey_type(key)
        },
        if allowed != 0 {
            b"allowed\0" as *const u8 as *const libc::c_char
        } else {
            b"not allowed\0" as *const u8 as *const libc::c_char
        },
    );
    auth2_record_key(authctxt, 0 as libc::c_int, key);
    monitor_reset_key_state();
    if allowed != 0 {
        r = sshkey_to_blob(key, &mut key_blob, &mut key_bloblen);
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"mm_answer_keyallowed\0",
                ))
                .as_ptr(),
                1212 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"sshkey_to_blob\0" as *const u8 as *const libc::c_char,
            );
        }
        key_blobtype = type_0;
        key_opts = opts;
        hostbased_cuser = cuser;
        hostbased_chost = chost;
    } else {
        auth_log(
            ssh,
            0 as libc::c_int,
            0 as libc::c_int,
            auth_method,
            0 as *const libc::c_char,
        );
        libc::free(cuser as *mut libc::c_void);
        libc::free(chost as *mut libc::c_void);
    }
    crate::sshkey::sshkey_free(key);
    crate::sshbuf::sshbuf_reset(m);
    r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, allowed as u_int32_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_keyallowed\0"))
                .as_ptr(),
            1227 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    if !opts.is_null() && {
        r = sshauthopt_serialise(opts, m, 1 as libc::c_int);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_answer_keyallowed\0"))
                .as_ptr(),
            1229 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"sshauthopt_serialise\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send(sock, MONITOR_ANS_KEYALLOWED, m);
    if allowed == 0 {
        sshauthopt_free(opts);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn monitor_valid_userblob(
    mut ssh: *mut ssh,
    mut data: *const u_char,
    mut datalen: u_int,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut hostkey: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut p: *const u_char = 0 as *const u_char;
    let mut userstyle: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;
    let mut type_0: u_char = 0;
    let mut hostbound: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    let mut fail: libc::c_int = 0 as libc::c_int;
    b = crate::sshbuf::sshbuf_from(data as *const libc::c_void, datalen as size_t);
    if b.is_null() {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"monitor_valid_userblob\0",
            ))
            .as_ptr(),
            1250 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::sshbuf::sshbuf_from\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*ssh).compat & 0x10 as libc::c_int != 0 {
        p = crate::sshbuf::sshbuf_ptr(b);
        len = crate::sshbuf::sshbuf_len(b);
        if session_id2.is_null()
            || len < session_id2_len as libc::c_ulong
            || timingsafe_bcmp(
                p as *const libc::c_void,
                session_id2 as *const libc::c_void,
                session_id2_len as size_t,
            ) != 0 as libc::c_int
        {
            fail += 1;
            fail;
        }
        r = sshbuf_consume(b, session_id2_len as size_t);
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"monitor_valid_userblob\0",
                ))
                .as_ptr(),
                1260 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"consume\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        r = sshbuf_get_string_direct(b, &mut p, &mut len);
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"monitor_valid_userblob\0",
                ))
                .as_ptr(),
                1263 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse sessionid\0" as *const u8 as *const libc::c_char,
            );
        }
        if session_id2.is_null()
            || len != session_id2_len as libc::c_ulong
            || timingsafe_bcmp(
                p as *const libc::c_void,
                session_id2 as *const libc::c_void,
                session_id2_len as size_t,
            ) != 0 as libc::c_int
        {
            fail += 1;
            fail;
        }
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_u8(b, &mut type_0);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"monitor_valid_userblob\0",
            ))
            .as_ptr(),
            1270 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse type\0" as *const u8 as *const libc::c_char,
        );
    }
    if type_0 as libc::c_int != 50 as libc::c_int {
        fail += 1;
        fail;
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut cp, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"monitor_valid_userblob\0",
            ))
            .as_ptr(),
            1274 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse userstyle\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::xmalloc::xasprintf(
        &mut userstyle as *mut *mut libc::c_char,
        b"%s%s%s\0" as *const u8 as *const libc::c_char,
        (*authctxt).user,
        if !((*authctxt).style).is_null() {
            b":\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*authctxt).style).is_null() {
            (*authctxt).style as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    if libc::strcmp(userstyle, cp) != 0 as libc::c_int {
        crate::log::sshlog(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"monitor_valid_userblob\0",
            ))
            .as_ptr(),
            1280 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"wrong user name passed to monitor: expected %s != %.100s\0" as *const u8
                as *const libc::c_char,
            userstyle,
            cp,
        );
        fail += 1;
        fail;
    }
    libc::free(userstyle as *mut libc::c_void);
    libc::free(cp as *mut libc::c_void);
    r = sshbuf_get_string_direct(b, 0 as *mut *const u_char, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut cp, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"monitor_valid_userblob\0",
            ))
            .as_ptr(),
            1287 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse method\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::strcmp(b"publickey\0" as *const u8 as *const libc::c_char, cp) != 0 as libc::c_int {
        if libc::strcmp(
            b"publickey-hostbound-v00@openssh.com\0" as *const u8 as *const libc::c_char,
            cp,
        ) == 0 as libc::c_int
        {
            hostbound = 1 as libc::c_int;
        } else {
            fail += 1;
            fail;
        }
    }
    libc::free(cp as *mut libc::c_void);
    r = crate::sshbuf_getput_basic::sshbuf_get_u8(b, &mut type_0);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"monitor_valid_userblob\0",
            ))
            .as_ptr(),
            1296 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse pktype\0" as *const u8 as *const libc::c_char,
        );
    }
    if type_0 as libc::c_int == 0 as libc::c_int {
        fail += 1;
        fail;
    }
    r = sshbuf_get_string_direct(b, 0 as *mut *const u_char, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_string_direct(b, 0 as *mut *const u_char, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || hostbound != 0 && {
            r = sshkey_froms(b, &mut hostkey);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"monitor_valid_userblob\0",
            ))
            .as_ptr(),
            1302 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse pk\0" as *const u8 as *const libc::c_char,
        );
    }
    if crate::sshbuf::sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong {
        fail += 1;
        fail;
    }
    crate::sshbuf::sshbuf_free(b);
    if !hostkey.is_null() {
        if get_hostkey_index(hostkey, 1 as libc::c_int, ssh) == -(1 as libc::c_int) {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"monitor_valid_userblob\0",
                ))
                .as_ptr(),
                1313 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"hostbound hostkey does not match\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::sshkey::sshkey_free(hostkey);
    }
    return (fail == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn monitor_valid_hostbasedblob(
    mut data: *const u_char,
    mut datalen: u_int,
    mut cuser: *const libc::c_char,
    mut chost: *const libc::c_char,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut p: *const u_char = 0 as *const u_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut userstyle: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut fail: libc::c_int = 0 as libc::c_int;
    let mut type_0: u_char = 0;
    b = crate::sshbuf::sshbuf_from(data as *const libc::c_void, datalen as size_t);
    if b.is_null() {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"monitor_valid_hostbasedblob\0",
            ))
            .as_ptr(),
            1331 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_get_string_direct(b, &mut p, &mut len);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"monitor_valid_hostbasedblob\0",
            ))
            .as_ptr(),
            1333 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse sessionid\0" as *const u8 as *const libc::c_char,
        );
    }
    if session_id2.is_null()
        || len != session_id2_len as libc::c_ulong
        || timingsafe_bcmp(
            p as *const libc::c_void,
            session_id2 as *const libc::c_void,
            session_id2_len as size_t,
        ) != 0 as libc::c_int
    {
        fail += 1;
        fail;
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_u8(b, &mut type_0);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"monitor_valid_hostbasedblob\0",
            ))
            .as_ptr(),
            1341 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse type\0" as *const u8 as *const libc::c_char,
        );
    }
    if type_0 as libc::c_int != 50 as libc::c_int {
        fail += 1;
        fail;
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut cp, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"monitor_valid_hostbasedblob\0",
            ))
            .as_ptr(),
            1345 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse userstyle\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::xmalloc::xasprintf(
        &mut userstyle as *mut *mut libc::c_char,
        b"%s%s%s\0" as *const u8 as *const libc::c_char,
        (*authctxt).user,
        if !((*authctxt).style).is_null() {
            b":\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*authctxt).style).is_null() {
            (*authctxt).style as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    if libc::strcmp(userstyle, cp) != 0 as libc::c_int {
        crate::log::sshlog(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"monitor_valid_hostbasedblob\0",
            ))
            .as_ptr(),
            1351 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"wrong user name passed to monitor: expected %s != %.100s\0" as *const u8
                as *const libc::c_char,
            userstyle,
            cp,
        );
        fail += 1;
        fail;
    }
    libc::free(userstyle as *mut libc::c_void);
    libc::free(cp as *mut libc::c_void);
    r = sshbuf_get_string_direct(b, 0 as *mut *const u_char, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut cp, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"monitor_valid_hostbasedblob\0",
            ))
            .as_ptr(),
            1358 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse method\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::strcmp(cp, b"hostbased\0" as *const u8 as *const libc::c_char) != 0 as libc::c_int {
        fail += 1;
        fail;
    }
    libc::free(cp as *mut libc::c_void);
    r = sshbuf_get_string_direct(b, 0 as *mut *const u_char, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_string_direct(b, 0 as *mut *const u_char, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"monitor_valid_hostbasedblob\0",
            ))
            .as_ptr(),
            1364 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse pk\0" as *const u8 as *const libc::c_char,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut cp, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"monitor_valid_hostbasedblob\0",
            ))
            .as_ptr(),
            1368 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse host\0" as *const u8 as *const libc::c_char,
        );
    }
    len = strlen(cp);
    if len > 0 as libc::c_int as libc::c_ulong
        && *cp.offset(len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize) as libc::c_int
            == '.' as i32
    {
        *cp.offset(len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize) =
            '\0' as i32 as libc::c_char;
    }
    if libc::strcmp(cp, chost) != 0 as libc::c_int {
        fail += 1;
        fail;
    }
    libc::free(cp as *mut libc::c_void);
    r = crate::sshbuf_getput_basic::sshbuf_get_cstring(b, &mut cp, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"monitor_valid_hostbasedblob\0",
            ))
            .as_ptr(),
            1377 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse ruser\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::strcmp(cp, cuser) != 0 as libc::c_int {
        fail += 1;
        fail;
    }
    libc::free(cp as *mut libc::c_void);
    if crate::sshbuf::sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong {
        fail += 1;
        fail;
    }
    crate::sshbuf::sshbuf_free(b);
    return (fail == 0 as libc::c_int) as libc::c_int;
}
pub unsafe extern "C" fn mm_answer_keyverify(
    mut ssh: *mut ssh,
    mut sock: libc::c_int,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut signature: *const u_char = 0 as *const u_char;
    let mut data: *const u_char = 0 as *const u_char;
    let mut blob: *const u_char = 0 as *const u_char;
    let mut sigalg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut signaturelen: size_t = 0;
    let mut datalen: size_t = 0;
    let mut bloblen: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut req_presence: libc::c_int = 0 as libc::c_int;
    let mut req_verify: libc::c_int = 0 as libc::c_int;
    let mut valid_data: libc::c_int = 0 as libc::c_int;
    let mut encoded_ret: libc::c_int = 0;
    let mut sig_details: *mut sshkey_sig_details = 0 as *mut sshkey_sig_details;
    r = sshbuf_get_string_direct(m, &mut blob, &mut bloblen);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_string_direct(m, &mut signature, &mut signaturelen);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_string_direct(m, &mut data, &mut datalen);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_cstring(m, &mut sigalg, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mm_answer_keyverify\0"))
                .as_ptr(),
            1403 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if hostbased_cuser.is_null()
        || hostbased_chost.is_null()
        || monitor_allowed_key(blob, bloblen as u_int) == 0
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mm_answer_keyverify\0"))
                .as_ptr(),
            1407 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"bad key, not previously allowed\0" as *const u8 as *const libc::c_char,
        );
    }
    if *sigalg as libc::c_int == '\0' as i32 {
        libc::free(sigalg as *mut libc::c_void);
        sigalg = 0 as *mut libc::c_char;
    }
    r = sshkey_from_blob(blob, bloblen, &mut key);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mm_answer_keyverify\0"))
                .as_ptr(),
            1417 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse key\0" as *const u8 as *const libc::c_char,
        );
    }
    match key_blobtype {
        2 => {
            valid_data = monitor_valid_userblob(ssh, data, datalen as u_int);
            auth_method = b"publickey\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
        1 => {
            valid_data = monitor_valid_hostbasedblob(
                data,
                datalen as u_int,
                hostbased_cuser,
                hostbased_chost,
            );
            auth_method = b"hostbased\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
        _ => {
            valid_data = 0 as libc::c_int;
        }
    }
    if valid_data == 0 {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mm_answer_keyverify\0"))
                .as_ptr(),
            1436 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"bad %s signature data blob\0" as *const u8 as *const libc::c_char,
            if key_blobtype == MM_USERKEY as libc::c_int as libc::c_uint {
                b"userkey\0" as *const u8 as *const libc::c_char
            } else if key_blobtype == MM_HOSTKEY as libc::c_int as libc::c_uint {
                b"hostkey\0" as *const u8 as *const libc::c_char
            } else {
                b"unknown\0" as *const u8 as *const libc::c_char
            },
        );
    }
    fp = crate::sshkey::sshkey_fingerprint(key, options.fingerprint_hash, SSH_FP_DEFAULT);
    if fp.is_null() {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mm_answer_keyverify\0"))
                .as_ptr(),
            1440 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::sshkey::sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
        );
    }
    ret = sshkey_verify(
        key,
        signature,
        signaturelen,
        data,
        datalen,
        sigalg,
        (*ssh).compat as u_int,
        &mut sig_details,
    );
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mm_answer_keyverify\0"))
            .as_ptr(),
        1447 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s %s signature using %s %s%s%s\0" as *const u8 as *const libc::c_char,
        auth_method,
        crate::sshkey::sshkey_type(key),
        if sigalg.is_null() {
            b"default\0" as *const u8 as *const libc::c_char
        } else {
            sigalg as *const libc::c_char
        },
        if ret == 0 as libc::c_int {
            b"verified\0" as *const u8 as *const libc::c_char
        } else {
            b"unverified\0" as *const u8 as *const libc::c_char
        },
        if ret != 0 as libc::c_int {
            b": \0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if ret != 0 as libc::c_int {
            ssh_err(ret)
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    if ret == 0 as libc::c_int
        && key_blobtype == MM_USERKEY as libc::c_int as libc::c_uint
        && !sig_details.is_null()
    {
        req_presence = (options.pubkey_auth_options & 1 as libc::c_int != 0
            || (*key_opts).no_require_user_presence == 0) as libc::c_int;
        if req_presence != 0
            && (*sig_details).sk_flags as libc::c_int & 0x1 as libc::c_int == 0 as libc::c_int
        {
            crate::log::sshlog(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<
                    &[u8; 20],
                    &[libc::c_char; 20],
                >(b"mm_answer_keyverify\0"))
                    .as_ptr(),
                1461 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"public key %s %s signature for %s%s from %.128s port %d rejected: user presence (authenticator touch) requirement not met \0"
                    as *const u8 as *const libc::c_char,
                crate::sshkey::sshkey_type(key),
                fp,
                if (*authctxt).valid != 0 {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    b"invalid user \0" as *const u8 as *const libc::c_char
                },
                (*authctxt).user,
                ssh_remote_ipaddr(ssh),
                ssh_remote_port(ssh),
            );
            ret = -(21 as libc::c_int);
        }
        req_verify = (options.pubkey_auth_options & (1 as libc::c_int) << 1 as libc::c_int != 0
            || (*key_opts).require_verify != 0) as libc::c_int;
        if req_verify != 0
            && (*sig_details).sk_flags as libc::c_int & 0x4 as libc::c_int == 0 as libc::c_int
        {
            crate::log::sshlog(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<
                    &[u8; 20],
                    &[libc::c_char; 20],
                >(b"mm_answer_keyverify\0"))
                    .as_ptr(),
                1473 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"public key %s %s signature for %s%s from %.128s port %d rejected: user verification requirement not met \0"
                    as *const u8 as *const libc::c_char,
                crate::sshkey::sshkey_type(key),
                fp,
                if (*authctxt).valid != 0 {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    b"invalid user \0" as *const u8 as *const libc::c_char
                },
                (*authctxt).user,
                ssh_remote_ipaddr(ssh),
                ssh_remote_port(ssh),
            );
            ret = -(21 as libc::c_int);
        }
    }
    auth2_record_key(authctxt, (ret == 0 as libc::c_int) as libc::c_int, key);
    if key_blobtype == MM_USERKEY as libc::c_int as libc::c_uint {
        auth_activate_options(ssh, key_opts);
    }
    monitor_reset_key_state();
    crate::sshbuf::sshbuf_reset(m);
    encoded_ret = (ret != 0 as libc::c_int) as libc::c_int;
    r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, encoded_ret as u_int32_t);
    if r != 0 as libc::c_int || {
        r = crate::sshbuf_getput_basic::sshbuf_put_u8(
            m,
            (sig_details != 0 as *mut libc::c_void as *mut sshkey_sig_details) as libc::c_int
                as u_char,
        );
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mm_answer_keyverify\0"))
                .as_ptr(),
            1489 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    if !sig_details.is_null() {
        r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, (*sig_details).sk_counter);
        if r != 0 as libc::c_int || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(m, (*sig_details).sk_flags);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"mm_answer_keyverify\0",
                ))
                .as_ptr(),
                1493 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble sk\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    sshkey_sig_details_free(sig_details);
    mm_request_send(sock, MONITOR_ANS_KEYVERIFY, m);
    libc::free(sigalg as *mut libc::c_void);
    libc::free(fp as *mut libc::c_void);
    crate::sshkey::sshkey_free(key);
    return (ret == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn mm_record_login(
    mut ssh: *mut ssh,
    mut s: *mut Session,
    mut pw: *mut libc::passwd,
) {
    let mut fromlen: socklen_t = 0;
    let mut from: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    memset(
        &mut from as *mut sockaddr_storage as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong,
    );
    fromlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    if ssh_packet_connection_is_on_socket(ssh) != 0 {
        if getpeername(
            ssh_packet_get_connection_in(ssh),
            __SOCKADDR_ARG {
                __sockaddr__: &mut from as *mut sockaddr_storage as *mut sockaddr,
            },
            &mut fromlen,
        ) == -(1 as libc::c_int)
        {
            crate::log::sshlog(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_record_login\0"))
                    .as_ptr(),
                1520 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"getpeername: %.100s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
            cleanup_exit(255 as libc::c_int);
        }
    }
    record_login(
        (*s).pid,
        ((*s).tty).as_mut_ptr(),
        (*pw).pw_name,
        (*pw).pw_uid,
        session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
        &mut from as *mut sockaddr_storage as *mut sockaddr,
        fromlen,
    );
}
unsafe extern "C" fn mm_session_close(mut s: *mut Session) {
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_session_close\0")).as_ptr(),
        1533 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"session %d pid %ld\0" as *const u8 as *const libc::c_char,
        (*s).self_0,
        (*s).pid as libc::c_long,
    );
    if (*s).ttyfd != -(1 as libc::c_int) {
        crate::log::sshlog(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_session_close\0"))
                .as_ptr(),
            1535 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"tty %s ptyfd %d\0" as *const u8 as *const libc::c_char,
            ((*s).tty).as_mut_ptr(),
            (*s).ptyfd,
        );
        session_pty_cleanup2(s);
    }
    session_unused((*s).self_0);
}
pub unsafe extern "C" fn mm_answer_pty(
    mut ssh: *mut ssh,
    mut sock: libc::c_int,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    extern "C" {
        static mut pmonitor: *mut monitor;
    }
    let mut s: *mut Session = 0 as *mut Session;
    let mut r: libc::c_int = 0;
    let mut res: libc::c_int = 0;
    let mut fd0: libc::c_int = 0;
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_answer_pty\0")).as_ptr(),
        1548 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    crate::sshbuf::sshbuf_reset(m);
    s = session_new();
    if !s.is_null() {
        (*s).authctxt = authctxt;
        (*s).pw = (*authctxt).pw;
        (*s).pid = (*pmonitor).m_pid;
        res = pty_allocate(
            &mut (*s).ptyfd,
            &mut (*s).ttyfd,
            ((*s).tty).as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
        );
        if !(res == 0 as libc::c_int) {
            pty_setowner((*authctxt).pw, ((*s).tty).as_mut_ptr());
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, 1 as libc::c_int as u_int32_t);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(m, ((*s).tty).as_mut_ptr());
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"monitor.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_answer_pty\0"))
                        .as_ptr(),
                    1564 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"assemble\0" as *const u8 as *const libc::c_char,
                );
            }
            if libc::dup2((*s).ttyfd, 0 as libc::c_int) == -(1 as libc::c_int) {
                sshfatal(
                    b"monitor.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_answer_pty\0"))
                        .as_ptr(),
                    1568 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"libc::dup2\0" as *const u8 as *const libc::c_char,
                );
            }
            mm_record_login(ssh, s, (*authctxt).pw);
            close(0 as libc::c_int);
            r = sshbuf_put_stringb(m, loginmsg);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"monitor.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_answer_pty\0"))
                        .as_ptr(),
                    1577 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"assemble loginmsg\0" as *const u8 as *const libc::c_char,
                );
            }
            crate::sshbuf::sshbuf_reset(loginmsg);
            mm_request_send(sock, MONITOR_ANS_PTY, m);
            if mm_send_fd(sock, (*s).ptyfd) == -(1 as libc::c_int)
                || mm_send_fd(sock, (*s).ttyfd) == -(1 as libc::c_int)
            {
                sshfatal(
                    b"monitor.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_answer_pty\0"))
                        .as_ptr(),
                    1584 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"send fds failed\0" as *const u8 as *const libc::c_char,
                );
            }
            fd0 = libc::open(
                b"/dev/null\0" as *const u8 as *const libc::c_char,
                0 as libc::c_int,
            );
            if fd0 == -(1 as libc::c_int) {
                sshfatal(
                    b"monitor.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_answer_pty\0"))
                        .as_ptr(),
                    1588 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"open(/dev/null): %s\0" as *const u8 as *const libc::c_char,
                    libc::strerror(*libc::__errno_location()),
                );
            }
            if fd0 != 0 as libc::c_int {
                crate::log::sshlog(
                    b"monitor.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_answer_pty\0"))
                        .as_ptr(),
                    1590 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"fd0 %d != 0\0" as *const u8 as *const libc::c_char,
                    fd0,
                );
            }
            close((*s).ttyfd);
            (*s).ttyfd = (*s).ptyfd;
            (*s).ptymaster = (*s).ptyfd;
            crate::log::sshlog(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_answer_pty\0"))
                    .as_ptr(),
                1598 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"tty %s ptyfd %d\0" as *const u8 as *const libc::c_char,
                ((*s).tty).as_mut_ptr(),
                (*s).ttyfd,
            );
            return 0 as libc::c_int;
        }
    }
    if !s.is_null() {
        mm_session_close(s);
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, 0 as libc::c_int as u_int32_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"mm_answer_pty\0"))
                .as_ptr(),
            1606 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble 0\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send(sock, MONITOR_ANS_PTY, m);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn mm_answer_pty_cleanup(
    mut _ssh: *mut ssh,
    mut _sock: libc::c_int,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut s: *mut Session = 0 as *mut Session;
    let mut tty: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"mm_answer_pty_cleanup\0"))
            .as_ptr(),
        1618 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    r = crate::sshbuf_getput_basic::sshbuf_get_cstring(m, &mut tty, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"mm_answer_pty_cleanup\0"))
                .as_ptr(),
            1621 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse tty\0" as *const u8 as *const libc::c_char,
        );
    }
    s = session_by_tty(tty);
    if !s.is_null() {
        mm_session_close(s);
    }
    crate::sshbuf::sshbuf_reset(m);
    libc::free(tty as *mut libc::c_void);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn monitor_clear_keystate(mut ssh: *mut ssh, mut _pmonitor: *mut monitor) {
    ssh_clear_newkeys(ssh, MODE_IN as libc::c_int);
    ssh_clear_newkeys(ssh, MODE_OUT as libc::c_int);
    crate::sshbuf::sshbuf_free(child_state);
    child_state = 0 as *mut crate::sshbuf::sshbuf;
}
pub unsafe extern "C" fn monitor_apply_keystate(mut ssh: *mut ssh, mut _pmonitor: *mut monitor) {
    let mut kex: *mut kex = 0 as *mut kex;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"monitor_apply_keystate\0"))
            .as_ptr(),
        1717 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"packet_set_state\0" as *const u8 as *const libc::c_char,
    );
    r = ssh_packet_set_state(ssh, child_state);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"monitor_apply_keystate\0",
            ))
            .as_ptr(),
            1719 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"packet_set_state\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_free(child_state);
    child_state = 0 as *mut crate::sshbuf::sshbuf;
    kex = (*ssh).kex;
    if kex.is_null() {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"monitor_apply_keystate\0",
            ))
            .as_ptr(),
            1723 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"internal error: ssh->kex == NULL\0" as *const u8 as *const libc::c_char,
        );
    }
    if session_id2_len as libc::c_ulong != crate::sshbuf::sshbuf_len((*(*ssh).kex).session_id) {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"monitor_apply_keystate\0",
            ))
            .as_ptr(),
            1726 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"incorrect session id length %zu (expected %u)\0" as *const u8 as *const libc::c_char,
            crate::sshbuf::sshbuf_len((*(*ssh).kex).session_id),
            session_id2_len,
        );
    }
    if memcmp(
        crate::sshbuf::sshbuf_ptr((*(*ssh).kex).session_id) as *const libc::c_void,
        session_id2 as *const libc::c_void,
        session_id2_len as libc::c_ulong,
    ) != 0 as libc::c_int
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"monitor_apply_keystate\0",
            ))
            .as_ptr(),
            1730 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"session ID mismatch\0" as *const u8 as *const libc::c_char,
        );
    }
    (*kex).kex[KEX_DH_GRP1_SHA1 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_DH_GRP14_SHA1 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_DH_GRP14_SHA256 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_DH_GRP16_SHA512 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_DH_GRP18_SHA512 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_DH_GEX_SHA1 as libc::c_int as usize] =
        Some(kexgex_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_DH_GEX_SHA256 as libc::c_int as usize] =
        Some(kexgex_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_ECDH_SHA2 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_C25519_SHA256 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_KEM_SNTRUP761X25519_SHA512 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).load_host_public_key = Some(
        get_hostkey_public_by_type
            as unsafe extern "C" fn(
                libc::c_int,
                libc::c_int,
                *mut ssh,
            ) -> *mut crate::sshkey::sshkey,
    );
    (*kex).load_host_private_key = Some(
        get_hostkey_private_by_type
            as unsafe extern "C" fn(
                libc::c_int,
                libc::c_int,
                *mut ssh,
            ) -> *mut crate::sshkey::sshkey,
    );
    (*kex).host_key_index = Some(
        get_hostkey_index
            as unsafe extern "C" fn(
                *mut crate::sshkey::sshkey,
                libc::c_int,
                *mut ssh,
            ) -> libc::c_int,
    );
    (*kex).sign = Some(
        sshd_hostkey_sign
            as unsafe extern "C" fn(
                *mut ssh,
                *mut crate::sshkey::sshkey,
                *mut crate::sshkey::sshkey,
                *mut *mut u_char,
                *mut size_t,
                *const u_char,
                size_t,
                *const libc::c_char,
            ) -> libc::c_int,
    );
}
pub unsafe extern "C" fn mm_get_keystate(mut _ssh: *mut ssh, mut pmonitor: *mut monitor) {
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_get_keystate\0")).as_ptr(),
        1757 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Waiting for new keys\0" as *const u8 as *const libc::c_char,
    );
    child_state = crate::sshbuf::sshbuf_new();
    if child_state.is_null() {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_get_keystate\0"))
                .as_ptr(),
            1760 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    mm_request_receive_expect((*pmonitor).m_sendfd, MONITOR_REQ_KEYEXPORT, child_state);
    crate::log::sshlog(
        b"monitor.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_get_keystate\0")).as_ptr(),
        1763 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"GOT new keys\0" as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn monitor_openfds(mut mon: *mut monitor, mut do_logfds: libc::c_int) {
    let mut pair: [libc::c_int; 2] = [0; 2];
    if libc::socketpair(
        1 as libc::c_int,
        SOCK_STREAM as libc::c_int,
        0 as libc::c_int,
        pair.as_mut_ptr(),
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"monitor_openfds\0"))
                .as_ptr(),
            1783 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::socketpair: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    if fcntl(
        pair[0 as libc::c_int as usize],
        2 as libc::c_int,
        1 as libc::c_int,
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"monitor_openfds\0"))
                .as_ptr(),
            1790 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"fcntl(%d, F_SETFD)\0" as *const u8 as *const libc::c_char,
            pair[0 as libc::c_int as usize],
        );
    }
    if fcntl(
        pair[1 as libc::c_int as usize],
        2 as libc::c_int,
        1 as libc::c_int,
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"monitor.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"monitor_openfds\0"))
                .as_ptr(),
            1791 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"fcntl(%d, F_SETFD)\0" as *const u8 as *const libc::c_char,
            pair[1 as libc::c_int as usize],
        );
    }
    (*mon).m_recvfd = pair[0 as libc::c_int as usize];
    (*mon).m_sendfd = pair[1 as libc::c_int as usize];
    if do_logfds != 0 {
        if pipe(pair.as_mut_ptr()) == -(1 as libc::c_int) {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"monitor_openfds\0"))
                    .as_ptr(),
                1797 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"pipe: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        if fcntl(
            pair[0 as libc::c_int as usize],
            2 as libc::c_int,
            1 as libc::c_int,
        ) == -(1 as libc::c_int)
        {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"monitor_openfds\0"))
                    .as_ptr(),
                1798 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"fcntl(%d, F_SETFD)\0" as *const u8 as *const libc::c_char,
                pair[0 as libc::c_int as usize],
            );
        }
        if fcntl(
            pair[1 as libc::c_int as usize],
            2 as libc::c_int,
            1 as libc::c_int,
        ) == -(1 as libc::c_int)
        {
            sshfatal(
                b"monitor.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"monitor_openfds\0"))
                    .as_ptr(),
                1799 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"fcntl(%d, F_SETFD)\0" as *const u8 as *const libc::c_char,
                pair[1 as libc::c_int as usize],
            );
        }
        (*mon).m_log_recvfd = pair[0 as libc::c_int as usize];
        (*mon).m_log_sendfd = pair[1 as libc::c_int as usize];
    } else {
        (*mon).m_log_sendfd = -(1 as libc::c_int);
        (*mon).m_log_recvfd = (*mon).m_log_sendfd;
    };
}
pub unsafe extern "C" fn monitor_init() -> *mut monitor {
    let mut mon: *mut monitor = 0 as *mut monitor;
    mon = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<monitor>() as libc::c_ulong,
    ) as *mut monitor;
    monitor_openfds(mon, 1 as libc::c_int);
    return mon;
}
pub unsafe extern "C" fn monitor_reinit(mut mon: *mut monitor) {
    monitor_openfds(mon, 0 as libc::c_int);
}
