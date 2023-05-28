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
    pub type ssh_channels;
    pub type sshbuf;
    pub type ec_key_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type kex;
    pub type session_state;
    fn socket(__domain: libc::c_int, __type: libc::c_int, __protocol: libc::c_int) -> libc::c_int;
    fn connect(__fd: libc::c_int, __addr: __CONST_SOCKADDR_ARG, __len: socklen_t) -> libc::c_int;
    fn tcgetattr(__fd: libc::c_int, __termios_p: *mut termios) -> libc::c_int;

    fn platform_pledge_mux();

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    static mut environ: *mut *mut libc::c_char;

    fn arc4random_uniform(_: uint32_t) -> uint32_t;
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: libc::c_int) -> libc::c_int;

    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    static mut stdout: *mut libc::FILE;
    static mut stderr: *mut libc::FILE;

    fn link(__from: *const libc::c_char, __to: *const libc::c_char) -> libc::c_int;
    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn strsignal(__sig: libc::c_int) -> *mut libc::c_char;

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;

    fn xreallocarray(_: *mut libc::c_void, _: size_t, _: size_t) -> *mut libc::c_void;

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
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;

    fn unix_listener(_: *const libc::c_char, _: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn stdfd_devnull(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn lookup_env_in_list(
        env: *const libc::c_char,
        envs: *const *mut libc::c_char,
        nenvs: size_t,
    ) -> *const libc::c_char;
    fn ask_permission(_: *const libc::c_char, _: ...) -> libc::c_int;

    fn match_pattern(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
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
    fn sshbuf_put_u32(buf: *mut sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_put(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_reserve(buf: *mut sshbuf, len: size_t, dpp: *mut *mut u_char) -> libc::c_int;
    fn sshbuf_ptr(buf: *const sshbuf) -> *const u_char;
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_reset(buf: *mut sshbuf);
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_froms(buf: *mut sshbuf, bufp: *mut *mut sshbuf) -> libc::c_int;
    fn sshbuf_new() -> *mut sshbuf;
    fn channel_by_id(_: *mut ssh, _: libc::c_int) -> *mut Channel;
    fn channel_new(
        _: *mut ssh,
        _: *mut libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: u_int,
        _: u_int,
        _: libc::c_int,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> *mut Channel;
    fn channel_free(_: *mut ssh, _: *mut Channel);
    fn channel_send_open(_: *mut ssh, _: libc::c_int);
    fn channel_request_start(_: *mut ssh, _: libc::c_int, _: *mut libc::c_char, _: libc::c_int);
    fn channel_register_cleanup(
        _: *mut ssh,
        _: libc::c_int,
        _: Option<channel_callback_fn>,
        _: libc::c_int,
    );
    fn channel_register_open_confirm(
        _: *mut ssh,
        _: libc::c_int,
        _: Option<channel_open_fn>,
        _: *mut libc::c_void,
    );
    fn channel_register_filter(
        _: *mut ssh,
        _: libc::c_int,
        _: Option<channel_infilter_fn>,
        _: Option<channel_outfilter_fn>,
        _: Option<channel_filter_cleanup_fn>,
        _: *mut libc::c_void,
    );
    fn channel_cancel_cleanup(_: *mut ssh, _: libc::c_int);
    fn channel_proxy_downstream(_: *mut ssh, mc: *mut Channel) -> libc::c_int;
    fn channel_update_permission(_: *mut ssh, _: libc::c_int, _: libc::c_int);
    fn channel_connect_stdio_fwd(
        _: *mut ssh,
        _: *const libc::c_char,
        _: u_short,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
    ) -> *mut Channel;
    fn channel_request_remote_forwarding(_: *mut ssh, _: *mut Forward) -> libc::c_int;
    fn channel_setup_local_fwd_listener(
        _: *mut ssh,
        _: *mut Forward,
        _: *mut ForwardOptions,
    ) -> libc::c_int;
    fn channel_request_rforward_cancel(_: *mut ssh, _: *mut Forward) -> libc::c_int;
    fn channel_cancel_lport_listener(
        _: *mut ssh,
        _: *mut Forward,
        _: libc::c_int,
        _: *mut ForwardOptions,
    ) -> libc::c_int;
    fn x11_request_forwarding_with_spoofing(
        _: *mut ssh,
        _: libc::c_int,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    );
    fn chan_mark_dead(_: *mut ssh, _: *mut Channel);
    fn chan_rcvd_oclose(_: *mut ssh, _: *mut Channel);
    fn chan_read_failed(_: *mut ssh, _: *mut Channel);
    fn chan_write_failed(_: *mut ssh, _: *mut Channel);
    fn sshpkt_get_u32(ssh: *mut ssh, valp: *mut u_int32_t) -> libc::c_int;
    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn mm_send_fd(_: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn mm_receive_fd(_: libc::c_int) -> libc::c_int;
    fn leave_raw_mode(_: libc::c_int);
    fn enter_raw_mode(_: libc::c_int);
    fn add_local_forward(_: *mut Options, _: *const Forward);
    fn add_remote_forward(_: *mut Options, _: *const Forward);
    fn client_x11_get_proto(
        _: *mut ssh,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: u_int,
        _: u_int,
        _: *mut *mut libc::c_char,
        _: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn client_session2_setup(
        _: *mut ssh,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: *const libc::c_char,
        _: *mut termios,
        _: libc::c_int,
        _: *mut sshbuf,
        _: *mut *mut libc::c_char,
    );
    fn client_stop_mux();
    fn client_new_escape_filter_ctx(_: libc::c_int) -> *mut libc::c_void;
    fn client_filter_cleanup(_: *mut ssh, _: libc::c_int, _: *mut libc::c_void);
    fn client_simple_escape_filter(
        _: *mut ssh,
        _: *mut Channel,
        _: *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn client_register_global_confirm(_: Option<global_confirm_cb>, _: *mut libc::c_void);
    fn client_expect_confirm(
        _: *mut ssh,
        _: libc::c_int,
        _: *const libc::c_char,
        _: confirm_action,
    );
    static mut tty_flag: libc::c_int;
    static mut options: Options;
    static mut host: *mut libc::c_char;
    static mut command: *mut sshbuf;
    static mut quit_pending: sig_atomic_t;
}
pub type __u_char = libc::c_uchar;
pub type __u_short = libc::c_ushort;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_short = __u_short;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
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
pub type cc_t = libc::c_uchar;
pub type speed_t = libc::c_uint;
pub type tcflag_t = libc::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; 32],
    pub c_ispeed: speed_t,
    pub c_ospeed: speed_t,
}

pub type _IO_lock_t = ();

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
pub struct Channel {
    pub type_0: libc::c_int,
    pub self_0: libc::c_int,
    pub remote_id: uint32_t,
    pub have_remote_id: libc::c_int,
    pub istate: u_int,
    pub ostate: u_int,
    pub flags: libc::c_int,
    pub rfd: libc::c_int,
    pub wfd: libc::c_int,
    pub efd: libc::c_int,
    pub sock: libc::c_int,
    pub io_want: u_int,
    pub io_ready: u_int,
    pub pfds: [libc::c_int; 4],
    pub ctl_chan: libc::c_int,
    pub isatty: libc::c_int,
    pub client_tty: libc::c_int,
    pub force_drain: libc::c_int,
    pub notbefore: time_t,
    pub delayed: libc::c_int,
    pub restore_block: libc::c_int,
    pub restore_flags: [libc::c_int; 3],
    pub input: *mut sshbuf,
    pub output: *mut sshbuf,
    pub extended: *mut sshbuf,
    pub path: *mut libc::c_char,
    pub listening_port: libc::c_int,
    pub listening_addr: *mut libc::c_char,
    pub host_port: libc::c_int,
    pub remote_name: *mut libc::c_char,
    pub remote_window: u_int,
    pub remote_maxpacket: u_int,
    pub local_window: u_int,
    pub local_window_max: u_int,
    pub local_consumed: u_int,
    pub local_maxpacket: u_int,
    pub extended_usage: libc::c_int,
    pub single_connection: libc::c_int,
    pub ctype: *mut libc::c_char,
    pub xctype: *mut libc::c_char,
    pub open_confirm: Option<channel_open_fn>,
    pub open_confirm_ctx: *mut libc::c_void,
    pub detach_user: Option<channel_callback_fn>,
    pub detach_close: libc::c_int,
    pub status_confirms: channel_confirms,
    pub input_filter: Option<channel_infilter_fn>,
    pub output_filter: Option<channel_outfilter_fn>,
    pub filter_ctx: *mut libc::c_void,
    pub filter_cleanup: Option<channel_filter_cleanup_fn>,
    pub datagram: libc::c_int,
    pub connect_ctx: channel_connect,
    pub mux_rcb: Option<mux_callback_fn>,
    pub mux_ctx: *mut libc::c_void,
    pub mux_pause: libc::c_int,
    pub mux_downstream_id: libc::c_int,
    pub lastused: time_t,
    pub inactive_deadline: u_int,
}
pub type mux_callback_fn = unsafe extern "C" fn(*mut ssh, *mut Channel) -> libc::c_int;
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
    pub private_keys: C2RustUnnamed_2,
    pub public_keys: C2RustUnnamed_0,
    pub authctxt: *mut libc::c_void,
    pub chanctxt: *mut ssh_channels,
    pub app_data: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct key_entry {
    pub next: C2RustUnnamed_1,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct channel_connect {
    pub host: *mut libc::c_char,
    pub port: libc::c_int,
    pub ai: *mut addrinfo,
    pub aitop: *mut addrinfo,
}
pub type channel_filter_cleanup_fn =
    unsafe extern "C" fn(*mut ssh, libc::c_int, *mut libc::c_void) -> ();
pub type channel_outfilter_fn =
    unsafe extern "C" fn(*mut ssh, *mut Channel, *mut *mut u_char, *mut size_t) -> *mut u_char;
pub type channel_infilter_fn =
    unsafe extern "C" fn(*mut ssh, *mut Channel, *mut libc::c_char, libc::c_int) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct channel_confirms {
    pub tqh_first: *mut channel_confirm,
    pub tqh_last: *mut *mut channel_confirm,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct channel_confirm {
    pub entry: C2RustUnnamed_3,
    pub cb: Option<channel_confirm_cb>,
    pub abandon_cb: Option<channel_confirm_abandon_cb>,
    pub ctx: *mut libc::c_void,
}
pub type channel_confirm_abandon_cb =
    unsafe extern "C" fn(*mut ssh, *mut Channel, *mut libc::c_void) -> ();
pub type channel_confirm_cb =
    unsafe extern "C" fn(*mut ssh, libc::c_int, *mut Channel, *mut libc::c_void) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
    pub tqe_next: *mut channel_confirm,
    pub tqe_prev: *mut *mut channel_confirm,
}
pub type channel_callback_fn =
    unsafe extern "C" fn(*mut ssh, libc::c_int, libc::c_int, *mut libc::c_void) -> ();
pub type channel_open_fn =
    unsafe extern "C" fn(*mut ssh, libc::c_int, libc::c_int, *mut libc::c_void) -> ();
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ForwardOptions {
    pub gateway_ports: libc::c_int,
    pub streamlocal_bind_mask: mode_t,
    pub streamlocal_bind_unlink: libc::c_int,
}
pub type sshsig_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct allowed_cname {
    pub source_list: *mut libc::c_char,
    pub target_list: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Options {
    pub host_arg: *mut libc::c_char,
    pub forward_agent: libc::c_int,
    pub forward_agent_sock_path: *mut libc::c_char,
    pub forward_x11: libc::c_int,
    pub forward_x11_timeout: libc::c_int,
    pub forward_x11_trusted: libc::c_int,
    pub exit_on_forward_failure: libc::c_int,
    pub xauth_location: *mut libc::c_char,
    pub fwd_opts: ForwardOptions,
    pub pubkey_authentication: libc::c_int,
    pub hostbased_authentication: libc::c_int,
    pub gss_authentication: libc::c_int,
    pub gss_deleg_creds: libc::c_int,
    pub password_authentication: libc::c_int,
    pub kbd_interactive_authentication: libc::c_int,
    pub kbd_interactive_devices: *mut libc::c_char,
    pub batch_mode: libc::c_int,
    pub check_host_ip: libc::c_int,
    pub strict_host_key_checking: libc::c_int,
    pub compression: libc::c_int,
    pub tcp_keep_alive: libc::c_int,
    pub ip_qos_interactive: libc::c_int,
    pub ip_qos_bulk: libc::c_int,
    pub log_facility: SyslogFacility,
    pub log_level: LogLevel,
    pub num_log_verbose: u_int,
    pub log_verbose: *mut *mut libc::c_char,
    pub port: libc::c_int,
    pub address_family: libc::c_int,
    pub connection_attempts: libc::c_int,
    pub connection_timeout: libc::c_int,
    pub number_of_password_prompts: libc::c_int,
    pub ciphers: *mut libc::c_char,
    pub macs: *mut libc::c_char,
    pub hostkeyalgorithms: *mut libc::c_char,
    pub kex_algorithms: *mut libc::c_char,
    pub ca_sign_algorithms: *mut libc::c_char,
    pub hostname: *mut libc::c_char,
    pub host_key_alias: *mut libc::c_char,
    pub proxy_command: *mut libc::c_char,
    pub user: *mut libc::c_char,
    pub escape_char: libc::c_int,
    pub num_system_hostfiles: u_int,
    pub system_hostfiles: [*mut libc::c_char; 32],
    pub num_user_hostfiles: u_int,
    pub user_hostfiles: [*mut libc::c_char; 32],
    pub preferred_authentications: *mut libc::c_char,
    pub bind_address: *mut libc::c_char,
    pub bind_interface: *mut libc::c_char,
    pub pkcs11_provider: *mut libc::c_char,
    pub sk_provider: *mut libc::c_char,
    pub verify_host_key_dns: libc::c_int,
    pub num_identity_files: libc::c_int,
    pub identity_files: [*mut libc::c_char; 100],
    pub identity_file_userprovided: [libc::c_int; 100],
    pub identity_keys: [*mut sshkey; 100],
    pub num_certificate_files: libc::c_int,
    pub certificate_files: [*mut libc::c_char; 100],
    pub certificate_file_userprovided: [libc::c_int; 100],
    pub certificates: [*mut sshkey; 100],
    pub add_keys_to_agent: libc::c_int,
    pub add_keys_to_agent_lifespan: libc::c_int,
    pub identity_agent: *mut libc::c_char,
    pub num_local_forwards: libc::c_int,
    pub local_forwards: *mut Forward,
    pub num_remote_forwards: libc::c_int,
    pub remote_forwards: *mut Forward,
    pub clear_forwardings: libc::c_int,
    pub permitted_remote_opens: *mut *mut libc::c_char,
    pub num_permitted_remote_opens: u_int,
    pub stdio_forward_host: *mut libc::c_char,
    pub stdio_forward_port: libc::c_int,
    pub enable_ssh_keysign: libc::c_int,
    pub rekey_limit: int64_t,
    pub rekey_interval: libc::c_int,
    pub no_host_authentication_for_localhost: libc::c_int,
    pub identities_only: libc::c_int,
    pub server_alive_interval: libc::c_int,
    pub server_alive_count_max: libc::c_int,
    pub num_send_env: u_int,
    pub send_env: *mut *mut libc::c_char,
    pub num_setenv: u_int,
    pub setenv: *mut *mut libc::c_char,
    pub control_path: *mut libc::c_char,
    pub control_master: libc::c_int,
    pub control_persist: libc::c_int,
    pub control_persist_timeout: libc::c_int,
    pub hash_known_hosts: libc::c_int,
    pub tun_open: libc::c_int,
    pub tun_local: libc::c_int,
    pub tun_remote: libc::c_int,
    pub local_command: *mut libc::c_char,
    pub permit_local_command: libc::c_int,
    pub remote_command: *mut libc::c_char,
    pub visual_host_key: libc::c_int,
    pub request_tty: libc::c_int,
    pub session_type: libc::c_int,
    pub stdin_null: libc::c_int,
    pub fork_after_authentication: libc::c_int,
    pub proxy_use_fdpass: libc::c_int,
    pub num_canonical_domains: libc::c_int,
    pub canonical_domains: [*mut libc::c_char; 32],
    pub canonicalize_hostname: libc::c_int,
    pub canonicalize_max_dots: libc::c_int,
    pub canonicalize_fallback_local: libc::c_int,
    pub num_permitted_cnames: libc::c_int,
    pub permitted_cnames: [allowed_cname; 32],
    pub revoked_host_keys: *mut libc::c_char,
    pub fingerprint_hash: libc::c_int,
    pub update_hostkeys: libc::c_int,
    pub hostbased_accepted_algos: *mut libc::c_char,
    pub pubkey_accepted_algos: *mut libc::c_char,
    pub jump_user: *mut libc::c_char,
    pub jump_host: *mut libc::c_char,
    pub jump_port: libc::c_int,
    pub jump_extra: *mut libc::c_char,
    pub known_hosts_command: *mut libc::c_char,
    pub required_rsa_size: libc::c_int,
    pub enable_escape_commandline: libc::c_int,
    pub ignored_unknown: *mut libc::c_char,
}
pub type global_confirm_cb =
    unsafe extern "C" fn(*mut ssh, libc::c_int, u_int32_t, *mut libc::c_void) -> ();
pub type confirm_action = libc::c_uint;
pub const CONFIRM_TTY: confirm_action = 2;
pub const CONFIRM_CLOSE: confirm_action = 1;
pub const CONFIRM_WARN: confirm_action = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub type_0: u_int,
    pub handler: Option<
        unsafe extern "C" fn(
            *mut ssh,
            u_int,
            *mut Channel,
            *mut sshbuf,
            *mut sshbuf,
        ) -> libc::c_int,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mux_stdio_confirm_ctx {
    pub rid: u_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mux_channel_confirm_ctx {
    pub cid: u_int,
    pub rid: u_int,
    pub fid: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mux_session_confirm_ctx {
    pub want_tty: u_int,
    pub want_subsys: u_int,
    pub want_x_fwd: u_int,
    pub want_agent_fwd: u_int,
    pub cmd: *mut sshbuf,
    pub term: *mut libc::c_char,
    pub tio: termios,
    pub env: *mut *mut libc::c_char,
    pub rid: u_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mux_master_state {
    pub hello_rcvd: libc::c_int,
}
pub static mut muxserver_sock: libc::c_int = -(1 as libc::c_int);
pub static mut muxclient_request_id: u_int = 0 as libc::c_int as u_int;
pub static mut muxclient_command: u_int = 0 as libc::c_int as u_int;
static mut muxclient_terminate: sig_atomic_t = 0 as libc::c_int;
static mut muxserver_pid: u_int = 0 as libc::c_int as u_int;
static mut mux_listener_channel: *mut Channel = 0 as *const Channel as *mut Channel;
static mut mux_master_handlers: [C2RustUnnamed_4; 10] = unsafe {
    [
        {
            let mut init = C2RustUnnamed_4 {
                type_0: 0x1 as libc::c_int as u_int,
                handler: Some(
                    mux_master_process_hello
                        as unsafe extern "C" fn(
                            *mut ssh,
                            u_int,
                            *mut Channel,
                            *mut sshbuf,
                            *mut sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed_4 {
                type_0: 0x10000002 as libc::c_int as u_int,
                handler: Some(
                    mux_master_process_new_session
                        as unsafe extern "C" fn(
                            *mut ssh,
                            u_int,
                            *mut Channel,
                            *mut sshbuf,
                            *mut sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed_4 {
                type_0: 0x10000004 as libc::c_int as u_int,
                handler: Some(
                    mux_master_process_alive_check
                        as unsafe extern "C" fn(
                            *mut ssh,
                            u_int,
                            *mut Channel,
                            *mut sshbuf,
                            *mut sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed_4 {
                type_0: 0x10000005 as libc::c_int as u_int,
                handler: Some(
                    mux_master_process_terminate
                        as unsafe extern "C" fn(
                            *mut ssh,
                            u_int,
                            *mut Channel,
                            *mut sshbuf,
                            *mut sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed_4 {
                type_0: 0x10000006 as libc::c_int as u_int,
                handler: Some(
                    mux_master_process_open_fwd
                        as unsafe extern "C" fn(
                            *mut ssh,
                            u_int,
                            *mut Channel,
                            *mut sshbuf,
                            *mut sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed_4 {
                type_0: 0x10000007 as libc::c_int as u_int,
                handler: Some(
                    mux_master_process_close_fwd
                        as unsafe extern "C" fn(
                            *mut ssh,
                            u_int,
                            *mut Channel,
                            *mut sshbuf,
                            *mut sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed_4 {
                type_0: 0x10000008 as libc::c_int as u_int,
                handler: Some(
                    mux_master_process_stdio_fwd
                        as unsafe extern "C" fn(
                            *mut ssh,
                            u_int,
                            *mut Channel,
                            *mut sshbuf,
                            *mut sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed_4 {
                type_0: 0x10000009 as libc::c_int as u_int,
                handler: Some(
                    mux_master_process_stop_listening
                        as unsafe extern "C" fn(
                            *mut ssh,
                            u_int,
                            *mut Channel,
                            *mut sshbuf,
                            *mut sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed_4 {
                type_0: 0x1000000f as libc::c_int as u_int,
                handler: Some(
                    mux_master_process_proxy
                        as unsafe extern "C" fn(
                            *mut ssh,
                            u_int,
                            *mut Channel,
                            *mut sshbuf,
                            *mut sshbuf,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed_4 {
                type_0: 0 as libc::c_int as u_int,
                handler: None,
            };
            init
        },
    ]
};
unsafe extern "C" fn mux_master_session_cleanup_cb(
    mut ssh: *mut ssh,
    mut cid: libc::c_int,
    mut _force: libc::c_int,
    mut _unused: *mut libc::c_void,
) {
    let mut cc: *mut Channel = 0 as *mut Channel;
    let mut c: *mut Channel = channel_by_id(ssh, cid);
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
            b"mux_master_session_cleanup_cb\0",
        ))
        .as_ptr(),
        194 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering for channel %d\0" as *const u8 as *const libc::c_char,
        cid,
    );
    if c.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"mux_master_session_cleanup_cb\0",
            ))
            .as_ptr(),
            196 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel_by_id(%i) == NULL\0" as *const u8 as *const libc::c_char,
            cid,
        );
    }
    if (*c).ctl_chan != -(1 as libc::c_int) {
        cc = channel_by_id(ssh, (*c).ctl_chan);
        if cc.is_null() {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                    b"mux_master_session_cleanup_cb\0",
                ))
                .as_ptr(),
                200 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"channel %d missing control channel %d\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
                (*c).ctl_chan,
            );
        }
        (*c).ctl_chan = -(1 as libc::c_int);
        (*cc).remote_id = 0 as libc::c_int as uint32_t;
        (*cc).have_remote_id = 0 as libc::c_int;
        chan_rcvd_oclose(ssh, cc);
    }
    channel_cancel_cleanup(ssh, (*c).self_0);
}
unsafe extern "C" fn mux_master_control_cleanup_cb(
    mut ssh: *mut ssh,
    mut cid: libc::c_int,
    mut _force: libc::c_int,
    mut _unused: *mut libc::c_void,
) {
    let mut sc: *mut Channel = 0 as *mut Channel;
    let mut c: *mut Channel = channel_by_id(ssh, cid);
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
            b"mux_master_control_cleanup_cb\0",
        ))
        .as_ptr(),
        215 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering for channel %d\0" as *const u8 as *const libc::c_char,
        cid,
    );
    if c.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"mux_master_control_cleanup_cb\0",
            ))
            .as_ptr(),
            217 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel_by_id(%i) == NULL\0" as *const u8 as *const libc::c_char,
            cid,
        );
    }
    if (*c).have_remote_id != 0 {
        sc = channel_by_id(ssh, (*c).remote_id as libc::c_int);
        if sc.is_null() {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                    b"mux_master_control_cleanup_cb\0",
                ))
                .as_ptr(),
                221 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"channel %d missing session channel %u\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
                (*c).remote_id,
            );
        }
        (*c).remote_id = 0 as libc::c_int as uint32_t;
        (*c).have_remote_id = 0 as libc::c_int;
        (*sc).ctl_chan = -(1 as libc::c_int);
        if (*sc).type_0 != 4 as libc::c_int && (*sc).type_0 != 3 as libc::c_int {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                    b"mux_master_control_cleanup_cb\0",
                ))
                .as_ptr(),
                227 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"channel %d: not open\0" as *const u8 as *const libc::c_char,
                (*sc).self_0,
            );
            chan_mark_dead(ssh, sc);
        } else {
            if (*sc).istate == 0 as libc::c_int as libc::c_uint {
                chan_read_failed(ssh, sc);
            }
            if (*sc).ostate == 0 as libc::c_int as libc::c_uint {
                chan_write_failed(ssh, sc);
            }
        }
    }
    channel_cancel_cleanup(ssh, (*c).self_0);
}
unsafe extern "C" fn env_permitted(mut env: *const libc::c_char) -> libc::c_int {
    let mut i: u_int = 0;
    let mut ret: libc::c_int = 0;
    let mut name: [libc::c_char; 1024] = [0; 1024];
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    cp = strchr(env, '=' as i32);
    if cp.is_null() || cp == env as *mut libc::c_char {
        return 0 as libc::c_int;
    }
    ret = libc::snprintf(
        name.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
        b"%.*s\0" as *const u8 as *const libc::c_char,
        cp.offset_from(env) as libc::c_long as libc::c_int,
        env,
    );
    if ret <= 0 as libc::c_int
        || ret as size_t >= ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong
    {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"env_permitted\0"))
                .as_ptr(),
            251 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"name '%.100s...' too long\0" as *const u8 as *const libc::c_char,
            env,
        );
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_send_env {
        if match_pattern(name.as_mut_ptr(), *(options.send_env).offset(i as isize)) != 0 {
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn mux_master_process_hello(
    mut _ssh: *mut ssh,
    mut _rid: u_int,
    mut c: *mut Channel,
    mut m: *mut sshbuf,
    mut _reply: *mut sshbuf,
) -> libc::c_int {
    let mut ver: u_int = 0;
    let mut state: *mut mux_master_state = (*c).mux_ctx as *mut mux_master_state;
    let mut r: libc::c_int = 0;
    if state.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_master_process_hello\0",
            ))
            .as_ptr(),
            273 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: c->mux_ctx == NULL\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    if (*state).hello_rcvd != 0 {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_master_process_hello\0",
            ))
            .as_ptr(),
            275 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"HELLO received twice\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    r = sshbuf_get_u32(m, &mut ver);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_master_process_hello\0",
            ))
            .as_ptr(),
            279 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if ver != 4 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_master_process_hello\0",
            ))
            .as_ptr(),
            284 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"unsupported multiplexing protocol version %u (expected %u)\0" as *const u8
                as *const libc::c_char,
            ver,
            4 as libc::c_int,
        );
        return -(1 as libc::c_int);
    }
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"mux_master_process_hello\0"))
            .as_ptr(),
        287 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d client version %u\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        ver,
    );
    while sshbuf_len(m) > 0 as libc::c_int as libc::c_ulong {
        let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut value_len: size_t = 0 as libc::c_int as size_t;
        r = sshbuf_get_cstring(m, &mut name, 0 as *mut size_t);
        if r != 0 as libc::c_int || {
            r = sshbuf_get_string_direct(m, 0 as *mut *const u_char, &mut value_len);
            r != 0 as libc::c_int
        } {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"mux_master_process_hello\0",
                ))
                .as_ptr(),
                296 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"parse extension\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_master_process_hello\0",
            ))
            .as_ptr(),
            300 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Unrecognised extension \"%s\" length %zu\0" as *const u8 as *const libc::c_char,
            name,
            value_len,
        );
        libc::free(name as *mut libc::c_void);
    }
    (*state).hello_rcvd = 1 as libc::c_int;
    return 0 as libc::c_int;
}
unsafe extern "C" fn reply_ok(mut reply: *mut sshbuf, mut rid: u_int) {
    let mut r: libc::c_int = 0;
    r = sshbuf_put_u32(reply, 0x80000001 as libc::c_uint);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_u32(reply, rid);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"reply_ok\0")).as_ptr(),
            315 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"reply\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn reply_error(
    mut reply: *mut sshbuf,
    mut type_0: u_int,
    mut rid: u_int,
    mut msg: *const libc::c_char,
) {
    let mut r: libc::c_int = 0;
    r = sshbuf_put_u32(reply, type_0);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(reply, rid);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(reply, msg);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"reply_error\0")).as_ptr(),
            327 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"reply\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn mux_master_process_new_session(
    mut ssh: *mut ssh,
    mut rid: u_int,
    mut c: *mut Channel,
    mut m: *mut sshbuf,
    mut reply: *mut sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut nc: *mut Channel = 0 as *mut Channel;
    let mut cctx: *mut mux_session_confirm_ctx = 0 as *mut mux_session_confirm_ctx;
    let mut cmd: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: u_int = 0;
    let mut j: u_int = 0;
    let mut env_len: u_int = 0;
    let mut escape_char: u_int = 0;
    let mut window: u_int = 0;
    let mut packetmax: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut new_fd: [libc::c_int; 3] = [0; 3];
    cctx = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<mux_session_confirm_ctx>() as libc::c_ulong,
    ) as *mut mux_session_confirm_ctx;
    (*cctx).term = 0 as *mut libc::c_char;
    (*cctx).rid = rid;
    cmd = 0 as *mut libc::c_char;
    (*cctx).env = 0 as *mut *mut libc::c_char;
    env_len = 0 as libc::c_int as u_int;
    r = sshbuf_get_string_direct(m, 0 as *mut *const u_char, 0 as *mut size_t);
    if !(r != 0 as libc::c_int
        || {
            r = sshbuf_get_u32(m, &mut (*cctx).want_tty);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(m, &mut (*cctx).want_x_fwd);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(m, &mut (*cctx).want_agent_fwd);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(m, &mut (*cctx).want_subsys);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(m, &mut escape_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(m, &mut (*cctx).term, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(m, &mut cmd, 0 as *mut size_t);
            r != 0 as libc::c_int
        })
    {
        loop {
            if !(sshbuf_len(m) > 0 as libc::c_int as libc::c_ulong) {
                current_block = 15089075282327824602;
                break;
            }
            r = sshbuf_get_cstring(m, &mut cp, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                current_block = 12595637239762536930;
                break;
            }
            if env_permitted(cp) == 0 {
                libc::free(cp as *mut libc::c_void);
            } else {
                (*cctx).env = xreallocarray(
                    (*cctx).env as *mut libc::c_void,
                    env_len.wrapping_add(2 as libc::c_int as libc::c_uint) as size_t,
                    ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                ) as *mut *mut libc::c_char;
                let fresh0 = env_len;
                env_len = env_len.wrapping_add(1);
                let ref mut fresh1 = *((*cctx).env).offset(fresh0 as isize);
                *fresh1 = cp;
                let ref mut fresh2 = *((*cctx).env).offset(env_len as isize);
                *fresh2 = 0 as *mut libc::c_char;
                if !(env_len > 4096 as libc::c_int as libc::c_uint) {
                    continue;
                }
                crate::log::sshlog(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                        b"mux_master_process_new_session\0",
                    ))
                    .as_ptr(),
                    380 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b">%d environment variables received, ignoring additional\0" as *const u8
                        as *const libc::c_char,
                    4096 as libc::c_int,
                );
                current_block = 15089075282327824602;
                break;
            }
        }
        match current_block {
            12595637239762536930 => {}
            _ => {
                crate::log::sshlog(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<
                        &[u8; 31],
                        &[libc::c_char; 31],
                    >(b"mux_master_process_new_session\0"))
                        .as_ptr(),
                    388 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"channel %d: request tty %d, X %d, agent %d, subsys %d, term \"%s\", cmd \"%s\", env %u\0"
                        as *const u8 as *const libc::c_char,
                    (*c).self_0,
                    (*cctx).want_tty,
                    (*cctx).want_x_fwd,
                    (*cctx).want_agent_fwd,
                    (*cctx).want_subsys,
                    (*cctx).term,
                    cmd,
                    env_len,
                );
                (*cctx).cmd = sshbuf_new();
                if ((*cctx).cmd).is_null() {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                            b"mux_master_process_new_session\0",
                        ))
                        .as_ptr(),
                        391 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"sshbuf_new\0" as *const u8 as *const libc::c_char,
                    );
                }
                r = sshbuf_put((*cctx).cmd, cmd as *const libc::c_void, strlen(cmd));
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                            b"mux_master_process_new_session\0",
                        ))
                        .as_ptr(),
                        393 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"sshbuf_put\0" as *const u8 as *const libc::c_char,
                    );
                }
                libc::free(cmd as *mut libc::c_void);
                cmd = 0 as *mut libc::c_char;
                i = 0 as libc::c_int as u_int;
                while i < 3 as libc::c_int as libc::c_uint {
                    new_fd[i as usize] = mm_receive_fd((*c).sock);
                    if new_fd[i as usize] == -(1 as libc::c_int) {
                        crate::log::sshlog(
                            b"mux.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                                b"mux_master_process_new_session\0",
                            ))
                            .as_ptr(),
                            400 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"failed to receive fd %d from client\0" as *const u8
                                as *const libc::c_char,
                            i,
                        );
                        j = 0 as libc::c_int as u_int;
                        while j < i {
                            close(new_fd[j as usize]);
                            j = j.wrapping_add(1);
                            j;
                        }
                        j = 0 as libc::c_int as u_int;
                        while j < env_len {
                            libc::free(*((*cctx).env).offset(j as isize) as *mut libc::c_void);
                            j = j.wrapping_add(1);
                            j;
                        }
                        libc::free((*cctx).env as *mut libc::c_void);
                        libc::free((*cctx).term as *mut libc::c_void);
                        sshbuf_free((*cctx).cmd);
                        libc::free(cctx as *mut libc::c_void);
                        reply_error(
                            reply,
                            0x80000003 as libc::c_uint,
                            rid,
                            b"did not receive file descriptors\0" as *const u8
                                as *const libc::c_char,
                        );
                        return -(1 as libc::c_int);
                    }
                    i = i.wrapping_add(1);
                    i;
                }
                crate::log::sshlog(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                        b"mux_master_process_new_session\0",
                    ))
                    .as_ptr(),
                    416 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"got fds stdin %d, stdout %d, stderr %d\0" as *const u8 as *const libc::c_char,
                    new_fd[0 as libc::c_int as usize],
                    new_fd[1 as libc::c_int as usize],
                    new_fd[2 as libc::c_int as usize],
                );
                if (*c).have_remote_id != 0 {
                    crate::log::sshlog(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                            b"mux_master_process_new_session\0",
                        ))
                        .as_ptr(),
                        420 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"session already open\0" as *const u8 as *const libc::c_char,
                    );
                    reply_error(
                        reply,
                        0x80000003 as libc::c_uint,
                        rid,
                        b"Multiple sessions not supported\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    if options.control_master == 3 as libc::c_int
                        || options.control_master == 4 as libc::c_int
                    {
                        if ask_permission(
                            b"Allow shared connection to %s? \0" as *const u8
                                as *const libc::c_char,
                            host,
                        ) == 0
                        {
                            crate::log::sshlog(
                                b"mux.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                                    b"mux_master_process_new_session\0",
                                ))
                                .as_ptr(),
                                441 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"session refused by user\0" as *const u8 as *const libc::c_char,
                            );
                            reply_error(
                                reply,
                                0x80000002 as libc::c_uint,
                                rid,
                                b"Permission denied\0" as *const u8 as *const libc::c_char,
                            );
                            current_block = 10691586025446557322;
                        } else {
                            current_block = 13325891313334703151;
                        }
                    } else {
                        current_block = 13325891313334703151;
                    }
                    match current_block {
                        10691586025446557322 => {}
                        _ => {
                            if (*cctx).want_tty != 0
                                && tcgetattr(new_fd[0 as libc::c_int as usize], &mut (*cctx).tio)
                                    == -(1 as libc::c_int)
                            {
                                crate::log::sshlog(
                                    b"mux.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                                        b"mux_master_process_new_session\0",
                                    ))
                                    .as_ptr(),
                                    450 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"tcgetattr: %s\0" as *const u8 as *const libc::c_char,
                                    libc::strerror(*libc::__errno_location()),
                                );
                            }
                            window = (64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int))
                                as u_int;
                            packetmax = (32 as libc::c_int * 1024 as libc::c_int) as u_int;
                            if (*cctx).want_tty != 0 {
                                window >>= 1 as libc::c_int;
                                packetmax >>= 1 as libc::c_int;
                            }
                            nc = channel_new(
                                ssh,
                                b"session\0" as *const u8 as *const libc::c_char
                                    as *mut libc::c_char,
                                3 as libc::c_int,
                                new_fd[0 as libc::c_int as usize],
                                new_fd[1 as libc::c_int as usize],
                                new_fd[2 as libc::c_int as usize],
                                window,
                                packetmax,
                                2 as libc::c_int,
                                b"client-session\0" as *const u8 as *const libc::c_char,
                                2 as libc::c_int,
                            );
                            (*nc).ctl_chan = (*c).self_0;
                            (*c).remote_id = (*nc).self_0 as uint32_t;
                            (*c).have_remote_id = 1 as libc::c_int;
                            if (*cctx).want_tty != 0 && escape_char != 0xffffffff as libc::c_uint {
                                channel_register_filter(
                                    ssh,
                                    (*nc).self_0,
                                    Some(
                                        client_simple_escape_filter
                                            as unsafe extern "C" fn(
                                                *mut ssh,
                                                *mut Channel,
                                                *mut libc::c_char,
                                                libc::c_int,
                                            )
                                                -> libc::c_int,
                                    ),
                                    None,
                                    Some(
                                        client_filter_cleanup
                                            as unsafe extern "C" fn(
                                                *mut ssh,
                                                libc::c_int,
                                                *mut libc::c_void,
                                            )
                                                -> (),
                                    ),
                                    client_new_escape_filter_ctx(escape_char as libc::c_int),
                                );
                            }
                            crate::log::sshlog(
                                b"mux.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                                    b"mux_master_process_new_session\0",
                                ))
                                .as_ptr(),
                                475 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"channel_new: %d linked to control channel %d\0" as *const u8
                                    as *const libc::c_char,
                                (*nc).self_0,
                                (*nc).ctl_chan,
                            );
                            channel_send_open(ssh, (*nc).self_0);
                            channel_register_open_confirm(
                                ssh,
                                (*nc).self_0,
                                Some(
                                    mux_session_confirm
                                        as unsafe extern "C" fn(
                                            *mut ssh,
                                            libc::c_int,
                                            libc::c_int,
                                            *mut libc::c_void,
                                        )
                                            -> (),
                                ),
                                cctx as *mut libc::c_void,
                            );
                            (*c).mux_pause = 1 as libc::c_int;
                            channel_register_cleanup(
                                ssh,
                                (*nc).self_0,
                                Some(
                                    mux_master_session_cleanup_cb
                                        as unsafe extern "C" fn(
                                            *mut ssh,
                                            libc::c_int,
                                            libc::c_int,
                                            *mut libc::c_void,
                                        )
                                            -> (),
                                ),
                                1 as libc::c_int,
                            );
                            return 0 as libc::c_int;
                        }
                    }
                }
                close(new_fd[0 as libc::c_int as usize]);
                close(new_fd[1 as libc::c_int as usize]);
                close(new_fd[2 as libc::c_int as usize]);
                libc::free((*cctx).term as *mut libc::c_void);
                if env_len != 0 as libc::c_int as libc::c_uint {
                    i = 0 as libc::c_int as u_int;
                    while i < env_len {
                        libc::free(*((*cctx).env).offset(i as isize) as *mut libc::c_void);
                        i = i.wrapping_add(1);
                        i;
                    }
                    libc::free((*cctx).env as *mut libc::c_void);
                }
                sshbuf_free((*cctx).cmd);
                libc::free(cctx as *mut libc::c_void);
                return 0 as libc::c_int;
            }
        }
    }
    libc::free(cmd as *mut libc::c_void);
    j = 0 as libc::c_int as u_int;
    while j < env_len {
        libc::free(*((*cctx).env).offset(j as isize) as *mut libc::c_void);
        j = j.wrapping_add(1);
        j;
    }
    libc::free((*cctx).env as *mut libc::c_void);
    libc::free((*cctx).term as *mut libc::c_void);
    libc::free(cctx as *mut libc::c_void);
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
            b"mux_master_process_new_session\0",
        ))
        .as_ptr(),
        362 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"malformed message\0" as *const u8 as *const libc::c_char,
    );
    return -(1 as libc::c_int);
}
unsafe extern "C" fn mux_master_process_alive_check(
    mut _ssh: *mut ssh,
    mut rid: u_int,
    mut c: *mut Channel,
    mut _m: *mut sshbuf,
    mut reply: *mut sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
            b"mux_master_process_alive_check\0",
        ))
        .as_ptr(),
        493 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: alive check\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    r = sshbuf_put_u32(reply, 0x80000005 as libc::c_uint);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(reply, rid);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(reply, libc::getpid() as u_int);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                b"mux_master_process_alive_check\0",
            ))
            .as_ptr(),
            499 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"reply\0" as *const u8 as *const libc::c_char,
        );
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn mux_master_process_terminate(
    mut _ssh: *mut ssh,
    mut rid: u_int,
    mut c: *mut Channel,
    mut _m: *mut sshbuf,
    mut reply: *mut sshbuf,
) -> libc::c_int {
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
            b"mux_master_process_terminate\0",
        ))
        .as_ptr(),
        508 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: terminate request\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    if options.control_master == 3 as libc::c_int || options.control_master == 4 as libc::c_int {
        if ask_permission(
            b"Terminate shared connection to %s? \0" as *const u8 as *const libc::c_char,
            host,
        ) == 0
        {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"mux_master_process_terminate\0",
                ))
                .as_ptr(),
                514 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"termination refused by user\0" as *const u8 as *const libc::c_char,
            );
            reply_error(
                reply,
                0x80000002 as libc::c_uint,
                rid,
                b"Permission denied\0" as *const u8 as *const libc::c_char,
            );
            return 0 as libc::c_int;
        }
    }
    ::core::ptr::write_volatile(&mut quit_pending as *mut sig_atomic_t, 1 as libc::c_int);
    reply_ok(reply, rid);
    return 0 as libc::c_int;
}
unsafe extern "C" fn format_forward(mut ftype: u_int, mut fwd: *mut Forward) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    match ftype {
        1 => {
            crate::xmalloc::xasprintf(
                &mut ret as *mut *mut libc::c_char,
                b"local forward %.200s:%d -> %.200s:%d\0" as *const u8 as *const libc::c_char,
                if !((*fwd).listen_path).is_null() {
                    (*fwd).listen_path as *const libc::c_char
                } else if ((*fwd).listen_host).is_null() {
                    if options.fwd_opts.gateway_ports != 0 {
                        b"*\0" as *const u8 as *const libc::c_char
                    } else {
                        b"LOCALHOST\0" as *const u8 as *const libc::c_char
                    }
                } else {
                    (*fwd).listen_host as *const libc::c_char
                },
                (*fwd).listen_port,
                if !((*fwd).connect_path).is_null() {
                    (*fwd).connect_path
                } else {
                    (*fwd).connect_host
                },
                (*fwd).connect_port,
            );
        }
        3 => {
            crate::xmalloc::xasprintf(
                &mut ret as *mut *mut libc::c_char,
                b"dynamic forward %.200s:%d -> *\0" as *const u8 as *const libc::c_char,
                if ((*fwd).listen_host).is_null() {
                    if options.fwd_opts.gateway_ports != 0 {
                        b"*\0" as *const u8 as *const libc::c_char
                    } else {
                        b"LOCALHOST\0" as *const u8 as *const libc::c_char
                    }
                } else {
                    (*fwd).listen_host as *const libc::c_char
                },
                (*fwd).listen_port,
            );
        }
        2 => {
            crate::xmalloc::xasprintf(
                &mut ret as *mut *mut libc::c_char,
                b"remote forward %.200s:%d -> %.200s:%d\0" as *const u8 as *const libc::c_char,
                if !((*fwd).listen_path).is_null() {
                    (*fwd).listen_path as *const libc::c_char
                } else if ((*fwd).listen_host).is_null() {
                    b"LOCALHOST\0" as *const u8 as *const libc::c_char
                } else {
                    (*fwd).listen_host as *const libc::c_char
                },
                (*fwd).listen_port,
                if !((*fwd).connect_path).is_null() {
                    (*fwd).connect_path
                } else {
                    (*fwd).connect_host
                },
                (*fwd).connect_port,
            );
        }
        _ => {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"format_forward\0"))
                    .as_ptr(),
                558 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unknown forward type %u\0" as *const u8 as *const libc::c_char,
                ftype,
            );
        }
    }
    return ret;
}
unsafe extern "C" fn compare_host(
    mut a: *const libc::c_char,
    mut b: *const libc::c_char,
) -> libc::c_int {
    if a.is_null() && b.is_null() {
        return 1 as libc::c_int;
    }
    if a.is_null() || b.is_null() {
        return 0 as libc::c_int;
    }
    return (strcmp(a, b) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn compare_forward(mut a: *mut Forward, mut b: *mut Forward) -> libc::c_int {
    if compare_host((*a).listen_host, (*b).listen_host) == 0 {
        return 0 as libc::c_int;
    }
    if compare_host((*a).listen_path, (*b).listen_path) == 0 {
        return 0 as libc::c_int;
    }
    if (*a).listen_port != (*b).listen_port {
        return 0 as libc::c_int;
    }
    if compare_host((*a).connect_host, (*b).connect_host) == 0 {
        return 0 as libc::c_int;
    }
    if compare_host((*a).connect_path, (*b).connect_path) == 0 {
        return 0 as libc::c_int;
    }
    if (*a).connect_port != (*b).connect_port {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn mux_confirm_remote_forward(
    mut ssh: *mut ssh,
    mut type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ctxt: *mut libc::c_void,
) {
    let mut current_block: u64;
    let mut fctx: *mut mux_channel_confirm_ctx = ctxt as *mut mux_channel_confirm_ctx;
    let mut failmsg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut rfwd: *mut Forward = 0 as *mut Forward;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut out: *mut sshbuf = 0 as *mut sshbuf;
    let mut port: u_int = 0;
    let mut r: libc::c_int = 0;
    c = channel_by_id(ssh, (*fctx).cid as libc::c_int);
    if c.is_null() {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_confirm_remote_forward\0",
            ))
            .as_ptr(),
            605 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"unknown channel\0" as *const u8 as *const libc::c_char,
        );
        return;
    }
    out = sshbuf_new();
    if out.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_confirm_remote_forward\0",
            ))
            .as_ptr(),
            609 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*fctx).fid >= options.num_remote_forwards
        || ((*(options.remote_forwards).offset((*fctx).fid as isize)).connect_path).is_null()
            && ((*(options.remote_forwards).offset((*fctx).fid as isize)).connect_host).is_null()
    {
        crate::xmalloc::xasprintf(
            &mut failmsg as *mut *mut libc::c_char,
            b"unknown forwarding id %d\0" as *const u8 as *const libc::c_char,
            (*fctx).fid,
        );
        current_block = 7428911785391588765;
    } else {
        rfwd = &mut *(options.remote_forwards).offset((*fctx).fid as isize) as *mut Forward;
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_confirm_remote_forward\0",
            ))
            .as_ptr(),
            620 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s for: listen %d, connect %s:%d\0" as *const u8 as *const libc::c_char,
            if type_0 == 81 as libc::c_int {
                b"success\0" as *const u8 as *const libc::c_char
            } else {
                b"failure\0" as *const u8 as *const libc::c_char
            },
            (*rfwd).listen_port,
            if !((*rfwd).connect_path).is_null() {
                (*rfwd).connect_path
            } else {
                (*rfwd).connect_host
            },
            (*rfwd).connect_port,
        );
        if type_0 == 81 as libc::c_int {
            if (*rfwd).listen_port == 0 as libc::c_int {
                r = sshpkt_get_u32(ssh, &mut port);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"mux_confirm_remote_forward\0",
                        ))
                        .as_ptr(),
                        624 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse port\0" as *const u8 as *const libc::c_char,
                    );
                }
                if port > 65535 as libc::c_int as libc::c_uint {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"mux_confirm_remote_forward\0",
                        ))
                        .as_ptr(),
                        628 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Invalid allocated port %u for mux remote forward to %s:%d\0" as *const u8
                            as *const libc::c_char,
                        port,
                        (*rfwd).connect_host,
                        (*rfwd).connect_port,
                    );
                }
                (*rfwd).allocated_port = port as libc::c_int;
                crate::log::sshlog(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"mux_confirm_remote_forward\0",
                    ))
                    .as_ptr(),
                    633 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Allocated port %u for mux remote forward to %s:%d\0" as *const u8
                        as *const libc::c_char,
                    (*rfwd).allocated_port,
                    (*rfwd).connect_host,
                    (*rfwd).connect_port,
                );
                r = sshbuf_put_u32(out, 0x80000007 as libc::c_uint);
                if r != 0 as libc::c_int
                    || {
                        r = sshbuf_put_u32(out, (*fctx).rid);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshbuf_put_u32(out, (*rfwd).allocated_port as u_int32_t);
                        r != 0 as libc::c_int
                    }
                {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"mux_confirm_remote_forward\0",
                        ))
                        .as_ptr(),
                        639 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"reply\0" as *const u8 as *const libc::c_char,
                    );
                }
                channel_update_permission(ssh, (*rfwd).handle, (*rfwd).allocated_port);
            } else {
                reply_ok(out, (*fctx).rid);
            }
            current_block = 5397656515118090575;
        } else {
            if (*rfwd).listen_port == 0 as libc::c_int {
                channel_update_permission(ssh, (*rfwd).handle, -(1 as libc::c_int));
            }
            if !((*rfwd).listen_path).is_null() {
                crate::xmalloc::xasprintf(
                    &mut failmsg as *mut *mut libc::c_char,
                    b"remote port forwarding failed for listen path %s\0" as *const u8
                        as *const libc::c_char,
                    (*rfwd).listen_path,
                );
            } else {
                crate::xmalloc::xasprintf(
                    &mut failmsg as *mut *mut libc::c_char,
                    b"remote port forwarding failed for listen port %d\0" as *const u8
                        as *const libc::c_char,
                    (*rfwd).listen_port,
                );
            }
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"mux_confirm_remote_forward\0",
                ))
                .as_ptr(),
                659 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"clearing registered forwarding for listen %d, connect %s:%d\0" as *const u8
                    as *const libc::c_char,
                (*rfwd).listen_port,
                if !((*rfwd).connect_path).is_null() {
                    (*rfwd).connect_path
                } else {
                    (*rfwd).connect_host
                },
                (*rfwd).connect_port,
            );
            libc::free((*rfwd).listen_host as *mut libc::c_void);
            libc::free((*rfwd).listen_path as *mut libc::c_void);
            libc::free((*rfwd).connect_host as *mut libc::c_void);
            libc::free((*rfwd).connect_path as *mut libc::c_void);
            memset(
                rfwd as *mut libc::c_void,
                0 as libc::c_int,
                ::core::mem::size_of::<Forward>() as libc::c_ulong,
            );
            current_block = 7428911785391588765;
        }
    }
    match current_block {
        7428911785391588765 => {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"mux_confirm_remote_forward\0",
                ))
                .as_ptr(),
                668 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"%s\0" as *const u8 as *const libc::c_char,
                failmsg,
            );
            reply_error(out, 0x80000003 as libc::c_uint, (*fctx).rid, failmsg);
            libc::free(failmsg as *mut libc::c_void);
        }
        _ => {}
    }
    r = sshbuf_put_stringb((*c).output, out);
    if r != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_confirm_remote_forward\0",
            ))
            .as_ptr(),
            673 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"enqueue\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(out);
    if (*c).mux_pause <= 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_confirm_remote_forward\0",
            ))
            .as_ptr(),
            676 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"mux_pause %d\0" as *const u8 as *const libc::c_char,
            (*c).mux_pause,
        );
    }
    (*c).mux_pause = 0 as libc::c_int;
}
unsafe extern "C" fn mux_master_process_open_fwd(
    mut ssh: *mut ssh,
    mut rid: u_int,
    mut c: *mut Channel,
    mut m: *mut sshbuf,
    mut reply: *mut sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut fwd: Forward = Forward {
        listen_host: 0 as *mut libc::c_char,
        listen_port: 0,
        listen_path: 0 as *mut libc::c_char,
        connect_host: 0 as *mut libc::c_char,
        connect_port: 0,
        connect_path: 0 as *mut libc::c_char,
        allocated_port: 0,
        handle: 0,
    };
    let mut fwd_desc: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut listen_addr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut connect_addr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ftype: u_int = 0;
    let mut lport: u_int = 0;
    let mut cport: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut freefwd: libc::c_int = 1 as libc::c_int;
    memset(
        &mut fwd as *mut Forward as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<Forward>() as libc::c_ulong,
    );
    r = sshbuf_get_u32(m, &mut ftype);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_cstring(m, &mut listen_addr, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(m, &mut lport);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(m, &mut connect_addr, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(m, &mut cport);
            r != 0 as libc::c_int
        }
        || lport != -(2 as libc::c_int) as u_int && lport > 65535 as libc::c_int as libc::c_uint
        || cport != -(2 as libc::c_int) as u_int && cport > 65535 as libc::c_int as libc::c_uint
    {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"mux_master_process_open_fwd\0",
            ))
            .as_ptr(),
            701 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"malformed message\0" as *const u8 as *const libc::c_char,
        );
        ret = -(1 as libc::c_int);
    } else {
        if *listen_addr as libc::c_int == '\0' as i32 {
            libc::free(listen_addr as *mut libc::c_void);
            listen_addr = 0 as *mut libc::c_char;
        }
        if *connect_addr as libc::c_int == '\0' as i32 {
            libc::free(connect_addr as *mut libc::c_void);
            connect_addr = 0 as *mut libc::c_char;
        }
        memset(
            &mut fwd as *mut Forward as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<Forward>() as libc::c_ulong,
        );
        fwd.listen_port = lport as libc::c_int;
        if fwd.listen_port == -(2 as libc::c_int) {
            fwd.listen_path = listen_addr;
        } else {
            fwd.listen_host = listen_addr;
        }
        fwd.connect_port = cport as libc::c_int;
        if fwd.connect_port == -(2 as libc::c_int) {
            fwd.connect_path = connect_addr;
        } else {
            fwd.connect_host = connect_addr;
        }
        fwd_desc = format_forward(ftype, &mut fwd);
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"mux_master_process_open_fwd\0",
            ))
            .as_ptr(),
            727 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: request %s\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            fwd_desc,
        );
        if ftype != 1 as libc::c_int as libc::c_uint
            && ftype != 2 as libc::c_int as libc::c_uint
            && ftype != 3 as libc::c_int as libc::c_uint
        {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"mux_master_process_open_fwd\0",
                ))
                .as_ptr(),
                731 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"invalid forwarding type %u\0" as *const u8 as *const libc::c_char,
                ftype,
            );
            current_block = 5047716924377657291;
        } else if ftype == 3 as libc::c_int as libc::c_uint && !(fwd.listen_path).is_null() {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"mux_master_process_open_fwd\0",
                ))
                .as_ptr(),
                741 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"streamlocal and dynamic forwards are mutually exclusive\0" as *const u8
                    as *const libc::c_char,
            );
            current_block = 5047716924377657291;
        } else if fwd.listen_port != -(2 as libc::c_int) && fwd.listen_port >= 65536 as libc::c_int
        {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"mux_master_process_open_fwd\0",
                ))
                .as_ptr(),
                745 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"invalid listen port %u\0" as *const u8 as *const libc::c_char,
                fwd.listen_port,
            );
            current_block = 5047716924377657291;
        } else if fwd.connect_port != -(2 as libc::c_int)
            && fwd.connect_port >= 65536 as libc::c_int
            || ftype != 3 as libc::c_int as libc::c_uint
                && ftype != 2 as libc::c_int as libc::c_uint
                && fwd.connect_port == 0 as libc::c_int
        {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"mux_master_process_open_fwd\0",
                ))
                .as_ptr(),
                753 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"invalid connect port %u\0" as *const u8 as *const libc::c_char,
                fwd.connect_port,
            );
            current_block = 5047716924377657291;
        } else if ftype != 3 as libc::c_int as libc::c_uint
            && (fwd.connect_host).is_null()
            && (fwd.connect_path).is_null()
        {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"mux_master_process_open_fwd\0",
                ))
                .as_ptr(),
                758 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"missing connect host\0" as *const u8 as *const libc::c_char,
            );
            current_block = 5047716924377657291;
        } else {
            match ftype {
                1 | 3 => {
                    i = 0 as libc::c_int;
                    loop {
                        if !(i < options.num_local_forwards) {
                            current_block = 2122094917359643297;
                            break;
                        }
                        if compare_forward(&mut fwd, (options.local_forwards).offset(i as isize))
                            != 0
                        {
                            current_block = 13052835669559576429;
                            break;
                        }
                        i += 1;
                        i;
                    }
                }
                2 => {
                    i = 0 as libc::c_int;
                    loop {
                        if !(i < options.num_remote_forwards) {
                            current_block = 2122094917359643297;
                            break;
                        }
                        if compare_forward(&mut fwd, (options.remote_forwards).offset(i as isize))
                            == 0
                        {
                            i += 1;
                            i;
                        } else {
                            if fwd.listen_port != 0 as libc::c_int {
                                current_block = 13052835669559576429;
                                break;
                            }
                            crate::log::sshlog(
                                b"mux.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                    b"mux_master_process_open_fwd\0",
                                ))
                                .as_ptr(),
                                782 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"found allocated port\0" as *const u8 as *const libc::c_char,
                            );
                            r = sshbuf_put_u32(reply, 0x80000007 as libc::c_uint);
                            if r != 0 as libc::c_int
                                || {
                                    r = sshbuf_put_u32(reply, rid);
                                    r != 0 as libc::c_int
                                }
                                || {
                                    r = sshbuf_put_u32(
                                        reply,
                                        (*(options.remote_forwards).offset(i as isize))
                                            .allocated_port
                                            as u_int32_t,
                                    );
                                    r != 0 as libc::c_int
                                }
                            {
                                sshfatal(
                                    b"mux.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                        b"mux_master_process_open_fwd\0",
                                    ))
                                    .as_ptr(),
                                    788 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"reply FWD_REMOTE\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            current_block = 5412649325144431251;
                            break;
                        }
                    }
                }
                _ => {
                    current_block = 2122094917359643297;
                }
            }
            match current_block {
                5412649325144431251 => {}
                _ => {
                    match current_block {
                        13052835669559576429 => {
                            crate::log::sshlog(
                                b"mux.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                    b"mux_master_process_open_fwd\0",
                                ))
                                .as_ptr(),
                                770 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"found existing forwarding\0" as *const u8 as *const libc::c_char,
                            );
                            reply_ok(reply, rid);
                        }
                        _ => {
                            if options.control_master == 3 as libc::c_int
                                || options.control_master == 4 as libc::c_int
                            {
                                if ask_permission(
                                    b"Open %s on %s?\0" as *const u8 as *const libc::c_char,
                                    fwd_desc,
                                    host,
                                ) == 0
                                {
                                    crate::log::sshlog(
                                        b"mux.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                            b"mux_master_process_open_fwd\0",
                                        ))
                                        .as_ptr(),
                                        797 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG2,
                                        0 as *const libc::c_char,
                                        b"forwarding refused by user\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                    reply_error(
                                        reply,
                                        0x80000002 as libc::c_uint,
                                        rid,
                                        b"Permission denied\0" as *const u8 as *const libc::c_char,
                                    );
                                    current_block = 5412649325144431251;
                                } else {
                                    current_block = 1423531122933789233;
                                }
                            } else {
                                current_block = 1423531122933789233;
                            }
                            match current_block {
                                5412649325144431251 => {}
                                _ => {
                                    if ftype == 1 as libc::c_int as libc::c_uint
                                        || ftype == 3 as libc::c_int as libc::c_uint
                                    {
                                        if channel_setup_local_fwd_listener(
                                            ssh,
                                            &mut fwd,
                                            &mut options.fwd_opts,
                                        ) == 0
                                        {
                                            current_block = 1889179602920924282;
                                        } else {
                                            add_local_forward(&mut options, &mut fwd);
                                            freefwd = 0 as libc::c_int;
                                            reply_ok(reply, rid);
                                            current_block = 5412649325144431251;
                                        }
                                    } else {
                                        let mut fctx: *mut mux_channel_confirm_ctx =
                                            0 as *mut mux_channel_confirm_ctx;
                                        fwd.handle =
                                            channel_request_remote_forwarding(ssh, &mut fwd);
                                        if fwd.handle < 0 as libc::c_int {
                                            current_block = 1889179602920924282;
                                        } else {
                                            add_remote_forward(&mut options, &mut fwd);
                                            fctx = crate::xmalloc::xcalloc(
                                                1 as libc::c_int as size_t,
                                                ::core::mem::size_of::<mux_channel_confirm_ctx>()
                                                    as libc::c_ulong,
                                            )
                                                as *mut mux_channel_confirm_ctx;
                                            (*fctx).cid = (*c).self_0 as u_int;
                                            (*fctx).rid = rid;
                                            (*fctx).fid =
                                                options.num_remote_forwards - 1 as libc::c_int;
                                            client_register_global_confirm(
                                                Some(
                                                    mux_confirm_remote_forward
                                                        as unsafe extern "C" fn(
                                                            *mut ssh,
                                                            libc::c_int,
                                                            u_int32_t,
                                                            *mut libc::c_void,
                                                        )
                                                            -> (),
                                                ),
                                                fctx as *mut libc::c_void,
                                            );
                                            freefwd = 0 as libc::c_int;
                                            (*c).mux_pause = 1 as libc::c_int;
                                            current_block = 5412649325144431251;
                                        }
                                    }
                                    match current_block {
                                        5412649325144431251 => {}
                                        _ => {
                                            crate::log::sshlog(
                                                b"mux.c\0" as *const u8 as *const libc::c_char,
                                                (*::core::mem::transmute::<
                                                    &[u8; 28],
                                                    &[libc::c_char; 28],
                                                >(
                                                    b"mux_master_process_open_fwd\0"
                                                ))
                                                .as_ptr(),
                                                808 as libc::c_int,
                                                1 as libc::c_int,
                                                SYSLOG_LEVEL_INFO,
                                                0 as *const libc::c_char,
                                                b"requested %s failed\0" as *const u8
                                                    as *const libc::c_char,
                                                fwd_desc,
                                            );
                                            reply_error(
                                                reply,
                                                0x80000003 as libc::c_uint,
                                                rid,
                                                b"Port forwarding failed\0" as *const u8
                                                    as *const libc::c_char,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    current_block = 5412649325144431251;
                }
            }
        }
        match current_block {
            5412649325144431251 => {}
            _ => {
                libc::free(listen_addr as *mut libc::c_void);
                libc::free(connect_addr as *mut libc::c_void);
                reply_error(
                    reply,
                    0x80000003 as libc::c_uint,
                    rid,
                    b"Invalid forwarding request\0" as *const u8 as *const libc::c_char,
                );
                return 0 as libc::c_int;
            }
        }
    }
    libc::free(fwd_desc as *mut libc::c_void);
    if freefwd != 0 {
        libc::free(fwd.listen_host as *mut libc::c_void);
        libc::free(fwd.listen_path as *mut libc::c_void);
        libc::free(fwd.connect_host as *mut libc::c_void);
        libc::free(fwd.connect_path as *mut libc::c_void);
    }
    return ret;
}
unsafe extern "C" fn mux_master_process_close_fwd(
    mut ssh: *mut ssh,
    mut rid: u_int,
    mut c: *mut Channel,
    mut m: *mut sshbuf,
    mut reply: *mut sshbuf,
) -> libc::c_int {
    let mut fwd: Forward = Forward {
        listen_host: 0 as *mut libc::c_char,
        listen_port: 0,
        listen_path: 0 as *mut libc::c_char,
        connect_host: 0 as *mut libc::c_char,
        connect_port: 0,
        connect_path: 0 as *mut libc::c_char,
        allocated_port: 0,
        handle: 0,
    };
    let mut found_fwd: *mut Forward = 0 as *mut Forward;
    let mut fwd_desc: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut error_reason: *const libc::c_char = 0 as *const libc::c_char;
    let mut listen_addr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut connect_addr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ftype: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut lport: u_int = 0;
    let mut cport: u_int = 0;
    memset(
        &mut fwd as *mut Forward as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<Forward>() as libc::c_ulong,
    );
    r = sshbuf_get_u32(m, &mut ftype);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_cstring(m, &mut listen_addr, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(m, &mut lport);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(m, &mut connect_addr, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(m, &mut cport);
            r != 0 as libc::c_int
        }
        || lport != -(2 as libc::c_int) as u_int && lport > 65535 as libc::c_int as libc::c_uint
        || cport != -(2 as libc::c_int) as u_int && cport > 65535 as libc::c_int as libc::c_uint
    {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_master_process_close_fwd\0",
            ))
            .as_ptr(),
            866 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"malformed message\0" as *const u8 as *const libc::c_char,
        );
        ret = -(1 as libc::c_int);
    } else {
        if *listen_addr as libc::c_int == '\0' as i32 {
            libc::free(listen_addr as *mut libc::c_void);
            listen_addr = 0 as *mut libc::c_char;
        }
        if *connect_addr as libc::c_int == '\0' as i32 {
            libc::free(connect_addr as *mut libc::c_void);
            connect_addr = 0 as *mut libc::c_char;
        }
        memset(
            &mut fwd as *mut Forward as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<Forward>() as libc::c_ulong,
        );
        fwd.listen_port = lport as libc::c_int;
        if fwd.listen_port == -(2 as libc::c_int) {
            fwd.listen_path = listen_addr;
        } else {
            fwd.listen_host = listen_addr;
        }
        fwd.connect_port = cport as libc::c_int;
        if fwd.connect_port == -(2 as libc::c_int) {
            fwd.connect_path = connect_addr;
        } else {
            fwd.connect_host = connect_addr;
        }
        fwd_desc = format_forward(ftype, &mut fwd);
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_master_process_close_fwd\0",
            ))
            .as_ptr(),
            893 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: request cancel %s\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            fwd_desc,
        );
        found_fwd = 0 as *mut Forward;
        match ftype {
            1 | 3 => {
                i = 0 as libc::c_int;
                while i < options.num_local_forwards {
                    if compare_forward(&mut fwd, (options.local_forwards).offset(i as isize)) != 0 {
                        found_fwd = (options.local_forwards).offset(i as isize);
                        break;
                    } else {
                        i += 1;
                        i;
                    }
                }
            }
            2 => {
                i = 0 as libc::c_int;
                while i < options.num_remote_forwards {
                    if compare_forward(&mut fwd, (options.remote_forwards).offset(i as isize)) != 0
                    {
                        found_fwd = (options.remote_forwards).offset(i as isize);
                        break;
                    } else {
                        i += 1;
                        i;
                    }
                }
            }
            _ => {}
        }
        if found_fwd.is_null() {
            error_reason = b"port not forwarded\0" as *const u8 as *const libc::c_char;
        } else if ftype == 2 as libc::c_int as libc::c_uint {
            if channel_request_rforward_cancel(ssh, found_fwd) == -(1 as libc::c_int) {
                error_reason = b"port not in permitted opens\0" as *const u8 as *const libc::c_char;
            }
        } else if channel_cancel_lport_listener(
            ssh,
            &mut fwd,
            fwd.connect_port,
            &mut options.fwd_opts,
        ) == -(1 as libc::c_int)
        {
            error_reason = b"port not found\0" as *const u8 as *const libc::c_char;
        }
        if !error_reason.is_null() {
            reply_error(reply, 0x80000003 as libc::c_uint, rid, error_reason);
        } else {
            reply_ok(reply, rid);
            libc::free((*found_fwd).listen_host as *mut libc::c_void);
            libc::free((*found_fwd).listen_path as *mut libc::c_void);
            libc::free((*found_fwd).connect_host as *mut libc::c_void);
            libc::free((*found_fwd).connect_path as *mut libc::c_void);
            (*found_fwd).connect_host = 0 as *mut libc::c_char;
            (*found_fwd).listen_host = (*found_fwd).connect_host;
            (*found_fwd).connect_path = 0 as *mut libc::c_char;
            (*found_fwd).listen_path = (*found_fwd).connect_path;
            (*found_fwd).connect_port = 0 as libc::c_int;
            (*found_fwd).listen_port = (*found_fwd).connect_port;
        }
    }
    libc::free(fwd_desc as *mut libc::c_void);
    libc::free(listen_addr as *mut libc::c_void);
    libc::free(connect_addr as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn mux_master_process_stdio_fwd(
    mut ssh: *mut ssh,
    mut rid: u_int,
    mut c: *mut Channel,
    mut m: *mut sshbuf,
    mut reply: *mut sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut nc: *mut Channel = 0 as *mut Channel;
    let mut chost: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cport: u_int = 0;
    let mut i: u_int = 0;
    let mut j: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut new_fd: [libc::c_int; 2] = [0; 2];
    let mut cctx: *mut mux_stdio_confirm_ctx = 0 as *mut mux_stdio_confirm_ctx;
    r = sshbuf_get_string_direct(m, 0 as *mut *const u_char, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_cstring(m, &mut chost, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(m, &mut cport);
            r != 0 as libc::c_int
        }
    {
        libc::free(chost as *mut libc::c_void);
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_master_process_stdio_fwd\0",
            ))
            .as_ptr(),
            971 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"malformed message\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
            b"mux_master_process_stdio_fwd\0",
        ))
        .as_ptr(),
        975 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: stdio fwd to %s:%u\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        chost,
        cport,
    );
    i = 0 as libc::c_int as u_int;
    while i < 2 as libc::c_int as libc::c_uint {
        new_fd[i as usize] = mm_receive_fd((*c).sock);
        if new_fd[i as usize] == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"mux_master_process_stdio_fwd\0",
                ))
                .as_ptr(),
                980 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"failed to receive fd %d from client\0" as *const u8 as *const libc::c_char,
                i,
            );
            j = 0 as libc::c_int as u_int;
            while j < i {
                close(new_fd[j as usize]);
                j = j.wrapping_add(1);
                j;
            }
            libc::free(chost as *mut libc::c_void);
            reply_error(
                reply,
                0x80000003 as libc::c_uint,
                rid,
                b"did not receive file descriptors\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        i = i.wrapping_add(1);
        i;
    }
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
            b"mux_master_process_stdio_fwd\0",
        ))
        .as_ptr(),
        992 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"got fds stdin %d, stdout %d\0" as *const u8 as *const libc::c_char,
        new_fd[0 as libc::c_int as usize],
        new_fd[1 as libc::c_int as usize],
    );
    if (*c).have_remote_id != 0 {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_master_process_stdio_fwd\0",
            ))
            .as_ptr(),
            996 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"session already open\0" as *const u8 as *const libc::c_char,
        );
        reply_error(
            reply,
            0x80000003 as libc::c_uint,
            rid,
            b"Multiple sessions not supported\0" as *const u8 as *const libc::c_char,
        );
    } else {
        if options.control_master == 3 as libc::c_int || options.control_master == 4 as libc::c_int
        {
            if ask_permission(
                b"Allow forward to %s:%u? \0" as *const u8 as *const libc::c_char,
                chost,
                cport,
            ) == 0
            {
                crate::log::sshlog(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"mux_master_process_stdio_fwd\0",
                    ))
                    .as_ptr(),
                    1010 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"stdio fwd refused by user\0" as *const u8 as *const libc::c_char,
                );
                reply_error(
                    reply,
                    0x80000002 as libc::c_uint,
                    rid,
                    b"Permission denied\0" as *const u8 as *const libc::c_char,
                );
                current_block = 16832162178441155431;
            } else {
                current_block = 2719512138335094285;
            }
        } else {
            current_block = 2719512138335094285;
        }
        match current_block {
            16832162178441155431 => {}
            _ => {
                nc = channel_connect_stdio_fwd(
                    ssh,
                    chost,
                    cport as u_short,
                    new_fd[0 as libc::c_int as usize],
                    new_fd[1 as libc::c_int as usize],
                    2 as libc::c_int,
                );
                libc::free(chost as *mut libc::c_void);
                (*nc).ctl_chan = (*c).self_0;
                (*c).remote_id = (*nc).self_0 as uint32_t;
                (*c).have_remote_id = 1 as libc::c_int;
                crate::log::sshlog(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"mux_master_process_stdio_fwd\0",
                    ))
                    .as_ptr(),
                    1025 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"channel_new: %d control %d\0" as *const u8 as *const libc::c_char,
                    (*nc).self_0,
                    (*nc).ctl_chan,
                );
                channel_register_cleanup(
                    ssh,
                    (*nc).self_0,
                    Some(
                        mux_master_session_cleanup_cb
                            as unsafe extern "C" fn(
                                *mut ssh,
                                libc::c_int,
                                libc::c_int,
                                *mut libc::c_void,
                            ) -> (),
                    ),
                    1 as libc::c_int,
                );
                cctx = crate::xmalloc::xcalloc(
                    1 as libc::c_int as size_t,
                    ::core::mem::size_of::<mux_stdio_confirm_ctx>() as libc::c_ulong,
                ) as *mut mux_stdio_confirm_ctx;
                (*cctx).rid = rid;
                channel_register_open_confirm(
                    ssh,
                    (*nc).self_0,
                    Some(
                        mux_stdio_confirm
                            as unsafe extern "C" fn(
                                *mut ssh,
                                libc::c_int,
                                libc::c_int,
                                *mut libc::c_void,
                            ) -> (),
                    ),
                    cctx as *mut libc::c_void,
                );
                (*c).mux_pause = 1 as libc::c_int;
                return 0 as libc::c_int;
            }
        }
    }
    close(new_fd[0 as libc::c_int as usize]);
    close(new_fd[1 as libc::c_int as usize]);
    libc::free(chost as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn mux_stdio_confirm(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut success: libc::c_int,
    mut arg: *mut libc::c_void,
) {
    let mut cctx: *mut mux_stdio_confirm_ctx = arg as *mut mux_stdio_confirm_ctx;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut cc: *mut Channel = 0 as *mut Channel;
    let mut reply: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    if cctx.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"mux_stdio_confirm\0"))
                .as_ptr(),
            1049 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"cctx == NULL\0" as *const u8 as *const libc::c_char,
        );
    }
    c = channel_by_id(ssh, id);
    if c.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"mux_stdio_confirm\0"))
                .as_ptr(),
            1051 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no channel for id %d\0" as *const u8 as *const libc::c_char,
            id,
        );
    }
    cc = channel_by_id(ssh, (*c).ctl_chan);
    if cc.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"mux_stdio_confirm\0"))
                .as_ptr(),
            1054 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d lacks control channel %d\0" as *const u8 as *const libc::c_char,
            id,
            (*c).ctl_chan,
        );
    }
    reply = sshbuf_new();
    if reply.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"mux_stdio_confirm\0"))
                .as_ptr(),
            1056 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    if success == 0 {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"mux_stdio_confirm\0"))
                .as_ptr(),
            1059 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"sending failure reply\0" as *const u8 as *const libc::c_char,
        );
        reply_error(
            reply,
            0x80000003 as libc::c_uint,
            (*cctx).rid,
            b"Session open refused by peer\0" as *const u8 as *const libc::c_char,
        );
    } else {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"mux_stdio_confirm\0"))
                .as_ptr(),
            1066 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"sending success reply\0" as *const u8 as *const libc::c_char,
        );
        r = sshbuf_put_u32(reply, 0x80000006 as libc::c_uint);
        if r != 0 as libc::c_int
            || {
                r = sshbuf_put_u32(reply, (*cctx).rid);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_u32(reply, (*c).self_0 as u_int32_t);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"mux_stdio_confirm\0"))
                    .as_ptr(),
                1071 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"reply\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    r = sshbuf_put_stringb((*cc).output, reply);
    if r != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"mux_stdio_confirm\0"))
                .as_ptr(),
            1076 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"enqueue\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(reply);
    if (*cc).mux_pause <= 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"mux_stdio_confirm\0"))
                .as_ptr(),
            1080 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"mux_pause %d\0" as *const u8 as *const libc::c_char,
            (*cc).mux_pause,
        );
    }
    (*cc).mux_pause = 0 as libc::c_int;
    (*c).open_confirm_ctx = 0 as *mut libc::c_void;
    libc::free(cctx as *mut libc::c_void);
}
unsafe extern "C" fn mux_master_process_stop_listening(
    mut ssh: *mut ssh,
    mut rid: u_int,
    mut c: *mut Channel,
    mut _m: *mut sshbuf,
    mut reply: *mut sshbuf,
) -> libc::c_int {
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
            b"mux_master_process_stop_listening\0",
        ))
        .as_ptr(),
        1090 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"channel %d: stop listening\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    if options.control_master == 3 as libc::c_int || options.control_master == 4 as libc::c_int {
        if ask_permission(
            b"Disable further multiplexing on shared connection to %s? \0" as *const u8
                as *const libc::c_char,
            host,
        ) == 0
        {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                    b"mux_master_process_stop_listening\0",
                ))
                .as_ptr(),
                1096 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"stop listen refused by user\0" as *const u8 as *const libc::c_char,
            );
            reply_error(
                reply,
                0x80000002 as libc::c_uint,
                rid,
                b"Permission denied\0" as *const u8 as *const libc::c_char,
            );
            return 0 as libc::c_int;
        }
    }
    if !mux_listener_channel.is_null() {
        channel_free(ssh, mux_listener_channel);
        client_stop_mux();
        libc::free(options.control_path as *mut libc::c_void);
        options.control_path = 0 as *mut libc::c_char;
        mux_listener_channel = 0 as *mut Channel;
        muxserver_sock = -(1 as libc::c_int);
    }
    reply_ok(reply, rid);
    return 0 as libc::c_int;
}
unsafe extern "C" fn mux_master_process_proxy(
    mut _ssh: *mut ssh,
    mut rid: u_int,
    mut c: *mut Channel,
    mut _m: *mut sshbuf,
    mut reply: *mut sshbuf,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"mux_master_process_proxy\0"))
            .as_ptr(),
        1122 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"channel %d: proxy request\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    (*c).mux_rcb = Some(
        channel_proxy_downstream as unsafe extern "C" fn(*mut ssh, *mut Channel) -> libc::c_int,
    );
    r = sshbuf_put_u32(reply, 0x8000000f as libc::c_uint);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_u32(reply, rid);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_master_process_proxy\0",
            ))
            .as_ptr(),
            1127 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"reply\0" as *const u8 as *const libc::c_char,
        );
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn mux_master_read_cb(mut ssh: *mut ssh, mut c: *mut Channel) -> libc::c_int {
    let mut current_block: u64;
    let mut state: *mut mux_master_state = (*c).mux_ctx as *mut mux_master_state;
    let mut in_0: *mut sshbuf = 0 as *mut sshbuf;
    let mut out: *mut sshbuf = 0 as *mut sshbuf;
    let mut type_0: u_int = 0;
    let mut rid: u_int = 0;
    let mut i: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    out = sshbuf_new();
    if out.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mux_master_read_cb\0"))
                .as_ptr(),
            1142 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    if ((*c).mux_ctx).is_null() {
        state = crate::xmalloc::xcalloc(
            1 as libc::c_int as size_t,
            ::core::mem::size_of::<mux_master_state>() as libc::c_ulong,
        ) as *mut mux_master_state;
        (*c).mux_ctx = state as *mut libc::c_void;
        channel_register_cleanup(
            ssh,
            (*c).self_0,
            Some(
                mux_master_control_cleanup_cb
                    as unsafe extern "C" fn(
                        *mut ssh,
                        libc::c_int,
                        libc::c_int,
                        *mut libc::c_void,
                    ) -> (),
            ),
            0 as libc::c_int,
        );
        r = sshbuf_put_u32(out, 0x1 as libc::c_int as u_int32_t);
        if r != 0 as libc::c_int || {
            r = sshbuf_put_u32(out, 4 as libc::c_int as u_int32_t);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"mux_master_read_cb\0",
                ))
                .as_ptr(),
                1154 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"reply\0" as *const u8 as *const libc::c_char,
            );
        }
        r = sshbuf_put_stringb((*c).output, out);
        if r != 0 as libc::c_int {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"mux_master_read_cb\0",
                ))
                .as_ptr(),
                1157 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"enqueue\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mux_master_read_cb\0"))
                .as_ptr(),
            1158 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"channel %d: hello sent\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        ret = 0 as libc::c_int;
    } else {
        r = sshbuf_froms((*c).input, &mut in_0);
        if r != 0 as libc::c_int {
            current_block = 15549934470666749764;
        } else {
            r = sshbuf_get_u32(in_0, &mut type_0);
            if r != 0 as libc::c_int {
                current_block = 15549934470666749764;
            } else {
                crate::log::sshlog(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"mux_master_read_cb\0",
                    ))
                    .as_ptr(),
                    1173 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"channel %d packet type 0x%08x len %zu\0" as *const u8 as *const libc::c_char,
                    (*c).self_0,
                    type_0,
                    sshbuf_len(in_0),
                );
                if type_0 == 0x1 as libc::c_int as libc::c_uint {
                    rid = 0 as libc::c_int as u_int;
                    current_block = 13242334135786603907;
                } else if (*state).hello_rcvd == 0 {
                    crate::log::sshlog(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"mux_master_read_cb\0",
                        ))
                        .as_ptr(),
                        1180 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"expected MUX_MSG_HELLO(0x%08x), received 0x%08x\0" as *const u8
                            as *const libc::c_char,
                        0x1 as libc::c_int,
                        type_0,
                    );
                    current_block = 3075895876153858643;
                } else {
                    r = sshbuf_get_u32(in_0, &mut rid);
                    if r != 0 as libc::c_int {
                        current_block = 15549934470666749764;
                    } else {
                        current_block = 13242334135786603907;
                    }
                }
                match current_block {
                    15549934470666749764 => {}
                    3075895876153858643 => {}
                    _ => {
                        i = 0 as libc::c_int as u_int;
                        while (mux_master_handlers[i as usize].handler).is_some() {
                            if type_0 == mux_master_handlers[i as usize].type_0 {
                                ret = (mux_master_handlers[i as usize].handler)
                                    .expect("non-null function pointer")(
                                    ssh, rid, c, in_0, out
                                );
                                break;
                            } else {
                                i = i.wrapping_add(1);
                                i;
                            }
                        }
                        if (mux_master_handlers[i as usize].handler).is_none() {
                            crate::log::sshlog(
                                b"mux.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                    b"mux_master_read_cb\0",
                                ))
                                .as_ptr(),
                                1195 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"unsupported mux message 0x%08x\0" as *const u8
                                    as *const libc::c_char,
                                type_0,
                            );
                            reply_error(
                                out,
                                0x80000003 as libc::c_uint,
                                rid,
                                b"unsupported request\0" as *const u8 as *const libc::c_char,
                            );
                            ret = 0 as libc::c_int;
                        }
                        if sshbuf_len(out) != 0 as libc::c_int as libc::c_ulong && {
                            r = sshbuf_put_stringb((*c).output, out);
                            r != 0 as libc::c_int
                        } {
                            sshfatal(
                                b"mux.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                    b"mux_master_read_cb\0",
                                ))
                                .as_ptr(),
                                1202 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                ssh_err(r),
                                b"enqueue\0" as *const u8 as *const libc::c_char,
                            );
                        }
                        current_block = 3075895876153858643;
                    }
                }
            }
        }
        match current_block {
            3075895876153858643 => {}
            _ => {
                crate::log::sshlog(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"mux_master_read_cb\0",
                    ))
                    .as_ptr(),
                    1166 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"malformed message\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
    sshbuf_free(in_0);
    sshbuf_free(out);
    return ret;
}
pub unsafe extern "C" fn mux_exit_message(
    mut ssh: *mut ssh,
    mut c: *mut Channel,
    mut exitval: libc::c_int,
) {
    let mut m: *mut sshbuf = 0 as *mut sshbuf;
    let mut mux_chan: *mut Channel = 0 as *mut Channel;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mux_exit_message\0")).as_ptr(),
        1216 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"channel %d: libc::exit message, exitval %d\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        exitval,
    );
    mux_chan = channel_by_id(ssh, (*c).ctl_chan);
    if mux_chan.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mux_exit_message\0"))
                .as_ptr(),
            1219 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d missing mux %d\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            (*c).ctl_chan,
        );
    }
    m = sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mux_exit_message\0"))
                .as_ptr(),
            1223 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, 0x80000004 as libc::c_uint);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(m, (*c).self_0 as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(m, exitval as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb((*mux_chan).output, m);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mux_exit_message\0"))
                .as_ptr(),
            1228 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"reply\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(m);
}
pub unsafe extern "C" fn mux_tty_alloc_failed(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut m: *mut sshbuf = 0 as *mut sshbuf;
    let mut mux_chan: *mut Channel = 0 as *mut Channel;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mux_tty_alloc_failed\0"))
            .as_ptr(),
        1239 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"channel %d: TTY alloc failed\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    mux_chan = channel_by_id(ssh, (*c).ctl_chan);
    if mux_chan.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mux_tty_alloc_failed\0"))
                .as_ptr(),
            1242 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d missing mux %d\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            (*c).ctl_chan,
        );
    }
    m = sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mux_tty_alloc_failed\0"))
                .as_ptr(),
            1246 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, 0x80000008 as libc::c_uint);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(m, (*c).self_0 as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb((*mux_chan).output, m);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mux_tty_alloc_failed\0"))
                .as_ptr(),
            1250 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"reply\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(m);
}
pub unsafe extern "C" fn muxserver_listen(mut ssh: *mut ssh) {
    let mut old_umask: mode_t = 0;
    let mut orig_control_path: *mut libc::c_char = options.control_path;
    let mut rbuf: [libc::c_char; 17] = [0; 17];
    let mut i: u_int = 0;
    let mut r: u_int = 0;
    let mut oerrno: libc::c_int = 0;
    if (options.control_path).is_null() || options.control_master == 0 as libc::c_int {
        return;
    }
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"muxserver_listen\0")).as_ptr(),
        1268 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"setting up multiplex master socket\0" as *const u8 as *const libc::c_char,
    );
    i = 0 as libc::c_int as u_int;
    while (i as libc::c_ulong)
        < (::core::mem::size_of::<[libc::c_char; 17]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
    {
        r = arc4random_uniform(
            (26 as libc::c_int + 26 as libc::c_int + 10 as libc::c_int) as uint32_t,
        );
        rbuf[i as usize] = (if r < 26 as libc::c_int as libc::c_uint {
            ('a' as i32 as libc::c_uint).wrapping_add(r)
        } else if r < (26 as libc::c_int * 2 as libc::c_int) as libc::c_uint {
            ('A' as i32 as libc::c_uint)
                .wrapping_add(r)
                .wrapping_sub(26 as libc::c_int as libc::c_uint)
        } else {
            ('0' as i32 as libc::c_uint)
                .wrapping_add(r)
                .wrapping_sub(26 as libc::c_int as libc::c_uint)
                .wrapping_sub(26 as libc::c_int as libc::c_uint)
        }) as libc::c_char;
        i = i.wrapping_add(1);
        i;
    }
    rbuf[(::core::mem::size_of::<[libc::c_char; 17]>() as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize] = '\0' as i32 as libc::c_char;
    options.control_path = 0 as *mut libc::c_char;
    crate::xmalloc::xasprintf(
        &mut options.control_path as *mut *mut libc::c_char,
        b"%s.%s\0" as *const u8 as *const libc::c_char,
        orig_control_path,
        rbuf.as_mut_ptr(),
    );
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"muxserver_listen\0")).as_ptr(),
        1285 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"temporary control path %s\0" as *const u8 as *const libc::c_char,
        options.control_path,
    );
    old_umask = libc::umask(0o177 as libc::c_int as __mode_t);
    muxserver_sock = unix_listener(options.control_path, 64 as libc::c_int, 0 as libc::c_int);
    oerrno = *libc::__errno_location();
    libc::umask(old_umask);
    if muxserver_sock < 0 as libc::c_int {
        if oerrno == 22 as libc::c_int || oerrno == 98 as libc::c_int {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"muxserver_listen\0"))
                    .as_ptr(),
                1294 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"ControlSocket %s already exists, disabling multiplexing\0" as *const u8
                    as *const libc::c_char,
                options.control_path,
            );
        } else {
            cleanup_exit(255 as libc::c_int);
        }
    } else if link(options.control_path, orig_control_path) != 0 as libc::c_int {
        if *libc::__errno_location() != 17 as libc::c_int {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"muxserver_listen\0"))
                    .as_ptr(),
                1316 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"link mux listener %s => %s: %s\0" as *const u8 as *const libc::c_char,
                options.control_path,
                orig_control_path,
                libc::strerror(*libc::__errno_location()),
            );
        }
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"muxserver_listen\0"))
                .as_ptr(),
            1319 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"ControlSocket %s already exists, disabling multiplexing\0" as *const u8
                as *const libc::c_char,
            orig_control_path,
        );
        unlink(options.control_path);
    } else {
        unlink(options.control_path);
        libc::free(options.control_path as *mut libc::c_void);
        options.control_path = orig_control_path;
        crate::misc::set_nonblock(muxserver_sock);
        mux_listener_channel = channel_new(
            ssh,
            b"mux listener\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            15 as libc::c_int,
            muxserver_sock,
            muxserver_sock,
            -(1 as libc::c_int),
            (64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int)) as u_int,
            (32 as libc::c_int * 1024 as libc::c_int) as u_int,
            0 as libc::c_int,
            options.control_path,
            1 as libc::c_int,
        );
        (*mux_listener_channel).mux_rcb =
            Some(mux_master_read_cb as unsafe extern "C" fn(*mut ssh, *mut Channel) -> libc::c_int);
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"muxserver_listen\0"))
                .as_ptr(),
            1335 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"mux listener channel %d fd %d\0" as *const u8 as *const libc::c_char,
            (*mux_listener_channel).self_0,
            (*mux_listener_channel).sock,
        );
        return;
    }
    if muxserver_sock != -(1 as libc::c_int) {
        close(muxserver_sock);
        muxserver_sock = -(1 as libc::c_int);
    }
    libc::free(orig_control_path as *mut libc::c_void);
    libc::free(options.control_path as *mut libc::c_void);
    options.control_path = 0 as *mut libc::c_char;
    options.control_master = 0 as libc::c_int;
}
unsafe extern "C" fn mux_session_confirm(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut success: libc::c_int,
    mut arg: *mut libc::c_void,
) {
    let mut cctx: *mut mux_session_confirm_ctx = arg as *mut mux_session_confirm_ctx;
    let mut display: *const libc::c_char = 0 as *const libc::c_char;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut cc: *mut Channel = 0 as *mut Channel;
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut reply: *mut sshbuf = 0 as *mut sshbuf;
    if cctx.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mux_session_confirm\0"))
                .as_ptr(),
            1349 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"cctx == NULL\0" as *const u8 as *const libc::c_char,
        );
    }
    c = channel_by_id(ssh, id);
    if c.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mux_session_confirm\0"))
                .as_ptr(),
            1351 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no channel for id %d\0" as *const u8 as *const libc::c_char,
            id,
        );
    }
    cc = channel_by_id(ssh, (*c).ctl_chan);
    if cc.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mux_session_confirm\0"))
                .as_ptr(),
            1354 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d lacks control channel %d\0" as *const u8 as *const libc::c_char,
            id,
            (*c).ctl_chan,
        );
    }
    reply = sshbuf_new();
    if reply.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mux_session_confirm\0"))
                .as_ptr(),
            1356 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    if success == 0 {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mux_session_confirm\0"))
                .as_ptr(),
            1359 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"sending failure reply\0" as *const u8 as *const libc::c_char,
        );
        reply_error(
            reply,
            0x80000003 as libc::c_uint,
            (*cctx).rid,
            b"Session open refused by peer\0" as *const u8 as *const libc::c_char,
        );
    } else {
        display = getenv(b"DISPLAY\0" as *const u8 as *const libc::c_char);
        if (*cctx).want_x_fwd != 0 && options.forward_x11 != 0 && !display.is_null() {
            let mut proto: *mut libc::c_char = 0 as *mut libc::c_char;
            let mut data: *mut libc::c_char = 0 as *mut libc::c_char;
            if client_x11_get_proto(
                ssh,
                display,
                options.xauth_location,
                options.forward_x11_trusted as u_int,
                options.forward_x11_timeout as u_int,
                &mut proto,
                &mut data,
            ) == 0 as libc::c_int
            {
                crate::log::sshlog(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"mux_session_confirm\0",
                    ))
                    .as_ptr(),
                    1375 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Requesting X11 forwarding with authentication spoofing.\0" as *const u8
                        as *const libc::c_char,
                );
                x11_request_forwarding_with_spoofing(
                    ssh,
                    id,
                    display,
                    proto,
                    data,
                    1 as libc::c_int,
                );
                client_expect_confirm(
                    ssh,
                    id,
                    b"X11 forwarding\0" as *const u8 as *const libc::c_char,
                    CONFIRM_WARN,
                );
            }
        }
        if (*cctx).want_agent_fwd != 0 && options.forward_agent != 0 {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"mux_session_confirm\0",
                ))
                .as_ptr(),
                1385 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Requesting authentication agent forwarding.\0" as *const u8
                    as *const libc::c_char,
            );
            channel_request_start(
                ssh,
                id,
                b"auth-agent-req@openssh.com\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                0 as libc::c_int,
            );
            r = sshpkt_send(ssh);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"mux_session_confirm\0",
                    ))
                    .as_ptr(),
                    1388 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"send\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        client_session2_setup(
            ssh,
            id,
            (*cctx).want_tty as libc::c_int,
            (*cctx).want_subsys as libc::c_int,
            (*cctx).term,
            &mut (*cctx).tio,
            (*c).rfd,
            (*cctx).cmd,
            (*cctx).env,
        );
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mux_session_confirm\0"))
                .as_ptr(),
            1394 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"sending success reply\0" as *const u8 as *const libc::c_char,
        );
        r = sshbuf_put_u32(reply, 0x80000006 as libc::c_uint);
        if r != 0 as libc::c_int
            || {
                r = sshbuf_put_u32(reply, (*cctx).rid);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_u32(reply, (*c).self_0 as u_int32_t);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"mux_session_confirm\0",
                ))
                .as_ptr(),
                1399 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"reply\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    r = sshbuf_put_stringb((*cc).output, reply);
    if r != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mux_session_confirm\0"))
                .as_ptr(),
            1404 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"enqueue\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(reply);
    if (*cc).mux_pause <= 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mux_session_confirm\0"))
                .as_ptr(),
            1408 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"mux_pause %d\0" as *const u8 as *const libc::c_char,
            (*cc).mux_pause,
        );
    }
    (*cc).mux_pause = 0 as libc::c_int;
    (*c).open_confirm_ctx = 0 as *mut libc::c_void;
    sshbuf_free((*cctx).cmd);
    libc::free((*cctx).term as *mut libc::c_void);
    if !((*cctx).env).is_null() {
        i = 0 as libc::c_int;
        while !(*((*cctx).env).offset(i as isize)).is_null() {
            libc::free(*((*cctx).env).offset(i as isize) as *mut libc::c_void);
            i += 1;
            i;
        }
        libc::free((*cctx).env as *mut libc::c_void);
    }
    libc::free(cctx as *mut libc::c_void);
}
unsafe extern "C" fn control_client_sighandler(mut signo: libc::c_int) {
    ::core::ptr::write_volatile(&mut muxclient_terminate as *mut sig_atomic_t, signo);
}
unsafe extern "C" fn control_client_sigrelay(mut signo: libc::c_int) {
    let mut save_errno: libc::c_int = *libc::__errno_location();
    if muxserver_pid > 1 as libc::c_int as libc::c_uint {
        kill(muxserver_pid as __pid_t, signo);
    }
    *libc::__errno_location() = save_errno;
}
unsafe extern "C" fn mux_client_read(
    mut fd: libc::c_int,
    mut b: *mut sshbuf,
    mut need: size_t,
) -> libc::c_int {
    let mut have: size_t = 0;
    let mut len: ssize_t = 0;
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut pfd: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    let mut r: libc::c_int = 0;
    pfd.fd = fd;
    pfd.events = 0x1 as libc::c_int as libc::c_short;
    r = sshbuf_reserve(b, need, &mut p);
    if r != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mux_client_read\0"))
                .as_ptr(),
            1457 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"reserve\0" as *const u8 as *const libc::c_char,
        );
    }
    have = 0 as libc::c_int as size_t;
    while have < need {
        if muxclient_terminate != 0 {
            *libc::__errno_location() = 4 as libc::c_int;
            return -(1 as libc::c_int);
        }
        len = read(
            fd,
            p.offset(have as isize) as *mut libc::c_void,
            need.wrapping_sub(have),
        );
        if len == -(1 as libc::c_int) as libc::c_long {
            match *libc::__errno_location() {
                11 => {
                    poll(&mut pfd, 1 as libc::c_int as nfds_t, -(1 as libc::c_int));
                }
                4 => {}
                _ => return -(1 as libc::c_int),
            }
        } else {
            if len == 0 as libc::c_int as libc::c_long {
                *libc::__errno_location() = 32 as libc::c_int;
                return -(1 as libc::c_int);
            }
            have = (have as libc::c_ulong).wrapping_add(len as size_t) as size_t as size_t;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn mux_client_write_packet(
    mut fd: libc::c_int,
    mut m: *mut sshbuf,
) -> libc::c_int {
    let mut queue: *mut sshbuf = 0 as *mut sshbuf;
    let mut have: u_int = 0;
    let mut need: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut ptr: *const u_char = 0 as *const u_char;
    let mut pfd: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    pfd.fd = fd;
    pfd.events = 0x4 as libc::c_int as libc::c_short;
    queue = sshbuf_new();
    if queue.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"mux_client_write_packet\0",
            ))
            .as_ptr(),
            1499 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_stringb(queue, m);
    if r != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"mux_client_write_packet\0",
            ))
            .as_ptr(),
            1501 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"enqueue\0" as *const u8 as *const libc::c_char,
        );
    }
    need = sshbuf_len(queue) as u_int;
    ptr = sshbuf_ptr(queue);
    have = 0 as libc::c_int as u_int;
    while have < need {
        if muxclient_terminate != 0 {
            sshbuf_free(queue);
            *libc::__errno_location() = 4 as libc::c_int;
            return -(1 as libc::c_int);
        }
        len = write(
            fd,
            ptr.offset(have as isize) as *const libc::c_void,
            need.wrapping_sub(have) as size_t,
        ) as libc::c_int;
        if len == -(1 as libc::c_int) {
            match *libc::__errno_location() {
                11 => {
                    poll(&mut pfd, 1 as libc::c_int as nfds_t, -(1 as libc::c_int));
                }
                4 => {}
                _ => {
                    oerrno = *libc::__errno_location();
                    sshbuf_free(queue);
                    *libc::__errno_location() = oerrno;
                    return -(1 as libc::c_int);
                }
            }
        } else {
            if len == 0 as libc::c_int {
                sshbuf_free(queue);
                *libc::__errno_location() = 32 as libc::c_int;
                return -(1 as libc::c_int);
            }
            have = (have as libc::c_uint).wrapping_add(len as u_int) as u_int as u_int;
        }
    }
    sshbuf_free(queue);
    return 0 as libc::c_int;
}
unsafe extern "C" fn mux_client_read_packet(
    mut fd: libc::c_int,
    mut m: *mut sshbuf,
) -> libc::c_int {
    let mut queue: *mut sshbuf = 0 as *mut sshbuf;
    let mut need: size_t = 0;
    let mut have: size_t = 0;
    let mut ptr: *const u_char = 0 as *const u_char;
    let mut r: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    queue = sshbuf_new();
    if queue.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"mux_client_read_packet\0",
            ))
            .as_ptr(),
            1550 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    if mux_client_read(fd, queue, 4 as libc::c_int as size_t) != 0 as libc::c_int {
        oerrno = *libc::__errno_location();
        if oerrno == 32 as libc::c_int {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"mux_client_read_packet\0",
                ))
                .as_ptr(),
                1554 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"read header failed: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        sshbuf_free(queue);
        *libc::__errno_location() = oerrno;
        return -(1 as libc::c_int);
    }
    need = ((*(sshbuf_ptr(queue)).offset(0 as libc::c_int as isize) as u_int32_t)
        << 24 as libc::c_int
        | (*(sshbuf_ptr(queue)).offset(1 as libc::c_int as isize) as u_int32_t)
            << 16 as libc::c_int
        | (*(sshbuf_ptr(queue)).offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
        | *(sshbuf_ptr(queue)).offset(3 as libc::c_int as isize) as u_int32_t) as size_t;
    if mux_client_read(fd, queue, need) != 0 as libc::c_int {
        oerrno = *libc::__errno_location();
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"mux_client_read_packet\0",
            ))
            .as_ptr(),
            1562 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"read body failed: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        sshbuf_free(queue);
        *libc::__errno_location() = oerrno;
        return -(1 as libc::c_int);
    }
    r = sshbuf_get_string_direct(queue, &mut ptr, &mut have);
    if r != 0 as libc::c_int || {
        r = sshbuf_put(m, ptr as *const libc::c_void, have);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"mux_client_read_packet\0",
            ))
            .as_ptr(),
            1569 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"dequeue\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(queue);
    return 0 as libc::c_int;
}
unsafe extern "C" fn mux_client_hello_exchange(mut fd: libc::c_int) -> libc::c_int {
    let mut current_block: u64;
    let mut m: *mut sshbuf = 0 as *mut sshbuf;
    let mut type_0: u_int = 0;
    let mut ver: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    m = sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"mux_client_hello_exchange\0",
            ))
            .as_ptr(),
            1582 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, 0x1 as libc::c_int as u_int32_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_u32(m, 4 as libc::c_int as u_int32_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"mux_client_hello_exchange\0",
            ))
            .as_ptr(),
            1585 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble hello\0" as *const u8 as *const libc::c_char,
        );
    }
    if mux_client_write_packet(fd, m) != 0 as libc::c_int {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"mux_client_hello_exchange\0",
            ))
            .as_ptr(),
            1589 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"write packet: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    } else {
        sshbuf_reset(m);
        if mux_client_read_packet(fd, m) != 0 as libc::c_int {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"mux_client_hello_exchange\0",
                ))
                .as_ptr(),
                1597 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"read packet failed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = sshbuf_get_u32(m, &mut type_0);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"mux_client_hello_exchange\0",
                    ))
                    .as_ptr(),
                    1602 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse type\0" as *const u8 as *const libc::c_char,
                );
            }
            if type_0 != 0x1 as libc::c_int as libc::c_uint {
                crate::log::sshlog(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"mux_client_hello_exchange\0",
                    ))
                    .as_ptr(),
                    1604 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"expected HELLO (%u) got %u\0" as *const u8 as *const libc::c_char,
                    0x1 as libc::c_int,
                    type_0,
                );
            } else {
                r = sshbuf_get_u32(m, &mut ver);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"mux_client_hello_exchange\0",
                        ))
                        .as_ptr(),
                        1608 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse version\0" as *const u8 as *const libc::c_char,
                    );
                }
                if ver != 4 as libc::c_int as libc::c_uint {
                    crate::log::sshlog(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"mux_client_hello_exchange\0",
                        ))
                        .as_ptr(),
                        1611 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Unsupported multiplexing protocol version %d (expected %d)\0" as *const u8
                            as *const libc::c_char,
                        ver,
                        4 as libc::c_int,
                    );
                } else {
                    crate::log::sshlog(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"mux_client_hello_exchange\0",
                        ))
                        .as_ptr(),
                        1614 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"master version %u\0" as *const u8 as *const libc::c_char,
                        ver,
                    );
                    loop {
                        if !(sshbuf_len(m) > 0 as libc::c_int as libc::c_ulong) {
                            current_block = 224731115979188411;
                            break;
                        }
                        let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
                        r = sshbuf_get_cstring(m, &mut name, 0 as *mut size_t);
                        if r != 0 as libc::c_int || {
                            r = sshbuf_get_string_direct(
                                m,
                                0 as *mut *const u_char,
                                0 as *mut size_t,
                            );
                            r != 0 as libc::c_int
                        } {
                            crate::log::sshlog(
                                b"mux.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                    b"mux_client_hello_exchange\0",
                                ))
                                .as_ptr(),
                                1621 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"parse extension\0" as *const u8 as *const libc::c_char,
                            );
                            current_block = 4930925120023413099;
                            break;
                        } else {
                            crate::log::sshlog(
                                b"mux.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                    b"mux_client_hello_exchange\0",
                                ))
                                .as_ptr(),
                                1624 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"Unrecognised master extension \"%s\"\0" as *const u8
                                    as *const libc::c_char,
                                name,
                            );
                            libc::free(name as *mut libc::c_void);
                        }
                    }
                    match current_block {
                        4930925120023413099 => {}
                        _ => {
                            ret = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    sshbuf_free(m);
    return ret;
}
unsafe extern "C" fn mux_client_request_alive(mut fd: libc::c_int) -> u_int {
    let mut m: *mut sshbuf = 0 as *mut sshbuf;
    let mut e: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pid: u_int = 0;
    let mut type_0: u_int = 0;
    let mut rid: u_int = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"mux_client_request_alive\0"))
            .as_ptr(),
        1642 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    m = sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_client_request_alive\0",
            ))
            .as_ptr(),
            1645 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, 0x10000004 as libc::c_int as u_int32_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_u32(m, muxclient_request_id);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_client_request_alive\0",
            ))
            .as_ptr(),
            1648 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    if mux_client_write_packet(fd, m) != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_client_request_alive\0",
            ))
            .as_ptr(),
            1651 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"write packet: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    sshbuf_reset(m);
    if mux_client_read_packet(fd, m) != 0 as libc::c_int {
        sshbuf_free(m);
        return 0 as libc::c_int as u_int;
    }
    r = sshbuf_get_u32(m, &mut type_0);
    if r != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_client_request_alive\0",
            ))
            .as_ptr(),
            1662 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse type\0" as *const u8 as *const libc::c_char,
        );
    }
    if type_0 != 0x80000005 as libc::c_uint {
        r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
        if r != 0 as libc::c_int {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"mux_client_request_alive\0",
                ))
                .as_ptr(),
                1665 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse error message\0" as *const u8 as *const libc::c_char,
            );
        }
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_client_request_alive\0",
            ))
            .as_ptr(),
            1666 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"master returned error: %s\0" as *const u8 as *const libc::c_char,
            e,
        );
    }
    r = sshbuf_get_u32(m, &mut rid);
    if r != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_client_request_alive\0",
            ))
            .as_ptr(),
            1670 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse remote ID\0" as *const u8 as *const libc::c_char,
        );
    }
    if rid != muxclient_request_id {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_client_request_alive\0",
            ))
            .as_ptr(),
            1673 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"out of sequence reply: my id %u theirs %u\0" as *const u8 as *const libc::c_char,
            muxclient_request_id,
            rid,
        );
    }
    r = sshbuf_get_u32(m, &mut pid);
    if r != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"mux_client_request_alive\0",
            ))
            .as_ptr(),
            1675 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse PID\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(m);
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"mux_client_request_alive\0"))
            .as_ptr(),
        1678 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"done pid = %u\0" as *const u8 as *const libc::c_char,
        pid,
    );
    muxclient_request_id = muxclient_request_id.wrapping_add(1);
    muxclient_request_id;
    return pid;
}
unsafe extern "C" fn mux_client_request_terminate(mut fd: libc::c_int) {
    let mut m: *mut sshbuf = 0 as *mut sshbuf;
    let mut e: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut type_0: u_int = 0;
    let mut rid: u_int = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
            b"mux_client_request_terminate\0",
        ))
        .as_ptr(),
        1693 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    m = sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_terminate\0",
            ))
            .as_ptr(),
            1696 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, 0x10000005 as libc::c_int as u_int32_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_u32(m, muxclient_request_id);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_terminate\0",
            ))
            .as_ptr(),
            1699 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"request\0" as *const u8 as *const libc::c_char,
        );
    }
    if mux_client_write_packet(fd, m) != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_terminate\0",
            ))
            .as_ptr(),
            1702 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"write packet: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    sshbuf_reset(m);
    if mux_client_read_packet(fd, m) != 0 as libc::c_int {
        if *libc::__errno_location() == 32 as libc::c_int {
            sshbuf_free(m);
            return;
        }
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_terminate\0",
            ))
            .as_ptr(),
            1713 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"read from master failed: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    r = sshbuf_get_u32(m, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(m, &mut rid);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_terminate\0",
            ))
            .as_ptr(),
            1718 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if rid != muxclient_request_id {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_terminate\0",
            ))
            .as_ptr(),
            1721 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"out of sequence reply: my id %u theirs %u\0" as *const u8 as *const libc::c_char,
            muxclient_request_id,
            rid,
        );
    }
    match type_0 {
        2147483649 => {}
        2147483650 => {
            r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"mux_client_request_terminate\0",
                    ))
                    .as_ptr(),
                    1727 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse error message\0" as *const u8 as *const libc::c_char,
                );
            }
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"mux_client_request_terminate\0",
                ))
                .as_ptr(),
                1728 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Master refused termination request: %s\0" as *const u8 as *const libc::c_char,
                e,
            );
        }
        2147483651 => {
            r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"mux_client_request_terminate\0",
                    ))
                    .as_ptr(),
                    1731 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse error message\0" as *const u8 as *const libc::c_char,
                );
            }
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"mux_client_request_terminate\0",
                ))
                .as_ptr(),
                1732 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"termination request failed: %s\0" as *const u8 as *const libc::c_char,
                e,
            );
        }
        _ => {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"mux_client_request_terminate\0",
                ))
                .as_ptr(),
                1734 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unexpected response from master 0x%08x\0" as *const u8 as *const libc::c_char,
                type_0,
            );
        }
    }
    sshbuf_free(m);
    muxclient_request_id = muxclient_request_id.wrapping_add(1);
    muxclient_request_id;
}
unsafe extern "C" fn mux_client_forward(
    mut fd: libc::c_int,
    mut cancel_flag: libc::c_int,
    mut ftype: u_int,
    mut fwd: *mut Forward,
) -> libc::c_int {
    let mut m: *mut sshbuf = 0 as *mut sshbuf;
    let mut e: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fwd_desc: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut lhost: *const libc::c_char = 0 as *const libc::c_char;
    let mut chost: *const libc::c_char = 0 as *const libc::c_char;
    let mut type_0: u_int = 0;
    let mut rid: u_int = 0;
    let mut r: libc::c_int = 0;
    fwd_desc = format_forward(ftype, fwd);
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mux_client_forward\0"))
            .as_ptr(),
        1751 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Requesting %s %s\0" as *const u8 as *const libc::c_char,
        if cancel_flag != 0 {
            b"cancellation of\0" as *const u8 as *const libc::c_char
        } else {
            b"forwarding of\0" as *const u8 as *const libc::c_char
        },
        fwd_desc,
    );
    libc::free(fwd_desc as *mut libc::c_void);
    type_0 = (if cancel_flag != 0 {
        0x10000007 as libc::c_int
    } else {
        0x10000006 as libc::c_int
    }) as u_int;
    if !((*fwd).listen_path).is_null() {
        lhost = (*fwd).listen_path;
    } else if ((*fwd).listen_host).is_null() {
        lhost = b"\0" as *const u8 as *const libc::c_char;
    } else if *(*fwd).listen_host as libc::c_int == '\0' as i32 {
        lhost = b"*\0" as *const u8 as *const libc::c_char;
    } else {
        lhost = (*fwd).listen_host;
    }
    if !((*fwd).connect_path).is_null() {
        chost = (*fwd).connect_path;
    } else if ((*fwd).connect_host).is_null() {
        chost = b"\0" as *const u8 as *const libc::c_char;
    } else {
        chost = (*fwd).connect_host;
    }
    m = sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mux_client_forward\0"))
                .as_ptr(),
            1772 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, type_0);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(m, muxclient_request_id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(m, ftype);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(m, lhost);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(m, (*fwd).listen_port as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(m, chost);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(m, (*fwd).connect_port as u_int32_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mux_client_forward\0"))
                .as_ptr(),
            1780 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"request\0" as *const u8 as *const libc::c_char,
        );
    }
    if mux_client_write_packet(fd, m) != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mux_client_forward\0"))
                .as_ptr(),
            1783 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"write packet: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    sshbuf_reset(m);
    if mux_client_read_packet(fd, m) != 0 as libc::c_int {
        sshbuf_free(m);
        return -(1 as libc::c_int);
    }
    r = sshbuf_get_u32(m, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(m, &mut rid);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mux_client_forward\0"))
                .as_ptr(),
            1795 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if rid != muxclient_request_id {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mux_client_forward\0"))
                .as_ptr(),
            1798 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"out of sequence reply: my id %u theirs %u\0" as *const u8 as *const libc::c_char,
            muxclient_request_id,
            rid,
        );
    }
    match type_0 {
        2147483649 => {}
        2147483655 => {
            if cancel_flag != 0 {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"mux_client_forward\0",
                    ))
                    .as_ptr(),
                    1805 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"got MUX_S_REMOTE_PORT for cancel\0" as *const u8 as *const libc::c_char,
                );
            }
            r = sshbuf_get_u32(
                m,
                &mut (*fwd).allocated_port as *mut libc::c_int as *mut u_int32_t,
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"mux_client_forward\0",
                    ))
                    .as_ptr(),
                    1807 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse port\0" as *const u8 as *const libc::c_char,
                );
            }
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"mux_client_forward\0",
                ))
                .as_ptr(),
                1811 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_VERBOSE,
                0 as *const libc::c_char,
                b"Allocated port %u for remote forward to %s:%d\0" as *const u8
                    as *const libc::c_char,
                (*fwd).allocated_port,
                if !((*fwd).connect_host).is_null() {
                    (*fwd).connect_host as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                (*fwd).connect_port,
            );
            if muxclient_command == 5 as libc::c_int as libc::c_uint {
                libc::fprintf(
                    stdout,
                    b"%i\n\0" as *const u8 as *const libc::c_char,
                    (*fwd).allocated_port,
                );
            }
        }
        2147483650 => {
            r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"mux_client_forward\0",
                    ))
                    .as_ptr(),
                    1817 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse error message\0" as *const u8 as *const libc::c_char,
                );
            }
            sshbuf_free(m);
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"mux_client_forward\0",
                ))
                .as_ptr(),
                1819 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Master refused forwarding request: %s\0" as *const u8 as *const libc::c_char,
                e,
            );
            return -(1 as libc::c_int);
        }
        2147483651 => {
            r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"mux_client_forward\0",
                    ))
                    .as_ptr(),
                    1823 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse error message\0" as *const u8 as *const libc::c_char,
                );
            }
            sshbuf_free(m);
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"mux_client_forward\0",
                ))
                .as_ptr(),
                1825 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"forwarding request failed: %s\0" as *const u8 as *const libc::c_char,
                e,
            );
            return -(1 as libc::c_int);
        }
        _ => {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"mux_client_forward\0",
                ))
                .as_ptr(),
                1828 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unexpected response from master 0x%08x\0" as *const u8 as *const libc::c_char,
                type_0,
            );
        }
    }
    sshbuf_free(m);
    muxclient_request_id = muxclient_request_id.wrapping_add(1);
    muxclient_request_id;
    return 0 as libc::c_int;
}
unsafe extern "C" fn mux_client_forwards(
    mut fd: libc::c_int,
    mut cancel_flag: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"mux_client_forwards\0"))
            .as_ptr(),
        1843 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s forwardings: %d local, %d remote\0" as *const u8 as *const libc::c_char,
        if cancel_flag != 0 {
            b"cancel\0" as *const u8 as *const libc::c_char
        } else {
            b"request\0" as *const u8 as *const libc::c_char
        },
        options.num_local_forwards,
        options.num_remote_forwards,
    );
    i = 0 as libc::c_int;
    while i < options.num_local_forwards {
        if mux_client_forward(
            fd,
            cancel_flag,
            (if (*(options.local_forwards).offset(i as isize)).connect_port == 0 as libc::c_int {
                3 as libc::c_int
            } else {
                1 as libc::c_int
            }) as u_int,
            (options.local_forwards).offset(i as isize),
        ) != 0 as libc::c_int
        {
            ret = -(1 as libc::c_int);
        }
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < options.num_remote_forwards {
        if mux_client_forward(
            fd,
            cancel_flag,
            2 as libc::c_int as u_int,
            (options.remote_forwards).offset(i as isize),
        ) != 0 as libc::c_int
        {
            ret = -(1 as libc::c_int);
        }
        i += 1;
        i;
    }
    return ret;
}
unsafe extern "C" fn mux_client_request_session(mut fd: libc::c_int) -> libc::c_int {
    let mut m: *mut sshbuf = 0 as *mut sshbuf;
    let mut e: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut term: *const libc::c_char = 0 as *const libc::c_char;
    let mut i: u_int = 0;
    let mut echar: u_int = 0;
    let mut rid: u_int = 0;
    let mut sid: u_int = 0;
    let mut esid: u_int = 0;
    let mut exitval: u_int = 0;
    let mut type_0: u_int = 0;
    let mut exitval_seen: u_int = 0;
    extern "C" {
        #[link_name = "environ"]
        static mut environ_0: *mut *mut libc::c_char;
    }
    let mut r: libc::c_int = 0;
    let mut rawmode: libc::c_int = 0;
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"mux_client_request_session\0",
        ))
        .as_ptr(),
        1871 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    muxserver_pid = mux_client_request_alive(fd);
    if muxserver_pid == 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            1874 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"master alive request failed\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    crate::misc::ssh_signal(
        13 as libc::c_int,
        ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
            1 as libc::c_int as libc::intptr_t,
        ),
    );
    if options.stdin_null != 0
        && stdfd_devnull(1 as libc::c_int, 0 as libc::c_int, 0 as libc::c_int)
            == -(1 as libc::c_int)
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            1881 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"stdfd_devnull failed\0" as *const u8 as *const libc::c_char,
        );
    }
    term = lookup_env_in_list(
        b"TERM\0" as *const u8 as *const libc::c_char,
        options.setenv,
        options.num_setenv as size_t,
    );
    if term.is_null() || *term as libc::c_int == '\0' as i32 {
        term = getenv(b"TERM\0" as *const u8 as *const libc::c_char);
    }
    echar = 0xffffffff as libc::c_uint;
    if options.escape_char != -(2 as libc::c_int) {
        echar = options.escape_char as u_int;
    }
    m = sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            1892 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, 0x10000002 as libc::c_int as u_int32_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(m, muxclient_request_id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(m, 0 as *const libc::c_void, 0 as libc::c_int as size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(m, tty_flag as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(m, options.forward_x11 as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(m, options.forward_agent as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(
                m,
                (options.session_type == 1 as libc::c_int) as libc::c_int as u_int32_t,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(m, echar);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(
                m,
                if term.is_null() {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    term
                },
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(m, command);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            1903 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"request\0" as *const u8 as *const libc::c_char,
        );
    }
    if options.num_send_env > 0 as libc::c_int as libc::c_uint && !environ.is_null() {
        i = 0 as libc::c_int as u_int;
        while !(*environ.offset(i as isize)).is_null() {
            if !(env_permitted(*environ.offset(i as isize)) == 0) {
                r = sshbuf_put_cstring(m, *environ.offset(i as isize));
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"mux_client_request_session\0",
                        ))
                        .as_ptr(),
                        1911 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"request sendenv\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            i = i.wrapping_add(1);
            i;
        }
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_setenv {
        r = sshbuf_put_cstring(m, *(options.setenv).offset(i as isize));
        if r != 0 as libc::c_int {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"mux_client_request_session\0",
                ))
                .as_ptr(),
                1916 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"request setenv\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    if mux_client_write_packet(fd, m) != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            1920 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"write packet: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    if mm_send_fd(fd, 0 as libc::c_int) == -(1 as libc::c_int)
        || mm_send_fd(fd, 1 as libc::c_int) == -(1 as libc::c_int)
        || mm_send_fd(fd, 2 as libc::c_int) == -(1 as libc::c_int)
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            1926 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"send fds failed\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"mux_client_request_session\0",
        ))
        .as_ptr(),
        1928 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"session request sent\0" as *const u8 as *const libc::c_char,
    );
    sshbuf_reset(m);
    if mux_client_read_packet(fd, m) != 0 as libc::c_int {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            1933 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"read from master failed: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        sshbuf_free(m);
        return -(1 as libc::c_int);
    }
    r = sshbuf_get_u32(m, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(m, &mut rid);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            1940 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if rid != muxclient_request_id {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            1943 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"out of sequence reply: my id %u theirs %u\0" as *const u8 as *const libc::c_char,
            muxclient_request_id,
            rid,
        );
    }
    match type_0 {
        2147483654 => {
            r = sshbuf_get_u32(m, &mut sid);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"mux_client_request_session\0",
                    ))
                    .as_ptr(),
                    1948 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse session ID\0" as *const u8 as *const libc::c_char,
                );
            }
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"mux_client_request_session\0",
                ))
                .as_ptr(),
                1949 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"master session id: %u\0" as *const u8 as *const libc::c_char,
                sid,
            );
        }
        2147483650 => {
            r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"mux_client_request_session\0",
                    ))
                    .as_ptr(),
                    1953 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse error message\0" as *const u8 as *const libc::c_char,
                );
            }
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"mux_client_request_session\0",
                ))
                .as_ptr(),
                1954 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Master refused session request: %s\0" as *const u8 as *const libc::c_char,
                e,
            );
            sshbuf_free(m);
            return -(1 as libc::c_int);
        }
        2147483651 => {
            r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"mux_client_request_session\0",
                    ))
                    .as_ptr(),
                    1959 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse error message\0" as *const u8 as *const libc::c_char,
                );
            }
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"mux_client_request_session\0",
                ))
                .as_ptr(),
                1960 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"session request failed: %s\0" as *const u8 as *const libc::c_char,
                e,
            );
            sshbuf_free(m);
            return -(1 as libc::c_int);
        }
        _ => {
            sshbuf_free(m);
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"mux_client_request_session\0",
                ))
                .as_ptr(),
                1965 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"unexpected response from master 0x%08x\0" as *const u8 as *const libc::c_char,
                type_0,
            );
            return -(1 as libc::c_int);
        }
    }
    muxclient_request_id = muxclient_request_id.wrapping_add(1);
    muxclient_request_id;
    if crate::openbsd_compat::bsd_misc::pledge(
        b"stdio proc tty\0" as *const u8 as *const libc::c_char,
        0 as *mut *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            1971 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::openbsd_compat::bsd_misc::pledge(): %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    platform_pledge_mux();
    crate::misc::ssh_signal(
        1 as libc::c_int,
        Some(control_client_sighandler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    crate::misc::ssh_signal(
        2 as libc::c_int,
        Some(control_client_sighandler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    crate::misc::ssh_signal(
        15 as libc::c_int,
        Some(control_client_sighandler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    crate::misc::ssh_signal(
        28 as libc::c_int,
        Some(control_client_sigrelay as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    rawmode = tty_flag;
    if tty_flag != 0 {
        enter_raw_mode((options.request_tty == 3 as libc::c_int) as libc::c_int);
    }
    exitval = 255 as libc::c_int as u_int;
    exitval_seen = 0 as libc::c_int as u_int;
    loop {
        sshbuf_reset(m);
        if mux_client_read_packet(fd, m) != 0 as libc::c_int {
            break;
        }
        r = sshbuf_get_u32(m, &mut type_0);
        if r != 0 as libc::c_int {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"mux_client_request_session\0",
                ))
                .as_ptr(),
                1995 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse type\0" as *const u8 as *const libc::c_char,
            );
        }
        match type_0 {
            2147483656 => {
                r = sshbuf_get_u32(m, &mut esid);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"mux_client_request_session\0",
                        ))
                        .as_ptr(),
                        1999 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse session ID\0" as *const u8 as *const libc::c_char,
                    );
                }
                if esid != sid {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"mux_client_request_session\0",
                        ))
                        .as_ptr(),
                        2002 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"tty alloc fail on unknown session: my id %u theirs %u\0" as *const u8
                            as *const libc::c_char,
                        sid,
                        esid,
                    );
                }
                leave_raw_mode((options.request_tty == 3 as libc::c_int) as libc::c_int);
                rawmode = 0 as libc::c_int;
            }
            2147483652 => {
                r = sshbuf_get_u32(m, &mut esid);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"mux_client_request_session\0",
                        ))
                        .as_ptr(),
                        2009 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse session ID\0" as *const u8 as *const libc::c_char,
                    );
                }
                if esid != sid {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"mux_client_request_session\0",
                        ))
                        .as_ptr(),
                        2012 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"libc::exit on unknown session: my id %u theirs %u\0" as *const u8
                            as *const libc::c_char,
                        sid,
                        esid,
                    );
                }
                if exitval_seen != 0 {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"mux_client_request_session\0",
                        ))
                        .as_ptr(),
                        2014 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"exitval sent twice\0" as *const u8 as *const libc::c_char,
                    );
                }
                r = sshbuf_get_u32(m, &mut exitval);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"mux_client_request_session\0",
                        ))
                        .as_ptr(),
                        2016 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse exitval\0" as *const u8 as *const libc::c_char,
                    );
                }
                exitval_seen = 1 as libc::c_int as u_int;
            }
            _ => {
                r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"mux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"mux_client_request_session\0",
                        ))
                        .as_ptr(),
                        2021 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse error message\0" as *const u8 as *const libc::c_char,
                    );
                }
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"mux_client_request_session\0",
                    ))
                    .as_ptr(),
                    2022 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"master returned error: %s\0" as *const u8 as *const libc::c_char,
                    e,
                );
            }
        }
    }
    close(fd);
    if rawmode != 0 {
        leave_raw_mode((options.request_tty == 3 as libc::c_int) as libc::c_int);
    }
    if muxclient_terminate != 0 {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            2031 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Exiting on signal: %s\0" as *const u8 as *const libc::c_char,
            strsignal(muxclient_terminate),
        );
        exitval = 255 as libc::c_int as u_int;
    } else if exitval_seen == 0 {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            2034 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Control master terminated unexpectedly\0" as *const u8 as *const libc::c_char,
        );
        exitval = 255 as libc::c_int as u_int;
    } else {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"mux_client_request_session\0",
            ))
            .as_ptr(),
            2037 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Received libc::exit status from master %d\0" as *const u8 as *const libc::c_char,
            exitval,
        );
    }
    if tty_flag != 0 && options.log_level as libc::c_int >= SYSLOG_LEVEL_INFO as libc::c_int {
        libc::fprintf(
            stderr,
            b"Shared connection to %s closed.\r\n\0" as *const u8 as *const libc::c_char,
            host,
        );
    }
    libc::exit(exitval as libc::c_int);
}
unsafe extern "C" fn mux_client_proxy(mut fd: libc::c_int) -> libc::c_int {
    let mut m: *mut sshbuf = 0 as *mut sshbuf;
    let mut e: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut type_0: u_int = 0;
    let mut rid: u_int = 0;
    let mut r: libc::c_int = 0;
    m = sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mux_client_proxy\0"))
                .as_ptr(),
            2054 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, 0x1000000f as libc::c_int as u_int32_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_u32(m, muxclient_request_id);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mux_client_proxy\0"))
                .as_ptr(),
            2057 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"request\0" as *const u8 as *const libc::c_char,
        );
    }
    if mux_client_write_packet(fd, m) != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mux_client_proxy\0"))
                .as_ptr(),
            2059 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"write packet: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    sshbuf_reset(m);
    if mux_client_read_packet(fd, m) != 0 as libc::c_int {
        sshbuf_free(m);
        return 0 as libc::c_int;
    }
    r = sshbuf_get_u32(m, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(m, &mut rid);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mux_client_proxy\0"))
                .as_ptr(),
            2070 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if rid != muxclient_request_id {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mux_client_proxy\0"))
                .as_ptr(),
            2073 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"out of sequence reply: my id %u theirs %u\0" as *const u8 as *const libc::c_char,
            muxclient_request_id,
            rid,
        );
    }
    if type_0 != 0x8000000f as libc::c_uint {
        r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
        if r != 0 as libc::c_int {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mux_client_proxy\0"))
                    .as_ptr(),
                2076 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse error message\0" as *const u8 as *const libc::c_char,
            );
        }
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mux_client_proxy\0"))
                .as_ptr(),
            2077 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"master returned error: %s\0" as *const u8 as *const libc::c_char,
            e,
        );
    }
    sshbuf_free(m);
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mux_client_proxy\0")).as_ptr(),
        2081 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"done\0" as *const u8 as *const libc::c_char,
    );
    muxclient_request_id = muxclient_request_id.wrapping_add(1);
    muxclient_request_id;
    return 0 as libc::c_int;
}
unsafe extern "C" fn mux_client_request_stdio_fwd(mut fd: libc::c_int) -> libc::c_int {
    let mut m: *mut sshbuf = 0 as *mut sshbuf;
    let mut e: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut type_0: u_int = 0;
    let mut rid: u_int = 0;
    let mut sid: u_int = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
            b"mux_client_request_stdio_fwd\0",
        ))
        .as_ptr(),
        2094 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    muxserver_pid = mux_client_request_alive(fd);
    if muxserver_pid == 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_stdio_fwd\0",
            ))
            .as_ptr(),
            2097 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"master alive request failed\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    crate::misc::ssh_signal(
        13 as libc::c_int,
        ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
            1 as libc::c_int as libc::intptr_t,
        ),
    );
    if options.stdin_null != 0
        && stdfd_devnull(1 as libc::c_int, 0 as libc::c_int, 0 as libc::c_int)
            == -(1 as libc::c_int)
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_stdio_fwd\0",
            ))
            .as_ptr(),
            2104 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"stdfd_devnull failed\0" as *const u8 as *const libc::c_char,
        );
    }
    m = sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_stdio_fwd\0",
            ))
            .as_ptr(),
            2107 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, 0x10000008 as libc::c_int as u_int32_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(m, muxclient_request_id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(m, 0 as *const libc::c_void, 0 as libc::c_int as size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(m, options.stdio_forward_host);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(m, options.stdio_forward_port as u_int32_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_stdio_fwd\0",
            ))
            .as_ptr(),
            2113 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"request\0" as *const u8 as *const libc::c_char,
        );
    }
    if mux_client_write_packet(fd, m) != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_stdio_fwd\0",
            ))
            .as_ptr(),
            2116 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"write packet: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    if mm_send_fd(fd, 0 as libc::c_int) == -(1 as libc::c_int)
        || mm_send_fd(fd, 1 as libc::c_int) == -(1 as libc::c_int)
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_stdio_fwd\0",
            ))
            .as_ptr(),
            2121 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"send fds failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if crate::openbsd_compat::bsd_misc::pledge(
        b"stdio proc tty\0" as *const u8 as *const libc::c_char,
        0 as *mut *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_stdio_fwd\0",
            ))
            .as_ptr(),
            2124 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::openbsd_compat::bsd_misc::pledge(): %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    platform_pledge_mux();
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
            b"mux_client_request_stdio_fwd\0",
        ))
        .as_ptr(),
        2127 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"stdio forward request sent\0" as *const u8 as *const libc::c_char,
    );
    sshbuf_reset(m);
    if mux_client_read_packet(fd, m) != 0 as libc::c_int {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_stdio_fwd\0",
            ))
            .as_ptr(),
            2133 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"read from master failed: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        sshbuf_free(m);
        return -(1 as libc::c_int);
    }
    r = sshbuf_get_u32(m, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(m, &mut rid);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_stdio_fwd\0",
            ))
            .as_ptr(),
            2140 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if rid != muxclient_request_id {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_stdio_fwd\0",
            ))
            .as_ptr(),
            2143 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"out of sequence reply: my id %u theirs %u\0" as *const u8 as *const libc::c_char,
            muxclient_request_id,
            rid,
        );
    }
    match type_0 {
        2147483654 => {
            r = sshbuf_get_u32(m, &mut sid);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"mux_client_request_stdio_fwd\0",
                    ))
                    .as_ptr(),
                    2147 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse session ID\0" as *const u8 as *const libc::c_char,
                );
            }
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"mux_client_request_stdio_fwd\0",
                ))
                .as_ptr(),
                2148 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"master session id: %u\0" as *const u8 as *const libc::c_char,
                sid,
            );
        }
        2147483650 => {
            r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"mux_client_request_stdio_fwd\0",
                    ))
                    .as_ptr(),
                    2152 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse error message\0" as *const u8 as *const libc::c_char,
                );
            }
            sshbuf_free(m);
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"mux_client_request_stdio_fwd\0",
                ))
                .as_ptr(),
                2154 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Master refused stdio forwarding request: %s\0" as *const u8
                    as *const libc::c_char,
                e,
            );
        }
        2147483651 => {
            r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"mux_client_request_stdio_fwd\0",
                    ))
                    .as_ptr(),
                    2157 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse error message\0" as *const u8 as *const libc::c_char,
                );
            }
            sshbuf_free(m);
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"mux_client_request_stdio_fwd\0",
                ))
                .as_ptr(),
                2159 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Stdio forwarding request failed: %s\0" as *const u8 as *const libc::c_char,
                e,
            );
        }
        _ => {
            sshbuf_free(m);
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"mux_client_request_stdio_fwd\0",
                ))
                .as_ptr(),
                2162 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"unexpected response from master 0x%08x\0" as *const u8 as *const libc::c_char,
                type_0,
            );
            return -(1 as libc::c_int);
        }
    }
    muxclient_request_id = muxclient_request_id.wrapping_add(1);
    muxclient_request_id;
    crate::misc::ssh_signal(
        1 as libc::c_int,
        Some(control_client_sighandler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    crate::misc::ssh_signal(
        2 as libc::c_int,
        Some(control_client_sighandler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    crate::misc::ssh_signal(
        15 as libc::c_int,
        Some(control_client_sighandler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    crate::misc::ssh_signal(
        28 as libc::c_int,
        Some(control_client_sigrelay as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    sshbuf_reset(m);
    if mux_client_read_packet(fd, m) != 0 as libc::c_int {
        if *libc::__errno_location() == 32 as libc::c_int
            || *libc::__errno_location() == 4 as libc::c_int
                && muxclient_terminate != 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"mux_client_request_stdio_fwd\0",
            ))
            .as_ptr(),
            2180 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"mux_client_read_packet: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    sshfatal(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
            b"mux_client_request_stdio_fwd\0",
        ))
        .as_ptr(),
        2182 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_FATAL,
        0 as *const libc::c_char,
        b"master returned unexpected message %u\0" as *const u8 as *const libc::c_char,
        type_0,
    );
}
unsafe extern "C" fn mux_client_request_stop_listening(mut fd: libc::c_int) {
    let mut m: *mut sshbuf = 0 as *mut sshbuf;
    let mut e: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut type_0: u_int = 0;
    let mut rid: u_int = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"mux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
            b"mux_client_request_stop_listening\0",
        ))
        .as_ptr(),
        2193 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    m = sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"mux_client_request_stop_listening\0",
            ))
            .as_ptr(),
            2196 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, 0x10000009 as libc::c_int as u_int32_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_u32(m, muxclient_request_id);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"mux_client_request_stop_listening\0",
            ))
            .as_ptr(),
            2199 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"request\0" as *const u8 as *const libc::c_char,
        );
    }
    if mux_client_write_packet(fd, m) != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"mux_client_request_stop_listening\0",
            ))
            .as_ptr(),
            2202 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"write packet: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    sshbuf_reset(m);
    if mux_client_read_packet(fd, m) != 0 as libc::c_int {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"mux_client_request_stop_listening\0",
            ))
            .as_ptr(),
            2208 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"read from master failed: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    r = sshbuf_get_u32(m, &mut type_0);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u32(m, &mut rid);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"mux_client_request_stop_listening\0",
            ))
            .as_ptr(),
            2212 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if rid != muxclient_request_id {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"mux_client_request_stop_listening\0",
            ))
            .as_ptr(),
            2215 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"out of sequence reply: my id %u theirs %u\0" as *const u8 as *const libc::c_char,
            muxclient_request_id,
            rid,
        );
    }
    match type_0 {
        2147483649 => {}
        2147483650 => {
            r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                        b"mux_client_request_stop_listening\0",
                    ))
                    .as_ptr(),
                    2222 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse error message\0" as *const u8 as *const libc::c_char,
                );
            }
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                    b"mux_client_request_stop_listening\0",
                ))
                .as_ptr(),
                2223 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Master refused stop listening request: %s\0" as *const u8 as *const libc::c_char,
                e,
            );
        }
        2147483651 => {
            r = sshbuf_get_cstring(m, &mut e, 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                        b"mux_client_request_stop_listening\0",
                    ))
                    .as_ptr(),
                    2226 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse error message\0" as *const u8 as *const libc::c_char,
                );
            }
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                    b"mux_client_request_stop_listening\0",
                ))
                .as_ptr(),
                2227 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"stop listening request failed: %s\0" as *const u8 as *const libc::c_char,
                e,
            );
        }
        _ => {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                    b"mux_client_request_stop_listening\0",
                ))
                .as_ptr(),
                2229 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unexpected response from master 0x%08x\0" as *const u8 as *const libc::c_char,
                type_0,
            );
        }
    }
    sshbuf_free(m);
    muxclient_request_id = muxclient_request_id.wrapping_add(1);
    muxclient_request_id;
}
pub unsafe extern "C" fn muxclient(mut path: *const libc::c_char) -> libc::c_int {
    let mut addr: sockaddr_un = sockaddr_un {
        sun_family: 0,
        sun_path: [0; 108],
    };
    let mut sock: libc::c_int = 0;
    let mut pid: u_int = 0;
    if muxclient_command == 0 as libc::c_int as libc::c_uint {
        if !(options.stdio_forward_host).is_null() {
            muxclient_command = 4 as libc::c_int as u_int;
        } else {
            muxclient_command = 1 as libc::c_int as u_int;
        }
    }
    match options.control_master {
        2 | 4 => {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0"))
                    .as_ptr(),
                2253 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"auto-mux: Trying existing master\0" as *const u8 as *const libc::c_char,
            );
        }
        0 => {}
        _ => return -(1 as libc::c_int),
    }
    memset(
        &mut addr as *mut sockaddr_un as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<sockaddr_un>() as libc::c_ulong,
    );
    addr.sun_family = 1 as libc::c_int as sa_family_t;
    if strlcpy(
        (addr.sun_path).as_mut_ptr(),
        path,
        ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong,
    ) >= ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong
    {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0")).as_ptr(),
            2267 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ControlPath too long ('%s' >= %u bytes)\0" as *const u8 as *const libc::c_char,
            path,
            ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong as libc::c_uint,
        );
    }
    sock = socket(
        1 as libc::c_int,
        SOCK_STREAM as libc::c_int,
        0 as libc::c_int,
    );
    if sock == -(1 as libc::c_int) {
        sshfatal(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0")).as_ptr(),
            2270 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"socket(): %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    if connect(
        sock,
        __CONST_SOCKADDR_ARG {
            __sockaddr__: &mut addr as *mut sockaddr_un as *mut sockaddr,
        },
        ::core::mem::size_of::<sockaddr_un>() as libc::c_ulong as socklen_t,
    ) == -(1 as libc::c_int)
    {
        match muxclient_command {
            1 | 4 => {}
            _ => {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0"))
                        .as_ptr(),
                    2279 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Control socket connect(%.100s): %s\0" as *const u8 as *const libc::c_char,
                    path,
                    libc::strerror(*libc::__errno_location()),
                );
            }
        }
        if *libc::__errno_location() == 111 as libc::c_int
            && options.control_master != 0 as libc::c_int
        {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0"))
                    .as_ptr(),
                2283 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Stale control socket %.100s, unlinking\0" as *const u8 as *const libc::c_char,
                path,
            );
            unlink(path);
        } else if *libc::__errno_location() == 2 as libc::c_int {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0"))
                    .as_ptr(),
                2286 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Control socket \"%.100s\" does not exist\0" as *const u8 as *const libc::c_char,
                path,
            );
        } else {
            crate::log::sshlog(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0"))
                    .as_ptr(),
                2289 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Control socket connect(%.100s): %s\0" as *const u8 as *const libc::c_char,
                path,
                libc::strerror(*libc::__errno_location()),
            );
        }
        close(sock);
        return -(1 as libc::c_int);
    }
    crate::misc::set_nonblock(sock);
    if mux_client_hello_exchange(sock) != 0 as libc::c_int {
        crate::log::sshlog(
            b"mux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0")).as_ptr(),
            2297 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"master hello exchange failed\0" as *const u8 as *const libc::c_char,
        );
        close(sock);
        return -(1 as libc::c_int);
    }
    match muxclient_command {
        2 => {
            pid = mux_client_request_alive(sock);
            if pid == 0 as libc::c_int as libc::c_uint {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0"))
                        .as_ptr(),
                    2305 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"master alive check failed\0" as *const u8 as *const libc::c_char,
                );
            }
            libc::fprintf(
                stderr,
                b"Master running (pid=%u)\r\n\0" as *const u8 as *const libc::c_char,
                pid,
            );
            libc::exit(0 as libc::c_int);
        }
        3 => {
            mux_client_request_terminate(sock);
            if options.log_level as libc::c_int != SYSLOG_LEVEL_QUIET as libc::c_int {
                libc::fprintf(
                    stderr,
                    b"Exit request sent.\r\n\0" as *const u8 as *const libc::c_char,
                );
            }
            libc::exit(0 as libc::c_int);
        }
        5 => {
            if mux_client_forwards(sock, 0 as libc::c_int) != 0 as libc::c_int {
                sshfatal(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0"))
                        .as_ptr(),
                    2315 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"master forward request failed\0" as *const u8 as *const libc::c_char,
                );
            }
            libc::exit(0 as libc::c_int);
        }
        1 => {
            if mux_client_forwards(sock, 0 as libc::c_int) != 0 as libc::c_int {
                crate::log::sshlog(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0"))
                        .as_ptr(),
                    2319 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"master forward request failed\0" as *const u8 as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            mux_client_request_session(sock);
            return -(1 as libc::c_int);
        }
        4 => {
            mux_client_request_stdio_fwd(sock);
            libc::exit(0 as libc::c_int);
        }
        6 => {
            mux_client_request_stop_listening(sock);
            if options.log_level as libc::c_int != SYSLOG_LEVEL_QUIET as libc::c_int {
                libc::fprintf(
                    stderr,
                    b"Stop listening request sent.\r\n\0" as *const u8 as *const libc::c_char,
                );
            }
            libc::exit(0 as libc::c_int);
        }
        7 => {
            if mux_client_forwards(sock, 1 as libc::c_int) != 0 as libc::c_int {
                crate::log::sshlog(
                    b"mux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0"))
                        .as_ptr(),
                    2334 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"master cancel forward request failed\0" as *const u8 as *const libc::c_char,
                );
            }
            libc::exit(0 as libc::c_int);
        }
        8 => {
            mux_client_proxy(sock);
            return sock;
        }
        _ => {
            sshfatal(
                b"mux.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"muxclient\0"))
                    .as_ptr(),
                2340 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"unrecognised muxclient_command %d\0" as *const u8 as *const libc::c_char,
                muxclient_command,
            );
        }
    };
}
