use crate::channels::ssh_channels;
use crate::hmac::ssh_hmac_ctx;
use crate::kex::sshenc;
use crate::packet::session_state;
use crate::umac::umac_ctx;

use crate::log::log_init;
use crate::utf8::msetlocale;
use ::libc;
use libc::close;
use libc::isatty;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    pub type ec_group_st;
    pub type dh_st;

    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn access(__name: *const libc::c_char, __type: libc::c_int) -> libc::c_int;

    fn closefrom(__lowfd: libc::c_int);
    fn dup(__fd: libc::c_int) -> libc::c_int;
    static mut environ: *mut *mut libc::c_char;

    fn seed_rng();
    static mut BSDoptarg: *mut libc::c_char;
    static mut BSDoptind: libc::c_int;

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
    static mut stdin: *mut libc::FILE;
    static mut stderr: *mut libc::FILE;

    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;

    fn fileno(__stream: *mut libc::FILE) -> libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn setproctitle(fmt: *const libc::c_char, _: ...);
    fn compat_init_setproctitle(argc: libc::c_int, argv: *mut *mut libc::c_char);
    static mut BSDoptreset: libc::c_int;

    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    fn daemon(__nochdir: libc::c_int, __noclose: libc::c_int) -> libc::c_int;
    fn gethostname(__name: *mut libc::c_char, __len: size_t) -> libc::c_int;

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn setenv(
        __name: *const libc::c_char,
        __value: *const libc::c_char,
        __replace: libc::c_int,
    ) -> libc::c_int;
    fn unsetenv(__name: *const libc::c_char) -> libc::c_int;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;

    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn OpenSSL_version(type_0: libc::c_int) -> *const libc::c_char;

    fn ciphers_valid(_: *const libc::c_char) -> libc::c_int;
    fn cipher_alg_list(_: libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn compression_alg_list(_: libc::c_int) -> *const libc::c_char;
    fn ssh_alloc_session_state() -> *mut ssh;
    fn ssh_packet_set_connection(_: *mut ssh, _: libc::c_int, _: libc::c_int) -> *mut ssh;
    fn ssh_packet_set_timeout(_: *mut ssh, _: libc::c_int, _: libc::c_int);
    fn ssh_packet_close(_: *mut ssh);
    fn ssh_packet_set_interactive(_: *mut ssh, _: libc::c_int, _: libc::c_int, _: libc::c_int);
    fn ssh_packet_set_mux(_: *mut ssh);
    fn ssh_packet_get_mux(_: *mut ssh) -> libc::c_int;
    fn sshpkt_start(ssh: *mut ssh, type_0: u_char) -> libc::c_int;
    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_put_u8(ssh: *mut ssh, val: u_char) -> libc::c_int;
    fn sshpkt_put_cstring(ssh: *mut ssh, v: *const libc::c_void) -> libc::c_int;
    fn sshpkt_get_u32(ssh: *mut ssh, valp: *mut u_int32_t) -> libc::c_int;

    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;

    fn channel_init_channels(ssh: *mut ssh);
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
    fn channel_set_af(_: *mut ssh, af: libc::c_int);
    fn channel_add_permission(
        _: *mut ssh,
        _: libc::c_int,
        _: libc::c_int,
        _: *mut libc::c_char,
        _: libc::c_int,
    );
    fn channel_clear_permission(_: *mut ssh, _: libc::c_int, _: libc::c_int);
    fn channel_disable_admin(_: *mut ssh, _: libc::c_int);
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
    fn permitopen_port(_: *const libc::c_char) -> libc::c_int;
    fn x11_request_forwarding_with_spoofing(
        _: *mut ssh,
        _: libc::c_int,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    );

    fn sshkey_is_cert(_: *const crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_ssh_name(_: *const crate::sshkey::sshkey) -> *const libc::c_char;
    fn sshkey_alg_list(
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_char,
    ) -> *mut libc::c_char;
    fn sshkey_check_rsa_length(_: *const crate::sshkey::sshkey, _: libc::c_int) -> libc::c_int;
    fn ssh_get_authentication_socket(fdp: *mut libc::c_int) -> libc::c_int;
    fn sshkey_load_cert(_: *const libc::c_char, _: *mut *mut crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_load_public(
        _: *const libc::c_char,
        _: *mut *mut crate::sshkey::sshkey,
        _: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn client_loop(_: *mut ssh, _: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_int;
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
        _: *mut crate::sshbuf::sshbuf,
        _: *mut *mut libc::c_char,
    );
    fn client_request_tun_fwd(
        _: *mut ssh,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: Option<channel_open_fn>,
        _: *mut libc::c_void,
    ) -> *mut libc::c_char;
    fn client_register_global_confirm(_: Option<global_confirm_cb>, _: *mut libc::c_void);
    fn client_expect_confirm(
        _: *mut ssh,
        _: libc::c_int,
        _: *const libc::c_char,
        _: confirm_action,
    );
    fn muxserver_listen(_: *mut ssh);
    fn muxclient(_: *const libc::c_char) -> libc::c_int;

    fn log_is_on_stderr() -> libc::c_int;
    fn log_redirect_stderr_to(_: *const libc::c_char);
    fn log_verbose_add(_: *const libc::c_char);
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

    fn a2tun(_: *const libc::c_char, _: *mut libc::c_int) -> libc::c_int;
    fn hpdelim(_: *mut *mut libc::c_char) -> *mut libc::c_char;
    fn cleanhostname(_: *mut libc::c_char) -> *mut libc::c_char;
    fn tilde_expand_filename(_: *const libc::c_char, _: uid_t) -> *mut libc::c_char;
    fn percent_expand(_: *const libc::c_char, _: ...) -> *mut libc::c_char;
    fn percent_dollar_expand(_: *const libc::c_char, _: ...) -> *mut libc::c_char;

    fn lowercase(s: *mut libc::c_char);
    fn valid_domain(
        _: *mut libc::c_char,
        _: libc::c_int,
        _: *mut *const libc::c_char,
    ) -> libc::c_int;
    fn valid_env_name(_: *const libc::c_char) -> libc::c_int;
    fn stdfd_devnull(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn pwcopy(_: *mut libc::passwd) -> *mut libc::passwd;
    fn ssh_gai_strerror(_: libc::c_int) -> *const libc::c_char;
    fn lookup_env_in_list(
        env: *const libc::c_char,
        envs: *const *mut libc::c_char,
        nenvs: size_t,
    ) -> *const libc::c_char;

    fn ssh_connection_hash(
        thishost: *const libc::c_char,
        host_0: *const libc::c_char,
        portstr: *const libc::c_char,
        user: *const libc::c_char,
    ) -> *mut libc::c_char;
    fn initialize_options(_: *mut Options);
    fn fill_default_options(_: *mut Options) -> libc::c_int;
    fn fill_default_options_for_canonicalization(_: *mut Options);
    fn process_config_line(
        _: *mut Options,
        _: *mut libc::passwd,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: *mut libc::c_int,
        _: libc::c_int,
    ) -> libc::c_int;
    fn read_config_file(
        _: *const libc::c_char,
        _: *mut libc::passwd,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut Options,
        _: libc::c_int,
        _: *mut libc::c_int,
    ) -> libc::c_int;
    fn parse_forward(
        _: *mut Forward,
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
    ) -> libc::c_int;
    fn parse_jump(_: *const libc::c_char, _: *mut Options, _: libc::c_int) -> libc::c_int;
    fn parse_ssh_uri(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: *mut *mut libc::c_char,
        _: *mut libc::c_int,
    ) -> libc::c_int;
    fn default_ssh_port() -> libc::c_int;
    fn option_clear_or_none(_: *const libc::c_char) -> libc::c_int;
    fn config_has_permitted_cnames(_: *mut Options) -> libc::c_int;
    fn dump_client_config(o: *mut Options, host_0: *const libc::c_char);
    fn add_local_forward(_: *mut Options, _: *const Forward);
    fn add_remote_forward(_: *mut Options, _: *const Forward);
    fn add_identity_file(
        _: *mut Options,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    );
    fn ssh_connect(
        _: *mut ssh,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut addrinfo,
        _: *mut sockaddr_storage,
        _: u_short,
        _: libc::c_int,
        _: *mut libc::c_int,
        _: libc::c_int,
    ) -> libc::c_int;
    fn ssh_kill_proxy_command();
    fn ssh_login(
        _: *mut ssh,
        _: *mut Sensitive,
        _: *const libc::c_char,
        _: *mut sockaddr,
        _: u_short,
        _: *mut libc::passwd,
        _: libc::c_int,
        _: *const ssh_conn_info,
    );
    fn ssh_local_cmd(_: *const libc::c_char) -> libc::c_int;
    fn kex_alg_list(_: libc::c_char) -> *mut libc::c_char;
    fn mac_alg_list(_: libc::c_char) -> *mut libc::c_char;
    fn mac_valid(_: *const libc::c_char) -> libc::c_int;
    fn match_pattern_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;

    fn pkcs11_init(_: libc::c_int) -> libc::c_int;
    fn pkcs11_add_provider(
        _: *mut libc::c_char,
        _: *mut libc::c_char,
        _: *mut *mut *mut crate::sshkey::sshkey,
        _: *mut *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn pkcs11_del_provider(_: *mut libc::c_char) -> libc::c_int;
    static mut __progname: *mut libc::c_char;
    static mut muxserver_sock: libc::c_int;
    static mut muxclient_command: u_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_short = libc::c_ushort;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
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
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_short = __u_short;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type mode_t = __mode_t;
pub type uid_t = __uid_t;
pub type pid_t = __pid_t;
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
    pub input: *mut crate::sshbuf::sshbuf,
    pub output: *mut crate::sshbuf::sshbuf,
    pub extended: *mut crate::sshbuf::sshbuf,
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
    pub key: *mut crate::sshkey::sshkey,
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
pub type global_confirm_cb =
    unsafe extern "C" fn(*mut ssh, libc::c_int, u_int32_t, *mut libc::c_void) -> ();
pub type confirm_action = libc::c_uint;
pub const CONFIRM_TTY: confirm_action = 2;
pub const CONFIRM_CLOSE: confirm_action = 1;
pub const CONFIRM_WARN: confirm_action = 0;
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
    pub identity_keys: [*mut crate::sshkey::sshkey; 100],
    pub num_certificate_files: libc::c_int,
    pub certificate_files: [*mut libc::c_char; 100],
    pub certificate_file_userprovided: [libc::c_int; 100],
    pub certificates: [*mut crate::sshkey::sshkey; 100],
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Sensitive {
    pub keys: *mut *mut crate::sshkey::sshkey,
    pub nkeys: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh_conn_info {
    pub conn_hash_hex: *mut libc::c_char,
    pub shorthost: *mut libc::c_char,
    pub uidstr: *mut libc::c_char,
    pub keyalias: *mut libc::c_char,
    pub thishost: *mut libc::c_char,
    pub host_arg: *mut libc::c_char,
    pub portstr: *mut libc::c_char,
    pub remhost: *mut libc::c_char,
    pub remuser: *mut libc::c_char,
    pub homedir: *mut libc::c_char,
    pub locuser: *mut libc::c_char,
}
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
static mut saved_av: *mut *mut libc::c_char =
    0 as *const *mut libc::c_char as *mut *mut libc::c_char;
pub static mut debug_flag: libc::c_int = 0 as libc::c_int;
pub static mut tty_flag: libc::c_int = 0 as libc::c_int;
pub static mut need_controlpersist_detach: libc::c_int = 0 as libc::c_int;
pub static mut ostdin_null_flag: libc::c_int = 0;
pub static mut osession_type: libc::c_int = 0;
pub static mut otty_flag: libc::c_int = 0;
pub static mut orequest_tty: libc::c_int = 0;
pub static mut options: Options = Options {
    host_arg: 0 as *const libc::c_char as *mut libc::c_char,
    forward_agent: 0,
    forward_agent_sock_path: 0 as *const libc::c_char as *mut libc::c_char,
    forward_x11: 0,
    forward_x11_timeout: 0,
    forward_x11_trusted: 0,
    exit_on_forward_failure: 0,
    xauth_location: 0 as *const libc::c_char as *mut libc::c_char,
    fwd_opts: ForwardOptions {
        gateway_ports: 0,
        streamlocal_bind_mask: 0,
        streamlocal_bind_unlink: 0,
    },
    pubkey_authentication: 0,
    hostbased_authentication: 0,
    gss_authentication: 0,
    gss_deleg_creds: 0,
    password_authentication: 0,
    kbd_interactive_authentication: 0,
    kbd_interactive_devices: 0 as *const libc::c_char as *mut libc::c_char,
    batch_mode: 0,
    check_host_ip: 0,
    strict_host_key_checking: 0,
    compression: 0,
    tcp_keep_alive: 0,
    ip_qos_interactive: 0,
    ip_qos_bulk: 0,
    log_facility: SYSLOG_FACILITY_DAEMON,
    log_level: SYSLOG_LEVEL_QUIET,
    num_log_verbose: 0,
    log_verbose: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    port: 0,
    address_family: 0,
    connection_attempts: 0,
    connection_timeout: 0,
    number_of_password_prompts: 0,
    ciphers: 0 as *const libc::c_char as *mut libc::c_char,
    macs: 0 as *const libc::c_char as *mut libc::c_char,
    hostkeyalgorithms: 0 as *const libc::c_char as *mut libc::c_char,
    kex_algorithms: 0 as *const libc::c_char as *mut libc::c_char,
    ca_sign_algorithms: 0 as *const libc::c_char as *mut libc::c_char,
    hostname: 0 as *const libc::c_char as *mut libc::c_char,
    host_key_alias: 0 as *const libc::c_char as *mut libc::c_char,
    proxy_command: 0 as *const libc::c_char as *mut libc::c_char,
    user: 0 as *const libc::c_char as *mut libc::c_char,
    escape_char: 0,
    num_system_hostfiles: 0,
    system_hostfiles: [0 as *const libc::c_char as *mut libc::c_char; 32],
    num_user_hostfiles: 0,
    user_hostfiles: [0 as *const libc::c_char as *mut libc::c_char; 32],
    preferred_authentications: 0 as *const libc::c_char as *mut libc::c_char,
    bind_address: 0 as *const libc::c_char as *mut libc::c_char,
    bind_interface: 0 as *const libc::c_char as *mut libc::c_char,
    pkcs11_provider: 0 as *const libc::c_char as *mut libc::c_char,
    sk_provider: 0 as *const libc::c_char as *mut libc::c_char,
    verify_host_key_dns: 0,
    num_identity_files: 0,
    identity_files: [0 as *const libc::c_char as *mut libc::c_char; 100],
    identity_file_userprovided: [0; 100],
    identity_keys: [0 as *const crate::sshkey::sshkey as *mut crate::sshkey::sshkey; 100],
    num_certificate_files: 0,
    certificate_files: [0 as *const libc::c_char as *mut libc::c_char; 100],
    certificate_file_userprovided: [0; 100],
    certificates: [0 as *const crate::sshkey::sshkey as *mut crate::sshkey::sshkey; 100],
    add_keys_to_agent: 0,
    add_keys_to_agent_lifespan: 0,
    identity_agent: 0 as *const libc::c_char as *mut libc::c_char,
    num_local_forwards: 0,
    local_forwards: 0 as *const Forward as *mut Forward,
    num_remote_forwards: 0,
    remote_forwards: 0 as *const Forward as *mut Forward,
    clear_forwardings: 0,
    permitted_remote_opens: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num_permitted_remote_opens: 0,
    stdio_forward_host: 0 as *const libc::c_char as *mut libc::c_char,
    stdio_forward_port: 0,
    enable_ssh_keysign: 0,
    rekey_limit: 0,
    rekey_interval: 0,
    no_host_authentication_for_localhost: 0,
    identities_only: 0,
    server_alive_interval: 0,
    server_alive_count_max: 0,
    num_send_env: 0,
    send_env: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num_setenv: 0,
    setenv: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    control_path: 0 as *const libc::c_char as *mut libc::c_char,
    control_master: 0,
    control_persist: 0,
    control_persist_timeout: 0,
    hash_known_hosts: 0,
    tun_open: 0,
    tun_local: 0,
    tun_remote: 0,
    local_command: 0 as *const libc::c_char as *mut libc::c_char,
    permit_local_command: 0,
    remote_command: 0 as *const libc::c_char as *mut libc::c_char,
    visual_host_key: 0,
    request_tty: 0,
    session_type: 0,
    stdin_null: 0,
    fork_after_authentication: 0,
    proxy_use_fdpass: 0,
    num_canonical_domains: 0,
    canonical_domains: [0 as *const libc::c_char as *mut libc::c_char; 32],
    canonicalize_hostname: 0,
    canonicalize_max_dots: 0,
    canonicalize_fallback_local: 0,
    num_permitted_cnames: 0,
    permitted_cnames: [allowed_cname {
        source_list: 0 as *const libc::c_char as *mut libc::c_char,
        target_list: 0 as *const libc::c_char as *mut libc::c_char,
    }; 32],
    revoked_host_keys: 0 as *const libc::c_char as *mut libc::c_char,
    fingerprint_hash: 0,
    update_hostkeys: 0,
    hostbased_accepted_algos: 0 as *const libc::c_char as *mut libc::c_char,
    pubkey_accepted_algos: 0 as *const libc::c_char as *mut libc::c_char,
    jump_user: 0 as *const libc::c_char as *mut libc::c_char,
    jump_host: 0 as *const libc::c_char as *mut libc::c_char,
    jump_port: 0,
    jump_extra: 0 as *const libc::c_char as *mut libc::c_char,
    known_hosts_command: 0 as *const libc::c_char as *mut libc::c_char,
    required_rsa_size: 0,
    enable_escape_commandline: 0,
    ignored_unknown: 0 as *const libc::c_char as *mut libc::c_char,
};
pub static mut config: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
pub static mut host: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
pub static mut forward_agent_sock_path: *mut libc::c_char =
    0 as *const libc::c_char as *mut libc::c_char;
pub static mut hostaddr: sockaddr_storage = sockaddr_storage {
    ss_family: 0,
    __ss_padding: [0; 118],
    __ss_align: 0,
};
pub static mut sensitive_data: Sensitive = Sensitive {
    keys: 0 as *const *mut crate::sshkey::sshkey as *mut *mut crate::sshkey::sshkey,
    nkeys: 0,
};
pub static mut command: *mut crate::sshbuf::sshbuf =
    0 as *const crate::sshbuf::sshbuf as *mut crate::sshbuf::sshbuf;
static mut forward_confirms_pending: libc::c_int = -(1 as libc::c_int);
unsafe extern "C" fn usage() {
    libc::fprintf(
        stderr,
        b"usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]\n           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]\n           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]\n           [-i identity_file] [-J [user@]host[:port]] [-L address]\n           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]\n           [-Q query_option] [-R address] [-S ctl_path] [-W host:port]\n           [-w local_tun[:remote_tun]] destination [command [argument ...]]\n\0"
            as *const u8 as *const libc::c_char,
    );
    libc::exit(255 as libc::c_int);
}
unsafe extern "C" fn tilde_expand_paths(mut paths: *mut *mut libc::c_char, mut num_paths: u_int) {
    let mut i: u_int = 0;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < num_paths {
        cp = tilde_expand_filename(*paths.offset(i as isize), libc::getuid());
        libc::free(*paths.offset(i as isize) as *mut libc::c_void);
        let ref mut fresh0 = *paths.offset(i as isize);
        *fresh0 = cp;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn default_client_percent_expand(
    mut str: *const libc::c_char,
    mut cinfo: *const ssh_conn_info,
) -> *mut libc::c_char {
    return percent_expand(
        str,
        b"C\0" as *const u8 as *const libc::c_char,
        (*cinfo).conn_hash_hex,
        b"L\0" as *const u8 as *const libc::c_char,
        (*cinfo).shorthost,
        b"i\0" as *const u8 as *const libc::c_char,
        (*cinfo).uidstr,
        b"k\0" as *const u8 as *const libc::c_char,
        (*cinfo).keyalias,
        b"l\0" as *const u8 as *const libc::c_char,
        (*cinfo).thishost,
        b"n\0" as *const u8 as *const libc::c_char,
        (*cinfo).host_arg,
        b"p\0" as *const u8 as *const libc::c_char,
        (*cinfo).portstr,
        b"d\0" as *const u8 as *const libc::c_char,
        (*cinfo).homedir,
        b"h\0" as *const u8 as *const libc::c_char,
        (*cinfo).remhost,
        b"r\0" as *const u8 as *const libc::c_char,
        (*cinfo).remuser,
        b"u\0" as *const u8 as *const libc::c_char,
        (*cinfo).locuser,
        0 as *mut libc::c_void as *mut libc::c_char,
    );
}
unsafe extern "C" fn default_client_percent_dollar_expand(
    mut str: *const libc::c_char,
    mut cinfo: *const ssh_conn_info,
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    ret = percent_dollar_expand(
        str,
        b"C\0" as *const u8 as *const libc::c_char,
        (*cinfo).conn_hash_hex,
        b"L\0" as *const u8 as *const libc::c_char,
        (*cinfo).shorthost,
        b"i\0" as *const u8 as *const libc::c_char,
        (*cinfo).uidstr,
        b"k\0" as *const u8 as *const libc::c_char,
        (*cinfo).keyalias,
        b"l\0" as *const u8 as *const libc::c_char,
        (*cinfo).thishost,
        b"n\0" as *const u8 as *const libc::c_char,
        (*cinfo).host_arg,
        b"p\0" as *const u8 as *const libc::c_char,
        (*cinfo).portstr,
        b"d\0" as *const u8 as *const libc::c_char,
        (*cinfo).homedir,
        b"h\0" as *const u8 as *const libc::c_char,
        (*cinfo).remhost,
        b"r\0" as *const u8 as *const libc::c_char,
        (*cinfo).remuser,
        b"u\0" as *const u8 as *const libc::c_char,
        (*cinfo).locuser,
        0 as *mut libc::c_void as *mut libc::c_char,
    );
    if ret.is_null() {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                b"default_client_percent_dollar_expand\0",
            ))
            .as_ptr(),
            240 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"invalid environment variable expansion\0" as *const u8 as *const libc::c_char,
        );
    }
    return ret;
}
unsafe extern "C" fn resolve_host(
    mut name: *const libc::c_char,
    mut port: libc::c_int,
    mut logerr: libc::c_int,
    mut cname: *mut libc::c_char,
    mut clen: size_t,
) -> *mut addrinfo {
    let mut strport: [libc::c_char; 32] = [0; 32];
    let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
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
    let mut res: *mut addrinfo = 0 as *mut addrinfo;
    let mut gaierr: libc::c_int = 0;
    let mut loglevel: LogLevel = SYSLOG_LEVEL_DEBUG1;
    if port <= 0 as libc::c_int {
        port = default_ssh_port();
    }
    if !cname.is_null() {
        *cname = '\0' as i32 as libc::c_char;
    }
    crate::log::sshlog(
        b"ssh.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"resolve_host\0")).as_ptr(),
        263 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"lookup %s:%d\0" as *const u8 as *const libc::c_char,
        name,
        port,
    );
    libc::snprintf(
        strport.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
        b"%d\0" as *const u8 as *const libc::c_char,
        port,
    );
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_family = if options.address_family == -(1 as libc::c_int) {
        0 as libc::c_int
    } else {
        options.address_family
    };
    hints.ai_socktype = SOCK_STREAM as libc::c_int;
    if !cname.is_null() {
        hints.ai_flags = 0x2 as libc::c_int;
    }
    gaierr = getaddrinfo(name, strport.as_mut_ptr(), &mut hints, &mut res);
    if gaierr != 0 as libc::c_int {
        if logerr != 0 || gaierr != -(2 as libc::c_int) && gaierr != -(5 as libc::c_int) {
            loglevel = SYSLOG_LEVEL_ERROR;
        }
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"resolve_host\0")).as_ptr(),
            276 as libc::c_int,
            0 as libc::c_int,
            loglevel,
            0 as *const libc::c_char,
            b"%s: Could not resolve hostname %.100s: %s\0" as *const u8 as *const libc::c_char,
            __progname,
            name,
            ssh_gai_strerror(gaierr),
        );
        return 0 as *mut addrinfo;
    }
    if !cname.is_null() && !((*res).ai_canonname).is_null() {
        if valid_domain((*res).ai_canonname, 0 as libc::c_int, &mut errstr) == 0 {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"resolve_host\0"))
                    .as_ptr(),
                282 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"ignoring bad CNAME \"%s\" for host \"%s\": %s\0" as *const u8
                    as *const libc::c_char,
                (*res).ai_canonname,
                name,
                errstr,
            );
        } else if strlcpy(cname, (*res).ai_canonname, clen) >= clen {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"resolve_host\0"))
                    .as_ptr(),
                285 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"host \"%s\" cname \"%s\" too long (max %lu)\0" as *const u8
                    as *const libc::c_char,
                name,
                (*res).ai_canonname,
                clen,
            );
            if clen > 0 as libc::c_int as libc::c_ulong {
                *cname = '\0' as i32 as libc::c_char;
            }
        }
    }
    return res;
}
unsafe extern "C" fn is_addr_fast(mut name: *const libc::c_char) -> libc::c_int {
    return (!(libc::strchr(name, '%' as i32)).is_null()
        || !(libc::strchr(name, ':' as i32)).is_null()
        || strspn(name, b"0123456789.\0" as *const u8 as *const libc::c_char) == strlen(name))
        as libc::c_int;
}
unsafe extern "C" fn is_addr(mut name: *const libc::c_char) -> libc::c_int {
    let mut strport: [libc::c_char; 32] = [0; 32];
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
    let mut res: *mut addrinfo = 0 as *mut addrinfo;
    if is_addr_fast(name) != 0 {
        return 1 as libc::c_int;
    }
    libc::snprintf(
        strport.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
        b"%u\0" as *const u8 as *const libc::c_char,
        default_ssh_port(),
    );
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_family = if options.address_family == -(1 as libc::c_int) {
        0 as libc::c_int
    } else {
        options.address_family
    };
    hints.ai_socktype = SOCK_STREAM as libc::c_int;
    hints.ai_flags = 0x4 as libc::c_int | 0x400 as libc::c_int;
    if getaddrinfo(name, strport.as_mut_ptr(), &mut hints, &mut res) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if res.is_null() || !((*res).ai_next).is_null() {
        freeaddrinfo(res);
        return 0 as libc::c_int;
    }
    freeaddrinfo(res);
    return 1 as libc::c_int;
}
unsafe extern "C" fn resolve_addr(
    mut name: *const libc::c_char,
    mut port: libc::c_int,
    mut caddr: *mut libc::c_char,
    mut clen: size_t,
) -> *mut addrinfo {
    let mut addr: [libc::c_char; 1025] = [0; 1025];
    let mut strport: [libc::c_char; 32] = [0; 32];
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
    let mut res: *mut addrinfo = 0 as *mut addrinfo;
    let mut gaierr: libc::c_int = 0;
    if port <= 0 as libc::c_int {
        port = default_ssh_port();
    }
    libc::snprintf(
        strport.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
        b"%u\0" as *const u8 as *const libc::c_char,
        port,
    );
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_family = if options.address_family == -(1 as libc::c_int) {
        0 as libc::c_int
    } else {
        options.address_family
    };
    hints.ai_socktype = SOCK_STREAM as libc::c_int;
    hints.ai_flags = 0x4 as libc::c_int | 0x400 as libc::c_int;
    gaierr = getaddrinfo(name, strport.as_mut_ptr(), &mut hints, &mut res);
    if gaierr != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"resolve_addr\0")).as_ptr(),
            350 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"could not resolve name %.100s as address: %s\0" as *const u8 as *const libc::c_char,
            name,
            ssh_gai_strerror(gaierr),
        );
        return 0 as *mut addrinfo;
    }
    if res.is_null() {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"resolve_addr\0")).as_ptr(),
            354 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"getaddrinfo %.100s returned no addresses\0" as *const u8 as *const libc::c_char,
            name,
        );
        return 0 as *mut addrinfo;
    }
    if !((*res).ai_next).is_null() {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"resolve_addr\0")).as_ptr(),
            358 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"getaddrinfo %.100s returned multiple addresses\0" as *const u8 as *const libc::c_char,
            name,
        );
    } else {
        gaierr = getnameinfo(
            (*res).ai_addr,
            (*res).ai_addrlen,
            addr.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as socklen_t,
            0 as *mut libc::c_char,
            0 as libc::c_int as socklen_t,
            1 as libc::c_int,
        );
        if gaierr != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"resolve_addr\0"))
                    .as_ptr(),
                364 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Could not format address for name %.100s: %s\0" as *const u8
                    as *const libc::c_char,
                name,
                ssh_gai_strerror(gaierr),
            );
        } else if strlcpy(caddr, addr.as_mut_ptr(), clen) >= clen {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"resolve_addr\0"))
                    .as_ptr(),
                369 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"host \"%s\" addr \"%s\" too long (max %lu)\0" as *const u8 as *const libc::c_char,
                name,
                addr.as_mut_ptr(),
                clen,
            );
            if clen > 0 as libc::c_int as libc::c_ulong {
                *caddr = '\0' as i32 as libc::c_char;
            }
        } else {
            return res;
        }
    }
    freeaddrinfo(res);
    return 0 as *mut addrinfo;
}
unsafe extern "C" fn check_follow_cname(
    mut direct: libc::c_int,
    mut namep: *mut *mut libc::c_char,
    mut cname: *const libc::c_char,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut rule: *mut allowed_cname = 0 as *mut allowed_cname;
    if *cname as libc::c_int == '\0' as i32
        || config_has_permitted_cnames(&mut options) == 0
        || libc::strcmp(*namep, cname) == 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    if options.canonicalize_hostname == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if direct == 0 && options.canonicalize_hostname != 2 as libc::c_int {
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"ssh.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"check_follow_cname\0"))
            .as_ptr(),
        402 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"check \"%s\" CNAME \"%s\"\0" as *const u8 as *const libc::c_char,
        *namep,
        cname,
    );
    i = 0 as libc::c_int;
    while i < options.num_permitted_cnames {
        rule = (options.permitted_cnames).as_mut_ptr().offset(i as isize);
        if match_pattern_list(*namep, (*rule).source_list, 1 as libc::c_int) != 1 as libc::c_int
            || match_pattern_list(cname, (*rule).target_list, 1 as libc::c_int) != 1 as libc::c_int
        {
            i += 1;
            i;
        } else {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"check_follow_cname\0",
                ))
                .as_ptr(),
                409 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_VERBOSE,
                0 as *const libc::c_char,
                b"Canonicalized DNS aliased hostname \"%s\" => \"%s\"\0" as *const u8
                    as *const libc::c_char,
                *namep,
                cname,
            );
            libc::free(*namep as *mut libc::c_void);
            *namep = crate::xmalloc::xstrdup(cname);
            return 1 as libc::c_int;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn resolve_canonicalize(
    mut hostp: *mut *mut libc::c_char,
    mut port: libc::c_int,
) -> *mut addrinfo {
    let mut current_block: u64;
    let mut i: libc::c_int = 0;
    let mut direct: libc::c_int = 0;
    let mut ndots: libc::c_int = 0;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fullhost: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut newname: [libc::c_char; 1025] = [0; 1025];
    let mut addrs: *mut addrinfo = 0 as *mut addrinfo;
    addrs = resolve_addr(
        *hostp,
        port,
        newname.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
    );
    if !addrs.is_null() {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"resolve_canonicalize\0"))
                .as_ptr(),
            436 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"hostname %.100s is address\0" as *const u8 as *const libc::c_char,
            *hostp,
        );
        if strcasecmp(*hostp, newname.as_mut_ptr()) != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"resolve_canonicalize\0",
                ))
                .as_ptr(),
                439 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"canonicalised address \"%s\" => \"%s\"\0" as *const u8 as *const libc::c_char,
                *hostp,
                newname.as_mut_ptr(),
            );
            libc::free(*hostp as *mut libc::c_void);
            *hostp = crate::xmalloc::xstrdup(newname.as_mut_ptr());
        }
        return addrs;
    }
    if is_addr_fast(*hostp) != 0 {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"resolve_canonicalize\0"))
                .as_ptr(),
            452 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"hostname %.100s is an unrecognised address\0" as *const u8 as *const libc::c_char,
            *hostp,
        );
        return 0 as *mut addrinfo;
    }
    if options.canonicalize_hostname == 0 as libc::c_int {
        return 0 as *mut addrinfo;
    }
    direct = (option_clear_or_none(options.proxy_command) != 0
        && option_clear_or_none(options.jump_host) != 0) as libc::c_int;
    if direct == 0 && options.canonicalize_hostname != 2 as libc::c_int {
        return 0 as *mut addrinfo;
    }
    if *(*hostp).offset((strlen(*hostp)).wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
        as libc::c_int
        == '.' as i32
    {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"resolve_canonicalize\0"))
                .as_ptr(),
            471 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"name is fully qualified\0" as *const u8 as *const libc::c_char,
        );
        fullhost = crate::xmalloc::xstrdup(*hostp);
        addrs = resolve_host(
            fullhost,
            port,
            0 as libc::c_int,
            newname.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
        );
        if !addrs.is_null() {
            current_block = 8954165352696300745;
        } else {
            libc::free(fullhost as *mut libc::c_void);
            current_block = 17524704725112814263;
        }
    } else {
        ndots = 0 as libc::c_int;
        cp = *hostp;
        while *cp as libc::c_int != '\0' as i32 {
            if *cp as libc::c_int == '.' as i32 {
                ndots += 1;
                ndots;
            }
            cp = cp.offset(1);
            cp;
        }
        if ndots > options.canonicalize_max_dots {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"resolve_canonicalize\0",
                ))
                .as_ptr(),
                488 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"not canonicalizing hostname \"%s\" (max dots %d)\0" as *const u8
                    as *const libc::c_char,
                *hostp,
                options.canonicalize_max_dots,
            );
            return 0 as *mut addrinfo;
        }
        i = 0 as libc::c_int;
        loop {
            if !(i < options.num_canonical_domains) {
                current_block = 17524704725112814263;
                break;
            }
            if strcasecmp(
                options.canonical_domains[i as usize],
                b"none\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
            {
                current_block = 17524704725112814263;
                break;
            }
            crate::xmalloc::xasprintf(
                &mut fullhost as *mut *mut libc::c_char,
                b"%s.%s.\0" as *const u8 as *const libc::c_char,
                *hostp,
                options.canonical_domains[i as usize],
            );
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"resolve_canonicalize\0",
                ))
                .as_ptr(),
                497 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"attempting \"%s\" => \"%s\"\0" as *const u8 as *const libc::c_char,
                *hostp,
                fullhost,
            );
            addrs = resolve_host(
                fullhost,
                port,
                0 as libc::c_int,
                newname.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
            );
            if !addrs.is_null() {
                current_block = 8954165352696300745;
                break;
            }
            libc::free(fullhost as *mut libc::c_void);
            i += 1;
            i;
        }
    }
    match current_block {
        17524704725112814263 => {
            if options.canonicalize_fallback_local == 0 {
                sshfatal(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"resolve_canonicalize\0",
                    ))
                    .as_ptr(),
                    517 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"%s: Could not resolve host \"%s\"\0" as *const u8 as *const libc::c_char,
                    __progname,
                    *hostp,
                );
            }
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"resolve_canonicalize\0",
                ))
                .as_ptr(),
                518 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"host %s not found in any suffix\0" as *const u8 as *const libc::c_char,
                *hostp,
            );
            return 0 as *mut addrinfo;
        }
        _ => {
            *fullhost.offset(
                (strlen(fullhost)).wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
            ) = '\0' as i32 as libc::c_char;
            if check_follow_cname(direct, &mut fullhost, newname.as_mut_ptr()) == 0 {
                crate::log::sshlog(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"resolve_canonicalize\0",
                    ))
                    .as_ptr(),
                    509 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Canonicalized hostname \"%s\" => \"%s\"\0" as *const u8
                        as *const libc::c_char,
                    *hostp,
                    fullhost,
                );
            }
            libc::free(*hostp as *mut libc::c_void);
            *hostp = fullhost;
            return addrs;
        }
    };
}
unsafe extern "C" fn check_load(
    mut r: libc::c_int,
    mut k: *mut *mut crate::sshkey::sshkey,
    mut path: *const libc::c_char,
    mut message: *const libc::c_char,
) {
    let mut current_block_6: u64;
    match r {
        0 => {
            if !k.is_null() && !(*k).is_null() && {
                r = sshkey_check_rsa_length(*k, options.required_rsa_size);
                r != 0 as libc::c_int
            } {
                crate::log::sshlog(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"check_load\0"))
                        .as_ptr(),
                    535 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"load %s \"%s\"\0" as *const u8 as *const libc::c_char,
                    message,
                    path,
                );
                libc::free(*k as *mut libc::c_void);
                *k = 0 as *mut crate::sshkey::sshkey;
            }
            current_block_6 = 13513818773234778473;
        }
        -1 | -2 => {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"check_load\0"))
                    .as_ptr(),
                542 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"load %s \"%s\"\0" as *const u8 as *const libc::c_char,
                message,
                path,
            );
        }
        -24 => {
            if *libc::__errno_location() == 2 as libc::c_int {
                current_block_6 = 13513818773234778473;
            } else {
                current_block_6 = 15401741586054900061;
            }
        }
        _ => {
            current_block_6 = 15401741586054900061;
        }
    }
    match current_block_6 {
        15401741586054900061 => {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"check_load\0"))
                    .as_ptr(),
                549 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"load %s \"%s\"\0" as *const u8 as *const libc::c_char,
                message,
                path,
            );
        }
        _ => {}
    };
}
unsafe extern "C" fn process_config_files(
    mut host_name: *const libc::c_char,
    mut pw: *mut libc::passwd,
    mut final_pass: libc::c_int,
    mut want_final_pass: *mut libc::c_int,
) {
    let mut buf: [libc::c_char; 4096] = [0; 4096];
    let mut r: libc::c_int = 0;
    if !config.is_null() {
        if strcasecmp(config, b"none\0" as *const u8 as *const libc::c_char) != 0 as libc::c_int
            && read_config_file(
                config,
                pw,
                host,
                host_name,
                &mut options,
                2 as libc::c_int
                    | (if final_pass != 0 {
                        4 as libc::c_int
                    } else {
                        0 as libc::c_int
                    }),
                want_final_pass,
            ) == 0
        {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"process_config_files\0",
                ))
                .as_ptr(),
                571 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Can't open user config file %.100s: %.100s\0" as *const u8 as *const libc::c_char,
                config,
                libc::strerror(*libc::__errno_location()),
            );
        }
    } else {
        r = libc::snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 4096]>() as usize,
            b"%s/%s\0" as *const u8 as *const libc::c_char,
            (*pw).pw_dir,
            b".ssh/config\0" as *const u8 as *const libc::c_char,
        );
        if r > 0 as libc::c_int
            && (r as size_t) < ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
        {
            read_config_file(
                buf.as_mut_ptr(),
                pw,
                host,
                host_name,
                &mut options,
                1 as libc::c_int
                    | 2 as libc::c_int
                    | (if final_pass != 0 {
                        4 as libc::c_int
                    } else {
                        0 as libc::c_int
                    }),
                want_final_pass,
            );
        }
        read_config_file(
            b"/usr/local/etc/ssh_config\0" as *const u8 as *const libc::c_char,
            pw,
            host,
            host_name,
            &mut options,
            if final_pass != 0 {
                4 as libc::c_int
            } else {
                0 as libc::c_int
            },
            want_final_pass,
        );
    };
}
unsafe extern "C" fn set_addrinfo_port(mut addrs: *mut addrinfo, mut port: libc::c_int) {
    let mut addr: *mut addrinfo = 0 as *mut addrinfo;
    addr = addrs;
    while !addr.is_null() {
        match (*addr).ai_family {
            2 => {
                (*((*addr).ai_addr as *mut sockaddr_in)).sin_port = __bswap_16(port as __uint16_t);
            }
            10 => {
                (*((*addr).ai_addr as *mut sockaddr_in6)).sin6_port =
                    __bswap_16(port as __uint16_t);
            }
            _ => {}
        }
        addr = (*addr).ai_next;
    }
}
unsafe extern "C" fn ssh_conn_info_free(mut cinfo: *mut ssh_conn_info) {
    if cinfo.is_null() {
        return;
    }
    libc::free((*cinfo).conn_hash_hex as *mut libc::c_void);
    libc::free((*cinfo).shorthost as *mut libc::c_void);
    libc::free((*cinfo).uidstr as *mut libc::c_void);
    libc::free((*cinfo).keyalias as *mut libc::c_void);
    libc::free((*cinfo).thishost as *mut libc::c_void);
    libc::free((*cinfo).host_arg as *mut libc::c_void);
    libc::free((*cinfo).portstr as *mut libc::c_void);
    libc::free((*cinfo).remhost as *mut libc::c_void);
    libc::free((*cinfo).remuser as *mut libc::c_void);
    libc::free((*cinfo).homedir as *mut libc::c_void);
    libc::free((*cinfo).locuser as *mut libc::c_void);
    libc::free(cinfo as *mut libc::c_void);
}
unsafe fn main_0(mut ac: libc::c_int, mut av: *mut *mut libc::c_char) -> libc::c_int {
    let mut current_block: u64;
    let mut ssh: *mut ssh = 0 as *mut ssh;
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut opt: libc::c_int = 0;
    let mut exit_status: libc::c_int = 0;
    let mut use_syslog: libc::c_int = 0;
    let mut direct: libc::c_int = 0;
    let mut timeout_ms: libc::c_int = 0;
    let mut was_addr: libc::c_int = 0;
    let mut config_test: libc::c_int = 0 as libc::c_int;
    let mut opt_terminated: libc::c_int = 0 as libc::c_int;
    let mut want_final_pass: libc::c_int = 0 as libc::c_int;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut argv0: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut logfile: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cname: [libc::c_char; 1025] = [0; 1025];
    let mut thishost: [libc::c_char; 1025] = [0; 1025];
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut pw: *mut libc::passwd = 0 as *mut libc::passwd;
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptreset"]
        static mut BSDoptreset_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptarg"]
        static mut BSDoptarg_0: *mut libc::c_char;
    }
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
    let mut addrs: *mut addrinfo = 0 as *mut addrinfo;
    let mut n: size_t = 0;
    let mut len: size_t = 0;
    let mut j: u_int = 0;
    let mut cinfo: *mut ssh_conn_info = 0 as *mut ssh_conn_info;
    crate::misc::sanitise_stdfd();
    closefrom(2 as libc::c_int + 1 as libc::c_int);
    __progname =
        crate::openbsd_compat::bsd_misc::ssh_get_progname(*av.offset(0 as libc::c_int as isize));
    saved_av = crate::xmalloc::xcalloc(
        (ac + 1 as libc::c_int) as size_t,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    i = 0 as libc::c_int;
    while i < ac {
        let ref mut fresh1 = *saved_av.offset(i as isize);
        *fresh1 = crate::xmalloc::xstrdup(*av.offset(i as isize));
        i += 1;
        i;
    }
    let ref mut fresh2 = *saved_av.offset(i as isize);
    *fresh2 = 0 as *mut libc::c_char;
    compat_init_setproctitle(ac, av);
    av = saved_av;
    seed_rng();
    pw = libc::getpwuid(libc::getuid());
    if pw.is_null() {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            674 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"No user exists for uid %lu\0" as *const u8 as *const libc::c_char,
            libc::getuid() as u_long,
        );
        libc::exit(255 as libc::c_int);
    }
    pw = pwcopy(pw);
    libc::umask(0o22 as libc::c_int as libc::c_uint | libc::umask(0o77 as libc::c_int as __mode_t));
    msetlocale();
    initialize_options(&mut options);
    ssh = ssh_alloc_session_state();
    if ssh.is_null() {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            700 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Couldn't allocate session state\0" as *const u8 as *const libc::c_char,
        );
    }
    channel_init_channels(ssh);
    host = 0 as *mut libc::c_char;
    use_syslog = 0 as libc::c_int;
    logfile = 0 as *mut libc::c_char;
    argv0 = *av.offset(0 as libc::c_int as isize);
    loop {
        loop {
            opt = crate::openbsd_compat::getopt_long::BSDgetopt(
                ac,
                av,
                b"1246ab:c:e:fgi:kl:m:no:p:qstvxAB:CD:E:F:GI:J:KL:MNO:PQ:R:S:TVw:W:XYy\0"
                    as *const u8 as *const libc::c_char,
            );
            if !(opt != -(1 as libc::c_int)) {
                break;
            }
            match opt {
                49 => {
                    sshfatal(
                        b"ssh.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        714 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"SSH protocol v.1 is no longer supported\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                50 => {}
                52 => {
                    options.address_family = 2 as libc::c_int;
                }
                54 => {
                    options.address_family = 10 as libc::c_int;
                }
                110 => {
                    options.stdin_null = 1 as libc::c_int;
                }
                102 => {
                    options.fork_after_authentication = 1 as libc::c_int;
                    options.stdin_null = 1 as libc::c_int;
                }
                120 => {
                    options.forward_x11 = 0 as libc::c_int;
                }
                88 => {
                    options.forward_x11 = 1 as libc::c_int;
                }
                121 => {
                    use_syslog = 1 as libc::c_int;
                }
                69 => {
                    logfile = BSDoptarg;
                }
                71 => {
                    config_test = 1 as libc::c_int;
                }
                89 => {
                    options.forward_x11 = 1 as libc::c_int;
                    options.forward_x11_trusted = 1 as libc::c_int;
                }
                103 => {
                    options.fwd_opts.gateway_ports = 1 as libc::c_int;
                }
                79 => {
                    if !(options.stdio_forward_host).is_null() {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            757 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Cannot specify multiplexing command with -W\0" as *const u8
                                as *const libc::c_char,
                        );
                    } else if muxclient_command != 0 as libc::c_int as libc::c_uint {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            759 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Multiplexing command already specified\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    if libc::strcmp(BSDoptarg, b"check\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                    {
                        muxclient_command = 2 as libc::c_int as u_int;
                    } else if libc::strcmp(
                        BSDoptarg,
                        b"forward\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        muxclient_command = 5 as libc::c_int as u_int;
                    } else if libc::strcmp(
                        BSDoptarg,
                        b"libc::exit\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        muxclient_command = 3 as libc::c_int as u_int;
                    } else if libc::strcmp(BSDoptarg, b"stop\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                    {
                        muxclient_command = 6 as libc::c_int as u_int;
                    } else if libc::strcmp(
                        BSDoptarg,
                        b"cancel\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        muxclient_command = 7 as libc::c_int as u_int;
                    } else if libc::strcmp(
                        BSDoptarg,
                        b"proxy\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        muxclient_command = 8 as libc::c_int as u_int;
                    } else {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            773 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Invalid multiplex command.\0" as *const u8 as *const libc::c_char,
                        );
                    }
                }
                80 => {}
                81 => {
                    cp = 0 as *mut libc::c_char;
                    if libc::strcmp(BSDoptarg, b"cipher\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                        || strcasecmp(BSDoptarg, b"Ciphers\0" as *const u8 as *const libc::c_char)
                            == 0 as libc::c_int
                    {
                        cp = cipher_alg_list('\n' as i32 as libc::c_char, 0 as libc::c_int);
                    } else if libc::strcmp(
                        BSDoptarg,
                        b"cipher-auth\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        cp = cipher_alg_list('\n' as i32 as libc::c_char, 1 as libc::c_int);
                    } else if libc::strcmp(BSDoptarg, b"mac\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                        || strcasecmp(BSDoptarg, b"MACs\0" as *const u8 as *const libc::c_char)
                            == 0 as libc::c_int
                    {
                        cp = mac_alg_list('\n' as i32 as libc::c_char);
                    } else if libc::strcmp(BSDoptarg, b"kex\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                        || strcasecmp(
                            BSDoptarg,
                            b"KexAlgorithms\0" as *const u8 as *const libc::c_char,
                        ) == 0 as libc::c_int
                    {
                        cp = kex_alg_list('\n' as i32 as libc::c_char);
                    } else if libc::strcmp(BSDoptarg, b"key\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                    {
                        cp = sshkey_alg_list(
                            0 as libc::c_int,
                            0 as libc::c_int,
                            0 as libc::c_int,
                            '\n' as i32 as libc::c_char,
                        );
                    } else if libc::strcmp(
                        BSDoptarg,
                        b"key-cert\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        cp = sshkey_alg_list(
                            1 as libc::c_int,
                            0 as libc::c_int,
                            0 as libc::c_int,
                            '\n' as i32 as libc::c_char,
                        );
                    } else if libc::strcmp(
                        BSDoptarg,
                        b"key-plain\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        cp = sshkey_alg_list(
                            0 as libc::c_int,
                            1 as libc::c_int,
                            0 as libc::c_int,
                            '\n' as i32 as libc::c_char,
                        );
                    } else if libc::strcmp(
                        BSDoptarg,
                        b"key-sig\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                        || strcasecmp(
                            BSDoptarg,
                            b"CASignatureAlgorithms\0" as *const u8 as *const libc::c_char,
                        ) == 0 as libc::c_int
                        || strcasecmp(
                            BSDoptarg,
                            b"PubkeyAcceptedKeyTypes\0" as *const u8 as *const libc::c_char,
                        ) == 0 as libc::c_int
                        || strcasecmp(
                            BSDoptarg,
                            b"PubkeyAcceptedAlgorithms\0" as *const u8 as *const libc::c_char,
                        ) == 0 as libc::c_int
                        || strcasecmp(
                            BSDoptarg,
                            b"HostKeyAlgorithms\0" as *const u8 as *const libc::c_char,
                        ) == 0 as libc::c_int
                        || strcasecmp(
                            BSDoptarg,
                            b"HostbasedKeyTypes\0" as *const u8 as *const libc::c_char,
                        ) == 0 as libc::c_int
                        || strcasecmp(
                            BSDoptarg,
                            b"HostbasedAcceptedKeyTypes\0" as *const u8 as *const libc::c_char,
                        ) == 0 as libc::c_int
                        || strcasecmp(
                            BSDoptarg,
                            b"HostbasedAcceptedAlgorithms\0" as *const u8 as *const libc::c_char,
                        ) == 0 as libc::c_int
                    {
                        cp = sshkey_alg_list(
                            0 as libc::c_int,
                            0 as libc::c_int,
                            1 as libc::c_int,
                            '\n' as i32 as libc::c_char,
                        );
                    } else if libc::strcmp(BSDoptarg, b"sig\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                    {
                        cp = sshkey_alg_list(
                            0 as libc::c_int,
                            1 as libc::c_int,
                            1 as libc::c_int,
                            '\n' as i32 as libc::c_char,
                        );
                    } else if libc::strcmp(
                        BSDoptarg,
                        b"protocol-version\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        cp = crate::xmalloc::xstrdup(b"2\0" as *const u8 as *const libc::c_char);
                    } else if libc::strcmp(
                        BSDoptarg,
                        b"compression\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        cp = crate::xmalloc::xstrdup(compression_alg_list(0 as libc::c_int));
                        len = strlen(cp);
                        n = 0 as libc::c_int as size_t;
                        while n < len {
                            if *cp.offset(n as isize) as libc::c_int == ',' as i32 {
                                *cp.offset(n as isize) = '\n' as i32 as libc::c_char;
                            }
                            n = n.wrapping_add(1);
                            n;
                        }
                    } else if libc::strcmp(BSDoptarg, b"help\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                    {
                        cp = crate::xmalloc::xstrdup(
                            b"cipher\ncipher-auth\ncompression\nkex\nkey\nkey-cert\nkey-plain\nkey-sig\nmac\nprotocol-version\nsig\0"
                                as *const u8 as *const libc::c_char,
                        );
                    }
                    if cp.is_null() {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            822 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Unsupported query \"%s\"\0" as *const u8 as *const libc::c_char,
                            BSDoptarg,
                        );
                    }
                    printf(b"%s\n\0" as *const u8 as *const libc::c_char, cp);
                    libc::free(cp as *mut libc::c_void);
                    libc::exit(0 as libc::c_int);
                }
                97 => {
                    options.forward_agent = 0 as libc::c_int;
                }
                65 => {
                    options.forward_agent = 1 as libc::c_int;
                }
                107 => {
                    options.gss_deleg_creds = 0 as libc::c_int;
                }
                75 => {
                    options.gss_authentication = 1 as libc::c_int;
                    options.gss_deleg_creds = 1 as libc::c_int;
                }
                105 => {
                    p = tilde_expand_filename(BSDoptarg, libc::getuid());
                    if libc::stat(p, &mut st) == -(1 as libc::c_int) {
                        libc::fprintf(
                            stderr,
                            b"Warning: Identity file %s not accessible: %s.\n\0" as *const u8
                                as *const libc::c_char,
                            p,
                            libc::strerror(*libc::__errno_location()),
                        );
                    } else {
                        add_identity_file(
                            &mut options,
                            0 as *const libc::c_char,
                            p,
                            1 as libc::c_int,
                        );
                    }
                    libc::free(p as *mut libc::c_void);
                }
                73 => {
                    libc::free(options.pkcs11_provider as *mut libc::c_void);
                    options.pkcs11_provider = crate::xmalloc::xstrdup(BSDoptarg);
                }
                74 => {
                    if !(options.jump_host).is_null() {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<
                                &[u8; 5],
                                &[libc::c_char; 5],
                            >(b"main\0"))
                                .as_ptr(),
                            862 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Only a single -J option is permitted (use commas to separate multiple jump hops)\0"
                                as *const u8 as *const libc::c_char,
                        );
                    }
                    if !(options.proxy_command).is_null() {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            865 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Cannot specify -J with ProxyCommand\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    if parse_jump(BSDoptarg, &mut options, 1 as libc::c_int) == -(1 as libc::c_int)
                    {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            867 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Invalid -J argument\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    options.proxy_command =
                        crate::xmalloc::xstrdup(b"none\0" as *const u8 as *const libc::c_char);
                }
                116 => {
                    if options.request_tty == 2 as libc::c_int {
                        options.request_tty = 3 as libc::c_int;
                    } else {
                        options.request_tty = 2 as libc::c_int;
                    }
                }
                118 => {
                    if debug_flag == 0 as libc::c_int {
                        debug_flag = 1 as libc::c_int;
                        options.log_level = SYSLOG_LEVEL_DEBUG1;
                    } else if (options.log_level as libc::c_int)
                        < SYSLOG_LEVEL_DEBUG3 as libc::c_int
                    {
                        debug_flag += 1;
                        debug_flag;
                        options.log_level += 1;
                        options.log_level;
                    }
                }
                86 => {
                    libc::fprintf(
                        stderr,
                        b"%s, %s\n\0" as *const u8 as *const libc::c_char,
                        b"OpenSSH_9.3p1\0" as *const u8 as *const libc::c_char,
                        OpenSSL_version(0 as libc::c_int),
                    );
                    libc::exit(0 as libc::c_int);
                }
                119 => {
                    if options.tun_open == -(1 as libc::c_int) {
                        options.tun_open = 0x1 as libc::c_int;
                    }
                    options.tun_local = a2tun(BSDoptarg, &mut options.tun_remote);
                    if options.tun_local == 0x7fffffff as libc::c_int - 1 as libc::c_int {
                        libc::fprintf(
                            stderr,
                            b"Bad tun device '%s'\n\0" as *const u8 as *const libc::c_char,
                            BSDoptarg,
                        );
                        libc::exit(255 as libc::c_int);
                    }
                }
                87 => {
                    if !(options.stdio_forward_host).is_null() {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            904 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"stdio forward already specified\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    if muxclient_command != 0 as libc::c_int as libc::c_uint {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            906 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Cannot specify stdio forward with -O\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    if parse_forward(&mut fwd, BSDoptarg, 1 as libc::c_int, 0 as libc::c_int) != 0 {
                        options.stdio_forward_host = fwd.listen_host;
                        options.stdio_forward_port = fwd.listen_port;
                        libc::free(fwd.connect_host as *mut libc::c_void);
                    } else {
                        libc::fprintf(
                            stderr,
                            b"Bad stdio forwarding specification '%s'\n\0" as *const u8
                                as *const libc::c_char,
                            BSDoptarg,
                        );
                        libc::exit(255 as libc::c_int);
                    }
                    options.request_tty = 1 as libc::c_int;
                    options.session_type = 0 as libc::c_int;
                }
                113 => {
                    options.log_level = SYSLOG_LEVEL_QUIET;
                }
                101 => {
                    if *BSDoptarg.offset(0 as libc::c_int as isize) as libc::c_int == '^' as i32
                        && *BSDoptarg.offset(2 as libc::c_int as isize) as libc::c_int
                            == 0 as libc::c_int
                        && *BSDoptarg.offset(1 as libc::c_int as isize) as u_char as libc::c_int
                            >= 64 as libc::c_int
                        && (*BSDoptarg.offset(1 as libc::c_int as isize) as u_char as libc::c_int)
                            < 128 as libc::c_int
                    {
                        options.escape_char = *BSDoptarg.offset(1 as libc::c_int as isize) as u_char
                            as libc::c_int
                            & 31 as libc::c_int;
                    } else if strlen(BSDoptarg) == 1 as libc::c_int as libc::c_ulong {
                        options.escape_char =
                            *BSDoptarg.offset(0 as libc::c_int as isize) as u_char as libc::c_int;
                    } else if libc::strcmp(BSDoptarg, b"none\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                    {
                        options.escape_char = -(2 as libc::c_int);
                    } else {
                        libc::fprintf(
                            stderr,
                            b"Bad escape character '%s'.\n\0" as *const u8 as *const libc::c_char,
                            BSDoptarg,
                        );
                        libc::exit(255 as libc::c_int);
                    }
                }
                99 => {
                    if ciphers_valid(
                        if *BSDoptarg as libc::c_int == '+' as i32
                            || *BSDoptarg as libc::c_int == '^' as i32
                        {
                            BSDoptarg.offset(1 as libc::c_int as isize)
                        } else {
                            BSDoptarg
                        },
                    ) == 0
                    {
                        libc::fprintf(
                            stderr,
                            b"Unknown cipher type '%s'\n\0" as *const u8 as *const libc::c_char,
                            BSDoptarg,
                        );
                        libc::exit(255 as libc::c_int);
                    }
                    libc::free(options.ciphers as *mut libc::c_void);
                    options.ciphers = crate::xmalloc::xstrdup(BSDoptarg);
                }
                109 => {
                    if mac_valid(BSDoptarg) != 0 {
                        libc::free(options.macs as *mut libc::c_void);
                        options.macs = crate::xmalloc::xstrdup(BSDoptarg);
                    } else {
                        libc::fprintf(
                            stderr,
                            b"Unknown mac type '%s'\n\0" as *const u8 as *const libc::c_char,
                            BSDoptarg,
                        );
                        libc::exit(255 as libc::c_int);
                    }
                }
                77 => {
                    if options.control_master == 1 as libc::c_int {
                        options.control_master = 3 as libc::c_int;
                    } else {
                        options.control_master = 1 as libc::c_int;
                    }
                }
                112 => {
                    if options.port == -(1 as libc::c_int) {
                        options.port = crate::misc::a2port(BSDoptarg);
                        if options.port <= 0 as libc::c_int {
                            libc::fprintf(
                                stderr,
                                b"Bad port '%s'\n\0" as *const u8 as *const libc::c_char,
                                BSDoptarg,
                            );
                            libc::exit(255 as libc::c_int);
                        }
                    }
                }
                108 => {
                    if (options.user).is_null() {
                        options.user = BSDoptarg;
                    }
                }
                76 => {
                    if parse_forward(&mut fwd, BSDoptarg, 0 as libc::c_int, 0 as libc::c_int) != 0 {
                        add_local_forward(&mut options, &mut fwd);
                    } else {
                        libc::fprintf(
                            stderr,
                            b"Bad local forwarding specification '%s'\n\0" as *const u8
                                as *const libc::c_char,
                            BSDoptarg,
                        );
                        libc::exit(255 as libc::c_int);
                    }
                }
                82 => {
                    if parse_forward(&mut fwd, BSDoptarg, 0 as libc::c_int, 1 as libc::c_int) != 0
                        || parse_forward(&mut fwd, BSDoptarg, 1 as libc::c_int, 1 as libc::c_int)
                            != 0
                    {
                        add_remote_forward(&mut options, &mut fwd);
                    } else {
                        libc::fprintf(
                            stderr,
                            b"Bad remote forwarding specification '%s'\n\0" as *const u8
                                as *const libc::c_char,
                            BSDoptarg,
                        );
                        libc::exit(255 as libc::c_int);
                    }
                }
                68 => {
                    if parse_forward(&mut fwd, BSDoptarg, 1 as libc::c_int, 0 as libc::c_int) != 0 {
                        add_local_forward(&mut options, &mut fwd);
                    } else {
                        libc::fprintf(
                            stderr,
                            b"Bad dynamic forwarding specification '%s'\n\0" as *const u8
                                as *const libc::c_char,
                            BSDoptarg,
                        );
                        libc::exit(255 as libc::c_int);
                    }
                }
                67 => {
                    options.compression = 1 as libc::c_int;
                }
                78 => {
                    if options.session_type != -(1 as libc::c_int)
                        && options.session_type != 0 as libc::c_int
                    {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1023 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Cannot specify -N with -s/SessionType\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    options.session_type = 0 as libc::c_int;
                    options.request_tty = 1 as libc::c_int;
                }
                84 => {
                    options.request_tty = 1 as libc::c_int;
                }
                111 => {
                    line = crate::xmalloc::xstrdup(BSDoptarg);
                    if process_config_line(
                        &mut options,
                        pw,
                        if !host.is_null() {
                            host as *const libc::c_char
                        } else {
                            b"\0" as *const u8 as *const libc::c_char
                        },
                        if !host.is_null() {
                            host as *const libc::c_char
                        } else {
                            b"\0" as *const u8 as *const libc::c_char
                        },
                        line,
                        b"command-line\0" as *const u8 as *const libc::c_char,
                        0 as libc::c_int,
                        0 as *mut libc::c_int,
                        2 as libc::c_int,
                    ) != 0 as libc::c_int
                    {
                        libc::exit(255 as libc::c_int);
                    }
                    libc::free(line as *mut libc::c_void);
                }
                115 => {
                    if options.session_type != -(1 as libc::c_int)
                        && options.session_type != 1 as libc::c_int
                    {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1041 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Cannot specify -s with -N/SessionType\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    options.session_type = 1 as libc::c_int;
                }
                83 => {
                    libc::free(options.control_path as *mut libc::c_void);
                    options.control_path = crate::xmalloc::xstrdup(BSDoptarg);
                }
                98 => {
                    options.bind_address = BSDoptarg;
                }
                66 => {
                    options.bind_interface = BSDoptarg;
                }
                70 => {
                    config = BSDoptarg;
                }
                _ => {
                    usage();
                }
            }
        }
        if BSDoptind > 1 as libc::c_int
            && libc::strcmp(
                *av.offset((BSDoptind - 1 as libc::c_int) as isize),
                b"--\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            opt_terminated = 1 as libc::c_int;
        }
        ac -= BSDoptind;
        av = av.offset(BSDoptind as isize);
        if !(ac > 0 as libc::c_int && host.is_null()) {
            break;
        }
        let mut tport: libc::c_int = 0;
        let mut tuser: *mut libc::c_char = 0 as *mut libc::c_char;
        match parse_ssh_uri(*av, &mut tuser, &mut host, &mut tport) {
            -1 => {
                usage();
            }
            0 => {
                if (options.user).is_null() {
                    options.user = tuser;
                    tuser = 0 as *mut libc::c_char;
                }
                libc::free(tuser as *mut libc::c_void);
                if options.port == -(1 as libc::c_int) && tport != -(1 as libc::c_int) {
                    options.port = tport;
                }
            }
            _ => {
                p = crate::xmalloc::xstrdup(*av);
                cp = libc::strrchr(p, '@' as i32);
                if !cp.is_null() {
                    if cp == p {
                        usage();
                    }
                    if (options.user).is_null() {
                        options.user = p;
                        p = 0 as *mut libc::c_char;
                    }
                    let fresh3 = cp;
                    cp = cp.offset(1);
                    *fresh3 = '\0' as i32 as libc::c_char;
                    host = crate::xmalloc::xstrdup(cp);
                    libc::free(p as *mut libc::c_void);
                } else {
                    host = p;
                }
            }
        }
        if ac > 1 as libc::c_int && opt_terminated == 0 {
            BSDoptreset = 1 as libc::c_int;
            BSDoptind = BSDoptreset;
        } else {
            ac -= 1;
            ac;
            av = av.offset(1);
            av;
            break;
        }
    }
    if host.is_null() {
        usage();
    }
    options.host_arg = crate::xmalloc::xstrdup(host);
    command = crate::sshbuf::sshbuf_new();
    if command.is_null() {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1116 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    if ac == 0 {
        if options.session_type == 1 as libc::c_int {
            libc::fprintf(
                stderr,
                b"You must specify a subsystem to invoke.\n\0" as *const u8 as *const libc::c_char,
            );
            usage();
        }
    } else {
        i = 0 as libc::c_int;
        while i < ac {
            r = crate::sshbuf_getput_basic::sshbuf_putf(
                command,
                b"%s%s\0" as *const u8 as *const libc::c_char,
                if i != 0 {
                    b" \0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                *av.offset(i as isize),
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1135 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"buffer error\0" as *const u8 as *const libc::c_char,
                );
            }
            i += 1;
            i;
        }
    }
    crate::misc::ssh_signal(
        13 as libc::c_int,
        ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
            1 as libc::c_int as libc::intptr_t,
        ),
    );
    if use_syslog != 0 && !logfile.is_null() {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1146 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Can't specify both -y and -E\0" as *const u8 as *const libc::c_char,
        );
    }
    if !logfile.is_null() {
        log_redirect_stderr_to(logfile);
    }
    log_init(
        argv0,
        (if options.log_level as libc::c_int == SYSLOG_LEVEL_NOT_SET as libc::c_int {
            SYSLOG_LEVEL_INFO as libc::c_int
        } else {
            options.log_level as libc::c_int
        }) as LogLevel,
        (if options.log_facility as libc::c_int == SYSLOG_FACILITY_NOT_SET as libc::c_int {
            SYSLOG_FACILITY_USER as libc::c_int
        } else {
            options.log_facility as libc::c_int
        }) as SyslogFacility,
        (use_syslog == 0) as libc::c_int,
    );
    if debug_flag != 0 {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1157 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%s, %s\0" as *const u8 as *const libc::c_char,
            b"OpenSSH_9.3p1\0" as *const u8 as *const libc::c_char,
            OpenSSL_version(0 as libc::c_int),
        );
    }
    process_config_files(options.host_arg, pw, 0 as libc::c_int, &mut want_final_pass);
    if want_final_pass != 0 {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1162 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"configuration requests final Match pass\0" as *const u8 as *const libc::c_char,
        );
    }
    fill_default_options_for_canonicalization(&mut options);
    if !(options.hostname).is_null() {
        cp = percent_expand(
            options.hostname,
            b"h\0" as *const u8 as *const libc::c_char,
            host,
            0 as *mut libc::c_void as *mut libc::c_char,
        );
        libc::free(host as *mut libc::c_void);
        host = cp;
        libc::free(options.hostname as *mut libc::c_void);
        options.hostname = crate::xmalloc::xstrdup(host);
    }
    was_addr = is_addr(host);
    if was_addr == 0 as libc::c_int {
        lowercase(host);
    }
    if options.canonicalize_hostname != 0 as libc::c_int || was_addr != 0 {
        addrs = resolve_canonicalize(&mut host, options.port);
    }
    direct = (option_clear_or_none(options.proxy_command) != 0
        && option_clear_or_none(options.jump_host) != 0) as libc::c_int;
    if addrs.is_null()
        && config_has_permitted_cnames(&mut options) != 0
        && (direct != 0 || options.canonicalize_hostname == 2 as libc::c_int)
    {
        addrs = resolve_host(
            host,
            options.port,
            direct,
            cname.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
        );
        if addrs.is_null() {
            if direct != 0 {
                cleanup_exit(255 as libc::c_int);
            }
        } else {
            check_follow_cname(direct, &mut host, cname.as_mut_ptr());
        }
    }
    if options.canonicalize_hostname != 0 as libc::c_int && want_final_pass == 0 {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1221 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"hostname canonicalisation enabled, will re-parse configuration\0" as *const u8
                as *const libc::c_char,
        );
        want_final_pass = 1 as libc::c_int;
    }
    if want_final_pass != 0 {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1226 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"re-parsing configuration\0" as *const u8 as *const libc::c_char,
        );
        libc::free(options.hostname as *mut libc::c_void);
        options.hostname = crate::xmalloc::xstrdup(host);
        process_config_files(
            options.host_arg,
            pw,
            1 as libc::c_int,
            0 as *mut libc::c_int,
        );
        if !addrs.is_null() && options.port > 0 as libc::c_int {
            set_addrinfo_port(addrs, options.port);
        }
    }
    if fill_default_options(&mut options) != 0 as libc::c_int {
        cleanup_exit(255 as libc::c_int);
    }
    if (options.user).is_null() {
        options.user = crate::xmalloc::xstrdup((*pw).pw_name);
    }
    if !(options.jump_host).is_null() {
        let mut port_s: [libc::c_char; 8] = [0; 8];
        let mut jumpuser: *const libc::c_char = options.jump_user;
        let mut sshbin: *const libc::c_char = argv0;
        let mut port: libc::c_int = options.port;
        let mut jumpport: libc::c_int = options.jump_port;
        if port <= 0 as libc::c_int {
            port = default_ssh_port();
        }
        if jumpport <= 0 as libc::c_int {
            jumpport = default_ssh_port();
        }
        if jumpuser.is_null() {
            jumpuser = options.user;
        }
        if libc::strcmp(options.jump_host, host) == 0 as libc::c_int
            && port == jumpport
            && libc::strcmp(options.user, jumpuser) == 0 as libc::c_int
        {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1262 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"jumphost loop via %s\0" as *const u8 as *const libc::c_char,
                options.jump_host,
            );
        }
        if !(libc::strchr(argv0, '/' as i32)).is_null()
            && access(argv0, 1 as libc::c_int) != 0 as libc::c_int
        {
            sshbin = b"ssh\0" as *const u8 as *const libc::c_char;
        }
        if !(options.proxy_command).is_null() {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1273 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"inconsistent options: ProxyCommand+ProxyJump\0" as *const u8
                    as *const libc::c_char,
            );
        }
        options.proxy_use_fdpass = 0 as libc::c_int;
        libc::snprintf(
            port_s.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 8]>() as usize,
            b"%d\0" as *const u8 as *const libc::c_char,
            options.jump_port,
        );
        crate::xmalloc::xasprintf(
            &mut options.proxy_command as *mut *mut libc::c_char,
            b"%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s\0" as *const u8 as *const libc::c_char,
            sshbin,
            if (options.jump_user).is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b" -l \0" as *const u8 as *const libc::c_char
            },
            if (options.jump_user).is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                options.jump_user as *const libc::c_char
            },
            if options.jump_port <= 0 as libc::c_int {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b" -p \0" as *const u8 as *const libc::c_char
            },
            if options.jump_port <= 0 as libc::c_int {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                port_s.as_mut_ptr() as *const libc::c_char
            },
            if (options.jump_extra).is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b" -J \0" as *const u8 as *const libc::c_char
            },
            if (options.jump_extra).is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                options.jump_extra as *const libc::c_char
            },
            if config.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b" -F \0" as *const u8 as *const libc::c_char
            },
            if config.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                config as *const libc::c_char
            },
            if debug_flag != 0 {
                b" -\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            debug_flag,
            b"vvv\0" as *const u8 as *const libc::c_char,
            options.jump_host,
        );
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1298 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Setting implicit ProxyCommand from ProxyJump: %s\0" as *const u8
                as *const libc::c_char,
            options.proxy_command,
        );
    }
    if options.port == 0 as libc::c_int {
        options.port = default_ssh_port();
    }
    channel_set_af(ssh, options.address_family);
    if !(options.host_key_alias).is_null() {
        lowercase(options.host_key_alias);
    }
    if !(options.proxy_command).is_null()
        && libc::strcmp(
            options.proxy_command,
            b"-\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        && options.proxy_use_fdpass != 0
    {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1311 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ProxyCommand=- and ProxyUseFDPass are incompatible\0" as *const u8
                as *const libc::c_char,
        );
    }
    if options.update_hostkeys == 2 as libc::c_int {
        if options.control_persist != 0 && !(options.control_path).is_null() {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1315 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"UpdateHostKeys=ask is incompatible with ControlPersist; disabling\0" as *const u8
                    as *const libc::c_char,
            );
            options.update_hostkeys = 0 as libc::c_int;
        } else if crate::sshbuf::sshbuf_len(command) != 0 as libc::c_int as libc::c_ulong
            || !(options.remote_command).is_null()
            || options.request_tty == 1 as libc::c_int
        {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1321 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"UpdateHostKeys=ask is incompatible with remote command execution; disabling\0"
                    as *const u8 as *const libc::c_char,
            );
            options.update_hostkeys = 0 as libc::c_int;
        } else if (options.log_level as libc::c_int) < SYSLOG_LEVEL_INFO as libc::c_int {
            options.update_hostkeys = 0 as libc::c_int;
        }
    }
    if options.connection_attempts <= 0 as libc::c_int {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1329 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Invalid number of ConnectionAttempts\0" as *const u8 as *const libc::c_char,
        );
    }
    if crate::sshbuf::sshbuf_len(command) != 0 as libc::c_int as libc::c_ulong
        && !(options.remote_command).is_null()
    {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1332 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Cannot execute command-line and remote command.\0" as *const u8
                as *const libc::c_char,
        );
    }
    if options.fork_after_authentication != 0
        && crate::sshbuf::sshbuf_len(command) == 0 as libc::c_int as libc::c_ulong
        && (options.remote_command).is_null()
        && options.session_type != 0 as libc::c_int
    {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1339 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Cannot libc::fork into background without a command to execute.\0" as *const u8
                as *const libc::c_char,
        );
    }
    log_init(
        argv0,
        options.log_level,
        options.log_facility,
        (use_syslog == 0) as libc::c_int,
    );
    j = 0 as libc::c_int as u_int;
    while j < options.num_log_verbose {
        if strcasecmp(
            *(options.log_verbose).offset(j as isize),
            b"none\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            break;
        }
        log_verbose_add(*(options.log_verbose).offset(j as isize));
        j = j.wrapping_add(1);
        j;
    }
    if options.request_tty == 2 as libc::c_int || options.request_tty == 3 as libc::c_int {
        tty_flag = 1 as libc::c_int;
    }
    if crate::sshbuf::sshbuf_len(command) == 0 as libc::c_int as libc::c_ulong
        && (options.remote_command).is_null()
    {
        tty_flag = (options.request_tty != 1 as libc::c_int) as libc::c_int;
    }
    if options.request_tty == 1 as libc::c_int
        || muxclient_command != 0 && muxclient_command != 8 as libc::c_int as libc::c_uint
        || options.session_type == 0 as libc::c_int
    {
        tty_flag = 0 as libc::c_int;
    }
    if (isatty(fileno(stdin)) == 0 || options.stdin_null != 0)
        && options.request_tty != 3 as libc::c_int
    {
        if tty_flag != 0 {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1367 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Pseudo-terminal will not be allocated because stdin is not a terminal.\0"
                    as *const u8 as *const libc::c_char,
            );
        }
        tty_flag = 0 as libc::c_int;
    }
    cinfo = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<ssh_conn_info>() as libc::c_ulong,
    ) as *mut ssh_conn_info;
    if gethostname(
        thishost.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1374 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"gethostname: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    (*cinfo).thishost = crate::xmalloc::xstrdup(thishost.as_mut_ptr());
    thishost[strcspn(
        thishost.as_mut_ptr(),
        b".\0" as *const u8 as *const libc::c_char,
    ) as usize] = '\0' as i32 as libc::c_char;
    (*cinfo).shorthost = crate::xmalloc::xstrdup(thishost.as_mut_ptr());
    crate::xmalloc::xasprintf(
        &mut (*cinfo).portstr as *mut *mut libc::c_char,
        b"%d\0" as *const u8 as *const libc::c_char,
        options.port,
    );
    crate::xmalloc::xasprintf(
        &mut (*cinfo).uidstr as *mut *mut libc::c_char,
        b"%llu\0" as *const u8 as *const libc::c_char,
        (*pw).pw_uid as libc::c_ulonglong,
    );
    (*cinfo).keyalias = crate::xmalloc::xstrdup(if !(options.host_key_alias).is_null() {
        options.host_key_alias
    } else {
        options.host_arg
    });
    (*cinfo).conn_hash_hex =
        ssh_connection_hash((*cinfo).thishost, host, (*cinfo).portstr, options.user);
    (*cinfo).host_arg = crate::xmalloc::xstrdup(options.host_arg);
    (*cinfo).remhost = crate::xmalloc::xstrdup(host);
    (*cinfo).remuser = crate::xmalloc::xstrdup(options.user);
    (*cinfo).homedir = crate::xmalloc::xstrdup((*pw).pw_dir);
    (*cinfo).locuser = crate::xmalloc::xstrdup((*pw).pw_name);
    if !(options.remote_command).is_null() {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1397 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"expanding RemoteCommand: %s\0" as *const u8 as *const libc::c_char,
            options.remote_command,
        );
        cp = options.remote_command;
        options.remote_command = default_client_percent_expand(cp, cinfo);
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1401 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"expanded RemoteCommand: %s\0" as *const u8 as *const libc::c_char,
            options.remote_command,
        );
        libc::free(cp as *mut libc::c_void);
        r = sshbuf_put(
            command,
            options.remote_command as *const libc::c_void,
            strlen(options.remote_command),
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1405 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"buffer error\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if !(options.control_path).is_null() {
        cp = tilde_expand_filename(options.control_path, libc::getuid());
        libc::free(options.control_path as *mut libc::c_void);
        options.control_path = default_client_percent_dollar_expand(cp, cinfo);
        libc::free(cp as *mut libc::c_void);
    }
    if !(options.identity_agent).is_null() {
        p = tilde_expand_filename(options.identity_agent, libc::getuid());
        cp = default_client_percent_dollar_expand(p, cinfo);
        libc::free(p as *mut libc::c_void);
        libc::free(options.identity_agent as *mut libc::c_void);
        options.identity_agent = cp;
    }
    if !(options.revoked_host_keys).is_null() {
        p = tilde_expand_filename(options.revoked_host_keys, libc::getuid());
        cp = default_client_percent_dollar_expand(p, cinfo);
        libc::free(p as *mut libc::c_void);
        libc::free(options.revoked_host_keys as *mut libc::c_void);
        options.revoked_host_keys = cp;
    }
    if !(options.forward_agent_sock_path).is_null() {
        p = tilde_expand_filename(options.forward_agent_sock_path, libc::getuid());
        cp = default_client_percent_dollar_expand(p, cinfo);
        libc::free(p as *mut libc::c_void);
        libc::free(options.forward_agent_sock_path as *mut libc::c_void);
        options.forward_agent_sock_path = cp;
        if libc::stat(options.forward_agent_sock_path, &mut st) != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1441 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Cannot forward agent socket path \"%s\": %s\0" as *const u8
                    as *const libc::c_char,
                options.forward_agent_sock_path,
                libc::strerror(*libc::__errno_location()),
            );
            if options.exit_on_forward_failure != 0 {
                cleanup_exit(255 as libc::c_int);
            }
        }
    }
    if options.num_system_hostfiles > 0 as libc::c_int as libc::c_uint
        && strcasecmp(
            options.system_hostfiles[0 as libc::c_int as usize],
            b"none\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
    {
        if options.num_system_hostfiles > 1 as libc::c_int as libc::c_uint {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1451 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Invalid GlobalKnownHostsFiles: \"none\" appears with other entries\0" as *const u8
                    as *const libc::c_char,
            );
        }
        libc::free(options.system_hostfiles[0 as libc::c_int as usize] as *mut libc::c_void);
        options.system_hostfiles[0 as libc::c_int as usize] = 0 as *mut libc::c_char;
        options.num_system_hostfiles = 0 as libc::c_int as u_int;
    }
    if options.num_user_hostfiles > 0 as libc::c_int as libc::c_uint
        && strcasecmp(
            options.user_hostfiles[0 as libc::c_int as usize],
            b"none\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
    {
        if options.num_user_hostfiles > 1 as libc::c_int as libc::c_uint {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1461 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Invalid UserKnownHostsFiles: \"none\" appears with other entries\0" as *const u8
                    as *const libc::c_char,
            );
        }
        libc::free(options.user_hostfiles[0 as libc::c_int as usize] as *mut libc::c_void);
        options.user_hostfiles[0 as libc::c_int as usize] = 0 as *mut libc::c_char;
        options.num_user_hostfiles = 0 as libc::c_int as u_int;
    }
    j = 0 as libc::c_int as u_int;
    while j < options.num_user_hostfiles {
        if !(options.user_hostfiles[j as usize]).is_null() {
            cp = tilde_expand_filename(options.user_hostfiles[j as usize], libc::getuid());
            p = default_client_percent_dollar_expand(cp, cinfo);
            if libc::strcmp(options.user_hostfiles[j as usize], p) != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1473 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"expanded UserKnownHostsFile '%s' -> '%s'\0" as *const u8
                        as *const libc::c_char,
                    options.user_hostfiles[j as usize],
                    p,
                );
            }
            libc::free(options.user_hostfiles[j as usize] as *mut libc::c_void);
            libc::free(cp as *mut libc::c_void);
            options.user_hostfiles[j as usize] = p;
        }
        j = j.wrapping_add(1);
        j;
    }
    i = 0 as libc::c_int;
    while i < options.num_local_forwards {
        if !((*(options.local_forwards).offset(i as isize)).listen_path).is_null() {
            cp = (*(options.local_forwards).offset(i as isize)).listen_path;
            let ref mut fresh4 = (*(options.local_forwards).offset(i as isize)).listen_path;
            *fresh4 = default_client_percent_expand(cp, cinfo);
            p = *fresh4;
            if libc::strcmp(cp, p) != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1486 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"expanded LocalForward listen path '%s' -> '%s'\0" as *const u8
                        as *const libc::c_char,
                    cp,
                    p,
                );
            }
            libc::free(cp as *mut libc::c_void);
        }
        if !((*(options.local_forwards).offset(i as isize)).connect_path).is_null() {
            cp = (*(options.local_forwards).offset(i as isize)).connect_path;
            let ref mut fresh5 = (*(options.local_forwards).offset(i as isize)).connect_path;
            *fresh5 = default_client_percent_expand(cp, cinfo);
            p = *fresh5;
            if libc::strcmp(cp, p) != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1495 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"expanded LocalForward connect path '%s' -> '%s'\0" as *const u8
                        as *const libc::c_char,
                    cp,
                    p,
                );
            }
            libc::free(cp as *mut libc::c_void);
        }
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < options.num_remote_forwards {
        if !((*(options.remote_forwards).offset(i as isize)).listen_path).is_null() {
            cp = (*(options.remote_forwards).offset(i as isize)).listen_path;
            let ref mut fresh6 = (*(options.remote_forwards).offset(i as isize)).listen_path;
            *fresh6 = default_client_percent_expand(cp, cinfo);
            p = *fresh6;
            if libc::strcmp(cp, p) != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1507 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"expanded RemoteForward listen path '%s' -> '%s'\0" as *const u8
                        as *const libc::c_char,
                    cp,
                    p,
                );
            }
            libc::free(cp as *mut libc::c_void);
        }
        if !((*(options.remote_forwards).offset(i as isize)).connect_path).is_null() {
            cp = (*(options.remote_forwards).offset(i as isize)).connect_path;
            let ref mut fresh7 = (*(options.remote_forwards).offset(i as isize)).connect_path;
            *fresh7 = default_client_percent_expand(cp, cinfo);
            p = *fresh7;
            if libc::strcmp(cp, p) != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1516 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"expanded RemoteForward connect path '%s' -> '%s'\0" as *const u8
                        as *const libc::c_char,
                    cp,
                    p,
                );
            }
            libc::free(cp as *mut libc::c_void);
        }
        i += 1;
        i;
    }
    if config_test != 0 {
        dump_client_config(&mut options, host);
        libc::exit(0 as libc::c_int);
    }
    if !(options.sk_provider).is_null()
        && *options.sk_provider as libc::c_int == '$' as i32
        && strlen(options.sk_provider) > 1 as libc::c_int as libc::c_ulong
    {
        cp = getenv((options.sk_provider).offset(1 as libc::c_int as isize));
        if cp.is_null() {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1531 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Authenticator provider %s did not resolve; disabling\0" as *const u8
                    as *const libc::c_char,
                options.sk_provider,
            );
            libc::free(options.sk_provider as *mut libc::c_void);
            options.sk_provider = 0 as *mut libc::c_char;
        } else {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1536 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"resolved SecurityKeyProvider %s => %s\0" as *const u8 as *const libc::c_char,
                options.sk_provider,
                cp,
            );
            libc::free(options.sk_provider as *mut libc::c_void);
            options.sk_provider = crate::xmalloc::xstrdup(cp);
        }
    }
    if muxclient_command != 0 as libc::c_int as libc::c_uint && (options.control_path).is_null() {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1543 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"No ControlPath specified for \"-O\" command\0" as *const u8 as *const libc::c_char,
        );
    }
    if !(options.control_path).is_null() {
        let mut sock: libc::c_int = 0;
        sock = muxclient(options.control_path);
        if sock >= 0 as libc::c_int {
            ssh_packet_set_connection(ssh, sock, sock);
            ssh_packet_set_mux(ssh);
            current_block = 13231702199404586646;
        } else {
            current_block = 10800801741953260091;
        }
    } else {
        current_block = 10800801741953260091;
    }
    match current_block {
        10800801741953260091 => {
            if addrs.is_null() && (options.proxy_command).is_null() {
                crate::log::sshlog(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1558 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"resolving \"%s\" port %d\0" as *const u8 as *const libc::c_char,
                    host,
                    options.port,
                );
                addrs = resolve_host(
                    host,
                    options.port,
                    1 as libc::c_int,
                    cname.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
                );
                if addrs.is_null() {
                    cleanup_exit(255 as libc::c_int);
                }
            }
            if options.connection_timeout >= 2147483647 as libc::c_int / 1000 as libc::c_int {
                timeout_ms = 2147483647 as libc::c_int;
            } else {
                timeout_ms = options.connection_timeout * 1000 as libc::c_int;
            }
            if ssh_connect(
                ssh,
                host,
                options.host_arg,
                addrs,
                &mut hostaddr,
                options.port as u_short,
                options.connection_attempts,
                &mut timeout_ms,
                options.tcp_keep_alive,
            ) != 0 as libc::c_int
            {
                libc::exit(255 as libc::c_int);
            }
            if !addrs.is_null() {
                freeaddrinfo(addrs);
            }
            ssh_packet_set_timeout(
                ssh,
                options.server_alive_interval,
                options.server_alive_count_max,
            );
            if timeout_ms > 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1582 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"timeout: %d ms remain after connect\0" as *const u8 as *const libc::c_char,
                    timeout_ms,
                );
            }
            sensitive_data.nkeys = 0 as libc::c_int;
            sensitive_data.keys = 0 as *mut *mut crate::sshkey::sshkey;
            if options.hostbased_authentication != 0 {
                let mut loaded: libc::c_int = 0 as libc::c_int;
                sensitive_data.nkeys = 10 as libc::c_int;
                sensitive_data.keys = crate::xmalloc::xcalloc(
                    sensitive_data.nkeys as size_t,
                    ::core::mem::size_of::<*mut crate::sshkey::sshkey>() as libc::c_ulong,
                ) as *mut *mut crate::sshkey::sshkey;
                if options.hostbased_authentication == 1 as libc::c_int {
                    if 0 as libc::c_int >= sensitive_data.nkeys {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1623 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"cert out of array bounds\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    check_load(
                        sshkey_load_cert(
                            b"/usr/local/etc/ssh_host_ecdsa_key\0" as *const u8
                                as *const libc::c_char,
                            &mut *(sensitive_data.keys).offset(0 as libc::c_int as isize),
                        ),
                        &mut *(sensitive_data.keys).offset(0 as libc::c_int as isize),
                        b"/usr/local/etc/ssh_host_ecdsa_key\0" as *const u8 as *const libc::c_char,
                        b"cert\0" as *const u8 as *const libc::c_char,
                    );
                    if !(*(sensitive_data.keys).offset(0 as libc::c_int as isize)).is_null() {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1623 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"hostbased key %d: %s cert from \"%s\"\0" as *const u8
                                as *const libc::c_char,
                            0 as libc::c_int,
                            sshkey_ssh_name(
                                *(sensitive_data.keys).offset(0 as libc::c_int as isize),
                            ),
                            b"/usr/local/etc/ssh_host_ecdsa_key\0" as *const u8
                                as *const libc::c_char,
                        );
                        loaded += 1;
                        loaded;
                    }
                    if 1 as libc::c_int >= sensitive_data.nkeys {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1624 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"cert out of array bounds\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    check_load(
                        sshkey_load_cert(
                            b"/usr/local/etc/ssh_host_ed25519_key\0" as *const u8
                                as *const libc::c_char,
                            &mut *(sensitive_data.keys).offset(1 as libc::c_int as isize),
                        ),
                        &mut *(sensitive_data.keys).offset(1 as libc::c_int as isize),
                        b"/usr/local/etc/ssh_host_ed25519_key\0" as *const u8
                            as *const libc::c_char,
                        b"cert\0" as *const u8 as *const libc::c_char,
                    );
                    if !(*(sensitive_data.keys).offset(1 as libc::c_int as isize)).is_null() {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1624 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"hostbased key %d: %s cert from \"%s\"\0" as *const u8
                                as *const libc::c_char,
                            1 as libc::c_int,
                            sshkey_ssh_name(
                                *(sensitive_data.keys).offset(1 as libc::c_int as isize),
                            ),
                            b"/usr/local/etc/ssh_host_ed25519_key\0" as *const u8
                                as *const libc::c_char,
                        );
                        loaded += 1;
                        loaded;
                    }
                    if 2 as libc::c_int >= sensitive_data.nkeys {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1625 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"cert out of array bounds\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    check_load(
                        sshkey_load_cert(
                            b"/usr/local/etc/ssh_host_rsa_key\0" as *const u8
                                as *const libc::c_char,
                            &mut *(sensitive_data.keys).offset(2 as libc::c_int as isize),
                        ),
                        &mut *(sensitive_data.keys).offset(2 as libc::c_int as isize),
                        b"/usr/local/etc/ssh_host_rsa_key\0" as *const u8 as *const libc::c_char,
                        b"cert\0" as *const u8 as *const libc::c_char,
                    );
                    if !(*(sensitive_data.keys).offset(2 as libc::c_int as isize)).is_null() {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1625 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"hostbased key %d: %s cert from \"%s\"\0" as *const u8
                                as *const libc::c_char,
                            2 as libc::c_int,
                            sshkey_ssh_name(
                                *(sensitive_data.keys).offset(2 as libc::c_int as isize),
                            ),
                            b"/usr/local/etc/ssh_host_rsa_key\0" as *const u8
                                as *const libc::c_char,
                        );
                        loaded += 1;
                        loaded;
                    }
                    if 3 as libc::c_int >= sensitive_data.nkeys {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1626 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"cert out of array bounds\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    check_load(
                        sshkey_load_cert(
                            b"/usr/local/etc/ssh_host_dsa_key\0" as *const u8
                                as *const libc::c_char,
                            &mut *(sensitive_data.keys).offset(3 as libc::c_int as isize),
                        ),
                        &mut *(sensitive_data.keys).offset(3 as libc::c_int as isize),
                        b"/usr/local/etc/ssh_host_dsa_key\0" as *const u8 as *const libc::c_char,
                        b"cert\0" as *const u8 as *const libc::c_char,
                    );
                    if !(*(sensitive_data.keys).offset(3 as libc::c_int as isize)).is_null() {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1626 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"hostbased key %d: %s cert from \"%s\"\0" as *const u8
                                as *const libc::c_char,
                            3 as libc::c_int,
                            sshkey_ssh_name(
                                *(sensitive_data.keys).offset(3 as libc::c_int as isize),
                            ),
                            b"/usr/local/etc/ssh_host_dsa_key\0" as *const u8
                                as *const libc::c_char,
                        );
                        loaded += 1;
                        loaded;
                    }
                    if 4 as libc::c_int >= sensitive_data.nkeys {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1627 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"pubkey out of array bounds\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    check_load(
                        sshkey_load_public(
                            b"/usr/local/etc/ssh_host_ecdsa_key\0" as *const u8
                                as *const libc::c_char,
                            &mut *(sensitive_data.keys).offset(4 as libc::c_int as isize),
                            0 as *mut *mut libc::c_char,
                        ),
                        &mut *(sensitive_data.keys).offset(4 as libc::c_int as isize),
                        b"/usr/local/etc/ssh_host_ecdsa_key\0" as *const u8 as *const libc::c_char,
                        b"pubkey\0" as *const u8 as *const libc::c_char,
                    );
                    if !(*(sensitive_data.keys).offset(4 as libc::c_int as isize)).is_null() {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1627 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"hostbased key %d: %s key from \"%s\"\0" as *const u8
                                as *const libc::c_char,
                            4 as libc::c_int,
                            sshkey_ssh_name(
                                *(sensitive_data.keys).offset(4 as libc::c_int as isize),
                            ),
                            b"/usr/local/etc/ssh_host_ecdsa_key\0" as *const u8
                                as *const libc::c_char,
                        );
                        loaded += 1;
                        loaded;
                    }
                    if 5 as libc::c_int >= sensitive_data.nkeys {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1628 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"pubkey out of array bounds\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    check_load(
                        sshkey_load_public(
                            b"/usr/local/etc/ssh_host_ed25519_key\0" as *const u8
                                as *const libc::c_char,
                            &mut *(sensitive_data.keys).offset(5 as libc::c_int as isize),
                            0 as *mut *mut libc::c_char,
                        ),
                        &mut *(sensitive_data.keys).offset(5 as libc::c_int as isize),
                        b"/usr/local/etc/ssh_host_ed25519_key\0" as *const u8
                            as *const libc::c_char,
                        b"pubkey\0" as *const u8 as *const libc::c_char,
                    );
                    if !(*(sensitive_data.keys).offset(5 as libc::c_int as isize)).is_null() {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1628 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"hostbased key %d: %s key from \"%s\"\0" as *const u8
                                as *const libc::c_char,
                            5 as libc::c_int,
                            sshkey_ssh_name(
                                *(sensitive_data.keys).offset(5 as libc::c_int as isize),
                            ),
                            b"/usr/local/etc/ssh_host_ed25519_key\0" as *const u8
                                as *const libc::c_char,
                        );
                        loaded += 1;
                        loaded;
                    }
                    if 6 as libc::c_int >= sensitive_data.nkeys {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1629 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"pubkey out of array bounds\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    check_load(
                        sshkey_load_public(
                            b"/usr/local/etc/ssh_host_rsa_key\0" as *const u8
                                as *const libc::c_char,
                            &mut *(sensitive_data.keys).offset(6 as libc::c_int as isize),
                            0 as *mut *mut libc::c_char,
                        ),
                        &mut *(sensitive_data.keys).offset(6 as libc::c_int as isize),
                        b"/usr/local/etc/ssh_host_rsa_key\0" as *const u8 as *const libc::c_char,
                        b"pubkey\0" as *const u8 as *const libc::c_char,
                    );
                    if !(*(sensitive_data.keys).offset(6 as libc::c_int as isize)).is_null() {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1629 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"hostbased key %d: %s key from \"%s\"\0" as *const u8
                                as *const libc::c_char,
                            6 as libc::c_int,
                            sshkey_ssh_name(
                                *(sensitive_data.keys).offset(6 as libc::c_int as isize),
                            ),
                            b"/usr/local/etc/ssh_host_rsa_key\0" as *const u8
                                as *const libc::c_char,
                        );
                        loaded += 1;
                        loaded;
                    }
                    if 7 as libc::c_int >= sensitive_data.nkeys {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1630 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"pubkey out of array bounds\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    check_load(
                        sshkey_load_public(
                            b"/usr/local/etc/ssh_host_dsa_key\0" as *const u8
                                as *const libc::c_char,
                            &mut *(sensitive_data.keys).offset(7 as libc::c_int as isize),
                            0 as *mut *mut libc::c_char,
                        ),
                        &mut *(sensitive_data.keys).offset(7 as libc::c_int as isize),
                        b"/usr/local/etc/ssh_host_dsa_key\0" as *const u8 as *const libc::c_char,
                        b"pubkey\0" as *const u8 as *const libc::c_char,
                    );
                    if !(*(sensitive_data.keys).offset(7 as libc::c_int as isize)).is_null() {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1630 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"hostbased key %d: %s key from \"%s\"\0" as *const u8
                                as *const libc::c_char,
                            7 as libc::c_int,
                            sshkey_ssh_name(
                                *(sensitive_data.keys).offset(7 as libc::c_int as isize),
                            ),
                            b"/usr/local/etc/ssh_host_dsa_key\0" as *const u8
                                as *const libc::c_char,
                        );
                        loaded += 1;
                        loaded;
                    }
                    if 8 as libc::c_int >= sensitive_data.nkeys {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1631 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"cert out of array bounds\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    check_load(
                        sshkey_load_cert(
                            b"/usr/local/etc/ssh_host_xmss_key\0" as *const u8
                                as *const libc::c_char,
                            &mut *(sensitive_data.keys).offset(8 as libc::c_int as isize),
                        ),
                        &mut *(sensitive_data.keys).offset(8 as libc::c_int as isize),
                        b"/usr/local/etc/ssh_host_xmss_key\0" as *const u8 as *const libc::c_char,
                        b"cert\0" as *const u8 as *const libc::c_char,
                    );
                    if !(*(sensitive_data.keys).offset(8 as libc::c_int as isize)).is_null() {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1631 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"hostbased key %d: %s cert from \"%s\"\0" as *const u8
                                as *const libc::c_char,
                            8 as libc::c_int,
                            sshkey_ssh_name(
                                *(sensitive_data.keys).offset(8 as libc::c_int as isize),
                            ),
                            b"/usr/local/etc/ssh_host_xmss_key\0" as *const u8
                                as *const libc::c_char,
                        );
                        loaded += 1;
                        loaded;
                    }
                    if 9 as libc::c_int >= sensitive_data.nkeys {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1632 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"pubkey out of array bounds\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    check_load(
                        sshkey_load_public(
                            b"/usr/local/etc/ssh_host_xmss_key\0" as *const u8
                                as *const libc::c_char,
                            &mut *(sensitive_data.keys).offset(9 as libc::c_int as isize),
                            0 as *mut *mut libc::c_char,
                        ),
                        &mut *(sensitive_data.keys).offset(9 as libc::c_int as isize),
                        b"/usr/local/etc/ssh_host_xmss_key\0" as *const u8 as *const libc::c_char,
                        b"pubkey\0" as *const u8 as *const libc::c_char,
                    );
                    if !(*(sensitive_data.keys).offset(9 as libc::c_int as isize)).is_null() {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1632 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"hostbased key %d: %s key from \"%s\"\0" as *const u8
                                as *const libc::c_char,
                            9 as libc::c_int,
                            sshkey_ssh_name(
                                *(sensitive_data.keys).offset(9 as libc::c_int as isize),
                            ),
                            b"/usr/local/etc/ssh_host_xmss_key\0" as *const u8
                                as *const libc::c_char,
                        );
                        loaded += 1;
                        loaded;
                    }
                    if loaded == 0 as libc::c_int {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<
                                &[u8; 5],
                                &[libc::c_char; 5],
                            >(b"main\0"))
                                .as_ptr(),
                            1635 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"HostbasedAuthentication enabled but no local public host keys could be loaded.\0"
                                as *const u8 as *const libc::c_char,
                        );
                    }
                }
            }
            load_public_identity_files(cinfo);
            if !(options.identity_agent).is_null()
                && libc::strcmp(
                    options.identity_agent,
                    b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char,
                ) != 0 as libc::c_int
            {
                if libc::strcmp(
                    options.identity_agent,
                    b"none\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
                {
                    unsetenv(b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char);
                } else {
                    cp = options.identity_agent;
                    if *cp.offset(0 as libc::c_int as isize) as libc::c_int == '$' as i32
                        && *cp.offset(1 as libc::c_int as isize) as libc::c_int != '{' as i32
                    {
                        if valid_env_name(cp.offset(1 as libc::c_int as isize)) == 0 {
                            sshfatal(
                                b"ssh.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(
                                    b"main\0",
                                ))
                                .as_ptr(),
                                1653 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                0 as *const libc::c_char,
                                b"Invalid IdentityAgent environment variable name %s\0" as *const u8
                                    as *const libc::c_char,
                                cp,
                            );
                        }
                        p = getenv(cp.offset(1 as libc::c_int as isize));
                        if p.is_null() {
                            unsetenv(b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char);
                        } else {
                            setenv(
                                b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char,
                                p,
                                1 as libc::c_int,
                            );
                        }
                    } else {
                        setenv(
                            b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char,
                            cp,
                            1 as libc::c_int,
                        );
                    }
                }
            }
            if options.forward_agent != 0 && !(options.forward_agent_sock_path).is_null() {
                cp = options.forward_agent_sock_path;
                if *cp.offset(0 as libc::c_int as isize) as libc::c_int == '$' as i32 {
                    if valid_env_name(cp.offset(1 as libc::c_int as isize)) == 0 {
                        sshfatal(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1670 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Invalid ForwardAgent environment variable name %s\0" as *const u8
                                as *const libc::c_char,
                            cp,
                        );
                    }
                    p = getenv(cp.offset(1 as libc::c_int as isize));
                    if !p.is_null() {
                        forward_agent_sock_path = crate::xmalloc::xstrdup(p);
                    } else {
                        options.forward_agent = 0 as libc::c_int;
                    }
                    libc::free(cp as *mut libc::c_void);
                } else {
                    forward_agent_sock_path = cp;
                }
            }
            tilde_expand_paths(
                (options.system_hostfiles).as_mut_ptr(),
                options.num_system_hostfiles,
            );
            tilde_expand_paths(
                (options.user_hostfiles).as_mut_ptr(),
                options.num_user_hostfiles,
            );
            crate::misc::ssh_signal(
                17 as libc::c_int,
                Some(main_sigchld_handler as unsafe extern "C" fn(libc::c_int) -> ()),
            );
            ssh_login(
                ssh,
                &mut sensitive_data,
                host,
                &mut hostaddr as *mut sockaddr_storage as *mut sockaddr,
                options.port as u_short,
                pw,
                timeout_ms,
                cinfo,
            );
            if sensitive_data.nkeys != 0 as libc::c_int {
                i = 0 as libc::c_int;
                while i < sensitive_data.nkeys {
                    if !(*(sensitive_data.keys).offset(i as isize)).is_null() {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1698 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG3,
                            0 as *const libc::c_char,
                            b"clear hostkey %d\0" as *const u8 as *const libc::c_char,
                            i,
                        );
                        crate::sshkey::sshkey_free(*(sensitive_data.keys).offset(i as isize));
                        let ref mut fresh8 = *(sensitive_data.keys).offset(i as isize);
                        *fresh8 = 0 as *mut crate::sshkey::sshkey;
                    }
                    i += 1;
                    i;
                }
                libc::free(sensitive_data.keys as *mut libc::c_void);
            }
            i = 0 as libc::c_int;
            while i < options.num_identity_files {
                libc::free(options.identity_files[i as usize] as *mut libc::c_void);
                options.identity_files[i as usize] = 0 as *mut libc::c_char;
                if !(options.identity_keys[i as usize]).is_null() {
                    crate::sshkey::sshkey_free(options.identity_keys[i as usize]);
                    options.identity_keys[i as usize] = 0 as *mut crate::sshkey::sshkey;
                }
                i += 1;
                i;
            }
            i = 0 as libc::c_int;
            while i < options.num_certificate_files {
                libc::free(options.certificate_files[i as usize] as *mut libc::c_void);
                options.certificate_files[i as usize] = 0 as *mut libc::c_char;
                i += 1;
                i;
            }
            pkcs11_del_provider(options.pkcs11_provider);
        }
        _ => {}
    }
    exit_status = ssh_session2(ssh, cinfo);
    ssh_conn_info_free(cinfo);
    ssh_packet_close(ssh);
    if !(options.control_path).is_null() && muxserver_sock != -(1 as libc::c_int) {
        unlink(options.control_path);
    }
    ssh_kill_proxy_command();
    return exit_status;
}
unsafe extern "C" fn control_persist_detach() {
    let mut pid: pid_t = 0;
    crate::log::sshlog(
        b"ssh.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"control_persist_detach\0"))
            .as_ptr(),
        1741 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"backgrounding master process\0" as *const u8 as *const libc::c_char,
    );
    pid = libc::fork();
    match pid {
        -1 => {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"control_persist_detach\0",
                ))
                .as_ptr(),
                1749 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"libc::fork: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        0 => {}
        _ => {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"control_persist_detach\0",
                ))
                .as_ptr(),
                1755 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"background process is %ld\0" as *const u8 as *const libc::c_char,
                pid as libc::c_long,
            );
            options.stdin_null = ostdin_null_flag;
            options.request_tty = orequest_tty;
            tty_flag = otty_flag;
            options.session_type = osession_type;
            close(muxserver_sock);
            muxserver_sock = -(1 as libc::c_int);
            options.control_master = 0 as libc::c_int;
            muxclient(options.control_path);
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"control_persist_detach\0",
                ))
                .as_ptr(),
                1765 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Failed to connect to new control master\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if stdfd_devnull(
        1 as libc::c_int,
        1 as libc::c_int,
        !(log_is_on_stderr() != 0 && debug_flag != 0) as libc::c_int,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"control_persist_detach\0",
            ))
            .as_ptr(),
            1768 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"stdfd_devnull failed\0" as *const u8 as *const libc::c_char,
        );
    }
    daemon(1 as libc::c_int, 1 as libc::c_int);
    setproctitle(
        b"%s [mux]\0" as *const u8 as *const libc::c_char,
        options.control_path,
    );
}
unsafe extern "C" fn fork_postauth() {
    if need_controlpersist_detach != 0 {
        control_persist_detach();
    }
    crate::log::sshlog(
        b"ssh.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"fork_postauth\0")).as_ptr(),
        1779 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"forking to background\0" as *const u8 as *const libc::c_char,
    );
    options.fork_after_authentication = 0 as libc::c_int;
    if daemon(1 as libc::c_int, 1 as libc::c_int) == -(1 as libc::c_int) {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"fork_postauth\0"))
                .as_ptr(),
            1782 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"daemon() failed: %.200s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    if stdfd_devnull(
        1 as libc::c_int,
        1 as libc::c_int,
        !(log_is_on_stderr() != 0 && debug_flag != 0) as libc::c_int,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"fork_postauth\0"))
                .as_ptr(),
            1784 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"stdfd_devnull failed\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn forwarding_success() {
    if forward_confirms_pending == -(1 as libc::c_int) {
        return;
    }
    forward_confirms_pending -= 1;
    if forward_confirms_pending == 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"forwarding_success\0"))
                .as_ptr(),
            1793 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"all expected forwarding replies received\0" as *const u8 as *const libc::c_char,
        );
        if options.fork_after_authentication != 0 {
            fork_postauth();
        }
    } else {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"forwarding_success\0"))
                .as_ptr(),
            1798 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"%d expected forwarding replies remaining\0" as *const u8 as *const libc::c_char,
            forward_confirms_pending,
        );
    };
}
unsafe extern "C" fn ssh_confirm_remote_forward(
    mut ssh: *mut ssh,
    mut type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ctxt: *mut libc::c_void,
) {
    let mut rfwd: *mut Forward = ctxt as *mut Forward;
    let mut port: u_int = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"ssh.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"ssh_confirm_remote_forward\0",
        ))
        .as_ptr(),
        1817 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"remote forward %s for: listen %s%s%d, connect %s:%d\0" as *const u8
            as *const libc::c_char,
        if type_0 == 81 as libc::c_int {
            b"success\0" as *const u8 as *const libc::c_char
        } else {
            b"failure\0" as *const u8 as *const libc::c_char
        },
        if !((*rfwd).listen_path).is_null() {
            (*rfwd).listen_path as *const libc::c_char
        } else if !((*rfwd).listen_host).is_null() {
            (*rfwd).listen_host as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*rfwd).listen_path).is_null() || !((*rfwd).listen_host).is_null() {
            b":\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        (*rfwd).listen_port,
        if !((*rfwd).connect_path).is_null() {
            (*rfwd).connect_path
        } else {
            (*rfwd).connect_host
        },
        (*rfwd).connect_port,
    );
    if ((*rfwd).listen_path).is_null() && (*rfwd).listen_port == 0 as libc::c_int {
        if type_0 == 81 as libc::c_int {
            r = sshpkt_get_u32(ssh, &mut port);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"ssh_confirm_remote_forward\0",
                    ))
                    .as_ptr(),
                    1821 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse packet\0" as *const u8 as *const libc::c_char,
                );
            }
            if port > 65535 as libc::c_int as libc::c_uint {
                crate::log::sshlog(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"ssh_confirm_remote_forward\0",
                    ))
                    .as_ptr(),
                    1825 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Invalid allocated port %u for remote forward to %s:%d\0" as *const u8
                        as *const libc::c_char,
                    port,
                    (*rfwd).connect_host,
                    (*rfwd).connect_port,
                );
                type_0 = 82 as libc::c_int;
                channel_update_permission(ssh, (*rfwd).handle, -(1 as libc::c_int));
            } else {
                (*rfwd).allocated_port = port as libc::c_int;
                crate::log::sshlog(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"ssh_confirm_remote_forward\0",
                    ))
                    .as_ptr(),
                    1836 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"Allocated port %u for remote forward to %s:%d\0" as *const u8
                        as *const libc::c_char,
                    (*rfwd).allocated_port,
                    if !((*rfwd).connect_path).is_null() {
                        (*rfwd).connect_path
                    } else {
                        (*rfwd).connect_host
                    },
                    (*rfwd).connect_port,
                );
                channel_update_permission(ssh, (*rfwd).handle, (*rfwd).allocated_port);
            }
        } else {
            channel_update_permission(ssh, (*rfwd).handle, -(1 as libc::c_int));
        }
    }
    if type_0 == 82 as libc::c_int {
        if options.exit_on_forward_failure != 0 {
            if !((*rfwd).listen_path).is_null() {
                sshfatal(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"ssh_confirm_remote_forward\0",
                    ))
                    .as_ptr(),
                    1849 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Error: remote port forwarding failed for listen path %s\0" as *const u8
                        as *const libc::c_char,
                    (*rfwd).listen_path,
                );
            } else {
                sshfatal(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"ssh_confirm_remote_forward\0",
                    ))
                    .as_ptr(),
                    1852 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Error: remote port forwarding failed for listen port %d\0" as *const u8
                        as *const libc::c_char,
                    (*rfwd).listen_port,
                );
            }
        } else if !((*rfwd).listen_path).is_null() {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"ssh_confirm_remote_forward\0",
                ))
                .as_ptr(),
                1856 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Warning: remote port forwarding failed for listen path %s\0" as *const u8
                    as *const libc::c_char,
                (*rfwd).listen_path,
            );
        } else {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"ssh_confirm_remote_forward\0",
                ))
                .as_ptr(),
                1859 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Warning: remote port forwarding failed for listen port %d\0" as *const u8
                    as *const libc::c_char,
                (*rfwd).listen_port,
            );
        }
    }
    forwarding_success();
}
unsafe extern "C" fn client_cleanup_stdio_fwd(
    mut _ssh: *mut ssh,
    mut _id: libc::c_int,
    mut _force: libc::c_int,
    mut _arg: *mut libc::c_void,
) {
    crate::log::sshlog(
        b"ssh.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"client_cleanup_stdio_fwd\0"))
            .as_ptr(),
        1868 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"stdio forwarding: done\0" as *const u8 as *const libc::c_char,
    );
    cleanup_exit(0 as libc::c_int);
}
unsafe extern "C" fn ssh_stdio_confirm(
    mut _ssh: *mut ssh,
    mut _id: libc::c_int,
    mut success: libc::c_int,
    mut _arg: *mut libc::c_void,
) {
    if success == 0 {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_stdio_confirm\0"))
                .as_ptr(),
            1876 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"stdio forwarding failed\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn ssh_tun_confirm(
    mut _ssh: *mut ssh,
    mut id: libc::c_int,
    mut success: libc::c_int,
    mut _arg: *mut libc::c_void,
) {
    if success == 0 {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"ssh_tun_confirm\0"))
                .as_ptr(),
            1883 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Tunnel forwarding failed\0" as *const u8 as *const libc::c_char,
        );
        if options.exit_on_forward_failure != 0 {
            cleanup_exit(255 as libc::c_int);
        }
    }
    crate::log::sshlog(
        b"ssh.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"ssh_tun_confirm\0")).as_ptr(),
        1888 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"tunnel forward established, id=%d\0" as *const u8 as *const libc::c_char,
        id,
    );
    forwarding_success();
}
unsafe extern "C" fn ssh_init_stdio_forwarding(mut ssh: *mut ssh) {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut in_0: libc::c_int = 0;
    let mut out: libc::c_int = 0;
    if (options.stdio_forward_host).is_null() {
        return;
    }
    crate::log::sshlog(
        b"ssh.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"ssh_init_stdio_forwarding\0"))
            .as_ptr(),
        1902 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s:%d\0" as *const u8 as *const libc::c_char,
        options.stdio_forward_host,
        options.stdio_forward_port,
    );
    in_0 = dup(0 as libc::c_int);
    if in_0 == -(1 as libc::c_int) || {
        out = dup(1 as libc::c_int);
        out == -(1 as libc::c_int)
    } {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"ssh_init_stdio_forwarding\0",
            ))
            .as_ptr(),
            1906 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"dup() in/out failed\0" as *const u8 as *const libc::c_char,
        );
    }
    c = channel_connect_stdio_fwd(
        ssh,
        options.stdio_forward_host,
        options.stdio_forward_port as u_short,
        in_0,
        out,
        2 as libc::c_int,
    );
    if c.is_null() {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"ssh_init_stdio_forwarding\0",
            ))
            .as_ptr(),
            1910 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel_connect_stdio_fwd failed\0" as *const u8 as *const libc::c_char,
        );
    }
    channel_register_cleanup(
        ssh,
        (*c).self_0,
        Some(
            client_cleanup_stdio_fwd
                as unsafe extern "C" fn(
                    *mut ssh,
                    libc::c_int,
                    libc::c_int,
                    *mut libc::c_void,
                ) -> (),
        ),
        0 as libc::c_int,
    );
    channel_register_open_confirm(
        ssh,
        (*c).self_0,
        Some(
            ssh_stdio_confirm
                as unsafe extern "C" fn(
                    *mut ssh,
                    libc::c_int,
                    libc::c_int,
                    *mut libc::c_void,
                ) -> (),
        ),
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn ssh_init_forward_permissions(
    mut ssh: *mut ssh,
    mut what: *const libc::c_char,
    mut opens: *mut *mut libc::c_char,
    mut num_opens: u_int,
) {
    let mut i: u_int = 0;
    let mut port: libc::c_int = 0;
    let mut addr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut arg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut oarg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut where_0: libc::c_int = (1 as libc::c_int) << 1 as libc::c_int;
    channel_clear_permission(ssh, 0x100 as libc::c_int, where_0);
    if num_opens == 0 as libc::c_int as libc::c_uint {
        return;
    }
    if num_opens == 1 as libc::c_int as libc::c_uint
        && libc::strcmp(
            *opens.offset(0 as libc::c_int as isize),
            b"any\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
    {
        return;
    }
    if num_opens == 1 as libc::c_int as libc::c_uint
        && libc::strcmp(
            *opens.offset(0 as libc::c_int as isize),
            b"none\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
    {
        channel_disable_admin(ssh, where_0);
        return;
    }
    i = 0 as libc::c_int as u_int;
    while i < num_opens {
        arg = crate::xmalloc::xstrdup(*opens.offset(i as isize));
        oarg = arg;
        addr = hpdelim(&mut arg);
        if addr.is_null() {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"ssh_init_forward_permissions\0",
                ))
                .as_ptr(),
                1940 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"missing host in %s\0" as *const u8 as *const libc::c_char,
                what,
            );
        }
        addr = cleanhostname(addr);
        if arg.is_null() || {
            port = permitopen_port(arg);
            port < 0 as libc::c_int
        } {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"ssh_init_forward_permissions\0",
                ))
                .as_ptr(),
                1943 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"bad port number in %s\0" as *const u8 as *const libc::c_char,
                what,
            );
        }
        channel_add_permission(ssh, 0x100 as libc::c_int, where_0, addr, port);
        libc::free(oarg as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn ssh_init_forwarding(mut ssh: *mut ssh, mut ifname: *mut *mut libc::c_char) {
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    ssh_init_forward_permissions(
        ssh,
        b"permitremoteopen\0" as *const u8 as *const libc::c_char,
        options.permitted_remote_opens,
        options.num_permitted_remote_opens,
    );
    if options.exit_on_forward_failure != 0 {
        forward_confirms_pending = 0 as libc::c_int;
    }
    i = 0 as libc::c_int;
    while i < options.num_local_forwards {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"ssh_init_forwarding\0"))
                .as_ptr(),
            1976 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Local connections to %.200s:%d forwarded to remote address %.200s:%d\0" as *const u8
                as *const libc::c_char,
            if !((*(options.local_forwards).offset(i as isize)).listen_path).is_null() {
                (*(options.local_forwards).offset(i as isize)).listen_path as *const libc::c_char
            } else if ((*(options.local_forwards).offset(i as isize)).listen_host).is_null() {
                if options.fwd_opts.gateway_ports != 0 {
                    b"*\0" as *const u8 as *const libc::c_char
                } else {
                    b"LOCALHOST\0" as *const u8 as *const libc::c_char
                }
            } else {
                (*(options.local_forwards).offset(i as isize)).listen_host as *const libc::c_char
            },
            (*(options.local_forwards).offset(i as isize)).listen_port,
            if !((*(options.local_forwards).offset(i as isize)).connect_path).is_null() {
                (*(options.local_forwards).offset(i as isize)).connect_path
            } else {
                (*(options.local_forwards).offset(i as isize)).connect_host
            },
            (*(options.local_forwards).offset(i as isize)).connect_port,
        );
        success += channel_setup_local_fwd_listener(
            ssh,
            &mut *(options.local_forwards).offset(i as isize),
            &mut options.fwd_opts,
        );
        i += 1;
        i;
    }
    if i > 0 as libc::c_int && success != i && options.exit_on_forward_failure != 0 {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"ssh_init_forwarding\0"))
                .as_ptr(),
            1981 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Could not request local forwarding.\0" as *const u8 as *const libc::c_char,
        );
    }
    if i > 0 as libc::c_int && success == 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"ssh_init_forwarding\0"))
                .as_ptr(),
            1983 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Could not request local forwarding.\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int;
    while i < options.num_remote_forwards {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"ssh_init_forwarding\0"))
                .as_ptr(),
            1997 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Remote connections from %.200s:%d forwarded to local address %.200s:%d\0" as *const u8
                as *const libc::c_char,
            if !((*(options.remote_forwards).offset(i as isize)).listen_path).is_null() {
                (*(options.remote_forwards).offset(i as isize)).listen_path as *const libc::c_char
            } else if ((*(options.remote_forwards).offset(i as isize)).listen_host).is_null() {
                b"LOCALHOST\0" as *const u8 as *const libc::c_char
            } else {
                (*(options.remote_forwards).offset(i as isize)).listen_host as *const libc::c_char
            },
            (*(options.remote_forwards).offset(i as isize)).listen_port,
            if !((*(options.remote_forwards).offset(i as isize)).connect_path).is_null() {
                (*(options.remote_forwards).offset(i as isize)).connect_path
            } else {
                (*(options.remote_forwards).offset(i as isize)).connect_host
            },
            (*(options.remote_forwards).offset(i as isize)).connect_port,
        );
        let ref mut fresh9 = (*(options.remote_forwards).offset(i as isize)).handle;
        *fresh9 = channel_request_remote_forwarding(
            ssh,
            &mut *(options.remote_forwards).offset(i as isize),
        );
        if *fresh9 >= 0 as libc::c_int {
            client_register_global_confirm(
                Some(
                    ssh_confirm_remote_forward
                        as unsafe extern "C" fn(
                            *mut ssh,
                            libc::c_int,
                            u_int32_t,
                            *mut libc::c_void,
                        ) -> (),
                ),
                &mut *(options.remote_forwards).offset(i as isize) as *mut Forward
                    as *mut libc::c_void,
            );
            forward_confirms_pending += 1;
            forward_confirms_pending;
        } else if options.exit_on_forward_failure != 0 {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"ssh_init_forwarding\0",
                ))
                .as_ptr(),
                2006 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Could not request remote forwarding.\0" as *const u8 as *const libc::c_char,
            );
        } else {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"ssh_init_forwarding\0",
                ))
                .as_ptr(),
                2008 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Warning: Could not request remote forwarding.\0" as *const u8
                    as *const libc::c_char,
            );
        }
        i += 1;
        i;
    }
    if options.tun_open != 0 as libc::c_int {
        *ifname = client_request_tun_fwd(
            ssh,
            options.tun_open,
            options.tun_local,
            options.tun_remote,
            Some(
                ssh_tun_confirm
                    as unsafe extern "C" fn(
                        *mut ssh,
                        libc::c_int,
                        libc::c_int,
                        *mut libc::c_void,
                    ) -> (),
            ),
            0 as *mut libc::c_void,
        );
        if !(*ifname).is_null() {
            forward_confirms_pending += 1;
            forward_confirms_pending;
        } else if options.exit_on_forward_failure != 0 {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"ssh_init_forwarding\0",
                ))
                .as_ptr(),
                2018 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Could not request tunnel forwarding.\0" as *const u8 as *const libc::c_char,
            );
        } else {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"ssh_init_forwarding\0",
                ))
                .as_ptr(),
                2020 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Could not request tunnel forwarding.\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if forward_confirms_pending > 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"ssh_init_forwarding\0"))
                .as_ptr(),
            2024 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"expecting replies for %d forwards\0" as *const u8 as *const libc::c_char,
            forward_confirms_pending,
        );
    }
}
unsafe extern "C" fn check_agent_present() {
    let mut r: libc::c_int = 0;
    if options.forward_agent != 0 {
        r = ssh_get_authentication_socket(0 as *mut libc::c_int);
        if r != 0 as libc::c_int {
            options.forward_agent = 0 as libc::c_int;
            if r != -(47 as libc::c_int) {
                crate::log::sshlog(
                    b"ssh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"check_agent_present\0",
                    ))
                    .as_ptr(),
                    2038 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    ssh_err(r),
                    b"ssh_get_authentication_socket\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
}
unsafe extern "C" fn ssh_session2_setup(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut success: libc::c_int,
    mut _arg: *mut libc::c_void,
) {
    extern "C" {
        #[link_name = "environ"]
        static mut environ_0: *mut *mut libc::c_char;
    }
    let mut display: *const libc::c_char = 0 as *const libc::c_char;
    let mut term: *const libc::c_char = 0 as *const libc::c_char;
    let mut r: libc::c_int = 0;
    let mut interactive: libc::c_int = tty_flag;
    let mut proto: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut data: *mut libc::c_char = 0 as *mut libc::c_char;
    if success == 0 {
        return;
    }
    display = getenv(b"DISPLAY\0" as *const u8 as *const libc::c_char);
    if display.is_null() && options.forward_x11 != 0 {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"ssh_session2_setup\0"))
                .as_ptr(),
            2056 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"X11 forwarding requested but DISPLAY not set\0" as *const u8 as *const libc::c_char,
        );
    }
    if options.forward_x11 != 0
        && client_x11_get_proto(
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
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"ssh_session2_setup\0"))
                .as_ptr(),
            2062 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Requesting X11 forwarding with authentication spoofing.\0" as *const u8
                as *const libc::c_char,
        );
        x11_request_forwarding_with_spoofing(ssh, id, display, proto, data, 1 as libc::c_int);
        client_expect_confirm(
            ssh,
            id,
            b"X11 forwarding\0" as *const u8 as *const libc::c_char,
            CONFIRM_WARN,
        );
        interactive = 1 as libc::c_int;
    }
    check_agent_present();
    if options.forward_agent != 0 {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"ssh_session2_setup\0"))
                .as_ptr(),
            2072 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Requesting authentication agent forwarding.\0" as *const u8 as *const libc::c_char,
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
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"ssh_session2_setup\0",
                ))
                .as_ptr(),
                2075 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"send packet\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    ssh_packet_set_interactive(
        ssh,
        interactive,
        options.ip_qos_interactive,
        options.ip_qos_bulk,
    );
    term = lookup_env_in_list(
        b"TERM\0" as *const u8 as *const libc::c_char,
        options.setenv,
        options.num_setenv as size_t,
    );
    if term.is_null() || *term as libc::c_int == '\0' as i32 {
        term = getenv(b"TERM\0" as *const u8 as *const libc::c_char);
    }
    client_session2_setup(
        ssh,
        id,
        tty_flag,
        (options.session_type == 1 as libc::c_int) as libc::c_int,
        term,
        0 as *mut termios,
        fileno(stdin),
        command,
        environ,
    );
}
unsafe extern "C" fn ssh_session2_open(mut ssh: *mut ssh) -> libc::c_int {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut window: libc::c_int = 0;
    let mut packetmax: libc::c_int = 0;
    let mut in_0: libc::c_int = 0;
    let mut out: libc::c_int = 0;
    let mut err: libc::c_int = 0;
    if options.stdin_null != 0 {
        in_0 = libc::open(
            b"/dev/null\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        );
    } else {
        in_0 = dup(0 as libc::c_int);
    }
    out = dup(1 as libc::c_int);
    err = dup(2 as libc::c_int);
    if in_0 == -(1 as libc::c_int) || out == -(1 as libc::c_int) || err == -(1 as libc::c_int) {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_session2_open\0"))
                .as_ptr(),
            2106 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"dup() in/out/err failed\0" as *const u8 as *const libc::c_char,
        );
    }
    window = 64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int);
    packetmax = 32 as libc::c_int * 1024 as libc::c_int;
    if tty_flag != 0 {
        window >>= 1 as libc::c_int;
        packetmax >>= 1 as libc::c_int;
    }
    c = channel_new(
        ssh,
        b"session\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        3 as libc::c_int,
        in_0,
        out,
        err,
        window as u_int,
        packetmax as u_int,
        2 as libc::c_int,
        b"client-session\0" as *const u8 as *const libc::c_char,
        2 as libc::c_int,
    );
    crate::log::sshlog(
        b"ssh.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_session2_open\0"))
            .as_ptr(),
        2119 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"channel_new: %d\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    channel_send_open(ssh, (*c).self_0);
    if options.session_type != 0 as libc::c_int {
        channel_register_open_confirm(
            ssh,
            (*c).self_0,
            Some(
                ssh_session2_setup
                    as unsafe extern "C" fn(
                        *mut ssh,
                        libc::c_int,
                        libc::c_int,
                        *mut libc::c_void,
                    ) -> (),
            ),
            0 as *mut libc::c_void,
        );
    }
    return (*c).self_0;
}
unsafe extern "C" fn ssh_session2(
    mut ssh: *mut ssh,
    mut cinfo: *const ssh_conn_info,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut id: libc::c_int = -(1 as libc::c_int);
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tun_fwd_ifname: *mut libc::c_char = 0 as *mut libc::c_char;
    if options.control_persist == 0 {
        ssh_init_stdio_forwarding(ssh);
    }
    ssh_init_forwarding(ssh, &mut tun_fwd_ifname);
    if !(options.local_command).is_null() {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_session2\0")).as_ptr(),
            2142 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"expanding LocalCommand: %s\0" as *const u8 as *const libc::c_char,
            options.local_command,
        );
        cp = options.local_command;
        options.local_command = percent_expand(
            cp,
            b"C\0" as *const u8 as *const libc::c_char,
            (*cinfo).conn_hash_hex,
            b"L\0" as *const u8 as *const libc::c_char,
            (*cinfo).shorthost,
            b"i\0" as *const u8 as *const libc::c_char,
            (*cinfo).uidstr,
            b"k\0" as *const u8 as *const libc::c_char,
            (*cinfo).keyalias,
            b"l\0" as *const u8 as *const libc::c_char,
            (*cinfo).thishost,
            b"n\0" as *const u8 as *const libc::c_char,
            (*cinfo).host_arg,
            b"p\0" as *const u8 as *const libc::c_char,
            (*cinfo).portstr,
            b"d\0" as *const u8 as *const libc::c_char,
            (*cinfo).homedir,
            b"h\0" as *const u8 as *const libc::c_char,
            (*cinfo).remhost,
            b"r\0" as *const u8 as *const libc::c_char,
            (*cinfo).remuser,
            b"u\0" as *const u8 as *const libc::c_char,
            (*cinfo).locuser,
            b"T\0" as *const u8 as *const libc::c_char,
            if tun_fwd_ifname.is_null() {
                b"NONE\0" as *const u8 as *const libc::c_char
            } else {
                tun_fwd_ifname as *const libc::c_char
            },
            0 as *mut libc::c_void as *mut libc::c_char,
        );
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_session2\0")).as_ptr(),
            2148 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"expanded LocalCommand: %s\0" as *const u8 as *const libc::c_char,
            options.local_command,
        );
        libc::free(cp as *mut libc::c_void);
    }
    if ssh_packet_get_mux(ssh) == 0 {
        muxserver_listen(ssh);
    }
    if options.control_persist != 0 && muxserver_sock != -(1 as libc::c_int) {
        ostdin_null_flag = options.stdin_null;
        osession_type = options.session_type;
        orequest_tty = options.request_tty;
        otty_flag = tty_flag;
        options.stdin_null = 1 as libc::c_int;
        options.session_type = 0 as libc::c_int;
        tty_flag = 0 as libc::c_int;
        if options.fork_after_authentication == 0
            && (osession_type != 0 as libc::c_int || !(options.stdio_forward_host).is_null())
        {
            need_controlpersist_detach = 1 as libc::c_int;
        }
        options.fork_after_authentication = 1 as libc::c_int;
    }
    if options.control_persist != 0 && muxserver_sock == -(1 as libc::c_int) {
        ssh_init_stdio_forwarding(ssh);
    }
    if options.session_type != 0 as libc::c_int {
        id = ssh_session2_open(ssh);
    } else {
        ssh_packet_set_interactive(
            ssh,
            (options.control_master == 0 as libc::c_int) as libc::c_int,
            options.ip_qos_interactive,
            options.ip_qos_bulk,
        );
    }
    if options.control_master == 0 as libc::c_int && (*ssh).compat & 0x4000000 as libc::c_int != 0 {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_session2\0")).as_ptr(),
            2197 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Requesting no-more-sessions@openssh.com\0" as *const u8 as *const libc::c_char,
        );
        r = sshpkt_start(ssh, 80 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshpkt_put_cstring(
                    ssh,
                    b"no-more-sessions@openssh.com\0" as *const u8 as *const libc::c_char
                        as *const libc::c_void,
                );
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_u8(ssh, 0 as libc::c_int as u_char);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_send(ssh);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_session2\0"))
                    .as_ptr(),
                2203 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"send packet\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if !(options.local_command).is_null() && options.permit_local_command != 0 {
        ssh_local_cmd(options.local_command);
    }
    if need_controlpersist_detach == 0
        && stdfd_devnull(0 as libc::c_int, 1 as libc::c_int, 0 as libc::c_int)
            == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_session2\0")).as_ptr(),
            2218 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"stdfd_devnull failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if options.fork_after_authentication != 0 {
        if options.exit_on_forward_failure != 0 && options.num_remote_forwards > 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"ssh_session2\0"))
                    .as_ptr(),
                2228 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"deferring postauth libc::fork until remote forward confirmation received\0"
                    as *const u8 as *const libc::c_char,
            );
        } else {
            fork_postauth();
        }
    }
    return client_loop(
        ssh,
        tty_flag,
        if tty_flag != 0 {
            options.escape_char
        } else {
            -(2 as libc::c_int)
        },
        id,
    );
}
unsafe extern "C" fn load_public_identity_files(mut cinfo: *const ssh_conn_info) {
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut public: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut i: libc::c_int = 0;
    let mut n_ids: u_int = 0;
    let mut n_certs: u_int = 0;
    let mut identity_files: [*mut libc::c_char; 100] = [0 as *mut libc::c_char; 100];
    let mut identity_keys: [*mut crate::sshkey::sshkey; 100] =
        [0 as *mut crate::sshkey::sshkey; 100];
    let mut identity_file_userprovided: [libc::c_int; 100] = [0; 100];
    let mut certificate_files: [*mut libc::c_char; 100] = [0 as *mut libc::c_char; 100];
    let mut certificates: [*mut crate::sshkey::sshkey; 100] =
        [0 as *mut crate::sshkey::sshkey; 100];
    let mut certificate_file_userprovided: [libc::c_int; 100] = [0; 100];
    let mut keys: *mut *mut crate::sshkey::sshkey = 0 as *mut *mut crate::sshkey::sshkey;
    let mut comments: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut nkeys: libc::c_int = 0;
    n_certs = 0 as libc::c_int as u_int;
    n_ids = n_certs;
    memset(
        identity_files.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[*mut libc::c_char; 100]>() as libc::c_ulong,
    );
    memset(
        identity_keys.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[*mut crate::sshkey::sshkey; 100]>() as libc::c_ulong,
    );
    memset(
        identity_file_userprovided.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[libc::c_int; 100]>() as libc::c_ulong,
    );
    memset(
        certificate_files.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[*mut libc::c_char; 100]>() as libc::c_ulong,
    );
    memset(
        certificates.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[*mut crate::sshkey::sshkey; 100]>() as libc::c_ulong,
    );
    memset(
        certificate_file_userprovided.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[libc::c_int; 100]>() as libc::c_ulong,
    );
    if !(options.pkcs11_provider).is_null()
        && options.num_identity_files < 100 as libc::c_int
        && pkcs11_init((options.batch_mode == 0) as libc::c_int) == 0 as libc::c_int
        && {
            nkeys = pkcs11_add_provider(
                options.pkcs11_provider,
                0 as *mut libc::c_char,
                &mut keys,
                &mut comments,
            );
            nkeys > 0 as libc::c_int
        }
    {
        i = 0 as libc::c_int;
        while i < nkeys {
            if n_ids >= 100 as libc::c_int as libc::c_uint {
                crate::sshkey::sshkey_free(*keys.offset(i as isize));
                libc::free(*comments.offset(i as isize) as *mut libc::c_void);
            } else {
                identity_keys[n_ids as usize] = *keys.offset(i as isize);
                identity_files[n_ids as usize] = *comments.offset(i as isize);
                n_ids = n_ids.wrapping_add(1);
                n_ids;
            }
            i += 1;
            i;
        }
        libc::free(keys as *mut libc::c_void);
        libc::free(comments as *mut libc::c_void);
    }
    i = 0 as libc::c_int;
    while i < options.num_identity_files {
        if n_ids >= 100 as libc::c_int as libc::c_uint
            || strcasecmp(
                options.identity_files[i as usize],
                b"none\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            libc::free(options.identity_files[i as usize] as *mut libc::c_void);
            options.identity_files[i as usize] = 0 as *mut libc::c_char;
        } else {
            cp = tilde_expand_filename(options.identity_files[i as usize], libc::getuid());
            filename = default_client_percent_dollar_expand(cp, cinfo);
            libc::free(cp as *mut libc::c_void);
            check_load(
                sshkey_load_public(filename, &mut public, 0 as *mut *mut libc::c_char),
                &mut public,
                filename,
                b"pubkey\0" as *const u8 as *const libc::c_char,
            );
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"load_public_identity_files\0",
                ))
                .as_ptr(),
                2300 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"identity file %s type %d\0" as *const u8 as *const libc::c_char,
                filename,
                if !public.is_null() {
                    (*public).type_0
                } else {
                    -(1 as libc::c_int)
                },
            );
            libc::free(options.identity_files[i as usize] as *mut libc::c_void);
            identity_files[n_ids as usize] = filename;
            identity_keys[n_ids as usize] = public;
            identity_file_userprovided[n_ids as usize] =
                options.identity_file_userprovided[i as usize];
            n_ids = n_ids.wrapping_add(1);
            if !(n_ids >= 100 as libc::c_int as libc::c_uint) {
                if !(options.num_certificate_files != 0 as libc::c_int) {
                    crate::xmalloc::xasprintf(
                        &mut cp as *mut *mut libc::c_char,
                        b"%s-cert\0" as *const u8 as *const libc::c_char,
                        filename,
                    );
                    check_load(
                        sshkey_load_public(cp, &mut public, 0 as *mut *mut libc::c_char),
                        &mut public,
                        filename,
                        b"pubkey\0" as *const u8 as *const libc::c_char,
                    );
                    crate::log::sshlog(
                        b"ssh.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"load_public_identity_files\0",
                        ))
                        .as_ptr(),
                        2319 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"identity file %s type %d\0" as *const u8 as *const libc::c_char,
                        cp,
                        if !public.is_null() {
                            (*public).type_0
                        } else {
                            -(1 as libc::c_int)
                        },
                    );
                    if public.is_null() {
                        libc::free(cp as *mut libc::c_void);
                    } else if sshkey_is_cert(public) == 0 {
                        crate::log::sshlog(
                            b"ssh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                                b"load_public_identity_files\0",
                            ))
                            .as_ptr(),
                            2326 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"key %s type %s is not a certificate\0" as *const u8
                                as *const libc::c_char,
                            cp,
                            crate::sshkey::sshkey_type(public),
                        );
                        crate::sshkey::sshkey_free(public);
                        libc::free(cp as *mut libc::c_void);
                    } else {
                        identity_files[n_ids as usize] = crate::xmalloc::xstrdup(filename);
                        identity_keys[n_ids as usize] = public;
                        identity_file_userprovided[n_ids as usize] =
                            options.identity_file_userprovided[i as usize];
                        n_ids = n_ids.wrapping_add(1);
                        n_ids;
                    }
                }
            }
        }
        i += 1;
        i;
    }
    if options.num_certificate_files > 100 as libc::c_int {
        sshfatal(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"load_public_identity_files\0",
            ))
            .as_ptr(),
            2340 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"too many certificates\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int;
    while i < options.num_certificate_files {
        cp = tilde_expand_filename(options.certificate_files[i as usize], libc::getuid());
        filename = default_client_percent_dollar_expand(cp, cinfo);
        libc::free(cp as *mut libc::c_void);
        check_load(
            sshkey_load_public(filename, &mut public, 0 as *mut *mut libc::c_char),
            &mut public,
            filename,
            b"certificate\0" as *const u8 as *const libc::c_char,
        );
        crate::log::sshlog(
            b"ssh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"load_public_identity_files\0",
            ))
            .as_ptr(),
            2350 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"certificate file %s type %d\0" as *const u8 as *const libc::c_char,
            filename,
            if !public.is_null() {
                (*public).type_0
            } else {
                -(1 as libc::c_int)
            },
        );
        libc::free(options.certificate_files[i as usize] as *mut libc::c_void);
        options.certificate_files[i as usize] = 0 as *mut libc::c_char;
        if public.is_null() {
            libc::free(filename as *mut libc::c_void);
        } else if sshkey_is_cert(public) == 0 {
            crate::log::sshlog(
                b"ssh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"load_public_identity_files\0",
                ))
                .as_ptr(),
                2359 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"key %s type %s is not a certificate\0" as *const u8 as *const libc::c_char,
                filename,
                crate::sshkey::sshkey_type(public),
            );
            crate::sshkey::sshkey_free(public);
            libc::free(filename as *mut libc::c_void);
        } else {
            certificate_files[n_certs as usize] = filename;
            certificates[n_certs as usize] = public;
            certificate_file_userprovided[n_certs as usize] =
                options.certificate_file_userprovided[i as usize];
            n_certs = n_certs.wrapping_add(1);
            n_certs;
        }
        i += 1;
        i;
    }
    options.num_identity_files = n_ids as libc::c_int;
    memcpy(
        (options.identity_files).as_mut_ptr() as *mut libc::c_void,
        identity_files.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[*mut libc::c_char; 100]>() as libc::c_ulong,
    );
    memcpy(
        (options.identity_keys).as_mut_ptr() as *mut libc::c_void,
        identity_keys.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[*mut crate::sshkey::sshkey; 100]>() as libc::c_ulong,
    );
    memcpy(
        (options.identity_file_userprovided).as_mut_ptr() as *mut libc::c_void,
        identity_file_userprovided.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[libc::c_int; 100]>() as libc::c_ulong,
    );
    options.num_certificate_files = n_certs as libc::c_int;
    memcpy(
        (options.certificate_files).as_mut_ptr() as *mut libc::c_void,
        certificate_files.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[*mut libc::c_char; 100]>() as libc::c_ulong,
    );
    memcpy(
        (options.certificates).as_mut_ptr() as *mut libc::c_void,
        certificates.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[*mut crate::sshkey::sshkey; 100]>() as libc::c_ulong,
    );
    memcpy(
        (options.certificate_file_userprovided).as_mut_ptr() as *mut libc::c_void,
        certificate_file_userprovided.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[libc::c_int; 100]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn main_sigchld_handler(mut _sig: libc::c_int) {
    let mut save_errno: libc::c_int = *libc::__errno_location();
    let mut pid: pid_t = 0;
    let mut status: libc::c_int = 0;
    loop {
        pid = libc::waitpid(-(1 as libc::c_int), &mut status, 1 as libc::c_int);
        if !(pid > 0 as libc::c_int
            || pid == -(1 as libc::c_int) && *libc::__errno_location() == 4 as libc::c_int)
        {
            break;
        }
    }
    *libc::__errno_location() = save_errno;
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
