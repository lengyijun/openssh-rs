use crate::kex::dh_st;
use crate::packet::key_entry;

use crate::packet::ssh;

use ::libc;
extern "C" {

    pub type ec_group_st;

    fn sigemptyset(__set: *mut sigset_t) -> libc::c_int;
    fn sigaddset(__set: *mut sigset_t, __signo: libc::c_int) -> libc::c_int;
    fn sigprocmask(
        __how: libc::c_int,
        __set: *const sigset_t,
        __oset: *mut sigset_t,
    ) -> libc::c_int;
    fn ppoll(
        __fds: *mut pollfd,
        __nfds: nfds_t,
        __timeout: *const libc::timespec,
        __ss: *const __sigset_t,
    ) -> libc::c_int;
    fn sys_tun_outfilter(
        _: *mut ssh,
        _: *mut Channel,
        _: *mut *mut u_char,
        _: *mut size_t,
    ) -> *mut u_char;
    fn sys_tun_infilter(
        _: *mut ssh,
        _: *mut Channel,
        _: *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;

    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;

    fn sshpkt_fmt_connection_id(ssh: *mut ssh, s: *mut libc::c_char, l: size_t);
    fn sshpkt_get_end(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_get_cstring(
        ssh: *mut ssh,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshpkt_get_string_direct(
        ssh: *mut ssh,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshpkt_get_u32(ssh: *mut ssh, valp: *mut u_int32_t) -> libc::c_int;
    fn sshpkt_get_u8(ssh: *mut ssh, valp: *mut u_char) -> libc::c_int;
    fn sshpkt_put_cstring(ssh: *mut ssh, v: *const libc::c_void) -> libc::c_int;
    fn sshpkt_put_u32(ssh: *mut ssh, val: u_int32_t) -> libc::c_int;
    fn sshpkt_put_u8(ssh: *mut ssh, val: u_char) -> libc::c_int;
    fn sshpkt_putb(ssh: *mut ssh, b: *const crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshpkt_fatal(ssh: *mut ssh, r: libc::c_int, fmt: *const libc::c_char, _: ...) -> !;
    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_start(ssh: *mut ssh, type_0: u_char) -> libc::c_int;
    fn ssh_packet_get_rekey_timeout(_: *mut ssh) -> time_t;
    fn ssh_remote_port(_: *mut ssh) -> libc::c_int;
    fn ssh_remote_ipaddr(_: *mut ssh) -> *const libc::c_char;
    fn ssh_packet_inc_alive_timeouts(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_set_alive_timeouts(_: *mut ssh, _: libc::c_int);
    fn ssh_packet_remaining(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_not_very_much_data_to_write(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_have_data_to_write(_: *mut ssh) -> libc::c_int;

    fn ssh_packet_write_poll(_: *mut ssh) -> libc::c_int;

    fn ssh_packet_send_debug(_: *mut ssh, fmt: *const libc::c_char, _: ...);
    fn ssh_packet_disconnect(_: *mut ssh, fmt: *const libc::c_char, _: ...) -> !;
    fn ssh_packet_process_read(_: *mut ssh, _: libc::c_int) -> libc::c_int;
    fn ssh_packet_check_rekey(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_is_rekeying(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_get_connection_out(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_get_connection_in(_: *mut ssh) -> libc::c_int;
    fn dispatch_protocol_error(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;

    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
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
    fn monotime() -> time_t;
    fn tun_open(_: libc::c_int, _: libc::c_int, _: *mut *mut libc::c_char) -> libc::c_int;
    fn ptimeout_init(pt: *mut libc::timespec);
    fn ptimeout_deadline_sec(pt: *mut libc::timespec, sec: libc::c_long);
    fn ptimeout_deadline_ms(pt: *mut libc::timespec, ms: libc::c_long);
    fn ptimeout_deadline_monotime(pt: *mut libc::timespec, when: time_t);
    fn ptimeout_get_tsp(pt: *mut libc::timespec) -> *mut libc::timespec;

    fn channel_lookup(_: *mut ssh, _: libc::c_int) -> *mut Channel;
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
    fn channel_free_all(_: *mut ssh);
    fn channel_request_start(_: *mut ssh, _: libc::c_int, _: *mut libc::c_char, _: libc::c_int);
    fn channel_register_cleanup(
        _: *mut ssh,
        _: libc::c_int,
        _: Option<channel_callback_fn>,
        _: libc::c_int,
    );
    fn channel_register_filter(
        _: *mut ssh,
        _: libc::c_int,
        _: Option<channel_infilter_fn>,
        _: Option<channel_outfilter_fn>,
        _: Option<channel_filter_cleanup_fn>,
        _: *mut libc::c_void,
    );
    fn channel_input_data(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_extended_data(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_ieof(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_oclose(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_open_confirmation(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_open_failure(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_window_adjust(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_prepare_poll(
        _: *mut ssh,
        _: *mut *mut pollfd,
        _: *mut u_int,
        _: *mut u_int,
        _: u_int,
        _: *mut libc::timespec,
    );
    fn channel_after_poll(_: *mut ssh, _: *mut pollfd, _: u_int);
    fn channel_output_poll(_: *mut ssh);
    fn channel_still_open(_: *mut ssh) -> libc::c_int;
    fn channel_find_open(_: *mut ssh) -> libc::c_int;
    fn channel_connect_to_port(
        _: *mut ssh,
        _: *const libc::c_char,
        _: u_short,
        _: *mut libc::c_char,
        _: *mut libc::c_char,
        _: *mut libc::c_int,
        _: *mut *const libc::c_char,
    ) -> *mut Channel;
    fn channel_connect_to_path(
        _: *mut ssh,
        _: *const libc::c_char,
        _: *mut libc::c_char,
        _: *mut libc::c_char,
    ) -> *mut Channel;
    fn channel_setup_remote_fwd_listener(
        _: *mut ssh,
        _: *mut Forward,
        _: *mut libc::c_int,
        _: *mut ForwardOptions,
    ) -> libc::c_int;
    fn channel_cancel_rport_listener(_: *mut ssh, _: *mut Forward) -> libc::c_int;
    fn chan_rcvd_eow(_: *mut ssh, _: *mut Channel);

    fn sshkey_type_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn sshkey_from_blob(
        _: *const u_char,
        _: size_t,
        _: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_puts(_: *const crate::sshkey::sshkey, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn kex_input_kexinit(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn get_hostkey_by_index(_: libc::c_int) -> *mut crate::sshkey::sshkey;
    fn get_hostkey_public_by_index(_: libc::c_int, _: *mut ssh) -> *mut crate::sshkey::sshkey;
    fn session_open(_: *mut Authctxt, _: libc::c_int) -> libc::c_int;
    fn session_input_channel_req(
        _: *mut ssh,
        _: *mut Channel,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn session_close_by_pid(ssh: *mut ssh, _: pid_t, _: libc::c_int);
    fn session_close_by_channel(_: *mut ssh, _: libc::c_int, _: libc::c_int, _: *mut libc::c_void);
    fn session_destroy_all(_: *mut ssh, _: Option<unsafe extern "C" fn(*mut Session) -> ()>);
    static mut options: ServerOptions;
    static mut the_authctxt: *mut Authctxt;
    static mut auth_opts: *mut sshauthopt;
    static mut use_privsep: libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_short = libc::c_ushort;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __mode_t = libc::c_uint;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_short = __u_short;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type uid_t = __uid_t;
pub type pid_t = __pid_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [libc::c_ulong; 16],
}
pub type sigset_t = __sigset_t;

pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;

pub type sig_atomic_t = __sig_atomic_t;
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
pub struct C2RustUnnamed {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub tqe_next: *mut key_entry,
    pub tqe_prev: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
pub type dispatch_fn = unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int;

pub type DH = dh_st;

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
    pub entry: C2RustUnnamed_2,
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
pub struct C2RustUnnamed_2 {
    pub tqe_next: *mut channel_confirm,
    pub tqe_prev: *mut *mut channel_confirm,
}
pub type channel_callback_fn =
    unsafe extern "C" fn(*mut ssh, libc::c_int, libc::c_int, *mut libc::c_void) -> ();
pub type channel_open_fn =
    unsafe extern "C" fn(*mut ssh, libc::c_int, libc::c_int, *mut libc::c_void) -> ();
pub type C2RustUnnamed_3 = libc::c_uint;
pub const DISPATCH_NONBLOCK: C2RustUnnamed_3 = 1;
pub const DISPATCH_BLOCK: C2RustUnnamed_3 = 0;
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
    pub env: *mut C2RustUnnamed_4,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub name: *mut libc::c_char,
    pub val: *mut libc::c_char,
}
static mut no_more_sessions: libc::c_int = 0 as libc::c_int;
static mut child_terminated: sig_atomic_t = 0 as libc::c_int;
static mut received_sigterm: sig_atomic_t = 0 as libc::c_int;
pub static mut tun_fwd_ifnames: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
unsafe extern "C" fn bind_permitted(mut port: libc::c_int, mut uid: uid_t) -> libc::c_int {
    if use_privsep != 0 {
        return 1 as libc::c_int;
    }
    if port < 1024 as libc::c_int && uid != 0 as libc::c_int as libc::c_uint {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn sigchld_handler(mut _sig: libc::c_int) {
    ::core::ptr::write_volatile(&mut child_terminated as *mut sig_atomic_t, 1 as libc::c_int);
}
unsafe extern "C" fn sigterm_handler(mut sig: libc::c_int) {
    ::core::ptr::write_volatile(&mut received_sigterm as *mut sig_atomic_t, sig);
}
unsafe extern "C" fn client_alive_check(mut ssh: *mut ssh) {
    let mut remote_id: [libc::c_char; 512] = [0; 512];
    let mut r: libc::c_int = 0;
    let mut channel_id: libc::c_int = 0;
    if options.client_alive_count_max > 0 as libc::c_int
        && ssh_packet_inc_alive_timeouts(ssh) > options.client_alive_count_max
    {
        sshpkt_fmt_connection_id(
            ssh,
            remote_id.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
        );
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"client_alive_check\0"))
                .as_ptr(),
            138 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Timeout, client not responding from %s\0" as *const u8 as *const libc::c_char,
            remote_id.as_mut_ptr(),
        );
        cleanup_exit(255 as libc::c_int);
    }
    channel_id = channel_find_open(ssh);
    if channel_id == -(1 as libc::c_int) {
        r = sshpkt_start(ssh, 80 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshpkt_put_cstring(
                    ssh,
                    b"keepalive@openssh.com\0" as *const u8 as *const libc::c_char
                        as *const libc::c_void,
                );
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_u8(ssh, 1 as libc::c_int as u_char);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"client_alive_check\0",
                ))
                .as_ptr(),
                151 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        channel_request_start(
            ssh,
            channel_id,
            b"keepalive@openssh.com\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            1 as libc::c_int,
        );
    }
    r = sshpkt_send(ssh);
    if r != 0 as libc::c_int {
        sshfatal(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"client_alive_check\0"))
                .as_ptr(),
            157 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn wait_until_can_do_something(
    mut ssh: *mut ssh,
    mut connection_in: libc::c_int,
    mut connection_out: libc::c_int,
    mut pfdp: *mut *mut pollfd,
    mut npfd_allocp: *mut u_int,
    mut npfd_activep: *mut u_int,
    mut sigsetp: *mut sigset_t,
    mut conn_in_readyp: *mut libc::c_int,
    mut conn_out_readyp: *mut libc::c_int,
) {
    let mut timeout: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut remote_id: [libc::c_char; 512] = [0; 512];
    let mut ret: libc::c_int = 0;
    let mut client_alive_scheduled: libc::c_int = 0 as libc::c_int;
    let mut p: u_int = 0;
    let mut now: time_t = 0;
    static mut last_client_time: time_t = 0;
    static mut unused_connection_expiry: time_t = 0;
    *conn_out_readyp = 0 as libc::c_int;
    *conn_in_readyp = *conn_out_readyp;
    ptimeout_init(&mut timeout);
    channel_prepare_poll(
        ssh,
        pfdp,
        npfd_allocp,
        npfd_activep,
        2 as libc::c_int as u_int,
        &mut timeout,
    );
    now = monotime();
    if *npfd_activep < 2 as libc::c_int as libc::c_uint {
        sshfatal(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"wait_until_can_do_something\0",
            ))
            .as_ptr(),
            186 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"bad npfd %u\0" as *const u8 as *const libc::c_char,
            *npfd_activep,
        );
    }
    if options.rekey_interval > 0 as libc::c_int && ssh_packet_is_rekeying(ssh) == 0 {
        ptimeout_deadline_sec(&mut timeout, ssh_packet_get_rekey_timeout(ssh));
    }
    if options.unused_connection_timeout != 0 as libc::c_int {
        if channel_still_open(ssh) != 0
            || unused_connection_expiry == 0 as libc::c_int as libc::c_long
        {
            unused_connection_expiry = now + options.unused_connection_timeout as libc::c_long;
        }
        ptimeout_deadline_monotime(&mut timeout, unused_connection_expiry);
    }
    if options.client_alive_interval != 0 {
        if last_client_time == 0 as libc::c_int as libc::c_long {
            last_client_time = now;
        }
        ptimeout_deadline_sec(&mut timeout, options.client_alive_interval as libc::c_long);
        client_alive_scheduled = 1 as libc::c_int;
    }
    (*(*pfdp).offset(0 as libc::c_int as isize)).fd = connection_in;
    (*(*pfdp).offset(0 as libc::c_int as isize)).events = 0x1 as libc::c_int as libc::c_short;
    (*(*pfdp).offset(1 as libc::c_int as isize)).fd = connection_out;
    (*(*pfdp).offset(1 as libc::c_int as isize)).events =
        (if ssh_packet_have_data_to_write(ssh) != 0 {
            0x4 as libc::c_int
        } else {
            0 as libc::c_int
        }) as libc::c_short;
    if child_terminated != 0 && ssh_packet_not_very_much_data_to_write(ssh) != 0 {
        ptimeout_deadline_ms(&mut timeout, 100 as libc::c_int as libc::c_long);
    }
    ret = ppoll(
        *pfdp,
        *npfd_activep as nfds_t,
        ptimeout_get_tsp(&mut timeout),
        sigsetp,
    );
    if ret == -(1 as libc::c_int) {
        p = 0 as libc::c_int as u_int;
        while p < *npfd_activep {
            (*(*pfdp).offset(p as isize)).revents = 0 as libc::c_int as libc::c_short;
            p = p.wrapping_add(1);
            p;
        }
        if *libc::__errno_location() != 4 as libc::c_int {
            sshfatal(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"wait_until_can_do_something\0",
                ))
                .as_ptr(),
                245 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"ppoll: %.100s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        return;
    }
    *conn_in_readyp = ((*(*pfdp).offset(0 as libc::c_int as isize)).revents as libc::c_int
        != 0 as libc::c_int) as libc::c_int;
    *conn_out_readyp = ((*(*pfdp).offset(1 as libc::c_int as isize)).revents as libc::c_int
        != 0 as libc::c_int) as libc::c_int;
    now = monotime();
    if client_alive_scheduled != 0 {
        if ret == 0 as libc::c_int
            && now > last_client_time + options.client_alive_interval as libc::c_long
        {
            client_alive_check(ssh);
            last_client_time = now;
        } else if ret != 0 as libc::c_int && *conn_in_readyp != 0 {
            last_client_time = now;
        }
    }
    if unused_connection_expiry != 0 as libc::c_int as libc::c_long
        && now > unused_connection_expiry
        && channel_still_open(ssh) == 0
    {
        sshpkt_fmt_connection_id(
            ssh,
            remote_id.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
        );
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"wait_until_can_do_something\0",
            ))
            .as_ptr(),
            270 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"terminating inactive connection from %s\0" as *const u8 as *const libc::c_char,
            remote_id.as_mut_ptr(),
        );
        cleanup_exit(255 as libc::c_int);
    }
}
unsafe extern "C" fn process_input(
    mut ssh: *mut ssh,
    mut connection_in: libc::c_int,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = ssh_packet_process_read(ssh, connection_in);
    if r == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if r == -(24 as libc::c_int) {
        if *libc::__errno_location() == 11 as libc::c_int
            || *libc::__errno_location() == 4 as libc::c_int
            || *libc::__errno_location() == 11 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if *libc::__errno_location() == 32 as libc::c_int {
            crate::log::sshlog(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_input\0"))
                    .as_ptr(),
                291 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_VERBOSE,
                0 as *const libc::c_char,
                b"Connection closed by %.100s port %d\0" as *const u8 as *const libc::c_char,
                ssh_remote_ipaddr(ssh),
                ssh_remote_port(ssh),
            );
            return -(1 as libc::c_int);
        }
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_input\0"))
                .as_ptr(),
            296 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"Read error from remote host %s port %d: %s\0" as *const u8 as *const libc::c_char,
            ssh_remote_ipaddr(ssh),
            ssh_remote_port(ssh),
            libc::strerror(*libc::__errno_location()),
        );
        cleanup_exit(255 as libc::c_int);
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn process_output(mut ssh: *mut ssh, mut _connection_out: libc::c_int) {
    let mut r: libc::c_int = 0;
    r = ssh_packet_write_poll(ssh);
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: ssh_packet_write_poll\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_output\0"))
                .as_ptr(),
        );
    }
}
unsafe extern "C" fn process_buffered_input_packets(mut ssh: *mut ssh) {
    crate::dispatch::ssh_dispatch_run_fatal(
        ssh,
        DISPATCH_NONBLOCK as libc::c_int,
        0 as *mut sig_atomic_t,
    );
}
unsafe extern "C" fn collect_children(mut ssh: *mut ssh) {
    let mut pid: pid_t = 0;
    let mut status: libc::c_int = 0;
    if child_terminated != 0 {
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"collect_children\0"))
                .as_ptr(),
            330 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Received SIGCHLD.\0" as *const u8 as *const libc::c_char,
        );
        loop {
            pid = libc::waitpid(-(1 as libc::c_int), &mut status, 1 as libc::c_int);
            if !(pid > 0 as libc::c_int
                || pid == -(1 as libc::c_int) && *libc::__errno_location() == 4 as libc::c_int)
            {
                break;
            }
            if pid > 0 as libc::c_int {
                session_close_by_pid(ssh, pid, status);
            }
        }
        ::core::ptr::write_volatile(&mut child_terminated as *mut sig_atomic_t, 0 as libc::c_int);
    }
}
pub unsafe extern "C" fn server_loop2(mut ssh: *mut ssh, mut _authctxt: *mut Authctxt) {
    let mut pfd: *mut pollfd = 0 as *mut pollfd;
    let mut npfd_alloc: u_int = 0 as libc::c_int as u_int;
    let mut npfd_active: u_int = 0 as libc::c_int as u_int;
    let mut r: libc::c_int = 0;
    let mut conn_in_ready: libc::c_int = 0;
    let mut conn_out_ready: libc::c_int = 0;
    let mut connection_in: u_int = 0;
    let mut connection_out: u_int = 0;
    let mut bsigset: sigset_t = sigset_t { __val: [0; 16] };
    let mut osigset: sigset_t = sigset_t { __val: [0; 16] };
    crate::log::sshlog(
        b"serverloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"server_loop2\0")).as_ptr(),
        348 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Entering interactive session for SSH2.\0" as *const u8 as *const libc::c_char,
    );
    if sigemptyset(&mut bsigset) == -(1 as libc::c_int)
        || sigaddset(&mut bsigset, 17 as libc::c_int) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"server_loop2\0")).as_ptr(),
            351 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"bsigset setup: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    crate::misc::ssh_signal(
        17 as libc::c_int,
        Some(sigchld_handler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    ::core::ptr::write_volatile(&mut child_terminated as *mut sig_atomic_t, 0 as libc::c_int);
    connection_in = ssh_packet_get_connection_in(ssh) as u_int;
    connection_out = ssh_packet_get_connection_out(ssh) as u_int;
    if use_privsep == 0 {
        crate::misc::ssh_signal(
            15 as libc::c_int,
            Some(sigterm_handler as unsafe extern "C" fn(libc::c_int) -> ()),
        );
        crate::misc::ssh_signal(
            2 as libc::c_int,
            Some(sigterm_handler as unsafe extern "C" fn(libc::c_int) -> ()),
        );
        crate::misc::ssh_signal(
            3 as libc::c_int,
            Some(sigterm_handler as unsafe extern "C" fn(libc::c_int) -> ()),
        );
    }
    server_init_dispatch(ssh);
    loop {
        process_buffered_input_packets(ssh);
        if ssh_packet_is_rekeying(ssh) == 0 && ssh_packet_not_very_much_data_to_write(ssh) != 0 {
            channel_output_poll(ssh);
        }
        if sigprocmask(0 as libc::c_int, &mut bsigset, &mut osigset) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"server_loop2\0"))
                    .as_ptr(),
                378 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"bsigset sigprocmask: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        collect_children(ssh);
        wait_until_can_do_something(
            ssh,
            connection_in as libc::c_int,
            connection_out as libc::c_int,
            &mut pfd,
            &mut npfd_alloc,
            &mut npfd_active,
            &mut osigset,
            &mut conn_in_ready,
            &mut conn_out_ready,
        );
        if sigprocmask(1 as libc::c_int, &mut bsigset, &mut osigset) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"server_loop2\0"))
                    .as_ptr(),
                384 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"osigset sigprocmask: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        if received_sigterm != 0 {
            crate::log::sshlog(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"server_loop2\0"))
                    .as_ptr(),
                387 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Exiting on signal %d\0" as *const u8 as *const libc::c_char,
                received_sigterm,
            );
            cleanup_exit(255 as libc::c_int);
        }
        channel_after_poll(ssh, pfd, npfd_active);
        if conn_in_ready != 0 && process_input(ssh, connection_in as libc::c_int) < 0 as libc::c_int
        {
            break;
        }
        r = ssh_packet_check_rekey(ssh);
        if r != 0 as libc::c_int {
            sshfatal(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"server_loop2\0"))
                    .as_ptr(),
                398 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"cannot start rekeying\0" as *const u8 as *const libc::c_char,
            );
        }
        if conn_out_ready != 0 {
            process_output(ssh, connection_out as libc::c_int);
        }
    }
    collect_children(ssh);
    libc::free(pfd as *mut libc::c_void);
    channel_free_all(ssh);
    session_destroy_all(ssh, None);
}
unsafe extern "C" fn server_input_keep_alive(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    crate::log::sshlog(
        b"serverloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"server_input_keep_alive\0"))
            .as_ptr(),
        415 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Got %d/%u for keepalive\0" as *const u8 as *const libc::c_char,
        type_0,
        seq,
    );
    ssh_packet_set_alive_timeouts(ssh, 0 as libc::c_int);
    return 0 as libc::c_int;
}
unsafe extern "C" fn server_request_direct_tcpip(
    mut ssh: *mut ssh,
    mut reason: *mut libc::c_int,
    mut errmsg: *mut *const libc::c_char,
) -> *mut Channel {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut target: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut originator: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut target_port: u_int = 0 as libc::c_int as u_int;
    let mut originator_port: u_int = 0 as libc::c_int as u_int;
    let mut r: libc::c_int = 0;
    r = sshpkt_get_cstring(ssh, &mut target, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_get_u32(ssh, &mut target_port);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_cstring(ssh, &mut originator, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_u32(ssh, &mut originator_port);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"server_request_direct_tcpip\0",
            ))
            .as_ptr(),
        );
    }
    if target_port > 0xffff as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"server_request_direct_tcpip\0",
            ))
            .as_ptr(),
            440 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"invalid target port\0" as *const u8 as *const libc::c_char,
        );
        *reason = 1 as libc::c_int;
    } else if originator_port > 0xffff as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"server_request_direct_tcpip\0",
            ))
            .as_ptr(),
            445 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"invalid originator port\0" as *const u8 as *const libc::c_char,
        );
        *reason = 1 as libc::c_int;
    } else {
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"server_request_direct_tcpip\0",
            ))
            .as_ptr(),
            451 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"originator %s port %u, target %s port %u\0" as *const u8 as *const libc::c_char,
            originator,
            originator_port,
            target,
            target_port,
        );
        if options.allow_tcp_forwarding & (1 as libc::c_int) << 1 as libc::c_int != 0 as libc::c_int
            && (*auth_opts).permit_port_forwarding_flag != 0
            && options.disable_forwarding == 0
        {
            c = channel_connect_to_port(
                ssh,
                target,
                target_port as u_short,
                b"direct-tcpip\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                b"direct-tcpip\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                reason,
                errmsg,
            );
        } else {
            crate::log::sshlog(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"server_request_direct_tcpip\0",
                ))
                .as_ptr(),
                462 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"refused local port forward: originator %s port %d, target %s port %d\0"
                    as *const u8 as *const libc::c_char,
                originator,
                originator_port,
                target,
                target_port,
            );
            if !reason.is_null() {
                *reason = 1 as libc::c_int;
            }
        }
    }
    libc::free(originator as *mut libc::c_void);
    libc::free(target as *mut libc::c_void);
    return c;
}
unsafe extern "C" fn server_request_direct_streamlocal(mut ssh: *mut ssh) -> *mut Channel {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut target: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut originator: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut originator_port: u_int = 0 as libc::c_int as u_int;
    let mut pw: *mut libc::passwd = (*the_authctxt).pw;
    let mut r: libc::c_int = 0;
    if pw.is_null() || (*the_authctxt).valid == 0 {
        sshfatal(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"server_request_direct_streamlocal\0",
            ))
            .as_ptr(),
            483 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no/invalid user\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshpkt_get_cstring(ssh, &mut target, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_get_cstring(ssh, &mut originator, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_u32(ssh, &mut originator_port);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"server_request_direct_streamlocal\0",
            ))
            .as_ptr(),
        );
    }
    if originator_port > 0xffff as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"server_request_direct_streamlocal\0",
            ))
            .as_ptr(),
            491 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"invalid originator port\0" as *const u8 as *const libc::c_char,
        );
    } else {
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"server_request_direct_streamlocal\0",
            ))
            .as_ptr(),
            496 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"originator %s port %d, target %s\0" as *const u8 as *const libc::c_char,
            originator,
            originator_port,
            target,
        );
        if options.allow_streamlocal_forwarding & (1 as libc::c_int) << 1 as libc::c_int
            != 0 as libc::c_int
            && (*auth_opts).permit_port_forwarding_flag != 0
            && options.disable_forwarding == 0
            && ((*pw).pw_uid == 0 as libc::c_int as libc::c_uint || use_privsep != 0)
        {
            c = channel_connect_to_path(
                ssh,
                target,
                b"direct-streamlocal@openssh.com\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                b"direct-streamlocal\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            );
        } else {
            crate::log::sshlog(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                    b"server_request_direct_streamlocal\0",
                ))
                .as_ptr(),
                507 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"refused streamlocal port forward: originator %s port %d, target %s\0" as *const u8
                    as *const libc::c_char,
                originator,
                originator_port,
                target,
            );
        }
    }
    libc::free(originator as *mut libc::c_void);
    libc::free(target as *mut libc::c_void);
    return c;
}
unsafe extern "C" fn server_request_tun(mut ssh: *mut ssh) -> *mut Channel {
    let mut current_block: u64;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut mode: u_int = 0;
    let mut tun: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut sock: libc::c_int = 0;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ifname: *mut libc::c_char = 0 as *mut libc::c_char;
    r = sshpkt_get_u32(ssh, &mut mode);
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse mode\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"server_request_tun\0"))
                .as_ptr(),
        );
    }
    match mode {
        1 | 2 => {}
        _ => {
            ssh_packet_send_debug(
                ssh,
                b"Unsupported tunnel device mode.\0" as *const u8 as *const libc::c_char,
            );
            return 0 as *mut Channel;
        }
    }
    if options.permit_tun as libc::c_uint & mode == 0 as libc::c_int as libc::c_uint {
        ssh_packet_send_debug(
            ssh,
            b"Server has rejected tunnel device forwarding\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut Channel;
    }
    r = sshpkt_get_u32(ssh, &mut tun);
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse device\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"server_request_tun\0"))
                .as_ptr(),
        );
    }
    if tun > 2147483647 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"server_request_tun\0"))
                .as_ptr(),
            543 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"invalid tun\0" as *const u8 as *const libc::c_char,
        );
    } else {
        if (*auth_opts).force_tun_device != -(1 as libc::c_int) {
            if tun != 0x7fffffff as libc::c_int as libc::c_uint
                && (*auth_opts).force_tun_device != tun as libc::c_int
            {
                current_block = 6625063970155628909;
            } else {
                tun = (*auth_opts).force_tun_device as u_int;
                current_block = 9606288038608642794;
            }
        } else {
            current_block = 9606288038608642794;
        }
        match current_block {
            6625063970155628909 => {}
            _ => {
                sock = tun_open(tun as libc::c_int, mode as libc::c_int, &mut ifname);
                if !(sock < 0 as libc::c_int) {
                    crate::log::sshlog(
                        b"serverloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"server_request_tun\0",
                        ))
                        .as_ptr(),
                        555 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"Tunnel forwarding using interface %s\0" as *const u8
                            as *const libc::c_char,
                        ifname,
                    );
                    c = channel_new(
                        ssh,
                        b"tun\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                        4 as libc::c_int,
                        sock,
                        sock,
                        -(1 as libc::c_int),
                        (64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int)) as u_int,
                        (32 as libc::c_int * 1024 as libc::c_int) as u_int,
                        0 as libc::c_int,
                        b"tun\0" as *const u8 as *const libc::c_char,
                        1 as libc::c_int,
                    );
                    (*c).datagram = 1 as libc::c_int;
                    if mode == 0x1 as libc::c_int as libc::c_uint {
                        channel_register_filter(
                            ssh,
                            (*c).self_0,
                            Some(
                                sys_tun_infilter
                                    as unsafe extern "C" fn(
                                        *mut ssh,
                                        *mut Channel,
                                        *mut libc::c_char,
                                        libc::c_int,
                                    )
                                        -> libc::c_int,
                            ),
                            Some(
                                sys_tun_outfilter
                                    as unsafe extern "C" fn(
                                        *mut ssh,
                                        *mut Channel,
                                        *mut *mut u_char,
                                        *mut size_t,
                                    )
                                        -> *mut u_char,
                            ),
                            None,
                            0 as *mut libc::c_void,
                        );
                    }
                    tmp = tun_fwd_ifnames;
                    crate::xmalloc::xasprintf(
                        &mut tun_fwd_ifnames as *mut *mut libc::c_char,
                        b"%s%s%s\0" as *const u8 as *const libc::c_char,
                        if tun_fwd_ifnames.is_null() {
                            b"\0" as *const u8 as *const libc::c_char
                        } else {
                            tun_fwd_ifnames as *const libc::c_char
                        },
                        if tun_fwd_ifnames.is_null() {
                            b"\0" as *const u8 as *const libc::c_char
                        } else {
                            b",\0" as *const u8 as *const libc::c_char
                        },
                        ifname,
                    );
                    libc::free(tmp as *mut libc::c_void);
                    libc::free(ifname as *mut libc::c_void);
                }
            }
        }
    }
    if c.is_null() {
        ssh_packet_send_debug(
            ssh,
            b"Failed to open the tunnel device.\0" as *const u8 as *const libc::c_char,
        );
    }
    return c;
}
unsafe extern "C" fn server_request_session(mut ssh: *mut ssh) -> *mut Channel {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"serverloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"server_request_session\0"))
            .as_ptr(),
        591 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"input_session_request\0" as *const u8 as *const libc::c_char,
    );
    r = sshpkt_get_end(ssh);
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"server_request_session\0",
            ))
            .as_ptr(),
        );
    }
    if no_more_sessions != 0 {
        ssh_packet_disconnect(
            ssh,
            b"Possible attack: attempt to open a session after additional sessions disabled\0"
                as *const u8 as *const libc::c_char,
        );
    }
    c = channel_new(
        ssh,
        b"session\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        10 as libc::c_int,
        -(1 as libc::c_int),
        -(1 as libc::c_int),
        -(1 as libc::c_int),
        0 as libc::c_int as u_int,
        (32 as libc::c_int * 1024 as libc::c_int) as u_int,
        0 as libc::c_int,
        b"server-session\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    if session_open(the_authctxt, (*c).self_0) != 1 as libc::c_int {
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"server_request_session\0",
            ))
            .as_ptr(),
            610 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"session open failed, libc::free channel %d\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        channel_free(ssh, c);
        return 0 as *mut Channel;
    }
    channel_register_cleanup(
        ssh,
        (*c).self_0,
        Some(
            session_close_by_channel
                as unsafe extern "C" fn(
                    *mut ssh,
                    libc::c_int,
                    libc::c_int,
                    *mut libc::c_void,
                ) -> (),
        ),
        0 as libc::c_int,
    );
    return c;
}
unsafe extern "C" fn server_input_channel_open(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut ctype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut errmsg: *const libc::c_char = 0 as *const libc::c_char;
    let mut r: libc::c_int = 0;
    let mut reason: libc::c_int = 2 as libc::c_int;
    let mut rchan: u_int = 0 as libc::c_int as u_int;
    let mut rmaxpack: u_int = 0 as libc::c_int as u_int;
    let mut rwindow: u_int = 0 as libc::c_int as u_int;
    r = sshpkt_get_cstring(ssh, &mut ctype, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_get_u32(ssh, &mut rchan);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_u32(ssh, &mut rwindow);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_u32(ssh, &mut rmaxpack);
            r != 0 as libc::c_int
        }
    {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"server_input_channel_open\0",
            ))
            .as_ptr(),
        );
    }
    crate::log::sshlog(
        b"serverloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"server_input_channel_open\0"))
            .as_ptr(),
        633 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"ctype %s rchan %u win %u max %u\0" as *const u8 as *const libc::c_char,
        ctype,
        rchan,
        rwindow,
        rmaxpack,
    );
    if libc::strcmp(ctype, b"session\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        c = server_request_session(ssh);
    } else if libc::strcmp(ctype, b"direct-tcpip\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        c = server_request_direct_tcpip(ssh, &mut reason, &mut errmsg);
    } else if libc::strcmp(
        ctype,
        b"direct-streamlocal@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        c = server_request_direct_streamlocal(ssh);
    } else if libc::strcmp(
        ctype,
        b"tun@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        c = server_request_tun(ssh);
    }
    if !c.is_null() {
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"server_input_channel_open\0",
            ))
            .as_ptr(),
            645 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"confirm %s\0" as *const u8 as *const libc::c_char,
            ctype,
        );
        (*c).remote_id = rchan;
        (*c).have_remote_id = 1 as libc::c_int;
        (*c).remote_window = rwindow;
        (*c).remote_maxpacket = rmaxpack;
        if (*c).type_0 != 12 as libc::c_int {
            r = sshpkt_start(ssh, 91 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = sshpkt_put_u32(ssh, (*c).remote_id);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_u32(ssh, (*c).self_0 as u_int32_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_u32(ssh, (*c).local_window);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_u32(ssh, (*c).local_maxpacket);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_send(ssh);
                    r != 0 as libc::c_int
                }
            {
                sshpkt_fatal(
                    ssh,
                    r,
                    b"%s: send open confirm\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"server_input_channel_open\0",
                    ))
                    .as_ptr(),
                );
            }
        }
    } else {
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"server_input_channel_open\0",
            ))
            .as_ptr(),
            662 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"failure %s\0" as *const u8 as *const libc::c_char,
            ctype,
        );
        r = sshpkt_start(ssh, 92 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshpkt_put_u32(ssh, rchan);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_u32(ssh, reason as u_int32_t);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_cstring(
                    ssh,
                    (if !errmsg.is_null() {
                        errmsg
                    } else {
                        b"open failed\0" as *const u8 as *const libc::c_char
                    }) as *const libc::c_void,
                );
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_cstring(
                    ssh,
                    b"\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                );
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_send(ssh);
                r != 0 as libc::c_int
            }
        {
            sshpkt_fatal(
                ssh,
                r,
                b"%s: send open failure\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"server_input_channel_open\0",
                ))
                .as_ptr(),
            );
        }
    }
    libc::free(ctype as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn server_input_hostkeys_prove(
    mut ssh: *mut ssh,
    mut respp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut resp: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sigbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut key_pub: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut key_prv: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut r: libc::c_int = 0;
    let mut ndx: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut blob: *const u_char = 0 as *const u_char;
    let mut sigalg: *const libc::c_char = 0 as *const libc::c_char;
    let mut kex_rsa_sigalg: *const libc::c_char = 0 as *const libc::c_char;
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut blen: size_t = 0;
    let mut slen: size_t = 0;
    resp = crate::sshbuf::sshbuf_new();
    if resp.is_null() || {
        sigbuf = crate::sshbuf::sshbuf_new();
        sigbuf.is_null()
    } {
        sshfatal(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"server_input_hostkeys_prove\0",
            ))
            .as_ptr(),
            690 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    if sshkey_type_plain(sshkey_type_from_name((*(*ssh).kex).hostkey_alg)) == KEY_RSA as libc::c_int
    {
        kex_rsa_sigalg = (*(*ssh).kex).hostkey_alg;
    }
    loop {
        if !(ssh_packet_remaining(ssh) > 0 as libc::c_int) {
            current_block = 11057878835866523405;
            break;
        }
        crate::sshkey::sshkey_free(key);
        key = 0 as *mut crate::sshkey::sshkey;
        r = sshpkt_get_string_direct(ssh, &mut blob, &mut blen);
        if r != 0 as libc::c_int || {
            r = sshkey_from_blob(blob, blen, &mut key);
            r != 0 as libc::c_int
        } {
            crate::log::sshlog(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"server_input_hostkeys_prove\0",
                ))
                .as_ptr(),
                699 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"parse key\0" as *const u8 as *const libc::c_char,
            );
            current_block = 8873184364881414274;
            break;
        } else {
            ndx = ((*(*ssh).kex).host_key_index).expect("non-null function pointer")(
                key,
                1 as libc::c_int,
                ssh,
            );
            if ndx == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"serverloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                        b"server_input_hostkeys_prove\0",
                    ))
                    .as_ptr(),
                    707 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"unknown host %s key\0" as *const u8 as *const libc::c_char,
                    crate::sshkey::sshkey_type(key),
                );
                current_block = 8873184364881414274;
                break;
            } else {
                key_prv = get_hostkey_by_index(ndx);
                if key_prv.is_null() && {
                    key_pub = get_hostkey_public_by_index(ndx, ssh);
                    key_pub.is_null()
                } {
                    crate::log::sshlog(
                        b"serverloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                            b"server_input_hostkeys_prove\0",
                        ))
                        .as_ptr(),
                        716 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"can't retrieve hostkey %d\0" as *const u8 as *const libc::c_char,
                        ndx,
                    );
                    current_block = 8873184364881414274;
                    break;
                } else {
                    crate::sshbuf::sshbuf_reset(sigbuf);
                    libc::free(sig as *mut libc::c_void);
                    sig = 0 as *mut u_char;
                    sigalg = 0 as *const libc::c_char;
                    if sshkey_type_plain((*key).type_0) == KEY_RSA as libc::c_int {
                        if !kex_rsa_sigalg.is_null() {
                            sigalg = kex_rsa_sigalg;
                        } else if (*(*ssh).kex).flags & 0x10 as libc::c_int as libc::c_uint != 0 {
                            sigalg = b"rsa-sha2-512\0" as *const u8 as *const libc::c_char;
                        } else if (*(*ssh).kex).flags & 0x8 as libc::c_int as libc::c_uint != 0 {
                            sigalg = b"rsa-sha2-256\0" as *const u8 as *const libc::c_char;
                        }
                    }
                    crate::log::sshlog(
                        b"serverloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                            b"server_input_hostkeys_prove\0",
                        ))
                        .as_ptr(),
                        736 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"sign %s key (index %d) using sigalg %s\0" as *const u8
                            as *const libc::c_char,
                        crate::sshkey::sshkey_type(key),
                        ndx,
                        if sigalg.is_null() {
                            b"default\0" as *const u8 as *const libc::c_char
                        } else {
                            sigalg
                        },
                    );
                    r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
                        sigbuf,
                        b"hostkeys-prove-00@openssh.com\0" as *const u8 as *const libc::c_char,
                    );
                    if !(r != 0 as libc::c_int
                        || {
                            r = sshbuf_put_stringb(sigbuf, (*(*ssh).kex).session_id);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = sshkey_puts(key, sigbuf);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = ((*(*ssh).kex).sign).expect("non-null function pointer")(
                                ssh,
                                key_prv,
                                key_pub,
                                &mut sig,
                                &mut slen,
                                crate::sshbuf::sshbuf_ptr(sigbuf),
                                crate::sshbuf::sshbuf_len(sigbuf),
                                sigalg,
                            );
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_string(
                                resp,
                                sig as *const libc::c_void,
                                slen,
                            );
                            r != 0 as libc::c_int
                        })
                    {
                        continue;
                    }
                    crate::log::sshlog(
                        b"serverloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                            b"server_input_hostkeys_prove\0",
                        ))
                        .as_ptr(),
                        745 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"assemble signature\0" as *const u8 as *const libc::c_char,
                    );
                    current_block = 8873184364881414274;
                    break;
                }
            }
        }
    }
    match current_block {
        11057878835866523405 => {
            *respp = resp;
            resp = 0 as *mut crate::sshbuf::sshbuf;
            success = 1 as libc::c_int;
        }
        _ => {}
    }
    libc::free(sig as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(resp);
    crate::sshbuf::sshbuf_free(sigbuf);
    crate::sshkey::sshkey_free(key);
    return success;
}
unsafe extern "C" fn server_input_global_request(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut rtype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut want_reply: u_char = 0 as libc::c_int as u_char;
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut allocated_listen_port: libc::c_int = 0 as libc::c_int;
    let mut port: u_int = 0 as libc::c_int as u_int;
    let mut resp: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut pw: *mut libc::passwd = (*the_authctxt).pw;
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
    memset(
        &mut fwd as *mut Forward as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<Forward>() as libc::c_ulong,
    );
    if pw.is_null() || (*the_authctxt).valid == 0 {
        sshfatal(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"server_input_global_request\0",
            ))
            .as_ptr(),
            774 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no/invalid user\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshpkt_get_cstring(ssh, &mut rtype, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = sshpkt_get_u8(ssh, &mut want_reply);
        r != 0 as libc::c_int
    } {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"server_input_global_request\0",
            ))
            .as_ptr(),
        );
    }
    crate::log::sshlog(
        b"serverloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
            b"server_input_global_request\0",
        ))
        .as_ptr(),
        779 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"rtype %s want_reply %d\0" as *const u8 as *const libc::c_char,
        rtype,
        want_reply as libc::c_int,
    );
    if libc::strcmp(
        rtype,
        b"tcpip-forward\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        r = sshpkt_get_cstring(ssh, &mut fwd.listen_host, 0 as *mut size_t);
        if r != 0 as libc::c_int || {
            r = sshpkt_get_u32(ssh, &mut port);
            r != 0 as libc::c_int
        } {
            sshpkt_fatal(
                ssh,
                r,
                b"%s: parse tcpip-forward\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"server_input_global_request\0",
                ))
                .as_ptr(),
            );
        }
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"server_input_global_request\0",
            ))
            .as_ptr(),
            787 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"tcpip-forward listen %s port %u\0" as *const u8 as *const libc::c_char,
            fwd.listen_host,
            port,
        );
        if port <= 2147483647 as libc::c_int as libc::c_uint {
            fwd.listen_port = port as libc::c_int;
        }
        if port > 2147483647 as libc::c_int as libc::c_uint
            || options.allow_tcp_forwarding & 1 as libc::c_int == 0 as libc::c_int
            || (*auth_opts).permit_port_forwarding_flag == 0
            || options.disable_forwarding != 0
            || want_reply == 0 && fwd.listen_port == 0 as libc::c_int
            || fwd.listen_port != 0 as libc::c_int
                && bind_permitted(fwd.listen_port, (*pw).pw_uid) == 0
        {
            success = 0 as libc::c_int;
            ssh_packet_send_debug(
                ssh,
                b"Server has disabled port forwarding.\0" as *const u8 as *const libc::c_char,
            );
        } else {
            success = channel_setup_remote_fwd_listener(
                ssh,
                &mut fwd,
                &mut allocated_listen_port,
                &mut options.fwd_opts,
            );
        }
        resp = crate::sshbuf::sshbuf_new();
        if resp.is_null() {
            sshfatal(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"server_input_global_request\0",
                ))
                .as_ptr(),
                806 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::crate::sshbuf::sshbuf::sshbuf_new\0" as *const u8 as *const libc::c_char,
            );
        }
        if allocated_listen_port != 0 as libc::c_int && {
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                resp,
                allocated_listen_port as u_int32_t,
            );
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"server_input_global_request\0",
                ))
                .as_ptr(),
                809 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"crate::sshbuf_getput_basic::sshbuf_put_u32\0" as *const u8 as *const libc::c_char,
            );
        }
    } else if libc::strcmp(
        rtype,
        b"cancel-tcpip-forward\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        r = sshpkt_get_cstring(ssh, &mut fwd.listen_host, 0 as *mut size_t);
        if r != 0 as libc::c_int || {
            r = sshpkt_get_u32(ssh, &mut port);
            r != 0 as libc::c_int
        } {
            sshpkt_fatal(
                ssh,
                r,
                b"%s: parse cancel-tcpip-forward\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"server_input_global_request\0",
                ))
                .as_ptr(),
            );
        }
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"server_input_global_request\0",
            ))
            .as_ptr(),
            816 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"cancel-tcpip-forward addr %s port %d\0" as *const u8 as *const libc::c_char,
            fwd.listen_host,
            port,
        );
        if port <= 2147483647 as libc::c_int as libc::c_uint {
            fwd.listen_port = port as libc::c_int;
            success = channel_cancel_rport_listener(ssh, &mut fwd);
        }
    } else if libc::strcmp(
        rtype,
        b"streamlocal-forward@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        r = sshpkt_get_cstring(ssh, &mut fwd.listen_path, 0 as *mut size_t);
        if r != 0 as libc::c_int {
            sshpkt_fatal(
                ssh,
                r,
                b"%s: parse streamlocal-forward@openssh.com\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"server_input_global_request\0",
                ))
                .as_ptr(),
            );
        }
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"server_input_global_request\0",
            ))
            .as_ptr(),
            825 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"streamlocal-forward listen path %s\0" as *const u8 as *const libc::c_char,
            fwd.listen_path,
        );
        if options.allow_streamlocal_forwarding & 1 as libc::c_int == 0 as libc::c_int
            || (*auth_opts).permit_port_forwarding_flag == 0
            || options.disable_forwarding != 0
            || (*pw).pw_uid != 0 as libc::c_int as libc::c_uint && use_privsep == 0
        {
            success = 0 as libc::c_int;
            ssh_packet_send_debug(
                ssh,
                b"Server has disabled streamlocal forwarding.\0" as *const u8
                    as *const libc::c_char,
            );
        } else {
            success = channel_setup_remote_fwd_listener(
                ssh,
                &mut fwd,
                0 as *mut libc::c_int,
                &mut options.fwd_opts,
            );
        }
    } else if libc::strcmp(
        rtype,
        b"cancel-streamlocal-forward@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        r = sshpkt_get_cstring(ssh, &mut fwd.listen_path, 0 as *mut size_t);
        if r != 0 as libc::c_int {
            sshpkt_fatal(
                ssh,
                r,
                b"%s: parse cancel-streamlocal-forward@openssh.com\0" as *const u8
                    as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"server_input_global_request\0",
                ))
                .as_ptr(),
            );
        }
        crate::log::sshlog(
            b"serverloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"server_input_global_request\0",
            ))
            .as_ptr(),
            844 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"cancel-streamlocal-forward path %s\0" as *const u8 as *const libc::c_char,
            fwd.listen_path,
        );
        success = channel_cancel_rport_listener(ssh, &mut fwd);
    } else if libc::strcmp(
        rtype,
        b"no-more-sessions@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        no_more_sessions = 1 as libc::c_int;
        success = 1 as libc::c_int;
    } else if libc::strcmp(
        rtype,
        b"hostkeys-prove-00@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        success = server_input_hostkeys_prove(ssh, &mut resp);
    }
    if want_reply != 0 {
        r = sshpkt_start(
            ssh,
            (if success != 0 {
                81 as libc::c_int
            } else {
                82 as libc::c_int
            }) as u_char,
        );
        if r != 0 as libc::c_int
            || success != 0 && !resp.is_null() && {
                r = sshpkt_putb(ssh, resp);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_send(ssh);
                r != 0 as libc::c_int
            }
            || {
                r = crate::packet::ssh_packet_write_wait(ssh);
                r != 0 as libc::c_int
            }
        {
            sshpkt_fatal(
                ssh,
                r,
                b"%s: send reply\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"server_input_global_request\0",
                ))
                .as_ptr(),
            );
        }
    }
    libc::free(fwd.listen_host as *mut libc::c_void);
    libc::free(fwd.listen_path as *mut libc::c_void);
    libc::free(rtype as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(resp);
    return 0 as libc::c_int;
}
unsafe extern "C" fn server_input_channel_req(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut rtype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut want_reply: u_char = 0 as libc::c_int as u_char;
    let mut id: u_int = 0 as libc::c_int as u_int;
    r = sshpkt_get_u32(ssh, &mut id);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_get_cstring(ssh, &mut rtype, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_u8(ssh, &mut want_reply);
            r != 0 as libc::c_int
        }
    {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"server_input_channel_req\0",
            ))
            .as_ptr(),
        );
    }
    crate::log::sshlog(
        b"serverloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"server_input_channel_req\0"))
            .as_ptr(),
        884 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"server_input_channel_req: channel %u request %s reply %d\0" as *const u8
            as *const libc::c_char,
        id,
        rtype,
        want_reply as libc::c_int,
    );
    if id >= 2147483647 as libc::c_int as libc::c_uint || {
        c = channel_lookup(ssh, id as libc::c_int);
        c.is_null()
    } {
        ssh_packet_disconnect(
            ssh,
            b"%s: unknown channel %d\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"server_input_channel_req\0",
            ))
            .as_ptr(),
            id,
        );
    }
    if libc::strcmp(
        rtype,
        b"eow@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0
    {
        r = sshpkt_get_end(ssh);
        if r != 0 as libc::c_int {
            sshpkt_fatal(
                ssh,
                r,
                b"%s: parse packet\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"server_input_channel_req\0",
                ))
                .as_ptr(),
            );
        }
        chan_rcvd_eow(ssh, c);
    } else if ((*c).type_0 == 10 as libc::c_int || (*c).type_0 == 4 as libc::c_int)
        && libc::strcmp((*c).ctype, b"session\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
    {
        success = session_input_channel_req(ssh, c, rtype);
    }
    if want_reply as libc::c_int != 0 && (*c).flags & 0x1 as libc::c_int == 0 {
        if (*c).have_remote_id == 0 {
            sshfatal(
                b"serverloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"server_input_channel_req\0",
                ))
                .as_ptr(),
                899 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"channel %d: no remote_id\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
        r = sshpkt_start(
            ssh,
            (if success != 0 {
                99 as libc::c_int
            } else {
                100 as libc::c_int
            }) as u_char,
        );
        if r != 0 as libc::c_int
            || {
                r = sshpkt_put_u32(ssh, (*c).remote_id);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_send(ssh);
                r != 0 as libc::c_int
            }
        {
            sshpkt_fatal(
                ssh,
                r,
                b"%s: send reply\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"server_input_channel_req\0",
                ))
                .as_ptr(),
            );
        }
    }
    libc::free(rtype as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn server_init_dispatch(mut ssh: *mut ssh) {
    crate::log::sshlog(
        b"serverloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"server_init_dispatch\0"))
            .as_ptr(),
        913 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"server_init_dispatch\0" as *const u8 as *const libc::c_char,
    );
    crate::dispatch::ssh_dispatch_init(
        ssh,
        Some(
            dispatch_protocol_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        97 as libc::c_int,
        Some(
            channel_input_oclose
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        94 as libc::c_int,
        Some(
            channel_input_data
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        96 as libc::c_int,
        Some(
            channel_input_ieof
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        95 as libc::c_int,
        Some(
            channel_input_extended_data
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        90 as libc::c_int,
        Some(
            server_input_channel_open
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        91 as libc::c_int,
        Some(
            channel_input_open_confirmation
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        92 as libc::c_int,
        Some(
            channel_input_open_failure
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        98 as libc::c_int,
        Some(
            server_input_channel_req
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        93 as libc::c_int,
        Some(
            channel_input_window_adjust
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        80 as libc::c_int,
        Some(
            server_input_global_request
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        99 as libc::c_int,
        Some(
            server_input_keep_alive
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        100 as libc::c_int,
        Some(
            server_input_keep_alive
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        81 as libc::c_int,
        Some(
            server_input_keep_alive
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        82 as libc::c_int,
        Some(
            server_input_keep_alive
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        20 as libc::c_int,
        Some(
            kex_input_kexinit
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
}
