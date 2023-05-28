use ::libc;
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
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn getpwnam(__name: *const libc::c_char) -> *mut libc::passwd;
    fn platform_locked_account(_: *mut libc::passwd) -> libc::c_int;
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
    fn arc4random_uniform(_: uint32_t) -> uint32_t;

    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;

    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn xasprintf(_: *mut *mut libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn match_user(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn ga_init(_: *const libc::c_char, _: gid_t) -> libc::c_int;
    fn ga_match(_: *const *mut libc::c_char, _: libc::c_int) -> libc::c_int;
    fn ga_free();
    fn log_change_level(_: LogLevel) -> libc::c_int;
    fn log_verbose_add(_: *const libc::c_char);
    fn log_verbose_reset();
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
    fn sshbuf_new() -> *mut sshbuf;
    fn sshbuf_reset(buf: *mut sshbuf);
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_get_cstring(
        buf: *mut sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn tilde_expand_filename(_: *const libc::c_char, _: uid_t) -> *mut libc::c_char;
    fn percent_expand(_: *const libc::c_char, _: ...) -> *mut libc::c_char;
    fn lowercase(s: *mut libc::c_char);
    fn format_absolute_time(_: uint64_t, _: *mut libc::c_char, _: size_t);
    fn path_absolute(_: *const libc::c_char) -> libc::c_int;
    fn pwcopy(_: *mut libc::passwd) -> *mut libc::passwd;
    fn get_connection_info(_: *mut ssh, _: libc::c_int, _: libc::c_int) -> *mut connection_info;
    fn process_permitopen(ssh: *mut ssh, options_0: *mut ServerOptions);
    fn parse_server_match_config(
        _: *mut ServerOptions,
        includes_0: *mut include_list,
        _: *mut connection_info,
    );
    fn sshkey_fingerprint(_: *const sshkey, _: libc::c_int, _: sshkey_fp_rep) -> *mut libc::c_char;
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_is_cert(_: *const sshkey) -> libc::c_int;
    fn init_hostkeys() -> *mut hostkeys;
    fn load_hostkeys(_: *mut hostkeys, _: *const libc::c_char, _: *const libc::c_char, _: u_int);
    fn free_hostkeys(_: *mut hostkeys);
    fn check_key_in_hostkeys(
        _: *mut hostkeys,
        _: *mut sshkey,
        _: *mut *const hostkey_entry,
    ) -> HostStatus;
    fn record_failed_login(
        _: *mut ssh,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
    );
    fn sshauthopt_new() -> *mut sshauthopt;
    fn sshauthopt_free(opts: *mut sshauthopt);
    fn sshauthopt_merge(
        primary: *const sshauthopt,
        additional: *const sshauthopt,
        errstrp: *mut *const libc::c_char,
    ) -> *mut sshauthopt;
    fn ipv64_normalise_mapped(_: *mut sockaddr_storage, _: *mut socklen_t);
    fn temporarily_use_uid(_: *mut libc::passwd);
    fn restore_uid();
    fn ssh_packet_get_connection_in(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_disconnect(_: *mut ssh, fmt: *const libc::c_char, _: ...) -> !;
    fn ssh_packet_send_debug(_: *mut ssh, fmt: *const libc::c_char, _: ...);
    fn ssh_remote_ipaddr(_: *mut ssh) -> *const libc::c_char;
    fn ssh_remote_port(_: *mut ssh) -> libc::c_int;
    fn sshkey_check_revoked(
        key: *mut sshkey,
        revoked_keys_file: *const libc::c_char,
    ) -> libc::c_int;
    static mut use_privsep: libc::c_int;
    fn mm_is_monitor() -> libc::c_int;
    static mut options: ServerOptions;
    static mut includes: include_list;
    static mut privsep_pw: *mut libc::passwd;
    static mut auth_opts: *mut sshauthopt;
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
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type gid_t = __gid_t;
pub type mode_t = __mode_t;
pub type uid_t = __uid_t;
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
pub struct ForwardOptions {
    pub gateway_ports: libc::c_int,
    pub streamlocal_bind_mask: mode_t,
    pub streamlocal_bind_unlink: libc::c_int,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct connection_info {
    pub user: *const libc::c_char,
    pub host: *const libc::c_char,
    pub address: *const libc::c_char,
    pub laddress: *const libc::c_char,
    pub lport: libc::c_int,
    pub rdomain: *const libc::c_char,
    pub test: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct include_item {
    pub selector: *mut libc::c_char,
    pub filename: *mut libc::c_char,
    pub contents: *mut sshbuf,
    pub entry: C2RustUnnamed_3,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
    pub tqe_next: *mut include_item,
    pub tqe_prev: *mut *mut include_item,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct include_list {
    pub tqh_first: *mut include_item,
    pub tqh_last: *mut *mut include_item,
}
pub type sshkey_fp_rep = libc::c_uint;
pub const SSH_FP_RANDOMART: sshkey_fp_rep = 4;
pub const SSH_FP_BUBBLEBABBLE: sshkey_fp_rep = 3;
pub const SSH_FP_BASE64: sshkey_fp_rep = 2;
pub const SSH_FP_HEX: sshkey_fp_rep = 1;
pub const SSH_FP_DEFAULT: sshkey_fp_rep = 0;
pub type HostStatus = libc::c_uint;
pub const HOST_FOUND: HostStatus = 4;
pub const HOST_REVOKED: HostStatus = 3;
pub const HOST_CHANGED: HostStatus = 2;
pub const HOST_NEW: HostStatus = 1;
pub const HOST_OK: HostStatus = 0;
pub type HostkeyMarker = libc::c_uint;
pub const MRK_CA: HostkeyMarker = 3;
pub const MRK_REVOKE: HostkeyMarker = 2;
pub const MRK_NONE: HostkeyMarker = 1;
pub const MRK_ERROR: HostkeyMarker = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostkey_entry {
    pub host: *mut libc::c_char,
    pub file: *mut libc::c_char,
    pub line: u_long,
    pub key: *mut sshkey,
    pub marker: HostkeyMarker,
    pub note: u_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostkeys {
    pub entries: *mut hostkey_entry,
    pub num_entries: u_int,
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
    pub loginmsg: *mut sshbuf,
    pub prev_keys: *mut *mut sshkey,
    pub nprev_keys: u_int,
    pub auth_method_key: *mut sshkey,
    pub auth_method_info: *mut libc::c_char,
    pub session_info: *mut sshbuf,
}
static mut auth_debug: *mut sshbuf = 0 as *const sshbuf as *mut sshbuf;
pub unsafe extern "C" fn allowed_user(mut ssh: *mut ssh, mut pw: *mut libc::passwd) -> libc::c_int {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut hostname: *const libc::c_char = 0 as *const libc::c_char;
    let mut ipaddr: *const libc::c_char = 0 as *const libc::c_char;
    let mut i: u_int = 0;
    let mut r: libc::c_int = 0;
    if pw.is_null() || ((*pw).pw_name).is_null() {
        return 0 as libc::c_int;
    }
    if options.use_pam == 0 && platform_locked_account(pw) != 0 {
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"allowed_user\0")).as_ptr(),
            113 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"User %.100s not allowed because account is locked\0" as *const u8
                as *const libc::c_char,
            (*pw).pw_name,
        );
        return 0 as libc::c_int;
    }
    if (options.chroot_directory).is_null()
        || strcasecmp(
            options.chroot_directory,
            b"none\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
    {
        let mut shell: *mut libc::c_char = xstrdup(
            if *((*pw).pw_shell).offset(0 as libc::c_int as isize) as libc::c_int == '\0' as i32 {
                b"/bin/sh\0" as *const u8 as *const libc::c_char
            } else {
                (*pw).pw_shell as *const libc::c_char
            },
        );
        if libc::stat(shell, &mut st) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"auth.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"allowed_user\0"))
                    .as_ptr(),
                128 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"User %.100s not allowed because shell %.100s does not exist\0" as *const u8
                    as *const libc::c_char,
                (*pw).pw_name,
                shell,
            );
            libc::free(shell as *mut libc::c_void);
            return 0 as libc::c_int;
        }
        if (st.st_mode & 0o170000 as libc::c_int as libc::c_uint
            == 0o100000 as libc::c_int as libc::c_uint) as libc::c_int
            == 0 as libc::c_int
            || st.st_mode
                & (0o100 as libc::c_int >> 3 as libc::c_int >> 3 as libc::c_int
                    | 0o100 as libc::c_int
                    | 0o100 as libc::c_int >> 3 as libc::c_int) as libc::c_uint
                == 0 as libc::c_int as libc::c_uint
        {
            crate::log::sshlog(
                b"auth.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"allowed_user\0"))
                    .as_ptr(),
                135 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"User %.100s not allowed because shell %.100s is not executable\0" as *const u8
                    as *const libc::c_char,
                (*pw).pw_name,
                shell,
            );
            libc::free(shell as *mut libc::c_void);
            return 0 as libc::c_int;
        }
        libc::free(shell as *mut libc::c_void);
    }
    if options.num_deny_users > 0 as libc::c_int as libc::c_uint
        || options.num_allow_users > 0 as libc::c_int as libc::c_uint
        || options.num_deny_groups > 0 as libc::c_int as libc::c_uint
        || options.num_allow_groups > 0 as libc::c_int as libc::c_uint
    {
        hostname = auth_get_canonical_hostname(ssh, options.use_dns);
        ipaddr = ssh_remote_ipaddr(ssh);
    }
    if options.num_deny_users > 0 as libc::c_int as libc::c_uint {
        i = 0 as libc::c_int as u_int;
        while i < options.num_deny_users {
            r = match_user(
                (*pw).pw_name,
                hostname,
                ipaddr,
                *(options.deny_users).offset(i as isize),
            );
            if r < 0 as libc::c_int {
                sshfatal(
                    b"auth.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"allowed_user\0"))
                        .as_ptr(),
                    155 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Invalid DenyUsers pattern \"%.100s\"\0" as *const u8 as *const libc::c_char,
                    *(options.deny_users).offset(i as isize),
                );
            } else if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"auth.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"allowed_user\0"))
                        .as_ptr(),
                    159 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"User %.100s from %.100s not allowed because listed in DenyUsers\0"
                        as *const u8 as *const libc::c_char,
                    (*pw).pw_name,
                    hostname,
                );
                return 0 as libc::c_int;
            }
            i = i.wrapping_add(1);
            i;
        }
    }
    if options.num_allow_users > 0 as libc::c_int as libc::c_uint {
        i = 0 as libc::c_int as u_int;
        while i < options.num_allow_users {
            r = match_user(
                (*pw).pw_name,
                hostname,
                ipaddr,
                *(options.allow_users).offset(i as isize),
            );
            if r < 0 as libc::c_int {
                sshfatal(
                    b"auth.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"allowed_user\0"))
                        .as_ptr(),
                    171 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Invalid AllowUsers pattern \"%.100s\"\0" as *const u8 as *const libc::c_char,
                    *(options.allow_users).offset(i as isize),
                );
            } else {
                if r == 1 as libc::c_int {
                    break;
                }
                i = i.wrapping_add(1);
                i;
            }
        }
        if i >= options.num_allow_users {
            crate::log::sshlog(
                b"auth.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"allowed_user\0"))
                    .as_ptr(),
                178 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"User %.100s from %.100s not allowed because not listed in AllowUsers\0"
                    as *const u8 as *const libc::c_char,
                (*pw).pw_name,
                hostname,
            );
            return 0 as libc::c_int;
        }
    }
    if options.num_deny_groups > 0 as libc::c_int as libc::c_uint
        || options.num_allow_groups > 0 as libc::c_int as libc::c_uint
    {
        if ga_init((*pw).pw_name, (*pw).pw_gid) == 0 as libc::c_int {
            crate::log::sshlog(
                b"auth.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"allowed_user\0"))
                    .as_ptr(),
                186 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"User %.100s from %.100s not allowed because not in any group\0" as *const u8
                    as *const libc::c_char,
                (*pw).pw_name,
                hostname,
            );
            return 0 as libc::c_int;
        }
        if options.num_deny_groups > 0 as libc::c_int as libc::c_uint {
            if ga_match(options.deny_groups, options.num_deny_groups as libc::c_int) != 0 {
                ga_free();
                crate::log::sshlog(
                    b"auth.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"allowed_user\0"))
                        .as_ptr(),
                    197 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"User %.100s from %.100s not allowed because a group is listed in DenyGroups\0"
                        as *const u8 as *const libc::c_char,
                    (*pw).pw_name,
                    hostname,
                );
                return 0 as libc::c_int;
            }
        }
        if options.num_allow_groups > 0 as libc::c_int as libc::c_uint {
            if ga_match(
                options.allow_groups,
                options.num_allow_groups as libc::c_int,
            ) == 0
            {
                ga_free();
                crate::log::sshlog(
                    b"auth.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<
                        &[u8; 13],
                        &[libc::c_char; 13],
                    >(b"allowed_user\0"))
                        .as_ptr(),
                    210 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"User %.100s from %.100s not allowed because none of user's groups are listed in AllowGroups\0"
                        as *const u8 as *const libc::c_char,
                    (*pw).pw_name,
                    hostname,
                );
                return 0 as libc::c_int;
            }
        }
        ga_free();
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn format_method_key(mut authctxt: *mut Authctxt) -> *mut libc::c_char {
    let mut key: *const sshkey = (*authctxt).auth_method_key;
    let mut methinfo: *const libc::c_char = (*authctxt).auth_method_info;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cafp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    if key.is_null() {
        return 0 as *mut libc::c_char;
    }
    if sshkey_is_cert(key) != 0 {
        fp = sshkey_fingerprint(key, options.fingerprint_hash, SSH_FP_DEFAULT);
        cafp = sshkey_fingerprint(
            (*(*key).cert).signature_key,
            options.fingerprint_hash,
            SSH_FP_DEFAULT,
        );
        xasprintf(
            &mut ret as *mut *mut libc::c_char,
            b"%s %s ID %s (serial %llu) CA %s %s%s%s\0" as *const u8 as *const libc::c_char,
            sshkey_type(key),
            if fp.is_null() {
                b"(null)\0" as *const u8 as *const libc::c_char
            } else {
                fp as *const libc::c_char
            },
            (*(*key).cert).key_id,
            (*(*key).cert).serial as libc::c_ulonglong,
            sshkey_type((*(*key).cert).signature_key),
            if cafp.is_null() {
                b"(null)\0" as *const u8 as *const libc::c_char
            } else {
                cafp as *const libc::c_char
            },
            if methinfo.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b", \0" as *const u8 as *const libc::c_char
            },
            if methinfo.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                methinfo
            },
        );
        libc::free(fp as *mut libc::c_void);
        libc::free(cafp as *mut libc::c_void);
    } else {
        fp = sshkey_fingerprint(key, options.fingerprint_hash, SSH_FP_DEFAULT);
        xasprintf(
            &mut ret as *mut *mut libc::c_char,
            b"%s %s%s%s\0" as *const u8 as *const libc::c_char,
            sshkey_type(key),
            if fp.is_null() {
                b"(null)\0" as *const u8 as *const libc::c_char
            } else {
                fp as *const libc::c_char
            },
            if methinfo.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b", \0" as *const u8 as *const libc::c_char
            },
            if methinfo.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                methinfo
            },
        );
        libc::free(fp as *mut libc::c_void);
    }
    return ret;
}
pub unsafe extern "C" fn auth_log(
    mut ssh: *mut ssh,
    mut authenticated: libc::c_int,
    mut partial: libc::c_int,
    mut method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut level: libc::c_int = SYSLOG_LEVEL_VERBOSE as libc::c_int;
    let mut authmsg: *const libc::c_char = 0 as *const libc::c_char;
    let mut extra: *mut libc::c_char = 0 as *mut libc::c_char;
    if use_privsep != 0 && mm_is_monitor() == 0 && (*authctxt).postponed == 0 {
        return;
    }
    if authenticated == 1 as libc::c_int
        || (*authctxt).valid == 0
        || (*authctxt).failures >= options.max_authtries / 2 as libc::c_int
        || strcmp(method, b"password\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        level = SYSLOG_LEVEL_INFO as libc::c_int;
    }
    if (*authctxt).postponed != 0 {
        authmsg = b"Postponed\0" as *const u8 as *const libc::c_char;
    } else if partial != 0 {
        authmsg = b"Partial\0" as *const u8 as *const libc::c_char;
    } else {
        authmsg = if authenticated != 0 {
            b"Accepted\0" as *const u8 as *const libc::c_char
        } else {
            b"Failed\0" as *const u8 as *const libc::c_char
        };
    }
    extra = format_method_key(authctxt);
    if extra.is_null() {
        if !((*authctxt).auth_method_info).is_null() {
            extra = xstrdup((*authctxt).auth_method_info);
        }
    }
    crate::log::sshlog(
        b"auth.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"auth_log\0")).as_ptr(),
        306 as libc::c_int,
        0 as libc::c_int,
        level as LogLevel,
        0 as *const libc::c_char,
        b"%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s\0" as *const u8
            as *const libc::c_char,
        authmsg,
        method,
        if !submethod.is_null() {
            b"/\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if submethod.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            submethod
        },
        if (*authctxt).valid != 0 {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b"invalid user \0" as *const u8 as *const libc::c_char
        },
        (*authctxt).user,
        ssh_remote_ipaddr(ssh),
        ssh_remote_port(ssh),
        if !extra.is_null() {
            b": \0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !extra.is_null() {
            extra as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    libc::free(extra as *mut libc::c_void);
    if authenticated == 0 as libc::c_int && !((*authctxt).postponed != 0 || partial != 0) {
        if strcmp(method, b"password\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            || strncmp(
                method,
                b"keyboard-interactive\0" as *const u8 as *const libc::c_char,
                20 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
            || strcmp(
                method,
                b"challenge-response\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            record_failed_login(
                ssh,
                (*authctxt).user,
                auth_get_canonical_hostname(ssh, options.use_dns),
                b"ssh\0" as *const u8 as *const libc::c_char,
            );
        }
    }
}
pub unsafe extern "C" fn auth_maxtries_exceeded(mut ssh: *mut ssh) -> ! {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    crate::log::sshlog(
        b"auth.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"auth_maxtries_exceeded\0"))
            .as_ptr(),
        343 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"maximum authentication attempts exceeded for %s%.100s from %.200s port %d ssh2\0"
            as *const u8 as *const libc::c_char,
        if (*authctxt).valid != 0 {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b"invalid user \0" as *const u8 as *const libc::c_char
        },
        (*authctxt).user,
        ssh_remote_ipaddr(ssh),
        ssh_remote_port(ssh),
    );
    ssh_packet_disconnect(
        ssh,
        b"Too many authentication failures\0" as *const u8 as *const libc::c_char,
    );
}
pub unsafe extern "C" fn auth_root_allowed(
    mut ssh: *mut ssh,
    mut method: *const libc::c_char,
) -> libc::c_int {
    match options.permit_root_login {
        3 => return 1 as libc::c_int,
        2 => {
            if strcmp(method, b"publickey\0" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
                || strcmp(method, b"hostbased\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                || strcmp(
                    method,
                    b"gssapi-with-mic\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
            {
                return 1 as libc::c_int;
            }
        }
        1 => {
            if !((*auth_opts).force_command).is_null() {
                crate::log::sshlog(
                    b"auth.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"auth_root_allowed\0",
                    ))
                    .as_ptr(),
                    365 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"Root login accepted for forced command.\0" as *const u8
                        as *const libc::c_char,
                );
                return 1 as libc::c_int;
            }
        }
        _ => {}
    }
    crate::log::sshlog(
        b"auth.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"auth_root_allowed\0"))
            .as_ptr(),
        371 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"ROOT LOGIN REFUSED FROM %.200s port %d\0" as *const u8 as *const libc::c_char,
        ssh_remote_ipaddr(ssh),
        ssh_remote_port(ssh),
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn expand_authorized_keys(
    mut filename: *const libc::c_char,
    mut pw: *mut libc::passwd,
) -> *mut libc::c_char {
    let mut file: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut uidstr: [libc::c_char; 32] = [0; 32];
    let mut ret: [libc::c_char; 4096] = [0; 4096];
    let mut i: libc::c_int = 0;
    libc::snprintf(
        uidstr.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
        b"%llu\0" as *const u8 as *const libc::c_char,
        (*pw).pw_uid as libc::c_ulonglong,
    );
    file = percent_expand(
        filename,
        b"h\0" as *const u8 as *const libc::c_char,
        (*pw).pw_dir,
        b"u\0" as *const u8 as *const libc::c_char,
        (*pw).pw_name,
        b"U\0" as *const u8 as *const libc::c_char,
        uidstr.as_mut_ptr(),
        0 as *mut libc::c_void as *mut libc::c_char,
    );
    if path_absolute(file) != 0 {
        return file;
    }
    i = libc::snprintf(
        ret.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 4096]>() as usize,
        b"%s/%s\0" as *const u8 as *const libc::c_char,
        (*pw).pw_dir,
        file,
    );
    if i < 0 as libc::c_int
        || i as size_t >= ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
    {
        sshfatal(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"expand_authorized_keys\0",
            ))
            .as_ptr(),
            403 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"expand_authorized_keys: path too long\0" as *const u8 as *const libc::c_char,
        );
    }
    libc::free(file as *mut libc::c_void);
    return xstrdup(ret.as_mut_ptr());
}
pub unsafe extern "C" fn authorized_principals_file(
    mut pw: *mut libc::passwd,
) -> *mut libc::c_char {
    if (options.authorized_principals_file).is_null() {
        return 0 as *mut libc::c_char;
    }
    return expand_authorized_keys(options.authorized_principals_file, pw);
}
pub unsafe extern "C" fn check_key_in_hostfiles(
    mut pw: *mut libc::passwd,
    mut key: *mut sshkey,
    mut host: *const libc::c_char,
    mut sysfile: *const libc::c_char,
    mut userfile: *const libc::c_char,
) -> HostStatus {
    let mut user_hostfile: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut host_status: HostStatus = HOST_OK;
    let mut hostkeys: *mut hostkeys = 0 as *mut hostkeys;
    let mut found: *const hostkey_entry = 0 as *const hostkey_entry;
    hostkeys = init_hostkeys();
    load_hostkeys(hostkeys, host, sysfile, 0 as libc::c_int as u_int);
    if !userfile.is_null() {
        user_hostfile = tilde_expand_filename(userfile, (*pw).pw_uid);
        if options.strict_modes != 0
            && libc::stat(user_hostfile, &mut st) == 0 as libc::c_int
            && (st.st_uid != 0 as libc::c_int as libc::c_uint && st.st_uid != (*pw).pw_uid
                || st.st_mode & 0o22 as libc::c_int as libc::c_uint
                    != 0 as libc::c_int as libc::c_uint)
        {
            crate::log::sshlog(
                b"auth.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"check_key_in_hostfiles\0",
                ))
                .as_ptr(),
                437 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Authentication refused for %.100s: bad owner or modes for %.200s\0" as *const u8
                    as *const libc::c_char,
                (*pw).pw_name,
                user_hostfile,
            );
            auth_debug_add(
                b"Ignored %.200s: bad ownership or modes\0" as *const u8 as *const libc::c_char,
                user_hostfile,
            );
        } else {
            temporarily_use_uid(pw);
            load_hostkeys(hostkeys, host, user_hostfile, 0 as libc::c_int as u_int);
            restore_uid();
        }
        libc::free(user_hostfile as *mut libc::c_void);
    }
    host_status = check_key_in_hostkeys(hostkeys, key, &mut found);
    if host_status as libc::c_uint == HOST_REVOKED as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"check_key_in_hostfiles\0",
            ))
            .as_ptr(),
            450 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"WARNING: revoked key for %s attempted authentication\0" as *const u8
                as *const libc::c_char,
            host,
        );
    } else if host_status as libc::c_uint == HOST_OK as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"check_key_in_hostfiles\0",
            ))
            .as_ptr(),
            453 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"key for %s found at %s:%ld\0" as *const u8 as *const libc::c_char,
            (*found).host,
            (*found).file,
            (*found).line,
        );
    } else {
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"check_key_in_hostfiles\0",
            ))
            .as_ptr(),
            455 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"key for host %s not found\0" as *const u8 as *const libc::c_char,
            host,
        );
    }
    free_hostkeys(hostkeys);
    return host_status;
}
pub unsafe extern "C" fn getpwnamallow(
    mut ssh: *mut ssh,
    mut user: *const libc::c_char,
) -> *mut libc::passwd {
    let mut pw: *mut libc::passwd = 0 as *mut libc::passwd;
    let mut ci: *mut connection_info = 0 as *mut connection_info;
    let mut i: u_int = 0;
    ci = get_connection_info(ssh, 1 as libc::c_int, options.use_dns);
    (*ci).user = user;
    parse_server_match_config(&mut options, &mut includes, ci);
    log_change_level(options.log_level);
    log_verbose_reset();
    i = 0 as libc::c_int as u_int;
    while i < options.num_log_verbose {
        log_verbose_add(*(options.log_verbose).offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    process_permitopen(ssh, &mut options);
    pw = getpwnam(user);
    if pw.is_null() {
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"getpwnamallow\0"))
                .as_ptr(),
            495 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Invalid user %.100s from %.100s port %d\0" as *const u8 as *const libc::c_char,
            user,
            ssh_remote_ipaddr(ssh),
            ssh_remote_port(ssh),
        );
        record_failed_login(
            ssh,
            user,
            auth_get_canonical_hostname(ssh, options.use_dns),
            b"ssh\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut libc::passwd;
    }
    if allowed_user(ssh, pw) == 0 {
        return 0 as *mut libc::passwd;
    }
    if !pw.is_null() {
        return pwcopy(pw);
    }
    return 0 as *mut libc::passwd;
}
pub unsafe extern "C" fn auth_key_is_revoked(mut key: *mut sshkey) -> libc::c_int {
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    if (options.revoked_keys_file).is_null() {
        return 0 as libc::c_int;
    }
    fp = sshkey_fingerprint(key, options.fingerprint_hash, SSH_FP_DEFAULT);
    if fp.is_null() {
        r = -(2 as libc::c_int);
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"auth_key_is_revoked\0"))
                .as_ptr(),
            539 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"fingerprint key\0" as *const u8 as *const libc::c_char,
        );
    } else {
        r = sshkey_check_revoked(key, options.revoked_keys_file);
        match r {
            0 => {
                r = 0 as libc::c_int;
            }
            -51 => {
                crate::log::sshlog(
                    b"auth.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"auth_key_is_revoked\0",
                    ))
                    .as_ptr(),
                    549 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Authentication key %s %s revoked by file %s\0" as *const u8
                        as *const libc::c_char,
                    sshkey_type(key),
                    fp,
                    options.revoked_keys_file,
                );
            }
            _ => {
                crate::log::sshlog(
                    b"auth.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"auth_key_is_revoked\0",
                    ))
                    .as_ptr(),
                    554 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"Error checking authentication key %s %s in revoked keys file %s\0"
                        as *const u8 as *const libc::c_char,
                    sshkey_type(key),
                    fp,
                    options.revoked_keys_file,
                );
            }
        }
    }
    libc::free(fp as *mut libc::c_void);
    return if r == 0 as libc::c_int {
        0 as libc::c_int
    } else {
        1 as libc::c_int
    };
}
pub unsafe extern "C" fn auth_debug_add(mut fmt: *const libc::c_char, mut args: ...) {
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut args_0: ::core::ffi::VaListImpl;
    let mut r: libc::c_int = 0;
    args_0 = args.clone();
    vsnprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        fmt,
        args_0.as_va_list(),
    );
    crate::log::sshlog(
        b"auth.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"auth_debug_add\0")).as_ptr(),
        576 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s\0" as *const u8 as *const libc::c_char,
        buf.as_mut_ptr(),
    );
    if !auth_debug.is_null() {
        r = sshbuf_put_cstring(auth_debug, buf.as_mut_ptr());
        if r != 0 as libc::c_int {
            sshfatal(
                b"auth.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"auth_debug_add\0"))
                    .as_ptr(),
                579 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"sshbuf_put_cstring\0" as *const u8 as *const libc::c_char,
            );
        }
    }
}
pub unsafe extern "C" fn auth_debug_send(mut ssh: *mut ssh) {
    let mut msg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    if auth_debug.is_null() {
        return;
    }
    while sshbuf_len(auth_debug) != 0 as libc::c_int as libc::c_ulong {
        r = sshbuf_get_cstring(auth_debug, &mut msg, 0 as *mut size_t);
        if r != 0 as libc::c_int {
            sshfatal(
                b"auth.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"auth_debug_send\0"))
                    .as_ptr(),
                592 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"sshbuf_get_cstring\0" as *const u8 as *const libc::c_char,
            );
        }
        ssh_packet_send_debug(ssh, b"%s\0" as *const u8 as *const libc::c_char, msg);
        libc::free(msg as *mut libc::c_void);
    }
}
pub unsafe extern "C" fn auth_debug_reset() {
    if !auth_debug.is_null() {
        sshbuf_reset(auth_debug);
    } else {
        auth_debug = sshbuf_new();
        if auth_debug.is_null() {
            sshfatal(
                b"auth.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"auth_debug_reset\0"))
                    .as_ptr(),
                604 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
            );
        }
    };
}
pub unsafe extern "C" fn fakepw() -> *mut libc::passwd {
    static mut done: libc::c_int = 0 as libc::c_int;
    static mut fake: libc::passwd = libc::passwd {
        pw_name: 0 as *const libc::c_char as *mut libc::c_char,
        pw_passwd: 0 as *const libc::c_char as *mut libc::c_char,
        pw_uid: 0,
        pw_gid: 0,
        pw_gecos: 0 as *const libc::c_char as *mut libc::c_char,
        pw_dir: 0 as *const libc::c_char as *mut libc::c_char,
        pw_shell: 0 as *const libc::c_char as *mut libc::c_char,
    };
    let hashchars: [libc::c_char; 65] = *::core::mem::transmute::<&[u8; 65], &[libc::c_char; 65]>(
        b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\0",
    );
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    if done != 0 {
        return &mut fake;
    }
    memset(
        &mut fake as *mut libc::passwd as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<libc::passwd>() as libc::c_ulong,
    );
    fake.pw_name = b"NOUSER\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    fake.pw_passwd = xstrdup(
        b"$2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\0" as *const u8
            as *const libc::c_char,
    );
    cp = (fake.pw_passwd).offset(7 as libc::c_int as isize);
    while *cp as libc::c_int != '\0' as i32 {
        *cp = hashchars[arc4random_uniform(
            (::core::mem::size_of::<[libc::c_char; 65]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as uint32_t,
        ) as usize];
        cp = cp.offset(1);
        cp;
    }
    fake.pw_gecos = b"NOUSER\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    fake.pw_uid = if privsep_pw.is_null() {
        -(1 as libc::c_int) as uid_t
    } else {
        (*privsep_pw).pw_uid
    };
    fake.pw_gid = if privsep_pw.is_null() {
        -(1 as libc::c_int) as gid_t
    } else {
        (*privsep_pw).pw_gid
    };
    fake.pw_dir = b"/nonexist\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    fake.pw_shell = b"/nonexist\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    done = 1 as libc::c_int;
    return &mut fake;
}
unsafe extern "C" fn remote_hostname(mut ssh: *mut ssh) -> *mut libc::c_char {
    let mut from: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut fromlen: socklen_t = 0;
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
    let mut name: [libc::c_char; 1025] = [0; 1025];
    let mut ntop2: [libc::c_char; 1025] = [0; 1025];
    let mut ntop: *const libc::c_char = ssh_remote_ipaddr(ssh);
    fromlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    memset(
        &mut from as *mut sockaddr_storage as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong,
    );
    if getpeername(
        ssh_packet_get_connection_in(ssh),
        __SOCKADDR_ARG {
            __sockaddr__: &mut from as *mut sockaddr_storage as *mut sockaddr,
        },
        &mut fromlen,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"remote_hostname\0"))
                .as_ptr(),
            662 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"getpeername failed: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        return xstrdup(ntop);
    }
    ipv64_normalise_mapped(&mut from, &mut fromlen);
    if from.ss_family as libc::c_int == 10 as libc::c_int {
        fromlen = ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong as socklen_t;
    }
    crate::log::sshlog(
        b"auth.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"remote_hostname\0")).as_ptr(),
        670 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Trying to reverse map address %.100s.\0" as *const u8 as *const libc::c_char,
        ntop,
    );
    if getnameinfo(
        &mut from as *mut sockaddr_storage as *mut sockaddr,
        fromlen,
        name.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as socklen_t,
        0 as *mut libc::c_char,
        0 as libc::c_int as socklen_t,
        8 as libc::c_int,
    ) != 0 as libc::c_int
    {
        return xstrdup(ntop);
    }
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_socktype = SOCK_DGRAM as libc::c_int;
    hints.ai_flags = 0x4 as libc::c_int;
    if getaddrinfo(
        name.as_mut_ptr(),
        0 as *const libc::c_char,
        &mut hints,
        &mut ai,
    ) == 0 as libc::c_int
    {
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"remote_hostname\0"))
                .as_ptr(),
            688 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Nasty PTR record \"%s\" is set up for %s, ignoring\0" as *const u8
                as *const libc::c_char,
            name.as_mut_ptr(),
            ntop,
        );
        freeaddrinfo(ai);
        return xstrdup(ntop);
    }
    lowercase(name.as_mut_ptr());
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_family = from.ss_family as libc::c_int;
    hints.ai_socktype = SOCK_STREAM as libc::c_int;
    if getaddrinfo(
        name.as_mut_ptr(),
        0 as *const libc::c_char,
        &mut hints,
        &mut aitop,
    ) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"remote_hostname\0"))
                .as_ptr(),
            710 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"reverse mapping checking getaddrinfo for %.700s [%s] failed.\0" as *const u8
                as *const libc::c_char,
            name.as_mut_ptr(),
            ntop,
        );
        return xstrdup(ntop);
    }
    ai = aitop;
    while !ai.is_null() {
        if getnameinfo(
            (*ai).ai_addr,
            (*ai).ai_addrlen,
            ntop2.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as socklen_t,
            0 as *mut libc::c_char,
            0 as libc::c_int as socklen_t,
            1 as libc::c_int,
        ) == 0 as libc::c_int
            && strcmp(ntop, ntop2.as_mut_ptr()) == 0 as libc::c_int
        {
            break;
        }
        ai = (*ai).ai_next;
    }
    freeaddrinfo(aitop);
    if ai.is_null() {
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"remote_hostname\0"))
                .as_ptr(),
            725 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Address %.100s maps to %.600s, but this does not map back to the address.\0"
                as *const u8 as *const libc::c_char,
            ntop,
            name.as_mut_ptr(),
        );
        return xstrdup(ntop);
    }
    return xstrdup(name.as_mut_ptr());
}
pub unsafe extern "C" fn auth_get_canonical_hostname(
    mut ssh: *mut ssh,
    mut use_dns: libc::c_int,
) -> *const libc::c_char {
    static mut dnsname: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
    if use_dns == 0 {
        return ssh_remote_ipaddr(ssh);
    } else if !dnsname.is_null() {
        return dnsname;
    } else {
        dnsname = remote_hostname(ssh);
        return dnsname;
    };
}
pub unsafe extern "C" fn auth_log_authopts(
    mut loc: *const libc::c_char,
    mut opts: *const sshauthopt,
    mut do_remote: libc::c_int,
) {
    let mut do_env: libc::c_int = (options.permit_user_env != 0
        && (*opts).nenv > 0 as libc::c_int as libc::c_ulong)
        as libc::c_int;
    let mut do_permitopen: libc::c_int = ((*opts).npermitopen > 0 as libc::c_int as libc::c_ulong
        && options.allow_tcp_forwarding & (1 as libc::c_int) << 1 as libc::c_int
            != 0 as libc::c_int) as libc::c_int;
    let mut do_permitlisten: libc::c_int = ((*opts).npermitlisten
        > 0 as libc::c_int as libc::c_ulong
        && options.allow_tcp_forwarding & 1 as libc::c_int != 0 as libc::c_int)
        as libc::c_int;
    let mut i: size_t = 0;
    let mut msg: [libc::c_char; 1024] = [0; 1024];
    let mut buf: [libc::c_char; 64] = [0; 64];
    libc::snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 64]>() as usize,
        b"%d\0" as *const u8 as *const libc::c_char,
        (*opts).force_tun_device,
    );
    libc::snprintf(
        msg.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
        b"key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\0" as *const u8 as *const libc::c_char,
        if (*opts).permit_agent_forwarding_flag != 0 {
            b" agent-forwarding\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if ((*opts).force_command).is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b" command\0" as *const u8 as *const libc::c_char
        },
        if do_env != 0 {
            b" environment\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if (*opts).valid_before == 0 as libc::c_int as libc::c_ulong {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b"expires\0" as *const u8 as *const libc::c_char
        },
        if (*opts).no_require_user_presence != 0 {
            b" no-touch-required\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if do_permitopen != 0 {
            b" permitopen\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if do_permitlisten != 0 {
            b" permitlisten\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if (*opts).permit_port_forwarding_flag != 0 {
            b" port-forwarding\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if ((*opts).cert_principals).is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b" principals\0" as *const u8 as *const libc::c_char
        },
        if (*opts).permit_pty_flag != 0 {
            b" pty\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if (*opts).require_verify != 0 {
            b" uv\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if (*opts).force_tun_device == -(1 as libc::c_int) {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b" tun=\0" as *const u8 as *const libc::c_char
        },
        if (*opts).force_tun_device == -(1 as libc::c_int) {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            buf.as_mut_ptr() as *const libc::c_char
        },
        if (*opts).permit_user_rc != 0 {
            b" user-rc\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if (*opts).permit_x11_forwarding_flag != 0 {
            b" x11-forwarding\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    crate::log::sshlog(
        b"auth.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"auth_log_authopts\0"))
            .as_ptr(),
        785 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"%s: %s\0" as *const u8 as *const libc::c_char,
        loc,
        msg.as_mut_ptr(),
    );
    if do_remote != 0 {
        auth_debug_add(
            b"%s: %s\0" as *const u8 as *const libc::c_char,
            loc,
            msg.as_mut_ptr(),
        );
    }
    if options.permit_user_env != 0 {
        i = 0 as libc::c_int as size_t;
        while i < (*opts).nenv {
            crate::log::sshlog(
                b"auth.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"auth_log_authopts\0"))
                    .as_ptr(),
                791 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"%s: environment: %s\0" as *const u8 as *const libc::c_char,
                loc,
                *((*opts).env).offset(i as isize),
            );
            if do_remote != 0 {
                auth_debug_add(
                    b"%s: environment: %s\0" as *const u8 as *const libc::c_char,
                    loc,
                    *((*opts).env).offset(i as isize),
                );
            }
            i = i.wrapping_add(1);
            i;
        }
    }
    if (*opts).valid_before != 0 as libc::c_int as libc::c_ulong {
        format_absolute_time(
            (*opts).valid_before,
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
        );
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"auth_log_authopts\0"))
                .as_ptr(),
            802 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s: expires at %s\0" as *const u8 as *const libc::c_char,
            loc,
            buf.as_mut_ptr(),
        );
    }
    if !((*opts).cert_principals).is_null() {
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"auth_log_authopts\0"))
                .as_ptr(),
            806 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s: authorized principals: \"%s\"\0" as *const u8 as *const libc::c_char,
            loc,
            (*opts).cert_principals,
        );
    }
    if !((*opts).force_command).is_null() {
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"auth_log_authopts\0"))
                .as_ptr(),
            809 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s: forced command: \"%s\"\0" as *const u8 as *const libc::c_char,
            loc,
            (*opts).force_command,
        );
    }
    if do_permitopen != 0 {
        i = 0 as libc::c_int as size_t;
        while i < (*opts).npermitopen {
            crate::log::sshlog(
                b"auth.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"auth_log_authopts\0"))
                    .as_ptr(),
                813 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"%s: permitted open: %s\0" as *const u8 as *const libc::c_char,
                loc,
                *((*opts).permitopen).offset(i as isize),
            );
            i = i.wrapping_add(1);
            i;
        }
    }
    if do_permitlisten != 0 {
        i = 0 as libc::c_int as size_t;
        while i < (*opts).npermitlisten {
            crate::log::sshlog(
                b"auth.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"auth_log_authopts\0"))
                    .as_ptr(),
                819 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"%s: permitted listen: %s\0" as *const u8 as *const libc::c_char,
                loc,
                *((*opts).permitlisten).offset(i as isize),
            );
            i = i.wrapping_add(1);
            i;
        }
    }
}
pub unsafe extern "C" fn auth_activate_options(
    mut _ssh: *mut ssh,
    mut opts: *mut sshauthopt,
) -> libc::c_int {
    let mut old: *mut sshauthopt = auth_opts;
    let mut emsg: *const libc::c_char = 0 as *const libc::c_char;
    crate::log::sshlog(
        b"auth.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth_activate_options\0"))
            .as_ptr(),
        831 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"setting new authentication options\0" as *const u8 as *const libc::c_char,
    );
    auth_opts = sshauthopt_merge(old, opts, &mut emsg);
    if auth_opts.is_null() {
        crate::log::sshlog(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth_activate_options\0"))
                .as_ptr(),
            833 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Inconsistent authentication options: %s\0" as *const u8 as *const libc::c_char,
            emsg,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn auth_restrict_session(mut ssh: *mut ssh) {
    let mut restricted: *mut sshauthopt = 0 as *mut sshauthopt;
    crate::log::sshlog(
        b"auth.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth_restrict_session\0"))
            .as_ptr(),
        845 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"restricting session\0" as *const u8 as *const libc::c_char,
    );
    restricted = sshauthopt_new();
    if restricted.is_null() {
        sshfatal(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth_restrict_session\0"))
                .as_ptr(),
            849 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshauthopt_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    (*restricted).permit_pty_flag = 1 as libc::c_int;
    (*restricted).restricted = 1 as libc::c_int;
    if auth_activate_options(ssh, restricted) != 0 as libc::c_int {
        sshfatal(
            b"auth.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth_restrict_session\0"))
                .as_ptr(),
            854 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"failed to restrict session\0" as *const u8 as *const libc::c_char,
        );
    }
    sshauthopt_free(restricted);
}
