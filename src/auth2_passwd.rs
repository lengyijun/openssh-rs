use ::libc;
extern "C" {
    pub type ssh_channels;
    pub type sshbuf;
    pub type ec_key_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type kex;
    pub type session_state;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn sshpkt_get_end(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_get_cstring(
        ssh: *mut ssh,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshpkt_get_u8(ssh: *mut ssh, valp: *mut u_char) -> libc::c_int;
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
    fn auth_password(_: *mut ssh, _: *const libc::c_char) -> libc::c_int;
    static mut use_privsep: libc::c_int;
    fn mm_auth_password(_: *mut ssh, _: *mut libc::c_char) -> libc::c_int;
    static mut options: ServerOptions;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __socklen_t = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
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
pub type uint8_t = __uint8_t;
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
    pub private_keys: C2RustUnnamed_1,
    pub public_keys: C2RustUnnamed,
    pub authctxt: *mut libc::c_void,
    pub chanctxt: *mut ssh_channels,
    pub app_data: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct key_entry {
    pub next: C2RustUnnamed_0,
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
pub struct Authmethod {
    pub name: *mut libc::c_char,
    pub synonym: *mut libc::c_char,
    pub userauth: Option<unsafe extern "C" fn(*mut ssh, *const libc::c_char) -> libc::c_int>,
    pub enabled: *mut libc::c_int,
}
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
unsafe extern "C" fn userauth_passwd(
    mut ssh: *mut ssh,
    mut _method: *const libc::c_char,
) -> libc::c_int {
    let mut password: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut authenticated: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    let mut change: u_char = 0;
    let mut len: size_t = 0 as libc::c_int as size_t;
    r = sshpkt_get_u8(ssh, &mut change);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_get_cstring(ssh, &mut password, &mut len);
            r != 0 as libc::c_int
        }
        || change as libc::c_int != 0 && {
            r = sshpkt_get_cstring(ssh, 0 as *mut *mut libc::c_char, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        freezero(password as *mut libc::c_void, len);
        sshfatal(
            b"auth2-libc::passwd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_passwd\0"))
                .as_ptr(),
            64 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse packet\0" as *const u8 as *const libc::c_char,
        );
    }
    if change != 0 {
        crate::log::sshlog(
            b"auth2-libc::passwd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_passwd\0"))
                .as_ptr(),
            68 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"password change not supported\0" as *const u8 as *const libc::c_char,
        );
    } else if (if use_privsep != 0 {
        mm_auth_password(ssh, password)
    } else {
        auth_password(ssh, password)
    }) == 1 as libc::c_int
    {
        authenticated = 1 as libc::c_int;
    }
    freezero(password as *mut libc::c_void, len);
    return authenticated;
}
pub static mut method_passwd: Authmethod = Authmethod {
    name: 0 as *const libc::c_char as *mut libc::c_char,
    synonym: 0 as *const libc::c_char as *mut libc::c_char,
    userauth: None,
    enabled: 0 as *const libc::c_int as *mut libc::c_int,
};
unsafe extern "C" fn run_static_initializers() {
    method_passwd = {
        let mut init = Authmethod {
            name: b"password\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            synonym: 0 as *mut libc::c_char,
            userauth: Some(
                userauth_passwd
                    as unsafe extern "C" fn(*mut ssh, *const libc::c_char) -> libc::c_int,
            ),
            enabled: &mut options.password_authentication,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
