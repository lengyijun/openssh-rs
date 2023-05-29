use crate::hmac::ssh_hmac_ctx;
use crate::kex::sshenc;
use crate::packet::session_state;
use crate::umac::umac_ctx;

use ::libc;
extern "C" {
    pub type ssh_channels;

    pub type ec_group_st;
    pub type dh_st;

    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn sshpkt_get_cstring(
        ssh: *mut ssh,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshpkt_get_string(ssh: *mut ssh, valp: *mut *mut u_char, lenp: *mut size_t) -> libc::c_int;
    fn ssh_remote_ipaddr(_: *mut ssh) -> *const libc::c_char;

    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
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

    fn sshkey_type_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_is_cert(_: *const crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_cert_check_authority_now(
        _: *const crate::sshkey::sshkey,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: *const libc::c_char,
        _: *mut *const libc::c_char,
    ) -> libc::c_int;
    fn sshkey_check_cert_sigtype(
        _: *const crate::sshkey::sshkey,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn sshkey_from_blob(
        _: *const u_char,
        _: size_t,
        _: *mut *mut crate::sshkey::sshkey,
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
    fn sshkey_check_rsa_length(_: *const crate::sshkey::sshkey, _: libc::c_int) -> libc::c_int;
    fn auth_rhosts2(
        _: *mut libc::passwd,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn auth2_record_key(_: *mut Authctxt, _: libc::c_int, _: *const crate::sshkey::sshkey);
    fn auth2_record_info(authctxt: *mut Authctxt, _: *const libc::c_char, _: ...);
    fn auth_get_canonical_hostname(_: *mut ssh, _: libc::c_int) -> *const libc::c_char;
    fn check_key_in_hostfiles(
        _: *mut libc::passwd,
        _: *mut crate::sshkey::sshkey,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> HostStatus;
    fn auth_key_is_revoked(_: *mut crate::sshkey::sshkey) -> libc::c_int;
    fn auth_debug_add(fmt: *const libc::c_char, _: ...);
    static mut use_privsep: libc::c_int;
    fn mm_hostbased_key_allowed(
        _: *mut ssh,
        _: *mut libc::passwd,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn mm_sshkey_verify(
        _: *const crate::sshkey::sshkey,
        _: *const u_char,
        _: size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: u_int,
        _: *mut *mut sshkey_sig_details,
    ) -> libc::c_int;
    fn match_pattern_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    static mut options: ServerOptions;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __mode_t = libc::c_uint;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
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
pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;

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
    pub key: *mut crate::sshkey::sshkey,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_sig_details {
    pub sk_counter: uint32_t,
    pub sk_flags: uint8_t,
}
pub type HostStatus = libc::c_uint;
pub const HOST_FOUND: HostStatus = 4;
pub const HOST_REVOKED: HostStatus = 3;
pub const HOST_CHANGED: HostStatus = 2;
pub const HOST_NEW: HostStatus = 1;
pub const HOST_OK: HostStatus = 0;
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
pub struct Authmethod {
    pub name: *mut libc::c_char,
    pub synonym: *mut libc::c_char,
    pub userauth: Option<unsafe extern "C" fn(*mut ssh, *const libc::c_char) -> libc::c_int>,
    pub enabled: *mut libc::c_int,
}
unsafe extern "C" fn userauth_hostbased(
    mut ssh: *mut ssh,
    mut method: *const libc::c_char,
) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut pkalg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cuser: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut chost: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pkblob: *mut u_char = 0 as *mut u_char;
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut alen: size_t = 0;
    let mut blen: size_t = 0;
    let mut slen: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut pktype: libc::c_int = 0;
    let mut authenticated: libc::c_int = 0 as libc::c_int;
    r = sshpkt_get_cstring(ssh, &mut pkalg, &mut alen);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_get_string(ssh, &mut pkblob, &mut blen);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_cstring(ssh, &mut chost, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_cstring(ssh, &mut cuser, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_string(ssh, &mut sig, &mut slen);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"userauth_hostbased\0"))
                .as_ptr(),
            75 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse packet\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"userauth_hostbased\0"))
            .as_ptr(),
        78 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"cuser %s chost %s pkalg %s slen %zu\0" as *const u8 as *const libc::c_char,
        cuser,
        chost,
        pkalg,
        slen,
    );
    pktype = sshkey_type_from_name(pkalg);
    if pktype == KEY_UNSPEC as libc::c_int {
        crate::log::sshlog(
            b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"userauth_hostbased\0"))
                .as_ptr(),
            87 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"unsupported public key algorithm: %s\0" as *const u8 as *const libc::c_char,
            pkalg,
        );
    } else {
        r = sshkey_from_blob(pkblob, blen, &mut key);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"userauth_hostbased\0",
                ))
                .as_ptr(),
                91 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"key_from_blob\0" as *const u8 as *const libc::c_char,
            );
        } else if key.is_null() {
            crate::log::sshlog(
                b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"userauth_hostbased\0",
                ))
                .as_ptr(),
                95 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"cannot decode key: %s\0" as *const u8 as *const libc::c_char,
                pkalg,
            );
        } else if (*key).type_0 != pktype {
            crate::log::sshlog(
                b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"userauth_hostbased\0",
                ))
                .as_ptr(),
                100 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"type mismatch for decoded key (received %d, expected %d)\0" as *const u8
                    as *const libc::c_char,
                (*key).type_0,
                pktype,
            );
        } else if match_pattern_list(pkalg, options.hostbased_accepted_algos, 0 as libc::c_int)
            != 1 as libc::c_int
        {
            crate::log::sshlog(
                b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"userauth_hostbased\0",
                ))
                .as_ptr(),
                105 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"signature algorithm %s not in HostbasedAcceptedAlgorithms\0" as *const u8
                    as *const libc::c_char,
                pkalg,
            );
        } else {
            r = sshkey_check_cert_sigtype(key, options.ca_sign_algorithms);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"userauth_hostbased\0",
                    ))
                    .as_ptr(),
                    112 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    ssh_err(r),
                    b"certificate signature algorithm %s\0" as *const u8 as *const libc::c_char,
                    if ((*key).cert).is_null() || ((*(*key).cert).signature_type).is_null() {
                        b"(null)\0" as *const u8 as *const libc::c_char
                    } else {
                        (*(*key).cert).signature_type as *const libc::c_char
                    },
                );
            } else {
                r = sshkey_check_rsa_length(key, options.required_rsa_size);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"userauth_hostbased\0",
                        ))
                        .as_ptr(),
                        117 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        ssh_err(r),
                        b"refusing %s key\0" as *const u8 as *const libc::c_char,
                        crate::sshkey::sshkey_type(key),
                    );
                } else if (*authctxt).valid == 0 || ((*authctxt).user).is_null() {
                    crate::log::sshlog(
                        b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"userauth_hostbased\0",
                        ))
                        .as_ptr(),
                        122 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"disabled because of invalid user\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    b = crate::sshbuf::sshbuf_new();
                    if b.is_null() {
                        sshfatal(
                            b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                b"userauth_hostbased\0",
                            ))
                            .as_ptr(),
                            127 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    r = sshbuf_put_stringb(b, (*(*ssh).kex).session_id);
                    if r != 0 as libc::c_int
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_u8(
                                b,
                                50 as libc::c_int as u_char,
                            );
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_cstring(b, (*authctxt).user);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
                                b,
                                (*authctxt).service,
                            );
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_cstring(b, method);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_string(
                                b,
                                pkalg as *const libc::c_void,
                                alen,
                            );
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_string(
                                b,
                                pkblob as *const libc::c_void,
                                blen,
                            );
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_cstring(b, chost);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_put_cstring(b, cuser);
                            r != 0 as libc::c_int
                        }
                    {
                        sshfatal(
                            b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                b"userauth_hostbased\0",
                            ))
                            .as_ptr(),
                            138 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"reconstruct packet\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    auth2_record_info(
                        authctxt,
                        b"client user \"%.100s\", client host \"%.100s\"\0" as *const u8
                            as *const libc::c_char,
                        cuser,
                        chost,
                    );
                    authenticated = 0 as libc::c_int;
                    if (if use_privsep != 0 {
                        mm_hostbased_key_allowed(ssh, (*authctxt).pw, cuser, chost, key)
                    } else {
                        hostbased_key_allowed(ssh, (*authctxt).pw, cuser, chost, key)
                    }) != 0
                        && (if use_privsep != 0 {
                            mm_sshkey_verify(
                                key,
                                sig,
                                slen,
                                crate::sshbuf::sshbuf_ptr(b),
                                crate::sshbuf::sshbuf_len(b),
                                pkalg,
                                (*ssh).compat as u_int,
                                0 as *mut *mut sshkey_sig_details,
                            )
                        } else {
                            sshkey_verify(
                                key,
                                sig,
                                slen,
                                crate::sshbuf::sshbuf_ptr(b),
                                crate::sshbuf::sshbuf_len(b),
                                pkalg,
                                (*ssh).compat as u_int,
                                0 as *mut *mut sshkey_sig_details,
                            )
                        }) == 0 as libc::c_int
                    {
                        authenticated = 1 as libc::c_int;
                    }
                    auth2_record_key(authctxt, authenticated, key);
                    crate::sshbuf::sshbuf_free(b);
                }
            }
        }
    }
    crate::log::sshlog(
        b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"userauth_hostbased\0"))
            .as_ptr(),
        157 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"authenticated %d\0" as *const u8 as *const libc::c_char,
        authenticated,
    );
    crate::sshkey::sshkey_free(key);
    libc::free(pkalg as *mut libc::c_void);
    libc::free(pkblob as *mut libc::c_void);
    libc::free(cuser as *mut libc::c_void);
    libc::free(chost as *mut libc::c_void);
    libc::free(sig as *mut libc::c_void);
    return authenticated;
}
pub unsafe extern "C" fn hostbased_key_allowed(
    mut ssh: *mut ssh,
    mut pw: *mut libc::passwd,
    mut cuser: *const libc::c_char,
    mut chost: *mut libc::c_char,
    mut key: *mut crate::sshkey::sshkey,
) -> libc::c_int {
    let mut resolvedname: *const libc::c_char = 0 as *const libc::c_char;
    let mut ipaddr: *const libc::c_char = 0 as *const libc::c_char;
    let mut lookup: *const libc::c_char = 0 as *const libc::c_char;
    let mut reason: *const libc::c_char = 0 as *const libc::c_char;
    let mut host_status: HostStatus = HOST_OK;
    let mut len: libc::c_int = 0;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    if auth_key_is_revoked(key) != 0 {
        return 0 as libc::c_int;
    }
    resolvedname = auth_get_canonical_hostname(ssh, options.use_dns);
    ipaddr = ssh_remote_ipaddr(ssh);
    crate::log::sshlog(
        b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"hostbased_key_allowed\0"))
            .as_ptr(),
        184 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"chost %s resolvedname %s ipaddr %s\0" as *const u8 as *const libc::c_char,
        chost,
        resolvedname,
        ipaddr,
    );
    len = strlen(chost) as libc::c_int;
    if len > 0 as libc::c_int
        && *chost.offset((len - 1 as libc::c_int) as isize) as libc::c_int == '.' as i32
    {
        crate::log::sshlog(
            b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"hostbased_key_allowed\0"))
                .as_ptr(),
            187 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"stripping trailing dot from chost %s\0" as *const u8 as *const libc::c_char,
            chost,
        );
        *chost.offset((len - 1 as libc::c_int) as isize) = '\0' as i32 as libc::c_char;
    }
    if options.hostbased_uses_name_from_packet_only != 0 {
        if auth_rhosts2(pw, cuser, chost, chost) == 0 as libc::c_int {
            crate::log::sshlog(
                b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"hostbased_key_allowed\0",
                ))
                .as_ptr(),
                194 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"auth_rhosts2 refused user \"%.100s\" host \"%.100s\" (from packet)\0" as *const u8
                    as *const libc::c_char,
                cuser,
                chost,
            );
            return 0 as libc::c_int;
        }
        lookup = chost;
    } else {
        if strcasecmp(resolvedname, chost) != 0 as libc::c_int {
            crate::log::sshlog(
                b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"hostbased_key_allowed\0",
                ))
                .as_ptr(),
                202 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"userauth_hostbased mismatch: client sends %s, but we resolve %s to %s\0"
                    as *const u8 as *const libc::c_char,
                chost,
                ipaddr,
                resolvedname,
            );
        }
        if auth_rhosts2(pw, cuser, resolvedname, ipaddr) == 0 as libc::c_int {
            crate::log::sshlog(
                b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"hostbased_key_allowed\0",
                ))
                .as_ptr(),
                206 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"auth_rhosts2 refused user \"%.100s\" host \"%.100s\" addr \"%.100s\"\0"
                    as *const u8 as *const libc::c_char,
                cuser,
                resolvedname,
                ipaddr,
            );
            return 0 as libc::c_int;
        }
        lookup = resolvedname;
    }
    crate::log::sshlog(
        b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"hostbased_key_allowed\0"))
            .as_ptr(),
        211 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"access allowed by auth_rhosts2\0" as *const u8 as *const libc::c_char,
    );
    if sshkey_is_cert(key) != 0
        && sshkey_cert_check_authority_now(
            key,
            1 as libc::c_int,
            0 as libc::c_int,
            0 as libc::c_int,
            lookup,
            &mut reason,
        ) != 0
    {
        crate::log::sshlog(
            b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"hostbased_key_allowed\0"))
                .as_ptr(),
            215 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s\0" as *const u8 as *const libc::c_char,
            reason,
        );
        auth_debug_add(b"%s\0" as *const u8 as *const libc::c_char, reason);
        return 0 as libc::c_int;
    }
    host_status = check_key_in_hostfiles(
        pw,
        key,
        lookup,
        b"/usr/local/etc/ssh_known_hosts\0" as *const u8 as *const libc::c_char,
        if options.ignore_user_known_hosts != 0 {
            0 as *const libc::c_char
        } else {
            b"~/.ssh/known_hosts\0" as *const u8 as *const libc::c_char
        },
    );
    if host_status as libc::c_uint == HOST_NEW as libc::c_int as libc::c_uint {
        host_status = check_key_in_hostfiles(
            pw,
            key,
            lookup,
            b"/usr/local/etc/ssh_known_hosts2\0" as *const u8 as *const libc::c_char,
            if options.ignore_user_known_hosts != 0 {
                0 as *const libc::c_char
            } else {
                b"~/.ssh/known_hosts2\0" as *const u8 as *const libc::c_char
            },
        );
    }
    if host_status as libc::c_uint == HOST_OK as libc::c_int as libc::c_uint {
        if sshkey_is_cert(key) != 0 {
            fp = crate::sshkey::sshkey_fingerprint(
                (*(*key).cert).signature_key,
                options.fingerprint_hash,
                SSH_FP_DEFAULT,
            );
            if fp.is_null() {
                sshfatal(
                    b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"hostbased_key_allowed\0",
                    ))
                    .as_ptr(),
                    236 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"crate::sshkey::sshkey_fingerprint fail\0" as *const u8 as *const libc::c_char,
                );
            }
            crate::log::sshlog(
                b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"hostbased_key_allowed\0",
                ))
                .as_ptr(),
                240 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_VERBOSE,
                0 as *const libc::c_char,
                b"Accepted certificate ID \"%s\" signed by %s CA %s from %s@%s\0" as *const u8
                    as *const libc::c_char,
                (*(*key).cert).key_id,
                crate::sshkey::sshkey_type((*(*key).cert).signature_key),
                fp,
                cuser,
                lookup,
            );
        } else {
            fp = crate::sshkey::sshkey_fingerprint(key, options.fingerprint_hash, SSH_FP_DEFAULT);
            if fp.is_null() {
                sshfatal(
                    b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"hostbased_key_allowed\0",
                    ))
                    .as_ptr(),
                    244 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"crate::sshkey::sshkey_fingerprint fail\0" as *const u8 as *const libc::c_char,
                );
            }
            crate::log::sshlog(
                b"auth2-hostbased.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"hostbased_key_allowed\0",
                ))
                .as_ptr(),
                246 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_VERBOSE,
                0 as *const libc::c_char,
                b"Accepted %s public key %s from %s@%s\0" as *const u8 as *const libc::c_char,
                crate::sshkey::sshkey_type(key),
                fp,
                cuser,
                lookup,
            );
        }
        libc::free(fp as *mut libc::c_void);
    }
    return (host_status as libc::c_uint == HOST_OK as libc::c_int as libc::c_uint) as libc::c_int;
}
pub static mut method_hostbased: Authmethod = Authmethod {
    name: 0 as *const libc::c_char as *mut libc::c_char,
    synonym: 0 as *const libc::c_char as *mut libc::c_char,
    userauth: None,
    enabled: 0 as *const libc::c_int as *mut libc::c_int,
};
unsafe extern "C" fn run_static_initializers() {
    method_hostbased = {
        let mut init = Authmethod {
            name: b"hostbased\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            synonym: 0 as *mut libc::c_char,
            userauth: Some(
                userauth_hostbased
                    as unsafe extern "C" fn(*mut ssh, *const libc::c_char) -> libc::c_int,
            ),
            enabled: &mut options.hostbased_authentication,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
