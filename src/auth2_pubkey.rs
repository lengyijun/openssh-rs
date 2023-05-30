use crate::auth::Authctxt;
use crate::auth_options::sshauthopt;
use crate::kex::dh_st;
use crate::packet::key_entry;
use crate::sshkey::sshkey_sig_details;
use libc::pid_t;

use crate::packet::ssh;

use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    pub type ec_group_st;

    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn getpwnam(__name: *const libc::c_char) -> *mut libc::passwd;
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;

    fn xreallocarray(_: *mut libc::c_void, _: size_t, _: size_t) -> *mut libc::c_void;

    fn sshpkt_getb_froms(ssh: *mut ssh, valp: *mut *mut crate::sshbuf::sshbuf) -> libc::c_int;

    fn sshpkt_put_string(ssh: *mut ssh, v: *const libc::c_void, len: size_t) -> libc::c_int;

    fn ssh_remote_port(_: *mut ssh) -> libc::c_int;
    fn ssh_remote_ipaddr(_: *mut ssh) -> *const libc::c_char;

    fn sshbuf_putb(buf: *mut crate::sshbuf::sshbuf, v: *const crate::sshbuf::sshbuf)
        -> libc::c_int;

    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_dtob64_string(
        buf: *const crate::sshbuf::sshbuf,
        wrap: libc::c_int,
    ) -> *mut libc::c_char;
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn log_level_get() -> LogLevel;

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
    fn percent_expand(_: *const libc::c_char, _: ...) -> *mut libc::c_char;
    fn subprocess(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: *mut *mut libc::c_char,
        _: *mut *mut libc::FILE,
        _: u_int,
        _: *mut libc::passwd,
        _: Option<privdrop_fn>,
        _: Option<privrestore_fn>,
    ) -> pid_t;
    fn argv_split(
        _: *const libc::c_char,
        _: *mut libc::c_int,
        _: *mut *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn argv_assemble(_: libc::c_int, argv: *mut *mut libc::c_char) -> *mut libc::c_char;
    fn exited_cleanly(
        _: pid_t,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;

    fn sshkey_equal(
        _: *const crate::sshkey::sshkey,
        _: *const crate::sshkey::sshkey,
    ) -> libc::c_int;

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
    fn sshkey_sig_details_free(_: *mut sshkey_sig_details);
    fn sshkey_check_rsa_length(_: *const crate::sshkey::sshkey, _: libc::c_int) -> libc::c_int;
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
    fn sshkey_puts(_: *const crate::sshkey::sshkey, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshkey_to_base64(_: *const crate::sshkey::sshkey, _: *mut *mut libc::c_char) -> libc::c_int;
    fn sshkey_fromb(
        _: *mut crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_from_blob(
        _: *const u_char,
        _: size_t,
        _: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_ssh_name(_: *const crate::sshkey::sshkey) -> *const libc::c_char;
    fn auth2_key_already_used(_: *mut Authctxt, _: *const crate::sshkey::sshkey) -> libc::c_int;
    fn auth2_record_key(_: *mut Authctxt, _: libc::c_int, _: *const crate::sshkey::sshkey);
    fn auth2_record_info(authctxt: *mut Authctxt, _: *const libc::c_char, _: ...);
    fn auth_process_principals(
        _: *mut libc::FILE,
        _: *const libc::c_char,
        _: *const crate::sshkey::sshkey_cert,
        _: *mut *mut sshauthopt,
    ) -> libc::c_int;
    fn auth_openprincipals(
        _: *const libc::c_char,
        _: *mut libc::passwd,
        _: libc::c_int,
    ) -> *mut libc::FILE;
    fn authorized_principals_file(_: *mut libc::passwd) -> *mut libc::c_char;
    fn auth_openkeyfile(
        _: *const libc::c_char,
        _: *mut libc::passwd,
        _: libc::c_int,
    ) -> *mut libc::FILE;
    fn expand_authorized_keys(_: *const libc::c_char, pw: *mut libc::passwd) -> *mut libc::c_char;
    fn auth_key_is_revoked(_: *mut crate::sshkey::sshkey) -> libc::c_int;
    fn auth_authorise_keyopts(
        _: *mut libc::passwd,
        _: *mut sshauthopt,
        _: libc::c_int,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn auth_debug_add(fmt: *const libc::c_char, _: ...);
    fn auth_activate_options(_: *mut ssh, _: *mut sshauthopt) -> libc::c_int;
    fn auth_check_authkeys_file(
        _: *mut libc::passwd,
        _: *mut libc::FILE,
        _: *mut libc::c_char,
        _: *mut crate::sshkey::sshkey,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut *mut sshauthopt,
    ) -> libc::c_int;
    fn auth_get_canonical_hostname(_: *mut ssh, _: libc::c_int) -> *const libc::c_char;
    fn temporarily_use_uid(_: *mut libc::passwd);
    fn restore_uid();
    fn sshauthopt_free(opts: *mut sshauthopt);
    fn sshauthopt_from_cert(k: *mut crate::sshkey::sshkey) -> *mut sshauthopt;
    fn sshauthopt_merge(
        primary: *const sshauthopt,
        additional: *const sshauthopt,
        errstrp: *mut *const libc::c_char,
    ) -> *mut sshauthopt;
    static mut use_privsep: libc::c_int;
    fn mm_user_key_allowed(
        ssh: *mut ssh,
        _: *mut libc::passwd,
        _: *mut crate::sshkey::sshkey,
        _: libc::c_int,
        _: *mut *mut sshauthopt,
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
    fn sshkey_in_file(
        _: *mut crate::sshkey::sshkey,
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
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
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
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
pub type uint64_t = __uint64_t;

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
pub type privdrop_fn = unsafe extern "C" fn(*mut libc::passwd) -> ();
pub type privrestore_fn = unsafe extern "C" fn() -> ();
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
pub type sshkey_fp_rep = libc::c_uint;
pub const SSH_FP_RANDOMART: sshkey_fp_rep = 4;
pub const SSH_FP_BUBBLEBABBLE: sshkey_fp_rep = 3;
pub const SSH_FP_BASE64: sshkey_fp_rep = 2;
pub const SSH_FP_HEX: sshkey_fp_rep = 1;
pub const SSH_FP_DEFAULT: sshkey_fp_rep = 0;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Authmethod {
    pub name: *mut libc::c_char,
    pub synonym: *mut libc::c_char,
    pub userauth: Option<unsafe extern "C" fn(*mut ssh, *const libc::c_char) -> libc::c_int>,
    pub enabled: *mut libc::c_int,
}
unsafe extern "C" fn format_key(mut key: *const crate::sshkey::sshkey) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fp: *mut libc::c_char =
        crate::sshkey::sshkey_fingerprint(key, options.fingerprint_hash, SSH_FP_DEFAULT);
    crate::xmalloc::xasprintf(
        &mut ret as *mut *mut libc::c_char,
        b"%s %s\0" as *const u8 as *const libc::c_char,
        crate::sshkey::sshkey_type(key),
        fp,
    );
    libc::free(fp as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn userauth_pubkey(
    mut ssh: *mut ssh,
    mut method: *const libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut pw: *mut libc::passwd = (*authctxt).pw;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut hostkey: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut pkalg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut userstyle: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut key_s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ca_s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pkblob: *mut u_char = 0 as *mut u_char;
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut have_sig: u_char = 0;
    let mut blen: size_t = 0;
    let mut slen: size_t = 0;
    let mut hostbound: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut pktype: libc::c_int = 0;
    let mut req_presence: libc::c_int = 0 as libc::c_int;
    let mut req_verify: libc::c_int = 0 as libc::c_int;
    let mut authenticated: libc::c_int = 0 as libc::c_int;
    let mut authopts: *mut sshauthopt = 0 as *mut sshauthopt;
    let mut sig_details: *mut sshkey_sig_details = 0 as *mut sshkey_sig_details;
    hostbound = (libc::strcmp(
        method,
        b"publickey-hostbound-v00@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int) as libc::c_int;
    r = crate::packet::sshpkt_get_u8(ssh, &mut have_sig);
    if r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_get_cstring(ssh, &mut pkalg, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_string(ssh, &mut pkblob, &mut blen);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                .as_ptr(),
            107 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s packet\0" as *const u8 as *const libc::c_char,
            method,
        );
    }
    if hostbound != 0 {
        r = sshpkt_getb_froms(ssh, &mut b);
        if r != 0 as libc::c_int || {
            r = sshkey_fromb(b, &mut hostkey);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                    .as_ptr(),
                113 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s hostkey\0" as *const u8 as *const libc::c_char,
                method,
            );
        }
        if ((*(*ssh).kex).initial_hostkey).is_null() {
            sshfatal(
                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                    .as_ptr(),
                115 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"internal error: initial hostkey not recorded\0" as *const u8
                    as *const libc::c_char,
            );
        }
        if sshkey_equal(hostkey, (*(*ssh).kex).initial_hostkey) == 0 {
            sshfatal(
                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                    .as_ptr(),
                117 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s packet contained wrong host key\0" as *const u8 as *const libc::c_char,
                method,
            );
        }
        crate::sshbuf::sshbuf_free(b);
        b = 0 as *mut crate::sshbuf::sshbuf;
    }
    if log_level_get() as libc::c_int >= SYSLOG_LEVEL_DEBUG2 as libc::c_int {
        let mut keystring: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut pkbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
        pkbuf = crate::sshbuf::sshbuf_from(pkblob as *const libc::c_void, blen);
        if pkbuf.is_null() {
            sshfatal(
                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                    .as_ptr(),
                127 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::sshbuf::sshbuf_from failed\0" as *const u8 as *const libc::c_char,
            );
        }
        keystring = sshbuf_dtob64_string(pkbuf, 0 as libc::c_int);
        if keystring.is_null() {
            sshfatal(
                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                    .as_ptr(),
                129 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"sshbuf_dtob64 failed\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::log::sshlog(
            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                .as_ptr(),
            132 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"%s user %s %s public key %s %s\0" as *const u8 as *const libc::c_char,
            if (*authctxt).valid != 0 {
                b"valid\0" as *const u8 as *const libc::c_char
            } else {
                b"invalid\0" as *const u8 as *const libc::c_char
            },
            (*authctxt).user,
            if have_sig as libc::c_int != 0 {
                b"attempting\0" as *const u8 as *const libc::c_char
            } else {
                b"querying\0" as *const u8 as *const libc::c_char
            },
            pkalg,
            keystring,
        );
        crate::sshbuf::sshbuf_free(pkbuf);
        libc::free(keystring as *mut libc::c_void);
    }
    pktype = sshkey_type_from_name(pkalg);
    if pktype == KEY_UNSPEC as libc::c_int {
        crate::log::sshlog(
            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                .as_ptr(),
            140 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"unsupported public key algorithm: %s\0" as *const u8 as *const libc::c_char,
            pkalg,
        );
    } else {
        r = sshkey_from_blob(pkblob, blen, &mut key);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                    .as_ptr(),
                144 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"parse key\0" as *const u8 as *const libc::c_char,
            );
        } else if key.is_null() {
            crate::log::sshlog(
                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                    .as_ptr(),
                148 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"cannot decode key: %s\0" as *const u8 as *const libc::c_char,
                pkalg,
            );
        } else if (*key).type_0 != pktype {
            crate::log::sshlog(
                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                    .as_ptr(),
                153 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"type mismatch for decoded key (received %d, expected %d)\0" as *const u8
                    as *const libc::c_char,
                (*key).type_0,
                pktype,
            );
        } else if auth2_key_already_used(authctxt, key) != 0 {
            crate::log::sshlog(
                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                    .as_ptr(),
                157 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"refusing previously-used %s key\0" as *const u8 as *const libc::c_char,
                crate::sshkey::sshkey_type(key),
            );
        } else if match_pattern_list(pkalg, options.pubkey_accepted_algos, 0 as libc::c_int)
            != 1 as libc::c_int
        {
            crate::log::sshlog(
                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                    .as_ptr(),
                162 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"signature algorithm %s not in PubkeyAcceptedAlgorithms\0" as *const u8
                    as *const libc::c_char,
                pkalg,
            );
        } else {
            r = sshkey_check_cert_sigtype(key, options.ca_sign_algorithms);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"userauth_pubkey\0",
                    ))
                    .as_ptr(),
                    169 as libc::c_int,
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
                        b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"userauth_pubkey\0",
                        ))
                        .as_ptr(),
                        174 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        ssh_err(r),
                        b"refusing %s key\0" as *const u8 as *const libc::c_char,
                        crate::sshkey::sshkey_type(key),
                    );
                } else {
                    key_s = format_key(key);
                    if sshkey_is_cert(key) != 0 {
                        ca_s = format_key((*(*key).cert).signature_key);
                    }
                    if have_sig != 0 {
                        crate::log::sshlog(
                            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"userauth_pubkey\0",
                            ))
                            .as_ptr(),
                            184 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG3,
                            0 as *const libc::c_char,
                            b"%s have %s signature for %s%s%s\0" as *const u8
                                as *const libc::c_char,
                            method,
                            pkalg,
                            key_s,
                            if ca_s.is_null() {
                                b"\0" as *const u8 as *const libc::c_char
                            } else {
                                b" CA \0" as *const u8 as *const libc::c_char
                            },
                            if ca_s.is_null() {
                                b"\0" as *const u8 as *const libc::c_char
                            } else {
                                ca_s as *const libc::c_char
                            },
                        );
                        r = crate::packet::sshpkt_get_string(ssh, &mut sig, &mut slen);
                        if r != 0 as libc::c_int || {
                            r = crate::packet::sshpkt_get_end(ssh);
                            r != 0 as libc::c_int
                        } {
                            sshfatal(
                                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"userauth_pubkey\0",
                                ))
                                .as_ptr(),
                                187 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                ssh_err(r),
                                b"parse signature packet\0" as *const u8 as *const libc::c_char,
                            );
                        }
                        b = crate::sshbuf::sshbuf_new();
                        if b.is_null() {
                            sshfatal(
                                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"userauth_pubkey\0",
                                ))
                                .as_ptr(),
                                189 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                0 as *const libc::c_char,
                                b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                                    as *const libc::c_char,
                            );
                        }
                        if (*ssh).compat & 0x10 as libc::c_int != 0 {
                            r = sshbuf_putb(b, (*(*ssh).kex).session_id);
                            if r != 0 as libc::c_int {
                                sshfatal(
                                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"userauth_pubkey\0",
                                    ))
                                    .as_ptr(),
                                    192 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"put old session id\0" as *const u8 as *const libc::c_char,
                                );
                            }
                        } else {
                            r = sshbuf_put_stringb(b, (*(*ssh).kex).session_id);
                            if r != 0 as libc::c_int {
                                sshfatal(
                                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"userauth_pubkey\0",
                                    ))
                                    .as_ptr(),
                                    196 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"put session id\0" as *const u8 as *const libc::c_char,
                                );
                            }
                        }
                        if (*authctxt).valid == 0 || ((*authctxt).user).is_null() {
                            crate::log::sshlog(
                                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"userauth_pubkey\0",
                                ))
                                .as_ptr(),
                                199 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"disabled because of invalid user\0" as *const u8
                                    as *const libc::c_char,
                            );
                        } else {
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
                            r = crate::sshbuf_getput_basic::sshbuf_put_u8(
                                b,
                                50 as libc::c_int as u_char,
                            );
                            if r != 0 as libc::c_int
                                || {
                                    r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
                                        b, userstyle,
                                    );
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
                                    r = crate::sshbuf_getput_basic::sshbuf_put_u8(b, have_sig);
                                    r != 0 as libc::c_int
                                }
                                || {
                                    r = crate::sshbuf_getput_basic::sshbuf_put_cstring(b, pkalg);
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
                            {
                                sshfatal(
                                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"userauth_pubkey\0",
                                    ))
                                    .as_ptr(),
                                    213 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"reconstruct %s packet\0" as *const u8 as *const libc::c_char,
                                    method,
                                );
                            }
                            if hostbound != 0 && {
                                r = sshkey_puts((*(*ssh).kex).initial_hostkey, b);
                                r != 0 as libc::c_int
                            } {
                                sshfatal(
                                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"userauth_pubkey\0",
                                    ))
                                    .as_ptr(),
                                    216 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"reconstruct %s packet\0" as *const u8 as *const libc::c_char,
                                    method,
                                );
                            }
                            authenticated = 0 as libc::c_int;
                            if (if use_privsep != 0 {
                                mm_user_key_allowed(ssh, pw, key, 1 as libc::c_int, &mut authopts)
                            } else {
                                user_key_allowed(ssh, pw, key, 1 as libc::c_int, &mut authopts)
                            }) != 0
                                && (if use_privsep != 0 {
                                    mm_sshkey_verify(
                                        key,
                                        sig,
                                        slen,
                                        crate::sshbuf::sshbuf_ptr(b),
                                        crate::sshbuf::sshbuf_len(b),
                                        if (*ssh).compat & 0x2 as libc::c_int == 0 as libc::c_int {
                                            pkalg
                                        } else {
                                            0 as *mut libc::c_char
                                        },
                                        (*ssh).compat as u_int,
                                        &mut sig_details,
                                    )
                                } else {
                                    sshkey_verify(
                                        key,
                                        sig,
                                        slen,
                                        crate::sshbuf::sshbuf_ptr(b),
                                        crate::sshbuf::sshbuf_len(b),
                                        if (*ssh).compat & 0x2 as libc::c_int == 0 as libc::c_int {
                                            pkalg
                                        } else {
                                            0 as *mut libc::c_char
                                        },
                                        (*ssh).compat as u_int,
                                        &mut sig_details,
                                    )
                                }) == 0 as libc::c_int
                            {
                                authenticated = 1 as libc::c_int;
                            }
                            if authenticated == 1 as libc::c_int && !sig_details.is_null() {
                                auth2_record_info(
                                    authctxt,
                                    b"signature count = %u\0" as *const u8 as *const libc::c_char,
                                    (*sig_details).sk_counter,
                                );
                                crate::log::sshlog(
                                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"userauth_pubkey\0",
                                    ))
                                    .as_ptr(),
                                    233 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG1,
                                    0 as *const libc::c_char,
                                    b"sk_counter = %u, sk_flags = 0x%02x\0" as *const u8
                                        as *const libc::c_char,
                                    (*sig_details).sk_counter,
                                    (*sig_details).sk_flags as libc::c_int,
                                );
                                req_presence = (options.pubkey_auth_options & 1 as libc::c_int != 0
                                    || (*authopts).no_require_user_presence == 0)
                                    as libc::c_int;
                                if req_presence != 0
                                    && (*sig_details).sk_flags as libc::c_int & 0x1 as libc::c_int
                                        == 0 as libc::c_int
                                {
                                    crate::log::sshlog(
                                        b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<
                                            &[u8; 16],
                                            &[libc::c_char; 16],
                                        >(b"userauth_pubkey\0"))
                                            .as_ptr(),
                                        245 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"public key %s signature for %s%s from %.128s port %d rejected: user presence (authenticator touch) requirement not met \0"
                                            as *const u8 as *const libc::c_char,
                                        key_s,
                                        if (*authctxt).valid != 0 {
                                            b"\0" as *const u8 as *const libc::c_char
                                        } else {
                                            b"invalid user \0" as *const u8 as *const libc::c_char
                                        },
                                        (*authctxt).user,
                                        ssh_remote_ipaddr(ssh),
                                        ssh_remote_port(ssh),
                                    );
                                    authenticated = 0 as libc::c_int;
                                    current_block = 4983000033041507161;
                                } else {
                                    req_verify = (options.pubkey_auth_options
                                        & (1 as libc::c_int) << 1 as libc::c_int
                                        != 0
                                        || (*authopts).require_verify != 0)
                                        as libc::c_int;
                                    if req_verify != 0
                                        && (*sig_details).sk_flags as libc::c_int
                                            & 0x4 as libc::c_int
                                            == 0 as libc::c_int
                                    {
                                        crate::log::sshlog(
                                            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 16],
                                                &[libc::c_char; 16],
                                            >(b"userauth_pubkey\0"))
                                                .as_ptr(),
                                            259 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"public key %s signature for %s%s from %.128s port %d rejected: user verification requirement not met \0"
                                                as *const u8 as *const libc::c_char,
                                            key_s,
                                            if (*authctxt).valid != 0 {
                                                b"\0" as *const u8 as *const libc::c_char
                                            } else {
                                                b"invalid user \0" as *const u8 as *const libc::c_char
                                            },
                                            (*authctxt).user,
                                            ssh_remote_ipaddr(ssh),
                                            ssh_remote_port(ssh),
                                        );
                                        authenticated = 0 as libc::c_int;
                                        current_block = 4983000033041507161;
                                    } else {
                                        current_block = 1874315696050160458;
                                    }
                                }
                            } else {
                                current_block = 1874315696050160458;
                            }
                            match current_block {
                                4983000033041507161 => {}
                                _ => {
                                    auth2_record_key(authctxt, authenticated, key);
                                }
                            }
                        }
                    } else {
                        crate::log::sshlog(
                            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"userauth_pubkey\0",
                            ))
                            .as_ptr(),
                            267 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"%s test pkalg %s pkblob %s%s%s\0" as *const u8 as *const libc::c_char,
                            method,
                            pkalg,
                            key_s,
                            if ca_s.is_null() {
                                b"\0" as *const u8 as *const libc::c_char
                            } else {
                                b" CA \0" as *const u8 as *const libc::c_char
                            },
                            if ca_s.is_null() {
                                b"\0" as *const u8 as *const libc::c_char
                            } else {
                                ca_s as *const libc::c_char
                            },
                        );
                        r = crate::packet::sshpkt_get_end(ssh);
                        if r != 0 as libc::c_int {
                            sshfatal(
                                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"userauth_pubkey\0",
                                ))
                                .as_ptr(),
                                270 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                ssh_err(r),
                                b"parse packet\0" as *const u8 as *const libc::c_char,
                            );
                        }
                        if (*authctxt).valid == 0 || ((*authctxt).user).is_null() {
                            crate::log::sshlog(
                                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"userauth_pubkey\0",
                                ))
                                .as_ptr(),
                                273 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"disabled because of invalid user\0" as *const u8
                                    as *const libc::c_char,
                            );
                        } else if if use_privsep != 0 {
                            mm_user_key_allowed(
                                ssh,
                                pw,
                                key,
                                0 as libc::c_int,
                                0 as *mut *mut sshauthopt,
                            )
                        } else {
                            user_key_allowed(
                                ssh,
                                pw,
                                key,
                                0 as libc::c_int,
                                0 as *mut *mut sshauthopt,
                            )
                        } != 0
                        {
                            r = crate::packet::sshpkt_start(ssh, 60 as libc::c_int as u_char);
                            if r != 0 as libc::c_int
                                || {
                                    r = crate::packet::sshpkt_put_cstring(
                                        ssh,
                                        pkalg as *const libc::c_void,
                                    );
                                    r != 0 as libc::c_int
                                }
                                || {
                                    r = sshpkt_put_string(ssh, pkblob as *const libc::c_void, blen);
                                    r != 0 as libc::c_int
                                }
                                || {
                                    r = crate::packet::sshpkt_send(ssh);
                                    r != 0 as libc::c_int
                                }
                                || {
                                    r = crate::packet::ssh_packet_write_wait(ssh);
                                    r != 0 as libc::c_int
                                }
                            {
                                sshfatal(
                                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"userauth_pubkey\0",
                                    ))
                                    .as_ptr(),
                                    291 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"send packet\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            (*authctxt).postponed = 1 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    if authenticated == 1 as libc::c_int && auth_activate_options(ssh, authopts) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                .as_ptr(),
            297 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"key options inconsistent with existing\0" as *const u8 as *const libc::c_char,
        );
        authenticated = 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0")).as_ptr(),
        300 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"authenticated %d pkalg %s\0" as *const u8 as *const libc::c_char,
        authenticated,
        pkalg,
    );
    crate::sshbuf::sshbuf_free(b);
    sshauthopt_free(authopts);
    crate::sshkey::sshkey_free(key);
    crate::sshkey::sshkey_free(hostkey);
    libc::free(userstyle as *mut libc::c_void);
    libc::free(pkalg as *mut libc::c_void);
    libc::free(pkblob as *mut libc::c_void);
    libc::free(key_s as *mut libc::c_void);
    libc::free(ca_s as *mut libc::c_void);
    libc::free(sig as *mut libc::c_void);
    sshkey_sig_details_free(sig_details);
    return authenticated;
}
unsafe extern "C" fn match_principals_file(
    mut pw: *mut libc::passwd,
    mut file: *mut libc::c_char,
    mut cert: *mut crate::sshkey::sshkey_cert,
    mut authoptsp: *mut *mut sshauthopt,
) -> libc::c_int {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut success: libc::c_int = 0;
    if !authoptsp.is_null() {
        *authoptsp = 0 as *mut sshauthopt;
    }
    temporarily_use_uid(pw);
    crate::log::sshlog(
        b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"match_principals_file\0"))
            .as_ptr(),
        327 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"trying authorized principals file %s\0" as *const u8 as *const libc::c_char,
        file,
    );
    f = auth_openprincipals(file, pw, options.strict_modes);
    if f.is_null() {
        restore_uid();
        return 0 as libc::c_int;
    }
    success = auth_process_principals(f, file, cert, authoptsp);
    fclose(f);
    restore_uid();
    return success;
}
unsafe extern "C" fn match_principals_command(
    mut user_pw: *mut libc::passwd,
    mut key: *const crate::sshkey::sshkey,
    mut authoptsp: *mut *mut sshauthopt,
) -> libc::c_int {
    let mut runas_pw: *mut libc::passwd = 0 as *mut libc::passwd;
    let mut cert: *const crate::sshkey::sshkey_cert = (*key).cert;
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut r: libc::c_int = 0;
    let mut ok: libc::c_int = 0;
    let mut found_principal: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut ac: libc::c_int = 0 as libc::c_int;
    let mut uid_swapped: libc::c_int = 0 as libc::c_int;
    let mut pid: pid_t = 0;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut username: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut command: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut av: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut ca_fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut key_fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut catext: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut keytext: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut serial_s: [libc::c_char; 32] = [0; 32];
    let mut uidstr: [libc::c_char; 32] = [0; 32];
    let mut osigchld: Option<unsafe extern "C" fn(libc::c_int) -> ()> = None;
    if !authoptsp.is_null() {
        *authoptsp = 0 as *mut sshauthopt;
    }
    if (options.authorized_principals_command).is_null() {
        return 0 as libc::c_int;
    }
    if (options.authorized_principals_command_user).is_null() {
        crate::log::sshlog(
            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"match_principals_command\0",
            ))
            .as_ptr(),
            363 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"No user for AuthorizedPrincipalsCommand specified, skipping\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    osigchld = crate::misc::ssh_signal(17 as libc::c_int, None);
    username = percent_expand(
        options.authorized_principals_command_user,
        b"u\0" as *const u8 as *const libc::c_char,
        (*user_pw).pw_name,
        0 as *mut libc::c_void as *mut libc::c_char,
    );
    runas_pw = getpwnam(username);
    if runas_pw.is_null() {
        crate::log::sshlog(
            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"match_principals_command\0",
            ))
            .as_ptr(),
            379 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"AuthorizedPrincipalsCommandUser \"%s\" not found: %s\0" as *const u8
                as *const libc::c_char,
            username,
            libc::strerror(*libc::__errno_location()),
        );
    } else if argv_split(
        options.authorized_principals_command,
        &mut ac,
        &mut av,
        0 as libc::c_int,
    ) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"match_principals_command\0",
            ))
            .as_ptr(),
            387 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"AuthorizedPrincipalsCommand \"%s\" contains invalid quotes\0" as *const u8
                as *const libc::c_char,
            options.authorized_principals_command,
        );
    } else if ac == 0 as libc::c_int {
        crate::log::sshlog(
            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"match_principals_command\0",
            ))
            .as_ptr(),
            392 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"AuthorizedPrincipalsCommand \"%s\" yielded no arguments\0" as *const u8
                as *const libc::c_char,
            options.authorized_principals_command,
        );
    } else {
        ca_fp = crate::sshkey::sshkey_fingerprint(
            (*cert).signature_key,
            options.fingerprint_hash,
            SSH_FP_DEFAULT,
        );
        if ca_fp.is_null() {
            crate::log::sshlog(
                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"match_principals_command\0",
                ))
                .as_ptr(),
                397 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"crate::sshkey::sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            key_fp =
                crate::sshkey::sshkey_fingerprint(key, options.fingerprint_hash, SSH_FP_DEFAULT);
            if key_fp.is_null() {
                crate::log::sshlog(
                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                        b"match_principals_command\0",
                    ))
                    .as_ptr(),
                    402 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"crate::sshkey::sshkey_fingerprint failed\0" as *const u8
                        as *const libc::c_char,
                );
            } else {
                r = sshkey_to_base64((*cert).signature_key, &mut catext);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                            b"match_principals_command\0",
                        ))
                        .as_ptr(),
                        406 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"sshkey_to_base64 failed\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    r = sshkey_to_base64(key, &mut keytext);
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"match_principals_command\0",
                            ))
                            .as_ptr(),
                            410 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"sshkey_to_base64 failed\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        libc::snprintf(
                            serial_s.as_mut_ptr(),
                            ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
                            b"%llu\0" as *const u8 as *const libc::c_char,
                            (*cert).serial as libc::c_ulonglong,
                        );
                        libc::snprintf(
                            uidstr.as_mut_ptr(),
                            ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
                            b"%llu\0" as *const u8 as *const libc::c_char,
                            (*user_pw).pw_uid as libc::c_ulonglong,
                        );
                        i = 1 as libc::c_int;
                        while i < ac {
                            tmp = percent_expand(
                                *av.offset(i as isize),
                                b"U\0" as *const u8 as *const libc::c_char,
                                uidstr.as_mut_ptr(),
                                b"u\0" as *const u8 as *const libc::c_char,
                                (*user_pw).pw_name,
                                b"h\0" as *const u8 as *const libc::c_char,
                                (*user_pw).pw_dir,
                                b"t\0" as *const u8 as *const libc::c_char,
                                sshkey_ssh_name(key),
                                b"T\0" as *const u8 as *const libc::c_char,
                                sshkey_ssh_name((*cert).signature_key),
                                b"f\0" as *const u8 as *const libc::c_char,
                                key_fp,
                                b"F\0" as *const u8 as *const libc::c_char,
                                ca_fp,
                                b"k\0" as *const u8 as *const libc::c_char,
                                keytext,
                                b"K\0" as *const u8 as *const libc::c_char,
                                catext,
                                b"i\0" as *const u8 as *const libc::c_char,
                                (*cert).key_id,
                                b"s\0" as *const u8 as *const libc::c_char,
                                serial_s.as_mut_ptr(),
                                0 as *mut libc::c_void as *mut libc::c_char,
                            );
                            if tmp.is_null() {
                                sshfatal(
                                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                        b"match_principals_command\0",
                                    ))
                                    .as_ptr(),
                                    432 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"percent_expand failed\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            libc::free(*av.offset(i as isize) as *mut libc::c_void);
                            let ref mut fresh0 = *av.offset(i as isize);
                            *fresh0 = tmp;
                            i += 1;
                            i;
                        }
                        command = argv_assemble(ac, av);
                        pid = subprocess(
                            b"AuthorizedPrincipalsCommand\0" as *const u8 as *const libc::c_char,
                            command,
                            ac,
                            av,
                            &mut f,
                            ((1 as libc::c_int) << 1 as libc::c_int
                                | (1 as libc::c_int) << 2 as libc::c_int)
                                as u_int,
                            runas_pw,
                            Some(
                                temporarily_use_uid
                                    as unsafe extern "C" fn(*mut libc::passwd) -> (),
                            ),
                            Some(restore_uid as unsafe extern "C" fn() -> ()),
                        );
                        if !(pid == 0 as libc::c_int) {
                            uid_swapped = 1 as libc::c_int;
                            temporarily_use_uid(runas_pw);
                            ok = auth_process_principals(
                                f,
                                b"(command)\0" as *const u8 as *const libc::c_char,
                                cert,
                                authoptsp,
                            );
                            fclose(f);
                            f = 0 as *mut libc::FILE;
                            if !(exited_cleanly(
                                pid,
                                b"AuthorizedPrincipalsCommand\0" as *const u8
                                    as *const libc::c_char,
                                command,
                                0 as libc::c_int,
                            ) != 0 as libc::c_int)
                            {
                                found_principal = ok;
                            }
                        }
                    }
                }
            }
        }
    }
    if !f.is_null() {
        fclose(f);
    }
    crate::misc::ssh_signal(17 as libc::c_int, osigchld);
    i = 0 as libc::c_int;
    while i < ac {
        libc::free(*av.offset(i as isize) as *mut libc::c_void);
        i += 1;
        i;
    }
    libc::free(av as *mut libc::c_void);
    if uid_swapped != 0 {
        restore_uid();
    }
    libc::free(command as *mut libc::c_void);
    libc::free(username as *mut libc::c_void);
    libc::free(ca_fp as *mut libc::c_void);
    libc::free(key_fp as *mut libc::c_void);
    libc::free(catext as *mut libc::c_void);
    libc::free(keytext as *mut libc::c_void);
    return found_principal;
}
unsafe extern "C" fn user_cert_trusted_ca(
    mut pw: *mut libc::passwd,
    mut key: *mut crate::sshkey::sshkey,
    mut remote_ip: *const libc::c_char,
    mut remote_host: *const libc::c_char,
    mut authoptsp: *mut *mut sshauthopt,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ca_fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut principals_file: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut reason: *const libc::c_char = 0 as *const libc::c_char;
    let mut principals_opts: *mut sshauthopt = 0 as *mut sshauthopt;
    let mut cert_opts: *mut sshauthopt = 0 as *mut sshauthopt;
    let mut final_opts: *mut sshauthopt = 0 as *mut sshauthopt;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut found_principal: libc::c_int = 0 as libc::c_int;
    let mut use_authorized_principals: libc::c_int = 0;
    if !authoptsp.is_null() {
        *authoptsp = 0 as *mut sshauthopt;
    }
    if sshkey_is_cert(key) == 0 || (options.trusted_user_ca_keys).is_null() {
        return 0 as libc::c_int;
    }
    ca_fp = crate::sshkey::sshkey_fingerprint(
        (*(*key).cert).signature_key,
        options.fingerprint_hash,
        SSH_FP_DEFAULT,
    );
    if ca_fp.is_null() {
        return 0 as libc::c_int;
    }
    r = sshkey_in_file(
        (*(*key).cert).signature_key,
        options.trusted_user_ca_keys,
        1 as libc::c_int,
        0 as libc::c_int,
    );
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"user_cert_trusted_ca\0"))
                .as_ptr(),
            502 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            ssh_err(r),
            b"CA %s %s is not listed in %s\0" as *const u8 as *const libc::c_char,
            crate::sshkey::sshkey_type((*(*key).cert).signature_key),
            ca_fp,
            options.trusted_user_ca_keys,
        );
    } else {
        principals_file = authorized_principals_file(pw);
        if !principals_file.is_null() {
            if match_principals_file(pw, principals_file, (*key).cert, &mut principals_opts) != 0 {
                found_principal = 1 as libc::c_int;
            }
        }
        if found_principal == 0 && match_principals_command(pw, key, &mut principals_opts) != 0 {
            found_principal = 1 as libc::c_int;
        }
        use_authorized_principals = (!principals_file.is_null()
            || !(options.authorized_principals_command).is_null())
            as libc::c_int;
        if found_principal == 0 && use_authorized_principals != 0 {
            reason = b"Certificate does not contain an authorized principal\0" as *const u8
                as *const libc::c_char;
            current_block = 13337532025718247604;
        } else {
            if use_authorized_principals != 0 && principals_opts.is_null() {
                sshfatal(
                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"user_cert_trusted_ca\0",
                    ))
                    .as_ptr(),
                    527 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"internal error: missing principals_opts\0" as *const u8
                        as *const libc::c_char,
                );
            }
            if sshkey_cert_check_authority_now(
                key,
                0 as libc::c_int,
                1 as libc::c_int,
                0 as libc::c_int,
                if use_authorized_principals != 0 {
                    0 as *mut libc::c_char
                } else {
                    (*pw).pw_name
                },
                &mut reason,
            ) != 0 as libc::c_int
            {
                current_block = 13337532025718247604;
            } else {
                cert_opts = sshauthopt_from_cert(key);
                if cert_opts.is_null() {
                    reason = b"Invalid certificate options\0" as *const u8 as *const libc::c_char;
                    current_block = 13337532025718247604;
                } else if auth_authorise_keyopts(
                    pw,
                    cert_opts,
                    0 as libc::c_int,
                    remote_ip,
                    remote_host,
                    b"cert\0" as *const u8 as *const libc::c_char,
                ) != 0 as libc::c_int
                {
                    reason =
                        b"Refused by certificate options\0" as *const u8 as *const libc::c_char;
                    current_block = 13337532025718247604;
                } else {
                    if principals_opts.is_null() {
                        final_opts = cert_opts;
                        cert_opts = 0 as *mut sshauthopt;
                        current_block = 11459959175219260272;
                    } else if auth_authorise_keyopts(
                        pw,
                        principals_opts,
                        0 as libc::c_int,
                        remote_ip,
                        remote_host,
                        b"principals\0" as *const u8 as *const libc::c_char,
                    ) != 0 as libc::c_int
                    {
                        reason = b"Refused by certificate principals options\0" as *const u8
                            as *const libc::c_char;
                        current_block = 13337532025718247604;
                    } else {
                        final_opts = sshauthopt_merge(principals_opts, cert_opts, &mut reason);
                        if final_opts.is_null() {
                            current_block = 13337532025718247604;
                        } else {
                            current_block = 11459959175219260272;
                        }
                    }
                    match current_block {
                        13337532025718247604 => {}
                        _ => {
                            crate::log::sshlog(
                                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<
                                    &[u8; 21],
                                    &[libc::c_char; 21],
                                >(b"user_cert_trusted_ca\0"))
                                    .as_ptr(),
                                565 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_VERBOSE,
                                0 as *const libc::c_char,
                                b"Accepted certificate ID \"%s\" (serial %llu) signed by %s CA %s via %s\0"
                                    as *const u8 as *const libc::c_char,
                                (*(*key).cert).key_id,
                                (*(*key).cert).serial as libc::c_ulonglong,
                                crate::sshkey::sshkey_type((*(*key).cert).signature_key),
                                ca_fp,
                                options.trusted_user_ca_keys,
                            );
                            if !authoptsp.is_null() {
                                *authoptsp = final_opts;
                                final_opts = 0 as *mut sshauthopt;
                            }
                            ret = 1 as libc::c_int;
                            current_block = 9791366122774864847;
                        }
                    }
                }
            }
        }
        match current_block {
            9791366122774864847 => {}
            _ => {
                crate::log::sshlog(
                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"user_cert_trusted_ca\0",
                    ))
                    .as_ptr(),
                    554 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s\0" as *const u8 as *const libc::c_char,
                    reason,
                );
                auth_debug_add(b"%s\0" as *const u8 as *const libc::c_char, reason);
            }
        }
    }
    sshauthopt_free(principals_opts);
    sshauthopt_free(cert_opts);
    sshauthopt_free(final_opts);
    libc::free(principals_file as *mut libc::c_void);
    libc::free(ca_fp as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn user_key_allowed2(
    mut pw: *mut libc::passwd,
    mut key: *mut crate::sshkey::sshkey,
    mut file: *mut libc::c_char,
    mut remote_ip: *const libc::c_char,
    mut remote_host: *const libc::c_char,
    mut authoptsp: *mut *mut sshauthopt,
) -> libc::c_int {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut found_key: libc::c_int = 0 as libc::c_int;
    if !authoptsp.is_null() {
        *authoptsp = 0 as *mut sshauthopt;
    }
    temporarily_use_uid(pw);
    crate::log::sshlog(
        b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"user_key_allowed2\0"))
            .as_ptr(),
        598 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"trying public key file %s\0" as *const u8 as *const libc::c_char,
        file,
    );
    f = auth_openkeyfile(file, pw, options.strict_modes);
    if !f.is_null() {
        found_key = auth_check_authkeys_file(pw, f, file, key, remote_ip, remote_host, authoptsp);
        fclose(f);
    }
    restore_uid();
    return found_key;
}
unsafe extern "C" fn user_key_command_allowed2(
    mut user_pw: *mut libc::passwd,
    mut key: *mut crate::sshkey::sshkey,
    mut remote_ip: *const libc::c_char,
    mut remote_host: *const libc::c_char,
    mut authoptsp: *mut *mut sshauthopt,
) -> libc::c_int {
    let mut runas_pw: *mut libc::passwd = 0 as *mut libc::passwd;
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut r: libc::c_int = 0;
    let mut ok: libc::c_int = 0;
    let mut found_key: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut uid_swapped: libc::c_int = 0 as libc::c_int;
    let mut ac: libc::c_int = 0 as libc::c_int;
    let mut pid: pid_t = 0;
    let mut username: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut key_fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut keytext: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut uidstr: [libc::c_char; 32] = [0; 32];
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut command: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut av: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut osigchld: Option<unsafe extern "C" fn(libc::c_int) -> ()> = None;
    if !authoptsp.is_null() {
        *authoptsp = 0 as *mut sshauthopt;
    }
    if (options.authorized_keys_command).is_null() {
        return 0 as libc::c_int;
    }
    if (options.authorized_keys_command_user).is_null() {
        crate::log::sshlog(
            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"user_key_command_allowed2\0",
            ))
            .as_ptr(),
            632 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"No user for AuthorizedKeysCommand specified, skipping\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    osigchld = crate::misc::ssh_signal(17 as libc::c_int, None);
    username = percent_expand(
        options.authorized_keys_command_user,
        b"u\0" as *const u8 as *const libc::c_char,
        (*user_pw).pw_name,
        0 as *mut libc::c_void as *mut libc::c_char,
    );
    runas_pw = getpwnam(username);
    if runas_pw.is_null() {
        crate::log::sshlog(
            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"user_key_command_allowed2\0",
            ))
            .as_ptr(),
            648 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"AuthorizedKeysCommandUser \"%s\" not found: %s\0" as *const u8 as *const libc::c_char,
            username,
            libc::strerror(*libc::__errno_location()),
        );
    } else {
        key_fp = crate::sshkey::sshkey_fingerprint(key, options.fingerprint_hash, SSH_FP_DEFAULT);
        if key_fp.is_null() {
            crate::log::sshlog(
                b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"user_key_command_allowed2\0",
                ))
                .as_ptr(),
                655 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"crate::sshkey::sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = sshkey_to_base64(key, &mut keytext);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"user_key_command_allowed2\0",
                    ))
                    .as_ptr(),
                    659 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"sshkey_to_base64 failed\0" as *const u8 as *const libc::c_char,
                );
            } else if argv_split(
                options.authorized_keys_command,
                &mut ac,
                &mut av,
                0 as libc::c_int,
            ) != 0 as libc::c_int
            {
                crate::log::sshlog(
                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"user_key_command_allowed2\0",
                    ))
                    .as_ptr(),
                    666 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"AuthorizedKeysCommand \"%s\" contains invalid quotes\0" as *const u8
                        as *const libc::c_char,
                    options.authorized_keys_command,
                );
            } else if ac == 0 as libc::c_int {
                crate::log::sshlog(
                    b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"user_key_command_allowed2\0",
                    ))
                    .as_ptr(),
                    671 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"AuthorizedKeysCommand \"%s\" yielded no arguments\0" as *const u8
                        as *const libc::c_char,
                    options.authorized_keys_command,
                );
            } else {
                libc::snprintf(
                    uidstr.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
                    b"%llu\0" as *const u8 as *const libc::c_char,
                    (*user_pw).pw_uid as libc::c_ulonglong,
                );
                i = 1 as libc::c_int;
                while i < ac {
                    tmp = percent_expand(
                        *av.offset(i as isize),
                        b"U\0" as *const u8 as *const libc::c_char,
                        uidstr.as_mut_ptr(),
                        b"u\0" as *const u8 as *const libc::c_char,
                        (*user_pw).pw_name,
                        b"h\0" as *const u8 as *const libc::c_char,
                        (*user_pw).pw_dir,
                        b"t\0" as *const u8 as *const libc::c_char,
                        sshkey_ssh_name(key),
                        b"f\0" as *const u8 as *const libc::c_char,
                        key_fp,
                        b"k\0" as *const u8 as *const libc::c_char,
                        keytext,
                        0 as *mut libc::c_void as *mut libc::c_char,
                    );
                    if tmp.is_null() {
                        sshfatal(
                            b"auth2-pubkey.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"user_key_command_allowed2\0",
                            ))
                            .as_ptr(),
                            686 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"percent_expand failed\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    libc::free(*av.offset(i as isize) as *mut libc::c_void);
                    let ref mut fresh1 = *av.offset(i as isize);
                    *fresh1 = tmp;
                    i += 1;
                    i;
                }
                command = argv_assemble(ac, av);
                if ac == 1 as libc::c_int {
                    av = xreallocarray(
                        av as *mut libc::c_void,
                        (ac + 2 as libc::c_int) as size_t,
                        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                    ) as *mut *mut libc::c_char;
                    let ref mut fresh2 = *av.offset(1 as libc::c_int as isize);
                    *fresh2 = crate::xmalloc::xstrdup((*user_pw).pw_name);
                    let ref mut fresh3 = *av.offset(2 as libc::c_int as isize);
                    *fresh3 = 0 as *mut libc::c_char;
                    libc::free(command as *mut libc::c_void);
                    crate::xmalloc::xasprintf(
                        &mut command as *mut *mut libc::c_char,
                        b"%s %s\0" as *const u8 as *const libc::c_char,
                        *av.offset(0 as libc::c_int as isize),
                        *av.offset(1 as libc::c_int as isize),
                    );
                }
                pid = subprocess(
                    b"AuthorizedKeysCommand\0" as *const u8 as *const libc::c_char,
                    command,
                    ac,
                    av,
                    &mut f,
                    ((1 as libc::c_int) << 1 as libc::c_int
                        | (1 as libc::c_int) << 2 as libc::c_int) as u_int,
                    runas_pw,
                    Some(temporarily_use_uid as unsafe extern "C" fn(*mut libc::passwd) -> ()),
                    Some(restore_uid as unsafe extern "C" fn() -> ()),
                );
                if !(pid == 0 as libc::c_int) {
                    uid_swapped = 1 as libc::c_int;
                    temporarily_use_uid(runas_pw);
                    ok = auth_check_authkeys_file(
                        user_pw,
                        f,
                        options.authorized_keys_command,
                        key,
                        remote_ip,
                        remote_host,
                        authoptsp,
                    );
                    fclose(f);
                    f = 0 as *mut libc::FILE;
                    if !(exited_cleanly(
                        pid,
                        b"AuthorizedKeysCommand\0" as *const u8 as *const libc::c_char,
                        command,
                        0 as libc::c_int,
                    ) != 0 as libc::c_int)
                    {
                        found_key = ok;
                    }
                }
            }
        }
    }
    if !f.is_null() {
        fclose(f);
    }
    crate::misc::ssh_signal(17 as libc::c_int, osigchld);
    i = 0 as libc::c_int;
    while i < ac {
        libc::free(*av.offset(i as isize) as *mut libc::c_void);
        i += 1;
        i;
    }
    libc::free(av as *mut libc::c_void);
    if uid_swapped != 0 {
        restore_uid();
    }
    libc::free(command as *mut libc::c_void);
    libc::free(username as *mut libc::c_void);
    libc::free(key_fp as *mut libc::c_void);
    libc::free(keytext as *mut libc::c_void);
    return found_key;
}
pub unsafe extern "C" fn user_key_allowed(
    mut ssh: *mut ssh,
    mut pw: *mut libc::passwd,
    mut key: *mut crate::sshkey::sshkey,
    mut _auth_attempt: libc::c_int,
    mut authoptsp: *mut *mut sshauthopt,
) -> libc::c_int {
    let mut success: u_int = 0 as libc::c_int as u_int;
    let mut i: u_int = 0;
    let mut file: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut opts: *mut sshauthopt = 0 as *mut sshauthopt;
    let mut remote_ip: *const libc::c_char = ssh_remote_ipaddr(ssh);
    let mut remote_host: *const libc::c_char = auth_get_canonical_hostname(ssh, options.use_dns);
    if !authoptsp.is_null() {
        *authoptsp = 0 as *mut sshauthopt;
    }
    if auth_key_is_revoked(key) != 0 {
        return 0 as libc::c_int;
    }
    if sshkey_is_cert(key) != 0 && auth_key_is_revoked((*(*key).cert).signature_key) != 0 {
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as u_int;
    while success == 0 && i < options.num_authkeys_files {
        if !(strcasecmp(
            *(options.authorized_keys_files).offset(i as isize),
            b"none\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int)
        {
            file = expand_authorized_keys(*(options.authorized_keys_files).offset(i as isize), pw);
            success = user_key_allowed2(pw, key, file, remote_ip, remote_host, &mut opts) as u_int;
            libc::free(file as *mut libc::c_void);
            if success == 0 {
                sshauthopt_free(opts);
                opts = 0 as *mut sshauthopt;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    if !(success != 0) {
        success = user_cert_trusted_ca(pw, key, remote_ip, remote_host, &mut opts) as u_int;
        if !(success != 0 as libc::c_int as libc::c_uint) {
            sshauthopt_free(opts);
            opts = 0 as *mut sshauthopt;
            success =
                user_key_command_allowed2(pw, key, remote_ip, remote_host, &mut opts) as u_int;
            if !(success != 0 as libc::c_int as libc::c_uint) {
                sshauthopt_free(opts);
                opts = 0 as *mut sshauthopt;
            }
        }
    }
    if success != 0 && !authoptsp.is_null() {
        *authoptsp = opts;
        opts = 0 as *mut sshauthopt;
    }
    sshauthopt_free(opts);
    return success as libc::c_int;
}
pub static mut method_pubkey: Authmethod = Authmethod {
    name: 0 as *const libc::c_char as *mut libc::c_char,
    synonym: 0 as *const libc::c_char as *mut libc::c_char,
    userauth: None,
    enabled: 0 as *const libc::c_int as *mut libc::c_int,
};
unsafe extern "C" fn run_static_initializers() {
    method_pubkey = {
        let mut init = Authmethod {
            name: b"publickey\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            synonym: b"publickey-hostbound-v00@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            userauth: Some(
                userauth_pubkey
                    as unsafe extern "C" fn(*mut ssh, *const libc::c_char) -> libc::c_int,
            ),
            enabled: &mut options.pubkey_authentication,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
