use crate::atomicio::atomicio;
use ::libc;
use libc::close;

extern "C" {
    pub type ssh_channels;
    pub type sshbuf;
    pub type ec_key_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type kex;
    pub type session_state;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn setproctitle(fmt: *const libc::c_char, _: ...);
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;

    fn vasprintf(
        __ptr: *mut *mut libc::c_char,
        __f: *const libc::c_char,
        __arg: ::core::ffi::VaList,
    ) -> libc::c_int;

    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;
    fn nanosleep(
        __requested_time: *const libc::timespec,
        __remaining: *mut libc::timespec,
    ) -> libc::c_int;

    fn xmalloc(_: size_t) -> *mut libc::c_void;
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn sshpkt_get_end(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_get_cstring(
        ssh: *mut ssh,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshpkt_put_cstring(ssh: *mut ssh, v: *const libc::c_void) -> libc::c_int;
    fn sshpkt_put_u8(ssh: *mut ssh, val: u_char) -> libc::c_int;
    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_start(ssh: *mut ssh, type_0: u_char) -> libc::c_int;
    fn dispatch_protocol_error(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn dispatch_protocol_ignore(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn ssh_dispatch_init(_: *mut ssh, _: Option<dispatch_fn>);
    fn ssh_dispatch_set(_: *mut ssh, _: libc::c_int, _: Option<dispatch_fn>);
    fn ssh_dispatch_run_fatal(_: *mut ssh, _: libc::c_int, _: *mut sig_atomic_t);
    fn ssh_packet_set_log_preamble(_: *mut ssh, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn ssh_packet_disconnect(_: *mut ssh, fmt: *const libc::c_char, _: ...) -> !;
    fn ssh_packet_write_wait(_: *mut ssh) -> libc::c_int;

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
    fn sshbuf_new() -> *mut sshbuf;
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_putf(buf: *mut sshbuf, fmt: *const libc::c_char, _: ...) -> libc::c_int;
    fn sshbuf_put_u8(buf: *mut sshbuf, val: u_char) -> libc::c_int;
    fn sshbuf_dup_string(buf: *mut sshbuf) -> *mut libc::c_char;
    fn monotime_double() -> libc::c_double;
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_equal_public(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_from_private(_: *const sshkey, _: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_format_text(_: *const sshkey, _: *mut sshbuf) -> libc::c_int;
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_fingerprint(_: *const sshkey, _: libc::c_int, _: sshkey_fp_rep) -> *mut libc::c_char;
    fn auth_log(
        _: *mut ssh,
        _: libc::c_int,
        _: libc::c_int,
        _: *const libc::c_char,
        _: *const libc::c_char,
    );
    fn auth_maxtries_exceeded(_: *mut ssh) -> !;
    fn getpwnamallow(_: *mut ssh, user: *const libc::c_char) -> *mut passwd;
    fn auth_root_allowed(_: *mut ssh, _: *const libc::c_char) -> libc::c_int;
    fn auth2_challenge_stop(_: *mut ssh);
    fn fakepw() -> *mut passwd;
    static mut use_privsep: libc::c_int;
    fn mm_inform_authserv(_: *mut libc::c_char, _: *mut libc::c_char);
    fn mm_getpwnamallow(_: *mut ssh, _: *const libc::c_char) -> *mut passwd;
    fn mm_auth2_read_banner() -> *mut libc::c_char;
    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_digest_memory(
        alg: libc::c_int,
        m: *const libc::c_void,
        mlen: size_t,
        d: *mut u_char,
        dlen: size_t,
    ) -> libc::c_int;
    static mut options: ServerOptions;
    static mut method_none: Authmethod;
    static mut method_pubkey: Authmethod;
    static mut method_passwd: Authmethod;
    static mut method_kbdint: Authmethod;
    static mut method_hostbased: Authmethod;
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
pub type __uint8_t = libc::c_uchar;
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
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type ssize_t = __ssize_t;
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
pub struct passwd {
    pub pw_name: *mut libc::c_char,
    pub pw_passwd: *mut libc::c_char,
    pub pw_uid: __uid_t,
    pub pw_gid: __gid_t,
    pub pw_gecos: *mut libc::c_char,
    pub pw_dir: *mut libc::c_char,
    pub pw_shell: *mut libc::c_char,
}
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
pub type C2RustUnnamed_2 = libc::c_uint;
pub const DISPATCH_NONBLOCK: C2RustUnnamed_2 = 1;
pub const DISPATCH_BLOCK: C2RustUnnamed_2 = 0;
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
pub type sshkey_fp_rep = libc::c_uint;
pub const SSH_FP_RANDOMART: sshkey_fp_rep = 4;
pub const SSH_FP_BUBBLEBABBLE: sshkey_fp_rep = 3;
pub const SSH_FP_BASE64: sshkey_fp_rep = 2;
pub const SSH_FP_HEX: sshkey_fp_rep = 1;
pub const SSH_FP_DEFAULT: sshkey_fp_rep = 0;
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
    pub pw: *mut passwd,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Authmethod {
    pub name: *mut libc::c_char,
    pub synonym: *mut libc::c_char,
    pub userauth: Option<unsafe extern "C" fn(*mut ssh, *const libc::c_char) -> libc::c_int>,
    pub enabled: *mut libc::c_int,
}
pub static mut authmethods: [*mut Authmethod; 6] = unsafe {
    [
        &method_none as *const Authmethod as *mut Authmethod,
        &method_pubkey as *const Authmethod as *mut Authmethod,
        &method_passwd as *const Authmethod as *mut Authmethod,
        &method_kbdint as *const Authmethod as *mut Authmethod,
        &method_hostbased as *const Authmethod as *mut Authmethod,
        0 as *const Authmethod as *mut Authmethod,
    ]
};
pub unsafe extern "C" fn auth2_read_banner() -> *mut libc::c_char {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut banner: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;
    let mut n: size_t = 0;
    let mut fd: libc::c_int = 0;
    fd = libc::open(options.banner, 0 as libc::c_int);
    if fd == -(1 as libc::c_int) {
        return 0 as *mut libc::c_char;
    }
    if libc::fstat(fd, &mut st) == -(1 as libc::c_int) {
        close(fd);
        return 0 as *mut libc::c_char;
    }
    if st.st_size <= 0 as libc::c_int as libc::c_long
        || st.st_size
            > (1 as libc::c_int * 1024 as libc::c_int * 1024 as libc::c_int) as libc::c_long
    {
        close(fd);
        return 0 as *mut libc::c_char;
    }
    len = st.st_size as size_t;
    banner = xmalloc(len.wrapping_add(1 as libc::c_int as libc::c_ulong)) as *mut libc::c_char;
    n = atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        fd,
        banner as *mut libc::c_void,
        len,
    );
    close(fd);
    if n != len {
        libc::free(banner as *mut libc::c_void);
        return 0 as *mut libc::c_char;
    }
    *banner.offset(n as isize) = '\0' as i32 as libc::c_char;
    return banner;
}
unsafe extern "C" fn userauth_send_banner(mut ssh: *mut ssh, mut msg: *const libc::c_char) {
    let mut r: libc::c_int = 0;
    r = sshpkt_start(ssh, 53 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_cstring(ssh, msg as *const libc::c_void);
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
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"userauth_send_banner\0"))
                .as_ptr(),
            146 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send packet\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"auth2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"userauth_send_banner\0"))
            .as_ptr(),
        147 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"%s: sent\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"userauth_send_banner\0"))
            .as_ptr(),
    );
}
unsafe extern "C" fn userauth_banner(mut ssh: *mut ssh) {
    let mut banner: *mut libc::c_char = 0 as *mut libc::c_char;
    if (options.banner).is_null() {
        return;
    }
    banner = if use_privsep != 0 {
        mm_auth2_read_banner()
    } else {
        auth2_read_banner()
    };
    if !banner.is_null() {
        userauth_send_banner(ssh, banner);
    }
    libc::free(banner as *mut libc::c_void);
}
pub unsafe extern "C" fn do_authentication2(mut ssh: *mut ssh) {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    ssh_dispatch_init(
        ssh,
        Some(
            dispatch_protocol_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        5 as libc::c_int,
        Some(
            input_service_request
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_run_fatal(
        ssh,
        DISPATCH_BLOCK as libc::c_int,
        &mut (*authctxt).success as *mut sig_atomic_t as *mut sig_atomic_t,
    );
    (*ssh).authctxt = 0 as *mut libc::c_void;
}
unsafe extern "C" fn input_service_request(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut service: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut acceptit: libc::c_int = 0 as libc::c_int;
    r = sshpkt_get_cstring(ssh, &mut service, 0 as *mut size_t);
    if !(r != 0 as libc::c_int || {
        r = sshpkt_get_end(ssh);
        r != 0 as libc::c_int
    }) {
        if authctxt.is_null() {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"input_service_request\0",
                ))
                .as_ptr(),
                192 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"input_service_request: no authctxt\0" as *const u8 as *const libc::c_char,
            );
        }
        if strcmp(
            service,
            b"ssh-userauth\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            if (*authctxt).success == 0 {
                acceptit = 1 as libc::c_int;
                ssh_dispatch_set(
                    ssh,
                    50 as libc::c_int,
                    Some(
                        input_userauth_request
                            as unsafe extern "C" fn(
                                libc::c_int,
                                u_int32_t,
                                *mut ssh,
                            ) -> libc::c_int,
                    ),
                );
            }
        }
        if acceptit != 0 {
            r = sshpkt_start(ssh, 6 as libc::c_int as u_char);
            if !(r != 0 as libc::c_int
                || {
                    r = sshpkt_put_cstring(ssh, service as *const libc::c_void);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_send(ssh);
                    r != 0 as libc::c_int
                }
                || {
                    r = ssh_packet_write_wait(ssh);
                    r != 0 as libc::c_int
                })
            {
                r = 0 as libc::c_int;
            }
        } else {
            crate::log::sshlog(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"input_service_request\0",
                ))
                .as_ptr(),
                211 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"bad service request %s\0" as *const u8 as *const libc::c_char,
                service,
            );
            ssh_packet_disconnect(
                ssh,
                b"bad service request %s\0" as *const u8 as *const libc::c_char,
                service,
            );
        }
    }
    libc::free(service as *mut libc::c_void);
    return r;
}
unsafe extern "C" fn user_specific_delay(mut user: *const libc::c_char) -> libc::c_double {
    let mut b: [libc::c_char; 512] = [0; 512];
    let mut len: size_t = ssh_digest_bytes(4 as libc::c_int);
    let mut hash: *mut u_char = xmalloc(len) as *mut u_char;
    let mut delay: libc::c_double = 0.;
    libc::snprintf(
        b.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 512]>() as usize,
        b"%llu%s\0" as *const u8 as *const libc::c_char,
        options.timing_secret as libc::c_ulonglong,
        user,
    );
    if ssh_digest_memory(
        4 as libc::c_int,
        b.as_mut_ptr() as *const libc::c_void,
        strlen(b.as_mut_ptr()),
        hash,
        len,
    ) != 0 as libc::c_int
    {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"user_specific_delay\0"))
                .as_ptr(),
            232 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ssh_digest_memory\0" as *const u8 as *const libc::c_char,
        );
    }
    delay = ((*(hash as *const u_char).offset(0 as libc::c_int as isize) as u_int32_t)
        << 24 as libc::c_int
        | (*(hash as *const u_char).offset(1 as libc::c_int as isize) as u_int32_t)
            << 16 as libc::c_int
        | (*(hash as *const u_char).offset(2 as libc::c_int as isize) as u_int32_t)
            << 8 as libc::c_int
        | *(hash as *const u_char).offset(3 as libc::c_int as isize) as u_int32_t)
        as libc::c_double
        / 1000 as libc::c_int as libc::c_double
        / 1000 as libc::c_int as libc::c_double
        / 1000 as libc::c_int as libc::c_double
        / 1000 as libc::c_int as libc::c_double;
    freezero(hash as *mut libc::c_void, len);
    crate::log::sshlog(
        b"auth2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"user_specific_delay\0"))
            .as_ptr(),
        236 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"user specific delay %0.3lfms\0" as *const u8 as *const libc::c_char,
        delay / 1000 as libc::c_int as libc::c_double,
    );
    return 0.005f64 + delay;
}
unsafe extern "C" fn ensure_minimum_time_since(
    mut start: libc::c_double,
    mut seconds: libc::c_double,
) {
    let mut ts: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut elapsed: libc::c_double = monotime_double() - start;
    let mut req: libc::c_double = seconds;
    let mut remain: libc::c_double = 0.;
    loop {
        remain = seconds - elapsed;
        if !(remain < 0.0f64) {
            break;
        }
        seconds *= 2 as libc::c_int as libc::c_double;
    }
    ts.tv_sec = remain as __time_t;
    ts.tv_nsec = ((remain - ts.tv_sec as libc::c_double)
        * 1000000000 as libc::c_int as libc::c_double) as __syscall_slong_t;
    crate::log::sshlog(
        b"auth2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"ensure_minimum_time_since\0"))
            .as_ptr(),
        253 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"elapsed %0.3lfms, delaying %0.3lfms (requested %0.3lfms)\0" as *const u8
            as *const libc::c_char,
        elapsed * 1000 as libc::c_int as libc::c_double,
        remain * 1000 as libc::c_int as libc::c_double,
        req * 1000 as libc::c_int as libc::c_double,
    );
    nanosleep(&mut ts, 0 as *mut libc::timespec);
}
unsafe extern "C" fn input_userauth_request(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut m: *mut Authmethod = 0 as *mut Authmethod;
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut service: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut method: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut style: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut authenticated: libc::c_int = 0 as libc::c_int;
    let mut tstart: libc::c_double = monotime_double();
    if authctxt.is_null() {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"input_userauth_request\0",
            ))
            .as_ptr(),
            267 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"input_userauth_request: no authctxt\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshpkt_get_cstring(ssh, &mut user, 0 as *mut size_t);
    if !(r != 0 as libc::c_int
        || {
            r = sshpkt_get_cstring(ssh, &mut service, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_cstring(ssh, &mut method, 0 as *mut size_t);
            r != 0 as libc::c_int
        })
    {
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"input_userauth_request\0",
            ))
            .as_ptr(),
            273 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"userauth-request for user %s service %s method %s\0" as *const u8
                as *const libc::c_char,
            user,
            service,
            method,
        );
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"input_userauth_request\0",
            ))
            .as_ptr(),
            274 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"attempt %d failures %d\0" as *const u8 as *const libc::c_char,
            (*authctxt).attempt,
            (*authctxt).failures,
        );
        style = strchr(user, ':' as i32);
        if !style.is_null() {
            let fresh0 = style;
            style = style.offset(1);
            *fresh0 = 0 as libc::c_int as libc::c_char;
        }
        if (*authctxt).attempt >= 1024 as libc::c_int {
            auth_maxtries_exceeded(ssh);
        }
        let fresh1 = (*authctxt).attempt;
        (*authctxt).attempt = (*authctxt).attempt + 1;
        if fresh1 == 0 as libc::c_int {
            (*authctxt).pw = if use_privsep != 0 {
                mm_getpwnamallow(ssh, user)
            } else {
                getpwnamallow(ssh, user)
            };
            (*authctxt).user = xstrdup(user);
            if !((*authctxt).pw).is_null()
                && strcmp(
                    service,
                    b"ssh-connection\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int
            {
                (*authctxt).valid = 1 as libc::c_int;
                crate::log::sshlog(
                    b"auth2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"input_userauth_request\0",
                    ))
                    .as_ptr(),
                    287 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"setting up authctxt for %s\0" as *const u8 as *const libc::c_char,
                    user,
                );
            } else {
                (*authctxt).valid = 0 as libc::c_int;
                (*authctxt).pw = fakepw();
            }
            ssh_packet_set_log_preamble(
                ssh,
                b"%suser %s\0" as *const u8 as *const libc::c_char,
                if (*authctxt).valid != 0 {
                    b"authenticating \0" as *const u8 as *const libc::c_char
                } else {
                    b"invalid \0" as *const u8 as *const libc::c_char
                },
                user,
            );
            setproctitle(
                b"%s%s\0" as *const u8 as *const libc::c_char,
                if (*authctxt).valid != 0 {
                    user as *const libc::c_char
                } else {
                    b"unknown\0" as *const u8 as *const libc::c_char
                },
                if use_privsep != 0 {
                    b" [net]\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
            );
            (*authctxt).service = xstrdup(service);
            (*authctxt).style = if !style.is_null() {
                xstrdup(style)
            } else {
                0 as *mut libc::c_char
            };
            if use_privsep != 0 {
                mm_inform_authserv(service, style);
            }
            userauth_banner(ssh);
            if auth2_setup_methods_lists(authctxt) != 0 as libc::c_int {
                ssh_packet_disconnect(
                    ssh,
                    b"no authentication methods enabled\0" as *const u8 as *const libc::c_char,
                );
            }
        } else if strcmp(user, (*authctxt).user) != 0 as libc::c_int
            || strcmp(service, (*authctxt).service) != 0 as libc::c_int
        {
            ssh_packet_disconnect(
                ssh,
                b"Change of username or service not allowed: (%s,%s) -> (%s,%s)\0" as *const u8
                    as *const libc::c_char,
                (*authctxt).user,
                (*authctxt).service,
                user,
                service,
            );
        }
        auth2_challenge_stop(ssh);
        auth2_authctxt_reset_info(authctxt);
        (*authctxt).postponed = 0 as libc::c_int;
        (*authctxt).server_caused_failure = 0 as libc::c_int;
        m = authmethod_lookup(authctxt, method);
        if !m.is_null() && (*authctxt).failures < options.max_authtries {
            crate::log::sshlog(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"input_userauth_request\0",
                ))
                .as_ptr(),
                334 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"input_userauth_request: try method %s\0" as *const u8 as *const libc::c_char,
                method,
            );
            authenticated = ((*m).userauth).expect("non-null function pointer")(ssh, method);
        }
        if (*authctxt).authenticated == 0 {
            ensure_minimum_time_since(tstart, user_specific_delay((*authctxt).user));
        }
        userauth_finish(ssh, authenticated, method, 0 as *const libc::c_char);
        r = 0 as libc::c_int;
    }
    libc::free(service as *mut libc::c_void);
    libc::free(user as *mut libc::c_void);
    libc::free(method as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn userauth_finish(
    mut ssh: *mut ssh,
    mut authenticated: libc::c_int,
    mut packet_method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut m: *mut Authmethod = 0 as *mut Authmethod;
    let mut method: *const libc::c_char = packet_method;
    let mut methods: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut partial: libc::c_int = 0 as libc::c_int;
    if authenticated != 0 {
        if (*authctxt).valid == 0 {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_finish\0"))
                    .as_ptr(),
                362 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"INTERNAL ERROR: authenticated invalid user %s\0" as *const u8
                    as *const libc::c_char,
                (*authctxt).user,
            );
        }
        if (*authctxt).postponed != 0 {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_finish\0"))
                    .as_ptr(),
                365 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"INTERNAL ERROR: authenticated and postponed\0" as *const u8
                    as *const libc::c_char,
            );
        }
        m = authmethod_byname(method);
        if m.is_null() {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_finish\0"))
                    .as_ptr(),
                368 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"INTERNAL ERROR: bad method %s\0" as *const u8 as *const libc::c_char,
                method,
            );
        }
        method = (*m).name;
    }
    if authenticated != 0
        && (*(*authctxt).pw).pw_uid == 0 as libc::c_int as libc::c_uint
        && auth_root_allowed(ssh, method) == 0
    {
        authenticated = 0 as libc::c_int;
    }
    if authenticated != 0 && options.num_auth_methods != 0 as libc::c_int as libc::c_uint {
        if auth2_update_methods_lists(authctxt, method, submethod) == 0 {
            authenticated = 0 as libc::c_int;
            partial = 1 as libc::c_int;
        }
    }
    auth_log(ssh, authenticated, partial, method, submethod);
    if authenticated != 0 || partial != 0 {
        auth2_update_session_info(authctxt, method, submethod);
    }
    if (*authctxt).postponed != 0 {
        return;
    }
    if authenticated == 1 as libc::c_int {
        ssh_dispatch_set(
            ssh,
            50 as libc::c_int,
            Some(
                dispatch_protocol_ignore
                    as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
            ),
        );
        r = sshpkt_start(ssh, 52 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshpkt_send(ssh);
                r != 0 as libc::c_int
            }
            || {
                r = ssh_packet_write_wait(ssh);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_finish\0"))
                    .as_ptr(),
                427 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"send success packet\0" as *const u8 as *const libc::c_char,
            );
        }
        (*authctxt).success = 1 as libc::c_int;
        ssh_packet_set_log_preamble(
            ssh,
            b"user %s\0" as *const u8 as *const libc::c_char,
            (*authctxt).user,
        );
    } else {
        if partial == 0
            && (*authctxt).server_caused_failure == 0
            && ((*authctxt).attempt > 1 as libc::c_int
                || strcmp(method, b"none\0" as *const u8 as *const libc::c_char)
                    != 0 as libc::c_int)
        {
            (*authctxt).failures += 1;
            (*authctxt).failures;
        }
        if (*authctxt).failures >= options.max_authtries {
            auth_maxtries_exceeded(ssh);
        }
        methods = authmethods_get(authctxt);
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_finish\0"))
                .as_ptr(),
            444 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"failure partial=%d next methods=\"%s\"\0" as *const u8 as *const libc::c_char,
            partial,
            methods,
        );
        r = sshpkt_start(ssh, 51 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshpkt_put_cstring(ssh, methods as *const libc::c_void);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_u8(ssh, partial as u_char);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_send(ssh);
                r != 0 as libc::c_int
            }
            || {
                r = ssh_packet_write_wait(ssh);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_finish\0"))
                    .as_ptr(),
                450 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"send failure packet\0" as *const u8 as *const libc::c_char,
            );
        }
        libc::free(methods as *mut libc::c_void);
    };
}
pub unsafe extern "C" fn auth2_method_allowed(
    mut authctxt: *mut Authctxt,
    mut method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) -> libc::c_int {
    let mut i: u_int = 0;
    if options.num_auth_methods == 0 as libc::c_int as libc::c_uint {
        return 1 as libc::c_int;
    }
    i = 0 as libc::c_int as u_int;
    while i < (*authctxt).num_auth_methods {
        if list_starts_with(
            *((*authctxt).auth_methods).offset(i as isize),
            method,
            submethod,
        ) != 0 as libc::c_int
        {
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn authmethods_get(mut authctxt: *mut Authctxt) -> *mut libc::c_char {
    let mut b: *mut sshbuf = 0 as *mut sshbuf;
    let mut list: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    b = sshbuf_new();
    if b.is_null() {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"authmethods_get\0"))
                .as_ptr(),
            488 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int;
    while !(authmethods[i as usize]).is_null() {
        if !(strcmp(
            (*authmethods[i as usize]).name,
            b"none\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int)
        {
            if !(((*authmethods[i as usize]).enabled).is_null()
                || *(*authmethods[i as usize]).enabled == 0 as libc::c_int)
            {
                if !(auth2_method_allowed(
                    authctxt,
                    (*authmethods[i as usize]).name,
                    0 as *const libc::c_char,
                ) == 0)
                {
                    r = sshbuf_putf(
                        b,
                        b"%s%s\0" as *const u8 as *const libc::c_char,
                        if sshbuf_len(b) != 0 {
                            b",\0" as *const u8 as *const libc::c_char
                        } else {
                            b"\0" as *const u8 as *const libc::c_char
                        },
                        (*authmethods[i as usize]).name,
                    );
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"auth2.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"authmethods_get\0",
                            ))
                            .as_ptr(),
                            500 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"buffer error\0" as *const u8 as *const libc::c_char,
                        );
                    }
                }
            }
        }
        i += 1;
        i;
    }
    list = sshbuf_dup_string(b);
    if list.is_null() {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"authmethods_get\0"))
                .as_ptr(),
            503 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_dup_string failed\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(b);
    return list;
}
unsafe extern "C" fn authmethod_byname(mut name: *const libc::c_char) -> *mut Authmethod {
    let mut i: libc::c_int = 0;
    if name.is_null() {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"authmethod_byname\0"))
                .as_ptr(),
            514 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"NULL authentication method name\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int;
    while !(authmethods[i as usize]).is_null() {
        if strcmp(name, (*authmethods[i as usize]).name) == 0 as libc::c_int
            || !((*authmethods[i as usize]).synonym).is_null()
                && strcmp(name, (*authmethods[i as usize]).synonym) == 0 as libc::c_int
        {
            return authmethods[i as usize];
        }
        i += 1;
        i;
    }
    crate::log::sshlog(
        b"auth2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"authmethod_byname\0"))
            .as_ptr(),
        521 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"unrecognized authentication method name: %s\0" as *const u8 as *const libc::c_char,
        name,
    );
    return 0 as *mut Authmethod;
}
unsafe extern "C" fn authmethod_lookup(
    mut authctxt: *mut Authctxt,
    mut name: *const libc::c_char,
) -> *mut Authmethod {
    let mut method: *mut Authmethod = 0 as *mut Authmethod;
    method = authmethod_byname(name);
    if method.is_null() {
        return 0 as *mut Authmethod;
    }
    if ((*method).enabled).is_null() || *(*method).enabled == 0 as libc::c_int {
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"authmethod_lookup\0"))
                .as_ptr(),
            534 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"method %s not enabled\0" as *const u8 as *const libc::c_char,
            name,
        );
        return 0 as *mut Authmethod;
    }
    if auth2_method_allowed(authctxt, (*method).name, 0 as *const libc::c_char) == 0 {
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"authmethod_lookup\0"))
                .as_ptr(),
            539 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"method %s not allowed by AuthenticationMethods\0" as *const u8 as *const libc::c_char,
            name,
        );
        return 0 as *mut Authmethod;
    }
    return method;
}
pub unsafe extern "C" fn auth2_methods_valid(
    mut _methods: *const libc::c_char,
    mut need_enable: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut methods: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut omethods: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut method: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: u_int = 0;
    let mut found: u_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if *_methods as libc::c_int == '\0' as i32 {
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"auth2_methods_valid\0"))
                .as_ptr(),
            558 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"empty authentication method list\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    methods = xstrdup(_methods);
    omethods = methods;
    's_23: loop {
        method = strsep(&mut methods, b",\0" as *const u8 as *const libc::c_char);
        if method.is_null() {
            current_block = 15976848397966268834;
            break;
        }
        i = 0 as libc::c_int as u_int;
        found = i;
        while found == 0 && !(authmethods[i as usize]).is_null() {
            p = strchr(method, ':' as i32);
            if !p.is_null() {
                *p = '\0' as i32 as libc::c_char;
            }
            if strcmp(method, (*authmethods[i as usize]).name) != 0 as libc::c_int {
                i = i.wrapping_add(1);
                i;
            } else {
                if need_enable != 0 {
                    if ((*authmethods[i as usize]).enabled).is_null()
                        || *(*authmethods[i as usize]).enabled == 0 as libc::c_int
                    {
                        crate::log::sshlog(
                            b"auth2.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                b"auth2_methods_valid\0",
                            ))
                            .as_ptr(),
                            573 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"Disabled method \"%s\" in AuthenticationMethods list \"%s\"\0"
                                as *const u8 as *const libc::c_char,
                            method,
                            _methods,
                        );
                        current_block = 4927200084332449060;
                        break 's_23;
                    }
                }
                found = 1 as libc::c_int as u_int;
                break;
            }
        }
        if !(found == 0) {
            continue;
        }
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"auth2_methods_valid\0"))
                .as_ptr(),
            582 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Unknown authentication method \"%s\" in list\0" as *const u8 as *const libc::c_char,
            method,
        );
        current_block = 4927200084332449060;
        break;
    }
    match current_block {
        15976848397966268834 => {
            ret = 0 as libc::c_int;
        }
        _ => {}
    }
    libc::free(omethods as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn auth2_setup_methods_lists(mut authctxt: *mut Authctxt) -> libc::c_int {
    let mut i: u_int = 0;
    if options.num_auth_methods == 1 as libc::c_int as libc::c_uint
        && strcmp(
            *(options.auth_methods).offset(0 as libc::c_int as isize),
            b"any\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
    {
        libc::free(*(options.auth_methods).offset(0 as libc::c_int as isize) as *mut libc::c_void);
        let ref mut fresh2 = *(options.auth_methods).offset(0 as libc::c_int as isize);
        *fresh2 = 0 as *mut libc::c_char;
        options.num_auth_methods = 0 as libc::c_int as u_int;
    }
    if options.num_auth_methods == 0 as libc::c_int as libc::c_uint {
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"auth2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"auth2_setup_methods_lists\0"))
            .as_ptr(),
        614 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"checking methods\0" as *const u8 as *const libc::c_char,
    );
    (*authctxt).auth_methods = xcalloc(
        options.num_auth_methods as size_t,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    (*authctxt).num_auth_methods = 0 as libc::c_int as u_int;
    i = 0 as libc::c_int as u_int;
    while i < options.num_auth_methods {
        if auth2_methods_valid(*(options.auth_methods).offset(i as isize), 1 as libc::c_int)
            != 0 as libc::c_int
        {
            crate::log::sshlog(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"auth2_setup_methods_lists\0",
                ))
                .as_ptr(),
                622 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Authentication methods list \"%s\" contains disabled method, skipping\0"
                    as *const u8 as *const libc::c_char,
                *(options.auth_methods).offset(i as isize),
            );
        } else {
            crate::log::sshlog(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"auth2_setup_methods_lists\0",
                ))
                .as_ptr(),
                626 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"authentication methods list %d: %s\0" as *const u8 as *const libc::c_char,
                (*authctxt).num_auth_methods,
                *(options.auth_methods).offset(i as isize),
            );
            let fresh3 = (*authctxt).num_auth_methods;
            (*authctxt).num_auth_methods = ((*authctxt).num_auth_methods).wrapping_add(1);
            let ref mut fresh4 = *((*authctxt).auth_methods).offset(fresh3 as isize);
            *fresh4 = xstrdup(*(options.auth_methods).offset(i as isize));
        }
        i = i.wrapping_add(1);
        i;
    }
    if (*authctxt).num_auth_methods == 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"auth2_setup_methods_lists\0",
            ))
            .as_ptr(),
            632 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"No AuthenticationMethods left after eliminating disabled methods\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn list_starts_with(
    mut methods: *const libc::c_char,
    mut method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) -> libc::c_int {
    let mut l: size_t = strlen(method);
    let mut match_0: libc::c_int = 0;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    if strncmp(methods, method, l) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    p = methods.offset(l as isize);
    match_0 = 1 as libc::c_int;
    if *p as libc::c_int == ':' as i32 {
        if submethod.is_null() {
            return 3 as libc::c_int;
        }
        l = strlen(submethod);
        p = p.offset(1 as libc::c_int as isize);
        if strncmp(submethod, p, l) != 0 {
            return 0 as libc::c_int;
        }
        p = p.offset(l as isize);
        match_0 = 2 as libc::c_int;
    }
    if *p as libc::c_int != ',' as i32 && *p as libc::c_int != '\0' as i32 {
        return 0 as libc::c_int;
    }
    return match_0;
}
unsafe extern "C" fn remove_method(
    mut methods: *mut *mut libc::c_char,
    mut method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) -> libc::c_int {
    let mut omethods: *mut libc::c_char = *methods;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut l: size_t = strlen(method);
    let mut match_0: libc::c_int = 0;
    match_0 = list_starts_with(omethods, method, submethod);
    if match_0 != 1 as libc::c_int && match_0 != 2 as libc::c_int {
        return 0 as libc::c_int;
    }
    p = omethods.offset(l as isize);
    if !submethod.is_null() && match_0 == 2 as libc::c_int {
        p = p.offset((1 as libc::c_int as libc::c_ulong).wrapping_add(strlen(submethod)) as isize);
    }
    if *p as libc::c_int == ',' as i32 {
        p = p.offset(1);
        p;
    }
    *methods = xstrdup(p);
    libc::free(omethods as *mut libc::c_void);
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn auth2_update_methods_lists(
    mut authctxt: *mut Authctxt,
    mut method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) -> libc::c_int {
    let mut i: u_int = 0;
    let mut found: u_int = 0 as libc::c_int as u_int;
    crate::log::sshlog(
        b"auth2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"auth2_update_methods_lists\0",
        ))
        .as_ptr(),
        702 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"updating methods list after \"%s\"\0" as *const u8 as *const libc::c_char,
        method,
    );
    i = 0 as libc::c_int as u_int;
    while i < (*authctxt).num_auth_methods {
        if !(remove_method(
            &mut *((*authctxt).auth_methods).offset(i as isize),
            method,
            submethod,
        ) == 0)
        {
            found = 1 as libc::c_int as u_int;
            if **((*authctxt).auth_methods).offset(i as isize) as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"auth2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"auth2_update_methods_lists\0",
                    ))
                    .as_ptr(),
                    709 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"authentication methods list %d complete\0" as *const u8
                        as *const libc::c_char,
                    i,
                );
                return 1 as libc::c_int;
            }
            crate::log::sshlog(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"auth2_update_methods_lists\0",
                ))
                .as_ptr(),
                713 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"authentication methods list %d remaining: \"%s\"\0" as *const u8
                    as *const libc::c_char,
                i,
                *((*authctxt).auth_methods).offset(i as isize),
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    if found == 0 {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"auth2_update_methods_lists\0",
            ))
            .as_ptr(),
            717 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"method not in AuthenticationMethods\0" as *const u8 as *const libc::c_char,
        );
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn auth2_authctxt_reset_info(mut authctxt: *mut Authctxt) {
    sshkey_free((*authctxt).auth_method_key);
    libc::free((*authctxt).auth_method_info as *mut libc::c_void);
    (*authctxt).auth_method_key = 0 as *mut sshkey;
    (*authctxt).auth_method_info = 0 as *mut libc::c_char;
}
pub unsafe extern "C" fn auth2_record_info(
    mut authctxt: *mut Authctxt,
    mut fmt: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::core::ffi::VaListImpl;
    let mut i: libc::c_int = 0;
    libc::free((*authctxt).auth_method_info as *mut libc::c_void);
    (*authctxt).auth_method_info = 0 as *mut libc::c_char;
    ap = args.clone();
    i = vasprintf(&mut (*authctxt).auth_method_info, fmt, ap.as_va_list());
    if i == -(1 as libc::c_int) {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"auth2_record_info\0"))
                .as_ptr(),
            745 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"vasprintf failed\0" as *const u8 as *const libc::c_char,
        );
    }
}
pub unsafe extern "C" fn auth2_record_key(
    mut authctxt: *mut Authctxt,
    mut authenticated: libc::c_int,
    mut key: *const sshkey,
) {
    let mut tmp: *mut *mut sshkey = 0 as *mut *mut sshkey;
    let mut dup: *mut sshkey = 0 as *mut sshkey;
    let mut r: libc::c_int = 0;
    r = sshkey_from_private(key, &mut dup);
    if r != 0 as libc::c_int {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"auth2_record_key\0"))
                .as_ptr(),
            761 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"copy key\0" as *const u8 as *const libc::c_char,
        );
    }
    sshkey_free((*authctxt).auth_method_key);
    (*authctxt).auth_method_key = dup;
    if authenticated == 0 {
        return;
    }
    r = sshkey_from_private(key, &mut dup);
    if r != 0 as libc::c_int {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"auth2_record_key\0"))
                .as_ptr(),
            770 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"copy key\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*authctxt).nprev_keys >= 2147483647 as libc::c_int as libc::c_uint || {
        tmp = recallocarray(
            (*authctxt).prev_keys as *mut libc::c_void,
            (*authctxt).nprev_keys as size_t,
            ((*authctxt).nprev_keys).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
            ::core::mem::size_of::<*mut sshkey>() as libc::c_ulong,
        ) as *mut *mut sshkey;
        tmp.is_null()
    } {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"auth2_record_key\0"))
                .as_ptr(),
            774 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"reallocarray failed\0" as *const u8 as *const libc::c_char,
        );
    }
    (*authctxt).prev_keys = tmp;
    let ref mut fresh5 = *((*authctxt).prev_keys).offset((*authctxt).nprev_keys as isize);
    *fresh5 = dup;
    (*authctxt).nprev_keys = ((*authctxt).nprev_keys).wrapping_add(1);
    (*authctxt).nprev_keys;
}
pub unsafe extern "C" fn auth2_key_already_used(
    mut authctxt: *mut Authctxt,
    mut key: *const sshkey,
) -> libc::c_int {
    let mut i: u_int = 0;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*authctxt).nprev_keys {
        if sshkey_equal_public(key, *((*authctxt).prev_keys).offset(i as isize)) != 0 {
            fp = sshkey_fingerprint(
                *((*authctxt).prev_keys).offset(i as isize),
                options.fingerprint_hash,
                SSH_FP_DEFAULT,
            );
            crate::log::sshlog(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"auth2_key_already_used\0",
                ))
                .as_ptr(),
                794 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"key already used: %s %s\0" as *const u8 as *const libc::c_char,
                sshkey_type(*((*authctxt).prev_keys).offset(i as isize)),
                if fp.is_null() {
                    b"UNKNOWN\0" as *const u8 as *const libc::c_char
                } else {
                    fp as *const libc::c_char
                },
            );
            libc::free(fp as *mut libc::c_void);
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn auth2_update_session_info(
    mut authctxt: *mut Authctxt,
    mut method: *const libc::c_char,
    mut submethod: *const libc::c_char,
) {
    let mut r: libc::c_int = 0;
    if ((*authctxt).session_info).is_null() {
        (*authctxt).session_info = sshbuf_new();
        if ((*authctxt).session_info).is_null() {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"auth2_update_session_info\0",
                ))
                .as_ptr(),
                814 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"sshbuf_new\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    r = sshbuf_putf(
        (*authctxt).session_info,
        b"%s%s%s\0" as *const u8 as *const libc::c_char,
        method,
        if submethod.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b"/\0" as *const u8 as *const libc::c_char
        },
        if submethod.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            submethod
        },
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"auth2_update_session_info\0",
            ))
            .as_ptr(),
            821 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"append method\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*authctxt).auth_method_key).is_null() {
        r = sshbuf_put_u8((*authctxt).session_info, ' ' as i32 as u_char);
        if r != 0 as libc::c_int || {
            r = sshkey_format_text((*authctxt).auth_method_key, (*authctxt).session_info);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"auth2_update_session_info\0",
                ))
                .as_ptr(),
                828 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"append key\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if !((*authctxt).auth_method_info).is_null() {
        if !(strchr((*authctxt).auth_method_info, '\n' as i32)).is_null() {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"auth2_update_session_info\0",
                ))
                .as_ptr(),
                834 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"auth_method_info contains \\n\0" as *const u8 as *const libc::c_char,
            );
        }
        r = sshbuf_put_u8((*authctxt).session_info, ' ' as i32 as u_char);
        if r != 0 as libc::c_int || {
            r = sshbuf_putf(
                (*authctxt).session_info,
                b"%s\0" as *const u8 as *const libc::c_char,
                (*authctxt).auth_method_info,
            );
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"auth2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"auth2_update_session_info\0",
                ))
                .as_ptr(),
                838 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"append method info\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    r = sshbuf_put_u8((*authctxt).session_info, '\n' as i32 as u_char);
    if r != 0 as libc::c_int {
        sshfatal(
            b"auth2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"auth2_update_session_info\0",
            ))
            .as_ptr(),
            842 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"append\0" as *const u8 as *const libc::c_char,
        );
    }
}
