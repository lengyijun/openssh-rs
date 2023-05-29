use crate::digest_openssl::ssh_digest_ctx;
use crate::misc::parse_uri;
use ::libc;
use libc::kill;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn vis(
        _: *mut libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
    ) -> *mut libc::c_char;

    fn access(__name: *const libc::c_char, __type: libc::c_int) -> libc::c_int;
    fn closefrom(__lowfd: libc::c_int);
    fn execv(__path: *const libc::c_char, __argv: *const *mut libc::c_char) -> libc::c_int;

    fn gethostname(__name: *mut libc::c_char, __len: size_t) -> libc::c_int;
    fn getservbyname(__name: *const libc::c_char, __proto: *const libc::c_char) -> *mut servent;
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::FILE;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;

    fn __getdelim(
        __lineptr: *mut *mut libc::c_char,
        __n: *mut size_t,
        __delimiter: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> __ssize_t;
    fn fileno(__stream: *mut libc::FILE) -> libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;

    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
        -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;

    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn _ssh__compat_glob(
        _: *const libc::c_char,
        _: libc::c_int,
        _: Option<unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int>,
        _: *mut crate::openbsd_compat::glob::_ssh_compat_glob_t,
    ) -> libc::c_int;
    fn _ssh__compat_globfree(_: *mut crate::openbsd_compat::glob::_ssh_compat_glob_t);
    fn xreallocarray(_: *mut libc::c_void, _: size_t, _: size_t) -> *mut libc::c_void;

    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn strtol(_: *const libc::c_char, _: *mut *mut libc::c_char, _: libc::c_int) -> libc::c_long;

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn ciphers_valid(_: *const libc::c_char) -> libc::c_int;
    fn cipher_alg_list(_: libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn log_facility_number(_: *mut libc::c_char) -> SyslogFacility;
    fn log_facility_name(_: SyslogFacility) -> *const libc::c_char;
    fn log_level_number(_: *mut libc::c_char) -> LogLevel;
    fn log_level_name(_: LogLevel) -> *const libc::c_char;

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

    fn sshkey_names_valid2(_: *const libc::c_char, _: libc::c_int) -> libc::c_int;
    fn sshkey_alg_list(
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_char,
    ) -> *mut libc::c_char;
    fn forward_equals(_: *const Forward, _: *const Forward) -> libc::c_int;
    fn rtrim(_: *mut libc::c_char);
    fn strdelim(_: *mut *mut libc::c_char) -> *mut libc::c_char;

    fn a2tun(_: *const libc::c_char, _: *mut libc::c_int) -> libc::c_int;
    fn hpdelim(_: *mut *mut libc::c_char) -> *mut libc::c_char;
    fn cleanhostname(_: *mut libc::c_char) -> *mut libc::c_char;
    fn parse_user_host_port(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: *mut *mut libc::c_char,
        _: *mut libc::c_int,
    ) -> libc::c_int;

    fn convtime(_: *const libc::c_char) -> libc::c_int;
    fn dollar_expand(_: *mut libc::c_int, string: *const libc::c_char, _: ...)
        -> *mut libc::c_char;
    fn percent_expand(_: *const libc::c_char, _: ...) -> *mut libc::c_char;
    fn tohex(_: *const libc::c_void, _: size_t) -> *mut libc::c_char;
    fn lowercase(s: *mut libc::c_char);
    fn valid_domain(
        _: *mut libc::c_char,
        _: libc::c_int,
        _: *mut *const libc::c_char,
    ) -> libc::c_int;
    fn valid_env_name(_: *const libc::c_char) -> libc::c_int;
    fn atoi_err(_: *const libc::c_char, _: *mut libc::c_int) -> *const libc::c_char;
    fn path_absolute(_: *const libc::c_char) -> libc::c_int;
    fn stdfd_devnull(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn parse_ipqos(_: *const libc::c_char) -> libc::c_int;
    fn iptos2str(_: libc::c_int) -> *const libc::c_char;
    fn lookup_setenv_in_list(
        env: *const libc::c_char,
        envs: *const *mut libc::c_char,
        nenvs: size_t,
    ) -> *const libc::c_char;
    fn argv_split(
        _: *const libc::c_char,
        _: *mut libc::c_int,
        _: *mut *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn argv_next(_: *mut libc::c_int, _: *mut *mut *mut libc::c_char) -> *mut libc::c_char;
    fn argv_consume(_: *mut libc::c_int);
    fn argv_free(_: *mut *mut libc::c_char, _: libc::c_int);
    fn opt_array_append(
        file: *const libc::c_char,
        line: libc::c_int,
        directive: *const libc::c_char,
        array: *mut *mut *mut libc::c_char,
        lp: *mut u_int,
        s: *const libc::c_char,
    );

    fn match_pattern(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn match_pattern_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn match_hostname(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn match_filter_allowlist(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn mac_valid(_: *const libc::c_char) -> libc::c_int;
    fn mac_alg_list(_: libc::c_char) -> *mut libc::c_char;
    fn kex_assemble_names(
        _: *mut *mut libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn kex_names_valid(_: *const libc::c_char) -> libc::c_int;
    fn kex_alg_list(_: libc::c_char) -> *mut libc::c_char;
    fn ssh_digest_alg_by_name(name: *const libc::c_char) -> libc::c_int;
    fn ssh_digest_alg_name(alg: libc::c_int) -> *const libc::c_char;
    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_digest_start(alg: libc::c_int) -> *mut ssh_digest_ctx;
    fn ssh_digest_update(
        ctx: *mut ssh_digest_ctx,
        m: *const libc::c_void,
        mlen: size_t,
    ) -> libc::c_int;
    fn ssh_digest_final(ctx: *mut ssh_digest_ctx, d: *mut u_char, dlen: size_t) -> libc::c_int;
    fn ssh_digest_free(ctx: *mut ssh_digest_ctx);
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
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
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type pid_t = __pid_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int64_t = __uint64_t;

pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_un {
    pub sun_family: sa_family_t,
    pub sun_path: [libc::c_char; 108],
}
pub type uint8_t = __uint8_t;

pub type _IO_lock_t = ();

pub type __sighandler_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct servent {
    pub s_name: *mut libc::c_char,
    pub s_aliases: *mut *mut libc::c_char,
    pub s_port: libc::c_int,
    pub s_proto: *mut libc::c_char,
}
pub type C2RustUnnamed = libc::c_uint;
pub const _ISalnum: C2RustUnnamed = 8;
pub const _ISpunct: C2RustUnnamed = 4;
pub const _IScntrl: C2RustUnnamed = 2;
pub const _ISblank: C2RustUnnamed = 1;
pub const _ISgraph: C2RustUnnamed = 32768;
pub const _ISprint: C2RustUnnamed = 16384;
pub const _ISspace: C2RustUnnamed = 8192;
pub const _ISxdigit: C2RustUnnamed = 4096;
pub const _ISdigit: C2RustUnnamed = 2048;
pub const _ISalpha: C2RustUnnamed = 1024;
pub const _ISlower: C2RustUnnamed = 512;
pub const _ISupper: C2RustUnnamed = 256;

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
pub const oUnsupported: OpCodes = 102;
pub const oDeprecated: OpCodes = 101;
pub const oRequiredRSASize: OpCodes = 97;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct multistate {
    pub key: *mut libc::c_char,
    pub value: libc::c_int,
}
pub const oEnableEscapeCommandline: OpCodes = 98;
pub const oIdentityAgent: OpCodes = 20;
pub const oAddKeysToAgent: OpCodes = 19;
pub const oPubkeyAcceptedAlgorithms: OpCodes = 92;
pub const oHostbasedAcceptedAlgorithms: OpCodes = 91;
pub const oUpdateHostkeys: OpCodes = 90;
pub const oFingerprintHash: OpCodes = 89;
pub const oRevokedHostKeys: OpCodes = 88;
pub const oStreamLocalBindUnlink: OpCodes = 87;
pub const oStreamLocalBindMask: OpCodes = 86;
pub const oCanonicalizeFallbackLocal: OpCodes = 84;
pub const oCanonicalizeMaxDots: OpCodes = 83;
pub const oCanonicalizeHostname: OpCodes = 82;
pub const oCanonicalizePermittedCNAMEs: OpCodes = 85;
pub const oCanonicalDomains: OpCodes = 81;
pub const oProxyUseFdpass: OpCodes = 80;
pub const oIgnoreUnknown: OpCodes = 79;
pub const oForkAfterAuthentication: OpCodes = 78;
pub const oStdinNull: OpCodes = 77;
pub const oSessionType: OpCodes = 76;
pub const oRequestTTY: OpCodes = 75;
pub const oIPQoS: OpCodes = 74;
pub const oInclude: OpCodes = 3;
pub const oVisualHostKey: OpCodes = 72;
pub const oRemoteCommand: OpCodes = 71;
pub const oPermitLocalCommand: OpCodes = 70;
pub const oLocalCommand: OpCodes = 69;
pub const oTunnelDevice: OpCodes = 68;
pub const oTunnel: OpCodes = 67;
pub const oHashKnownHosts: OpCodes = 66;
pub const oControlPersist: OpCodes = 65;
pub const oControlMaster: OpCodes = 64;
pub const oControlPath: OpCodes = 63;
pub type OpCodes = libc::c_uint;
pub const oIgnoredUnknownOption: OpCodes = 100;
pub const oIgnore: OpCodes = 99;
pub const oKnownHostsCommand: OpCodes = 96;
pub const oSecurityKeyProvider: OpCodes = 95;
pub const oProxyJump: OpCodes = 94;
pub const oCASignatureAlgorithms: OpCodes = 93;
pub const oKexAlgorithms: OpCodes = 73;
pub const oSetEnv: OpCodes = 62;
pub const oSendEnv: OpCodes = 61;
pub const oIdentitiesOnly: OpCodes = 60;
pub const oServerAliveCountMax: OpCodes = 59;
pub const oServerAliveInterval: OpCodes = 58;
pub const oGssDelegateCreds: OpCodes = 57;
pub const oGssAuthentication: OpCodes = 56;
pub const oAddressFamily: OpCodes = 55;
pub const oConnectTimeout: OpCodes = 54;
pub const oVerifyHostKeyDNS: OpCodes = 53;
pub const oRekeyLimit: OpCodes = 52;
pub const oEnableSSHKeysign: OpCodes = 51;
pub const oNoHostAuthenticationForLocalhost: OpCodes = 50;
pub const oClearAllForwardings: OpCodes = 49;
pub const oPKCS11Provider: OpCodes = 48;
pub const oBindInterface: OpCodes = 47;
pub const oBindAddress: OpCodes = 46;
pub const oHostKeyAlgorithms: OpCodes = 45;
pub const oHostbasedAuthentication: OpCodes = 44;
pub const oPreferredAuthentications: OpCodes = 43;
pub const oDynamicForward: OpCodes = 42;
pub const oHostKeyAlias: OpCodes = 41;
pub const oKbdInteractiveDevices: OpCodes = 40;
pub const oKbdInteractiveAuthentication: OpCodes = 39;
pub const oPubkeyAuthentication: OpCodes = 38;
pub const oMacs: OpCodes = 37;
pub const oCiphers: OpCodes = 36;
pub const oLogVerbose: OpCodes = 35;
pub const oLogLevel: OpCodes = 34;
pub const oLogFacility: OpCodes = 33;
pub const oNumberOfPasswordPrompts: OpCodes = 32;
pub const oTCPKeepAlive: OpCodes = 31;
pub const oCompression: OpCodes = 30;
pub const oStrictHostKeyChecking: OpCodes = 29;
pub const oCheckHostIP: OpCodes = 28;
pub const oBatchMode: OpCodes = 27;
pub const oConnectionAttempts: OpCodes = 26;
pub const oUserKnownHostsFile: OpCodes = 25;
pub const oGlobalKnownHostsFile: OpCodes = 24;
pub const oProxyCommand: OpCodes = 23;
pub const oEscapeChar: OpCodes = 22;
pub const oUser: OpCodes = 21;
pub const oCertificateFile: OpCodes = 18;
pub const oPermitRemoteOpen: OpCodes = 17;
pub const oLocalForward: OpCodes = 16;
pub const oRemoteForward: OpCodes = 15;
pub const oPort: OpCodes = 14;
pub const oHostname: OpCodes = 13;
pub const oIdentityFile: OpCodes = 12;
pub const oXAuthLocation: OpCodes = 11;
pub const oPasswordAuthentication: OpCodes = 10;
pub const oExitOnForwardFailure: OpCodes = 9;
pub const oGatewayPorts: OpCodes = 8;
pub const oForwardX11Timeout: OpCodes = 7;
pub const oForwardX11Trusted: OpCodes = 6;
pub const oForwardX11: OpCodes = 5;
pub const oForwardAgent: OpCodes = 4;
pub const oMatch: OpCodes = 2;
pub const oHost: OpCodes = 1;
pub const oBadOption: OpCodes = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub name: *const libc::c_char,
    pub opcode: OpCodes,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fwdarg {
    pub arg: *mut libc::c_char,
    pub ispath: libc::c_int,
}
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
#[inline]
unsafe extern "C" fn getline(
    mut __lineptr: *mut *mut libc::c_char,
    mut __n: *mut size_t,
    mut __stream: *mut libc::FILE,
) -> __ssize_t {
    return __getdelim(__lineptr, __n, '\n' as i32, __stream);
}
static mut keywords: [C2RustUnnamed_0; 123] = [
    {
        let mut init = C2RustUnnamed_0 {
            name: b"protocol\0" as *const u8 as *const libc::c_char,
            opcode: oIgnore,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"cipher\0" as *const u8 as *const libc::c_char,
            opcode: oDeprecated,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"fallbacktorsh\0" as *const u8 as *const libc::c_char,
            opcode: oDeprecated,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"globalknownhostsfile2\0" as *const u8 as *const libc::c_char,
            opcode: oDeprecated,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"rhostsauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oDeprecated,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"userknownhostsfile2\0" as *const u8 as *const libc::c_char,
            opcode: oDeprecated,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"useroaming\0" as *const u8 as *const libc::c_char,
            opcode: oDeprecated,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"usersh\0" as *const u8 as *const libc::c_char,
            opcode: oDeprecated,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"useprivilegedport\0" as *const u8 as *const libc::c_char,
            opcode: oDeprecated,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"afstokenpassing\0" as *const u8 as *const libc::c_char,
            opcode: oUnsupported,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"kerberosauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oUnsupported,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"kerberostgtpassing\0" as *const u8 as *const libc::c_char,
            opcode: oUnsupported,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"rsaauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oUnsupported,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"rhostsrsaauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oUnsupported,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"compressionlevel\0" as *const u8 as *const libc::c_char,
            opcode: oUnsupported,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"gssapiauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oUnsupported,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"gssapidelegatecredentials\0" as *const u8 as *const libc::c_char,
            opcode: oUnsupported,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"pkcs11provider\0" as *const u8 as *const libc::c_char,
            opcode: oPKCS11Provider,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"smartcarddevice\0" as *const u8 as *const libc::c_char,
            opcode: oPKCS11Provider,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"forwardagent\0" as *const u8 as *const libc::c_char,
            opcode: oForwardAgent,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"forwardx11\0" as *const u8 as *const libc::c_char,
            opcode: oForwardX11,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"forwardx11trusted\0" as *const u8 as *const libc::c_char,
            opcode: oForwardX11Trusted,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"forwardx11timeout\0" as *const u8 as *const libc::c_char,
            opcode: oForwardX11Timeout,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"exitonforwardfailure\0" as *const u8 as *const libc::c_char,
            opcode: oExitOnForwardFailure,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"xauthlocation\0" as *const u8 as *const libc::c_char,
            opcode: oXAuthLocation,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"gatewayports\0" as *const u8 as *const libc::c_char,
            opcode: oGatewayPorts,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"passwordauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oPasswordAuthentication,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"kbdinteractiveauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oKbdInteractiveAuthentication,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"kbdinteractivedevices\0" as *const u8 as *const libc::c_char,
            opcode: oKbdInteractiveDevices,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"challengeresponseauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oKbdInteractiveAuthentication,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"skeyauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oKbdInteractiveAuthentication,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"tisauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oKbdInteractiveAuthentication,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"pubkeyauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oPubkeyAuthentication,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"dsaauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oPubkeyAuthentication,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"hostbasedauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oHostbasedAuthentication,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"identityfile\0" as *const u8 as *const libc::c_char,
            opcode: oIdentityFile,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"identityfile2\0" as *const u8 as *const libc::c_char,
            opcode: oIdentityFile,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"identitiesonly\0" as *const u8 as *const libc::c_char,
            opcode: oIdentitiesOnly,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"certificatefile\0" as *const u8 as *const libc::c_char,
            opcode: oCertificateFile,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"addkeystoagent\0" as *const u8 as *const libc::c_char,
            opcode: oAddKeysToAgent,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"identityagent\0" as *const u8 as *const libc::c_char,
            opcode: oIdentityAgent,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"hostname\0" as *const u8 as *const libc::c_char,
            opcode: oHostname,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"hostkeyalias\0" as *const u8 as *const libc::c_char,
            opcode: oHostKeyAlias,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"proxycommand\0" as *const u8 as *const libc::c_char,
            opcode: oProxyCommand,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"port\0" as *const u8 as *const libc::c_char,
            opcode: oPort,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"ciphers\0" as *const u8 as *const libc::c_char,
            opcode: oCiphers,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"macs\0" as *const u8 as *const libc::c_char,
            opcode: oMacs,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"remoteforward\0" as *const u8 as *const libc::c_char,
            opcode: oRemoteForward,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"localforward\0" as *const u8 as *const libc::c_char,
            opcode: oLocalForward,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"permitremoteopen\0" as *const u8 as *const libc::c_char,
            opcode: oPermitRemoteOpen,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"user\0" as *const u8 as *const libc::c_char,
            opcode: oUser,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"host\0" as *const u8 as *const libc::c_char,
            opcode: oHost,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"match\0" as *const u8 as *const libc::c_char,
            opcode: oMatch,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"escapechar\0" as *const u8 as *const libc::c_char,
            opcode: oEscapeChar,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"globalknownhostsfile\0" as *const u8 as *const libc::c_char,
            opcode: oGlobalKnownHostsFile,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"userknownhostsfile\0" as *const u8 as *const libc::c_char,
            opcode: oUserKnownHostsFile,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"connectionattempts\0" as *const u8 as *const libc::c_char,
            opcode: oConnectionAttempts,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"batchmode\0" as *const u8 as *const libc::c_char,
            opcode: oBatchMode,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"checkhostip\0" as *const u8 as *const libc::c_char,
            opcode: oCheckHostIP,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"stricthostkeychecking\0" as *const u8 as *const libc::c_char,
            opcode: oStrictHostKeyChecking,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"compression\0" as *const u8 as *const libc::c_char,
            opcode: oCompression,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"tcpkeepalive\0" as *const u8 as *const libc::c_char,
            opcode: oTCPKeepAlive,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"keepalive\0" as *const u8 as *const libc::c_char,
            opcode: oTCPKeepAlive,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"numberofpasswordprompts\0" as *const u8 as *const libc::c_char,
            opcode: oNumberOfPasswordPrompts,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"syslogfacility\0" as *const u8 as *const libc::c_char,
            opcode: oLogFacility,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"loglevel\0" as *const u8 as *const libc::c_char,
            opcode: oLogLevel,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"logverbose\0" as *const u8 as *const libc::c_char,
            opcode: oLogVerbose,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"dynamicforward\0" as *const u8 as *const libc::c_char,
            opcode: oDynamicForward,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"preferredauthentications\0" as *const u8 as *const libc::c_char,
            opcode: oPreferredAuthentications,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"hostkeyalgorithms\0" as *const u8 as *const libc::c_char,
            opcode: oHostKeyAlgorithms,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"casignaturealgorithms\0" as *const u8 as *const libc::c_char,
            opcode: oCASignatureAlgorithms,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"bindaddress\0" as *const u8 as *const libc::c_char,
            opcode: oBindAddress,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"bindinterface\0" as *const u8 as *const libc::c_char,
            opcode: oBindInterface,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"clearallforwardings\0" as *const u8 as *const libc::c_char,
            opcode: oClearAllForwardings,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"enablesshkeysign\0" as *const u8 as *const libc::c_char,
            opcode: oEnableSSHKeysign,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"verifyhostkeydns\0" as *const u8 as *const libc::c_char,
            opcode: oVerifyHostKeyDNS,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"nohostauthenticationforlocalhost\0" as *const u8 as *const libc::c_char,
            opcode: oNoHostAuthenticationForLocalhost,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"rekeylimit\0" as *const u8 as *const libc::c_char,
            opcode: oRekeyLimit,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"connecttimeout\0" as *const u8 as *const libc::c_char,
            opcode: oConnectTimeout,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"addressfamily\0" as *const u8 as *const libc::c_char,
            opcode: oAddressFamily,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"serveraliveinterval\0" as *const u8 as *const libc::c_char,
            opcode: oServerAliveInterval,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"serveralivecountmax\0" as *const u8 as *const libc::c_char,
            opcode: oServerAliveCountMax,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"sendenv\0" as *const u8 as *const libc::c_char,
            opcode: oSendEnv,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"setenv\0" as *const u8 as *const libc::c_char,
            opcode: oSetEnv,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"controlpath\0" as *const u8 as *const libc::c_char,
            opcode: oControlPath,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"controlmaster\0" as *const u8 as *const libc::c_char,
            opcode: oControlMaster,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"controlpersist\0" as *const u8 as *const libc::c_char,
            opcode: oControlPersist,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"hashknownhosts\0" as *const u8 as *const libc::c_char,
            opcode: oHashKnownHosts,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"include\0" as *const u8 as *const libc::c_char,
            opcode: oInclude,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"tunnel\0" as *const u8 as *const libc::c_char,
            opcode: oTunnel,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"tunneldevice\0" as *const u8 as *const libc::c_char,
            opcode: oTunnelDevice,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"localcommand\0" as *const u8 as *const libc::c_char,
            opcode: oLocalCommand,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"permitlocalcommand\0" as *const u8 as *const libc::c_char,
            opcode: oPermitLocalCommand,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"remotecommand\0" as *const u8 as *const libc::c_char,
            opcode: oRemoteCommand,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"visualhostkey\0" as *const u8 as *const libc::c_char,
            opcode: oVisualHostKey,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"kexalgorithms\0" as *const u8 as *const libc::c_char,
            opcode: oKexAlgorithms,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"ipqos\0" as *const u8 as *const libc::c_char,
            opcode: oIPQoS,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"requesttty\0" as *const u8 as *const libc::c_char,
            opcode: oRequestTTY,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"sessiontype\0" as *const u8 as *const libc::c_char,
            opcode: oSessionType,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"stdinnull\0" as *const u8 as *const libc::c_char,
            opcode: oStdinNull,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"forkafterauthentication\0" as *const u8 as *const libc::c_char,
            opcode: oForkAfterAuthentication,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"proxyusefdpass\0" as *const u8 as *const libc::c_char,
            opcode: oProxyUseFdpass,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"canonicaldomains\0" as *const u8 as *const libc::c_char,
            opcode: oCanonicalDomains,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"canonicalizefallbacklocal\0" as *const u8 as *const libc::c_char,
            opcode: oCanonicalizeFallbackLocal,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"canonicalizehostname\0" as *const u8 as *const libc::c_char,
            opcode: oCanonicalizeHostname,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"canonicalizemaxdots\0" as *const u8 as *const libc::c_char,
            opcode: oCanonicalizeMaxDots,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"canonicalizepermittedcnames\0" as *const u8 as *const libc::c_char,
            opcode: oCanonicalizePermittedCNAMEs,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"streamlocalbindmask\0" as *const u8 as *const libc::c_char,
            opcode: oStreamLocalBindMask,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"streamlocalbindunlink\0" as *const u8 as *const libc::c_char,
            opcode: oStreamLocalBindUnlink,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"revokedhostkeys\0" as *const u8 as *const libc::c_char,
            opcode: oRevokedHostKeys,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"fingerprinthash\0" as *const u8 as *const libc::c_char,
            opcode: oFingerprintHash,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"updatehostkeys\0" as *const u8 as *const libc::c_char,
            opcode: oUpdateHostkeys,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"hostbasedacceptedalgorithms\0" as *const u8 as *const libc::c_char,
            opcode: oHostbasedAcceptedAlgorithms,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"hostbasedkeytypes\0" as *const u8 as *const libc::c_char,
            opcode: oHostbasedAcceptedAlgorithms,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"pubkeyacceptedalgorithms\0" as *const u8 as *const libc::c_char,
            opcode: oPubkeyAcceptedAlgorithms,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"pubkeyacceptedkeytypes\0" as *const u8 as *const libc::c_char,
            opcode: oPubkeyAcceptedAlgorithms,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"ignoreunknown\0" as *const u8 as *const libc::c_char,
            opcode: oIgnoreUnknown,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"proxyjump\0" as *const u8 as *const libc::c_char,
            opcode: oProxyJump,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"securitykeyprovider\0" as *const u8 as *const libc::c_char,
            opcode: oSecurityKeyProvider,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"knownhostscommand\0" as *const u8 as *const libc::c_char,
            opcode: oKnownHostsCommand,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"requiredrsasize\0" as *const u8 as *const libc::c_char,
            opcode: oRequiredRSASize,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: b"enableescapecommandline\0" as *const u8 as *const libc::c_char,
            opcode: oEnableEscapeCommandline,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            name: 0 as *const libc::c_char,
            opcode: oBadOption,
        };
        init
    },
];
pub unsafe extern "C" fn kex_default_pk_alg() -> *const libc::c_char {
    static mut pkalgs: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
    if pkalgs.is_null() {
        let mut all_key: *mut libc::c_char = 0 as *mut libc::c_char;
        all_key = sshkey_alg_list(
            0 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int,
            ',' as i32 as libc::c_char,
        );
        pkalgs = match_filter_allowlist(
            b"ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\0"
                as *const u8 as *const libc::c_char,
            all_key,
        );
        libc::free(all_key as *mut libc::c_void);
    }
    return pkalgs;
}
pub unsafe extern "C" fn ssh_connection_hash(
    mut thishost: *const libc::c_char,
    mut host: *const libc::c_char,
    mut portstr: *const libc::c_char,
    mut user: *const libc::c_char,
) -> *mut libc::c_char {
    let mut md: *mut ssh_digest_ctx = 0 as *mut ssh_digest_ctx;
    let mut conn_hash: [u_char; 64] = [0; 64];
    md = ssh_digest_start(1 as libc::c_int);
    if md.is_null()
        || ssh_digest_update(md, thishost as *const libc::c_void, strlen(thishost))
            < 0 as libc::c_int
        || ssh_digest_update(md, host as *const libc::c_void, strlen(host)) < 0 as libc::c_int
        || ssh_digest_update(md, portstr as *const libc::c_void, strlen(portstr)) < 0 as libc::c_int
        || ssh_digest_update(md, user as *const libc::c_void, strlen(user)) < 0 as libc::c_int
        || ssh_digest_final(
            md,
            conn_hash.as_mut_ptr(),
            ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
        ) < 0 as libc::c_int
    {
        sshfatal(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"ssh_connection_hash\0"))
                .as_ptr(),
            359 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"mux digest failed\0" as *const u8 as *const libc::c_char,
        );
    }
    ssh_digest_free(md);
    return tohex(
        conn_hash.as_mut_ptr() as *const libc::c_void,
        ssh_digest_bytes(1 as libc::c_int),
    );
}
pub unsafe extern "C" fn add_local_forward(mut options: *mut Options, mut newfwd: *const Forward) {
    let mut fwd: *mut Forward = 0 as *mut Forward;
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < (*options).num_local_forwards {
        if forward_equals(newfwd, ((*options).local_forwards).offset(i as isize)) != 0 {
            return;
        }
        i += 1;
        i;
    }
    (*options).local_forwards = xreallocarray(
        (*options).local_forwards as *mut libc::c_void,
        ((*options).num_local_forwards + 1 as libc::c_int) as size_t,
        ::core::mem::size_of::<Forward>() as libc::c_ulong,
    ) as *mut Forward;
    let fresh0 = (*options).num_local_forwards;
    (*options).num_local_forwards = (*options).num_local_forwards + 1;
    fwd = &mut *((*options).local_forwards).offset(fresh0 as isize) as *mut Forward;
    (*fwd).listen_host = (*newfwd).listen_host;
    (*fwd).listen_port = (*newfwd).listen_port;
    (*fwd).listen_path = (*newfwd).listen_path;
    (*fwd).connect_host = (*newfwd).connect_host;
    (*fwd).connect_port = (*newfwd).connect_port;
    (*fwd).connect_path = (*newfwd).connect_path;
}
pub unsafe extern "C" fn add_remote_forward(mut options: *mut Options, mut newfwd: *const Forward) {
    let mut fwd: *mut Forward = 0 as *mut Forward;
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < (*options).num_remote_forwards {
        if forward_equals(newfwd, ((*options).remote_forwards).offset(i as isize)) != 0 {
            return;
        }
        i += 1;
        i;
    }
    (*options).remote_forwards = xreallocarray(
        (*options).remote_forwards as *mut libc::c_void,
        ((*options).num_remote_forwards + 1 as libc::c_int) as size_t,
        ::core::mem::size_of::<Forward>() as libc::c_ulong,
    ) as *mut Forward;
    let fresh1 = (*options).num_remote_forwards;
    (*options).num_remote_forwards = (*options).num_remote_forwards + 1;
    fwd = &mut *((*options).remote_forwards).offset(fresh1 as isize) as *mut Forward;
    (*fwd).listen_host = (*newfwd).listen_host;
    (*fwd).listen_port = (*newfwd).listen_port;
    (*fwd).listen_path = (*newfwd).listen_path;
    (*fwd).connect_host = (*newfwd).connect_host;
    (*fwd).connect_port = (*newfwd).connect_port;
    (*fwd).connect_path = (*newfwd).connect_path;
    (*fwd).handle = (*newfwd).handle;
    (*fwd).allocated_port = 0 as libc::c_int;
}
unsafe extern "C" fn clear_forwardings(mut options: *mut Options) {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < (*options).num_local_forwards {
        libc::free(
            (*((*options).local_forwards).offset(i as isize)).listen_host as *mut libc::c_void,
        );
        libc::free(
            (*((*options).local_forwards).offset(i as isize)).listen_path as *mut libc::c_void,
        );
        libc::free(
            (*((*options).local_forwards).offset(i as isize)).connect_host as *mut libc::c_void,
        );
        libc::free(
            (*((*options).local_forwards).offset(i as isize)).connect_path as *mut libc::c_void,
        );
        i += 1;
        i;
    }
    if (*options).num_local_forwards > 0 as libc::c_int {
        libc::free((*options).local_forwards as *mut libc::c_void);
        (*options).local_forwards = 0 as *mut Forward;
    }
    (*options).num_local_forwards = 0 as libc::c_int;
    i = 0 as libc::c_int;
    while i < (*options).num_remote_forwards {
        libc::free(
            (*((*options).remote_forwards).offset(i as isize)).listen_host as *mut libc::c_void,
        );
        libc::free(
            (*((*options).remote_forwards).offset(i as isize)).listen_path as *mut libc::c_void,
        );
        libc::free(
            (*((*options).remote_forwards).offset(i as isize)).connect_host as *mut libc::c_void,
        );
        libc::free(
            (*((*options).remote_forwards).offset(i as isize)).connect_path as *mut libc::c_void,
        );
        i += 1;
        i;
    }
    if (*options).num_remote_forwards > 0 as libc::c_int {
        libc::free((*options).remote_forwards as *mut libc::c_void);
        (*options).remote_forwards = 0 as *mut Forward;
    }
    (*options).num_remote_forwards = 0 as libc::c_int;
    (*options).tun_open = 0 as libc::c_int;
}
pub unsafe extern "C" fn add_certificate_file(
    mut options: *mut Options,
    mut path: *const libc::c_char,
    mut userprovided: libc::c_int,
) {
    let mut i: libc::c_int = 0;
    if (*options).num_certificate_files >= 100 as libc::c_int {
        sshfatal(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"add_certificate_file\0"))
                .as_ptr(),
            461 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Too many certificate files specified (max %d)\0" as *const u8 as *const libc::c_char,
            100 as libc::c_int,
        );
    }
    i = 0 as libc::c_int;
    while i < (*options).num_certificate_files {
        if (*options).certificate_file_userprovided[i as usize] == userprovided
            && libc::strcmp((*options).certificate_files[i as usize], path) == 0 as libc::c_int
        {
            crate::log::sshlog(
                b"readconf.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"add_certificate_file\0",
                ))
                .as_ptr(),
                467 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"ignoring duplicate key %s\0" as *const u8 as *const libc::c_char,
                path,
            );
            return;
        }
        i += 1;
        i;
    }
    (*options).certificate_file_userprovided[(*options).num_certificate_files as usize] =
        userprovided;
    let fresh2 = (*options).num_certificate_files;
    (*options).num_certificate_files = (*options).num_certificate_files + 1;
    (*options).certificate_files[fresh2 as usize] = crate::xmalloc::xstrdup(path);
}
pub unsafe extern "C" fn add_identity_file(
    mut options: *mut Options,
    mut dir: *const libc::c_char,
    mut filename: *const libc::c_char,
    mut userprovided: libc::c_int,
) {
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: libc::c_int = 0;
    if (*options).num_identity_files >= 100 as libc::c_int {
        sshfatal(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"add_identity_file\0"))
                .as_ptr(),
            487 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Too many identity files specified (max %d)\0" as *const u8 as *const libc::c_char,
            100 as libc::c_int,
        );
    }
    if dir.is_null() {
        path = crate::xmalloc::xstrdup(filename);
    } else if crate::xmalloc::xasprintf(
        &mut path as *mut *mut libc::c_char,
        b"%s%s\0" as *const u8 as *const libc::c_char,
        dir,
        filename,
    ) >= 4096 as libc::c_int
    {
        sshfatal(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"add_identity_file\0"))
                .as_ptr(),
            492 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Identity file path %s too long\0" as *const u8 as *const libc::c_char,
            path,
        );
    }
    i = 0 as libc::c_int;
    while i < (*options).num_identity_files {
        if (*options).identity_file_userprovided[i as usize] == userprovided
            && libc::strcmp((*options).identity_files[i as usize], path) == 0 as libc::c_int
        {
            crate::log::sshlog(
                b"readconf.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"add_identity_file\0"))
                    .as_ptr(),
                498 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"ignoring duplicate key %s\0" as *const u8 as *const libc::c_char,
                path,
            );
            libc::free(path as *mut libc::c_void);
            return;
        }
        i += 1;
        i;
    }
    (*options).identity_file_userprovided[(*options).num_identity_files as usize] = userprovided;
    let fresh3 = (*options).num_identity_files;
    (*options).num_identity_files = (*options).num_identity_files + 1;
    (*options).identity_files[fresh3 as usize] = path;
}
pub unsafe extern "C" fn default_ssh_port() -> libc::c_int {
    static mut port: libc::c_int = 0;
    let mut sp: *mut servent = 0 as *mut servent;
    if port == 0 as libc::c_int {
        sp = getservbyname(
            b"ssh\0" as *const u8 as *const libc::c_char,
            b"tcp\0" as *const u8 as *const libc::c_char,
        );
        port = if !sp.is_null() {
            __bswap_16((*sp).s_port as __uint16_t) as libc::c_int
        } else {
            22 as libc::c_int
        };
    }
    return port;
}
unsafe extern "C" fn execute_in_shell(mut cmd: *const libc::c_char) -> libc::c_int {
    let mut shell: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pid: pid_t = 0;
    let mut status: libc::c_int = 0;
    shell = getenv(b"SHELL\0" as *const u8 as *const libc::c_char);
    if shell.is_null() {
        shell = b"/bin/sh\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if access(shell, 1 as libc::c_int) == -(1 as libc::c_int) {
        sshfatal(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"execute_in_shell\0"))
                .as_ptr(),
            538 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Shell \"%s\" is not executable: %s\0" as *const u8 as *const libc::c_char,
            shell,
            libc::strerror(*libc::__errno_location()),
        );
    }
    crate::log::sshlog(
        b"readconf.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"execute_in_shell\0")).as_ptr(),
        541 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Executing command: '%.500s'\0" as *const u8 as *const libc::c_char,
        cmd,
    );
    pid = libc::fork();
    if pid == 0 as libc::c_int {
        let mut argv: [*mut libc::c_char; 4] = [0 as *mut libc::c_char; 4];
        if stdfd_devnull(1 as libc::c_int, 1 as libc::c_int, 0 as libc::c_int)
            == -(1 as libc::c_int)
        {
            sshfatal(
                b"readconf.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"execute_in_shell\0"))
                    .as_ptr(),
                548 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"stdfd_devnull failed\0" as *const u8 as *const libc::c_char,
            );
        }
        closefrom(2 as libc::c_int + 1 as libc::c_int);
        argv[0 as libc::c_int as usize] = shell;
        argv[1 as libc::c_int as usize] =
            b"-c\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        argv[2 as libc::c_int as usize] = crate::xmalloc::xstrdup(cmd);
        argv[3 as libc::c_int as usize] = 0 as *mut libc::c_char;
        execv(
            argv[0 as libc::c_int as usize],
            argv.as_mut_ptr() as *const *mut libc::c_char,
        );
        crate::log::sshlog(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"execute_in_shell\0"))
                .as_ptr(),
            557 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Unable to execute '%.100s': %s\0" as *const u8 as *const libc::c_char,
            cmd,
            libc::strerror(*libc::__errno_location()),
        );
        crate::misc::ssh_signal(15 as libc::c_int, None);
        kill(libc::getpid(), 15 as libc::c_int);
        libc::_exit(1 as libc::c_int);
    }
    if pid == -(1 as libc::c_int) {
        sshfatal(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"execute_in_shell\0"))
                .as_ptr(),
            565 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::fork: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    while libc::waitpid(pid, &mut status, 0 as libc::c_int) == -(1 as libc::c_int) {
        if *libc::__errno_location() != 4 as libc::c_int
            && *libc::__errno_location() != 11 as libc::c_int
        {
            sshfatal(
                b"readconf.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"execute_in_shell\0"))
                    .as_ptr(),
                569 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"libc::waitpid: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
    }
    if !(status & 0x7f as libc::c_int == 0 as libc::c_int) {
        crate::log::sshlog(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"execute_in_shell\0"))
                .as_ptr(),
            572 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"command '%.100s' exited abnormally\0" as *const u8 as *const libc::c_char,
            cmd,
        );
        return -(1 as libc::c_int);
    }
    crate::log::sshlog(
        b"readconf.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"execute_in_shell\0")).as_ptr(),
        575 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"command returned status %d\0" as *const u8 as *const libc::c_char,
        (status & 0xff00 as libc::c_int) >> 8 as libc::c_int,
    );
    return (status & 0xff00 as libc::c_int) >> 8 as libc::c_int;
}
unsafe extern "C" fn match_cfg_line(
    mut options: *mut Options,
    mut condition: *mut *mut libc::c_char,
    mut pw: *mut libc::passwd,
    mut host_arg: *const libc::c_char,
    mut original_host: *const libc::c_char,
    mut final_pass: libc::c_int,
    mut want_final_pass: *mut libc::c_int,
    mut filename: *const libc::c_char,
    mut linenum: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut arg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut oattrib: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut attrib: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cmd: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = *condition;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut criteria: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ruser: *const libc::c_char = 0 as *const libc::c_char;
    let mut r: libc::c_int = 0;
    let mut port: libc::c_int = 0;
    let mut this_result: libc::c_int = 0;
    let mut result: libc::c_int = 1 as libc::c_int;
    let mut attributes: libc::c_int = 0 as libc::c_int;
    let mut negate: libc::c_int = 0;
    let mut thishost: [libc::c_char; 1025] = [0; 1025];
    let mut shorthost: [libc::c_char; 1025] = [0; 1025];
    let mut portstr: [libc::c_char; 32] = [0; 32];
    let mut uidstr: [libc::c_char; 32] = [0; 32];
    port = if (*options).port <= 0 as libc::c_int {
        default_ssh_port()
    } else {
        (*options).port
    };
    ruser = if ((*options).user).is_null() {
        (*pw).pw_name
    } else {
        (*options).user
    };
    if final_pass != 0 {
        host = crate::xmalloc::xstrdup((*options).hostname);
    } else if !((*options).hostname).is_null() {
        host = percent_expand(
            (*options).hostname,
            b"h\0" as *const u8 as *const libc::c_char,
            host_arg,
            0 as *mut libc::c_void as *mut libc::c_char,
        );
    } else {
        host = crate::xmalloc::xstrdup(host_arg);
    }
    crate::log::sshlog(
        b"readconf.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"match_cfg_line\0")).as_ptr(),
        610 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"checking match for '%s' host %s originally %s\0" as *const u8 as *const libc::c_char,
        cp,
        host,
        original_host,
    );
    loop {
        attrib = strdelim(&mut cp);
        oattrib = attrib;
        if !(!oattrib.is_null() && *attrib as libc::c_int != '\0' as i32) {
            current_block = 13853033528615664019;
            break;
        }
        if *attrib as libc::c_int == '#' as i32 {
            cp = 0 as *mut libc::c_char;
            current_block = 13853033528615664019;
            break;
        } else {
            criteria = 0 as *mut libc::c_char;
            arg = criteria;
            this_result = 1 as libc::c_int;
            negate = (*attrib.offset(0 as libc::c_int as isize) as libc::c_int == '!' as i32)
                as libc::c_int;
            if negate != 0 {
                attrib = attrib.offset(1);
                attrib;
            }
            if strcasecmp(attrib, b"all\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            {
                if attributes > 1 as libc::c_int || {
                    arg = strdelim(&mut cp);
                    !arg.is_null()
                        && *arg as libc::c_int != '\0' as i32
                        && *arg as libc::c_int != '#' as i32
                } {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"match_cfg_line\0",
                        ))
                        .as_ptr(),
                        627 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: '%s' cannot be combined with other Match attributes\0"
                            as *const u8 as *const libc::c_char,
                        filename,
                        linenum,
                        oattrib,
                    );
                    result = -(1 as libc::c_int);
                    current_block = 9655279610079891732;
                    break;
                } else {
                    if !arg.is_null() && *arg as libc::c_int == '#' as i32 {
                        cp = 0 as *mut libc::c_char;
                    }
                    if result != 0 {
                        result = if negate != 0 {
                            0 as libc::c_int
                        } else {
                            1 as libc::c_int
                        };
                    }
                    current_block = 9655279610079891732;
                    break;
                }
            } else {
                attributes += 1;
                attributes;
                if strcasecmp(attrib, b"canonical\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                    || strcasecmp(attrib, b"final\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                {
                    if strcasecmp(attrib, b"final\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                        && !want_final_pass.is_null()
                    {
                        *want_final_pass = 1 as libc::c_int;
                    }
                    r = (final_pass != 0) as libc::c_int;
                    if r == (if negate != 0 {
                        1 as libc::c_int
                    } else {
                        0 as libc::c_int
                    }) {
                        result = 0 as libc::c_int;
                        this_result = result;
                    }
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"match_cfg_line\0",
                        ))
                        .as_ptr(),
                        653 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"%.200s line %d: %smatched '%s'\0" as *const u8 as *const libc::c_char,
                        filename,
                        linenum,
                        if this_result != 0 {
                            b"\0" as *const u8 as *const libc::c_char
                        } else {
                            b"not \0" as *const u8 as *const libc::c_char
                        },
                        oattrib,
                    );
                } else {
                    arg = strdelim(&mut cp);
                    if arg.is_null()
                        || *arg as libc::c_int == '\0' as i32
                        || *arg as libc::c_int == '#' as i32
                    {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"match_cfg_line\0",
                            ))
                            .as_ptr(),
                            659 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"Missing Match criteria for %s\0" as *const u8 as *const libc::c_char,
                            attrib,
                        );
                        result = -(1 as libc::c_int);
                        current_block = 9655279610079891732;
                        break;
                    } else {
                        if strcasecmp(attrib, b"host\0" as *const u8 as *const libc::c_char)
                            == 0 as libc::c_int
                        {
                            criteria = crate::xmalloc::xstrdup(host);
                            r = (match_hostname(host, arg) == 1 as libc::c_int) as libc::c_int;
                            if r == (if negate != 0 {
                                1 as libc::c_int
                            } else {
                                0 as libc::c_int
                            }) {
                                result = 0 as libc::c_int;
                                this_result = result;
                            }
                        } else if strcasecmp(
                            attrib,
                            b"originalhost\0" as *const u8 as *const libc::c_char,
                        ) == 0 as libc::c_int
                        {
                            criteria = crate::xmalloc::xstrdup(original_host);
                            r = (match_hostname(original_host, arg) == 1 as libc::c_int)
                                as libc::c_int;
                            if r == (if negate != 0 {
                                1 as libc::c_int
                            } else {
                                0 as libc::c_int
                            }) {
                                result = 0 as libc::c_int;
                                this_result = result;
                            }
                        } else if strcasecmp(attrib, b"user\0" as *const u8 as *const libc::c_char)
                            == 0 as libc::c_int
                        {
                            criteria = crate::xmalloc::xstrdup(ruser);
                            r = (match_pattern_list(ruser, arg, 0 as libc::c_int)
                                == 1 as libc::c_int) as libc::c_int;
                            if r == (if negate != 0 {
                                1 as libc::c_int
                            } else {
                                0 as libc::c_int
                            }) {
                                result = 0 as libc::c_int;
                                this_result = result;
                            }
                        } else if strcasecmp(
                            attrib,
                            b"localuser\0" as *const u8 as *const libc::c_char,
                        ) == 0 as libc::c_int
                        {
                            criteria = crate::xmalloc::xstrdup((*pw).pw_name);
                            r = (match_pattern_list((*pw).pw_name, arg, 0 as libc::c_int)
                                == 1 as libc::c_int) as libc::c_int;
                            if r == (if negate != 0 {
                                1 as libc::c_int
                            } else {
                                0 as libc::c_int
                            }) {
                                result = 0 as libc::c_int;
                                this_result = result;
                            }
                        } else if strcasecmp(attrib, b"exec\0" as *const u8 as *const libc::c_char)
                            == 0 as libc::c_int
                        {
                            let mut conn_hash_hex: *mut libc::c_char = 0 as *mut libc::c_char;
                            let mut keyalias: *mut libc::c_char = 0 as *mut libc::c_char;
                            if gethostname(
                                thishost.as_mut_ptr(),
                                ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
                            ) == -(1 as libc::c_int)
                            {
                                sshfatal(
                                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                        b"match_cfg_line\0",
                                    ))
                                    .as_ptr(),
                                    687 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"gethostname: %s\0" as *const u8 as *const libc::c_char,
                                    libc::strerror(*libc::__errno_location()),
                                );
                            }
                            strlcpy(
                                shorthost.as_mut_ptr(),
                                thishost.as_mut_ptr(),
                                ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
                            );
                            shorthost[strcspn(
                                thishost.as_mut_ptr(),
                                b".\0" as *const u8 as *const libc::c_char,
                            ) as usize] = '\0' as i32 as libc::c_char;
                            libc::snprintf(
                                portstr.as_mut_ptr(),
                                ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
                                b"%d\0" as *const u8 as *const libc::c_char,
                                port,
                            );
                            libc::snprintf(
                                uidstr.as_mut_ptr(),
                                ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
                                b"%llu\0" as *const u8 as *const libc::c_char,
                                (*pw).pw_uid as libc::c_ulonglong,
                            );
                            conn_hash_hex = ssh_connection_hash(
                                thishost.as_mut_ptr(),
                                host,
                                portstr.as_mut_ptr(),
                                ruser,
                            );
                            keyalias = if !((*options).host_key_alias).is_null() {
                                (*options).host_key_alias
                            } else {
                                host
                            };
                            cmd = percent_expand(
                                arg,
                                b"C\0" as *const u8 as *const libc::c_char,
                                conn_hash_hex,
                                b"L\0" as *const u8 as *const libc::c_char,
                                shorthost.as_mut_ptr(),
                                b"d\0" as *const u8 as *const libc::c_char,
                                (*pw).pw_dir,
                                b"h\0" as *const u8 as *const libc::c_char,
                                host,
                                b"k\0" as *const u8 as *const libc::c_char,
                                keyalias,
                                b"l\0" as *const u8 as *const libc::c_char,
                                thishost.as_mut_ptr(),
                                b"n\0" as *const u8 as *const libc::c_char,
                                original_host,
                                b"p\0" as *const u8 as *const libc::c_char,
                                portstr.as_mut_ptr(),
                                b"r\0" as *const u8 as *const libc::c_char,
                                ruser,
                                b"u\0" as *const u8 as *const libc::c_char,
                                (*pw).pw_name,
                                b"i\0" as *const u8 as *const libc::c_char,
                                uidstr.as_mut_ptr(),
                                0 as *mut libc::c_void as *mut libc::c_char,
                            );
                            libc::free(conn_hash_hex as *mut libc::c_void);
                            if result != 1 as libc::c_int {
                                crate::log::sshlog(
                                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                        b"match_cfg_line\0",
                                    ))
                                    .as_ptr(),
                                    715 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG3,
                                    0 as *const libc::c_char,
                                    b"%.200s line %d: skipped exec \"%.100s\"\0" as *const u8
                                        as *const libc::c_char,
                                    filename,
                                    linenum,
                                    cmd,
                                );
                                libc::free(cmd as *mut libc::c_void);
                                continue;
                            } else {
                                r = execute_in_shell(cmd);
                                if r == -(1 as libc::c_int) {
                                    sshfatal(
                                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                            b"match_cfg_line\0",
                                        ))
                                        .as_ptr(),
                                        723 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_FATAL,
                                        0 as *const libc::c_char,
                                        b"%.200s line %d: match exec '%.100s' error\0" as *const u8
                                            as *const libc::c_char,
                                        filename,
                                        linenum,
                                        cmd,
                                    );
                                }
                                criteria = crate::xmalloc::xstrdup(cmd);
                                libc::free(cmd as *mut libc::c_void);
                                r = (r == 0 as libc::c_int) as libc::c_int;
                                if r == (if negate != 0 {
                                    1 as libc::c_int
                                } else {
                                    0 as libc::c_int
                                }) {
                                    result = 0 as libc::c_int;
                                    this_result = result;
                                }
                            }
                        } else {
                            crate::log::sshlog(
                                b"readconf.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                    b"match_cfg_line\0",
                                ))
                                .as_ptr(),
                                732 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"Unsupported Match attribute %s\0" as *const u8
                                    as *const libc::c_char,
                                attrib,
                            );
                            result = -(1 as libc::c_int);
                            current_block = 9655279610079891732;
                            break;
                        }
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"match_cfg_line\0",
                            ))
                            .as_ptr(),
                            738 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG3,
                            0 as *const libc::c_char,
                            b"%.200s line %d: %smatched '%s \"%.100s\"' \0" as *const u8
                                as *const libc::c_char,
                            filename,
                            linenum,
                            if this_result != 0 {
                                b"\0" as *const u8 as *const libc::c_char
                            } else {
                                b"not \0" as *const u8 as *const libc::c_char
                            },
                            oattrib,
                            criteria,
                        );
                        libc::free(criteria as *mut libc::c_void);
                    }
                }
            }
        }
    }
    match current_block {
        13853033528615664019 => {
            if attributes == 0 as libc::c_int {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"match_cfg_line\0",
                    ))
                    .as_ptr(),
                    742 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"One or more attributes required for Match\0" as *const u8
                        as *const libc::c_char,
                );
                result = -(1 as libc::c_int);
            }
        }
        _ => {}
    }
    if result != -(1 as libc::c_int) {
        crate::log::sshlog(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"match_cfg_line\0"))
                .as_ptr(),
            748 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"match %sfound\0" as *const u8 as *const libc::c_char,
            if result != 0 {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b"not \0" as *const u8 as *const libc::c_char
            },
        );
    }
    *condition = cp;
    libc::free(host as *mut libc::c_void);
    return result;
}
unsafe extern "C" fn rm_env(
    mut options: *mut Options,
    mut arg: *const libc::c_char,
    mut filename: *const libc::c_char,
    mut linenum: libc::c_int,
) {
    let mut i: u_int = 0;
    let mut j: u_int = 0;
    let mut onum_send_env: u_int = (*options).num_send_env;
    i = 0 as libc::c_int as u_int;
    while i < (*options).num_send_env {
        if match_pattern(
            *((*options).send_env).offset(i as isize),
            arg.offset(1 as libc::c_int as isize),
        ) == 0
        {
            i = i.wrapping_add(1);
            i;
        } else {
            crate::log::sshlog(
                b"readconf.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 7], &[libc::c_char; 7]>(b"rm_env\0")).as_ptr(),
                767 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"%s line %d: removing environment %s\0" as *const u8 as *const libc::c_char,
                filename,
                linenum,
                *((*options).send_env).offset(i as isize),
            );
            libc::free(*((*options).send_env).offset(i as isize) as *mut libc::c_void);
            let ref mut fresh4 = *((*options).send_env).offset(i as isize);
            *fresh4 = 0 as *mut libc::c_char;
            j = i;
            while j < ((*options).num_send_env).wrapping_sub(1 as libc::c_int as libc::c_uint) {
                let ref mut fresh5 = *((*options).send_env).offset(j as isize);
                *fresh5 = *((*options).send_env)
                    .offset(j.wrapping_add(1 as libc::c_int as libc::c_uint) as isize);
                let ref mut fresh6 = *((*options).send_env)
                    .offset(j.wrapping_add(1 as libc::c_int as libc::c_uint) as isize);
                *fresh6 = 0 as *mut libc::c_char;
                j = j.wrapping_add(1);
                j;
            }
            (*options).num_send_env = ((*options).num_send_env).wrapping_sub(1);
            (*options).num_send_env;
        }
    }
    if onum_send_env != (*options).num_send_env {
        (*options).send_env = crate::xmalloc::xrecallocarray(
            (*options).send_env as *mut libc::c_void,
            onum_send_env as size_t,
            (*options).num_send_env as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        ) as *mut *mut libc::c_char;
    }
}
unsafe extern "C" fn parse_token(
    mut cp: *const libc::c_char,
    mut filename: *const libc::c_char,
    mut linenum: libc::c_int,
    mut ignored_unknown: *const libc::c_char,
) -> OpCodes {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while !(keywords[i as usize].name).is_null() {
        if libc::strcmp(cp, keywords[i as usize].name) == 0 as libc::c_int {
            return keywords[i as usize].opcode;
        }
        i += 1;
        i;
    }
    if !ignored_unknown.is_null()
        && match_pattern_list(cp, ignored_unknown, 1 as libc::c_int) == 1 as libc::c_int
    {
        return oIgnoredUnknownOption;
    }
    crate::log::sshlog(
        b"readconf.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"parse_token\0")).as_ptr(),
        800 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"%s: line %d: Bad configuration option: %s\0" as *const u8 as *const libc::c_char,
        filename,
        linenum,
        cp,
    );
    return oBadOption;
}
static mut multistate_flag: [multistate; 5] = [
    {
        let mut init = multistate {
            key: b"true\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"false\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: 0 as *const libc::c_char as *mut libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
static mut multistate_yesnoask: [multistate; 6] = [
    {
        let mut init = multistate {
            key: b"true\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"false\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"ask\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: 0 as *const libc::c_char as *mut libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
static mut multistate_strict_hostkey: [multistate; 8] = [
    {
        let mut init = multistate {
            key: b"true\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"false\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"ask\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 3 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"off\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"accept-new\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: 0 as *const libc::c_char as *mut libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
static mut multistate_yesnoaskconfirm: [multistate; 7] = [
    {
        let mut init = multistate {
            key: b"true\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"false\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"ask\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"confirm\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 3 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: 0 as *const libc::c_char as *mut libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
static mut multistate_addressfamily: [multistate; 4] = [
    {
        let mut init = multistate {
            key: b"inet\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"inet6\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 10 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"any\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: 0 as *const libc::c_char as *mut libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
static mut multistate_controlmaster: [multistate; 8] = [
    {
        let mut init = multistate {
            key: b"true\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"false\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"auto\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"ask\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 3 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"autoask\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 4 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: 0 as *const libc::c_char as *mut libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
static mut multistate_tunnel: [multistate; 7] = [
    {
        let mut init = multistate {
            key: b"ethernet\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0x2 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"point-to-point\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0x1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"true\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0x1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0x1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"false\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: 0 as *const libc::c_char as *mut libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
static mut multistate_requesttty: [multistate; 7] = [
    {
        let mut init = multistate {
            key: b"true\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"false\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"force\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 3 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"auto\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: 0 as *const libc::c_char as *mut libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
static mut multistate_sessiontype: [multistate; 4] = [
    {
        let mut init = multistate {
            key: b"none\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"subsystem\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"default\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: 0 as *const libc::c_char as *mut libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
static mut multistate_canonicalizehostname: [multistate; 6] = [
    {
        let mut init = multistate {
            key: b"true\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"false\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"always\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: 0 as *const libc::c_char as *mut libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
static mut multistate_pubkey_auth: [multistate; 7] = [
    {
        let mut init = multistate {
            key: b"true\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0x3 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"false\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0x3 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"unbound\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0x1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"host-bound\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0x2 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: 0 as *const libc::c_char as *mut libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
static mut multistate_compression: [multistate; 3] = [
    {
        let mut init = multistate {
            key: b"yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: b"no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = multistate {
            key: 0 as *const libc::c_char as *mut libc::c_char,
            value: -(1 as libc::c_int),
        };
        init
    },
];
unsafe extern "C" fn parse_multistate_value(
    mut arg: *const libc::c_char,
    mut filename: *const libc::c_char,
    mut linenum: libc::c_int,
    mut multistate_ptr: *const multistate,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
        crate::log::sshlog(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"parse_multistate_value\0",
            ))
            .as_ptr(),
            915 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s line %d: missing argument.\0" as *const u8 as *const libc::c_char,
            filename,
            linenum,
        );
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int;
    while !((*multistate_ptr.offset(i as isize)).key).is_null() {
        if strcasecmp(arg, (*multistate_ptr.offset(i as isize)).key) == 0 as libc::c_int {
            return (*multistate_ptr.offset(i as isize)).value;
        }
        i += 1;
        i;
    }
    return -(1 as libc::c_int);
}
pub unsafe extern "C" fn process_config_line(
    mut options: *mut Options,
    mut pw: *mut libc::passwd,
    mut host: *const libc::c_char,
    mut original_host: *const libc::c_char,
    mut line: *mut libc::c_char,
    mut filename: *const libc::c_char,
    mut linenum: libc::c_int,
    mut activep: *mut libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    return process_config_line_depth(
        options,
        pw,
        host,
        original_host,
        line,
        filename,
        linenum,
        activep,
        flags,
        0 as *mut libc::c_int,
        0 as libc::c_int,
    );
}
unsafe extern "C" fn process_config_line_depth(
    mut options: *mut Options,
    mut pw: *mut libc::passwd,
    mut host: *const libc::c_char,
    mut original_host: *const libc::c_char,
    mut line: *mut libc::c_char,
    mut filename: *const libc::c_char,
    mut linenum: libc::c_int,
    mut activep: *mut libc::c_int,
    mut flags: libc::c_int,
    mut want_final_pass: *mut libc::c_int,
    mut depth: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut str: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut charptr: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut endofnumber: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut keyword: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut arg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut arg2: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cpptr: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut cppptr: *mut *mut *mut libc::c_char = 0 as *mut *mut *mut libc::c_char;
    let mut fwdarg: [libc::c_char; 256] = [0; 256];
    let mut i: u_int = 0;
    let mut uintptr: *mut u_int = 0 as *mut u_int;
    let mut uvalue: u_int = 0;
    let mut max_entries: u_int = 0 as libc::c_int as u_int;
    let mut r: libc::c_int = 0;
    let mut oactive: libc::c_int = 0;
    let mut negated: libc::c_int = 0;
    let mut opcode: libc::c_int = 0;
    let mut intptr: *mut libc::c_int = 0 as *mut libc::c_int;
    let mut value: libc::c_int = 0;
    let mut value2: libc::c_int = 0;
    let mut cmdline: libc::c_int = 0 as libc::c_int;
    let mut remotefwd: libc::c_int = 0;
    let mut dynamicfwd: libc::c_int = 0;
    let mut log_level_ptr: *mut LogLevel = 0 as *mut LogLevel;
    let mut log_facility_ptr: *mut SyslogFacility = 0 as *mut SyslogFacility;
    let mut val64: libc::c_longlong = 0;
    let mut len: size_t = 0;
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
    let mut multistate_ptr: *const multistate = 0 as *const multistate;
    let mut cname: *mut allowed_cname = 0 as *mut allowed_cname;
    let mut gl: crate::openbsd_compat::glob::_ssh_compat_glob_t =
        crate::openbsd_compat::glob::_ssh_compat_glob_t {
            gl_pathc: 0,
            gl_matchc: 0,
            gl_offs: 0,
            gl_flags: 0,
            gl_pathv: 0 as *mut *mut libc::c_char,
            gl_statv: 0 as *mut *mut libc::stat,
            gl_errfunc: None,
            gl_closedir: None,
            gl_readdir: None,
            gl_opendir: None,
            gl_lstat: None,
            gl_stat: None,
        };
    let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
    let mut oav: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut av: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut oac: libc::c_int = 0 as libc::c_int;
    let mut ac: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if activep.is_null() {
        cmdline = 1 as libc::c_int;
        activep = &mut cmdline;
    }
    len = strlen(line);
    if len == 0 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    len = len.wrapping_sub(1);
    len;
    while len > 0 as libc::c_int as libc::c_ulong {
        if (libc::strchr(
            b" \t\r\n\x0C\0" as *const u8 as *const libc::c_char,
            *line.offset(len as isize) as libc::c_int,
        ))
        .is_null()
        {
            break;
        }
        *line.offset(len as isize) = '\0' as i32 as libc::c_char;
        len = len.wrapping_sub(1);
        len;
    }
    str = line;
    keyword = strdelim(&mut str);
    if keyword.is_null() {
        return 0 as libc::c_int;
    }
    if *keyword as libc::c_int == '\0' as i32 {
        keyword = strdelim(&mut str);
    }
    if keyword.is_null()
        || *keyword == 0
        || *keyword as libc::c_int == '\n' as i32
        || *keyword as libc::c_int == '#' as i32
    {
        return 0 as libc::c_int;
    }
    lowercase(keyword);
    if !str.is_null() {
        str = str.offset(strspn(str, b" \t\r\n\0" as *const u8 as *const libc::c_char) as isize);
    }
    if str.is_null() || *str as libc::c_int == '\0' as i32 {
        crate::log::sshlog(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"process_config_line_depth\0",
            ))
            .as_ptr(),
            993 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s line %d: no argument after keyword \"%s\"\0" as *const u8 as *const libc::c_char,
            filename,
            linenum,
            keyword,
        );
        return -(1 as libc::c_int);
    }
    opcode = parse_token(keyword, filename, linenum, (*options).ignored_unknown) as libc::c_int;
    if argv_split(str, &mut oac, &mut oav, 1 as libc::c_int) != 0 as libc::c_int {
        crate::log::sshlog(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"process_config_line_depth\0",
            ))
            .as_ptr(),
            999 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s line %d: invalid quotes\0" as *const u8 as *const libc::c_char,
            filename,
            linenum,
        );
        return -(1 as libc::c_int);
    }
    ac = oac;
    av = oav;
    match opcode {
        0 => {
            current_block = 7482270440933722938;
        }
        99 => {
            argv_consume(&mut ac);
            current_block = 3935247052025034411;
        }
        100 => {
            crate::log::sshlog(
                b"readconf.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"process_config_line_depth\0",
                ))
                .as_ptr(),
                1014 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"%s line %d: Ignored unknown option \"%s\"\0" as *const u8 as *const libc::c_char,
                filename,
                linenum,
                keyword,
            );
            argv_consume(&mut ac);
            current_block = 3935247052025034411;
        }
        54 => {
            intptr = &mut (*options).connection_timeout;
            current_block = 11955811698013090598;
        }
        4 => {
            intptr = &mut (*options).forward_agent;
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1043 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s line %d: missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                value = -(1 as libc::c_int);
                multistate_ptr = multistate_flag.as_ptr();
                i = 0 as libc::c_int as u_int;
                while !((*multistate_ptr.offset(i as isize)).key).is_null() {
                    if strcasecmp(arg, (*multistate_ptr.offset(i as isize)).key) == 0 as libc::c_int
                    {
                        value = (*multistate_ptr.offset(i as isize)).value;
                        break;
                    } else {
                        i = i.wrapping_add(1);
                        i;
                    }
                }
                if value != -(1 as libc::c_int) {
                    if *activep != 0 && *intptr == -(1 as libc::c_int) {
                        *intptr = value;
                    }
                    current_block = 3935247052025034411;
                } else {
                    if *activep != 0 && *intptr == -(1 as libc::c_int) {
                        *intptr = 1 as libc::c_int;
                    }
                    charptr = &mut (*options).forward_agent_sock_path;
                    current_block = 16523242387479284007;
                }
            }
        }
        5 => {
            intptr = &mut (*options).forward_x11;
            current_block = 15720799472059460288;
        }
        6 => {
            intptr = &mut (*options).forward_x11_trusted;
            current_block = 15720799472059460288;
        }
        7 => {
            intptr = &mut (*options).forward_x11_timeout;
            current_block = 11955811698013090598;
        }
        8 => {
            intptr = &mut (*options).fwd_opts.gateway_ports;
            current_block = 15720799472059460288;
        }
        9 => {
            intptr = &mut (*options).exit_on_forward_failure;
            current_block = 15720799472059460288;
        }
        10 => {
            intptr = &mut (*options).password_authentication;
            current_block = 15720799472059460288;
        }
        39 => {
            intptr = &mut (*options).kbd_interactive_authentication;
            current_block = 15720799472059460288;
        }
        40 => {
            charptr = &mut (*options).kbd_interactive_devices;
            current_block = 6865066298509711319;
        }
        38 => {
            multistate_ptr = multistate_pubkey_auth.as_ptr();
            intptr = &mut (*options).pubkey_authentication;
            current_block = 790863646429703468;
        }
        44 => {
            intptr = &mut (*options).hostbased_authentication;
            current_block = 15720799472059460288;
        }
        56 => {
            intptr = &mut (*options).gss_authentication;
            current_block = 15720799472059460288;
        }
        57 => {
            intptr = &mut (*options).gss_deleg_creds;
            current_block = 15720799472059460288;
        }
        27 => {
            intptr = &mut (*options).batch_mode;
            current_block = 15720799472059460288;
        }
        28 => {
            intptr = &mut (*options).check_host_ip;
            current_block = 15720799472059460288;
        }
        53 => {
            intptr = &mut (*options).verify_host_key_dns;
            multistate_ptr = multistate_yesnoask.as_ptr();
            current_block = 790863646429703468;
        }
        29 => {
            intptr = &mut (*options).strict_host_key_checking;
            multistate_ptr = multistate_strict_hostkey.as_ptr();
            current_block = 790863646429703468;
        }
        30 => {
            intptr = &mut (*options).compression;
            multistate_ptr = multistate_compression.as_ptr();
            current_block = 790863646429703468;
        }
        31 => {
            intptr = &mut (*options).tcp_keep_alive;
            current_block = 15720799472059460288;
        }
        50 => {
            intptr = &mut (*options).no_host_authentication_for_localhost;
            current_block = 15720799472059460288;
        }
        32 => {
            intptr = &mut (*options).number_of_password_prompts;
            current_block = 17629687495357276654;
        }
        52 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1167 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                if libc::strcmp(arg, b"default\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    val64 = 0 as libc::c_int as libc::c_longlong;
                    current_block = 9521147444787763968;
                } else if crate::openbsd_compat::fmt_scaled::scan_scaled(arg, &mut val64)
                    == -(1 as libc::c_int)
                {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1175 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: Bad number '%s': %s\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        linenum,
                        arg,
                        libc::strerror(*libc::__errno_location()),
                    );
                    current_block = 7482270440933722938;
                } else if val64 != 0 as libc::c_int as libc::c_longlong
                    && val64 < 16 as libc::c_int as libc::c_longlong
                {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1180 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: RekeyLimit too small\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        linenum,
                    );
                    current_block = 7482270440933722938;
                } else {
                    current_block = 9521147444787763968;
                }
                match current_block {
                    7482270440933722938 => {}
                    _ => {
                        if *activep != 0
                            && (*options).rekey_limit == -(1 as libc::c_int) as libc::c_long
                        {
                            (*options).rekey_limit = val64 as int64_t;
                        }
                        if ac != 0 as libc::c_int {
                            if libc::strcmp(
                                *av.offset(0 as libc::c_int as isize),
                                b"none\0" as *const u8 as *const libc::c_char,
                            ) == 0 as libc::c_int
                            {
                                argv_next(&mut ac, &mut av);
                                current_block = 3935247052025034411;
                            } else {
                                intptr = &mut (*options).rekey_interval;
                                current_block = 11955811698013090598;
                            }
                        } else {
                            current_block = 3935247052025034411;
                        }
                    }
                }
            }
        }
        12 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1200 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else if *activep != 0 {
                intptr = &mut (*options).num_identity_files;
                if *intptr >= 100 as libc::c_int {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1208 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: Too many identity files specified (max %d).\0"
                            as *const u8 as *const libc::c_char,
                        filename,
                        linenum,
                        100 as libc::c_int,
                    );
                    current_block = 7482270440933722938;
                } else {
                    add_identity_file(
                        options,
                        0 as *const libc::c_char,
                        arg,
                        flags & 2 as libc::c_int,
                    );
                    current_block = 3935247052025034411;
                }
            } else {
                current_block = 3935247052025034411;
            }
        }
        18 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1220 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else if *activep != 0 {
                intptr = &mut (*options).num_certificate_files;
                if *intptr >= 100 as libc::c_int {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1229 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: Too many certificate files specified (max %d).\0"
                            as *const u8 as *const libc::c_char,
                        filename,
                        linenum,
                        100 as libc::c_int,
                    );
                    current_block = 7482270440933722938;
                } else {
                    add_certificate_file(options, arg, flags & 2 as libc::c_int);
                    current_block = 3935247052025034411;
                }
            } else {
                current_block = 3935247052025034411;
            }
        }
        11 => {
            charptr = &mut (*options).xauth_location;
            current_block = 6865066298509711319;
        }
        21 => {
            charptr = &mut (*options).user;
            current_block = 6865066298509711319;
        }
        24 => {
            cpptr = &mut (*options).system_hostfiles as *mut [*mut libc::c_char; 32]
                as *mut *mut libc::c_char;
            uintptr = &mut (*options).num_system_hostfiles;
            max_entries = 32 as libc::c_int as u_int;
            current_block = 16874605264102726382;
        }
        25 => {
            cpptr = &mut (*options).user_hostfiles as *mut [*mut libc::c_char; 32]
                as *mut *mut libc::c_char;
            uintptr = &mut (*options).num_user_hostfiles;
            max_entries = 32 as libc::c_int as u_int;
            current_block = 16874605264102726382;
        }
        13 => {
            charptr = &mut (*options).hostname;
            current_block = 6865066298509711319;
        }
        41 => {
            charptr = &mut (*options).host_key_alias;
            current_block = 6865066298509711319;
        }
        43 => {
            charptr = &mut (*options).preferred_authentications;
            current_block = 6865066298509711319;
        }
        46 => {
            charptr = &mut (*options).bind_address;
            current_block = 6865066298509711319;
        }
        47 => {
            charptr = &mut (*options).bind_interface;
            current_block = 6865066298509711319;
        }
        48 => {
            charptr = &mut (*options).pkcs11_provider;
            current_block = 6865066298509711319;
        }
        95 => {
            charptr = &mut (*options).sk_provider;
            current_block = 6865066298509711319;
        }
        96 => {
            charptr = &mut (*options).known_hosts_command;
            current_block = 13881330248250323440;
        }
        23 => {
            charptr = &mut (*options).proxy_command;
            if !((*options).jump_host).is_null() {
                charptr = &mut (*options).jump_host;
            }
            current_block = 13881330248250323440;
        }
        94 => {
            if str.is_null() {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1347 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                len = strspn(str, b" \t\r\n=\0" as *const u8 as *const libc::c_char);
                if parse_jump(str.offset(len as isize), options, *activep) == -(1 as libc::c_int) {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1354 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: Invalid ProxyJump \"%s\"\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        linenum,
                        str.offset(len as isize),
                    );
                    current_block = 7482270440933722938;
                } else {
                    argv_consume(&mut ac);
                    current_block = 3935247052025034411;
                }
            }
        }
        14 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1364 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                value = crate::misc::a2port(arg);
                if value <= 0 as libc::c_int {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1370 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: Bad port '%s'.\0" as *const u8 as *const libc::c_char,
                        filename,
                        linenum,
                        arg,
                    );
                    current_block = 7482270440933722938;
                } else {
                    if *activep != 0 && (*options).port == -(1 as libc::c_int) {
                        (*options).port = value;
                    }
                    current_block = 3935247052025034411;
                }
            }
        }
        26 => {
            intptr = &mut (*options).connection_attempts;
            current_block = 17629687495357276654;
        }
        36 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1394 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else if *arg as libc::c_int != '-' as i32
                && ciphers_valid(
                    if *arg as libc::c_int == '+' as i32 || *arg as libc::c_int == '^' as i32 {
                        arg.offset(1 as libc::c_int as isize)
                    } else {
                        arg
                    },
                ) == 0
            {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1400 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Bad SSH2 cipher spec '%s'.\0" as *const u8
                        as *const libc::c_char,
                    filename,
                    linenum,
                    if !arg.is_null() {
                        arg as *const libc::c_char
                    } else {
                        b"<NONE>\0" as *const u8 as *const libc::c_char
                    },
                );
                current_block = 7482270440933722938;
            } else {
                if *activep != 0 && ((*options).ciphers).is_null() {
                    (*options).ciphers = crate::xmalloc::xstrdup(arg);
                }
                current_block = 3935247052025034411;
            }
        }
        37 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1411 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else if *arg as libc::c_int != '-' as i32
                && mac_valid(
                    if *arg as libc::c_int == '+' as i32 || *arg as libc::c_int == '^' as i32 {
                        arg.offset(1 as libc::c_int as isize)
                    } else {
                        arg
                    },
                ) == 0
            {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1417 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Bad SSH2 MAC spec '%s'.\0" as *const u8
                        as *const libc::c_char,
                    filename,
                    linenum,
                    if !arg.is_null() {
                        arg as *const libc::c_char
                    } else {
                        b"<NONE>\0" as *const u8 as *const libc::c_char
                    },
                );
                current_block = 7482270440933722938;
            } else {
                if *activep != 0 && ((*options).macs).is_null() {
                    (*options).macs = crate::xmalloc::xstrdup(arg);
                }
                current_block = 3935247052025034411;
            }
        }
        73 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1428 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else if *arg as libc::c_int != '-' as i32
                && kex_names_valid(
                    if *arg as libc::c_int == '+' as i32 || *arg as libc::c_int == '^' as i32 {
                        arg.offset(1 as libc::c_int as isize)
                    } else {
                        arg
                    },
                ) == 0
            {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1435 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Bad SSH2 KexAlgorithms '%s'.\0" as *const u8
                        as *const libc::c_char,
                    filename,
                    linenum,
                    if !arg.is_null() {
                        arg as *const libc::c_char
                    } else {
                        b"<NONE>\0" as *const u8 as *const libc::c_char
                    },
                );
                current_block = 7482270440933722938;
            } else {
                if *activep != 0 && ((*options).kex_algorithms).is_null() {
                    (*options).kex_algorithms = crate::xmalloc::xstrdup(arg);
                }
                current_block = 3935247052025034411;
            }
        }
        45 => {
            charptr = &mut (*options).hostkeyalgorithms;
            current_block = 11785309045061247795;
        }
        93 => {
            charptr = &mut (*options).ca_sign_algorithms;
            current_block = 11785309045061247795;
        }
        34 => {
            log_level_ptr = &mut (*options).log_level;
            arg = argv_next(&mut ac, &mut av);
            value = log_level_number(arg) as libc::c_int;
            if value == SYSLOG_LEVEL_NOT_SET as libc::c_int {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1472 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: unsupported log level '%s'\0" as *const u8
                        as *const libc::c_char,
                    filename,
                    linenum,
                    if !arg.is_null() {
                        arg as *const libc::c_char
                    } else {
                        b"<NONE>\0" as *const u8 as *const libc::c_char
                    },
                );
                current_block = 7482270440933722938;
            } else {
                if *activep != 0
                    && *log_level_ptr as libc::c_int == SYSLOG_LEVEL_NOT_SET as libc::c_int
                {
                    *log_level_ptr = value as LogLevel;
                }
                current_block = 3935247052025034411;
            }
        }
        33 => {
            log_facility_ptr = &mut (*options).log_facility;
            arg = argv_next(&mut ac, &mut av);
            value = log_facility_number(arg) as libc::c_int;
            if value == SYSLOG_FACILITY_NOT_SET as libc::c_int {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1485 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: unsupported log facility '%s'\0" as *const u8
                        as *const libc::c_char,
                    filename,
                    linenum,
                    if !arg.is_null() {
                        arg as *const libc::c_char
                    } else {
                        b"<NONE>\0" as *const u8 as *const libc::c_char
                    },
                );
                current_block = 7482270440933722938;
            } else {
                if *log_facility_ptr as libc::c_int == -(1 as libc::c_int) {
                    *log_facility_ptr = value as SyslogFacility;
                }
                current_block = 3935247052025034411;
            }
        }
        35 => {
            cppptr = &mut (*options).log_verbose;
            uintptr = &mut (*options).num_log_verbose;
            i = 0 as libc::c_int as u_int;
            loop {
                arg = argv_next(&mut ac, &mut av);
                if arg.is_null() {
                    current_block = 3935247052025034411;
                    break;
                }
                if *arg as libc::c_int == '\0' as i32 {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1499 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s line %d: keyword %s empty argument\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        linenum,
                        keyword,
                    );
                    current_block = 7482270440933722938;
                    break;
                } else {
                    if strcasecmp(arg, b"none\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                    {
                        if i > 0 as libc::c_int as libc::c_uint || ac > 0 as libc::c_int {
                            crate::log::sshlog(
                                b"readconf.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                    b"process_config_line_depth\0",
                                ))
                                .as_ptr(),
                                1507 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"%s line %d: keyword %s \"none\" argument must appear alone.\0"
                                    as *const u8
                                    as *const libc::c_char,
                                filename,
                                linenum,
                                keyword,
                            );
                            current_block = 7482270440933722938;
                            break;
                        }
                    }
                    i = i.wrapping_add(1);
                    i;
                    if *activep != 0 && *uintptr == 0 as libc::c_int as libc::c_uint {
                        *cppptr = crate::xmalloc::xrecallocarray(
                            *cppptr as *mut libc::c_void,
                            *uintptr as size_t,
                            (*uintptr).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
                            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                        ) as *mut *mut libc::c_char;
                        let fresh9 = *uintptr;
                        *uintptr = (*uintptr).wrapping_add(1);
                        let ref mut fresh10 = *(*cppptr).offset(fresh9 as isize);
                        *fresh10 = crate::xmalloc::xstrdup(arg);
                    }
                }
            }
        }
        16 | 15 | 42 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1526 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                remotefwd = (opcode == oRemoteForward as libc::c_int) as libc::c_int;
                dynamicfwd = (opcode == oDynamicForward as libc::c_int) as libc::c_int;
                if dynamicfwd == 0 {
                    arg2 = argv_next(&mut ac, &mut av);
                    if arg2.is_null() || *arg2 as libc::c_int == '\0' as i32 {
                        if remotefwd != 0 {
                            dynamicfwd = 1 as libc::c_int;
                            current_block = 15055213890147597004;
                        } else {
                            crate::log::sshlog(
                                b"readconf.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                    b"process_config_line_depth\0",
                                ))
                                .as_ptr(),
                                1540 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"%.200s line %d: Missing target argument.\0" as *const u8
                                    as *const libc::c_char,
                                filename,
                                linenum,
                            );
                            current_block = 7482270440933722938;
                        }
                    } else {
                        libc::snprintf(
                            fwdarg.as_mut_ptr(),
                            ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
                            b"%s:%s\0" as *const u8 as *const libc::c_char,
                            arg,
                            arg2,
                        );
                        current_block = 15055213890147597004;
                    }
                } else {
                    current_block = 15055213890147597004;
                }
                match current_block {
                    7482270440933722938 => {}
                    _ => {
                        if dynamicfwd != 0 {
                            strlcpy(
                                fwdarg.as_mut_ptr(),
                                arg,
                                ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                            );
                        }
                        if parse_forward(&mut fwd, fwdarg.as_mut_ptr(), dynamicfwd, remotefwd)
                            == 0 as libc::c_int
                        {
                            crate::log::sshlog(
                                b"readconf.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                    b"process_config_line_depth\0",
                                ))
                                .as_ptr(),
                                1554 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"%.200s line %d: Bad forwarding specification.\0" as *const u8
                                    as *const libc::c_char,
                                filename,
                                linenum,
                            );
                            current_block = 7482270440933722938;
                        } else {
                            if *activep != 0 {
                                if remotefwd != 0 {
                                    add_remote_forward(options, &mut fwd);
                                } else {
                                    add_local_forward(options, &mut fwd);
                                }
                            }
                            current_block = 3935247052025034411;
                        }
                    }
                }
            }
        }
        17 => {
            uintptr = &mut (*options).num_permitted_remote_opens;
            cppptr = &mut (*options).permitted_remote_opens;
            uvalue = *uintptr;
            i = 0 as libc::c_int as u_int;
            loop {
                arg = argv_next(&mut ac, &mut av);
                if arg.is_null() {
                    current_block = 6226880432621243913;
                    break;
                }
                arg2 = crate::xmalloc::xstrdup(arg);
                if strcasecmp(arg, b"none\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                    || strcasecmp(arg, b"any\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                {
                    if i > 0 as libc::c_int as libc::c_uint || ac > 0 as libc::c_int {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1580 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s line %d: keyword %s \"%s\" argument must appear alone.\0"
                                as *const u8 as *const libc::c_char,
                            filename,
                            linenum,
                            keyword,
                            arg,
                        );
                        libc::free(arg2 as *mut libc::c_void);
                        current_block = 7482270440933722938;
                        break;
                    }
                } else {
                    p = hpdelim(&mut arg);
                    if p.is_null() {
                        sshfatal(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1589 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"%s line %d: missing host in %s\0" as *const u8 as *const libc::c_char,
                            filename,
                            linenum,
                            lookup_opcode_name(opcode as OpCodes),
                        );
                    }
                    p = cleanhostname(p);
                    if arg.is_null()
                        || libc::strcmp(arg, b"*\0" as *const u8 as *const libc::c_char)
                            != 0 as libc::c_int
                            && crate::misc::a2port(arg) <= 0 as libc::c_int
                    {
                        sshfatal(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1600 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"%s line %d: bad port number in %s\0" as *const u8
                                as *const libc::c_char,
                            filename,
                            linenum,
                            lookup_opcode_name(opcode as OpCodes),
                        );
                    }
                }
                if *activep != 0 && uvalue == 0 as libc::c_int as libc::c_uint {
                    opt_array_append(
                        filename,
                        linenum,
                        lookup_opcode_name(opcode as OpCodes),
                        cppptr,
                        uintptr,
                        arg2,
                    );
                }
                libc::free(arg2 as *mut libc::c_void);
                i = i.wrapping_add(1);
                i;
            }
            match current_block {
                7482270440933722938 => {}
                _ => {
                    if i == 0 as libc::c_int as libc::c_uint {
                        sshfatal(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1613 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"%s line %d: missing %s specification\0" as *const u8
                                as *const libc::c_char,
                            filename,
                            linenum,
                            lookup_opcode_name(opcode as OpCodes),
                        );
                    }
                    current_block = 3935247052025034411;
                }
            }
        }
        49 => {
            intptr = &mut (*options).clear_forwardings;
            current_block = 15720799472059460288;
        }
        1 => {
            if cmdline != 0 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1623 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Host directive not supported as a command-line option\0" as *const u8
                        as *const libc::c_char,
                );
                current_block = 7482270440933722938;
            } else {
                *activep = 0 as libc::c_int;
                arg2 = 0 as *mut libc::c_char;
                loop {
                    arg = argv_next(&mut ac, &mut av);
                    if arg.is_null() {
                        current_block = 5600328731811258759;
                        break;
                    }
                    if *arg as libc::c_int == '\0' as i32 {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1631 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s line %d: keyword %s empty argument\0" as *const u8
                                as *const libc::c_char,
                            filename,
                            linenum,
                            keyword,
                        );
                        current_block = 7482270440933722938;
                        break;
                    } else if flags & 8 as libc::c_int != 0 as libc::c_int {
                        argv_consume(&mut ac);
                        current_block = 5600328731811258759;
                        break;
                    } else {
                        negated = (*arg as libc::c_int == '!' as i32) as libc::c_int;
                        if negated != 0 {
                            arg = arg.offset(1);
                            arg;
                        }
                        if !(match_pattern(host, arg) != 0) {
                            continue;
                        }
                        if negated != 0 {
                            crate::log::sshlog(
                                b"readconf.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<
                                    &[u8; 26],
                                    &[libc::c_char; 26],
                                >(b"process_config_line_depth\0"))
                                    .as_ptr(),
                                1646 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"%.200s line %d: Skipping Host block because of negated match for %.100s\0"
                                    as *const u8 as *const libc::c_char,
                                filename,
                                linenum,
                                arg,
                            );
                            *activep = 0 as libc::c_int;
                            argv_consume(&mut ac);
                            current_block = 5600328731811258759;
                            break;
                        } else {
                            if *activep == 0 {
                                arg2 = arg;
                            }
                            *activep = 1 as libc::c_int;
                        }
                    }
                }
                match current_block {
                    7482270440933722938 => {}
                    _ => {
                        if *activep != 0 {
                            crate::log::sshlog(
                                b"readconf.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                    b"process_config_line_depth\0",
                                ))
                                .as_ptr(),
                                1658 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"%.200s line %d: Applying options for %.100s\0" as *const u8
                                    as *const libc::c_char,
                                filename,
                                linenum,
                                arg2,
                            );
                        }
                        current_block = 3935247052025034411;
                    }
                }
            }
        }
        2 => {
            if cmdline != 0 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1664 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Host directive not supported as a command-line option\0" as *const u8
                        as *const libc::c_char,
                );
                current_block = 7482270440933722938;
            } else {
                value = match_cfg_line(
                    options,
                    &mut str,
                    pw,
                    host,
                    original_host,
                    flags & 4 as libc::c_int,
                    want_final_pass,
                    filename,
                    linenum,
                );
                if value < 0 as libc::c_int {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1672 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: Bad Match condition\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        linenum,
                    );
                    current_block = 7482270440933722938;
                } else {
                    *activep = if flags & 8 as libc::c_int != 0 {
                        0 as libc::c_int
                    } else {
                        value
                    };
                    if str.is_null() || *str as libc::c_int == '\0' as i32 {
                        argv_consume(&mut ac);
                    }
                    current_block = 3935247052025034411;
                }
            }
        }
        22 => {
            intptr = &mut (*options).escape_char;
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1690 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                if libc::strcmp(arg, b"none\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    value = -(2 as libc::c_int);
                    current_block = 15439134456549723682;
                } else if *arg.offset(1 as libc::c_int as isize) as libc::c_int == '\0' as i32 {
                    value = *arg.offset(0 as libc::c_int as isize) as u_char as libc::c_int;
                    current_block = 15439134456549723682;
                } else if *arg.offset(0 as libc::c_int as isize) as libc::c_int == '^' as i32
                    && *arg.offset(2 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
                    && *arg.offset(1 as libc::c_int as isize) as u_char as libc::c_int
                        >= 64 as libc::c_int
                    && (*arg.offset(1 as libc::c_int as isize) as u_char as libc::c_int)
                        < 128 as libc::c_int
                {
                    value = *arg.offset(1 as libc::c_int as isize) as u_char as libc::c_int
                        & 31 as libc::c_int;
                    current_block = 15439134456549723682;
                } else {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1702 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: Bad escape character.\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        linenum,
                    );
                    current_block = 7482270440933722938;
                }
                match current_block {
                    7482270440933722938 => {}
                    _ => {
                        if *activep != 0 && *intptr == -(1 as libc::c_int) {
                            *intptr = value;
                        }
                        current_block = 3935247052025034411;
                    }
                }
            }
        }
        55 => {
            intptr = &mut (*options).address_family;
            multistate_ptr = multistate_addressfamily.as_ptr();
            current_block = 790863646429703468;
        }
        51 => {
            intptr = &mut (*options).enable_ssh_keysign;
            current_block = 15720799472059460288;
        }
        60 => {
            intptr = &mut (*options).identities_only;
            current_block = 15720799472059460288;
        }
        58 => {
            intptr = &mut (*options).server_alive_interval;
            current_block = 11955811698013090598;
        }
        59 => {
            intptr = &mut (*options).server_alive_count_max;
            current_block = 17629687495357276654;
        }
        61 => loop {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() {
                current_block = 3935247052025034411;
                break;
            }
            if *arg as libc::c_int == '\0' as i32 || !(libc::strchr(arg, '=' as i32)).is_null() {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1734 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s line %d: Invalid environment name.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
                break;
            } else {
                if *activep == 0 {
                    continue;
                }
                if *arg as libc::c_int == '-' as i32 {
                    rm_env(options, arg, filename, linenum);
                } else {
                    opt_array_append(
                        filename,
                        linenum,
                        lookup_opcode_name(opcode as OpCodes),
                        &mut (*options).send_env,
                        &mut (*options).num_send_env,
                        arg,
                    );
                }
            }
        },
        62 => {
            value = (*options).num_setenv as libc::c_int;
            loop {
                arg = argv_next(&mut ac, &mut av);
                if arg.is_null() {
                    current_block = 3935247052025034411;
                    break;
                }
                if (libc::strchr(arg, '=' as i32)).is_null() {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1755 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s line %d: Invalid SetEnv.\0" as *const u8 as *const libc::c_char,
                        filename,
                        linenum,
                    );
                    current_block = 7482270440933722938;
                    break;
                } else {
                    if *activep == 0 || value != 0 as libc::c_int {
                        continue;
                    }
                    if !(lookup_setenv_in_list(
                        arg,
                        (*options).setenv,
                        (*options).num_setenv as size_t,
                    ))
                    .is_null()
                    {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1763 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"%s line %d: ignoring duplicate env name \"%.64s\"\0" as *const u8
                                as *const libc::c_char,
                            filename,
                            linenum,
                            arg,
                        );
                    } else {
                        opt_array_append(
                            filename,
                            linenum,
                            lookup_opcode_name(opcode as OpCodes),
                            &mut (*options).setenv,
                            &mut (*options).num_setenv,
                            arg,
                        );
                    }
                }
            }
        }
        63 => {
            charptr = &mut (*options).control_path;
            current_block = 6865066298509711319;
        }
        64 => {
            intptr = &mut (*options).control_master;
            multistate_ptr = multistate_controlmaster.as_ptr();
            current_block = 790863646429703468;
        }
        65 => {
            intptr = &mut (*options).control_persist;
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1787 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing ControlPersist argument.\0" as *const u8
                        as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                value = 0 as libc::c_int;
                value2 = 0 as libc::c_int;
                if libc::strcmp(arg, b"no\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                    || libc::strcmp(arg, b"false\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                {
                    value = 0 as libc::c_int;
                    current_block = 763911284580919563;
                } else if libc::strcmp(arg, b"yes\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                    || libc::strcmp(arg, b"true\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                {
                    value = 1 as libc::c_int;
                    current_block = 763911284580919563;
                } else {
                    value2 = convtime(arg);
                    if value2 >= 0 as libc::c_int {
                        value = 1 as libc::c_int;
                        current_block = 763911284580919563;
                    } else {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1800 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%.200s line %d: Bad ControlPersist argument.\0" as *const u8
                                as *const libc::c_char,
                            filename,
                            linenum,
                        );
                        current_block = 7482270440933722938;
                    }
                }
                match current_block {
                    7482270440933722938 => {}
                    _ => {
                        if *activep != 0 && *intptr == -(1 as libc::c_int) {
                            *intptr = value;
                            (*options).control_persist_timeout = value2;
                        }
                        current_block = 3935247052025034411;
                    }
                }
            }
        }
        66 => {
            intptr = &mut (*options).hash_known_hosts;
            current_block = 15720799472059460288;
        }
        67 => {
            intptr = &mut (*options).tun_open;
            multistate_ptr = multistate_tunnel.as_ptr();
            current_block = 790863646429703468;
        }
        68 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1822 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                value = a2tun(arg, &mut value2);
                if value == 0x7fffffff as libc::c_int - 1 as libc::c_int {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1828 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: Bad tun device.\0" as *const u8 as *const libc::c_char,
                        filename,
                        linenum,
                    );
                    current_block = 7482270440933722938;
                } else {
                    if *activep != 0 && (*options).tun_local == -(1 as libc::c_int) {
                        (*options).tun_local = value;
                        (*options).tun_remote = value2;
                    }
                    current_block = 3935247052025034411;
                }
            }
        }
        69 => {
            charptr = &mut (*options).local_command;
            current_block = 13881330248250323440;
        }
        70 => {
            intptr = &mut (*options).permit_local_command;
            current_block = 15720799472059460288;
        }
        71 => {
            charptr = &mut (*options).remote_command;
            current_block = 13881330248250323440;
        }
        72 => {
            intptr = &mut (*options).visual_host_key;
            current_block = 15720799472059460288;
        }
        3 => {
            if cmdline != 0 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1856 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Include directive not supported as a command-line option\0" as *const u8
                        as *const libc::c_char,
                );
                current_block = 7482270440933722938;
            } else {
                value = 0 as libc::c_int;
                's_1975: loop {
                    arg = argv_next(&mut ac, &mut av);
                    if arg.is_null() {
                        current_block = 14170946608255986518;
                        break;
                    }
                    if *arg as libc::c_int == '\0' as i32 {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1863 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s line %d: keyword %s empty argument\0" as *const u8
                                as *const libc::c_char,
                            filename,
                            linenum,
                            keyword,
                        );
                        current_block = 7482270440933722938;
                        break;
                    } else if *arg as libc::c_int == '~' as i32
                        && flags & 2 as libc::c_int == 0 as libc::c_int
                    {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1875 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%.200s line %d: bad include path %s.\0" as *const u8
                                as *const libc::c_char,
                            filename,
                            linenum,
                            arg,
                        );
                        current_block = 7482270440933722938;
                        break;
                    } else {
                        if path_absolute(arg) == 0 && *arg as libc::c_int != '~' as i32 {
                            crate::xmalloc::xasprintf(
                                &mut arg2 as *mut *mut libc::c_char,
                                b"%s/%s\0" as *const u8 as *const libc::c_char,
                                if flags & 2 as libc::c_int != 0 {
                                    b"~/.ssh\0" as *const u8 as *const libc::c_char
                                } else {
                                    b"/usr/local/etc\0" as *const u8 as *const libc::c_char
                                },
                                arg,
                            );
                        } else {
                            arg2 = crate::xmalloc::xstrdup(arg);
                        }
                        memset(
                            &mut gl as *mut crate::openbsd_compat::glob::_ssh_compat_glob_t
                                as *mut libc::c_void,
                            0 as libc::c_int,
                            ::core::mem::size_of::<crate::openbsd_compat::glob::_ssh_compat_glob_t>(
                            ) as libc::c_ulong,
                        );
                        r = _ssh__compat_glob(arg2, 0x800 as libc::c_int, None, &mut gl);
                        if r == -(3 as libc::c_int) {
                            crate::log::sshlog(
                                b"readconf.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                    b"process_config_line_depth\0",
                                ))
                                .as_ptr(),
                                1888 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"%.200s line %d: include %s matched no files\0" as *const u8
                                    as *const libc::c_char,
                                filename,
                                linenum,
                                arg2,
                            );
                            libc::free(arg2 as *mut libc::c_void);
                        } else if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"readconf.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                    b"process_config_line_depth\0",
                                ))
                                .as_ptr(),
                                1893 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"%.200s line %d: glob failed for %s.\0" as *const u8
                                    as *const libc::c_char,
                                filename,
                                linenum,
                                arg2,
                            );
                            current_block = 7482270440933722938;
                            break;
                        } else {
                            libc::free(arg2 as *mut libc::c_void);
                            oactive = *activep;
                            i = 0 as libc::c_int as u_int;
                            while (i as libc::c_ulong) < gl.gl_pathc {
                                crate::log::sshlog(
                                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                        b"process_config_line_depth\0",
                                    ))
                                    .as_ptr(),
                                    1902 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG3,
                                    0 as *const libc::c_char,
                                    b"%.200s line %d: Including file %s depth %d%s\0" as *const u8
                                        as *const libc::c_char,
                                    filename,
                                    linenum,
                                    *(gl.gl_pathv).offset(i as isize),
                                    depth,
                                    if oactive != 0 {
                                        b"\0" as *const u8 as *const libc::c_char
                                    } else {
                                        b" (parse only)\0" as *const u8 as *const libc::c_char
                                    },
                                );
                                r = read_config_file_depth(
                                    *(gl.gl_pathv).offset(i as isize),
                                    pw,
                                    host,
                                    original_host,
                                    options,
                                    flags
                                        | 1 as libc::c_int
                                        | (if oactive != 0 {
                                            0 as libc::c_int
                                        } else {
                                            8 as libc::c_int
                                        }),
                                    activep,
                                    want_final_pass,
                                    depth + 1 as libc::c_int,
                                );
                                if r != 1 as libc::c_int
                                    && *libc::__errno_location() != 2 as libc::c_int
                                {
                                    crate::log::sshlog(
                                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                            b"process_config_line_depth\0",
                                        ))
                                        .as_ptr(),
                                        1911 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"Can't open user config file %.100s: %.100s\0" as *const u8
                                            as *const libc::c_char,
                                        *(gl.gl_pathv).offset(i as isize),
                                        libc::strerror(*libc::__errno_location()),
                                    );
                                    _ssh__compat_globfree(&mut gl);
                                    current_block = 7482270440933722938;
                                    break 's_1975;
                                } else {
                                    *activep = oactive;
                                    if r != 1 as libc::c_int {
                                        value = -(1 as libc::c_int);
                                    }
                                    i = i.wrapping_add(1);
                                    i;
                                }
                            }
                            _ssh__compat_globfree(&mut gl);
                        }
                    }
                }
                match current_block {
                    7482270440933722938 => {}
                    _ => {
                        if value != 0 as libc::c_int {
                            ret = value;
                        }
                        current_block = 3935247052025034411;
                    }
                }
            }
        }
        74 => {
            arg = argv_next(&mut ac, &mut av);
            value = parse_ipqos(arg);
            if value == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1933 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s line %d: Bad IPQoS value: %s\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                    arg,
                );
                current_block = 7482270440933722938;
            } else {
                arg = argv_next(&mut ac, &mut av);
                if arg.is_null() {
                    value2 = value;
                    current_block = 10800801741953260091;
                } else {
                    value2 = parse_ipqos(arg);
                    if value2 == -(1 as libc::c_int) {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1941 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s line %d: Bad IPQoS value: %s\0" as *const u8
                                as *const libc::c_char,
                            filename,
                            linenum,
                            arg,
                        );
                        current_block = 7482270440933722938;
                    } else {
                        current_block = 10800801741953260091;
                    }
                }
                match current_block {
                    7482270440933722938 => {}
                    _ => {
                        if *activep != 0 && (*options).ip_qos_interactive == -(1 as libc::c_int) {
                            (*options).ip_qos_interactive = value;
                            (*options).ip_qos_bulk = value2;
                        }
                        current_block = 3935247052025034411;
                    }
                }
            }
        }
        75 => {
            intptr = &mut (*options).request_tty;
            multistate_ptr = multistate_requesttty.as_ptr();
            current_block = 790863646429703468;
        }
        76 => {
            intptr = &mut (*options).session_type;
            multistate_ptr = multistate_sessiontype.as_ptr();
            current_block = 790863646429703468;
        }
        77 => {
            intptr = &mut (*options).stdin_null;
            current_block = 15720799472059460288;
        }
        78 => {
            intptr = &mut (*options).fork_after_authentication;
            current_block = 15720799472059460288;
        }
        79 => {
            charptr = &mut (*options).ignored_unknown;
            current_block = 6865066298509711319;
        }
        80 => {
            intptr = &mut (*options).proxy_use_fdpass;
            current_block = 15720799472059460288;
        }
        81 => {
            value = ((*options).num_canonical_domains != 0 as libc::c_int) as libc::c_int;
            i = 0 as libc::c_int as u_int;
            loop {
                arg = argv_next(&mut ac, &mut av);
                if arg.is_null() {
                    current_block = 3935247052025034411;
                    break;
                }
                if *arg as libc::c_int == '\0' as i32 {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1982 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s line %d: keyword %s empty argument\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        linenum,
                        keyword,
                    );
                    current_block = 7482270440933722938;
                    break;
                } else {
                    if strcasecmp(arg, b"none\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                    {
                        if i > 0 as libc::c_int as libc::c_uint || ac > 0 as libc::c_int {
                            crate::log::sshlog(
                                b"readconf.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                    b"process_config_line_depth\0",
                                ))
                                .as_ptr(),
                                1990 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"%s line %d: keyword %s \"none\" argument must appear alone.\0"
                                    as *const u8
                                    as *const libc::c_char,
                                filename,
                                linenum,
                                keyword,
                            );
                            current_block = 7482270440933722938;
                            break;
                        }
                    }
                    i = i.wrapping_add(1);
                    i;
                    if valid_domain(arg, 1 as libc::c_int, &mut errstr) == 0 {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1997 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s line %d: %s\0" as *const u8 as *const libc::c_char,
                            filename,
                            linenum,
                            errstr,
                        );
                        current_block = 7482270440933722938;
                        break;
                    } else {
                        if *activep == 0 || value != 0 {
                            continue;
                        }
                        if (*options).num_canonical_domains >= 32 as libc::c_int {
                            crate::log::sshlog(
                                b"readconf.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                    b"process_config_line_depth\0",
                                ))
                                .as_ptr(),
                                2005 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"%s line %d: too many hostname suffixes.\0" as *const u8
                                    as *const libc::c_char,
                                filename,
                                linenum,
                            );
                            current_block = 7482270440933722938;
                            break;
                        } else {
                            let fresh11 = (*options).num_canonical_domains;
                            (*options).num_canonical_domains = (*options).num_canonical_domains + 1;
                            (*options).canonical_domains[fresh11 as usize] =
                                crate::xmalloc::xstrdup(arg);
                        }
                    }
                }
            }
        }
        85 => {
            value = ((*options).num_permitted_cnames != 0 as libc::c_int) as libc::c_int;
            i = 0 as libc::c_int as u_int;
            loop {
                arg = argv_next(&mut ac, &mut av);
                if arg.is_null() {
                    current_block = 3935247052025034411;
                    break;
                }
                if strcasecmp(arg, b"none\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    if i > 0 as libc::c_int as libc::c_uint || ac > 0 as libc::c_int {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            2025 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s line %d: keyword %s \"none\" argument must appear alone.\0"
                                as *const u8 as *const libc::c_char,
                            filename,
                            linenum,
                            keyword,
                        );
                        current_block = 7482270440933722938;
                        break;
                    } else {
                        arg2 = b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
                    }
                } else if libc::strcmp(arg, b"*\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    arg2 = arg;
                } else {
                    lowercase(arg);
                    arg2 = libc::strchr(arg, ':' as i32);
                    if arg2.is_null()
                        || *arg2.offset(1 as libc::c_int as isize) as libc::c_int == '\0' as i32
                    {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            2037 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s line %d: Invalid permitted CNAME \"%s\"\0" as *const u8
                                as *const libc::c_char,
                            filename,
                            linenum,
                            arg,
                        );
                        current_block = 7482270440933722938;
                        break;
                    } else {
                        *arg2 = '\0' as i32 as libc::c_char;
                        arg2 = arg2.offset(1);
                        arg2;
                    }
                }
                i = i.wrapping_add(1);
                i;
                if *activep == 0 || value != 0 {
                    continue;
                }
                if (*options).num_permitted_cnames >= 32 as libc::c_int {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        2049 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s line %d: too many permitted CNAMEs.\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        linenum,
                    );
                    current_block = 7482270440933722938;
                    break;
                } else {
                    let fresh12 = (*options).num_permitted_cnames;
                    (*options).num_permitted_cnames = (*options).num_permitted_cnames + 1;
                    cname = ((*options).permitted_cnames)
                        .as_mut_ptr()
                        .offset(fresh12 as isize);
                    (*cname).source_list = crate::xmalloc::xstrdup(arg);
                    (*cname).target_list = crate::xmalloc::xstrdup(arg2);
                }
            }
        }
        82 => {
            intptr = &mut (*options).canonicalize_hostname;
            multistate_ptr = multistate_canonicalizehostname.as_ptr();
            current_block = 790863646429703468;
        }
        83 => {
            intptr = &mut (*options).canonicalize_max_dots;
            current_block = 17629687495357276654;
        }
        84 => {
            intptr = &mut (*options).canonicalize_fallback_local;
            current_block = 15720799472059460288;
        }
        86 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    2076 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing StreamLocalBindMask argument.\0" as *const u8
                        as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                value = strtol(arg, &mut endofnumber, 8 as libc::c_int) as libc::c_int;
                if arg == endofnumber || value < 0 as libc::c_int || value > 0o777 as libc::c_int {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        2082 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: Bad mask.\0" as *const u8 as *const libc::c_char,
                        filename,
                        linenum,
                    );
                    current_block = 7482270440933722938;
                } else {
                    (*options).fwd_opts.streamlocal_bind_mask = value as mode_t;
                    current_block = 3935247052025034411;
                }
            }
        }
        87 => {
            intptr = &mut (*options).fwd_opts.streamlocal_bind_unlink;
            current_block = 15720799472059460288;
        }
        88 => {
            charptr = &mut (*options).revoked_host_keys;
            current_block = 6865066298509711319;
        }
        89 => {
            intptr = &mut (*options).fingerprint_hash;
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    2101 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                value = ssh_digest_alg_by_name(arg);
                if value == -(1 as libc::c_int) {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        2106 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: Invalid hash algorithm \"%s\".\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        linenum,
                        arg,
                    );
                    current_block = 7482270440933722938;
                } else {
                    if *activep != 0 && *intptr == -(1 as libc::c_int) {
                        *intptr = value;
                    }
                    current_block = 3935247052025034411;
                }
            }
        }
        90 => {
            intptr = &mut (*options).update_hostkeys;
            multistate_ptr = multistate_yesnoask.as_ptr();
            current_block = 790863646429703468;
        }
        91 => {
            charptr = &mut (*options).hostbased_accepted_algos;
            current_block = 11785309045061247795;
        }
        92 => {
            charptr = &mut (*options).pubkey_accepted_algos;
            current_block = 11785309045061247795;
        }
        19 => {
            arg = argv_next(&mut ac, &mut av);
            arg2 = argv_next(&mut ac, &mut av);
            value =
                parse_multistate_value(arg, filename, linenum, multistate_yesnoaskconfirm.as_ptr());
            value2 = 0 as libc::c_int;
            if value == 3 as libc::c_int && !arg2.is_null() {
                value2 = convtime(arg2);
                if value2 == -(1 as libc::c_int) {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        2136 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s line %d: invalid time value.\0" as *const u8 as *const libc::c_char,
                        filename,
                        linenum,
                    );
                    current_block = 7482270440933722938;
                } else {
                    current_block = 819159959065740665;
                }
            } else if value == -(1 as libc::c_int) && arg2.is_null() {
                value2 = convtime(arg);
                if value2 == -(1 as libc::c_int) {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        2142 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s line %d: unsupported option\0" as *const u8 as *const libc::c_char,
                        filename,
                        linenum,
                    );
                    current_block = 7482270440933722938;
                } else {
                    value = 1 as libc::c_int;
                    current_block = 819159959065740665;
                }
            } else if value == -(1 as libc::c_int) || !arg2.is_null() {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    2148 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s line %d: unsupported option\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                current_block = 819159959065740665;
            }
            match current_block {
                7482270440933722938 => {}
                _ => {
                    if *activep != 0 && (*options).add_keys_to_agent == -(1 as libc::c_int) {
                        (*options).add_keys_to_agent = value;
                        (*options).add_keys_to_agent_lifespan = value2;
                    }
                    current_block = 3935247052025034411;
                }
            }
        }
        20 => {
            charptr = &mut (*options).identity_agent;
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    2162 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                current_block = 16523242387479284007;
            }
        }
        98 => {
            intptr = &mut (*options).enable_escape_commandline;
            current_block = 15720799472059460288;
        }
        97 => {
            intptr = &mut (*options).required_rsa_size;
            current_block = 17629687495357276654;
        }
        101 => {
            crate::log::sshlog(
                b"readconf.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"process_config_line_depth\0",
                ))
                .as_ptr(),
                2194 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"%s line %d: Deprecated option \"%s\"\0" as *const u8 as *const libc::c_char,
                filename,
                linenum,
                keyword,
            );
            argv_consume(&mut ac);
            current_block = 3935247052025034411;
        }
        102 => {
            crate::log::sshlog(
                b"readconf.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"process_config_line_depth\0",
                ))
                .as_ptr(),
                2200 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"%s line %d: Unsupported option \"%s\"\0" as *const u8 as *const libc::c_char,
                filename,
                linenum,
                keyword,
            );
            argv_consume(&mut ac);
            current_block = 3935247052025034411;
        }
        _ => {
            crate::log::sshlog(
                b"readconf.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"process_config_line_depth\0",
                ))
                .as_ptr(),
                2206 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"%s line %d: Unimplemented opcode %d\0" as *const u8 as *const libc::c_char,
                filename,
                linenum,
                opcode,
            );
            current_block = 7482270440933722938;
        }
    }
    match current_block {
        11785309045061247795 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1448 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else if *arg as libc::c_int != '-' as i32
                && sshkey_names_valid2(
                    if *arg as libc::c_int == '+' as i32 || *arg as libc::c_int == '^' as i32 {
                        arg.offset(1 as libc::c_int as isize)
                    } else {
                        arg
                    },
                    1 as libc::c_int,
                ) == 0
            {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1455 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s line %d: Bad key types '%s'.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                    if !arg.is_null() {
                        arg as *const libc::c_char
                    } else {
                        b"<NONE>\0" as *const u8 as *const libc::c_char
                    },
                );
                current_block = 7482270440933722938;
            } else {
                if *activep != 0 && (*charptr).is_null() {
                    *charptr = crate::xmalloc::xstrdup(arg);
                }
                current_block = 3935247052025034411;
            }
        }
        17629687495357276654 => {
            arg = argv_next(&mut ac, &mut av);
            errstr = atoi_err(arg, &mut value);
            if !errstr.is_null() {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1383 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s line %d: integer value %s.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                    errstr,
                );
                current_block = 7482270440933722938;
            } else {
                if *activep != 0 && *intptr == -(1 as libc::c_int) {
                    *intptr = value;
                }
                current_block = 3935247052025034411;
            }
        }
        13881330248250323440 => {
            if str.is_null() {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1335 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                len = strspn(str, b" \t\r\n=\0" as *const u8 as *const libc::c_char);
                if *activep != 0 && (*charptr).is_null() {
                    *charptr = crate::xmalloc::xstrdup(str.offset(len as isize));
                }
                argv_consume(&mut ac);
                current_block = 3935247052025034411;
            }
        }
        16874605264102726382 => {
            i = 0 as libc::c_int as u_int;
            value = (*uintptr == 0 as libc::c_int as libc::c_uint) as libc::c_int;
            loop {
                arg = argv_next(&mut ac, &mut av);
                if arg.is_null() {
                    current_block = 3935247052025034411;
                    break;
                }
                if *arg as libc::c_int == '\0' as i32 {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        1264 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s line %d: keyword %s empty argument\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        linenum,
                        keyword,
                    );
                    current_block = 7482270440933722938;
                    break;
                } else {
                    if strcasecmp(arg, b"none\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                    {
                        if i > 0 as libc::c_int as libc::c_uint || ac > 0 as libc::c_int {
                            crate::log::sshlog(
                                b"readconf.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                    b"process_config_line_depth\0",
                                ))
                                .as_ptr(),
                                1272 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"%s line %d: keyword %s \"none\" argument must appear alone.\0"
                                    as *const u8
                                    as *const libc::c_char,
                                filename,
                                linenum,
                                keyword,
                            );
                            current_block = 7482270440933722938;
                            break;
                        }
                    }
                    i = i.wrapping_add(1);
                    i;
                    if !(*activep != 0 && value != 0) {
                        continue;
                    }
                    if *uintptr >= max_entries {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1281 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s line %d: too many %s entries.\0" as *const u8
                                as *const libc::c_char,
                            filename,
                            linenum,
                            keyword,
                        );
                        current_block = 7482270440933722938;
                        break;
                    } else {
                        let fresh7 = *uintptr;
                        *uintptr = (*uintptr).wrapping_add(1);
                        let ref mut fresh8 = *cpptr.offset(fresh7 as isize);
                        *fresh8 = crate::xmalloc::xstrdup(arg);
                    }
                }
            }
        }
        6865066298509711319 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1247 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Missing argument.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                if *activep != 0 && (*charptr).is_null() {
                    *charptr = crate::xmalloc::xstrdup(arg);
                }
                current_block = 3935247052025034411;
            }
        }
        11955811698013090598 => {
            arg = argv_next(&mut ac, &mut av);
            if arg.is_null() || *arg as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1023 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s line %d: missing time value.\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                );
                current_block = 7482270440933722938;
            } else {
                if libc::strcmp(arg, b"none\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
                {
                    value = -(1 as libc::c_int);
                    current_block = 12199444798915819164;
                } else {
                    value = convtime(arg);
                    if value == -(1 as libc::c_int) {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                b"process_config_line_depth\0",
                            ))
                            .as_ptr(),
                            1030 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s line %d: invalid time value.\0" as *const u8
                                as *const libc::c_char,
                            filename,
                            linenum,
                        );
                        current_block = 7482270440933722938;
                    } else {
                        current_block = 12199444798915819164;
                    }
                }
                match current_block {
                    7482270440933722938 => {}
                    _ => {
                        if *activep != 0 && *intptr == -(1 as libc::c_int) {
                            *intptr = value;
                        }
                        current_block = 3935247052025034411;
                    }
                }
            }
        }
        16523242387479284007 => {
            arg2 = dollar_expand(&mut r as *mut libc::c_int, arg);
            if arg2.is_null() || r != 0 {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    2169 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: Invalid environment expansion %s.\0" as *const u8
                        as *const libc::c_char,
                    filename,
                    linenum,
                    arg,
                );
                current_block = 7482270440933722938;
            } else {
                libc::free(arg2 as *mut libc::c_void);
                if *arg.offset(0 as libc::c_int as isize) as libc::c_int == '$' as i32
                    && *arg.offset(1 as libc::c_int as isize) as libc::c_int != '{' as i32
                    && valid_env_name(arg.offset(1 as libc::c_int as isize)) == 0
                {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"process_config_line_depth\0",
                        ))
                        .as_ptr(),
                        2177 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%.200s line %d: Invalid environment name %s.\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        linenum,
                        arg,
                    );
                    current_block = 7482270440933722938;
                } else {
                    if *activep != 0 && (*charptr).is_null() {
                        *charptr = crate::xmalloc::xstrdup(arg);
                    }
                    current_block = 3935247052025034411;
                }
            }
        }
        15720799472059460288 => {
            multistate_ptr = multistate_flag.as_ptr();
            current_block = 790863646429703468;
        }
        _ => {}
    }
    match current_block {
        790863646429703468 => {
            arg = argv_next(&mut ac, &mut av);
            value = parse_multistate_value(arg, filename, linenum, multistate_ptr);
            if value == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    1076 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s line %d: unsupported option \"%s\".\0" as *const u8 as *const libc::c_char,
                    filename,
                    linenum,
                    arg,
                );
                current_block = 7482270440933722938;
            } else {
                if *activep != 0 && *intptr == -(1 as libc::c_int) {
                    *intptr = value;
                }
                current_block = 3935247052025034411;
            }
        }
        _ => {}
    }
    match current_block {
        3935247052025034411 => {
            if ac > 0 as libc::c_int {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"process_config_line_depth\0",
                    ))
                    .as_ptr(),
                    2213 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%.200s line %d: keyword %s extra arguments at end of line\0" as *const u8
                        as *const libc::c_char,
                    filename,
                    linenum,
                    keyword,
                );
            } else {
                ret = 0 as libc::c_int;
            }
        }
        _ => {}
    }
    argv_free(oav, oac);
    return ret;
}
pub unsafe extern "C" fn read_config_file(
    mut filename: *const libc::c_char,
    mut pw: *mut libc::passwd,
    mut host: *const libc::c_char,
    mut original_host: *const libc::c_char,
    mut options: *mut Options,
    mut flags: libc::c_int,
    mut want_final_pass: *mut libc::c_int,
) -> libc::c_int {
    let mut active: libc::c_int = 1 as libc::c_int;
    return read_config_file_depth(
        filename,
        pw,
        host,
        original_host,
        options,
        flags,
        &mut active,
        want_final_pass,
        0 as libc::c_int,
    );
}
unsafe extern "C" fn read_config_file_depth(
    mut filename: *const libc::c_char,
    mut pw: *mut libc::passwd,
    mut host: *const libc::c_char,
    mut original_host: *const libc::c_char,
    mut options: *mut Options,
    mut flags: libc::c_int,
    mut activep: *mut libc::c_int,
    mut want_final_pass: *mut libc::c_int,
    mut depth: libc::c_int,
) -> libc::c_int {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut linenum: libc::c_int = 0;
    let mut bad_options: libc::c_int = 0 as libc::c_int;
    if depth < 0 as libc::c_int || depth > 16 as libc::c_int {
        sshfatal(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"read_config_file_depth\0",
            ))
            .as_ptr(),
            2253 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Too many recursive configuration includes\0" as *const u8 as *const libc::c_char,
        );
    }
    f = fopen(filename, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        return 0 as libc::c_int;
    }
    if flags & 1 as libc::c_int != 0 {
        let mut sb: libc::stat = unsafe { std::mem::zeroed() };
        if libc::fstat(fileno(f), &mut sb) == -(1 as libc::c_int) {
            sshfatal(
                b"readconf.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"read_config_file_depth\0",
                ))
                .as_ptr(),
                2262 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"libc::fstat %s: %s\0" as *const u8 as *const libc::c_char,
                filename,
                libc::strerror(*libc::__errno_location()),
            );
        }
        if sb.st_uid != 0 as libc::c_int as libc::c_uint && sb.st_uid != libc::getuid()
            || sb.st_mode & 0o22 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
        {
            sshfatal(
                b"readconf.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"read_config_file_depth\0",
                ))
                .as_ptr(),
                2265 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Bad owner or permissions on %s\0" as *const u8 as *const libc::c_char,
                filename,
            );
        }
    }
    crate::log::sshlog(
        b"readconf.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"read_config_file_depth\0"))
            .as_ptr(),
        2268 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Reading configuration data %.200s\0" as *const u8 as *const libc::c_char,
        filename,
    );
    linenum = 0 as libc::c_int;
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        linenum += 1;
        linenum;
        if process_config_line_depth(
            options,
            pw,
            host,
            original_host,
            line,
            filename,
            linenum,
            activep,
            flags,
            want_final_pass,
            depth,
        ) != 0 as libc::c_int
        {
            bad_options += 1;
            bad_options;
        }
    }
    libc::free(line as *mut libc::c_void);
    fclose(f);
    if bad_options > 0 as libc::c_int {
        sshfatal(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"read_config_file_depth\0",
            ))
            .as_ptr(),
            2292 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: terminating, %d bad configuration options\0" as *const u8 as *const libc::c_char,
            filename,
            bad_options,
        );
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn option_clear_or_none(mut o: *const libc::c_char) -> libc::c_int {
    return (o.is_null()
        || strcasecmp(o, b"none\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int)
        as libc::c_int;
}
pub unsafe extern "C" fn config_has_permitted_cnames(mut options: *mut Options) -> libc::c_int {
    if (*options).num_permitted_cnames == 1 as libc::c_int
        && strcasecmp(
            (*options).permitted_cnames[0 as libc::c_int as usize].source_list,
            b"none\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        && libc::strcmp(
            (*options).permitted_cnames[0 as libc::c_int as usize].target_list,
            b"\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return ((*options).num_permitted_cnames > 0 as libc::c_int) as libc::c_int;
}
pub unsafe extern "C" fn initialize_options(mut options: *mut Options) {
    memset(
        options as *mut libc::c_void,
        'X' as i32,
        ::core::mem::size_of::<Options>() as libc::c_ulong,
    );
    (*options).host_arg = 0 as *mut libc::c_char;
    (*options).forward_agent = -(1 as libc::c_int);
    (*options).forward_agent_sock_path = 0 as *mut libc::c_char;
    (*options).forward_x11 = -(1 as libc::c_int);
    (*options).forward_x11_trusted = -(1 as libc::c_int);
    (*options).forward_x11_timeout = -(1 as libc::c_int);
    (*options).stdio_forward_host = 0 as *mut libc::c_char;
    (*options).stdio_forward_port = 0 as libc::c_int;
    (*options).clear_forwardings = -(1 as libc::c_int);
    (*options).exit_on_forward_failure = -(1 as libc::c_int);
    (*options).xauth_location = 0 as *mut libc::c_char;
    (*options).fwd_opts.gateway_ports = -(1 as libc::c_int);
    (*options).fwd_opts.streamlocal_bind_mask = -(1 as libc::c_int) as mode_t;
    (*options).fwd_opts.streamlocal_bind_unlink = -(1 as libc::c_int);
    (*options).pubkey_authentication = -(1 as libc::c_int);
    (*options).gss_authentication = -(1 as libc::c_int);
    (*options).gss_deleg_creds = -(1 as libc::c_int);
    (*options).password_authentication = -(1 as libc::c_int);
    (*options).kbd_interactive_authentication = -(1 as libc::c_int);
    (*options).kbd_interactive_devices = 0 as *mut libc::c_char;
    (*options).hostbased_authentication = -(1 as libc::c_int);
    (*options).batch_mode = -(1 as libc::c_int);
    (*options).check_host_ip = -(1 as libc::c_int);
    (*options).strict_host_key_checking = -(1 as libc::c_int);
    (*options).compression = -(1 as libc::c_int);
    (*options).tcp_keep_alive = -(1 as libc::c_int);
    (*options).port = -(1 as libc::c_int);
    (*options).address_family = -(1 as libc::c_int);
    (*options).connection_attempts = -(1 as libc::c_int);
    (*options).connection_timeout = -(1 as libc::c_int);
    (*options).number_of_password_prompts = -(1 as libc::c_int);
    (*options).ciphers = 0 as *mut libc::c_char;
    (*options).macs = 0 as *mut libc::c_char;
    (*options).kex_algorithms = 0 as *mut libc::c_char;
    (*options).hostkeyalgorithms = 0 as *mut libc::c_char;
    (*options).ca_sign_algorithms = 0 as *mut libc::c_char;
    (*options).num_identity_files = 0 as libc::c_int;
    memset(
        ((*options).identity_keys).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[*mut crate::sshkey::sshkey; 100]>() as libc::c_ulong,
    );
    (*options).num_certificate_files = 0 as libc::c_int;
    memset(
        ((*options).certificates).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[*mut crate::sshkey::sshkey; 100]>() as libc::c_ulong,
    );
    (*options).hostname = 0 as *mut libc::c_char;
    (*options).host_key_alias = 0 as *mut libc::c_char;
    (*options).proxy_command = 0 as *mut libc::c_char;
    (*options).jump_user = 0 as *mut libc::c_char;
    (*options).jump_host = 0 as *mut libc::c_char;
    (*options).jump_port = -(1 as libc::c_int);
    (*options).jump_extra = 0 as *mut libc::c_char;
    (*options).user = 0 as *mut libc::c_char;
    (*options).escape_char = -(1 as libc::c_int);
    (*options).num_system_hostfiles = 0 as libc::c_int as u_int;
    (*options).num_user_hostfiles = 0 as libc::c_int as u_int;
    (*options).local_forwards = 0 as *mut Forward;
    (*options).num_local_forwards = 0 as libc::c_int;
    (*options).remote_forwards = 0 as *mut Forward;
    (*options).num_remote_forwards = 0 as libc::c_int;
    (*options).permitted_remote_opens = 0 as *mut *mut libc::c_char;
    (*options).num_permitted_remote_opens = 0 as libc::c_int as u_int;
    (*options).log_facility = SYSLOG_FACILITY_NOT_SET;
    (*options).log_level = SYSLOG_LEVEL_NOT_SET;
    (*options).num_log_verbose = 0 as libc::c_int as u_int;
    (*options).log_verbose = 0 as *mut *mut libc::c_char;
    (*options).preferred_authentications = 0 as *mut libc::c_char;
    (*options).bind_address = 0 as *mut libc::c_char;
    (*options).bind_interface = 0 as *mut libc::c_char;
    (*options).pkcs11_provider = 0 as *mut libc::c_char;
    (*options).sk_provider = 0 as *mut libc::c_char;
    (*options).enable_ssh_keysign = -(1 as libc::c_int);
    (*options).no_host_authentication_for_localhost = -(1 as libc::c_int);
    (*options).identities_only = -(1 as libc::c_int);
    (*options).rekey_limit = -(1 as libc::c_int) as int64_t;
    (*options).rekey_interval = -(1 as libc::c_int);
    (*options).verify_host_key_dns = -(1 as libc::c_int);
    (*options).server_alive_interval = -(1 as libc::c_int);
    (*options).server_alive_count_max = -(1 as libc::c_int);
    (*options).send_env = 0 as *mut *mut libc::c_char;
    (*options).num_send_env = 0 as libc::c_int as u_int;
    (*options).setenv = 0 as *mut *mut libc::c_char;
    (*options).num_setenv = 0 as libc::c_int as u_int;
    (*options).control_path = 0 as *mut libc::c_char;
    (*options).control_master = -(1 as libc::c_int);
    (*options).control_persist = -(1 as libc::c_int);
    (*options).control_persist_timeout = 0 as libc::c_int;
    (*options).hash_known_hosts = -(1 as libc::c_int);
    (*options).tun_open = -(1 as libc::c_int);
    (*options).tun_local = -(1 as libc::c_int);
    (*options).tun_remote = -(1 as libc::c_int);
    (*options).local_command = 0 as *mut libc::c_char;
    (*options).permit_local_command = -(1 as libc::c_int);
    (*options).remote_command = 0 as *mut libc::c_char;
    (*options).add_keys_to_agent = -(1 as libc::c_int);
    (*options).add_keys_to_agent_lifespan = -(1 as libc::c_int);
    (*options).identity_agent = 0 as *mut libc::c_char;
    (*options).visual_host_key = -(1 as libc::c_int);
    (*options).ip_qos_interactive = -(1 as libc::c_int);
    (*options).ip_qos_bulk = -(1 as libc::c_int);
    (*options).request_tty = -(1 as libc::c_int);
    (*options).session_type = -(1 as libc::c_int);
    (*options).stdin_null = -(1 as libc::c_int);
    (*options).fork_after_authentication = -(1 as libc::c_int);
    (*options).proxy_use_fdpass = -(1 as libc::c_int);
    (*options).ignored_unknown = 0 as *mut libc::c_char;
    (*options).num_canonical_domains = 0 as libc::c_int;
    (*options).num_permitted_cnames = 0 as libc::c_int;
    (*options).canonicalize_max_dots = -(1 as libc::c_int);
    (*options).canonicalize_fallback_local = -(1 as libc::c_int);
    (*options).canonicalize_hostname = -(1 as libc::c_int);
    (*options).revoked_host_keys = 0 as *mut libc::c_char;
    (*options).fingerprint_hash = -(1 as libc::c_int);
    (*options).update_hostkeys = -(1 as libc::c_int);
    (*options).hostbased_accepted_algos = 0 as *mut libc::c_char;
    (*options).pubkey_accepted_algos = 0 as *mut libc::c_char;
    (*options).known_hosts_command = 0 as *mut libc::c_char;
    (*options).required_rsa_size = -(1 as libc::c_int);
    (*options).enable_escape_commandline = -(1 as libc::c_int);
}
pub unsafe extern "C" fn fill_default_options_for_canonicalization(mut options: *mut Options) {
    if (*options).canonicalize_max_dots == -(1 as libc::c_int) {
        (*options).canonicalize_max_dots = 1 as libc::c_int;
    }
    if (*options).canonicalize_fallback_local == -(1 as libc::c_int) {
        (*options).canonicalize_fallback_local = 1 as libc::c_int;
    }
    if (*options).canonicalize_hostname == -(1 as libc::c_int) {
        (*options).canonicalize_hostname = 0 as libc::c_int;
    }
}
pub unsafe extern "C" fn fill_default_options(mut options: *mut Options) -> libc::c_int {
    let mut all_cipher: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut all_mac: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut all_kex: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut all_key: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut all_sig: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut def_cipher: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut def_mac: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut def_kex: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut def_key: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut def_sig: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    if (*options).forward_agent == -(1 as libc::c_int) {
        (*options).forward_agent = 0 as libc::c_int;
    }
    if (*options).forward_x11 == -(1 as libc::c_int) {
        (*options).forward_x11 = 0 as libc::c_int;
    }
    if (*options).forward_x11_trusted == -(1 as libc::c_int) {
        (*options).forward_x11_trusted = 0 as libc::c_int;
    }
    if (*options).forward_x11_timeout == -(1 as libc::c_int) {
        (*options).forward_x11_timeout = 1200 as libc::c_int;
    }
    if (*options).exit_on_forward_failure == -(1 as libc::c_int) {
        (*options).exit_on_forward_failure = if !((*options).stdio_forward_host).is_null() {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        };
    }
    if (*options).clear_forwardings == -(1 as libc::c_int) {
        (*options).clear_forwardings = if !((*options).stdio_forward_host).is_null() {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        };
    }
    if (*options).clear_forwardings == 1 as libc::c_int {
        clear_forwardings(options);
    }
    if ((*options).xauth_location).is_null() {
        (*options).xauth_location =
            crate::xmalloc::xstrdup(b"/usr/bin/xauth\0" as *const u8 as *const libc::c_char);
    }
    if (*options).fwd_opts.gateway_ports == -(1 as libc::c_int) {
        (*options).fwd_opts.gateway_ports = 0 as libc::c_int;
    }
    if (*options).fwd_opts.streamlocal_bind_mask == -(1 as libc::c_int) as mode_t {
        (*options).fwd_opts.streamlocal_bind_mask = 0o177 as libc::c_int as mode_t;
    }
    if (*options).fwd_opts.streamlocal_bind_unlink == -(1 as libc::c_int) {
        (*options).fwd_opts.streamlocal_bind_unlink = 0 as libc::c_int;
    }
    if (*options).pubkey_authentication == -(1 as libc::c_int) {
        (*options).pubkey_authentication = 0x3 as libc::c_int;
    }
    if (*options).gss_authentication == -(1 as libc::c_int) {
        (*options).gss_authentication = 0 as libc::c_int;
    }
    if (*options).gss_deleg_creds == -(1 as libc::c_int) {
        (*options).gss_deleg_creds = 0 as libc::c_int;
    }
    if (*options).password_authentication == -(1 as libc::c_int) {
        (*options).password_authentication = 1 as libc::c_int;
    }
    if (*options).kbd_interactive_authentication == -(1 as libc::c_int) {
        (*options).kbd_interactive_authentication = 1 as libc::c_int;
    }
    if (*options).hostbased_authentication == -(1 as libc::c_int) {
        (*options).hostbased_authentication = 0 as libc::c_int;
    }
    if (*options).batch_mode == -(1 as libc::c_int) {
        (*options).batch_mode = 0 as libc::c_int;
    }
    if (*options).check_host_ip == -(1 as libc::c_int) {
        (*options).check_host_ip = 0 as libc::c_int;
    }
    if (*options).strict_host_key_checking == -(1 as libc::c_int) {
        (*options).strict_host_key_checking = 3 as libc::c_int;
    }
    if (*options).compression == -(1 as libc::c_int) {
        (*options).compression = 0 as libc::c_int;
    }
    if (*options).tcp_keep_alive == -(1 as libc::c_int) {
        (*options).tcp_keep_alive = 1 as libc::c_int;
    }
    if (*options).port == -(1 as libc::c_int) {
        (*options).port = 0 as libc::c_int;
    }
    if (*options).address_family == -(1 as libc::c_int) {
        (*options).address_family = 0 as libc::c_int;
    }
    if (*options).connection_attempts == -(1 as libc::c_int) {
        (*options).connection_attempts = 1 as libc::c_int;
    }
    if (*options).number_of_password_prompts == -(1 as libc::c_int) {
        (*options).number_of_password_prompts = 3 as libc::c_int;
    }
    if (*options).add_keys_to_agent == -(1 as libc::c_int) {
        (*options).add_keys_to_agent = 0 as libc::c_int;
        (*options).add_keys_to_agent_lifespan = 0 as libc::c_int;
    }
    if (*options).num_identity_files == 0 as libc::c_int {
        add_identity_file(
            options,
            b"~/\0" as *const u8 as *const libc::c_char,
            b".ssh/id_rsa\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        );
        add_identity_file(
            options,
            b"~/\0" as *const u8 as *const libc::c_char,
            b".ssh/id_ecdsa\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        );
        add_identity_file(
            options,
            b"~/\0" as *const u8 as *const libc::c_char,
            b".ssh/id_ecdsa_sk\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        );
        add_identity_file(
            options,
            b"~/\0" as *const u8 as *const libc::c_char,
            b".ssh/id_ed25519\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        );
        add_identity_file(
            options,
            b"~/\0" as *const u8 as *const libc::c_char,
            b".ssh/id_ed25519_sk\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        );
        add_identity_file(
            options,
            b"~/\0" as *const u8 as *const libc::c_char,
            b".ssh/id_xmss\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        );
        add_identity_file(
            options,
            b"~/\0" as *const u8 as *const libc::c_char,
            b".ssh/id_dsa\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        );
    }
    if (*options).escape_char == -(1 as libc::c_int) {
        (*options).escape_char = '~' as i32;
    }
    if (*options).num_system_hostfiles == 0 as libc::c_int as libc::c_uint {
        let fresh13 = (*options).num_system_hostfiles;
        (*options).num_system_hostfiles = ((*options).num_system_hostfiles).wrapping_add(1);
        (*options).system_hostfiles[fresh13 as usize] = crate::xmalloc::xstrdup(
            b"/usr/local/etc/ssh_known_hosts\0" as *const u8 as *const libc::c_char,
        );
        let fresh14 = (*options).num_system_hostfiles;
        (*options).num_system_hostfiles = ((*options).num_system_hostfiles).wrapping_add(1);
        (*options).system_hostfiles[fresh14 as usize] = crate::xmalloc::xstrdup(
            b"/usr/local/etc/ssh_known_hosts2\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*options).update_hostkeys == -(1 as libc::c_int) {
        if (*options).verify_host_key_dns <= 0 as libc::c_int
            && ((*options).num_user_hostfiles == 0 as libc::c_int as libc::c_uint
                || (*options).num_user_hostfiles == 1 as libc::c_int as libc::c_uint
                    && libc::strcmp(
                        (*options).user_hostfiles[0 as libc::c_int as usize],
                        b"~/.ssh/known_hosts\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int)
        {
            (*options).update_hostkeys = 1 as libc::c_int;
        } else {
            (*options).update_hostkeys = 0 as libc::c_int;
        }
    }
    if (*options).num_user_hostfiles == 0 as libc::c_int as libc::c_uint {
        let fresh15 = (*options).num_user_hostfiles;
        (*options).num_user_hostfiles = ((*options).num_user_hostfiles).wrapping_add(1);
        (*options).user_hostfiles[fresh15 as usize] =
            crate::xmalloc::xstrdup(b"~/.ssh/known_hosts\0" as *const u8 as *const libc::c_char);
        let fresh16 = (*options).num_user_hostfiles;
        (*options).num_user_hostfiles = ((*options).num_user_hostfiles).wrapping_add(1);
        (*options).user_hostfiles[fresh16 as usize] =
            crate::xmalloc::xstrdup(b"~/.ssh/known_hosts2\0" as *const u8 as *const libc::c_char);
    }
    if (*options).log_level as libc::c_int == SYSLOG_LEVEL_NOT_SET as libc::c_int {
        (*options).log_level = SYSLOG_LEVEL_INFO;
    }
    if (*options).log_facility as libc::c_int == SYSLOG_FACILITY_NOT_SET as libc::c_int {
        (*options).log_facility = SYSLOG_FACILITY_USER;
    }
    if (*options).no_host_authentication_for_localhost == -(1 as libc::c_int) {
        (*options).no_host_authentication_for_localhost = 0 as libc::c_int;
    }
    if (*options).identities_only == -(1 as libc::c_int) {
        (*options).identities_only = 0 as libc::c_int;
    }
    if (*options).enable_ssh_keysign == -(1 as libc::c_int) {
        (*options).enable_ssh_keysign = 0 as libc::c_int;
    }
    if (*options).rekey_limit == -(1 as libc::c_int) as libc::c_long {
        (*options).rekey_limit = 0 as libc::c_int as int64_t;
    }
    if (*options).rekey_interval == -(1 as libc::c_int) {
        (*options).rekey_interval = 0 as libc::c_int;
    }
    if (*options).verify_host_key_dns == -(1 as libc::c_int) {
        (*options).verify_host_key_dns = 0 as libc::c_int;
    }
    if (*options).server_alive_interval == -(1 as libc::c_int) {
        (*options).server_alive_interval = 0 as libc::c_int;
    }
    if (*options).server_alive_count_max == -(1 as libc::c_int) {
        (*options).server_alive_count_max = 3 as libc::c_int;
    }
    if (*options).control_master == -(1 as libc::c_int) {
        (*options).control_master = 0 as libc::c_int;
    }
    if (*options).control_persist == -(1 as libc::c_int) {
        (*options).control_persist = 0 as libc::c_int;
        (*options).control_persist_timeout = 0 as libc::c_int;
    }
    if (*options).hash_known_hosts == -(1 as libc::c_int) {
        (*options).hash_known_hosts = 0 as libc::c_int;
    }
    if (*options).tun_open == -(1 as libc::c_int) {
        (*options).tun_open = 0 as libc::c_int;
    }
    if (*options).tun_local == -(1 as libc::c_int) {
        (*options).tun_local = 0x7fffffff as libc::c_int;
    }
    if (*options).tun_remote == -(1 as libc::c_int) {
        (*options).tun_remote = 0x7fffffff as libc::c_int;
    }
    if (*options).permit_local_command == -(1 as libc::c_int) {
        (*options).permit_local_command = 0 as libc::c_int;
    }
    if (*options).visual_host_key == -(1 as libc::c_int) {
        (*options).visual_host_key = 0 as libc::c_int;
    }
    if (*options).ip_qos_interactive == -(1 as libc::c_int) {
        (*options).ip_qos_interactive = 0x48 as libc::c_int;
    }
    if (*options).ip_qos_bulk == -(1 as libc::c_int) {
        (*options).ip_qos_bulk = 0x20 as libc::c_int;
    }
    if (*options).request_tty == -(1 as libc::c_int) {
        (*options).request_tty = 0 as libc::c_int;
    }
    if (*options).session_type == -(1 as libc::c_int) {
        (*options).session_type = 2 as libc::c_int;
    }
    if (*options).stdin_null == -(1 as libc::c_int) {
        (*options).stdin_null = 0 as libc::c_int;
    }
    if (*options).fork_after_authentication == -(1 as libc::c_int) {
        (*options).fork_after_authentication = 0 as libc::c_int;
    }
    if (*options).proxy_use_fdpass == -(1 as libc::c_int) {
        (*options).proxy_use_fdpass = 0 as libc::c_int;
    }
    if (*options).canonicalize_max_dots == -(1 as libc::c_int) {
        (*options).canonicalize_max_dots = 1 as libc::c_int;
    }
    if (*options).canonicalize_fallback_local == -(1 as libc::c_int) {
        (*options).canonicalize_fallback_local = 1 as libc::c_int;
    }
    if (*options).canonicalize_hostname == -(1 as libc::c_int) {
        (*options).canonicalize_hostname = 0 as libc::c_int;
    }
    if (*options).fingerprint_hash == -(1 as libc::c_int) {
        (*options).fingerprint_hash = 2 as libc::c_int;
    }
    if ((*options).sk_provider).is_null() {
        (*options).sk_provider =
            crate::xmalloc::xstrdup(b"$SSH_SK_PROVIDER\0" as *const u8 as *const libc::c_char);
    }
    if (*options).required_rsa_size == -(1 as libc::c_int) {
        (*options).required_rsa_size = 1024 as libc::c_int;
    }
    if (*options).enable_escape_commandline == -(1 as libc::c_int) {
        (*options).enable_escape_commandline = 0 as libc::c_int;
    }
    all_cipher = cipher_alg_list(',' as i32 as libc::c_char, 0 as libc::c_int);
    all_mac = mac_alg_list(',' as i32 as libc::c_char);
    all_kex = kex_alg_list(',' as i32 as libc::c_char);
    all_key = sshkey_alg_list(
        0 as libc::c_int,
        0 as libc::c_int,
        1 as libc::c_int,
        ',' as i32 as libc::c_char,
    );
    all_sig = sshkey_alg_list(
        0 as libc::c_int,
        1 as libc::c_int,
        1 as libc::c_int,
        ',' as i32 as libc::c_char,
    );
    def_cipher = match_filter_allowlist(
        b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\0"
            as *const u8 as *const libc::c_char,
        all_cipher,
    );
    def_mac = match_filter_allowlist(
        b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\0"
            as *const u8 as *const libc::c_char,
        all_mac,
    );
    def_kex = match_filter_allowlist(
        b"sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256\0"
            as *const u8 as *const libc::c_char,
        all_kex,
    );
    def_key = match_filter_allowlist(
        b"ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\0"
            as *const u8 as *const libc::c_char,
        all_key,
    );
    def_sig = match_filter_allowlist(
        b"ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\0"
            as *const u8 as *const libc::c_char,
        all_sig,
    );
    r = kex_assemble_names(&mut (*options).ciphers, def_cipher, all_cipher);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"fill_default_options\0"))
                .as_ptr(),
            2663 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"%s\0" as *const u8 as *const libc::c_char,
            b"ciphers\0" as *const u8 as *const libc::c_char,
        );
    } else {
        r = kex_assemble_names(&mut (*options).macs, def_mac, all_mac);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"readconf.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"fill_default_options\0",
                ))
                .as_ptr(),
                2664 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"%s\0" as *const u8 as *const libc::c_char,
                b"macs\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = kex_assemble_names(&mut (*options).kex_algorithms, def_kex, all_kex);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"readconf.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"fill_default_options\0",
                    ))
                    .as_ptr(),
                    2665 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"%s\0" as *const u8 as *const libc::c_char,
                    b"kex_algorithms\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = kex_assemble_names(&mut (*options).hostbased_accepted_algos, def_key, all_key);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"readconf.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"fill_default_options\0",
                        ))
                        .as_ptr(),
                        2666 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"%s\0" as *const u8 as *const libc::c_char,
                        b"hostbased_accepted_algos\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    r = kex_assemble_names(&mut (*options).pubkey_accepted_algos, def_key, all_key);
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"readconf.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                                b"fill_default_options\0",
                            ))
                            .as_ptr(),
                            2667 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"%s\0" as *const u8 as *const libc::c_char,
                            b"pubkey_accepted_algos\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        r = kex_assemble_names(
                            &mut (*options).ca_sign_algorithms,
                            def_sig,
                            all_sig,
                        );
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"readconf.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                                    b"fill_default_options\0",
                                ))
                                .as_ptr(),
                                2668 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"%s\0" as *const u8 as *const libc::c_char,
                                b"ca_sign_algorithms\0" as *const u8 as *const libc::c_char,
                            );
                        } else {
                            if option_clear_or_none((*options).local_command) != 0 {
                                libc::free((*options).local_command as *mut libc::c_void);
                                (*options).local_command = 0 as *mut libc::c_char;
                            }
                            if option_clear_or_none((*options).remote_command) != 0 {
                                libc::free((*options).remote_command as *mut libc::c_void);
                                (*options).remote_command = 0 as *mut libc::c_char;
                            }
                            if option_clear_or_none((*options).proxy_command) != 0 {
                                libc::free((*options).proxy_command as *mut libc::c_void);
                                (*options).proxy_command = 0 as *mut libc::c_char;
                            }
                            if option_clear_or_none((*options).control_path) != 0 {
                                libc::free((*options).control_path as *mut libc::c_void);
                                (*options).control_path = 0 as *mut libc::c_char;
                            }
                            if option_clear_or_none((*options).revoked_host_keys) != 0 {
                                libc::free((*options).revoked_host_keys as *mut libc::c_void);
                                (*options).revoked_host_keys = 0 as *mut libc::c_char;
                            }
                            if option_clear_or_none((*options).pkcs11_provider) != 0 {
                                libc::free((*options).pkcs11_provider as *mut libc::c_void);
                                (*options).pkcs11_provider = 0 as *mut libc::c_char;
                            }
                            if option_clear_or_none((*options).sk_provider) != 0 {
                                libc::free((*options).sk_provider as *mut libc::c_void);
                                (*options).sk_provider = 0 as *mut libc::c_char;
                            }
                            if option_clear_or_none((*options).known_hosts_command) != 0 {
                                libc::free((*options).known_hosts_command as *mut libc::c_void);
                                (*options).known_hosts_command = 0 as *mut libc::c_char;
                            }
                            if !((*options).jump_host).is_null()
                                && libc::strcmp(
                                    (*options).jump_host,
                                    b"none\0" as *const u8 as *const libc::c_char,
                                ) == 0 as libc::c_int
                                && (*options).jump_port == 0 as libc::c_int
                                && ((*options).jump_user).is_null()
                            {
                                libc::free((*options).jump_host as *mut libc::c_void);
                                (*options).jump_host = 0 as *mut libc::c_char;
                            }
                            if (*options).num_permitted_cnames == 1 as libc::c_int
                                && config_has_permitted_cnames(options) == 0
                            {
                                libc::free(
                                    (*options).permitted_cnames[0 as libc::c_int as usize]
                                        .source_list
                                        as *mut libc::c_void,
                                );
                                libc::free(
                                    (*options).permitted_cnames[0 as libc::c_int as usize]
                                        .target_list
                                        as *mut libc::c_void,
                                );
                                memset(
                                    ((*options).permitted_cnames).as_mut_ptr() as *mut libc::c_void,
                                    '\0' as i32,
                                    ::core::mem::size_of::<allowed_cname>() as libc::c_ulong,
                                );
                                (*options).num_permitted_cnames = 0 as libc::c_int;
                            }
                            ret = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    libc::free(all_cipher as *mut libc::c_void);
    libc::free(all_mac as *mut libc::c_void);
    libc::free(all_kex as *mut libc::c_void);
    libc::free(all_key as *mut libc::c_void);
    libc::free(all_sig as *mut libc::c_void);
    libc::free(def_cipher as *mut libc::c_void);
    libc::free(def_mac as *mut libc::c_void);
    libc::free(def_kex as *mut libc::c_void);
    libc::free(def_key as *mut libc::c_void);
    libc::free(def_sig as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn free_options(mut o: *mut Options) {
    let mut i: libc::c_int = 0;
    if o.is_null() {
        return;
    }
    libc::free((*o).forward_agent_sock_path as *mut libc::c_void);
    libc::free((*o).xauth_location as *mut libc::c_void);
    let mut _i: u_int = 0;
    _i = 0 as libc::c_int as u_int;
    while _i < (*o).num_log_verbose {
        libc::free(*((*o).log_verbose).offset(_i as isize) as *mut libc::c_void);
        _i = _i.wrapping_add(1);
        _i;
    }
    libc::free((*o).log_verbose as *mut libc::c_void);
    libc::free((*o).ciphers as *mut libc::c_void);
    libc::free((*o).macs as *mut libc::c_void);
    libc::free((*o).hostkeyalgorithms as *mut libc::c_void);
    libc::free((*o).kex_algorithms as *mut libc::c_void);
    libc::free((*o).ca_sign_algorithms as *mut libc::c_void);
    libc::free((*o).hostname as *mut libc::c_void);
    libc::free((*o).host_key_alias as *mut libc::c_void);
    libc::free((*o).proxy_command as *mut libc::c_void);
    libc::free((*o).user as *mut libc::c_void);
    let mut _i_0: u_int = 0;
    _i_0 = 0 as libc::c_int as u_int;
    while _i_0 < (*o).num_system_hostfiles {
        libc::free((*o).system_hostfiles[_i_0 as usize] as *mut libc::c_void);
        _i_0 = _i_0.wrapping_add(1);
        _i_0;
    }
    let mut _i_1: u_int = 0;
    _i_1 = 0 as libc::c_int as u_int;
    while _i_1 < (*o).num_user_hostfiles {
        libc::free((*o).user_hostfiles[_i_1 as usize] as *mut libc::c_void);
        _i_1 = _i_1.wrapping_add(1);
        _i_1;
    }
    libc::free((*o).preferred_authentications as *mut libc::c_void);
    libc::free((*o).bind_address as *mut libc::c_void);
    libc::free((*o).bind_interface as *mut libc::c_void);
    libc::free((*o).pkcs11_provider as *mut libc::c_void);
    libc::free((*o).sk_provider as *mut libc::c_void);
    i = 0 as libc::c_int;
    while i < (*o).num_identity_files {
        libc::free((*o).identity_files[i as usize] as *mut libc::c_void);
        crate::sshkey::sshkey_free((*o).identity_keys[i as usize]);
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < (*o).num_certificate_files {
        libc::free((*o).certificate_files[i as usize] as *mut libc::c_void);
        crate::sshkey::sshkey_free((*o).certificates[i as usize]);
        i += 1;
        i;
    }
    libc::free((*o).identity_agent as *mut libc::c_void);
    i = 0 as libc::c_int;
    while i < (*o).num_local_forwards {
        libc::free((*((*o).local_forwards).offset(i as isize)).listen_host as *mut libc::c_void);
        libc::free((*((*o).local_forwards).offset(i as isize)).listen_path as *mut libc::c_void);
        libc::free((*((*o).local_forwards).offset(i as isize)).connect_host as *mut libc::c_void);
        libc::free((*((*o).local_forwards).offset(i as isize)).connect_path as *mut libc::c_void);
        i += 1;
        i;
    }
    libc::free((*o).local_forwards as *mut libc::c_void);
    i = 0 as libc::c_int;
    while i < (*o).num_remote_forwards {
        libc::free((*((*o).remote_forwards).offset(i as isize)).listen_host as *mut libc::c_void);
        libc::free((*((*o).remote_forwards).offset(i as isize)).listen_path as *mut libc::c_void);
        libc::free((*((*o).remote_forwards).offset(i as isize)).connect_host as *mut libc::c_void);
        libc::free((*((*o).remote_forwards).offset(i as isize)).connect_path as *mut libc::c_void);
        i += 1;
        i;
    }
    libc::free((*o).remote_forwards as *mut libc::c_void);
    libc::free((*o).stdio_forward_host as *mut libc::c_void);
    let mut _i_2: u_int = 0;
    _i_2 = 0 as libc::c_int as u_int;
    while _i_2 < (*o).num_send_env {
        libc::free(*((*o).send_env).offset(_i_2 as isize) as *mut libc::c_void);
        _i_2 = _i_2.wrapping_add(1);
        _i_2;
    }
    libc::free((*o).send_env as *mut libc::c_void);
    let mut _i_3: u_int = 0;
    _i_3 = 0 as libc::c_int as u_int;
    while _i_3 < (*o).num_setenv {
        libc::free(*((*o).setenv).offset(_i_3 as isize) as *mut libc::c_void);
        _i_3 = _i_3.wrapping_add(1);
        _i_3;
    }
    libc::free((*o).setenv as *mut libc::c_void);
    libc::free((*o).control_path as *mut libc::c_void);
    libc::free((*o).local_command as *mut libc::c_void);
    libc::free((*o).remote_command as *mut libc::c_void);
    let mut _i_4: libc::c_int = 0;
    _i_4 = 0 as libc::c_int;
    while _i_4 < (*o).num_canonical_domains {
        libc::free((*o).canonical_domains[_i_4 as usize] as *mut libc::c_void);
        _i_4 += 1;
        _i_4;
    }
    i = 0 as libc::c_int;
    while i < (*o).num_permitted_cnames {
        libc::free((*o).permitted_cnames[i as usize].source_list as *mut libc::c_void);
        libc::free((*o).permitted_cnames[i as usize].target_list as *mut libc::c_void);
        i += 1;
        i;
    }
    libc::free((*o).revoked_host_keys as *mut libc::c_void);
    libc::free((*o).hostbased_accepted_algos as *mut libc::c_void);
    libc::free((*o).pubkey_accepted_algos as *mut libc::c_void);
    libc::free((*o).jump_user as *mut libc::c_void);
    libc::free((*o).jump_host as *mut libc::c_void);
    libc::free((*o).jump_extra as *mut libc::c_void);
    libc::free((*o).ignored_unknown as *mut libc::c_void);
    explicit_bzero(
        o as *mut libc::c_void,
        ::core::mem::size_of::<Options>() as libc::c_ulong,
    );
}
unsafe extern "C" fn parse_fwd_field(
    mut p: *mut *mut libc::c_char,
    mut fwd: *mut fwdarg,
) -> libc::c_int {
    let mut ep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = *p;
    let mut ispath: libc::c_int = 0 as libc::c_int;
    if *cp as libc::c_int == '\0' as i32 {
        *p = 0 as *mut libc::c_char;
        return -(1 as libc::c_int);
    }
    if *cp as libc::c_int == '[' as i32 {
        ep = cp.offset(1 as libc::c_int as isize);
        while *ep as libc::c_int != ']' as i32 && *ep as libc::c_int != '\0' as i32 {
            if *ep as libc::c_int == '/' as i32 {
                ispath = 1 as libc::c_int;
            }
            ep = ep.offset(1);
            ep;
        }
        if *ep.offset(0 as libc::c_int as isize) as libc::c_int != ']' as i32
            || *ep.offset(1 as libc::c_int as isize) as libc::c_int != ':' as i32
                && *ep.offset(1 as libc::c_int as isize) as libc::c_int != '\0' as i32
        {
            return -(1 as libc::c_int);
        }
        let fresh17 = ep;
        ep = ep.offset(1);
        *fresh17 = '\0' as i32 as libc::c_char;
        if *ep as libc::c_int != '\0' as i32 {
            let fresh18 = ep;
            ep = ep.offset(1);
            *fresh18 = '\0' as i32 as libc::c_char;
        }
        (*fwd).arg = cp.offset(1 as libc::c_int as isize);
        (*fwd).ispath = ispath;
        *p = ep;
        return 0 as libc::c_int;
    }
    cp = *p;
    while *cp as libc::c_int != '\0' as i32 {
        match *cp as libc::c_int {
            92 => {
                memmove(
                    cp as *mut libc::c_void,
                    cp.offset(1 as libc::c_int as isize) as *const libc::c_void,
                    (strlen(cp.offset(1 as libc::c_int as isize)))
                        .wrapping_add(1 as libc::c_int as libc::c_ulong),
                );
                if *cp as libc::c_int == '\0' as i32 {
                    return -(1 as libc::c_int);
                }
            }
            47 => {
                ispath = 1 as libc::c_int;
            }
            58 => {
                let fresh19 = cp;
                cp = cp.offset(1);
                *fresh19 = '\0' as i32 as libc::c_char;
                break;
            }
            _ => {}
        }
        cp = cp.offset(1);
        cp;
    }
    (*fwd).arg = *p;
    (*fwd).ispath = ispath;
    *p = cp;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn parse_forward(
    mut fwd: *mut Forward,
    mut fwdspec: *const libc::c_char,
    mut dynamicfwd: libc::c_int,
    mut remotefwd: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut fwdargs: [fwdarg; 4] = [fwdarg {
        arg: 0 as *mut libc::c_char,
        ispath: 0,
    }; 4];
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: libc::c_int = 0;
    let mut err: libc::c_int = 0;
    memset(
        fwd as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<Forward>() as libc::c_ulong,
    );
    memset(
        fwdargs.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[fwdarg; 4]>() as libc::c_ulong,
    );
    p = dollar_expand(&mut err as *mut libc::c_int, fwdspec);
    cp = p;
    if p.is_null() || err != 0 {
        return 0 as libc::c_int;
    }
    while *(*__ctype_b_loc()).offset(*cp as u_char as libc::c_int as isize) as libc::c_int
        & _ISspace as libc::c_int as libc::c_ushort as libc::c_int
        != 0
    {
        cp = cp.offset(1);
        cp;
    }
    i = 0 as libc::c_int;
    while i < 4 as libc::c_int {
        if parse_fwd_field(&mut cp, &mut *fwdargs.as_mut_ptr().offset(i as isize))
            != 0 as libc::c_int
        {
            break;
        }
        i += 1;
        i;
    }
    if !cp.is_null() && *cp as libc::c_int != '\0' as i32 {
        i = 0 as libc::c_int;
    }
    match i {
        1 => {
            if fwdargs[0 as libc::c_int as usize].ispath != 0 {
                (*fwd).listen_path =
                    crate::xmalloc::xstrdup(fwdargs[0 as libc::c_int as usize].arg);
                (*fwd).listen_port = -(2 as libc::c_int);
            } else {
                (*fwd).listen_host = 0 as *mut libc::c_char;
                (*fwd).listen_port = crate::misc::a2port(fwdargs[0 as libc::c_int as usize].arg);
            }
            (*fwd).connect_host =
                crate::xmalloc::xstrdup(b"socks\0" as *const u8 as *const libc::c_char);
        }
        2 => {
            if fwdargs[0 as libc::c_int as usize].ispath != 0
                && fwdargs[1 as libc::c_int as usize].ispath != 0
            {
                (*fwd).listen_path =
                    crate::xmalloc::xstrdup(fwdargs[0 as libc::c_int as usize].arg);
                (*fwd).listen_port = -(2 as libc::c_int);
                (*fwd).connect_path =
                    crate::xmalloc::xstrdup(fwdargs[1 as libc::c_int as usize].arg);
                (*fwd).connect_port = -(2 as libc::c_int);
            } else if fwdargs[1 as libc::c_int as usize].ispath != 0 {
                (*fwd).listen_host = 0 as *mut libc::c_char;
                (*fwd).listen_port = crate::misc::a2port(fwdargs[0 as libc::c_int as usize].arg);
                (*fwd).connect_path =
                    crate::xmalloc::xstrdup(fwdargs[1 as libc::c_int as usize].arg);
                (*fwd).connect_port = -(2 as libc::c_int);
            } else {
                (*fwd).listen_host =
                    crate::xmalloc::xstrdup(fwdargs[0 as libc::c_int as usize].arg);
                (*fwd).listen_port = crate::misc::a2port(fwdargs[1 as libc::c_int as usize].arg);
                (*fwd).connect_host =
                    crate::xmalloc::xstrdup(b"socks\0" as *const u8 as *const libc::c_char);
            }
        }
        3 => {
            if fwdargs[0 as libc::c_int as usize].ispath != 0 {
                (*fwd).listen_path =
                    crate::xmalloc::xstrdup(fwdargs[0 as libc::c_int as usize].arg);
                (*fwd).listen_port = -(2 as libc::c_int);
                (*fwd).connect_host =
                    crate::xmalloc::xstrdup(fwdargs[1 as libc::c_int as usize].arg);
                (*fwd).connect_port = crate::misc::a2port(fwdargs[2 as libc::c_int as usize].arg);
            } else if fwdargs[2 as libc::c_int as usize].ispath != 0 {
                (*fwd).listen_host =
                    crate::xmalloc::xstrdup(fwdargs[0 as libc::c_int as usize].arg);
                (*fwd).listen_port = crate::misc::a2port(fwdargs[1 as libc::c_int as usize].arg);
                (*fwd).connect_path =
                    crate::xmalloc::xstrdup(fwdargs[2 as libc::c_int as usize].arg);
                (*fwd).connect_port = -(2 as libc::c_int);
            } else {
                (*fwd).listen_host = 0 as *mut libc::c_char;
                (*fwd).listen_port = crate::misc::a2port(fwdargs[0 as libc::c_int as usize].arg);
                (*fwd).connect_host =
                    crate::xmalloc::xstrdup(fwdargs[1 as libc::c_int as usize].arg);
                (*fwd).connect_port = crate::misc::a2port(fwdargs[2 as libc::c_int as usize].arg);
            }
        }
        4 => {
            (*fwd).listen_host = crate::xmalloc::xstrdup(fwdargs[0 as libc::c_int as usize].arg);
            (*fwd).listen_port = crate::misc::a2port(fwdargs[1 as libc::c_int as usize].arg);
            (*fwd).connect_host = crate::xmalloc::xstrdup(fwdargs[2 as libc::c_int as usize].arg);
            (*fwd).connect_port = crate::misc::a2port(fwdargs[3 as libc::c_int as usize].arg);
        }
        _ => {
            i = 0 as libc::c_int;
        }
    }
    libc::free(p as *mut libc::c_void);
    if dynamicfwd != 0 {
        if !(i == 1 as libc::c_int || i == 2 as libc::c_int) {
            current_block = 741112630038433975;
        } else {
            current_block = 16415152177862271243;
        }
    } else {
        if !(i == 3 as libc::c_int || i == 4 as libc::c_int) {
            if ((*fwd).connect_path).is_null() && ((*fwd).listen_path).is_null() {
                current_block = 741112630038433975;
            } else {
                current_block = 9353995356876505083;
            }
        } else {
            current_block = 9353995356876505083;
        }
        match current_block {
            741112630038433975 => {}
            _ => {
                if (*fwd).connect_port <= 0 as libc::c_int && ((*fwd).connect_path).is_null() {
                    current_block = 741112630038433975;
                } else {
                    current_block = 16415152177862271243;
                }
            }
        }
    }
    match current_block {
        16415152177862271243 => {
            if !((*fwd).listen_port < 0 as libc::c_int && ((*fwd).listen_path).is_null()
                || remotefwd == 0 && (*fwd).listen_port == 0 as libc::c_int)
            {
                if !(!((*fwd).connect_host).is_null()
                    && strlen((*fwd).connect_host) >= 1025 as libc::c_int as libc::c_ulong)
                {
                    if !(!((*fwd).connect_path).is_null()
                        && strlen((*fwd).connect_path)
                            >= ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong)
                    {
                        if !(!((*fwd).listen_host).is_null()
                            && strlen((*fwd).listen_host) >= 1025 as libc::c_int as libc::c_ulong)
                        {
                            if !(!((*fwd).listen_path).is_null()
                                && strlen((*fwd).listen_path)
                                    >= ::core::mem::size_of::<[libc::c_char; 108]>()
                                        as libc::c_ulong)
                            {
                                return i;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    libc::free((*fwd).connect_host as *mut libc::c_void);
    (*fwd).connect_host = 0 as *mut libc::c_char;
    libc::free((*fwd).connect_path as *mut libc::c_void);
    (*fwd).connect_path = 0 as *mut libc::c_char;
    libc::free((*fwd).listen_host as *mut libc::c_void);
    (*fwd).listen_host = 0 as *mut libc::c_char;
    libc::free((*fwd).listen_path as *mut libc::c_void);
    (*fwd).listen_path = 0 as *mut libc::c_char;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn parse_jump(
    mut s: *const libc::c_char,
    mut o: *mut Options,
    mut active: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut orig: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sdup: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut port: libc::c_int = -(1 as libc::c_int);
    let mut first: libc::c_int = 0;
    active &= (((*o).proxy_command).is_null() && ((*o).jump_host).is_null()) as libc::c_int;
    sdup = crate::xmalloc::xstrdup(s);
    orig = sdup;
    cp = libc::strchr(orig, '#' as i32);
    if !cp.is_null() {
        *cp = '\0' as i32 as libc::c_char;
    }
    rtrim(orig);
    first = active;
    loop {
        if strcasecmp(s, b"none\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
            current_block = 1054647088692577877;
            break;
        }
        cp = libc::strrchr(sdup, ',' as i32);
        if cp.is_null() {
            cp = sdup;
        } else {
            let fresh20 = cp;
            cp = cp.offset(1);
            *fresh20 = '\0' as i32 as libc::c_char;
        }
        if first != 0 {
            r = parse_ssh_uri(cp, &mut user, &mut host, &mut port);
            if r == -(1 as libc::c_int)
                || r == 1 as libc::c_int
                    && parse_user_host_port(cp, &mut user, &mut host, &mut port) != 0 as libc::c_int
            {
                current_block = 16217910265081073014;
                break;
            }
        } else {
            r = parse_ssh_uri(
                cp,
                0 as *mut *mut libc::c_char,
                0 as *mut *mut libc::c_char,
                0 as *mut libc::c_int,
            );
            if r == -(1 as libc::c_int)
                || r == 1 as libc::c_int
                    && parse_user_host_port(
                        cp,
                        0 as *mut *mut libc::c_char,
                        0 as *mut *mut libc::c_char,
                        0 as *mut libc::c_int,
                    ) != 0 as libc::c_int
            {
                current_block = 16217910265081073014;
                break;
            }
        }
        first = 0 as libc::c_int;
        if !(cp != sdup) {
            current_block = 1054647088692577877;
            break;
        }
    }
    match current_block {
        1054647088692577877 => {
            if active != 0 {
                if strcasecmp(s, b"none\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
                {
                    (*o).jump_host =
                        crate::xmalloc::xstrdup(b"none\0" as *const u8 as *const libc::c_char);
                    (*o).jump_port = 0 as libc::c_int;
                } else {
                    (*o).jump_user = user;
                    (*o).jump_host = host;
                    (*o).jump_port = port;
                    (*o).proxy_command =
                        crate::xmalloc::xstrdup(b"none\0" as *const u8 as *const libc::c_char);
                    host = 0 as *mut libc::c_char;
                    user = host;
                    cp = libc::strrchr(s, ',' as i32);
                    if !cp.is_null() && cp != s as *mut libc::c_char {
                        (*o).jump_extra = crate::xmalloc::xstrdup(s);
                        *((*o).jump_extra).offset(cp.offset_from(s) as libc::c_long as isize) =
                            '\0' as i32 as libc::c_char;
                    }
                }
            }
            ret = 0 as libc::c_int;
        }
        _ => {}
    }
    libc::free(orig as *mut libc::c_void);
    libc::free(user as *mut libc::c_void);
    libc::free(host as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn parse_ssh_uri(
    mut uri: *const libc::c_char,
    mut userp: *mut *mut libc::c_char,
    mut hostp: *mut *mut libc::c_char,
    mut portp: *mut libc::c_int,
) -> libc::c_int {
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut port: libc::c_int = 0;
    r = parse_uri(
        b"ssh\0" as *const u8 as *const libc::c_char,
        uri,
        &mut user,
        &mut host,
        &mut port,
        &mut path,
    );
    if r == 0 as libc::c_int && !path.is_null() {
        r = -(1 as libc::c_int);
    }
    if r == 0 as libc::c_int {
        if !userp.is_null() {
            *userp = user;
            user = 0 as *mut libc::c_char;
        }
        if !hostp.is_null() {
            *hostp = host;
            host = 0 as *mut libc::c_char;
        }
        if !portp.is_null() {
            *portp = port;
        }
    }
    libc::free(user as *mut libc::c_void);
    libc::free(host as *mut libc::c_void);
    libc::free(path as *mut libc::c_void);
    return r;
}
unsafe extern "C" fn fmt_multistate_int(
    mut val: libc::c_int,
    mut m: *const multistate,
) -> *const libc::c_char {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while !((*m.offset(i as isize)).key).is_null() {
        if (*m.offset(i as isize)).value == val {
            return (*m.offset(i as isize)).key;
        }
        i = i.wrapping_add(1);
        i;
    }
    return b"UNKNOWN\0" as *const u8 as *const libc::c_char;
}
unsafe extern "C" fn fmt_intarg(mut code: OpCodes, mut val: libc::c_int) -> *const libc::c_char {
    if val == -(1 as libc::c_int) {
        return b"unset\0" as *const u8 as *const libc::c_char;
    }
    match code as libc::c_uint {
        55 => return fmt_multistate_int(val, multistate_addressfamily.as_ptr()),
        53 | 90 => return fmt_multistate_int(val, multistate_yesnoask.as_ptr()),
        29 => return fmt_multistate_int(val, multistate_strict_hostkey.as_ptr()),
        64 => return fmt_multistate_int(val, multistate_controlmaster.as_ptr()),
        67 => return fmt_multistate_int(val, multistate_tunnel.as_ptr()),
        75 => return fmt_multistate_int(val, multistate_requesttty.as_ptr()),
        76 => return fmt_multistate_int(val, multistate_sessiontype.as_ptr()),
        82 => return fmt_multistate_int(val, multistate_canonicalizehostname.as_ptr()),
        19 => return fmt_multistate_int(val, multistate_yesnoaskconfirm.as_ptr()),
        38 => return fmt_multistate_int(val, multistate_pubkey_auth.as_ptr()),
        89 => return ssh_digest_alg_name(val),
        _ => match val {
            0 => return b"no\0" as *const u8 as *const libc::c_char,
            1 => return b"yes\0" as *const u8 as *const libc::c_char,
            _ => return b"UNKNOWN\0" as *const u8 as *const libc::c_char,
        },
    };
}
unsafe extern "C" fn lookup_opcode_name(mut code: OpCodes) -> *const libc::c_char {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while !(keywords[i as usize].name).is_null() {
        if keywords[i as usize].opcode as libc::c_uint == code as libc::c_uint {
            return keywords[i as usize].name;
        }
        i = i.wrapping_add(1);
        i;
    }
    return b"UNKNOWN\0" as *const u8 as *const libc::c_char;
}
unsafe extern "C" fn dump_cfg_int(mut code: OpCodes, mut val: libc::c_int) {
    printf(
        b"%s %d\n\0" as *const u8 as *const libc::c_char,
        lookup_opcode_name(code),
        val,
    );
}
unsafe extern "C" fn dump_cfg_fmtint(mut code: OpCodes, mut val: libc::c_int) {
    printf(
        b"%s %s\n\0" as *const u8 as *const libc::c_char,
        lookup_opcode_name(code),
        fmt_intarg(code, val),
    );
}
unsafe extern "C" fn dump_cfg_string(mut code: OpCodes, mut val: *const libc::c_char) {
    if val.is_null() {
        return;
    }
    printf(
        b"%s %s\n\0" as *const u8 as *const libc::c_char,
        lookup_opcode_name(code),
        val,
    );
}
unsafe extern "C" fn dump_cfg_strarray(
    mut code: OpCodes,
    mut count: u_int,
    mut vals: *mut *mut libc::c_char,
) {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < count {
        printf(
            b"%s %s\n\0" as *const u8 as *const libc::c_char,
            lookup_opcode_name(code),
            *vals.offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn dump_cfg_strarray_oneline(
    mut code: OpCodes,
    mut count: u_int,
    mut vals: *mut *mut libc::c_char,
) {
    let mut i: u_int = 0;
    printf(
        b"%s\0" as *const u8 as *const libc::c_char,
        lookup_opcode_name(code),
    );
    if count == 0 as libc::c_int as libc::c_uint {
        printf(b" none\0" as *const u8 as *const libc::c_char);
    }
    i = 0 as libc::c_int as u_int;
    while i < count {
        printf(
            b" %s\0" as *const u8 as *const libc::c_char,
            *vals.offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
    printf(b"\n\0" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn dump_cfg_forwards(
    mut code: OpCodes,
    mut count: u_int,
    mut fwds: *const Forward,
) {
    let mut fwd: *const Forward = 0 as *const Forward;
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < count {
        fwd = &*fwds.offset(i as isize) as *const Forward;
        if !(code as libc::c_uint == oDynamicForward as libc::c_int as libc::c_uint
            && !((*fwd).connect_host).is_null()
            && libc::strcmp(
                (*fwd).connect_host,
                b"socks\0" as *const u8 as *const libc::c_char,
            ) != 0 as libc::c_int)
        {
            if !(code as libc::c_uint == oLocalForward as libc::c_int as libc::c_uint
                && !((*fwd).connect_host).is_null()
                && libc::strcmp(
                    (*fwd).connect_host,
                    b"socks\0" as *const u8 as *const libc::c_char,
                ) == 0 as libc::c_int)
            {
                printf(
                    b"%s\0" as *const u8 as *const libc::c_char,
                    lookup_opcode_name(code),
                );
                if (*fwd).listen_port == -(2 as libc::c_int) {
                    printf(
                        b" %s\0" as *const u8 as *const libc::c_char,
                        (*fwd).listen_path,
                    );
                } else if ((*fwd).listen_host).is_null() {
                    printf(
                        b" %d\0" as *const u8 as *const libc::c_char,
                        (*fwd).listen_port,
                    );
                } else {
                    printf(
                        b" [%s]:%d\0" as *const u8 as *const libc::c_char,
                        (*fwd).listen_host,
                        (*fwd).listen_port,
                    );
                }
                if code as libc::c_uint != oDynamicForward as libc::c_int as libc::c_uint {
                    if (*fwd).connect_port == -(2 as libc::c_int) {
                        printf(
                            b" %s\0" as *const u8 as *const libc::c_char,
                            (*fwd).connect_path,
                        );
                    } else if ((*fwd).connect_host).is_null() {
                        printf(
                            b" %d\0" as *const u8 as *const libc::c_char,
                            (*fwd).connect_port,
                        );
                    } else {
                        printf(
                            b" [%s]:%d\0" as *const u8 as *const libc::c_char,
                            (*fwd).connect_host,
                            (*fwd).connect_port,
                        );
                    }
                }
                printf(b"\n\0" as *const u8 as *const libc::c_char);
            }
        }
        i = i.wrapping_add(1);
        i;
    }
}
pub unsafe extern "C" fn dump_client_config(mut o: *mut Options, mut host: *const libc::c_char) {
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut buf: [libc::c_char; 8] = [0; 8];
    let mut all_key: *mut libc::c_char = 0 as *mut libc::c_char;
    all_key = sshkey_alg_list(
        0 as libc::c_int,
        0 as libc::c_int,
        1 as libc::c_int,
        ',' as i32 as libc::c_char,
    );
    r = kex_assemble_names(&mut (*o).hostkeyalgorithms, kex_default_pk_alg(), all_key);
    if r != 0 as libc::c_int {
        sshfatal(
            b"readconf.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"dump_client_config\0"))
                .as_ptr(),
            3276 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"expand HostKeyAlgorithms\0" as *const u8 as *const libc::c_char,
        );
    }
    libc::free(all_key as *mut libc::c_void);
    dump_cfg_string(oHost, (*o).host_arg);
    dump_cfg_string(oUser, (*o).user);
    dump_cfg_string(oHostname, host);
    dump_cfg_int(oPort, (*o).port);
    dump_cfg_fmtint(oAddressFamily, (*o).address_family);
    dump_cfg_fmtint(oBatchMode, (*o).batch_mode);
    dump_cfg_fmtint(oCanonicalizeFallbackLocal, (*o).canonicalize_fallback_local);
    dump_cfg_fmtint(oCanonicalizeHostname, (*o).canonicalize_hostname);
    dump_cfg_fmtint(oCheckHostIP, (*o).check_host_ip);
    dump_cfg_fmtint(oCompression, (*o).compression);
    dump_cfg_fmtint(oControlMaster, (*o).control_master);
    dump_cfg_fmtint(oEnableSSHKeysign, (*o).enable_ssh_keysign);
    dump_cfg_fmtint(oClearAllForwardings, (*o).clear_forwardings);
    dump_cfg_fmtint(oExitOnForwardFailure, (*o).exit_on_forward_failure);
    dump_cfg_fmtint(oFingerprintHash, (*o).fingerprint_hash);
    dump_cfg_fmtint(oForwardX11, (*o).forward_x11);
    dump_cfg_fmtint(oForwardX11Trusted, (*o).forward_x11_trusted);
    dump_cfg_fmtint(oGatewayPorts, (*o).fwd_opts.gateway_ports);
    dump_cfg_fmtint(oHashKnownHosts, (*o).hash_known_hosts);
    dump_cfg_fmtint(oHostbasedAuthentication, (*o).hostbased_authentication);
    dump_cfg_fmtint(oIdentitiesOnly, (*o).identities_only);
    dump_cfg_fmtint(
        oKbdInteractiveAuthentication,
        (*o).kbd_interactive_authentication,
    );
    dump_cfg_fmtint(
        oNoHostAuthenticationForLocalhost,
        (*o).no_host_authentication_for_localhost,
    );
    dump_cfg_fmtint(oPasswordAuthentication, (*o).password_authentication);
    dump_cfg_fmtint(oPermitLocalCommand, (*o).permit_local_command);
    dump_cfg_fmtint(oProxyUseFdpass, (*o).proxy_use_fdpass);
    dump_cfg_fmtint(oPubkeyAuthentication, (*o).pubkey_authentication);
    dump_cfg_fmtint(oRequestTTY, (*o).request_tty);
    dump_cfg_fmtint(oSessionType, (*o).session_type);
    dump_cfg_fmtint(oStdinNull, (*o).stdin_null);
    dump_cfg_fmtint(oForkAfterAuthentication, (*o).fork_after_authentication);
    dump_cfg_fmtint(
        oStreamLocalBindUnlink,
        (*o).fwd_opts.streamlocal_bind_unlink,
    );
    dump_cfg_fmtint(oStrictHostKeyChecking, (*o).strict_host_key_checking);
    dump_cfg_fmtint(oTCPKeepAlive, (*o).tcp_keep_alive);
    dump_cfg_fmtint(oTunnel, (*o).tun_open);
    dump_cfg_fmtint(oVerifyHostKeyDNS, (*o).verify_host_key_dns);
    dump_cfg_fmtint(oVisualHostKey, (*o).visual_host_key);
    dump_cfg_fmtint(oUpdateHostkeys, (*o).update_hostkeys);
    dump_cfg_fmtint(oEnableEscapeCommandline, (*o).enable_escape_commandline);
    dump_cfg_int(oCanonicalizeMaxDots, (*o).canonicalize_max_dots);
    dump_cfg_int(oConnectionAttempts, (*o).connection_attempts);
    dump_cfg_int(oForwardX11Timeout, (*o).forward_x11_timeout);
    dump_cfg_int(oNumberOfPasswordPrompts, (*o).number_of_password_prompts);
    dump_cfg_int(oServerAliveCountMax, (*o).server_alive_count_max);
    dump_cfg_int(oServerAliveInterval, (*o).server_alive_interval);
    dump_cfg_int(oRequiredRSASize, (*o).required_rsa_size);
    dump_cfg_string(oBindAddress, (*o).bind_address);
    dump_cfg_string(oBindInterface, (*o).bind_interface);
    dump_cfg_string(oCiphers, (*o).ciphers);
    dump_cfg_string(oControlPath, (*o).control_path);
    dump_cfg_string(oHostKeyAlgorithms, (*o).hostkeyalgorithms);
    dump_cfg_string(oHostKeyAlias, (*o).host_key_alias);
    dump_cfg_string(oHostbasedAcceptedAlgorithms, (*o).hostbased_accepted_algos);
    dump_cfg_string(oIdentityAgent, (*o).identity_agent);
    dump_cfg_string(oIgnoreUnknown, (*o).ignored_unknown);
    dump_cfg_string(oKbdInteractiveDevices, (*o).kbd_interactive_devices);
    dump_cfg_string(oKexAlgorithms, (*o).kex_algorithms);
    dump_cfg_string(oCASignatureAlgorithms, (*o).ca_sign_algorithms);
    dump_cfg_string(oLocalCommand, (*o).local_command);
    dump_cfg_string(oRemoteCommand, (*o).remote_command);
    dump_cfg_string(oLogLevel, log_level_name((*o).log_level));
    dump_cfg_string(oMacs, (*o).macs);
    dump_cfg_string(oPKCS11Provider, (*o).pkcs11_provider);
    dump_cfg_string(oSecurityKeyProvider, (*o).sk_provider);
    dump_cfg_string(oPreferredAuthentications, (*o).preferred_authentications);
    dump_cfg_string(oPubkeyAcceptedAlgorithms, (*o).pubkey_accepted_algos);
    dump_cfg_string(oRevokedHostKeys, (*o).revoked_host_keys);
    dump_cfg_string(oXAuthLocation, (*o).xauth_location);
    dump_cfg_string(oKnownHostsCommand, (*o).known_hosts_command);
    dump_cfg_forwards(
        oDynamicForward,
        (*o).num_local_forwards as u_int,
        (*o).local_forwards,
    );
    dump_cfg_forwards(
        oLocalForward,
        (*o).num_local_forwards as u_int,
        (*o).local_forwards,
    );
    dump_cfg_forwards(
        oRemoteForward,
        (*o).num_remote_forwards as u_int,
        (*o).remote_forwards,
    );
    dump_cfg_strarray(
        oIdentityFile,
        (*o).num_identity_files as u_int,
        ((*o).identity_files).as_mut_ptr(),
    );
    dump_cfg_strarray_oneline(
        oCanonicalDomains,
        (*o).num_canonical_domains as u_int,
        ((*o).canonical_domains).as_mut_ptr(),
    );
    dump_cfg_strarray(
        oCertificateFile,
        (*o).num_certificate_files as u_int,
        ((*o).certificate_files).as_mut_ptr(),
    );
    dump_cfg_strarray_oneline(
        oGlobalKnownHostsFile,
        (*o).num_system_hostfiles,
        ((*o).system_hostfiles).as_mut_ptr(),
    );
    dump_cfg_strarray_oneline(
        oUserKnownHostsFile,
        (*o).num_user_hostfiles,
        ((*o).user_hostfiles).as_mut_ptr(),
    );
    dump_cfg_strarray(oSendEnv, (*o).num_send_env, (*o).send_env);
    dump_cfg_strarray(oSetEnv, (*o).num_setenv, (*o).setenv);
    dump_cfg_strarray_oneline(oLogVerbose, (*o).num_log_verbose, (*o).log_verbose);
    if (*o).num_permitted_remote_opens == 0 as libc::c_int as libc::c_uint {
        printf(
            b"%s any\n\0" as *const u8 as *const libc::c_char,
            lookup_opcode_name(oPermitRemoteOpen),
        );
    } else {
        dump_cfg_strarray_oneline(
            oPermitRemoteOpen,
            (*o).num_permitted_remote_opens,
            (*o).permitted_remote_opens,
        );
    }
    if (*o).add_keys_to_agent_lifespan <= 0 as libc::c_int {
        dump_cfg_fmtint(oAddKeysToAgent, (*o).add_keys_to_agent);
    } else {
        printf(
            b"addkeystoagent%s %d\n\0" as *const u8 as *const libc::c_char,
            if (*o).add_keys_to_agent == 3 as libc::c_int {
                b" confirm\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            (*o).add_keys_to_agent_lifespan,
        );
    }
    if ((*o).forward_agent_sock_path).is_null() {
        dump_cfg_fmtint(oForwardAgent, (*o).forward_agent);
    } else {
        dump_cfg_string(oForwardAgent, (*o).forward_agent_sock_path);
    }
    if (*o).connection_timeout == -(1 as libc::c_int) {
        printf(b"connecttimeout none\n\0" as *const u8 as *const libc::c_char);
    } else {
        dump_cfg_int(oConnectTimeout, (*o).connection_timeout);
    }
    printf(b"tunneldevice\0" as *const u8 as *const libc::c_char);
    if (*o).tun_local == 0x7fffffff as libc::c_int {
        printf(b" any\0" as *const u8 as *const libc::c_char);
    } else {
        printf(b" %d\0" as *const u8 as *const libc::c_char, (*o).tun_local);
    }
    if (*o).tun_remote == 0x7fffffff as libc::c_int {
        printf(b":any\0" as *const u8 as *const libc::c_char);
    } else {
        printf(
            b":%d\0" as *const u8 as *const libc::c_char,
            (*o).tun_remote,
        );
    }
    printf(b"\n\0" as *const u8 as *const libc::c_char);
    printf(b"canonicalizePermittedcnames\0" as *const u8 as *const libc::c_char);
    if (*o).num_permitted_cnames == 0 as libc::c_int {
        printf(b" none\0" as *const u8 as *const libc::c_char);
    }
    i = 0 as libc::c_int;
    while i < (*o).num_permitted_cnames {
        printf(
            b" %s:%s\0" as *const u8 as *const libc::c_char,
            (*o).permitted_cnames[i as usize].source_list,
            (*o).permitted_cnames[i as usize].target_list,
        );
        i += 1;
        i;
    }
    printf(b"\n\0" as *const u8 as *const libc::c_char);
    if (*o).control_persist == 0 as libc::c_int || (*o).control_persist_timeout == 0 as libc::c_int
    {
        dump_cfg_fmtint(oControlPersist, (*o).control_persist);
    } else {
        dump_cfg_int(oControlPersist, (*o).control_persist_timeout);
    }
    if (*o).escape_char == -(2 as libc::c_int) {
        printf(b"escapechar none\n\0" as *const u8 as *const libc::c_char);
    } else {
        vis(
            buf.as_mut_ptr(),
            (*o).escape_char,
            0x4 as libc::c_int | 0x8 as libc::c_int | 0x10 as libc::c_int,
            0 as libc::c_int,
        );
        printf(
            b"escapechar %s\n\0" as *const u8 as *const libc::c_char,
            buf.as_mut_ptr(),
        );
    }
    printf(
        b"ipqos %s \0" as *const u8 as *const libc::c_char,
        iptos2str((*o).ip_qos_interactive),
    );
    printf(
        b"%s\n\0" as *const u8 as *const libc::c_char,
        iptos2str((*o).ip_qos_bulk),
    );
    printf(
        b"rekeylimit %llu %d\n\0" as *const u8 as *const libc::c_char,
        (*o).rekey_limit as libc::c_ulonglong,
        (*o).rekey_interval,
    );
    printf(
        b"streamlocalbindmask 0%o\n\0" as *const u8 as *const libc::c_char,
        (*o).fwd_opts.streamlocal_bind_mask,
    );
    printf(
        b"syslogfacility %s\n\0" as *const u8 as *const libc::c_char,
        log_facility_name((*o).log_facility),
    );
    if ((*o).jump_host).is_null() {
        dump_cfg_string(oProxyCommand, (*o).proxy_command);
    } else {
        i = (!(libc::strchr((*o).jump_host, ':' as i32)).is_null()
            || strspn(
                (*o).jump_host,
                b"1234567890.\0" as *const u8 as *const libc::c_char,
            ) == strlen((*o).jump_host)) as libc::c_int;
        libc::snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 8]>() as usize,
            b"%d\0" as *const u8 as *const libc::c_char,
            (*o).jump_port,
        );
        printf(
            b"proxyjump %s%s%s%s%s%s%s%s%s\n\0" as *const u8 as *const libc::c_char,
            if ((*o).jump_extra).is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                (*o).jump_extra as *const libc::c_char
            },
            if ((*o).jump_extra).is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b",\0" as *const u8 as *const libc::c_char
            },
            if ((*o).jump_user).is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                (*o).jump_user as *const libc::c_char
            },
            if ((*o).jump_user).is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b"@\0" as *const u8 as *const libc::c_char
            },
            if i != 0 {
                b"[\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            (*o).jump_host,
            if i != 0 {
                b"]\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
            if (*o).jump_port <= 0 as libc::c_int {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b":\0" as *const u8 as *const libc::c_char
            },
            if (*o).jump_port <= 0 as libc::c_int {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                buf.as_mut_ptr() as *const libc::c_char
            },
        );
    };
}
