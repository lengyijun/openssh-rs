use crate::atomicio::atomicio;
use ::libc;
use libc::close;

extern "C" {
    pub type ssh_channels;

    pub type ec_key_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_group_st;
    pub type dh_st;
    pub type umac_ctx;
    pub type ssh_hmac_ctx;
    pub type sshcipher;
    pub type session_state;
    pub type bignum_st;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;

    fn dup(__fd: libc::c_int) -> libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn dh_new_group(_: *mut BIGNUM, _: *mut BIGNUM) -> *mut DH;

    fn sshbuf_reset(buf: *mut crate::sshbuf::sshbuf);

    fn sshbuf_mutable_ptr(buf: *const crate::sshbuf::sshbuf) -> *mut u_char;
    fn sshbuf_reserve(
        buf: *mut crate::sshbuf::sshbuf,
        len: size_t,
        dpp: *mut *mut u_char,
    ) -> libc::c_int;
    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut crate::sshbuf::sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut crate::sshbuf::sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut crate::sshbuf::sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_get_string(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_string(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut crate::sshbuf::sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_get_string_direct(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_bignum2(buf: *mut crate::sshbuf::sshbuf, valp: *mut *mut BIGNUM) -> libc::c_int;
    fn sshkey_puts(_: *const sshkey, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshauthopt_free(opts: *mut sshauthopt);
    fn sshauthopt_deserialise(
        m: *mut crate::sshbuf::sshbuf,
        opts: *mut *mut sshauthopt,
    ) -> libc::c_int;
    fn ssh_packet_get_state(_: *mut ssh, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn log_change_level(_: LogLevel) -> libc::c_int;
    fn log_verbose_add(_: *const libc::c_char);
    fn log_verbose_reset();
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

    fn mm_receive_fd(_: libc::c_int) -> libc::c_int;
    fn process_permitopen(ssh: *mut ssh, options_0: *mut ServerOptions);
    fn process_channel_timeouts(ssh: *mut ssh, _: *mut ServerOptions);
    fn copy_set_server_options(_: *mut ServerOptions, _: *mut ServerOptions, _: libc::c_int);
    static mut pmonitor: *mut monitor;
    static mut loginmsg: *mut crate::sshbuf::sshbuf;
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
pub type __pid_t = libc::c_int;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type pid_t = __pid_t;
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
    pub sk_key_handle: *mut crate::sshbuf::sshbuf,
    pub sk_reserved: *mut crate::sshbuf::sshbuf,
    pub cert: *mut sshkey_cert,
    pub shielded_private: *mut u_char,
    pub shielded_len: size_t,
    pub shield_prekey: *mut u_char,
    pub shield_prekey_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_cert {
    pub certblob: *mut crate::sshbuf::sshbuf,
    pub type_0: u_int,
    pub serial: u_int64_t,
    pub key_id: *mut libc::c_char,
    pub nprincipals: u_int,
    pub principals: *mut *mut libc::c_char,
    pub valid_after: u_int64_t,
    pub valid_before: u_int64_t,
    pub critical: *mut crate::sshbuf::sshbuf,
    pub extensions: *mut crate::sshbuf::sshbuf,
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
    pub initial_hostkey: *mut sshkey,
    pub done: sig_atomic_t,
    pub flags: u_int,
    pub hash_alg: libc::c_int,
    pub ec_nid: libc::c_int,
    pub failed_choice: *mut libc::c_char,
    pub verify_host_key: Option<unsafe extern "C" fn(*mut sshkey, *mut ssh) -> libc::c_int>,
    pub load_host_public_key:
        Option<unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut sshkey>,
    pub load_host_private_key:
        Option<unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut sshkey>,
    pub host_key_index:
        Option<unsafe extern "C" fn(*mut sshkey, libc::c_int, *mut ssh) -> libc::c_int>,
    pub sign: Option<
        unsafe extern "C" fn(
            *mut ssh,
            *mut sshkey,
            *mut sshkey,
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
    pub ec_client_key: *mut EC_KEY,
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
pub struct sshenc {
    pub name: *mut libc::c_char,
    pub cipher: *const sshcipher,
    pub enabled: libc::c_int,
    pub key_len: u_int,
    pub iv_len: u_int,
    pub block_size: u_int,
    pub key: *mut u_char,
    pub iv: *mut u_char,
}
pub type BIGNUM = bignum_st;
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
    pub prev_keys: *mut *mut sshkey,
    pub nprev_keys: u_int,
    pub auth_method_key: *mut sshkey,
    pub auth_method_info: *mut libc::c_char,
    pub session_info: *mut crate::sshbuf::sshbuf,
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
pub type mm_keytype = libc::c_uint;
pub const MM_USERKEY: mm_keytype = 2;
pub const MM_HOSTKEY: mm_keytype = 1;
pub const MM_NOKEY: mm_keytype = 0;
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
pub struct ForwardOptions {
    pub gateway_ports: libc::c_int,
    pub streamlocal_bind_mask: mode_t,
    pub streamlocal_bind_unlink: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct listenaddr {
    pub rdomain: *mut libc::c_char,
    pub addrs: *mut addrinfo,
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
    pub env: *mut C2RustUnnamed_2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub name: *mut libc::c_char,
    pub val: *mut libc::c_char,
}
pub unsafe extern "C" fn mm_log_handler(
    mut level: LogLevel,
    mut forced: libc::c_int,
    mut msg: *const libc::c_char,
    mut ctx: *mut libc::c_void,
) {
    let mut log_msg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut mon: *mut monitor = ctx as *mut monitor;
    let mut r: libc::c_int = 0;
    let mut len: size_t = 0;
    if (*mon).m_log_sendfd == -(1 as libc::c_int) {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_log_handler\0"))
                .as_ptr(),
            93 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no log channel\0" as *const u8 as *const libc::c_char,
        );
    }
    log_msg = crate::sshbuf::sshbuf_new();
    if log_msg.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_log_handler\0"))
                .as_ptr(),
            96 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(log_msg, 0 as libc::c_int as u_int32_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(log_msg, level as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(log_msg, forced as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(log_msg, msg);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_log_handler\0"))
                .as_ptr(),
            102 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    len = crate::sshbuf::sshbuf_len(log_msg);
    if len < 4 as libc::c_int as libc::c_ulong || len > 0xffffffff as libc::c_uint as libc::c_ulong
    {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_log_handler\0"))
                .as_ptr(),
            104 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"bad length %zu\0" as *const u8 as *const libc::c_char,
            len,
        );
    }
    let __v: u_int32_t = len.wrapping_sub(4 as libc::c_int as libc::c_ulong) as u_int32_t;
    *(sshbuf_mutable_ptr(log_msg)).offset(0 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *(sshbuf_mutable_ptr(log_msg)).offset(1 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *(sshbuf_mutable_ptr(log_msg)).offset(2 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *(sshbuf_mutable_ptr(log_msg)).offset(3 as libc::c_int as isize) =
        (__v & 0xff as libc::c_int as libc::c_uint) as u_char;
    if atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        (*mon).m_log_sendfd,
        sshbuf_mutable_ptr(log_msg) as *mut libc::c_void,
        len,
    ) != len
    {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_log_handler\0"))
                .as_ptr(),
            108 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"write: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    crate::sshbuf::sshbuf_free(log_msg);
}
pub unsafe extern "C" fn mm_is_monitor() -> libc::c_int {
    return (!pmonitor.is_null() && (*pmonitor).m_pid > 0 as libc::c_int) as libc::c_int;
}
pub unsafe extern "C" fn mm_request_send(
    mut sock: libc::c_int,
    mut type_0: monitor_reqtype,
    mut m: *mut crate::sshbuf::sshbuf,
) {
    let mut mlen: size_t = crate::sshbuf::sshbuf_len(m);
    let mut buf: [u_char; 5] = [0; 5];
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_request_send\0")).as_ptr(),
        128 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering, type %d\0" as *const u8 as *const libc::c_char,
        type_0 as libc::c_uint,
    );
    if mlen >= 0xffffffff as libc::c_uint as libc::c_ulong {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_request_send\0"))
                .as_ptr(),
            131 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"bad length %zu\0" as *const u8 as *const libc::c_char,
            mlen,
        );
    }
    let __v: u_int32_t = mlen.wrapping_add(1 as libc::c_int as libc::c_ulong) as u_int32_t;
    *buf.as_mut_ptr().offset(0 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *buf.as_mut_ptr().offset(1 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *buf.as_mut_ptr().offset(2 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *buf.as_mut_ptr().offset(3 as libc::c_int as isize) =
        (__v & 0xff as libc::c_int as libc::c_uint) as u_char;
    buf[4 as libc::c_int as usize] = type_0 as u_char;
    if atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        sock,
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 5]>() as libc::c_ulong,
    ) != ::core::mem::size_of::<[u_char; 5]>() as libc::c_ulong
    {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_request_send\0"))
                .as_ptr(),
            135 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"write: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    if atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        sock,
        sshbuf_mutable_ptr(m) as *mut libc::c_void,
        mlen,
    ) != mlen
    {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_request_send\0"))
                .as_ptr(),
            137 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"write: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
}
pub unsafe extern "C" fn mm_request_receive(
    mut sock: libc::c_int,
    mut m: *mut crate::sshbuf::sshbuf,
) {
    let mut buf: [u_char; 4] = [0; 4];
    let mut p: *mut u_char = 0 as *mut u_char;
    let mut msg_len: u_int = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_request_receive\0"))
            .as_ptr(),
        147 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    if atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        sock,
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 4]>() as libc::c_ulong,
    ) != ::core::mem::size_of::<[u_char; 4]>() as libc::c_ulong
    {
        if *libc::__errno_location() == 32 as libc::c_int {
            cleanup_exit(255 as libc::c_int);
        }
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_request_receive\0"))
                .as_ptr(),
            152 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"read: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    msg_len = (*(buf.as_mut_ptr() as *const u_char).offset(0 as libc::c_int as isize) as u_int32_t)
        << 24 as libc::c_int
        | (*(buf.as_mut_ptr() as *const u_char).offset(1 as libc::c_int as isize) as u_int32_t)
            << 16 as libc::c_int
        | (*(buf.as_mut_ptr() as *const u_char).offset(2 as libc::c_int as isize) as u_int32_t)
            << 8 as libc::c_int
        | *(buf.as_mut_ptr() as *const u_char).offset(3 as libc::c_int as isize) as u_int32_t;
    if msg_len > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_uint {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_request_receive\0"))
                .as_ptr(),
            156 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"read: bad msg_len %d\0" as *const u8 as *const libc::c_char,
            msg_len,
        );
    }
    sshbuf_reset(m);
    r = sshbuf_reserve(m, msg_len as size_t, &mut p);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_request_receive\0"))
                .as_ptr(),
            159 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"reserve\0" as *const u8 as *const libc::c_char,
        );
    }
    if atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        sock,
        p as *mut libc::c_void,
        msg_len as size_t,
    ) != msg_len as libc::c_ulong
    {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_request_receive\0"))
                .as_ptr(),
            161 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"read: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
}
pub unsafe extern "C" fn mm_request_receive_expect(
    mut sock: libc::c_int,
    mut type_0: monitor_reqtype,
    mut m: *mut crate::sshbuf::sshbuf,
) {
    let mut rtype: u_char = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"mm_request_receive_expect\0"))
            .as_ptr(),
        170 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering, type %d\0" as *const u8 as *const libc::c_char,
        type_0 as libc::c_uint,
    );
    mm_request_receive(sock, m);
    r = sshbuf_get_u8(m, &mut rtype);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"mm_request_receive_expect\0",
            ))
            .as_ptr(),
            174 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if rtype as libc::c_uint != type_0 as libc::c_uint {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"mm_request_receive_expect\0",
            ))
            .as_ptr(),
            176 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"read: rtype %d != type %d\0" as *const u8 as *const libc::c_char,
            rtype as libc::c_int,
            type_0 as libc::c_uint,
        );
    }
}
pub unsafe extern "C" fn mm_choose_dh(
    mut min: libc::c_int,
    mut nbits: libc::c_int,
    mut max: libc::c_int,
) -> *mut DH {
    let mut p: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut g: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut r: libc::c_int = 0;
    let mut success: u_char = 0 as libc::c_int as u_char;
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"mm_choose_dh\0")).as_ptr(),
            189 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, min as u_int32_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(m, nbits as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(m, max as u_int32_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"mm_choose_dh\0")).as_ptr(),
            193 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_MODULI, m);
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"mm_choose_dh\0")).as_ptr(),
        197 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"waiting for MONITOR_ANS_MODULI\0" as *const u8 as *const libc::c_char,
    );
    mm_request_receive_expect((*pmonitor).m_recvfd, MONITOR_ANS_MODULI, m);
    r = sshbuf_get_u8(m, &mut success);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"mm_choose_dh\0")).as_ptr(),
            201 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse success\0" as *const u8 as *const libc::c_char,
        );
    }
    if success as libc::c_int == 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"mm_choose_dh\0")).as_ptr(),
            203 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"MONITOR_ANS_MODULI failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_get_bignum2(m, &mut p);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_bignum2(m, &mut g);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"mm_choose_dh\0")).as_ptr(),
            207 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse group\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"mm_choose_dh\0")).as_ptr(),
        209 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"remaining %zu\0" as *const u8 as *const libc::c_char,
        crate::sshbuf::sshbuf_len(m),
    );
    crate::sshbuf::sshbuf_free(m);
    return dh_new_group(g, p);
}
pub unsafe extern "C" fn mm_sshkey_sign(
    mut ssh: *mut ssh,
    mut key: *mut sshkey,
    mut sigp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut data: *const u_char,
    mut datalen: size_t,
    mut hostkey_alg: *const libc::c_char,
    mut _sk_provider: *const libc::c_char,
    mut _sk_pin: *const libc::c_char,
    mut compat: u_int,
) -> libc::c_int {
    let mut kex: *mut kex = *(*pmonitor).m_pkex;
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut ndx: u_int =
        ((*kex).host_key_index).expect("non-null function pointer")(key, 0 as libc::c_int, ssh)
            as u_int;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_sshkey_sign\0")).as_ptr(),
        226 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_sshkey_sign\0"))
                .as_ptr(),
            228 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, ndx);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_string(m, data as *const libc::c_void, datalen);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(m, hostkey_alg);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(m, compat);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_sshkey_sign\0"))
                .as_ptr(),
            233 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_SIGN, m);
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_sshkey_sign\0")).as_ptr(),
        237 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"waiting for MONITOR_ANS_SIGN\0" as *const u8 as *const libc::c_char,
    );
    mm_request_receive_expect((*pmonitor).m_recvfd, MONITOR_ANS_SIGN, m);
    r = sshbuf_get_string(m, sigp, lenp);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_sshkey_sign\0"))
                .as_ptr(),
            240 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_free(m);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn mm_getpwnamallow(
    mut ssh: *mut ssh,
    mut username: *const libc::c_char,
) -> *mut libc::passwd {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut pw: *mut libc::passwd = 0 as *mut libc::passwd;
    let mut len: size_t = 0;
    let mut i: u_int = 0;
    let mut newopts: *mut ServerOptions = 0 as *mut ServerOptions;
    let mut r: libc::c_int = 0;
    let mut ok: u_char = 0;
    let mut p: *const u_char = 0 as *const u_char;
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0")).as_ptr(),
        267 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            270 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshbuf_put_cstring(m, username);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            272 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_PWNAM, m);
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0")).as_ptr(),
        276 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"waiting for MONITOR_ANS_PWNAM\0" as *const u8 as *const libc::c_char,
    );
    mm_request_receive_expect((*pmonitor).m_recvfd, MONITOR_ANS_PWNAM, m);
    r = sshbuf_get_u8(m, &mut ok);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            280 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse success\0" as *const u8 as *const libc::c_char,
        );
    }
    if ok as libc::c_int == 0 as libc::c_int {
        pw = 0 as *mut libc::passwd;
    } else {
        pw = crate::xmalloc::xcalloc(
            ::core::mem::size_of::<libc::passwd>() as libc::c_ulong,
            1 as libc::c_int as size_t,
        ) as *mut libc::passwd;
        r = sshbuf_get_string_direct(m, &mut p, &mut len);
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                288 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse pw %s\0" as *const u8 as *const libc::c_char,
                b"pw_uid\0" as *const u8 as *const libc::c_char,
            );
        }
        if len != ::core::mem::size_of::<__uid_t>() as libc::c_ulong {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                288 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"bad length for %s\0" as *const u8 as *const libc::c_char,
                b"pw_uid\0" as *const u8 as *const libc::c_char,
            );
        }
        memcpy(
            &mut (*pw).pw_uid as *mut __uid_t as *mut libc::c_void,
            p as *const libc::c_void,
            len,
        );
        r = sshbuf_get_string_direct(m, &mut p, &mut len);
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                289 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse pw %s\0" as *const u8 as *const libc::c_char,
                b"pw_gid\0" as *const u8 as *const libc::c_char,
            );
        }
        if len != ::core::mem::size_of::<__gid_t>() as libc::c_ulong {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                289 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"bad length for %s\0" as *const u8 as *const libc::c_char,
                b"pw_gid\0" as *const u8 as *const libc::c_char,
            );
        }
        memcpy(
            &mut (*pw).pw_gid as *mut __gid_t as *mut libc::c_void,
            p as *const libc::c_void,
            len,
        );
        r = sshbuf_get_cstring(m, &mut (*pw).pw_name, 0 as *mut size_t);
        if r != 0 as libc::c_int
            || {
                r = sshbuf_get_cstring(m, &mut (*pw).pw_passwd, 0 as *mut size_t);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_get_cstring(m, &mut (*pw).pw_gecos, 0 as *mut size_t);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_get_cstring(m, &mut (*pw).pw_dir, 0 as *mut size_t);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_get_cstring(m, &mut (*pw).pw_shell, 0 as *mut size_t);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                306 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse pw\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    r = sshbuf_get_string_direct(m, &mut p, &mut len);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            311 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse opts\0" as *const u8 as *const libc::c_char,
        );
    }
    if len != ::core::mem::size_of::<ServerOptions>() as libc::c_ulong {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            313 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"option block size mismatch\0" as *const u8 as *const libc::c_char,
        );
    }
    newopts = crate::xmalloc::xcalloc(
        ::core::mem::size_of::<ServerOptions>() as libc::c_ulong,
        1 as libc::c_int as size_t,
    ) as *mut ServerOptions;
    memcpy(
        newopts as *mut libc::c_void,
        p as *const libc::c_void,
        ::core::mem::size_of::<ServerOptions>() as libc::c_ulong,
    );
    if !((*newopts).banner).is_null() && {
        r = sshbuf_get_cstring(m, &mut (*newopts).banner, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"banner\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*newopts).trusted_user_ca_keys).is_null() && {
        r = sshbuf_get_cstring(m, &mut (*newopts).trusted_user_ca_keys, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"trusted_user_ca_keys\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*newopts).revoked_keys_file).is_null() && {
        r = sshbuf_get_cstring(m, &mut (*newopts).revoked_keys_file, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"revoked_keys_file\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*newopts).authorized_keys_command).is_null() && {
        r = sshbuf_get_cstring(m, &mut (*newopts).authorized_keys_command, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"authorized_keys_command\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*newopts).authorized_keys_command_user).is_null() && {
        r = sshbuf_get_cstring(
            m,
            &mut (*newopts).authorized_keys_command_user,
            0 as *mut size_t,
        );
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"authorized_keys_command_user\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*newopts).authorized_principals_file).is_null() && {
        r = sshbuf_get_cstring(
            m,
            &mut (*newopts).authorized_principals_file,
            0 as *mut size_t,
        );
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"authorized_principals_file\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*newopts).authorized_principals_command).is_null() && {
        r = sshbuf_get_cstring(
            m,
            &mut (*newopts).authorized_principals_command,
            0 as *mut size_t,
        );
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"authorized_principals_command\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*newopts).authorized_principals_command_user).is_null() && {
        r = sshbuf_get_cstring(
            m,
            &mut (*newopts).authorized_principals_command_user,
            0 as *mut size_t,
        );
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"authorized_principals_command_user\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*newopts).hostbased_accepted_algos).is_null() && {
        r = sshbuf_get_cstring(
            m,
            &mut (*newopts).hostbased_accepted_algos,
            0 as *mut size_t,
        );
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"hostbased_accepted_algos\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*newopts).pubkey_accepted_algos).is_null() && {
        r = sshbuf_get_cstring(m, &mut (*newopts).pubkey_accepted_algos, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"pubkey_accepted_algos\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*newopts).ca_sign_algorithms).is_null() && {
        r = sshbuf_get_cstring(m, &mut (*newopts).ca_sign_algorithms, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"ca_sign_algorithms\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*newopts).routing_domain).is_null() && {
        r = sshbuf_get_cstring(m, &mut (*newopts).routing_domain, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"routing_domain\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*newopts).permit_user_env_allowlist).is_null() && {
        r = sshbuf_get_cstring(
            m,
            &mut (*newopts).permit_user_env_allowlist,
            0 as *mut size_t,
        );
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                .as_ptr(),
            332 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse %s\0" as *const u8 as *const libc::c_char,
            b"permit_user_env_allowlist\0" as *const u8 as *const libc::c_char,
        );
    }
    (*newopts).authorized_keys_files =
        (if (*newopts).num_authkeys_files == 0 as libc::c_int as libc::c_uint {
            0 as *mut libc::c_void
        } else {
            crate::xmalloc::xcalloc(
                (*newopts).num_authkeys_files as size_t,
                ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
            )
        }) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*newopts).num_authkeys_files {
        r = sshbuf_get_cstring(
            m,
            &mut *((*newopts).authorized_keys_files).offset(i as isize),
            0 as *mut size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                332 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s\0" as *const u8 as *const libc::c_char,
                b"authorized_keys_files\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    (*newopts).allow_users = (if (*newopts).num_allow_users == 0 as libc::c_int as libc::c_uint {
        0 as *mut libc::c_void
    } else {
        crate::xmalloc::xcalloc(
            (*newopts).num_allow_users as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        )
    }) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*newopts).num_allow_users {
        r = sshbuf_get_cstring(
            m,
            &mut *((*newopts).allow_users).offset(i as isize),
            0 as *mut size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                332 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s\0" as *const u8 as *const libc::c_char,
                b"allow_users\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    (*newopts).deny_users = (if (*newopts).num_deny_users == 0 as libc::c_int as libc::c_uint {
        0 as *mut libc::c_void
    } else {
        crate::xmalloc::xcalloc(
            (*newopts).num_deny_users as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        )
    }) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*newopts).num_deny_users {
        r = sshbuf_get_cstring(
            m,
            &mut *((*newopts).deny_users).offset(i as isize),
            0 as *mut size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                332 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s\0" as *const u8 as *const libc::c_char,
                b"deny_users\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    (*newopts).allow_groups = (if (*newopts).num_allow_groups == 0 as libc::c_int as libc::c_uint {
        0 as *mut libc::c_void
    } else {
        crate::xmalloc::xcalloc(
            (*newopts).num_allow_groups as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        )
    }) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*newopts).num_allow_groups {
        r = sshbuf_get_cstring(
            m,
            &mut *((*newopts).allow_groups).offset(i as isize),
            0 as *mut size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                332 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s\0" as *const u8 as *const libc::c_char,
                b"allow_groups\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    (*newopts).deny_groups = (if (*newopts).num_deny_groups == 0 as libc::c_int as libc::c_uint {
        0 as *mut libc::c_void
    } else {
        crate::xmalloc::xcalloc(
            (*newopts).num_deny_groups as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        )
    }) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*newopts).num_deny_groups {
        r = sshbuf_get_cstring(
            m,
            &mut *((*newopts).deny_groups).offset(i as isize),
            0 as *mut size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                332 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s\0" as *const u8 as *const libc::c_char,
                b"deny_groups\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    (*newopts).accept_env = (if (*newopts).num_accept_env == 0 as libc::c_int as libc::c_uint {
        0 as *mut libc::c_void
    } else {
        crate::xmalloc::xcalloc(
            (*newopts).num_accept_env as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        )
    }) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*newopts).num_accept_env {
        r = sshbuf_get_cstring(
            m,
            &mut *((*newopts).accept_env).offset(i as isize),
            0 as *mut size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                332 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s\0" as *const u8 as *const libc::c_char,
                b"accept_env\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    (*newopts).setenv = (if (*newopts).num_setenv == 0 as libc::c_int as libc::c_uint {
        0 as *mut libc::c_void
    } else {
        crate::xmalloc::xcalloc(
            (*newopts).num_setenv as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        )
    }) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*newopts).num_setenv {
        r = sshbuf_get_cstring(
            m,
            &mut *((*newopts).setenv).offset(i as isize),
            0 as *mut size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                332 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s\0" as *const u8 as *const libc::c_char,
                b"setenv\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    (*newopts).auth_methods = (if (*newopts).num_auth_methods == 0 as libc::c_int as libc::c_uint {
        0 as *mut libc::c_void
    } else {
        crate::xmalloc::xcalloc(
            (*newopts).num_auth_methods as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        )
    }) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*newopts).num_auth_methods {
        r = sshbuf_get_cstring(
            m,
            &mut *((*newopts).auth_methods).offset(i as isize),
            0 as *mut size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                332 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s\0" as *const u8 as *const libc::c_char,
                b"auth_methods\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    (*newopts).permitted_opens =
        (if (*newopts).num_permitted_opens == 0 as libc::c_int as libc::c_uint {
            0 as *mut libc::c_void
        } else {
            crate::xmalloc::xcalloc(
                (*newopts).num_permitted_opens as size_t,
                ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
            )
        }) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*newopts).num_permitted_opens {
        r = sshbuf_get_cstring(
            m,
            &mut *((*newopts).permitted_opens).offset(i as isize),
            0 as *mut size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                332 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s\0" as *const u8 as *const libc::c_char,
                b"permitted_opens\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    (*newopts).permitted_listens =
        (if (*newopts).num_permitted_listens == 0 as libc::c_int as libc::c_uint {
            0 as *mut libc::c_void
        } else {
            crate::xmalloc::xcalloc(
                (*newopts).num_permitted_listens as size_t,
                ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
            )
        }) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*newopts).num_permitted_listens {
        r = sshbuf_get_cstring(
            m,
            &mut *((*newopts).permitted_listens).offset(i as isize),
            0 as *mut size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                332 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s\0" as *const u8 as *const libc::c_char,
                b"permitted_listens\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    (*newopts).channel_timeouts =
        (if (*newopts).num_channel_timeouts == 0 as libc::c_int as libc::c_uint {
            0 as *mut libc::c_void
        } else {
            crate::xmalloc::xcalloc(
                (*newopts).num_channel_timeouts as size_t,
                ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
            )
        }) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*newopts).num_channel_timeouts {
        r = sshbuf_get_cstring(
            m,
            &mut *((*newopts).channel_timeouts).offset(i as isize),
            0 as *mut size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                332 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s\0" as *const u8 as *const libc::c_char,
                b"channel_timeouts\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    (*newopts).log_verbose = (if (*newopts).num_log_verbose == 0 as libc::c_int as libc::c_uint {
        0 as *mut libc::c_void
    } else {
        crate::xmalloc::xcalloc(
            (*newopts).num_log_verbose as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        )
    }) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*newopts).num_log_verbose {
        r = sshbuf_get_cstring(
            m,
            &mut *((*newopts).log_verbose).offset(i as isize),
            0 as *mut size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_getpwnamallow\0"))
                    .as_ptr(),
                332 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse %s\0" as *const u8 as *const libc::c_char,
                b"log_verbose\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    copy_set_server_options(&mut options, newopts, 1 as libc::c_int);
    log_change_level(options.log_level);
    log_verbose_reset();
    i = 0 as libc::c_int as u_int;
    while i < options.num_log_verbose {
        log_verbose_add(*(options.log_verbose).offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    process_permitopen(ssh, &mut options);
    process_channel_timeouts(ssh, &mut options);
    libc::free(newopts as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(m);
    return pw;
}
pub unsafe extern "C" fn mm_auth2_read_banner() -> *mut libc::c_char {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut banner: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_auth2_read_banner\0"))
            .as_ptr(),
        357 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_auth2_read_banner\0"))
                .as_ptr(),
            360 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_AUTH2_READ_BANNER, m);
    sshbuf_reset(m);
    mm_request_receive_expect((*pmonitor).m_recvfd, MONITOR_ANS_AUTH2_READ_BANNER, m);
    r = sshbuf_get_cstring(m, &mut banner, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"mm_auth2_read_banner\0"))
                .as_ptr(),
            367 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_free(m);
    if strlen(banner) == 0 as libc::c_int as libc::c_ulong {
        libc::free(banner as *mut libc::c_void);
        banner = 0 as *mut libc::c_char;
    }
    return banner;
}
pub unsafe extern "C" fn mm_inform_authserv(
    mut service: *mut libc::c_char,
    mut style: *mut libc::c_char,
) {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_inform_authserv\0"))
            .as_ptr(),
        386 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_inform_authserv\0"))
                .as_ptr(),
            389 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshbuf_put_cstring(m, service);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_cstring(
            m,
            if !style.is_null() {
                style as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
        );
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_inform_authserv\0"))
                .as_ptr(),
            392 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_AUTHSERV, m);
    crate::sshbuf::sshbuf_free(m);
}
pub unsafe extern "C" fn mm_auth_password(
    mut _ssh: *mut ssh,
    mut password: *mut libc::c_char,
) -> libc::c_int {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    let mut authenticated: libc::c_int = 0 as libc::c_int;
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_auth_password\0")).as_ptr(),
        409 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_auth_password\0"))
                .as_ptr(),
            412 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshbuf_put_cstring(m, password);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_auth_password\0"))
                .as_ptr(),
            414 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_AUTHPASSWORD, m);
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_auth_password\0")).as_ptr(),
        417 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"waiting for MONITOR_ANS_AUTHPASSWORD\0" as *const u8 as *const libc::c_char,
    );
    mm_request_receive_expect((*pmonitor).m_recvfd, MONITOR_ANS_AUTHPASSWORD, m);
    r = sshbuf_get_u32(m, &mut authenticated as *mut libc::c_int as *mut u_int32_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_auth_password\0"))
                .as_ptr(),
            422 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_free(m);
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_auth_password\0")).as_ptr(),
        433 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"user %sauthenticated\0" as *const u8 as *const libc::c_char,
        if authenticated != 0 {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b"not \0" as *const u8 as *const libc::c_char
        },
    );
    return authenticated;
}
pub unsafe extern "C" fn mm_user_key_allowed(
    mut _ssh: *mut ssh,
    mut _pw: *mut libc::passwd,
    mut key: *mut sshkey,
    mut pubkey_auth_attempt: libc::c_int,
    mut authoptp: *mut *mut sshauthopt,
) -> libc::c_int {
    return mm_key_allowed(
        MM_USERKEY,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        key,
        pubkey_auth_attempt,
        authoptp,
    );
}
pub unsafe extern "C" fn mm_hostbased_key_allowed(
    mut _ssh: *mut ssh,
    mut _pw: *mut libc::passwd,
    mut user: *const libc::c_char,
    mut host: *const libc::c_char,
    mut key: *mut sshkey,
) -> libc::c_int {
    return mm_key_allowed(
        MM_HOSTKEY,
        user,
        host,
        key,
        0 as libc::c_int,
        0 as *mut *mut sshauthopt,
    );
}
pub unsafe extern "C" fn mm_key_allowed(
    mut type_0: mm_keytype,
    mut user: *const libc::c_char,
    mut host: *const libc::c_char,
    mut key: *mut sshkey,
    mut pubkey_auth_attempt: libc::c_int,
    mut authoptp: *mut *mut sshauthopt,
) -> libc::c_int {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    let mut allowed: libc::c_int = 0 as libc::c_int;
    let mut opts: *mut sshauthopt = 0 as *mut sshauthopt;
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_key_allowed\0")).as_ptr(),
        460 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    if !authoptp.is_null() {
        *authoptp = 0 as *mut sshauthopt;
    }
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_key_allowed\0"))
                .as_ptr(),
            466 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshbuf_put_u32(m, type_0 as u_int32_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_cstring(
                m,
                if !user.is_null() {
                    user
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(
                m,
                if !host.is_null() {
                    host
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshkey_puts(key, m);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(m, pubkey_auth_attempt as u_int32_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_key_allowed\0"))
                .as_ptr(),
            472 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_KEYALLOWED, m);
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_key_allowed\0")).as_ptr(),
        476 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"waiting for MONITOR_ANS_KEYALLOWED\0" as *const u8 as *const libc::c_char,
    );
    mm_request_receive_expect((*pmonitor).m_recvfd, MONITOR_ANS_KEYALLOWED, m);
    r = sshbuf_get_u32(m, &mut allowed as *mut libc::c_int as *mut u_int32_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_key_allowed\0"))
                .as_ptr(),
            481 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if allowed != 0 && type_0 as libc::c_uint == MM_USERKEY as libc::c_int as libc::c_uint && {
        r = sshauthopt_deserialise(m, &mut opts);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"mm_key_allowed\0"))
                .as_ptr(),
            484 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"sshauthopt_deserialise\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_free(m);
    if !authoptp.is_null() {
        *authoptp = opts;
        opts = 0 as *mut sshauthopt;
    }
    sshauthopt_free(opts);
    return allowed;
}
pub unsafe extern "C" fn mm_sshkey_verify(
    mut key: *const sshkey,
    mut sig: *const u_char,
    mut siglen: size_t,
    mut data: *const u_char,
    mut datalen: size_t,
    mut sigalg: *const libc::c_char,
    mut _compat: u_int,
    mut sig_detailsp: *mut *mut sshkey_sig_details,
) -> libc::c_int {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut encoded_ret: u_int = 0 as libc::c_int as u_int;
    let mut r: libc::c_int = 0;
    let mut sig_details_present: u_char = 0;
    let mut flags: u_char = 0;
    let mut counter: u_int = 0;
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_sshkey_verify\0")).as_ptr(),
        513 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    if !sig_detailsp.is_null() {
        *sig_detailsp = 0 as *mut sshkey_sig_details;
    }
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_sshkey_verify\0"))
                .as_ptr(),
            518 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshkey_puts(key, m);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_string(m, sig as *const libc::c_void, siglen);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(m, data as *const libc::c_void, datalen);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(
                m,
                if sigalg.is_null() {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    sigalg
                },
            );
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_sshkey_verify\0"))
                .as_ptr(),
            523 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_KEYVERIFY, m);
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_sshkey_verify\0")).as_ptr(),
        527 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"waiting for MONITOR_ANS_KEYVERIFY\0" as *const u8 as *const libc::c_char,
    );
    mm_request_receive_expect((*pmonitor).m_recvfd, MONITOR_ANS_KEYVERIFY, m);
    r = sshbuf_get_u32(m, &mut encoded_ret);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_u8(m, &mut sig_details_present);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_sshkey_verify\0"))
                .as_ptr(),
            533 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if sig_details_present as libc::c_int != 0 && encoded_ret == 0 as libc::c_int as libc::c_uint {
        r = sshbuf_get_u32(m, &mut counter);
        if r != 0 as libc::c_int || {
            r = sshbuf_get_u8(m, &mut flags);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_sshkey_verify\0"))
                    .as_ptr(),
                537 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse sig_details\0" as *const u8 as *const libc::c_char,
            );
        }
        if !sig_detailsp.is_null() {
            *sig_detailsp = crate::xmalloc::xcalloc(
                1 as libc::c_int as size_t,
                ::core::mem::size_of::<sshkey_sig_details>() as libc::c_ulong,
            ) as *mut sshkey_sig_details;
            (**sig_detailsp).sk_counter = counter;
            (**sig_detailsp).sk_flags = flags;
        }
    }
    crate::sshbuf::sshbuf_free(m);
    if encoded_ret != 0 as libc::c_int as libc::c_uint {
        return -(21 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn mm_send_keystate(mut ssh: *mut ssh, mut monitor: *mut monitor) {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_send_keystate\0"))
                .as_ptr(),
            559 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = ssh_packet_get_state(ssh, m);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_send_keystate\0"))
                .as_ptr(),
            561 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"ssh_packet_get_state\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send((*monitor).m_recvfd, MONITOR_REQ_KEYEXPORT, m);
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_send_keystate\0")).as_ptr(),
        563 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Finished sending state\0" as *const u8 as *const libc::c_char,
    );
    crate::sshbuf::sshbuf_free(m);
}
pub unsafe extern "C" fn mm_pty_allocate(
    mut ptyfd: *mut libc::c_int,
    mut ttyfd: *mut libc::c_int,
    mut namebuf: *mut libc::c_char,
    mut namebuflen: size_t,
) -> libc::c_int {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut msg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut tmp1: libc::c_int = -(1 as libc::c_int);
    let mut tmp2: libc::c_int = -(1 as libc::c_int);
    let mut r: libc::c_int = 0;
    tmp1 = dup((*pmonitor).m_recvfd);
    if tmp1 == -(1 as libc::c_int) || {
        tmp2 = dup((*pmonitor).m_recvfd);
        tmp2 == -(1 as libc::c_int)
    } {
        crate::log::sshlog(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_pty_allocate\0"))
                .as_ptr(),
            577 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"cannot allocate fds for pty\0" as *const u8 as *const libc::c_char,
        );
        if tmp1 >= 0 as libc::c_int {
            close(tmp1);
        }
        return 0 as libc::c_int;
    }
    close(tmp1);
    close(tmp2);
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_pty_allocate\0"))
                .as_ptr(),
            586 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_PTY, m);
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_pty_allocate\0")).as_ptr(),
        589 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"waiting for MONITOR_ANS_PTY\0" as *const u8 as *const libc::c_char,
    );
    mm_request_receive_expect((*pmonitor).m_recvfd, MONITOR_ANS_PTY, m);
    r = sshbuf_get_u32(m, &mut success as *mut libc::c_int as *mut u_int32_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_pty_allocate\0"))
                .as_ptr(),
            593 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse success\0" as *const u8 as *const libc::c_char,
        );
    }
    if success == 0 as libc::c_int {
        crate::log::sshlog(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_pty_allocate\0"))
                .as_ptr(),
            595 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"pty alloc failed\0" as *const u8 as *const libc::c_char,
        );
        crate::sshbuf::sshbuf_free(m);
        return 0 as libc::c_int;
    }
    r = sshbuf_get_cstring(m, &mut p, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_cstring(m, &mut msg, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_pty_allocate\0"))
                .as_ptr(),
            601 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_free(m);
    strlcpy(namebuf, p, namebuflen);
    libc::free(p as *mut libc::c_void);
    r = sshbuf_put(loginmsg, msg as *const libc::c_void, strlen(msg));
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_pty_allocate\0"))
                .as_ptr(),
            608 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"put loginmsg\0" as *const u8 as *const libc::c_char,
        );
    }
    libc::free(msg as *mut libc::c_void);
    *ptyfd = mm_receive_fd((*pmonitor).m_recvfd);
    if *ptyfd == -(1 as libc::c_int) || {
        *ttyfd = mm_receive_fd((*pmonitor).m_recvfd);
        *ttyfd == -(1 as libc::c_int)
    } {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"mm_pty_allocate\0"))
                .as_ptr(),
            613 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"receive fds failed\0" as *const u8 as *const libc::c_char,
        );
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn mm_session_pty_cleanup2(mut s: *mut Session) {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    if (*s).ttyfd == -(1 as libc::c_int) {
        return;
    }
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"mm_session_pty_cleanup2\0",
            ))
            .as_ptr(),
            628 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshbuf_put_cstring(m, ((*s).tty).as_mut_ptr());
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"mm_session_pty_cleanup2\0",
            ))
            .as_ptr(),
            630 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assmble\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_PTYCLEANUP, m);
    crate::sshbuf::sshbuf_free(m);
    if (*s).ptymaster != -(1 as libc::c_int) && close((*s).ptymaster) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"mm_session_pty_cleanup2\0",
            ))
            .as_ptr(),
            637 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"close(s->ptymaster/%d): %s\0" as *const u8 as *const libc::c_char,
            (*s).ptymaster,
            libc::strerror(*libc::__errno_location()),
        );
    }
    (*s).ttyfd = -(1 as libc::c_int);
}
pub unsafe extern "C" fn mm_terminate() {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"mm_terminate\0")).as_ptr(),
            803 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_TERM, m);
    crate::sshbuf::sshbuf_free(m);
}
unsafe extern "C" fn mm_chall_setup(
    mut name: *mut *mut libc::c_char,
    mut infotxt: *mut *mut libc::c_char,
    mut numprompts: *mut u_int,
    mut prompts: *mut *mut *mut libc::c_char,
    mut echo_on: *mut *mut u_int,
) {
    *name = crate::xmalloc::xstrdup(b"\0" as *const u8 as *const libc::c_char);
    *infotxt = crate::xmalloc::xstrdup(b"\0" as *const u8 as *const libc::c_char);
    *numprompts = 1 as libc::c_int as u_int;
    *prompts = crate::xmalloc::xcalloc(
        *numprompts as size_t,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    *echo_on = crate::xmalloc::xcalloc(
        *numprompts as size_t,
        ::core::mem::size_of::<u_int>() as libc::c_ulong,
    ) as *mut u_int;
    *(*echo_on).offset(0 as libc::c_int as isize) = 0 as libc::c_int as u_int;
}
pub unsafe extern "C" fn mm_bsdauth_query(
    mut _ctx: *mut libc::c_void,
    mut name: *mut *mut libc::c_char,
    mut infotxt: *mut *mut libc::c_char,
    mut numprompts: *mut u_int,
    mut prompts: *mut *mut *mut libc::c_char,
    mut echo_on: *mut *mut u_int,
) -> libc::c_int {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut success: u_int = 0;
    let mut challenge: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_bsdauth_query\0")).as_ptr(),
        829 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_bsdauth_query\0"))
                .as_ptr(),
            832 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_BSDAUTHQUERY, m);
    mm_request_receive_expect((*pmonitor).m_recvfd, MONITOR_ANS_BSDAUTHQUERY, m);
    r = sshbuf_get_u32(m, &mut success);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_bsdauth_query\0"))
                .as_ptr(),
            838 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse success\0" as *const u8 as *const libc::c_char,
        );
    }
    if success == 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_bsdauth_query\0"))
                .as_ptr(),
            840 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"no challenge\0" as *const u8 as *const libc::c_char,
        );
        crate::sshbuf::sshbuf_free(m);
        return -(1 as libc::c_int);
    }
    r = sshbuf_get_cstring(m, &mut challenge, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_bsdauth_query\0"))
                .as_ptr(),
            847 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse challenge\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_free(m);
    mm_chall_setup(name, infotxt, numprompts, prompts, echo_on);
    let ref mut fresh0 = *(*prompts).offset(0 as libc::c_int as isize);
    *fresh0 = challenge;
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"mm_bsdauth_query\0")).as_ptr(),
        853 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"received challenge: %s\0" as *const u8 as *const libc::c_char,
        challenge,
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn mm_bsdauth_respond(
    mut _ctx: *mut libc::c_void,
    mut numresponses: u_int,
    mut responses: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut m: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    let mut authok: libc::c_int = 0;
    crate::log::sshlog(
        b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_bsdauth_respond\0"))
            .as_ptr(),
        864 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    if numresponses != 1 as libc::c_int as libc::c_uint {
        return -(1 as libc::c_int);
    }
    m = crate::sshbuf::sshbuf_new();
    if m.is_null() {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_bsdauth_respond\0"))
                .as_ptr(),
            869 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshbuf_put_cstring(m, *responses.offset(0 as libc::c_int as isize));
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_bsdauth_respond\0"))
                .as_ptr(),
            871 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"assemble\0" as *const u8 as *const libc::c_char,
        );
    }
    mm_request_send((*pmonitor).m_recvfd, MONITOR_REQ_BSDAUTHRESPOND, m);
    mm_request_receive_expect((*pmonitor).m_recvfd, MONITOR_ANS_BSDAUTHRESPOND, m);
    r = sshbuf_get_u32(m, &mut authok as *mut libc::c_int as *mut u_int32_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"monitor_wrap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"mm_bsdauth_respond\0"))
                .as_ptr(),
            878 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_free(m);
    return if authok == 0 as libc::c_int {
        -(1 as libc::c_int)
    } else {
        0 as libc::c_int
    };
}
