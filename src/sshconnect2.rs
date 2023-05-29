use crate::kex::dh_st;
use crate::packet::key_entry;

use crate::packet::ssh;

use crate::utf8::fmprintf;
use ::libc;
use libc::close;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    pub type ec_group_st;

    pub type notifier_ctx;

    fn closefrom(__lowfd: libc::c_int);
    fn pipe(__pipedes: *mut libc::c_int) -> libc::c_int;

    fn execl(__path: *const libc::c_char, __arg: *const libc::c_char, _: ...) -> libc::c_int;

    static mut stdout: *mut libc::FILE;
    static mut stderr: *mut libc::FILE;

    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn freezero(_: *mut libc::c_void, _: size_t);

    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;

    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;

    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;

    fn sshbuf_putb(buf: *mut crate::sshbuf::sshbuf, v: *const crate::sshbuf::sshbuf)
        -> libc::c_int;

    fn ssh_packet_get_connection_in(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_connection_is_on_socket(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_remaining(_: *mut ssh) -> libc::c_int;
    fn ssh_remote_ipaddr(_: *mut ssh) -> *const libc::c_char;
    fn ssh_remote_port(_: *mut ssh) -> libc::c_int;
    fn sshpkt_get_u32(ssh: *mut ssh, valp: *mut u_int32_t) -> libc::c_int;
    fn sshpkt_get_string(ssh: *mut ssh, valp: *mut *mut u_char, lenp: *mut size_t) -> libc::c_int;

    fn sshpkt_put_string(ssh: *mut ssh, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshpkt_put_u32(ssh: *mut ssh, val: u_int32_t) -> libc::c_int;

    fn sshpkt_putb(ssh: *mut ssh, b: *const crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshpkt_get_u8(ssh: *mut ssh, valp: *mut u_char) -> libc::c_int;
    fn sshpkt_add_padding(_: *mut ssh, _: u_char) -> libc::c_int;

    fn ssh_packet_set_rekey_limits(_: *mut ssh, _: u_int64_t, _: u_int32_t);

    fn ssh_dispatch_range(_: *mut ssh, _: u_int, _: u_int, _: Option<dispatch_fn>);

    fn compat_kex_proposal(_: *mut ssh, _: *const libc::c_char) -> *mut libc::c_char;
    fn compression_alg_list(_: libc::c_int) -> *const libc::c_char;

    fn sshkey_equal(
        _: *const crate::sshkey::sshkey,
        _: *const crate::sshkey::sshkey,
    ) -> libc::c_int;

    fn sshkey_type_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_is_cert(_: *const crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_is_sk(_: *const crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_type_is_cert(_: libc::c_int) -> libc::c_int;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn sshkey_match_keyname_to_sigalgs(
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn sshkey_ecdsa_nid_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_ssh_name(_: *const crate::sshkey::sshkey) -> *const libc::c_char;
    fn sshkey_alg_list(
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_char,
    ) -> *mut libc::c_char;
    fn sshkey_from_blob(
        _: *const u_char,
        _: size_t,
        _: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_to_blob(
        _: *const crate::sshkey::sshkey,
        _: *mut *mut u_char,
        _: *mut size_t,
    ) -> libc::c_int;
    fn sshkey_puts(_: *const crate::sshkey::sshkey, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshkey_sign(
        _: *mut crate::sshkey::sshkey,
        _: *mut *mut u_char,
        _: *mut size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: u_int,
    ) -> libc::c_int;
    fn sshkey_check_sigtype(_: *const u_char, _: size_t, _: *const libc::c_char) -> libc::c_int;
    fn sshkey_sigalg_by_name(_: *const libc::c_char) -> *const libc::c_char;
    fn sshkey_check_rsa_length(_: *const crate::sshkey::sshkey, _: libc::c_int) -> libc::c_int;
    fn kex_names_cat(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn kex_assemble_names(
        _: *mut *mut libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn kex_proposal_populate_entries(
        _: *mut ssh,
        prop: *mut *mut libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
    );
    fn kex_proposal_free_entries(prop: *mut *mut libc::c_char);
    fn kex_setup(_: *mut ssh, _: *mut *mut libc::c_char) -> libc::c_int;
    fn kex_prop2buf(_: *mut crate::sshbuf::sshbuf, proposal: *mut *mut libc::c_char)
        -> libc::c_int;
    fn kex_input_ext_info(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn kexgex_client(_: *mut ssh) -> libc::c_int;
    fn kex_gen_client(_: *mut ssh) -> libc::c_int;
    fn verify_host_key(
        _: *mut libc::c_char,
        _: *mut sockaddr,
        _: *mut crate::sshkey::sshkey,
        _: *const ssh_conn_info,
    ) -> libc::c_int;
    fn get_hostfile_hostname_ipaddr(
        _: *mut libc::c_char,
        _: *mut sockaddr,
        _: u_short,
        _: *mut *mut libc::c_char,
        _: *mut *mut libc::c_char,
    );
    fn maybe_add_key_to_agent(
        _: *const libc::c_char,
        _: *mut crate::sshkey::sshkey,
        _: *const libc::c_char,
        _: *const libc::c_char,
    );
    fn load_hostkeys_command(
        _: *mut hostkeys,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const ssh_conn_info,
        _: *const crate::sshkey::sshkey,
        _: *const libc::c_char,
    );
    fn sshkey_load_private_type(
        _: libc::c_int,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut *mut crate::sshkey::sshkey,
        _: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn ssh_get_authentication_socket(fdp: *mut libc::c_int) -> libc::c_int;
    fn ssh_close_authentication_socket(sock: libc::c_int);
    fn ssh_fetch_identitylist(sock: libc::c_int, idlp: *mut *mut ssh_identitylist) -> libc::c_int;
    fn ssh_free_identitylist(idl: *mut ssh_identitylist);
    fn ssh_agent_sign(
        sock: libc::c_int,
        key: *const crate::sshkey::sshkey,
        sigp: *mut *mut u_char,
        lenp: *mut size_t,
        data: *const u_char,
        datalen: size_t,
        alg: *const libc::c_char,
        compat: u_int,
    ) -> libc::c_int;
    fn ssh_agent_bind_hostkey(
        sock: libc::c_int,
        key: *const crate::sshkey::sshkey,
        session_id: *const crate::sshbuf::sshbuf,
        signature: *const crate::sshbuf::sshbuf,
        forwarding: libc::c_int,
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
    fn read_passphrase(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn notify_start(_: libc::c_int, _: *const libc::c_char, _: ...) -> *mut notifier_ctx;
    fn notify_complete(_: *mut notifier_ctx, _: *const libc::c_char, _: ...);

    fn kex_default_pk_alg() -> *const libc::c_char;
    fn match_pattern_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn match_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut u_int,
    ) -> *mut libc::c_char;
    fn get_local_name(_: libc::c_int) -> *mut libc::c_char;
    fn ssh_msg_send(_: libc::c_int, _: u_char, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn ssh_msg_recv(_: libc::c_int, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn init_hostkeys() -> *mut hostkeys;
    fn load_hostkeys(_: *mut hostkeys, _: *const libc::c_char, _: *const libc::c_char, _: u_int);
    fn free_hostkeys(_: *mut hostkeys);
    fn lookup_key_in_hostkeys_by_type(
        _: *mut hostkeys,
        _: libc::c_int,
        _: libc::c_int,
        _: *mut *const hostkey_entry,
    ) -> libc::c_int;
    fn lookup_marker_in_hostkeys(_: *mut hostkeys, _: libc::c_int) -> libc::c_int;

    fn asmprintf(
        _: *mut *mut libc::c_char,
        _: size_t,
        _: *mut libc::c_int,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    static mut options: Options;
}
pub type __u_char = libc::c_uchar;
pub type __u_short = libc::c_ushort;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
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
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_short = __u_short;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type mode_t = __mode_t;
pub type pid_t = __pid_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;

pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type uint8_t = __uint8_t;

pub type _IO_lock_t = ();

pub type sig_atomic_t = __sig_atomic_t;
pub type __sighandler_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;

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

pub type C2RustUnnamed_2 = libc::c_uint;
pub const DISPATCH_NONBLOCK: C2RustUnnamed_2 = 1;
pub const DISPATCH_BLOCK: C2RustUnnamed_2 = 0;
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
pub type kex_init_proposals = libc::c_uint;
pub const PROPOSAL_MAX: kex_init_proposals = 10;
pub const PROPOSAL_LANG_STOC: kex_init_proposals = 9;
pub const PROPOSAL_LANG_CTOS: kex_init_proposals = 8;
pub const PROPOSAL_COMP_ALGS_STOC: kex_init_proposals = 7;
pub const PROPOSAL_COMP_ALGS_CTOS: kex_init_proposals = 6;
pub const PROPOSAL_MAC_ALGS_STOC: kex_init_proposals = 5;
pub const PROPOSAL_MAC_ALGS_CTOS: kex_init_proposals = 4;
pub const PROPOSAL_ENC_ALGS_STOC: kex_init_proposals = 3;
pub const PROPOSAL_ENC_ALGS_CTOS: kex_init_proposals = 2;
pub const PROPOSAL_SERVER_HOST_KEY_ALGS: kex_init_proposals = 1;
pub const PROPOSAL_KEX_ALGS: kex_init_proposals = 0;
pub type kex_exchange = libc::c_uint;
pub const KEX_MAX: kex_exchange = 10;
pub const KEX_KEM_SNTRUP761X25519_SHA512: kex_exchange = 9;
pub const KEX_C25519_SHA256: kex_exchange = 8;
pub const KEX_ECDH_SHA2: kex_exchange = 7;
pub const KEX_DH_GEX_SHA256: kex_exchange = 6;
pub const KEX_DH_GEX_SHA1: kex_exchange = 5;
pub const KEX_DH_GRP18_SHA512: kex_exchange = 4;
pub const KEX_DH_GRP16_SHA512: kex_exchange = 3;
pub const KEX_DH_GRP14_SHA256: kex_exchange = 2;
pub const KEX_DH_GRP14_SHA1: kex_exchange = 1;
pub const KEX_DH_GRP1_SHA1: kex_exchange = 0;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostkeys {
    pub entries: *mut hostkey_entry,
    pub num_entries: u_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostkey_entry {
    pub host: *mut libc::c_char,
    pub file: *mut libc::c_char,
    pub line: u_long,
    pub key: *mut crate::sshkey::sshkey,
    pub marker: HostkeyMarker,
    pub note: u_int,
}
pub type HostkeyMarker = libc::c_uint;
pub const MRK_CA: HostkeyMarker = 3;
pub const MRK_REVOKE: HostkeyMarker = 2;
pub const MRK_NONE: HostkeyMarker = 1;
pub const MRK_ERROR: HostkeyMarker = 0;
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
pub struct allowed_cname {
    pub source_list: *mut libc::c_char,
    pub target_list: *mut libc::c_char,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ForwardOptions {
    pub gateway_ports: libc::c_int,
    pub streamlocal_bind_mask: mode_t,
    pub streamlocal_bind_unlink: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cauthmethod {
    pub name: *mut libc::c_char,
    pub userauth: Option<unsafe extern "C" fn(*mut ssh) -> libc::c_int>,
    pub cleanup: Option<unsafe extern "C" fn(*mut ssh) -> ()>,
    pub enabled: *mut libc::c_int,
    pub batch_flag: *mut libc::c_int,
}
pub type Authctxt = cauthctxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cauthctxt {
    pub server_user: *const libc::c_char,
    pub local_user: *const libc::c_char,
    pub host: *const libc::c_char,
    pub service: *const libc::c_char,
    pub method: *mut cauthmethod,
    pub success: sig_atomic_t,
    pub authlist: *mut libc::c_char,
    pub keys: idlist,
    pub agent_fd: libc::c_int,
    pub sensitive: *mut Sensitive,
    pub oktypes: *mut libc::c_char,
    pub ktypes: *mut libc::c_char,
    pub active_ktype: *const libc::c_char,
    pub info_req_seen: libc::c_int,
    pub attempt_kbdint: libc::c_int,
    pub attempt_passwd: libc::c_int,
    pub methoddata: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct idlist {
    pub tqh_first: *mut identity,
    pub tqh_last: *mut *mut identity,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct identity {
    pub next: C2RustUnnamed_3,
    pub agent_fd: libc::c_int,
    pub key: *mut crate::sshkey::sshkey,
    pub filename: *mut libc::c_char,
    pub tried: libc::c_int,
    pub isprivate: libc::c_int,
    pub userprovided: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
    pub tqe_next: *mut identity,
    pub tqe_prev: *mut *mut identity,
}
pub type Identity = identity;
pub type Authmethod = cauthmethod;
pub type sshsig_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh_identitylist {
    pub nkeys: size_t,
    pub keys: *mut *mut crate::sshkey::sshkey,
    pub comments: *mut *mut libc::c_char,
}
static mut xxx_host: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut xxx_hostaddr: *mut sockaddr = 0 as *const sockaddr as *mut sockaddr;
static mut xxx_conn_info: *const ssh_conn_info = 0 as *const ssh_conn_info;
unsafe extern "C" fn verify_host_key_callback(
    mut hostkey: *mut crate::sshkey::sshkey,
    mut _ssh: *mut ssh,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = sshkey_check_rsa_length(hostkey, options.required_rsa_size);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"verify_host_key_callback\0",
            ))
            .as_ptr(),
            102 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"Bad server host key\0" as *const u8 as *const libc::c_char,
        );
    }
    if verify_host_key(xxx_host, xxx_hostaddr, hostkey, xxx_conn_info) == -(1 as libc::c_int) {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"verify_host_key_callback\0",
            ))
            .as_ptr(),
            105 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Host key verification failed.\0" as *const u8 as *const libc::c_char,
        );
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn first_alg(mut algs: *const libc::c_char) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    ret = crate::xmalloc::xstrdup(algs);
    cp = libc::strchr(ret, ',' as i32);
    if !cp.is_null() {
        *cp = '\0' as i32 as libc::c_char;
    }
    return ret;
}
unsafe extern "C" fn order_hostkeyalgs(
    mut host: *mut libc::c_char,
    mut hostaddr: *mut sockaddr,
    mut port: u_short,
    mut cinfo: *const ssh_conn_info,
) -> *mut libc::c_char {
    let mut oavail: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut avail: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut first: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut last: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut alg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hostname: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut best: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut maxlen: size_t = 0;
    let mut hostkeys: *mut hostkeys = 0 as *mut hostkeys;
    let mut ktype: libc::c_int = 0;
    let mut i: u_int = 0;
    get_hostfile_hostname_ipaddr(
        host,
        hostaddr,
        port,
        &mut hostname,
        0 as *mut *mut libc::c_char,
    );
    hostkeys = init_hostkeys();
    i = 0 as libc::c_int as u_int;
    while i < options.num_user_hostfiles {
        load_hostkeys(
            hostkeys,
            hostname,
            options.user_hostfiles[i as usize],
            0 as libc::c_int as u_int,
        );
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_system_hostfiles {
        load_hostkeys(
            hostkeys,
            hostname,
            options.system_hostfiles[i as usize],
            0 as libc::c_int as u_int,
        );
        i = i.wrapping_add(1);
        i;
    }
    if !(options.known_hosts_command).is_null() {
        load_hostkeys_command(
            hostkeys,
            options.known_hosts_command,
            b"ORDER\0" as *const u8 as *const libc::c_char,
            cinfo,
            0 as *const crate::sshkey::sshkey,
            host,
        );
    }
    best = first_alg(options.hostkeyalgorithms);
    if lookup_key_in_hostkeys_by_type(
        hostkeys,
        sshkey_type_plain(sshkey_type_from_name(best)),
        sshkey_ecdsa_nid_from_name(best),
        0 as *mut *const hostkey_entry,
    ) != 0
    {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"order_hostkeyalgs\0"))
                .as_ptr(),
            157 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"have matching best-preference key type %s, using HostkeyAlgorithms verbatim\0"
                as *const u8 as *const libc::c_char,
            best,
        );
        ret = crate::xmalloc::xstrdup(options.hostkeyalgorithms);
    } else {
        avail = crate::xmalloc::xstrdup(options.hostkeyalgorithms);
        oavail = avail;
        maxlen = (strlen(avail)).wrapping_add(1 as libc::c_int as libc::c_ulong);
        first = crate::xmalloc::xmalloc(maxlen) as *mut libc::c_char;
        last = crate::xmalloc::xmalloc(maxlen) as *mut libc::c_char;
        *last = '\0' as i32 as libc::c_char;
        *first = *last;
        loop {
            alg = strsep(&mut avail, b",\0" as *const u8 as *const libc::c_char);
            if !(!alg.is_null() && *alg as libc::c_int != '\0' as i32) {
                break;
            }
            ktype = sshkey_type_from_name(alg);
            if ktype == KEY_UNSPEC as libc::c_int {
                sshfatal(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"order_hostkeyalgs\0",
                    ))
                    .as_ptr(),
                    181 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"unknown alg %s\0" as *const u8 as *const libc::c_char,
                    alg,
                );
            }
            if sshkey_type_is_cert(ktype) != 0
                && lookup_marker_in_hostkeys(hostkeys, MRK_CA as libc::c_int) != 0
            {
                if *first as libc::c_int != '\0' as i32 {
                    strlcat(first, b",\0" as *const u8 as *const libc::c_char, maxlen);
                }
                strlcat(first, alg, maxlen);
            } else if lookup_key_in_hostkeys_by_type(
                hostkeys,
                sshkey_type_plain(ktype),
                sshkey_ecdsa_nid_from_name(alg),
                0 as *mut *const hostkey_entry,
            ) != 0
            {
                if *first as libc::c_int != '\0' as i32 {
                    strlcat(first, b",\0" as *const u8 as *const libc::c_char, maxlen);
                }
                strlcat(first, alg, maxlen);
            } else {
                if *last as libc::c_int != '\0' as i32 {
                    strlcat(last, b",\0" as *const u8 as *const libc::c_char, maxlen);
                }
                strlcat(last, alg, maxlen);
            }
        }
        crate::xmalloc::xasprintf(
            &mut ret as *mut *mut libc::c_char,
            b"%s%s%s\0" as *const u8 as *const libc::c_char,
            first,
            if *first as libc::c_int == '\0' as i32 || *last as libc::c_int == '\0' as i32 {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b",\0" as *const u8 as *const libc::c_char
            },
            last,
        );
        if *first as libc::c_int != '\0' as i32 {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"order_hostkeyalgs\0"))
                    .as_ptr(),
                205 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"prefer hostkeyalgs: %s\0" as *const u8 as *const libc::c_char,
                first,
            );
        } else {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"order_hostkeyalgs\0"))
                    .as_ptr(),
                207 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"no algorithms matched; accept original\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    libc::free(best as *mut libc::c_void);
    libc::free(first as *mut libc::c_void);
    libc::free(last as *mut libc::c_void);
    libc::free(hostname as *mut libc::c_void);
    libc::free(oavail as *mut libc::c_void);
    free_hostkeys(hostkeys);
    return ret;
}
pub unsafe extern "C" fn ssh_kex2(
    mut ssh: *mut ssh,
    mut host: *mut libc::c_char,
    mut hostaddr: *mut sockaddr,
    mut port: u_short,
    mut cinfo: *const ssh_conn_info,
) {
    let mut myproposal: [*mut libc::c_char; 10] = [0 as *mut libc::c_char; 10];
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut all_key: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hkalgs: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut use_known_hosts_order: libc::c_int = 0 as libc::c_int;
    xxx_host = host;
    xxx_hostaddr = hostaddr;
    xxx_conn_info = cinfo;
    if options.rekey_limit != 0 || options.rekey_interval != 0 {
        ssh_packet_set_rekey_limits(
            ssh,
            options.rekey_limit as u_int64_t,
            options.rekey_interval as u_int32_t,
        );
    }
    if (options.hostkeyalgorithms).is_null()
        || *(options.hostkeyalgorithms).offset(0 as libc::c_int as isize) as libc::c_int
            == '-' as i32
        || *(options.hostkeyalgorithms).offset(0 as libc::c_int as isize) as libc::c_int
            == '+' as i32
    {
        use_known_hosts_order = 1 as libc::c_int;
    }
    all_key = sshkey_alg_list(
        0 as libc::c_int,
        0 as libc::c_int,
        1 as libc::c_int,
        ',' as i32 as libc::c_char,
    );
    r = kex_assemble_names(
        &mut options.hostkeyalgorithms,
        kex_default_pk_alg(),
        all_key,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"ssh_kex2\0")).as_ptr(),
            249 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"kex_assemble_namelist\0" as *const u8 as *const libc::c_char,
        );
    }
    libc::free(all_key as *mut libc::c_void);
    s = kex_names_cat(
        options.kex_algorithms,
        b"ext-info-c\0" as *const u8 as *const libc::c_char,
    );
    if s.is_null() {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"ssh_kex2\0")).as_ptr(),
            253 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"kex_names_cat\0" as *const u8 as *const libc::c_char,
        );
    }
    if use_known_hosts_order != 0 {
        hkalgs = order_hostkeyalgs(host, hostaddr, port, cinfo);
    }
    kex_proposal_populate_entries(
        ssh,
        myproposal.as_mut_ptr(),
        s,
        options.ciphers,
        options.macs,
        compression_alg_list(options.compression),
        if !hkalgs.is_null() {
            hkalgs
        } else {
            options.hostkeyalgorithms
        },
    );
    libc::free(hkalgs as *mut libc::c_void);
    r = kex_setup(ssh, myproposal.as_mut_ptr());
    if r != 0 as libc::c_int {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"ssh_kex2\0")).as_ptr(),
            266 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"kex_setup\0" as *const u8 as *const libc::c_char,
        );
    }
    (*(*ssh).kex).kex[KEX_DH_GRP1_SHA1 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*ssh).kex).kex[KEX_DH_GRP14_SHA1 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*ssh).kex).kex[KEX_DH_GRP14_SHA256 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*ssh).kex).kex[KEX_DH_GRP16_SHA512 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*ssh).kex).kex[KEX_DH_GRP18_SHA512 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*ssh).kex).kex[KEX_DH_GEX_SHA1 as libc::c_int as usize] =
        Some(kexgex_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*ssh).kex).kex[KEX_DH_GEX_SHA256 as libc::c_int as usize] =
        Some(kexgex_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*ssh).kex).kex[KEX_ECDH_SHA2 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*ssh).kex).kex[KEX_C25519_SHA256 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*ssh).kex).kex[KEX_KEM_SNTRUP761X25519_SHA512 as libc::c_int as usize] =
        Some(kex_gen_client as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*(*ssh).kex).verify_host_key = Some(
        verify_host_key_callback
            as unsafe extern "C" fn(*mut crate::sshkey::sshkey, *mut ssh) -> libc::c_int,
    );
    crate::dispatch::ssh_dispatch_run_fatal(
        ssh,
        DISPATCH_BLOCK as libc::c_int,
        &mut (*(*ssh).kex).done as *mut sig_atomic_t as *mut sig_atomic_t,
    );
    libc::free(myproposal[PROPOSAL_KEX_ALGS as libc::c_int as usize] as *mut libc::c_void);
    myproposal[PROPOSAL_KEX_ALGS as libc::c_int as usize] =
        compat_kex_proposal(ssh, options.kex_algorithms);
    r = kex_prop2buf((*(*ssh).kex).my, myproposal.as_mut_ptr());
    if r != 0 as libc::c_int {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"ssh_kex2\0")).as_ptr(),
            290 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"kex_prop2buf\0" as *const u8 as *const libc::c_char,
        );
    }
    kex_proposal_free_entries(myproposal.as_mut_ptr());
}
pub static mut authmethods: [Authmethod; 6] = [Authmethod {
    name: 0 as *mut libc::c_char,
    userauth: None,
    cleanup: None,
    enabled: 0 as *mut libc::c_int,
    batch_flag: 0 as *mut libc::c_int,
}; 6];
pub unsafe extern "C" fn ssh_userauth2(
    mut ssh: *mut ssh,
    mut local_user: *const libc::c_char,
    mut server_user: *const libc::c_char,
    mut host: *mut libc::c_char,
    mut sensitive: *mut Sensitive,
) {
    let mut authctxt: Authctxt = Authctxt {
        server_user: 0 as *const libc::c_char,
        local_user: 0 as *const libc::c_char,
        host: 0 as *const libc::c_char,
        service: 0 as *const libc::c_char,
        method: 0 as *mut cauthmethod,
        success: 0,
        authlist: 0 as *mut libc::c_char,
        keys: idlist {
            tqh_first: 0 as *mut identity,
            tqh_last: 0 as *mut *mut identity,
        },
        agent_fd: 0,
        sensitive: 0 as *mut Sensitive,
        oktypes: 0 as *mut libc::c_char,
        ktypes: 0 as *mut libc::c_char,
        active_ktype: 0 as *const libc::c_char,
        info_req_seen: 0,
        attempt_kbdint: 0,
        attempt_passwd: 0,
        methoddata: 0 as *mut libc::c_void,
    };
    let mut r: libc::c_int = 0;
    if (options.preferred_authentications).is_null() {
        options.preferred_authentications = authmethods_get();
    }
    memset(
        &mut authctxt as *mut Authctxt as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<Authctxt>() as libc::c_ulong,
    );
    authctxt.server_user = server_user;
    authctxt.local_user = local_user;
    authctxt.host = host;
    authctxt.service = b"ssh-connection\0" as *const u8 as *const libc::c_char;
    authctxt.success = 0 as libc::c_int;
    authctxt.method = authmethod_lookup(b"none\0" as *const u8 as *const libc::c_char);
    authctxt.authlist = 0 as *mut libc::c_char;
    authctxt.methoddata = 0 as *mut libc::c_void;
    authctxt.sensitive = sensitive;
    authctxt.ktypes = 0 as *mut libc::c_char;
    authctxt.oktypes = authctxt.ktypes;
    authctxt.active_ktype = authctxt.oktypes;
    authctxt.info_req_seen = 0 as libc::c_int;
    authctxt.attempt_kbdint = 0 as libc::c_int;
    authctxt.attempt_passwd = 0 as libc::c_int;
    authctxt.agent_fd = -(1 as libc::c_int);
    pubkey_prepare(ssh, &mut authctxt);
    if (authctxt.method).is_null() {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ssh_userauth2\0"))
                .as_ptr(),
            465 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"internal error: cannot send userauth none request\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = crate::packet::sshpkt_start(ssh, 5 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_put_cstring(
                ssh,
                b"ssh-userauth\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ssh_userauth2\0"))
                .as_ptr(),
            471 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send packet\0" as *const u8 as *const libc::c_char,
        );
    }
    (*ssh).authctxt = &mut authctxt as *mut Authctxt as *mut libc::c_void;
    crate::dispatch::ssh_dispatch_init(
        ssh,
        Some(
            input_userauth_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        7 as libc::c_int,
        Some(
            input_userauth_ext_info
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        6 as libc::c_int,
        Some(
            input_userauth_service_accept
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::dispatch::ssh_dispatch_run_fatal(
        ssh,
        DISPATCH_BLOCK as libc::c_int,
        &mut authctxt.success as *mut sig_atomic_t as *mut sig_atomic_t,
    );
    pubkey_cleanup(ssh);
    (*ssh).authctxt = 0 as *mut libc::c_void;
    ssh_dispatch_range(
        ssh,
        50 as libc::c_int as u_int,
        79 as libc::c_int as u_int,
        None,
    );
    if authctxt.success == 0 {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ssh_userauth2\0"))
                .as_ptr(),
            484 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Authentication failed.\0" as *const u8 as *const libc::c_char,
        );
    }
    if ssh_packet_connection_is_on_socket(ssh) != 0 {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ssh_userauth2\0"))
                .as_ptr(),
            488 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"Authenticated to %s ([%s]:%d) using \"%s\".\0" as *const u8 as *const libc::c_char,
            host,
            ssh_remote_ipaddr(ssh),
            ssh_remote_port(ssh),
            (*authctxt.method).name,
        );
    } else {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ssh_userauth2\0"))
                .as_ptr(),
            491 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"Authenticated to %s (via proxy) using \"%s\".\0" as *const u8 as *const libc::c_char,
            host,
            (*authctxt.method).name,
        );
    };
}
unsafe extern "C" fn input_userauth_service_accept(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = 0;
    if ssh_packet_remaining(ssh) > 0 as libc::c_int {
        let mut reply: *mut libc::c_char = 0 as *mut libc::c_char;
        r = crate::packet::sshpkt_get_cstring(ssh, &mut reply, 0 as *mut size_t);
        if r != 0 as libc::c_int {
            current_block = 10572056890585088958;
        } else {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                    b"input_userauth_service_accept\0",
                ))
                .as_ptr(),
                505 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"service_accept: %s\0" as *const u8 as *const libc::c_char,
                reply,
            );
            libc::free(reply as *mut libc::c_void);
            current_block = 6873731126896040597;
        }
    } else {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"input_userauth_service_accept\0",
            ))
            .as_ptr(),
            508 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"buggy server: service_accept w/o service\0" as *const u8 as *const libc::c_char,
        );
        current_block = 6873731126896040597;
    }
    match current_block {
        6873731126896040597 => {
            r = crate::packet::sshpkt_get_end(ssh);
            if !(r != 0 as libc::c_int) {
                crate::log::sshlog(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                        b"input_userauth_service_accept\0",
                    ))
                    .as_ptr(),
                    512 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"SSH2_MSG_SERVICE_ACCEPT received\0" as *const u8 as *const libc::c_char,
                );
                userauth_none(ssh);
                crate::dispatch::ssh_dispatch_set(
                    ssh,
                    7 as libc::c_int,
                    Some(
                        input_userauth_error
                            as unsafe extern "C" fn(
                                libc::c_int,
                                u_int32_t,
                                *mut ssh,
                            ) -> libc::c_int,
                    ),
                );
                crate::dispatch::ssh_dispatch_set(
                    ssh,
                    52 as libc::c_int,
                    Some(
                        input_userauth_success
                            as unsafe extern "C" fn(
                                libc::c_int,
                                u_int32_t,
                                *mut ssh,
                            ) -> libc::c_int,
                    ),
                );
                crate::dispatch::ssh_dispatch_set(
                    ssh,
                    51 as libc::c_int,
                    Some(
                        input_userauth_failure
                            as unsafe extern "C" fn(
                                libc::c_int,
                                u_int32_t,
                                *mut ssh,
                            ) -> libc::c_int,
                    ),
                );
                crate::dispatch::ssh_dispatch_set(
                    ssh,
                    53 as libc::c_int,
                    Some(
                        input_userauth_banner
                            as unsafe extern "C" fn(
                                libc::c_int,
                                u_int32_t,
                                *mut ssh,
                            ) -> libc::c_int,
                    ),
                );
                r = 0 as libc::c_int;
            }
        }
        _ => {}
    }
    return r;
}
unsafe extern "C" fn input_userauth_ext_info(
    mut type_0: libc::c_int,
    mut seqnr: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    return kex_input_ext_info(type_0, seqnr, ssh);
}
pub unsafe extern "C" fn userauth(mut ssh: *mut ssh, mut authlist: *mut libc::c_char) {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    if !((*authctxt).method).is_null() && ((*(*authctxt).method).cleanup).is_some() {
        ((*(*authctxt).method).cleanup).expect("non-null function pointer")(ssh);
    }
    libc::free((*authctxt).methoddata);
    (*authctxt).methoddata = 0 as *mut libc::c_void;
    if authlist.is_null() {
        authlist = (*authctxt).authlist;
    } else {
        libc::free((*authctxt).authlist as *mut libc::c_void);
        (*authctxt).authlist = authlist;
    }
    loop {
        let mut method: *mut Authmethod = authmethod_get(authlist);
        if method.is_null() {
            sshfatal(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"userauth\0")).as_ptr(),
                552 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s@%s: Permission denied (%s).\0" as *const u8 as *const libc::c_char,
                (*authctxt).server_user,
                (*authctxt).host,
                authlist,
            );
        }
        (*authctxt).method = method;
        ssh_dispatch_range(
            ssh,
            60 as libc::c_int as u_int,
            79 as libc::c_int as u_int,
            None,
        );
        if ((*method).userauth).expect("non-null function pointer")(ssh) != 0 as libc::c_int {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"userauth\0")).as_ptr(),
                561 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"we sent a %s packet, wait for reply\0" as *const u8 as *const libc::c_char,
                (*method).name,
            );
            break;
        } else {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"userauth\0")).as_ptr(),
                564 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"we did not send a packet, disable method\0" as *const u8 as *const libc::c_char,
            );
            (*method).enabled = 0 as *mut libc::c_int;
        }
    }
}
unsafe extern "C" fn input_userauth_error(
    mut type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut _ssh: *mut ssh,
) -> libc::c_int {
    sshfatal(
        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"input_userauth_error\0"))
            .as_ptr(),
        573 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_FATAL,
        0 as *const libc::c_char,
        b"bad message during authentication: type %d\0" as *const u8 as *const libc::c_char,
        type_0,
    );
}
unsafe extern "C" fn input_userauth_banner(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut msg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"input_userauth_banner\0"))
            .as_ptr(),
        584 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    r = crate::packet::sshpkt_get_cstring(ssh, &mut msg, &mut len);
    if !(r != 0 as libc::c_int || {
        r = crate::packet::sshpkt_get_cstring(ssh, 0 as *mut *mut libc::c_char, 0 as *mut size_t);
        r != 0 as libc::c_int
    }) {
        if len > 0 as libc::c_int as libc::c_ulong
            && options.log_level as libc::c_int >= SYSLOG_LEVEL_INFO as libc::c_int
        {
            fmprintf(stderr, b"%s\0" as *const u8 as *const libc::c_char, msg);
        }
        r = 0 as libc::c_int;
    }
    libc::free(msg as *mut libc::c_void);
    return r;
}
unsafe extern "C" fn input_userauth_success(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    if authctxt.is_null() {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"input_userauth_success\0",
            ))
            .as_ptr(),
            602 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no authentication context\0" as *const u8 as *const libc::c_char,
        );
    }
    libc::free((*authctxt).authlist as *mut libc::c_void);
    (*authctxt).authlist = 0 as *mut libc::c_char;
    if !((*authctxt).method).is_null() && ((*(*authctxt).method).cleanup).is_some() {
        ((*(*authctxt).method).cleanup).expect("non-null function pointer")(ssh);
    }
    libc::free((*authctxt).methoddata);
    (*authctxt).methoddata = 0 as *mut libc::c_void;
    (*authctxt).success = 1 as libc::c_int;
    return 0 as libc::c_int;
}
unsafe extern "C" fn input_userauth_failure(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut authlist: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut partial: u_char = 0;
    if authctxt.is_null() {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"input_userauth_failure\0",
            ))
            .as_ptr(),
            636 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"input_userauth_failure: no authentication context\0" as *const u8
                as *const libc::c_char,
        );
    }
    if !(crate::packet::sshpkt_get_cstring(ssh, &mut authlist, 0 as *mut size_t)
        != 0 as libc::c_int
        || sshpkt_get_u8(ssh, &mut partial) != 0 as libc::c_int
        || crate::packet::sshpkt_get_end(ssh) != 0 as libc::c_int)
    {
        if partial as libc::c_int != 0 as libc::c_int {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"input_userauth_failure\0",
                ))
                .as_ptr(),
                645 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_VERBOSE,
                0 as *const libc::c_char,
                b"Authenticated using \"%s\" with partial success.\0" as *const u8
                    as *const libc::c_char,
                (*(*authctxt).method).name,
            );
            pubkey_reset(authctxt);
        }
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"input_userauth_failure\0",
            ))
            .as_ptr(),
            649 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Authentications that can continue: %s\0" as *const u8 as *const libc::c_char,
            authlist,
        );
        userauth(ssh, authlist);
        authlist = 0 as *mut libc::c_char;
    }
    libc::free(authlist as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn format_identity(mut id: *mut Identity) -> *mut libc::c_char {
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut note: *const libc::c_char = b"\0" as *const u8 as *const libc::c_char;
    if !((*id).key).is_null() {
        fp = crate::sshkey::sshkey_fingerprint((*id).key, options.fingerprint_hash, SSH_FP_DEFAULT);
    }
    if !((*id).key).is_null() {
        if (*(*id).key).flags & 0x1 as libc::c_int != 0 as libc::c_int {
            note = b" token\0" as *const u8 as *const libc::c_char;
        } else if sshkey_is_sk((*id).key) != 0 {
            note = b" authenticator\0" as *const u8 as *const libc::c_char;
        }
    }
    crate::xmalloc::xasprintf(
        &mut ret as *mut *mut libc::c_char,
        b"%s %s%s%s%s%s%s\0" as *const u8 as *const libc::c_char,
        (*id).filename,
        if !((*id).key).is_null() {
            crate::sshkey::sshkey_type((*id).key)
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*id).key).is_null() {
            b" \0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !fp.is_null() {
            fp as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if (*id).userprovided != 0 {
            b" explicit\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        note,
        if (*id).agent_fd != -(1 as libc::c_int) {
            b" agent\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    libc::free(fp as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn input_userauth_pk_ok(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut id: *mut Identity = 0 as *mut Identity;
    let mut pktype: libc::c_int = 0;
    let mut found: libc::c_int = 0 as libc::c_int;
    let mut sent: libc::c_int = 0 as libc::c_int;
    let mut blen: size_t = 0;
    let mut pkalg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ident: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pkblob: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    if authctxt.is_null() {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"input_userauth_pk_ok\0"))
                .as_ptr(),
            701 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"input_userauth_pk_ok: no authentication context\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = crate::packet::sshpkt_get_cstring(ssh, &mut pkalg, 0 as *mut size_t);
    if !(r != 0 as libc::c_int
        || {
            r = sshpkt_get_string(ssh, &mut pkblob, &mut blen);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        })
    {
        pktype = sshkey_type_from_name(pkalg);
        if pktype == KEY_UNSPEC as libc::c_int {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"input_userauth_pk_ok\0",
                ))
                .as_ptr(),
                709 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"server sent unknown pkalg %s\0" as *const u8 as *const libc::c_char,
                pkalg,
            );
        } else {
            r = sshkey_from_blob(pkblob, blen, &mut key);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"input_userauth_pk_ok\0",
                    ))
                    .as_ptr(),
                    713 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    ssh_err(r),
                    b"no key from blob. pkalg %s\0" as *const u8 as *const libc::c_char,
                    pkalg,
                );
            } else if (*key).type_0 != pktype {
                crate::log::sshlog(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<
                        &[u8; 21],
                        &[libc::c_char; 21],
                    >(b"input_userauth_pk_ok\0"))
                        .as_ptr(),
                    719 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"input_userauth_pk_ok: type mismatch for decoded key (received %d, expected %d)\0"
                        as *const u8 as *const libc::c_char,
                    (*key).type_0,
                    pktype,
                );
            } else {
                id = *(*((*authctxt).keys.tqh_last as *mut idlist)).tqh_last;
                while !id.is_null() {
                    if sshkey_equal(key, (*id).key) != 0 {
                        found = 1 as libc::c_int;
                        break;
                    } else {
                        id = *(*((*id).next.tqe_prev as *mut idlist)).tqh_last;
                    }
                }
                if found == 0 || id.is_null() {
                    fp = crate::sshkey::sshkey_fingerprint(
                        key,
                        options.fingerprint_hash,
                        SSH_FP_DEFAULT,
                    );
                    crate::log::sshlog(
                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"input_userauth_pk_ok\0",
                        ))
                        .as_ptr(),
                        738 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"server replied with unknown key: %s %s\0" as *const u8
                            as *const libc::c_char,
                        crate::sshkey::sshkey_type(key),
                        if fp.is_null() {
                            b"<ERROR>\0" as *const u8 as *const libc::c_char
                        } else {
                            fp as *const libc::c_char
                        },
                    );
                } else {
                    ident = format_identity(id);
                    crate::log::sshlog(
                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"input_userauth_pk_ok\0",
                        ))
                        .as_ptr(),
                        742 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"Server accepts key: %s\0" as *const u8 as *const libc::c_char,
                        ident,
                    );
                    sent = sign_and_send_pubkey(ssh, id);
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    crate::sshkey::sshkey_free(key);
    libc::free(ident as *mut libc::c_void);
    libc::free(fp as *mut libc::c_void);
    libc::free(pkalg as *mut libc::c_void);
    libc::free(pkblob as *mut libc::c_void);
    if r == 0 as libc::c_int && sent == 0 as libc::c_int {
        userauth(ssh, 0 as *mut libc::c_char);
    }
    return r;
}
unsafe extern "C" fn userauth_none(mut ssh: *mut ssh) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut r: libc::c_int = 0;
    r = crate::packet::sshpkt_start(ssh, 50 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_put_cstring(
                ssh,
                (*authctxt).server_user as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_cstring(ssh, (*authctxt).service as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_cstring(
                ssh,
                (*(*authctxt).method).name as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"userauth_none\0"))
                .as_ptr(),
            1038 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send packet\0" as *const u8 as *const libc::c_char,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn userauth_passwd(mut ssh: *mut ssh) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut password: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut prompt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *const libc::c_char = if !(options.host_key_alias).is_null() {
        options.host_key_alias as *const libc::c_char
    } else {
        (*authctxt).host
    };
    let mut r: libc::c_int = 0;
    let fresh0 = (*authctxt).attempt_passwd;
    (*authctxt).attempt_passwd = (*authctxt).attempt_passwd + 1;
    if fresh0 >= options.number_of_password_prompts {
        return 0 as libc::c_int;
    }
    if (*authctxt).attempt_passwd != 1 as libc::c_int {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_passwd\0"))
                .as_ptr(),
            1055 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Permission denied, please try again.\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::xmalloc::xasprintf(
        &mut prompt as *mut *mut libc::c_char,
        b"%s@%s's password: \0" as *const u8 as *const libc::c_char,
        (*authctxt).server_user,
        host,
    );
    password = read_passphrase(prompt, 0 as libc::c_int);
    r = crate::packet::sshpkt_start(ssh, 50 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_put_cstring(
                ssh,
                (*authctxt).server_user as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_cstring(ssh, (*authctxt).service as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_cstring(
                ssh,
                (*(*authctxt).method).name as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_u8(ssh, 0 as libc::c_int as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_cstring(ssh, password as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_add_padding(ssh, 64 as libc::c_int as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_passwd\0"))
                .as_ptr(),
            1067 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send packet\0" as *const u8 as *const libc::c_char,
        );
    }
    libc::free(prompt as *mut libc::c_void);
    if !password.is_null() {
        freezero(password as *mut libc::c_void, strlen(password));
    }
    crate::dispatch::ssh_dispatch_set(
        ssh,
        60 as libc::c_int,
        Some(
            input_userauth_passwd_changereq
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn input_userauth_passwd_changereq(
    mut _type_0: libc::c_int,
    mut _seqnr: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut current_block: u64;
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut info: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut lang: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut password: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut retype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut prompt: [libc::c_char; 256] = [0; 256];
    let mut host: *const libc::c_char = 0 as *const libc::c_char;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
            b"input_userauth_passwd_changereq\0",
        ))
        .as_ptr(),
        1091 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"input_userauth_passwd_changereq\0" as *const u8 as *const libc::c_char,
    );
    if authctxt.is_null() {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
                b"input_userauth_passwd_changereq\0",
            ))
            .as_ptr(),
            1095 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"input_userauth_passwd_changereq: no authentication context\0" as *const u8
                as *const libc::c_char,
        );
    }
    host = if !(options.host_key_alias).is_null() {
        options.host_key_alias as *const libc::c_char
    } else {
        (*authctxt).host
    };
    r = crate::packet::sshpkt_get_cstring(ssh, &mut info, 0 as *mut size_t);
    if !(r != 0 as libc::c_int || {
        r = crate::packet::sshpkt_get_cstring(ssh, &mut lang, 0 as *mut size_t);
        r != 0 as libc::c_int
    }) {
        if strlen(info) > 0 as libc::c_int as libc::c_ulong {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
                    b"input_userauth_passwd_changereq\0",
                ))
                .as_ptr(),
                1102 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"%s\0" as *const u8 as *const libc::c_char,
                info,
            );
        }
        r = crate::packet::sshpkt_start(ssh, 50 as libc::c_int as u_char);
        if !(r != 0 as libc::c_int
            || {
                r = crate::packet::sshpkt_put_cstring(
                    ssh,
                    (*authctxt).server_user as *const libc::c_void,
                );
                r != 0 as libc::c_int
            }
            || {
                r = crate::packet::sshpkt_put_cstring(
                    ssh,
                    (*authctxt).service as *const libc::c_void,
                );
                r != 0 as libc::c_int
            }
            || {
                r = crate::packet::sshpkt_put_cstring(
                    ssh,
                    (*(*authctxt).method).name as *const libc::c_void,
                );
                r != 0 as libc::c_int
            }
            || {
                r = crate::packet::sshpkt_put_u8(ssh, 1 as libc::c_int as u_char);
                r != 0 as libc::c_int
            })
        {
            libc::snprintf(
                prompt.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
                b"Enter %.30s@%.128s's old password: \0" as *const u8 as *const libc::c_char,
                (*authctxt).server_user,
                host,
            );
            password = read_passphrase(prompt.as_mut_ptr(), 0 as libc::c_int);
            r = crate::packet::sshpkt_put_cstring(ssh, password as *const libc::c_void);
            if !(r != 0 as libc::c_int) {
                freezero(password as *mut libc::c_void, strlen(password));
                password = 0 as *mut libc::c_char;
                loop {
                    if !password.is_null() {
                        current_block = 15089075282327824602;
                        break;
                    }
                    libc::snprintf(
                        prompt.as_mut_ptr(),
                        ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
                        b"Enter %.30s@%.128s's new password: \0" as *const u8
                            as *const libc::c_char,
                        (*authctxt).server_user,
                        host,
                    );
                    password = read_passphrase(prompt.as_mut_ptr(), 0x4 as libc::c_int);
                    if password.is_null() {
                        r = 0 as libc::c_int;
                        current_block = 9935336519555149225;
                        break;
                    } else {
                        libc::snprintf(
                            prompt.as_mut_ptr(),
                            ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
                            b"Retype %.30s@%.128s's new password: \0" as *const u8
                                as *const libc::c_char,
                            (*authctxt).server_user,
                            host,
                        );
                        retype = read_passphrase(prompt.as_mut_ptr(), 0 as libc::c_int);
                        if libc::strcmp(password, retype) != 0 as libc::c_int {
                            freezero(password as *mut libc::c_void, strlen(password));
                            crate::log::sshlog(
                                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
                                    b"input_userauth_passwd_changereq\0",
                                ))
                                .as_ptr(),
                                1135 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_INFO,
                                0 as *const libc::c_char,
                                b"Mismatch; try again, EOF to quit.\0" as *const u8
                                    as *const libc::c_char,
                            );
                            password = 0 as *mut libc::c_char;
                        }
                        freezero(retype as *mut libc::c_void, strlen(retype));
                    }
                }
                match current_block {
                    9935336519555149225 => {}
                    _ => {
                        r = crate::packet::sshpkt_put_cstring(ssh, password as *const libc::c_void);
                        if !(r != 0 as libc::c_int
                            || {
                                r = sshpkt_add_padding(ssh, 64 as libc::c_int as u_char);
                                r != 0 as libc::c_int
                            }
                            || {
                                r = crate::packet::sshpkt_send(ssh);
                                r != 0 as libc::c_int
                            })
                        {
                            crate::dispatch::ssh_dispatch_set(
                                ssh,
                                60 as libc::c_int,
                                Some(
                                    input_userauth_passwd_changereq
                                        as unsafe extern "C" fn(
                                            libc::c_int,
                                            u_int32_t,
                                            *mut ssh,
                                        )
                                            -> libc::c_int,
                                ),
                            );
                            r = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    if !password.is_null() {
        freezero(password as *mut libc::c_void, strlen(password));
    }
    libc::free(info as *mut libc::c_void);
    libc::free(lang as *mut libc::c_void);
    return r;
}
unsafe extern "C" fn key_sig_algorithm(
    mut ssh: *mut ssh,
    mut key: *const crate::sshkey::sshkey,
) -> *mut libc::c_char {
    let mut allowed: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut oallowed: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut alg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut server_sig_algs: *const libc::c_char = 0 as *const libc::c_char;
    if ssh.is_null()
        || ((*(*ssh).kex).server_sig_algs).is_null()
        || (*key).type_0 != KEY_RSA as libc::c_int && (*key).type_0 != KEY_RSA_CERT as libc::c_int
        || (*key).type_0 == KEY_RSA_CERT as libc::c_int && (*ssh).compat & 0x2 as libc::c_int != 0
    {
        return match_list(
            sshkey_ssh_name(key),
            options.pubkey_accepted_algos,
            0 as *mut u_int,
        );
    }
    server_sig_algs = (*(*ssh).kex).server_sig_algs;
    if (*key).type_0 == KEY_RSA as libc::c_int && (*ssh).compat & 0x4 as libc::c_int != 0 {
        server_sig_algs = b"rsa-sha2-256,rsa-sha2-512\0" as *const u8 as *const libc::c_char;
    }
    allowed = crate::xmalloc::xstrdup(options.pubkey_accepted_algos);
    oallowed = allowed;
    loop {
        cp = strsep(&mut allowed, b",\0" as *const u8 as *const libc::c_char);
        if cp.is_null() {
            break;
        }
        if sshkey_type_from_name(cp) != (*key).type_0 {
            continue;
        }
        tmp = match_list(sshkey_sigalg_by_name(cp), server_sig_algs, 0 as *mut u_int);
        if !tmp.is_null() {
            alg = crate::xmalloc::xstrdup(cp);
        }
        libc::free(tmp as *mut libc::c_void);
        if !alg.is_null() {
            break;
        }
    }
    libc::free(oallowed as *mut libc::c_void);
    return alg;
}
unsafe extern "C" fn identity_sign(
    mut id: *mut identity,
    mut sigp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut data: *const u_char,
    mut datalen: size_t,
    mut compat: u_int,
    mut alg: *const libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut sign_key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut prv: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut is_agent: libc::c_int = 0 as libc::c_int;
    let mut retried: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut notifier: *mut notifier_ctx = 0 as *mut notifier_ctx;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut prompt: *mut libc::c_char = 0 as *mut libc::c_char;
    *sigp = 0 as *mut u_char;
    *lenp = 0 as libc::c_int as size_t;
    if !((*id).key).is_null() && (*id).agent_fd != -(1 as libc::c_int) {
        return ssh_agent_sign(
            (*id).agent_fd,
            (*id).key,
            sigp,
            lenp,
            data,
            datalen,
            alg,
            compat,
        );
    }
    if !((*id).key).is_null()
        && ((*id).isprivate != 0 || (*(*id).key).flags & 0x1 as libc::c_int != 0)
    {
        sign_key = (*id).key;
        is_agent = 1 as libc::c_int;
        current_block = 14674158960904727851;
    } else {
        prv = load_identity_file(id);
        if prv.is_null() {
            return -(46 as libc::c_int);
        }
        if !((*id).key).is_null() && crate::sshkey::sshkey_equal_public(prv, (*id).key) == 0 {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"identity_sign\0"))
                    .as_ptr(),
                1244 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"private key %s contents do not match public\0" as *const u8
                    as *const libc::c_char,
                (*id).filename,
            );
            r = -(46 as libc::c_int);
            current_block = 7499137372788269677;
        } else {
            sign_key = prv;
            current_block = 14674158960904727851;
        }
    }
    loop {
        match current_block {
            7499137372788269677 => {
                libc::free(prompt as *mut libc::c_void);
                break;
            }
            _ => {
                if is_agent == 0
                    && sshkey_is_sk(sign_key) != 0
                    && (*sign_key).sk_flags as libc::c_int & 0x1 as libc::c_int != 0
                {
                    fp = crate::sshkey::sshkey_fingerprint(
                        sign_key,
                        options.fingerprint_hash,
                        SSH_FP_DEFAULT,
                    );
                    if fp.is_null() {
                        sshfatal(
                            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(
                                b"identity_sign\0",
                            ))
                            .as_ptr(),
                            1257 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"fingerprint failed\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    notifier = notify_start(
                        options.batch_mode,
                        b"Confirm user presence for key %s %s\0" as *const u8
                            as *const libc::c_char,
                        crate::sshkey::sshkey_type(sign_key),
                        fp,
                    );
                    libc::free(fp as *mut libc::c_void);
                }
                r = sshkey_sign(
                    sign_key,
                    sigp,
                    lenp,
                    data,
                    datalen,
                    alg,
                    options.sk_provider,
                    pin,
                    compat,
                );
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(
                            b"identity_sign\0",
                        ))
                        .as_ptr(),
                        1265 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        ssh_err(r),
                        b"sshkey_sign\0" as *const u8 as *const libc::c_char,
                    );
                    if !(retried == 0
                        && pin.is_null()
                        && is_agent == 0
                        && sshkey_is_sk(sign_key) != 0
                        && r == -(43 as libc::c_int))
                    {
                        current_block = 7499137372788269677;
                        continue;
                    }
                    notify_complete(notifier, 0 as *const libc::c_char);
                    notifier = 0 as *mut notifier_ctx;
                    crate::xmalloc::xasprintf(
                        &mut prompt as *mut *mut libc::c_char,
                        b"Enter PIN for %s key %s: \0" as *const u8 as *const libc::c_char,
                        crate::sshkey::sshkey_type(sign_key),
                        (*id).filename,
                    );
                    pin = read_passphrase(prompt, 0 as libc::c_int);
                    retried = 1 as libc::c_int;
                    current_block = 14674158960904727851;
                } else {
                    r = sshkey_check_sigtype(*sigp, *lenp, alg);
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(
                                b"identity_sign\0",
                            ))
                            .as_ptr(),
                            1285 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            ssh_err(r),
                            b"sshkey_check_sigtype\0" as *const u8 as *const libc::c_char,
                        );
                        current_block = 7499137372788269677;
                    } else {
                        r = 0 as libc::c_int;
                        current_block = 7499137372788269677;
                    }
                }
            }
        }
    }
    if !pin.is_null() {
        freezero(pin as *mut libc::c_void, strlen(pin));
    }
    notify_complete(
        notifier,
        if r == 0 as libc::c_int {
            b"User presence confirmed\0" as *const u8 as *const libc::c_char
        } else {
            0 as *const libc::c_char
        },
    );
    crate::sshkey::sshkey_free(prv);
    return r;
}
unsafe extern "C" fn id_filename_matches(
    mut id: *mut Identity,
    mut private_id: *mut Identity,
) -> libc::c_int {
    static mut suffixes: [*const libc::c_char; 3] = [
        b".pub\0" as *const u8 as *const libc::c_char,
        b"-cert.pub\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    let mut len: size_t = strlen((*id).filename);
    let mut plen: size_t = strlen((*private_id).filename);
    let mut i: size_t = 0;
    let mut slen: size_t = 0;
    if libc::strcmp((*id).filename, (*private_id).filename) == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    i = 0 as libc::c_int as size_t;
    while !(suffixes[i as usize]).is_null() {
        slen = strlen(suffixes[i as usize]);
        if len > slen
            && plen == len.wrapping_sub(slen)
            && libc::strcmp(
                ((*id).filename).offset(len.wrapping_sub(slen) as isize),
                suffixes[i as usize],
            ) == 0 as libc::c_int
            && memcmp(
                (*id).filename as *const libc::c_void,
                (*private_id).filename as *const libc::c_void,
                plen,
            ) == 0 as libc::c_int
        {
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn sign_and_send_pubkey(mut ssh: *mut ssh, mut id: *mut Identity) -> libc::c_int {
    let mut current_block: u64;
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut private_id: *mut Identity = 0 as *mut Identity;
    let mut sign_id: *mut Identity = 0 as *mut Identity;
    let mut signature: *mut u_char = 0 as *mut u_char;
    let mut slen: size_t = 0 as libc::c_int as size_t;
    let mut skip: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    let mut fallback_sigtype: libc::c_int = 0;
    let mut sent: libc::c_int = 0 as libc::c_int;
    let mut alg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut loc: *const libc::c_char = b"\0" as *const u8 as *const libc::c_char;
    let mut method: *const libc::c_char = b"publickey\0" as *const u8 as *const libc::c_char;
    let mut hostbound: libc::c_int = 0 as libc::c_int;
    if (*(*ssh).kex).flags & 0x4 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
        && options.pubkey_authentication & 0x2 as libc::c_int != 0 as libc::c_int
    {
        hostbound = 1 as libc::c_int;
        method = b"publickey-hostbound-v00@openssh.com\0" as *const u8 as *const libc::c_char;
    }
    fp = crate::sshkey::sshkey_fingerprint((*id).key, options.fingerprint_hash, SSH_FP_DEFAULT);
    if fp.is_null() {
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"sign_and_send_pubkey\0"))
            .as_ptr(),
        1342 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"using %s with %s %s\0" as *const u8 as *const libc::c_char,
        method,
        crate::sshkey::sshkey_type((*id).key),
        fp,
    );
    if sshkey_is_cert((*id).key) != 0 {
        private_id = (*authctxt).keys.tqh_first;
        while !private_id.is_null() {
            if crate::sshkey::sshkey_equal_public((*id).key, (*private_id).key) != 0
                && (*(*id).key).type_0 != (*(*private_id).key).type_0
            {
                sign_id = private_id;
                break;
            } else {
                private_id = (*private_id).next.tqe_next;
            }
        }
        if sign_id.is_null()
            && (*id).isprivate == 0
            && (*id).agent_fd == -(1 as libc::c_int)
            && (*(*id).key).flags & 0x1 as libc::c_int == 0 as libc::c_int
        {
            private_id = (*authctxt).keys.tqh_first;
            while !private_id.is_null() {
                if ((*private_id).key).is_null() && id_filename_matches(id, private_id) != 0 {
                    sign_id = private_id;
                    break;
                } else {
                    private_id = (*private_id).next.tqe_next;
                }
            }
        }
        if !sign_id.is_null() {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"sign_and_send_pubkey\0",
                ))
                .as_ptr(),
                1381 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"using private key \"%s\"%s for certificate\0" as *const u8 as *const libc::c_char,
                (*sign_id).filename,
                if (*sign_id).agent_fd != -(1 as libc::c_int) {
                    b" from agent\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
            );
        } else {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"sign_and_send_pubkey\0",
                ))
                .as_ptr(),
                1384 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"no separate private key for certificate \"%s\"\0" as *const u8
                    as *const libc::c_char,
                (*id).filename,
            );
        }
    }
    if sign_id.is_null() {
        sign_id = id;
    }
    fallback_sigtype = 0 as libc::c_int;
    loop {
        if !(fallback_sigtype <= 1 as libc::c_int) {
            current_block = 9859671972921157070;
            break;
        }
        libc::free(alg as *mut libc::c_void);
        slen = 0 as libc::c_int as size_t;
        signature = 0 as *mut u_char;
        alg = key_sig_algorithm(
            if fallback_sigtype != 0 {
                0 as *mut ssh
            } else {
                ssh
            },
            (*id).key,
        );
        if alg.is_null() {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"sign_and_send_pubkey\0",
                ))
                .as_ptr(),
                1402 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"no mutual signature supported\0" as *const u8 as *const libc::c_char,
            );
            current_block = 5830272081365907917;
            break;
        } else {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"sign_and_send_pubkey\0",
                ))
                .as_ptr(),
                1405 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"signing using %s %s\0" as *const u8 as *const libc::c_char,
                alg,
                fp,
            );
            crate::sshbuf::sshbuf_free(b);
            b = crate::sshbuf::sshbuf_new();
            if b.is_null() {
                sshfatal(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"sign_and_send_pubkey\0",
                    ))
                    .as_ptr(),
                    1409 as libc::c_int,
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
                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"sign_and_send_pubkey\0",
                        ))
                        .as_ptr(),
                        1412 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"sshbuf_putb\0" as *const u8 as *const libc::c_char,
                    );
                }
            } else {
                r = sshbuf_put_stringb(b, (*(*ssh).kex).session_id);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"sign_and_send_pubkey\0",
                        ))
                        .as_ptr(),
                        1416 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"sshbuf_put_stringb\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            skip = crate::sshbuf::sshbuf_len(b);
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(b, 50 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_cstring(b, (*authctxt).server_user);
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_cstring(b, (*authctxt).service);
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_cstring(b, method);
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u8(b, 1 as libc::c_int as u_char);
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_cstring(b, alg);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshkey_puts((*id).key, b);
                    r != 0 as libc::c_int
                }
            {
                sshfatal(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"sign_and_send_pubkey\0",
                    ))
                    .as_ptr(),
                    1426 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"assemble signed data\0" as *const u8 as *const libc::c_char,
                );
            }
            if hostbound != 0 {
                if ((*(*ssh).kex).initial_hostkey).is_null() {
                    sshfatal(
                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"sign_and_send_pubkey\0",
                        ))
                        .as_ptr(),
                        1431 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"internal error: initial hostkey not recorded\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                r = sshkey_puts((*(*ssh).kex).initial_hostkey, b);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"sign_and_send_pubkey\0",
                        ))
                        .as_ptr(),
                        1434 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"assemble %s hostkey\0" as *const u8 as *const libc::c_char,
                        method,
                    );
                }
            }
            r = identity_sign(
                sign_id,
                &mut signature,
                &mut slen,
                crate::sshbuf::sshbuf_ptr(b),
                crate::sshbuf::sshbuf_len(b),
                (*ssh).compat as u_int,
                alg,
            );
            if r == 0 as libc::c_int {
                current_block = 9859671972921157070;
                break;
            }
            if r == -(46 as libc::c_int) {
                current_block = 5830272081365907917;
                break;
            }
            if r == -(58 as libc::c_int) && fallback_sigtype == 0 {
                if (*sign_id).agent_fd != -(1 as libc::c_int) {
                    loc = b"agent \0" as *const u8 as *const libc::c_char;
                } else if (*(*sign_id).key).flags & 0x1 as libc::c_int != 0 as libc::c_int {
                    loc = b"token \0" as *const u8 as *const libc::c_char;
                }
                crate::log::sshlog(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"sign_and_send_pubkey\0",
                    ))
                    .as_ptr(),
                    1450 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"%skey %s %s returned incorrect signature type\0" as *const u8
                        as *const libc::c_char,
                    loc,
                    crate::sshkey::sshkey_type((*id).key),
                    fp,
                );
                fallback_sigtype += 1;
                fallback_sigtype;
            } else {
                crate::log::sshlog(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"sign_and_send_pubkey\0",
                    ))
                    .as_ptr(),
                    1455 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"signing failed for %s \"%s\"%s\0" as *const u8 as *const libc::c_char,
                    crate::sshkey::sshkey_type((*sign_id).key),
                    (*sign_id).filename,
                    if (*id).agent_fd != -(1 as libc::c_int) {
                        b" from agent\0" as *const u8 as *const libc::c_char
                    } else {
                        b"\0" as *const u8 as *const libc::c_char
                    },
                );
                current_block = 5830272081365907917;
                break;
            }
        }
    }
    match current_block {
        9859671972921157070 => {
            if slen == 0 as libc::c_int as libc::c_ulong || signature.is_null() {
                sshfatal(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"sign_and_send_pubkey\0",
                    ))
                    .as_ptr(),
                    1459 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"no signature\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_string(
                b,
                signature as *const libc::c_void,
                slen,
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"sign_and_send_pubkey\0",
                    ))
                    .as_ptr(),
                    1463 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"append signature\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf::sshbuf_consume(
                b,
                skip.wrapping_add(1 as libc::c_int as libc::c_ulong),
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"sign_and_send_pubkey\0",
                    ))
                    .as_ptr(),
                    1470 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"consume\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::packet::sshpkt_start(ssh, 50 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = sshpkt_putb(ssh, b);
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::packet::sshpkt_send(ssh);
                    r != 0 as libc::c_int
                }
            {
                sshfatal(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"sign_and_send_pubkey\0",
                    ))
                    .as_ptr(),
                    1476 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"enqueue request\0" as *const u8 as *const libc::c_char,
                );
            }
            sent = 1 as libc::c_int;
        }
        _ => {}
    }
    libc::free(fp as *mut libc::c_void);
    libc::free(alg as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(b);
    freezero(signature as *mut libc::c_void, slen);
    return sent;
}
unsafe extern "C" fn send_pubkey_test(mut ssh: *mut ssh, mut id: *mut Identity) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut blob: *mut u_char = 0 as *mut u_char;
    let mut alg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut bloblen: size_t = 0;
    let mut have_sig: u_int = 0 as libc::c_int as u_int;
    let mut sent: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    alg = key_sig_algorithm(ssh, (*id).key);
    if alg.is_null() {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"send_pubkey_test\0"))
                .as_ptr(),
            1500 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"no mutual signature algorithm\0" as *const u8 as *const libc::c_char,
        );
    } else {
        r = sshkey_to_blob((*id).key, &mut blob, &mut bloblen);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"send_pubkey_test\0"))
                    .as_ptr(),
                1506 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"cannot handle key\0" as *const u8 as *const libc::c_char,
            );
        } else {
            crate::dispatch::ssh_dispatch_set(
                ssh,
                60 as libc::c_int,
                Some(
                    input_userauth_pk_ok
                        as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
                ),
            );
            r = crate::packet::sshpkt_start(ssh, 50 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = crate::packet::sshpkt_put_cstring(
                        ssh,
                        (*authctxt).server_user as *const libc::c_void,
                    );
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::packet::sshpkt_put_cstring(
                        ssh,
                        (*authctxt).service as *const libc::c_void,
                    );
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::packet::sshpkt_put_cstring(
                        ssh,
                        (*(*authctxt).method).name as *const libc::c_void,
                    );
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::packet::sshpkt_put_u8(ssh, have_sig as u_char);
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::packet::sshpkt_put_cstring(ssh, alg as *const libc::c_void);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_string(ssh, blob as *const libc::c_void, bloblen);
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::packet::sshpkt_send(ssh);
                    r != 0 as libc::c_int
                }
            {
                sshfatal(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"send_pubkey_test\0",
                    ))
                    .as_ptr(),
                    1520 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"send packet\0" as *const u8 as *const libc::c_char,
                );
            }
            sent = 1 as libc::c_int;
        }
    }
    libc::free(alg as *mut libc::c_void);
    libc::free(blob as *mut libc::c_void);
    return sent;
}
unsafe extern "C" fn load_identity_file(mut id: *mut Identity) -> *mut crate::sshkey::sshkey {
    let mut private: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut prompt: [libc::c_char; 300] = [0; 300];
    let mut passphrase: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut quit: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if libc::stat((*id).filename, &mut st) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"load_identity_file\0"))
                .as_ptr(),
            1540 as libc::c_int,
            0 as libc::c_int,
            (if (*id).userprovided != 0 {
                SYSLOG_LEVEL_INFO as libc::c_int
            } else {
                SYSLOG_LEVEL_DEBUG3 as libc::c_int
            }) as LogLevel,
            0 as *const libc::c_char,
            b"no such identity: %s: %s\0" as *const u8 as *const libc::c_char,
            (*id).filename,
            libc::strerror(*libc::__errno_location()),
        );
        return 0 as *mut crate::sshkey::sshkey;
    }
    libc::snprintf(
        prompt.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 300]>() as usize,
        b"Enter passphrase for key '%.100s': \0" as *const u8 as *const libc::c_char,
        (*id).filename,
    );
    i = 0 as libc::c_int;
    while i <= options.number_of_password_prompts {
        if i == 0 as libc::c_int {
            passphrase = b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        } else {
            passphrase = read_passphrase(prompt.as_mut_ptr(), 0 as libc::c_int);
            if *passphrase as libc::c_int == '\0' as i32 {
                crate::log::sshlog(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"load_identity_file\0",
                    ))
                    .as_ptr(),
                    1551 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"no passphrase given, try next key\0" as *const u8 as *const libc::c_char,
                );
                libc::free(passphrase as *mut libc::c_void);
                break;
            }
        }
        let mut current_block_16: u64;
        r = sshkey_load_private_type(
            KEY_UNSPEC as libc::c_int,
            (*id).filename,
            passphrase,
            &mut private,
            &mut comment,
        );
        match r {
            0 => {
                current_block_16 = 14576567515993809846;
            }
            -43 => {
                if options.batch_mode != 0 {
                    quit = 1 as libc::c_int;
                } else if i != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"load_identity_file\0",
                        ))
                        .as_ptr(),
                        1566 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"bad passphrase given, try again...\0" as *const u8 as *const libc::c_char,
                    );
                }
                current_block_16 = 14576567515993809846;
            }
            -24 => {
                if *libc::__errno_location() == 2 as libc::c_int {
                    crate::log::sshlog(
                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"load_identity_file\0",
                        ))
                        .as_ptr(),
                        1570 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        ssh_err(r),
                        b"Load key \"%s\"\0" as *const u8 as *const libc::c_char,
                        (*id).filename,
                    );
                    quit = 1 as libc::c_int;
                    current_block_16 = 14576567515993809846;
                } else {
                    current_block_16 = 2599243031073004384;
                }
            }
            _ => {
                current_block_16 = 2599243031073004384;
            }
        }
        match current_block_16 {
            2599243031073004384 => {
                crate::log::sshlog(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"load_identity_file\0",
                    ))
                    .as_ptr(),
                    1576 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"Load key \"%s\"\0" as *const u8 as *const libc::c_char,
                    (*id).filename,
                );
                quit = 1 as libc::c_int;
            }
            _ => {}
        }
        if !private.is_null() && sshkey_is_sk(private) != 0 && (options.sk_provider).is_null() {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"load_identity_file\0",
                ))
                .as_ptr(),
                1583 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"key \"%s\" is an authenticator-hosted key, but no provider specified\0"
                    as *const u8 as *const libc::c_char,
                (*id).filename,
            );
            crate::sshkey::sshkey_free(private);
            private = 0 as *mut crate::sshkey::sshkey;
            quit = 1 as libc::c_int;
        }
        if quit == 0 && {
            r = sshkey_check_rsa_length(private, options.required_rsa_size);
            r != 0 as libc::c_int
        } {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"load_identity_file\0",
                ))
                .as_ptr(),
                1590 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                ssh_err(r),
                b"Skipping key %s\0" as *const u8 as *const libc::c_char,
                (*id).filename,
            );
            crate::sshkey::sshkey_free(private);
            private = 0 as *mut crate::sshkey::sshkey;
            quit = 1 as libc::c_int;
        }
        if quit == 0
            && !private.is_null()
            && (*id).agent_fd == -(1 as libc::c_int)
            && !(!((*id).key).is_null() && (*id).isprivate != 0)
        {
            maybe_add_key_to_agent((*id).filename, private, comment, passphrase);
        }
        if i > 0 as libc::c_int {
            freezero(passphrase as *mut libc::c_void, strlen(passphrase));
        }
        libc::free(comment as *mut libc::c_void);
        if !private.is_null() || quit != 0 {
            break;
        }
        i += 1;
        i;
    }
    return private;
}
unsafe extern "C" fn key_type_allowed_by_config(
    mut key: *mut crate::sshkey::sshkey,
) -> libc::c_int {
    if match_pattern_list(
        sshkey_ssh_name(key),
        options.pubkey_accepted_algos,
        0 as libc::c_int,
    ) == 1 as libc::c_int
    {
        return 1 as libc::c_int;
    }
    match (*key).type_0 {
        0 => {
            if match_pattern_list(
                b"rsa-sha2-512\0" as *const u8 as *const libc::c_char,
                options.pubkey_accepted_algos,
                0 as libc::c_int,
            ) == 1 as libc::c_int
            {
                return 1 as libc::c_int;
            }
            if match_pattern_list(
                b"rsa-sha2-256\0" as *const u8 as *const libc::c_char,
                options.pubkey_accepted_algos,
                0 as libc::c_int,
            ) == 1 as libc::c_int
            {
                return 1 as libc::c_int;
            }
        }
        4 => {
            if match_pattern_list(
                b"rsa-sha2-512-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
                options.pubkey_accepted_algos,
                0 as libc::c_int,
            ) == 1 as libc::c_int
            {
                return 1 as libc::c_int;
            }
            if match_pattern_list(
                b"rsa-sha2-256-cert-v01@openssh.com\0" as *const u8 as *const libc::c_char,
                options.pubkey_accepted_algos,
                0 as libc::c_int,
            ) == 1 as libc::c_int
            {
                return 1 as libc::c_int;
            }
        }
        _ => {}
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn get_agent_identities(
    mut ssh: *mut ssh,
    mut agent_fdp: *mut libc::c_int,
    mut idlistp: *mut *mut ssh_identitylist,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut agent_fd: libc::c_int = 0;
    let mut idlist: *mut ssh_identitylist = 0 as *mut ssh_identitylist;
    r = ssh_get_authentication_socket(&mut agent_fd);
    if r != 0 as libc::c_int {
        if r != -(47 as libc::c_int) {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"get_agent_identities\0",
                ))
                .as_ptr(),
                1647 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                ssh_err(r),
                b"ssh_get_authentication_socket\0" as *const u8 as *const libc::c_char,
            );
        }
        return r;
    }
    r = ssh_agent_bind_hostkey(
        agent_fd,
        (*(*ssh).kex).initial_hostkey,
        (*(*ssh).kex).session_id,
        (*(*ssh).kex).initial_sig,
        0 as libc::c_int,
    );
    if r == 0 as libc::c_int {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"get_agent_identities\0"))
                .as_ptr(),
            1652 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"bound agent to hostkey\0" as *const u8 as *const libc::c_char,
        );
    } else {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"get_agent_identities\0"))
                .as_ptr(),
            1654 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            ssh_err(r),
            b"ssh_agent_bind_hostkey\0" as *const u8 as *const libc::c_char,
        );
    }
    r = ssh_fetch_identitylist(agent_fd, &mut idlist);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"get_agent_identities\0"))
                .as_ptr(),
            1657 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            ssh_err(r),
            b"ssh_fetch_identitylist\0" as *const u8 as *const libc::c_char,
        );
        close(agent_fd);
        return r;
    }
    *agent_fdp = agent_fd;
    *idlistp = idlist;
    crate::log::sshlog(
        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"get_agent_identities\0"))
            .as_ptr(),
        1664 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"agent returned %zu keys\0" as *const u8 as *const libc::c_char,
        (*idlist).nkeys,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn pubkey_prepare(mut ssh: *mut ssh, mut authctxt: *mut Authctxt) {
    let mut id: *mut identity = 0 as *mut identity;
    let mut id2: *mut identity = 0 as *mut identity;
    let mut tmp: *mut identity = 0 as *mut identity;
    let mut agent: idlist = idlist {
        tqh_first: 0 as *mut identity,
        tqh_last: 0 as *mut *mut identity,
    };
    let mut files: idlist = idlist {
        tqh_first: 0 as *mut identity,
        tqh_last: 0 as *mut *mut identity,
    };
    let mut preferred_0: *mut idlist = 0 as *mut idlist;
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut agent_fd: libc::c_int = -(1 as libc::c_int);
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut found: libc::c_int = 0;
    let mut j: size_t = 0;
    let mut idlist: *mut ssh_identitylist = 0 as *mut ssh_identitylist;
    let mut ident: *mut libc::c_char = 0 as *mut libc::c_char;
    agent.tqh_first = 0 as *mut identity;
    agent.tqh_last = &mut agent.tqh_first;
    files.tqh_first = 0 as *mut identity;
    files.tqh_last = &mut files.tqh_first;
    preferred_0 = &mut (*authctxt).keys;
    (*preferred_0).tqh_first = 0 as *mut identity;
    (*preferred_0).tqh_last = &mut (*preferred_0).tqh_first;
    i = 0 as libc::c_int;
    while i < options.num_identity_files {
        key = options.identity_keys[i as usize];
        if !key.is_null()
            && !((*key).cert).is_null()
            && (*(*key).cert).type_0 != 1 as libc::c_int as libc::c_uint
        {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"pubkey_prepare\0"))
                    .as_ptr(),
                1698 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"ignoring certificate %s: not a user certificate\0" as *const u8
                    as *const libc::c_char,
                options.identity_files[i as usize],
            );
        } else if !key.is_null() && sshkey_is_sk(key) != 0 && (options.sk_provider).is_null() {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<
                    &[u8; 15],
                    &[libc::c_char; 15],
                >(b"pubkey_prepare\0"))
                    .as_ptr(),
                1704 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"ignoring authenticator-hosted key %s as no SecurityKeyProvider has been specified\0"
                    as *const u8 as *const libc::c_char,
                options.identity_files[i as usize],
            );
        } else {
            options.identity_keys[i as usize] = 0 as *mut crate::sshkey::sshkey;
            id = crate::xmalloc::xcalloc(
                1 as libc::c_int as size_t,
                ::core::mem::size_of::<identity>() as libc::c_ulong,
            ) as *mut identity;
            (*id).agent_fd = -(1 as libc::c_int);
            (*id).key = key;
            (*id).filename = crate::xmalloc::xstrdup(options.identity_files[i as usize]);
            (*id).userprovided = options.identity_file_userprovided[i as usize];
            (*id).next.tqe_next = 0 as *mut identity;
            (*id).next.tqe_prev = files.tqh_last;
            *files.tqh_last = id;
            files.tqh_last = &mut (*id).next.tqe_next;
        }
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < options.num_certificate_files {
        key = options.certificates[i as usize];
        if sshkey_is_cert(key) == 0
            || ((*key).cert).is_null()
            || (*(*key).cert).type_0 != 1 as libc::c_int as libc::c_uint
        {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"pubkey_prepare\0"))
                    .as_ptr(),
                1721 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"ignoring certificate %s: not a user certificate\0" as *const u8
                    as *const libc::c_char,
                options.identity_files[i as usize],
            );
        } else if !key.is_null() && sshkey_is_sk(key) != 0 && (options.sk_provider).is_null() {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<
                    &[u8; 15],
                    &[libc::c_char; 15],
                >(b"pubkey_prepare\0"))
                    .as_ptr(),
                1728 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"ignoring authenticator-hosted key certificate %s as no SecurityKeyProvider has been specified\0"
                    as *const u8 as *const libc::c_char,
                options.identity_files[i as usize],
            );
        } else {
            id = crate::xmalloc::xcalloc(
                1 as libc::c_int as size_t,
                ::core::mem::size_of::<identity>() as libc::c_ulong,
            ) as *mut identity;
            (*id).agent_fd = -(1 as libc::c_int);
            (*id).key = key;
            (*id).filename = crate::xmalloc::xstrdup(options.certificate_files[i as usize]);
            (*id).userprovided = options.certificate_file_userprovided[i as usize];
            (*id).next.tqe_next = 0 as *mut identity;
            (*id).next.tqe_prev = (*preferred_0).tqh_last;
            *(*preferred_0).tqh_last = id;
            (*preferred_0).tqh_last = &mut (*id).next.tqe_next;
        }
        i += 1;
        i;
    }
    r = get_agent_identities(ssh, &mut agent_fd, &mut idlist);
    if r == 0 as libc::c_int {
        j = 0 as libc::c_int as size_t;
        while j < (*idlist).nkeys {
            r = sshkey_check_rsa_length(
                *((*idlist).keys).offset(j as isize),
                options.required_rsa_size,
            );
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"pubkey_prepare\0",
                    ))
                    .as_ptr(),
                    1744 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    ssh_err(r),
                    b"ignoring %s agent key\0" as *const u8 as *const libc::c_char,
                    sshkey_ssh_name(*((*idlist).keys).offset(j as isize)),
                );
            } else {
                found = 0 as libc::c_int;
                id = files.tqh_first;
                while !id.is_null() {
                    if sshkey_equal(*((*idlist).keys).offset(j as isize), (*id).key) != 0 {
                        if !((*id).next.tqe_next).is_null() {
                            (*(*id).next.tqe_next).next.tqe_prev = (*id).next.tqe_prev;
                        } else {
                            files.tqh_last = (*id).next.tqe_prev;
                        }
                        *(*id).next.tqe_prev = (*id).next.tqe_next;
                        (*id).next.tqe_next = 0 as *mut identity;
                        (*id).next.tqe_prev = (*preferred_0).tqh_last;
                        *(*preferred_0).tqh_last = id;
                        (*preferred_0).tqh_last = &mut (*id).next.tqe_next;
                        (*id).agent_fd = agent_fd;
                        found = 1 as libc::c_int;
                        break;
                    } else {
                        id = (*id).next.tqe_next;
                    }
                }
                if found == 0 && options.identities_only == 0 {
                    id = crate::xmalloc::xcalloc(
                        1 as libc::c_int as size_t,
                        ::core::mem::size_of::<identity>() as libc::c_ulong,
                    ) as *mut identity;
                    (*id).key = *((*idlist).keys).offset(j as isize);
                    (*id).filename = *((*idlist).comments).offset(j as isize);
                    let ref mut fresh1 = *((*idlist).keys).offset(j as isize);
                    *fresh1 = 0 as *mut crate::sshkey::sshkey;
                    let ref mut fresh2 = *((*idlist).comments).offset(j as isize);
                    *fresh2 = 0 as *mut libc::c_char;
                    (*id).agent_fd = agent_fd;
                    (*id).next.tqe_next = 0 as *mut identity;
                    (*id).next.tqe_prev = agent.tqh_last;
                    *agent.tqh_last = id;
                    agent.tqh_last = &mut (*id).next.tqe_next;
                }
            }
            j = j.wrapping_add(1);
            j;
        }
        ssh_free_identitylist(idlist);
        if !(agent.tqh_first).is_null() {
            *(*preferred_0).tqh_last = agent.tqh_first;
            (*agent.tqh_first).next.tqe_prev = (*preferred_0).tqh_last;
            (*preferred_0).tqh_last = agent.tqh_last;
            agent.tqh_first = 0 as *mut identity;
            agent.tqh_last = &mut agent.tqh_first;
        }
        (*authctxt).agent_fd = agent_fd;
    }
    id = files.tqh_first;
    while !id.is_null() && {
        tmp = (*id).next.tqe_next;
        1 as libc::c_int != 0
    } {
        if !(((*id).key).is_null() || (*(*id).key).flags & 0x1 as libc::c_int == 0 as libc::c_int) {
            found = 0 as libc::c_int;
            id2 = files.tqh_first;
            while !id2.is_null() {
                if !(((*id2).key).is_null()
                    || (*(*id2).key).flags & 0x1 as libc::c_int != 0 as libc::c_int)
                {
                    if sshkey_equal((*id).key, (*id2).key) != 0 {
                        if !((*id).next.tqe_next).is_null() {
                            (*(*id).next.tqe_next).next.tqe_prev = (*id).next.tqe_prev;
                        } else {
                            files.tqh_last = (*id).next.tqe_prev;
                        }
                        *(*id).next.tqe_prev = (*id).next.tqe_next;
                        (*id).next.tqe_next = 0 as *mut identity;
                        (*id).next.tqe_prev = (*preferred_0).tqh_last;
                        *(*preferred_0).tqh_last = id;
                        (*preferred_0).tqh_last = &mut (*id).next.tqe_next;
                        found = 1 as libc::c_int;
                        break;
                    }
                }
                id2 = (*id2).next.tqe_next;
            }
            if found == 0 && options.identities_only != 0 {
                if !((*id).next.tqe_next).is_null() {
                    (*(*id).next.tqe_next).next.tqe_prev = (*id).next.tqe_prev;
                } else {
                    files.tqh_last = (*id).next.tqe_prev;
                }
                *(*id).next.tqe_prev = (*id).next.tqe_next;
                freezero(
                    id as *mut libc::c_void,
                    ::core::mem::size_of::<identity>() as libc::c_ulong,
                );
            }
        }
        id = tmp;
    }
    if !(files.tqh_first).is_null() {
        *(*preferred_0).tqh_last = files.tqh_first;
        (*files.tqh_first).next.tqe_prev = (*preferred_0).tqh_last;
        (*preferred_0).tqh_last = files.tqh_last;
        files.tqh_first = 0 as *mut identity;
        files.tqh_last = &mut files.tqh_first;
    }
    id = (*preferred_0).tqh_first;
    while !id.is_null() && {
        id2 = (*id).next.tqe_next;
        1 as libc::c_int != 0
    } {
        if !((*id).key).is_null() && key_type_allowed_by_config((*id).key) == 0 {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"pubkey_prepare\0"))
                    .as_ptr(),
                1806 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Skipping %s key %s - corresponding algo not in PubkeyAcceptedAlgorithms\0"
                    as *const u8 as *const libc::c_char,
                sshkey_ssh_name((*id).key),
                (*id).filename,
            );
            if !((*id).next.tqe_next).is_null() {
                (*(*id).next.tqe_next).next.tqe_prev = (*id).next.tqe_prev;
            } else {
                (*preferred_0).tqh_last = (*id).next.tqe_prev;
            }
            *(*id).next.tqe_prev = (*id).next.tqe_next;
            crate::sshkey::sshkey_free((*id).key);
            libc::free((*id).filename as *mut libc::c_void);
            memset(
                id as *mut libc::c_void,
                0 as libc::c_int,
                ::core::mem::size_of::<identity>() as libc::c_ulong,
            );
        }
        id = id2;
    }
    id = (*preferred_0).tqh_first;
    while !id.is_null() && {
        id2 = (*id).next.tqe_next;
        1 as libc::c_int != 0
    } {
        ident = format_identity(id);
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"pubkey_prepare\0"))
                .as_ptr(),
            1817 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Will attempt key: %s\0" as *const u8 as *const libc::c_char,
            ident,
        );
        libc::free(ident as *mut libc::c_void);
        id = id2;
    }
    crate::log::sshlog(
        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"pubkey_prepare\0")).as_ptr(),
        1820 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"done\0" as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn pubkey_cleanup(mut ssh: *mut ssh) {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut id: *mut Identity = 0 as *mut Identity;
    if (*authctxt).agent_fd != -(1 as libc::c_int) {
        ssh_close_authentication_socket((*authctxt).agent_fd);
        (*authctxt).agent_fd = -(1 as libc::c_int);
    }
    id = (*authctxt).keys.tqh_first;
    while !id.is_null() {
        if !((*id).next.tqe_next).is_null() {
            (*(*id).next.tqe_next).next.tqe_prev = (*id).next.tqe_prev;
        } else {
            (*authctxt).keys.tqh_last = (*id).next.tqe_prev;
        }
        *(*id).next.tqe_prev = (*id).next.tqe_next;
        crate::sshkey::sshkey_free((*id).key);
        libc::free((*id).filename as *mut libc::c_void);
        libc::free(id as *mut libc::c_void);
        id = (*authctxt).keys.tqh_first;
    }
}
unsafe extern "C" fn pubkey_reset(mut authctxt: *mut Authctxt) {
    let mut id: *mut Identity = 0 as *mut Identity;
    id = (*authctxt).keys.tqh_first;
    while !id.is_null() {
        (*id).tried = 0 as libc::c_int;
        id = (*id).next.tqe_next;
    }
}
unsafe extern "C" fn userauth_pubkey(mut ssh: *mut ssh) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut id: *mut Identity = 0 as *mut Identity;
    let mut sent: libc::c_int = 0 as libc::c_int;
    let mut ident: *mut libc::c_char = 0 as *mut libc::c_char;
    loop {
        id = (*authctxt).keys.tqh_first;
        if id.is_null() {
            break;
        }
        let fresh3 = (*id).tried;
        (*id).tried = (*id).tried + 1;
        if fresh3 != 0 {
            return 0 as libc::c_int;
        }
        if !((*id).next.tqe_next).is_null() {
            (*(*id).next.tqe_next).next.tqe_prev = (*id).next.tqe_prev;
        } else {
            (*authctxt).keys.tqh_last = (*id).next.tqe_prev;
        }
        *(*id).next.tqe_prev = (*id).next.tqe_next;
        (*id).next.tqe_next = 0 as *mut identity;
        (*id).next.tqe_prev = (*authctxt).keys.tqh_last;
        *(*authctxt).keys.tqh_last = id;
        (*authctxt).keys.tqh_last = &mut (*id).next.tqe_next;
        if !((*id).key).is_null() {
            if !((*id).key).is_null() {
                ident = format_identity(id);
                crate::log::sshlog(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"userauth_pubkey\0",
                    ))
                    .as_ptr(),
                    1873 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Offering public key: %s\0" as *const u8 as *const libc::c_char,
                    ident,
                );
                libc::free(ident as *mut libc::c_void);
                sent = send_pubkey_test(ssh, id);
            }
        } else {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_pubkey\0"))
                    .as_ptr(),
                1878 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Trying private key: %s\0" as *const u8 as *const libc::c_char,
                (*id).filename,
            );
            (*id).key = load_identity_file(id);
            if !((*id).key).is_null() {
                if !((*id).key).is_null() {
                    (*id).isprivate = 1 as libc::c_int;
                    sent = sign_and_send_pubkey(ssh, id);
                }
                crate::sshkey::sshkey_free((*id).key);
                (*id).key = 0 as *mut crate::sshkey::sshkey;
                (*id).isprivate = 0 as libc::c_int;
            }
        }
        if sent != 0 {
            return sent;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn userauth_kbdint(mut ssh: *mut ssh) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut r: libc::c_int = 0;
    let fresh4 = (*authctxt).attempt_kbdint;
    (*authctxt).attempt_kbdint = (*authctxt).attempt_kbdint + 1;
    if fresh4 >= options.number_of_password_prompts {
        return 0 as libc::c_int;
    }
    if (*authctxt).attempt_kbdint > 1 as libc::c_int && (*authctxt).info_req_seen == 0 {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_kbdint\0"))
                .as_ptr(),
            1909 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"userauth_kbdint: disable: no info_req_seen\0" as *const u8 as *const libc::c_char,
        );
        crate::dispatch::ssh_dispatch_set(ssh, 60 as libc::c_int, None);
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_kbdint\0")).as_ptr(),
        1914 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"userauth_kbdint\0" as *const u8 as *const libc::c_char,
    );
    r = crate::packet::sshpkt_start(ssh, 50 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_put_cstring(
                ssh,
                (*authctxt).server_user as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_cstring(ssh, (*authctxt).service as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_cstring(
                ssh,
                (*(*authctxt).method).name as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_cstring(
                ssh,
                b"\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_cstring(
                ssh,
                (if !(options.kbd_interactive_devices).is_null() {
                    options.kbd_interactive_devices as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                }) as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"userauth_kbdint\0"))
                .as_ptr(),
            1923 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send packet\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::dispatch::ssh_dispatch_set(
        ssh,
        60 as libc::c_int,
        Some(
            input_userauth_info_req
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn input_userauth_info_req(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut current_block: u64;
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut inst: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut lang: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut prompt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut display_prompt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut response: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut echo: u_char = 0 as libc::c_int as u_char;
    let mut num_prompts: u_int = 0;
    let mut i: u_int = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"input_userauth_info_req\0"))
            .as_ptr(),
        1942 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    if authctxt.is_null() {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"input_userauth_info_req\0",
            ))
            .as_ptr(),
            1945 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no authentication context\0" as *const u8 as *const libc::c_char,
        );
    }
    (*authctxt).info_req_seen = 1 as libc::c_int;
    r = crate::packet::sshpkt_get_cstring(ssh, &mut name, 0 as *mut size_t);
    if !(r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_get_cstring(ssh, &mut inst, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_cstring(ssh, &mut lang, 0 as *mut size_t);
            r != 0 as libc::c_int
        })
    {
        if strlen(name) > 0 as libc::c_int as libc::c_ulong {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"input_userauth_info_req\0",
                ))
                .as_ptr(),
                1954 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"%s\0" as *const u8 as *const libc::c_char,
                name,
            );
        }
        if strlen(inst) > 0 as libc::c_int as libc::c_ulong {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"input_userauth_info_req\0",
                ))
                .as_ptr(),
                1956 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"%s\0" as *const u8 as *const libc::c_char,
                inst,
            );
        }
        r = sshpkt_get_u32(ssh, &mut num_prompts);
        if !(r != 0 as libc::c_int) {
            r = crate::packet::sshpkt_start(ssh, 61 as libc::c_int as u_char);
            if !(r != 0 as libc::c_int || {
                r = sshpkt_put_u32(ssh, num_prompts);
                r != 0 as libc::c_int
            }) {
                crate::log::sshlog(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"input_userauth_info_req\0",
                    ))
                    .as_ptr(),
                    1970 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"num_prompts %d\0" as *const u8 as *const libc::c_char,
                    num_prompts,
                );
                i = 0 as libc::c_int as u_int;
                loop {
                    if !(i < num_prompts) {
                        current_block = 11584701595673473500;
                        break;
                    }
                    r = crate::packet::sshpkt_get_cstring(ssh, &mut prompt, 0 as *mut size_t);
                    if r != 0 as libc::c_int || {
                        r = sshpkt_get_u8(ssh, &mut echo);
                        r != 0 as libc::c_int
                    } {
                        current_block = 2494389617458814963;
                        break;
                    }
                    if asmprintf(
                        &mut display_prompt as *mut *mut libc::c_char,
                        2147483647 as libc::c_int as size_t,
                        0 as *mut libc::c_int,
                        b"(%s@%s) %s\0" as *const u8 as *const libc::c_char,
                        (*authctxt).server_user,
                        if !(options.host_key_alias).is_null() {
                            options.host_key_alias as *const libc::c_char
                        } else {
                            (*authctxt).host
                        },
                        prompt,
                    ) == -(1 as libc::c_int)
                    {
                        sshfatal(
                            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                b"input_userauth_info_req\0",
                            ))
                            .as_ptr(),
                            1978 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"asmprintf failed\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    response = read_passphrase(
                        display_prompt,
                        if echo as libc::c_int != 0 {
                            0x1 as libc::c_int
                        } else {
                            0 as libc::c_int
                        },
                    );
                    r = crate::packet::sshpkt_put_cstring(ssh, response as *const libc::c_void);
                    if r != 0 as libc::c_int {
                        current_block = 2494389617458814963;
                        break;
                    }
                    freezero(response as *mut libc::c_void, strlen(response));
                    libc::free(prompt as *mut libc::c_void);
                    libc::free(display_prompt as *mut libc::c_void);
                    prompt = 0 as *mut libc::c_char;
                    response = prompt;
                    display_prompt = response;
                    i = i.wrapping_add(1);
                    i;
                }
                match current_block {
                    2494389617458814963 => {}
                    _ => {
                        r = crate::packet::sshpkt_get_end(ssh);
                        if !(r != 0 as libc::c_int || {
                            r = sshpkt_add_padding(ssh, 64 as libc::c_int as u_char);
                            r != 0 as libc::c_int
                        }) {
                            r = crate::packet::sshpkt_send(ssh);
                        }
                    }
                }
            }
        }
    }
    if !response.is_null() {
        freezero(response as *mut libc::c_void, strlen(response));
    }
    libc::free(prompt as *mut libc::c_void);
    libc::free(display_prompt as *mut libc::c_void);
    libc::free(name as *mut libc::c_void);
    libc::free(inst as *mut libc::c_void);
    libc::free(lang as *mut libc::c_void);
    return r;
}
unsafe extern "C" fn ssh_keysign(
    mut ssh: *mut ssh,
    mut _key: *mut crate::sshkey::sshkey,
    mut sigp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut data: *const u_char,
    mut datalen: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut pid: pid_t = 0;
    let mut r: libc::c_int = 0;
    let mut to: [libc::c_int; 2] = [0; 2];
    let mut from: [libc::c_int; 2] = [0; 2];
    let mut status: libc::c_int = 0;
    let mut sock: libc::c_int = ssh_packet_get_connection_in(ssh);
    let mut rversion: u_char = 0 as libc::c_int as u_char;
    let mut version: u_char = 2 as libc::c_int as u_char;
    let mut osigchld: Option<unsafe extern "C" fn(libc::c_int) -> ()> = None;
    *sigp = 0 as *mut u_char;
    *lenp = 0 as libc::c_int as size_t;
    if libc::stat(
        b"/usr/local/libexec/ssh-keysign\0" as *const u8 as *const libc::c_char,
        &mut st,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0")).as_ptr(),
            2019 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"not installed: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if libc::fflush(stdout) != 0 as libc::c_int {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0")).as_ptr(),
            2023 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libc::fflush: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if pipe(to.as_mut_ptr()) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0")).as_ptr(),
            2027 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"pipe: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if pipe(from.as_mut_ptr()) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0")).as_ptr(),
            2031 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"pipe: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    pid = libc::fork();
    if pid == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0")).as_ptr(),
            2035 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libc::fork: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    osigchld = crate::misc::ssh_signal(17 as libc::c_int, None);
    if pid == 0 as libc::c_int {
        close(from[0 as libc::c_int as usize]);
        if libc::dup2(from[1 as libc::c_int as usize], 1 as libc::c_int) == -(1 as libc::c_int) {
            sshfatal(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0"))
                    .as_ptr(),
                2042 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"libc::dup2: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        close(to[1 as libc::c_int as usize]);
        if libc::dup2(to[0 as libc::c_int as usize], 0 as libc::c_int) == -(1 as libc::c_int) {
            sshfatal(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0"))
                    .as_ptr(),
                2045 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"libc::dup2: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        close(from[1 as libc::c_int as usize]);
        close(to[0 as libc::c_int as usize]);
        if libc::dup2(sock, 2 as libc::c_int + 1 as libc::c_int) == -(1 as libc::c_int) {
            sshfatal(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0"))
                    .as_ptr(),
                2050 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"libc::dup2: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        sock = 2 as libc::c_int + 1 as libc::c_int;
        if fcntl(sock, 2 as libc::c_int, 0 as libc::c_int) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0"))
                    .as_ptr(),
                2053 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"fcntl F_SETFD: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        closefrom(sock + 1 as libc::c_int);
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0")).as_ptr(),
            2057 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"[child] pid=%ld, exec %s\0" as *const u8 as *const libc::c_char,
            libc::getpid() as libc::c_long,
            b"/usr/local/libexec/ssh-keysign\0" as *const u8 as *const libc::c_char,
        );
        execl(
            b"/usr/local/libexec/ssh-keysign\0" as *const u8 as *const libc::c_char,
            b"/usr/local/libexec/ssh-keysign\0" as *const u8 as *const libc::c_char,
            0 as *mut libc::c_void as *mut libc::c_char,
        );
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0")).as_ptr(),
            2060 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"exec(%s): %s\0" as *const u8 as *const libc::c_char,
            b"/usr/local/libexec/ssh-keysign\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    close(from[1 as libc::c_int as usize]);
    close(to[0 as libc::c_int as usize]);
    sock = 2 as libc::c_int + 1 as libc::c_int;
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0")).as_ptr(),
            2067 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u32(b, sock as u_int32_t);
    if r != 0 as libc::c_int || {
        r = crate::sshbuf_getput_basic::sshbuf_put_string(b, data as *const libc::c_void, datalen);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0")).as_ptr(),
            2071 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"buffer error\0" as *const u8 as *const libc::c_char,
        );
    }
    if ssh_msg_send(to[1 as libc::c_int as usize], version, b) == -(1 as libc::c_int) {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0")).as_ptr(),
            2073 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"couldn't send request\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_reset(b);
    r = ssh_msg_recv(from[0 as libc::c_int as usize], b);
    close(from[0 as libc::c_int as usize]);
    close(to[1 as libc::c_int as usize]);
    if r < 0 as libc::c_int {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0")).as_ptr(),
            2079 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no reply\0" as *const u8 as *const libc::c_char,
        );
    } else {
        *libc::__errno_location() = 0 as libc::c_int;
        loop {
            if !(libc::waitpid(pid, &mut status, 0 as libc::c_int) == -(1 as libc::c_int)) {
                current_block = 1622411330066726685;
                break;
            }
            if !(*libc::__errno_location() != 4 as libc::c_int) {
                continue;
            }
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_keysign\0"))
                    .as_ptr(),
                2086 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"libc::waitpid %ld: %s\0" as *const u8 as *const libc::c_char,
                pid as libc::c_long,
                libc::strerror(*libc::__errno_location()),
            );
            current_block = 8198075662177925590;
            break;
        }
        match current_block {
            8198075662177925590 => {}
            _ => {
                if !(status & 0x7f as libc::c_int == 0 as libc::c_int) {
                    crate::log::sshlog(
                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                            b"ssh_keysign\0",
                        ))
                        .as_ptr(),
                        2091 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"exited abnormally\0" as *const u8 as *const libc::c_char,
                    );
                } else if (status & 0xff00 as libc::c_int) >> 8 as libc::c_int != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                            b"ssh_keysign\0",
                        ))
                        .as_ptr(),
                        2095 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"exited with status %d\0" as *const u8 as *const libc::c_char,
                        (status & 0xff00 as libc::c_int) >> 8 as libc::c_int,
                    );
                } else {
                    r = crate::sshbuf_getput_basic::sshbuf_get_u8(b, &mut rversion);
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"ssh_keysign\0",
                            ))
                            .as_ptr(),
                            2099 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"buffer error\0" as *const u8 as *const libc::c_char,
                        );
                    } else if rversion as libc::c_int != version as libc::c_int {
                        crate::log::sshlog(
                            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"ssh_keysign\0",
                            ))
                            .as_ptr(),
                            2103 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"bad version\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        r = crate::sshbuf_getput_basic::sshbuf_get_string(b, sigp, lenp);
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                    b"ssh_keysign\0",
                                ))
                                .as_ptr(),
                                2107 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"buffer error\0" as *const u8 as *const libc::c_char,
                            );
                        } else {
                            crate::misc::ssh_signal(17 as libc::c_int, osigchld);
                            crate::sshbuf::sshbuf_free(b);
                            return 0 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    crate::misc::ssh_signal(17 as libc::c_int, osigchld);
    crate::sshbuf::sshbuf_free(b);
    return -(1 as libc::c_int);
}
unsafe extern "C" fn userauth_hostbased(mut ssh: *mut ssh) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut private: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut keyblob: *mut u_char = 0 as *mut u_char;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut chost: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut lname: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut siglen: size_t = 0 as libc::c_int as size_t;
    let mut keylen: size_t = 0 as libc::c_int as size_t;
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    if ((*authctxt).ktypes).is_null() {
        (*authctxt).oktypes = crate::xmalloc::xstrdup(options.hostbased_accepted_algos);
        (*authctxt).ktypes = (*authctxt).oktypes;
    }
    loop {
        if ((*authctxt).active_ktype).is_null() {
            (*authctxt).active_ktype = strsep(
                &mut (*authctxt).ktypes,
                b",\0" as *const u8 as *const libc::c_char,
            );
        }
        if ((*authctxt).active_ktype).is_null()
            || *(*authctxt).active_ktype as libc::c_int == '\0' as i32
        {
            break;
        }
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"userauth_hostbased\0"))
                .as_ptr(),
            2145 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"trying key type %s\0" as *const u8 as *const libc::c_char,
            (*authctxt).active_ktype,
        );
        private = 0 as *mut crate::sshkey::sshkey;
        i = 0 as libc::c_int;
        while i < (*(*authctxt).sensitive).nkeys {
            if !((*((*(*authctxt).sensitive).keys).offset(i as isize)).is_null()
                || (**((*(*authctxt).sensitive).keys).offset(i as isize)).type_0
                    == KEY_UNSPEC as libc::c_int)
            {
                if !(sshkey_match_keyname_to_sigalgs(
                    sshkey_ssh_name(*((*(*authctxt).sensitive).keys).offset(i as isize)),
                    (*authctxt).active_ktype,
                ) == 0)
                {
                    private = *((*(*authctxt).sensitive).keys).offset(i as isize);
                    let ref mut fresh5 = *((*(*authctxt).sensitive).keys).offset(i as isize);
                    *fresh5 = 0 as *mut crate::sshkey::sshkey;
                    break;
                }
            }
            i += 1;
            i;
        }
        if !private.is_null() {
            break;
        }
        (*authctxt).active_ktype = 0 as *const libc::c_char;
    }
    if private.is_null() {
        libc::free((*authctxt).oktypes as *mut libc::c_void);
        (*authctxt).ktypes = 0 as *mut libc::c_char;
        (*authctxt).oktypes = (*authctxt).ktypes;
        (*authctxt).active_ktype = 0 as *const libc::c_char;
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"userauth_hostbased\0"))
                .as_ptr(),
            2172 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"No more client hostkeys for hostbased authentication.\0" as *const u8
                as *const libc::c_char,
        );
    } else {
        fp = crate::sshkey::sshkey_fingerprint(private, options.fingerprint_hash, SSH_FP_DEFAULT);
        if fp.is_null() {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"userauth_hostbased\0",
                ))
                .as_ptr(),
                2178 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"crate::sshkey::sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"userauth_hostbased\0",
                ))
                .as_ptr(),
                2182 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"trying hostkey %s %s using sigalg %s\0" as *const u8 as *const libc::c_char,
                sshkey_ssh_name(private),
                fp,
                (*authctxt).active_ktype,
            );
            lname = get_local_name(ssh_packet_get_connection_in(ssh));
            if lname.is_null() {
                crate::log::sshlog(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"userauth_hostbased\0",
                    ))
                    .as_ptr(),
                    2187 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"cannot get local ipaddr/name\0" as *const u8 as *const libc::c_char,
                );
            } else {
                crate::xmalloc::xasprintf(
                    &mut chost as *mut *mut libc::c_char,
                    b"%s.\0" as *const u8 as *const libc::c_char,
                    lname,
                );
                crate::log::sshlog(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"userauth_hostbased\0",
                    ))
                    .as_ptr(),
                    2193 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"chost %s\0" as *const u8 as *const libc::c_char,
                    chost,
                );
                b = crate::sshbuf::sshbuf_new();
                if b.is_null() {
                    crate::log::sshlog(
                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"userauth_hostbased\0",
                        ))
                        .as_ptr(),
                        2197 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                            as *const libc::c_char,
                    );
                } else {
                    r = sshkey_to_blob(private, &mut keyblob, &mut keylen);
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                b"userauth_hostbased\0",
                            ))
                            .as_ptr(),
                            2201 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"sshkey_to_blob\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
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
                                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
                                    b,
                                    (*authctxt).server_user,
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
                                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
                                    b,
                                    (*(*authctxt).method).name,
                                );
                                r != 0 as libc::c_int
                            }
                            || {
                                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
                                    b,
                                    (*authctxt).active_ktype,
                                );
                                r != 0 as libc::c_int
                            }
                            || {
                                r = crate::sshbuf_getput_basic::sshbuf_put_string(
                                    b,
                                    keyblob as *const libc::c_void,
                                    keylen,
                                );
                                r != 0 as libc::c_int
                            }
                            || {
                                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(b, chost);
                                r != 0 as libc::c_int
                            }
                            || {
                                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
                                    b,
                                    (*authctxt).local_user,
                                );
                                r != 0 as libc::c_int
                            }
                        {
                            crate::log::sshlog(
                                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                    b"userauth_hostbased\0",
                                ))
                                .as_ptr(),
                                2213 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"buffer error\0" as *const u8 as *const libc::c_char,
                            );
                        } else {
                            r = ssh_keysign(
                                ssh,
                                private,
                                &mut sig,
                                &mut siglen,
                                crate::sshbuf::sshbuf_ptr(b),
                                crate::sshbuf::sshbuf_len(b),
                            );
                            if r != 0 as libc::c_int {
                                crate::log::sshlog(
                                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                        b"userauth_hostbased\0",
                                    ))
                                    .as_ptr(),
                                    2223 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"sign using hostkey %s %s failed\0" as *const u8
                                        as *const libc::c_char,
                                    sshkey_ssh_name(private),
                                    fp,
                                );
                            } else {
                                r = crate::packet::sshpkt_start(ssh, 50 as libc::c_int as u_char);
                                if r != 0 as libc::c_int
                                    || {
                                        r = crate::packet::sshpkt_put_cstring(
                                            ssh,
                                            (*authctxt).server_user as *const libc::c_void,
                                        );
                                        r != 0 as libc::c_int
                                    }
                                    || {
                                        r = crate::packet::sshpkt_put_cstring(
                                            ssh,
                                            (*authctxt).service as *const libc::c_void,
                                        );
                                        r != 0 as libc::c_int
                                    }
                                    || {
                                        r = crate::packet::sshpkt_put_cstring(
                                            ssh,
                                            (*(*authctxt).method).name as *const libc::c_void,
                                        );
                                        r != 0 as libc::c_int
                                    }
                                    || {
                                        r = crate::packet::sshpkt_put_cstring(
                                            ssh,
                                            (*authctxt).active_ktype as *const libc::c_void,
                                        );
                                        r != 0 as libc::c_int
                                    }
                                    || {
                                        r = sshpkt_put_string(
                                            ssh,
                                            keyblob as *const libc::c_void,
                                            keylen,
                                        );
                                        r != 0 as libc::c_int
                                    }
                                    || {
                                        r = crate::packet::sshpkt_put_cstring(
                                            ssh,
                                            chost as *const libc::c_void,
                                        );
                                        r != 0 as libc::c_int
                                    }
                                    || {
                                        r = crate::packet::sshpkt_put_cstring(
                                            ssh,
                                            (*authctxt).local_user as *const libc::c_void,
                                        );
                                        r != 0 as libc::c_int
                                    }
                                    || {
                                        r = sshpkt_put_string(
                                            ssh,
                                            sig as *const libc::c_void,
                                            siglen,
                                        );
                                        r != 0 as libc::c_int
                                    }
                                    || {
                                        r = crate::packet::sshpkt_send(ssh);
                                        r != 0 as libc::c_int
                                    }
                                {
                                    crate::log::sshlog(
                                        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                            b"userauth_hostbased\0",
                                        ))
                                        .as_ptr(),
                                        2236 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        ssh_err(r),
                                        b"packet error\0" as *const u8 as *const libc::c_char,
                                    );
                                } else {
                                    success = 1 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !sig.is_null() {
        freezero(sig as *mut libc::c_void, siglen);
    }
    libc::free(keyblob as *mut libc::c_void);
    libc::free(lname as *mut libc::c_void);
    libc::free(fp as *mut libc::c_void);
    libc::free(chost as *mut libc::c_void);
    crate::sshkey::sshkey_free(private);
    crate::sshbuf::sshbuf_free(b);
    return success;
}
unsafe extern "C" fn authmethod_is_enabled(mut method: *mut Authmethod) -> libc::c_int {
    if method.is_null() {
        return 0 as libc::c_int;
    }
    if ((*method).enabled).is_null() || *(*method).enabled == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if !((*method).batch_flag).is_null() && *(*method).batch_flag != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn authmethod_lookup(mut name: *const libc::c_char) -> *mut Authmethod {
    let mut method: *mut Authmethod = 0 as *mut Authmethod;
    if !name.is_null() {
        method = authmethods.as_mut_ptr();
        while !((*method).name).is_null() {
            if libc::strcmp(name, (*method).name) == 0 as libc::c_int {
                return method;
            }
            method = method.offset(1);
            method;
        }
    }
    crate::log::sshlog(
        b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"authmethod_lookup\0"))
            .as_ptr(),
        2282 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"Unrecognized authentication method name: %s\0" as *const u8 as *const libc::c_char,
        if !name.is_null() {
            name
        } else {
            b"NULL\0" as *const u8 as *const libc::c_char
        },
    );
    return 0 as *mut Authmethod;
}
static mut current: *mut Authmethod = 0 as *const Authmethod as *mut Authmethod;
static mut supported: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut preferred: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
unsafe extern "C" fn authmethod_get(mut authlist: *mut libc::c_char) -> *mut Authmethod {
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut next: u_int = 0;
    if authlist.is_null() || strlen(authlist) == 0 as libc::c_int as libc::c_ulong {
        authlist = options.preferred_authentications;
    }
    if supported.is_null() || libc::strcmp(authlist, supported) != 0 as libc::c_int {
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"authmethod_get\0"))
                .as_ptr(),
            2307 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"start over, passed a different list %s\0" as *const u8 as *const libc::c_char,
            authlist,
        );
        libc::free(supported as *mut libc::c_void);
        supported = crate::xmalloc::xstrdup(authlist);
        preferred = options.preferred_authentications;
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"authmethod_get\0"))
                .as_ptr(),
            2311 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"preferred %s\0" as *const u8 as *const libc::c_char,
            preferred,
        );
        current = 0 as *mut Authmethod;
    } else if !current.is_null() && authmethod_is_enabled(current) != 0 {
        return current;
    }
    loop {
        name = match_list(preferred, supported, &mut next);
        if name.is_null() {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"authmethod_get\0"))
                    .as_ptr(),
                2318 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"No more authentication methods to try.\0" as *const u8 as *const libc::c_char,
            );
            current = 0 as *mut Authmethod;
            return 0 as *mut Authmethod;
        }
        preferred = preferred.offset(next as isize);
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"authmethod_get\0"))
                .as_ptr(),
            2323 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"authmethod_lookup %s\0" as *const u8 as *const libc::c_char,
            name,
        );
        crate::log::sshlog(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"authmethod_get\0"))
                .as_ptr(),
            2324 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"remaining preferred: %s\0" as *const u8 as *const libc::c_char,
            preferred,
        );
        current = authmethod_lookup(name);
        if !current.is_null() && authmethod_is_enabled(current) != 0 {
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"authmethod_get\0"))
                    .as_ptr(),
                2327 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"authmethod_is_enabled %s\0" as *const u8 as *const libc::c_char,
                name,
            );
            crate::log::sshlog(
                b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"authmethod_get\0"))
                    .as_ptr(),
                2328 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Next authentication method: %s\0" as *const u8 as *const libc::c_char,
                name,
            );
            libc::free(name as *mut libc::c_void);
            return current;
        }
        libc::free(name as *mut libc::c_void);
    }
}
unsafe extern "C" fn authmethods_get() -> *mut libc::c_char {
    let mut method: *mut Authmethod = 0 as *mut Authmethod;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut list: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"authmethods_get\0"))
                .as_ptr(),
            2345 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    method = authmethods.as_mut_ptr();
    while !((*method).name).is_null() {
        if authmethod_is_enabled(method) != 0 {
            r = crate::sshbuf_getput_basic::sshbuf_putf(
                b,
                b"%s%s\0" as *const u8 as *const libc::c_char,
                if crate::sshbuf::sshbuf_len(b) != 0 {
                    b",\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                (*method).name,
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"authmethods_get\0",
                    ))
                    .as_ptr(),
                    2350 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"buffer error\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        method = method.offset(1);
        method;
    }
    list = crate::sshbuf_misc::sshbuf_dup_string(b);
    if list.is_null() {
        sshfatal(
            b"sshconnect2.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"authmethods_get\0"))
                .as_ptr(),
            2354 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::sshbuf_misc::sshbuf_dup_string failed\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_free(b);
    return list;
}
unsafe extern "C" fn run_static_initializers() {
    authmethods = [
        {
            let mut init = cauthmethod {
                name: b"hostbased\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                userauth: Some(userauth_hostbased as unsafe extern "C" fn(*mut ssh) -> libc::c_int),
                cleanup: None,
                enabled: &mut options.hostbased_authentication,
                batch_flag: 0 as *mut libc::c_int,
            };
            init
        },
        {
            let mut init = cauthmethod {
                name: b"publickey\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                userauth: Some(userauth_pubkey as unsafe extern "C" fn(*mut ssh) -> libc::c_int),
                cleanup: None,
                enabled: &mut options.pubkey_authentication,
                batch_flag: 0 as *mut libc::c_int,
            };
            init
        },
        {
            let mut init = cauthmethod {
                name: b"keyboard-interactive\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                userauth: Some(userauth_kbdint as unsafe extern "C" fn(*mut ssh) -> libc::c_int),
                cleanup: None,
                enabled: &mut options.kbd_interactive_authentication,
                batch_flag: &mut options.batch_mode,
            };
            init
        },
        {
            let mut init = cauthmethod {
                name: b"password\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                userauth: Some(userauth_passwd as unsafe extern "C" fn(*mut ssh) -> libc::c_int),
                cleanup: None,
                enabled: &mut options.password_authentication,
                batch_flag: &mut options.batch_mode,
            };
            init
        },
        {
            let mut init = cauthmethod {
                name: b"none\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                userauth: Some(userauth_none as unsafe extern "C" fn(*mut ssh) -> libc::c_int),
                cleanup: None,
                enabled: 0 as *mut libc::c_int,
                batch_flag: 0 as *mut libc::c_int,
            };
            init
        },
        {
            let mut init = cauthmethod {
                name: 0 as *mut libc::c_char,
                userauth: None,
                cleanup: None,
                enabled: 0 as *mut libc::c_int,
                batch_flag: 0 as *mut libc::c_int,
            };
            init
        },
    ];
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
