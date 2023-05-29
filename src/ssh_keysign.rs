use ::libc;
use libc::close;
extern "C" {

    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    fn seed_rng();
    fn strncasecmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong)
        -> libc::c_int;

    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

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
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_equal_public(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_fingerprint(_: *const sshkey, _: libc::c_int, _: sshkey_fp_rep) -> *mut libc::c_char;
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_type_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_from_blob(_: *const u_char, _: size_t, _: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_sign(
        _: *mut sshkey,
        _: *mut *mut u_char,
        _: *mut size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: u_int,
    ) -> libc::c_int;
    fn pwcopy(_: *mut libc::passwd) -> *mut libc::passwd;

    fn sshbuf_from(blob: *const libc::c_void, len: size_t) -> *mut crate::sshbuf::sshbuf;

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
    fn sshbuf_get_string_direct(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshkey_load_private_type_fd(
        fd: libc::c_int,
        type_0: libc::c_int,
        passphrase: *const libc::c_char,
        keyp: *mut *mut sshkey,
        commentp: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn ssh_msg_send(_: libc::c_int, _: u_char, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn ssh_msg_recv(_: libc::c_int, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn get_local_name(_: libc::c_int) -> *mut libc::c_char;
    fn initialize_options(_: *mut Options);
    fn fill_default_options(_: *mut Options) -> libc::c_int;
    fn read_config_file(
        _: *const libc::c_char,
        _: *mut libc::passwd,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut Options,
        _: libc::c_int,
        _: *mut libc::c_int,
    ) -> libc::c_int;
    fn permanently_set_uid(_: *mut libc::passwd);
    static mut __progname: *mut libc::c_char;
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
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type uint8_t = __uint8_t;

pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type EC_KEY = ec_key_st;
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
    pub identity_keys: [*mut sshkey; 100],
    pub num_certificate_files: libc::c_int,
    pub certificate_files: [*mut libc::c_char; 100],
    pub certificate_file_userprovided: [libc::c_int; 100],
    pub certificates: [*mut sshkey; 100],
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
unsafe extern "C" fn valid_request(
    mut pw: *mut libc::passwd,
    mut host: *mut libc::c_char,
    mut ret: *mut *mut sshkey,
    mut pkalgp: *mut *mut libc::c_char,
    mut data: *mut u_char,
    mut datalen: size_t,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut type_0: u_char = 0;
    let mut pkblob: *mut u_char = 0 as *mut u_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut blen: size_t = 0;
    let mut len: size_t = 0;
    let mut pkalg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut luser: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut pktype: libc::c_int = 0;
    let mut fail: libc::c_int = 0;
    if !ret.is_null() {
        *ret = 0 as *mut sshkey;
    }
    if !pkalgp.is_null() {
        *pkalgp = 0 as *mut libc::c_char;
    }
    fail = 0 as libc::c_int;
    b = sshbuf_from(data as *const libc::c_void, datalen);
    if b.is_null() {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"valid_request\0"))
                .as_ptr(),
            83 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_from failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_get_string(b, 0 as *mut *mut u_char, &mut len);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"valid_request\0"))
                .as_ptr(),
            87 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse session ID\0" as *const u8 as *const libc::c_char,
        );
    }
    if len != 20 as libc::c_int as libc::c_ulong
        && len != 32 as libc::c_int as libc::c_ulong
        && len != 48 as libc::c_int as libc::c_ulong
        && len != 64 as libc::c_int as libc::c_ulong
    {
        fail += 1;
        fail;
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_u8(b, &mut type_0);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"valid_request\0"))
                .as_ptr(),
            95 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse type\0" as *const u8 as *const libc::c_char,
        );
    }
    if type_0 as libc::c_int != 50 as libc::c_int {
        fail += 1;
        fail;
    }
    r = sshbuf_get_string_direct(b, 0 as *mut *const u_char, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"valid_request\0"))
                .as_ptr(),
            101 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse user\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_get_cstring(b, &mut p, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"valid_request\0"))
                .as_ptr(),
            105 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse service\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::strcmp(b"ssh-connection\0" as *const u8 as *const libc::c_char, p) != 0 as libc::c_int
    {
        fail += 1;
        fail;
    }
    libc::free(p as *mut libc::c_void);
    r = sshbuf_get_cstring(b, &mut p, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"valid_request\0"))
                .as_ptr(),
            112 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse method\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::strcmp(b"hostbased\0" as *const u8 as *const libc::c_char, p) != 0 as libc::c_int {
        fail += 1;
        fail;
    }
    libc::free(p as *mut libc::c_void);
    r = sshbuf_get_cstring(b, &mut pkalg, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_string(b, &mut pkblob, &mut blen);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"valid_request\0"))
                .as_ptr(),
            120 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse pk\0" as *const u8 as *const libc::c_char,
        );
    }
    pktype = sshkey_type_from_name(pkalg);
    if pktype == KEY_UNSPEC as libc::c_int {
        fail += 1;
        fail;
    } else {
        r = sshkey_from_blob(pkblob, blen, &mut key);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"valid_request\0"))
                    .as_ptr(),
                126 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"decode key\0" as *const u8 as *const libc::c_char,
            );
            fail += 1;
            fail;
        } else if (*key).type_0 != pktype {
            fail += 1;
            fail;
        }
    }
    r = sshbuf_get_cstring(b, &mut p, &mut len);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"valid_request\0"))
                .as_ptr(),
            133 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse hostname\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"valid_request\0")).as_ptr(),
        134 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"check expect chost %s got %s\0" as *const u8 as *const libc::c_char,
        host,
        p,
    );
    if strlen(host) != len.wrapping_sub(1 as libc::c_int as libc::c_ulong) {
        fail += 1;
        fail;
    } else if *p.offset(len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize) as libc::c_int
        != '.' as i32
    {
        fail += 1;
        fail;
    } else if strncasecmp(host, p, len.wrapping_sub(1 as libc::c_int as libc::c_ulong))
        != 0 as libc::c_int
    {
        fail += 1;
        fail;
    }
    libc::free(p as *mut libc::c_void);
    r = sshbuf_get_cstring(b, &mut luser, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"valid_request\0"))
                .as_ptr(),
            145 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse luser\0" as *const u8 as *const libc::c_char,
        );
    }
    if libc::strcmp((*pw).pw_name, luser) != 0 as libc::c_int {
        fail += 1;
        fail;
    }
    libc::free(luser as *mut libc::c_void);
    if crate::sshbuf::sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong {
        fail += 1;
        fail;
    }
    crate::sshbuf::sshbuf_free(b);
    crate::log::sshlog(
        b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"valid_request\0")).as_ptr(),
        156 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"fail %d\0" as *const u8 as *const libc::c_char,
        fail,
    );
    if fail == 0 {
        if !ret.is_null() {
            *ret = key;
            key = 0 as *mut sshkey;
        }
        if !pkalgp.is_null() {
            *pkalgp = pkalg;
            pkalg = 0 as *mut libc::c_char;
        }
    }
    sshkey_free(key);
    libc::free(pkalg as *mut libc::c_void);
    libc::free(pkblob as *mut libc::c_void);
    return if fail != 0 {
        -(1 as libc::c_int)
    } else {
        0 as libc::c_int
    };
}
unsafe fn main_0(mut _argc: libc::c_int, mut _argv: *mut *mut libc::c_char) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut options: Options = Options {
        host_arg: 0 as *mut libc::c_char,
        forward_agent: 0,
        forward_agent_sock_path: 0 as *mut libc::c_char,
        forward_x11: 0,
        forward_x11_timeout: 0,
        forward_x11_trusted: 0,
        exit_on_forward_failure: 0,
        xauth_location: 0 as *mut libc::c_char,
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
        kbd_interactive_devices: 0 as *mut libc::c_char,
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
        log_verbose: 0 as *mut *mut libc::c_char,
        port: 0,
        address_family: 0,
        connection_attempts: 0,
        connection_timeout: 0,
        number_of_password_prompts: 0,
        ciphers: 0 as *mut libc::c_char,
        macs: 0 as *mut libc::c_char,
        hostkeyalgorithms: 0 as *mut libc::c_char,
        kex_algorithms: 0 as *mut libc::c_char,
        ca_sign_algorithms: 0 as *mut libc::c_char,
        hostname: 0 as *mut libc::c_char,
        host_key_alias: 0 as *mut libc::c_char,
        proxy_command: 0 as *mut libc::c_char,
        user: 0 as *mut libc::c_char,
        escape_char: 0,
        num_system_hostfiles: 0,
        system_hostfiles: [0 as *mut libc::c_char; 32],
        num_user_hostfiles: 0,
        user_hostfiles: [0 as *mut libc::c_char; 32],
        preferred_authentications: 0 as *mut libc::c_char,
        bind_address: 0 as *mut libc::c_char,
        bind_interface: 0 as *mut libc::c_char,
        pkcs11_provider: 0 as *mut libc::c_char,
        sk_provider: 0 as *mut libc::c_char,
        verify_host_key_dns: 0,
        num_identity_files: 0,
        identity_files: [0 as *mut libc::c_char; 100],
        identity_file_userprovided: [0; 100],
        identity_keys: [0 as *mut sshkey; 100],
        num_certificate_files: 0,
        certificate_files: [0 as *mut libc::c_char; 100],
        certificate_file_userprovided: [0; 100],
        certificates: [0 as *mut sshkey; 100],
        add_keys_to_agent: 0,
        add_keys_to_agent_lifespan: 0,
        identity_agent: 0 as *mut libc::c_char,
        num_local_forwards: 0,
        local_forwards: 0 as *mut Forward,
        num_remote_forwards: 0,
        remote_forwards: 0 as *mut Forward,
        clear_forwardings: 0,
        permitted_remote_opens: 0 as *mut *mut libc::c_char,
        num_permitted_remote_opens: 0,
        stdio_forward_host: 0 as *mut libc::c_char,
        stdio_forward_port: 0,
        enable_ssh_keysign: 0,
        rekey_limit: 0,
        rekey_interval: 0,
        no_host_authentication_for_localhost: 0,
        identities_only: 0,
        server_alive_interval: 0,
        server_alive_count_max: 0,
        num_send_env: 0,
        send_env: 0 as *mut *mut libc::c_char,
        num_setenv: 0,
        setenv: 0 as *mut *mut libc::c_char,
        control_path: 0 as *mut libc::c_char,
        control_master: 0,
        control_persist: 0,
        control_persist_timeout: 0,
        hash_known_hosts: 0,
        tun_open: 0,
        tun_local: 0,
        tun_remote: 0,
        local_command: 0 as *mut libc::c_char,
        permit_local_command: 0,
        remote_command: 0 as *mut libc::c_char,
        visual_host_key: 0,
        request_tty: 0,
        session_type: 0,
        stdin_null: 0,
        fork_after_authentication: 0,
        proxy_use_fdpass: 0,
        num_canonical_domains: 0,
        canonical_domains: [0 as *mut libc::c_char; 32],
        canonicalize_hostname: 0,
        canonicalize_max_dots: 0,
        canonicalize_fallback_local: 0,
        num_permitted_cnames: 0,
        permitted_cnames: [allowed_cname {
            source_list: 0 as *mut libc::c_char,
            target_list: 0 as *mut libc::c_char,
        }; 32],
        revoked_host_keys: 0 as *mut libc::c_char,
        fingerprint_hash: 0,
        update_hostkeys: 0,
        hostbased_accepted_algos: 0 as *mut libc::c_char,
        pubkey_accepted_algos: 0 as *mut libc::c_char,
        jump_user: 0 as *mut libc::c_char,
        jump_host: 0 as *mut libc::c_char,
        jump_port: 0,
        jump_extra: 0 as *mut libc::c_char,
        known_hosts_command: 0 as *mut libc::c_char,
        required_rsa_size: 0,
        enable_escape_commandline: 0,
        ignored_unknown: 0 as *mut libc::c_char,
    };
    let mut keys: [*mut sshkey; 5] = [0 as *mut sshkey; 5];
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut pw: *mut libc::passwd = 0 as *mut libc::passwd;
    let mut r: libc::c_int = 0;
    let mut key_fd: [libc::c_int; 5] = [0; 5];
    let mut i: libc::c_int = 0;
    let mut found: libc::c_int = 0;
    let mut version: libc::c_int = 2 as libc::c_int;
    let mut fd: libc::c_int = 0;
    let mut signature: *mut u_char = 0 as *mut u_char;
    let mut data: *mut u_char = 0 as *mut u_char;
    let mut rver: u_char = 0;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pkalg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut slen: size_t = 0;
    let mut dlen: size_t = 0;
    if crate::openbsd_compat::bsd_misc::pledge(
        b"stdio rpath getpw dns id\0" as *const u8 as *const libc::c_char,
        0 as *mut *const libc::c_char,
    ) != 0 as libc::c_int
    {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            189 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: crate::openbsd_compat::bsd_misc::pledge: %s\0" as *const u8
                as *const libc::c_char,
            __progname,
            libc::strerror(*libc::__errno_location()),
        );
    }
    fd = libc::open(
        b"/dev/null\0" as *const u8 as *const libc::c_char,
        0o2 as libc::c_int,
    );
    if fd < 2 as libc::c_int {
        libc::exit(1 as libc::c_int);
    }
    if fd > 2 as libc::c_int {
        close(fd);
    }
    i = 0 as libc::c_int;
    let fresh0 = i;
    i = i + 1;
    key_fd[fresh0 as usize] = libc::open(
        b"/usr/local/etc/ssh_host_dsa_key\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    let fresh1 = i;
    i = i + 1;
    key_fd[fresh1 as usize] = libc::open(
        b"/usr/local/etc/ssh_host_ecdsa_key\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    let fresh2 = i;
    i = i + 1;
    key_fd[fresh2 as usize] = libc::open(
        b"/usr/local/etc/ssh_host_ed25519_key\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    let fresh3 = i;
    i = i + 1;
    key_fd[fresh3 as usize] = libc::open(
        b"/usr/local/etc/ssh_host_xmss_key\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    let fresh4 = i;
    i = i + 1;
    key_fd[fresh4 as usize] = libc::open(
        b"/usr/local/etc/ssh_host_rsa_key\0" as *const u8 as *const libc::c_char,
        0 as libc::c_int,
    );
    pw = libc::getpwuid(libc::getuid());
    if pw.is_null() {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            207 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::getpwuid failed\0" as *const u8 as *const libc::c_char,
        );
    }
    pw = pwcopy(pw);
    permanently_set_uid(pw);
    seed_rng();
    initialize_options(&mut options);
    read_config_file(
        b"/usr/local/etc/ssh_config\0" as *const u8 as *const libc::c_char,
        pw,
        b"\0" as *const u8 as *const libc::c_char,
        b"\0" as *const u8 as *const libc::c_char,
        &mut options,
        0 as libc::c_int,
        0 as *mut libc::c_int,
    );
    fill_default_options(&mut options);
    if options.enable_ssh_keysign != 1 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            225 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ssh-keysign not enabled in %s\0" as *const u8 as *const libc::c_char,
            b"/usr/local/etc/ssh_config\0" as *const u8 as *const libc::c_char,
        );
    }
    if crate::openbsd_compat::bsd_misc::pledge(
        b"stdio dns\0" as *const u8 as *const libc::c_char,
        0 as *mut *const libc::c_char,
    ) != 0 as libc::c_int
    {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            228 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: crate::openbsd_compat::bsd_misc::pledge: %s\0" as *const u8
                as *const libc::c_char,
            __progname,
            libc::strerror(*libc::__errno_location()),
        );
    }
    found = 0 as libc::c_int;
    i = found;
    while i < 5 as libc::c_int {
        if key_fd[i as usize] != -(1 as libc::c_int) {
            found = 1 as libc::c_int;
        }
        i += 1;
        i;
    }
    if found == 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            235 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"could not open any host key\0" as *const u8 as *const libc::c_char,
        );
    }
    found = 0 as libc::c_int;
    i = 0 as libc::c_int;
    while i < 5 as libc::c_int {
        keys[i as usize] = 0 as *mut sshkey;
        if !(key_fd[i as usize] == -(1 as libc::c_int)) {
            r = sshkey_load_private_type_fd(
                key_fd[i as usize],
                KEY_UNSPEC as libc::c_int,
                0 as *const libc::c_char,
                &mut key,
                0 as *mut *mut libc::c_char,
            );
            close(key_fd[i as usize]);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    246 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    ssh_err(r),
                    b"parse key %d\0" as *const u8 as *const libc::c_char,
                    i,
                );
            } else if !key.is_null() {
                keys[i as usize] = key;
                found = 1 as libc::c_int;
            }
        }
        i += 1;
        i;
    }
    if found == 0 {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            253 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no hostkey found\0" as *const u8 as *const libc::c_char,
        );
    }
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            256 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
            __progname,
        );
    }
    if ssh_msg_recv(0 as libc::c_int, b) < 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            258 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: ssh_msg_recv failed\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_u8(b, &mut rver);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            260 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s: buffer error\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if rver as libc::c_int != version {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            263 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: bad version: received %d, expected %d\0" as *const u8 as *const libc::c_char,
            __progname,
            rver as libc::c_int,
            version,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_u32(b, &mut fd as *mut libc::c_int as *mut u_int);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            265 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s: buffer error\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if fd < 0 as libc::c_int || fd == 0 as libc::c_int || fd == 1 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            267 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: bad fd = %d\0" as *const u8 as *const libc::c_char,
            __progname,
            fd,
        );
    }
    host = get_local_name(fd);
    if host.is_null() {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            269 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: cannot get local name for fd\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    r = sshbuf_get_string(b, &mut data, &mut dlen);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            272 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s: buffer error\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if valid_request(pw, host, &mut key, &mut pkalg, data, dlen) < 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            274 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: not a valid request\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    libc::free(host as *mut libc::c_void);
    found = 0 as libc::c_int;
    i = 0 as libc::c_int;
    while i < 5 as libc::c_int {
        if !(keys[i as usize]).is_null() && sshkey_equal_public(key, keys[i as usize]) != 0 {
            found = 1 as libc::c_int;
            break;
        } else {
            i += 1;
            i;
        }
    }
    if found == 0 {
        fp = sshkey_fingerprint(key, options.fingerprint_hash, SSH_FP_DEFAULT);
        if fp.is_null() {
            sshfatal(
                b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                288 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s: sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
                __progname,
            );
        }
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            290 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: no matching hostkey found for key %s %s\0" as *const u8 as *const libc::c_char,
            __progname,
            sshkey_type(key),
            if !fp.is_null() {
                fp as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
        );
    }
    r = sshkey_sign(
        keys[i as usize],
        &mut signature,
        &mut slen,
        data,
        dlen,
        pkalg,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        0 as libc::c_int as u_int,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            295 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s: sshkey_sign failed\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    libc::free(data as *mut libc::c_void);
    crate::sshbuf::sshbuf_reset(b);
    r = sshbuf_put_string(b, signature as *const libc::c_void, slen);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            301 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s: buffer error\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if ssh_msg_send(1 as libc::c_int, version as u_char, b) == -(1 as libc::c_int) {
        sshfatal(
            b"ssh-keysign.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            303 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: ssh_msg_send failed\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    return 0 as libc::c_int;
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
