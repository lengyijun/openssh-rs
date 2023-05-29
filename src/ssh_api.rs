use crate::kex::newkeys;

use crate::channels::ssh_channels;

use crate::sshkey::EC_GROUP;

use crate::packet::session_state;

use ::libc;
extern "C" {

    pub type ec_group_st;
    pub type dh_st;

    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn seed_rng();
    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;

    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn sshpkt_ptr(_: *mut ssh, lenp: *mut size_t) -> *const u_char;
    fn sshpkt_put(ssh: *mut ssh, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_start(ssh: *mut ssh, type_0: u_char) -> libc::c_int;
    fn ssh_packet_get_output(_: *mut ssh) -> *mut libc::c_void;
    fn ssh_packet_get_input(_: *mut ssh) -> *mut libc::c_void;
    fn ssh_packet_read_poll2(_: *mut ssh, _: *mut u_char, seqnr_p: *mut u_int32_t) -> libc::c_int;
    fn ssh_packet_set_server(_: *mut ssh);
    fn ssh_packet_close(_: *mut ssh);
    fn ssh_packet_set_connection(_: *mut ssh, _: libc::c_int, _: libc::c_int) -> *mut ssh;
    fn kex_gen_server(_: *mut ssh) -> libc::c_int;
    fn kex_gen_client(_: *mut ssh) -> libc::c_int;
    fn kexgex_server(_: *mut ssh) -> libc::c_int;
    fn kexgex_client(_: *mut ssh) -> libc::c_int;
    fn kex_send_kexinit(_: *mut ssh) -> libc::c_int;
    fn kex_prop_free(_: *mut *mut libc::c_char);
    fn kex_prop2buf(_: *mut crate::sshbuf::sshbuf, proposal: *mut *mut libc::c_char)
        -> libc::c_int;
    fn kex_buf2prop(
        _: *mut crate::sshbuf::sshbuf,
        _: *mut libc::c_int,
        _: *mut *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn kex_ready(_: *mut ssh, _: *mut *mut libc::c_char) -> libc::c_int;
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
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn sshkey_is_cert(_: *const crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_type_from_name(_: *const libc::c_char) -> libc::c_int;

    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;
    fn compat_banner(_: *mut ssh, _: *const libc::c_char);

    fn sshbuf_check_reserve(buf: *const crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_consume(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_consume_end(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_putb(buf: *mut crate::sshbuf::sshbuf, v: *const crate::sshbuf::sshbuf)
        -> libc::c_int;

}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type uint8_t = __uint8_t;
pub type sig_atomic_t = __sig_atomic_t;
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

pub type DH = dh_st;

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
pub struct kex_params {
    pub proposal: [*mut libc::c_char; 10],
}
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
pub static mut use_privsep: libc::c_int = 0 as libc::c_int;
pub unsafe extern "C" fn mm_sshkey_sign(
    mut _key: *mut crate::sshkey::sshkey,
    mut _sigp: *mut *mut u_char,
    mut _lenp: *mut u_int,
    mut _data: *const u_char,
    mut _datalen: u_int,
    mut _alg: *const libc::c_char,
    mut _sk_provider: *const libc::c_char,
    mut _sk_pin: *const libc::c_char,
    mut _compat: u_int,
) -> libc::c_int {
    return -(1 as libc::c_int);
}
pub unsafe extern "C" fn mm_choose_dh(
    mut _min: libc::c_int,
    mut _nbits: libc::c_int,
    mut _max: libc::c_int,
) -> *mut DH {
    return 0 as *mut DH;
}
pub unsafe extern "C" fn ssh_init(
    mut sshp: *mut *mut ssh,
    mut is_server: libc::c_int,
    mut kex_params: *mut kex_params,
) -> libc::c_int {
    let mut myproposal: [*mut libc::c_char; 10] = [
        b"sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256\0"
            as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\0"
            as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\0"
            as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\0"
            as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\0"
            as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\0"
            as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"none,zlib@openssh.com\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        b"none,zlib@openssh.com\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ];
    let mut ssh: *mut ssh = 0 as *mut ssh;
    let mut proposal: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    static mut called: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    if called == 0 {
        seed_rng();
        called = 1 as libc::c_int;
    }
    ssh = ssh_packet_set_connection(0 as *mut ssh, -(1 as libc::c_int), -(1 as libc::c_int));
    if ssh.is_null() {
        return -(2 as libc::c_int);
    }
    if is_server != 0 {
        ssh_packet_set_server(ssh);
    }
    proposal = if !kex_params.is_null() {
        ((*kex_params).proposal).as_mut_ptr()
    } else {
        myproposal.as_mut_ptr()
    };
    r = kex_ready(ssh, proposal);
    if r != 0 as libc::c_int {
        ssh_free(ssh);
        return r;
    }
    (*(*ssh).kex).server = is_server;
    if is_server != 0 {
        (*(*ssh).kex).kex[KEX_DH_GRP1_SHA1 as libc::c_int as usize] =
            Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
        (*(*ssh).kex).kex[KEX_DH_GRP14_SHA1 as libc::c_int as usize] =
            Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
        (*(*ssh).kex).kex[KEX_DH_GRP14_SHA256 as libc::c_int as usize] =
            Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
        (*(*ssh).kex).kex[KEX_DH_GRP16_SHA512 as libc::c_int as usize] =
            Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
        (*(*ssh).kex).kex[KEX_DH_GRP18_SHA512 as libc::c_int as usize] =
            Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
        (*(*ssh).kex).kex[KEX_DH_GEX_SHA1 as libc::c_int as usize] =
            Some(kexgex_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
        (*(*ssh).kex).kex[KEX_DH_GEX_SHA256 as libc::c_int as usize] =
            Some(kexgex_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
        (*(*ssh).kex).kex[KEX_ECDH_SHA2 as libc::c_int as usize] =
            Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
        (*(*ssh).kex).kex[KEX_C25519_SHA256 as libc::c_int as usize] =
            Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
        (*(*ssh).kex).kex[KEX_KEM_SNTRUP761X25519_SHA512 as libc::c_int as usize] =
            Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
        (*(*ssh).kex).load_host_public_key = Some(
            _ssh_host_public_key
                as unsafe extern "C" fn(
                    libc::c_int,
                    libc::c_int,
                    *mut ssh,
                ) -> *mut crate::sshkey::sshkey,
        );
        (*(*ssh).kex).load_host_private_key = Some(
            _ssh_host_private_key
                as unsafe extern "C" fn(
                    libc::c_int,
                    libc::c_int,
                    *mut ssh,
                ) -> *mut crate::sshkey::sshkey,
        );
        (*(*ssh).kex).sign = Some(
            _ssh_host_key_sign
                as unsafe extern "C" fn(
                    *mut ssh,
                    *mut crate::sshkey::sshkey,
                    *mut crate::sshkey::sshkey,
                    *mut *mut u_char,
                    *mut size_t,
                    *const u_char,
                    size_t,
                    *const libc::c_char,
                ) -> libc::c_int,
        );
    } else {
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
            _ssh_verify_host_key
                as unsafe extern "C" fn(*mut crate::sshkey::sshkey, *mut ssh) -> libc::c_int,
        );
    }
    *sshp = ssh;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_free(mut ssh: *mut ssh) {
    let mut k: *mut key_entry = 0 as *mut key_entry;
    if ssh.is_null() {
        return;
    }
    loop {
        k = (*ssh).public_keys.tqh_first;
        if k.is_null() {
            break;
        }
        if !((*k).next.tqe_next).is_null() {
            (*(*k).next.tqe_next).next.tqe_prev = (*k).next.tqe_prev;
        } else {
            (*ssh).public_keys.tqh_last = (*k).next.tqe_prev;
        }
        *(*k).next.tqe_prev = (*k).next.tqe_next;
        if !((*ssh).kex).is_null() && (*(*ssh).kex).server != 0 {
            crate::sshkey::sshkey_free((*k).key);
        }
        libc::free(k as *mut libc::c_void);
    }
    loop {
        k = (*ssh).private_keys.tqh_first;
        if k.is_null() {
            break;
        }
        if !((*k).next.tqe_next).is_null() {
            (*(*k).next.tqe_next).next.tqe_prev = (*k).next.tqe_prev;
        } else {
            (*ssh).private_keys.tqh_last = (*k).next.tqe_prev;
        }
        *(*k).next.tqe_prev = (*k).next.tqe_next;
        libc::free(k as *mut libc::c_void);
    }
    ssh_packet_close(ssh);
    libc::free(ssh as *mut libc::c_void);
}
pub unsafe extern "C" fn ssh_set_app_data(mut ssh: *mut ssh, mut app_data: *mut libc::c_void) {
    (*ssh).app_data = app_data;
}
pub unsafe extern "C" fn ssh_get_app_data(mut ssh: *mut ssh) -> *mut libc::c_void {
    return (*ssh).app_data;
}
pub unsafe extern "C" fn ssh_add_hostkey(
    mut ssh: *mut ssh,
    mut key: *mut crate::sshkey::sshkey,
) -> libc::c_int {
    let mut pubkey: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut k: *mut key_entry = 0 as *mut key_entry;
    let mut k_prv: *mut key_entry = 0 as *mut key_entry;
    let mut r: libc::c_int = 0;
    if (*(*ssh).kex).server != 0 {
        r = crate::sshkey::sshkey_from_private(key, &mut pubkey);
        if r != 0 as libc::c_int {
            return r;
        }
        k = libc::malloc(::core::mem::size_of::<key_entry>() as usize) as *mut key_entry;
        if k.is_null() || {
            k_prv = libc::malloc(::core::mem::size_of::<key_entry>() as usize) as *mut key_entry;
            k_prv.is_null()
        } {
            libc::free(k as *mut libc::c_void);
            crate::sshkey::sshkey_free(pubkey);
            return -(2 as libc::c_int);
        }
        (*k_prv).key = key;
        (*k_prv).next.tqe_next = 0 as *mut key_entry;
        (*k_prv).next.tqe_prev = (*ssh).private_keys.tqh_last;
        *(*ssh).private_keys.tqh_last = k_prv;
        (*ssh).private_keys.tqh_last = &mut (*k_prv).next.tqe_next;
        (*k).key = pubkey;
        (*k).next.tqe_next = 0 as *mut key_entry;
        (*k).next.tqe_prev = (*ssh).public_keys.tqh_last;
        *(*ssh).public_keys.tqh_last = k;
        (*ssh).public_keys.tqh_last = &mut (*k).next.tqe_next;
        r = 0 as libc::c_int;
    } else {
        k = libc::malloc(::core::mem::size_of::<key_entry>() as usize) as *mut key_entry;
        if k.is_null() {
            return -(2 as libc::c_int);
        }
        (*k).key = key;
        (*k).next.tqe_next = 0 as *mut key_entry;
        (*k).next.tqe_prev = (*ssh).public_keys.tqh_last;
        *(*ssh).public_keys.tqh_last = k;
        (*ssh).public_keys.tqh_last = &mut (*k).next.tqe_next;
        r = 0 as libc::c_int;
    }
    return r;
}
pub unsafe extern "C" fn ssh_set_verify_host_key_callback(
    mut ssh: *mut ssh,
    mut cb: Option<unsafe extern "C" fn(*mut crate::sshkey::sshkey, *mut ssh) -> libc::c_int>,
) -> libc::c_int {
    if cb.is_none() || ((*ssh).kex).is_null() {
        return -(10 as libc::c_int);
    }
    (*(*ssh).kex).verify_host_key = cb;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_input_append(
    mut ssh: *mut ssh,
    mut data: *const u_char,
    mut len: size_t,
) -> libc::c_int {
    return sshbuf_put(
        ssh_packet_get_input(ssh) as *mut crate::sshbuf::sshbuf,
        data as *const libc::c_void,
        len,
    );
}
pub unsafe extern "C" fn ssh_packet_next(mut ssh: *mut ssh, mut typep: *mut u_char) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut seqnr: u_int32_t = 0;
    let mut type_0: u_char = 0;
    *typep = 0 as libc::c_int as u_char;
    if crate::sshbuf::sshbuf_len((*(*ssh).kex).client_version) == 0 as libc::c_int as libc::c_ulong
        || crate::sshbuf::sshbuf_len((*(*ssh).kex).server_version)
            == 0 as libc::c_int as libc::c_ulong
    {
        return _ssh_exchange_banner(ssh);
    }
    loop {
        r = ssh_packet_read_poll2(ssh, &mut type_0, &mut seqnr);
        if r != 0 as libc::c_int {
            return r;
        }
        if type_0 as libc::c_int > 0 as libc::c_int
            && (type_0 as libc::c_int) < 255 as libc::c_int
            && type_0 as libc::c_int >= 20 as libc::c_int
            && type_0 as libc::c_int <= 49 as libc::c_int
            && ((*ssh).dispatch[type_0 as usize]).is_some()
        {
            r = (Some(
                (*((*ssh).dispatch).as_mut_ptr().offset(type_0 as isize))
                    .expect("non-null function pointer"),
            ))
            .expect("non-null function pointer")(type_0 as libc::c_int, seqnr, ssh);
            if r != 0 as libc::c_int {
                return r;
            }
        } else {
            *typep = type_0;
            return 0 as libc::c_int;
        }
    }
}
pub unsafe extern "C" fn ssh_packet_payload(
    mut ssh: *mut ssh,
    mut lenp: *mut size_t,
) -> *const u_char {
    return sshpkt_ptr(ssh, lenp);
}
pub unsafe extern "C" fn ssh_packet_put(
    mut ssh: *mut ssh,
    mut type_0: libc::c_int,
    mut data: *const u_char,
    mut len: size_t,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = sshpkt_start(ssh, type_0 as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put(ssh, data as *const libc::c_void, len);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_output_ptr(mut ssh: *mut ssh, mut len: *mut size_t) -> *const u_char {
    let mut output: *mut crate::sshbuf::sshbuf =
        ssh_packet_get_output(ssh) as *mut crate::sshbuf::sshbuf;
    *len = crate::sshbuf::sshbuf_len(output);
    return crate::sshbuf::sshbuf_ptr(output);
}
pub unsafe extern "C" fn ssh_output_consume(mut ssh: *mut ssh, mut len: size_t) -> libc::c_int {
    return sshbuf_consume(
        ssh_packet_get_output(ssh) as *mut crate::sshbuf::sshbuf,
        len,
    );
}
pub unsafe extern "C" fn ssh_output_space(mut ssh: *mut ssh, mut len: size_t) -> libc::c_int {
    return (0 as libc::c_int
        == sshbuf_check_reserve(
            ssh_packet_get_output(ssh) as *const crate::sshbuf::sshbuf,
            len,
        )) as libc::c_int;
}
pub unsafe extern "C" fn ssh_input_space(mut ssh: *mut ssh, mut len: size_t) -> libc::c_int {
    return (0 as libc::c_int
        == sshbuf_check_reserve(
            ssh_packet_get_input(ssh) as *const crate::sshbuf::sshbuf,
            len,
        )) as libc::c_int;
}
pub unsafe extern "C" fn _ssh_read_banner(
    mut ssh: *mut ssh,
    mut banner: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut input: *mut crate::sshbuf::sshbuf =
        ssh_packet_get_input(ssh) as *mut crate::sshbuf::sshbuf;
    let mut mismatch: *const libc::c_char =
        b"Protocol mismatch.\r\n\0" as *const u8 as *const libc::c_char;
    let mut s: *const u_char = crate::sshbuf::sshbuf_ptr(input);
    let mut c: u_char = 0;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut remote_version: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0 as libc::c_int;
    let mut remote_major: libc::c_int = 0;
    let mut remote_minor: libc::c_int = 0;
    let mut expect_nl: libc::c_int = 0;
    let mut n: size_t = 0;
    let mut j: size_t = 0;
    n = 0 as libc::c_int as size_t;
    j = n;
    loop {
        crate::sshbuf::sshbuf_reset(banner);
        expect_nl = 0 as libc::c_int;
        loop {
            if j >= crate::sshbuf::sshbuf_len(input) {
                return 0 as libc::c_int;
            }
            let fresh0 = j;
            j = j.wrapping_add(1);
            c = *s.offset(fresh0 as isize);
            if c as libc::c_int == '\r' as i32 {
                expect_nl = 1 as libc::c_int;
            } else {
                if c as libc::c_int == '\n' as i32 {
                    current_block = 1054647088692577877;
                    break;
                }
                if expect_nl != 0 {
                    current_block = 5020065448061302065;
                    break;
                }
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(banner, c);
                if r != 0 as libc::c_int {
                    return r;
                }
                if crate::sshbuf::sshbuf_len(banner) > 8192 as libc::c_int as libc::c_ulong {
                    current_block = 5020065448061302065;
                    break;
                }
            }
        }
        match current_block {
            1054647088692577877 => {
                if crate::sshbuf::sshbuf_len(banner) >= 4 as libc::c_int as libc::c_ulong
                    && memcmp(
                        crate::sshbuf::sshbuf_ptr(banner) as *const libc::c_void,
                        b"SSH-\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                        4 as libc::c_int as libc::c_ulong,
                    ) == 0 as libc::c_int
                {
                    break;
                }
                crate::log::sshlog(
                    b"ssh_api.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"_ssh_read_banner\0",
                    ))
                    .as_ptr(),
                    359 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"%.*s\0" as *const u8 as *const libc::c_char,
                    crate::sshbuf::sshbuf_len(banner) as libc::c_int,
                    crate::sshbuf::sshbuf_ptr(banner),
                );
                if !((*(*ssh).kex).server != 0 || {
                    n = n.wrapping_add(1);
                    n > 1024 as libc::c_int as libc::c_ulong
                }) {
                    continue;
                }
            }
            _ => {}
        }
        r = sshbuf_put(
            ssh_packet_get_output(ssh) as *mut crate::sshbuf::sshbuf,
            mismatch as *const libc::c_void,
            strlen(mismatch),
        );
        if r != 0 as libc::c_int {
            return r;
        }
        return -(38 as libc::c_int);
    }
    r = sshbuf_consume(input, j);
    if r != 0 as libc::c_int {
        return r;
    }
    cp = crate::sshbuf_misc::sshbuf_dup_string(banner);
    if cp.is_null() || {
        remote_version = calloc(
            1 as libc::c_int as libc::c_ulong,
            crate::sshbuf::sshbuf_len(banner),
        ) as *mut libc::c_char;
        remote_version.is_null()
    } {
        r = -(2 as libc::c_int);
    } else if sscanf(
        cp,
        b"SSH-%d.%d-%[^\n]\n\0" as *const u8 as *const libc::c_char,
        &mut remote_major as *mut libc::c_int,
        &mut remote_minor as *mut libc::c_int,
        remote_version,
    ) != 3 as libc::c_int
    {
        r = -(4 as libc::c_int);
    } else {
        crate::log::sshlog(
            b"ssh_api.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"_ssh_read_banner\0"))
                .as_ptr(),
            389 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Remote protocol version %d.%d, remote software version %.100s\0" as *const u8
                as *const libc::c_char,
            remote_major,
            remote_minor,
            remote_version,
        );
        compat_banner(ssh, remote_version);
        if remote_major == 1 as libc::c_int && remote_minor == 99 as libc::c_int {
            remote_major = 2 as libc::c_int;
            remote_minor = 0 as libc::c_int;
        }
        if remote_major != 2 as libc::c_int {
            r = -(37 as libc::c_int);
        }
        crate::log::sshlog(
            b"ssh_api.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"_ssh_read_banner\0"))
                .as_ptr(),
            399 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Remote version string %.100s\0" as *const u8 as *const libc::c_char,
            cp,
        );
    }
    libc::free(cp as *mut libc::c_void);
    libc::free(remote_version as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn _ssh_send_banner(
    mut ssh: *mut ssh,
    mut banner: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    r = crate::sshbuf_getput_basic::sshbuf_putf(
        banner,
        b"SSH-2.0-%.100s\r\n\0" as *const u8 as *const libc::c_char,
        b"OpenSSH_9.3\0" as *const u8 as *const libc::c_char,
    );
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshbuf_putb(
        ssh_packet_get_output(ssh) as *mut crate::sshbuf::sshbuf,
        banner,
    );
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshbuf_consume_end(banner, 2 as libc::c_int as size_t);
    if r != 0 as libc::c_int {
        return r;
    }
    cp = crate::sshbuf_misc::sshbuf_dup_string(banner);
    if cp.is_null() {
        return -(2 as libc::c_int);
    }
    crate::log::sshlog(
        b"ssh_api.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"_ssh_send_banner\0")).as_ptr(),
        422 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Local version string %.100s\0" as *const u8 as *const libc::c_char,
        cp,
    );
    libc::free(cp as *mut libc::c_void);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn _ssh_exchange_banner(mut ssh: *mut ssh) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut r: libc::c_int = 0;
    r = 0 as libc::c_int;
    if (*kex).server != 0 {
        if crate::sshbuf::sshbuf_len((*(*ssh).kex).server_version)
            == 0 as libc::c_int as libc::c_ulong
        {
            r = _ssh_send_banner(ssh, (*(*ssh).kex).server_version);
        }
        if r == 0 as libc::c_int
            && crate::sshbuf::sshbuf_len((*(*ssh).kex).server_version)
                != 0 as libc::c_int as libc::c_ulong
            && crate::sshbuf::sshbuf_len((*(*ssh).kex).client_version)
                == 0 as libc::c_int as libc::c_ulong
        {
            r = _ssh_read_banner(ssh, (*(*ssh).kex).client_version);
        }
    } else {
        if crate::sshbuf::sshbuf_len((*(*ssh).kex).server_version)
            == 0 as libc::c_int as libc::c_ulong
        {
            r = _ssh_read_banner(ssh, (*(*ssh).kex).server_version);
        }
        if r == 0 as libc::c_int
            && crate::sshbuf::sshbuf_len((*(*ssh).kex).server_version)
                != 0 as libc::c_int as libc::c_ulong
            && crate::sshbuf::sshbuf_len((*(*ssh).kex).client_version)
                == 0 as libc::c_int as libc::c_ulong
        {
            r = _ssh_send_banner(ssh, (*(*ssh).kex).client_version);
        }
    }
    if r != 0 as libc::c_int {
        return r;
    }
    if crate::sshbuf::sshbuf_len((*(*ssh).kex).server_version) != 0 as libc::c_int as libc::c_ulong
        && crate::sshbuf::sshbuf_len((*(*ssh).kex).client_version)
            != 0 as libc::c_int as libc::c_ulong
    {
        r = _ssh_order_hostkeyalgs(ssh);
        if r != 0 as libc::c_int || {
            r = kex_send_kexinit(ssh);
            r != 0 as libc::c_int
        } {
            return r;
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn _ssh_host_public_key(
    mut type_0: libc::c_int,
    mut nid: libc::c_int,
    mut ssh: *mut ssh,
) -> *mut crate::sshkey::sshkey {
    let mut k: *mut key_entry = 0 as *mut key_entry;
    crate::log::sshlog(
        b"ssh_api.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"_ssh_host_public_key\0"))
            .as_ptr(),
        471 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"need %d\0" as *const u8 as *const libc::c_char,
        type_0,
    );
    k = (*ssh).public_keys.tqh_first;
    while !k.is_null() {
        crate::log::sshlog(
            b"ssh_api.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"_ssh_host_public_key\0"))
                .as_ptr(),
            473 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"check %s\0" as *const u8 as *const libc::c_char,
            crate::sshkey::sshkey_type((*k).key),
        );
        if (*(*k).key).type_0 == type_0
            && (type_0 != KEY_ECDSA as libc::c_int || (*(*k).key).ecdsa_nid == nid)
        {
            return (*k).key;
        }
        k = (*k).next.tqe_next;
    }
    return 0 as *mut crate::sshkey::sshkey;
}
pub unsafe extern "C" fn _ssh_host_private_key(
    mut type_0: libc::c_int,
    mut nid: libc::c_int,
    mut ssh: *mut ssh,
) -> *mut crate::sshkey::sshkey {
    let mut k: *mut key_entry = 0 as *mut key_entry;
    crate::log::sshlog(
        b"ssh_api.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"_ssh_host_private_key\0"))
            .as_ptr(),
        486 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"need %d\0" as *const u8 as *const libc::c_char,
        type_0,
    );
    k = (*ssh).private_keys.tqh_first;
    while !k.is_null() {
        crate::log::sshlog(
            b"ssh_api.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"_ssh_host_private_key\0"))
                .as_ptr(),
            488 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"check %s\0" as *const u8 as *const libc::c_char,
            crate::sshkey::sshkey_type((*k).key),
        );
        if (*(*k).key).type_0 == type_0
            && (type_0 != KEY_ECDSA as libc::c_int || (*(*k).key).ecdsa_nid == nid)
        {
            return (*k).key;
        }
        k = (*k).next.tqe_next;
    }
    return 0 as *mut crate::sshkey::sshkey;
}
pub unsafe extern "C" fn _ssh_verify_host_key(
    mut hostkey: *mut crate::sshkey::sshkey,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut k: *mut key_entry = 0 as *mut key_entry;
    crate::log::sshlog(
        b"ssh_api.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"_ssh_verify_host_key\0"))
            .as_ptr(),
        501 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"need %s\0" as *const u8 as *const libc::c_char,
        crate::sshkey::sshkey_type(hostkey),
    );
    k = (*ssh).public_keys.tqh_first;
    while !k.is_null() {
        crate::log::sshlog(
            b"ssh_api.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"_ssh_verify_host_key\0"))
                .as_ptr(),
            503 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"check %s\0" as *const u8 as *const libc::c_char,
            crate::sshkey::sshkey_type((*k).key),
        );
        if crate::sshkey::sshkey_equal_public(hostkey, (*k).key) != 0 {
            return 0 as libc::c_int;
        }
        k = (*k).next.tqe_next;
    }
    return -(1 as libc::c_int);
}
pub unsafe extern "C" fn _ssh_order_hostkeyalgs(mut ssh: *mut ssh) -> libc::c_int {
    let mut k: *mut key_entry = 0 as *mut key_entry;
    let mut orig: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut avail: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut oavail: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut alg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut replace: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut proposal: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut maxlen: size_t = 0;
    let mut ktype: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    r = kex_buf2prop((*(*ssh).kex).my, 0 as *mut libc::c_int, &mut proposal);
    if r != 0 as libc::c_int {
        return r;
    }
    orig = *proposal.offset(PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as isize);
    avail = libc::strdup(orig);
    oavail = avail;
    if oavail.is_null() {
        r = -(2 as libc::c_int);
    } else {
        maxlen = (strlen(avail)).wrapping_add(1 as libc::c_int as libc::c_ulong);
        replace = calloc(1 as libc::c_int as libc::c_ulong, maxlen) as *mut libc::c_char;
        if replace.is_null() {
            r = -(2 as libc::c_int);
        } else {
            *replace = '\0' as i32 as libc::c_char;
            loop {
                alg = strsep(&mut avail, b",\0" as *const u8 as *const libc::c_char);
                if !(!alg.is_null() && *alg as libc::c_int != '\0' as i32) {
                    break;
                }
                ktype = sshkey_type_from_name(alg);
                if ktype == KEY_UNSPEC as libc::c_int {
                    continue;
                }
                k = (*ssh).public_keys.tqh_first;
                while !k.is_null() {
                    if (*(*k).key).type_0 == ktype
                        || sshkey_is_cert((*k).key) != 0
                            && (*(*k).key).type_0 == sshkey_type_plain(ktype)
                    {
                        if *replace as libc::c_int != '\0' as i32 {
                            strlcat(replace, b",\0" as *const u8 as *const libc::c_char, maxlen);
                        }
                        strlcat(replace, alg, maxlen);
                        break;
                    } else {
                        k = (*k).next.tqe_next;
                    }
                }
            }
            if *replace as libc::c_int != '\0' as i32 {
                crate::log::sshlog(
                    b"ssh_api.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"_ssh_order_hostkeyalgs\0",
                    ))
                    .as_ptr(),
                    549 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"orig/%d    %s\0" as *const u8 as *const libc::c_char,
                    (*(*ssh).kex).server,
                    orig,
                );
                crate::log::sshlog(
                    b"ssh_api.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"_ssh_order_hostkeyalgs\0",
                    ))
                    .as_ptr(),
                    550 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"replace/%d %s\0" as *const u8 as *const libc::c_char,
                    (*(*ssh).kex).server,
                    replace,
                );
                libc::free(orig as *mut libc::c_void);
                let ref mut fresh1 =
                    *proposal.offset(PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as isize);
                *fresh1 = replace;
                replace = 0 as *mut libc::c_char;
                r = kex_prop2buf((*(*ssh).kex).my, proposal);
            }
        }
    }
    libc::free(oavail as *mut libc::c_void);
    libc::free(replace as *mut libc::c_void);
    kex_prop_free(proposal);
    return r;
}
pub unsafe extern "C" fn _ssh_host_key_sign(
    mut ssh: *mut ssh,
    mut privkey: *mut crate::sshkey::sshkey,
    mut _pubkey: *mut crate::sshkey::sshkey,
    mut signature: *mut *mut u_char,
    mut slen: *mut size_t,
    mut data: *const u_char,
    mut dlen: size_t,
    mut alg: *const libc::c_char,
) -> libc::c_int {
    return sshkey_sign(
        privkey,
        signature,
        slen,
        data,
        dlen,
        alg,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        (*ssh).compat as u_int,
    );
}
